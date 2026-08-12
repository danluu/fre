//! Native emission for graph-proven interior DFA self-loop skipping.
//!
//! This is a child of `module`: it deliberately reuses the audited byte-set
//! comparisons used by start and required-literal scanners. The hot scalar
//! DFA loop pays one row-address comparison. On the selected row, whole SIMD
//! blocks containing no exit byte advance without table lookups; the first
//! possible exit is refined scalarly and processed by the ordinary DFA loop.

use crate::{
    dfa::NativeDfaView,
    dfa_loop_skip::{DfaLoopSkipPlan, MAX_DFA_LOOP_VECTOR_CONSTANTS, select_dfa_loop_skip},
    program::OutputContract,
};

use super::{
    AARCH64_EQ, AARCH64_HS, AARCH64_LO, AARCH64_LS, AARCH64_NE, Aarch64Assembler,
    Aarch64ExactSveKind, Aarch64Label, Aarch64SveFilterKind, EMPTY_NATIVE_START_FILTER,
    NativeDfaLayout, NativeStartFilter, NativeVectorFilter, ObjectError, X86Assembler,
    X86CandidateMask, X86Label, X86StartFilterKind, aarch64_add_x_imm, aarch64_cmp_w_imm,
    aarch64_cmp_w_zero, aarch64_cmp_x, aarch64_cmp_x_imm, aarch64_cmp_x_lsl, aarch64_csel_x,
    aarch64_emit_candidate_any, aarch64_emit_exact_sve_constants,
    aarch64_emit_first_candidate_in_batch, aarch64_emit_first_candidate_lane,
    aarch64_emit_start_filter_address, aarch64_emit_start_filter_batch_candidates,
    aarch64_emit_start_filter_constants, aarch64_emit_start_filter_scalar_load,
    aarch64_emit_start_filter_vector_candidates, aarch64_load_q, aarch64_mov_x, aarch64_orr_16b,
    aarch64_set_table_address, aarch64_sub_x_reg, aarch64_sve_addvl, aarch64_sve_and_b,
    aarch64_sve_brkb_p0, aarch64_sve_cmpeq_b, aarch64_sve_cmphs_b, aarch64_sve_cntb,
    aarch64_sve_dup_b_imm, aarch64_sve_incp_b, aarch64_sve_ld1b_vl, aarch64_sve_ld1rqb,
    aarch64_sve_orr_b, aarch64_sve_ptest_p0, aarch64_sve_ptrue_b, aarch64_sve_whilelo_b,
    aarch64_sve2_match_b, x86_emit_first_candidate_lane, x86_emit_start_filter_constants,
    x86_emit_start_filter_scalar_load, x86_emit_start_filter_vector_candidate,
};

/// Lowering-time form of one target-neutral self-loop plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NativeDfaLoopSkip {
    pub(super) filter: NativeStartFilter,
    /// Every skipped byte updates the pending selected end when true.
    pub(super) accepting: bool,
    /// Semantic DFA state selected by the target-neutral graph analysis.
    pub(super) state: u32,
    /// Table-relative byte address of the selected state's physical row.
    pub(super) row_offset: u32,
    /// Optional target-installed 16-byte table for SVE2 `MATCH`.
    ///
    /// Base SVE uses immediate constants and leaves this absent. Installation
    /// is transactional and target-specific, so a failed optional allocation
    /// retains the exact base-SVE lowering.
    pub(super) sve2_match_table_offset: Option<u32>,
}

const AARCH64_ASIMD_LOOP_BATCH_MAX_EXIT_BYTES: u16 = 4;

/// Whether the fixed-width AArch64 lowering can amortize its loop guard over
/// the established four-vector (64-byte) group. Mixed SVE targets use this
/// same graph-only gate before retaining an ASIMD VL16 arm.
#[must_use]
pub(super) const fn aarch64_uses_asimd_batch(plan: NativeDfaLoopSkip) -> bool {
    plan.filter.candidate_bytes <= AARCH64_ASIMD_LOOP_BATCH_MAX_EXIT_BYTES
}

/// Select and address one interior loop after the transition row size is
/// known. A malformed or unprofitable analysis conservatively emits no plan.
pub(super) fn derive_native_dfa_loop_skip(
    dfa: &NativeDfaView<'_>,
    output: OutputContract,
    forward_offset: usize,
    row_bytes: usize,
    logical_to_physical: Option<&[u32]>,
    physical_row_offsets: Option<&[u32]>,
) -> Result<Option<NativeDfaLoopSkip>, ObjectError> {
    let Some(plan) = select_dfa_loop_skip(dfa, output) else {
        return Ok(None);
    };
    let state = usize::try_from(plan.state)
        .map_err(|_| ObjectError::ArithmeticOverflow("native loop-skip state"))?;
    let physical_state = logical_to_physical
        .map(|mapping| {
            mapping
                .get(state)
                .copied()
                .ok_or(ObjectError::InvalidModule(
                    "native loop-skip state has no physical row",
                ))
                .and_then(|state| {
                    usize::try_from(state).map_err(|_| {
                        ObjectError::ArithmeticOverflow("native loop-skip physical state")
                    })
                })
        })
        .transpose()?
        .unwrap_or(state);
    let row_offset = if let Some(offsets) = physical_row_offsets {
        offsets
            .get(physical_state)
            .copied()
            .ok_or(ObjectError::InvalidModule(
                "native loop-skip physical row has no variable offset",
            ))?
    } else {
        physical_state
            .checked_mul(row_bytes)
            .and_then(|offset| offset.checked_add(forward_offset))
            .and_then(|offset| u32::try_from(offset).ok())
            .ok_or(ObjectError::ArithmeticOverflow(
                "native loop-skip row offset",
            ))?
    };
    Ok(Some(NativeDfaLoopSkip {
        filter: native_filter(plan)?,
        accepting: plan.accepting,
        state: plan.state,
        row_offset,
        sve2_match_table_offset: None,
    }))
}

fn native_filter(plan: DfaLoopSkipPlan) -> Result<NativeStartFilter, ObjectError> {
    if plan.vector_constant_count > MAX_DFA_LOOP_VECTOR_CONSTANTS {
        return Err(ObjectError::InvalidModule(
            "native loop-skip vector register budget",
        ));
    }
    let mut filter = EMPTY_NATIVE_START_FILTER;
    for (index, range) in plan.ranges().iter().copied().enumerate() {
        let destination = filter
            .ranges
            .get_mut(index)
            .ok_or(ObjectError::InvalidModule("native loop-skip range count"))?;
        destination.start = range.start;
        destination.end = range.end;
    }
    filter.range_count = u8::try_from(plan.ranges().len())
        .map_err(|_| ObjectError::ArithmeticOverflow("native loop-skip ranges"))?;
    filter.candidate_bytes = plan.exit_byte_count;
    Ok(filter)
}

fn x86_restore_start_constants(
    assembler: &mut X86Assembler,
    layout: &NativeDfaLayout,
    vector_filter: Option<NativeVectorFilter>,
    kind: X86StartFilterKind,
    exact_vector_kind: Option<X86StartFilterKind>,
) -> Result<(), ObjectError> {
    if let Some(exact_vector_kind) = exact_vector_kind {
        let storage = layout
            .exact_start_storage
            .ok_or(ObjectError::InvalidModule(
                "x86 loop-skip restore lost exact scanner storage",
            ))?;
        return super::x86_emit_exact_vector_constants(
            assembler,
            storage,
            exact_vector_kind,
        );
    }
    if let Some(plan) = layout
        .prefix_relation
        .and_then(|relation| relation.vector_plan)
    {
        return super::x86_emit_prefix_relation_constants(assembler, plan, kind);
    }
    let Some(primary) = layout.start_filter else {
        return Ok(());
    };
    if primary.ranges().is_empty() {
        return Ok(());
    }
    if let Some(vector_filter) = vector_filter {
        let mut first_register = 1_u8;
        for &column in vector_filter.columns() {
            x86_emit_start_filter_constants(assembler, column, kind, first_register)?;
            first_register = first_register
                .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                    ObjectError::ArithmeticOverflow("x86 restored vector-filter constants")
                })?)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 restored vector-filter constants",
                ))?;
        }
    } else {
        x86_emit_start_filter_constants(assembler, primary, kind, 1)?;
    }
    Ok(())
}

/// Emit one guarded x86-64 loop skipper.
///
/// `ordinary` is the original scalar transition body and `exhausted` is its
/// existing end-of-window path. The function always branches to one of them.
#[allow(
    clippy::too_many_arguments,
    reason = "the emitter needs the active scanner mode and its four control-flow inputs"
)]
pub(super) fn x86_emit_dfa_loop_skip(
    assembler: &mut X86Assembler,
    plan: NativeDfaLoopSkip,
    layout: &NativeDfaLayout,
    vector_filter: Option<NativeVectorFilter>,
    kind: X86StartFilterKind,
    exact_vector_kind: Option<X86StartFilterKind>,
    ordinary: X86Label,
    exhausted: X86Label,
) -> Result<(), ObjectError> {
    let vector = assembler.label()?;
    let single_vector = assembler.label()?;
    let scalar = assembler.label()?;
    let vector_hit = assembler.label()?;
    let exit = assembler.label()?;

    let mut plan_row = vec![0x49, 0x8d, 0x81]; // lea row_offset(r9), rax
    plan_row.extend_from_slice(&plan.row_offset.to_le_bytes());
    assembler.instruction(&plan_row)?;
    assembler.instruction(&[0x49, 0x39, 0xc2])?; // cmp r10, rax
    assembler.branch(&[0x0f, 0x85], ordinary)?;

    // Version the loop only when at least two vectors remain. This bounds the
    // row-guard/constant-setup tax on short windows without using input or
    // pattern identities in the cost model.
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
    let minimum_remaining = u32::from(kind.width())
        .checked_mul(2)
        .ok_or(ObjectError::ArithmeticOverflow("x86 loop-skip entry width"))?;
    let mut compare_entry = vec![0x48, 0x3d];
    compare_entry.extend_from_slice(&minimum_remaining.to_le_bytes());
    assembler.instruction(&compare_entry)?;
    assembler.branch(&[0x0f, 0x82], ordinary)?;

    x86_emit_start_filter_constants(assembler, plan.filter, kind, 1)?;
    assembler.bind(vector)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
    let unrolled_bytes =
        u32::from(kind.width())
            .checked_mul(4)
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 loop-skip unrolled width",
            ))?;
    let mut compare_unrolled = vec![0x48, 0x3d];
    compare_unrolled.extend_from_slice(&unrolled_bytes.to_le_bytes());
    assembler.instruction(&compare_unrolled)?;
    assembler.branch(&[0x0f, 0x82], single_vector)?;
    for _ in 0..4 {
        x86_emit_start_filter_vector_candidate(assembler, plan.filter, kind, vector_hit)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        if plan.accepting {
            assembler.instruction(&[0x49, 0x89, 0xd3])?; // pending end = position
        }
    }
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(single_vector)?;
    assembler.instruction(&[0x48, 0x83, 0xf8, kind.width()])?;
    assembler.branch(&[0x0f, 0x82], scalar)?;
    x86_emit_start_filter_vector_candidate(assembler, plan.filter, kind, vector_hit)?;
    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    if plan.accepting {
        assembler.instruction(&[0x49, 0x89, 0xd3])?; // pending end = position
    }
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(vector_hit)?;
    x86_emit_first_candidate_lane(assembler, X86CandidateMask::for_filter(plan.filter, kind))?;
    if plan.accepting {
        // Lane zero means no accepting transition was skipped. Preserve the
        // prior pending end in that case; otherwise the exit's byte offset is
        // exactly the end of the final skipped accepting transition.
        assembler.instruction(&[0x48, 0x85, 0xc0])?; // test rax, rax
        assembler.branch(&[0x0f, 0x84], exit)?;
        assembler.instruction(&[0x48, 0x01, 0xc2])?; // position += lane
        assembler.instruction(&[0x49, 0x89, 0xd3])?; // pending end = position
    } else {
        assembler.instruction(&[0x48, 0x01, 0xc2])?; // position += lane
    }
    assembler.branch(&[0xe9], exit)?;

    assembler.bind(scalar)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?; // position >= end
    assembler.branch(&[0x0f, 0x83], exhausted)?;
    x86_emit_start_filter_scalar_load(assembler, 0)?;
    for range in plan.filter.ranges() {
        assembler.instruction(&[0x3c, range.start])?;
        if range.start == range.end {
            assembler.branch(&[0x0f, 0x84], exit)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch(&[0x0f, 0x82], next_range)?;
            assembler.instruction(&[0x3c, range.end])?;
            assembler.branch(&[0x0f, 0x86], exit)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    if plan.accepting {
        assembler.instruction(&[0x49, 0x89, 0xd3])?; // pending end = position
    }
    assembler.branch(&[0xe9], scalar)?;

    assembler.bind(exit)?;
    x86_restore_start_constants(
        assembler,
        layout,
        vector_filter,
        kind,
        exact_vector_kind,
    )?;
    assembler.branch(&[0xe9], ordinary)?;
    Ok(())
}

fn aarch64_restore_start_constants(
    assembler: &mut Aarch64Assembler,
    layout: &NativeDfaLayout,
    vector_filter: Option<NativeVectorFilter>,
    exact_sve_kind: Option<Aarch64ExactSveKind>,
) -> Result<(), ObjectError> {
    if layout.exact_start_byte_set.is_some() {
        let storage = layout
            .exact_start_storage
            .ok_or(ObjectError::InvalidModule(
                "AArch64 loop-skip restore lost exact scanner storage",
            ))?;
        return if let Some(kind) = exact_sve_kind {
            aarch64_emit_exact_sve_constants(assembler, storage, kind)
        } else {
            super::aarch64_emit_exact_asimd_constants(assembler, storage)
        };
    }
    if let Some(plan) = layout
        .prefix_relation
        .and_then(|relation| relation.vector_plan)
    {
        return super::aarch64_emit_prefix_relation_constants(assembler, plan);
    }
    let Some(primary) = layout.start_filter else {
        return Ok(());
    };
    if primary.ranges().is_empty() {
        return Ok(());
    }
    if let Some(vector_filter) = vector_filter {
        let mut first_register = 1_u8;
        for &column in vector_filter.columns() {
            aarch64_emit_start_filter_constants(assembler, column, first_register)?;
            first_register = first_register
                .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                    ObjectError::ArithmeticOverflow("AArch64 restored vector-filter constants")
                })?)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 restored vector-filter constants",
                ))?;
        }
    } else {
        let first_register = if primary.is_exact() { 1 } else { 16 };
        aarch64_emit_start_filter_constants(assembler, primary, first_register)?;
    }
    Ok(())
}

pub(super) const AARCH64_SVE_LOOP_FIRST_CONSTANT: u8 = 24;
const AARCH64_SVE_LOOP_LAST_CONSTANT: u8 = 27;

fn aarch64_sve_loop_constant(index: usize) -> Result<u8, ObjectError> {
    AARCH64_SVE_LOOP_FIRST_CONSTANT
        .checked_add(
            u8::try_from(index)
                .map_err(|_| ObjectError::ArithmeticOverflow("SVE loop-skip constant"))?,
        )
        .filter(|&register| register <= AARCH64_SVE_LOOP_LAST_CONSTANT)
        .ok_or(ObjectError::InvalidModule(
            "SVE loop-skip constant escaped Z24..Z27",
        ))
}

/// Establish loop-local scalable constants without disturbing Z16..Z23.
///
/// Pure-SVE roots deliberately retain their graph-filter constants in
/// Z16..Z23 across retries. Keeping this independent loop proof in Z24..Z27
/// means an interior-loop exit needs no root-constant restoration. SVE2 uses
/// the same first scratch register for its target-installed MATCH table.
fn aarch64_emit_sve_loop_setup(
    assembler: &mut Aarch64Assembler,
    filter: NativeStartFilter,
    kind: Aarch64SveFilterKind,
) -> Result<(), ObjectError> {
    if filter.scan_offset != 0 || filter.ranges().is_empty() {
        return Err(ObjectError::InvalidModule("invalid SVE loop-skip filter"));
    }
    match kind {
        Aarch64SveFilterKind::Sve => {
            let required = filter.constant_count();
            if required > usize::from(MAX_DFA_LOOP_VECTOR_CONSTANTS) {
                return Err(ObjectError::InvalidModule("SVE loop-skip constant budget"));
            }
            for (index, range) in filter.ranges().iter().enumerate() {
                if filter.is_exact() {
                    let register = aarch64_sve_loop_constant(index)?;
                    assembler.instruction(aarch64_sve_dup_b_imm(register, range.start)?)?;
                } else {
                    let low_index = index.checked_mul(2).ok_or(ObjectError::ArithmeticOverflow(
                        "SVE loop-skip low constant",
                    ))?;
                    let high_index =
                        low_index
                            .checked_add(1)
                            .ok_or(ObjectError::ArithmeticOverflow(
                                "SVE loop-skip high constant",
                            ))?;
                    let low = aarch64_sve_loop_constant(low_index)?;
                    let high = aarch64_sve_loop_constant(high_index)?;
                    assembler.instruction(aarch64_sve_dup_b_imm(low, range.start)?)?;
                    assembler.instruction(aarch64_sve_dup_b_imm(high, range.end)?)?;
                }
            }
        }
        Aarch64SveFilterKind::Sve2 { match_table_offset } => {
            if !filter.is_exact() || filter.ranges().len() > 16 {
                return Err(ObjectError::InvalidModule(
                    "invalid SVE2 loop-skip MATCH filter",
                ));
            }
            // LD1RQB is governed by P0, which the entry gate established for
            // every byte lane before this one-time setup.
            aarch64_set_table_address(assembler, 12, match_table_offset)?;
            assembler.instruction(aarch64_sve_ld1rqb(AARCH64_SVE_LOOP_FIRST_CONSTANT, 12)?)?;
        }
    }
    Ok(())
}

fn aarch64_emit_sve_loop_candidates(
    assembler: &mut Aarch64Assembler,
    filter: NativeStartFilter,
    kind: Aarch64SveFilterKind,
) -> Result<(), ObjectError> {
    match kind {
        Aarch64SveFilterKind::Sve2 { .. } => assembler
            .instruction(aarch64_sve2_match_b(1, 0, AARCH64_SVE_LOOP_FIRST_CONSTANT)?)
            .map(|_| ()),
        Aarch64SveFilterKind::Sve if filter.is_exact() => {
            for (index, _) in filter.ranges().iter().enumerate() {
                let constant = aarch64_sve_loop_constant(index)?;
                let comparison = if index == 0 { 1 } else { 2 };
                assembler.instruction(aarch64_sve_cmpeq_b(comparison, 0, constant)?)?;
                if index != 0 {
                    assembler.instruction(aarch64_sve_orr_b(1, 1, 2)?)?;
                }
            }
            Ok(())
        }
        Aarch64SveFilterKind::Sve => {
            for (index, _) in filter.ranges().iter().enumerate() {
                let low_index = index.checked_mul(2).ok_or(ObjectError::ArithmeticOverflow(
                    "SVE loop-skip candidate low",
                ))?;
                let high_index =
                    low_index
                        .checked_add(1)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "SVE loop-skip candidate high",
                        ))?;
                let low = aarch64_sve_loop_constant(low_index)?;
                let high = aarch64_sve_loop_constant(high_index)?;
                let comparison = if index == 0 { 1 } else { 2 };
                assembler.instruction(aarch64_sve_cmphs_b(comparison, 0, low)?)?;
                // CMPLS(data, high) is the CMPHS(high, data) alias.
                assembler.instruction(aarch64_sve_cmphs_b(3, high, 0)?)?;
                assembler.instruction(aarch64_sve_and_b(comparison, comparison, 3)?)?;
                if index != 0 {
                    assembler.instruction(aarch64_sve_orr_b(1, 1, 2)?)?;
                }
            }
            Ok(())
        }
    }
}

/// Emit a vector-length-agnostic loop skipper over completed partial rows.
///
/// Full vectors use P0=all lanes. After at least one profitable full-vector
/// probe, a final predicated tail uses WHILELO and cannot read beyond the
/// authenticated window. BRKB+INCP selects the exact first exit lane without
/// assuming any process vector length.
fn aarch64_emit_sve_dfa_loop_skip(
    assembler: &mut Aarch64Assembler,
    plan: NativeDfaLoopSkip,
    kind: Aarch64SveFilterKind,
    retained_vector_length: Option<u8>,
    ordinary: Aarch64Label,
    exhausted: Aarch64Label,
) -> Result<(), ObjectError> {
    let vector = assembler.label()?;
    let partial = assembler.label()?;
    let hit = assembler.label()?;

    assembler.instruction(aarch64_sve_ptrue_b())?;
    let vector_length = if let Some(vector_length) = retained_vector_length {
        vector_length
    } else {
        assembler.instruction(aarch64_sve_cntb(6)?)?;
        6
    };
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    // Version only when at least two runtime vectors remain. This is the
    // scalable analogue of the existing SSE/AVX/ASIMD entry gate.
    assembler.instruction(aarch64_cmp_x_lsl(12, vector_length, 1)?)?;
    assembler.branch_cond(AARCH64_LO, ordinary)?;
    aarch64_emit_sve_loop_setup(assembler, plan.filter, kind)?;

    assembler.bind(vector)?;
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    assembler.instruction(aarch64_cmp_x(12, vector_length)?)?;
    assembler.branch_cond(AARCH64_LO, partial)?;
    aarch64_emit_start_filter_address(assembler, 0)?;
    assembler.instruction(aarch64_sve_ld1b_vl(0, 12, 0)?)?;
    aarch64_emit_sve_loop_candidates(assembler, plan.filter, kind)?;
    assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
    assembler.branch_cond(AARCH64_NE, hit)?;
    assembler.instruction(aarch64_sve_addvl(2, 2, 1)?)?;
    if plan.accepting {
        assembler.instruction(aarch64_mov_x(7, 2)?)?;
    }
    assembler.branch(vector)?;

    assembler.bind(partial)?;
    assembler.instruction(aarch64_sve_whilelo_b(0, 2, 3)?)?;
    aarch64_emit_start_filter_address(assembler, 0)?;
    assembler.instruction(aarch64_sve_ld1b_vl(0, 12, 0)?)?;
    aarch64_emit_sve_loop_candidates(assembler, plan.filter, kind)?;
    assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
    assembler.branch_cond(AARCH64_NE, hit)?;
    assembler.instruction(aarch64_mov_x(2, 3)?)?;
    if plan.accepting {
        assembler.instruction(aarch64_mov_x(7, 3)?)?;
    }
    assembler.branch(exhausted)?;

    assembler.bind(hit)?;
    if plan.accepting {
        assembler.instruction(aarch64_mov_x(12, 2)?)?;
    }
    assembler.instruction(aarch64_sve_brkb_p0(2, 1)?)?;
    assembler.instruction(aarch64_sve_incp_b(2, 2)?)?;
    if plan.accepting {
        // Lane zero skips no accepting byte. Otherwise the exit position is
        // exactly the end of the final skipped accepting transition.
        assembler.instruction(aarch64_cmp_x(2, 12)?)?;
        assembler.instruction(aarch64_csel_x(7, 7, 2, AARCH64_EQ)?)?;
    }
    assembler.branch(ordinary)?;
    Ok(())
}

/// Emit one guarded `AArch64` loop skipper. A mixed Linux target dispatches a
/// retained VL16 to the ASIMD four-vector path when its graph filter admits
/// that batch; wider vector lengths use SVE/SVE2. Pure capability tiers retain
/// their established scalable, fixed-width, or scalar path unchanged.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the loop-skip proof, vector batches, scalar tail, and exits form one auditable CFG"
)]
pub(super) fn aarch64_emit_dfa_loop_skip(
    assembler: &mut Aarch64Assembler,
    plan: NativeDfaLoopSkip,
    layout: &NativeDfaLayout,
    vector_filter: Option<NativeVectorFilter>,
    sve_kind: Option<Aarch64SveFilterKind>,
    use_asimd: bool,
    mixed_vector_registers: Option<(u8, u8)>,
    use_exact_asimd_lane: bool,
    exact_sve_kind: Option<Aarch64ExactSveKind>,
    ordinary: Aarch64Label,
    exhausted: Aarch64Label,
) -> Result<(), ObjectError> {
    aarch64_set_table_address(assembler, 12, plan.row_offset)?;
    assembler.instruction(aarch64_cmp_x(11, 12)?)?;
    assembler.branch_cond(AARCH64_NE, ordinary)?;
    if let Some(kind) = sve_kind {
        if let Some((vector_length, wide_mode)) = mixed_vector_registers {
            if !use_asimd {
                return Err(ObjectError::InvalidModule(
                    "mixed SVE loop dispatch has no ASIMD arm",
                ));
            }
            let asimd = assembler.label()?;
            // The direct-DFA entry sampled the process VL once, after every
            // optional prepass. A zero mode is exactly architectural VL16;
            // wider processes retain their byte count for the SVE arm.
            assembler.branch_zero_w(wide_mode, asimd)?;
            aarch64_emit_sve_dfa_loop_skip(
                assembler,
                plan,
                kind,
                Some(vector_length),
                ordinary,
                exhausted,
            )?;
            assembler.bind(asimd)?;
        } else {
            return aarch64_emit_sve_dfa_loop_skip(
                assembler,
                plan,
                kind,
                None,
                ordinary,
                exhausted,
            );
        }
    } else if mixed_vector_registers.is_some() {
        return Err(ObjectError::InvalidModule(
            "mixed loop dispatch has no SVE arm",
        ));
    }
    let vector = assembler.label()?;
    let single_vector = assembler.label()?;
    let batch_hit = assembler.label()?;
    let single_hit = assembler.label()?;
    let selected_exit = assembler.label()?;
    let scalar = assembler.label()?;
    let exit = assembler.label()?;

    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    let minimum_remaining = if use_asimd { 32 } else { 8 };
    assembler.instruction(aarch64_cmp_x_imm(12, minimum_remaining)?)?;
    assembler.branch_cond(AARCH64_LO, ordinary)?;

    if use_asimd {
        let first_register = if plan.filter.is_exact() { 1 } else { 16 };
        let mut batch_first_candidates = None;
        aarch64_emit_start_filter_constants(assembler, plan.filter, first_register)?;
        assembler.bind(vector)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        if aarch64_uses_asimd_batch(plan) {
            assembler.instruction(aarch64_cmp_x_imm(12, 64)?)?;
            assembler.branch_cond(AARCH64_LO, single_vector)?;
            let first_candidates =
                aarch64_emit_start_filter_batch_candidates(assembler, plan.filter, first_register)?;
            batch_first_candidates = Some(first_candidates);
            assembler.instruction(aarch64_orr_16b(28, first_candidates, first_candidates)?)?;
            for lane in 1_u8..4 {
                let candidates =
                    first_candidates
                        .checked_add(lane)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "AArch64 loop-skip batch candidates",
                        ))?;
                assembler.instruction(aarch64_orr_16b(28, 28, candidates)?)?;
            }
            aarch64_emit_candidate_any(assembler, 28)?;
            assembler.branch_cond(
                AARCH64_NE,
                if use_exact_asimd_lane {
                    batch_hit
                } else {
                    scalar
                },
            )?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 64)?)?;
            if plan.accepting {
                assembler.instruction(aarch64_mov_x(7, 2)?)?;
            }
            assembler.branch(vector)?;
        }
        assembler.bind(single_vector)?;
        assembler.instruction(aarch64_cmp_x_imm(12, 16)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(assembler, 0)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        aarch64_emit_start_filter_vector_candidates(assembler, plan.filter, 0, 24, first_register)?;
        aarch64_emit_candidate_any(assembler, 24)?;
        assembler.branch_cond(
            AARCH64_NE,
            if use_exact_asimd_lane {
                single_hit
            } else {
                scalar
            },
        )?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        if plan.accepting {
            assembler.instruction(aarch64_mov_x(7, 2)?)?;
        }
        assembler.branch(vector)?;

        assembler.bind(batch_hit)?;
        if use_exact_asimd_lane && let Some(first_candidates) = batch_first_candidates {
            aarch64_emit_first_candidate_in_batch(assembler, first_candidates)?;
            assembler.branch(selected_exit)?;
        } else {
            assembler.branch(scalar)?;
        }
        assembler.bind(single_hit)?;
        if use_exact_asimd_lane {
            aarch64_emit_first_candidate_lane(assembler, 24)?;
            assembler.branch(selected_exit)?;
        } else {
            assembler.branch(scalar)?;
        }
        assembler.bind(selected_exit)?;
        if use_exact_asimd_lane && plan.accepting {
            // A lane-zero exit skips no accepting transition. Preserve the
            // prior pending end in that case; otherwise the selected exit's
            // address is the end of the final skipped accepting transition.
            assembler.instruction(aarch64_cmp_w_zero(12)?)?;
            assembler.instruction(aarch64_csel_x(7, 7, 2, AARCH64_EQ)?)?;
        }
        assembler.branch(exit)?;
    } else {
        // Keep every label bound for the assembler's control-flow audit.
        assembler.bind(vector)?;
        assembler.bind(single_vector)?;
        assembler.branch(scalar)?;
        assembler.bind(batch_hit)?;
        assembler.branch(scalar)?;
        assembler.bind(single_hit)?;
        assembler.branch(scalar)?;
        assembler.bind(selected_exit)?;
        assembler.branch(scalar)?;
    }

    assembler.bind(scalar)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, exhausted)?;
    aarch64_emit_start_filter_scalar_load(assembler, 0)?;
    for range in plan.filter.ranges() {
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.start))?)?;
        if range.start == range.end {
            assembler.branch_cond(AARCH64_EQ, exit)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch_cond(AARCH64_LO, next_range)?;
            assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.end))?)?;
            assembler.branch_cond(AARCH64_LS, exit)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    if plan.accepting {
        assembler.instruction(aarch64_mov_x(7, 2)?)?;
    }
    assembler.branch(scalar)?;

    assembler.bind(exit)?;
    if use_asimd {
        aarch64_restore_start_constants(
            assembler,
            layout,
            vector_filter,
            if mixed_vector_registers.is_some() {
                // VL16 always returns to the fixed-width root arm. Exact SVE
                // constants would merely be overwritten by its ASIMD reload.
                None
            } else {
                exact_sve_kind
            },
        )?;
    }
    assembler.branch(ordinary)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AARCH64_ASIMD_LOOP_BATCH_MAX_EXIT_BYTES;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExitKind {
        CompletedRow,
        PartialHole,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LoopOutcome {
        position: usize,
        pending_end: Option<usize>,
        exhausted: bool,
        exit_kind: ExitKind,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MixedLoopRoute {
        Asimd,
        Sve,
    }

    const fn mixed_loop_route(vector_length: usize, exit_bytes: u16) -> MixedLoopRoute {
        if vector_length == 16 && exit_bytes <= AARCH64_ASIMD_LOOP_BATCH_MAX_EXIT_BYTES {
            MixedLoopRoute::Asimd
        } else {
            MixedLoopRoute::Sve
        }
    }

    fn scalar_outcome(
        length: usize,
        exit_at: usize,
        accepting: bool,
        old_pending: Option<usize>,
        exit_kind: ExitKind,
    ) -> LoopOutcome {
        let position = exit_at.min(length);
        LoopOutcome {
            position,
            pending_end: if accepting && position != 0 {
                Some(position)
            } else {
                old_pending
            },
            exhausted: exit_at >= length,
            exit_kind,
        }
    }

    fn scalable_outcome(
        length: usize,
        exit_at: usize,
        vector_length: usize,
        accepting: bool,
        old_pending: Option<usize>,
        exit_kind: ExitKind,
    ) -> Option<LoopOutcome> {
        if length < vector_length.checked_mul(2)? {
            return None;
        }
        let mut position = 0_usize;
        let mut pending_end = old_pending;
        while length.checked_sub(position)? >= vector_length {
            let block_end = position.checked_add(vector_length)?;
            if (position..block_end).contains(&exit_at) {
                let skipped = exit_at.checked_sub(position)?;
                if accepting && skipped != 0 {
                    pending_end = Some(exit_at);
                }
                return Some(LoopOutcome {
                    position: exit_at,
                    pending_end,
                    exhausted: false,
                    exit_kind,
                });
            }
            position = block_end;
            if accepting {
                pending_end = Some(position);
            }
        }

        if (position..length).contains(&exit_at) {
            let skipped = exit_at.checked_sub(position)?;
            if accepting && skipped != 0 {
                pending_end = Some(exit_at);
            }
            Some(LoopOutcome {
                position: exit_at,
                pending_end,
                exhausted: false,
                exit_kind,
            })
        } else {
            if accepting && position != length {
                pending_end = Some(length);
            }
            Some(LoopOutcome {
                position: length,
                pending_end,
                exhausted: true,
                exit_kind,
            })
        }
    }

    #[test]
    fn scalable_loop_model_exhausts_vls_tails_holes_and_acceptance() {
        for vector_length in (16_usize..=256).step_by(16) {
            for length in 0..vector_length * 2 {
                assert!(
                    scalable_outcome(
                        length,
                        length,
                        vector_length,
                        false,
                        Some(7),
                        ExitKind::CompletedRow,
                    )
                    .is_none(),
                    "VL={vector_length}, length={length}"
                );
            }
            // Every possible final predicate population is represented by
            // one length in [2*VL, 3*VL], including an empty tail. Every
            // possible first exit before or at that end is then checked.
            for length in vector_length * 2..=vector_length * 3 {
                for exit_at in 0..=length {
                    for accepting in [false, true] {
                        for exit_kind in [ExitKind::CompletedRow, ExitKind::PartialHole] {
                            let expected =
                                scalar_outcome(length, exit_at, accepting, Some(7), exit_kind);
                            let actual = scalable_outcome(
                                length,
                                exit_at,
                                vector_length,
                                accepting,
                                Some(7),
                                exit_kind,
                            )
                            .expect("two-vector entry gate");
                            assert_eq!(
                                actual, expected,
                                "VL={vector_length}, length={length}, exit={exit_at}, accepting={accepting}, kind={exit_kind:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn mixed_loop_route_model_pins_vl_and_batch_boundaries() {
        for vector_length in (16_usize..=256).step_by(16) {
            for exit_bytes in 1_u16..=64 {
                assert_eq!(
                    mixed_loop_route(vector_length, exit_bytes),
                    if vector_length == 16 && exit_bytes <= 4 {
                        MixedLoopRoute::Asimd
                    } else {
                        MixedLoopRoute::Sve
                    },
                    "VL={vector_length}, exit bytes={exit_bytes}"
                );
            }
        }
        assert_eq!(mixed_loop_route(16, 4), MixedLoopRoute::Asimd);
        assert_eq!(mixed_loop_route(16, 5), MixedLoopRoute::Sve);
        assert_eq!(mixed_loop_route(32, 4), MixedLoopRoute::Sve);
    }
}
