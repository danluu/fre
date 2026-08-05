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
    Aarch64ExactSveKind, Aarch64Label, EMPTY_NATIVE_START_FILTER, NativeDfaLayout,
    NativeStartFilter, NativeVectorFilter, ObjectError, X86Assembler, X86CandidateMask, X86Label,
    X86StartFilterKind, aarch64_add_x_imm, aarch64_cmp_w_imm, aarch64_cmp_w_zero,
    aarch64_cmp_x, aarch64_cmp_x_imm, aarch64_csel_x, aarch64_emit_candidate_any,
    aarch64_emit_exact_sve_constants, aarch64_emit_first_candidate_in_batch,
    aarch64_emit_first_candidate_lane, aarch64_emit_start_filter_address,
    aarch64_emit_start_filter_batch_candidates, aarch64_emit_start_filter_constants,
    aarch64_emit_start_filter_scalar_load, aarch64_emit_start_filter_vector_candidates,
    aarch64_load_q, aarch64_mov_x, aarch64_orr_16b, aarch64_set_table_address, aarch64_sub_x_reg,
    x86_emit_first_candidate_lane, x86_emit_start_filter_constants,
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
    /// Table-relative byte address of the semantic state's forward row.
    pub(super) row_offset: u32,
}

/// Select and address one interior loop after the transition row size is
/// known. A malformed or unprofitable analysis conservatively emits no plan.
pub(super) fn derive_native_dfa_loop_skip(
    dfa: &NativeDfaView<'_>,
    output: OutputContract,
    forward_offset: usize,
    row_bytes: usize,
) -> Result<Option<NativeDfaLoopSkip>, ObjectError> {
    let Some(plan) = select_dfa_loop_skip(dfa, output) else {
        return Ok(None);
    };
    let state = usize::try_from(plan.state)
        .map_err(|_| ObjectError::ArithmeticOverflow("native loop-skip state"))?;
    let row_offset = state
        .checked_mul(row_bytes)
        .and_then(|offset| offset.checked_add(forward_offset))
        .and_then(|offset| u32::try_from(offset).ok())
        .ok_or(ObjectError::ArithmeticOverflow(
            "native loop-skip row offset",
        ))?;
    Ok(Some(NativeDfaLoopSkip {
        filter: native_filter(plan)?,
        accepting: plan.accepting,
        state: plan.state,
        row_offset,
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

/// Emit one guarded `AArch64` loop skipper. ASIMD is used when selected by the
/// explicit target feature set; the same graph proof still enables a compact
/// scalar byte loop otherwise.
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
    use_asimd: bool,
    use_exact_asimd_lane: bool,
    exact_sve_kind: Option<Aarch64ExactSveKind>,
    ordinary: Aarch64Label,
    exhausted: Aarch64Label,
) -> Result<(), ObjectError> {
    let vector = assembler.label()?;
    let single_vector = assembler.label()?;
    let batch_hit = assembler.label()?;
    let single_hit = assembler.label()?;
    let selected_exit = assembler.label()?;
    let scalar = assembler.label()?;
    let exit = assembler.label()?;

    aarch64_set_table_address(assembler, 12, plan.row_offset)?;
    assembler.instruction(aarch64_cmp_x(11, 12)?)?;
    assembler.branch_cond(AARCH64_NE, ordinary)?;
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
        if plan.filter.candidate_bytes <= 4 {
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
            exact_sve_kind,
        )?;
    }
    assembler.branch(ordinary)?;
    Ok(())
}
