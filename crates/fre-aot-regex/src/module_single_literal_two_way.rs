//! Call-free Two-Way lowering for one authenticated exact literal.
//!
//! A source-authenticated literal wider than the incumbent short-literal
//! portfolio is factored once at compile time. The emitted Crochemore-Perrin
//! search retains constant runtime space and a worst-case linear bound for
//! periodic and non-periodic inputs. The initial 33..=4096-byte envelope is a
//! bounded target-finalization cost policy, not a semantic algorithm limit.

#[allow(
    clippy::wildcard_imports,
    reason = "this private module deliberately shares its parent's checked assembler vocabulary"
)]
use super::*;
use crate::finite_language::{NativeFiniteExistsChoiceKind, NativeFiniteExistsChoiceView};

pub(super) const MIN_TWO_WAY_LITERAL_BYTES: usize = 33;
pub(super) const MAX_TWO_WAY_LITERAL_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TwoWayShift {
    SmallPeriod { period: u32 },
    Large { shift: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TwoWayPlan {
    literal_len: u32,
    critical_position: u32,
    shift: TwoWayShift,
    approximate_byteset: u64,
}

#[derive(Clone, Copy)]
enum SuffixKind {
    Minimal,
    Maximal,
}

#[derive(Clone, Copy, Debug)]
struct Suffix {
    position: usize,
    period: usize,
}

impl Suffix {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the planner admits at most 4096 bytes and maintains candidate and offset indices strictly inside the literal"
    )]
    fn forward(needle: &[u8], kind: SuffixKind) -> Self {
        let mut suffix = Self {
            position: 0,
            period: 1,
        };
        let mut candidate_start = 1_usize;
        let mut offset = 0_usize;
        while candidate_start + offset < needle.len() {
            let current = needle[suffix.position + offset];
            let candidate = needle[candidate_start + offset];
            let accept = match kind {
                SuffixKind::Minimal => candidate < current,
                SuffixKind::Maximal => candidate > current,
            };
            let skip = match kind {
                SuffixKind::Minimal => candidate > current,
                SuffixKind::Maximal => candidate < current,
            };
            if accept {
                suffix = Self {
                    position: candidate_start,
                    period: 1,
                };
                candidate_start += 1;
                offset = 0;
            } else if skip {
                candidate_start += offset + 1;
                offset = 0;
                suffix.period = candidate_start - suffix.position;
            } else if offset + 1 == suffix.period {
                candidate_start += suffix.period;
                offset = 0;
            } else {
                offset += 1;
            }
        }
        suffix
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the preceding length comparison proves the suffix subtraction cannot underflow"
)]
fn slice_ends_with(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack[haystack.len() - needle.len()..] == *needle
}

fn derive_two_way_plan(literal: &[u8]) -> Option<TwoWayPlan> {
    if !(MIN_TWO_WAY_LITERAL_BYTES..=MAX_TWO_WAY_LITERAL_BYTES).contains(&literal.len()) {
        return None;
    }
    let minimum = Suffix::forward(literal, SuffixKind::Minimal);
    let maximum = Suffix::forward(literal, SuffixKind::Maximal);
    let selected = if minimum.position > maximum.position {
        minimum
    } else {
        maximum
    };
    let critical = selected.position;
    let large_shift = critical.max(literal.len().checked_sub(critical)?);
    let shift = if critical.checked_mul(2)? < literal.len() {
        let (left, right) = literal.split_at(critical);
        let period_prefix = right.get(..selected.period)?;
        if slice_ends_with(period_prefix, left) {
            TwoWayShift::SmallPeriod {
                period: u32::try_from(selected.period).ok()?,
            }
        } else {
            TwoWayShift::Large {
                shift: u32::try_from(large_shift).ok()?,
            }
        }
    } else {
        TwoWayShift::Large {
            shift: u32::try_from(large_shift).ok()?,
        }
    };
    let approximate_byteset = literal
        .iter()
        .fold(0_u64, |bits, &byte| bits | (1_u64 << (byte % 64)));
    Some(TwoWayPlan {
        literal_len: u32::try_from(literal.len()).ok()?,
        critical_position: u32::try_from(critical).ok()?,
        shift,
        approximate_byteset,
    })
}

fn report_shift(plan: TwoWayPlan) -> Option<ExactSingleLiteralTwoWayShift> {
    match plan.shift {
        TwoWayShift::SmallPeriod { period } => Some(ExactSingleLiteralTwoWayShift::SmallPeriod {
            period: usize::try_from(period).ok()?,
        }),
        TwoWayShift::Large { shift } => Some(ExactSingleLiteralTwoWayShift::Large {
            shift: usize::try_from(shift).ok()?,
        }),
    }
}

fn relocation_digest(relocations: &[ModuleRelocation]) -> Option<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(u64::try_from(relocations.len()).ok()?.to_le_bytes());
    for relocation in relocations {
        digest.update(u64::try_from(relocation.section).ok()?.to_le_bytes());
        digest.update(relocation.offset.to_le_bytes());
        let kind = match relocation.kind {
            RelocationKind::X86PcRelative32 => 0_u8,
            RelocationKind::X86PltRelative32 => 1,
            RelocationKind::Aarch64Page21 => 2,
            RelocationKind::Aarch64PageOff12 => 3,
            RelocationKind::Aarch64Branch26 => 4,
        };
        digest.update([kind]);
        digest.update(u64::try_from(relocation.symbol).ok()?.to_le_bytes());
        digest.update(relocation.addend.to_le_bytes());
    }
    Some(digest.finalize().into())
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the fresh source-authenticated Choice is a frozen Copy planning receipt consumed once during target finalization"
)]
pub(super) fn lower_optional_exact_single_literal_two_way(
    choice: NativeFiniteExistsChoiceView<'_>,
    target: Target,
    max_native_data_bytes: usize,
) -> Result<Option<(NativeLowering, ExactSingleLiteralAotReport)>, ObjectError> {
    target.validate()?;
    if choice.kind() != NativeFiniteExistsChoiceKind::SingleLiteral {
        return Ok(None);
    }
    let [literal] = choice.literals() else {
        return Err(ObjectError::InvalidModule(
            "single-literal Choice does not own exactly one literal",
        ));
    };
    if choice.minimum_width() != choice.maximum_width()
        || usize::try_from(choice.minimum_width()).ok() != Some(literal.len())
        || choice.total_source_bytes() != literal.len()
    {
        return Err(ObjectError::InvalidModule(
            "single-literal Choice dimensions are inconsistent",
        ));
    }
    let Some(plan) = derive_two_way_plan(literal) else {
        return Ok(None);
    };
    if literal.len() > max_native_data_bytes {
        return Ok(None);
    }
    let mut data = Vec::new();
    data.try_reserve_exact(literal.len())
        .map_err(|_| ObjectError::Allocation("exact single-literal data"))?;
    data.extend_from_slice(literal);
    let (code, relocations, emitted_isa) = match target.architecture {
        Architecture::X86_64 => {
            let (code, relocations) = lower_x86_64_two_way(plan)?;
            (code, relocations, ExactSingleLiteralAotIsa::X86Scalar)
        }
        Architecture::Aarch64 => {
            let (code, relocations) = lower_aarch64_two_way(plan)?;
            (code, relocations, ExactSingleLiteralAotIsa::Aarch64Scalar)
        }
    };
    let report = ExactSingleLiteralAotReport {
        literal_sha256: Sha256::digest(literal).into(),
        native_code_sha256: Sha256::digest(&code).into(),
        relocations_sha256: relocation_digest(&relocations).ok_or(
            ObjectError::ArithmeticOverflow("Two-Way relocation receipt"),
        )?,
        literal_bytes: literal.len(),
        critical_position: usize::try_from(plan.critical_position)
            .map_err(|_| ObjectError::ArithmeticOverflow("Two-Way critical position"))?,
        shift: report_shift(plan).ok_or(ObjectError::ArithmeticOverflow("Two-Way shift"))?,
        approximate_last_byte_membership: plan.approximate_byteset,
        emitted_isa,
        scanner: StartAccelerator::Scalar,
        native_data_bytes: data.len(),
    };
    Ok(Some((
        NativeLowering {
            code,
            data,
            relocations,
            slow_partial_table: None,
            needs_runtime: false,
            start_accelerator: StartAccelerator::Scalar,
            anchored_prefix_filter_bytes: 0,
        },
        report,
    )))
}

fn relocations_match_target(lowering: &NativeLowering, target: Target) -> bool {
    match target.architecture {
        Architecture::X86_64 => {
            let [relocation] = lowering.relocations.as_slice() else {
                return false;
            };
            relocation.section == TEXT_SECTION
                && relocation.kind == RelocationKind::X86PcRelative32
                && relocation.symbol == PROGRAM_SYMBOL
                && relocation.addend == -4
                && usize::try_from(relocation.offset)
                    .ok()
                    .and_then(|offset| offset.checked_add(4))
                    .is_some_and(|end| end <= lowering.code.len())
        }
        Architecture::Aarch64 => {
            let [page, page_offset] = lowering.relocations.as_slice() else {
                return false;
            };
            let valid = |relocation: &ModuleRelocation, kind| {
                relocation.section == TEXT_SECTION
                    && relocation.kind == kind
                    && relocation.symbol == PROGRAM_SYMBOL
                    && relocation.addend == 0
                    && usize::try_from(relocation.offset)
                        .ok()
                        .is_some_and(|offset| {
                            offset.is_multiple_of(4)
                                && offset
                                    .checked_add(4)
                                    .is_some_and(|end| end <= lowering.code.len())
                        })
            };
            valid(page, RelocationKind::Aarch64Page21)
                && valid(page_offset, RelocationKind::Aarch64PageOff12)
                && page.offset != page_offset.offset
        }
    }
}

pub(super) fn report_matches_lowering(
    report: &ExactSingleLiteralAotReport,
    lowering: &NativeLowering,
    target: Target,
) -> bool {
    let Some(plan) = derive_two_way_plan(&lowering.data) else {
        return false;
    };
    let Some(shift) = report_shift(plan) else {
        return false;
    };
    let target_matches = matches!(
        (target.architecture, report.emitted_isa),
        (Architecture::X86_64, ExactSingleLiteralAotIsa::X86Scalar)
            | (
                Architecture::Aarch64,
                ExactSingleLiteralAotIsa::Aarch64Scalar
            )
    );
    let literal_sha256: [u8; 32] = Sha256::digest(&lowering.data).into();
    let native_code_sha256: [u8; 32] = Sha256::digest(&lowering.code).into();
    target_matches
        && report.literal_sha256 == literal_sha256
        && report.native_code_sha256 == native_code_sha256
        && relocation_digest(&lowering.relocations)
            .is_some_and(|digest| report.relocations_sha256 == digest)
        && report.literal_bytes == lowering.data.len()
        && report.critical_position == usize::try_from(plan.critical_position).unwrap_or(usize::MAX)
        && report.shift == shift
        && report.approximate_last_byte_membership == plan.approximate_byteset
        && report.scanner == StartAccelerator::Scalar
        && report.native_data_bytes == lowering.data.len()
        && !lowering.code.is_empty()
        && lowering.start_accelerator == StartAccelerator::Scalar
        && lowering.anchored_prefix_filter_bytes == 0
        && !lowering.needs_runtime
        && lowering.slow_partial_table.is_none()
        && relocations_match_target(lowering, target)
}

fn x86_mov_r32_imm(
    assembler: &mut X86Assembler,
    register_opcode: u8,
    value: u32,
) -> Result<(), ObjectError> {
    let mut instruction = vec![0x41, register_opcode];
    instruction.extend_from_slice(&value.to_le_bytes());
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_add_rdx_imm(assembler: &mut X86Assembler, value: u32) -> Result<(), ObjectError> {
    let mut instruction = vec![0x48, 0x81, 0xc2];
    instruction.extend_from_slice(&value.to_le_bytes());
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_two_way_byte_compare(assembler: &mut X86Assembler) -> Result<(), ObjectError> {
    assembler.instruction(&[0x45, 0x0f, 0xb6, 0x14, 0x01])?;
    assembler.instruction(&[0x44, 0x3a, 0x14, 0x02])?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete call-free Two-Way control-flow graph is kept in one auditable checked-assembler transaction"
)]
fn lower_x86_64_two_way(plan: TwoWayPlan) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let width = plan.literal_len;
    let critical = plan.critical_position;
    let last = width
        .checked_sub(1)
        .ok_or(ObjectError::InvalidModule("Two-Way literal width is zero"))?;
    let mut assembler = X86Assembler::new();
    let search = assembler.label()?;
    let byteset_skip = assembler.label()?;
    let right = assembler.label()?;
    let right_complete = assembler.label()?;
    let right_mismatch = assembler.label()?;
    let left = assembler.label()?;
    let left_mismatch = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;

    x86_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;
    assembler.instruction(&[0x4c, 0x8d, 0x0d])?;
    let program_displacement = assembler.label()?;
    assembler.bind(program_displacement)?;
    push_bytes(&mut assembler.code, &[0; 4])?;
    assembler.instruction(&[0x48, 0x01, 0xfa])?;
    assembler.instruction(&[0x48, 0x01, 0xf9])?;
    x86_mov_r32_imm(&mut assembler, 0xb8, last)?;
    let mut byteset = vec![0x49, 0xbb];
    byteset.extend_from_slice(&plan.approximate_byteset.to_le_bytes());
    assembler.instruction(&byteset)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(&[0x31, 0xf6])?;
    }

    assembler.bind(search)?;
    assembler.instruction(&[0x49, 0x89, 0xca])?;
    assembler.instruction(&[0x49, 0x29, 0xd2])?;
    let mut compare_width = vec![0x49, 0x81, 0xfa];
    compare_width.extend_from_slice(&width.to_le_bytes());
    assembler.instruction(&compare_width)?;
    assembler.branch(&[0x0f, 0x82], no_match)?;
    assembler.instruction(&[0x42, 0x0f, 0xb6, 0x04, 0x02])?;
    assembler.instruction(&[0x83, 0xe0, 0x3f])?;
    assembler.instruction(&[0x49, 0x0f, 0xa3, 0xc3])?;
    assembler.branch(&[0x0f, 0x83], byteset_skip)?;

    let mut load_critical = vec![0xb8];
    load_critical.extend_from_slice(&critical.to_le_bytes());
    assembler.instruction(&load_critical)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(&[0x48, 0x39, 0xf0])?;
        assembler.instruction(&[0x48, 0x0f, 0x42, 0xc6])?;
    }
    assembler.bind(right)?;
    let mut compare_i_width = vec![0x48, 0x3d];
    compare_i_width.extend_from_slice(&width.to_le_bytes());
    assembler.instruction(&compare_i_width)?;
    assembler.branch(&[0x0f, 0x83], right_complete)?;
    x86_emit_two_way_byte_compare(&mut assembler)?;
    assembler.branch(&[0x0f, 0x85], right_mismatch)?;
    assembler.instruction(&[0x48, 0xff, 0xc0])?;
    assembler.branch(&[0xe9], right)?;

    assembler.bind(right_mismatch)?;
    let mut subtract_critical = vec![0x48, 0x2d];
    subtract_critical.extend_from_slice(&critical.to_le_bytes());
    assembler.instruction(&subtract_critical)?;
    assembler.instruction(&[0x48, 0x8d, 0x54, 0x02, 0x01])?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(&[0x31, 0xf6])?;
    }
    assembler.branch(&[0xe9], search)?;

    assembler.bind(right_complete)?;
    assembler.instruction(&load_critical)?;
    assembler.bind(left)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(&[0x48, 0x39, 0xf0])?;
        assembler.branch(&[0x0f, 0x86], matched)?;
    } else {
        assembler.instruction(&[0x48, 0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x84], matched)?;
    }
    assembler.instruction(&[0x48, 0xff, 0xc8])?;
    x86_emit_two_way_byte_compare(&mut assembler)?;
    assembler.branch(&[0x0f, 0x85], left_mismatch)?;
    assembler.branch(&[0xe9], left)?;

    assembler.bind(left_mismatch)?;
    match plan.shift {
        TwoWayShift::SmallPeriod { period } => {
            x86_add_rdx_imm(&mut assembler, period)?;
            let memory = width.checked_sub(period).ok_or(ObjectError::InvalidModule(
                "Two-Way small period exceeds literal width",
            ))?;
            let mut load_memory = vec![0xbe];
            load_memory.extend_from_slice(&memory.to_le_bytes());
            assembler.instruction(&load_memory)?;
        }
        TwoWayShift::Large { shift } => x86_add_rdx_imm(&mut assembler, shift)?,
    }
    assembler.branch(&[0xe9], search)?;

    assembler.bind(byteset_skip)?;
    x86_add_rdx_imm(&mut assembler, width)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(&[0x31, 0xf6])?;
    }
    assembler.branch(&[0xe9], search)?;

    x86_finish_native_finite_exists_leaf(&mut assembler, matched, no_match, invalid, false)?;
    let finished = assembler.finish_with_label_offsets()?;
    let program_displacement = finished.label_offset(program_displacement)?;
    Ok((
        finished.code,
        vec![ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(program_displacement, "x86 Two-Way literal relocation")?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        }],
    ))
}

fn lower_aarch64_two_way(
    plan: TwoWayPlan,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let width = u64::from(plan.literal_len);
    let critical = u64::from(plan.critical_position);
    let last = width
        .checked_sub(1)
        .ok_or(ObjectError::InvalidModule("Two-Way literal width is zero"))?;
    let mut assembler = Aarch64Assembler::new();
    let search = assembler.label()?;
    let byteset_skip = assembler.label()?;
    let right = assembler.label()?;
    let right_complete = assembler.label()?;
    let right_mismatch = assembler.label()?;
    let left = assembler.label()?;
    let left_mismatch = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;

    aarch64_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    let program_relocation = aarch64_emit_native_finite_exists_program_base(&mut assembler)?;
    assembler.instruction(aarch64_add_x_reg(2, 0, 2)?)?;
    assembler.instruction(aarch64_add_x_reg(3, 0, 3)?)?;
    aarch64_load_u64_constant(&mut assembler, 6, width)?;
    aarch64_load_u64_constant(&mut assembler, 7, last)?;
    aarch64_load_u64_constant(&mut assembler, 11, plan.approximate_byteset)?;
    aarch64_load_u64_constant(&mut assembler, 14, critical)?;
    let shift = match plan.shift {
        TwoWayShift::SmallPeriod { period } => u64::from(period),
        TwoWayShift::Large { shift } => u64::from(shift),
    };
    aarch64_load_u64_constant(&mut assembler, 15, shift)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(aarch64_movz_x(13, 0, 0)?)?;
    }

    assembler.bind(search)?;
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    assembler.instruction(aarch64_cmp_x(12, 6)?)?;
    assembler.branch_cond(AARCH64_LO, no_match)?;
    assembler.instruction(aarch64_load_byte_reg(8, 2, 7)?)?;
    assembler.instruction(aarch64_and_low_x(8, 8, 63)?)?;
    assembler.instruction(aarch64_lsrv_x(10, 11, 8)?)?;
    assembler.instruction(aarch64_and_low_x(10, 10, 1)?)?;
    assembler.branch_zero_x(10, byteset_skip)?;

    assembler.instruction(aarch64_mov_x(9, 14)?)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(aarch64_cmp_x(13, 9)?)?;
        assembler.instruction(aarch64_csel_x(9, 13, 9, AARCH64_HI)?)?;
    }
    assembler.bind(right)?;
    assembler.instruction(aarch64_cmp_x(9, 6)?)?;
    assembler.branch_cond(AARCH64_HS, right_complete)?;
    assembler.instruction(aarch64_load_byte_reg(8, 2, 9)?)?;
    assembler.instruction(aarch64_load_byte_reg(10, 5, 9)?)?;
    assembler.instruction(aarch64_cmp_w(8, 10)?)?;
    assembler.branch_cond(AARCH64_NE, right_mismatch)?;
    assembler.instruction(aarch64_add_x_imm(9, 9, 1)?)?;
    assembler.branch(right)?;

    assembler.bind(right_mismatch)?;
    assembler.instruction(aarch64_sub_x_reg(9, 9, 14)?)?;
    assembler.instruction(aarch64_add_x_reg(2, 2, 9)?)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(aarch64_movz_x(13, 0, 0)?)?;
    }
    assembler.branch(search)?;

    assembler.bind(right_complete)?;
    assembler.instruction(aarch64_mov_x(9, 14)?)?;
    assembler.bind(left)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(aarch64_cmp_x(9, 13)?)?;
        assembler.branch_cond(AARCH64_LS, matched)?;
    } else {
        assembler.branch_zero_x(9, matched)?;
    }
    assembler.instruction(aarch64_sub_x_imm(9, 9, 1)?)?;
    assembler.instruction(aarch64_load_byte_reg(8, 2, 9)?)?;
    assembler.instruction(aarch64_load_byte_reg(10, 5, 9)?)?;
    assembler.instruction(aarch64_cmp_w(8, 10)?)?;
    assembler.branch_cond(AARCH64_NE, left_mismatch)?;
    assembler.branch(left)?;

    assembler.bind(left_mismatch)?;
    assembler.instruction(aarch64_add_x_reg(2, 2, 15)?)?;
    if let TwoWayShift::SmallPeriod { period } = plan.shift {
        let memory = u64::from(plan.literal_len.checked_sub(period).ok_or(
            ObjectError::InvalidModule("Two-Way small period exceeds literal width"),
        )?);
        aarch64_load_u64_constant(&mut assembler, 13, memory)?;
    }
    assembler.branch(search)?;

    assembler.bind(byteset_skip)?;
    assembler.instruction(aarch64_add_x_reg(2, 2, 6)?)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(aarch64_movz_x(13, 0, 0)?)?;
    }
    assembler.branch(search)?;

    aarch64_finish_native_finite_exists_leaf(&mut assembler, matched, no_match, invalid)?;
    aarch64_finish_native_finite_exists_with_optional_program_relocation(
        assembler,
        Some(program_relocation),
    )
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the bounded reference model uses checked loop limits and test-only in-range indices"
)]
fn two_way_find_counted(
    plan: TwoWayPlan,
    haystack: &[u8],
    needle: &[u8],
    work: &mut usize,
) -> Option<usize> {
    let width = needle.len();
    let critical = usize::try_from(plan.critical_position).ok()?;
    let mut position = 0_usize;
    match plan.shift {
        TwoWayShift::SmallPeriod { period } => {
            let period = usize::try_from(period).ok()?;
            let mut memory = 0_usize;
            while position.checked_add(width)? <= haystack.len() {
                *work += 1;
                if plan.approximate_byteset & (1_u64 << (haystack[position + width - 1] % 64)) == 0
                {
                    position += width;
                    memory = 0;
                    continue;
                }
                let mut index = critical.max(memory);
                while index < width {
                    *work += 1;
                    if needle[index] != haystack[position + index] {
                        break;
                    }
                    index += 1;
                }
                if index < width {
                    position += index - critical + 1;
                    memory = 0;
                    continue;
                }
                index = critical;
                while index > memory {
                    *work += 1;
                    if needle[index] != haystack[position + index] {
                        break;
                    }
                    index -= 1;
                }
                if index <= memory {
                    *work += 1;
                    if needle[memory] == haystack[position + memory] {
                        return Some(position);
                    }
                }
                position += period;
                memory = width - period;
            }
        }
        TwoWayShift::Large { shift } => {
            let shift = usize::try_from(shift).ok()?;
            'outer: while position.checked_add(width)? <= haystack.len() {
                *work += 1;
                if plan.approximate_byteset & (1_u64 << (haystack[position + width - 1] % 64)) == 0
                {
                    position += width;
                    continue;
                }
                let mut index = critical;
                while index < width {
                    *work += 1;
                    if needle[index] != haystack[position + index] {
                        break;
                    }
                    index += 1;
                }
                if index < width {
                    position += index - critical + 1;
                    continue;
                }
                index = critical;
                while index > 0 {
                    index -= 1;
                    *work += 1;
                    if needle[index] != haystack[position + index] {
                        position += shift;
                        continue 'outer;
                    }
                }
                return Some(position);
            }
        }
    }
    None
}

#[cfg(test)]
fn two_way_find(plan: TwoWayPlan, haystack: &[u8], needle: &[u8]) -> Option<usize> {
    two_way_find_counted(plan, haystack, needle, &mut 0)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "all fixture sizes, window indices, and generated harness status codes are small test constants"
)]
mod tests {
    use super::*;
    use crate::{
        CompileMode, CompileRequest, MatchResult, OptimizationPass, OutputContract, SearchWindow,
        compile,
    };

    fn compile_two_way(
        pattern: &str,
        target: Target,
        output: OutputContract,
    ) -> crate::CompiledRegex {
        compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(output),
        )
        .expect("compile exact single-literal Two-Way leaf")
    }

    #[test]
    fn critical_factorization_matches_naive_search_including_period_memory() {
        let periodic = b"ababababababababababababababababab";
        let mut shifted = b"bb".to_vec();
        shifted.extend_from_slice(periodic);
        let needles = [
            periodic.as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".as_slice(),
            b"the_quick_brown_fox_jumps_over_0123456789".as_slice(),
            b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzy".as_slice(),
        ];
        for needle in needles {
            let plan = derive_two_way_plan(needle).expect("derive Two-Way plan");
            let haystacks = [
                Vec::new(),
                needle.to_vec(),
                vec![needle[0]; needle.len() * 3],
                [vec![b'!'; 71], needle.to_vec(), vec![b'?'; 39]].concat(),
                shifted.clone(),
            ];
            for haystack in haystacks {
                assert_eq!(
                    two_way_find(plan, &haystack, needle),
                    haystack
                        .windows(needle.len())
                        .position(|window| window == needle),
                    "needle={needle:?} haystack_len={}",
                    haystack.len(),
                );
            }
        }
        let periodic_plan = derive_two_way_plan(periodic).expect("periodic Two-Way plan");
        assert!(matches!(
            periodic_plan.shift,
            TwoWayShift::SmallPeriod { .. }
        ));
        assert_eq!(two_way_find(periodic_plan, &shifted, periodic), Some(2));
    }

    #[test]
    fn two_way_work_stays_linear_for_both_factorization_cases() {
        let periodic = b"abababababababababababababababababababababababababababababababab";
        let aperiodic = b"abababababababababababababababababababababababababababababababc";
        let periodic_plan = derive_two_way_plan(periodic).expect("derive periodic plan");
        let aperiodic_plan = derive_two_way_plan(aperiodic).expect("derive aperiodic plan");
        assert!(matches!(
            periodic_plan.shift,
            TwoWayShift::SmallPeriod { period: 2 }
        ));
        assert!(matches!(aperiodic_plan.shift, TwoWayShift::Large { .. }));
        for (needle, plan) in [
            (periodic.as_slice(), periodic_plan),
            (aperiodic, aperiodic_plan),
        ] {
            for length in [256_usize, 1024, 4096, 16 * 1024] {
                let mut haystack = (0..length)
                    .map(|index| if index.is_multiple_of(2) { b'a' } else { b'b' })
                    .collect::<Vec<_>>();
                if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
                    for index in (needle.len() - 2..haystack.len()).step_by(needle.len() - 1) {
                        haystack[index] = b'c';
                    }
                }
                let mut work = 0_usize;
                let actual = two_way_find_counted(plan, &haystack, needle, &mut work);
                assert_eq!(
                    actual,
                    haystack
                        .windows(needle.len())
                        .position(|window| window == needle),
                );
                let linear_bound = 4_usize
                    .checked_mul(haystack.len() + needle.len())
                    .expect("bounded linear-work oracle");
                assert!(
                    work <= linear_bound,
                    "Two-Way work {work} escaped the linear bound at length {length}",
                );
            }
        }
    }

    #[test]
    fn exact_single_literal_two_way_is_cross_target_and_transactional() {
        let literal = b"the_quick_brown_fox_jumps_over_0123456789";
        assert!(derive_two_way_plan(&literal[..32]).is_none());
        assert!(derive_two_way_plan(literal).is_some());
        assert!(derive_two_way_plan(&vec![b'x'; MAX_TWO_WAY_LITERAL_BYTES]).is_some());
        assert!(derive_two_way_plan(&vec![b'x'; MAX_TWO_WAY_LITERAL_BYTES + 1]).is_none());
        for target in [Target::x86_64_linux(), Target::aarch64_macos()] {
            let plan = derive_two_way_plan(literal).expect("derive plan");
            let (code, relocations) = match target.architecture {
                Architecture::X86_64 => lower_x86_64_two_way(plan).expect("x86 lowering"),
                Architecture::Aarch64 => lower_aarch64_two_way(plan).expect("AArch64 lowering"),
            };
            assert!(!code.is_empty());
            assert_eq!(
                relocations.len(),
                if target.architecture == Architecture::X86_64 {
                    1
                } else {
                    2
                }
            );
        }
    }

    #[test]
    fn exact_single_literal_two_way_receipt_is_exclusive_and_reauthenticated() {
        let pattern = "abababababababababababababababababababababababababababababababc";
        for target in [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ] {
            let compiled = compile_two_way(pattern, target, OutputContract::Exists);
            let report = compiled
                .module()
                .exact_single_literal_aot_report()
                .copied()
                .expect("Two-Way receipt");
            assert_eq!(compiled.receipt().exact_single_literal_aot, Some(report));
            assert_eq!(report.literal_bytes, pattern.len());
            assert_eq!(report.native_data_bytes, pattern.len());
            assert_eq!(report.scanner, StartAccelerator::Scalar);
            assert_eq!(
                report.emitted_isa,
                match target.architecture {
                    Architecture::X86_64 => ExactSingleLiteralAotIsa::X86Scalar,
                    Architecture::Aarch64 => ExactSingleLiteralAotIsa::Aarch64Scalar,
                },
            );
            assert!(
                compiled
                    .receipt()
                    .passes
                    .contains(&OptimizationPass::ExactFiniteExistsSingleLiteralLowering),
            );
            assert!(compiled.module().required_runtime_symbol().is_none());
            assert!(compiled.module().prepared_entry_symbol().is_none());
            assert!(compiled.module().prepared_bulk_strategy().is_none());
            assert!(
                compiled
                    .module()
                    .exact_finite_exists_byte_set_aot_report()
                    .is_none(),
            );

            let choice = compiled
                .program()
                .native_finite_exists_choice_view()
                .expect("authenticated single-literal Choice");
            let (mut lowering, emitted) =
                lower_optional_exact_single_literal_two_way(choice, target, usize::MAX)
                    .expect("lower exact leaf")
                    .expect("eligible exact leaf");
            assert_eq!(emitted, report);
            assert!(report_matches_lowering(&report, &lowering, target));

            let mut bad = report;
            bad.critical_position = bad.critical_position.saturating_add(1);
            assert!(!report_matches_lowering(&bad, &lowering, target));
            let mut bad = report;
            bad.native_code_sha256[0] ^= 1;
            assert!(!report_matches_lowering(&bad, &lowering, target));
            lowering.code[0] ^= 1;
            assert!(!report_matches_lowering(&report, &lowering, target));
        }
    }

    #[test]
    fn exact_single_literal_two_way_respects_route_and_data_boundaries() {
        let target = Target::x86_64_linux();
        let width_32 = compile_two_way(&"x".repeat(32), target, OutputContract::Exists);
        assert!(width_32.receipt().exact_single_literal_aot.is_none());
        let maximum = compile_two_way(
            &"x".repeat(MAX_TWO_WAY_LITERAL_BYTES),
            target,
            OutputContract::Exists,
        );
        assert!(maximum.receipt().exact_single_literal_aot.is_some());
        let over_maximum = compile_two_way(
            &"x".repeat(MAX_TWO_WAY_LITERAL_BYTES + 1),
            target,
            OutputContract::Exists,
        );
        assert!(over_maximum.receipt().exact_single_literal_aot.is_none());

        let pattern = "x".repeat(MIN_TWO_WAY_LITERAL_BYTES);
        let compiled = compile_two_way(&pattern, target, OutputContract::Exists);
        assert!(compiled.receipt().exact_single_literal_aot.is_some());
        let exact_cap = CompiledModule::lower_optimizing_with_limits_and_native_data_limit(
            compiled.program(),
            target,
            SlowAotLimits::default(),
            pattern.len(),
        )
        .expect("exact data-cap lowering");
        assert!(exact_cap.exact_single_literal_aot_report().is_some());
        let declined = CompiledModule::lower_optimizing_with_limits_and_native_data_limit(
            compiled.program(),
            target,
            SlowAotLimits::default(),
            pattern.len() - 1,
        )
        .expect("data-cap fallback");
        assert!(declined.exact_single_literal_aot_report().is_none());

        let serialized = compiled.program().serialize().expect("serialize program");
        let restored = CompiledProgram::deserialize(&serialized).expect("restore program");
        let restored =
            CompiledModule::lower_optimizing(&restored, target).expect("lower restored program");
        assert!(restored.exact_single_literal_aot_report().is_none());

        for output in [OutputContract::SelectedEnd, OutputContract::Span] {
            let control = compile_two_way(&pattern, target, output);
            assert!(control.receipt().exact_single_literal_aot.is_none());
        }
        let fast = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile Fast control");
        assert!(fast.receipt().exact_single_literal_aot.is_none());
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes exact single-literal Two-Way leaves on the host ISA"]
    #[allow(
        clippy::too_many_lines,
        reason = "the generated C differential keeps object linking, ABI failures, and every subwindow in one auditable transaction"
    )]
    fn linked_host_exact_single_literal_two_way_matches_every_window() {
        use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

        let target = match (cfg!(target_arch = "x86_64"), cfg!(target_os = "linux")) {
            (true, true) => Target::x86_64_linux(),
            (true, false) => Target::x86_64_macos(),
            (false, true) => Target::aarch64_linux(),
            (false, false) => Target::aarch64_macos(),
        };
        let patterns = [
            "abababababababababababababababababababababababababababababababab",
            "abababababababababababababababababababababababababababababababc",
            "the_quick_brown_fox_jumps_over_the_lazy_dog_0123456789_ABCDEF",
        ];
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("wall clock after epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-single-literal-two-way-{}-{unique}",
            std::process::id(),
        ));
        fs::create_dir(&directory).expect("create linker directory");
        let mut source = String::from("#include <stdint.h>\n#include <stddef.h>\n");
        let mut calls = String::from("int main(void){size_t r[2];uint32_t s;\n");
        let mut objects = Vec::new();
        for (case, pattern) in patterns.iter().enumerate() {
            let compiled = compile_two_way(pattern, target, OutputContract::Exists);
            let needle = pattern.as_bytes();
            let haystacks = [
                [vec![b'!'], needle.to_vec(), vec![b'?']].concat(),
                [b"bb".to_vec(), needle.to_vec()].concat(),
                vec![needle[0]; needle.len() * 2 + 3],
            ];
            let symbol = compiled.module().entry_symbol();
            writeln!(
                source,
                "extern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);"
            )
            .expect("write declaration");
            let object = directory.join(format!("case{case}.o"));
            fs::write(&object, compiled.object()).expect("write object");
            objects.push(object);
            for (haystack_index, haystack) in haystacks.iter().enumerate() {
                let name = format!("h{case}_{haystack_index}");
                let bytes = haystack
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                writeln!(source, "static const unsigned char {name}[]={{{bytes}}};")
                    .expect("write haystack");
                let windows: Box<dyn Iterator<Item = (usize, usize)>> =
                    if haystack_index == 0 {
                        Box::new((0..=haystack.len()).flat_map(|start| {
                            (start..=haystack.len()).map(move |end| (start, end))
                        }))
                    } else {
                        Box::new(
                            [
                                (0, haystack.len()),
                                (0, needle.len().saturating_sub(1)),
                                (1, haystack.len()),
                                (2, haystack.len()),
                            ]
                            .into_iter(),
                        )
                    };
                for (start, end) in windows {
                    let MatchResult::Exists(expected) = compiled
                        .search(haystack, SearchWindow::new(start, end))
                        .expect("portable result")
                    else {
                        panic!("unexpected output contract");
                    };
                    writeln!(
                        calls,
                        "r[0]=91;r[1]=92;s={symbol}({name},{},{start},{end},r);if(s!={}||r[0]!=0||r[1]!=0)return {};",
                        haystack.len(),
                        u8::from(expected),
                        10 + case,
                    )
                    .expect("write differential call");
                }
            }
            writeln!(
                calls,
                "r[0]=91;r[1]=92;s={symbol}((const unsigned char*)\"x\",1,1,0,r);if(s!=2||r[0]!=91||r[1]!=92)return {};",
                40 + case,
            )
            .expect("write invalid-bounds call");
            writeln!(
                calls,
                "r[0]=91;r[1]=92;s={symbol}(NULL,1,0,1,r);if(s!=2||r[0]!=91||r[1]!=92)return {};",
                50 + case,
            )
            .expect("write null-haystack call");
            writeln!(
                calls,
                "r[0]=91;r[1]=92;s={symbol}((const unsigned char*)\"x\",1,0,1,NULL);if(s!=2||r[0]!=91||r[1]!=92)return {};",
                60 + case,
            )
            .expect("write null-result call");
        }
        calls.push_str("return 0;}\n");
        source.push_str(&calls);
        let c_path = directory.join("two_way.c");
        let executable = directory.join("two_way");
        fs::write(&c_path, source).expect("write harness");
        let compiler = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("link harness");
        let result = status
            .success()
            .then(|| Command::new(&executable).output().expect("execute harness"));
        fs::remove_dir_all(&directory).expect("remove linker directory");
        assert!(status.success(), "host linker rejected Two-Way objects");
        let output = result.expect("successful link has execution output");
        assert!(
            output.status.success(),
            "native differential failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
