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
const MAX_PAIR_PREFILTER_LITERAL_BYTES: usize = 255;
const PAIR_PREFILTER_VECTOR_BYTES: u8 = 16;
const PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES: u8 = 4;
const PAIR_PREFILTER_MAX_CANDIDATE_REPORTS: u8 = 2;
const PAIR_PREFILTER_MAX_FREQUENCY_NUMERATOR: u16 = 32;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PairPrefilterPlan {
    offsets: [u8; 2],
    bytes: [u8; 2],
    minimum_vector_remaining_bytes: u16,
    estimated_frequency_numerator: u16,
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

/// Use memchr's stable packed-pair rank and ordering for this deliberately
/// narrow first slice. Lower frequency ranks are preferred and strict
/// comparisons retain the earlier offset on a tie; FRE then applies its own
/// width, distinct-byte and frequency-product gates.
fn select_pair_prefilter(literal: &[u8]) -> Option<PairPrefilterPlan> {
    if literal.len() < 2 || literal.len() > MAX_PAIR_PREFILTER_LITERAL_BYTES {
        return None;
    }
    let mut first_byte = literal[0];
    let mut first_offset = 0_u8;
    let mut second_byte = literal[1];
    let mut second_offset = 1_u8;
    if byte_frequency_rank(second_byte) < byte_frequency_rank(first_byte) {
        core::mem::swap(&mut first_byte, &mut second_byte);
        core::mem::swap(&mut first_offset, &mut second_offset);
    }
    for (offset, &byte) in literal
        .iter()
        .enumerate()
        .take(usize::from(u8::MAX))
        .skip(2)
    {
        let offset = u8::try_from(offset).ok()?;
        if byte_frequency_rank(byte) < byte_frequency_rank(first_byte) {
            second_byte = first_byte;
            second_offset = first_offset;
            first_byte = byte;
            first_offset = offset;
        } else if byte != first_byte && byte_frequency_rank(byte) < byte_frequency_rank(second_byte)
        {
            second_byte = byte;
            second_offset = offset;
        }
    }
    if first_byte == second_byte || first_offset == second_offset {
        return None;
    }
    let estimated_frequency_numerator = estimated_byte_frequency_units(first_byte)
        .checked_mul(estimated_byte_frequency_units(second_byte))?;
    let minimum_vector_remaining_bytes = literal
        .len()
        .checked_add(usize::from(PAIR_PREFILTER_VECTOR_BYTES.checked_sub(1)?))
        .and_then(|value| u16::try_from(value).ok())?;
    Some(PairPrefilterPlan {
        offsets: [first_offset, second_offset],
        bytes: [first_byte, second_byte],
        minimum_vector_remaining_bytes,
        estimated_frequency_numerator,
    })
}

fn derive_pair_prefilter(
    literal: &[u8],
    two_way: TwoWayPlan,
    target: Target,
) -> Option<PairPrefilterPlan> {
    if target.architecture != Architecture::Aarch64
        || !target.features.has(CpuFeature::Aarch64Asimd)
        || !matches!(two_way.shift, TwoWayShift::Large { .. })
    {
        return None;
    }
    let pair = select_pair_prefilter(literal)?;
    (pair.estimated_frequency_numerator <= PAIR_PREFILTER_MAX_FREQUENCY_NUMERATOR).then_some(pair)
}

fn pair_prefilter_report(plan: PairPrefilterPlan) -> ExactSingleLiteralPairPrefilterReport {
    ExactSingleLiteralPairPrefilterReport {
        offsets: plan.offsets,
        bytes: plan.bytes,
        vector_bytes: PAIR_PREFILTER_VECTOR_BYTES,
        activation_consecutive_failures: PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES,
        maximum_candidate_reports: PAIR_PREFILTER_MAX_CANDIDATE_REPORTS,
        minimum_vector_remaining_bytes: usize::from(plan.minimum_vector_remaining_bytes),
        estimated_frequency_numerator: plan.estimated_frequency_numerator,
    }
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
    let pair_prefilter = derive_pair_prefilter(literal, plan, target);
    if literal.len() > max_native_data_bytes {
        return Ok(None);
    }
    let mut data = Vec::new();
    data.try_reserve_exact(literal.len())
        .map_err(|_| ObjectError::Allocation("exact single-literal data"))?;
    data.extend_from_slice(literal);
    let (code, relocations, emitted_isa, scanner) = match target.architecture {
        Architecture::X86_64 => {
            let (code, relocations) = lower_x86_64_two_way(plan)?;
            (
                code,
                relocations,
                ExactSingleLiteralAotIsa::X86Scalar,
                StartAccelerator::Scalar,
            )
        }
        Architecture::Aarch64 => {
            let (code, relocations) = lower_aarch64_two_way(plan, pair_prefilter)?;
            if pair_prefilter.is_some() {
                (
                    code,
                    relocations,
                    ExactSingleLiteralAotIsa::Aarch64AsimdPairPrefilter,
                    StartAccelerator::Aarch64Asimd,
                )
            } else {
                (
                    code,
                    relocations,
                    ExactSingleLiteralAotIsa::Aarch64Scalar,
                    StartAccelerator::Scalar,
                )
            }
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
        pair_prefilter: pair_prefilter.map(pair_prefilter_report),
        emitted_isa,
        scanner,
        native_data_bytes: data.len(),
    };
    Ok(Some((
        NativeLowering {
            code,
            data,
            relocations,
            slow_partial_table: None,
            needs_runtime: false,
            start_accelerator: scanner,
            anchored_prefix_filter_bytes: 0,
            synchronizing_accept_reverse_lowered: false,
            exact_pair_suffix_lowered: false,
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
    let pair_prefilter = derive_pair_prefilter(&lowering.data, plan, target);
    let expected_pair_report = pair_prefilter.map(pair_prefilter_report);
    let expected_scanner = if pair_prefilter.is_some() {
        StartAccelerator::Aarch64Asimd
    } else {
        StartAccelerator::Scalar
    };
    let expected_isa = match (target.architecture, pair_prefilter.is_some()) {
        (Architecture::X86_64, false) => ExactSingleLiteralAotIsa::X86Scalar,
        (Architecture::Aarch64, false) => ExactSingleLiteralAotIsa::Aarch64Scalar,
        (Architecture::Aarch64, true) => ExactSingleLiteralAotIsa::Aarch64AsimdPairPrefilter,
        (Architecture::X86_64, true) => return false,
    };
    let literal_sha256: [u8; 32] = Sha256::digest(&lowering.data).into();
    let native_code_sha256: [u8; 32] = Sha256::digest(&lowering.code).into();
    report.emitted_isa == expected_isa
        && report.literal_sha256 == literal_sha256
        && report.native_code_sha256 == native_code_sha256
        && relocation_digest(&lowering.relocations)
            .is_some_and(|digest| report.relocations_sha256 == digest)
        && report.literal_bytes == lowering.data.len()
        && report.critical_position == usize::try_from(plan.critical_position).unwrap_or(usize::MAX)
        && report.shift == shift
        && report.approximate_last_byte_membership == plan.approximate_byteset
        && report.pair_prefilter == expected_pair_report
        && report.scanner == expected_scanner
        && report.native_data_bytes == lowering.data.len()
        && !lowering.code.is_empty()
        && lowering.start_accelerator == expected_scanner
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

/// Record one pre-activation scalar candidate that passed the approximate
/// terminal-byte gate and then failed exact verification without advancing by
/// a complete vector. A larger pre-activation scalar verifier advance
/// permanently retires the prefilter, so activation measures repeated
/// low-progress scalar work without repeatedly taxing inputs on which Two-Way
/// demonstrates useful jumps.
///
/// `x16 == 0` is pre-activation scalar mode and `x17` counts bounded warm-up
/// failures. Reaching the threshold initializes the two vector constants
/// lazily and changes `x16` to one (active with zero reported pair candidates).
/// Active values through `PAIR_PREFILTER_MAX_CANDIDATE_REPORTS` encode one plus
/// the report count; `PAIR_PREFILTER_MAX_CANDIDATE_REPORTS + 1` is permanently
/// retired.
fn aarch64_emit_pair_prefilter_activation_observation(
    assembler: &mut Aarch64Assembler,
    pair: PairPrefilterPlan,
    continuation: Aarch64Label,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_cmp_x_imm(
        17,
        u16::from(PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES),
    )?)?;
    assembler.branch_cond(AARCH64_HS, continuation)?;
    assembler.instruction(aarch64_add_x_imm(17, 17, 1)?)?;
    assembler.instruction(aarch64_cmp_x_imm(
        17,
        u16::from(PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES),
    )?)?;
    assembler.branch_cond(AARCH64_LO, continuation)?;
    assembler.instruction(aarch64_movi_16b(16, pair.bytes[0])?)?;
    assembler.instruction(aarch64_movi_16b(17, pair.bytes[1])?)?;
    assembler.instruction(aarch64_movz_x(16, 1, 0)?)?;
    Ok(())
}

fn lower_aarch64_two_way(
    plan: TwoWayPlan,
    pair_prefilter: Option<PairPrefilterPlan>,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let width = u64::from(plan.literal_len);
    let critical = u64::from(plan.critical_position);
    let last = width
        .checked_sub(1)
        .ok_or(ObjectError::InvalidModule("Two-Way literal width is zero"))?;
    let pair_disabled_state =
        u16::from(PAIR_PREFILTER_MAX_CANDIDATE_REPORTS.checked_add(1).ok_or(
            ObjectError::ArithmeticOverflow("pair-prefilter disabled state"),
        )?);
    let mut assembler = Aarch64Assembler::new();
    let search = assembler.label()?;
    let warm_search = assembler.label()?;
    let retired_search = assembler.label()?;
    let vector_search = assembler.label()?;
    let byteset_skip = assembler.label()?;
    let warm_byteset_skip = assembler.label()?;
    let retired_byteset_skip = assembler.label()?;
    let pair_byteset_skip = assembler.label()?;
    let right = assembler.label()?;
    let right_complete = assembler.label()?;
    let right_mismatch = assembler.label()?;
    let left = assembler.label()?;
    let left_mismatch = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    let scalar_candidate = assembler.label()?;
    let warm_scalar_candidate = assembler.label()?;
    let retired_scalar_candidate = assembler.label()?;
    let pair_scalar_candidate = assembler.label()?;
    let scalar_verify = assembler.label()?;
    let retired_right = assembler.label()?;
    let retired_right_complete = assembler.label()?;
    let retired_right_mismatch = assembler.label()?;
    let retired_left = assembler.label()?;
    let retired_left_mismatch = assembler.label()?;
    let right_mismatch_observe = assembler.label()?;
    let right_mismatch_advance = assembler.label()?;
    let left_mismatch_advance = assembler.label()?;
    let after_scalar_mismatch = assembler.label()?;
    let active_after_scalar_mismatch = assembler.label()?;
    let pair_labels = if pair_prefilter.is_some() {
        Some((
            assembler.label()?, // permanently disable the prefilter
            assembler.label()?, // pair-vector miss
            assembler.label()?, // scalar first-lane refinement
            assembler.label()?, // scalar lane miss
            assembler.label()?, // refined pair candidate
        ))
    } else {
        None
    };

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

    if let Some(pair) = pair_prefilter {
        let (_, _, _, _, _) = pair_labels.ok_or(ObjectError::InvalidModule(
            "AArch64 pair-prefilter labels are absent",
        ))?;
        // A call that cannot contain one complete pair vector cannot ever use
        // the prefilter. Route it directly to the baseline-equivalent scalar
        // loop before initializing or dispatching any adaptive state.
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x_imm(
            12,
            pair.minimum_vector_remaining_bytes,
        )?)?;
        assembler.branch_cond(AARCH64_LO, retired_search)?;
        assembler.instruction(aarch64_movz_x(16, 0, 0)?)?;
        assembler.instruction(aarch64_movz_x(17, 0, 0)?)?;
    }

    assembler.bind(search)?;
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    assembler.instruction(aarch64_cmp_x(12, 6)?)?;
    assembler.branch_cond(AARCH64_LO, no_match)?;

    assembler.bind(scalar_candidate)?;
    assembler.instruction(aarch64_load_byte_reg(8, 2, 7)?)?;
    assembler.instruction(aarch64_and_low_x(8, 8, 63)?)?;
    assembler.instruction(aarch64_lsrv_x(10, 11, 8)?)?;
    assembler.instruction(aarch64_and_low_x(10, 10, 1)?)?;
    assembler.branch_zero_x(10, byteset_skip)?;

    assembler.bind(scalar_verify)?;
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
    if let Some(pair) = pair_prefilter {
        assembler.branch_nonzero_x(16, right_mismatch_advance)?;
        assembler.instruction(aarch64_sub_x_reg(12, 9, 14)?)?;
        assembler.instruction(aarch64_add_x_imm(12, 12, 1)?)?;
        assembler.instruction(aarch64_cmp_x_imm(
            12,
            u16::from(PAIR_PREFILTER_VECTOR_BYTES),
        )?)?;
        assembler.branch_cond(AARCH64_LO, right_mismatch_observe)?;
        assembler.instruction(aarch64_movz_x(16, pair_disabled_state, 0)?)?;
        assembler.branch(right_mismatch_advance)?;
        assembler.bind(right_mismatch_observe)?;
        aarch64_emit_pair_prefilter_activation_observation(
            &mut assembler,
            pair,
            right_mismatch_advance,
        )?;
    }
    assembler.bind(right_mismatch_advance)?;
    assembler.instruction(aarch64_sub_x_reg(9, 9, 14)?)?;
    assembler.instruction(aarch64_add_x_reg(2, 2, 9)?)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(aarch64_movz_x(13, 0, 0)?)?;
    }
    if pair_prefilter.is_some() {
        assembler.branch(after_scalar_mismatch)?;
    } else {
        assembler.branch(search)?;
    }

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
    if pair_prefilter.is_some() {
        assembler.branch_nonzero_x(16, left_mismatch_advance)?;
        assembler.instruction(aarch64_movz_x(16, pair_disabled_state, 0)?)?;
    }
    assembler.bind(left_mismatch_advance)?;
    assembler.instruction(aarch64_add_x_reg(2, 2, 15)?)?;
    if let TwoWayShift::SmallPeriod { period } = plan.shift {
        let memory = u64::from(plan.literal_len.checked_sub(period).ok_or(
            ObjectError::InvalidModule("Two-Way small period exceeds literal width"),
        )?);
        aarch64_load_u64_constant(&mut assembler, 13, memory)?;
    }
    if pair_prefilter.is_some() {
        assembler.branch(after_scalar_mismatch)?;
    } else {
        assembler.branch(search)?;
    }

    if pair_prefilter.is_some() {
        assembler.bind(after_scalar_mismatch)?;
        assembler.branch_nonzero_x(16, active_after_scalar_mismatch)?;
        assembler.branch_zero_x(17, search)?;
        assembler.branch(warm_search)?;
        assembler.bind(active_after_scalar_mismatch)?;
        assembler.instruction(aarch64_cmp_x_imm(16, pair_disabled_state)?)?;
        assembler.branch_cond(AARCH64_HS, retired_search)?;
        assembler.branch(vector_search)?;
    }

    assembler.bind(byteset_skip)?;
    assembler.instruction(aarch64_add_x_reg(2, 2, 6)?)?;
    if matches!(plan.shift, TwoWayShift::SmallPeriod { .. }) {
        assembler.instruction(aarch64_movz_x(13, 0, 0)?)?;
    }
    assembler.branch(search)?;

    if pair_prefilter.is_some() {
        assembler.bind(pair_byteset_skip)?;
        assembler.instruction(aarch64_add_x_reg(2, 2, 6)?)?;
        assembler.branch(after_scalar_mismatch)?;
    }

    if let Some(pair) = pair_prefilter {
        let (prefilter_disable, vector_miss, lane, lane_miss, pair_candidate) = pair_labels.ok_or(
            ObjectError::InvalidModule("AArch64 pair-prefilter labels are absent"),
        )?;
        assembler.bind(warm_search)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x(12, 6)?)?;
        assembler.branch_cond(AARCH64_LO, no_match)?;

        assembler.bind(warm_scalar_candidate)?;
        assembler.instruction(aarch64_load_byte_reg(8, 2, 7)?)?;
        assembler.instruction(aarch64_and_low_x(8, 8, 63)?)?;
        assembler.instruction(aarch64_lsrv_x(10, 11, 8)?)?;
        assembler.instruction(aarch64_and_low_x(10, 10, 1)?)?;
        assembler.branch_zero_x(10, warm_byteset_skip)?;
        assembler.branch(scalar_verify)?;

        assembler.bind(warm_byteset_skip)?;
        assembler.instruction(aarch64_movz_x(17, 0, 0)?)?;
        assembler.instruction(aarch64_add_x_reg(2, 2, 6)?)?;
        assembler.branch(search)?;

        // Permanent retirement converges here after the pre-activation scalar
        // policy declines activation or the active pair scanner exhausts its
        // report budget. Keeping this loop separate makes the steady retired
        // path instruction-for-instruction equivalent to scalar Large Two-Way
        // instead of charging mode checks forever.
        assembler.bind(retired_search)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x(12, 6)?)?;
        assembler.branch_cond(AARCH64_LO, no_match)?;

        assembler.bind(retired_scalar_candidate)?;
        assembler.instruction(aarch64_load_byte_reg(8, 2, 7)?)?;
        assembler.instruction(aarch64_and_low_x(8, 8, 63)?)?;
        assembler.instruction(aarch64_lsrv_x(10, 11, 8)?)?;
        assembler.instruction(aarch64_and_low_x(10, 10, 1)?)?;
        assembler.branch_zero_x(10, retired_byteset_skip)?;

        assembler.instruction(aarch64_mov_x(9, 14)?)?;
        assembler.bind(retired_right)?;
        assembler.instruction(aarch64_cmp_x(9, 6)?)?;
        assembler.branch_cond(AARCH64_HS, retired_right_complete)?;
        assembler.instruction(aarch64_load_byte_reg(8, 2, 9)?)?;
        assembler.instruction(aarch64_load_byte_reg(10, 5, 9)?)?;
        assembler.instruction(aarch64_cmp_w(8, 10)?)?;
        assembler.branch_cond(AARCH64_NE, retired_right_mismatch)?;
        assembler.instruction(aarch64_add_x_imm(9, 9, 1)?)?;
        assembler.branch(retired_right)?;

        assembler.bind(retired_right_mismatch)?;
        assembler.instruction(aarch64_sub_x_reg(9, 9, 14)?)?;
        assembler.instruction(aarch64_add_x_reg(2, 2, 9)?)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.branch(retired_search)?;

        assembler.bind(retired_right_complete)?;
        assembler.instruction(aarch64_mov_x(9, 14)?)?;
        assembler.bind(retired_left)?;
        assembler.branch_zero_x(9, matched)?;
        assembler.instruction(aarch64_sub_x_imm(9, 9, 1)?)?;
        assembler.instruction(aarch64_load_byte_reg(8, 2, 9)?)?;
        assembler.instruction(aarch64_load_byte_reg(10, 5, 9)?)?;
        assembler.instruction(aarch64_cmp_w(8, 10)?)?;
        assembler.branch_cond(AARCH64_NE, retired_left_mismatch)?;
        assembler.branch(retired_left)?;

        assembler.bind(retired_left_mismatch)?;
        assembler.instruction(aarch64_add_x_reg(2, 2, 15)?)?;
        assembler.branch(retired_search)?;

        assembler.bind(retired_byteset_skip)?;
        assembler.instruction(aarch64_add_x_reg(2, 2, 6)?)?;
        assembler.branch(retired_search)?;

        assembler.bind(vector_search)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x(12, 6)?)?;
        assembler.branch_cond(AARCH64_LO, no_match)?;
        assembler.instruction(aarch64_cmp_x_imm(16, pair_disabled_state)?)?;
        assembler.branch_cond(AARCH64_HS, prefilter_disable)?;
        assembler.instruction(aarch64_cmp_x_imm(12, pair.minimum_vector_remaining_bytes)?)?;
        assembler.branch_cond(AARCH64_LO, prefilter_disable)?;

        assembler.instruction(aarch64_add_x_imm(12, 2, u16::from(pair.offsets[0]))?)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        assembler.instruction(aarch64_add_x_imm(12, 2, u16::from(pair.offsets[1]))?)?;
        assembler.instruction(aarch64_load_q(1, 12)?)?;
        assembler.instruction(aarch64_cmeq_16b(24, 0, 16)?)?;
        assembler.instruction(aarch64_cmeq_16b(1, 1, 17)?)?;
        assembler.instruction(aarch64_and_16b(24, 24, 1)?)?;
        aarch64_emit_candidate_any(&mut assembler, 24)?;
        assembler.branch_cond(AARCH64_EQ, vector_miss)?;

        assembler.instruction(aarch64_movz_x(12, 0, 0)?)?;
        assembler.bind(lane)?;
        assembler.instruction(aarch64_add_x_reg(9, 2, 12)?)?;
        assembler.instruction(aarch64_load_byte_imm(8, 9, u16::from(pair.offsets[0]))?)?;
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(pair.bytes[0]))?)?;
        assembler.branch_cond(AARCH64_NE, lane_miss)?;
        assembler.instruction(aarch64_load_byte_imm(8, 9, u16::from(pair.offsets[1]))?)?;
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(pair.bytes[1]))?)?;
        assembler.branch_cond(AARCH64_EQ, pair_candidate)?;
        assembler.bind(lane_miss)?;
        assembler.instruction(aarch64_add_x_imm(12, 12, 1)?)?;
        assembler.instruction(aarch64_cmp_x_imm(
            12,
            u16::from(PAIR_PREFILTER_VECTOR_BYTES),
        )?)?;
        assembler.branch_cond(AARCH64_LO, lane)?;

        assembler.bind(vector_miss)?;
        assembler.instruction(aarch64_add_x_imm(
            2,
            2,
            u16::from(PAIR_PREFILTER_VECTOR_BYTES),
        )?)?;
        assembler.branch(vector_search)?;

        assembler.bind(pair_candidate)?;
        assembler.instruction(aarch64_mov_x(2, 9)?)?;
        assembler.instruction(aarch64_add_x_imm(16, 16, 1)?)?;
        assembler.branch(pair_scalar_candidate)?;

        assembler.bind(prefilter_disable)?;
        assembler.instruction(aarch64_movz_x(16, pair_disabled_state, 0)?)?;
        assembler.branch(retired_scalar_candidate)?;

        assembler.bind(pair_scalar_candidate)?;
        assembler.instruction(aarch64_load_byte_reg(8, 2, 7)?)?;
        assembler.instruction(aarch64_and_low_x(8, 8, 63)?)?;
        assembler.instruction(aarch64_lsrv_x(10, 11, 8)?)?;
        assembler.instruction(aarch64_and_low_x(10, 10, 1)?)?;
        assembler.branch_zero_x(10, pair_byteset_skip)?;
        assembler.branch(scalar_verify)?;
    }

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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PairPrefilterModelStats {
    consecutive_failures: usize,
    candidate_reports: usize,
    vector_windows: usize,
    retired: bool,
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the bounded model mirrors the admitted 33..=255-byte Large Two-Way prefilter and indexes only after explicit extent checks"
)]
fn pair_prefilter_find_counted(
    plan: TwoWayPlan,
    pair: PairPrefilterPlan,
    haystack: &[u8],
    needle: &[u8],
    stats: &mut PairPrefilterModelStats,
) -> Option<usize> {
    let TwoWayShift::Large { shift } = plan.shift else {
        return None;
    };
    let width = needle.len();
    let critical = usize::try_from(plan.critical_position).ok()?;
    let shift = usize::try_from(shift).ok()?;
    let mut position = 0_usize;
    let mut active = false;
    'outer: while position.checked_add(width)? <= haystack.len() {
        if active
            && (stats.candidate_reports >= usize::from(PAIR_PREFILTER_MAX_CANDIDATE_REPORTS)
                || haystack.len() - position < usize::from(pair.minimum_vector_remaining_bytes))
        {
            active = false;
            stats.retired = true;
        }
        if active {
            stats.vector_windows += 1;
            let lane = (0..usize::from(PAIR_PREFILTER_VECTOR_BYTES)).find(|&lane| {
                haystack[position + lane + usize::from(pair.offsets[0])] == pair.bytes[0]
                    && haystack[position + lane + usize::from(pair.offsets[1])] == pair.bytes[1]
            });
            let Some(lane) = lane else {
                position += usize::from(PAIR_PREFILTER_VECTOR_BYTES);
                continue;
            };
            position += lane;
            stats.candidate_reports += 1;
        }
        if plan.approximate_byteset & (1_u64 << (haystack[position + width - 1] % 64)) == 0 {
            if !active && !stats.retired {
                stats.consecutive_failures = 0;
            }
            position += width;
            continue;
        }
        let mut index = critical;
        while index < width && needle[index] == haystack[position + index] {
            index += 1;
        }
        if index < width {
            if !active && !stats.retired {
                let advance = index - critical + 1;
                if advance < usize::from(PAIR_PREFILTER_VECTOR_BYTES) {
                    stats.consecutive_failures += 1;
                    active = stats.consecutive_failures
                        >= usize::from(PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES);
                } else {
                    stats.consecutive_failures = 0;
                    stats.retired = true;
                }
            }
            position += index - critical + 1;
            continue;
        }
        index = critical;
        while index > 0 {
            index -= 1;
            if needle[index] != haystack[position + index] {
                if !active && !stats.retired {
                    stats.consecutive_failures = 0;
                    stats.retired = true;
                }
                position += shift;
                continue 'outer;
            }
        }
        return Some(position);
    }
    None
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
    fn packed_pair_policy_is_stable_narrow_and_target_authenticated() {
        let mut literal = Vec::new();
        for _ in 0..31 {
            literal.extend_from_slice(b"ab");
        }
        literal.push(b'c');
        let two_way = derive_two_way_plan(&literal).expect("derive width-63 plan");
        assert!(matches!(two_way.shift, TwoWayShift::Large { shift: 62 }));
        let selected = select_pair_prefilter(&literal).expect("select canonical pair");
        assert_eq!(selected.offsets, [1, 62]);
        assert_eq!(selected.bytes, [b'b', b'c']);
        assert_eq!(selected.estimated_frequency_numerator, 32);
        assert_eq!(
            selected.minimum_vector_remaining_bytes,
            u16::try_from(literal.len() + 15).expect("bounded minimum"),
        );
        assert!(PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES > 1);

        let asimd = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .expect("ASIMD target");
        assert_eq!(
            derive_pair_prefilter(&literal, two_way, asimd),
            Some(selected)
        );
        assert!(derive_pair_prefilter(&literal, two_way, Target::aarch64_macos()).is_none());
        assert!(derive_pair_prefilter(&literal, two_way, Target::x86_64_linux()).is_none());

        let periodic = b"bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc";
        let periodic_plan = derive_two_way_plan(periodic).expect("periodic plan");
        assert!(matches!(
            periodic_plan.shift,
            TwoWayShift::SmallPeriod { .. }
        ));
        assert!(select_pair_prefilter(periodic).is_some());
        assert!(derive_pair_prefilter(periodic, periodic_plan, asimd).is_none());

        let mut over_cost = vec![b'a'; 62];
        over_cost.push(b'b');
        let over_cost_plan = derive_two_way_plan(&over_cost).expect("over-cost plan");
        assert!(select_pair_prefilter(&over_cost).is_some_and(|pair| {
            pair.estimated_frequency_numerator > PAIR_PREFILTER_MAX_FREQUENCY_NUMERATOR
        }));
        assert!(derive_pair_prefilter(&over_cost, over_cost_plan, asimd).is_none());
        assert!(select_pair_prefilter(&[b'x'; 63]).is_none());
        assert!(select_pair_prefilter(&[b'x'; 256]).is_none());
    }

    #[test]
    fn asimd_pair_prefilter_emits_exact_vector_and_first_lane_primitives() {
        let literal = format!("{}c", "ab".repeat(31));
        let plan = derive_two_way_plan(literal.as_bytes()).expect("derive ASIMD plan");
        let pair = select_pair_prefilter(literal.as_bytes()).expect("select ASIMD pair");
        let (code, _) = lower_aarch64_two_way(plan, Some(pair)).expect("lower ASIMD pair");
        let words = code
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("instruction word")))
            .collect::<Vec<_>>();
        let vector = [
            aarch64_add_x_imm(12, 2, u16::from(pair.offsets[0])).expect("first address"),
            aarch64_load_q(0, 12).expect("first vector load"),
            aarch64_add_x_imm(12, 2, u16::from(pair.offsets[1])).expect("second address"),
            aarch64_load_q(1, 12).expect("second vector load"),
            aarch64_cmeq_16b(24, 0, 16).expect("first equality"),
            aarch64_cmeq_16b(1, 1, 17).expect("second equality"),
            aarch64_and_16b(24, 24, 1).expect("pair intersection"),
            aarch64_umaxv_16b(7, 24).expect("candidate reduction"),
            aarch64_umov_b0(12, 7).expect("candidate scalar"),
            aarch64_cmp_w_zero(12).expect("candidate test"),
        ];
        assert!(words.windows(vector.len()).any(|window| window == vector));
        let scalar_lane = [
            aarch64_add_x_reg(9, 2, 12).expect("lane address"),
            aarch64_load_byte_imm(8, 9, u16::from(pair.offsets[0])).expect("first lane byte"),
            aarch64_cmp_w_imm(8, u16::from(pair.bytes[0])).expect("first lane compare"),
        ];
        assert!(
            words
                .windows(scalar_lane.len())
                .any(|window| window == scalar_lane),
        );
        assert!(
            words.contains(
                &aarch64_cmp_x_imm(
                    16,
                    u16::from(
                        PAIR_PREFILTER_MAX_CANDIDATE_REPORTS
                            .checked_add(1)
                            .expect("candidate disabled state"),
                    ),
                )
                .expect("candidate budget")
            )
        );
        assert!(
            words.contains(
                &aarch64_cmp_x_imm(
                    17,
                    u16::from(PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES),
                )
                .expect("adaptive warm-up threshold")
            )
        );
        assert!(
            words.contains(
                &aarch64_add_x_imm(2, 2, u16::from(PAIR_PREFILTER_VECTOR_BYTES),)
                    .expect("vector miss advance")
            )
        );

        let (scalar, _) = lower_aarch64_two_way(plan, None).expect("lower scalar control");
        assert!(!scalar.windows(4).any(|bytes| {
            u32::from_le_bytes(bytes.try_into().expect("scalar word"))
                == aarch64_movi_16b(16, pair.bytes[0]).expect("first splat")
        }));
    }

    #[test]
    fn packed_pair_model_preserves_first_match_boundaries_and_budget() {
        let mut needle = Vec::new();
        for _ in 0..31 {
            needle.extend_from_slice(b"ab");
        }
        needle.push(b'c');
        let plan = derive_two_way_plan(&needle).expect("derive pair model plan");
        let pair = select_pair_prefilter(&needle).expect("select pair model plan");
        for valid_starts in [0_usize, 1, 15, 16, 17] {
            let length = needle.len().saturating_sub(1) + valid_starts;
            let haystack = vec![b'!'; length];
            let mut stats = PairPrefilterModelStats::default();
            assert_eq!(
                pair_prefilter_find_counted(plan, pair, &haystack, &needle, &mut stats),
                None,
            );
            assert_eq!(stats.candidate_reports, 0);
        }
        let mut stats = PairPrefilterModelStats::default();
        let scalar_skip_haystack = vec![b'~'; 64 * 1024];
        assert_eq!(
            pair_prefilter_find_counted(
                plan,
                pair,
                &scalar_skip_haystack,
                &needle,
                &mut stats,
            ),
            None,
        );
        assert_eq!(stats, PairPrefilterModelStats::default());
        for lane in 0_usize..16 {
            let mut haystack = vec![b'!'; needle.len() + 15];
            haystack[lane..lane + needle.len()].copy_from_slice(&needle);
            let mut stats = PairPrefilterModelStats::default();
            assert_eq!(
                pair_prefilter_find_counted(plan, pair, &haystack, &needle, &mut stats),
                Some(lane),
                "lane {lane}",
            );
            assert!(stats.candidate_reports <= 1);
        }

        let mut large_shift_candidate = needle.clone();
        large_shift_candidate[0] = b'!';
        let mut scalar_haystack = Vec::new();
        for _ in 0..16 {
            scalar_haystack.extend_from_slice(&large_shift_candidate);
        }
        let expected = scalar_haystack.len();
        scalar_haystack.extend_from_slice(&needle);
        let mut stats = PairPrefilterModelStats::default();
        assert_eq!(
            pair_prefilter_find_counted(plan, pair, &scalar_haystack, &needle, &mut stats),
            Some(expected),
        );
        assert_eq!(stats.vector_windows, 0);
        assert_eq!(stats.candidate_reports, 0);
        assert!(stats.retired);

        let mut low_progress_candidate = needle.clone();
        low_progress_candidate[needle.len() - 1] = b'b';
        let mut adaptive_haystack = Vec::new();
        for _ in 0..8 {
            adaptive_haystack.extend_from_slice(&low_progress_candidate);
        }
        for _ in 0..=usize::from(PAIR_PREFILTER_MAX_CANDIDATE_REPORTS) {
            adaptive_haystack.extend_from_slice(&large_shift_candidate);
        }
        let expected = adaptive_haystack.len();
        adaptive_haystack.extend_from_slice(&needle);
        let mut stats = PairPrefilterModelStats::default();
        assert_eq!(
            pair_prefilter_find_counted(plan, pair, &adaptive_haystack, &needle, &mut stats),
            Some(expected),
        );
        assert_eq!(
            stats.consecutive_failures,
            usize::from(PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES),
        );
        assert!(stats.vector_windows > 0);
        assert_eq!(
            stats.candidate_reports,
            usize::from(PAIR_PREFILTER_MAX_CANDIDATE_REPORTS),
        );
        assert!(stats.retired);
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
                Architecture::Aarch64 => {
                    lower_aarch64_two_way(plan, None).expect("AArch64 lowering")
                }
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
    fn asimd_pair_prefilter_receipt_is_exact_and_scalar_controls_are_unchanged() {
        let pattern = format!("{}c", "ab".repeat(31));
        let asimd = FeatureSet::of(CpuFeature::Aarch64Asimd);
        for base in [Target::aarch64_linux(), Target::aarch64_macos()] {
            let target = base.with_features(asimd).expect("ASIMD target");
            let compiled = compile_two_way(&pattern, target, OutputContract::Exists);
            let report = compiled
                .receipt()
                .exact_single_literal_aot
                .expect("ASIMD pair receipt");
            let pair = report.pair_prefilter.expect("packed-pair receipt");
            assert_eq!(pair.offsets, [1, 62]);
            assert_eq!(pair.bytes, [b'b', b'c']);
            assert_eq!(pair.vector_bytes, PAIR_PREFILTER_VECTOR_BYTES);
            assert_eq!(
                pair.activation_consecutive_failures,
                PAIR_PREFILTER_ACTIVATION_CONSECUTIVE_FAILURES,
            );
            assert_eq!(
                pair.maximum_candidate_reports,
                PAIR_PREFILTER_MAX_CANDIDATE_REPORTS,
            );
            assert_eq!(pair.minimum_vector_remaining_bytes, pattern.len() + 15);
            assert_eq!(pair.estimated_frequency_numerator, 32);
            assert_eq!(
                report.emitted_isa,
                ExactSingleLiteralAotIsa::Aarch64AsimdPairPrefilter,
            );
            assert_eq!(report.scanner, StartAccelerator::Aarch64Asimd);
            assert!(
                compiled
                    .receipt()
                    .passes
                    .contains(&OptimizationPass::StartStateScanAcceleration),
            );

            let repeated = compile_two_way(&pattern, target, OutputContract::Exists);
            assert_eq!(compiled.object(), repeated.object());
            assert_eq!(
                compiled.receipt().exact_single_literal_aot,
                repeated.receipt().exact_single_literal_aot
            );

            let choice = compiled
                .program()
                .native_finite_exists_choice_view()
                .expect("single-literal Choice");
            let (mut lowering, emitted) =
                lower_optional_exact_single_literal_two_way(choice, target, usize::MAX)
                    .expect("lower ASIMD pair leaf")
                    .expect("eligible ASIMD pair leaf");
            assert_eq!(emitted, report);
            assert!(report_matches_lowering(&report, &lowering, target));

            for mutate in 0_u8..7 {
                let mut bad = report;
                let pair = bad.pair_prefilter.as_mut().expect("pair receipt");
                match mutate {
                    0 => pair.offsets[0] ^= 1,
                    1 => pair.bytes[1] ^= 1,
                    2 => pair.activation_consecutive_failures -= 1,
                    3 => pair.maximum_candidate_reports -= 1,
                    4 => pair.minimum_vector_remaining_bytes -= 1,
                    5 => pair.estimated_frequency_numerator -= 1,
                    6 => pair.vector_bytes -= 1,
                    _ => unreachable!(),
                }
                assert!(!report_matches_lowering(&bad, &lowering, target));
            }
            let mut bad = report;
            bad.emitted_isa = ExactSingleLiteralAotIsa::Aarch64Scalar;
            assert!(!report_matches_lowering(&bad, &lowering, target));
            let mut bad = report;
            bad.scanner = StartAccelerator::Scalar;
            assert!(!report_matches_lowering(&bad, &lowering, target));
            assert!(!report_matches_lowering(&report, &lowering, base));

            lowering.data[0] ^= 1;
            assert!(!report_matches_lowering(&report, &lowering, target));
            lowering.data[0] ^= 1;
            let original_offset = lowering.relocations[0].offset;
            lowering.relocations[0].offset = original_offset.saturating_add(4);
            assert!(!report_matches_lowering(&report, &lowering, target));
            lowering.relocations[0].offset = original_offset;
        }

        let scalar_target = Target::aarch64_macos();
        let scalar = compile_two_way(&pattern, scalar_target, OutputContract::Exists);
        let scalar_report = scalar
            .receipt()
            .exact_single_literal_aot
            .expect("scalar Two-Way receipt");
        assert_eq!(scalar_report.pair_prefilter, None);
        assert_eq!(
            scalar_report.emitted_isa,
            ExactSingleLiteralAotIsa::Aarch64Scalar
        );
        assert_eq!(scalar_report.scanner, StartAccelerator::Scalar);
        assert!(
            !scalar
                .receipt()
                .passes
                .contains(&OptimizationPass::StartStateScanAcceleration),
        );
        let choice = scalar
            .program()
            .native_finite_exists_choice_view()
            .expect("scalar Choice");
        let plan = derive_two_way_plan(pattern.as_bytes()).expect("scalar plan");
        let (expected_code, expected_relocations) =
            lower_aarch64_two_way(plan, None).expect("canonical scalar lowering");
        let (actual, _) =
            lower_optional_exact_single_literal_two_way(choice, scalar_target, usize::MAX)
                .expect("scalar lowering")
                .expect("eligible scalar lowering");
        assert_eq!(actual.code, expected_code);
        assert_eq!(actual.relocations, expected_relocations);
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
        let target = if target.architecture == Architecture::Aarch64 {
            target
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .expect("host ASIMD target")
        } else {
            target
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
            let mut haystacks = vec![
                [vec![b'!'; 20], needle.to_vec(), vec![b'?']].concat(),
                [b"bb".to_vec(), needle.to_vec()].concat(),
                vec![needle[0]; needle.len() * 2 + 3],
            ];
            if case == 1 {
                let mut false_candidate = needle.to_vec();
                false_candidate[0] = b'!';
                let mut low_progress_candidate = needle.to_vec();
                low_progress_candidate[needle.len() - 1] = b'b';
                let mut budget_haystack = Vec::new();
                for _ in 0..8 {
                    budget_haystack.extend_from_slice(&low_progress_candidate);
                }
                for _ in 0..=usize::from(PAIR_PREFILTER_MAX_CANDIDATE_REPORTS) {
                    budget_haystack.extend_from_slice(&false_candidate);
                }
                budget_haystack.extend_from_slice(needle);
                haystacks.push(budget_haystack);
            }
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
