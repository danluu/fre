//! Target-final exact-finite `Exists` leaves.
//!
//! These lowerings consume only the separately authenticated finite-language
//! Choice view. They remain simultaneous competitors with the ordinary native
//! machine: owning the source-derived sidecar does not by itself select one.

use super::*;
use crate::finite_language::{NativeFiniteExistsChoiceKind, NativeFiniteExistsChoiceView};

/// Exact one-byte languages do strictly less match-time work than a complete
/// DFA: one input classification proves the whole semantic answer, while the
/// incumbent must additionally classify/load a transition and inspect its
/// accepting metadata. This proof is independent of source spelling and input
/// data. The exact target image is still charged against the caller's native
/// data ceiling before selection.
pub(super) fn lower_atomic_exists_choice(
    choice: NativeFiniteExistsChoiceView<'_>,
    target: Target,
    max_native_data_bytes: usize,
    incumbent: Option<NativeProgramView<'_>>,
) -> Result<Option<NativeLowering>, ObjectError> {
    target.validate()?;
    if let Some(incumbent) = incumbent
        && (incumbent.output != OutputContract::Exists
            || incumbent.partial_discovered_states.is_some()
            || incumbent.collapse_partial_holes
            || incumbent.dfa.initial_pending)
    {
        return Ok(None);
    }
    if choice.kind() == NativeFiniteExistsChoiceKind::SingleLiteral {
        return lower_single_literal_exists_choice(
            choice,
            target,
            max_native_data_bytes,
            incumbent,
        );
    }
    let NativeFiniteExistsChoiceKind::ByteSet { membership } = choice.kind() else {
        return Ok(None);
    };
    if choice.minimum_width() != 1
        || choice.maximum_width() != 1
        || choice.literals().is_empty()
        || choice.total_source_bytes() != choice.literals().len()
    {
        return Err(ObjectError::InvalidModule(
            "exact-finite byte Choice dimensions are inconsistent",
        ));
    }
    let cardinality = u16::try_from(membership.iter().map(|word| word.count_ones()).sum::<u32>())
        .map_err(|_| ObjectError::ArithmeticOverflow("exact-finite byte Choice cardinality"))?;
    let mut reconstructed = [0_u64; 4];
    for literal in choice.literals() {
        let [byte] = literal.as_slice() else {
            return Err(ObjectError::InvalidModule(
                "exact-finite byte Choice contains a non-byte literal",
            ));
        };
        let byte = usize::from(*byte);
        reconstructed[byte / 64] |= 1_u64 << (byte % 64);
    }
    // Source-order duplicates are semantically harmless for `Exists` and are
    // deliberately preserved by the authenticated sidecar. Compare their
    // exact union instead of requiring source count to equal cardinality.
    if cardinality == 0 || reconstructed != membership {
        return Err(ObjectError::InvalidModule(
            "exact-finite byte Choice membership is inconsistent",
        ));
    }

    if cardinality == 256 {
        let lowering = lower_universal_byte_exists(target)?;
        return Ok((lowering.data.len() <= max_native_data_bytes).then_some(lowering));
    }
    if cardinality <= 3 {
        let filter = exact_atomic_byte_filter(membership, cardinality)?;
        let (code, data, relocations, start_accelerator) = match target.architecture {
            Architecture::X86_64 => {
                let kind = x86_start_filter_kind(target.features);
                let code = lower_x86_64_atomic_byte_exists(filter, kind)?;
                let accelerator = match kind {
                    X86StartFilterKind::Sse2 => StartAccelerator::X86Sse2,
                    X86StartFilterKind::Avx2 => StartAccelerator::X86Avx2,
                    X86StartFilterKind::Avx512Bw => StartAccelerator::X86Avx512Bw,
                };
                (code, vec![0], Vec::new(), accelerator)
            }
            Architecture::Aarch64 => {
                let (code, data, relocations, accelerator) =
                    lower_aarch64_atomic_byte_exists(filter, target)?;
                (code, data, relocations, accelerator)
            }
        };
        if data.len() > max_native_data_bytes {
            return Ok(None);
        }
        return Ok(Some(NativeLowering {
            code,
            data,
            relocations,
            slow_partial_table: None,
            needs_runtime: false,
            start_accelerator,
            anchored_prefix_filter_bytes: 1,
        }));
    }
    if !arbitrary_byte_set_preferred_to_incumbent(incumbent)? {
        return Ok(None);
    }
    let exact = NativeExactByteSet::from_membership(membership, 0, true).ok_or(
        ObjectError::InvalidModule("exact-finite byte Choice has no exact set"),
    )?;
    let mut data = Vec::new();
    let Some(storage) = append_native_exact_byte_set(
        &mut data,
        exact,
        target.architecture,
        max_native_data_bytes,
    )? else {
        return Ok(None);
    };
    if data.len() > max_native_data_bytes {
        return Ok(None);
    }
    let (code, relocations, start_accelerator) = match target.architecture {
        Architecture::X86_64 => {
            let kind = x86_start_filter_kind(target.features);
            let vector_kind = (!matches!(kind, X86StartFilterKind::Sse2)).then_some(kind);
            let (code, relocations) = lower_x86_64_exact_byte_exists(exact, storage, vector_kind)?;
            let accelerator = match vector_kind {
                Some(X86StartFilterKind::Avx2) => StartAccelerator::X86Avx2,
                Some(X86StartFilterKind::Avx512Bw) => StartAccelerator::X86Avx512Bw,
                Some(X86StartFilterKind::Sse2) => unreachable!("SSE2 exact-set vector declined"),
                None => StartAccelerator::Scalar,
            };
            (code, relocations, accelerator)
        }
        Architecture::Aarch64 => {
            let (code, relocations, accelerator) =
                lower_aarch64_exact_byte_exists(exact, storage, target)?;
            (code, relocations, accelerator)
        }
    };
    Ok(Some(NativeLowering {
        code,
        data,
        relocations,
        slow_partial_table: None,
        needs_runtime: false,
        start_accelerator,
        anchored_prefix_filter_bytes: 1,
    }))
}

/// Preserve distinct singleton alternatives even when two source bytes are
/// adjacent. The general range builder intentionally coalesces adjacency, but
/// memchr1/2/3 lowering is cheaper as equality plus OR on every vector tier.
fn exact_atomic_byte_filter(
    membership: [u64; 4],
    cardinality: u16,
) -> Result<NativeStartFilter, ObjectError> {
    if !(1..=3).contains(&cardinality) {
        return Err(ObjectError::InvalidModule(
            "atomic byte Choice cardinality is not in 1..=3",
        ));
    }
    let mut filter = EMPTY_NATIVE_START_FILTER;
    for byte in u8::MIN..=u8::MAX {
        let index = usize::from(byte);
        if membership[index / 64] & (1_u64 << (index % 64)) == 0 {
            continue;
        }
        let slot = filter
            .ranges
            .get_mut(usize::from(filter.range_count))
            .ok_or(ObjectError::InvalidModule(
                "atomic byte Choice exceeded its singleton range budget",
            ))?;
        *slot = NativeByteRange {
            start: byte,
            end: byte,
        };
        filter.range_count = filter
            .range_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "atomic byte Choice range count",
            ))?;
    }
    filter.candidate_bytes = cardinality;
    filter.from_anchored_prefix = true;
    if u16::from(filter.range_count) != cardinality || !filter.is_exact() {
        return Err(ObjectError::InvalidModule(
            "atomic byte Choice membership is inconsistent",
        ));
    }
    Ok(filter)
}

/// A wider arbitrary-set classifier owns the route only when the incumbent
/// has no graph-derived moving scanner. If the complete DFA can already batch
/// the same search with a start, mandatory, coalesced, or loop scanner, the
/// nibble classifier has no structural proof of dominance and declines. The
/// no-incumbent arm is the explicit resource-fallback opportunity.
fn arbitrary_byte_set_preferred_to_incumbent(
    incumbent: Option<NativeProgramView<'_>>,
) -> Result<bool, ObjectError> {
    let Some(incumbent) = incumbent else {
        return Ok(true);
    };
    if derive_start_filter(incumbent)?.is_some()
        || derive_coalesced_initial_start_filter(incumbent)?.is_some()
        || derive_suffix_filter(incumbent)?.is_some()
        || dfa_loop_skip::select_dfa_loop_skip(&incumbent.dfa, incumbent.output).is_some()
    {
        return Ok(false);
    }
    Ok(true)
}

/// Exact memchr1/2/3 lowering. The target's ordinary start-filter emitter
/// already has equality-plus-union forms for SSE2, AVX2, and AVX-512BW; this
/// leaf removes all DFA replay after a hit because membership is the complete
/// `Exists` answer.
fn lower_x86_64_atomic_byte_exists(
    filter: NativeStartFilter,
    kind: X86StartFilterKind,
) -> Result<Vec<u8>, ObjectError> {
    if filter.scan_offset != 0
        || !filter.is_exact()
        || !(1..=3).contains(&filter.ranges().len())
        || filter
            .ranges()
            .iter()
            .any(|range| range.start != range.end)
    {
        return Err(ObjectError::InvalidModule(
            "x86 atomic-byte Choice filter is malformed",
        ));
    }

    let mut assembler = X86Assembler::new();
    let vector = assembler.label()?;
    let scalar = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let returned = assembler.label()?;
    let invalid = assembler.label()?;

    x86_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(&[0x31, 0xc0])?; // xor eax, eax
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;
    x86_emit_start_filter_constants(&mut assembler, filter, kind, 1)?;

    assembler.bind(vector)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
    let mut vector_bound = vec![0x48, 0x3d]; // cmp remaining, width
    vector_bound.extend_from_slice(&u32::from(kind.width()).to_le_bytes());
    assembler.instruction(&vector_bound)?;
    assembler.branch(&[0x0f, 0x82], scalar)?;
    let _ = x86_emit_start_filter_vector_test(&mut assembler, filter, kind)?;
    assembler.branch(&[0x0f, 0x85], matched)?;
    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(scalar)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x83], no_match)?;
    x86_emit_exact_byte_set_scalar_load(&mut assembler, 0)?;
    for range in filter.ranges() {
        assembler.instruction(&[0x3c, range.start])?; // cmp al, member
        assembler.branch(&[0x0f, 0x84], matched)?;
    }
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar)?;

    assembler.bind(matched)?;
    assembler.instruction(&[0xb8, 1, 0, 0, 0])?;
    assembler.branch(&[0xe9], returned)?;
    assembler.bind(no_match)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.bind(returned)?;
    if kind.needs_vzeroupper() {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    assembler.instruction(&[0xc3])?;
    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 2, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;
    Ok(assembler.finish_with_label_offsets()?.code)
}

/// Exact memchr1/2/3 lowering for scalar AArch64, ASIMD, SVE, and SVE2. Linux
/// targets carrying both ASIMD and SVE retain the shared runtime-VL policy:
/// VL16 uses ASIMD and wider vector lengths use SVE. SVE2 MATCH is selected
/// for two or three members, where it replaces several equality/OR operations
/// with one table-backed membership instruction.
fn lower_aarch64_atomic_byte_exists(
    filter: NativeStartFilter,
    target: Target,
) -> Result<(Vec<u8>, Vec<u8>, Vec<ModuleRelocation>, StartAccelerator), ObjectError> {
    if filter.scan_offset != 0
        || !filter.is_exact()
        || !(1..=3).contains(&filter.ranges().len())
        || filter
            .ranges()
            .iter()
            .any(|range| range.start != range.end)
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 atomic-byte Choice filter is malformed",
        ));
    }

    let scanner_isa = aarch64_primary_scanner_isa(
        target.operating_system,
        target.features,
        true,
    );
    let use_sve = aarch64_primary_scanner_uses_sve(scanner_isa);
    let use_mixed = matches!(scanner_isa, Aarch64PrimaryScannerIsa::SveWithAsimdVl16);
    let use_asimd = target.features.has(CpuFeature::Aarch64Asimd)
        && (!use_sve || use_mixed);
    let use_sve2 = use_sve
        && filter.ranges().len() >= 2
        && target.operating_system == OperatingSystem::Linux
        && target.features.has(CpuFeature::Aarch64Sve2);
    let sve_kind = if use_sve2 {
        Aarch64SveFilterKind::Sve2 {
            match_table_offset: 0,
        }
    } else {
        Aarch64SveFilterKind::Sve
    };
    let accelerator = if use_sve2 {
        StartAccelerator::Aarch64Sve2
    } else if use_sve {
        StartAccelerator::Aarch64Sve
    } else if use_asimd {
        StartAccelerator::Aarch64Asimd
    } else {
        StartAccelerator::Scalar
    };
    let data = if use_sve2 {
        let first = filter.ranges()[0].start;
        let mut table = vec![first; 16];
        for (slot, range) in table.iter_mut().zip(filter.ranges()) {
            *slot = range.start;
        }
        table
    } else {
        vec![0]
    };

    let mut assembler = Aarch64Assembler::new();
    let sve_setup = assembler.label()?;
    let sve_scan = assembler.label()?;
    let asimd_setup = assembler.label()?;
    let asimd_scan = assembler.label()?;
    let scalar = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    aarch64_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;

    let mut relocation_offsets = Vec::new();
    if use_sve2 {
        relocation_offsets.push(assembler.instruction(0x9000_0005)?);
        relocation_offsets.push(assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?);
    }
    if use_mixed {
        assembler.instruction(aarch64_sve_cntb(15)?)?;
        assembler.instruction(aarch64_sub_x_imm(
            14,
            15,
            AARCH64_SVE_MIN_VECTOR_BYTES,
        )?)?;
        assembler.branch_zero_w(14, asimd_setup)?;
        assembler.branch(sve_setup)?;
    } else if use_sve {
        assembler.instruction(aarch64_sve_cntb(15)?)?;
        assembler.branch(sve_setup)?;
    } else if use_asimd {
        assembler.branch(asimd_setup)?;
    } else {
        assembler.branch(scalar)?;
    }

    if use_sve {
        assembler.bind(sve_setup)?;
        aarch64_emit_sve_filter_setup(&mut assembler, filter, sve_kind, 0)?;
        assembler.bind(sve_scan)?;
        assembler.instruction(aarch64_sve_ptrue_b())?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x(12, 15)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(&mut assembler, 0)?;
        assembler.instruction(aarch64_sve_ld1b_vl(0, 12, 0)?)?;
        aarch64_emit_sve_filter_candidates(
            &mut assembler,
            filter,
            sve_kind,
            0,
            0,
            1,
            2,
            3,
        )?;
        assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
        assembler.branch_cond(AARCH64_NE, matched)?;
        assembler.instruction(aarch64_sve_addvl(2, 2, 1)?)?;
        assembler.branch(sve_scan)?;
    }

    if use_asimd {
        assembler.bind(asimd_setup)?;
        aarch64_emit_start_filter_constants(
            &mut assembler,
            filter,
            AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
        )?;
        assembler.bind(asimd_scan)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x_imm(12, 16)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(&mut assembler, 0)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        aarch64_emit_start_filter_vector_test(&mut assembler, filter, 0, 24)?;
        assembler.branch_cond(AARCH64_NE, matched)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(asimd_scan)?;
    }

    assembler.bind(scalar)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, no_match)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
    for range in filter.ranges() {
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.start))?)?;
        assembler.branch_cond(AARCH64_EQ, matched)?;
    }
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(scalar)?;

    assembler.bind(matched)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(no_match)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.instruction(0xd65f_03c0)?;

    let code = assembler.finish_with_offsets(&mut relocation_offsets)?;
    let relocations = if use_sve2 {
        vec![
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(
                    relocation_offsets[0],
                    "AArch64 atomic-byte Choice page",
                )?,
                kind: RelocationKind::Aarch64Page21,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(
                    relocation_offsets[1],
                    "AArch64 atomic-byte Choice pageoff",
                )?,
                kind: RelocationKind::Aarch64PageOff12,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
        ]
    } else {
        Vec::new()
    };
    Ok((code, data, relocations, accelerator))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeSingleLiteralLayout {
    literal_len: u32,
    failure_offset: u32,
    prefilter: NativeStartFilter,
    lane_index_offset: Option<u32>,
}

fn lower_single_literal_exists_choice(
    choice: NativeFiniteExistsChoiceView<'_>,
    target: Target,
    max_native_data_bytes: usize,
    incumbent: Option<NativeProgramView<'_>>,
) -> Result<Option<NativeLowering>, ObjectError> {
    let [literal] = choice.literals() else {
        return Err(ObjectError::InvalidModule(
            "single-literal Choice does not own exactly one literal",
        ));
    };
    if literal.len() < 2
        || choice.minimum_width() != choice.maximum_width()
        || usize::try_from(choice.minimum_width()).ok() != Some(literal.len())
        || choice.total_source_bytes() != literal.len()
    {
        return Err(ObjectError::InvalidModule(
            "single-literal Choice dimensions are inconsistent",
        ));
    }
    let Some((layout, data)) = materialize_single_literal_data(
        literal,
        target,
        max_native_data_bytes,
    )? else {
        return Ok(None);
    };
    if !single_literal_preferred_to_incumbent(layout, incumbent)? {
        return Ok(None);
    }
    let (code, relocations, start_accelerator) = match target.architecture {
        Architecture::X86_64 => {
            let kind = x86_start_filter_kind(target.features);
            let (code, relocations) = lower_x86_64_single_literal_exists(layout, kind)?;
            let accelerator = match kind {
                X86StartFilterKind::Sse2 => StartAccelerator::X86Sse2,
                X86StartFilterKind::Avx2 => StartAccelerator::X86Avx2,
                X86StartFilterKind::Avx512Bw => StartAccelerator::X86Avx512Bw,
            };
            (code, relocations, accelerator)
        }
        Architecture::Aarch64 => {
            let (code, relocations, accelerator) =
                lower_aarch64_single_literal_exists(layout, target)?;
            (code, relocations, accelerator)
        }
    };
    Ok(Some(NativeLowering {
        code,
        data,
        relocations,
        slow_partial_table: None,
        needs_runtime: false,
        start_accelerator,
        anchored_prefix_filter_bytes: 0,
    }))
}

/// Keep KMP as a resource-fallback route unless the complete incumbent has no
/// stronger candidate proof. A literal of length at least two ordinarily
/// gives that incumbent multiple exact anchored columns (and sometimes a
/// correlated pair scanner); comparing only the frequency of KMP's one chosen
/// column would ignore that advantage. Fail closed whenever two selective
/// anchored positions survive. An unavailable incumbent remains the explicit
/// resource-fallback arm.
fn single_literal_preferred_to_incumbent(
    layout: NativeSingleLiteralLayout,
    incumbent: Option<NativeProgramView<'_>>,
) -> Result<bool, ObjectError> {
    let Some(incumbent) = incumbent else {
        return Ok(true);
    };
    if incumbent
        .anchored_prefix
        .sets()
        .iter()
        .filter(|set| set.cardinality() < 256)
        .take(2)
        .count()
        >= 2
    {
        return Ok(false);
    }
    let own_frequency = estimated_filter_frequency_units(layout.prefilter);
    let mut incumbent_frequency = BYTE_FREQUENCY_DENOMINATOR;
    if let Some(filter) = derive_start_filter(incumbent)? {
        incumbent_frequency = incumbent_frequency.min(estimated_filter_frequency_units(filter));
    }
    if let Some(suffix) = derive_suffix_filter(incumbent)? {
        incumbent_frequency =
            incumbent_frequency.min(estimated_filter_frequency_units(suffix.filter));
    }
    Ok(own_frequency <= incumbent_frequency)
}

fn materialize_single_literal_data(
    literal: &[u8],
    target: Target,
    max_native_data_bytes: usize,
) -> Result<Option<(NativeSingleLiteralLayout, Vec<u8>)>, ObjectError> {
    let literal_len = u32::try_from(literal.len())
        .map_err(|_| ObjectError::ArithmeticOverflow("single-literal Choice width"))?;
    let scan_limit = literal.len().min(usize::from(u8::MAX) + 1);
    let (prefilter_offset, &prefilter_byte) = literal[..scan_limit]
        .iter()
        .enumerate()
        .min_by_key(|&(offset, &byte)| {
            (
                estimated_byte_frequency_units(byte),
                byte_frequency_rank(byte),
                u8::MAX.saturating_sub(u8::try_from(offset).unwrap_or(u8::MAX)),
            )
        })
        .ok_or(ObjectError::InvalidModule(
            "single-literal Choice has no prefilter byte",
        ))?;
    let prefilter_offset = u8::try_from(prefilter_offset)
        .map_err(|_| ObjectError::ArithmeticOverflow("single-literal prefilter offset"))?;
    let mut membership = [0_u64; 4];
    let byte = usize::from(prefilter_byte);
    membership[byte / 64] |= 1_u64 << (byte % 64);
    let prefilter = filter_from_membership_words(
        membership,
        usize::from(prefilter_offset),
        true,
    )?
    .ok_or(ObjectError::InvalidModule(
        "single-literal Choice prefilter is not representable",
    ))?;

    let failure_offset = literal
        .len()
        .checked_add(3)
        .map(|offset| offset & !3)
        .ok_or(ObjectError::ArithmeticOverflow(
            "single-literal failure alignment",
        ))?;
    let failure_bytes = literal.len().checked_mul(4).ok_or(
        ObjectError::ArithmeticOverflow("single-literal failure bytes"),
    )?;
    let mut required = failure_offset.checked_add(failure_bytes).ok_or(
        ObjectError::ArithmeticOverflow("single-literal data extent"),
    )?;
    let lane_index_offset = if target.architecture == Architecture::Aarch64
        && target.features.has(CpuFeature::Aarch64Asimd)
    {
        let aligned = required
            .checked_add(15)
            .map(|offset| offset & !15)
            .ok_or(ObjectError::ArithmeticOverflow(
                "single-literal lane-index alignment",
            ))?;
        required = aligned.checked_add(AARCH64_FIRST_LANE_INDEX.len()).ok_or(
            ObjectError::ArithmeticOverflow("single-literal lane-index extent"),
        )?;
        Some(
            u32::try_from(aligned)
                .map_err(|_| ObjectError::ArithmeticOverflow("single-literal lane index"))?,
        )
    } else {
        None
    };
    if required > max_native_data_bytes
        || u32::try_from(failure_offset).is_err()
        || target.architecture == Architecture::X86_64 && i32::try_from(failure_offset).is_err()
    {
        return Ok(None);
    }

    let mut failure = Vec::new();
    if failure.try_reserve_exact(literal.len()).is_err() {
        return Ok(None);
    }
    failure.resize(literal.len(), 0_u32);
    let mut matched = 0_usize;
    for index in 1..literal.len() {
        while matched != 0 && literal[matched] != literal[index] {
            matched = usize::try_from(failure[matched - 1]).map_err(|_| {
                ObjectError::ArithmeticOverflow("single-literal failure state")
            })?;
        }
        if literal[matched] == literal[index] {
            matched = matched.checked_add(1).ok_or(ObjectError::ArithmeticOverflow(
                "single-literal failure state",
            ))?;
        }
        failure[index] = u32::try_from(matched)
            .map_err(|_| ObjectError::ArithmeticOverflow("single-literal failure state"))?;
    }

    let mut data = Vec::new();
    if data.try_reserve_exact(required).is_err() {
        return Ok(None);
    }
    data.extend_from_slice(literal);
    data.resize(failure_offset, 0);
    for state in failure {
        data.extend_from_slice(&state.to_le_bytes());
    }
    if let Some(lane_index_offset) = lane_index_offset {
        data.resize(usize::try_from(lane_index_offset).map_err(|_| {
            ObjectError::ArithmeticOverflow("single-literal lane index")
        })?, 0);
        data.extend_from_slice(&AARCH64_FIRST_LANE_INDEX);
    }
    if data.len() != required {
        return Err(ObjectError::InvalidModule(
            "single-literal Choice data changed extent",
        ));
    }
    Ok(Some((
        NativeSingleLiteralLayout {
            literal_len,
            failure_offset: u32::try_from(failure_offset).map_err(|_| {
                ObjectError::ArithmeticOverflow("single-literal failure offset")
            })?,
            prefilter,
            lane_index_offset,
        },
        data,
    )))
}

fn lower_x86_64_single_literal_exists(
    layout: NativeSingleLiteralLayout,
    kind: X86StartFilterKind,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    if layout.literal_len < 2
        || layout.prefilter.ranges().len() != 1
        || !layout.prefilter.is_exact()
        || layout.prefilter.candidate_bytes != 1
    {
        return Err(ObjectError::InvalidModule(
            "x86 single-literal Choice layout is malformed",
        ));
    }
    let failure_offset = i32::try_from(layout.failure_offset)
        .map_err(|_| ObjectError::InvalidModule("x86 single-literal failure offset"))?;
    let prefilter_byte = layout.prefilter.ranges()[0].start;
    let mut assembler = X86Assembler::new();
    let vector = assembler.label()?;
    let vector_hit = assembler.label()?;
    let scalar = assembler.label()?;
    let kmp = assembler.label()?;
    let compare = assembler.label()?;
    let advance = assembler.label()?;
    let consume = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let returned = assembler.label()?;
    let invalid = assembler.label()?;

    x86_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;
    assembler.instruction(&[0x4c, 0x8d, 0x0d])?;
    let program_displacement = assembler.label()?;
    assembler.bind(program_displacement)?;
    push_bytes(&mut assembler.code, &[0; 4])?;
    let mut failure_base = vec![0x4d, 0x8d, 0x99]; // lea failure(r9), r11
    failure_base.extend_from_slice(&failure_offset.to_le_bytes());
    assembler.instruction(&failure_base)?;
    let mut width = vec![0x41, 0xb8]; // mov width, r8d
    width.extend_from_slice(&layout.literal_len.to_le_bytes());
    assembler.instruction(&width)?;
    assembler.instruction(&[0x45, 0x31, 0xd2])?; // q = 0
    x86_emit_start_filter_constants(&mut assembler, layout.prefilter, kind, 1)?;

    assembler.bind(vector)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
    assembler.instruction(&[0x4c, 0x39, 0xc0])?; // remaining < width?
    assembler.branch(&[0x0f, 0x82], no_match)?;
    assembler.instruction(&[0x4c, 0x29, 0xc0])?; // candidate count - 1
    assembler.instruction(&[0x48, 0x83, 0xf8, kind.width() - 1])?;
    assembler.branch(&[0x0f, 0x82], scalar)?;
    let mask = x86_emit_start_filter_vector_test(&mut assembler, layout.prefilter, kind)?;
    assembler.branch(&[0x0f, 0x85], vector_hit)?;
    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    assembler.branch(&[0xe9], vector)?;
    assembler.bind(vector_hit)?;
    x86_emit_first_candidate_lane(&mut assembler, mask)?;
    assembler.instruction(&[0x48, 0x01, 0xc2])?;
    assembler.branch(&[0xe9], kmp)?;

    assembler.bind(scalar)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?;
    assembler.instruction(&[0x48, 0x29, 0xd0])?;
    assembler.instruction(&[0x4c, 0x39, 0xc0])?;
    assembler.branch(&[0x0f, 0x82], no_match)?;
    x86_emit_exact_byte_set_scalar_load(
        &mut assembler,
        u16::from(layout.prefilter.scan_offset),
    )?;
    assembler.instruction(&[0x3c, prefilter_byte])?;
    assembler.branch(&[0x0f, 0x84], kmp)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], vector)?;

    // Standard KMP consumes every byte at most once. Failure edges decrease
    // q without moving the input cursor, so scanner skips plus failure work
    // remain linear in the search-window length.
    assembler.bind(kmp)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x83], no_match)?;
    assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?; // haystack[position]
    assembler.bind(compare)?;
    assembler.instruction(&[0x43, 0x0f, 0xb6, 0x34, 0x11])?; // literal[q]
    assembler.instruction(&[0x39, 0xf0])?;
    assembler.branch(&[0x0f, 0x84], advance)?;
    assembler.instruction(&[0x4d, 0x85, 0xd2])?;
    assembler.branch(&[0x0f, 0x84], consume)?;
    assembler.instruction(&[0x47, 0x8b, 0x54, 0x93, 0xfc])?; // q = failure[q-1]
    assembler.branch(&[0xe9], compare)?;
    assembler.bind(advance)?;
    assembler.instruction(&[0x49, 0xff, 0xc2])?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.instruction(&[0x4d, 0x39, 0xc2])?;
    assembler.branch(&[0x0f, 0x84], matched)?;
    assembler.branch(&[0xe9], kmp)?;
    assembler.bind(consume)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(matched)?;
    assembler.instruction(&[0xb8, 1, 0, 0, 0])?;
    assembler.branch(&[0xe9], returned)?;
    assembler.bind(no_match)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.bind(returned)?;
    if kind.needs_vzeroupper() {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    assembler.instruction(&[0xc3])?;
    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 2, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;

    let finished = assembler.finish_with_label_offsets()?;
    let program_displacement = finished.label_offset(program_displacement)?;
    Ok((
        finished.code,
        vec![ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(
                program_displacement,
                "x86 single-literal Choice relocation",
            )?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        }],
    ))
}

fn lower_aarch64_single_literal_exists(
    layout: NativeSingleLiteralLayout,
    target: Target,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>, StartAccelerator), ObjectError> {
    if layout.literal_len < 2
        || layout.prefilter.ranges().len() != 1
        || !layout.prefilter.is_exact()
        || layout.prefilter.candidate_bytes != 1
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 single-literal Choice layout is malformed",
        ));
    }
    let scanner_isa = aarch64_primary_scanner_isa(
        target.operating_system,
        target.features,
        true,
    );
    let use_sve = aarch64_primary_scanner_uses_sve(scanner_isa);
    let use_mixed = matches!(scanner_isa, Aarch64PrimaryScannerIsa::SveWithAsimdVl16);
    let use_asimd = target.features.has(CpuFeature::Aarch64Asimd)
        && (!use_sve || use_mixed);
    let accelerator = if use_sve {
        StartAccelerator::Aarch64Sve
    } else if use_asimd {
        StartAccelerator::Aarch64Asimd
    } else {
        StartAccelerator::Scalar
    };
    let prefilter_byte = layout.prefilter.ranges()[0].start;

    let mut assembler = Aarch64Assembler::new();
    let dispatch = assembler.label()?;
    let sve_scan = assembler.label()?;
    let asimd_scan = assembler.label()?;
    let scalar = assembler.label()?;
    let kmp = assembler.label()?;
    let compare = assembler.label()?;
    let advance = assembler.label()?;
    let consume = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    aarch64_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    let program_page = assembler.instruction(0x9000_0005)?;
    let program_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;
    aarch64_set_table_address(&mut assembler, 11, layout.failure_offset)?;
    aarch64_load_u32_constant(&mut assembler, 10, layout.literal_len)?;
    assembler.instruction(aarch64_movz_x(9, 0, 0)?)?;
    if use_mixed {
        assembler.instruction(aarch64_sve_cntb(15)?)?;
        assembler.instruction(aarch64_sub_x_imm(14, 15, AARCH64_SVE_MIN_VECTOR_BYTES)?)?;
        assembler.instruction(aarch64_sve_dup_b_imm(16, prefilter_byte)?)?;
    } else if use_sve {
        assembler.instruction(aarch64_sve_cntb(15)?)?;
        assembler.instruction(aarch64_sve_dup_b_imm(16, prefilter_byte)?)?;
    } else if use_asimd {
        assembler.instruction(aarch64_movi_16b(16, prefilter_byte)?)?;
    }
    if use_asimd {
        aarch64_emit_first_lane_constants(
            &mut assembler,
            layout.lane_index_offset.ok_or(ObjectError::InvalidModule(
                "AArch64 single-literal Choice has no lane-index table",
            ))?,
        )?;
    }

    assembler.bind(dispatch)?;
    if use_mixed {
        assembler.branch_zero_w(14, asimd_scan)?;
        assembler.branch(sve_scan)?;
    } else if use_sve {
        assembler.branch(sve_scan)?;
    } else if use_asimd {
        assembler.branch(asimd_scan)?;
    } else {
        assembler.branch(scalar)?;
    }

    if use_sve {
        let sve_hit = assembler.label()?;
        assembler.bind(sve_scan)?;
        assembler.instruction(aarch64_sve_ptrue_b())?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x(12, 10)?)?;
        assembler.branch_cond(AARCH64_LO, no_match)?;
        assembler.instruction(aarch64_sub_x_reg(12, 12, 10)?)?;
        assembler.instruction(aarch64_add_x_imm(12, 12, 1)?)?;
        assembler.instruction(aarch64_cmp_x(12, 15)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(&mut assembler, layout.prefilter.scan_offset)?;
        assembler.instruction(aarch64_sve_ld1b_vl(0, 12, 0)?)?;
        assembler.instruction(aarch64_sve_cmpeq_b(1, 0, 16)?)?;
        assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
        assembler.branch_cond(AARCH64_NE, sve_hit)?;
        assembler.instruction(aarch64_sve_addvl(2, 2, 1)?)?;
        assembler.branch(sve_scan)?;
        assembler.bind(sve_hit)?;
        aarch64_emit_sve_first_candidate(&mut assembler, 1, kmp)?;
    }

    if use_asimd {
        let asimd_hit = assembler.label()?;
        assembler.bind(asimd_scan)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x(12, 10)?)?;
        assembler.branch_cond(AARCH64_LO, no_match)?;
        assembler.instruction(aarch64_sub_x_reg(12, 12, 10)?)?;
        assembler.instruction(aarch64_cmp_x_imm(12, 15)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(&mut assembler, layout.prefilter.scan_offset)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        assembler.instruction(aarch64_cmeq_16b(24, 0, 16)?)?;
        aarch64_emit_candidate_any(&mut assembler, 24)?;
        assembler.branch_cond(AARCH64_NE, asimd_hit)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(asimd_scan)?;
        assembler.bind(asimd_hit)?;
        aarch64_emit_first_candidate_lane(&mut assembler, 24)?;
        assembler.branch(kmp)?;
    }

    assembler.bind(scalar)?;
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    assembler.instruction(aarch64_cmp_x(12, 10)?)?;
    assembler.branch_cond(AARCH64_LO, no_match)?;
    aarch64_emit_start_filter_scalar_load(&mut assembler, layout.prefilter.scan_offset)?;
    assembler.instruction(aarch64_cmp_w_imm(8, u16::from(prefilter_byte))?)?;
    assembler.branch_cond(AARCH64_EQ, kmp)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(dispatch)?;

    assembler.bind(kmp)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, no_match)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
    assembler.bind(compare)?;
    assembler.instruction(aarch64_load_byte_reg(13, 5, 9)?)?;
    assembler.instruction(aarch64_cmp_w(8, 13)?)?;
    assembler.branch_cond(AARCH64_EQ, advance)?;
    assembler.branch_zero_x(9, consume)?;
    assembler.instruction(aarch64_sub_x_imm(12, 9, 1)?)?;
    assembler.instruction(aarch64_load_w_uxtw(9, 11, 12)?)?;
    assembler.branch(compare)?;
    assembler.bind(advance)?;
    assembler.instruction(aarch64_add_x_imm(9, 9, 1)?)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.instruction(aarch64_cmp_x(9, 10)?)?;
    assembler.branch_cond(AARCH64_EQ, matched)?;
    assembler.branch(kmp)?;
    assembler.bind(consume)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(dispatch)?;

    assembler.bind(matched)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(no_match)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.instruction(0xd65f_03c0)?;

    let mut offsets = [program_page, program_page_offset];
    let code = assembler.finish_with_offsets(&mut offsets)?;
    Ok((
        code,
        vec![
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(offsets[0], "AArch64 single-literal Choice page")?,
                kind: RelocationKind::Aarch64Page21,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(offsets[1], "AArch64 single-literal Choice pageoff")?,
                kind: RelocationKind::Aarch64PageOff12,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
        ],
        accelerator,
    ))
}

fn lower_universal_byte_exists(target: Target) -> Result<NativeLowering, ObjectError> {
    let (code, relocations) = match target.architecture {
        Architecture::X86_64 => lower_x86_64_universal_byte_exists()?,
        Architecture::Aarch64 => lower_aarch64_universal_byte_exists()?,
    };
    Ok(NativeLowering {
        code,
        // Keep the program symbol backed by one deterministic byte even
        // though this leaf needs no table relocation.
        data: vec![0],
        relocations,
        slow_partial_table: None,
        needs_runtime: false,
        start_accelerator: StartAccelerator::None,
        anchored_prefix_filter_bytes: 1,
    })
}

fn lower_x86_64_universal_byte_exists()
-> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = X86Assembler::new();
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    x86_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(&[0x31, 0xc0])?; // xor eax, eax
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;
    assembler.instruction(&[0x48, 0x39, 0xca])?; // start == end?
    assembler.branch(&[0x0f, 0x83], no_match)?;
    assembler.instruction(&[0xb8, 1, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;
    assembler.bind(no_match)?;
    assembler.instruction(&[0xc3])?;
    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 2, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;
    Ok((assembler.finish_with_label_offsets()?.code, Vec::new()))
}

fn lower_x86_64_exact_byte_exists(
    exact: NativeExactByteSet,
    storage: NativeExactByteSetStorage,
    vector_kind: Option<X86StartFilterKind>,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    if exact.scan_offset != 0 || !exact.is_valid() || storage.aarch64_lut_offset.is_some() {
        return Err(ObjectError::InvalidModule(
            "x86 exact-finite byte Choice storage is malformed",
        ));
    }
    let mut assembler = X86Assembler::new();
    let scalar = assembler.label()?;
    let scan = assembler.label()?;
    let lane_one = assembler.label()?;
    let lane_two = assembler.label()?;
    let lane_three = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let returned = assembler.label()?;
    let invalid = assembler.label()?;

    x86_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;
    assembler.instruction(&[0x4c, 0x8d, 0x0d])?;
    let program_displacement = assembler.label()?;
    assembler.bind(program_displacement)?;
    push_bytes(&mut assembler.code, &[0; 4])?;

    if let Some(kind) = vector_kind {
        x86_emit_exact_vector_constants(&mut assembler, storage, kind)?;
        assembler.bind(scan)?;
        assembler.instruction(&[0x48, 0x89, 0xc8])?;
        assembler.instruction(&[0x48, 0x29, 0xd0])?;
        let mut compare = vec![0x48, 0x3d];
        compare.extend_from_slice(&u32::from(kind.width()).to_le_bytes());
        assembler.instruction(&compare)?;
        assembler.branch(&[0x0f, 0x82], scalar)?;
        let mask = x86_emit_exact_vector_candidates(&mut assembler, kind, 0)?;
        x86_emit_candidate_nonzero(&mut assembler, mask)?;
        assembler.branch(&[0x0f, 0x85], matched)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        assembler.branch(&[0xe9], scan)?;
    } else {
        assembler.bind(scan)?;
        assembler.instruction(&[0x48, 0x89, 0xc8])?;
        assembler.instruction(&[0x48, 0x29, 0xd0])?;
        assembler.instruction(&[0x48, 0x83, 0xf8, 4])?;
        assembler.branch(&[0x0f, 0x82], scalar)?;
        x86_emit_exact_byte_set_scalar_load(&mut assembler, 0)?;
        x86_emit_exact_byte_set_test(&mut assembler, storage, matched)?;
        x86_emit_exact_byte_set_scalar_load(&mut assembler, 1)?;
        x86_emit_exact_byte_set_test(&mut assembler, storage, lane_one)?;
        x86_emit_exact_byte_set_scalar_load(&mut assembler, 2)?;
        x86_emit_exact_byte_set_test(&mut assembler, storage, lane_two)?;
        x86_emit_exact_byte_set_scalar_load(&mut assembler, 3)?;
        x86_emit_exact_byte_set_test(&mut assembler, storage, lane_three)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, 4])?;
        assembler.branch(&[0xe9], scan)?;
        assembler.bind(lane_three)?;
        assembler.bind(lane_two)?;
        assembler.bind(lane_one)?;
        assembler.branch(&[0xe9], matched)?;
    }

    assembler.bind(scalar)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x83], no_match)?;
    x86_emit_exact_byte_set_scalar_load(&mut assembler, 0)?;
    x86_emit_exact_byte_set_test(&mut assembler, storage, matched)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar)?;

    assembler.bind(matched)?;
    assembler.instruction(&[0xb8, 1, 0, 0, 0])?;
    assembler.branch(&[0xe9], returned)?;
    assembler.bind(no_match)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.bind(returned)?;
    if vector_kind.is_some_and(X86StartFilterKind::needs_vzeroupper) {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    assembler.instruction(&[0xc3])?;
    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 2, 0, 0, 0])?;
    assembler.instruction(&[0xc3])?;

    let finished = assembler.finish_with_label_offsets()?;
    let program_displacement = finished.label_offset(program_displacement)?;
    Ok((
        finished.code,
        vec![ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(
                program_displacement,
                "x86 exact-finite byte Choice relocation",
            )?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        }],
    ))
}

fn lower_aarch64_universal_byte_exists()
-> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = Aarch64Assembler::new();
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    aarch64_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, no_match)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(no_match)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.instruction(0xd65f_03c0)?;
    Ok((assembler.finish_with_offsets(&mut [])?, Vec::new()))
}

fn lower_aarch64_exact_byte_exists(
    exact: NativeExactByteSet,
    storage: NativeExactByteSetStorage,
    target: Target,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>, StartAccelerator), ObjectError> {
    if exact.scan_offset != 0
        || !exact.is_valid()
        || storage.aarch64_lut_offset != storage.bitmap_offset.checked_add(32)
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 exact-finite byte Choice storage is malformed",
        ));
    }
    let scanner_isa = aarch64_primary_scanner_isa(
        target.operating_system,
        target.features,
        true,
    );
    let sve_kind = selected_aarch64_exact_sve_kind(
        target.operating_system,
        target.features,
        storage,
    );
    let use_mixed = sve_kind.is_some()
        && matches!(scanner_isa, Aarch64PrimaryScannerIsa::SveWithAsimdVl16);
    let use_sve = sve_kind.is_some();
    let use_asimd = target.features.has(CpuFeature::Aarch64Asimd)
        && (!use_sve || use_mixed);
    let accelerator = if let Some(kind) = sve_kind {
        match kind {
            Aarch64ExactSveKind::Nibble => StartAccelerator::Aarch64Sve,
            Aarch64ExactSveKind::Sve2Match(_) => StartAccelerator::Aarch64Sve2,
        }
    } else if use_asimd {
        StartAccelerator::Aarch64Asimd
    } else {
        StartAccelerator::Scalar
    };

    let mut assembler = Aarch64Assembler::new();
    let sve_scan = assembler.label()?;
    let sve_partial = assembler.label()?;
    let asimd_setup = assembler.label()?;
    let asimd_scan = assembler.label()?;
    let scalar_setup = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let matched = assembler.label()?;
    let no_match = assembler.label()?;
    let invalid = assembler.label()?;
    aarch64_emit_public_search_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    let program_page = assembler.instruction(0x9000_0005)?;
    let program_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;

    if use_mixed {
        assembler.instruction(aarch64_sve_cntb(16)?)?;
        assembler.instruction(aarch64_cmp_x_imm(16, AARCH64_SVE_MIN_VECTOR_BYTES)?)?;
        assembler.branch_cond(AARCH64_EQ, asimd_setup)?;
    }
    if let Some(kind) = sve_kind {
        aarch64_emit_exact_sve_constants(&mut assembler, storage, kind)?;
        assembler.bind(sve_scan)?;
        assembler.instruction(aarch64_sve_ptrue_b())?;
        assembler.instruction(aarch64_sve_cntb(6)?)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x(12, 6)?)?;
        assembler.branch_cond(AARCH64_LO, sve_partial)?;
        aarch64_emit_exact_sve_candidates(&mut assembler, kind, 0)?;
        assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
        assembler.branch_cond(AARCH64_NE, matched)?;
        assembler.instruction(aarch64_sve_addvl(2, 2, 1)?)?;
        assembler.branch(sve_scan)?;
        assembler.bind(sve_partial)?;
        assembler.instruction(aarch64_cmp_x(2, 3)?)?;
        assembler.branch_cond(AARCH64_HS, no_match)?;
        assembler.instruction(aarch64_sve_whilelo_b(0, 2, 3)?)?;
        aarch64_emit_exact_sve_candidates(&mut assembler, kind, 0)?;
        assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
        assembler.branch_cond(AARCH64_NE, matched)?;
        assembler.branch(no_match)?;
    }

    if use_asimd {
        assembler.bind(asimd_setup)?;
        aarch64_emit_exact_asimd_constants(&mut assembler, storage)?;
        assembler.bind(asimd_scan)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x_imm(12, 16)?)?;
        assembler.branch_cond(AARCH64_LO, scalar_setup)?;
        aarch64_emit_exact_asimd_candidates(&mut assembler, 0)?;
        assembler.branch_cond(AARCH64_NE, matched)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(asimd_scan)?;
    }

    assembler.bind(scalar_setup)?;
    aarch64_set_table_address(
        &mut assembler,
        6,
        storage.aarch64_lut_offset.ok_or(ObjectError::InvalidModule(
            "AArch64 exact-finite byte Choice has no scalar LUT",
        ))?,
    )?;
    assembler.bind(scalar_scan)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, no_match)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
    aarch64_emit_exact_byte_set_lut_test(&mut assembler, 6, matched)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(scalar_scan)?;

    assembler.bind(matched)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(no_match)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.instruction(0xd65f_03c0)?;

    let mut offsets = [program_page, program_page_offset];
    let code = assembler.finish_with_offsets(&mut offsets)?;
    Ok((
        code,
        vec![
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(offsets[0], "AArch64 exact-finite byte Choice page")?,
                kind: RelocationKind::Aarch64Page21,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(offsets[1], "AArch64 exact-finite byte Choice pageoff")?,
                kind: RelocationKind::Aarch64PageOff12,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
        ],
        accelerator,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompileMode, CompileRequest, MatchResult, ObjectFormat, SearchWindow, compile,
        emit_object,
    };

    fn byte_choice_program() -> crate::CompiledRegex {
        compile(
            CompileRequest::new("a|z", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile exact-finite byte Choice fixture")
    }

    fn byte_choice_program_for(pattern: &str) -> crate::CompiledRegex {
        compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile exact-finite byte Choice fixture")
    }

    #[test]
    fn atomic_byte_filter_keeps_adjacent_members_as_equalities() {
        let mut membership = [0_u64; 4];
        for byte in [b'a', b'b', b'c'] {
            let byte = usize::from(byte);
            membership[byte / 64] |= 1_u64 << (byte % 64);
        }
        let filter = exact_atomic_byte_filter(membership, 3).unwrap();
        assert!(filter.is_exact());
        assert_eq!(filter.candidate_bytes, 3);
        assert_eq!(
            filter.ranges(),
            [
                NativeByteRange {
                    start: b'a',
                    end: b'a',
                },
                NativeByteRange {
                    start: b'b',
                    end: b'b',
                },
                NativeByteRange {
                    start: b'c',
                    end: b'c',
                },
            ],
        );
    }

    #[test]
    fn atomic_byte_choice_uses_sve2_only_when_match_reduces_work() {
        let target = Target::aarch64_linux()
            .with_features(
                FeatureSet::of(CpuFeature::Aarch64Sve)
                    .with(CpuFeature::Aarch64Sve2),
            )
            .unwrap();
        for (pattern, expected, expected_relocations, expected_data) in [
            ("a", StartAccelerator::Aarch64Sve, 0, 1),
            ("a|b", StartAccelerator::Aarch64Sve2, 2, 16),
            ("a|b|c", StartAccelerator::Aarch64Sve2, 2, 16),
        ] {
            let compiled = byte_choice_program_for(pattern);
            let choice = compiled
                .program()
                .native_finite_exists_choice_view()
                .expect("authenticated byte Choice");
            let incumbent = compiled.program().native_dfa_view().unwrap();
            let lowering =
                lower_atomic_exists_choice(choice, target, usize::MAX, Some(incumbent))
                    .unwrap()
                    .expect("small exact byte Choice");
            assert_eq!(lowering.start_accelerator, expected, "{pattern}");
            assert_eq!(lowering.relocations.len(), expected_relocations, "{pattern}");
            assert_eq!(lowering.data.len(), expected_data, "{pattern}");
        }
    }

    #[test]
    fn arbitrary_byte_set_declines_a_moving_incumbent() {
        let compiled = byte_choice_program_for("a|c|e|g");
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated arbitrary byte Choice");
        let incumbent = compiled.program().native_dfa_view().unwrap();
        let target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        assert!(
            lower_atomic_exists_choice(choice, target, usize::MAX, Some(incumbent))
                .unwrap()
                .is_none(),
            "arbitrary classifier displaced a graph-derived scanner",
        );
        assert!(
            lower_atomic_exists_choice(choice, target, usize::MAX, None)
                .unwrap()
                .is_some(),
            "arbitrary classifier was unavailable as a resource fallback",
        );
    }

    #[test]
    fn byte_choice_target_portfolio_is_structural_and_exact() {
        let compiled = byte_choice_program();
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated byte Choice");
        let incumbent = compiled
            .program()
            .native_dfa_view()
            .expect("complete incumbent DFA");
        let cases = [
            (Target::x86_64_linux(), StartAccelerator::X86Sse2),
            (
                Target::x86_64_linux()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                StartAccelerator::X86Avx2,
            ),
            (
                Target::x86_64_linux().with_features(
                    FeatureSet::of(CpuFeature::X86Avx512F)
                        .with(CpuFeature::X86Avx512Bw),
                ).unwrap(),
                StartAccelerator::X86Avx512Bw,
            ),
            (
                Target::aarch64_macos()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
                StartAccelerator::Aarch64Asimd,
            ),
            (
                Target::aarch64_linux()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
                    .unwrap(),
                StartAccelerator::Aarch64Sve,
            ),
            (
                Target::aarch64_linux().with_features(
                    FeatureSet::of(CpuFeature::Aarch64Sve)
                        .with(CpuFeature::Aarch64Sve2),
                ).unwrap(),
                StartAccelerator::Aarch64Sve2,
            ),
            (
                Target::aarch64_linux().with_features(
                    FeatureSet::of(CpuFeature::Aarch64Asimd)
                        .with(CpuFeature::Aarch64Sve),
                ).unwrap(),
                StartAccelerator::Aarch64Sve,
            ),
            (
                Target::aarch64_linux().with_features(
                    FeatureSet::of(CpuFeature::Aarch64Asimd)
                        .with(CpuFeature::Aarch64Sve)
                        .with(CpuFeature::Aarch64Sve2),
                ).unwrap(),
                StartAccelerator::Aarch64Sve2,
            ),
        ];
        for (target, expected) in cases {
            let lowering = lower_atomic_exists_choice(choice, target, usize::MAX, Some(incumbent))
                .unwrap()
                .unwrap_or_else(|| panic!("target declined byte Choice: {target:?}"));
            assert_eq!(lowering.start_accelerator, expected, "{target:?}");
            assert!(!lowering.needs_runtime, "{target:?}");
            assert!(!lowering.code.is_empty(), "{target:?}");
            assert!(!lowering.data.is_empty(), "{target:?}");
            assert_eq!(
                lowering.relocations.len(),
                if expected == StartAccelerator::Aarch64Sve2 {
                    2
                } else {
                    0
                },
                "{target:?}",
            );
            if target.architecture == Architecture::Aarch64 {
                let words = lowering
                    .code
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                if expected == StartAccelerator::Aarch64Sve2 {
                    assert!(
                        words.contains(&aarch64_sve2_match_b(1, 0, 16).unwrap()),
                        "{target:?}",
                    );
                } else if expected == StartAccelerator::Aarch64Sve {
                    assert!(
                        words.contains(&aarch64_sve_cmpeq_b(1, 0, 16).unwrap()),
                        "{target:?}",
                    );
                }
                if target.features.has(CpuFeature::Aarch64Asimd)
                    && target.features.has(CpuFeature::Aarch64Sve)
                {
                    assert!(words.contains(&aarch64_sve_cntb(15).unwrap()), "{target:?}");
                    assert!(
                        words.contains(&aarch64_cmeq_16b(24, 0, 16).unwrap()),
                        "{target:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn byte_choice_is_selected_and_obeys_native_data_limit() {
        let target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let compiled = compile(
            CompileRequest::new("a|z", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile selected byte Choice");
        assert_eq!(compiled.receipt().start_accelerator, StartAccelerator::X86Avx2);
        assert!(compiled.module().required_runtime_symbol().is_none());

        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated selected Choice");
        let incumbent = compiled.program().native_dfa_view().unwrap();
        let selected = lower_atomic_exists_choice(choice, target, usize::MAX, Some(incumbent))
            .unwrap()
            .unwrap();
        assert!(!selected.data.is_empty());
        assert!(
            lower_atomic_exists_choice(
                choice,
                target,
                selected.data.len().checked_sub(1).unwrap(),
                Some(incumbent),
            )
            .unwrap()
            .is_none(),
        );
    }

    fn single_choice_program(pattern: &str) -> crate::CompiledRegex {
        compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile single-literal Choice fixture")
    }

    #[test]
    fn single_literal_choice_builds_exact_kmp_and_all_target_scanners() {
        let compiled = single_choice_program("ababaca");
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated single-literal Choice");
        assert_eq!(choice.kind(), NativeFiniteExistsChoiceKind::SingleLiteral);
        let cases = [
            (Target::x86_64_linux(), StartAccelerator::X86Sse2),
            (
                Target::x86_64_linux()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                StartAccelerator::X86Avx2,
            ),
            (
                Target::x86_64_linux()
                    .with_features(
                        FeatureSet::of(CpuFeature::X86Avx512F)
                            .with(CpuFeature::X86Avx512Bw),
                    )
                    .unwrap(),
                StartAccelerator::X86Avx512Bw,
            ),
            (
                Target::aarch64_macos()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
                StartAccelerator::Aarch64Asimd,
            ),
            (
                Target::aarch64_linux()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
                    .unwrap(),
                StartAccelerator::Aarch64Sve,
            ),
            (
                Target::aarch64_linux()
                    .with_features(
                        FeatureSet::of(CpuFeature::Aarch64Sve)
                            .with(CpuFeature::Aarch64Sve2),
                    )
                    .unwrap(),
                // Equality already has a single-instruction base-SVE
                // classifier; SVE2 MATCH cannot reduce it further.
                StartAccelerator::Aarch64Sve,
            ),
        ];
        for (target, expected) in cases {
            let lowering = lower_atomic_exists_choice(choice, target, usize::MAX, None)
                .unwrap()
                .unwrap_or_else(|| panic!("target declined single literal: {target:?}"));
            assert_eq!(lowering.start_accelerator, expected, "{target:?}");
            assert!(!lowering.needs_runtime, "{target:?}");
            assert_eq!(
                lowering.relocations.len(),
                if target.architecture == Architecture::X86_64 { 1 } else { 2 },
            );

            let (layout, data) = materialize_single_literal_data(
                b"ababaca",
                target,
                usize::MAX,
            )
            .unwrap()
            .unwrap();
            let failure = data[usize::try_from(layout.failure_offset).unwrap()
                ..usize::try_from(layout.failure_offset).unwrap() + 7 * 4]
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            assert_eq!(failure, [0, 0, 1, 2, 3, 0, 1]);
            assert_eq!(layout.prefilter.ranges()[0].start, b'b');
            assert_eq!(layout.prefilter.scan_offset, 3);
        }
    }

    #[test]
    fn single_literal_choice_competes_and_data_is_bounded() {
        let target = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let compiled = compile(
            CompileRequest::new("ababaca", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated selected single literal");
        let incumbent = compiled.program().native_dfa_view().unwrap();
        assert!(
            lower_atomic_exists_choice(choice, target, usize::MAX, Some(incumbent))
                .unwrap()
                .is_none(),
            "one-column KMP displaced a multicolumn complete scanner",
        );
        let selected = lower_atomic_exists_choice(choice, target, usize::MAX, None)
            .unwrap()
            .expect("resource-fallback single-literal lowering");
        assert_eq!(compiled.receipt().start_accelerator, StartAccelerator::X86Avx2);
        assert!(compiled.module().required_runtime_symbol().is_none());
        assert!(
            lower_atomic_exists_choice(
                choice,
                target,
                selected.data.len() - 1,
                None,
            )
            .unwrap()
            .is_none(),
        );
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes exact-finite byte Choice objects on the host ISA"]
    fn linked_host_byte_choice_matches_portable_for_every_window() {
        use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

        let target = if cfg!(target_arch = "x86_64") {
            let base = if cfg!(target_os = "linux") {
                Target::x86_64_linux()
            } else {
                Target::x86_64_macos()
            };
            base.with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap()
        } else {
            let base = if cfg!(target_os = "linux") {
                Target::aarch64_linux()
            } else {
                Target::aarch64_macos()
            };
            base.with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
        };
        for (case, pattern) in ["a", "a|z", "a|b|z"].into_iter().enumerate() {
        let compiled = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile host byte Choice");
        assert!(compiled.module().required_runtime_symbol().is_none());
        let reference = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile portable byte Choice reference");

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-byte-choice-{}-{case}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).unwrap();
        let object = directory.join("choice.o");
        fs::write(&object, compiled.object()).unwrap();
        let symbol = compiled.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\nint main(void){{size_t r[2];uint32_t s;\n",
        );
        let haystacks: &[&[u8]] = &[
            b"",
            b"a",
            b"b",
            b"z",
            b"qqqqqqqqqqqqqqq",
            b"qqqqqqqqqqqqqqqa",
            b"qqqqqqqqqqqqqqqqzqqqqqqqqqqqqqqq",
        ];
        for (index, haystack) in haystacks.iter().enumerate() {
            let bytes = if haystack.is_empty() {
                "0".to_owned()
            } else {
                haystack.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
            };
            writeln!(source, "static const unsigned char h{index}[]={{{bytes}}};").unwrap();
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let MatchResult::Exists(expected) = reference
                        .search(haystack, SearchWindow::new(start, end))
                        .unwrap()
                    else {
                        unreachable!();
                    };
                    writeln!(
                        source,
                        "r[0]=91;r[1]=92;s={symbol}(h{index},{},{start},{end},r);if(s!={}||r[0]!=0||r[1]!=0)return {};",
                        haystack.len(),
                        u8::from(expected),
                        10 + index,
                    )
                    .unwrap();
                }
            }
        }
        writeln!(
            source,
            "r[0]=93;r[1]=94;s={symbol}(h0,(size_t)-1,0,0,r);if(s!=2||r[0]!=93||r[1]!=94)return 90;return 0;}}",
        )
        .unwrap();
        let c_path = directory.join("choice.c");
        let executable = directory.join("choice");
        fs::write(&c_path, source).unwrap();
        let compiler = if cfg!(target_os = "macos") { "clang" } else { "cc" };
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("link byte Choice differential");
        assert!(status.success());
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        fs::remove_dir_all(&directory).unwrap();
        }
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes the worst-case-linear single-literal Choice on the host ISA"]
    fn linked_host_single_literal_choice_matches_portable_for_every_window() {
        use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

        let target = if cfg!(target_arch = "x86_64") {
            let base = if cfg!(target_os = "linux") {
                Target::x86_64_linux()
            } else {
                Target::x86_64_macos()
            };
            base.with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap()
        } else {
            let base = if cfg!(target_os = "linux") {
                Target::aarch64_linux()
            } else {
                Target::aarch64_macos()
            };
            base.with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
        };
        let pattern = "ababaca";
        let compiled = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated host single-literal Choice");
        let lowering = lower_atomic_exists_choice(choice, target, usize::MAX, None)
            .unwrap()
            .expect("host resource-fallback single-literal lowering");
        let module = CompiledModule::lower_serialized_with_prelowered(
            compiled.program().serialize().unwrap(),
            Some(lowering),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            target,
        )
        .unwrap();
        assert!(module.required_runtime_symbol().is_none());
        let reference = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-single-choice-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).unwrap();
        let object = directory.join("choice.o");
        fs::write(
            &object,
            emit_object(&module, ObjectFormat::for_target(target), usize::MAX).unwrap(),
        )
        .unwrap();
        let symbol = module.entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\nint main(void){{size_t r[2];uint32_t s;\n",
        );
        let haystacks: &[&[u8]] = &[
            b"",
            b"ababaca",
            b"abababababababababababab",
            b"zzzzzzzzzzzzzzzzababaca",
            b"abababacababacaabababaca",
            b"cccccccccccccccccccccccc",
        ];
        for (index, haystack) in haystacks.iter().enumerate() {
            let bytes = if haystack.is_empty() {
                "0".to_owned()
            } else {
                haystack.iter().map(u8::to_string).collect::<Vec<_>>().join(",")
            };
            writeln!(source, "static const unsigned char h{index}[]={{{bytes}}};").unwrap();
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let MatchResult::Exists(expected) = reference
                        .search(haystack, SearchWindow::new(start, end))
                        .unwrap()
                    else {
                        unreachable!();
                    };
                    writeln!(
                        source,
                        "r[0]=91;r[1]=92;s={symbol}(h{index},{},{start},{end},r);if(s!={}||r[0]!=0||r[1]!=0)return {};",
                        haystack.len(),
                        u8::from(expected),
                        20 + index,
                    )
                    .unwrap();
                }
            }
        }
        writeln!(
            source,
            "r[0]=93;r[1]=94;s={symbol}(h0,(size_t)-1,0,0,r);if(s!=2||r[0]!=93||r[1]!=94)return 90;return 0;}}",
        )
        .unwrap();
        let c_path = directory.join("choice.c");
        let executable = directory.join("choice");
        fs::write(&c_path, source).unwrap();
        let compiler = if cfg!(target_os = "macos") { "clang" } else { "cc" };
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap();
        assert!(status.success());
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        fs::remove_dir_all(&directory).unwrap();
    }

}
