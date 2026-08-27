//! Self-contained lowering for the bounded bit-parallel `Exists` executor.
//!
//! This backend consumes only the authenticated canonical graph view. It emits
//! target-aware root scanners and fixed-width transition unions for SSE2,
//! AVX2, AVX-512, ASIMD, SVE, and SVE2, while retaining a scalar recurrence
//! for feature-empty targets and dense roots. Feature selection changes only
//! lowering, never the route's publication proof.

use crate::{
    ObjectError,
    bit_parallel_exists::{
        BitParallelExists, MAX_BIT_PARALLEL_EXISTS_STATES, MAX_BIT_PARALLEL_EXISTS_WORDS,
        NativeBitParallelExistsView,
    },
};

use std::collections::BTreeMap;

use super::{
    AARCH64_EQ, AARCH64_HI, AARCH64_HS, AARCH64_LO, AARCH64_MI, AARCH64_NE,
    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT, Aarch64Assembler, Aarch64SveFilterKind, Architecture,
    CpuFeature, FeatureSet, MAX_SCALAR_REFINEMENT_PRIMARY_FREQUENCY_UNITS, ModuleRelocation,
    NativeLowering, NativeStartFilter, OperatingSystem, PROGRAM_SYMBOL, RelocationKind,
    StartAccelerator, TEXT_SECTION, Target, X86Assembler, X86CandidateMask, aarch64_add_x_imm,
    aarch64_add_x_reg, aarch64_and_low_x, aarch64_cmp_x, aarch64_emit_candidate_any,
    aarch64_emit_candidate_batch_any, aarch64_emit_first_candidate_in_batch,
    aarch64_emit_first_candidate_lane, aarch64_emit_first_lane_constants,
    aarch64_emit_scalar_filter_membership, aarch64_emit_start_filter_address,
    aarch64_emit_start_filter_batch_candidates, aarch64_emit_start_filter_constants,
    aarch64_emit_start_filter_scalar_bound, aarch64_emit_start_filter_vector_candidates,
    aarch64_emit_sve_filter_setup, aarch64_emit_sve_start_filter_scanner, aarch64_load_byte_reg,
    aarch64_load_q, aarch64_load_u64_constant, aarch64_load_x_lsl3, aarch64_lsr_x_imm,
    aarch64_mov_x, aarch64_movz_w, aarch64_orr_16b, aarch64_reg, aarch64_store_x,
    estimated_filter_frequency_units, filter_from_membership_words, offset_u64, push_bytes,
    x86_emit_first_candidate_lane, x86_emit_scalar_filter_membership,
    x86_emit_start_filter_constants, x86_emit_start_filter_scalar_bound,
    x86_emit_start_filter_vector_candidate, x86_range_scanner_emission, x86_start_filter_kind,
};

const BYTE_VALUES: usize = 256;
const CLASSIFIER_ENTRY_BYTES: usize = core::mem::size_of::<u32>();
const CLASSIFIER_BYTES: usize = BYTE_VALUES * CLASSIFIER_ENTRY_BYTES;
const NIBBLE_BITS: usize = 4;
const NIBBLE_SUBSETS: usize = 1 << NIBBLE_BITS;
const NIBBLE_ROW_BYTES: usize = NIBBLE_SUBSETS * core::mem::size_of::<u64>();
const ACCEPT_BIT: u64 = 1_u64 << 63;
const CONSUMING_BITS: u64 = ACCEPT_BIT - 1;

// This prototype is deliberately narrower than semantic compilability. A
// root-departure set wider than one eighth of the alphabet makes recurrence
// replay common enough that publication must remain with the prepared K0
// runtime until a stronger cost model proves otherwise.
const MAX_ROOT_SKIP_CANDIDATE_BYTES: u16 = 32;
const ROOT_SKIP_FIRST_LANE_BYTES: usize = 16;
const NATIVE_STATE_VECTOR_BYTES: usize = MAX_BIT_PARALLEL_EXISTS_WORDS * 8;
const MULTIWORD_ROOT_VECTOR_OFFSET: usize = CLASSIFIER_BYTES;
const MULTIWORD_ACCEPT_VECTOR_OFFSET: usize =
    MULTIWORD_ROOT_VECTOR_OFFSET + NATIVE_STATE_VECTOR_BYTES;
const MULTIWORD_ROOT_ROWS_OFFSET: usize =
    MULTIWORD_ACCEPT_VECTOR_OFFSET + NATIVE_STATE_VECTOR_BYTES;

// The sidecar itself proves a tighter retained-memory ceiling. These native
// caps independently bound object growth and make a failed optional lowering
// fall back to the serialized runtime route.
const MAX_NATIVE_BIT_PARALLEL_DATA_BYTES: usize = 4 * 1024 * 1024 + ROOT_SKIP_FIRST_LANE_BYTES * 2;
// Hybrid admission reserves the maximum scanner suffix inside the original
// 4 MiB table budget. Keep that stricter bound local to hybrid layouts so a
// graph that selects no subset sources retains the exact parent resource cap.
const MAX_NATIVE_BIT_PARALLEL_HYBRID_DATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_NATIVE_BIT_PARALLEL_CODE_BYTES: usize = 8 * 1024;

// Hybrid multiword rows are selected from an input-independent Cesaro model
// over the canonical byte classes. The finite distribution is exact until
// either bound is reached; a graph that exceeds either bound simply retains
// direct rows everywhere.
const MULTIWORD_ACTIVITY_WARMUP_STEPS: usize = 4;
const MULTIWORD_ACTIVITY_SAMPLE_STEPS: usize = 20;
const MAX_MULTIWORD_ACTIVITY_FRONTIERS: usize = 4_096;
const MAX_MULTIWORD_ACTIVITY_ROW_UNIONS: usize = 16_000_000;
const MULTIWORD_ACTIVITY_PROBABILITY_SCALE: u64 = 1_u64 << 32;
// One subset union has more scalar address-generation work than one direct
// row. Requiring at least seven direct rows for every four subset rows is a
// target-neutral, deliberately conservative admission threshold.
const SUBSET_ROW_DIRECT_COST_NUMERATOR: i128 = 7;
const SUBSET_ROW_DIRECT_COST_DENOMINATOR: i128 = 4;

#[derive(Debug)]
struct NativeBitParallelLayout {
    data: Vec<u8>,
    root: u64,
    roots: [u64; MAX_BIT_PARALLEL_EXISTS_WORDS],
    words: usize,
    consuming_states: usize,
    direct_row_words: usize,
    source_row_offsets: [u32; MAX_BIT_PARALLEL_EXISTS_WORDS],
    source_row_nibbles: [u8; MAX_BIT_PARALLEL_EXISTS_WORDS],
    subset_source_mask: u8,
    source_nibbles: usize,
    constant_result: Option<bool>,
    root_filter: Option<NativeStartFilter>,
    first_lane_table_offset: Option<u32>,
    sve2_match_table_offset: Option<u32>,
    root_vector_offset: Option<u32>,
    accept_vector_offset: Option<u32>,
}

#[derive(Debug)]
struct NativeBitParallelEmission {
    code: Vec<u8>,
    relocations: Vec<ModuleRelocation>,
    emitted_nibbles: usize,
    emitted_words: usize,
    matched_cursor: NativeBitParallelMatchedCursor,
}

/// Authenticated private return register holding the one-past-byte boundary
/// when a native recurrence returns status one. Every backend advances this
/// cursor before testing the accept bit; endpoint composition consumes it
/// only after the lowering receipt agrees with the requested architecture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum NativeBitParallelMatchedCursor {
    X86Rdx,
    Aarch64X2,
}

pub(super) struct NativeBitParallelExactEndpointLowering {
    pub(super) lowering: NativeLowering,
    pub(super) matched_cursor: NativeBitParallelMatchedCursor,
}

struct NativeBitParallelLoweringReceipt {
    lowering: NativeLowering,
    matched_cursor: NativeBitParallelMatchedCursor,
}

fn aarch64_load_pair_q_signed(
    first_destination: u8,
    second_destination: u8,
    base: u8,
    byte_offset: i16,
) -> Result<u32, ObjectError> {
    if byte_offset % 16 != 0 || !(-1024..=1008).contains(&byte_offset) {
        return Err(ObjectError::InvalidModule("AArch64 signed LDP Q offset"));
    }
    let scaled = i32::from(byte_offset / 16);
    let immediate = u32::try_from(scaled & 0x7f)
        .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 signed LDP Q offset"))?;
    Ok(0xad40_0000
        | (immediate << 15)
        | aarch64_reg(second_destination, 10)?
        | aarch64_reg(base, 5)?
        | aarch64_reg(first_destination, 0)?)
}

fn admitted_root_scanner_filter(
    layout: &NativeBitParallelLayout,
    target: Target,
) -> Option<NativeStartFilter> {
    if layout.constant_result.is_some() {
        return None;
    }
    let filter = layout.root_filter?;
    if filter.candidate_bytes > MAX_ROOT_SKIP_CANDIDATE_BYTES
        || filter.constant_count() > 8
        || filter.ranges().is_empty()
    {
        return None;
    }
    if target.architecture == Architecture::Aarch64
        && !target.features.has(CpuFeature::Aarch64Asimd)
        && !(target.operating_system == OperatingSystem::Linux
            && target.features.has(CpuFeature::Aarch64Sve))
    {
        return None;
    }
    Some(filter)
}

fn admitted_standalone_one_word_exists(layout: &NativeBitParallelLayout, target: Target) -> bool {
    layout.constant_result.is_some()
        || layout.source_nibbles == 1
            && admitted_root_scanner_filter(layout, target).is_some_and(|filter| {
                estimated_filter_frequency_units(filter)
                    <= MAX_SCALAR_REFINEMENT_PRIMARY_FREQUENCY_UNITS
            })
}

fn admitted_standalone_exists(layout: &NativeBitParallelLayout, target: Target) -> bool {
    if layout.words == 1 {
        return admitted_standalone_one_word_exists(layout, target);
    }
    // A multiword root hit must leave the scanner and run a serial recurrence
    // across every represented word. Even a rare scanner therefore performs
    // poorly on true and near candidates. Recurrence-only multiword leaves do
    // not pay that scanner/refinement composition and remain available, while
    // endpoint compositions retain the complete layout independently below.
    admitted_root_scanner_filter(layout, target).is_none()
}

pub(super) fn lower_native_bit_parallel_exists(
    view: NativeBitParallelExistsView<'_>,
    target: Target,
) -> Result<Option<NativeLowering>, ObjectError> {
    let Some(layout) = build_native_bit_parallel_layout(view) else {
        return Ok(None);
    };
    // A non-constant one-word recurrence needs one dependent subset-table
    // load per source nibble for every consumed byte. Beyond one nibble, or
    // any multiword scanner/refinement composition, the prepared fallback's
    // warmed transition loop is the cheaper general owner. Keep the complete
    // layout available to endpoint compositions, where avoiding an ordered
    // replay can still amortize that work.
    if !admitted_standalone_exists(&layout, target) {
        return Ok(None);
    }
    Ok(lower_native_bit_parallel_layout(layout, target)?.map(|receipt| receipt.lowering))
}

/// Lower the same complete existence machine for use as a false-only
/// endpoint oracle. A constant-positive machine can never prove the only
/// outcome this composition consumes, so publishing it would add a native
/// call and an ordered replay to every search without a possible win.
pub(super) fn lower_native_bit_parallel_endpoint_oracle(
    view: NativeBitParallelExistsView<'_>,
    target: Target,
) -> Result<Option<NativeLowering>, ObjectError> {
    let Some(layout) = build_native_bit_parallel_layout(view) else {
        return Ok(None);
    };
    if layout.constant_result == Some(true) {
        return Ok(None);
    }
    Ok(lower_native_bit_parallel_layout(layout, target)?.map(|receipt| receipt.lowering))
}

/// Lower a complete exact-width endpoint machine. Unlike the false-only
/// composition, a constant-positive machine is useful: its first accepting
/// end is the unchanged window-start cursor and directly completes a nullable
/// endpoint result.
pub(super) fn lower_native_bit_parallel_exact_endpoint(
    view: NativeBitParallelExistsView<'_>,
    target: Target,
) -> Result<Option<NativeBitParallelExactEndpointLowering>, ObjectError> {
    let Some(layout) = build_native_bit_parallel_layout(view) else {
        return Ok(None);
    };
    Ok(
        lower_native_bit_parallel_layout(layout, target)?.map(|receipt| {
            NativeBitParallelExactEndpointLowering {
                lowering: receipt.lowering,
                matched_cursor: receipt.matched_cursor,
            }
        }),
    )
}

fn lower_native_bit_parallel_layout(
    layout: NativeBitParallelLayout,
    target: Target,
) -> Result<Option<NativeBitParallelLoweringReceipt>, ObjectError> {
    let scanner_filter = admitted_root_scanner_filter(&layout, target);
    let emission = match target.architecture {
        Architecture::X86_64 => lower_x86_64_bit_parallel(&layout, target)?,
        Architecture::Aarch64 => lower_aarch64_bit_parallel(&layout, target)?,
    };
    if emission.code.len() > MAX_NATIVE_BIT_PARALLEL_CODE_BYTES
        || (layout.words == 1 && emission.emitted_nibbles != layout.source_nibbles)
        || (layout.words != 1 && emission.emitted_words != layout.words)
    {
        return Ok(None);
    }
    let start_accelerator = if scanner_filter.is_none() {
        StartAccelerator::None
    } else {
        let filter = scanner_filter.ok_or(ObjectError::InvalidModule(
            "native bit-parallel scanner receipt has no root filter",
        ))?;
        match target.architecture {
            Architecture::X86_64 => {
                x86_range_scanner_emission(filter, x86_start_filter_kind(target.features))?
                    .start_accelerator()
            }
            Architecture::Aarch64
                if target.operating_system == OperatingSystem::Linux
                    && target.features.has(CpuFeature::Aarch64Sve2)
                    && layout.sve2_match_table_offset.is_some() =>
            {
                StartAccelerator::Aarch64Sve2
            }
            Architecture::Aarch64
                if target.operating_system == OperatingSystem::Linux
                    && target.features.has(CpuFeature::Aarch64Sve) =>
            {
                StartAccelerator::Aarch64Sve
            }
            Architecture::Aarch64 => StartAccelerator::Aarch64Asimd,
        }
    };
    Ok(Some(NativeBitParallelLoweringReceipt {
        lowering: NativeLowering {
            code: emission.code,
            data: layout.data,
            relocations: emission.relocations,
            slow_partial_table: None,
            needs_runtime: false,
            start_accelerator,
            anchored_prefix_filter_bytes: 0,
            synchronizing_accept_reverse_lowered: false,
            exact_pair_suffix_lowered: false,
            complete_pair_relation_handoff_lowered: false,
            complete_pair_relation_persistent_batch_lowered: false,
            exact_finite_exists_complete_dfa_receipt: None,
            exact_finite_exists_complete_dfa_expected_receipt_sha256: None,
            direct_search_trusted_core: None,
            complete_span_reduce_source: None,
        },
        matched_cursor: emission.matched_cursor,
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "canonical dimensions, masks, exact extent, and allocation form one publication proof"
)]
fn build_native_bit_parallel_layout(
    view: NativeBitParallelExistsView<'_>,
) -> Option<NativeBitParallelLayout> {
    let stats = view.stats;
    if stats.words != 1 {
        return build_native_multiword_bit_parallel_layout(view);
    }
    if stats.thompson_states == 0
        || stats.thompson_states > MAX_BIT_PARALLEL_EXISTS_STATES
        || stats.words != 1
        || stats.consuming_states > 63
        || !(1..=BYTE_VALUES).contains(&stats.byte_classes)
    {
        return None;
    }
    let source_nibbles = stats.consuming_states.checked_add(NIBBLE_BITS - 1)? / NIBBLE_BITS;
    let transition_entries = stats
        .byte_classes
        .checked_mul(source_nibbles)?
        .checked_mul(NIBBLE_SUBSETS)?;
    let transition_bytes = transition_entries.checked_mul(core::mem::size_of::<u64>())?;
    let data_bytes = CLASSIFIER_BYTES.checked_add(transition_bytes)?;
    let retained_bytes = core::mem::size_of::<BitParallelExists>().checked_add(transition_bytes)?;
    if stats.source_nibbles != source_nibbles
        || stats.transition_entries != transition_entries
        || stats.root_transition_entries != 0
        || view.transition_masks.len() != transition_entries
        || !view.root_transition_masks.is_empty()
        || stats.retained_bytes != retained_bytes
        || stats.peak_build_bytes < stats.retained_bytes
        || data_bytes > MAX_NATIVE_BIT_PARALLEL_DATA_BYTES
    {
        return None;
    }
    let mut prior_class = 0_u8;
    for (byte, &class) in view.byte_to_class.iter().enumerate() {
        if usize::from(class) >= stats.byte_classes
            || byte == 0 && class != 0
            || byte != 0 && class != prior_class && class != prior_class.checked_add(1)?
        {
            return None;
        }
        prior_class = class;
    }
    if usize::from(prior_class).checked_add(1)? != stats.byte_classes {
        return None;
    }

    let consuming_mask = match stats.consuming_states {
        0 => 0,
        63 => CONSUMING_BITS,
        consuming_count => 1_u64
            .checked_shl(u32::try_from(consuming_count).ok()?)?
            .checked_sub(1)?,
    };
    let valid_mask = consuming_mask | ACCEPT_BIT;
    if view.initial[0] & !valid_mask != 0 || view.initial[1..].iter().any(|&word| word != 0) {
        return None;
    }
    for row in view.transition_masks.chunks_exact(NIBBLE_SUBSETS) {
        if row[0] != 0 || row.iter().any(|mask| mask & !valid_mask != 0) {
            return None;
        }
        for subset in 1..NIBBLE_SUBSETS {
            let previous_subset = subset & subset.checked_sub(1)?;
            let isolated_bit = 1_usize.checked_shl(subset.trailing_zeros())?;
            if row[subset] != row[previous_subset] | row[isolated_bit] {
                return None;
            }
        }
    }

    let root = view.initial[0] & CONSUMING_BITS;
    let constant_result = if view.initial[0] & ACCEPT_BIT != 0 {
        Some(true)
    } else if root == 0 {
        Some(false)
    } else {
        None
    };
    if constant_result.is_none() && source_nibbles == 0 {
        return None;
    }

    let root_filter = if constant_result.is_none() {
        let mut membership = [0_u64; 4];
        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(view.byte_to_class[usize::from(byte)]);
            let class_base = class
                .checked_mul(source_nibbles)?
                .checked_mul(NIBBLE_SUBSETS)?;
            let mut reached = 0_u64;
            for nibble in 0..source_nibbles {
                let shift = nibble.checked_mul(NIBBLE_BITS)?;
                let subset = usize::try_from((root >> shift) & 0x0f).ok()?;
                let index = class_base
                    .checked_add(nibble.checked_mul(NIBBLE_SUBSETS)?)?
                    .checked_add(subset)?;
                reached |= *view.transition_masks.get(index)?;
            }
            let changes_root = reached & (ACCEPT_BIT | (CONSUMING_BITS & !root)) != 0;
            if changes_root {
                let byte = usize::from(byte);
                membership[byte / 64] |= 1_u64 << (byte % 64);
            }
        }
        filter_from_membership_words(membership, 0, false)
            .ok()
            .flatten()
    } else {
        None
    };
    let constant_result = if constant_result.is_none()
        && root_filter.is_some_and(|filter| filter.ranges().is_empty())
    {
        Some(false)
    } else {
        constant_result
    };
    let root_filter = if constant_result.is_some() {
        None
    } else {
        root_filter
    };

    let mut data = Vec::new();
    if constant_result.is_none() {
        data.try_reserve_exact(data_bytes).ok()?;
        let class_stride = source_nibbles.checked_mul(NIBBLE_ROW_BYTES)?;
        for &class in view.byte_to_class {
            let offset = usize::from(class)
                .checked_mul(class_stride)?
                .checked_add(CLASSIFIER_BYTES)?;
            data.extend_from_slice(&u32::try_from(offset).ok()?.to_le_bytes());
        }
        for &mask in view.transition_masks {
            data.extend_from_slice(&mask.to_le_bytes());
        }
        if data.len() != data_bytes {
            return None;
        }
    }

    let mut first_lane_table_offset = None;
    let mut sve2_match_table_offset = None;
    if let Some(filter) = root_filter.filter(|filter| !filter.ranges().is_empty()) {
        first_lane_table_offset = Some(u32::try_from(data.len()).ok()?);
        data.try_reserve_exact(ROOT_SKIP_FIRST_LANE_BYTES.checked_mul(2)?)
            .ok()?;
        data.extend(0_u8..u8::try_from(ROOT_SKIP_FIRST_LANE_BYTES).ok()?);
        if filter.is_exact() {
            sve2_match_table_offset = Some(u32::try_from(data.len()).ok()?);
            let first = filter.ranges().first()?.start;
            for index in 0..ROOT_SKIP_FIRST_LANE_BYTES {
                data.push(
                    filter
                        .ranges()
                        .get(index)
                        .map_or(first, |range| range.start),
                );
            }
        }
    }
    if data.len() > MAX_NATIVE_BIT_PARALLEL_DATA_BYTES {
        return None;
    }
    Some(NativeBitParallelLayout {
        data,
        root,
        roots: [root, 0, 0, 0],
        words: 1,
        consuming_states: stats.consuming_states,
        direct_row_words: 1,
        source_row_offsets: [0; MAX_BIT_PARALLEL_EXISTS_WORDS],
        source_row_nibbles: [0; MAX_BIT_PARALLEL_EXISTS_WORDS],
        subset_source_mask: 0,
        source_nibbles,
        constant_result,
        root_filter,
        first_lane_table_offset,
        sve2_match_table_offset,
        root_vector_offset: None,
        accept_vector_offset: None,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct MultiwordSourceActivity {
    expected_bits_q32: u64,
    expected_nibbles_q32: u64,
}

fn source_word_bits(consuming_states: usize, source_word: usize) -> Option<usize> {
    consuming_states
        .checked_sub(source_word.checked_mul(64)?)
        .map(|remaining| remaining.min(64))
}

fn nonzero_nibbles(mut bits: u64) -> u32 {
    let mut count = 0_u32;
    while bits != 0 {
        count += u32::from(bits & 0x0f != 0);
        bits >>= NIBBLE_BITS;
    }
    count
}

/// Measure a deterministic Q32 iid-byte frontier distribution, then take a
/// Cesaro average of live source density. This uses only the authenticated
/// classifier, direct rows, and root frontier. It intentionally declines the
/// hybrid representation if the canonical graph's frontier distribution is
/// too large to model within a fixed compiler-work budget. Q32 truncation is
/// deterministic across compiler hosts and drops only sub-2^-32 mass.
fn multiword_source_activity(
    view: NativeBitParallelExistsView<'_>,
    roots: [u64; MAX_BIT_PARALLEL_EXISTS_WORDS],
) -> Option<[MultiwordSourceActivity; MAX_BIT_PARALLEL_EXISTS_WORDS]> {
    let words = view.stats.words;
    let mut class_weights = [0_u16; BYTE_VALUES];
    for &class in view.byte_to_class {
        let class = usize::from(class);
        class_weights[class] = class_weights[class].checked_add(1)?;
    }

    let mut distribution = BTreeMap::new();
    distribution.insert(roots, MULTIWORD_ACTIVITY_PROBABILITY_SCALE);
    let mut activity = [MultiwordSourceActivity::default(); MAX_BIT_PARALLEL_EXISTS_WORDS];
    let mut sampled_steps = 0_usize;
    let mut row_unions = 0_usize;
    let total_steps =
        MULTIWORD_ACTIVITY_WARMUP_STEPS.checked_add(MULTIWORD_ACTIVITY_SAMPLE_STEPS)?;

    for step in 0..total_steps {
        if step >= MULTIWORD_ACTIVITY_WARMUP_STEPS {
            let total_weight: u128 = distribution
                .values()
                .map(|&weight| u128::from(weight))
                .sum();
            if total_weight == 0 {
                break;
            }
            let mut bit_weight = [0_u128; MAX_BIT_PARALLEL_EXISTS_WORDS];
            let mut nibble_weight = [0_u128; MAX_BIT_PARALLEL_EXISTS_WORDS];
            for (frontier, &weight) in &distribution {
                for word in 0..words {
                    let nonroot = frontier[word] & !roots[word];
                    bit_weight[word] = bit_weight[word]
                        .checked_add(u128::from(weight) * u128::from(nonroot.count_ones()))?;
                    nibble_weight[word] = nibble_weight[word]
                        .checked_add(u128::from(weight) * u128::from(nonzero_nibbles(nonroot)))?;
                }
            }
            for word in 0..words {
                let bit_step = bit_weight[word]
                    .checked_mul(u128::from(MULTIWORD_ACTIVITY_PROBABILITY_SCALE))?
                    / total_weight;
                let nibble_step = nibble_weight[word]
                    .checked_mul(u128::from(MULTIWORD_ACTIVITY_PROBABILITY_SCALE))?
                    / total_weight;
                activity[word].expected_bits_q32 = activity[word]
                    .expected_bits_q32
                    .checked_add(u64::try_from(bit_step).ok()?)?;
                activity[word].expected_nibbles_q32 = activity[word]
                    .expected_nibbles_q32
                    .checked_add(u64::try_from(nibble_step).ok()?)?;
            }
            sampled_steps = sampled_steps.checked_add(1)?;
        }

        let mut raw_next = BTreeMap::new();
        for (frontier, &weight) in &distribution {
            for (class, &class_weight) in class_weights
                .iter()
                .enumerate()
                .take(view.stats.byte_classes)
            {
                if class_weight == 0 {
                    continue;
                }
                let mut reached = [0_u64; MAX_BIT_PARALLEL_EXISTS_WORDS];
                for source_word in 0..words {
                    let mut sources = frontier[source_word];
                    while sources != 0 {
                        row_unions = row_unions.checked_add(1)?;
                        if row_unions > MAX_MULTIWORD_ACTIVITY_ROW_UNIONS {
                            return None;
                        }
                        let source_bit = usize::try_from(sources.trailing_zeros()).ok()?;
                        sources &= sources.checked_sub(1)?;
                        let ordinal = source_word.checked_mul(64)?.checked_add(source_bit)?;
                        if ordinal >= view.stats.consuming_states {
                            return None;
                        }
                        let direct_base = class
                            .checked_mul(view.stats.consuming_states)?
                            .checked_add(ordinal)?
                            .checked_mul(words)?;
                        for destination_word in 0..words {
                            reached[destination_word] |= *view
                                .transition_masks
                                .get(direct_base.checked_add(destination_word)?)?;
                        }
                    }
                }
                if reached[words.checked_sub(1)?] & ACCEPT_BIT != 0 {
                    continue;
                }
                let mut successor = roots;
                for word in 0..words {
                    successor[word] |= reached[word];
                }
                let successor_weight = u128::from(weight).checked_mul(u128::from(class_weight))?;
                let entry = raw_next.entry(successor).or_insert(0_u128);
                *entry = entry.checked_add(successor_weight)?;
                if raw_next.len() > MAX_MULTIWORD_ACTIVITY_FRONTIERS {
                    return None;
                }
            }
        }
        let surviving_weight: u128 = raw_next.values().copied().sum();
        if surviving_weight == 0 {
            break;
        }
        let mut next = BTreeMap::new();
        for (frontier, raw_weight) in raw_next {
            let normalized = raw_weight
                .checked_mul(u128::from(MULTIWORD_ACTIVITY_PROBABILITY_SCALE))?
                / surviving_weight;
            let normalized = u64::try_from(normalized).ok()?;
            if normalized != 0 {
                next.insert(frontier, normalized);
            }
        }
        if next.is_empty() {
            break;
        }
        distribution = next;
    }

    if sampled_steps == 0 {
        return Some(activity);
    }
    let denominator = u64::try_from(sampled_steps).ok()?;
    for word_activity in activity.iter_mut().take(words) {
        word_activity.expected_bits_q32 /= denominator;
        word_activity.expected_nibbles_q32 /= denominator;
    }
    Some(activity)
}

fn multiword_source_layout(
    consuming_states: usize,
    words: usize,
    subset_source_mask: u8,
    native_row_bytes: usize,
) -> Option<(
    [u32; MAX_BIT_PARALLEL_EXISTS_WORDS],
    [u8; MAX_BIT_PARALLEL_EXISTS_WORDS],
    usize,
)> {
    let mut offsets = [0_u32; MAX_BIT_PARALLEL_EXISTS_WORDS];
    let mut nibbles = [0_u8; MAX_BIT_PARALLEL_EXISTS_WORDS];
    let mut class_bytes = 0_usize;
    for source_word in 0..words {
        offsets[source_word] = u32::try_from(class_bytes).ok()?;
        let source_bits = source_word_bits(consuming_states, source_word)?;
        if source_bits == 0 {
            return None;
        }
        let source_rows = if subset_source_mask & (1_u8 << source_word) != 0 {
            let source_nibbles = source_bits.div_ceil(NIBBLE_BITS);
            nibbles[source_word] = u8::try_from(source_nibbles).ok()?;
            source_nibbles.checked_mul(NIBBLE_SUBSETS)?
        } else {
            source_bits
        };
        class_bytes = class_bytes.checked_add(source_rows.checked_mul(native_row_bytes)?)?;
    }
    Some((offsets, nibbles, class_bytes))
}

fn admitted_multiword_subset_sources(
    view: NativeBitParallelExistsView<'_>,
    roots: [u64; MAX_BIT_PARALLEL_EXISTS_WORDS],
    native_row_bytes: usize,
    fixed_table_bytes: usize,
) -> Option<u8> {
    let activity = multiword_source_activity(view, roots)?;
    let mut gains = [0_i128; MAX_BIT_PARALLEL_EXISTS_WORDS];
    for word in 0..view.stats.words {
        gains[word] = i128::from(activity[word].expected_bits_q32)
            * SUBSET_ROW_DIRECT_COST_DENOMINATOR
            - i128::from(activity[word].expected_nibbles_q32) * SUBSET_ROW_DIRECT_COST_NUMERATOR;
    }

    // Reserve the maximum scanner suffix so selection never depends on target
    // ISA or on a later auxiliary-table append. The canonical state vectors
    // are already included in `fixed_table_bytes`.
    let auxiliary_reserve = ROOT_SKIP_FIRST_LANE_BYTES.checked_mul(2)?;
    let mut best_mask = 0_u8;
    let mut best_gain = 0_i128;
    let mut best_data_bytes = usize::MAX;
    for mask in 1_u8..(1_u8 << view.stats.words) {
        let mut gain = 0_i128;
        let mut all_profitable = true;
        for word in 0..view.stats.words {
            if mask & (1_u8 << word) != 0 {
                // Gain is in quarter-row Q32 units. Two Q32 units therefore
                // encode the required half-row expected saving.
                if gains[word]
                    < i128::from(MULTIWORD_ACTIVITY_PROBABILITY_SCALE)
                        * (SUBSET_ROW_DIRECT_COST_DENOMINATOR / 2)
                {
                    all_profitable = false;
                    break;
                }
                gain += gains[word];
            }
        }
        if !all_profitable {
            continue;
        }
        let (_, _, class_bytes) = multiword_source_layout(
            view.stats.consuming_states,
            view.stats.words,
            mask,
            native_row_bytes,
        )?;
        let data_bytes = fixed_table_bytes
            .checked_add(view.stats.byte_classes.checked_mul(class_bytes)?)?
            .checked_add(auxiliary_reserve)?;
        if data_bytes > MAX_NATIVE_BIT_PARALLEL_HYBRID_DATA_BYTES {
            continue;
        }
        if gain > best_gain || gain == best_gain && data_bytes < best_data_bytes {
            best_mask = mask;
            best_gain = gain;
            best_data_bytes = data_bytes;
        }
    }
    Some(best_mask)
}

#[allow(
    clippy::too_many_lines,
    reason = "multiword dimensions, root-cache authentication, and target-private padding form one publication proof"
)]
fn build_native_multiword_bit_parallel_layout(
    view: NativeBitParallelExistsView<'_>,
) -> Option<NativeBitParallelLayout> {
    let stats = view.stats;
    let words = stats.words;
    if !(2..=MAX_BIT_PARALLEL_EXISTS_WORDS).contains(&words)
        || stats.thompson_states == 0
        || stats.thompson_states > MAX_BIT_PARALLEL_EXISTS_STATES
        || !(1..=BYTE_VALUES).contains(&stats.byte_classes)
        || stats.consuming_states == 0
        || stats.consuming_states > words.checked_mul(64)?.checked_sub(1)?
        || stats.consuming_states.checked_add(1)?.div_ceil(64) != words
        || stats.source_nibbles != 0
    {
        return None;
    }
    let transition_entries = stats
        .byte_classes
        .checked_mul(stats.consuming_states)?
        .checked_mul(words)?;
    let root_transition_entries = BYTE_VALUES.checked_mul(words)?;
    let retained_entries = transition_entries.checked_add(root_transition_entries)?;
    let retained_bytes = core::mem::size_of::<BitParallelExists>()
        .checked_add(retained_entries.checked_mul(core::mem::size_of::<u64>())?)?;
    if stats.transition_entries != transition_entries
        || stats.root_transition_entries != root_transition_entries
        || view.transition_masks.len() != transition_entries
        || view.root_transition_masks.len() != root_transition_entries
        || stats.retained_bytes != retained_bytes
        || stats.peak_build_bytes < retained_bytes
    {
        return None;
    }

    let mut prior_class = 0_u8;
    for (byte, &class) in view.byte_to_class.iter().enumerate() {
        if usize::from(class) >= stats.byte_classes
            || byte == 0 && class != 0
            || byte != 0 && class != prior_class && class != prior_class.checked_add(1)?
        {
            return None;
        }
        prior_class = class;
    }
    if usize::from(prior_class).checked_add(1)? != stats.byte_classes {
        return None;
    }

    let final_word = words.checked_sub(1)?;
    let final_consuming_bits = stats
        .consuming_states
        .checked_sub(final_word.checked_mul(64)?)?;
    if !(1..=63).contains(&final_consuming_bits) {
        return None;
    }
    let final_consuming_mask = 1_u64
        .checked_shl(u32::try_from(final_consuming_bits).ok()?)?
        .checked_sub(1)?;
    let final_valid_mask = final_consuming_mask | ACCEPT_BIT;
    if view.initial[final_word] & !final_valid_mask != 0
        || view.initial[words..].iter().any(|&word| word != 0)
    {
        return None;
    }
    for row in view.transition_masks.chunks_exact(words) {
        if row[final_word] & !final_valid_mask != 0 {
            return None;
        }
    }
    for row in view.root_transition_masks.chunks_exact(words) {
        if row[final_word] & !final_valid_mask != 0 {
            return None;
        }
    }

    let mut roots = view.initial;
    roots[final_word] &= final_consuming_mask;
    for byte in 0..BYTE_VALUES {
        let class = usize::from(view.byte_to_class[byte]);
        let root_base = byte.checked_mul(words)?;
        let mut expected = [0_u64; MAX_BIT_PARALLEL_EXISTS_WORDS];
        for source_word in 0..words {
            let mut sources = roots[source_word];
            while sources != 0 {
                let source_bit = usize::try_from(sources.trailing_zeros()).ok()?;
                sources &= sources.checked_sub(1)?;
                let ordinal = source_word.checked_mul(64)?.checked_add(source_bit)?;
                if ordinal >= stats.consuming_states {
                    return None;
                }
                let direct_base = class
                    .checked_mul(stats.consuming_states)?
                    .checked_add(ordinal)?
                    .checked_mul(words)?;
                for destination_word in 0..words {
                    expected[destination_word] |= *view
                        .transition_masks
                        .get(direct_base.checked_add(destination_word)?)?;
                }
            }
        }
        if view
            .root_transition_masks
            .get(root_base..root_base.checked_add(words)?)?
            != &expected[..words]
        {
            return None;
        }
    }

    let constant_result = if view.initial[final_word] & ACCEPT_BIT != 0 {
        Some(true)
    } else if roots[..words].iter().all(|&word| word == 0) {
        Some(false)
    } else {
        None
    };
    let root_filter = if constant_result.is_none() {
        let mut membership = [0_u64; 4];
        for byte in 0..BYTE_VALUES {
            let root_base = byte.checked_mul(words)?;
            let reached = view
                .root_transition_masks
                .get(root_base..root_base.checked_add(words)?)?;
            if reached
                .iter()
                .zip(&roots)
                .take(words)
                .any(|(&reached, &root)| reached & !root != 0)
            {
                membership[byte / 64] |= 1_u64 << (byte % 64);
            }
        }
        filter_from_membership_words(membership, 0, false)
            .ok()
            .flatten()
    } else {
        None
    };
    let constant_result = if constant_result.is_none()
        && root_filter.is_some_and(|filter| filter.ranges().is_empty())
    {
        Some(false)
    } else {
        constant_result
    };
    let root_filter = if constant_result.is_some() {
        None
    } else {
        root_filter
    };

    // Four target-private words permit one AVX2 row load and at most two
    // ASIMD loads for every admitted word count. Padding is zero and excluded
    // from the portable resource receipt.
    let direct_row_words = MAX_BIT_PARALLEL_EXISTS_WORDS;
    let native_row_bytes = direct_row_words.checked_mul(core::mem::size_of::<u64>())?;
    let native_root_entries = BYTE_VALUES.checked_mul(direct_row_words)?;
    let root_offset = MULTIWORD_ROOT_ROWS_OFFSET;
    let direct_offset =
        root_offset.checked_add(native_root_entries.checked_mul(core::mem::size_of::<u64>())?)?;
    let subset_source_mask = if constant_result.is_none() {
        admitted_multiword_subset_sources(view, roots, native_row_bytes, direct_offset).unwrap_or(0)
    } else {
        0
    };
    let (source_row_offsets, source_row_nibbles, class_stride) = multiword_source_layout(
        stats.consuming_states,
        words,
        subset_source_mask,
        native_row_bytes,
    )?;
    let table_bytes = direct_offset.checked_add(stats.byte_classes.checked_mul(class_stride)?)?;

    let mut data = Vec::new();
    if constant_result.is_none() {
        data.try_reserve_exact(
            table_bytes.checked_add(ROOT_SKIP_FIRST_LANE_BYTES.checked_mul(2)?)?,
        )
        .ok()?;
        for byte in 0..BYTE_VALUES {
            let class_row = direct_offset
                .checked_add(usize::from(view.byte_to_class[byte]).checked_mul(class_stride)?)?;
            data.extend_from_slice(&u32::try_from(class_row).ok()?.to_le_bytes());
        }
        if data.len() != MULTIWORD_ROOT_VECTOR_OFFSET {
            return None;
        }
        for &root in &roots {
            data.extend_from_slice(&root.to_le_bytes());
        }
        if data.len() != MULTIWORD_ACCEPT_VECTOR_OFFSET {
            return None;
        }
        for word in 0..MAX_BIT_PARALLEL_EXISTS_WORDS {
            let accept = if word + 1 == words { ACCEPT_BIT } else { 0 };
            data.extend_from_slice(&accept.to_le_bytes());
        }
        if data.len() != MULTIWORD_ROOT_ROWS_OFFSET {
            return None;
        }
        for byte in 0..BYTE_VALUES {
            let source = byte.checked_mul(words)?;
            for word in 0..direct_row_words {
                let value = if word < words {
                    *view.root_transition_masks.get(source.checked_add(word)?)?
                } else {
                    0
                };
                data.extend_from_slice(&value.to_le_bytes());
            }
        }
        if subset_source_mask == 0 {
            // Preserve the parent's ordinal-major table construction exactly.
            // Besides making the compatibility boundary explicit, this keeps
            // zero-mask object bytes independent of hybrid implementation
            // details.
            for class in 0..stats.byte_classes {
                for ordinal in 0..stats.consuming_states {
                    let source = class
                        .checked_mul(stats.consuming_states)?
                        .checked_add(ordinal)?
                        .checked_mul(words)?;
                    for word in 0..direct_row_words {
                        let value = if word < words {
                            *view.transition_masks.get(source.checked_add(word)?)?
                        } else {
                            0
                        };
                        data.extend_from_slice(&value.to_le_bytes());
                    }
                }
            }
        } else {
            for class in 0..stats.byte_classes {
                for source_word in 0..words {
                    let source_bits = source_word_bits(stats.consuming_states, source_word)?;
                    if subset_source_mask & (1_u8 << source_word) != 0 {
                        for nibble in 0..usize::from(source_row_nibbles[source_word]) {
                            for subset in 0..NIBBLE_SUBSETS {
                                let mut reached = [0_u64; MAX_BIT_PARALLEL_EXISTS_WORDS];
                                for nibble_bit in 0..NIBBLE_BITS {
                                    if subset & (1 << nibble_bit) == 0 {
                                        continue;
                                    }
                                    let source_bit =
                                        nibble.checked_mul(NIBBLE_BITS)?.checked_add(nibble_bit)?;
                                    if source_bit >= source_bits {
                                        continue;
                                    }
                                    let ordinal =
                                        source_word.checked_mul(64)?.checked_add(source_bit)?;
                                    let source = class
                                        .checked_mul(stats.consuming_states)?
                                        .checked_add(ordinal)?
                                        .checked_mul(words)?;
                                    for word in 0..words {
                                        reached[word] |= *view
                                            .transition_masks
                                            .get(source.checked_add(word)?)?;
                                    }
                                }
                                for value in reached.iter().take(direct_row_words) {
                                    data.extend_from_slice(&value.to_le_bytes());
                                }
                            }
                        }
                    } else {
                        for source_bit in 0..source_bits {
                            let ordinal = source_word.checked_mul(64)?.checked_add(source_bit)?;
                            let source = class
                                .checked_mul(stats.consuming_states)?
                                .checked_add(ordinal)?
                                .checked_mul(words)?;
                            for word in 0..direct_row_words {
                                let value = if word < words {
                                    *view.transition_masks.get(source.checked_add(word)?)?
                                } else {
                                    0
                                };
                                data.extend_from_slice(&value.to_le_bytes());
                            }
                        }
                    }
                }
            }
        }
        if data.len() != table_bytes {
            return None;
        }
    }

    let mut first_lane_table_offset = None;
    let mut sve2_match_table_offset = None;
    if let Some(filter) = root_filter.filter(|filter| !filter.ranges().is_empty()) {
        first_lane_table_offset = Some(u32::try_from(data.len()).ok()?);
        data.extend(0_u8..u8::try_from(ROOT_SKIP_FIRST_LANE_BYTES).ok()?);
        if filter.is_exact() {
            sve2_match_table_offset = Some(u32::try_from(data.len()).ok()?);
            let first = filter.ranges().first()?.start;
            for index in 0..ROOT_SKIP_FIRST_LANE_BYTES {
                data.push(
                    filter
                        .ranges()
                        .get(index)
                        .map_or(first, |range| range.start),
                );
            }
        }
    }
    let root_vector_offset = constant_result
        .is_none()
        .then_some(u32::try_from(MULTIWORD_ROOT_VECTOR_OFFSET).ok()?);
    let accept_vector_offset = constant_result
        .is_none()
        .then_some(u32::try_from(MULTIWORD_ACCEPT_VECTOR_OFFSET).ok()?);
    let data_limit = if subset_source_mask == 0 {
        MAX_NATIVE_BIT_PARALLEL_DATA_BYTES
    } else {
        MAX_NATIVE_BIT_PARALLEL_HYBRID_DATA_BYTES
    };
    if data.len() > data_limit {
        return None;
    }
    Some(NativeBitParallelLayout {
        data,
        root: roots[0],
        roots,
        words,
        consuming_states: stats.consuming_states,
        direct_row_words,
        source_row_offsets,
        source_row_nibbles,
        subset_source_mask,
        source_nibbles: 0,
        constant_result,
        root_filter,
        first_lane_table_offset,
        sve2_match_table_offset,
        root_vector_offset,
        accept_vector_offset,
    })
}

fn x86_emit_abi_validation(
    assembler: &mut X86Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x48, 0x85, 0xf6])?; // test length sign bit
    assembler.branch(&[0x0f, 0x88], invalid)?; // js
    assembler.instruction(&[0x48, 0x39, 0xf1])?; // cmp end, length
    assembler.branch(&[0x0f, 0x87], invalid)?; // ja
    assembler.instruction(&[0x48, 0x39, 0xca])?; // cmp start, end
    assembler.branch(&[0x0f, 0x87], invalid)?;
    assembler.instruction(&[0x4d, 0x85, 0xc0])?; // test result, result
    assembler.branch(&[0x0f, 0x84], invalid)?;
    assembler.instruction(&[0x41, 0xf6, 0xc0, 0x07])?; // 8-byte result alignment
    assembler.branch(&[0x0f, 0x85], invalid)?;
    assembler.instruction(&[0x48, 0x85, 0xff])?; // test haystack, haystack
    assembler.branch(&[0x0f, 0x84], invalid)?;
    Ok(())
}

fn x86_emit_result_zero(assembler: &mut X86Assembler) -> Result<(), ObjectError> {
    assembler.instruction(&[0x31, 0xc0])?; // xor eax, eax
    assembler.instruction(&[0x49, 0x89, 0x00])?; // mov [r8], rax
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?; // mov [r8 + 8], rax
    Ok(())
}

fn lower_x86_64_bit_parallel(
    layout: &NativeBitParallelLayout,
    target: Target,
) -> Result<NativeBitParallelEmission, ObjectError> {
    let scanner_filter = admitted_root_scanner_filter(layout, target);
    if layout.words != 1 {
        return lower_x86_64_multiword_bit_parallel(layout, target.features, scanner_filter);
    }
    let mut assembler = X86Assembler::new();
    let scan = assembler.label()?;
    let vector_scan = assembler.label()?;
    let vector_hit = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let scalar_miss = assembler.label()?;
    let root_recurrence = assembler.label()?;
    let recurrence = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;

    x86_emit_abi_validation(&mut assembler, invalid)?;
    x86_emit_result_zero(&mut assembler)?;
    let filter_kind = scanner_filter.map(|_| x86_start_filter_kind(target.features));
    if let Some(result) = layout.constant_result {
        assembler.instruction(&[0xb8, u8::from(result), 0, 0, 0])?;
        assembler.branch(&[0xe9], done)?;
    } else {
        // lea table(%rip), r9
        assembler.instruction(&[0x4c, 0x8d, 0x0d])?;
        let table_displacement_label = assembler.label()?;
        assembler.bind(table_displacement_label)?;
        push_bytes(&mut assembler.code, &[0; 4])?;

        let mut root = vec![0x49, 0xbb]; // movabs root, r11
        root.extend_from_slice(&layout.root.to_le_bytes());
        assembler.instruction(&root)?;
        assembler.instruction(&[0x4d, 0x89, 0xda])?; // active r10 = root r11
        if let Some((filter, kind)) = scanner_filter.zip(filter_kind) {
            x86_emit_start_filter_constants(&mut assembler, filter, kind, 1)?;

            // Only this edge owns the exact restart/root state. Every miss byte
            // is graph-proven to preserve that state and non-acceptance.
            assembler.bind(scan)?;
            assembler.bind(vector_scan)?;
            assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
            assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
            assembler.instruction(&[0x48, 0x83, 0xf8, kind.width()])?;
            assembler.branch(&[0x0f, 0x82], scalar_scan)?;
            x86_emit_start_filter_vector_candidate(&mut assembler, filter, kind, vector_hit)?;
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
            assembler.branch(&[0xe9], vector_scan)?;

            assembler.bind(vector_hit)?;
            x86_emit_first_candidate_lane(
                &mut assembler,
                X86CandidateMask::for_filter(filter, kind),
            )?;
            assembler.instruction(&[0x48, 0x01, 0xc2])?; // position += first lane
            assembler.branch(&[0xe9], root_recurrence)?;

            assembler.bind(scalar_scan)?;
            x86_emit_start_filter_scalar_bound(&mut assembler, 0, no_match)?;
            x86_emit_scalar_filter_membership(&mut assembler, filter, scalar_miss)?;
            assembler.branch(&[0xe9], root_recurrence)?;
            assembler.bind(scalar_miss)?;
            assembler.instruction(&[0x48, 0xff, 0xc2])?;
            assembler.branch(&[0xe9], scalar_scan)?;

            assembler.bind(root_recurrence)?;
            assembler.instruction(&[0x4d, 0x89, 0xda])?; // exact root active
        }
        assembler.bind(recurrence)?;
        assembler.instruction(&[0x48, 0x39, 0xca])?; // position >= end
        assembler.branch(&[0x0f, 0x83], no_match)?;
        assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?; // byte at position
        assembler.instruction(&[0x48, 0xff, 0xc2])?; // position += 1
        assembler.instruction(&[0x41, 0x8b, 0x04, 0x81])?; // row offset = table[byte]
        assembler.instruction(&[0x49, 0x8d, 0x34, 0x01])?; // row = table + offset
        assembler.instruction(&[0x31, 0xc0])?; // reached = 0
        for nibble in 0..layout.source_nibbles {
            assembler.instruction(&[0x4d, 0x89, 0xd0])?; // active -> temporary r8
            let shift = u8::try_from(
                nibble
                    .checked_mul(NIBBLE_BITS)
                    .ok_or(ObjectError::ArithmeticOverflow("x86 bit-parallel shift"))?,
            )
            .map_err(|_| ObjectError::ArithmeticOverflow("x86 bit-parallel shift"))?;
            if shift != 0 {
                assembler.instruction(&[0x49, 0xc1, 0xe8, shift])?;
            }
            assembler.instruction(&[0x41, 0x83, 0xe0, 0x0f])?;
            let displacement = u32::try_from(nibble.checked_mul(NIBBLE_ROW_BYTES).ok_or(
                ObjectError::ArithmeticOverflow("x86 bit-parallel row offset"),
            )?)
            .map_err(|_| ObjectError::ArithmeticOverflow("x86 bit-parallel row offset"))?;
            let mut union = vec![0x4a, 0x0b, 0x84, 0xc6];
            union.extend_from_slice(&displacement.to_le_bytes());
            assembler.instruction(&union)?; // reached |= row[r8 * 8 + displacement]
        }
        assembler.instruction(&[0x48, 0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x88], matched)?; // acceptance marker is the sign bit
        assembler.instruction(&[0x48, 0x0f, 0xba, 0xf0, 0x3f])?; // btr 63, rax
        assembler.instruction(&[0x4c, 0x09, 0xd8])?; // root | reached
        assembler.instruction(&[0x49, 0x89, 0xc2])?; // next active
        if scanner_filter.is_some() {
            assembler.instruction(&[0x4d, 0x39, 0xda])?; // root restored?
            assembler.branch(&[0x0f, 0x84], scan)?;
        }
        assembler.branch(&[0xe9], recurrence)?;

        assembler.bind(no_match)?;
        assembler.instruction(&[0x31, 0xc0])?;
        assembler.branch(&[0xe9], done)?;
        assembler.bind(matched)?;
        assembler.instruction(&[0xb8, 0x01, 0, 0, 0])?;
        assembler.branch(&[0xe9], done)?;

        assembler.bind(invalid)?;
        assembler.instruction(&[0xb8, 0x02, 0, 0, 0])?;
        assembler.bind(done)?;
        if filter_kind.is_some_and(|kind| kind.needs_vzeroupper()) {
            assembler.instruction(&[0xc5, 0xf8, 0x77])?;
        }
        assembler.instruction(&[0xc3])?;
        let finished = assembler.finish_with_label_offsets()?;
        let table_displacement = finished.label_offset(table_displacement_label)?;
        return Ok(NativeBitParallelEmission {
            code: finished.code,
            relocations: vec![ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(
                    table_displacement,
                    "x86 bit-parallel table relocation offset",
                )?,
                kind: RelocationKind::X86PcRelative32,
                symbol: PROGRAM_SYMBOL,
                addend: -4,
            }],
            emitted_nibbles: layout.source_nibbles,
            emitted_words: 1,
            matched_cursor: NativeBitParallelMatchedCursor::X86Rdx,
        });
    }

    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 0x02, 0, 0, 0])?;
    assembler.bind(done)?;
    if filter_kind.is_some_and(|kind| kind.needs_vzeroupper()) {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    assembler.instruction(&[0xc3])?;
    Ok(NativeBitParallelEmission {
        code: assembler.finish_with_label_offsets()?.code,
        relocations: Vec::new(),
        emitted_nibbles: layout.source_nibbles,
        emitted_words: 1,
        matched_cursor: NativeBitParallelMatchedCursor::X86Rdx,
    })
}

fn x86_emit_movabs(
    assembler: &mut X86Assembler,
    register_opcode: u8,
    value: u64,
) -> Result<(), ObjectError> {
    let mut instruction = vec![0x49, register_opcode];
    instruction.extend_from_slice(&value.to_le_bytes());
    assembler.instruction(&instruction).map(|_| ())
}

fn x86_emit_stack_load_rax(assembler: &mut X86Assembler, offset: u8) -> Result<(), ObjectError> {
    assembler
        .instruction(&[0x48, 0x8b, 0x44, 0x24, offset])
        .map(|_| ())
}

fn x86_emit_stack_store_rax(assembler: &mut X86Assembler, offset: u8) -> Result<(), ObjectError> {
    assembler
        .instruction(&[0x48, 0x89, 0x44, 0x24, offset])
        .map(|_| ())
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed-register multiword leaf, bit loops, stack unwind, and relocation form one CFG"
)]
fn lower_x86_64_multiword_bit_parallel(
    layout: &NativeBitParallelLayout,
    features: FeatureSet,
    scanner_filter: Option<NativeStartFilter>,
) -> Result<NativeBitParallelEmission, ObjectError> {
    if !(2..=MAX_BIT_PARALLEL_EXISTS_WORDS).contains(&layout.words)
        || layout.source_nibbles != 0
        || layout.consuming_states == 0
        || layout.direct_row_words < layout.words
    {
        return Err(ObjectError::InvalidModule(
            "x86 multiword bit-parallel layout dimensions",
        ));
    }
    let mut assembler = X86Assembler::new();
    let use_avx2 = features.has(CpuFeature::X86Avx2);
    let use_avx512_rows =
        !use_avx2 && features.has(CpuFeature::X86Avx512F) && features.has(CpuFeature::X86Avx512Vl);
    let avx2_state_vectors = if use_avx2 && layout.constant_result.is_none() {
        Some((
            layout
                .root_vector_offset
                .ok_or(ObjectError::InvalidModule("x86 AVX2 root vector is absent"))?,
            layout
                .accept_vector_offset
                .ok_or(ObjectError::InvalidModule(
                    "x86 AVX2 accept vector is absent",
                ))?,
        ))
    } else {
        None
    };
    let avx512_state_vectors = if use_avx512_rows && layout.constant_result.is_none() {
        Some((
            layout.root_vector_offset.ok_or(ObjectError::InvalidModule(
                "x86 AVX-512 root vector is absent",
            ))?,
            layout
                .accept_vector_offset
                .ok_or(ObjectError::InvalidModule(
                    "x86 AVX-512 accept vector is absent",
                ))?,
        ))
    } else {
        None
    };
    let sse2_root_vector_offset =
        if !use_avx2 && !use_avx512_rows && layout.constant_result.is_none() {
            Some(
                layout
                    .root_vector_offset
                    .ok_or(ObjectError::InvalidModule("x86 SSE2 root vector is absent"))?,
            )
        } else {
            None
        };
    let scan = assembler.label()?;
    let vector_scan = assembler.label()?;
    let vector_hit = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let scalar_miss = assembler.label()?;
    let root_recurrence = assembler.label()?;
    let recurrence = assembler.label()?;
    let finish_reached = assembler.label()?;
    let check_root = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;

    x86_emit_abi_validation(&mut assembler, invalid)?;
    x86_emit_result_zero(&mut assembler)?;
    let filter_kind = scanner_filter.map(|_| x86_start_filter_kind(features));
    if let Some(result) = layout.constant_result {
        assembler.instruction(&[0xb8, u8::from(result), 0, 0, 0])?;
        assembler.branch(&[0xe9], done)?;
    } else {
        assembler.instruction(&[0x4c, 0x8d, 0x0d])?; // lea table(%rip), r9
        let table_displacement_label = assembler.label()?;
        assembler.bind(table_displacement_label)?;
        push_bytes(&mut assembler.code, &[0; 4])?;

        assembler.instruction(&[0x48, 0x83, 0xec, 0x50])?; // active[4], reached[4], end
        assembler.instruction(&[0x48, 0x89, 0x4c, 0x24, 0x40])?; // save end index
        if let Some((root_vector_offset, accept_vector_offset)) = avx2_state_vectors {
            // This lowering reserves YMM13/YMM14 across its root scanner. The
            // scanner owns YMM0..YMM12; both constants are caller-saved under
            // the x86-64 Linux and macOS ABIs.
            let mut root_vector_load = vec![0xc4, 0x41, 0x7e, 0x6f, 0xa9];
            root_vector_load.extend_from_slice(&root_vector_offset.to_le_bytes());
            assembler.instruction(&root_vector_load)?; // root vector -> ymm13
            let mut accept_vector_load = vec![0xc4, 0x41, 0x7e, 0x6f, 0xb1];
            accept_vector_load.extend_from_slice(&accept_vector_offset.to_le_bytes());
            assembler.instruction(&accept_vector_load)?; // accept vector -> ymm14
        }
        if let Some((root_vector_offset, accept_vector_offset)) = avx512_state_vectors {
            // YMM16/YMM17 exist only under AVX-512 and are caller-saved under
            // both supported x86-64 ABIs. They are outside every start-filter
            // constant and scratch bank, including the SSE2 scanner selected
            // by an authenticated F+VL target that does not also have BW.
            let mut avx512_root_constant = vec![0x62, 0xc1, 0xfe, 0x28, 0x6f, 0x81];
            avx512_root_constant.extend_from_slice(&root_vector_offset.to_le_bytes());
            assembler.instruction(&avx512_root_constant)?; // root vector -> ymm16
            let mut avx512_accept_constant = vec![0x62, 0xc1, 0xfe, 0x28, 0x6f, 0x89];
            avx512_accept_constant.extend_from_slice(&accept_vector_offset.to_le_bytes());
            assembler.instruction(&avx512_accept_constant)?; // accept vector -> ymm17
        }
        if let Some((filter, kind)) = scanner_filter.zip(filter_kind) {
            x86_emit_start_filter_constants(&mut assembler, filter, kind, 1)?;

            assembler.bind(scan)?;
            assembler.instruction(&[0x48, 0x8b, 0x4c, 0x24, 0x40])?; // restore scanner end
            assembler.bind(vector_scan)?;
            assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
            assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
            assembler.instruction(&[0x48, 0x83, 0xf8, kind.width()])?;
            assembler.branch(&[0x0f, 0x82], scalar_scan)?;
            x86_emit_start_filter_vector_candidate(&mut assembler, filter, kind, vector_hit)?;
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
            assembler.branch(&[0xe9], vector_scan)?;

            assembler.bind(vector_hit)?;
            x86_emit_first_candidate_lane(
                &mut assembler,
                X86CandidateMask::for_filter(filter, kind),
            )?;
            assembler.instruction(&[0x48, 0x01, 0xc2])?;
            assembler.branch(&[0xe9], root_recurrence)?;

            assembler.bind(scalar_scan)?;
            x86_emit_start_filter_scalar_bound(&mut assembler, 0, no_match)?;
            x86_emit_scalar_filter_membership(&mut assembler, filter, scalar_miss)?;
            assembler.branch(&[0xe9], root_recurrence)?;
            assembler.bind(scalar_miss)?;
            assembler.instruction(&[0x48, 0xff, 0xc2])?;
            assembler.branch(&[0xe9], scalar_scan)?;

            // The scanner owns only the exact root frontier. Its scratch
            // registers cannot alter authenticated active words on the stack.
        }
        assembler.bind(root_recurrence)?;
        assembler.instruction(&[0x4c, 0x8b, 0x5c, 0x24, 0x40])?; // end -> r11
        assembler.instruction(&[0x4c, 0x39, 0xda])?; // position >= end
        assembler.branch(&[0x0f, 0x83], no_match)?;
        assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?; // byte at position
        assembler.instruction(&[0x48, 0xff, 0xc2])?; // position += 1
        assembler.instruction(&[0x48, 0xc1, 0xe0, 0x05])?; // byte * native row bytes
        let mut root_only_row = vec![0x4d, 0x8d, 0x94, 0x01];
        root_only_row.extend_from_slice(
            &u32::try_from(MULTIWORD_ROOT_ROWS_OFFSET)
                .map_err(|_| ObjectError::ArithmeticOverflow("x86 root-row base"))?
                .to_le_bytes(),
        );
        assembler.instruction(&root_only_row)?;
        if use_avx2 || use_avx512_rows {
            if use_avx2 {
                assembler.instruction(&[0xc4, 0xc1, 0x7e, 0x6f, 0x02])?;
            } else {
                assembler.instruction(&[0x62, 0xd1, 0xfe, 0x28, 0x6f, 0x02])?;
            }
        } else {
            assembler.instruction(&[0xf3, 0x41, 0x0f, 0x6f, 0x02])?; // root low -> xmm0
            if layout.words > 2 {
                assembler.instruction(&[0xf3, 0x45, 0x0f, 0x6f, 0x6a, 0x10])?; // high -> xmm13
            }
        }
        assembler.branch(&[0xe9], finish_reached)?;

        assembler.bind(recurrence)?;
        assembler.instruction(&[0x4c, 0x39, 0xda])?; // position >= end
        assembler.branch(&[0x0f, 0x83], no_match)?;
        assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?; // byte at position
        assembler.instruction(&[0x48, 0xff, 0xc2])?; // position += 1
        assembler.instruction(&[0x45, 0x8b, 0x04, 0x81])?; // class row offset -> r8d
        assembler.instruction(&[0x48, 0xc1, 0xe0, 0x05])?; // byte * native row bytes
        assembler.instruction(&[0x4d, 0x01, 0xc8])?; // class row pointer -> r8
        let mut root_row = vec![0x4d, 0x8d, 0x94, 0x01];
        root_row.extend_from_slice(
            &u32::try_from(MULTIWORD_ROOT_ROWS_OFFSET)
                .map_err(|_| ObjectError::ArithmeticOverflow("x86 root-row base"))?
                .to_le_bytes(),
        );
        assembler.instruction(&root_row)?; // root row pointer -> r10
        if use_avx2 || use_avx512_rows {
            if use_avx2 {
                assembler.instruction(&[0xc4, 0xc1, 0x7e, 0x6f, 0x02])?; // vmovdqu -> ymm0
            } else {
                assembler.instruction(&[0x62, 0xd1, 0xfe, 0x28, 0x6f, 0x02])?; // vmovdqu64
            }
        } else {
            assembler.instruction(&[0xf3, 0x41, 0x0f, 0x6f, 0x02])?; // root low -> xmm0
            if layout.words > 2 {
                assembler.instruction(&[0xf3, 0x45, 0x0f, 0x6f, 0x6a, 0x10])?; // high -> xmm13
            }
        }

        if layout.subset_source_mask == 0 {
            // Keep the exact parent emitter for direct-only layouts. In
            // particular, retain its source-word address progression and
            // label allocation so the complete native object is unchanged.
            for source_word in 0..layout.words {
                let bit_loop = assembler.label()?;
                let bit_done = assembler.label()?;
                x86_emit_stack_load_rax(
                    &mut assembler,
                    u8::try_from(source_word * 8)
                        .map_err(|_| ObjectError::ArithmeticOverflow("x86 source stack offset"))?,
                )?;
                if layout.roots[source_word] != 0 {
                    x86_emit_movabs(&mut assembler, 0xba, !layout.roots[source_word])?;
                    assembler.instruction(&[0x4c, 0x21, 0xd0])?; // active & !root
                }
                assembler.instruction(&[0x48, 0x85, 0xc0])?;
                assembler.branch(&[0x0f, 0x84], bit_done)?;
                assembler.bind(bit_loop)?;
                assembler.instruction(&[0x48, 0x0f, 0xbc, 0xc8])?; // bsf rax, rcx
                assembler.instruction(&[0x48, 0xc1, 0xe1, 0x05])?; // bit * native row bytes
                if source_word == 0 {
                    assembler.instruction(&[0x49, 0x8d, 0x34, 0x08])?;
                } else {
                    let source_word_offset = source_word
                        .checked_mul(64)
                        .and_then(|states| states.checked_mul(layout.direct_row_words))
                        .and_then(|words| words.checked_mul(core::mem::size_of::<u64>()))
                        .ok_or(ObjectError::ArithmeticOverflow("x86 source-word row base"))?;
                    let mut direct_row = vec![0x49, 0x8d, 0xb4, 0x08];
                    direct_row.extend_from_slice(
                        &u32::try_from(source_word_offset)
                            .map_err(|_| {
                                ObjectError::ArithmeticOverflow("x86 source-word row base")
                            })?
                            .to_le_bytes(),
                    );
                    assembler.instruction(&direct_row)?;
                }
                if use_avx2 {
                    assembler.instruction(&[0xc5, 0xfd, 0xeb, 0x06])?; // vpor
                } else if use_avx512_rows {
                    assembler.instruction(&[0x62, 0xf1, 0x7d, 0x28, 0xeb, 0x06])?; // vpord
                } else {
                    assembler.instruction(&[0x66, 0x0f, 0xeb, 0x06])?; // por low row -> xmm0
                    if layout.words > 2 {
                        assembler.instruction(&[0x66, 0x44, 0x0f, 0xeb, 0x6e, 0x10])?; // high
                    }
                }
                assembler.instruction(&[0x4c, 0x8d, 0x50, 0xff])?; // active - 1 -> r10
                assembler.instruction(&[0x4c, 0x21, 0xd0])?; // clear lowest active bit
                assembler.branch(&[0x0f, 0x85], bit_loop)?;
                assembler.bind(bit_done)?;
            }
        } else {
            for source_word in 0..layout.words {
                let bit_loop = assembler.label()?;
                let bit_done = assembler.label()?;
                x86_emit_stack_load_rax(
                    &mut assembler,
                    u8::try_from(source_word * 8)
                        .map_err(|_| ObjectError::ArithmeticOverflow("x86 source stack offset"))?,
                )?;
                if layout.roots[source_word] != 0 {
                    x86_emit_movabs(&mut assembler, 0xba, !layout.roots[source_word])?;
                    assembler.instruction(&[0x4c, 0x21, 0xd0])?; // active & !root
                }
                assembler.instruction(&[0x48, 0x85, 0xc0])?;
                assembler.branch(&[0x0f, 0x84], bit_done)?;
                let source_row_offset = layout.source_row_offsets[source_word];
                if layout.subset_source_mask & (1_u8 << source_word) != 0 {
                    if layout.source_row_nibbles[source_word] == 0 {
                        return Err(ObjectError::InvalidModule(
                            "x86 multiword subset source has no nibbles",
                        ));
                    }
                    if source_row_offset == 0 {
                        assembler.instruction(&[0x4c, 0x89, 0xc6])?; // class row -> rsi
                    } else {
                        let mut source_base = vec![0x49, 0x8d, 0xb0];
                        source_base.extend_from_slice(&source_row_offset.to_le_bytes());
                        assembler.instruction(&source_base)?; // subset source base -> rsi
                    }
                    assembler.bind(bit_loop)?;
                    assembler.instruction(&[0x48, 0x0f, 0xbc, 0xc8])?; // first live bit -> rcx
                    assembler.instruction(&[0x83, 0xe1, 0xfc])?; // align to its nibble
                    assembler.instruction(&[0x48, 0xd3, 0xe8])?; // discard lower empty nibbles
                    assembler.instruction(&[0x48, 0xc1, 0xe1, 0x07])?; // bit * 128
                    assembler.instruction(&[0x48, 0x01, 0xce])?; // selected nibble base
                    assembler.instruction(&[0x48, 0x89, 0xc1])?; // active subset -> rcx
                    assembler.instruction(&[0x83, 0xe1, 0x0f])?;
                    assembler.instruction(&[0x48, 0xc1, 0xe1, 0x05])?; // subset row offset
                    if use_avx2 {
                        assembler.instruction(&[0xc5, 0xfd, 0xeb, 0x04, 0x0e])?;
                    } else if use_avx512_rows {
                        assembler.instruction(&[0x62, 0xf1, 0x7d, 0x28, 0xeb, 0x04, 0x0e])?;
                    } else {
                        assembler.instruction(&[0x66, 0x0f, 0xeb, 0x04, 0x0e])?;
                        if layout.words > 2 {
                            assembler.instruction(&[0x66, 0x44, 0x0f, 0xeb, 0x6c, 0x0e, 0x10])?;
                        }
                    }
                    assembler.instruction(&[0x48, 0x81, 0xc6, 0x00, 0x02, 0x00, 0x00])?;
                    assembler.instruction(&[0x48, 0xc1, 0xe8, 0x04])?; // consume the nibble
                    assembler.branch(&[0x0f, 0x85], bit_loop)?;
                } else {
                    assembler.bind(bit_loop)?;
                    assembler.instruction(&[0x48, 0x0f, 0xbc, 0xc8])?; // bsf rax, rcx
                    assembler.instruction(&[0x48, 0xc1, 0xe1, 0x05])?; // bit * native row bytes
                    if source_row_offset == 0 {
                        assembler.instruction(&[0x49, 0x8d, 0x34, 0x08])?;
                    } else {
                        let mut direct_row = vec![0x49, 0x8d, 0xb4, 0x08];
                        direct_row.extend_from_slice(&source_row_offset.to_le_bytes());
                        assembler.instruction(&direct_row)?;
                    }
                    if use_avx2 {
                        assembler.instruction(&[0xc5, 0xfd, 0xeb, 0x06])?; // vpor
                    } else if use_avx512_rows {
                        assembler.instruction(&[0x62, 0xf1, 0x7d, 0x28, 0xeb, 0x06])?; // vpord
                    } else {
                        assembler.instruction(&[0x66, 0x0f, 0xeb, 0x06])?; // por low row -> xmm0
                        if layout.words > 2 {
                            assembler.instruction(&[0x66, 0x44, 0x0f, 0xeb, 0x6e, 0x10])?; // high
                        }
                    }
                    assembler.instruction(&[0x4c, 0x8d, 0x50, 0xff])?; // active - 1 -> r10
                    assembler.instruction(&[0x4c, 0x21, 0xd0])?; // clear lowest active bit
                    assembler.branch(&[0x0f, 0x85], bit_loop)?;
                }
                assembler.bind(bit_done)?;
            }
        }

        assembler.bind(finish_reached)?;
        if avx2_state_vectors.is_some() {
            assembler.instruction(&[0xc4, 0xc2, 0x7d, 0x17, 0xc6])?; // vptest accept
            assembler.branch(&[0x0f, 0x85], matched)?;
            assembler.instruction(&[0xc5, 0x95, 0xeb, 0xc0])?; // reached | root -> ymm0
            assembler.instruction(&[0xc5, 0xfe, 0x7f, 0x04, 0x24])?; // active vector
            if scanner_filter.is_some() {
                assembler.instruction(&[0xc5, 0x95, 0xef, 0xc0])?; // active ^ root
                assembler.instruction(&[0xc4, 0xe2, 0x7d, 0x17, 0xc0])?; // vptest
                assembler.branch(&[0x0f, 0x85], recurrence)?;
                assembler.branch(&[0xe9], scan)?;
            } else {
                assembler.branch(&[0xe9], recurrence)?;
            }
        } else if avx512_state_vectors.is_some() {
            // AVX-512F+VL is sufficient for every instruction in this block;
            // in particular, it does not borrow AVX2 or AVX-512BW from real
            // hardware feature correlations. VPTESTMQ publishes the exact
            // per-qword accept test in K1 and KORTESTW sets flags without a
            // reached-vector stack round trip.
            assembler.instruction(&[0x62, 0xb2, 0xfd, 0x28, 0x27, 0xc9])?; // vptestmq k1, ymm0, ymm17
            assembler.instruction(&[0xc5, 0xf8, 0x98, 0xc9])?; // kortestw k1, k1
            assembler.branch(&[0x0f, 0x85], matched)?;
            assembler.instruction(&[0x62, 0xb1, 0x7d, 0x28, 0xeb, 0xc0])?; // reached | root -> ymm0
            assembler.instruction(&[0x62, 0xf1, 0xfe, 0x28, 0x7f, 0x04, 0x24])?; // active vector
            if scanner_filter.is_some() {
                // Every native row and state constant has four authenticated
                // qwords. W2/W3 padding is zero, so all four equality bits
                // must be set before the exact-root scanner may regain control.
                assembler.instruction(&[0x62, 0xb2, 0xfd, 0x28, 0x29, 0xc8])?; // active == root -> k1
                assembler.instruction(&[0xc5, 0xf8, 0x93, 0xc1])?; // kmovw k1, eax
                assembler.instruction(&[0x3c, 0x0f])?; // all four qwords equal
                assembler.branch(&[0x0f, 0x85], recurrence)?;
                assembler.branch(&[0xe9], scan)?;
            } else {
                assembler.branch(&[0xe9], recurrence)?;
            }
        } else if let Some(root_vector_offset) = sse2_root_vector_offset {
            // ACCEPT_BIT is the sign bit of the final word. PMOVMSKB extracts
            // exactly that bit from the reached vector without a stack round
            // trip or an SSE4.1 dependency.
            let (accept_vector_mask, accept_mask_extract) = match layout.words {
                2 => (1_u32 << 15, &[0x66, 0x0f, 0xd7, 0xc0][..]), // xmm0 -> eax
                3 => (1_u32 << 7, &[0x66, 0x41, 0x0f, 0xd7, 0xc5][..]), // xmm13 -> eax
                4 => (1_u32 << 15, &[0x66, 0x41, 0x0f, 0xd7, 0xc5][..]),
                _ => {
                    return Err(ObjectError::InvalidModule(
                        "x86 SSE2 multiword accept vector dimensions",
                    ));
                }
            };
            assembler.instruction(accept_mask_extract)?;
            let mut accept_test = vec![0xa9]; // test imm32, eax
            accept_test.extend_from_slice(&accept_vector_mask.to_le_bytes());
            assembler.instruction(&accept_test)?;
            assembler.branch(&[0x0f, 0x85], matched)?;

            let mut root_low = vec![0x66, 0x41, 0x0f, 0xeb, 0x81]; // por disp32[r9], xmm0
            root_low.extend_from_slice(&root_vector_offset.to_le_bytes());
            assembler.instruction(&root_low)?;
            if layout.words > 2 {
                let mut root_high = vec![0x66, 0x45, 0x0f, 0xeb, 0xa9]; // -> xmm13
                root_high.extend_from_slice(
                    &root_vector_offset
                        .checked_add(16)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "x86 SSE2 high root vector offset",
                        ))?
                        .to_le_bytes(),
                );
                assembler.instruction(&root_high)?;
            }
            assembler.instruction(&[0xf3, 0x0f, 0x7f, 0x04, 0x24])?; // active low
            if layout.words > 2 {
                assembler.instruction(&[0xf3, 0x44, 0x0f, 0x7f, 0x6c, 0x24, 0x10])?; // high
            }

            if scanner_filter.is_some() {
                // The active vectors have already been authenticated on the
                // stack. Reuse their registers to prove active == root using
                // only SSE2 before handing exact roots back to the scanner.
                // Its persistent constants occupy XMM1..XMM8; XMM13 is
                // scanner scratch and is recomputed on every scan block.
                let mut root_equal_low = vec![0x66, 0x41, 0x0f, 0x74, 0x81];
                root_equal_low.extend_from_slice(&root_vector_offset.to_le_bytes());
                assembler.instruction(&root_equal_low)?; // active == root bytes -> xmm0
                if layout.words > 2 {
                    let mut root_equal_high = vec![0x66, 0x45, 0x0f, 0x74, 0xa9];
                    root_equal_high.extend_from_slice(
                        &root_vector_offset
                            .checked_add(16)
                            .ok_or(ObjectError::ArithmeticOverflow(
                                "x86 SSE2 high root vector offset",
                            ))?
                            .to_le_bytes(),
                    );
                    assembler.instruction(&root_equal_high)?;
                    assembler.instruction(&[0x66, 0x41, 0x0f, 0xdb, 0xc5])?; // both halves
                }
                assembler.instruction(&[0x66, 0x0f, 0xd7, 0xc0])?; // byte mask -> eax
                assembler.instruction(&[0x66, 0x83, 0xf8, 0xff])?; // all 16 bytes equal
                assembler.branch(&[0x0f, 0x85], recurrence)?;
                assembler.branch(&[0xe9], scan)?;
            } else {
                assembler.branch(&[0xe9], recurrence)?;
            }
        } else {
            if use_avx512_rows {
                assembler.instruction(&[0x62, 0xf1, 0xfe, 0x28, 0x7f, 0x44, 0x24, 0x01])?; // vmovdqu64
            } else {
                assembler.instruction(&[0xf3, 0x0f, 0x7f, 0x44, 0x24, 0x20])?; // reached low
                if layout.words > 2 {
                    assembler.instruction(&[0xf3, 0x44, 0x0f, 0x7f, 0x6c, 0x24, 0x30])?;
                }
            }
            x86_emit_stack_load_rax(
                &mut assembler,
                u8::try_from(32 + (layout.words - 1) * 8)
                    .map_err(|_| ObjectError::ArithmeticOverflow("x86 accept stack offset"))?,
            )?;
            assembler.instruction(&[0x48, 0x85, 0xc0])?;
            assembler.branch(&[0x0f, 0x88], matched)?;
            if scanner_filter.is_some() {
                assembler.instruction(&[0x31, 0xc9])?; // root-difference union -> rcx
            }
            for word in 0..layout.words {
                x86_emit_stack_load_rax(
                    &mut assembler,
                    u8::try_from(32 + word * 8)
                        .map_err(|_| ObjectError::ArithmeticOverflow("x86 next stack offset"))?,
                )?;
                if layout.roots[word] != 0 {
                    x86_emit_movabs(&mut assembler, 0xba, layout.roots[word])?;
                    assembler.instruction(&[0x4c, 0x09, 0xd0])?;
                }
                x86_emit_stack_store_rax(
                    &mut assembler,
                    u8::try_from(word * 8)
                        .map_err(|_| ObjectError::ArithmeticOverflow("x86 active update offset"))?,
                )?;
                if scanner_filter.is_some() {
                    if layout.roots[word] != 0 {
                        assembler.instruction(&[0x4c, 0x31, 0xd0])?; // next active ^ root
                    }
                    assembler.instruction(&[0x48, 0x09, 0xc1])?; // accumulate non-root bits
                }
            }

            if scanner_filter.is_some() {
                assembler.bind(check_root)?;
                assembler.instruction(&[0x48, 0x85, 0xc9])?;
                assembler.branch(&[0x0f, 0x85], recurrence)?;
                assembler.branch(&[0xe9], scan)?;
            } else {
                assembler.branch(&[0xe9], recurrence)?;
            }
        }

        assembler.bind(no_match)?;
        assembler.instruction(&[0x48, 0x83, 0xc4, 0x50])?;
        assembler.instruction(&[0x31, 0xc0])?;
        assembler.branch(&[0xe9], done)?;
        assembler.bind(matched)?;
        assembler.instruction(&[0x48, 0x83, 0xc4, 0x50])?;
        assembler.instruction(&[0xb8, 0x01, 0, 0, 0])?;
        assembler.branch(&[0xe9], done)?;
        assembler.bind(invalid)?;
        assembler.instruction(&[0xb8, 0x02, 0, 0, 0])?;
        assembler.bind(done)?;
        if use_avx2 || use_avx512_rows || filter_kind.is_some_and(|kind| kind.needs_vzeroupper()) {
            assembler.instruction(&[0xc5, 0xf8, 0x77])?;
        }
        assembler.instruction(&[0xc3])?;
        let finished = assembler.finish_with_label_offsets()?;
        let table_displacement = finished.label_offset(table_displacement_label)?;
        return Ok(NativeBitParallelEmission {
            code: finished.code,
            relocations: vec![ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(
                    table_displacement,
                    "x86 multiword bit-parallel table relocation offset",
                )?,
                kind: RelocationKind::X86PcRelative32,
                symbol: PROGRAM_SYMBOL,
                addend: -4,
            }],
            emitted_nibbles: 0,
            emitted_words: layout.words,
            matched_cursor: NativeBitParallelMatchedCursor::X86Rdx,
        });
    }

    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 0x02, 0, 0, 0])?;
    assembler.bind(done)?;
    if filter_kind.is_some_and(|kind| kind.needs_vzeroupper()) {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    assembler.instruction(&[0xc3])?;
    Ok(NativeBitParallelEmission {
        code: assembler.finish_with_label_offsets()?.code,
        relocations: Vec::new(),
        emitted_nibbles: 0,
        emitted_words: layout.words,
        matched_cursor: NativeBitParallelMatchedCursor::X86Rdx,
    })
}
fn aarch64_load_w_lsl2(destination: u8, base: u8, index: u8) -> Result<u32, ObjectError> {
    Ok(
        0xb860_7800
            | aarch64_reg(index, 16)?
            | aarch64_reg(base, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_orr_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0xaa00_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_ands_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0xea00_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_eor_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0xca00_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_bic_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x8a20_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_load_x_imm(destination: u8, base: u8, byte_offset: u16) -> Result<u32, ObjectError> {
    if !byte_offset.is_multiple_of(8) || byte_offset / 8 > 0x0fff {
        return Err(ObjectError::InvalidModule("AArch64 LDR X offset"));
    }
    Ok(0xf940_0000
        | (u32::from(byte_offset / 8) << 10)
        | aarch64_reg(base, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_rbit_x(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0xdac0_0000 | aarch64_reg(source, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_clz_x(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0xdac0_1000 | aarch64_reg(source, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_umov_d(destination: u8, source: u8, lane: u8) -> Result<u32, ObjectError> {
    if lane > 1 {
        return Err(ObjectError::InvalidModule("AArch64 UMOV D lane"));
    }
    Ok(0x4e08_3c00
        | (u32::from(lane) << 20)
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_emit_abi_validation(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.instruction(0xf100_003f)?; // cmp length, #0
    assembler.branch_cond(AARCH64_MI, invalid)?;
    assembler.instruction(aarch64_cmp_x(3, 1)?)?;
    assembler.branch_cond(AARCH64_HI, invalid)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HI, invalid)?;
    assembler.instruction(0xf100_009f)?; // cmp x4, #0
    assembler.branch_cond(super::AARCH64_EQ, invalid)?;
    assembler.instruction(super::aarch64_and_low_x(5, 4, 3)?)?;
    assembler.instruction(0xf100_00bf)?;
    assembler.branch_cond(AARCH64_NE, invalid)?;
    assembler.instruction(0xf100_001f)?; // cmp x0, #0
    assembler.branch_cond(super::AARCH64_EQ, invalid)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the validated leaf CFG and its exact relocation transaction remain contiguous"
)]
fn lower_aarch64_bit_parallel(
    layout: &NativeBitParallelLayout,
    target: Target,
) -> Result<NativeBitParallelEmission, ObjectError> {
    let scanner_filter = admitted_root_scanner_filter(layout, target);
    if layout.words != 1 {
        return lower_aarch64_multiword_bit_parallel(layout, target, scanner_filter);
    }
    let mut assembler = Aarch64Assembler::new();
    let scan = assembler.label()?;
    let single_vector = assembler.label()?;
    let single_hit = assembler.label()?;
    let batch_hit = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let scalar_miss = assembler.label()?;
    let root_recurrence = assembler.label()?;
    let recurrence = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;

    aarch64_emit_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    if let Some(result) = layout.constant_result {
        assembler.instruction(aarch64_movz_w(0, u16::from(result))?)?;
        assembler.branch(done)?;
    } else {
        let use_sve = target.operating_system == OperatingSystem::Linux
            && target.features.has(CpuFeature::Aarch64Sve);
        let use_asimd = !use_sve && target.features.has(CpuFeature::Aarch64Asimd);
        let table_page = assembler.instruction(0x9000_0005)?; // adrp x5, table
        let table_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;
        aarch64_load_u64_constant(&mut assembler, 9, layout.root)?;
        assembler.instruction(aarch64_mov_x(8, 9)?)?;

        if let Some(filter) = scanner_filter {
            if !use_sve && !use_asimd {
                return Err(ObjectError::InvalidModule(
                    "native bit-parallel AArch64 scanner is not vectorized",
                ));
            }
            if use_sve {
                let kind = if target.features.has(CpuFeature::Aarch64Sve2)
                    && let Some(match_table_offset) = layout.sve2_match_table_offset
                {
                    Aarch64SveFilterKind::Sve2 { match_table_offset }
                } else {
                    Aarch64SveFilterKind::Sve
                };
                aarch64_emit_sve_filter_setup(&mut assembler, filter, kind, 0)?;
                aarch64_emit_sve_start_filter_scanner(
                    &mut assembler,
                    filter,
                    0,
                    kind,
                    false,
                    false,
                    scan,
                    scalar_scan,
                    root_recurrence,
                )?;
            } else {
                aarch64_emit_start_filter_constants(
                    &mut assembler,
                    filter,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
                aarch64_emit_first_lane_constants(
                    &mut assembler,
                    layout
                        .first_lane_table_offset
                        .ok_or(ObjectError::InvalidModule(
                            "native bit-parallel ASIMD first-lane table is absent",
                        ))?,
                )?;

                assembler.bind(scan)?;
                assembler.instruction(super::aarch64_sub_x_reg(12, 3, 2)?)?;
                assembler.instruction(super::aarch64_cmp_x_imm(12, 64)?)?;
                assembler.branch_cond(AARCH64_LO, single_vector)?;
                let first_candidates = aarch64_emit_start_filter_batch_candidates(
                    &mut assembler,
                    filter,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
                aarch64_emit_candidate_batch_any(&mut assembler, first_candidates)?;
                assembler.branch_cond(AARCH64_NE, batch_hit)?;
                assembler.instruction(aarch64_add_x_imm(2, 2, 64)?)?;
                assembler.branch(scan)?;

                assembler.bind(batch_hit)?;
                aarch64_emit_first_candidate_in_batch(&mut assembler, first_candidates)?;
                assembler.branch(root_recurrence)?;

                assembler.bind(single_vector)?;
                assembler.instruction(super::aarch64_sub_x_reg(12, 3, 2)?)?;
                assembler.instruction(super::aarch64_cmp_x_imm(12, 16)?)?;
                assembler.branch_cond(AARCH64_LO, scalar_scan)?;
                aarch64_emit_start_filter_address(&mut assembler, 0)?;
                assembler.instruction(aarch64_load_q(0, 12)?)?;
                aarch64_emit_start_filter_vector_candidates(
                    &mut assembler,
                    filter,
                    0,
                    24,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
                aarch64_emit_candidate_any(&mut assembler, 24)?;
                assembler.branch_cond(AARCH64_NE, single_hit)?;
                assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
                assembler.branch(scan)?;

                assembler.bind(single_hit)?;
                aarch64_emit_first_candidate_lane(&mut assembler, 24)?;
                assembler.branch(root_recurrence)?;
            }

            assembler.bind(scalar_scan)?;
            aarch64_emit_start_filter_scalar_bound(&mut assembler, 0, no_match)?;
            aarch64_emit_scalar_filter_membership(&mut assembler, filter, scalar_miss)?;
            assembler.branch(root_recurrence)?;
            assembler.bind(scalar_miss)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
            assembler.branch(scalar_scan)?;

            assembler.bind(root_recurrence)?;
            assembler.instruction(aarch64_mov_x(8, 9)?)?; // exact root active
        }
        assembler.bind(recurrence)?;
        assembler.instruction(aarch64_cmp_x(2, 3)?)?;
        assembler.branch_cond(AARCH64_HS, no_match)?;
        assembler.instruction(aarch64_load_byte_reg(12, 0, 2)?)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.instruction(aarch64_load_w_lsl2(11, 5, 12)?)?;
        assembler.instruction(aarch64_add_x_reg(11, 5, 11)?)?;
        assembler.instruction(aarch64_movz_w(10, 0)?)?;
        for nibble in 0..layout.source_nibbles {
            let shift = u8::try_from(nibble.checked_mul(NIBBLE_BITS).ok_or(
                ObjectError::ArithmeticOverflow("AArch64 bit-parallel shift"),
            )?)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 bit-parallel shift"))?;
            if shift == 0 {
                assembler.instruction(aarch64_mov_x(12, 8)?)?;
            } else {
                assembler.instruction(aarch64_lsr_x_imm(12, 8, shift)?)?;
            }
            assembler.instruction(aarch64_and_low_x(
                12,
                12,
                u8::try_from(NIBBLE_BITS)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 nibble width"))?,
            )?)?;
            assembler.instruction(aarch64_load_x_lsl3(13, 11, 12)?)?;
            assembler.instruction(aarch64_orr_x(10, 10, 13)?)?;
            if nibble
                .checked_add(1)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 next bit-parallel nibble",
                ))?
                != layout.source_nibbles
            {
                assembler.instruction(aarch64_add_x_imm(
                    11,
                    11,
                    u16::try_from(NIBBLE_ROW_BYTES).map_err(|_| {
                        ObjectError::ArithmeticOverflow("AArch64 bit-parallel row stride")
                    })?,
                )?)?;
            }
        }
        assembler.branch_bit_set_x(10, 63, matched)?;
        assembler.instruction(aarch64_and_low_x(8, 10, 63)?)?;
        assembler.instruction(aarch64_orr_x(8, 8, 9)?)?;
        if scanner_filter.is_some() {
            assembler.instruction(aarch64_cmp_x(8, 9)?)?;
            assembler.branch_cond(AARCH64_EQ, scan)?;
        }
        assembler.branch(recurrence)?;

        assembler.bind(no_match)?;
        assembler.instruction(aarch64_movz_w(0, 0)?)?;
        assembler.branch(done)?;
        assembler.bind(matched)?;
        assembler.instruction(aarch64_movz_w(0, 1)?)?;
        assembler.branch(done)?;
        assembler.bind(invalid)?;
        assembler.instruction(aarch64_movz_w(0, 2)?)?;
        assembler.bind(done)?;
        assembler.instruction(0xd65f_03c0)?;
        let mut relocation_offsets = [table_page, table_page_offset];
        let code = assembler.finish_with_offsets(&mut relocation_offsets)?;
        return Ok(NativeBitParallelEmission {
            code,
            relocations: vec![
                ModuleRelocation {
                    section: TEXT_SECTION,
                    offset: offset_u64(
                        relocation_offsets[0],
                        "AArch64 bit-parallel ADRP relocation offset",
                    )?,
                    kind: RelocationKind::Aarch64Page21,
                    symbol: PROGRAM_SYMBOL,
                    addend: 0,
                },
                ModuleRelocation {
                    section: TEXT_SECTION,
                    offset: offset_u64(
                        relocation_offsets[1],
                        "AArch64 bit-parallel ADD relocation offset",
                    )?,
                    kind: RelocationKind::Aarch64PageOff12,
                    symbol: PROGRAM_SYMBOL,
                    addend: 0,
                },
            ],
            emitted_nibbles: layout.source_nibbles,
            emitted_words: 1,
            matched_cursor: NativeBitParallelMatchedCursor::Aarch64X2,
        });
    }

    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.bind(done)?;
    assembler.instruction(0xd65f_03c0)?;
    Ok(NativeBitParallelEmission {
        code: assembler.finish_with_offsets(&mut [])?,
        relocations: Vec::new(),
        emitted_nibbles: layout.source_nibbles,
        emitted_words: 1,
        matched_cursor: NativeBitParallelMatchedCursor::Aarch64X2,
    })
}

fn lower_aarch64_multiword_bit_parallel(
    layout: &NativeBitParallelLayout,
    target: Target,
    scanner_filter: Option<NativeStartFilter>,
) -> Result<NativeBitParallelEmission, ObjectError> {
    if !(2..=MAX_BIT_PARALLEL_EXISTS_WORDS).contains(&layout.words)
        || layout.source_nibbles != 0
        || layout.consuming_states == 0
        || layout.direct_row_words < layout.words
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 multiword bit-parallel layout dimensions",
        ));
    }
    let mut assembler = Aarch64Assembler::new();
    // W=2..4 is at most two Q registers. A target may use SVE/SVE2 for the
    // root scanner and ASIMD for the fixed-width transition-row unions. Pure
    // SVE targets retain scalar unions because predicating a 16/24/32-byte
    // row costs more instructions and cannot exploit a wider vector length.
    let use_sve = target.operating_system == OperatingSystem::Linux
        && target.features.has(CpuFeature::Aarch64Sve);
    let use_asimd = target.features.has(CpuFeature::Aarch64Asimd);
    // Every fixed-width ASIMD multiword machine keeps the frontier in Q0/Q1.
    // Each admitted candidate lazily loads both root halves in one LDP after
    // its bounds check. The terminal edge repays that instruction even at
    // W=2; wider machines and non-root recurrence steps save additional work.
    let use_asimd_state_vectors = use_asimd;
    let scan = assembler.label()?;
    let single_vector = assembler.label()?;
    let single_hit = assembler.label()?;
    let batch_hit = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let scalar_miss = assembler.label()?;
    let root_recurrence = assembler.label()?;
    let recurrence = assembler.label()?;
    let finish_reached = assembler.label()?;
    let check_root = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;

    let saved_root_bytes = if layout.constant_result.is_none() && !use_asimd_state_vectors {
        if layout.words > 2 { 32 } else { 16 }
    } else {
        0
    };
    if saved_root_bytes != 0 {
        assembler.instruction(super::aarch64_sub_x_imm(31, 31, saved_root_bytes)?)?;
        assembler.instruction(super::aarch64_store_pair_x(19, 20, 31, 0)?)?;
        if layout.words > 2 {
            assembler.instruction(super::aarch64_store_pair_x(21, 22, 31, 16)?)?;
        }
    }
    aarch64_emit_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    if let Some(result) = layout.constant_result {
        assembler.instruction(aarch64_movz_w(0, u16::from(result))?)?;
        assembler.branch(done)?;
    } else {
        let table_page = assembler.instruction(0x9000_0005)?;
        let table_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;
        assembler.instruction(aarch64_add_x_imm(
            4,
            5,
            u16::try_from(MULTIWORD_ROOT_ROWS_OFFSET)
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 root-row base"))?,
        )?)?;
        if !use_asimd_state_vectors {
            for word in 0..layout.words {
                aarch64_load_u64_constant(
                    &mut assembler,
                    u8::try_from(19 + word)
                        .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 root register"))?,
                    layout.roots[word],
                )?;
            }
        }

        if let Some(filter) = scanner_filter {
            if !use_sve && !use_asimd {
                return Err(ObjectError::InvalidModule(
                    "AArch64 multiword bit-parallel scanner is not vectorized",
                ));
            }
            if use_sve {
                let kind = if target.features.has(CpuFeature::Aarch64Sve2)
                    && let Some(match_table_offset) = layout.sve2_match_table_offset
                {
                    Aarch64SveFilterKind::Sve2 { match_table_offset }
                } else {
                    Aarch64SveFilterKind::Sve
                };
                aarch64_emit_sve_filter_setup(&mut assembler, filter, kind, 0)?;
                aarch64_emit_sve_start_filter_scanner(
                    &mut assembler,
                    filter,
                    0,
                    kind,
                    false,
                    false,
                    scan,
                    scalar_scan,
                    root_recurrence,
                )?;
            } else {
                aarch64_emit_start_filter_constants(
                    &mut assembler,
                    filter,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
                aarch64_emit_first_lane_constants(
                    &mut assembler,
                    layout
                        .first_lane_table_offset
                        .ok_or(ObjectError::InvalidModule(
                            "AArch64 multiword bit-parallel ASIMD first-lane table is absent",
                        ))?,
                )?;

                assembler.bind(scan)?;
                assembler.instruction(super::aarch64_sub_x_reg(12, 3, 2)?)?;
                assembler.instruction(super::aarch64_cmp_x_imm(12, 64)?)?;
                assembler.branch_cond(AARCH64_LO, single_vector)?;
                let first_candidates = aarch64_emit_start_filter_batch_candidates(
                    &mut assembler,
                    filter,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
                aarch64_emit_candidate_batch_any(&mut assembler, first_candidates)?;
                assembler.branch_cond(AARCH64_NE, batch_hit)?;
                assembler.instruction(aarch64_add_x_imm(2, 2, 64)?)?;
                assembler.branch(scan)?;

                assembler.bind(batch_hit)?;
                aarch64_emit_first_candidate_in_batch(&mut assembler, first_candidates)?;
                assembler.branch(root_recurrence)?;

                assembler.bind(single_vector)?;
                assembler.instruction(super::aarch64_sub_x_reg(12, 3, 2)?)?;
                assembler.instruction(super::aarch64_cmp_x_imm(12, 16)?)?;
                assembler.branch_cond(AARCH64_LO, scalar_scan)?;
                aarch64_emit_start_filter_address(&mut assembler, 0)?;
                assembler.instruction(aarch64_load_q(0, 12)?)?;
                aarch64_emit_start_filter_vector_candidates(
                    &mut assembler,
                    filter,
                    0,
                    24,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
                aarch64_emit_candidate_any(&mut assembler, 24)?;
                assembler.branch_cond(AARCH64_NE, single_hit)?;
                assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
                assembler.branch(scan)?;

                assembler.bind(single_hit)?;
                aarch64_emit_first_candidate_lane(&mut assembler, 24)?;
                assembler.branch(root_recurrence)?;
            }

            assembler.bind(scalar_scan)?;
            aarch64_emit_start_filter_scalar_bound(&mut assembler, 0, no_match)?;
            aarch64_emit_scalar_filter_membership(&mut assembler, filter, scalar_miss)?;
            assembler.branch(root_recurrence)?;
            assembler.bind(scalar_miss)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
            assembler.branch(scalar_scan)?;

            // Every scanner implementation owns X6, X8, X9, X12 and vector
            // scratch. The exact-root edge consumes directly from the cached
            // root row, so no scanner-owned active register survives it.
        }
        assembler.bind(root_recurrence)?;
        assembler.instruction(aarch64_cmp_x(2, 3)?)?;
        assembler.branch_cond(AARCH64_HS, no_match)?;
        if use_asimd_state_vectors {
            // X4 is the 32-byte root-row base. The adjacent persistent root
            // vector is exactly 64 bytes behind it, so empty searches and
            // scanner misses pay no state setup while every candidate episode
            // materializes both halves with one instruction.
            assembler.instruction(aarch64_load_pair_q_signed(4, 7, 4, -64)?)?;
        }
        assembler.instruction(aarch64_load_byte_reg(7, 0, 2)?)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.instruction(super::aarch64_add_x_lsl(1, 4, 7, 5)?)?; // root row
        if use_asimd {
            if layout.words > 2 {
                assembler.instruction(super::aarch64_load_pair_q(0, 1, 1, 0)?)?;
            } else {
                assembler.instruction(aarch64_load_q(0, 1)?)?;
            }
        } else {
            for word in 0..layout.words {
                assembler.instruction(aarch64_load_x_imm(
                    u8::try_from(12 + word)
                        .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 reached register"))?,
                    1,
                    u16::try_from(word * 8)
                        .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 root row offset"))?,
                )?)?;
            }
        }
        assembler.branch(finish_reached)?;

        assembler.bind(recurrence)?;
        assembler.instruction(aarch64_cmp_x(2, 3)?)?;
        assembler.branch_cond(AARCH64_HS, no_match)?;
        if use_asimd_state_vectors {
            for word in 0..layout.words {
                assembler.instruction(aarch64_umov_d(
                    u8::try_from(8 + word)
                        .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 active register"))?,
                    u8::try_from(2 + word / 2).map_err(|_| {
                        ObjectError::ArithmeticOverflow("AArch64 active vector register")
                    })?,
                    u8::try_from(word % 2).map_err(|_| {
                        ObjectError::ArithmeticOverflow("AArch64 active vector lane")
                    })?,
                )?)?;
            }
        }
        assembler.instruction(aarch64_load_byte_reg(7, 0, 2)?)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.instruction(aarch64_load_w_lsl2(16, 5, 7)?)?;
        assembler.instruction(aarch64_add_x_reg(17, 5, 16)?)?; // class row
        assembler.instruction(super::aarch64_add_x_lsl(1, 4, 7, 5)?)?; // root row
        if use_asimd {
            if layout.words > 2 {
                assembler.instruction(super::aarch64_load_pair_q(0, 1, 1, 0)?)?;
            } else {
                assembler.instruction(aarch64_load_q(0, 1)?)?;
            }
        } else {
            for word in 0..layout.words {
                assembler.instruction(aarch64_load_x_imm(
                    u8::try_from(12 + word)
                        .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 reached register"))?,
                    1,
                    u16::try_from(word * 8)
                        .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 root row offset"))?,
                )?)?;
            }
        }
        if layout.subset_source_mask == 0 {
            // Keep the exact parent direct-row emitter, including its single
            // rolling source pointer, when graph activity selects no hybrid
            // source words.
            assembler.instruction(aarch64_mov_x(1, 17)?)?; // current source-word row base
            for source_word in 0..layout.words {
                let bit_loop = assembler.label()?;
                let bit_done = assembler.label()?;
                let active = u8::try_from(8 + source_word)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 source register"))?;
                if !use_asimd_state_vectors && layout.roots[source_word] != 0 {
                    assembler.instruction(aarch64_bic_x(
                        active,
                        active,
                        u8::try_from(19 + source_word).map_err(|_| {
                            ObjectError::ArithmeticOverflow("AArch64 root register")
                        })?,
                    )?)?;
                }
                assembler.branch_zero_x(active, bit_done)?;
                assembler.bind(bit_loop)?;
                assembler.instruction(aarch64_rbit_x(6, active)?)?;
                assembler.instruction(aarch64_clz_x(6, 6)?)?;
                assembler.instruction(super::aarch64_sub_x_imm(7, active, 1)?)?;
                assembler.instruction(aarch64_ands_x(active, active, 7)?)?;
                assembler.instruction(super::aarch64_add_x_lsl(6, 1, 6, 5)?)?;
                if use_asimd {
                    if layout.words > 2 {
                        assembler.instruction(super::aarch64_load_pair_q(2, 3, 6, 0)?)?;
                        assembler.instruction(aarch64_orr_16b(0, 0, 2)?)?;
                        assembler.instruction(aarch64_orr_16b(1, 1, 3)?)?;
                    } else {
                        assembler.instruction(aarch64_load_q(2, 6)?)?;
                        assembler.instruction(aarch64_orr_16b(0, 0, 2)?)?;
                    }
                } else {
                    for destination_word in 0..layout.words {
                        assembler.instruction(aarch64_load_x_imm(
                            7,
                            6,
                            u16::try_from(destination_word * 8).map_err(|_| {
                                ObjectError::ArithmeticOverflow("AArch64 direct row offset")
                            })?,
                        )?)?;
                        let reached = u8::try_from(12 + destination_word).map_err(|_| {
                            ObjectError::ArithmeticOverflow("AArch64 reached register")
                        })?;
                        assembler.instruction(aarch64_orr_x(reached, reached, 7)?)?;
                    }
                }
                assembler.branch_cond(AARCH64_NE, bit_loop)?;
                assembler.bind(bit_done)?;
                if source_word + 1 != layout.words {
                    assembler.instruction(aarch64_add_x_imm(
                        1,
                        1,
                        u16::try_from(64 * layout.direct_row_words * core::mem::size_of::<u64>())
                            .map_err(|_| {
                            ObjectError::ArithmeticOverflow("AArch64 source-word row stride")
                        })?,
                    )?)?;
                }
            }
        } else {
            for source_word in 0..layout.words {
                let bit_loop = assembler.label()?;
                let bit_done = assembler.label()?;
                let source_row_offset = layout.source_row_offsets[source_word];
                if source_row_offset == 0 {
                    assembler.instruction(aarch64_mov_x(1, 17)?)?;
                } else {
                    aarch64_load_u64_constant(&mut assembler, 6, u64::from(source_row_offset))?;
                    assembler.instruction(aarch64_add_x_reg(1, 17, 6)?)?;
                }
                let active = u8::try_from(8 + source_word)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 source register"))?;
                if !use_asimd_state_vectors && layout.roots[source_word] != 0 {
                    assembler.instruction(aarch64_bic_x(
                        active,
                        active,
                        u8::try_from(19 + source_word).map_err(|_| {
                            ObjectError::ArithmeticOverflow("AArch64 root register")
                        })?,
                    )?)?;
                }
                assembler.branch_zero_x(active, bit_done)?;
                if layout.subset_source_mask & (1_u8 << source_word) != 0 {
                    if layout.source_row_nibbles[source_word] == 0 {
                        return Err(ObjectError::InvalidModule(
                            "AArch64 multiword subset source has no nibbles",
                        ));
                    }
                    assembler.bind(bit_loop)?;
                    assembler.instruction(aarch64_rbit_x(6, active)?)?;
                    assembler.instruction(aarch64_clz_x(6, 6)?)?;
                    assembler.instruction(aarch64_lsr_x_imm(6, 6, 2)?)?; // first nibble
                    assembler.instruction(super::aarch64_add_x_lsl(7, 31, 6, 2)?)?;
                    assembler.instruction(super::aarch64_lsrv_x(active, active, 7)?)?;
                    assembler.instruction(super::aarch64_add_x_lsl(1, 1, 6, 9)?)?;
                    assembler.instruction(aarch64_and_low_x(7, active, 4)?)?;
                    assembler.instruction(super::aarch64_add_x_lsl(6, 1, 7, 5)?)?;
                    if use_asimd {
                        if layout.words > 2 {
                            assembler.instruction(super::aarch64_load_pair_q(2, 3, 6, 0)?)?;
                            assembler.instruction(aarch64_orr_16b(0, 0, 2)?)?;
                            assembler.instruction(aarch64_orr_16b(1, 1, 3)?)?;
                        } else {
                            assembler.instruction(aarch64_load_q(2, 6)?)?;
                            assembler.instruction(aarch64_orr_16b(0, 0, 2)?)?;
                        }
                    } else {
                        for destination_word in 0..layout.words {
                            assembler.instruction(aarch64_load_x_imm(
                                7,
                                6,
                                u16::try_from(destination_word * 8).map_err(|_| {
                                    ObjectError::ArithmeticOverflow("AArch64 subset row offset")
                                })?,
                            )?)?;
                            let reached = u8::try_from(12 + destination_word).map_err(|_| {
                                ObjectError::ArithmeticOverflow("AArch64 reached register")
                            })?;
                            assembler.instruction(aarch64_orr_x(reached, reached, 7)?)?;
                        }
                    }
                    assembler.instruction(aarch64_add_x_imm(1, 1, 512)?)?;
                    assembler.instruction(aarch64_lsr_x_imm(active, active, 4)?)?;
                    assembler.branch_nonzero_x(active, bit_loop)?;
                } else {
                    assembler.bind(bit_loop)?;
                    assembler.instruction(aarch64_rbit_x(6, active)?)?;
                    assembler.instruction(aarch64_clz_x(6, 6)?)?;
                    assembler.instruction(super::aarch64_sub_x_imm(7, active, 1)?)?;
                    assembler.instruction(aarch64_ands_x(active, active, 7)?)?;
                    assembler.instruction(super::aarch64_add_x_lsl(6, 1, 6, 5)?)?;
                    if use_asimd {
                        if layout.words > 2 {
                            assembler.instruction(super::aarch64_load_pair_q(2, 3, 6, 0)?)?;
                            assembler.instruction(aarch64_orr_16b(0, 0, 2)?)?;
                            assembler.instruction(aarch64_orr_16b(1, 1, 3)?)?;
                        } else {
                            assembler.instruction(aarch64_load_q(2, 6)?)?;
                            assembler.instruction(aarch64_orr_16b(0, 0, 2)?)?;
                        }
                    } else {
                        for destination_word in 0..layout.words {
                            assembler.instruction(aarch64_load_x_imm(
                                7,
                                6,
                                u16::try_from(destination_word * 8).map_err(|_| {
                                    ObjectError::ArithmeticOverflow("AArch64 direct row offset")
                                })?,
                            )?)?;
                            let reached = u8::try_from(12 + destination_word).map_err(|_| {
                                ObjectError::ArithmeticOverflow("AArch64 reached register")
                            })?;
                            assembler.instruction(aarch64_orr_x(reached, reached, 7)?)?;
                        }
                    }
                    assembler.branch_cond(AARCH64_NE, bit_loop)?;
                }
                assembler.bind(bit_done)?;
            }
        }

        assembler.bind(finish_reached)?;
        if use_asimd_state_vectors {
            let final_word = layout.words - 1;
            let final_reached = u8::try_from(12 + final_word)
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 final reached register"))?;
            assembler.instruction(aarch64_umov_d(
                final_reached,
                u8::try_from(final_word / 2)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 final reached vector"))?,
                u8::try_from(final_word % 2)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 final reached lane"))?,
            )?)?;
            assembler.branch_bit_set_x(final_reached, 63, matched)?;
            assembler.instruction(aarch64_orr_16b(0, 0, 4)?)?;
            if layout.words > 2 {
                assembler.instruction(aarch64_orr_16b(1, 1, 7)?)?;
            }
            // V2/V3 carry the non-root frontier into recurrence. Root is a
            // subset of active after the ORR, so XOR removes exactly those
            // implicit start states and avoids W scalar BIC/MOV operations.
            assembler.instruction(super::aarch64_eor_16b(2, 0, 4)?)?;
            if layout.words > 2 {
                assembler.instruction(super::aarch64_eor_16b(3, 1, 7)?)?;
            }
            if scanner_filter.is_some() {
                let reduction = if layout.words > 2 { 6 } else { 2 };
                if layout.words > 2 {
                    assembler.instruction(aarch64_orr_16b(6, 2, 3)?)?;
                }
                assembler.instruction(super::aarch64_umaxv_16b(6, reduction)?)?;
                assembler.instruction(super::aarch64_umov_b0(7, 6)?)?;
                assembler.branch_nonzero_w(7, recurrence)?;
                assembler.branch(scan)?;
            } else {
                assembler.branch(recurrence)?;
            }
        } else {
            let final_reached = u8::try_from(11 + layout.words)
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 final reached register"))?;
            assembler.branch_bit_set_x(final_reached, 63, matched)?;
            if scanner_filter.is_some() {
                assembler.instruction(aarch64_movz_w(7, 0)?)?;
            }
            for word in 0..layout.words {
                let active = u8::try_from(8 + word)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 active register"))?;
                let reached = u8::try_from(12 + word)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 reached register"))?;
                let root = u8::try_from(19 + word)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 root register"))?;
                if layout.roots[word] == 0 {
                    assembler.instruction(aarch64_mov_x(active, reached)?)?;
                } else {
                    assembler.instruction(aarch64_orr_x(active, reached, root)?)?;
                }
                if scanner_filter.is_some() {
                    if layout.roots[word] == 0 {
                        assembler.instruction(aarch64_orr_x(7, 7, active)?)?;
                    } else {
                        assembler.instruction(aarch64_eor_x(1, active, root)?)?;
                        assembler.instruction(aarch64_orr_x(7, 7, 1)?)?;
                    }
                }
            }
            if scanner_filter.is_some() {
                assembler.bind(check_root)?;
                assembler.branch_nonzero_x(7, recurrence)?;
                assembler.branch(scan)?;
            } else {
                assembler.branch(recurrence)?;
            }
        }

        assembler.bind(no_match)?;
        assembler.instruction(aarch64_movz_w(0, 0)?)?;
        assembler.branch(done)?;
        assembler.bind(matched)?;
        assembler.instruction(aarch64_movz_w(0, 1)?)?;
        assembler.branch(done)?;
        assembler.bind(invalid)?;
        assembler.instruction(aarch64_movz_w(0, 2)?)?;
        assembler.bind(done)?;
        if saved_root_bytes != 0 {
            if layout.words > 2 {
                assembler.instruction(super::aarch64_load_pair_x(21, 22, 31, 16)?)?;
            }
            assembler.instruction(super::aarch64_load_pair_x(19, 20, 31, 0)?)?;
            assembler.instruction(aarch64_add_x_imm(31, 31, saved_root_bytes)?)?;
        }
        assembler.instruction(0xd65f_03c0)?;
        let mut relocation_offsets = [table_page, table_page_offset];
        let code = assembler.finish_with_offsets(&mut relocation_offsets)?;
        return Ok(NativeBitParallelEmission {
            code,
            relocations: vec![
                ModuleRelocation {
                    section: TEXT_SECTION,
                    offset: offset_u64(
                        relocation_offsets[0],
                        "AArch64 multiword bit-parallel ADRP relocation offset",
                    )?,
                    kind: RelocationKind::Aarch64Page21,
                    symbol: PROGRAM_SYMBOL,
                    addend: 0,
                },
                ModuleRelocation {
                    section: TEXT_SECTION,
                    offset: offset_u64(
                        relocation_offsets[1],
                        "AArch64 multiword bit-parallel ADD relocation offset",
                    )?,
                    kind: RelocationKind::Aarch64PageOff12,
                    symbol: PROGRAM_SYMBOL,
                    addend: 0,
                },
            ],
            emitted_nibbles: 0,
            emitted_words: layout.words,
            matched_cursor: NativeBitParallelMatchedCursor::Aarch64X2,
        });
    }

    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.bind(done)?;
    assembler.instruction(0xd65f_03c0)?;
    Ok(NativeBitParallelEmission {
        code: assembler.finish_with_offsets(&mut [])?,
        relocations: Vec::new(),
        emitted_nibbles: 0,
        emitted_words: layout.words,
        matched_cursor: NativeBitParallelMatchedCursor::Aarch64X2,
    })
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;
    use crate::{
        CompileLimitsV1, CompileMode, CompileRequest, CompiledProgram, CpuFeature,
        DeterminizeLimits, FeatureSet, MatchResult, OutputContract, SearchWindow, SlowAotLimits,
        Target, compile_with_slow_aot_limits,
    };

    const GENERAL_PATTERN: &str = r"(?:ab|c)*z";
    const SELECTIVE_PATTERN: &str = r"(?:\x01\x02|\x03)*\x04";
    const MULTI_NIBBLE_PATTERN: &str = r"(?:abcdef|ghijkl)*z";

    fn fallback_limits() -> CompileLimitsV1 {
        CompileLimitsV1 {
            determinize: DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
            ..CompileLimitsV1::default()
        }
    }

    fn compiled_sidecar_for(pattern: &str, target: Target) -> crate::CompiledRegex {
        let compiled = compile_with_slow_aot_limits(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists)
                .limits(fallback_limits()),
            SlowAotLimits {
                determinize: DeterminizeLimits {
                    max_states: 0,
                    max_transitions: 0,
                    max_work: 0,
                },
                max_allocation_bytes: 0,
                max_native_data_bytes: 0,
            },
        )
        .expect("compile bit-parallel fallback");
        assert!(
            compiled.program().bit_parallel_exists_stats().is_some(),
            "missing bit-parallel sidecar for {pattern:?} on {target:?}"
        );
        compiled
    }

    fn compiled_sidecar(target: Target) -> crate::CompiledRegex {
        compiled_sidecar_for(GENERAL_PATTERN, target)
    }

    fn compiled_multi_nibble_sidecar(target: Target) -> crate::CompiledRegex {
        compiled_sidecar_for(MULTI_NIBBLE_PATTERN, target)
    }

    fn compiled_recurrence_only_oneword_sidecar(
        target: Target,
        represented_wide_filter: bool,
    ) -> crate::CompiledRegex {
        let pattern = if represented_wide_filter {
            r"(?:[A-z]ab|[A-z]cd)*z"
        } else {
            r"(?s:.)z"
        };
        let compiled = compiled_sidecar_for(pattern, target);
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("recurrence-only one-word sidecar");
        assert_eq!(view.stats.words, 1);
        let layout = build_native_bit_parallel_layout(view).expect("recurrence-only W1 layout");
        if represented_wide_filter {
            assert!(
                layout.root_filter.is_some_and(|filter| {
                    filter.candidate_bytes > MAX_ROOT_SKIP_CANDIDATE_BYTES
                })
            );
        } else {
            assert!(layout.root_filter.is_none());
        }
        assert!(admitted_root_scanner_filter(&layout, target).is_none());
        assert!(compiled.receipt().runtime_helper_required);
        assert!(compiled.module().required_runtime_symbol().is_some());
        assert!(
            compiled
                .module()
                .required_prepared_fallback_runtime_symbol()
                .is_some()
        );
        compiled
    }

    fn compiled_multiword_sidecar_for_words(
        target: Target,
        expected_words: usize,
    ) -> crate::CompiledRegex {
        assert!((2..=MAX_BIT_PARALLEL_EXISTS_WORDS).contains(&expected_words));
        let consuming_prefix = (expected_words - 1) * 64;
        let pattern = format!("{}\\x02", "\\x01".repeat(consuming_prefix));
        let compiled = compiled_sidecar_for(&pattern, target);
        let stats = compiled
            .program()
            .bit_parallel_exists_stats()
            .expect("multiword bit-parallel sidecar");
        assert_eq!(stats.words, expected_words);
        assert!(stats.consuming_states >= consuming_prefix);
        compiled
    }

    fn compiled_multiword_sidecar(target: Target) -> crate::CompiledRegex {
        compiled_multiword_sidecar_for_words(target, 2)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the asserted W2-W4 fixture domain makes its pattern length exact"
    )]
    fn compiled_range_scanner_multiword_sidecar_for_words(
        target: Target,
        expected_words: usize,
    ) -> crate::CompiledRegex {
        assert!((2..=MAX_BIT_PARALLEL_EXISTS_WORDS).contains(&expected_words));
        let consuming_prefix = (expected_words - 1) * 64;
        let pattern = format!("[a-z]{}z", "a".repeat(consuming_prefix - 1));
        let compiled = compiled_sidecar_for(&pattern, target);
        let stats = compiled
            .program()
            .bit_parallel_exists_stats()
            .expect("range-scanner multiword bit-parallel sidecar");
        assert_eq!(stats.words, expected_words);
        compiled
    }

    fn compiled_hybrid_subset_sidecar(target: Target) -> crate::CompiledRegex {
        let pattern = format!("(?s-u:{}z)", ".".repeat(128));
        let compiled = compiled_sidecar_for(&pattern, target);
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("hybrid subset sidecar");
        let layout = build_native_bit_parallel_layout(view).expect("hybrid subset layout");
        assert_ne!(layout.subset_source_mask, 0);
        compiled
    }

    fn compiled_recurrence_only_sidecar_for_words(
        target: Target,
        expected_words: usize,
    ) -> crate::CompiledRegex {
        assert!((2..=MAX_BIT_PARALLEL_EXISTS_WORDS).contains(&expected_words));
        let consuming_prefix = (expected_words - 1) * 64;
        let pattern = format!("(?s:.){}z", "a".repeat(consuming_prefix));
        let compiled = compiled_sidecar_for(&pattern, target);
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("recurrence-only multiword sidecar");
        assert_eq!(view.stats.words, expected_words);
        let layout = build_native_bit_parallel_layout(view).expect("recurrence-only layout");
        assert!(layout.root_filter.is_none());
        assert!(layout.constant_result.is_none());
        assert!(admitted_root_scanner_filter(&layout, target).is_none());
        assert_eq!(
            compiled.module().start_accelerator(),
            StartAccelerator::None
        );
        assert!(compiled.module().required_runtime_symbol().is_none());
        compiled
    }

    fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count()
    }

    fn digest_hex(digest: [u8; 32]) -> String {
        let mut result = String::with_capacity(64);
        for byte in digest {
            write!(&mut result, "{byte:02x}").unwrap();
        }
        result
    }

    #[test]
    fn zero_subset_mask_objects_are_stable_across_isas_and_word_counts() {
        // Full-object digests from a source-neutral rare-root fixture. These
        // pin the table layout, recurrence emitter, relocations, and target
        // feature routing together; a structural layout assertion alone would
        // miss code drift in the zero-mask compatibility path. Every digest
        // includes the 64-byte native text alignment introduced by 58696f4e0;
        // that object-level change invalidated all 21 earlier frozen values.
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Vl);
        let sve = FeatureSet::of(CpuFeature::Aarch64Sve);
        let sve2 = sve.with(CpuFeature::Aarch64Sve2);
        let targets = [
            (
                "x86-sse2",
                Target::x86_64_linux(),
                [
                    "8647285c9c6b109c277f033b3943379ebeaafd2f1314c6ab10bae1e2db4e9cfd",
                    "9ebba671831ed07022a0ad82f038af1c3d70569446365293a8a60136922530e0",
                    "43447af9e53a813b26a30486d4366cd0bae235683fd76233149011854fa01127",
                ],
            ),
            (
                "x86-avx2",
                Target::x86_64_linux()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                [
                    "c109ad97a046d926c3466fa193004e99b0194ba642d7e0cad0cd180c28a2b107",
                    "6347ed615cd12bd5d9a857afe024ebbe9334ecc4c903e8a7602e6b933e864088",
                    "21d046021fbc5a3e6fb875f35fb7b959ce59b87dc49b7d322eafd8dae3376048",
                ],
            ),
            (
                "x86-avx512",
                Target::x86_64_linux().with_features(avx512).unwrap(),
                [
                    "5471e787158544d90480d8acf921ebc73bbb97a394e8f5d7e5daa39ee4674e70",
                    "bc3a3dd2d978f1d37adf3e44178c2c6a28d1dccc0a80a235dd6180d3fe9d2594",
                    "99acd2e275c6fb5e041c57007d913a9a441efdd73612fdb5e17d8b4057c585da",
                ],
            ),
            (
                "arm-scalar",
                Target::aarch64_macos(),
                [
                    "9dc27ab8c7827d2cc99ec83e8b0f982300fe789a272dba191af21d77f0f4e579",
                    "0e487892b48de76baae0460bdd752766c3144c7da5f0a0da1250629411c326f2",
                    "0dfcbb63cc23135395de0d087be9b941a701cdaabfe37949aa617994cd9f3eb5",
                ],
            ),
            (
                "arm-asimd",
                Target::aarch64_macos()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
                [
                    "b5d0a93926e66648c0d83a87356f986043af9a21fb28ce53a8d0f31e014b2591",
                    "f2e980aa9bb05168f11f53c015810ef306e21eb8e0f1507a2e8fbae1db557f9b",
                    "2e823bc4510502658bddd105f11cf7bf5495a19b49052b5f0f19d0354c0cccf3",
                ],
            ),
            (
                "arm-sve",
                Target::aarch64_linux().with_features(sve).unwrap(),
                [
                    "a7d86a56584a311d3751b98c1fe797c8908ef2d65fb5f7226c8cc79c1dfba6d7",
                    "9b8a5a30b80c78ef858354f8bddb79a5d821dd1ec9a6b08e89cfc0cbe64cb21a",
                    "1b9605a81b1639de2cd9f99de56a9a73bbf92805518cac5fbdf366a4c97df0b7",
                ],
            ),
            (
                "arm-sve2",
                Target::aarch64_linux().with_features(sve2).unwrap(),
                [
                    "ec75fdb1558239b36316594a504ebb33b0f167cb959392cff3c8032f55e0433e",
                    "3aef28e53fe84e8b09fdbea7fdfc71b04aea3096e43db66cf7eaa020f0814e23",
                    "898cb367994abf6e09c8a83e3bbe5f46882690f44f3aacf5632000fa189b4a5c",
                ],
            ),
        ];
        // Retain every target/word failure in one run. A changed first object
        // must not hide drift in the other independently frozen objects.
        let mut digest_mismatches = Vec::new();
        for (target_name, target, expected_digests) in targets {
            for (word_index, pattern_repetitions) in [78_usize, 142, 206].into_iter().enumerate() {
                let pattern = format!(r"(?:{}Q|(?-u:\xFF))", r"\x01".repeat(pattern_repetitions));
                let compiled = compiled_sidecar_for(&pattern, target);
                let view = compiled
                    .program()
                    .native_bit_parallel_exists_view()
                    .expect("zero-mask compatibility sidecar");
                let layout = build_native_bit_parallel_layout(view)
                    .expect("zero-mask compatibility native layout");
                assert_eq!(layout.words, word_index + 2, "{target_name}");
                assert_eq!(layout.subset_source_mask, 0, "{target_name}");
                let actual = digest_hex(compiled.receipt().object_sha256);
                if actual != expected_digests[word_index] {
                    digest_mismatches.push((
                        target_name,
                        word_index + 2,
                        actual,
                        expected_digests[word_index],
                    ));
                }
            }
        }
        assert!(
            digest_mismatches.is_empty(),
            "zero-mask object digest mismatches: {digest_mismatches:#?}"
        );
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the authenticated W2-W4 table dimensions bound every test-only offset"
    )]
    fn assert_multiword_native_padding_is_zero(
        layout: &NativeBitParallelLayout,
        view: NativeBitParallelExistsView<'_>,
    ) {
        assert!((2..=MAX_BIT_PARALLEL_EXISTS_WORDS).contains(&layout.words));
        assert_eq!(layout.direct_row_words, MAX_BIT_PARALLEL_EXISTS_WORDS);
        let root_vector_offset = usize::try_from(
            layout
                .root_vector_offset
                .expect("multiword root vector offset"),
        )
        .unwrap();
        let accept_vector_offset = usize::try_from(
            layout
                .accept_vector_offset
                .expect("multiword accept vector offset"),
        )
        .unwrap();
        for word in 0..MAX_BIT_PARALLEL_EXISTS_WORDS {
            let root_offset = root_vector_offset + word * core::mem::size_of::<u64>();
            let accept_offset = accept_vector_offset + word * core::mem::size_of::<u64>();
            let root = u64::from_le_bytes(
                layout.data[root_offset..root_offset + 8]
                    .try_into()
                    .unwrap(),
            );
            let accept = u64::from_le_bytes(
                layout.data[accept_offset..accept_offset + 8]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(root, layout.roots[word]);
            assert_eq!(
                accept,
                if word + 1 == layout.words {
                    ACCEPT_BIT
                } else {
                    0
                }
            );
            if word >= layout.words {
                assert_eq!(root, 0, "W{} root padding word {word}", layout.words);
                assert_eq!(accept, 0, "W{} accept padding word {word}", layout.words);
            }
        }

        let row_bytes = MAX_BIT_PARALLEL_EXISTS_WORDS * core::mem::size_of::<u64>();
        for byte in 0..BYTE_VALUES {
            let row_offset = MULTIWORD_ROOT_ROWS_OFFSET + byte * row_bytes;
            for word in layout.words..MAX_BIT_PARALLEL_EXISTS_WORDS {
                let offset = row_offset + word * core::mem::size_of::<u64>();
                assert_eq!(
                    u64::from_le_bytes(layout.data[offset..offset + 8].try_into().unwrap()),
                    0,
                    "W{} byte {byte:#04x} root-row padding word {word}",
                    layout.words
                );
            }
        }

        let direct_offset = MULTIWORD_ROOT_ROWS_OFFSET + BYTE_VALUES * row_bytes;
        let direct_rows = view.stats.byte_classes * view.stats.consuming_states;
        for row in 0..direct_rows {
            let row_offset = direct_offset + row * row_bytes;
            for word in layout.words..MAX_BIT_PARALLEL_EXISTS_WORDS {
                let offset = row_offset + word * core::mem::size_of::<u64>();
                assert_eq!(
                    u64::from_le_bytes(layout.data[offset..offset + 8].try_into().unwrap()),
                    0,
                    "W{} direct row {row} padding word {word}",
                    layout.words
                );
            }
        }
    }

    fn synthetic_view<'a>(
        consuming_states: usize,
        byte_to_class: &'a [u8; BYTE_VALUES],
        masks: &'a [u64],
    ) -> NativeBitParallelExistsView<'a> {
        let source_nibbles = consuming_states.div_ceil(NIBBLE_BITS);
        let transition_bytes = core::mem::size_of_val(masks);
        let retained_bytes = core::mem::size_of::<BitParallelExists>()
            .checked_add(transition_bytes)
            .expect("synthetic retained extent");
        NativeBitParallelExistsView {
            byte_to_class,
            transition_masks: masks,
            root_transition_masks: &[],
            initial: [1, 0, 0, 0],
            stats: crate::BitParallelExistsStats {
                thompson_states: consuming_states.max(1),
                thompson_edges: 0,
                consuming_states,
                byte_classes: 1,
                words: 1,
                source_nibbles,
                transition_entries: masks.len(),
                root_transition_entries: 0,
                retained_bytes,
                peak_build_bytes: retained_bytes,
                derivation_work: 0,
            },
        }
    }

    fn synthetic_multiword_view<'a>(
        consuming_states: usize,
        byte_to_class: &'a [u8; BYTE_VALUES],
        masks: &'a [u64],
        root_masks: &'a [u64],
        initial: [u64; MAX_BIT_PARALLEL_EXISTS_WORDS],
    ) -> NativeBitParallelExistsView<'a> {
        let words = consuming_states.checked_add(1).unwrap().div_ceil(64);
        let byte_classes = usize::from(*byte_to_class.iter().max().unwrap()) + 1;
        let retained_bytes = core::mem::size_of::<BitParallelExists>()
            .checked_add(core::mem::size_of_val(masks))
            .and_then(|bytes| bytes.checked_add(core::mem::size_of_val(root_masks)))
            .unwrap();
        NativeBitParallelExistsView {
            byte_to_class,
            transition_masks: masks,
            root_transition_masks: root_masks,
            initial,
            stats: crate::BitParallelExistsStats {
                thompson_states: consuming_states,
                thompson_edges: 0,
                consuming_states,
                byte_classes,
                words,
                source_nibbles: 0,
                transition_entries: masks.len(),
                root_transition_entries: root_masks.len(),
                retained_bytes,
                peak_build_bytes: retained_bytes,
                derivation_work: 0,
            },
        }
    }

    #[test]
    fn dense_graph_activity_selects_exact_bounded_hybrid_subset_rows() {
        let consuming_states = 65;
        let words = 2;
        let byte_to_class = [0_u8; BYTE_VALUES];
        let mut masks = vec![0_u64; consuming_states * words];
        for ordinal in 0..consuming_states {
            masks[ordinal * words] = u64::MAX;
        }
        let mut root_masks = vec![0_u64; BYTE_VALUES * words];
        for byte in 0..BYTE_VALUES {
            root_masks[byte * words] = u64::MAX;
        }
        let view = synthetic_multiword_view(
            consuming_states,
            &byte_to_class,
            &masks,
            &root_masks,
            [1, 0, 0, 0],
        );
        let layout = build_native_bit_parallel_layout(view).expect("dense hybrid layout");
        assert_eq!(layout.subset_source_mask, 1);
        assert_eq!(layout.source_row_nibbles, [16, 0, 0, 0]);
        assert_eq!(layout.source_row_offsets[0], 0);
        assert_eq!(layout.source_row_offsets[1], 16 * 16 * 32);
        assert!(layout.data.len() <= MAX_NATIVE_BIT_PARALLEL_DATA_BYTES);

        let class_row = usize::try_from(u32::from_le_bytes(
            layout.data[..CLASSIFIER_ENTRY_BYTES].try_into().unwrap(),
        ))
        .unwrap();
        for nibble in 0..16 {
            for subset in 0..NIBBLE_SUBSETS {
                let packed_row = class_row + (nibble * NIBBLE_SUBSETS + subset) * 32;
                let expected = if subset == 0 { 0 } else { u64::MAX };
                assert_eq!(
                    u64::from_le_bytes(layout.data[packed_row..packed_row + 8].try_into().unwrap()),
                    expected
                );
                for word in 1..MAX_BIT_PARALLEL_EXISTS_WORDS {
                    assert_eq!(
                        u64::from_le_bytes(
                            layout.data[packed_row + word * 8..packed_row + word * 8 + 8]
                                .try_into()
                                .unwrap()
                        ),
                        0
                    );
                }
            }
        }
        let cold_row = class_row + usize::try_from(layout.source_row_offsets[1]).unwrap();
        assert_eq!(
            u64::from_le_bytes(layout.data[cold_row..cold_row + 8].try_into().unwrap()),
            u64::MAX
        );

        let avx2 = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let x86 = lower_x86_64_bit_parallel(&layout, avx2).expect("x86 hybrid leaf");
        assert_eq!(x86.emitted_words, words);
        assert!(x86.code.len() <= MAX_NATIVE_BIT_PARALLEL_CODE_BYTES);
        assert_eq!(count_bytes(&x86.code, &[0x83, 0xe1, 0xfc]), 1);
        assert_eq!(count_bytes(&x86.code, &[0xc5, 0xfd, 0xeb, 0x04, 0x0e]), 1);

        let asimd = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let arm = lower_aarch64_bit_parallel(&layout, asimd).expect("ASIMD hybrid leaf");
        assert_eq!(arm.emitted_words, words);
        assert!(arm.code.len() <= MAX_NATIVE_BIT_PARALLEL_CODE_BYTES);
        let arm_words = arm
            .code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(arm_words.contains(&super::super::aarch64_lsrv_x(8, 8, 7).unwrap()));
        assert!(arm_words.contains(&aarch64_and_low_x(7, 8, 4).unwrap()));

        // This is the address progression emitted by both loops: after one
        // loaded nibble, BSF or RBIT+CLZ skips directly over every interior
        // zero nibble before the next load.
        fn emitted_subset_rows(mut active: u64) -> Vec<(usize, usize)> {
            let mut nibble_base = 0_usize;
            let mut rows = Vec::new();
            while active != 0 {
                let aligned_bit = usize::try_from(active.trailing_zeros()).unwrap() & !3;
                active >>= aligned_bit;
                nibble_base += aligned_bit / NIBBLE_BITS;
                rows.push((nibble_base, usize::try_from(active & 0x0f).unwrap()));
                active >>= NIBBLE_BITS;
                nibble_base += 1;
            }
            rows
        }
        for (active, expected) in [
            (1_u64 | 1_u64 << 60, vec![(0, 1), (15, 1)]),
            (
                0b1011_u64 | 0b1100_u64 << 28 | 1_u64 << 60,
                vec![(0, 11), (7, 12), (15, 1)],
            ),
        ] {
            let rows = emitted_subset_rows(active);
            assert_eq!(rows, expected);
            assert_eq!(
                rows.len(),
                usize::try_from(nonzero_nibbles(active)).unwrap()
            );
            for (nibble, subset) in rows {
                let offset = class_row + (nibble * NIBBLE_SUBSETS + subset) * 32;
                assert!(
                    offset < class_row + usize::try_from(layout.source_row_offsets[1]).unwrap()
                );
            }
        }
    }

    #[test]
    fn hybrid_activity_uses_exact_byte_class_mass_not_class_count() {
        let consuming_states = 65;
        let words = 2;
        let mut byte_to_class = [0_u8; BYTE_VALUES];
        byte_to_class[BYTE_VALUES - 1] = 1;
        let mut masks = vec![0_u64; 2 * consuming_states * words];
        let rare_class = consuming_states * words;
        for ordinal in 0..consuming_states {
            masks[rare_class + ordinal * words] = u64::MAX;
        }
        let mut root_masks = vec![0_u64; BYTE_VALUES * words];
        root_masks[(BYTE_VALUES - 1) * words] = u64::MAX;
        let view = synthetic_multiword_view(
            consuming_states,
            &byte_to_class,
            &masks,
            &root_masks,
            [1, 0, 0, 0],
        );
        let activity = multiword_source_activity(view, [1, 0, 0, 0]).unwrap();
        assert_eq!(
            activity[0].expected_bits_q32,
            MULTIWORD_ACTIVITY_PROBABILITY_SCALE * 63 / 256
        );
        assert_eq!(
            activity[0].expected_nibbles_q32,
            MULTIWORD_ACTIVITY_PROBABILITY_SCALE * 16 / 256
        );
        let layout = build_native_bit_parallel_layout(view).expect("byte-mass layout");
        assert_eq!(layout.subset_source_mask, 0);
    }

    #[test]
    fn general_wildcard_pipeline_admits_hybrid_rows_without_pattern_identity() {
        let compiled = compiled_hybrid_subset_sidecar(Target::aarch64_macos());
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .unwrap();
        assert!(view.stats.words >= 2);
        assert!(compiled.module().required_runtime_symbol().is_none());
        assert!(
            compiled.module().sections()[1].bytes().len() <= MAX_NATIVE_BIT_PARALLEL_DATA_BYTES
        );
        assert!(compiled.module().code_bytes() <= MAX_NATIVE_BIT_PARALLEL_CODE_BYTES);
    }

    #[test]
    fn canonical_table_extent_and_union_addressing_are_exhaustive() {
        let compiled = compiled_sidecar(Target::aarch64_macos());
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native bit-parallel view");
        assert!(
            view.stats.consuming_states <= 16,
            "keep full subset audit bounded"
        );
        let layout = build_native_bit_parallel_layout(view).expect("native layout");
        let transition_extent = CLASSIFIER_BYTES
            .checked_add(core::mem::size_of_val(view.transition_masks))
            .expect("native transition extent");
        assert_eq!(
            layout.first_lane_table_offset,
            Some(u32::try_from(transition_extent).unwrap())
        );
        assert_eq!(layout.data.len(), transition_extent + 32);
        let class_stride = view.stats.source_nibbles * NIBBLE_ROW_BYTES;
        for (byte, &class) in view.byte_to_class.iter().enumerate() {
            let classifier_offset = byte * CLASSIFIER_ENTRY_BYTES;
            let actual = u32::from_le_bytes(
                layout.data[classifier_offset..classifier_offset + CLASSIFIER_ENTRY_BYTES]
                    .try_into()
                    .expect("one classifier offset"),
            );
            assert_eq!(
                usize::try_from(actual).unwrap(),
                CLASSIFIER_BYTES + usize::from(class) * class_stride
            );
        }

        for class in 0..view.stats.byte_classes {
            for nibble in 0..view.stats.source_nibbles {
                for subset in 0..NIBBLE_SUBSETS {
                    let table_index =
                        (class * view.stats.source_nibbles + nibble) * NIBBLE_SUBSETS + subset;
                    let offset = CLASSIFIER_BYTES + table_index * core::mem::size_of::<u64>();
                    let actual = u64::from_le_bytes(
                        layout.data[offset..offset + 8]
                            .try_into()
                            .expect("one native union word"),
                    );
                    assert_eq!(actual, view.transition_masks[table_index]);
                }
            }
        }

        let subset_count = 1_u64 << view.stats.consuming_states;
        for active in 0..subset_count {
            for byte in 0_u16..=u16::from(u8::MAX) {
                let byte = u8::try_from(byte).unwrap();
                let class = usize::from(view.byte_to_class[usize::from(byte)]);
                let classifier_offset = usize::from(byte) * CLASSIFIER_ENTRY_BYTES;
                let class_offset = usize::try_from(u32::from_le_bytes(
                    layout.data[classifier_offset..classifier_offset + CLASSIFIER_ENTRY_BYTES]
                        .try_into()
                        .expect("one classifier offset"),
                ))
                .unwrap();
                assert_eq!(class_offset, CLASSIFIER_BYTES + class * class_stride);
                let mut canonical = 0_u64;
                let mut packed = 0_u64;
                for nibble in 0..view.stats.source_nibbles {
                    let subset = usize::try_from((active >> (nibble * NIBBLE_BITS)) & 15)
                        .expect("four-bit subset");
                    let index =
                        (class * view.stats.source_nibbles + nibble) * NIBBLE_SUBSETS + subset;
                    canonical |= view.transition_masks[index];
                    let offset = class_offset
                        + nibble * NIBBLE_ROW_BYTES
                        + subset * core::mem::size_of::<u64>();
                    packed |= u64::from_le_bytes(
                        layout.data[offset..offset + 8]
                            .try_into()
                            .expect("packed transition word"),
                    );
                }
                assert_eq!(packed, canonical, "active={active:#x}, byte={byte:#04x}");
            }
        }
    }

    #[test]
    fn exact_w1_has_one_recurrence_load_and_empty_root_departures_fold_false() {
        let compiled = compiled_sidecar(Target::x86_64_linux());
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native W1 view");
        let layout = build_native_bit_parallel_layout(view).expect("native W1 layout");
        assert_eq!(layout.source_nibbles, 1);
        let filter = layout.root_filter.expect("exact root filter");
        assert!(!filter.ranges().is_empty());
        assert!(filter.candidate_bytes <= MAX_ROOT_SKIP_CANDIDATE_BYTES);
        let root_subset = usize::try_from(layout.root & 0x0f).unwrap();
        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(view.byte_to_class[usize::from(byte)]);
            let reached = view.transition_masks[class * NIBBLE_SUBSETS + root_subset];
            let expected = reached & (ACCEPT_BIT | (CONSUMING_BITS & !layout.root)) != 0;
            let admitted = filter
                .ranges()
                .iter()
                .any(|range| range.start <= byte && byte <= range.end);
            assert_eq!(admitted, expected, "root departure byte {byte:#04x}");
            if !admitted {
                assert_eq!(reached & ACCEPT_BIT, 0);
                assert_eq!((reached & CONSUMING_BITS) | layout.root, layout.root);
            }
        }

        let avx2 = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let x86 = lower_x86_64_bit_parallel(&layout, avx2).expect("x86 W1 leaf");
        assert_eq!(x86.emitted_nibbles, 1);
        assert_eq!(count_bytes(&x86.code, &[0x41, 0x8b, 0x04, 0x81]), 1);
        assert_eq!(count_bytes(&x86.code, &[0xc5, 0xf8, 0x77]), 1);
        assert_eq!(x86.relocations.len(), 1);

        let asimd = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let aarch64 = lower_aarch64_bit_parallel(&layout, asimd).expect("ASIMD W1 leaf");
        let union_load = aarch64_load_x_lsl3(13, 11, 12).unwrap();
        let classifier_load = aarch64_load_w_lsl2(11, 5, 12).unwrap();
        for expected in [union_load, classifier_load] {
            assert_eq!(
                aarch64
                    .code
                    .chunks_exact(4)
                    .filter(|bytes| u32::from_le_bytes((*bytes).try_into().unwrap()) == expected)
                    .count(),
                1
            );
        }
        assert_eq!(aarch64.emitted_nibbles, 1);
        assert_eq!(aarch64.relocations.len(), 2);

        let byte_to_class = [0_u8; BYTE_VALUES];
        let max_one_word_nibbles = 63_usize.div_ceil(NIBBLE_BITS);
        for source_nibbles in 2..=max_one_word_nibbles {
            let consuming_states = if source_nibbles == max_one_word_nibbles {
                63
            } else {
                source_nibbles * NIBBLE_BITS
            };
            let masks = vec![0_u64; source_nibbles * NIBBLE_SUBSETS];
            let view = synthetic_view(consuming_states, &byte_to_class, &masks);
            let layout = build_native_bit_parallel_layout(view).expect("synthetic native layout");
            assert_eq!(layout.source_nibbles, source_nibbles);
            assert_eq!(layout.constant_result, Some(false));
            assert!(layout.root_filter.is_none());
            assert!(layout.data.is_empty());
            let native = lower_native_bit_parallel_exists(view, Target::x86_64_linux())
                .unwrap()
                .expect("constant-false native leaf");
            assert!(!native.needs_runtime);
            assert_eq!(native.start_accelerator, StartAccelerator::None);
        }
    }

    #[test]
    fn standalone_one_word_portfolio_requires_a_selective_vector_root() {
        let target = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let compiled = compiled_sidecar(target);
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native one-word view");
        let mut layout = build_native_bit_parallel_layout(view).expect("native one-word layout");
        assert_eq!(layout.words, 1);
        assert_eq!(layout.source_nibbles, 1);
        assert!(layout.constant_result.is_none());

        let singleton = |byte: u8| {
            let mut membership = [0_u64; 4];
            membership[usize::from(byte) / 64] |= 1_u64 << (usize::from(byte) % 64);
            filter_from_membership_words(membership, 0, false)
                .expect("valid singleton filter")
                .expect("nonempty singleton filter")
        };
        layout.root_filter = Some(singleton(1));
        assert!(admitted_standalone_one_word_exists(&layout, target));
        layout.root_filter = Some(singleton(b'e'));
        assert!(!admitted_standalone_one_word_exists(&layout, target));
        layout.root_filter = None;
        assert!(!admitted_standalone_one_word_exists(&layout, target));

        layout.constant_result = Some(false);
        assert!(admitted_standalone_one_word_exists(&layout, target));
    }

    #[test]
    fn standalone_multiword_portfolio_uses_only_recurrence_without_a_scanner() {
        let target = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let compiled = compiled_multiword_sidecar(target);
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native multiword view");
        let mut layout = build_native_bit_parallel_layout(view).expect("native multiword layout");
        assert!(layout.words > 1);
        assert!(layout.constant_result.is_none());

        let singleton = |byte: u8| {
            let mut membership = [0_u64; 4];
            membership[usize::from(byte) / 64] |= 1_u64 << (usize::from(byte) % 64);
            filter_from_membership_words(membership, 0, false)
                .expect("valid singleton filter")
                .expect("nonempty singleton filter")
        };
        layout.root_filter = Some(singleton(1));
        assert!(!admitted_standalone_exists(&layout, target));
        layout.root_filter = Some(singleton(b'e'));
        assert!(!admitted_standalone_exists(&layout, target));
        layout.root_filter = None;
        assert!(admitted_standalone_exists(&layout, target));
    }

    #[test]
    fn multi_nibble_recurrence_and_root_filter_publish_exactly() {
        let avx2 = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let compiled = compiled_multi_nibble_sidecar(avx2);
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("multi-nibble native view");
        assert!(view.stats.consuming_states > NIBBLE_BITS);
        assert!(view.stats.consuming_states <= 63);
        assert!(view.stats.source_nibbles > 1);
        let layout = build_native_bit_parallel_layout(view).expect("multi-nibble native layout");
        let filter = layout.root_filter.expect("multi-nibble root filter");
        assert!(!filter.ranges().is_empty());
        assert!(filter.candidate_bytes <= MAX_ROOT_SKIP_CANDIDATE_BYTES);

        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(view.byte_to_class[usize::from(byte)]);
            let class_base = class * view.stats.source_nibbles * NIBBLE_SUBSETS;
            let mut reached = 0_u64;
            for nibble in 0..view.stats.source_nibbles {
                let subset =
                    usize::try_from((layout.root >> (nibble * NIBBLE_BITS)) & 0x0f).unwrap();
                reached |= view.transition_masks[class_base + nibble * NIBBLE_SUBSETS + subset];
            }
            let expected = reached & (ACCEPT_BIT | (CONSUMING_BITS & !layout.root)) != 0;
            let admitted = filter
                .ranges()
                .iter()
                .any(|range| range.start <= byte && byte <= range.end);
            assert_eq!(admitted, expected, "root departure byte {byte:#04x}");
            if !admitted {
                assert_eq!(reached & ACCEPT_BIT, 0);
                assert_eq!((reached & CONSUMING_BITS) | layout.root, layout.root);
            }
        }

        let x86 = lower_x86_64_bit_parallel(&layout, avx2).expect("x86 multi-nibble leaf");
        assert_eq!(x86.emitted_nibbles, view.stats.source_nibbles);
        assert_eq!(
            count_bytes(&x86.code, &[0x4a, 0x0b, 0x84, 0xc6]),
            view.stats.source_nibbles
        );
        assert_eq!(x86.relocations.len(), 1);

        let asimd = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let aarch64 =
            lower_aarch64_bit_parallel(&layout, asimd).expect("AArch64 multi-nibble leaf");
        let union_load = aarch64_load_x_lsl3(13, 11, 12).unwrap();
        assert_eq!(
            aarch64
                .code
                .chunks_exact(4)
                .filter(|bytes| u32::from_le_bytes((*bytes).try_into().unwrap()) == union_load)
                .count(),
            view.stats.source_nibbles
        );
        assert_eq!(aarch64.emitted_nibbles, view.stats.source_nibbles);
        assert_eq!(aarch64.relocations.len(), 2);
        assert!(
            lower_native_bit_parallel_exists(view, avx2)
                .expect("multi-nibble portfolio decision")
                .is_none()
        );
        assert!(
            lower_native_bit_parallel_exact_endpoint(view, avx2)
                .expect("multi-nibble endpoint decision")
                .is_some()
        );
        assert!(
            compiled
                .module()
                .required_prepared_fallback_runtime_symbol()
                .is_some()
        );
    }

    #[test]
    fn multiword_rows_root_cache_and_native_receipts_are_exact() {
        let target = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let compiled = compiled_multiword_sidecar(target);
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native multiword view");
        let layout = build_native_bit_parallel_layout(view).expect("native multiword layout");
        assert_eq!(layout.words, view.stats.words);
        assert_eq!(layout.words, 2);
        assert_eq!(layout.direct_row_words, MAX_BIT_PARALLEL_EXISTS_WORDS);
        assert_eq!(layout.source_nibbles, 0);
        assert_eq!(layout.consuming_states, view.stats.consuming_states);
        let filter = layout.root_filter.expect("multiword root filter");
        assert!(filter.candidate_bytes <= MAX_ROOT_SKIP_CANDIDATE_BYTES);
        assert!(!filter.ranges().is_empty());

        let root_vector_offset = usize::try_from(
            layout
                .root_vector_offset
                .expect("multiword native root vector"),
        )
        .unwrap();
        let accept_vector_offset = usize::try_from(
            layout
                .accept_vector_offset
                .expect("multiword native accept vector"),
        )
        .unwrap();
        assert_eq!(root_vector_offset, MULTIWORD_ROOT_VECTOR_OFFSET);
        assert_eq!(accept_vector_offset, MULTIWORD_ACCEPT_VECTOR_OFFSET);
        assert_eq!(MULTIWORD_ROOT_ROWS_OFFSET, accept_vector_offset + 32);
        assert_eq!(
            aarch64_load_pair_q_signed(4, 7, 4, -64).unwrap(),
            0xad7e_1c84
        );
        assert!(aarch64_load_pair_q_signed(4, 7, 4, -1040).is_err());
        assert!(aarch64_load_pair_q_signed(4, 7, 4, 1024).is_err());
        assert!(aarch64_load_pair_q_signed(4, 7, 4, -63).is_err());
        for word in 0..MAX_BIT_PARALLEL_EXISTS_WORDS {
            let packed_root = u64::from_le_bytes(
                layout.data[root_vector_offset + word * 8..root_vector_offset + word * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
            let packed_accept = u64::from_le_bytes(
                layout.data[accept_vector_offset + word * 8..accept_vector_offset + word * 8 + 8]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(packed_root, layout.roots[word]);
            assert_eq!(
                packed_accept,
                if word + 1 == layout.words {
                    ACCEPT_BIT
                } else {
                    0
                }
            );
        }

        let direct_offset = MULTIWORD_ROOT_ROWS_OFFSET
            + BYTE_VALUES * MAX_BIT_PARALLEL_EXISTS_WORDS * core::mem::size_of::<u64>();
        let class_stride =
            layout.consuming_states * layout.direct_row_words * core::mem::size_of::<u64>();
        for byte in 0..BYTE_VALUES {
            let classifier = byte * CLASSIFIER_ENTRY_BYTES;
            let class_row = usize::try_from(u32::from_le_bytes(
                layout.data[classifier..classifier + CLASSIFIER_ENTRY_BYTES]
                    .try_into()
                    .unwrap(),
            ))
            .unwrap();
            assert_eq!(
                class_row,
                direct_offset + usize::from(view.byte_to_class[byte]) * class_stride
            );
            let root_row = MULTIWORD_ROOT_ROWS_OFFSET + byte * 4 * 8;
            let source = byte * view.stats.words;
            for word in 0..view.stats.words {
                let packed = u64::from_le_bytes(
                    layout.data[root_row + word * 8..root_row + word * 8 + 8]
                        .try_into()
                        .unwrap(),
                );
                assert_eq!(packed, view.root_transition_masks[source + word]);
            }
        }

        let x86 = lower_x86_64_bit_parallel(
            &layout,
            Target::x86_64_linux()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap(),
        )
        .expect("x86 multiword leaf");
        assert_eq!(x86.emitted_words, layout.words);
        assert_eq!(x86.relocations.len(), 1);
        assert!(count_bytes(&x86.code, &[0xc4, 0xc2, 0x7d, 0x17, 0xc6]) > 0);
        assert!(count_bytes(&x86.code, &[0xc5, 0x95, 0xeb, 0xc0]) > 0);
        assert!(count_bytes(&x86.code, &[0xc5, 0xfe, 0x7f, 0x04, 0x24]) > 0);
        let arm = lower_aarch64_bit_parallel(&layout, target).expect("AArch64 multiword leaf");
        assert_eq!(arm.emitted_words, layout.words);
        assert_eq!(arm.relocations.len(), 2);
        let arm_words = arm
            .code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(arm_words.contains(&aarch64_load_pair_q_signed(4, 7, 4, -64).unwrap()));
        assert!(arm_words.contains(&aarch64_orr_16b(0, 0, 4).unwrap()));
        assert!(arm_words.contains(&super::super::aarch64_eor_16b(2, 0, 4).unwrap()));
        assert!(arm_words.contains(&super::super::aarch64_umaxv_16b(6, 2).unwrap()));
        assert!(arm_words.contains(&aarch64_umov_d(8, 2, 0).unwrap()));
        assert!(!arm_words.contains(&aarch64_umov_d(8, 0, 0).unwrap()));
        assert!(!arm_words.contains(&aarch64_bic_x(8, 8, 19).unwrap()));
        assert!(!arm_words.contains(&super::super::aarch64_store_pair_x(19, 20, 31, 0).unwrap()));
        assert!(!arm_words.contains(&super::super::aarch64_load_pair_x(19, 20, 31, 0).unwrap()));
        let scalar_arm = lower_aarch64_bit_parallel(&layout, Target::aarch64_macos())
            .expect("scalar AArch64 multiword leaf");
        let scalar_arm_words = scalar_arm
            .code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(
            scalar_arm_words.contains(&super::super::aarch64_store_pair_x(19, 20, 31, 0).unwrap())
        );
        assert!(
            scalar_arm_words.contains(&super::super::aarch64_load_pair_x(19, 20, 31, 0).unwrap())
        );
        assert!(scalar_arm_words.contains(&aarch64_bic_x(8, 8, 19).unwrap()));
        assert!(compiled.module().required_runtime_symbol().is_some());
        assert!(compiled.module().prepared_entry_symbol().is_some());
    }

    #[test]
    fn baseline_x86_multiword_finish_stays_in_sse2_vectors() {
        let target = Target::x86_64_linux();
        for words in 2..=MAX_BIT_PARALLEL_EXISTS_WORDS {
            for scanner in [true, false] {
                let compiled = if scanner {
                    compiled_multiword_sidecar_for_words(target, words)
                } else {
                    compiled_recurrence_only_sidecar_for_words(target, words)
                };
                let view = compiled
                    .program()
                    .native_bit_parallel_exists_view()
                    .expect("multiword SSE2 view");
                let layout = build_native_bit_parallel_layout(view).expect("multiword SSE2 layout");
                assert_eq!(
                    admitted_root_scanner_filter(&layout, target).is_some(),
                    scanner
                );
                let emission =
                    lower_x86_64_bit_parallel(&layout, target).expect("multiword SSE2 leaf");
                let root_offset = layout.root_vector_offset.expect("SSE2 root vector offset");
                for padding_word in words..MAX_BIT_PARALLEL_EXISTS_WORDS {
                    let offset = usize::try_from(root_offset).unwrap() + padding_word * 8;
                    assert_eq!(
                        u64::from_le_bytes(layout.data[offset..offset + 8].try_into().unwrap()),
                        0,
                        "W{words} root-vector padding word {padding_word}"
                    );
                }

                let mut accept_test = if words == 2 {
                    vec![0x66, 0x0f, 0xd7, 0xc0, 0xa9]
                } else {
                    vec![0x66, 0x41, 0x0f, 0xd7, 0xc5, 0xa9]
                };
                let accept_mask = if words == 3 { 1_u32 << 7 } else { 1_u32 << 15 };
                accept_test.extend_from_slice(&accept_mask.to_le_bytes());
                assert_eq!(count_bytes(&emission.code, &accept_test), 1);

                let mut root_low = vec![0x66, 0x41, 0x0f, 0xeb, 0x81];
                root_low.extend_from_slice(&root_offset.to_le_bytes());
                assert_eq!(count_bytes(&emission.code, &root_low), 1);
                assert_eq!(
                    count_bytes(&emission.code, &[0xf3, 0x0f, 0x7f, 0x04, 0x24]),
                    1
                );
                if words > 2 {
                    let mut root_high = vec![0x66, 0x45, 0x0f, 0xeb, 0xa9];
                    root_high.extend_from_slice(&(root_offset + 16).to_le_bytes());
                    assert_eq!(count_bytes(&emission.code, &root_high), 1);
                    assert_eq!(
                        count_bytes(&emission.code, &[0xf3, 0x44, 0x0f, 0x7f, 0x6c, 0x24, 0x10]),
                        1
                    );
                }

                let mut root_equal_low = vec![0x66, 0x41, 0x0f, 0x74, 0x81];
                root_equal_low.extend_from_slice(&root_offset.to_le_bytes());
                assert_eq!(
                    count_bytes(&emission.code, &root_equal_low),
                    usize::from(scanner)
                );
                assert_eq!(
                    count_bytes(
                        &emission.code,
                        &[
                            0x66, 0x0f, 0xd7, 0xc0, // pmovmskb xmm0, eax
                            0x66, 0x83, 0xf8, 0xff, // cmp 0xffff, ax
                        ]
                    ),
                    usize::from(scanner)
                );
                if words > 2 {
                    let mut root_equal_high = vec![0x66, 0x45, 0x0f, 0x74, 0xa9];
                    root_equal_high.extend_from_slice(&(root_offset + 16).to_le_bytes());
                    assert_eq!(
                        count_bytes(&emission.code, &root_equal_high),
                        usize::from(scanner)
                    );
                    assert_eq!(
                        count_bytes(&emission.code, &[0x66, 0x41, 0x0f, 0xdb, 0xc5]),
                        usize::from(scanner)
                    );
                }
                assert_eq!(
                    count_bytes(&emission.code, &[0x66, 0x0f, 0x38, 0x17]),
                    0,
                    "SSE4.1 PTEST leaked into W{words}"
                );
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the cross-OS feature lattice, encodings, and padding form one AVX-512 receipt"
    )]
    fn avx512f_vl_multiword_finish_stays_in_vectors_for_sparse_and_dense_rows() {
        let f_vl = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Vl);
        let f_bw_vl = f_vl.with(CpuFeature::X86Avx512Bw);
        assert!(!f_vl.has(CpuFeature::X86Avx2));
        assert!(!f_vl.has(CpuFeature::X86Avx512Bw));

        for words in 2..=MAX_BIT_PARALLEL_EXISTS_WORDS {
            // Some(true) is an exact sparse scanner, Some(false) is a sparse
            // range scanner, and None is the dense recurrence-only route.
            for scanner_shape in [Some(true), Some(false), None] {
                let scanner = scanner_shape.is_some();
                let source_target = Target::x86_64_linux().with_features(f_vl).unwrap();
                let compiled = match scanner_shape {
                    Some(true) => compiled_multiword_sidecar_for_words(source_target, words),
                    Some(false) => {
                        compiled_range_scanner_multiword_sidecar_for_words(source_target, words)
                    }
                    None => compiled_recurrence_only_sidecar_for_words(source_target, words),
                };
                let view = compiled
                    .program()
                    .native_bit_parallel_exists_view()
                    .expect("multiword AVX-512 view");
                let layout =
                    build_native_bit_parallel_layout(view).expect("multiword AVX-512 layout");
                assert_multiword_native_padding_is_zero(&layout, view);
                if let Some(expected_exact) = scanner_shape {
                    assert_eq!(
                        layout
                            .root_filter
                            .expect("sparse AVX-512 root scanner")
                            .is_exact(),
                        expected_exact
                    );
                }

                for base_target in [Target::x86_64_linux(), Target::x86_64_macos()] {
                    for features in [f_vl, f_bw_vl] {
                        let target = base_target.with_features(features).unwrap();
                        assert_eq!(
                            admitted_root_scanner_filter(&layout, target).is_some(),
                            scanner
                        );
                        let emission = lower_x86_64_bit_parallel(&layout, target)
                            .expect("multiword AVX-512 leaf");
                        let root_offset = layout
                            .root_vector_offset
                            .expect("AVX-512 root vector offset");
                        let accept_offset = layout
                            .accept_vector_offset
                            .expect("AVX-512 accept vector offset");

                        let mut root_load = vec![0x62, 0xc1, 0xfe, 0x28, 0x6f, 0x81];
                        root_load.extend_from_slice(&root_offset.to_le_bytes());
                        let mut accept_load = vec![0x62, 0xc1, 0xfe, 0x28, 0x6f, 0x89];
                        accept_load.extend_from_slice(&accept_offset.to_le_bytes());
                        assert_eq!(count_bytes(&emission.code, &root_load), 1);
                        assert_eq!(count_bytes(&emission.code, &accept_load), 1);
                        assert_eq!(
                            count_bytes(&emission.code, &[0x62, 0xb2, 0xfd, 0x28, 0x27, 0xc9]),
                            1
                        );
                        assert_eq!(count_bytes(&emission.code, &[0xc5, 0xf8, 0x98, 0xc9]), 1);
                        assert_eq!(
                            count_bytes(&emission.code, &[0x62, 0xb1, 0x7d, 0x28, 0xeb, 0xc0]),
                            1
                        );
                        assert_eq!(
                            count_bytes(
                                &emission.code,
                                &[0x62, 0xf1, 0xfe, 0x28, 0x7f, 0x04, 0x24]
                            ),
                            1
                        );
                        assert_eq!(
                            count_bytes(&emission.code, &[0x62, 0xb2, 0xfd, 0x28, 0x29, 0xc8]),
                            usize::from(scanner)
                        );
                        assert_eq!(
                            count_bytes(&emission.code, &[0xc5, 0xf8, 0x93, 0xc1, 0x3c, 0x0f]),
                            usize::from(scanner)
                        );

                        // The old AVX-512 finish spilled reached at rsp+32 and
                        // then rebuilt active one scalar word at a time.
                        assert_eq!(
                            count_bytes(
                                &emission.code,
                                &[0x62, 0xf1, 0xfe, 0x28, 0x7f, 0x44, 0x24, 0x01]
                            ),
                            0
                        );
                        for offset in [0_u8, 8, 16, 24] {
                            assert_eq!(
                                count_bytes(&emission.code, &[0x48, 0x89, 0x44, 0x24, offset]),
                                0,
                                "W{words} scalar active store at {offset}"
                            );
                        }
                        assert_eq!(
                            count_bytes(&emission.code, &[0xc4, 0xc2, 0x7d, 0x17, 0xc6]),
                            0,
                            "W{words} borrowed the AVX2 accept test"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn exact_endpoint_lowering_receipts_first_end_cursor_on_every_isa_tier() {
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F)
            .with(CpuFeature::X86Avx512Bw)
            .with(CpuFeature::X86Avx512Vl);
        let sve = FeatureSet::of(CpuFeature::Aarch64Sve);
        let sve2 = sve.with(CpuFeature::Aarch64Sve2);
        let targets = [
            (
                Target::x86_64_linux(),
                NativeBitParallelMatchedCursor::X86Rdx,
            ),
            (
                Target::x86_64_macos()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                NativeBitParallelMatchedCursor::X86Rdx,
            ),
            (
                Target::x86_64_linux().with_features(avx512).unwrap(),
                NativeBitParallelMatchedCursor::X86Rdx,
            ),
            (
                Target::aarch64_linux(),
                NativeBitParallelMatchedCursor::Aarch64X2,
            ),
            (
                Target::aarch64_macos()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
                NativeBitParallelMatchedCursor::Aarch64X2,
            ),
            (
                Target::aarch64_linux().with_features(sve).unwrap(),
                NativeBitParallelMatchedCursor::Aarch64X2,
            ),
            (
                Target::aarch64_linux().with_features(sve2).unwrap(),
                NativeBitParallelMatchedCursor::Aarch64X2,
            ),
        ];
        for (target, expected_cursor) in targets {
            let one_word = compiled_sidecar(target);
            let one_view = one_word
                .program()
                .native_bit_parallel_exists_view()
                .expect("one-word exact endpoint view");
            let one = lower_native_bit_parallel_exact_endpoint(one_view, target)
                .unwrap()
                .expect("one-word exact endpoint lowering");
            assert_eq!(one.matched_cursor, expected_cursor, "{target:?}/W1");
            assert!(!one.lowering.needs_runtime);

            let multiword = compiled_recurrence_only_sidecar_for_words(target, 2);
            let multi_view = multiword
                .program()
                .native_bit_parallel_exists_view()
                .expect("multiword exact endpoint view");
            let multi = lower_native_bit_parallel_exact_endpoint(multi_view, target)
                .unwrap()
                .expect("multiword exact endpoint lowering");
            assert_eq!(multi.matched_cursor, expected_cursor, "{target:?}/W2");
            assert!(!multi.lowering.needs_runtime);
        }
    }

    #[test]
    fn dense_multiword_roots_use_general_recurrence_only_native_leaf() {
        let avx2 = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let avx512 = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Vl))
            .unwrap();
        let asimd = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let sve = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
            .unwrap();
        for target in [
            Target::x86_64_linux(),
            avx2,
            avx512,
            Target::aarch64_linux(),
            asimd,
            sve,
        ] {
            for words in 2..=MAX_BIT_PARALLEL_EXISTS_WORDS {
                let compiled = compiled_recurrence_only_sidecar_for_words(target, words);
                assert!(
                    !compiled.receipt().runtime_helper_required,
                    "{target:?} W={words}"
                );
                assert_eq!(
                    compiled.module().start_accelerator(),
                    StartAccelerator::None,
                    "{target:?} W={words}"
                );
                let bytes = compiled
                    .program()
                    .serialize()
                    .expect("serialize dense sidecar");
                let restored = CompiledProgram::deserialize(&bytes).expect("restore dense sidecar");
                let restored_module = super::super::CompiledModule::lower(&restored, target)
                    .expect("lower restored dense sidecar");
                assert!(restored_module.required_runtime_symbol().is_none());
                assert_eq!(restored_module.start_accelerator(), StartAccelerator::None);
            }
        }

        let compiled = compiled_recurrence_only_sidecar_for_words(avx2, 4);
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("dense W4 view");
        let layout = build_native_bit_parallel_layout(view).expect("dense W4 layout");
        let scalar = lower_x86_64_bit_parallel(&layout, Target::x86_64_linux())
            .expect("scalar dense x86 leaf");
        let vector = lower_x86_64_bit_parallel(&layout, avx2).expect("AVX2 dense x86 leaf");
        let wide = lower_x86_64_bit_parallel(&layout, avx512).expect("AVX-512 dense x86 leaf");
        assert!(count_bytes(&scalar.code, &[0xf3, 0x41, 0x0f, 0x6f, 0x02]) > 0);
        assert!(count_bytes(&scalar.code, &[0x66, 0x0f, 0xeb, 0x06]) > 0);
        assert_eq!(
            count_bytes(&scalar.code, &[0xc4, 0xc1, 0x7e, 0x6f, 0x02]),
            0
        );
        assert!(count_bytes(&vector.code, &[0xc4, 0xc1, 0x7e, 0x6f, 0x02]) > 0);
        assert!(count_bytes(&wide.code, &[0x62, 0xd1, 0xfe, 0x28, 0x6f, 0x02]) > 0);
        let arm = lower_aarch64_bit_parallel(&layout, asimd).expect("ASIMD dense W4 leaf");
        let arm_words = arm
            .code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(!arm_words.contains(&super::super::aarch64_store_pair_x(21, 22, 31, 16).unwrap()));
        assert!(!arm_words.contains(&super::super::aarch64_load_pair_x(21, 22, 31, 16).unwrap()));
        assert!(arm_words.contains(&super::super::aarch64_eor_16b(3, 1, 7).unwrap()));
        assert!(arm_words.contains(&aarch64_umov_d(11, 3, 1).unwrap()));
        assert!(!arm_words.contains(&aarch64_bic_x(8, 8, 19).unwrap()));
        let scalar_arm = lower_aarch64_bit_parallel(&layout, Target::aarch64_linux())
            .expect("scalar AArch64 dense W4 leaf");
        let scalar_arm_words = scalar_arm
            .code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(
            scalar_arm_words.contains(&super::super::aarch64_store_pair_x(21, 22, 31, 16).unwrap())
        );
        assert!(
            scalar_arm_words.contains(&super::super::aarch64_load_pair_x(21, 22, 31, 16).unwrap())
        );
    }

    #[test]
    fn dense_and_wide_oneword_roots_defer_to_the_prepared_portfolio() {
        let targets = [
            Target::x86_64_linux(),
            Target::x86_64_linux()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap(),
            Target::aarch64_linux(),
            Target::aarch64_macos()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
                .unwrap(),
        ];
        for target in targets {
            for represented_wide_filter in [false, true] {
                let compiled =
                    compiled_recurrence_only_oneword_sidecar(target, represented_wide_filter);
                assert!(compiled.receipt().runtime_helper_required, "{target:?}");
                // The prepared incumbent may own its own authenticated root
                // scanner even though the standalone recurrence declined.
                assert_ne!(
                    compiled.module().start_accelerator(),
                    StartAccelerator::None,
                    "{target:?}"
                );
                assert!(compiled.module().required_runtime_symbol().is_some());
            }
        }
    }

    #[test]
    fn malformed_native_views_decline_without_weakening_the_runtime_fallback() {
        let compiled = compiled_sidecar(Target::x86_64_linux());
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native bit-parallel view");

        let mut wrong_extent = view;
        wrong_extent.stats.transition_entries -= 1;
        assert!(build_native_bit_parallel_layout(wrong_extent).is_none());

        let mut wrong_nibbles = view;
        wrong_nibbles.stats.source_nibbles += 1;
        assert!(build_native_bit_parallel_layout(wrong_nibbles).is_none());

        let mut wrong_class = *view.byte_to_class;
        wrong_class[0] = u8::try_from(view.stats.byte_classes).unwrap();
        let wrong_class = NativeBitParallelExistsView {
            byte_to_class: &wrong_class,
            ..view
        };
        assert!(build_native_bit_parallel_layout(wrong_class).is_none());

        let mut wrong_mask = view.transition_masks.to_vec();
        wrong_mask[0] = 1;
        let wrong_mask = NativeBitParallelExistsView {
            transition_masks: &wrong_mask,
            ..view
        };
        assert!(build_native_bit_parallel_layout(wrong_mask).is_none());
    }

    #[test]
    fn publication_receipt_names_scanner_or_recurrence_only_native_leaf() {
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F)
            .with(CpuFeature::X86Avx512Bw)
            .with(CpuFeature::X86Avx512Vl);
        let sve = FeatureSet::of(CpuFeature::Aarch64Sve);
        let sve2 = sve.with(CpuFeature::Aarch64Sve2);
        let mixed_sve2 = FeatureSet::of(CpuFeature::Aarch64Asimd).union(sve2);
        let targets = [
            (Target::x86_64_linux(), StartAccelerator::X86Sse2),
            (
                Target::x86_64_macos()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                StartAccelerator::X86Avx2,
            ),
            (
                Target::x86_64_linux().with_features(avx512).unwrap(),
                StartAccelerator::X86Avx512Bw,
            ),
            (
                Target::aarch64_macos()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
                StartAccelerator::Aarch64Asimd,
            ),
            (
                Target::aarch64_linux().with_features(sve).unwrap(),
                StartAccelerator::Aarch64Sve,
            ),
            (
                Target::aarch64_linux().with_features(sve2).unwrap(),
                StartAccelerator::Aarch64Sve2,
            ),
            (
                Target::aarch64_linux().with_features(mixed_sve2).unwrap(),
                StartAccelerator::Aarch64Sve2,
            ),
            (
                Target::aarch64_macos().with_features(mixed_sve2).unwrap(),
                StartAccelerator::Aarch64Asimd,
            ),
        ];

        let mut canonical_native_data = None::<Vec<u8>>;
        for (target, expected_accelerator) in targets {
            let compiled = compiled_sidecar_for(SELECTIVE_PATTERN, target);
            assert!(!compiled.receipt().runtime_helper_required, "{target:?}");
            assert!(
                compiled.module().required_runtime_symbol().is_none(),
                "{target:?}"
            );
            assert_eq!(
                compiled.module().start_accelerator(),
                expected_accelerator,
                "{target:?}"
            );
            assert_eq!(compiled.module().anchored_prefix_filter_bytes(), 0);
            let data = compiled.module().sections()[1].bytes();
            if let Some(expected) = &canonical_native_data {
                assert_eq!(
                    data, expected,
                    "target-private table changed for {target:?}"
                );
            } else {
                canonical_native_data = Some(data.to_vec());
            }
            assert!(compiled.module().relocations().iter().all(|relocation| {
                relocation.section == TEXT_SECTION
                    && relocation.symbol == PROGRAM_SYMBOL
                    && usize::try_from(relocation.offset)
                        .is_ok_and(|offset| offset < compiled.module().code_bytes())
            }));
            match target.architecture {
                Architecture::X86_64 => assert_eq!(
                    compiled
                        .module()
                        .relocations()
                        .iter()
                        .map(|relocation| relocation.kind)
                        .collect::<Vec<_>>(),
                    [RelocationKind::X86PcRelative32]
                ),
                Architecture::Aarch64 => assert_eq!(
                    compiled
                        .module()
                        .relocations()
                        .iter()
                        .map(|relocation| relocation.kind)
                        .collect::<Vec<_>>(),
                    [
                        RelocationKind::Aarch64Page21,
                        RelocationKind::Aarch64PageOff12
                    ]
                ),
            }

            let bytes = compiled.program().serialize().expect("serialize sidecar");
            let restored = CompiledProgram::deserialize(&bytes).expect("restore sidecar");
            let restored_module = super::super::CompiledModule::lower(&restored, target)
                .expect("lower restored sidecar");
            assert!(restored_module.required_runtime_symbol().is_none());
            assert_eq!(restored_module.sections()[1].bytes(), data);
            assert_eq!(
                restored_module.relocations(),
                compiled.module().relocations()
            );
        }
    }

    #[test]
    fn multiword_scanner_receipt_defers_to_the_prepared_owner() {
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F)
            .with(CpuFeature::X86Avx512Bw)
            .with(CpuFeature::X86Avx512Vl);
        let sve = FeatureSet::of(CpuFeature::Aarch64Sve);
        let sve2 = sve.with(CpuFeature::Aarch64Sve2);
        let mixed_sve2 = FeatureSet::of(CpuFeature::Aarch64Asimd).union(sve2);
        let targets = [
            Target::x86_64_linux(),
            Target::x86_64_macos()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap(),
            Target::x86_64_linux().with_features(avx512).unwrap(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
            Target::aarch64_macos()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
            Target::aarch64_linux().with_features(sve).unwrap(),
            Target::aarch64_linux().with_features(sve2).unwrap(),
            Target::aarch64_linux()
                .with_features(mixed_sve2)
                .unwrap(),
            Target::aarch64_macos().with_features(sve2).unwrap(),
            Target::aarch64_macos()
                .with_features(mixed_sve2)
                .unwrap(),
        ];
        for target in targets {
            let compiled = compiled_multiword_sidecar(target);
            let has_vector_root_scanner = target.architecture == Architecture::X86_64
                || target.features.has(CpuFeature::Aarch64Asimd)
                || target.operating_system == OperatingSystem::Linux
                    && target.features.has(CpuFeature::Aarch64Sve);
            assert_eq!(
                compiled.receipt().runtime_helper_required,
                has_vector_root_scanner,
                "{target:?}"
            );
            assert_eq!(
                compiled.module().required_runtime_symbol().is_some(),
                has_vector_root_scanner,
                "{target:?}"
            );
            assert_eq!(
                compiled.module().prepared_entry_symbol().is_some(),
                has_vector_root_scanner,
                "{target:?}"
            );
            assert_eq!(
                compiled.module().start_accelerator() != StartAccelerator::None,
                has_vector_root_scanner,
                "{target:?}"
            );
        }
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[allow(
        clippy::too_many_lines,
        reason = "the opt-in linker differential keeps object, ABI, and every-window expectations together"
    )]
    fn run_linked_bit_parallel_differential(target: Target, x86_rosetta: bool, machine: u8) {
        use std::{fmt::Write as _, fs, process::Command};

        let compiled = match machine {
            0 => compiled_sidecar_for(SELECTIVE_PATTERN, target),
            1 => compiled_multi_nibble_sidecar(target),
            2..=4 => compiled_multiword_sidecar_for_words(target, usize::from(machine)),
            10 | 11 => compiled_recurrence_only_oneword_sidecar(target, machine == 11),
            12..=14 => {
                compiled_recurrence_only_sidecar_for_words(target, usize::from(machine - 10))
            }
            15 => compiled_hybrid_subset_sidecar(target),
            _ => panic!("unknown bit-parallel fixture"),
        };
        assert!(compiled.module().required_runtime_symbol().is_none());
        let haystacks: Vec<Vec<u8>> = match machine {
            0 => vec![
                vec![],
                vec![4],
                vec![0x7f, 0x7f, 1, 2, 3, 4, 0x7f],
                vec![1, 2, 1, 2, 1, 2, 0x7f],
                vec![3, 3, 1, 2, 3, 4],
            ],
            1 => vec![
                b"".to_vec(),
                b"z".to_vec(),
                b"xxabcdefzxx".to_vec(),
                b"ghijklx".to_vec(),
                b"abcdefabcdefz".to_vec(),
            ],
            2..=4 => {
                let consuming_prefix = (usize::from(machine) - 1) * 64;
                let mut matching = vec![1; consuming_prefix];
                matching.push(2);
                let mut almost = Vec::with_capacity(consuming_prefix + 2);
                almost.push(0x7f);
                almost.extend(std::iter::repeat_n(1, consuming_prefix));
                almost.push(0x7f);
                let mut two_episodes = vec![1, 0x7f];
                two_episodes.extend_from_slice(&matching);
                vec![
                    Vec::new(),
                    vec![2],
                    matching,
                    almost,
                    vec![0x7f; 129],
                    vec![0x7f, 0x7f, 2, 0x7f, 0x7f],
                    two_episodes,
                ]
            }
            10 => vec![
                Vec::new(),
                b"z".to_vec(),
                b"qz".to_vec(),
                b"qx".to_vec(),
                b"xxqzxx".to_vec(),
                vec![b'x'; 129],
            ],
            11 => vec![
                Vec::new(),
                b"Az".to_vec(),
                b"zz".to_vec(),
                b"0z".to_vec(),
                b"xxQzxx".to_vec(),
                vec![b'0'; 129],
            ],
            12..=14 => {
                let consuming_prefix = (usize::from(machine - 10) - 1) * 64;
                let mut matching = Vec::with_capacity(consuming_prefix + 2);
                matching.push(b'q');
                matching.extend(std::iter::repeat_n(b'a', consuming_prefix));
                matching.push(b'z');
                let mut almost = matching.clone();
                *almost.last_mut().expect("dense fixture terminator") = b'x';
                let mut shifted = vec![b'x', b'x'];
                shifted.extend_from_slice(&matching);
                shifted.extend_from_slice(b"xx");
                vec![
                    Vec::new(),
                    b"z".to_vec(),
                    matching,
                    almost,
                    shifted,
                    vec![b'x'; 129],
                ]
            }
            15 => {
                let mut matching = vec![b'x'; 128];
                matching.push(b'z');
                vec![Vec::new(), b"z".to_vec(), vec![b'x'; 64], matching]
            }
            _ => unreachable!(),
        };
        let fixture_name = match machine {
            0 => "one".to_owned(),
            1 => "nibbles".to_owned(),
            2..=4 => format!("words-{machine}"),
            10 => "dense-one".to_owned(),
            11 => "wide-one".to_owned(),
            12..=14 => format!("dense-words-{}", machine - 10),
            15 => "hybrid-subsets".to_owned(),
            _ => unreachable!(),
        };
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-bit-parallel-exists-{}-{}",
            std::process::id(),
            format_args!(
                "{}-{fixture_name}",
                if x86_rosetta { "x86" } else { "host" }
            )
        ));
        fs::create_dir_all(&directory).expect("create linked fixture directory");
        let object = directory.join("bit_parallel.o");
        fs::write(&object, compiled.object()).expect("write bit-parallel object");
        let symbol = compiled.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\n"
        );
        let mut calls = String::from("int main(void){size_t r[2],i,j,k;uint32_t s;\n");
        let mut portable_workspace = compiled
            .prepare_workspace()
            .expect("prepare reusable portable differential workspace");
        for (haystack_index, haystack) in haystacks.iter().enumerate() {
            let bytes = if haystack.is_empty() {
                "0".to_owned()
            } else {
                haystack
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            writeln!(
                source,
                "static const unsigned char h{haystack_index}[]={{{bytes}}};"
            )
            .unwrap();
            let mut expected = Vec::new();
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let result = compiled
                        .search_with_workspace(
                            haystack,
                            SearchWindow::new(start, end),
                            &mut portable_workspace,
                        )
                        .expect("portable result");
                    let MatchResult::Exists(found) = result else {
                        panic!("Exists contract changed")
                    };
                    expected.push(u8::from(found));
                }
            }
            let expected_bytes = expected
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                source,
                "static const unsigned char e{haystack_index}[]={{{expected_bytes}}};"
            )
            .unwrap();
            writeln!(
                calls,
                "k=0;for(i=0;i<={0};i++)for(j=i;j<={0};j++){{r[0]=99;r[1]=99;s={symbol}(h{haystack_index},{0},i,j,r);if(s!=e{haystack_index}[k++]||r[0]!=0||r[1]!=0)return {1};}}",
                haystack.len(),
                haystack_index.checked_add(10).expect("fixture failure code")
            )
            .unwrap();
        }
        writeln!(
            calls,
            "r[0]=71;r[1]=73;s={symbol}(h1,1,1,0,r);if(s!=2||r[0]!=71||r[1]!=73)return 80;"
        )
        .unwrap();
        writeln!(
            calls,
            "r[0]=71;r[1]=73;s={symbol}(h1,1,0,2,r);if(s!=2||r[0]!=71||r[1]!=73)return 81;"
        )
        .unwrap();
        writeln!(calls, "s={symbol}(h1,1,0,1,(size_t*)0);if(s!=2)return 82;").unwrap();
        writeln!(
            calls,
            "s={symbol}((const unsigned char*)0,0,0,0,r);if(s!=2)return 83;"
        )
        .unwrap();
        calls.push_str("return 0;}\n");
        source.push_str(&calls);
        let c_path = directory.join("bit_parallel.c");
        let executable = directory.join("bit_parallel");
        fs::write(&c_path, source).expect("write linked harness");
        let compiler_command = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        let mut linker = Command::new(compiler_command);
        linker.arg("-O0");
        if x86_rosetta {
            linker.args(["-arch", "x86_64"]);
        }
        let status = linker
            .arg(&c_path)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("invoke host C compiler");
        assert!(status.success());
        let output = if x86_rosetta {
            Command::new("arch")
                .arg("-x86_64")
                .arg(&executable)
                .output()
        } else {
            Command::new(&executable).output()
        }
        .expect("execute linked bit-parallel leaf");
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes the admitted hybrid subset-row leaf on the host"]
    fn linked_host_hybrid_subset_rows_match_portable_for_every_window() {
        let target = if cfg!(target_arch = "x86_64") {
            if cfg!(target_os = "linux") {
                Target::x86_64_linux()
            } else {
                Target::x86_64_macos()
            }
        } else if cfg!(target_os = "linux") {
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
        } else {
            Target::aarch64_macos()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
        };
        run_linked_bit_parallel_differential(target, false, 15);
        if cfg!(target_arch = "aarch64") {
            let scalar = if cfg!(target_os = "linux") {
                Target::aarch64_linux()
            } else {
                Target::aarch64_macos()
            };
            run_linked_bit_parallel_differential(scalar, false, 15);
        }
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes the bit-parallel fallback leaf on the host"]
    fn linked_host_bit_parallel_exists_matches_portable_for_every_window() {
        let target = if cfg!(target_arch = "x86_64") {
            if cfg!(target_os = "linux") {
                Target::x86_64_linux()
            } else {
                Target::x86_64_macos()
            }
        } else if cfg!(target_os = "linux") {
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
        } else {
            Target::aarch64_macos()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
        };
        run_linked_bit_parallel_differential(target, false, 0);
        run_linked_bit_parallel_differential(target, false, 15);
        for words in 2..=4 {
            run_linked_bit_parallel_differential(target, false, words + 10);
        }
        if cfg!(target_arch = "aarch64") {
            let scalar_target = if cfg!(target_os = "linux") {
                Target::aarch64_linux()
            } else {
                Target::aarch64_macos()
            };
            for words in 2..=4 {
                run_linked_bit_parallel_differential(scalar_target, false, words);
                run_linked_bit_parallel_differential(scalar_target, false, words + 10);
            }
            run_linked_bit_parallel_differential(scalar_target, false, 15);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    #[test]
    #[ignore = "executes recurrence-only multiword leaves through every Linux SVE tier"]
    fn linked_aarch64_sve_bit_parallel_exists_matches_portable_for_every_window() {
        let sve = FeatureSet::of(CpuFeature::Aarch64Sve);
        let sve2 = sve.with(CpuFeature::Aarch64Sve2);
        let mixed_sve = FeatureSet::of(CpuFeature::Aarch64Asimd).with(CpuFeature::Aarch64Sve);
        let mixed_sve2 = mixed_sve.with(CpuFeature::Aarch64Sve2);
        for features in [sve, sve2, mixed_sve, mixed_sve2] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            for words in 2..=MAX_BIT_PARALLEL_EXISTS_WORDS {
                run_linked_bit_parallel_differential(
                    target,
                    false,
                    u8::try_from(words + 10)
                        .expect("bit-parallel word count fits in fixture selector"),
                );
            }
            run_linked_bit_parallel_differential(target, false, 15);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    #[ignore = "cross-links admitted SSE2/AVX2 hybrid rows and executes them through Rosetta"]
    fn linked_x86_64_hybrid_subset_rows_match_portable_under_rosetta() {
        run_linked_bit_parallel_differential(Target::x86_64_macos(), true, 15);
        let avx2 = Target::x86_64_macos()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        run_linked_bit_parallel_differential(avx2, true, 15);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    #[ignore = "cross-links x86-64 and executes it through macOS Rosetta"]
    fn linked_x86_64_bit_parallel_exists_matches_portable_under_rosetta() {
        run_linked_bit_parallel_differential(Target::x86_64_macos(), true, 0);
        run_linked_bit_parallel_differential(Target::x86_64_macos(), true, 15);
        for words in 2..=4 {
            run_linked_bit_parallel_differential(Target::x86_64_macos(), true, words + 10);
        }
        let avx2 = Target::x86_64_macos()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        for words in 2..=4 {
            run_linked_bit_parallel_differential(avx2, true, words + 10);
        }
        run_linked_bit_parallel_differential(avx2, true, 15);
    }
}
