//! Self-contained native lowering for contextual ordered DFAs.
//!
//! This is a child of `module`, rather than a second object pipeline. It uses
//! the same five-argument leaf ABI, assemblers and relocation vocabulary as
//! the byte-only DFA lowering. All assertion decisions are represented by the
//! packed tables in `context_native`; emitted code never calls the runtime.

use super::{
    AARCH64_EQ, AARCH64_FIRST_LANE_INDEX, AARCH64_HI, AARCH64_HS, AARCH64_LO, AARCH64_LS,
    AARCH64_MI, AARCH64_NE, AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
    AARCH64_VECTOR_FILTER_FIRST_CONSTANT, Aarch64Assembler, Aarch64PrimaryScannerIsa,
    Aarch64SveFilterKind, Architecture, BYTE_FREQUENCY_DENOMINATOR, CpuFeature,
    EMPTY_NATIVE_PREFIX_RELATION_RECTANGLE, FeatureSet, MAX_NATIVE_PREFIX_RELATION_RECTANGLES,
    ModuleRelocation, NativeLowering, NativePrefixFilter, NativePrefixRelationPredicate,
    NativePrefixRelationRectangle, NativePrefixRelationVectorPlan, NativeStartFilter,
    NativeVectorFilter, PROGRAM_SYMBOL, RelocationKind, StartAccelerator, TEXT_SECTION, Target,
    X86Assembler, X86CandidateMask, X86StartFilterKind, aarch64_add_x_imm, aarch64_add_x_reg,
    aarch64_cmp_w_imm, aarch64_cmp_x, aarch64_cmp_x_imm, aarch64_csel_x,
    aarch64_emit_candidate_any, aarch64_emit_candidate_batch_any,
    aarch64_emit_first_candidate_in_batch, aarch64_emit_first_candidate_lane,
    aarch64_emit_first_lane_constants, aarch64_emit_prefix_predicate,
    aarch64_emit_prefix_relation_vector_test, aarch64_emit_scalar_filter_membership,
    aarch64_emit_start_filter_address, aarch64_emit_start_filter_batch_candidates,
    aarch64_emit_start_filter_constants, aarch64_emit_start_filter_scalar_bound,
    aarch64_emit_start_filter_vector_candidates, aarch64_emit_start_filter_vector_test,
    aarch64_emit_sve_start_filter_scanner, aarch64_emit_vector_filter_secondary_batch,
    aarch64_emit_vector_filter_secondary_candidates_at, aarch64_load_byte_reg,
    aarch64_load_halfword_reg, aarch64_load_q, aarch64_load_u32_constant,
    aarch64_load_u64_constant, aarch64_lsr_x_imm, aarch64_mov_x, aarch64_movi_16b, aarch64_movz_w,
    aarch64_orr_16b, aarch64_prefix_relation_constant_register, aarch64_set_table_address,
    aarch64_primary_scanner_isa, aarch64_primary_scanner_uses_sve, aarch64_store_x,
    aarch64_sub_w_imm, aarch64_sub_x_imm,
    aarch64_sub_x_reg, aarch64_sve_cntb, aarch64_use_exact_first_lane,
    append_native_prefix_filter,
    coalesced_filter_from_membership_words, derive_anchored_prefix_start_filter,
    derive_vector_filter, estimated_byte_frequency_units, estimated_filter_frequency_units,
    filter_from_membership_words, filter_selection_key, native_prefix_relation_predicate,
    native_prefix_relation_vector_contains, offset_u64, push_bytes,
    vector_filter_instruction_units, x86_emit_first_candidate_lane, x86_emit_prefix_predicate,
    x86_emit_prefix_relation_vector_test, x86_emit_scalar_filter_membership,
    x86_emit_start_filter_constants, x86_emit_start_filter_scalar_bound,
    x86_emit_start_filter_vector_candidates, x86_emit_start_filter_vector_test,
    x86_emit_vector_filter_secondary_test, x86_start_filter_kind,
};
#[cfg(test)]
use crate::context_native::build_context_native_layout_with_reverse;
use crate::{
    ObjectError,
    context_dfa::{NativeContextAnchoredForwardView, NativeContextDfaView},
    context_native::{
        CONTEXT_CELL_STATE_MASK, CONTEXT_FORWARD_CELL_FLAGS_SHIFT, CONTEXT_FORWARD_CELL_STATE_MASK,
        CONTEXT_RAW_FORWARD_EMPTY, CONTEXT_RAW_FORWARD_STATE_MASK, CONTEXT_RAW_FORWARD_VALID,
        CONTEXT_RAW_REVERSE_EVENT, CONTEXT_RAW_REVERSE_STATE_MASK, CONTEXT_RAW_REVERSE_VALID,
        CONTEXT_STATE_EMPTY, CONTEXT_STATE_PENDING, CONTEXT_STATE_TERMINAL,
        ContextAnchoredForwardLayout, ContextNativeLayout, ContextNativeLimits,
        ContextRawPairInitialLayout, ContextRawPairReverseInitialLayout,
        MAX_CONTEXT_NATIVE_DATA_BYTES, build_context_native_layout_with_accelerators,
    },
    prefix_predicate::{
        AARCH64_SCALAR_PREFIX_COSTS, PrefixPredicateInput, ScalarPrefixConjunctionPlan,
        X86_64_SCALAR_PREFIX_COSTS, plan_scalar_prefix_predicates,
    },
    program::{
        AnchoredByteSet, MAX_ANCHORED_PREFIX_BYTES, NativeContextProgramView, OutputContract,
    },
    required_literals::{MAX_REQUIRED_LITERAL_DEPTH, MaximumConsumedDistance},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextPrepassRestart {
    CandidateBase,
    Bounded(u32),
    OriginalStart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextInteriorGuard {
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    restart: ContextPrepassRestart,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ContextSve2MatchTables {
    interior: Option<u32>,
    anchored: Option<u32>,
    ordinary: Option<u32>,
}

/// Candidate scanner selected for the exact-start contextual verifier.
///
/// An exact graph column is preferred. If its membership is too fragmented
/// for the bounded SIMD representation, `primary` may instead be a weighted
/// four-range cover. Such a cover is sidecar-only: it can introduce false
/// candidates, so it must never justify the ordinary prefix fast-forward or
/// known-start proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextAnchoredCandidateFilter {
    primary: NativeStartFilter,
    exact_membership: bool,
    cover_inflation: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextAnchoredForwardSearch {
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    guarded_bytes: u8,
    max_verify_bytes: u8,
    cover_inflation: u16,
    overlap_period: Option<u8>,
}

/// One rectangle in the exact raw-byte projection of productive anchored
/// initial contexts.
///
/// A candidate pair belongs to the relation when its previous byte belongs
/// to `before_words` and its current byte belongs to `current_words`. The
/// rectangles are disjoint in their previous-byte dimension because the
/// canonical factorization groups identical semantic property rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextBoundaryPairFactor {
    before_words: [u64; 4],
    current_words: [u64; 4],
}

/// Exact two-byte projection of the graph language at one candidate start.
///
/// For an interior candidate `p > 0`, `matches(before, current)` is true iff
/// the exact-start contextual DFA has some accepting continuation from the
/// initial context formed by those two bytes. It is consequently the
/// strongest sound predicate that observes only `hay[p - 1]` and `hay[p]`.
/// `absolute_start_words` is the separate one-byte projection for `p == 0`;
/// absence before the haystack is never represented by a fabricated byte.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ContextBoundaryPairRelation {
    factors: Vec<ContextBoundaryPairFactor>,
    absolute_start_words: [u64; 4],
}

impl ContextBoundaryPairRelation {
    fn matches(&self, before: u8, current: u8) -> bool {
        let before_index = usize::from(before);
        let current_index = usize::from(current);
        self.factors.iter().any(|factor| {
            factor.before_words[before_index / 64] & (1_u64 << (before_index % 64)) != 0
                && factor.current_words[current_index / 64] & (1_u64 << (current_index % 64)) != 0
        })
    }

    #[cfg(test)]
    fn matches_absolute_start(&self, current: u8) -> bool {
        let index = usize::from(current);
        self.absolute_start_words[index / 64] & (1_u64 << (index % 64)) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ContextBoundaryPairOrientation {
    BeforeRows,
    CurrentRows,
}

/// Target-lowerable exact relation after an exact offset-zero current-byte
/// base mask has already been proved by the SIMD scanner.
///
/// `plan` is a cost-bounded union of exact byte-set rectangles. Identical leaf
/// filters share one logical constant block, including a compatible scanner
/// block when persistent registers fit. Otherwise the complete relation bank
/// is materialized transiently on a rare base hit and every scanner-resume
/// edge restores the overwritten constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextBoundaryPairExpression {
    plan: NativePrefixRelationVectorPlan,
    orientation: ContextBoundaryPairOrientation,
    /// Logical constant slots already initialized by the persistent scanner
    /// bank. Relation blocks above this boundary are emitted once at entry.
    scanner_constant_count: u8,
    emitted_constant_count: u8,
    instruction_units: u16,
    /// Constants do not fit beside the persistent scanner constants and are
    /// materialized only on the rare base-mask hit.
    transient_constants: bool,
    /// Evaluation overwrites the persistent scanner bank and must reconstruct
    /// it before resuming after a false pair hit. This includes transient
    /// relation constants and AArch64's V16 source/scratch overlap with the
    /// standalone V16..V23 scanner bank.
    restore_scanner_constants: bool,
}

const CONTEXT_BOUNDARY_PAIR_PROPERTY_ROWS: usize = 16;
const CONTEXT_BOUNDARY_PAIR_MAX_FACTORS: usize = CONTEXT_BOUNDARY_PAIR_PROPERTY_ROWS;
const CONTEXT_BOUNDARY_PAIR_MAX_COACCESS_CELLS: usize = 1 << 20;
const CONTEXT_BOUNDARY_PAIR_X86_CONSTANT_BUDGET: u8 = 8;
const CONTEXT_BOUNDARY_PAIR_AARCH64_CONSTANT_BUDGET: u8 = 6;
const CONTEXT_BOUNDARY_PAIR_X86_INSTRUCTION_BUDGET: u16 = 96;
const CONTEXT_BOUNDARY_PAIR_AARCH64_INSTRUCTION_BUDGET: u16 = 72;

/// Fixed-point cumulative-work guard for the optional exact-start sidecar.
///
/// Native code initializes `debt` to the semantic window start. Vector
/// refinement and exact-candidate handling are charged independently. An
/// admitted candidate reserves the largest whole-transition prefix affordable
/// under its current allowance, up to the complete maximum verifier cost. A
/// rejected or resolved-no-match attempt refunds the unused capacity. Thus its
/// final debt is exactly the transitions it actually executed, without an
/// allowance calculation or conditional branch in the transition loop. A
/// successful attempt may keep the reservation because native execution
/// terminates immediately.
/// Every work unit adds
/// [`CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR`] to that debt and admits work only
/// while
///
/// `debt <= candidate + initial_credit`.
///
/// Thus the allowance is exactly one vector refinement plus one complete
/// maximum-sized initial candidate attempt, followed by one work unit per
/// denominator bytes strictly before the current candidate. Verification
/// progress is deliberately excluded: those bytes have not yet been ruled out
/// as possible later match starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextAnchoredAdaptiveGuard {
    vector_debt: u16,
    candidate_debt: u16,
    transition_debt: u16,
    initial_credit: u16,
}

fn context_anchored_transition_reserve(
    search: ContextAnchoredForwardSearch,
    guard: ContextAnchoredAdaptiveGuard,
) -> Result<u16, ObjectError> {
    u16::from(search.max_verify_bytes)
        .checked_mul(guard.transition_debt)
        .filter(|&reserve| reserve <= 4_095)
        .ok_or(ObjectError::ArithmeticOverflow(
            "context anchored transition reserve",
        ))
}

fn context_anchored_transition_shift(
    guard: ContextAnchoredAdaptiveGuard,
) -> Result<u8, ObjectError> {
    if !guard.transition_debt.is_power_of_two() {
        return Err(ObjectError::InvalidModule(
            "context anchored transition debt is not a power of two",
        ));
    }
    u8::try_from(guard.transition_debt.trailing_zeros())
        .map_err(|_| ObjectError::ArithmeticOverflow("context anchored transition debt shift"))
}

const CONTEXT_ANCHORED_MAX_VERIFY_BYTES: u8 = 64;
const CONTEXT_ANCHORED_PROFIT_DENOMINATOR: u128 = 1;
const CONTEXT_ANCHORED_MAX_SCANNER_FREQUENCY_UNITS: u16 = 64;
const CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR: u16 = 32;
const CONTEXT_ANCHORED_CANDIDATE_BASE_WORK: u16 = 1;
const CONTEXT_ANCHORED_TRANSITION_WORK: u16 = 1;
const CONTEXT_ANCHORED_COVER_BYTES_PER_WORK: u16 = 8;
const CONTEXT_ANCHORED_MAX_OVERLAP_WORK: u16 = 7;
const CONTEXT_ANCHORED_MAX_OVERLAP_FREQUENCY_WORK: u32 = 256;
const ENABLE_CONTEXT_ANCHORED_FORWARD_SEARCH: bool = true;
/// Private source-identical switch for graph-derived terminal-suffix search.
const ENABLE_CONTEXT_TERMINAL_SUFFIX_SEARCH: bool = true;
/// Trust transition cells populated by the checked target-neutral layout.
///
/// Initial dispatch and sidecar-map entries remain checked because those
/// tables deliberately contain holes. Forward and anchored transition rows
/// are complete and always have live successors; reverse transition rows are
/// complete but retain their valid zero-payload dead-state encoding. Keeping
/// this as a private switch permits source-identical code-shape A/B runs.
const ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS: bool = true;

/// Compute the least fixed point of anchored states that can produce an
/// ordered acceptance on some continuation.
///
/// Reverse CSR storage keeps the traversal linear in the published graph.
/// The accelerator owns an independent structural ceiling and declines on
/// allocation failure; neither condition can turn a valid compilation into
/// an error or expose a partial relation.
fn derive_context_anchored_coaccessible(
    anchored: NativeContextAnchoredForwardView<'_>,
) -> Result<Option<Vec<bool>>, ObjectError> {
    let states = anchored.states.len();
    if states == 0
        || anchored.row_offsets.len() != states.saturating_add(1)
        || anchored.cells.len() > CONTEXT_BOUNDARY_PAIR_MAX_COACCESS_CELLS
    {
        return Ok(None);
    }
    let mut counts = Vec::new();
    if counts.try_reserve_exact(states).is_err() {
        return Ok(None);
    }
    counts.resize(states, 0_usize);
    let mut good = Vec::new();
    if good.try_reserve_exact(states).is_err() {
        return Ok(None);
    }
    good.resize(states, false);

    for (state, flags) in anchored.states.iter().enumerate() {
        let begin = usize::try_from(*anchored.row_offsets.get(state).ok_or(
            ObjectError::InvalidModule("context pair anchored row start is absent"),
        )?)
        .map_err(|_| ObjectError::ArithmeticOverflow("context pair anchored row start"))?;
        let end = usize::try_from(*anchored.row_offsets.get(state + 1).ok_or(
            ObjectError::InvalidModule("context pair anchored row end is absent"),
        )?)
        .map_err(|_| ObjectError::ArithmeticOverflow("context pair anchored row end"))?;
        let row = anchored
            .cells
            .get(begin..end)
            .ok_or(ObjectError::InvalidModule(
                "context pair anchored row is out of range",
            ))?;
        let mut productive = flags.pending;
        for cell in row {
            let next = usize::try_from(cell.next)
                .map_err(|_| ObjectError::ArithmeticOverflow("context pair anchored target"))?;
            let count = counts.get_mut(next).ok_or(ObjectError::InvalidModule(
                "context pair anchored target is out of range",
            ))?;
            if cell.accepted {
                productive = true;
            } else {
                *count = count.checked_add(1).ok_or(ObjectError::ArithmeticOverflow(
                    "context pair predecessor count",
                ))?;
            }
        }
        good[state] = productive;
    }

    let mut offsets = Vec::new();
    if offsets.try_reserve_exact(states.saturating_add(1)).is_err() {
        return Ok(None);
    }
    offsets.push(0_usize);
    for &count in &counts {
        let next = offsets
            .last()
            .copied()
            .and_then(|offset| offset.checked_add(count))
            .ok_or(ObjectError::ArithmeticOverflow(
                "context pair predecessor offsets",
            ))?;
        offsets.push(next);
    }
    let edge_count = offsets.last().copied().unwrap_or(0);
    let mut predecessors = Vec::new();
    if predecessors.try_reserve_exact(edge_count).is_err() {
        return Ok(None);
    }
    predecessors.resize(edge_count, 0_u32);
    let mut cursors = Vec::new();
    if cursors.try_reserve_exact(states).is_err() {
        return Ok(None);
    }
    cursors.extend_from_slice(&offsets[..states]);
    for source in 0..states {
        let begin = usize::try_from(anchored.row_offsets[source])
            .map_err(|_| ObjectError::ArithmeticOverflow("context pair source row"))?;
        let end = usize::try_from(anchored.row_offsets[source + 1])
            .map_err(|_| ObjectError::ArithmeticOverflow("context pair source row"))?;
        for cell in anchored
            .cells
            .get(begin..end)
            .ok_or(ObjectError::InvalidModule(
                "context pair source row is out of range",
            ))?
        {
            if cell.accepted {
                continue;
            }
            let target = usize::try_from(cell.next)
                .map_err(|_| ObjectError::ArithmeticOverflow("context pair target"))?;
            let cursor = cursors.get_mut(target).ok_or(ObjectError::InvalidModule(
                "context pair predecessor target is out of range",
            ))?;
            let slot = predecessors
                .get_mut(*cursor)
                .ok_or(ObjectError::InvalidModule(
                    "context pair predecessor cursor is out of range",
                ))?;
            *slot = u32::try_from(source)
                .map_err(|_| ObjectError::ArithmeticOverflow("context pair predecessor"))?;
            *cursor = cursor
                .checked_add(1)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context pair predecessor cursor",
                ))?;
        }
    }
    if cursors
        .iter()
        .zip(&offsets[1..])
        .any(|(&actual, &expected)| actual != expected)
    {
        return Err(ObjectError::InvalidModule(
            "context pair predecessor geometry disagrees",
        ));
    }

    let mut queue = Vec::new();
    if queue.try_reserve_exact(states).is_err() {
        return Ok(None);
    }
    for (state, &productive) in good.iter().enumerate() {
        if productive {
            queue.push(
                u32::try_from(state).map_err(|_| {
                    ObjectError::ArithmeticOverflow("context pair productive state")
                })?,
            );
        }
    }
    let mut cursor = 0_usize;
    while cursor < queue.len() {
        let target = usize::try_from(queue[cursor])
            .map_err(|_| ObjectError::ArithmeticOverflow("context pair queue state"))?;
        cursor = cursor
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow("context pair queue cursor"))?;
        let begin = offsets[target];
        let end = offsets[target + 1];
        for &source in &predecessors[begin..end] {
            let source = usize::try_from(source)
                .map_err(|_| ObjectError::ArithmeticOverflow("context pair source state"))?;
            let marker = good.get_mut(source).ok_or(ObjectError::InvalidModule(
                "context pair source state is out of range",
            ))?;
            if !*marker {
                *marker = true;
                queue.push(u32::try_from(source).map_err(|_| {
                    ObjectError::ArithmeticOverflow("context pair queued predecessor")
                })?);
            }
        }
    }
    Ok(Some(good))
}

fn context_initial_is_coaccessible(
    dfa: NativeContextDfaView<'_>,
    anchored: NativeContextAnchoredForwardView<'_>,
    coaccessible: &[bool],
    context: u32,
) -> Result<bool, ObjectError> {
    let initial = dfa
        .forward_initial
        .binary_search_by_key(&context, |entry| entry.context)
        .ok()
        .and_then(|index| dfa.forward_initial.get(index))
        .ok_or(ObjectError::InvalidModule(
            "context pair initial dispatch entry is absent",
        ))?;
    let main = usize::try_from(initial.state)
        .map_err(|_| ObjectError::ArithmeticOverflow("context pair main initial"))?;
    let exact = *anchored
        .main_initial_to_anchored
        .get(main)
        .filter(|&&state| state != u32::MAX)
        .ok_or(ObjectError::InvalidModule(
            "context pair anchored initial mapping is absent",
        ))?;
    let exact = usize::try_from(exact)
        .map_err(|_| ObjectError::ArithmeticOverflow("context pair anchored initial"))?;
    coaccessible
        .get(exact)
        .copied()
        .ok_or(ObjectError::InvalidModule(
            "context pair anchored initial is out of range",
        ))
}

/// Derive and canonically factor the exact raw-byte initial-boundary
/// projection. Equal previous-property rows are merged, so no source identity
/// or iteration order can affect the result and at most sixteen rectangles
/// are published.
fn derive_context_boundary_pair_relation(
    view: NativeContextProgramView<'_>,
) -> Result<Option<ContextBoundaryPairRelation>, ObjectError> {
    let dfa = view.dfa;
    let Some(anchored) = dfa.anchored_forward else {
        return Ok(None);
    };
    let Some(coaccessible) = derive_context_anchored_coaccessible(anchored)? else {
        return Ok(None);
    };
    let class_count = usize::try_from(dfa.initial_dispatch.class_count)
        .map_err(|_| ObjectError::ArithmeticOverflow("context pair class count"))?;
    if class_count == 0 || class_count > 256 || dfa.class_properties.len() != class_count {
        return Err(ObjectError::InvalidModule(
            "context pair byte-class geometry is invalid",
        ));
    }

    let mut factors = Vec::<ContextBoundaryPairFactor>::new();
    if factors
        .try_reserve_exact(CONTEXT_BOUNDARY_PAIR_MAX_FACTORS)
        .is_err()
    {
        return Ok(None);
    }
    for properties in
        0_u8..u8::try_from(CONTEXT_BOUNDARY_PAIR_PROPERTY_ROWS).expect("property row bound fits u8")
    {
        let mut before_words = [0_u64; 4];
        for before in u8::MIN..=u8::MAX {
            let byte_index = usize::from(before);
            let class = usize::from(dfa.byte_classes[byte_index]);
            let Some(&actual) = dfa.class_properties.get(class) else {
                return Err(ObjectError::InvalidModule(
                    "context pair previous-byte class is out of range",
                ));
            };
            if actual == properties {
                before_words[byte_index / 64] |= 1_u64 << (byte_index % 64);
            }
        }
        if before_words.iter().all(|&word| word == 0) {
            continue;
        }

        let mut current_words = [0_u64; 4];
        for current in u8::MIN..=u8::MAX {
            let byte_index = usize::from(current);
            let class = u32::from(dfa.byte_classes[byte_index]);
            let context = dfa
                .initial_dispatch
                .pack(class, properties, true, false, false)
                .ok_or(ObjectError::InvalidModule(
                    "context pair interior key does not pack",
                ))?;
            if context_initial_is_coaccessible(dfa, anchored, &coaccessible, context)? {
                current_words[byte_index / 64] |= 1_u64 << (byte_index % 64);
            }
        }
        if current_words.iter().all(|&word| word == 0) {
            continue;
        }
        if let Some(existing) = factors
            .iter_mut()
            .find(|factor| factor.current_words == current_words)
        {
            for (existing, additional) in existing.before_words.iter_mut().zip(before_words) {
                *existing |= additional;
            }
        } else {
            if factors.len() == CONTEXT_BOUNDARY_PAIR_MAX_FACTORS {
                return Ok(None);
            }
            factors.push(ContextBoundaryPairFactor {
                before_words,
                current_words,
            });
        }
    }

    let mut absolute_start_words = [0_u64; 4];
    for current in u8::MIN..=u8::MAX {
        let byte_index = usize::from(current);
        let class = u32::from(dfa.byte_classes[byte_index]);
        let context = dfa
            .initial_dispatch
            .pack(class, 0, false, true, false)
            .ok_or(ObjectError::InvalidModule(
                "context pair absolute-start key does not pack",
            ))?;
        if context_initial_is_coaccessible(dfa, anchored, &coaccessible, context)? {
            absolute_start_words[byte_index / 64] |= 1_u64 << (byte_index % 64);
        }
    }
    Ok(Some(ContextBoundaryPairRelation {
        factors,
        absolute_start_words,
    }))
}

fn context_filter_contains(filter: NativeStartFilter, byte: u8) -> bool {
    filter
        .ranges()
        .iter()
        .any(|range| range.start <= byte && byte <= range.end)
}

fn context_filter_same_membership(left: NativeStartFilter, right: NativeStartFilter) -> bool {
    left.ranges() == right.ranges()
}

fn context_scanner_constant_filters(
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
) -> impl Iterator<Item = NativeStartFilter> {
    let mut filters = [primary; 3];
    let count = if let Some(vector) = vector_filter {
        let columns = vector.columns();
        filters[..columns.len()].copy_from_slice(columns);
        columns.len()
    } else {
        1
    };
    filters.into_iter().take(count)
}

fn context_boundary_pair_filter_words(filter: NativeStartFilter) -> [u64; 4] {
    let mut words = [0_u64; 4];
    for byte in u8::MIN..=u8::MAX {
        if context_filter_contains(filter, byte) {
            let index = usize::from(byte);
            words[index / 64] |= 1_u64 << (index % 64);
        }
    }
    words
}

fn context_boundary_pair_push_factor(
    factors: &mut Vec<ContextBoundaryPairFactor>,
    factor: ContextBoundaryPairFactor,
    merge_before: bool,
) -> Option<()> {
    let merged = factors.iter_mut().find(|existing| {
        if merge_before {
            existing.before_words == factor.before_words
        } else {
            existing.current_words == factor.current_words
        }
    });
    if let Some(existing) = merged {
        let (destination, source) = if merge_before {
            (&mut existing.current_words, factor.current_words)
        } else {
            (&mut existing.before_words, factor.before_words)
        };
        for (destination, source) in destination.iter_mut().zip(source) {
            *destination |= source;
        }
        return Some(());
    }
    if factors.len() == CONTEXT_BOUNDARY_PAIR_MAX_FACTORS {
        return None;
    }
    factors.push(factor);
    Some(())
}

fn context_boundary_pair_factorizations(
    relation: &ContextBoundaryPairRelation,
    base_words: [u64; 4],
) -> Option<(
    Vec<ContextBoundaryPairFactor>,
    Vec<ContextBoundaryPairFactor>,
)> {
    let mut before_rows = Vec::new();
    before_rows
        .try_reserve_exact(CONTEXT_BOUNDARY_PAIR_MAX_FACTORS)
        .ok()?;
    for factor in &relation.factors {
        let current_words =
            core::array::from_fn(|index| factor.current_words[index] & base_words[index]);
        if current_words.iter().all(|&word| word == 0) {
            continue;
        }
        context_boundary_pair_push_factor(
            &mut before_rows,
            ContextBoundaryPairFactor {
                before_words: factor.before_words,
                current_words,
            },
            false,
        )?;
    }

    let mut current_rows = Vec::new();
    current_rows
        .try_reserve_exact(CONTEXT_BOUNDARY_PAIR_MAX_FACTORS)
        .ok()?;
    for current in u8::MIN..=u8::MAX {
        let current_index = usize::from(current);
        if base_words[current_index / 64] & (1_u64 << (current_index % 64)) == 0 {
            continue;
        }
        let mut before_words = [0_u64; 4];
        for before in u8::MIN..=u8::MAX {
            if relation.matches(before, current) {
                let before_index = usize::from(before);
                before_words[before_index / 64] |= 1_u64 << (before_index % 64);
            }
        }
        if before_words.iter().all(|&word| word == 0) {
            continue;
        }
        let mut current_words = [0_u64; 4];
        current_words[current_index / 64] |= 1_u64 << (current_index % 64);
        if context_boundary_pair_push_factor(
            &mut current_rows,
            ContextBoundaryPairFactor {
                before_words,
                current_words,
            },
            true,
        )
        .is_none()
        {
            // This orientation is not representable within the structural
            // rectangle bound. Retain the canonical orientation instead of
            // allowing one over-wide transpose to decline both candidates.
            current_rows.clear();
            break;
        }
    }
    Some((before_rows, current_rows))
}

fn context_boundary_pair_predicate_units(
    predicate: NativePrefixRelationPredicate,
    architecture: Architecture,
) -> Option<u16> {
    if predicate.any {
        return Some(1);
    }
    let negation = if predicate.negated { 2 } else { 0 };
    vector_filter_instruction_units(predicate.filter)
        .checked_add(negation)?
        .checked_add(match architecture {
            Architecture::X86_64 => 2,  // aligned load plus result move
            Architecture::Aarch64 => 0, // both columns are loaded once
        })
}

fn context_boundary_pair_unassigned_plan(
    factors: &[ContextBoundaryPairFactor],
    base_words: [u64; 4],
    architecture: Architecture,
) -> Option<NativePrefixRelationVectorPlan> {
    if factors.is_empty() || factors.len() > MAX_NATIVE_PREFIX_RELATION_RECTANGLES {
        return None;
    }
    let mut rectangles =
        [EMPTY_NATIVE_PREFIX_RELATION_RECTANGLE; MAX_NATIVE_PREFIX_RELATION_RECTANGLES];
    let mut instruction_units: u16 = match architecture {
        Architecture::X86_64 => 8,
        Architecture::Aarch64 => 14,
    };
    for (index, factor) in factors.iter().enumerate() {
        let before =
            native_prefix_relation_predicate(AnchoredByteSet::from_words(factor.before_words), 0)?;
        let current_words = if factor.current_words == base_words {
            [u64::MAX; 4]
        } else {
            factor.current_words
        };
        let current =
            native_prefix_relation_predicate(AnchoredByteSet::from_words(current_words), 1)?;
        instruction_units = instruction_units
            .checked_add(context_boundary_pair_predicate_units(before, architecture)?)?;
        if !current.any {
            instruction_units = instruction_units
                .checked_add(context_boundary_pair_predicate_units(
                    current,
                    architecture,
                )?)?
                .checked_add(1)?;
        }
        instruction_units = instruction_units.checked_add(1)?;
        rectangles[index] = NativePrefixRelationRectangle {
            first: before,
            second: current,
        };
    }
    Some(NativePrefixRelationVectorPlan {
        rectangles,
        rectangle_count: u8::try_from(factors.len()).ok()?,
        constant_count: 0,
        instruction_units,
    })
}

fn context_boundary_pair_assign_constants(
    mut plan: NativePrefixRelationVectorPlan,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    target: Target,
    transient_constants: bool,
) -> Option<ContextBoundaryPairExpression> {
    let capacity = match target.architecture {
        Architecture::X86_64 => CONTEXT_BOUNDARY_PAIR_X86_CONSTANT_BUDGET,
        Architecture::Aarch64 => CONTEXT_BOUNDARY_PAIR_AARCH64_CONSTANT_BUDGET,
    };
    let shared_scanner_bank = target.architecture == Architecture::X86_64
        || (target.architecture == Architecture::Aarch64 && vector_filter.is_some());
    let mut blocks = Vec::<(NativeStartFilter, u8)>::new();
    blocks.try_reserve_exact(32).ok()?;
    let mut next = 1_u8;
    let scanner_constant_count = if !transient_constants && shared_scanner_bank {
        for filter in context_scanner_constant_filters(primary, vector_filter) {
            blocks.push((filter, next));
            next = next.checked_add(u8::try_from(filter.constant_count()).ok()?)?;
        }
        next.checked_sub(1)?
    } else {
        0
    };
    if scanner_constant_count > capacity {
        return None;
    }

    let mut emitted_constant_count = 0_u8;
    for rectangle in &mut plan.rectangles[..usize::from(plan.rectangle_count)] {
        for predicate in [&mut rectangle.first, &mut rectangle.second] {
            if predicate.any {
                continue;
            }
            if let Some((_, first)) = blocks
                .iter()
                .find(|(filter, _)| context_filter_same_membership(*filter, predicate.filter))
            {
                predicate.first_constant = *first;
                continue;
            }
            let count = u8::try_from(predicate.filter.constant_count()).ok()?;
            let end = next.checked_add(count)?.checked_sub(1)?;
            if end > capacity {
                return None;
            }
            predicate.first_constant = next;
            blocks.push((predicate.filter, next));
            next = end.checked_add(1)?;
            emitted_constant_count = emitted_constant_count.checked_add(count)?;
        }
    }
    plan.constant_count = next.checked_sub(1)?;
    let restore_scanner_constants = (transient_constants && shared_scanner_bank)
        || (target.architecture == Architecture::Aarch64 && vector_filter.is_none());
    let constant_units = match target.architecture {
        Architecture::X86_64 => 3_u16,
        Architecture::Aarch64 => 1_u16,
    };
    let relation_runtime_constants = if transient_constants {
        emitted_constant_count
    } else {
        0
    };
    let scanner_restore_constants = if restore_scanner_constants {
        context_scanner_constant_filters(primary, vector_filter)
            .try_fold(0_u8, |count, filter| {
                count.checked_add(u8::try_from(filter.constant_count()).ok()?)
            })?
    } else {
        0
    };
    let runtime_constant_count =
        relation_runtime_constants.checked_add(scanner_restore_constants)?;
    let instruction_units = plan
        .instruction_units
        .checked_add(u16::from(runtime_constant_count).checked_mul(constant_units)?)?;
    let instruction_budget = match target.architecture {
        Architecture::X86_64 => CONTEXT_BOUNDARY_PAIR_X86_INSTRUCTION_BUDGET,
        Architecture::Aarch64 => CONTEXT_BOUNDARY_PAIR_AARCH64_INSTRUCTION_BUDGET,
    };
    if instruction_units > instruction_budget {
        return None;
    }
    Some(ContextBoundaryPairExpression {
        plan,
        orientation: ContextBoundaryPairOrientation::BeforeRows,
        scanner_constant_count,
        emitted_constant_count,
        instruction_units,
        transient_constants,
        restore_scanner_constants,
    })
}

fn lower_context_boundary_pair_expression(
    relation: &ContextBoundaryPairRelation,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    target: Target,
) -> Result<Option<ContextBoundaryPairExpression>, ObjectError> {
    if primary.scan_offset != 0 || !primary.from_anchored_prefix || primary.ranges().is_empty() {
        return Ok(None);
    }
    let base_words = context_boundary_pair_filter_words(primary);
    let Some((before_rows, current_rows)) =
        context_boundary_pair_factorizations(relation, base_words)
    else {
        return Ok(None);
    };
    let mut selected = None;
    for (orientation, factors) in [
        (ContextBoundaryPairOrientation::BeforeRows, before_rows),
        (ContextBoundaryPairOrientation::CurrentRows, current_rows),
    ] {
        let Some(unassigned) =
            context_boundary_pair_unassigned_plan(&factors, base_words, target.architecture)
        else {
            continue;
        };
        let candidate = context_boundary_pair_assign_constants(
            unassigned,
            primary,
            vector_filter,
            target,
            false,
        )
        .or_else(|| {
            context_boundary_pair_assign_constants(unassigned, primary, vector_filter, target, true)
        });
        let Some(mut candidate) = candidate else {
            continue;
        };
        candidate.orientation = orientation;
        let exact = (u8::MIN..=u8::MAX).all(|before| {
            (u8::MIN..=u8::MAX).all(|current| {
                let in_base = context_filter_contains(primary, current);
                let expected = in_base && relation.matches(before, current);
                let actual = in_base
                    && native_prefix_relation_vector_contains(candidate.plan, before, current);
                actual == expected
            })
        });
        if !exact {
            continue;
        }
        let key = (
            candidate.instruction_units,
            candidate.transient_constants,
            candidate.emitted_constant_count,
            candidate.plan.rectangle_count,
            candidate.orientation,
        );
        if selected
            .as_ref()
            .is_none_or(|current: &ContextBoundaryPairExpression| {
                key < (
                    current.instruction_units,
                    current.transient_constants,
                    current.emitted_constant_count,
                    current.plan.rectangle_count,
                    current.orientation,
                )
            })
        {
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

fn derive_context_anchored_candidate_filter(
    sets: &[AnchoredByteSet],
) -> Result<Option<ContextAnchoredCandidateFilter>, ObjectError> {
    let mut selected = None;
    for (position, set) in sets.iter().copied().enumerate() {
        if set.cardinality() == 0 {
            continue;
        }
        let exact = filter_from_membership_words(set.words(), position, true)?;
        let candidate = if let Some(primary) = exact {
            ContextAnchoredCandidateFilter {
                primary,
                exact_membership: true,
                cover_inflation: 0,
            }
        } else {
            let Some(primary) =
                coalesced_filter_from_membership_words(set.words(), position, false)?
            else {
                continue;
            };
            ContextAnchoredCandidateFilter {
                primary,
                exact_membership: false,
                cover_inflation: primary.candidate_bytes.saturating_sub(set.cardinality()),
            }
        };
        let key = (
            filter_selection_key(candidate.primary),
            !candidate.exact_membership,
        );
        if selected.is_none_or(|current: ContextAnchoredCandidateFilter| {
            key < (
                filter_selection_key(current.primary),
                !current.exact_membership,
            )
        }) {
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

fn anchored_set_frequency_units(set: AnchoredByteSet) -> u16 {
    let words = set.words();
    let mut units = 0_u16;
    for byte in u8::MIN..=u8::MAX {
        let index = usize::from(byte);
        if words[index / 64] & (1_u64 << (index % 64)) != 0 {
            units = units.saturating_add(estimated_byte_frequency_units(byte));
        }
    }
    units.min(BYTE_FREQUENCY_DENOMINATOR)
}

/// Return the shortest prefix shift whose overlapping columns can all agree.
///
/// This is intentionally a cheap necessary-condition detector: intersecting
/// byte sets do not prove that a complete graph path realizes the overlap.
/// Consequently it is used only to make admission and runtime costing more
/// conservative; the adaptive guard remains the independent hard bound.
fn context_anchored_overlap_period(sets: &[AnchoredByteSet]) -> Option<u8> {
    for period in 1..sets.len() {
        let overlaps = (period..sets.len()).all(|position| {
            sets[position]
                .words()
                .iter()
                .zip(sets[position - period].words())
                .any(|(&left, right)| left & right != 0)
        });
        if overlaps {
            return u8::try_from(period).ok();
        }
    }
    None
}

fn context_anchored_overlap_work(guarded_bytes: u8, period: Option<u8>) -> u16 {
    period.map_or(0, |period| {
        u16::from(guarded_bytes)
            .div_ceil(u16::from(period))
            .saturating_sub(1)
            .min(CONTEXT_ANCHORED_MAX_OVERLAP_WORK)
    })
}

fn context_anchored_scanner_work(search: ContextAnchoredForwardSearch) -> Option<u16> {
    if let Some(filter) = search.vector_filter {
        filter.columns().iter().try_fold(0_u16, |work, &column| {
            work.checked_add(vector_filter_instruction_units(column))
        })
    } else {
        Some(vector_filter_instruction_units(search.primary))
    }
}

fn derive_context_anchored_adaptive_guard(
    search: ContextAnchoredForwardSearch,
    prefix_filter: Option<NativePrefixFilter>,
) -> Result<ContextAnchoredAdaptiveGuard, ObjectError> {
    let scanner_work = context_anchored_scanner_work(search).ok_or(
        ObjectError::ArithmeticOverflow("context anchored scanner guard work"),
    )?;
    let predicate_work = prefix_filter.map_or(0, |filter| {
        u16::try_from(filter.predicates().len()).unwrap_or(u16::MAX)
    });
    let cover_work = search
        .cover_inflation
        .div_ceil(CONTEXT_ANCHORED_COVER_BYTES_PER_WORK);
    let overlap_work = context_anchored_overlap_work(search.guarded_bytes, search.overlap_period);
    let candidate_work = CONTEXT_ANCHORED_CANDIDATE_BASE_WORK
        .checked_add(predicate_work)
        .and_then(|work| work.checked_add(cover_work))
        .and_then(|work| work.checked_add(overlap_work))
        .ok_or(ObjectError::ArithmeticOverflow(
            "context anchored candidate guard work",
        ))?;
    let initial_work = u16::from(search.max_verify_bytes)
        .checked_mul(CONTEXT_ANCHORED_TRANSITION_WORK)
        .and_then(|work| work.checked_add(candidate_work))
        .and_then(|work| work.checked_add(scanner_work))
        .ok_or(ObjectError::ArithmeticOverflow(
            "context anchored initial guard work",
        ))?;
    let scale = |work: u16, site| {
        work.checked_mul(CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR)
            .filter(|&scaled| scaled <= 4_095)
            .ok_or(ObjectError::ArithmeticOverflow(site))
    };
    Ok(ContextAnchoredAdaptiveGuard {
        vector_debt: scale(scanner_work, "context anchored vector debt")?,
        candidate_debt: scale(candidate_work, "context anchored candidate debt")?,
        transition_debt: scale(
            CONTEXT_ANCHORED_TRANSITION_WORK,
            "context anchored transition debt",
        )?,
        initial_credit: scale(initial_work, "context anchored initial credit")?,
    })
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the copyable native view is the lowering module's established analysis interface"
)]
fn derive_context_anchored_forward_search(
    view: NativeContextProgramView<'_>,
) -> Result<Option<ContextAnchoredForwardSearch>, ObjectError> {
    if !matches!(
        view.output,
        OutputContract::Span | OutputContract::SelectedEnd
    ) || view.exact_match_width.is_some()
    {
        return Ok(None);
    }
    let Some(anchored) = view.dfa.anchored_forward else {
        return Ok(None);
    };
    let mut mapped_initials = 0_usize;
    for &state in anchored.main_initial_to_anchored {
        if state == u32::MAX {
            continue;
        }
        mapped_initials = mapped_initials
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context anchored initial count",
            ))?;
        let state = usize::try_from(state)
            .map_err(|_| ObjectError::ArithmeticOverflow("context anchored initial state"))?;
        let flags = anchored
            .states
            .get(state)
            .ok_or(ObjectError::InvalidModule(
                "context anchored initial state is absent",
            ))?;
        // A nonempty prefix scanner cannot enumerate the window-end empty
        // candidate. Nullable graphs therefore stay on the complete machine.
        if flags.pending {
            return Ok(None);
        }
    }
    if mapped_initials == 0 {
        return Ok(None);
    }

    let sets = view.anchored_prefix.sets();
    let Some(candidate) = derive_context_anchored_candidate_filter(sets)? else {
        return Ok(None);
    };
    let scanner_frequency = estimated_filter_frequency_units(candidate.primary);
    if scanner_frequency > CONTEXT_ANCHORED_MAX_SCANNER_FREQUENCY_UNITS {
        return Ok(None);
    }
    let guarded_bytes = u8::try_from(sets.len())
        .map_err(|_| ObjectError::ArithmeticOverflow("context anchored prefix bytes"))?;
    if guarded_bytes == 0 {
        return Ok(None);
    }
    let overlap_period = context_anchored_overlap_period(sets);
    let overlap_work = context_anchored_overlap_work(guarded_bytes, overlap_period);
    if u32::from(scanner_frequency).saturating_mul(u32::from(overlap_work.saturating_add(1)))
        > CONTEXT_ANCHORED_MAX_OVERLAP_FREQUENCY_WORK
    {
        return Ok(None);
    }

    // Prefix predicates run before the verifier. Model their complete
    // graph-required conjunction rather than any false-positive range cover.
    // This affects profitability only; the global runtime fuel remains the
    // adversarial bound if the stable frequency model is inaccurate.
    let mut probability_numerator = 1_u128;
    let mut probability_denominator = 1_u128;
    let mut selective_columns = 0_u8;
    for &set in sets {
        let units = anchored_set_frequency_units(set);
        if units == BYTE_FREQUENCY_DENOMINATOR {
            continue;
        }
        probability_numerator = probability_numerator.saturating_mul(u128::from(units));
        probability_denominator =
            probability_denominator.saturating_mul(u128::from(BYTE_FREQUENCY_DENOMINATOR));
        selective_columns = selective_columns.saturating_add(1);
    }
    if selective_columns == 0 {
        return Ok(None);
    }
    let max_verify_bytes = anchored
        .max_resolution_steps
        .and_then(|steps| u8::try_from(steps).ok())
        .map_or(CONTEXT_ANCHORED_MAX_VERIFY_BYTES, |steps| {
            steps.min(CONTEXT_ANCHORED_MAX_VERIFY_BYTES)
        });
    if max_verify_bytes == 0
        || probability_numerator
            .saturating_mul(u128::from(max_verify_bytes))
            .saturating_mul(2)
            .saturating_mul(CONTEXT_ANCHORED_PROFIT_DENOMINATOR)
            > probability_denominator
    {
        return Ok(None);
    }

    Ok(Some(ContextAnchoredForwardSearch {
        primary: candidate.primary,
        vector_filter: derive_vector_filter(Some(candidate.primary), sets)?,
        guarded_bytes,
        max_verify_bytes,
        cover_inflation: candidate.cover_inflation,
        overlap_period,
    }))
}

/// A selective terminal-suffix scan whose candidates are proved exactly by
/// the contextual reverse DFA. Exists can return the first proof. Ordered
/// outputs keep the earliest reverse-derived start across the complete
/// window, then replay the forward machine locally to select the exact end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextTerminalSuffixSearch {
    primary: NativeStartFilter,
    vector_filter: NativeVectorFilter,
    minimum_width: u8,
    /// Once a match start is known, a later suffix base this many bytes past
    /// it cannot produce an earlier start. None denotes an unbounded match.
    bounded_scan_distance: Option<u32>,
}

const CONTEXT_EXISTS_SUFFIX_CANDIDATE_PERIOD: u64 = 64;
const CONTEXT_EXISTS_SUFFIX_MAX_REVERSE_CELLS: usize = 1 << 20;
const CONTEXT_ORDERED_SUFFIX_MIN_WINDOW_BYTES: u32 = 256;

/// A small row-equivalent contextual state kernel.
///
/// Every retained raw byte moves every member to another member without an
/// event. Since all member rows are identical, one replay transition from the
/// canonical member reconstructs the exact state after an arbitrarily long
/// skipped run.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ContextStateSkipPlan {
    states: Vec<u32>,
    canonical_state: u32,
    /// `None` means every real byte self loops; only the window boundary can
    /// leave the state.
    exit_filter: Option<NativeStartFilter>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextStateMembership {
    Singleton(u32),
    Table { offset: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextStateSkip {
    membership: ContextStateMembership,
    canonical_state: u32,
    exit_filter: Option<NativeStartFilter>,
}

/// A table-proved contextual supertransition after a complete anchored-prefix
/// guard. The initial contextual dispatch already represents prefix byte zero,
/// so `consumed_bytes` advances over subsequent proved bytes only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextPrefixFastForward {
    guaranteed_bytes: u8,
    consumed_bytes: u8,
    target_state: u32,
}

/// A sufficient, graph-only proof that an exactly guarded prefix candidate
/// has already produced the selected match start.
///
/// `following_words` classifies the byte immediately after the guarded
/// prefix. `accepts_haystack_end` is the corresponding end-of-haystack fact;
/// search-window end is deliberately not treated as an absolute boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextKnownSpanStartProof {
    guarded_bytes: u8,
    following_words: [u64; 4],
    accepts_haystack_end: bool,
}

/// Installed native form of [`ContextKnownSpanStartProof`].
///
/// A partial real-byte set uses the ordinary exact scalar prefix predicate
/// machinery. Empty and universal sets need no auxiliary table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextKnownSpanStartGuard {
    guarded_bytes: u8,
    following_filter: Option<NativePrefixFilter>,
    accepts_any_byte: bool,
    accepts_all_bytes: bool,
    accepts_haystack_end: bool,
}

const CONTEXT_PREFIX_FAST_FORWARD_MAX_STATES: usize = 65_536;
const CONTEXT_PREFIX_FAST_FORWARD_MAX_CELLS: usize = 16_777_216;
const CONTEXT_PREFIX_FAST_FORWARD_MAX_WORK: u64 = 1_000_000;
const CONTEXT_PREFIX_FAST_FORWARD_MAX_MEMORY_BYTES: usize = 1024 * 1024;
const CONTEXT_KNOWN_START_MAX_STATES: usize = 65_536;
const CONTEXT_KNOWN_START_MAX_CELLS: usize = 16_777_216;
const CONTEXT_KNOWN_START_MAX_WORK: u64 = 16_777_216;
const CONTEXT_KNOWN_START_MAX_MEMORY_BYTES: usize = 1024 * 1024;
const ENABLE_CONTEXT_PREFIX_FAST_FORWARD: bool = true;
const ENABLE_CONTEXT_KNOWN_SPAN_START: bool = true;
const ENABLE_CONTEXT_PREFIX_DISPATCH_REUSE: bool = true;
const ENABLE_CONTEXT_X86_WIDE_SCANNERS: bool = true;
const ENABLE_CONTEXT_X86_AVX2_SHORT_BATCH: bool = true;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the max prefix distinguishes configurable proof ceilings from measured usage"
)]
struct ContextKnownStartLimits {
    max_states: usize,
    max_cells: usize,
    max_work: u64,
    max_memory_bytes: usize,
}

impl Default for ContextKnownStartLimits {
    fn default() -> Self {
        Self {
            max_states: CONTEXT_KNOWN_START_MAX_STATES,
            max_cells: CONTEXT_KNOWN_START_MAX_CELLS,
            max_work: CONTEXT_KNOWN_START_MAX_WORK,
            max_memory_bytes: CONTEXT_KNOWN_START_MAX_MEMORY_BYTES,
        }
    }
}

fn context_x86_start_filter_kind(features: FeatureSet) -> X86StartFilterKind {
    if ENABLE_CONTEXT_X86_WIDE_SCANNERS {
        x86_start_filter_kind(features)
    } else {
        X86StartFilterKind::Sse2
    }
}

fn context_x86_short_batch_bytes(kind: X86StartFilterKind, use_batch: bool) -> Option<u32> {
    (use_batch && ENABLE_CONTEXT_X86_AVX2_SHORT_BATCH && kind == X86StartFilterKind::Avx2)
        .then(|| u32::from(kind.width()) * 2)
}

#[derive(Clone, Copy, Debug)]
struct ContextPrefixWork {
    used: u64,
}

impl ContextPrefixWork {
    const fn new() -> Self {
        Self { used: 0 }
    }

    fn charge(&mut self, amount: u64) -> bool {
        let Some(next) = self.used.checked_add(amount) else {
            return false;
        };
        if next > CONTEXT_PREFIX_FAST_FORWARD_MAX_WORK {
            return false;
        }
        self.used = next;
        true
    }
}

fn context_prefix_classes(
    view: NativeContextProgramView<'_>,
    set: AnchoredByteSet,
    work: &mut ContextPrefixWork,
) -> Option<[bool; 256]> {
    let class_count = usize::try_from(view.dfa.initial_dispatch.class_count).ok()?;
    let mut classes = [false; 256];
    for byte in u8::MIN..=u8::MAX {
        if !work.charge(1) {
            return None;
        }
        let index = usize::from(byte);
        if set.words()[index / 64] & (1_u64 << (index % 64)) == 0 {
            continue;
        }
        let class = usize::from(view.dfa.byte_classes[index]);
        if class >= class_count {
            return None;
        }
        classes[class] = true;
    }
    Some(classes)
}

fn context_prefix_state_is_safe(view: NativeContextProgramView<'_>, state: u32) -> Option<bool> {
    let flags = view.dfa.forward_states.get(usize::try_from(state).ok()?)?;
    Some(!flags.pending && !flags.empty && !flags.terminal)
}

/// Prove the longest replay-free suffix of an already guarded contextual
/// prefix. Every independent byte-set product is retained during analysis;
/// only convergence to one live, non-accepting state produces a plan.
#[allow(
    clippy::too_many_lines,
    reason = "the bounded product proof is clearer with validation and traversal together"
)]
fn derive_context_prefix_fast_forward(
    view: NativeContextProgramView<'_>,
) -> Option<ContextPrefixFastForward> {
    let sets = view.anchored_prefix.sets();
    if sets.len() < 2 || sets.iter().any(|set| set.cardinality() == 0) {
        return None;
    }
    let state_count = view.dfa.forward_states.len();
    let class_count = usize::try_from(view.dfa.initial_dispatch.class_count).ok()?;
    let row_width = usize::try_from(view.dfa.initial_dispatch.row_width).ok()?;
    if state_count == 0
        || state_count > CONTEXT_PREFIX_FAST_FORWARD_MAX_STATES
        || class_count == 0
        || class_count > 256
        || row_width != class_count.checked_add(1)?
        || view.dfa.forward_row_offsets.len() != state_count.checked_add(1)?
        || view.dfa.forward_cells.len() > CONTEXT_PREFIX_FAST_FORWARD_MAX_CELLS
        || view.dfa.forward_cells.len() != state_count.checked_mul(row_width)?
        || state_count
            .checked_mul(core::mem::size_of::<u32>())?
            .checked_mul(3)?
            > CONTEXT_PREFIX_FAST_FORWARD_MAX_MEMORY_BYTES
    {
        return None;
    }
    for (state, offsets) in view.dfa.forward_row_offsets.windows(2).enumerate() {
        let expected = state.checked_mul(row_width)?;
        if usize::try_from(offsets[0]).ok()? != expected
            || usize::try_from(offsets[1]).ok()? != expected.checked_add(row_width)?
        {
            return None;
        }
    }

    let mut work = ContextPrefixWork::new();
    let first_classes = context_prefix_classes(view, sets[0], &mut work)?;
    let mut current = Vec::new();
    current.try_reserve_exact(state_count).ok()?;
    let mut next = Vec::new();
    next.try_reserve_exact(state_count).ok()?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(state_count).ok()?;
    seen.resize(state_count, 0_u32);
    let mut generation = 1_u32;

    for entry in view.dfa.forward_initial {
        if !work.charge(1) {
            return None;
        }
        let class = usize::try_from(entry.context & view.dfa.initial_dispatch.class_mask).ok()?;
        if class >= class_count || !first_classes[class] {
            continue;
        }
        if !context_prefix_state_is_safe(view, entry.state)? {
            continue;
        }
        let state = usize::try_from(entry.state).ok()?;
        let marker = seen.get_mut(state)?;
        if *marker != generation {
            *marker = generation;
            current.push(entry.state);
        }
    }
    if current.is_empty() {
        return None;
    }

    let guaranteed_bytes = u8::try_from(sets.len()).ok()?;
    let mut best = None;
    for (position, &set) in sets.iter().enumerate().skip(1) {
        let classes = context_prefix_classes(view, set, &mut work)?;
        generation = generation.checked_add(1)?;
        next.clear();
        for &state in &current {
            let row = usize::try_from(state).ok()?.checked_mul(row_width)?;
            for (class, &present) in classes[..class_count].iter().enumerate() {
                if !present {
                    continue;
                }
                if !work.charge(1) {
                    return best;
                }
                let cell = *view.dfa.forward_cells.get(row.checked_add(class)?)?;
                if cell.accepted || !context_prefix_state_is_safe(view, cell.next)? {
                    return best;
                }
                let target = usize::try_from(cell.next).ok()?;
                let marker = seen.get_mut(target)?;
                if *marker != generation {
                    *marker = generation;
                    next.push(cell.next);
                }
            }
        }
        if next.is_empty() {
            return best;
        }
        core::mem::swap(&mut current, &mut next);
        if let [target_state] = current.as_slice() {
            best = Some(ContextPrefixFastForward {
                guaranteed_bytes,
                consumed_bytes: u8::try_from(position).ok()?,
                target_state: *target_state,
            });
        }
    }
    best
}

#[derive(Clone, Copy, Debug)]
struct ContextKnownStartWork {
    used: u64,
    limit: u64,
}

impl ContextKnownStartWork {
    const fn new(limit: u64) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self, amount: u64) -> bool {
        let Some(next) = self.used.checked_add(amount) else {
            return false;
        };
        if next > self.limit {
            return false;
        }
        self.used = next;
        true
    }
}

fn context_known_start_classes(
    view: NativeContextProgramView<'_>,
    set: AnchoredByteSet,
    work: &mut ContextKnownStartWork,
) -> Option<[bool; 256]> {
    let class_count = usize::try_from(view.dfa.initial_dispatch.class_count).ok()?;
    let mut classes = [false; 256];
    for byte in u8::MIN..=u8::MAX {
        if !work.charge(1) {
            return None;
        }
        let byte_index = usize::from(byte);
        if set.words()[byte_index / 64] & (1_u64 << (byte_index % 64)) == 0 {
            continue;
        }
        let class = usize::from(*view.dfa.byte_classes.get(byte_index)?);
        if class >= class_count {
            return None;
        }
        classes[class] = true;
    }
    Some(classes)
}

/// Prove a sufficient following-boundary guard for a known Span start.
///
/// The anchored-prefix construction visits assertions as if enabled and
/// stops before adding another byte as soon as it reaches accept. Therefore,
/// for a non-empty derived prefix of length `L`, no accepting graph path can
/// consume fewer than `L` bytes. We retain every Cartesian product admitted
/// by the conservative byte sets and every feasible contextual initial
/// dispatch. After replaying positions `1..L`, a final transition accepting
/// on following class `C` must belong to the candidate at position zero: a
/// subsequently injected search start has consumed strictly fewer than `L`
/// bytes. Ordered closure drops lower-priority items below that acceptance,
/// and pending acceptance prevents later start injection, so every eventual
/// selected end has the same candidate start.
///
/// Empty contextual initial frontiers are omitted only because native
/// lowering installs the exact dispatch check before applying this proof.
/// A following class is published only when every still-unmatched product
/// state accepts it. Failure or exhaustion declines the optional tag and
/// leaves ordinary reverse reconstruction intact.
fn derive_context_known_span_start(
    view: NativeContextProgramView<'_>,
) -> Option<ContextKnownSpanStartProof> {
    derive_context_known_span_start_with_limits(view, ContextKnownStartLimits::default())
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded all-path proof keeps its resource checks and traversal together"
)]
fn derive_context_known_span_start_with_limits(
    view: NativeContextProgramView<'_>,
    limits: ContextKnownStartLimits,
) -> Option<ContextKnownSpanStartProof> {
    if !ENABLE_CONTEXT_KNOWN_SPAN_START
        || view.output != OutputContract::Span
        || view.exact_match_width.is_some()
    {
        return None;
    }
    let sets = view.anchored_prefix.sets();
    if sets.is_empty() || sets.iter().any(|set| set.cardinality() == 0) {
        return None;
    }

    let state_count = view.dfa.forward_states.len();
    let class_count = usize::try_from(view.dfa.initial_dispatch.class_count).ok()?;
    let row_width = usize::try_from(view.dfa.initial_dispatch.row_width).ok()?;
    let cell_count = state_count.checked_mul(row_width)?;
    let scratch_bytes =
        state_count.checked_mul(core::mem::size_of::<u32>().checked_mul(2)?.checked_add(1)?)?;
    if state_count == 0
        || state_count > limits.max_states
        || class_count == 0
        || class_count > 256
        || row_width != class_count.checked_add(1)?
        || view.dfa.forward_row_offsets.len() != state_count.checked_add(1)?
        || cell_count > limits.max_cells
        || view.dfa.forward_cells.len() != cell_count
        || scratch_bytes > limits.max_memory_bytes
    {
        return None;
    }
    for (state, offsets) in view.dfa.forward_row_offsets.windows(2).enumerate() {
        let expected = state.checked_mul(row_width)?;
        if usize::try_from(offsets[0]).ok()? != expected
            || usize::try_from(offsets[1]).ok()? != expected.checked_add(row_width)?
        {
            return None;
        }
    }

    let mut work = ContextKnownStartWork::new(limits.max_work);
    let first_classes = context_known_start_classes(view, sets[0], &mut work)?;
    let mut current = Vec::new();
    current.try_reserve_exact(state_count).ok()?;
    let mut next = Vec::new();
    next.try_reserve_exact(state_count).ok()?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(state_count).ok()?;
    seen.resize(state_count, false);
    let mut has_proved_branch = false;

    for entry in view.dfa.forward_initial {
        if !work.charge(1) {
            return None;
        }
        let class = usize::try_from(entry.context & view.dfa.initial_dispatch.class_mask).ok()?;
        if class >= class_count || !first_classes[class] {
            continue;
        }
        let state = usize::try_from(entry.state).ok()?;
        let flags = view.dfa.forward_states.get(state)?;
        if flags.pending {
            has_proved_branch = true;
            continue;
        }
        if flags.empty || flags.terminal {
            continue;
        }
        let marker = seen.get_mut(state)?;
        if !*marker {
            *marker = true;
            current.push(entry.state);
        }
    }
    if current.is_empty() {
        return has_proved_branch.then_some(ContextKnownSpanStartProof {
            guarded_bytes: u8::try_from(sets.len()).ok()?,
            following_words: [u64::MAX; 4],
            accepts_haystack_end: true,
        });
    }

    for &set in sets.iter().skip(1) {
        let classes = context_known_start_classes(view, set, &mut work)?;
        next.clear();
        seen.fill(false);
        for &state in &current {
            let row = usize::try_from(state).ok()?.checked_mul(row_width)?;
            for (class, &present) in classes[..class_count].iter().enumerate() {
                if !present {
                    continue;
                }
                if !work.charge(1) {
                    return None;
                }
                let cell = *view.dfa.forward_cells.get(row.checked_add(class)?)?;
                if cell.accepted {
                    has_proved_branch = true;
                    continue;
                }
                let target = usize::try_from(cell.next).ok()?;
                let marker = seen.get_mut(target)?;
                if !*marker {
                    *marker = true;
                    next.push(cell.next);
                }
            }
        }
        if next.is_empty() {
            return has_proved_branch.then_some(ContextKnownSpanStartProof {
                guarded_bytes: u8::try_from(sets.len()).ok()?,
                following_words: [u64::MAX; 4],
                accepts_haystack_end: true,
            });
        }
        core::mem::swap(&mut current, &mut next);
    }

    let mut accepted_classes = [false; 256];
    for (class, accepted) in accepted_classes[..class_count].iter_mut().enumerate() {
        let mut all_accept = true;
        for &state in &current {
            if !work.charge(1) {
                return None;
            }
            let row = usize::try_from(state).ok()?.checked_mul(row_width)?;
            if !view
                .dfa
                .forward_cells
                .get(row.checked_add(class)?)?
                .accepted
            {
                all_accept = false;
                break;
            }
        }
        *accepted = all_accept;
    }
    let mut accepts_haystack_end = true;
    for &state in &current {
        if !work.charge(1) {
            return None;
        }
        let row = usize::try_from(state).ok()?.checked_mul(row_width)?;
        if !view
            .dfa
            .forward_cells
            .get(row.checked_add(class_count)?)?
            .accepted
        {
            accepts_haystack_end = false;
            break;
        }
    }

    let mut following_words = [0_u64; 4];
    for byte in u8::MIN..=u8::MAX {
        if !work.charge(1) {
            return None;
        }
        let byte_index = usize::from(byte);
        let class = usize::from(*view.dfa.byte_classes.get(byte_index)?);
        if *accepted_classes.get(class)? {
            following_words[byte_index / 64] |= 1_u64 << (byte_index % 64);
        }
    }
    if following_words.iter().all(|&word| word == 0) && !accepts_haystack_end {
        return None;
    }
    Some(ContextKnownSpanStartProof {
        guarded_bytes: u8::try_from(sets.len()).ok()?,
        following_words,
        accepts_haystack_end,
    })
}

fn derive_context_prefix_predicates(
    sets: &[AnchoredByteSet],
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    architecture: Architecture,
) -> Result<ScalarPrefixConjunctionPlan, ObjectError> {
    if sets.len() > MAX_ANCHORED_PREFIX_BYTES {
        return Err(ObjectError::InvalidModule(
            "context prefix exceeds the structural depth bound",
        ));
    }
    let empty = PrefixPredicateInput::new(0, [0; 4]);
    let mut inputs = [empty; MAX_ANCHORED_PREFIX_BYTES];
    let mut input_count = 0_usize;
    for (position, set) in sets.iter().copied().enumerate() {
        let scanner_proves = vector_filter.map_or(
            primary.from_anchored_prefix && usize::from(primary.scan_offset) == position,
            |filter| {
                filter.columns().iter().any(|column| {
                    column.from_anchored_prefix && usize::from(column.scan_offset) == position
                })
            },
        );
        if scanner_proves || set.cardinality() == 256 {
            continue;
        }
        let slot = inputs
            .get_mut(input_count)
            .ok_or(ObjectError::InvalidModule(
                "context prefix predicate count exceeds its structural bound",
            ))?;
        *slot = PrefixPredicateInput::new(
            u8::try_from(position)
                .map_err(|_| ObjectError::ArithmeticOverflow("context prefix position"))?,
            set.words(),
        );
        input_count = input_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context prefix predicate count",
            ))?;
    }
    let costs = match architecture {
        Architecture::X86_64 => X86_64_SCALAR_PREFIX_COSTS,
        Architecture::Aarch64 => AARCH64_SCALAR_PREFIX_COSTS,
    };
    let mut byte_weights = [0_u16; 256];
    for byte in u8::MIN..=u8::MAX {
        byte_weights[usize::from(byte)] = estimated_byte_frequency_units(byte);
    }
    plan_scalar_prefix_predicates(&inputs[..input_count], costs, &byte_weights)
        .map_err(|_| ObjectError::InvalidModule("context prefix predicate plan failed"))
}

fn install_context_known_span_start(
    layout: &mut ContextNativeLayout,
    proof: ContextKnownSpanStartProof,
    architecture: Architecture,
) -> Result<Option<ContextKnownSpanStartGuard>, ObjectError> {
    let passing_bytes = proof
        .following_words
        .iter()
        .map(|word| word.count_ones())
        .sum::<u32>();
    let accepts_any_byte = passing_bytes != 0;
    let accepts_all_bytes = passing_bytes == 256;
    let following_filter = if accepts_any_byte && !accepts_all_bytes {
        let input = PrefixPredicateInput::new(proof.guarded_bytes, proof.following_words);
        let costs = match architecture {
            Architecture::X86_64 => X86_64_SCALAR_PREFIX_COSTS,
            Architecture::Aarch64 => AARCH64_SCALAR_PREFIX_COSTS,
        };
        let mut byte_weights = [0_u16; 256];
        for byte in u8::MIN..=u8::MAX {
            byte_weights[usize::from(byte)] = estimated_byte_frequency_units(byte);
        }
        let plan =
            plan_scalar_prefix_predicates(std::slice::from_ref(&input), costs, &byte_weights)
                .map_err(|_| ObjectError::InvalidModule("context known-start plan failed"))?;
        let auxiliary_bytes = usize::from(plan.bitmap_count())
            .checked_mul(core::mem::size_of::<[u64; 4]>())
            .ok_or(ObjectError::ArithmeticOverflow(
                "context known-start auxiliary bytes",
            ))?;
        if layout
            .data
            .len()
            .checked_add(auxiliary_bytes)
            .is_none_or(|total| total > MAX_CONTEXT_NATIVE_DATA_BYTES)
        {
            return Ok(None);
        }
        if layout.data.try_reserve_exact(auxiliary_bytes).is_err() {
            return Ok(None);
        }
        let guaranteed_bytes = usize::from(proof.guarded_bytes).checked_add(1).ok_or(
            ObjectError::ArithmeticOverflow("context known-start byte bound"),
        )?;
        let filter = append_native_prefix_filter(&mut layout.data, plan, guaranteed_bytes)?.ok_or(
            ObjectError::InvalidModule("context known-start partial set has no predicate"),
        )?;
        if filter.predicates().len() != 1 || filter.predicates()[0].position != proof.guarded_bytes
        {
            return Err(ObjectError::InvalidModule(
                "context known-start predicate changed position",
            ));
        }
        Some(filter)
    } else {
        None
    };
    Ok(Some(ContextKnownSpanStartGuard {
        guarded_bytes: proof.guarded_bytes,
        following_filter,
        accepts_any_byte,
        accepts_all_bytes,
        accepts_haystack_end: proof.accepts_haystack_end,
    }))
}

fn derive_context_terminal_suffix_search(
    view: NativeContextProgramView<'_>,
) -> Result<Option<ContextTerminalSuffixSearch>, ObjectError> {
    if !matches!(
        view.output,
        OutputContract::Exists | OutputContract::SelectedEnd | OutputContract::Span
    ) || (matches!(
        view.output,
        OutputContract::SelectedEnd | OutputContract::Span
    ) && view.exact_match_width.is_some())
    {
        return Ok(None);
    }
    let suffix_sets = view.anchored_suffix.sets();
    if suffix_sets.len() < 2
        || suffix_sets
            .iter()
            .filter(|set| set.cardinality() < 256)
            .count()
            < 2
    {
        return Ok(None);
    }

    let mut forward_sets = Vec::new();
    forward_sets
        .try_reserve_exact(suffix_sets.len())
        .map_err(|_| ObjectError::InvalidModule("context suffix allocation failed"))?;
    forward_sets.extend(suffix_sets.iter().rev().copied());
    let Some(primary) = derive_anchored_prefix_start_filter(&forward_sets)? else {
        return Ok(None);
    };
    let Some(mut vector_filter) = derive_vector_filter(Some(primary), &forward_sets)? else {
        return Ok(None);
    };
    if vector_filter.columns().len() < 2 {
        return Ok(None);
    }
    // Two aligned graph columns match the packed-pair prefilter used by
    // mature substring engines. A third eager comparison increases the hot
    // scanner cost on every block, while exact reverse verification already
    // rejects the remaining false positives. Keep deeper suffix evidence for
    // the minimum-width proof, but lower the two most selective columns.
    vector_filter.column_count = vector_filter.column_count.min(2);

    // The frequency table is a profitability model, never a semantic proof.
    // Admit only aligned conjunctions expected at most once per cache line.
    let mut probability_numerator = 1_u64;
    let mut probability_denominator = 1_u64;
    for &column in vector_filter.columns() {
        probability_numerator = probability_numerator
            .saturating_mul(u64::from(estimated_filter_frequency_units(column)));
        probability_denominator =
            probability_denominator.saturating_mul(u64::from(BYTE_FREQUENCY_DENOMINATOR));
    }
    if probability_numerator.saturating_mul(CONTEXT_EXISTS_SUFFIX_CANDIDATE_PERIOD)
        > probability_denominator
    {
        return Ok(None);
    }

    let reverse_states =
        view.dfa
            .reverse_row_offsets
            .len()
            .checked_sub(1)
            .ok_or(ObjectError::InvalidModule(
                "context suffix reverse rows are empty",
            ))?;
    let row_width = usize::try_from(view.dfa.initial_dispatch.row_width)
        .map_err(|_| ObjectError::ArithmeticOverflow("context suffix reverse row width"))?;
    let reverse_cells =
        reverse_states
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context suffix reverse cells",
            ))?;
    if reverse_states == 0 || reverse_cells > CONTEXT_EXISTS_SUFFIX_MAX_REVERSE_CELLS {
        return Ok(None);
    }

    let minimum_width = u8::try_from(forward_sets.len())
        .map_err(|_| ObjectError::ArithmeticOverflow("context suffix minimum width"))?;
    let bounded_scan_distance = match view.max_match_width {
        Some(maximum) => maximum
            .checked_sub(usize::from(minimum_width))
            .ok_or(ObjectError::InvalidModule(
                "context suffix is wider than the maximum match",
            ))?
            .try_into()
            .ok(),
        None => None,
    };

    Ok(Some(ContextTerminalSuffixSearch {
        primary,
        vector_filter,
        minimum_width,
        bounded_scan_distance,
    }))
}

fn use_context_terminal_suffix_search(
    output: OutputContract,
    suffix: ContextTerminalSuffixSearch,
    prefix: Option<NativeStartFilter>,
    prefix_vector: Option<NativeVectorFilter>,
    interior_guard: Option<ContextInteriorGuard>,
) -> bool {
    match interior_guard.map(|guard| guard.restart) {
        // Reverse verification eliminates the otherwise unavoidable replay
        // from the original window start, so even a two-column suffix can pay.
        Some(ContextPrepassRestart::OriginalStart) => {
            output == OutputContract::Exists
                || (suffix.vector_filter.columns().len() >= 2
                    && suffix
                        .vector_filter
                        .columns()
                        .iter()
                        .all(|column| column.candidate_bytes <= 4))
        }
        // A bounded restart already gives the forward machine a cheap exact
        // neighborhood. Do not retain reverse tables for the same proof.
        Some(ContextPrepassRestart::Bounded(_) | ContextPrepassRestart::CandidateBase) => false,
        // Without a competing mandatory guard, require a deeper sparse
        // conjunction that is strictly more selective than the ordinary
        // anchored-prefix scan. Reverse verification has a higher fixed cost,
        // so an equivalent prefix/suffix filter should stay on the forward
        // machine.
        None => {
            suffix.vector_filter.columns().len() >= 2
                && suffix
                    .vector_filter
                    .columns()
                    .iter()
                    .all(|column| column.candidate_bytes <= 4)
                && context_suffix_filter_is_stricter(suffix, prefix, prefix_vector)
        }
    }
}

fn context_filter_frequency(columns: &[NativeStartFilter]) -> (u64, u64) {
    columns
        .iter()
        .fold((1_u64, 1_u64), |(numerator, denominator), &column| {
            (
                numerator.saturating_mul(u64::from(estimated_filter_frequency_units(column))),
                denominator.saturating_mul(u64::from(BYTE_FREQUENCY_DENOMINATOR)),
            )
        })
}

fn context_suffix_filter_is_stricter(
    suffix: ContextTerminalSuffixSearch,
    prefix: Option<NativeStartFilter>,
    prefix_vector: Option<NativeVectorFilter>,
) -> bool {
    let (suffix_numerator, suffix_denominator) =
        context_filter_frequency(suffix.vector_filter.columns());
    let (prefix_numerator, prefix_denominator) = match prefix_vector {
        Some(vector) => context_filter_frequency(vector.columns()),
        None => match prefix {
            Some(filter) => context_filter_frequency(std::slice::from_ref(&filter)),
            None => (1, 1),
        },
    };
    suffix_numerator.saturating_mul(prefix_denominator)
        < prefix_numerator.saturating_mul(suffix_denominator)
}

fn derive_context_interior_guard(
    view: NativeContextProgramView<'_>,
) -> Result<Option<ContextInteriorGuard>, ObjectError> {
    let mut selected = None;
    let mut selected_key = None;
    for candidate in view.required_literals.interior().candidates() {
        let depth = candidate.depth();
        if depth == 0
            || depth > MAX_REQUIRED_LITERAL_DEPTH
            || candidate.literals().is_empty()
            || candidate
                .literals()
                .iter()
                .any(|literal| literal.as_bytes().len() != depth)
        {
            continue;
        }
        let mut words = [[0_u64; 4]; MAX_REQUIRED_LITERAL_DEPTH];
        for literal in candidate.literals() {
            for (position, &byte) in literal.as_bytes().iter().enumerate() {
                let index = usize::from(byte);
                words[position][index / 64] |= 1_u64 << (index % 64);
            }
        }
        let mut sets = [AnchoredByteSet::from_words([0; 4]); MAX_REQUIRED_LITERAL_DEPTH];
        for (set, words) in sets[..depth].iter_mut().zip(words) {
            *set = AnchoredByteSet::from_words(words);
        }
        let Some(primary) = derive_anchored_prefix_start_filter(&sets[..depth])? else {
            continue;
        };
        let vector_filter = derive_vector_filter(Some(primary), &sets[..depth])?;
        let key =
            (
                filter_selection_key(primary),
                u8::MAX.saturating_sub(u8::try_from(depth).map_err(|_| {
                    ObjectError::ArithmeticOverflow("context interior literal depth")
                })?),
                candidate.literals().len(),
            );
        if selected_key.as_ref().is_none_or(|current| key < *current) {
            let restart = match candidate.max_before_root() {
                MaximumConsumedDistance::Finite(maximum) => ContextPrepassRestart::Bounded(maximum),
                MaximumConsumedDistance::Unbounded => ContextPrepassRestart::OriginalStart,
            };
            selected = Some(ContextInteriorGuard {
                primary,
                vector_filter,
                restart,
            });
            selected_key = Some(key);
        }
    }
    Ok(selected)
}

#[allow(
    clippy::too_many_lines,
    reason = "state-skip selection is one bounded graph-analysis pass"
)]
fn derive_context_state_skip(
    view: NativeContextProgramView<'_>,
) -> Result<Option<ContextStateSkipPlan>, ObjectError> {
    let dfa = view.dfa;
    let state_count = dfa.forward_states.len();
    let class_count = usize::try_from(dfa.initial_dispatch.class_count)
        .map_err(|_| ObjectError::ArithmeticOverflow("context skip class count"))?;
    let row_width = usize::try_from(dfa.initial_dispatch.row_width)
        .map_err(|_| ObjectError::ArithmeticOverflow("context skip row width"))?;
    if class_count == 0
        || class_count > 256
        || row_width != class_count.saturating_add(1)
        || dfa.forward_row_offsets.len() != state_count.saturating_add(1)
    {
        return Err(ObjectError::InvalidModule(
            "context skip has invalid forward geometry",
        ));
    }

    let mut class_cardinality = [0_u16; 256];
    for &class in dfa.byte_classes {
        let class = usize::from(class);
        if class >= class_count {
            return Err(ObjectError::InvalidModule(
                "context skip byte class is out of range",
            ));
        }
        class_cardinality[class] =
            class_cardinality[class]
                .checked_add(1)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context skip class cardinality",
                ))?;
    }

    let mut initial = vec![0_u64; state_count];
    for entry in dfa.forward_initial {
        let state = usize::try_from(entry.state)
            .map_err(|_| ObjectError::ArithmeticOverflow("context skip initial state"))?;
        let count = initial.get_mut(state).ok_or(ObjectError::InvalidModule(
            "context skip initial state is out of range",
        ))?;
        *count = count.checked_add(1).ok_or(ObjectError::ArithmeticOverflow(
            "context skip initial weight",
        ))?;
    }
    let mut incoming = vec![0_u64; state_count];
    for source in 0..state_count {
        let begin = source
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow("context skip incoming row"))?;
        for (class, &cardinality) in class_cardinality[..class_count].iter().enumerate() {
            let index = begin
                .checked_add(class)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context skip incoming index",
                ))?;
            let cell = *dfa
                .forward_cells
                .get(index)
                .ok_or(ObjectError::InvalidModule(
                    "context skip incoming cell is absent",
                ))?;
            let target = usize::try_from(cell.next)
                .map_err(|_| ObjectError::ArithmeticOverflow("context skip incoming target"))?;
            let count = incoming.get_mut(target).ok_or(ObjectError::InvalidModule(
                "context skip incoming target is out of range",
            ))?;
            *count = count.saturating_add(u64::from(cardinality));
        }
    }

    let mut row_groups = std::collections::BTreeMap::<(bool, Vec<u64>), Vec<usize>>::new();
    for (state, flags) in dfa.forward_states.iter().enumerate() {
        if flags.terminal {
            continue;
        }
        let begin = state
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow("context skip row"))?;
        let mut signature = Vec::new();
        signature
            .try_reserve_exact(class_count)
            .map_err(|_| ObjectError::InvalidModule("context skip signature allocation failed"))?;
        for class in 0..class_count {
            let index = begin
                .checked_add(class)
                .ok_or(ObjectError::ArithmeticOverflow("context skip cell index"))?;
            let cell = *dfa
                .forward_cells
                .get(index)
                .ok_or(ObjectError::InvalidModule(
                    "context skip forward cell is absent",
                ))?;
            signature.push(u64::from(cell.next) | (u64::from(cell.accepted) << 32));
        }
        row_groups
            .entry((flags.pending, signature))
            .or_default()
            .push(state);
    }

    let mut selected = None;
    let mut selected_key = None;
    for states in row_groups.values() {
        if states.is_empty() {
            continue;
        }
        let canonical = states[0];
        let begin = canonical
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context skip canonical row",
            ))?;
        let mut words = [0_u64; 4];
        let mut exit_bytes = 0_u16;
        for (byte, &class) in dfa.byte_classes.iter().enumerate() {
            let index =
                begin
                    .checked_add(usize::from(class))
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "context skip forward byte index",
                    ))?;
            let cell = *dfa
                .forward_cells
                .get(index)
                .ok_or(ObjectError::InvalidModule(
                    "context skip forward byte cell is absent",
                ))?;
            let target = usize::try_from(cell.next)
                .map_err(|_| ObjectError::ArithmeticOverflow("context skip target state"))?;
            if cell.accepted || states.binary_search(&target).is_err() {
                words[byte / 64] |= 1_u64 << (byte % 64);
                exit_bytes = exit_bytes
                    .checked_add(1)
                    .ok_or(ObjectError::ArithmeticOverflow("context skip exit bytes"))?;
            }
        }
        let exit_filter = if exit_bytes == 0 {
            None
        } else {
            let Some(filter) = filter_from_membership_words(words, 1, false)? else {
                continue;
            };
            Some(filter)
        };
        let mut initial_weight = 0_u64;
        for &state in states {
            initial_weight = initial_weight.saturating_add(initial[state]);
        }
        let mut external_incoming = 0_u64;
        for source in 0..state_count {
            if states.binary_search(&source).is_ok() {
                continue;
            }
            let source_begin = source
                .checked_mul(row_width)
                .ok_or(ObjectError::ArithmeticOverflow("context skip source row"))?;
            for (class, &cardinality) in class_cardinality[..class_count].iter().enumerate() {
                let index =
                    source_begin
                        .checked_add(class)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "context skip incoming cell",
                        ))?;
                let cell = *dfa
                    .forward_cells
                    .get(index)
                    .ok_or(ObjectError::InvalidModule(
                        "context skip incoming cell is absent",
                    ))?;
                let target = usize::try_from(cell.next)
                    .map_err(|_| ObjectError::ArithmeticOverflow("context skip incoming target"))?;
                if states.binary_search(&target).is_ok() {
                    external_incoming = external_incoming.saturating_add(u64::from(cardinality));
                }
            }
        }
        if external_incoming == 0 && initial_weight <= 1 {
            continue;
        }
        let hotness = initial_weight
            .saturating_mul(257)
            .saturating_add(external_incoming);
        let canonical_state = u32::try_from(canonical)
            .map_err(|_| ObjectError::ArithmeticOverflow("context skip canonical state"))?;
        let key = (
            u64::MAX.saturating_sub(hotness),
            exit_bytes,
            u32::MAX.saturating_sub(u32::try_from(states.len()).unwrap_or(u32::MAX)),
            canonical_state,
        );
        if selected_key.is_none_or(|current| key < current) {
            selected = Some(ContextStateSkipPlan {
                states: states
                    .iter()
                    .map(|&state| {
                        u32::try_from(state)
                            .map_err(|_| ObjectError::ArithmeticOverflow("context skip state"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                canonical_state,
                exit_filter,
            });
            selected_key = Some(key);
        }
    }
    // A useful row may share its signature with distant sink copies that do
    // not fit the compact kernel mask. Retain the ordinary single-state proof
    // as a fallback instead of losing that hot self loop with the group.
    for (state, flags) in dfa.forward_states.iter().enumerate().take(64) {
        if flags.terminal {
            continue;
        }
        let begin = state
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow("context self-skip row"))?;
        let mut words = [0_u64; 4];
        let mut exit_bytes = 0_u16;
        let mut self_incoming = 0_u64;
        for (byte, &class) in dfa.byte_classes.iter().enumerate() {
            let index =
                begin
                    .checked_add(usize::from(class))
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "context self-skip byte index",
                    ))?;
            let cell = *dfa
                .forward_cells
                .get(index)
                .ok_or(ObjectError::InvalidModule(
                    "context self-skip byte cell is absent",
                ))?;
            if !cell.accepted && usize::try_from(cell.next).ok() == Some(state) {
                self_incoming = self_incoming.saturating_add(1);
            } else {
                words[byte / 64] |= 1_u64 << (byte % 64);
                exit_bytes = exit_bytes
                    .checked_add(1)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "context self-skip exit bytes",
                    ))?;
            }
        }
        let exit_filter = if exit_bytes == 0 {
            None
        } else {
            let Some(filter) = filter_from_membership_words(words, 1, false)? else {
                continue;
            };
            Some(filter)
        };
        let external_incoming = incoming[state].saturating_sub(self_incoming);
        if external_incoming == 0 && initial[state] <= 1 {
            continue;
        }
        let hotness = initial[state]
            .saturating_mul(257)
            .saturating_add(external_incoming);
        let canonical_state = u32::try_from(state)
            .map_err(|_| ObjectError::ArithmeticOverflow("context self-skip state"))?;
        let key = (
            u64::MAX.saturating_sub(hotness),
            exit_bytes,
            u32::MAX - 1,
            canonical_state,
        );
        if selected_key.is_none_or(|current| key < current) {
            selected = Some(ContextStateSkipPlan {
                states: vec![canonical_state],
                canonical_state,
                exit_filter,
            });
            selected_key = Some(key);
        }
    }
    Ok(selected)
}

/// Decide whether an empty ordered frontier should return to the anchored
/// prefix scanner instead of using the selected graph kernel.
///
/// If the kernel covers most empty initial states for real current bytes and
/// scans an equal-or-smaller byte set, entering it is the cheaper general
/// search restart (for example, a one-byte line-boundary exit). Otherwise the
/// anchored prefix is the stronger proof (notably for fragmented word-class
/// exits). This compares only compiler-derived table facts.
fn use_empty_prefix_restart(
    view: NativeContextProgramView<'_>,
    prefix: NativeStartFilter,
    state_skip: Option<&ContextStateSkipPlan>,
) -> bool {
    let Some(state_skip) = state_skip else {
        return true;
    };
    let mut empty_states = 0_usize;
    let mut covered_states = 0_usize;
    for entry in view.dfa.forward_initial {
        let class = entry.context & view.dfa.initial_dispatch.class_mask;
        if class >= view.dfa.initial_dispatch.class_count {
            continue;
        }
        let Some(flags) = usize::try_from(entry.state)
            .ok()
            .and_then(|state| view.dfa.forward_states.get(state))
        else {
            return true;
        };
        if flags.empty && !flags.pending {
            empty_states = empty_states.saturating_add(1);
            if state_skip.states.binary_search(&entry.state).is_ok() {
                covered_states = covered_states.saturating_add(1);
            }
        }
    }
    if empty_states == 0 {
        return false;
    }
    if covered_states.saturating_mul(2) < empty_states {
        return true;
    }
    state_skip
        .exit_filter
        .is_some_and(|exit| prefix.candidate_bytes < exit.candidate_bytes)
}

fn install_context_state_skip(
    layout: &mut ContextNativeLayout,
    plan: Option<ContextStateSkipPlan>,
) -> Result<Option<ContextStateSkip>, ObjectError> {
    let Some(plan) = plan else {
        return Ok(None);
    };
    let canonical_state = plan.canonical_state;
    let membership = if let [state] = plan.states.as_slice() {
        ContextStateMembership::Singleton(*state)
    } else {
        if plan.states.is_empty() {
            return Err(ObjectError::InvalidModule(
                "context state-skip kernel is empty",
            ));
        }
        let state_count = usize::try_from(layout.forward_states)
            .map_err(|_| ObjectError::ArithmeticOverflow("context state-skip states"))?;
        let membership_entries = state_count;
        let offset = layout.data.len();
        let Some(total) = offset.checked_add(membership_entries) else {
            return Ok(None);
        };
        let Ok(maximum) = usize::try_from(i32::MAX) else {
            return Ok(None);
        };
        if total > maximum {
            return Ok(None);
        }
        if layout.data.try_reserve_exact(membership_entries).is_err() {
            return Ok(None);
        }
        layout.data.resize(total, 0);
        for state in plan.states {
            let state = usize::try_from(state)
                .map_err(|_| ObjectError::ArithmeticOverflow("context state-skip member"))?;
            let destination = offset
                .checked_add(state)
                .filter(|&index| index < total)
                .ok_or(ObjectError::InvalidModule(
                    "context state-skip member is out of range",
                ))?;
            layout.data[destination] = 1;
        }
        ContextStateMembership::Table {
            offset: u32::try_from(offset)
                .map_err(|_| ObjectError::ArithmeticOverflow("context state-skip offset"))?,
        }
    };
    Ok(Some(ContextStateSkip {
        membership,
        canonical_state,
        exit_filter: plan.exit_filter,
    }))
}

/// Append the target-neutral lane ramp used by the Apple ASIMD first-hit
/// lowering. This auxiliary is optional and transactionally installed after
/// every other context table, so an allocation failure merely retains scalar
/// refinement of a vector hit.
fn install_context_asimd_lane_index(
    layout: &mut ContextNativeLayout,
    target: Target,
    has_vector_prepass: bool,
) -> Result<Option<u32>, ObjectError> {
    if target.architecture != Architecture::Aarch64
        || !target.features.has(CpuFeature::Aarch64Asimd)
        || !aarch64_use_exact_first_lane(target.operating_system)
        || !has_vector_prepass
    {
        return Ok(None);
    }
    let alignment = AARCH64_FIRST_LANE_INDEX.len();
    let aligned =
        layout
            .data
            .len()
            .checked_add(alignment - 1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context AArch64 lane-index alignment",
            ))?
            & !(alignment - 1);
    let total = aligned
        .checked_add(alignment)
        .ok_or(ObjectError::ArithmeticOverflow(
            "context AArch64 lane-index bytes",
        ))?;
    let maximum_table_bytes = usize::try_from(i32::MAX)
        .map_err(|_| ObjectError::ArithmeticOverflow("context table address limit"))?
        .min(MAX_CONTEXT_NATIVE_DATA_BYTES);
    if total > maximum_table_bytes {
        return Ok(None);
    }
    let additional =
        total
            .checked_sub(layout.data.len())
            .ok_or(ObjectError::ArithmeticOverflow(
                "context AArch64 lane-index reservation",
            ))?;
    if layout.data.try_reserve_exact(additional).is_err() {
        return Ok(None);
    }
    layout.data.resize(aligned, 0);
    layout.data.extend_from_slice(&AARCH64_FIRST_LANE_INDEX);
    Ok(Some(u32::try_from(aligned).map_err(|_| {
        ObjectError::ArithmeticOverflow("context AArch64 lane-index offset")
    })?))
}

fn install_context_sve2_match_table(
    layout: &mut ContextNativeLayout,
    target: Target,
    filter: Option<NativeStartFilter>,
) -> Result<Option<u32>, ObjectError> {
    if target.architecture != Architecture::Aarch64
        || !aarch64_primary_scanner_uses_sve(aarch64_primary_scanner_isa(
            target.operating_system,
            target.features,
            true,
        ))
        || !target.features.has(CpuFeature::Aarch64Sve2)
    {
        return Ok(None);
    }
    let Some(filter) = filter.filter(|filter| filter.is_exact() && !filter.ranges().is_empty())
    else {
        return Ok(None);
    };
    let alignment = 16_usize;
    let aligned =
        layout
            .data
            .len()
            .checked_add(alignment - 1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context SVE2 match-table alignment",
            ))?
            & !(alignment - 1);
    let total = aligned
        .checked_add(16)
        .ok_or(ObjectError::ArithmeticOverflow(
            "context SVE2 match-table bytes",
        ))?;
    let maximum_table_bytes = usize::try_from(i32::MAX)
        .map_err(|_| ObjectError::ArithmeticOverflow("context SVE2 table address limit"))?
        .min(MAX_CONTEXT_NATIVE_DATA_BYTES);
    if total > maximum_table_bytes {
        return Ok(None);
    }
    let additional =
        total
            .checked_sub(layout.data.len())
            .ok_or(ObjectError::ArithmeticOverflow(
                "context SVE2 table reservation",
            ))?;
    if layout.data.try_reserve_exact(additional).is_err() {
        return Ok(None);
    }
    layout.data.resize(aligned, 0);
    for index in 0..16_usize {
        let range = filter
            .ranges()
            .get(index % filter.ranges().len())
            .ok_or(ObjectError::InvalidModule("empty context SVE2 match table"))?;
        layout.data.push(range.start);
    }
    Ok(Some(u32::try_from(aligned).map_err(|_| {
        ObjectError::ArithmeticOverflow("context SVE2 match-table offset")
    })?))
}

fn aarch64_context_prefix_accelerator(
    target: Target,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    boundary_pair: Option<ContextBoundaryPairExpression>,
    sve2_match_table: Option<u32>,
) -> Option<StartAccelerator> {
    if primary.ranges().is_empty() {
        return None;
    }
    let sve_route_supported = vector_filter.is_none() && boundary_pair.is_none();
    Some(match aarch64_primary_scanner_isa(
        target.operating_system,
        target.features,
        sve_route_supported,
    ) {
        Aarch64PrimaryScannerIsa::Sve | Aarch64PrimaryScannerIsa::SveWithAsimdVl16
            if sve2_match_table.is_some() =>
        {
            StartAccelerator::Aarch64Sve2
        }
        Aarch64PrimaryScannerIsa::Sve | Aarch64PrimaryScannerIsa::SveWithAsimdVl16 => {
            StartAccelerator::Aarch64Sve
        }
        Aarch64PrimaryScannerIsa::Asimd => StartAccelerator::Aarch64Asimd,
        Aarch64PrimaryScannerIsa::Scalar => StartAccelerator::Scalar,
    })
}

const fn aarch64_context_accelerator_rank(accelerator: StartAccelerator) -> u8 {
    match accelerator {
        StartAccelerator::None => 0,
        StartAccelerator::Scalar => 1,
        StartAccelerator::Aarch64Asimd => 2,
        StartAccelerator::Aarch64Sve => 3,
        StartAccelerator::Aarch64Sve2 => 4,
        StartAccelerator::X86Sse2 | StartAccelerator::X86Avx2 | StartAccelerator::X86Avx512Bw => 0,
    }
}

fn strongest_aarch64_context_accelerator(
    current: &mut StartAccelerator,
    candidate: Option<StartAccelerator>,
) {
    if let Some(candidate) = candidate
        && aarch64_context_accelerator_rank(candidate) > aarch64_context_accelerator_rank(*current)
    {
        *current = candidate;
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the receipt must mirror every independently emitted context scanner route"
)]
fn selected_context_start_accelerator(
    target: Target,
    terminal_suffix_search: Option<ContextTerminalSuffixSearch>,
    anchored_forward_search: Option<ContextAnchoredForwardSearch>,
    anchored_boundary_pair: Option<ContextBoundaryPairExpression>,
    start_filter: Option<NativeStartFilter>,
    vector_filter: Option<NativeVectorFilter>,
    ordinary_boundary_pair: Option<ContextBoundaryPairExpression>,
    interior_guard: Option<ContextInteriorGuard>,
    sve2_match_tables: ContextSve2MatchTables,
) -> StartAccelerator {
    let has_prefix_scanner = interior_guard.is_some_and(|guard| !guard.primary.ranges().is_empty())
        || anchored_forward_search.is_some_and(|search| !search.primary.ranges().is_empty())
        || start_filter.is_some_and(|filter| !filter.ranges().is_empty());
    match target.architecture {
        Architecture::X86_64 => {
            if !has_prefix_scanner && terminal_suffix_search.is_none() {
                return StartAccelerator::None;
            }
            match context_x86_start_filter_kind(target.features) {
                X86StartFilterKind::Sse2 => StartAccelerator::X86Sse2,
                X86StartFilterKind::Avx2 => StartAccelerator::X86Avx2,
                X86StartFilterKind::Avx512Bw => StartAccelerator::X86Avx512Bw,
            }
        }
        Architecture::Aarch64 => {
            let mut selected = StartAccelerator::None;
            if let Some(guard) = interior_guard {
                strongest_aarch64_context_accelerator(
                    &mut selected,
                    aarch64_context_prefix_accelerator(
                        target,
                        guard.primary,
                        guard.vector_filter,
                        None,
                        sve2_match_tables.interior,
                    ),
                );
            }
            if let Some(search) = anchored_forward_search {
                strongest_aarch64_context_accelerator(
                    &mut selected,
                    aarch64_context_prefix_accelerator(
                        target,
                        search.primary,
                        search.vector_filter,
                        anchored_boundary_pair,
                        sve2_match_tables.anchored,
                    ),
                );
            }
            if let Some(primary) = start_filter {
                strongest_aarch64_context_accelerator(
                    &mut selected,
                    aarch64_context_prefix_accelerator(
                        target,
                        primary,
                        vector_filter,
                        ordinary_boundary_pair,
                        sve2_match_tables.ordinary,
                    ),
                );
            }
            // The existing terminal-suffix implementation is an ASIMD
            // scanner on AArch64 independently of the primary prepasses.
            if terminal_suffix_search.is_some() {
                strongest_aarch64_context_accelerator(
                    &mut selected,
                    Some(StartAccelerator::Aarch64Asimd),
                );
            }
            selected
        }
    }
}

/// Lower a complete contextual DFA without retaining a runtime dependency.
#[allow(
    clippy::too_many_lines,
    reason = "native-plan selection and layout installation form one transactional lowering"
)]
pub(super) fn lower_native_context(
    view: NativeContextProgramView<'_>,
    target: Target,
) -> Result<NativeLowering, ObjectError> {
    let boundary_pair_relation = derive_context_boundary_pair_relation(view)?;
    let start_filter = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())?;
    let vector_filter = derive_vector_filter(start_filter, view.anchored_prefix.sets())?;
    let interior_guard = derive_context_interior_guard(view)?.filter(|guard| {
        start_filter
            .is_none_or(|prefix| filter_selection_key(guard.primary) < filter_selection_key(prefix))
    });
    let terminal_suffix_search = ENABLE_CONTEXT_TERMINAL_SUFFIX_SEARCH
        .then(|| derive_context_terminal_suffix_search(view))
        .transpose()?
        .flatten()
        .filter(|suffix| {
            use_context_terminal_suffix_search(
                view.output,
                *suffix,
                start_filter,
                vector_filter,
                interior_guard,
            )
        })
        .filter(|_| {
            target.architecture == Architecture::X86_64
                || target.features.has(CpuFeature::Aarch64Asimd)
        });
    // The exact-start sidecar and terminal-suffix verifier are deliberately
    // exclusive. Retaining both duplicates optional tables and makes the
    // entry policy depend on a fragile cost comparison. Prefer the already
    // selected suffix route; otherwise the anchored machine owns candidate
    // scanning completely and never leaks a false-positive cover into the
    // ordinary prefix proofs.
    let mut anchored_forward_search =
        if ENABLE_CONTEXT_ANCHORED_FORWARD_SEARCH && terminal_suffix_search.is_none() {
            derive_context_anchored_forward_search(view)?
        } else {
            None
        };
    let state_skip_plan = derive_context_state_skip(view)?;
    let empty_prefix_restart = start_filter
        .is_some_and(|prefix| use_empty_prefix_restart(view, prefix, state_skip_plan.as_ref()));
    let mut prefix_fast_forward = if ENABLE_CONTEXT_PREFIX_FAST_FORWARD {
        start_filter
            .filter(|filter| filter.candidate_bytes != 0 && !filter.ranges().is_empty())
            .and_then(|_| derive_context_prefix_fast_forward(view))
    } else {
        None
    };
    let mut known_span_start_proof = start_filter
        .filter(|filter| {
            filter.from_anchored_prefix
                && filter.candidate_bytes != 0
                && !filter.ranges().is_empty()
        })
        .and_then(|_| derive_context_known_span_start(view));
    let ordinary_prefix_predicate_plan = match (
        prefix_fast_forward.is_some() || known_span_start_proof.is_some(),
        start_filter,
    ) {
        (true, Some(primary)) => Some(derive_context_prefix_predicates(
            view.anchored_prefix.sets(),
            primary,
            vector_filter,
            target.architecture,
        )?),
        _ => None,
    };
    let anchored_prefix_predicate_plan = anchored_forward_search
        .map(|search| {
            derive_context_prefix_predicates(
                view.anchored_prefix.sets(),
                search.primary,
                search.vector_filter,
                target.architecture,
            )
        })
        .transpose()?;

    // Optional sidecar installation is transactional. If either physical
    // representation cannot fit, or its exact auxiliary conjunction cannot
    // be installed, rebuild the mandatory image and retain the complete main
    // DFA route. No emitted code can then observe a half-installed plan.
    let (mut layout, prefix_filter, anchored_prefix_filter, anchored_adaptive_guard) = loop {
        let mut candidate = build_context_native_layout_with_accelerators(
            view,
            ContextNativeLimits::default(),
            terminal_suffix_search.is_some(),
            anchored_forward_search.is_some(),
        )?;
        if anchored_forward_search.is_some() && candidate.anchored_forward.is_none() {
            anchored_forward_search = None;
            continue;
        }

        if let (Some(search), Some(plan)) =
            (anchored_forward_search, anchored_prefix_predicate_plan)
        {
            let auxiliary_bytes = usize::from(plan.bitmap_count())
                .checked_mul(core::mem::size_of::<[u64; 4]>())
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context anchored prefix auxiliary bytes",
                ))?;
            if candidate
                .data
                .len()
                .checked_add(auxiliary_bytes)
                .is_none_or(|total| total > MAX_CONTEXT_NATIVE_DATA_BYTES)
            {
                anchored_forward_search = None;
                continue;
            }
            if candidate.data.try_reserve_exact(auxiliary_bytes).is_err() {
                anchored_forward_search = None;
                continue;
            }
            let installed = append_native_prefix_filter(
                &mut candidate.data,
                plan,
                usize::from(search.guarded_bytes),
            )?;
            // A cover does not prove its graph column. It must always be
            // accompanied by at least one exact predicate for that column.
            if !search.primary.from_anchored_prefix && installed.is_none() {
                anchored_forward_search = None;
                continue;
            }
            let Ok(adaptive_guard) = derive_context_anchored_adaptive_guard(search, installed)
            else {
                anchored_forward_search = None;
                continue;
            };
            // Keep the ordinary prefix proof available to the one-shot
            // adaptive fallback. The sidecar's predicates can differ (and a
            // cover predicate is never an ordinary proof), so install the two
            // optional plans independently and transactionally.
            let ordinary = if let Some(plan) = ordinary_prefix_predicate_plan {
                let auxiliary_bytes = usize::from(plan.bitmap_count())
                    .checked_mul(core::mem::size_of::<[u64; 4]>())
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "context fallback prefix auxiliary bytes",
                    ))?;
                if candidate
                    .data
                    .len()
                    .checked_add(auxiliary_bytes)
                    .is_some_and(|total| total <= MAX_CONTEXT_NATIVE_DATA_BYTES)
                    && candidate.data.try_reserve_exact(auxiliary_bytes).is_ok()
                {
                    append_native_prefix_filter(
                        &mut candidate.data,
                        plan,
                        view.anchored_prefix.sets().len(),
                    )?
                } else {
                    prefix_fast_forward = None;
                    known_span_start_proof = None;
                    None
                }
            } else {
                None
            };
            break (candidate, ordinary, installed, Some(adaptive_guard));
        }

        let ordinary = if let Some(plan) = ordinary_prefix_predicate_plan {
            let auxiliary_bytes = usize::from(plan.bitmap_count())
                .checked_mul(core::mem::size_of::<[u64; 4]>())
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context prefix auxiliary bytes",
                ))?;
            if candidate
                .data
                .len()
                .checked_add(auxiliary_bytes)
                .is_some_and(|total| total <= MAX_CONTEXT_NATIVE_DATA_BYTES)
                && candidate.data.try_reserve_exact(auxiliary_bytes).is_ok()
            {
                append_native_prefix_filter(
                    &mut candidate.data,
                    plan,
                    view.anchored_prefix.sets().len(),
                )?
            } else {
                prefix_fast_forward = None;
                known_span_start_proof = None;
                None
            }
        } else {
            None
        };
        break (candidate, ordinary, None, None);
    };
    let known_span_start = known_span_start_proof
        .map(|proof| install_context_known_span_start(&mut layout, proof, target.architecture))
        .transpose()?
        .flatten();
    let ordinary_boundary_pair = match (boundary_pair_relation.as_ref(), start_filter) {
        (Some(relation), Some(primary)) => {
            lower_context_boundary_pair_expression(relation, primary, vector_filter, target)?
        }
        _ => None,
    };
    let anchored_boundary_pair = match (boundary_pair_relation.as_ref(), anchored_forward_search) {
        (Some(relation), Some(search)) => lower_context_boundary_pair_expression(
            relation,
            search.primary,
            search.vector_filter,
            target,
        )?,
        _ => None,
    };
    let state_skip = install_context_state_skip(&mut layout, state_skip_plan)?;
    let has_vector_prepass = start_filter.is_some_and(|filter| !filter.ranges().is_empty())
        || interior_guard.is_some_and(|guard| !guard.primary.ranges().is_empty())
        || anchored_forward_search.is_some_and(|search| !search.primary.ranges().is_empty())
        || terminal_suffix_search.is_some();
    let asimd_lane_index_offset =
        install_context_asimd_lane_index(&mut layout, target, has_vector_prepass)?;
    let sve2_match_tables = ContextSve2MatchTables {
        interior: install_context_sve2_match_table(
            &mut layout,
            target,
            interior_guard
                .filter(|guard| guard.vector_filter.is_none())
                .map(|guard| guard.primary),
        )?,
        anchored: install_context_sve2_match_table(
            &mut layout,
            target,
            anchored_forward_search
                .filter(|search| search.vector_filter.is_none() && anchored_boundary_pair.is_none())
                .map(|search| search.primary),
        )?,
        ordinary: install_context_sve2_match_table(
            &mut layout,
            target,
            start_filter.filter(|_| vector_filter.is_none() && ordinary_boundary_pair.is_none()),
        )?,
    };
    let (code, relocations) = match target.architecture {
        Architecture::X86_64 => lower_x86_64_context(
            &layout,
            terminal_suffix_search,
            anchored_forward_search,
            anchored_adaptive_guard,
            anchored_prefix_filter,
            anchored_boundary_pair,
            start_filter,
            vector_filter,
            ordinary_boundary_pair,
            prefix_filter,
            prefix_fast_forward,
            known_span_start,
            interior_guard,
            state_skip,
            empty_prefix_restart,
            target.features,
        )?,
        Architecture::Aarch64 => lower_aarch64_context(
            &layout,
            terminal_suffix_search,
            anchored_forward_search,
            anchored_adaptive_guard,
            anchored_prefix_filter,
            anchored_boundary_pair,
            start_filter,
            vector_filter,
            ordinary_boundary_pair,
            prefix_filter,
            prefix_fast_forward,
            known_span_start,
            interior_guard,
            state_skip,
            empty_prefix_restart,
            target.features,
            target.operating_system,
            asimd_lane_index_offset,
            sve2_match_tables,
        )?,
    };
    let start_accelerator = selected_context_start_accelerator(
        target,
        terminal_suffix_search,
        anchored_forward_search,
        anchored_boundary_pair,
        start_filter,
        vector_filter,
        ordinary_boundary_pair,
        interior_guard,
        sve2_match_tables,
    );
    Ok(NativeLowering {
        code,
        data: layout.data,
        relocations,
        needs_runtime: false,
        start_accelerator,
        anchored_prefix_filter_bytes: anchored_forward_search.map_or_else(
            || {
                start_filter
                    .map(|_| u8::try_from(view.anchored_prefix.sets().len()))
                    .transpose()
                    .map_err(|_| ObjectError::ArithmeticOverflow("context anchored-prefix bytes"))
                    .map(|bytes| bytes.unwrap_or(0))
            },
            |search| Ok(search.guarded_bytes),
        )?,
    })
}

fn x86_disp32(offset: u32) -> [u8; 4] {
    offset.to_le_bytes()
}

fn x86_emit_data_byte_at_rax(assembler: &mut X86Assembler, offset: u32) -> Result<(), ObjectError> {
    // movzx eax, byte ptr [r9 + rax + offset]
    let mut instruction = vec![0x41, 0x0f, 0xb6, 0x84, 0x01];
    instruction.extend_from_slice(&x86_disp32(offset));
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_data_halfword_at_rax(
    assembler: &mut X86Assembler,
    offset: u32,
) -> Result<(), ObjectError> {
    // movzx eax, word ptr [r9 + rax*2 + offset]
    let mut instruction = vec![0x41, 0x0f, 0xb7, 0x84, 0x41];
    instruction.extend_from_slice(&x86_disp32(offset));
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_class_at_position(
    assembler: &mut X86Assembler,
    classes_offset: u32,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?; // eax = hay[position]
    x86_emit_data_byte_at_rax(assembler, classes_offset)
}

fn x86_emit_class_before_position(
    assembler: &mut X86Assembler,
    classes_offset: u32,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x0f, 0xb6, 0x44, 0x17, 0xff])?; // hay[position - 1]
    x86_emit_data_byte_at_rax(assembler, classes_offset)
}

fn x86_emit_property_before_position(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    x86_emit_class_before_position(assembler, layout.byte_classes_offset)?;
    x86_emit_data_byte_at_rax(assembler, layout.class_properties_offset)
}

fn x86_emit_property_at_position(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    x86_emit_class_at_position(assembler, layout.byte_classes_offset)?;
    x86_emit_data_byte_at_rax(assembler, layout.class_properties_offset)
}

fn x86_emit_test_valid(assembler: &mut X86Assembler, invalid: usize) -> Result<(), ObjectError> {
    assembler.instruction(&[0xa9, 0x00, 0x00, 0x00, 0x40])?; // test eax, valid
    assembler.branch(&[0x0f, 0x84], invalid)?; // jz
    Ok(())
}

fn x86_emit_decode_forward_state_checked(
    assembler: &mut X86Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    let mut payload = vec![0x25];
    payload.extend_from_slice(&CONTEXT_CELL_STATE_MASK.to_le_bytes());
    assembler.instruction(&payload)?;
    assembler.branch(&[0x0f, 0x84], invalid)?;
    assembler.instruction(&[0xff, 0xc8])?; // state = payload - 1
    assembler.instruction(&[0x41, 0x89, 0xc2])?; // r10d = state
    Ok(())
}

fn x86_emit_populated_transition_valid_mode(
    assembler: &mut X86Assembler,
    invalid: usize,
    trust: bool,
) -> Result<(), ObjectError> {
    if trust {
        Ok(())
    } else {
        x86_emit_test_valid(assembler, invalid)
    }
}

fn x86_emit_decode_populated_forward_transition_mode(
    assembler: &mut X86Assembler,
    invalid: usize,
    trust: bool,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x41, 0x89, 0xc3])?; // preserve event bit
    let mut payload = vec![0x25];
    payload.extend_from_slice(&CONTEXT_FORWARD_CELL_STATE_MASK.to_le_bytes());
    assembler.instruction(&payload)?;
    if !trust {
        assembler.instruction(&[0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x84], invalid)?;
    }
    assembler.instruction(&[0xff, 0xc8])?; // state = payload - 1
    assembler.instruction(&[0x41, 0x89, 0xc2])?; // r10d = state
    assembler.instruction(&[0x44, 0x89, 0xd8])?; // packed cell
    assembler.instruction(&[0xc1, 0xe8, CONTEXT_FORWARD_CELL_FLAGS_SHIFT])?;
    Ok(())
}

fn x86_emit_indexed_byte_at_r10(
    assembler: &mut X86Assembler,
    offset: u32,
) -> Result<(), ObjectError> {
    // movzx eax, byte ptr [r9 + r10 + offset]
    let mut instruction = vec![0x43, 0x0f, 0xb6, 0x84, 0x11];
    instruction.extend_from_slice(&x86_disp32(offset));
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_forward_flags(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    x86_emit_indexed_byte_at_r10(assembler, layout.forward_state_flags_offset)
}

fn x86_emit_anchored_forward_flags(
    assembler: &mut X86Assembler,
    anchored: ContextAnchoredForwardLayout,
) -> Result<(), ObjectError> {
    x86_emit_indexed_byte_at_r10(assembler, anchored.state_flags_offset)
}

fn x86_emit_anchored_initial_map(
    assembler: &mut X86Assembler,
    anchored: ContextAnchoredForwardLayout,
    invalid: usize,
) -> Result<(), ObjectError> {
    // The complete initial dispatch left its zero-based state in r10d.
    // Translate it through the checked sidecar map.
    let mut load = vec![0x43, 0x8b, 0x84, 0x91];
    load.extend_from_slice(&anchored.main_initial_to_anchored_offset.to_le_bytes());
    assembler.instruction(&load)?;
    assembler.instruction(&[0x83, 0xf8, 0xff])?; // cmp eax, -1
    assembler.branch(&[0x0f, 0x84], invalid)?;
    let mut bound = vec![0x3d]; // cmp eax, states
    bound.extend_from_slice(&anchored.states.to_le_bytes());
    assembler.instruction(&bound)?;
    assembler.branch(&[0x0f, 0x83], invalid)?;
    assembler.instruction(&[0x41, 0x89, 0xc2])?;
    x86_emit_anchored_forward_flags(assembler, anchored)
}

fn x86_emit_decode_raw_forward_state(
    assembler: &mut X86Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x41, 0x89, 0xc2])?; // r10d = packed raw cell
    assembler.instruction(&[
        0x41,
        0x81,
        0xe2,
        u8::try_from(CONTEXT_RAW_FORWARD_STATE_MASK & 0xff).unwrap(),
        u8::try_from(CONTEXT_RAW_FORWARD_STATE_MASK >> 8).unwrap(),
        0x00,
        0x00,
    ])?;
    assembler.branch(&[0x0f, 0x84], invalid)?;
    assembler.instruction(&[0x41, 0xff, 0xca])?; // state = payload - 1
    Ok(())
}

fn x86_emit_test_raw_forward_valid(
    assembler: &mut X86Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    let valid = u32::from(CONTEXT_RAW_FORWARD_VALID).to_le_bytes();
    let mut instruction = vec![0xa9];
    instruction.extend_from_slice(&valid);
    assembler.instruction(&instruction)?;
    assembler.branch(&[0x0f, 0x84], invalid)?;
    Ok(())
}

fn x86_emit_test_raw_reverse_valid(
    assembler: &mut X86Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    let valid = u32::from(CONTEXT_RAW_REVERSE_VALID).to_le_bytes();
    let mut instruction = vec![0xa9];
    instruction.extend_from_slice(&valid);
    assembler.instruction(&instruction)?;
    assembler.branch(&[0x0f, 0x84], invalid)?;
    Ok(())
}

fn x86_emit_raw_forward_initial(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
    raw: ContextRawPairInitialLayout,
    invalid: usize,
) -> Result<(), ObjectError> {
    let absolute_start = assembler.label()?;
    let empty_haystack = assembler.label()?;
    let absolute_end = assembler.label()?;
    let loaded = assembler.label()?;

    assembler.instruction(&[0x48, 0x85, 0xd2])?; // position == 0
    assembler.branch(&[0x0f, 0x84], absolute_start)?;
    assembler.instruction(&[0x48, 0x39, 0xf2])?; // position == haystack length
    assembler.branch(&[0x0f, 0x84], absolute_end)?;
    // All supported x86-64 targets are little-endian: previous | current<<8.
    assembler.instruction(&[0x0f, 0xb7, 0x44, 0x17, 0xff])?;
    x86_emit_data_halfword_at_rax(assembler, layout.forward_initial_offset)?;
    assembler.branch(&[0xe9], loaded)?;

    assembler.bind(absolute_start)?;
    assembler.instruction(&[0x48, 0x85, 0xf6])?;
    assembler.branch(&[0x0f, 0x84], empty_haystack)?;
    assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?;
    x86_emit_data_halfword_at_rax(assembler, raw.forward_start_offset)?;
    assembler.branch(&[0xe9], loaded)?;
    assembler.bind(empty_haystack)?;
    assembler.instruction(&[0xb8, 0x00, 0x01, 0x00, 0x00])?; // sentinel index 256
    x86_emit_data_halfword_at_rax(assembler, raw.forward_start_offset)?;
    assembler.branch(&[0xe9], loaded)?;

    assembler.bind(absolute_end)?;
    assembler.instruction(&[0x0f, 0xb6, 0x44, 0x17, 0xff])?;
    x86_emit_data_halfword_at_rax(assembler, raw.forward_end_offset)?;
    assembler.bind(loaded)?;
    x86_emit_test_raw_forward_valid(assembler, invalid)?;
    x86_emit_decode_raw_forward_state(assembler, invalid)?;
    x86_emit_forward_flags(assembler, layout)?;
    Ok(())
}

fn x86_emit_decode_raw_reverse_payload(assembler: &mut X86Assembler) -> Result<(), ObjectError> {
    let mask = u32::from(CONTEXT_RAW_REVERSE_STATE_MASK).to_le_bytes();
    let mut instruction = vec![0x25]; // and eax, payload mask
    instruction.extend_from_slice(&mask);
    assembler.instruction(&instruction)?;
    assembler.instruction(&[0x41, 0x89, 0xc2])?; // r10d = state+1, possibly zero
    Ok(())
}

/// Load one raw reverse initial cell for a full-haystack boundary.
///
/// The cursor is in rdx and the complete haystack length is in rsi. The
/// packed cell remains in eax so callers can consume `reaches_start` before
/// decoding the low payload into r10d.
fn x86_emit_raw_reverse_initial(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
    raw: ContextRawPairReverseInitialLayout,
    invalid: usize,
) -> Result<(), ObjectError> {
    let reverse_pairs = layout
        .reverse_initial_offset
        .ok_or(ObjectError::InvalidModule(
            "context raw reverse dispatch has no pair table",
        ))?;
    let absolute_start = assembler.label()?;
    let empty_haystack = assembler.label()?;
    let absolute_end = assembler.label()?;
    let loaded = assembler.label()?;

    assembler.instruction(&[0x48, 0x85, 0xd2])?;
    assembler.branch(&[0x0f, 0x84], absolute_start)?;
    assembler.instruction(&[0x48, 0x39, 0xf2])?;
    assembler.branch(&[0x0f, 0x84], absolute_end)?;
    assembler.instruction(&[0x0f, 0xb7, 0x44, 0x17, 0xff])?;
    x86_emit_data_halfword_at_rax(assembler, reverse_pairs)?;
    assembler.branch(&[0xe9], loaded)?;

    assembler.bind(absolute_start)?;
    assembler.instruction(&[0x48, 0x85, 0xf6])?;
    assembler.branch(&[0x0f, 0x84], empty_haystack)?;
    assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?;
    x86_emit_data_halfword_at_rax(assembler, raw.reverse_start_offset)?;
    assembler.branch(&[0xe9], loaded)?;
    assembler.bind(empty_haystack)?;
    assembler.instruction(&[0xb8, 0x00, 0x01, 0x00, 0x00])?;
    x86_emit_data_halfword_at_rax(assembler, raw.reverse_start_offset)?;
    assembler.branch(&[0xe9], loaded)?;

    assembler.bind(absolute_end)?;
    assembler.instruction(&[0x0f, 0xb6, 0x44, 0x17, 0xff])?;
    x86_emit_data_halfword_at_rax(assembler, raw.reverse_end_offset)?;
    assembler.bind(loaded)?;
    x86_emit_test_raw_reverse_valid(assembler, invalid)
}

/// Raw reverse lookup for x86 ordered-output suffix verification.
///
/// rsi holds the suffix base in this CFG, so the sign tag in result[0]
/// distinguishes an absolute window end from an interior one. The original
/// semantic-key lowering used the same tag to decide current-byte presence.
fn x86_emit_raw_ordered_suffix_reverse_initial(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
    raw: ContextRawPairReverseInitialLayout,
    invalid: usize,
) -> Result<(), ObjectError> {
    let reverse_pairs = layout
        .reverse_initial_offset
        .ok_or(ObjectError::InvalidModule(
            "context raw reverse dispatch has no pair table",
        ))?;
    let absolute_start = assembler.label()?;
    let start_current = assembler.label()?;
    let start_empty = assembler.label()?;
    let absolute_end = assembler.label()?;
    let interior = assembler.label()?;
    let loaded = assembler.label()?;

    assembler.instruction(&[0x48, 0x85, 0xd2])?;
    assembler.branch(&[0x0f, 0x84], absolute_start)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?; // cursor vs window end
    assembler.branch(&[0x0f, 0x85], interior)?;
    assembler.instruction(&[0x49, 0x8b, 0x00])?; // tagged original start
    assembler.instruction(&[0x48, 0x85, 0xc0])?;
    assembler.branch(&[0x0f, 0x88], absolute_end)?;
    assembler.bind(interior)?;
    assembler.instruction(&[0x0f, 0xb7, 0x44, 0x17, 0xff])?;
    x86_emit_data_halfword_at_rax(assembler, reverse_pairs)?;
    assembler.branch(&[0xe9], loaded)?;

    assembler.bind(absolute_start)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x85], start_current)?;
    assembler.instruction(&[0x49, 0x8b, 0x00])?;
    assembler.instruction(&[0x48, 0x85, 0xc0])?;
    assembler.branch(&[0x0f, 0x88], start_empty)?;
    assembler.bind(start_current)?;
    assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?;
    x86_emit_data_halfword_at_rax(assembler, raw.reverse_start_offset)?;
    assembler.branch(&[0xe9], loaded)?;
    assembler.bind(start_empty)?;
    assembler.instruction(&[0xb8, 0x00, 0x01, 0x00, 0x00])?;
    x86_emit_data_halfword_at_rax(assembler, raw.reverse_start_offset)?;
    assembler.branch(&[0xe9], loaded)?;

    assembler.bind(absolute_end)?;
    assembler.instruction(&[0x0f, 0xb6, 0x44, 0x17, 0xff])?;
    x86_emit_data_halfword_at_rax(assembler, raw.reverse_end_offset)?;
    assembler.bind(loaded)?;
    x86_emit_test_raw_reverse_valid(assembler, invalid)
}

fn x86_emit_context_cell(
    assembler: &mut X86Assembler,
    table_offset: u32,
    row_width: u16,
    symbol_in_r11d: bool,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x44, 0x89, 0xd0])?; // eax = state
    if row_width <= 0x7f {
        assembler.instruction(&[0x6b, 0xc0, u8::try_from(row_width).unwrap()])?;
    } else {
        let mut instruction = vec![0x69, 0xc0];
        instruction.extend_from_slice(&u32::from(row_width).to_le_bytes());
        assembler.instruction(&instruction)?;
    }
    if symbol_in_r11d {
        assembler.instruction(&[0x44, 0x01, 0xd8])?; // eax += r11d
    }
    // mov eax, dword ptr [r9 + rax*4 + table_offset]
    let mut instruction = vec![0x41, 0x8b, 0x84, 0x81];
    instruction.extend_from_slice(&x86_disp32(table_offset));
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_reverse_context_cell(
    assembler: &mut X86Assembler,
    table_offset: u32,
    row_width: u16,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x41, 0x8d, 0x42, 0xff])?; // eax = payload - 1
    if row_width <= 0x7f {
        assembler.instruction(&[0x6b, 0xc0, u8::try_from(row_width).unwrap()])?;
    } else {
        let mut multiply = vec![0x69, 0xc0];
        multiply.extend_from_slice(&u32::from(row_width).to_le_bytes());
        assembler.instruction(&multiply)?;
    }
    assembler.instruction(&[0x44, 0x01, 0xd8])?;
    let mut load = vec![0x41, 0x8b, 0x84, 0x81];
    load.extend_from_slice(&table_offset.to_le_bytes());
    assembler.instruction(&load)?;
    Ok(())
}

fn x86_emit_direct_byte_context_cell(
    assembler: &mut X86Assembler,
    table_offset: u32,
) -> Result<(), ObjectError> {
    // eax is the raw byte. The old state dies at this transition, so scale
    // r10d destructively and let the ordinary decoder install its successor.
    assembler.instruction(&[0x41, 0xc1, 0xe2, 0x08])?;
    assembler.instruction(&[0x44, 0x01, 0xd0])?;
    let mut load = vec![0x41, 0x8b, 0x84, 0x81];
    load.extend_from_slice(&table_offset.to_le_bytes());
    assembler.instruction(&load)?;
    Ok(())
}

fn x86_emit_direct_sentinel_context_cell(
    assembler: &mut X86Assembler,
    table_offset: u32,
) -> Result<(), ObjectError> {
    let mut load = vec![0x43, 0x8b, 0x84, 0x91];
    load.extend_from_slice(&table_offset.to_le_bytes());
    assembler.instruction(&load)?;
    Ok(())
}

/// Load the forward cell for the byte at the already-advanced cursor.
///
/// `DirectByte` rows consume the raw byte in r11d and keep the absolute-end
/// cell in a separate state-indexed table. Narrow rows retain the semantic
/// class lookup and multiply used by the legacy layout.
fn x86_emit_forward_transition_cell_at(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
    cells_offset: u32,
    byte_sentinel_offset: Option<u32>,
) -> Result<(), ObjectError> {
    let sentinel = assembler.label()?;
    let ready = assembler.label()?;
    assembler.instruction(&[0x48, 0x39, 0xf2])?; // cursor vs haystack length
    assembler.branch(&[0x0f, 0x84], sentinel)?;
    if let Some(sentinel_offset) = byte_sentinel_offset {
        assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?; // raw byte
        x86_emit_direct_byte_context_cell(assembler, cells_offset)?;
        assembler.branch(&[0xe9], ready)?;
        assembler.bind(sentinel)?;
        x86_emit_direct_sentinel_context_cell(assembler, sentinel_offset)?;
    } else {
        x86_emit_class_at_position(assembler, layout.byte_classes_offset)?;
        assembler.instruction(&[0x41, 0x89, 0xc3])?;
        x86_emit_context_cell(assembler, cells_offset, layout.row_width, true)?;
        assembler.branch(&[0xe9], ready)?;
        assembler.bind(sentinel)?;
        assembler.instruction(&[0x41, 0xbb])?;
        push_bytes(
            &mut assembler.code,
            &u32::from(layout.class_count).to_le_bytes(),
        )?;
        x86_emit_context_cell(assembler, cells_offset, layout.row_width, true)?;
    }
    assembler.bind(ready)?;
    Ok(())
}

fn x86_emit_forward_transition_cell(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    x86_emit_forward_transition_cell_at(
        assembler,
        layout,
        layout.forward_cells_offset,
        layout.forward_byte_sentinel_offset,
    )
}

fn x86_emit_anchored_forward_transition_cell(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
    anchored: ContextAnchoredForwardLayout,
) -> Result<(), ObjectError> {
    x86_emit_forward_transition_cell_at(
        assembler,
        layout,
        anchored.cells_offset,
        anchored.byte_sentinel_offset,
    )
}

/// Load the reverse cell for the byte before the already-retreated cursor.
fn x86_emit_reverse_transition_cell(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    let reverse_cells = layout
        .reverse_cells_offset
        .ok_or(ObjectError::InvalidModule(
            "context reverse transition has no rows",
        ))?;
    let sentinel = assembler.label()?;
    let ready = assembler.label()?;
    if layout.reverse_byte_sentinel_offset.is_some() {
        assembler.instruction(&[0x41, 0xff, 0xca])?; // payload to zero-based state
    }
    assembler.instruction(&[0x48, 0x85, 0xd2])?;
    assembler.branch(&[0x0f, 0x84], sentinel)?;
    if let Some(sentinel_offset) = layout.reverse_byte_sentinel_offset {
        assembler.instruction(&[0x0f, 0xb6, 0x44, 0x17, 0xff])?; // raw byte
        x86_emit_direct_byte_context_cell(assembler, reverse_cells)?;
        assembler.branch(&[0xe9], ready)?;
        assembler.bind(sentinel)?;
        x86_emit_direct_sentinel_context_cell(assembler, sentinel_offset)?;
    } else {
        x86_emit_class_before_position(assembler, layout.byte_classes_offset)?;
        assembler.instruction(&[0x41, 0x89, 0xc3])?;
        x86_emit_reverse_context_cell(assembler, reverse_cells, layout.row_width)?;
        assembler.branch(&[0xe9], ready)?;
        assembler.bind(sentinel)?;
        assembler.instruction(&[0x41, 0xbb])?;
        push_bytes(
            &mut assembler.code,
            &u32::from(layout.class_count).to_le_bytes(),
        )?;
        x86_emit_reverse_context_cell(assembler, reverse_cells, layout.row_width)?;
    }
    assembler.bind(ready)?;
    Ok(())
}

fn x86_emit_dispatch_cell(
    assembler: &mut X86Assembler,
    table_offset: u32,
) -> Result<(), ObjectError> {
    // mov eax, dword ptr [r9 + rax*4 + table_offset]
    let mut instruction = vec![0x41, 0x8b, 0x84, 0x81];
    instruction.extend_from_slice(&x86_disp32(table_offset));
    assembler.instruction(&instruction)?;
    Ok(())
}

fn x86_emit_clear_result(assembler: &mut X86Assembler) -> Result<(), ObjectError> {
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;
    Ok(())
}

fn x86_emit_prepass_restart(
    assembler: &mut X86Assembler,
    restart: ContextPrepassRestart,
) -> Result<(), ObjectError> {
    match restart {
        ContextPrepassRestart::CandidateBase | ContextPrepassRestart::Bounded(0) => {
            assembler.instruction(&[0x49, 0x89, 0x10])?;
        }
        ContextPrepassRestart::OriginalStart => {
            assembler.instruction(&[0x49, 0x8b, 0x10])?;
        }
        ContextPrepassRestart::Bounded(maximum) => {
            let keep_original = assembler.label()?;
            let selected = assembler.label()?;
            assembler.instruction(&[0x49, 0x8b, 0x00])?; // original start
            let mut load = vec![0x41, 0xbb]; // r11d = maximum
            load.extend_from_slice(&maximum.to_le_bytes());
            assembler.instruction(&load)?;
            assembler.instruction(&[0x4c, 0x39, 0xda])?; // candidate vs maximum
            assembler.branch(&[0x0f, 0x86], keep_original)?;
            assembler.instruction(&[0x4c, 0x29, 0xda])?;
            assembler.instruction(&[0x48, 0x39, 0xc2])?; // lower bound vs original
            assembler.branch(&[0x0f, 0x83], selected)?;
            assembler.bind(keep_original)?;
            assembler.instruction(&[0x48, 0x89, 0xc2])?;
            assembler.bind(selected)?;
            assembler.instruction(&[0x49, 0x89, 0x10])?;
        }
    }
    Ok(())
}

/// Reject a literal-prefix hit when the exact initial contextual dispatch has
/// no active consuming frontier. The candidate byte cannot start a match in
/// that state, so advancing one byte and resuming the prefix scanner is the
/// same transition the ordered DFA would perform before restarting.
fn x86_emit_reject_empty_prefix_candidate(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
    rejected: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    if let Some(raw) = layout.raw_pair_initial {
        let absolute_start = assembler.label()?;
        let loaded = assembler.label()?;
        assembler.instruction(&[0x48, 0x85, 0xd2])?;
        assembler.branch(&[0x0f, 0x84], absolute_start)?;
        // Prefix candidates are real bytes. Loading at position-1 preserves
        // assertion context immediately outside an interior search window.
        assembler.instruction(&[0x0f, 0xb7, 0x44, 0x17, 0xff])?;
        x86_emit_data_halfword_at_rax(assembler, layout.forward_initial_offset)?;
        assembler.branch(&[0xe9], loaded)?;
        assembler.bind(absolute_start)?;
        assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?;
        x86_emit_data_halfword_at_rax(assembler, raw.forward_start_offset)?;
        assembler.bind(loaded)?;
        x86_emit_test_raw_forward_valid(assembler, invalid)?;
        let empty = u32::from(CONTEXT_RAW_FORWARD_EMPTY).to_le_bytes();
        let mut test_empty = vec![0xa9];
        test_empty.extend_from_slice(&empty);
        assembler.instruction(&test_empty)?;
        assembler.branch(&[0x0f, 0x85], rejected)?;
        x86_emit_decode_raw_forward_state(assembler, invalid)?;
        x86_emit_forward_flags(assembler, layout)?;
        return Ok(());
    }
    let no_before = assembler.label()?;
    let key_ready = assembler.label()?;

    // A prefix candidate is strictly before the search-window end, hence it
    // is a real current byte and cannot carry absolute-end.
    x86_emit_class_at_position(assembler, layout.byte_classes_offset)?;
    assembler.instruction(&[0x41, 0x89, 0xc3])?; // r11d = current class
    assembler.instruction(&[0x48, 0x85, 0xd2])?;
    assembler.branch(&[0x0f, 0x84], no_before)?;
    x86_emit_property_before_position(assembler, layout)?;
    assembler.instruction(&[0xc1, 0xe0, 0x09])?;
    assembler.instruction(&[0x41, 0x09, 0xc3])?;
    assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x20, 0x00, 0x00])?;
    assembler.branch(&[0xe9], key_ready)?;
    assembler.bind(no_before)?;
    assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x40, 0x00, 0x00])?;
    assembler.bind(key_ready)?;

    assembler.instruction(&[0x44, 0x89, 0xd8])?;
    x86_emit_dispatch_cell(assembler, layout.forward_initial_offset)?;
    x86_emit_test_valid(assembler, invalid)?;
    assembler.instruction(&[0x85, 0xc0])?;
    assembler.branch(&[0x0f, 0x88], invalid)?;
    x86_emit_decode_forward_state_checked(assembler, invalid)?;
    x86_emit_forward_flags(assembler, layout)?;
    assembler.instruction(&[0xa8, CONTEXT_STATE_EMPTY])?;
    assembler.branch(&[0x0f, 0x85], rejected)?;
    Ok(())
}

fn x86_emit_known_span_start_tag(
    assembler: &mut X86Assembler,
    guard: ContextKnownSpanStartGuard,
) -> Result<(), ObjectError> {
    if guard.accepts_all_bytes && guard.accepts_haystack_end {
        assembler.instruction(&[0x49, 0x0f, 0xba, 0x28, 0x3f])?; // tag result.start
        return Ok(());
    }
    let tag = assembler.label()?;
    let done = assembler.label()?;
    assembler.instruction(&[0x48, 0x8d, 0x42, guard.guarded_bytes])?; // following position
    assembler.instruction(&[0x48, 0x39, 0xf0])?; // following vs full length
    assembler.branch(
        &[0x0f, 0x84],
        if guard.accepts_haystack_end {
            tag
        } else {
            done
        },
    )?;
    assembler.branch(&[0x0f, 0x87], done)?; // defensive: following > full length
    if guard.accepts_all_bytes {
        assembler.branch(&[0xe9], tag)?;
    } else if guard.accepts_any_byte {
        let filter = guard.following_filter.ok_or(ObjectError::InvalidModule(
            "context known-start partial byte set has no filter",
        ))?;
        for &predicate in filter.predicates() {
            x86_emit_prefix_predicate(assembler, predicate, done)?;
        }
        assembler.branch(&[0xe9], tag)?;
    } else {
        assembler.branch(&[0xe9], done)?;
    }
    assembler.bind(tag)?;
    assembler.instruction(&[0x49, 0x0f, 0xba, 0x28, 0x3f])?; // tag result.start
    assembler.bind(done)?;
    Ok(())
}

fn x86_emit_anchored_position_charge(
    assembler: &mut X86Assembler,
    guard: ContextAnchoredAdaptiveGuard,
    debt: u16,
    fallback: usize,
) -> Result<(), ObjectError> {
    // r12 is fixed-point debt and rdx is the current semantic candidate.
    let mut charge = vec![0x49, 0x81, 0xc4]; // add r12, fixed-point work
    charge.extend_from_slice(&u32::from(debt).to_le_bytes());
    assembler.instruction(&charge)?;
    let mut allowance = vec![0x4c, 0x8d, 0x9a]; // lea r11, [rdx + initial_credit]
    allowance.extend_from_slice(&u32::from(guard.initial_credit).to_le_bytes());
    assembler.instruction(&allowance)?;
    assembler.instruction(&[0x4d, 0x39, 0xdc])?; // debt vs allowance
    let admitted = assembler.label()?;
    assembler.branch(&[0x0f, 0x86], admitted)?;
    // This primary/vector hit is the earliest candidate not yet processed by
    // the sidecar. Publish it before the common one-shot main-DFA fallback.
    assembler.instruction(&[0x49, 0x89, 0x10])?;
    assembler.branch(&[0xe9], fallback)?;
    assembler.bind(admitted)?;
    Ok(())
}

fn x86_emit_anchored_candidate_charge(
    assembler: &mut X86Assembler,
    guard: ContextAnchoredAdaptiveGuard,
    fallback: usize,
) -> Result<(), ObjectError> {
    x86_emit_anchored_position_charge(assembler, guard, guard.candidate_debt, fallback)
}

fn x86_emit_anchored_transition_reserve(
    assembler: &mut X86Assembler,
    search: ContextAnchoredForwardSearch,
    guard: ContextAnchoredAdaptiveGuard,
    fallback: usize,
) -> Result<(), ObjectError> {
    let shift = context_anchored_transition_shift(guard)?;
    let _maximum_reserve = context_anchored_transition_reserve(search, guard)?;

    // The candidate charge immediately before exact prefix verification proved
    // debt <= candidate + initial_credit. Convert that headroom to affordable
    // whole transitions and clamp it to this verifier's structural maximum.
    let mut allowance = vec![0x4c, 0x8d, 0x9a]; // lea r11, [rdx + initial_credit]
    allowance.extend_from_slice(&u32::from(guard.initial_credit).to_le_bytes());
    assembler.instruction(&allowance)?;
    assembler.instruction(&[0x4d, 0x29, 0xe3])?; // sub r11, r12: headroom
    if shift != 0 {
        assembler.instruction(&[0x49, 0xc1, 0xeb, shift])?; // affordable transitions
    }
    let mut cap = vec![0x41, 0xbd]; // mov r13d, max_verify_bytes
    cap.extend_from_slice(&u32::from(search.max_verify_bytes).to_le_bytes());
    assembler.instruction(&cap)?;
    assembler.instruction(&[0x4d, 0x39, 0xeb])?; // affordable vs maximum
    assembler.instruction(&[0x4d, 0x0f, 0x42, 0xeb])?; // cap = min(affordable, maximum)
    assembler.instruction(&[0x45, 0x85, 0xed])?;
    assembler.branch(&[0x0f, 0x84], fallback)?;
    assembler.instruction(&[0x4d, 0x89, 0xeb])?; // r11 = reserved transitions
    if shift != 0 {
        assembler.instruction(&[0x49, 0xc1, 0xe3, shift])?; // fixed-point reserve
    }
    assembler.instruction(&[0x4d, 0x01, 0xdc])?; // debt += reserve
    Ok(())
}

fn x86_emit_anchored_transition_refund(
    assembler: &mut X86Assembler,
    guard: ContextAnchoredAdaptiveGuard,
) -> Result<(), ObjectError> {
    // Rejection ends this attempt, so r13 can become the fixed-point refund in
    // place. The next admitted attempt reconstructs its transition cap.
    let shift = context_anchored_transition_shift(guard)?;
    if shift != 0 {
        assembler.instruction(&[0x49, 0xc1, 0xe5, shift])?; // cap *= transition_debt
    }
    assembler.instruction(&[0x4d, 0x29, 0xec])?; // debt -= unused reserve
    Ok(())
}

fn x86_emit_context_scanner_constants(
    assembler: &mut X86Assembler,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    let mut first_register = 1_u8;
    for filter in context_scanner_constant_filters(primary, vector_filter) {
        x86_emit_start_filter_constants(assembler, filter, kind, first_register)?;
        first_register =
            first_register
                .checked_add(u8::try_from(filter.constant_count()).map_err(|_| {
                    ObjectError::ArithmeticOverflow("x86 context scanner constants")
                })?)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 context scanner constants",
                ))?;
    }
    Ok(())
}

fn x86_emit_context_pair_expression_constants(
    assembler: &mut X86Assembler,
    expression: ContextBoundaryPairExpression,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    let mut emitted = [false; 9];
    for rectangle in expression.plan.rectangles() {
        for predicate in [rectangle.first, rectangle.second] {
            if predicate.any
                || (!expression.transient_constants
                    && predicate.first_constant <= expression.scanner_constant_count)
            {
                continue;
            }
            let first = usize::from(predicate.first_constant);
            let marker = emitted.get_mut(first).ok_or(ObjectError::InvalidModule(
                "x86 context pair constant escaped its budget",
            ))?;
            if *marker {
                continue;
            }
            x86_emit_start_filter_constants(
                assembler,
                predicate.filter,
                kind,
                predicate.first_constant,
            )?;
            *marker = true;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct X86PrefixRefinementStub {
    hit: usize,
    resume: usize,
    needs_secondary: bool,
}

fn x86_emit_prefix_vector_dispatch(
    assembler: &mut X86Assembler,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    kind: X86StartFilterKind,
    anchored_guard: Option<(ContextAnchoredAdaptiveGuard, usize)>,
    boundary_pair: Option<ContextBoundaryPairExpression>,
    vector_hit: usize,
) -> Result<Option<X86PrefixRefinementStub>, ObjectError> {
    if let Some(filter) = vector_filter {
        if anchored_guard.is_some() {
            // Besides producing the vector comparison, the full test
            // materializes SSE2/AVX2 candidates in eax (AVX-512 candidates
            // already live in an opmask). The outlined refinement stub must
            // preserve that exact mask until it intersects later columns.
            let _mask = x86_emit_start_filter_vector_test(assembler, primary, kind)?;
            let hit = assembler.label()?;
            let resume = assembler.label()?;
            // Primary misses are the hot fallthrough. The rare outlined stub
            // accounts for and computes secondary-column intersections while
            // the exact primary mask remains live.
            assembler.branch(&[0x0f, 0x85], hit)?;
            assembler.bind(resume)?;
            Ok(Some(X86PrefixRefinementStub {
                hit,
                resume,
                needs_secondary: true,
            }))
        } else {
            x86_emit_start_filter_vector_candidates(assembler, primary, kind, 1)?;
            x86_emit_vector_filter_secondary_test(assembler, filter, kind)?;
            if boundary_pair.is_some() {
                let hit = assembler.label()?;
                let resume = assembler.label()?;
                assembler.branch(&[0x0f, 0x85], hit)?;
                assembler.bind(resume)?;
                Ok(Some(X86PrefixRefinementStub {
                    hit,
                    resume,
                    needs_secondary: false,
                }))
            } else {
                assembler.branch(&[0x0f, 0x85], vector_hit)?;
                Ok(None)
            }
        }
    } else {
        let _mask = x86_emit_start_filter_vector_test(assembler, primary, kind)?;
        if boundary_pair.is_some() {
            let hit = assembler.label()?;
            let resume = assembler.label()?;
            assembler.branch(&[0x0f, 0x85], hit)?;
            assembler.bind(resume)?;
            Ok(Some(X86PrefixRefinementStub {
                hit,
                resume,
                needs_secondary: false,
            }))
        } else {
            assembler.branch(&[0x0f, 0x85], vector_hit)?;
            Ok(None)
        }
    }
}

fn x86_emit_boundary_pair_expression_mask(
    assembler: &mut X86Assembler,
    expression: ContextBoundaryPairExpression,
    base_mask: X86CandidateMask,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    if let Some(register) = base_mask.opmask_register() {
        assembler.instruction(&[0xc4, 0xe1, 0xfb, 0x93, 0xc0 | register])?;
        assembler.instruction(&[0x49, 0x89, 0xc3])?; // r11 = all 64 base lanes
    } else {
        assembler.instruction(&[0x41, 0x89, 0xc3])?; // r11d = base lanes
    }
    if expression.transient_constants {
        x86_emit_context_pair_expression_constants(assembler, expression, kind)?;
    }
    // Predicate offsets zero and one become previous and current after this
    // temporary semantic-base shift. Candidate accounting remains unchanged.
    assembler.instruction(&[0x48, 0xff, 0xca])?;
    let relation_mask = x86_emit_prefix_relation_vector_test(assembler, expression.plan, kind)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    match kind {
        X86StartFilterKind::Sse2 | X86StartFilterKind::Avx2 => {
            if relation_mask != X86CandidateMask::MovemaskEax {
                return Err(ObjectError::InvalidModule(
                    "x86 context pair expression returned a non-movemask",
                ));
            }
            assembler.instruction(&[0x44, 0x21, 0xd8])?;
            assembler.instruction(&[0x85, 0xc0])?;
        }
        X86StartFilterKind::Avx512Bw => {
            let register = relation_mask
                .opmask_register()
                .ok_or(ObjectError::InvalidModule(
                    "AVX-512 context pair expression has no opmask",
                ))?;
            assembler.instruction(&[0xc4, 0xe1, 0xfb, 0x93, 0xc0 | register])?;
            assembler.instruction(&[0x4c, 0x21, 0xd8])?;
            assembler.instruction(&[0x48, 0x85, 0xc0])?;
        }
    }
    Ok(())
}

fn x86_restore_scanner_constants_preserving_pair_mask(
    assembler: &mut X86Assembler,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    kind: X86StartFilterKind,
) -> Result<(), ObjectError> {
    match kind {
        X86StartFilterKind::Sse2 | X86StartFilterKind::Avx2 => {
            assembler.instruction(&[0x41, 0x89, 0xc3])?; // r11d = final lane mask
        }
        X86StartFilterKind::Avx512Bw => {
            assembler.instruction(&[0x49, 0x89, 0xc3])?; // r11 = all 64 final lanes
        }
    }
    x86_emit_context_scanner_constants(assembler, primary, vector_filter, kind)?;
    match kind {
        X86StartFilterKind::Sse2 | X86StartFilterKind::Avx2 => {
            assembler.instruction(&[0x44, 0x89, 0xd8])?; // eax = final lane mask
            assembler.instruction(&[0x85, 0xc0])?;
        }
        X86StartFilterKind::Avx512Bw => {
            assembler.instruction(&[0x4c, 0x89, 0xd8])?; // rax = all 64 final lanes
            assembler.instruction(&[0x48, 0x85, 0xc0])?;
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the emitter receives explicit filters, CFG labels, and restart policy"
)]
fn x86_emit_scalar_prefix_prepass(
    assembler: &mut X86Assembler,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    prefix_filter: Option<NativePrefixFilter>,
    guarded_bytes: Option<u8>,
    known_span_start: Option<ContextKnownSpanStartGuard>,
    restart: ContextPrepassRestart,
    reject_empty_with: Option<(&ContextNativeLayout, Option<usize>)>,
    anchored_guard: Option<(ContextAnchoredAdaptiveGuard, usize)>,
    no_match: usize,
    invalid: usize,
    candidate_retry: Option<usize>,
    scalar_miss_retry: Option<usize>,
    vector_candidate: usize,
    complete: usize,
) -> Result<(), ObjectError> {
    if primary.ranges().is_empty() {
        assembler.branch(&[0xe9], no_match)?;
        return Ok(());
    }
    let scan = assembler.label()?;
    let scalar_miss = assembler.label()?;
    let candidate_rejected = assembler.label()?;
    let maximum_offset =
        vector_filter.map_or(primary.scan_offset, NativeVectorFilter::max_scan_offset);
    assembler.bind(scan)?;
    x86_emit_start_filter_scalar_bound(assembler, maximum_offset, no_match)?;
    if let Some(filter) = vector_filter {
        for &column in filter.columns() {
            x86_emit_scalar_filter_membership(assembler, column, scalar_miss)?;
        }
    } else {
        x86_emit_scalar_filter_membership(assembler, primary, scalar_miss)?;
    }
    assembler.bind(vector_candidate)?;
    if let Some((guard, fallback)) = anchored_guard {
        x86_emit_anchored_candidate_charge(assembler, guard, fallback)?;
    }
    if let Some(guarded_bytes) = guarded_bytes {
        assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
        assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= candidate
        assembler.instruction(&[0x48, 0x83, 0xf8, guarded_bytes])?;
        assembler.branch(&[0x0f, 0x82], candidate_rejected)?;
        if let Some(filter) = prefix_filter {
            for &predicate in filter.predicates() {
                x86_emit_prefix_predicate(assembler, predicate, candidate_rejected)?;
            }
        }
    }
    if let Some((layout, _)) = reject_empty_with {
        x86_emit_reject_empty_prefix_candidate(assembler, layout, candidate_rejected, invalid)?;
    }
    x86_emit_prepass_restart(assembler, restart)?;
    if let Some(guard) = known_span_start {
        x86_emit_known_span_start_tag(assembler, guard)?;
    }
    if known_span_start.is_some()
        && let Some((layout, Some(_))) = reject_empty_with
    {
        // Optional predicates use eax. Dispatch reuse enters the common
        // initial block with the exact state flags live in eax.
        x86_emit_forward_flags(assembler, layout)?;
    }
    if let Some((_, Some(initialized))) = reject_empty_with {
        assembler.branch(&[0xe9], initialized)?;
    } else {
        assembler.branch(&[0xe9], complete)?;
    }
    assembler.bind(candidate_rejected)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], candidate_retry.unwrap_or(scan))?;
    assembler.bind(scalar_miss)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar_miss_retry.unwrap_or(scan))?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the vector/scalar prepass is one register-sensitive emitted CFG"
)]
fn x86_emit_prefix_prepass(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    boundary_pair: Option<ContextBoundaryPairExpression>,
    prefix_filter: Option<NativePrefixFilter>,
    guarded_bytes: Option<u8>,
    known_span_start: Option<ContextKnownSpanStartGuard>,
    restart: ContextPrepassRestart,
    reject_empty_with: Option<(&ContextNativeLayout, Option<usize>)>,
    anchored_guard: Option<(ContextAnchoredAdaptiveGuard, usize)>,
    no_match: usize,
    invalid: usize,
    vector_entry: Option<usize>,
) -> Result<(), ObjectError> {
    if primary.ranges().is_empty() {
        assembler.branch(&[0xe9], no_match)?;
        return Ok(());
    }
    let use_batch = reject_empty_with.is_some();
    let vector = match vector_entry {
        Some(label) => label,
        None => assembler.label()?,
    };
    let single_vector = assembler.label()?;
    let short_batch_bytes = context_x86_short_batch_bytes(kind, use_batch);
    let short_batch = short_batch_bytes
        .is_some()
        .then(|| assembler.label())
        .transpose()?;
    let scalar = assembler.label()?;
    let vector_hit = assembler.label()?;
    let vector_candidate = assembler.label()?;
    let lazy_vector_filter = vector_filter;
    let mut refinement_stubs = Vec::new();
    refinement_stubs
        .try_reserve_exact(7)
        .map_err(|_| ObjectError::InvalidModule("x86 context stub allocation failed"))?;
    let complete = assembler.label()?;
    x86_emit_context_scanner_constants(assembler, primary, lazy_vector_filter, kind)?;
    if let Some(expression) = boundary_pair.filter(|pair| !pair.transient_constants) {
        x86_emit_context_pair_expression_constants(assembler, expression, kind)?;
    }
    assembler.bind(vector)?;
    if boundary_pair.is_some() {
        // The interior relation has no fabricated sentinel row. Candidate
        // zero is evaluated once by the scalar absolute-start dispatch.
        assembler.instruction(&[0x48, 0x85, 0xd2])?;
        assembler.branch(&[0x0f, 0x84], scalar)?;
    }
    assembler.instruction(&[0x48, 0x89, 0xc8])?;
    assembler.instruction(&[0x48, 0x29, 0xd0])?;
    let maximum_offset =
        vector_filter.map_or(primary.scan_offset, NativeVectorFilter::max_scan_offset);
    if use_batch {
        let unrolled_required = u32::from(kind.width())
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(u32::from(maximum_offset)))
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 context prefix unrolled bound",
            ))?;
        let mut compare = vec![0x48, 0x3d];
        compare.extend_from_slice(&unrolled_required.to_le_bytes());
        assembler.instruction(&compare)?;
        assembler.branch(&[0x0f, 0x82], short_batch.unwrap_or(single_vector))?;
        for _ in 0..4 {
            if let Some(stub) = x86_emit_prefix_vector_dispatch(
                assembler,
                primary,
                lazy_vector_filter,
                kind,
                anchored_guard,
                boundary_pair,
                vector_hit,
            )? {
                refinement_stubs.push(stub);
            }
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        }
        assembler.branch(&[0xe9], vector)?;
    }

    if let Some(short_batch) = short_batch {
        assembler.bind(short_batch)?;
        let short_required = short_batch_bytes
            .ok_or(ObjectError::InvalidModule(
                "x86 context short-batch label has no width",
            ))?
            .checked_add(u32::from(maximum_offset))
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 context prefix short-batch bound",
            ))?;
        let mut compare = vec![0x48, 0x3d];
        compare.extend_from_slice(&short_required.to_le_bytes());
        assembler.instruction(&compare)?;
        assembler.branch(&[0x0f, 0x82], single_vector)?;
        for _ in 0..2 {
            if let Some(stub) = x86_emit_prefix_vector_dispatch(
                assembler,
                primary,
                lazy_vector_filter,
                kind,
                anchored_guard,
                boundary_pair,
                vector_hit,
            )? {
                refinement_stubs.push(stub);
            }
            assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        }
        assembler.branch(&[0xe9], vector)?;
    }

    assembler.bind(single_vector)?;
    let single_required = u32::from(kind.width())
        .checked_add(u32::from(maximum_offset))
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 context prefix vector bound",
        ))?;
    let mut compare = vec![0x48, 0x3d];
    compare.extend_from_slice(&single_required.to_le_bytes());
    assembler.instruction(&compare)?;
    assembler.branch(&[0x0f, 0x82], scalar)?;
    if let Some(stub) = x86_emit_prefix_vector_dispatch(
        assembler,
        primary,
        lazy_vector_filter,
        kind,
        anchored_guard,
        boundary_pair,
        vector_hit,
    )? {
        refinement_stubs.push(stub);
    }
    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    assembler.branch(&[0xe9], vector)?;

    for stub in refinement_stubs {
        assembler.bind(stub.hit)?;
        if let Some((guard, fallback)) = anchored_guard {
            x86_emit_anchored_position_charge(assembler, guard, guard.vector_debt, fallback)?;
        }
        if stub.needs_secondary {
            let filter = lazy_vector_filter.ok_or(ObjectError::InvalidModule(
                "x86 context refinement has no secondary columns",
            ))?;
            x86_emit_vector_filter_secondary_test(assembler, filter, kind)?;
            assembler.branch(&[0x0f, 0x84], stub.resume)?;
        }
        if let Some(pair) = boundary_pair {
            let base_mask = lazy_vector_filter.map_or_else(
                || X86CandidateMask::for_filter(primary, kind),
                |_| X86CandidateMask::for_intersection(kind),
            );
            x86_emit_boundary_pair_expression_mask(assembler, pair, base_mask, kind)?;
            if pair.restore_scanner_constants {
                // A pair hit can still be rejected by exact prefix/initial or
                // sidecar verification and resume this scanner. Reconstruct
                // transiently overwritten constants before choosing either
                // edge, while retaining every AVX-512 lane in a full GPR.
                x86_restore_scanner_constants_preserving_pair_mask(
                    assembler,
                    primary,
                    lazy_vector_filter,
                    kind,
                )?;
            }
            assembler.branch(&[0x0f, 0x85], vector_hit)?;
            assembler.branch(&[0xe9], stub.resume)?;
        } else {
            assembler.branch(&[0xe9], vector_hit)?;
        }
    }

    assembler.bind(vector_hit)?;
    if boundary_pair.is_none()
        && lazy_vector_filter.is_none()
        && let Some((guard, fallback)) = anchored_guard
    {
        x86_emit_anchored_position_charge(assembler, guard, guard.vector_debt, fallback)?;
    }
    if boundary_pair.is_some() && kind == X86StartFilterKind::Avx512Bw {
        // Pair refinement leaves the complete 64-lane intersection in rax.
        assembler.instruction(&[0x48, 0x0f, 0xbc, 0xc0])?;
    } else {
        let vector_hit_mask = lazy_vector_filter.map_or_else(
            || X86CandidateMask::for_filter(primary, kind),
            |_| X86CandidateMask::for_intersection(kind),
        );
        x86_emit_first_candidate_lane(assembler, vector_hit_mask)?;
    }
    assembler.instruction(&[0x48, 0x01, 0xc2])?; // candidate += first lane
    assembler.branch(&[0xe9], vector_candidate)?;

    assembler.bind(scalar)?;
    x86_emit_scalar_prefix_prepass(
        assembler,
        primary,
        vector_filter,
        prefix_filter,
        guarded_bytes,
        known_span_start,
        restart,
        reject_empty_with,
        anchored_guard,
        no_match,
        invalid,
        Some(vector),
        boundary_pair.map(|_| vector),
        vector_candidate,
        complete,
    )?;
    assembler.bind(complete)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the reverse verifier is one register-sensitive emitted CFG"
)]
fn x86_emit_exists_suffix_reverse(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
    minimum_width: u8,
    resume: usize,
    matched: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    let reverse_initial = layout
        .reverse_initial_offset
        .ok_or(ObjectError::InvalidModule(
            "context Exists suffix has no reverse dispatch",
        ))?;
    let before_sentinel = assembler.label()?;
    let before_ready = assembler.label()?;
    let no_current = assembler.label()?;
    let not_absolute_start = assembler.label()?;
    let not_absolute_end = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let failed = assembler.label()?;

    assembler.instruction(&[0x49, 0x89, 0x50, 0x08])?; // preserve suffix base
    if minimum_width <= 0x7f {
        assembler.instruction(&[0x48, 0x83, 0xc2, minimum_width])?;
    } else {
        let mut add = vec![0x48, 0x81, 0xc2];
        add.extend_from_slice(&u32::from(minimum_width).to_le_bytes());
        assembler.instruction(&add)?;
    }

    if let Some(raw) = layout.raw_pair_reverse_initial {
        x86_emit_raw_reverse_initial(assembler, layout, raw, invalid)?;
        let event = u32::from(CONTEXT_RAW_REVERSE_EVENT).to_le_bytes();
        let mut test_event = vec![0xa9];
        test_event.extend_from_slice(&event);
        assembler.instruction(&test_event)?;
        assembler.branch(&[0x0f, 0x85], matched)?;
        x86_emit_decode_raw_reverse_payload(assembler)?;
    } else {
        // Build the exact reverse boundary key at the candidate end.
        assembler.instruction(&[0x48, 0x85, 0xd2])?;
        assembler.branch(&[0x0f, 0x84], before_sentinel)?;
        x86_emit_class_before_position(assembler, layout.byte_classes_offset)?;
        assembler.branch(&[0xe9], before_ready)?;
        assembler.bind(before_sentinel)?;
        assembler.instruction(&[0xb8])?;
        push_bytes(
            &mut assembler.code,
            &u32::from(layout.class_count).to_le_bytes(),
        )?;
        assembler.bind(before_ready)?;
        assembler.instruction(&[0x41, 0x89, 0xc3])?;
        assembler.instruction(&[0x48, 0x39, 0xf2])?;
        assembler.branch(&[0x0f, 0x84], no_current)?;
        x86_emit_property_at_position(assembler, layout)?;
        assembler.instruction(&[0xc1, 0xe0, 0x09])?;
        assembler.instruction(&[0x41, 0x09, 0xc3])?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x20, 0x00, 0x00])?;
        assembler.bind(no_current)?;
        assembler.instruction(&[0x48, 0x85, 0xd2])?;
        assembler.branch(&[0x0f, 0x85], not_absolute_start)?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x40, 0x00, 0x00])?;
        assembler.bind(not_absolute_start)?;
        assembler.instruction(&[0x48, 0x39, 0xf2])?;
        assembler.branch(&[0x0f, 0x85], not_absolute_end)?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x80, 0x00, 0x00])?;
        assembler.bind(not_absolute_end)?;
        assembler.instruction(&[0x44, 0x89, 0xd8])?;
        x86_emit_dispatch_cell(assembler, reverse_initial)?;
        x86_emit_test_valid(assembler, invalid)?;
        assembler.instruction(&[0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x88], matched)?;
        assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
        assembler.instruction(&[0x41, 0x89, 0xc2])?; // reverse payload state+1
    }

    assembler.bind(reverse_loop)?;
    assembler.instruction(&[0x4d, 0x8b, 0x18])?; // original window start
    assembler.instruction(&[0x4c, 0x39, 0xda])?;
    assembler.branch(&[0x0f, 0x86], failed)?;
    assembler.instruction(&[0x45, 0x85, 0xd2])?;
    assembler.branch(&[0x0f, 0x84], failed)?;
    assembler.instruction(&[0x48, 0xff, 0xca])?;
    x86_emit_reverse_transition_cell(assembler, layout)?;
    x86_emit_populated_transition_valid_mode(
        assembler,
        invalid,
        ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
    )?;
    assembler.instruction(&[0x41, 0x89, 0xc3])?;
    assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
    assembler.instruction(&[0x41, 0x89, 0xc2])?;
    assembler.instruction(&[0x45, 0x85, 0xdb])?;
    assembler.branch(&[0x0f, 0x88], matched)?;
    assembler.branch(&[0xe9], reverse_loop)?;

    assembler.bind(failed)?;
    assembler.instruction(&[0x49, 0x8b, 0x50, 0x08])?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], resume)?;
    Ok(())
}

fn x86_emit_ordered_suffix_update_best(
    assembler: &mut X86Assembler,
    complete: usize,
) -> Result<(), ObjectError> {
    let unchanged = assembler.label()?;
    assembler.instruction(&[0x49, 0x3b, 0x50, 0x08])?; // cmp rdx, best
    assembler.branch(&[0x0f, 0x83], unchanged)?; // candidate >= best
    assembler.instruction(&[0x49, 0x89, 0x50, 0x08])?; // best = candidate
    assembler.bind(unchanged)?;
    assembler.instruction(&[0x4d, 0x8b, 0x18])?; // tagged original start
    assembler.instruction(&[0x49, 0x0f, 0xba, 0xf3, 0x3f])?;
    assembler.instruction(&[0x4c, 0x39, 0xda])?;
    assembler.branch(&[0x0f, 0x84], complete)?; // no earlier start is possible
    Ok(())
}

/// Collect every start proved for one aligned terminal-suffix end.
///
/// The original window start is stored in result[0], with bit 63 recording
/// whether the window end is the absolute haystack end. result[1] is the
/// smallest start seen across all suffix ends. `rsi` is free after entry
/// validation and preserves the suffix base while the reverse DFA uses the
/// remaining volatile registers.
#[allow(
    clippy::too_many_lines,
    reason = "the reverse ordered-output verifier is one register-sensitive emitted CFG"
)]
fn x86_emit_ordered_suffix_reverse(
    assembler: &mut X86Assembler,
    layout: &ContextNativeLayout,
    minimum_width: u8,
    resume: usize,
    complete: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    let reverse_initial = layout
        .reverse_initial_offset
        .ok_or(ObjectError::InvalidModule(
            "context ordered suffix has no reverse dispatch",
        ))?;
    let before_sentinel = assembler.label()?;
    let before_ready = assembler.label()?;
    let has_current = assembler.label()?;
    let no_current = assembler.label()?;
    let current_ready = assembler.label()?;
    let not_absolute_start = assembler.label()?;
    let not_absolute_end = assembler.label()?;
    let no_initial_event = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let no_event = assembler.label()?;
    let finished = assembler.label()?;

    assembler.instruction(&[0x48, 0x89, 0xd6])?; // rsi = suffix base
    if minimum_width <= 0x7f {
        assembler.instruction(&[0x48, 0x83, 0xc2, minimum_width])?;
    } else {
        let mut add = vec![0x48, 0x81, 0xc2];
        add.extend_from_slice(&u32::from(minimum_width).to_le_bytes());
        assembler.instruction(&add)?;
    }

    if let Some(raw) = layout.raw_pair_reverse_initial {
        x86_emit_raw_ordered_suffix_reverse_initial(assembler, layout, raw, invalid)?;
        let no_raw_initial_event = assembler.label()?;
        let event = u32::from(CONTEXT_RAW_REVERSE_EVENT).to_le_bytes();
        let mut test_event = vec![0xa9];
        test_event.extend_from_slice(&event);
        assembler.instruction(&test_event)?;
        assembler.branch(&[0x0f, 0x84], no_raw_initial_event)?;
        x86_emit_ordered_suffix_update_best(assembler, complete)?;
        assembler.bind(no_raw_initial_event)?;
        x86_emit_decode_raw_reverse_payload(assembler)?;
    } else {
        // Build the reverse boundary key at this candidate end. When the search
        // window ends before the haystack, its following byte remains visible to
        // line/word assertions; the tagged original start distinguishes that
        // case after rsi has become the suffix-base register.
        assembler.instruction(&[0x48, 0x85, 0xd2])?;
        assembler.branch(&[0x0f, 0x84], before_sentinel)?;
        x86_emit_class_before_position(assembler, layout.byte_classes_offset)?;
        assembler.branch(&[0xe9], before_ready)?;
        assembler.bind(before_sentinel)?;
        assembler.instruction(&[0xb8])?;
        push_bytes(
            &mut assembler.code,
            &u32::from(layout.class_count).to_le_bytes(),
        )?;
        assembler.bind(before_ready)?;
        assembler.instruction(&[0x41, 0x89, 0xc3])?;
        assembler.instruction(&[0x48, 0x39, 0xca])?; // candidate end vs window end
        assembler.branch(&[0x0f, 0x85], has_current)?;
        assembler.instruction(&[0x49, 0x8b, 0x00])?; // tagged original start
        assembler.instruction(&[0x48, 0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x88], no_current)?;
        assembler.bind(has_current)?;
        x86_emit_property_at_position(assembler, layout)?;
        assembler.instruction(&[0xc1, 0xe0, 0x09])?;
        assembler.instruction(&[0x41, 0x09, 0xc3])?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x20, 0x00, 0x00])?;
        assembler.branch(&[0xe9], current_ready)?;
        assembler.bind(no_current)?;
        assembler.bind(current_ready)?;
        assembler.instruction(&[0x48, 0x85, 0xd2])?;
        assembler.branch(&[0x0f, 0x85], not_absolute_start)?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x40, 0x00, 0x00])?;
        assembler.bind(not_absolute_start)?;
        assembler.instruction(&[0x48, 0x39, 0xca])?;
        assembler.branch(&[0x0f, 0x85], not_absolute_end)?;
        assembler.instruction(&[0x49, 0x8b, 0x00])?;
        assembler.instruction(&[0x48, 0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x89], not_absolute_end)?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x80, 0x00, 0x00])?;
        assembler.bind(not_absolute_end)?;
        assembler.instruction(&[0x44, 0x89, 0xd8])?;
        x86_emit_dispatch_cell(assembler, reverse_initial)?;
        x86_emit_test_valid(assembler, invalid)?;
        assembler.instruction(&[0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x89], no_initial_event)?;
        x86_emit_ordered_suffix_update_best(assembler, complete)?;
        assembler.bind(no_initial_event)?;
        assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
        assembler.instruction(&[0x41, 0x89, 0xc2])?; // reverse payload state+1
    }

    assembler.bind(reverse_loop)?;
    assembler.instruction(&[0x4d, 0x8b, 0x18])?; // tagged original start
    assembler.instruction(&[0x49, 0x0f, 0xba, 0xf3, 0x3f])?; // clear tag
    assembler.instruction(&[0x4c, 0x39, 0xda])?;
    assembler.branch(&[0x0f, 0x86], finished)?;
    assembler.instruction(&[0x45, 0x85, 0xd2])?;
    assembler.branch(&[0x0f, 0x84], finished)?;
    assembler.instruction(&[0x48, 0xff, 0xca])?;
    x86_emit_reverse_transition_cell(assembler, layout)?;
    x86_emit_populated_transition_valid_mode(
        assembler,
        invalid,
        ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
    )?;
    assembler.instruction(&[0x41, 0x89, 0xc3])?;
    assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
    assembler.instruction(&[0x41, 0x89, 0xc2])?;
    assembler.instruction(&[0x45, 0x85, 0xdb])?;
    assembler.branch(&[0x0f, 0x89], no_event)?;
    x86_emit_ordered_suffix_update_best(assembler, complete)?;
    assembler.bind(no_event)?;
    assembler.branch(&[0xe9], reverse_loop)?;

    assembler.bind(finished)?;
    assembler.instruction(&[0x48, 0x89, 0xf2])?; // restore suffix base
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], resume)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct X86TerminalSuffixScannerLabels {
    vector: usize,
    single_vector: usize,
    scalar: usize,
    scalar_reject: usize,
    primary_hit: usize,
    vector_hit: usize,
    verify: usize,
}

fn x86_terminal_suffix_scanner_labels(
    assembler: &mut X86Assembler,
) -> Result<X86TerminalSuffixScannerLabels, ObjectError> {
    Ok(X86TerminalSuffixScannerLabels {
        vector: assembler.label()?,
        single_vector: assembler.label()?,
        scalar: assembler.label()?,
        scalar_reject: assembler.label()?,
        primary_hit: assembler.label()?,
        vector_hit: assembler.label()?,
        verify: assembler.label()?,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the shared initial/budgeted suffix scanner is one emitted CFG"
)]
fn x86_emit_terminal_suffix_scanner(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
    layout: &ContextNativeLayout,
    suffix: ContextTerminalSuffixSearch,
    lazy_vector_filter: Option<NativeVectorFilter>,
    required_offset: u8,
    labels: X86TerminalSuffixScannerLabels,
    exhausted: usize,
) -> Result<(), ObjectError> {
    assembler.bind(labels.vector)?;
    if matches!(
        layout.output,
        OutputContract::SelectedEnd | OutputContract::Span
    ) && let Some(distance) = suffix.bounded_scan_distance
    {
        let no_best = assembler.label()?;
        assembler.instruction(&[0x49, 0x8b, 0x40, 0x08])?;
        assembler.instruction(&[0x48, 0x83, 0xf8, 0xff])?;
        assembler.branch(&[0x0f, 0x84], no_best)?;
        assembler.instruction(&[0x49, 0x89, 0xd3])?; // r11 = suffix base
        assembler.instruction(&[0x49, 0x29, 0xc3])?; // base - best start
        assembler.instruction(&[0xb8])?;
        push_bytes(&mut assembler.code, &distance.to_le_bytes())?;
        assembler.instruction(&[0x49, 0x39, 0xc3])?;
        assembler.branch(&[0x0f, 0x83], exhausted)?;
        assembler.bind(no_best)?;
    }
    assembler.instruction(&[0x48, 0x89, 0xc8])?;
    assembler.instruction(&[0x48, 0x29, 0xd0])?;
    let batch_required = u32::from(kind.width())
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(u32::from(required_offset)))
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 context suffix batch bound",
        ))?;
    let mut batch_compare = vec![0x48, 0x3d];
    batch_compare.extend_from_slice(&batch_required.to_le_bytes());
    assembler.instruction(&batch_compare)?;
    assembler.branch(&[0x0f, 0x82], labels.single_vector)?;
    for _ in 0..4 {
        x86_emit_start_filter_vector_test(assembler, suffix.primary, kind)?;
        assembler.branch(
            &[0x0f, 0x85],
            if lazy_vector_filter.is_some() {
                labels.primary_hit
            } else {
                labels.scalar
            },
        )?;
        assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    }
    assembler.branch(&[0xe9], labels.vector)?;

    assembler.bind(labels.single_vector)?;
    let single_required = u32::from(kind.width())
        .checked_add(u32::from(required_offset))
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 context suffix vector bound",
        ))?;
    let mut single_compare = vec![0x48, 0x3d];
    single_compare.extend_from_slice(&single_required.to_le_bytes());
    assembler.instruction(&single_compare)?;
    assembler.branch(&[0x0f, 0x82], labels.scalar)?;
    x86_emit_start_filter_vector_test(assembler, suffix.primary, kind)?;
    assembler.branch(
        &[0x0f, 0x85],
        if lazy_vector_filter.is_some() {
            labels.primary_hit
        } else {
            labels.scalar
        },
    )?;
    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    assembler.branch(&[0xe9], labels.vector)?;

    assembler.bind(labels.primary_hit)?;
    if let Some(filter) = lazy_vector_filter {
        x86_emit_vector_filter_secondary_test(assembler, filter, kind)?;
        assembler.branch(&[0x0f, 0x85], labels.vector_hit)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        assembler.branch(&[0xe9], labels.vector)?;
    } else {
        assembler.branch(&[0xe9], labels.scalar)?;
    }

    assembler.bind(labels.vector_hit)?;
    if lazy_vector_filter.is_some() {
        x86_emit_first_candidate_lane(assembler, X86CandidateMask::for_intersection(kind))?;
        assembler.instruction(&[0x48, 0x01, 0xc2])?;
        assembler.branch(&[0xe9], labels.verify)?;
    } else {
        assembler.branch(&[0xe9], labels.scalar)?;
    }

    assembler.bind(labels.scalar)?;
    x86_emit_start_filter_scalar_bound(assembler, required_offset, exhausted)?;
    for &column in suffix.vector_filter.columns() {
        x86_emit_scalar_filter_membership(assembler, column, labels.scalar_reject)?;
    }
    assembler.branch(&[0xe9], labels.verify)?;
    assembler.bind(labels.scalar_reject)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], labels.vector)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "suffix scanning, verification, and replay share one emitted control-flow graph"
)]
fn x86_emit_terminal_suffix_search(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
    layout: &ContextNativeLayout,
    suffix: ContextTerminalSuffixSearch,
    no_match: usize,
    matched: usize,
    invalid: usize,
    prepass_entry: usize,
    forward_entry: usize,
) -> Result<(), ObjectError> {
    let scanner = x86_terminal_suffix_scanner_labels(assembler)?;
    let ordered_output = matches!(
        layout.output,
        OutputContract::SelectedEnd | OutputContract::Span
    );
    let exhausted = if ordered_output {
        assembler.label()?
    } else {
        no_match
    };
    if ordered_output {
        let scan = assembler.label()?;
        assembler.instruction(&[0x48, 0x89, 0xc8])?;
        assembler.instruction(&[0x48, 0x29, 0xd0])?;
        let mut compare = vec![0x48, 0x3d];
        compare.extend_from_slice(&CONTEXT_ORDERED_SUFFIX_MIN_WINDOW_BYTES.to_le_bytes());
        assembler.instruction(&compare)?;
        assembler.branch(&[0x0f, 0x83], scan)?;
        assembler.branch(&[0xe9], prepass_entry)?;
        // Keep every downstream block at its previous address while deleting
        // the five-byte short-path BTR. Both branches above jump over this
        // padding, so it has no execution cost.
        assembler.instruction(&[0x0f, 0x1f, 0x44, 0x00, 0x00])?;
        assembler.bind(scan)?;

        // The reverse verifier temporarily repurposes rsi, so remember only
        // the absolute-end fact needed by the forward replay. Short windows
        // take the ordinary path and never need this scratch tag.
        let not_absolute_window_end = assembler.label()?;
        assembler.instruction(&[0x48, 0x39, 0xf1])?; // window end vs full length
        assembler.branch(&[0x0f, 0x85], not_absolute_window_end)?;
        assembler.instruction(&[0x49, 0x0f, 0xba, 0x28, 0x3f])?; // tag result[0]
        assembler.bind(not_absolute_window_end)?;
    }
    let lazy_vector_filter = (kind != X86StartFilterKind::Avx512Bw).then_some(suffix.vector_filter);
    if let Some(filter) = lazy_vector_filter {
        let mut first_register = 1_u8;
        for &column in filter.columns() {
            x86_emit_start_filter_constants(assembler, column, kind, first_register)?;
            first_register =
                first_register
                    .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                        ObjectError::ArithmeticOverflow("x86 context suffix constants")
                    })?)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "x86 context suffix constants",
                    ))?;
        }
    } else {
        x86_emit_start_filter_constants(assembler, suffix.primary, kind, 1)?;
    }
    let required_offset = suffix
        .vector_filter
        .max_scan_offset()
        .max(suffix.minimum_width.saturating_sub(1));

    x86_emit_terminal_suffix_scanner(
        assembler,
        kind,
        layout,
        suffix,
        lazy_vector_filter,
        required_offset,
        scanner,
        exhausted,
    )?;

    assembler.bind(scanner.verify)?;
    match layout.output {
        OutputContract::Exists => {
            let verified_match = assembler.label()?;
            x86_emit_exists_suffix_reverse(
                assembler,
                layout,
                suffix.minimum_width,
                scanner.vector,
                verified_match,
                invalid,
            )?;
            assembler.bind(verified_match)?;
            x86_emit_clear_result(assembler)?;
            assembler.branch(&[0xe9], matched)?;
        }
        OutputContract::SelectedEnd | OutputContract::Span => {
            x86_emit_ordered_suffix_reverse(
                assembler,
                layout,
                suffix.minimum_width,
                scanner.vector,
                exhausted,
                invalid,
            )?;
            assembler.bind(exhausted)?;
            assembler.instruction(&[0x49, 0x8b, 0x40, 0x08])?; // best start
            assembler.instruction(&[0x48, 0x83, 0xf8, 0xff])?;
            assembler.branch(&[0x0f, 0x84], no_match)?;

            // Reconstruct the only observable fact about the original full
            // length after rsi served as the reverse verifier's suffix base.
            // Positions never exceed the window end, so end or end+1 exactly
            // preserves absolute-end and following-byte behavior.
            let absolute_end = assembler.label()?;
            let length_ready = assembler.label()?;
            assembler.instruction(&[0x4d, 0x8b, 0x18])?; // tagged original start
            assembler.instruction(&[0x4d, 0x85, 0xdb])?;
            assembler.branch(&[0x0f, 0x88], absolute_end)?;
            assembler.instruction(&[0x48, 0x8d, 0x71, 0x01])?; // length = end + 1
            assembler.branch(&[0xe9], length_ready)?;
            assembler.bind(absolute_end)?;
            assembler.instruction(&[0x48, 0x89, 0xce])?; // length = end
            assembler.bind(length_ready)?;

            assembler.instruction(&[0x48, 0x89, 0xc2])?; // restart at best start
            assembler.instruction(&[0x49, 0x89, 0x00])?;
            if layout.output == OutputContract::Span && ENABLE_CONTEXT_KNOWN_SPAN_START {
                assembler.instruction(&[0x49, 0x0f, 0xba, 0x28, 0x3f])?; // exact start tag
            }
            assembler.instruction(&[0x49, 0xc7, 0x40, 0x08, 0xff, 0xff, 0xff, 0xff])?;
            assembler.branch(&[0xe9], forward_entry)?;
        }
    }

    Ok(())
}

fn x86_emit_state_skip(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
    skip: ContextStateSkip,
    scalar_step: usize,
) -> Result<(), ObjectError> {
    let landing = assembler.label()?;
    let replay = matches!(skip.membership, ContextStateMembership::Table { .. });
    if replay {
        assembler.instruction(&[0x49, 0x89, 0xd3])?; // original position in r11
    }
    let Some(filter) = skip.exit_filter else {
        assembler.instruction(&[0x48, 0x8d, 0x51, 0xff])?; // rdx = end - 1
        assembler.branch(&[0xe9], landing)?;
        assembler.bind(landing)?;
        if !replay {
            assembler.branch(&[0xe9], scalar_step)?;
            return Ok(());
        }
        assembler.instruction(&[0x4c, 0x39, 0xda])?; // position vs original
        assembler.branch(&[0x0f, 0x84], scalar_step)?;
        assembler.instruction(&[0x48, 0xff, 0xca])?; // replay last skipped byte
        let mut canonical = vec![0x41, 0xba]; // r10d = canonical state
        canonical.extend_from_slice(&skip.canonical_state.to_le_bytes());
        assembler.instruction(&canonical)?;
        assembler.branch(&[0xe9], scalar_step)?;
        return Ok(());
    };
    x86_emit_start_filter_constants(assembler, filter, kind, 1)?;
    let vector = assembler.label()?;
    let scalar = assembler.label()?;
    let rejected = assembler.label()?;
    let exhausted = assembler.label()?;
    assembler.bind(vector)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // rax = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining = end - position
    let required = u32::from(kind.width())
        .checked_add(u32::from(filter.scan_offset))
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 context state-skip vector bound",
        ))?;
    let mut compare = vec![0x48, 0x3d];
    compare.extend_from_slice(&required.to_le_bytes());
    assembler.instruction(&compare)?;
    assembler.branch(&[0x0f, 0x82], scalar)?;
    x86_emit_start_filter_vector_test(assembler, filter, kind)?;
    assembler.branch(&[0x0f, 0x85], scalar)?;
    assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
    assembler.branch(&[0xe9], vector)?;
    assembler.bind(scalar)?;
    x86_emit_start_filter_scalar_bound(assembler, filter.scan_offset, exhausted)?;
    x86_emit_scalar_filter_membership(assembler, filter, rejected)?;
    assembler.branch(&[0xe9], landing)?;
    assembler.bind(rejected)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar)?;
    assembler.bind(exhausted)?;
    assembler.instruction(&[0x48, 0x8d, 0x51, 0xff])?; // rdx = end - 1
    assembler.bind(landing)?;
    if !replay {
        assembler.branch(&[0xe9], scalar_step)?;
        return Ok(());
    }
    assembler.instruction(&[0x4c, 0x39, 0xda])?; // position vs original
    assembler.branch(&[0x0f, 0x84], scalar_step)?;
    assembler.instruction(&[0x48, 0xff, 0xca])?; // replay last skipped byte
    let mut canonical = vec![0x41, 0xba]; // r10d = canonical state
    canonical.extend_from_slice(&skip.canonical_state.to_le_bytes());
    assembler.instruction(&canonical)?;
    assembler.branch(&[0xe9], scalar_step)?;
    Ok(())
}

fn x86_emit_subtract_width(
    assembler: &mut X86Assembler,
    width: u64,
    invalid: usize,
) -> Result<(), ObjectError> {
    // r11 = selected end; leave selected end in result[1].
    assembler.instruction(&[0x4d, 0x8b, 0x58, 0x08])?;
    if let Ok(width) = i32::try_from(width) {
        let mut compare = vec![0x49, 0x81, 0xfb];
        compare.extend_from_slice(&width.to_le_bytes());
        assembler.instruction(&compare)?;
        assembler.branch(&[0x0f, 0x82], invalid)?;
        let mut subtract = vec![0x49, 0x81, 0xeb];
        subtract.extend_from_slice(&width.to_le_bytes());
        assembler.instruction(&subtract)?;
    } else {
        let mut load = vec![0x48, 0xb8];
        load.extend_from_slice(&width.to_le_bytes());
        assembler.instruction(&load)?;
        assembler.instruction(&[0x49, 0x39, 0xc3])?; // cmp r11, rax
        assembler.branch(&[0x0f, 0x82], invalid)?;
        assembler.instruction(&[0x49, 0x29, 0xc3])?;
    }
    assembler.instruction(&[0x4d, 0x3b, 0x18])?; // cmp r11, original start
    assembler.branch(&[0x0f, 0x82], invalid)?;
    assembler.instruction(&[0x4d, 0x89, 0x18])?;
    Ok(())
}

/// Scan exact graph-derived candidate starts and resolve each with the
/// restart-free anchored forward machine.
///
/// result[0] holds the current candidate, result[1] its best pending end,
/// r12 is fixed-point cumulative debt and r13d is the per-candidate cap. Both
/// nonvolatile registers are saved by the surrounding entry point.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "candidate scanning, exact dispatch, bounded verification, and one-shot fallback form one CFG"
)]
fn x86_emit_anchored_forward_search(
    assembler: &mut X86Assembler,
    kind: X86StartFilterKind,
    layout: &ContextNativeLayout,
    search: ContextAnchoredForwardSearch,
    adaptive_guard: ContextAnchoredAdaptiveGuard,
    prefix_filter: Option<NativePrefixFilter>,
    boundary_pair: Option<ContextBoundaryPairExpression>,
    no_match: usize,
    matched: usize,
    invalid: usize,
    forward_entry: usize,
) -> Result<(), ObjectError> {
    let anchored = layout.anchored_forward.ok_or(ObjectError::InvalidModule(
        "context anchored search has no physical sidecar",
    ))?;
    let scan = assembler.label()?;
    let verify_loop = assembler.label()?;
    let no_event = assembler.label()?;
    let resolved = assembler.label()?;
    let rejected = assembler.label()?;
    let resume_scan = assembler.label()?;
    let fallback = assembler.label()?;

    x86_emit_prefix_prepass(
        assembler,
        kind,
        search.primary,
        search.vector_filter,
        boundary_pair,
        prefix_filter,
        Some(search.guarded_bytes),
        None,
        ContextPrepassRestart::CandidateBase,
        Some((layout, None)),
        Some((adaptive_guard, fallback)),
        no_match,
        invalid,
        Some(scan),
    )?;

    // The prefix prepass performed the complete full-haystack boundary
    // dispatch, rejected an empty main frontier, stored the candidate in
    // result[0], and left the main state in r10d.
    x86_emit_anchored_initial_map(assembler, anchored, invalid)?;
    assembler.instruction(&[0xa8, CONTEXT_STATE_PENDING])?;
    assembler.branch(&[0x0f, 0x85], invalid)?;
    assembler.instruction(&[0xa8, CONTEXT_STATE_EMPTY])?;
    assembler.branch(&[0x0f, 0x85], resume_scan)?;
    assembler.instruction(&[0x49, 0xc7, 0x40, 0x08, 0xff, 0xff, 0xff, 0xff])?;

    // Reserve every whole verifier transition currently affordable, up to the
    // graph-derived cap. r13d retains the unconsumed transition count.
    x86_emit_anchored_transition_reserve(assembler, search, adaptive_guard, fallback)?;

    assembler.bind(verify_loop)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    x86_emit_anchored_forward_transition_cell(assembler, layout, anchored)?;
    x86_emit_decode_populated_forward_transition_mode(
        assembler,
        invalid,
        ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
    )?;
    assembler.instruction(&[0x41, 0xff, 0xcd])?; // dec r13d
    assembler.instruction(&[0x45, 0x85, 0xdb])?;
    assembler.branch(&[0x0f, 0x89], no_event)?;
    assembler.instruction(&[0x49, 0x89, 0x50, 0x08])?;
    assembler.bind(no_event)?;

    assembler.instruction(&[0xa8, CONTEXT_STATE_TERMINAL])?;
    assembler.branch(&[0x0f, 0x85], resolved)?;
    assembler.instruction(&[0xa8, CONTEXT_STATE_EMPTY])?;
    assembler.branch(&[0x0f, 0x85], rejected)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x83], resolved)?;
    assembler.instruction(&[0x45, 0x85, 0xed])?;
    assembler.branch(&[0x0f, 0x84], fallback)?;
    assembler.branch(&[0xe9], verify_loop)?;

    assembler.bind(resolved)?;
    assembler.instruction(&[0x49, 0x83, 0x78, 0x08, 0xff])?;
    assembler.branch(&[0x0f, 0x84], rejected)?;
    if layout.output == OutputContract::SelectedEnd {
        assembler.instruction(&[0x49, 0x8b, 0x40, 0x08])?;
        assembler.instruction(&[0x49, 0x89, 0x00])?;
    }
    assembler.branch(&[0xe9], matched)?;

    assembler.bind(rejected)?;
    x86_emit_anchored_transition_refund(assembler, adaptive_guard)?;
    assembler.bind(resume_scan)?;
    assembler.instruction(&[0x49, 0x8b, 0x10])?; // candidate
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.instruction(&[0x49, 0xc7, 0x40, 0x08, 0xff, 0xff, 0xff, 0xff])?;
    assembler.branch(&[0xe9], scan)?;

    assembler.bind(fallback)?;
    assembler.instruction(&[0x49, 0x8b, 0x10])?; // same candidate
    assembler.instruction(&[0x49, 0x0f, 0xba, 0x30, 0x3f])?; // clear start tag
    assembler.instruction(&[0x49, 0xc7, 0x40, 0x08, 0xff, 0xff, 0xff, 0xff])?;
    assembler.instruction(&[0x45, 0x31, 0xd2])?; // clear state/tag scratch
    assembler.branch(&[0xe9], forward_entry)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the leaf ABI, forward selection and reverse reconstruction are one auditable CFG"
)]
fn lower_x86_64_context(
    layout: &ContextNativeLayout,
    terminal_suffix_search: Option<ContextTerminalSuffixSearch>,
    anchored_forward_search: Option<ContextAnchoredForwardSearch>,
    anchored_adaptive_guard: Option<ContextAnchoredAdaptiveGuard>,
    anchored_prefix_filter: Option<NativePrefixFilter>,
    anchored_boundary_pair: Option<ContextBoundaryPairExpression>,
    start_filter: Option<NativeStartFilter>,
    vector_filter: Option<NativeVectorFilter>,
    ordinary_boundary_pair: Option<ContextBoundaryPairExpression>,
    prefix_filter: Option<NativePrefixFilter>,
    prefix_fast_forward: Option<ContextPrefixFastForward>,
    known_span_start: Option<ContextKnownSpanStartGuard>,
    interior_guard: Option<ContextInteriorGuard>,
    state_skip: Option<ContextStateSkip>,
    empty_prefix_restart: bool,
    features: FeatureSet,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = X86Assembler::new();
    let filter_kind = context_x86_start_filter_kind(features);
    let has_vector_scanner = terminal_suffix_search.is_some()
        || anchored_forward_search.is_some_and(|search| !search.primary.ranges().is_empty())
        || start_filter.is_some_and(|filter| !filter.ranges().is_empty())
        || interior_guard.is_some_and(|guard| !guard.primary.ranges().is_empty())
        || state_skip.is_some_and(|skip| {
            skip.exit_filter
                .is_some_and(|filter| !filter.ranges().is_empty())
        });
    let current_sentinel = assembler.label()?;
    let current_ready = assembler.label()?;
    let no_before = assembler.label()?;
    let before_ready = assembler.label()?;
    let not_absolute_start = assembler.label()?;
    let not_absolute_end = assembler.label()?;
    let initial_not_pending = assembler.label()?;
    let forward_loop = assembler.label()?;
    let forward_scalar_step = assembler.label()?;
    let forward_finish = assembler.label()?;
    let forward_no_event = assembler.label()?;
    let span_not_initial = assembler.label()?;
    let reverse_before_sentinel = assembler.label()?;
    let reverse_before_ready = assembler.label()?;
    let reverse_no_current = assembler.label()?;
    let reverse_current_ready = assembler.label()?;
    let reverse_not_absolute_start = assembler.label()?;
    let reverse_not_absolute_end = assembler.label()?;
    let reverse_no_initial_event = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let reverse_finish = assembler.label()?;
    let reverse_no_event = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid_initialized = assembler.label()?;
    let invalid_input = assembler.label()?;
    let done = assembler.label()?;
    let prepass_entry = assembler.label()?;
    let forward_entry = assembler.label()?;
    let forward_initialized = assembler.label()?;
    let anchored_prefix_scan = if start_filter.is_some() && empty_prefix_restart {
        Some(assembler.label()?)
    } else {
        None
    };
    let anchored_accelerated_fallback =
        if anchored_forward_search.is_some() && start_filter.is_some() {
            Some(assembler.label()?)
        } else {
            None
        };

    // Preserve verifier counters only in the sidecar specialization. Ordinary
    // contextual modules retain their byte-identical leaf prologue/epilogue.
    if anchored_forward_search.is_some() {
        assembler.instruction(&[0x41, 0x54])?; // push r12
        assembler.instruction(&[0x41, 0x55])?; // push r13
    }

    // Validate before touching result memory. As in the byte-DFA entry, the
    // signed-length guard makes the high bit available as an internal marker.
    assembler.instruction(&[0x48, 0x85, 0xf6])?;
    assembler.branch(&[0x0f, 0x88], invalid_input)?;
    assembler.instruction(&[0x48, 0x39, 0xf1])?;
    assembler.branch(&[0x0f, 0x87], invalid_input)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?;
    assembler.branch(&[0x0f, 0x87], invalid_input)?;
    assembler.instruction(&[0x4d, 0x85, 0xc0])?;
    assembler.branch(&[0x0f, 0x84], invalid_input)?;
    assembler.instruction(&[0x41, 0xf6, 0xc0, 0x07])?;
    assembler.branch(&[0x0f, 0x85], invalid_input)?;
    assembler.instruction(&[0x48, 0x85, 0xff])?;
    assembler.branch(&[0x0f, 0x84], invalid_input)?;

    if anchored_forward_search.is_some() {
        assembler.instruction(&[0x49, 0x89, 0xd4])?; // debt origin = window start
    }

    assembler.instruction(&[0x49, 0x89, 0x10])?; // scratch start = window start
    assembler.instruction(&[0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?; // pending = none

    assembler.instruction(&[0x4c, 0x8d, 0x0d])?; // data(%rip), r9
    let table_displacement_label = assembler.label()?;
    assembler.bind(table_displacement_label)?;
    push_bytes(&mut assembler.code, &[0; 4])?;

    if let Some(suffix) = terminal_suffix_search {
        x86_emit_terminal_suffix_search(
            &mut assembler,
            filter_kind,
            layout,
            suffix,
            no_match,
            matched,
            invalid_initialized,
            prepass_entry,
            forward_entry,
        )?;
    }

    assembler.bind(prepass_entry)?;
    if let Some(guard) = interior_guard {
        x86_emit_prefix_prepass(
            &mut assembler,
            filter_kind,
            guard.primary,
            guard.vector_filter,
            None,
            None,
            None,
            None,
            guard.restart,
            None,
            None,
            no_match,
            invalid_initialized,
            None,
        )?;
    }
    if let Some(search) = anchored_forward_search {
        let adaptive_guard = anchored_adaptive_guard.ok_or(ObjectError::InvalidModule(
            "context anchored search has no adaptive guard",
        ))?;
        x86_emit_anchored_forward_search(
            &mut assembler,
            filter_kind,
            layout,
            search,
            adaptive_guard,
            anchored_prefix_filter,
            anchored_boundary_pair,
            no_match,
            matched,
            invalid_initialized,
            anchored_accelerated_fallback.unwrap_or(forward_entry),
        )?;
    }
    if let Some(fallback) = anchored_accelerated_fallback {
        assembler.bind(fallback)?;
    }
    if let Some(filter) = start_filter {
        if let Some(prefix_scan) = anchored_prefix_scan {
            assembler.bind(prefix_scan)?;
        }
        x86_emit_prefix_prepass(
            &mut assembler,
            filter_kind,
            filter,
            vector_filter,
            ordinary_boundary_pair,
            prefix_filter,
            prefix_fast_forward
                .map(|plan| plan.guaranteed_bytes)
                .or(known_span_start.map(|guard| guard.guarded_bytes)),
            known_span_start,
            ContextPrepassRestart::CandidateBase,
            (empty_prefix_restart || known_span_start.is_some()).then_some((
                layout,
                ENABLE_CONTEXT_PREFIX_DISPATCH_REUSE.then_some(forward_initialized),
            )),
            None,
            no_match,
            invalid_initialized,
            None,
        )?;
    }

    assembler.bind(forward_entry)?;
    if let Some(raw) = layout.raw_pair_initial {
        x86_emit_raw_forward_initial(&mut assembler, layout, raw, invalid_initialized)?;
    } else {
        // Build the forward boundary key in r11d.
        assembler.instruction(&[0x48, 0x39, 0xf2])?;
        assembler.branch(&[0x0f, 0x84], current_sentinel)?;
        x86_emit_class_at_position(&mut assembler, layout.byte_classes_offset)?;
        assembler.branch(&[0xe9], current_ready)?;
        assembler.bind(current_sentinel)?;
        assembler.instruction(&[0xb8])?;
        push_bytes(
            &mut assembler.code,
            &u32::from(layout.class_count).to_le_bytes(),
        )?;
        assembler.bind(current_ready)?;
        assembler.instruction(&[0x41, 0x89, 0xc3])?; // key = class
        assembler.instruction(&[0x48, 0x85, 0xd2])?;
        assembler.branch(&[0x0f, 0x84], no_before)?;
        x86_emit_property_before_position(&mut assembler, layout)?;
        assembler.instruction(&[0xc1, 0xe0, 0x09])?;
        assembler.instruction(&[0x41, 0x09, 0xc3])?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x20, 0x00, 0x00])?;
        assembler.branch(&[0xe9], before_ready)?;
        assembler.bind(no_before)?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x40, 0x00, 0x00])?;
        assembler.bind(before_ready)?;
        assembler.instruction(&[0x48, 0x85, 0xd2])?;
        assembler.branch(&[0x0f, 0x85], not_absolute_start)?;
        // The no-before arm already installed absolute-start. This explicit
        // arm makes malformed register flow fail rather than omit the fact.
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x40, 0x00, 0x00])?;
        assembler.bind(not_absolute_start)?;
        assembler.instruction(&[0x48, 0x39, 0xf2])?;
        assembler.branch(&[0x0f, 0x85], not_absolute_end)?;
        assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x80, 0x00, 0x00])?;
        assembler.bind(not_absolute_end)?;
        assembler.instruction(&[0x44, 0x89, 0xd8])?;
        x86_emit_dispatch_cell(&mut assembler, layout.forward_initial_offset)?;
        x86_emit_test_valid(&mut assembler, invalid_initialized)?;
        assembler.instruction(&[0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x88], invalid_initialized)?;
        x86_emit_decode_forward_state_checked(&mut assembler, invalid_initialized)?;
        x86_emit_forward_flags(&mut assembler, layout)?;
    }
    assembler.bind(forward_initialized)?;
    assembler.instruction(&[0xa8, CONTEXT_STATE_PENDING])?;
    assembler.branch(&[0x0f, 0x84], initial_not_pending)?;
    assembler.instruction(&[0x49, 0x89, 0x50, 0x08])?;
    assembler.instruction(&[0x49, 0x0f, 0xba, 0x28, 0x3f])?; // bts [result.start], 63
    if layout.output == OutputContract::Exists {
        assembler.branch(&[0xe9], forward_finish)?;
    } else {
        assembler.instruction(&[0xa8, CONTEXT_STATE_TERMINAL])?;
        assembler.branch(&[0x0f, 0x85], forward_finish)?;
    }
    assembler.bind(initial_not_pending)?;

    if let Some(plan) = prefix_fast_forward {
        let ordinary = assembler.label()?;
        assembler.instruction(&[
            0xa8,
            CONTEXT_STATE_PENDING | CONTEXT_STATE_TERMINAL | CONTEXT_STATE_EMPTY,
        ])?;
        assembler.branch(&[0x0f, 0x85], ordinary)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, plan.consumed_bytes])?;
        let mut target = vec![0x41, 0xba]; // r10d = proved target state
        target.extend_from_slice(&plan.target_state.to_le_bytes());
        assembler.instruction(&target)?;
        assembler.branch(&[0xe9], forward_loop)?;
        assembler.bind(ordinary)?;
    }

    assembler.bind(forward_loop)?;
    assembler.instruction(&[0x48, 0x39, 0xca])?; // position vs window end
    assembler.branch(&[0x0f, 0x83], forward_finish)?;
    assembler.instruction(&[0xa8, CONTEXT_STATE_TERMINAL])?;
    assembler.branch(&[0x0f, 0x85], forward_finish)?;
    if let Some(prefix_scan) = anchored_prefix_scan {
        let active = assembler.label()?;
        assembler.instruction(&[0xa8, CONTEXT_STATE_EMPTY])?;
        assembler.branch(&[0x0f, 0x84], active)?;
        assembler.instruction(&[0x48, 0xff, 0xc2])?;
        assembler.branch(&[0xe9], prefix_scan)?;
        assembler.bind(active)?;
    }
    if let Some(skip) = state_skip {
        match skip.membership {
            ContextStateMembership::Singleton(state) => {
                let mut compare = vec![0x41, 0x81, 0xfa]; // cmp r10d, state
                compare.extend_from_slice(&state.to_le_bytes());
                assembler.instruction(&compare)?;
                assembler.branch(&[0x0f, 0x85], forward_scalar_step)?;
            }
            ContextStateMembership::Table { offset } => {
                x86_emit_indexed_byte_at_r10(&mut assembler, offset)?;
                assembler.instruction(&[0x84, 0xc0])?;
                assembler.branch(&[0x0f, 0x84], forward_scalar_step)?;
            }
        }
        x86_emit_state_skip(&mut assembler, filter_kind, skip, forward_scalar_step)?;
    }
    assembler.bind(forward_scalar_step)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?; // destination
    x86_emit_forward_transition_cell(&mut assembler, layout)?;
    x86_emit_decode_populated_forward_transition_mode(
        &mut assembler,
        invalid_initialized,
        ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
    )?;
    assembler.instruction(&[0x45, 0x85, 0xdb])?;
    assembler.branch(&[0x0f, 0x89], forward_no_event)?;
    assembler.instruction(&[0x49, 0x89, 0x50, 0x08])?;
    if layout.output == OutputContract::Exists {
        assembler.branch(&[0xe9], forward_finish)?;
    }
    assembler.bind(forward_no_event)?;
    assembler.branch(&[0xe9], forward_loop)?;

    assembler.bind(forward_finish)?;
    assembler.instruction(&[0x49, 0x83, 0x78, 0x08, 0xff])?;
    assembler.branch(&[0x0f, 0x84], no_match)?;
    match layout.output {
        OutputContract::Exists => {
            x86_emit_clear_result(&mut assembler)?;
            assembler.branch(&[0xe9], matched)?;
        }
        OutputContract::SelectedEnd => {
            assembler.instruction(&[0x49, 0x8b, 0x40, 0x08])?;
            assembler.instruction(&[0x49, 0x89, 0x00])?;
            assembler.branch(&[0xe9], matched)?;
        }
        OutputContract::Span => {
            assembler.instruction(&[0x49, 0x8b, 0x00])?;
            assembler.instruction(&[0x48, 0x85, 0xc0])?;
            assembler.branch(&[0x0f, 0x89], span_not_initial)?;
            assembler.instruction(&[0x48, 0x0f, 0xba, 0xf0, 0x3f])?; // btr rax, 63
            assembler.instruction(&[0x49, 0x89, 0x00])?;
            assembler.branch(&[0xe9], matched)?;
            assembler.bind(span_not_initial)?;
            if let Some(width) = layout.exact_match_width {
                x86_emit_subtract_width(&mut assembler, width, invalid_initialized)?;
                assembler.branch(&[0xe9], matched)?;
            } else {
                let reverse_initial =
                    layout
                        .reverse_initial_offset
                        .ok_or(ObjectError::InvalidModule(
                            "context span lowering has no reverse dispatch",
                        ))?;
                assembler.instruction(&[0x49, 0x8b, 0x50, 0x08])?;
                assembler.instruction(&[0x48, 0xc7, 0xc1, 0xff, 0xff, 0xff, 0xff])?;
                if let Some(raw) = layout.raw_pair_reverse_initial {
                    x86_emit_raw_reverse_initial(&mut assembler, layout, raw, invalid_initialized)?;
                    let no_raw_initial_event = assembler.label()?;
                    let event = u32::from(CONTEXT_RAW_REVERSE_EVENT).to_le_bytes();
                    let mut test_event = vec![0xa9];
                    test_event.extend_from_slice(&event);
                    assembler.instruction(&test_event)?;
                    assembler.branch(&[0x0f, 0x84], no_raw_initial_event)?;
                    assembler.instruction(&[0x48, 0x89, 0xd1])?; // candidate = end
                    assembler.bind(no_raw_initial_event)?;
                    x86_emit_decode_raw_reverse_payload(&mut assembler)?;
                } else {
                    // Cursor is the selected end. Build its reverse boundary key.
                    assembler.instruction(&[0x48, 0x85, 0xd2])?;
                    assembler.branch(&[0x0f, 0x84], reverse_before_sentinel)?;
                    x86_emit_class_before_position(&mut assembler, layout.byte_classes_offset)?;
                    assembler.branch(&[0xe9], reverse_before_ready)?;
                    assembler.bind(reverse_before_sentinel)?;
                    assembler.instruction(&[0xb8])?;
                    push_bytes(
                        &mut assembler.code,
                        &u32::from(layout.class_count).to_le_bytes(),
                    )?;
                    assembler.bind(reverse_before_ready)?;
                    assembler.instruction(&[0x41, 0x89, 0xc3])?;
                    assembler.instruction(&[0x48, 0x39, 0xf2])?;
                    assembler.branch(&[0x0f, 0x84], reverse_no_current)?;
                    x86_emit_property_at_position(&mut assembler, layout)?;
                    assembler.instruction(&[0xc1, 0xe0, 0x09])?;
                    assembler.instruction(&[0x41, 0x09, 0xc3])?;
                    assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x20, 0x00, 0x00])?;
                    assembler.bind(reverse_no_current)?;
                    assembler.bind(reverse_current_ready)?;
                    assembler.instruction(&[0x48, 0x85, 0xd2])?;
                    assembler.branch(&[0x0f, 0x85], reverse_not_absolute_start)?;
                    assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x40, 0x00, 0x00])?;
                    assembler.bind(reverse_not_absolute_start)?;
                    assembler.instruction(&[0x48, 0x39, 0xf2])?;
                    assembler.branch(&[0x0f, 0x85], reverse_not_absolute_end)?;
                    assembler.instruction(&[0x41, 0x81, 0xcb, 0x00, 0x80, 0x00, 0x00])?;
                    assembler.bind(reverse_not_absolute_end)?;
                    assembler.instruction(&[0x44, 0x89, 0xd8])?;
                    x86_emit_dispatch_cell(&mut assembler, reverse_initial)?;
                    x86_emit_test_valid(&mut assembler, invalid_initialized)?;
                    assembler.instruction(&[0x85, 0xc0])?;
                    assembler.branch(&[0x0f, 0x89], reverse_no_initial_event)?;
                    assembler.instruction(&[0x48, 0x89, 0xd1])?; // candidate = end
                    assembler.bind(reverse_no_initial_event)?;
                    assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
                    assembler.instruction(&[0x41, 0x89, 0xc2])?; // payload state+1
                }
                assembler.instruction(&[0x49, 0x8b, 0x00])?;
                assembler.instruction(&[0x48, 0x0f, 0xba, 0xf0, 0x3f])?;
                assembler.instruction(&[0x48, 0x89, 0xc6])?; // original start in rsi
                assembler.bind(reverse_loop)?;
                assembler.instruction(&[0x48, 0x39, 0xf2])?;
                assembler.branch(&[0x0f, 0x86], reverse_finish)?;
                assembler.instruction(&[0x45, 0x85, 0xd2])?;
                assembler.branch(&[0x0f, 0x84], reverse_finish)?;
                assembler.instruction(&[0x48, 0xff, 0xca])?; // source
                x86_emit_reverse_transition_cell(&mut assembler, layout)?;
                x86_emit_populated_transition_valid_mode(
                    &mut assembler,
                    invalid_initialized,
                    ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
                )?;
                assembler.instruction(&[0x41, 0x89, 0xc3])?;
                assembler.instruction(&[0x25, 0xff, 0xff, 0xff, 0x3f])?;
                assembler.instruction(&[0x41, 0x89, 0xc2])?;
                assembler.instruction(&[0x45, 0x85, 0xdb])?;
                assembler.branch(&[0x0f, 0x89], reverse_no_event)?;
                assembler.instruction(&[0x48, 0x89, 0xd1])?;
                assembler.bind(reverse_no_event)?;
                assembler.branch(&[0xe9], reverse_loop)?;
                assembler.bind(reverse_finish)?;
                assembler.instruction(&[0x48, 0x83, 0xf9, 0xff])?;
                assembler.branch(&[0x0f, 0x84], invalid_initialized)?;
                assembler.instruction(&[0x49, 0x89, 0x08])?;
                assembler.branch(&[0xe9], matched)?;
            }
        }
    }

    assembler.bind(no_match)?;
    x86_emit_clear_result(&mut assembler)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.branch(&[0xe9], done)?;
    assembler.bind(matched)?;
    assembler.instruction(&[0xb8, 0x01, 0x00, 0x00, 0x00])?;
    assembler.branch(&[0xe9], done)?;
    assembler.bind(invalid_initialized)?;
    x86_emit_clear_result(&mut assembler)?;
    assembler.bind(invalid_input)?;
    assembler.instruction(&[0xb8, 0x02, 0x00, 0x00, 0x00])?;
    assembler.bind(done)?;
    if has_vector_scanner && filter_kind.needs_vzeroupper() {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    if anchored_forward_search.is_some() {
        assembler.instruction(&[0x41, 0x5d])?; // pop r13
        assembler.instruction(&[0x41, 0x5c])?; // pop r12
    }
    assembler.instruction(&[0xc3])?;

    let finished = assembler.finish_with_label_offsets()?;
    let table_displacement = finished.label_offset(table_displacement_label)?;
    let code = finished.code;
    Ok((
        code,
        vec![ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(table_displacement, "x86 context table relocation offset")?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        }],
    ))
}

// AArch64 logical-immediate AND with a contiguous low-bit mask.
fn aarch64_context_and_low_w(destination: u8, source: u8, bits: u8) -> Result<u32, ObjectError> {
    let mask_end = bits
        .checked_sub(1)
        .filter(|&value| value < 32)
        .ok_or(ObjectError::InvalidModule("AArch64 context low-bit mask"))?;
    Ok(0x1200_0000
        | (u32::from(mask_end) << 10)
        | super::aarch64_reg(source, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_orr_w(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(0x2a00_0000
        | super::aarch64_reg(right, 16)?
        | super::aarch64_reg(left, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_lsl_w(destination: u8, source: u8, shift: u8) -> Result<u32, ObjectError> {
    if shift > 31 {
        return Err(ObjectError::InvalidModule("AArch64 context LSL shift"));
    }
    let rotate_right = 32_u8.wrapping_sub(shift) & 31;
    let last_source_bit = 31_u8
        .checked_sub(shift)
        .ok_or(ObjectError::InvalidModule("AArch64 context LSL shift"))?;
    Ok(0x5300_0000
        | (u32::from(rotate_right) << 16)
        | (u32::from(last_source_bit) << 10)
        | super::aarch64_reg(source, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_add_x_lsl(
    destination: u8,
    left: u8,
    right: u8,
    shift: u8,
) -> Result<u32, ObjectError> {
    if shift > 63 {
        return Err(ObjectError::InvalidModule(
            "AArch64 context shifted-add amount",
        ));
    }
    Ok(0x8b00_0000
        | super::aarch64_reg(right, 16)?
        | (u32::from(shift) << 10)
        | super::aarch64_reg(left, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_sub_x_lsl(
    destination: u8,
    left: u8,
    right: u8,
    shift: u8,
) -> Result<u32, ObjectError> {
    if shift > 63 {
        return Err(ObjectError::InvalidModule(
            "AArch64 context shifted-subtract amount",
        ));
    }
    Ok(0xcb00_0000
        | super::aarch64_reg(right, 16)?
        | (u32::from(shift) << 10)
        | super::aarch64_reg(left, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_mul_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(0x9b00_7c00
        | super::aarch64_reg(right, 16)?
        | super::aarch64_reg(left, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_load_w_lsl2(destination: u8, base: u8, index: u8) -> Result<u32, ObjectError> {
    Ok(0xb860_7800
        | super::aarch64_reg(index, 16)?
        | super::aarch64_reg(base, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_load_h_lsl1(destination: u8, base: u8, index: u8) -> Result<u32, ObjectError> {
    Ok(0x7860_7800
        | super::aarch64_reg(index, 16)?
        | super::aarch64_reg(base, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_load_x(destination: u8, base: u8, byte_offset: u16) -> Result<u32, ObjectError> {
    if !byte_offset.is_multiple_of(8) {
        return Err(ObjectError::InvalidModule(
            "AArch64 context X load offset is not aligned",
        ));
    }
    let scaled = u32::from(byte_offset / 8);
    if scaled > 0x0fff {
        return Err(ObjectError::InvalidModule(
            "AArch64 context X load offset is out of range",
        ));
    }
    Ok(0xf940_0000
        | (scaled << 10)
        | super::aarch64_reg(base, 5)?
        | super::aarch64_reg(destination, 0)?)
}

fn aarch64_context_emit_valid(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.branch_bit_clear_w(8, 30, invalid)?;
    Ok(())
}

fn aarch64_context_emit_class_at(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    position: u8,
    destination: u8,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_load_byte_reg(destination, 0, position)?)?;
    let table = if destination == 12 { 15 } else { 12 };
    aarch64_set_table_address(assembler, table, layout.byte_classes_offset)?;
    assembler.instruction(aarch64_load_byte_reg(destination, table, destination)?)?;
    Ok(())
}

fn aarch64_context_emit_property_at(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    position: u8,
    destination: u8,
) -> Result<(), ObjectError> {
    aarch64_context_emit_class_at(assembler, layout, position, destination)?;
    let table = if destination == 12 { 15 } else { 12 };
    aarch64_set_table_address(assembler, table, layout.class_properties_offset)?;
    assembler.instruction(aarch64_load_byte_reg(destination, table, destination)?)?;
    Ok(())
}

fn aarch64_context_emit_forward_flags(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    aarch64_set_table_address(assembler, 12, layout.forward_state_flags_offset)?;
    assembler.instruction(aarch64_load_byte_reg(8, 12, 6)?)?;
    Ok(())
}

fn aarch64_context_emit_anchored_forward_flags(
    assembler: &mut Aarch64Assembler,
    anchored: ContextAnchoredForwardLayout,
) -> Result<(), ObjectError> {
    aarch64_set_table_address(assembler, 12, anchored.state_flags_offset)?;
    assembler.instruction(aarch64_load_byte_reg(8, 12, 6)?)?;
    Ok(())
}

fn aarch64_context_emit_anchored_initial_map(
    assembler: &mut Aarch64Assembler,
    anchored: ContextAnchoredForwardLayout,
    invalid: usize,
) -> Result<(), ObjectError> {
    aarch64_set_table_address(assembler, 12, anchored.main_initial_to_anchored_offset)?;
    assembler.instruction(aarch64_context_load_w_lsl2(8, 12, 6)?)?;
    aarch64_load_u32_constant(assembler, 11, u32::MAX)?;
    assembler.instruction(aarch64_cmp_x(8, 11)?)?;
    assembler.branch_cond(AARCH64_EQ, invalid)?;
    aarch64_load_u32_constant(assembler, 11, anchored.states)?;
    assembler.instruction(aarch64_cmp_x(8, 11)?)?;
    assembler.branch_cond(AARCH64_HS, invalid)?;
    assembler.instruction(aarch64_mov_x(6, 8)?)?;
    aarch64_context_emit_anchored_forward_flags(assembler, anchored)
}

fn aarch64_context_emit_raw_forward_valid(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.branch_bit_clear_w(8, 14, invalid)?;
    Ok(())
}

fn aarch64_context_emit_raw_reverse_valid(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.branch_bit_clear_w(8, 14, invalid)?;
    Ok(())
}

fn aarch64_context_emit_decode_raw_forward(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_context_and_low_w(6, 8, 14)?)?;
    assembler.branch_zero_w(6, invalid)?;
    assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    Ok(())
}

fn aarch64_context_emit_raw_initial_lookup(
    assembler: &mut Aarch64Assembler,
    table_offset: u32,
) -> Result<(), ObjectError> {
    aarch64_set_table_address(assembler, 12, table_offset)?;
    assembler.instruction(aarch64_context_load_h_lsl1(8, 12, 8)?)?;
    Ok(())
}

fn aarch64_context_emit_raw_forward_initial(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    raw: ContextRawPairInitialLayout,
    invalid: usize,
) -> Result<(), ObjectError> {
    let absolute_start = assembler.label()?;
    let empty_haystack = assembler.label()?;
    let absolute_end = assembler.label()?;
    let loaded = assembler.label()?;

    assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, absolute_start)?;
    assembler.instruction(aarch64_cmp_x(2, 1)?)?;
    assembler.branch_cond(AARCH64_EQ, absolute_end)?;
    assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
    // Supported AArch64 targets are little-endian: previous | current<<8.
    assembler.instruction(aarch64_load_halfword_reg(8, 0, 11)?)?;
    aarch64_context_emit_raw_initial_lookup(assembler, layout.forward_initial_offset)?;
    assembler.branch(loaded)?;

    assembler.bind(absolute_start)?;
    assembler.instruction(aarch64_cmp_x_imm(1, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, empty_haystack)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
    aarch64_context_emit_raw_initial_lookup(assembler, raw.forward_start_offset)?;
    assembler.branch(loaded)?;
    assembler.bind(empty_haystack)?;
    assembler.instruction(aarch64_movz_w(8, 256)?)?;
    aarch64_context_emit_raw_initial_lookup(assembler, raw.forward_start_offset)?;
    assembler.branch(loaded)?;

    assembler.bind(absolute_end)?;
    assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 11)?)?;
    aarch64_context_emit_raw_initial_lookup(assembler, raw.forward_end_offset)?;
    assembler.bind(loaded)?;
    aarch64_context_emit_raw_forward_valid(assembler, invalid)?;
    aarch64_context_emit_decode_raw_forward(assembler, invalid)?;
    aarch64_context_emit_forward_flags(assembler, layout)?;
    Ok(())
}

fn aarch64_context_emit_decode_raw_reverse_payload(
    assembler: &mut Aarch64Assembler,
) -> Result<(), ObjectError> {
    // Reverse payloads remain state+1. Zero is a valid dead frontier and must
    // reach the ordinary reverse-loop termination check unchanged.
    assembler.instruction(aarch64_context_and_low_w(6, 8, 14)?)?;
    Ok(())
}

/// Load one raw reverse cell for the full-haystack boundary in x2.
///
/// All `AArch64` reverse CFGs retain the complete haystack length in x1. The
/// cell remains in w8 for the caller's explicit bit-15 event test.
fn aarch64_context_emit_raw_reverse_initial(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    raw: ContextRawPairReverseInitialLayout,
    invalid: usize,
) -> Result<(), ObjectError> {
    let reverse_pairs = layout
        .reverse_initial_offset
        .ok_or(ObjectError::InvalidModule(
            "context raw reverse dispatch has no pair table",
        ))?;
    let absolute_start = assembler.label()?;
    let empty_haystack = assembler.label()?;
    let absolute_end = assembler.label()?;
    let loaded = assembler.label()?;

    assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, absolute_start)?;
    assembler.instruction(aarch64_cmp_x(2, 1)?)?;
    assembler.branch_cond(AARCH64_EQ, absolute_end)?;
    assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
    assembler.instruction(aarch64_load_halfword_reg(8, 0, 11)?)?;
    aarch64_context_emit_raw_initial_lookup(assembler, reverse_pairs)?;
    assembler.branch(loaded)?;

    assembler.bind(absolute_start)?;
    assembler.instruction(aarch64_cmp_x_imm(1, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, empty_haystack)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
    aarch64_context_emit_raw_initial_lookup(assembler, raw.reverse_start_offset)?;
    assembler.branch(loaded)?;
    assembler.bind(empty_haystack)?;
    assembler.instruction(aarch64_movz_w(8, 256)?)?;
    aarch64_context_emit_raw_initial_lookup(assembler, raw.reverse_start_offset)?;
    assembler.branch(loaded)?;

    assembler.bind(absolute_end)?;
    assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, 11)?)?;
    aarch64_context_emit_raw_initial_lookup(assembler, raw.reverse_end_offset)?;
    assembler.bind(loaded)?;
    aarch64_context_emit_raw_reverse_valid(assembler, invalid)
}

fn aarch64_context_emit_decode_forward_checked(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_context_and_low_w(6, 8, 30)?)?;
    assembler.branch_zero_w(6, invalid)?;
    assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    Ok(())
}

fn aarch64_context_emit_populated_transition_valid_mode(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
    trust: bool,
) -> Result<(), ObjectError> {
    if trust {
        Ok(())
    } else {
        aarch64_context_emit_valid(assembler, invalid)
    }
}

fn aarch64_context_emit_decode_populated_forward_transition_mode(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
    trust: bool,
) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_mov_x(12, 8)?)?; // preserve event bit
    assembler.instruction(aarch64_context_and_low_w(6, 8, 28)?)?;
    if !trust {
        assembler.branch_zero_w(6, invalid)?;
    }
    assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    assembler.instruction(aarch64_lsr_x_imm(8, 8, CONTEXT_FORWARD_CELL_FLAGS_SHIFT)?)?;
    Ok(())
}

fn aarch64_context_emit_clear_result(assembler: &mut Aarch64Assembler) -> Result<(), ObjectError> {
    assembler.instruction(aarch64_movz_w(8, 0)?)?;
    assembler.instruction(aarch64_store_x(8, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(8, 4, 8)?)?;
    Ok(())
}

fn aarch64_context_emit_prepass_restart(
    assembler: &mut Aarch64Assembler,
    restart: ContextPrepassRestart,
) -> Result<(), ObjectError> {
    match restart {
        ContextPrepassRestart::CandidateBase | ContextPrepassRestart::Bounded(0) => {
            assembler.instruction(aarch64_mov_x(9, 2)?)?;
            assembler.instruction(aarch64_store_x(2, 4, 0)?)?;
        }
        ContextPrepassRestart::OriginalStart => {
            assembler.instruction(aarch64_mov_x(2, 9)?)?;
        }
        ContextPrepassRestart::Bounded(maximum) => {
            let keep_original = assembler.label()?;
            let selected = assembler.label()?;
            aarch64_load_u32_constant(assembler, 11, maximum)?;
            assembler.instruction(aarch64_cmp_x(2, 11)?)?;
            assembler.branch_cond(AARCH64_LS, keep_original)?;
            assembler.instruction(aarch64_sub_x_reg(12, 2, 11)?)?;
            assembler.instruction(aarch64_cmp_x(12, 9)?)?;
            assembler.branch_cond(AARCH64_LO, keep_original)?;
            assembler.instruction(aarch64_mov_x(2, 12)?)?;
            assembler.branch(selected)?;
            assembler.bind(keep_original)?;
            assembler.instruction(aarch64_mov_x(2, 9)?)?;
            assembler.bind(selected)?;
            assembler.instruction(aarch64_mov_x(9, 2)?)?;
            assembler.instruction(aarch64_store_x(2, 4, 0)?)?;
        }
    }
    Ok(())
}

fn aarch64_context_emit_reject_empty_prefix_candidate(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    rejected: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    if let Some(raw) = layout.raw_pair_initial {
        let absolute_start = assembler.label()?;
        let loaded = assembler.label()?;
        assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
        assembler.branch_cond(AARCH64_EQ, absolute_start)?;
        assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
        // The previous byte may be outside the search window but remains in
        // the complete haystack and therefore participates in assertions.
        assembler.instruction(aarch64_load_halfword_reg(8, 0, 11)?)?;
        aarch64_context_emit_raw_initial_lookup(assembler, layout.forward_initial_offset)?;
        assembler.branch(loaded)?;
        assembler.bind(absolute_start)?;
        assembler.instruction(aarch64_load_byte_reg(8, 0, 2)?)?;
        aarch64_context_emit_raw_initial_lookup(assembler, raw.forward_start_offset)?;
        assembler.bind(loaded)?;
        aarch64_context_emit_raw_forward_valid(assembler, invalid)?;
        assembler.branch_bit_set_w(8, 15, rejected)?;
        aarch64_context_emit_decode_raw_forward(assembler, invalid)?;
        aarch64_context_emit_forward_flags(assembler, layout)?;
        return Ok(());
    }
    let no_before = assembler.label()?;
    let key_ready = assembler.label()?;

    // A selected prefix base is strictly before x3, and x3 is bounded by the
    // complete haystack length. Its current-class key is therefore never the
    // sentinel and never absolute-end.
    aarch64_context_emit_class_at(assembler, layout, 2, 8)?;
    assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, no_before)?;
    assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
    aarch64_context_emit_property_at(assembler, layout, 11, 11)?;
    assembler.instruction(aarch64_context_lsl_w(11, 11, 9)?)?;
    assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
    aarch64_load_u32_constant(assembler, 11, 1 << 13)?;
    assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
    assembler.branch(key_ready)?;
    assembler.bind(no_before)?;
    aarch64_load_u32_constant(assembler, 11, 1 << 14)?;
    assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
    assembler.bind(key_ready)?;

    aarch64_context_emit_dispatch(assembler, layout.forward_initial_offset)?;
    aarch64_context_emit_valid(assembler, invalid)?;
    assembler.branch_bit_set_w(8, 31, invalid)?;
    aarch64_context_emit_decode_forward_checked(assembler, invalid)?;
    aarch64_context_emit_forward_flags(assembler, layout)?;
    assembler.branch_bit_set_w(8, 2, rejected)?;
    Ok(())
}

fn aarch64_context_emit_known_span_start_tag(
    assembler: &mut Aarch64Assembler,
    guard: ContextKnownSpanStartGuard,
) -> Result<(), ObjectError> {
    if guard.accepts_all_bytes && guard.accepts_haystack_end {
        assembler.instruction(aarch64_movz_w(10, 1)?)?;
        return Ok(());
    }
    let tag = assembler.label()?;
    let done = assembler.label()?;
    assembler.instruction(aarch64_add_x_imm(11, 2, u16::from(guard.guarded_bytes))?)?;
    assembler.instruction(aarch64_cmp_x(11, 1)?)?;
    assembler.branch_cond(
        AARCH64_EQ,
        if guard.accepts_haystack_end {
            tag
        } else {
            done
        },
    )?;
    assembler.branch_cond(AARCH64_HI, done)?;
    if guard.accepts_all_bytes {
        assembler.branch(tag)?;
    } else if guard.accepts_any_byte {
        let filter = guard.following_filter.ok_or(ObjectError::InvalidModule(
            "context known-start partial byte set has no filter",
        ))?;
        for &predicate in filter.predicates() {
            aarch64_emit_prefix_predicate(assembler, predicate, done)?;
        }
        assembler.branch(tag)?;
    } else {
        assembler.branch(done)?;
    }
    assembler.bind(tag)?;
    assembler.instruction(aarch64_movz_w(10, 1)?)?;
    assembler.bind(done)?;
    Ok(())
}

fn aarch64_context_emit_anchored_position_charge(
    assembler: &mut Aarch64Assembler,
    guard: ContextAnchoredAdaptiveGuard,
    debt: u16,
    fallback: usize,
) -> Result<(), ObjectError> {
    // x17 is fixed-point debt and x2 is the current semantic candidate.
    assembler.instruction(aarch64_add_x_imm(17, 17, debt)?)?;
    assembler.instruction(aarch64_add_x_imm(12, 2, guard.initial_credit)?)?;
    assembler.instruction(aarch64_cmp_x(17, 12)?)?;
    let admitted = assembler.label()?;
    assembler.branch_cond(AARCH64_LS, admitted)?;
    assembler.instruction(aarch64_store_x(2, 4, 0)?)?;
    assembler.branch(fallback)?;
    assembler.bind(admitted)?;
    Ok(())
}

fn aarch64_context_emit_anchored_candidate_charge(
    assembler: &mut Aarch64Assembler,
    guard: ContextAnchoredAdaptiveGuard,
    fallback: usize,
) -> Result<(), ObjectError> {
    aarch64_context_emit_anchored_position_charge(assembler, guard, guard.candidate_debt, fallback)
}

fn aarch64_context_emit_anchored_transition_reserve(
    assembler: &mut Aarch64Assembler,
    search: ContextAnchoredForwardSearch,
    guard: ContextAnchoredAdaptiveGuard,
    fallback: usize,
) -> Result<(), ObjectError> {
    let shift = context_anchored_transition_shift(guard)?;
    let _maximum_reserve = context_anchored_transition_reserve(search, guard)?;

    // Convert the allowance left after candidate admission to whole verifier
    // transitions, clamp it to the structural cap, then precharge that exact
    // affordable prefix once.
    assembler.instruction(aarch64_add_x_imm(12, 2, guard.initial_credit)?)?;
    assembler.instruction(aarch64_sub_x_reg(12, 12, 17)?)?;
    if shift != 0 {
        assembler.instruction(aarch64_lsr_x_imm(12, 12, shift)?)?;
    }
    assembler.instruction(aarch64_movz_w(10, u16::from(search.max_verify_bytes))?)?;
    assembler.instruction(aarch64_cmp_x(12, 10)?)?;
    assembler.instruction(aarch64_csel_x(10, 12, 10, AARCH64_LO)?)?;
    assembler.branch_zero_w(10, fallback)?;
    assembler.instruction(aarch64_context_add_x_lsl(17, 17, 10, shift)?)?;
    Ok(())
}

fn aarch64_context_emit_anchored_transition_refund(
    assembler: &mut Aarch64Assembler,
    guard: ContextAnchoredAdaptiveGuard,
) -> Result<(), ObjectError> {
    let shift = context_anchored_transition_shift(guard)?;
    assembler.instruction(aarch64_context_sub_x_lsl(17, 17, 10, shift)?)?;
    Ok(())
}

fn aarch64_context_emit_adaptive_vector_hit_dispatch(
    assembler: &mut Aarch64Assembler,
    anchored_guard: Option<(ContextAnchoredAdaptiveGuard, usize)>,
    scalar: usize,
) -> Result<(), ObjectError> {
    if let Some((guard, fallback)) = anchored_guard {
        // The final vector-test flags are live on entry. Account for every
        // block sent to scalar refinement, even if its coarse hit is rejected
        // before the scalar scanner reaches an exact candidate. x2 is the
        // block base and is therefore a conservative fallback resume point.
        let no_hit = assembler.label()?;
        assembler.branch_cond(AARCH64_EQ, no_hit)?;
        aarch64_context_emit_anchored_position_charge(
            assembler,
            guard,
            guard.vector_debt,
            fallback,
        )?;
        assembler.branch(scalar)?;
        assembler.bind(no_hit)?;
    } else {
        // Preserve the ordinary scanner's exact code shape.
        assembler.branch_cond(AARCH64_NE, scalar)?;
    }
    Ok(())
}

fn aarch64_emit_context_scanner_constants(
    assembler: &mut Aarch64Assembler,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
) -> Result<(), ObjectError> {
    let mut first_register = if vector_filter.is_some() {
        AARCH64_VECTOR_FILTER_FIRST_CONSTANT
    } else {
        AARCH64_STANDALONE_FILTER_FIRST_CONSTANT
    };
    for filter in context_scanner_constant_filters(primary, vector_filter) {
        aarch64_emit_start_filter_constants(assembler, filter, first_register)?;
        first_register = first_register
            .checked_add(u8::try_from(filter.constant_count()).map_err(|_| {
                ObjectError::ArithmeticOverflow("AArch64 context scanner constants")
            })?)
            .ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 context scanner constants",
            ))?;
    }
    Ok(())
}

fn aarch64_emit_context_pair_expression_constants(
    assembler: &mut Aarch64Assembler,
    expression: ContextBoundaryPairExpression,
) -> Result<(), ObjectError> {
    let mut emitted = [false; 7];
    for rectangle in expression.plan.rectangles() {
        for predicate in [rectangle.first, rectangle.second] {
            if predicate.any
                || (!expression.transient_constants
                    && predicate.first_constant <= expression.scanner_constant_count)
            {
                continue;
            }
            let first = usize::from(predicate.first_constant);
            let marker = emitted.get_mut(first).ok_or(ObjectError::InvalidModule(
                "AArch64 context pair constant escaped its budget",
            ))?;
            if *marker {
                continue;
            }
            for (index, range) in predicate.filter.ranges().iter().enumerate() {
                if predicate.filter.is_exact() {
                    let register =
                        aarch64_prefix_relation_constant_register(predicate.first_constant, index)?;
                    assembler.instruction(aarch64_movi_16b(register, range.start)?)?;
                } else {
                    let logical_low = index.checked_mul(2).ok_or(
                        ObjectError::ArithmeticOverflow("AArch64 context pair range constant"),
                    )?;
                    let logical_high =
                        logical_low
                            .checked_add(1)
                            .ok_or(ObjectError::ArithmeticOverflow(
                                "AArch64 context pair range constant",
                            ))?;
                    let low = aarch64_prefix_relation_constant_register(
                        predicate.first_constant,
                        logical_low,
                    )?;
                    let high = aarch64_prefix_relation_constant_register(
                        predicate.first_constant,
                        logical_high,
                    )?;
                    assembler.instruction(aarch64_movi_16b(low, range.start)?)?;
                    assembler.instruction(aarch64_movi_16b(high, range.end)?)?;
                }
            }
            *marker = true;
        }
    }
    Ok(())
}

fn aarch64_emit_boundary_pair_expression_candidates(
    assembler: &mut Aarch64Assembler,
    expression: ContextBoundaryPairExpression,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
) -> Result<(), ObjectError> {
    // Preserve the exact current-byte base mask while the relation emitter
    // computes its independent rectangle union in V24.
    assembler.instruction(aarch64_orr_16b(23, 24, 24)?)?;
    if expression.transient_constants {
        aarch64_emit_context_pair_expression_constants(assembler, expression)?;
    }
    // Predicate offsets zero and one become previous and current after this
    // temporary semantic-base shift. x2 retains the candidate position on
    // every emitted resume edge.
    assembler.instruction(aarch64_sub_x_imm(2, 2, 1)?)?;
    aarch64_emit_prefix_relation_vector_test(assembler, expression.plan)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.instruction(super::aarch64_and_16b(24, 24, 23)?)?;
    if expression.restore_scanner_constants {
        aarch64_emit_context_scanner_constants(assembler, primary, vector_filter)?;
    }
    aarch64_emit_candidate_any(assembler, 24)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the emitter receives explicit filters, CFG labels, and restart policy"
)]
fn aarch64_context_emit_scalar_prefix_prepass(
    assembler: &mut Aarch64Assembler,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    prefix_filter: Option<NativePrefixFilter>,
    guarded_bytes: Option<u8>,
    known_span_start: Option<ContextKnownSpanStartGuard>,
    restart: ContextPrepassRestart,
    reject_empty_with: Option<(&ContextNativeLayout, Option<usize>)>,
    anchored_guard: Option<(ContextAnchoredAdaptiveGuard, usize)>,
    no_match: usize,
    invalid: usize,
    candidate_retry: Option<usize>,
    scalar_miss_retry: Option<usize>,
    vector_candidate: usize,
) -> Result<(), ObjectError> {
    if primary.ranges().is_empty() {
        assembler.branch(no_match)?;
        return Ok(());
    }
    let scan = assembler.label()?;
    let scalar_miss = assembler.label()?;
    let candidate_rejected = assembler.label()?;
    let done = assembler.label()?;
    let maximum_offset =
        vector_filter.map_or(primary.scan_offset, NativeVectorFilter::max_scan_offset);
    assembler.bind(scan)?;
    aarch64_emit_start_filter_scalar_bound(assembler, maximum_offset, no_match)?;
    if let Some(filter) = vector_filter {
        for &column in filter.columns() {
            aarch64_emit_scalar_filter_membership(assembler, column, scalar_miss)?;
        }
    } else {
        aarch64_emit_scalar_filter_membership(assembler, primary, scalar_miss)?;
    }
    assembler.bind(vector_candidate)?;
    if let Some((guard, fallback)) = anchored_guard {
        aarch64_context_emit_anchored_candidate_charge(assembler, guard, fallback)?;
    }
    if let Some(guarded_bytes) = guarded_bytes {
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x_imm(12, u16::from(guarded_bytes))?)?;
        assembler.branch_cond(AARCH64_LO, candidate_rejected)?;
        if let Some(filter) = prefix_filter {
            for &predicate in filter.predicates() {
                aarch64_emit_prefix_predicate(assembler, predicate, candidate_rejected)?;
            }
        }
    }
    if let Some((layout, _)) = reject_empty_with {
        aarch64_context_emit_reject_empty_prefix_candidate(
            assembler,
            layout,
            candidate_rejected,
            invalid,
        )?;
    }
    aarch64_context_emit_prepass_restart(assembler, restart)?;
    // Scalar bitmap predicates use x10 as membership scratch. Span later
    // interprets w10 == 1 as an exact-start tag, so every ordinary prefix
    // candidate must clear that scratch before an optional proof sets it.
    assembler.instruction(aarch64_movz_w(10, 0)?)?;
    if let Some(guard) = known_span_start {
        aarch64_context_emit_known_span_start_tag(assembler, guard)?;
    }
    if known_span_start.is_some()
        && let Some((layout, Some(_))) = reject_empty_with
    {
        // Optional predicates may use w8. Dispatch reuse enters the common
        // initial block with the exact state flags live in w8.
        aarch64_context_emit_forward_flags(assembler, layout)?;
    }
    if let Some((_, Some(initialized))) = reject_empty_with {
        assembler.branch(initialized)?;
    } else {
        assembler.branch(done)?;
    }
    assembler.bind(candidate_rejected)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(candidate_retry.unwrap_or(scan))?;
    assembler.bind(scalar_miss)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(scalar_miss_retry.unwrap_or(scan))?;
    assembler.bind(done)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the ASIMD/scalar prepass is one register-sensitive emitted CFG"
)]
fn aarch64_context_emit_prefix_prepass(
    assembler: &mut Aarch64Assembler,
    primary: NativeStartFilter,
    vector_filter: Option<NativeVectorFilter>,
    boundary_pair: Option<ContextBoundaryPairExpression>,
    prefix_filter: Option<NativePrefixFilter>,
    guarded_bytes: Option<u8>,
    known_span_start: Option<ContextKnownSpanStartGuard>,
    restart: ContextPrepassRestart,
    reject_empty_with: Option<(&ContextNativeLayout, Option<usize>)>,
    anchored_guard: Option<(ContextAnchoredAdaptiveGuard, usize)>,
    sve_filter_kind: Option<Aarch64SveFilterKind>,
    use_asimd: bool,
    use_exact_asimd_lane: bool,
    no_match: usize,
    invalid: usize,
    vector_entry: Option<usize>,
) -> Result<(), ObjectError> {
    let selected_sve = sve_filter_kind.filter(|_| {
        vector_filter.is_none() && boundary_pair.is_none() && !primary.ranges().is_empty()
    });
    if let Some(selected_sve) = selected_sve
        && use_asimd
    {
        // A mixed-capability module keeps both graph-equivalent lowerings.
        // Re-enter through this width dispatch after external context routes;
        // route-private retries stay on the already selected invariant path.
        let dispatch = match vector_entry {
            Some(label) => label,
            None => assembler.label()?,
        };
        let sve_entry = assembler.label()?;
        let asimd_setup = assembler.label()?;
        let joined = assembler.label()?;
        assembler.bind(dispatch)?;
        assembler.instruction(aarch64_sve_cntb(6)?)?;
        assembler.instruction(aarch64_cmp_x_imm(6, 16)?)?;
        assembler.branch_cond(AARCH64_LS, asimd_setup)?;
        aarch64_context_emit_prefix_prepass(
            assembler,
            primary,
            vector_filter,
            boundary_pair,
            prefix_filter,
            guarded_bytes,
            known_span_start,
            restart,
            reject_empty_with,
            anchored_guard,
            Some(selected_sve),
            false,
            use_exact_asimd_lane,
            no_match,
            invalid,
            Some(sve_entry),
        )?;
        assembler.branch(joined)?;
        assembler.bind(asimd_setup)?;
        // No external entry is passed here: the ASIMD core must materialize
        // its constants by fallthrough before binding its route-private loop.
        aarch64_context_emit_prefix_prepass(
            assembler,
            primary,
            vector_filter,
            boundary_pair,
            prefix_filter,
            guarded_bytes,
            known_span_start,
            restart,
            reject_empty_with,
            anchored_guard,
            None,
            true,
            use_exact_asimd_lane,
            no_match,
            invalid,
            None,
        )?;
        assembler.bind(joined)?;
        return Ok(());
    }
    let vector_candidate = assembler.label()?;
    if let Some(sve_filter_kind) = selected_sve {
        let vector = match vector_entry {
            Some(label) => label,
            None => assembler.label()?,
        };
        let scalar = assembler.label()?;
        aarch64_emit_sve_start_filter_scanner(
            assembler,
            primary,
            primary.scan_offset,
            sve_filter_kind,
            vector,
            scalar,
            vector_candidate,
        )?;
        assembler.bind(scalar)?;
        return aarch64_context_emit_scalar_prefix_prepass(
            assembler,
            primary,
            vector_filter,
            prefix_filter,
            guarded_bytes,
            known_span_start,
            restart,
            reject_empty_with,
            anchored_guard,
            no_match,
            invalid,
            Some(vector),
            None,
            vector_candidate,
        );
    }
    if !use_asimd || primary.ranges().is_empty() {
        if let Some(entry) = vector_entry {
            assembler.bind(entry)?;
        }
        return aarch64_context_emit_scalar_prefix_prepass(
            assembler,
            primary,
            vector_filter,
            prefix_filter,
            guarded_bytes,
            known_span_start,
            restart,
            reject_empty_with,
            anchored_guard,
            no_match,
            invalid,
            vector_entry,
            None,
            vector_candidate,
        );
    }
    let vector = match vector_entry {
        Some(label) => label,
        None => assembler.label()?,
    };
    let single_vector = assembler.label()?;
    let scalar = assembler.label()?;
    let use_batch = primary.candidate_bytes <= 4 && boundary_pair.is_none();
    let batch_primary_hit = if use_batch && vector_filter.is_some() {
        Some(assembler.label()?)
    } else {
        None
    };
    let single_primary_hit = vector_filter.map(|_| assembler.label()).transpose()?;
    let single_pair_hit = boundary_pair.map(|_| assembler.label()).transpose()?;
    let batch_hit = (use_batch && use_exact_asimd_lane)
        .then(|| assembler.label())
        .transpose()?;
    let single_hit = use_exact_asimd_lane
        .then(|| assembler.label())
        .transpose()?;
    let mut batch_first_candidates = None;
    aarch64_emit_context_scanner_constants(assembler, primary, vector_filter)?;
    if let Some(expression) = boundary_pair.filter(|pair| !pair.transient_constants) {
        aarch64_emit_context_pair_expression_constants(assembler, expression)?;
    }
    assembler.bind(vector)?;
    if boundary_pair.is_some() {
        assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
        assembler.branch_cond(AARCH64_EQ, scalar)?;
    }
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    let maximum_offset =
        vector_filter.map_or(primary.scan_offset, NativeVectorFilter::max_scan_offset);
    if use_batch {
        let batch_required =
            u16::from(maximum_offset)
                .checked_add(64)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 context prefix batch bound",
                ))?;
        assembler.instruction(aarch64_cmp_x_imm(12, batch_required)?)?;
        assembler.branch_cond(AARCH64_LO, single_vector)?;
        let first_register = if vector_filter.is_some() {
            AARCH64_VECTOR_FILTER_FIRST_CONSTANT
        } else {
            AARCH64_STANDALONE_FILTER_FIRST_CONSTANT
        };
        let first_candidates =
            aarch64_emit_start_filter_batch_candidates(assembler, primary, first_register)?;
        batch_first_candidates = Some(first_candidates);
        aarch64_emit_candidate_batch_any(assembler, first_candidates)?;
        if let Some(primary_hit) = batch_primary_hit {
            // The secondary vector columns decide whether this block needs
            // scalar refinement, so defer adaptive accounting until then.
            assembler.branch_cond(AARCH64_NE, primary_hit)?;
        } else {
            aarch64_context_emit_adaptive_vector_hit_dispatch(
                assembler,
                anchored_guard,
                batch_hit.unwrap_or(scalar),
            )?;
        }
        assembler.instruction(aarch64_add_x_imm(2, 2, 64)?)?;
        assembler.branch(vector)?;
    }

    assembler.bind(single_vector)?;
    let required =
        u16::from(maximum_offset)
            .checked_add(16)
            .ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 context prefix vector bound",
            ))?;
    assembler.instruction(aarch64_cmp_x_imm(12, required)?)?;
    assembler.branch_cond(AARCH64_LO, scalar)?;
    aarch64_emit_start_filter_address(assembler, primary.scan_offset)?;
    assembler.instruction(aarch64_load_q(0, 12)?)?;
    if vector_filter.is_some() {
        aarch64_emit_start_filter_vector_candidates(
            assembler,
            primary,
            0,
            24,
            AARCH64_VECTOR_FILTER_FIRST_CONSTANT,
        )?;
        aarch64_emit_candidate_any(assembler, 24)?;
        assembler.branch_cond(
            AARCH64_NE,
            single_primary_hit.ok_or(ObjectError::InvalidModule(
                "AArch64 context vector filter has no primary-hit label",
            ))?,
        )?;
    } else {
        aarch64_emit_start_filter_vector_candidates(
            assembler,
            primary,
            0,
            24,
            AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
        )?;
        aarch64_emit_candidate_any(assembler, 24)?;
        aarch64_context_emit_adaptive_vector_hit_dispatch(
            assembler,
            anchored_guard,
            single_pair_hit.or(single_hit).unwrap_or(scalar),
        )?;
    }
    assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
    assembler.branch(vector)?;

    if let (Some(filter), Some(primary_hit)) = (vector_filter, batch_primary_hit) {
        assembler.bind(primary_hit)?;
        if let Some((guard, fallback)) = anchored_guard {
            aarch64_context_emit_anchored_position_charge(
                assembler,
                guard,
                guard.vector_debt,
                fallback,
            )?;
        }
        aarch64_emit_vector_filter_secondary_batch(assembler, filter)?;
        aarch64_emit_candidate_batch_any(assembler, 24)?;
        assembler.branch_cond(AARCH64_NE, batch_hit.unwrap_or(scalar))?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 64)?)?;
        assembler.branch(vector)?;
    }

    if let (Some(filter), Some(primary_hit)) = (vector_filter, single_primary_hit) {
        assembler.bind(primary_hit)?;
        if let Some((guard, fallback)) = anchored_guard {
            aarch64_context_emit_anchored_position_charge(
                assembler,
                guard,
                guard.vector_debt,
                fallback,
            )?;
        }
        aarch64_emit_vector_filter_secondary_candidates_at(assembler, filter, 0, 24)?;
        aarch64_emit_candidate_any(assembler, 24)?;
        assembler.branch_cond(AARCH64_NE, single_pair_hit.or(single_hit).unwrap_or(scalar))?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(vector)?;
    }

    if let (Some(pair), Some(pair_hit)) = (boundary_pair, single_pair_hit) {
        assembler.bind(pair_hit)?;
        aarch64_emit_boundary_pair_expression_candidates(assembler, pair, primary, vector_filter)?;
        assembler.branch_cond(AARCH64_NE, single_hit.unwrap_or(scalar))?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(vector)?;
    }

    if let Some(batch_hit) = batch_hit {
        assembler.bind(batch_hit)?;
        let first_candidates = batch_first_candidates.ok_or(ObjectError::InvalidModule(
            "AArch64 context batch hit has no candidate masks",
        ))?;
        aarch64_emit_first_candidate_in_batch(assembler, first_candidates)?;
        assembler.branch(vector_candidate)?;
    }
    if let Some(single_hit) = single_hit {
        assembler.bind(single_hit)?;
        aarch64_emit_first_candidate_lane(assembler, 24)?;
        assembler.branch(vector_candidate)?;
    }

    assembler.bind(scalar)?;
    aarch64_context_emit_scalar_prefix_prepass(
        assembler,
        primary,
        vector_filter,
        prefix_filter,
        guarded_bytes,
        known_span_start,
        restart,
        reject_empty_with,
        anchored_guard,
        no_match,
        invalid,
        Some(vector),
        boundary_pair.map(|_| vector),
        vector_candidate,
    )
}

fn aarch64_context_emit_exists_suffix_reverse(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    minimum_width: u8,
    resume: usize,
    matched: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    let reverse_initial = layout
        .reverse_initial_offset
        .ok_or(ObjectError::InvalidModule(
            "context Exists suffix has no reverse dispatch",
        ))?;
    let before_sentinel = assembler.label()?;
    let before_ready = assembler.label()?;
    let no_current = assembler.label()?;
    let not_absolute_start = assembler.label()?;
    let not_absolute_end = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let failed = assembler.label()?;

    // x13 is the row-width scratch in aarch64_context_emit_row_cell; keep the
    // suffix base in x17 across an arbitrarily long reverse traversal.
    assembler.instruction(aarch64_mov_x(17, 2)?)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, u16::from(minimum_width))?)?;
    if let Some(raw) = layout.raw_pair_reverse_initial {
        aarch64_context_emit_raw_reverse_initial(assembler, layout, raw, invalid)?;
        assembler.branch_bit_set_w(8, 15, matched)?;
        aarch64_context_emit_decode_raw_reverse_payload(assembler)?;
    } else {
        assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
        assembler.branch_cond(AARCH64_EQ, before_sentinel)?;
        assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
        aarch64_context_emit_class_at(assembler, layout, 11, 8)?;
        assembler.branch(before_ready)?;
        assembler.bind(before_sentinel)?;
        assembler.instruction(aarch64_mov_x(8, 14)?)?;
        assembler.bind(before_ready)?;
        assembler.instruction(aarch64_cmp_x(2, 1)?)?;
        assembler.branch_cond(AARCH64_EQ, no_current)?;
        aarch64_context_emit_property_at(assembler, layout, 2, 11)?;
        assembler.instruction(aarch64_context_lsl_w(11, 11, 9)?)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        aarch64_load_u32_constant(assembler, 11, 1 << 13)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(no_current)?;
        assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
        assembler.branch_cond(AARCH64_NE, not_absolute_start)?;
        aarch64_load_u32_constant(assembler, 11, 1 << 14)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(not_absolute_start)?;
        assembler.instruction(aarch64_cmp_x(2, 1)?)?;
        assembler.branch_cond(AARCH64_NE, not_absolute_end)?;
        aarch64_load_u32_constant(assembler, 11, 1 << 15)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(not_absolute_end)?;
        aarch64_context_emit_dispatch(assembler, reverse_initial)?;
        aarch64_context_emit_valid(assembler, invalid)?;
        assembler.branch_bit_set_w(8, 31, matched)?;
        assembler.instruction(aarch64_context_and_low_w(6, 8, 30)?)?;
    }

    aarch64_context_pin_reverse_direct_tables(assembler, layout)?;
    assembler.bind(reverse_loop)?;
    assembler.instruction(aarch64_cmp_x(2, 9)?)?;
    assembler.branch_cond(AARCH64_LS, failed)?;
    assembler.branch_zero_w(6, failed)?;
    assembler.instruction(aarch64_sub_x_imm(2, 2, 1)?)?;
    aarch64_context_emit_reverse_transition_cell(assembler, layout)?;
    aarch64_context_emit_populated_transition_valid_mode(
        assembler,
        invalid,
        ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
    )?;
    assembler.instruction(aarch64_context_and_low_w(6, 8, 30)?)?;
    assembler.branch_bit_set_w(8, 31, matched)?;
    assembler.branch(reverse_loop)?;

    assembler.bind(failed)?;
    assembler.instruction(aarch64_add_x_imm(2, 17, 1)?)?;
    assembler.branch(resume)?;
    Ok(())
}

fn aarch64_context_emit_ordered_suffix_update_best(
    assembler: &mut Aarch64Assembler,
    complete: usize,
) -> Result<(), ObjectError> {
    let unchanged = assembler.label()?;
    assembler.instruction(aarch64_context_load_x(11, 4, 8)?)?;
    assembler.instruction(aarch64_cmp_x(2, 11)?)?;
    assembler.branch_cond(AARCH64_HS, unchanged)?;
    assembler.instruction(aarch64_store_x(2, 4, 8)?)?;
    assembler.bind(unchanged)?;
    assembler.instruction(aarch64_cmp_x(2, 9)?)?;
    assembler.branch_cond(AARCH64_EQ, complete)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the reverse ordered-output verifier is one register-sensitive emitted CFG"
)]
fn aarch64_context_emit_ordered_suffix_reverse(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    minimum_width: u8,
    resume: usize,
    complete: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    let reverse_initial = layout
        .reverse_initial_offset
        .ok_or(ObjectError::InvalidModule(
            "context ordered suffix has no reverse dispatch",
        ))?;
    let before_sentinel = assembler.label()?;
    let before_ready = assembler.label()?;
    let no_current = assembler.label()?;
    let not_absolute_start = assembler.label()?;
    let not_absolute_end = assembler.label()?;
    let no_initial_event = assembler.label()?;
    let initial_event = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let event = assembler.label()?;
    let finished = assembler.label()?;

    assembler.instruction(aarch64_mov_x(17, 2)?)?; // suffix base
    assembler.instruction(aarch64_add_x_imm(2, 2, u16::from(minimum_width))?)?;
    if let Some(raw) = layout.raw_pair_reverse_initial {
        aarch64_context_emit_raw_reverse_initial(assembler, layout, raw, invalid)?;
        let no_raw_initial_event = assembler.label()?;
        assembler.branch_bit_clear_w(8, 15, no_raw_initial_event)?;
        aarch64_context_emit_ordered_suffix_update_best(assembler, complete)?;
        assembler.bind(no_raw_initial_event)?;
        aarch64_context_emit_decode_raw_reverse_payload(assembler)?;
    } else {
        assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
        assembler.branch_cond(AARCH64_EQ, before_sentinel)?;
        assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
        aarch64_context_emit_class_at(assembler, layout, 11, 8)?;
        assembler.branch(before_ready)?;
        assembler.bind(before_sentinel)?;
        assembler.instruction(aarch64_mov_x(8, 14)?)?;
        assembler.bind(before_ready)?;
        assembler.instruction(aarch64_cmp_x(2, 1)?)?;
        assembler.branch_cond(AARCH64_EQ, no_current)?;
        aarch64_context_emit_property_at(assembler, layout, 2, 11)?;
        assembler.instruction(aarch64_context_lsl_w(11, 11, 9)?)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        aarch64_load_u32_constant(assembler, 11, 1 << 13)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(no_current)?;
        assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
        assembler.branch_cond(AARCH64_NE, not_absolute_start)?;
        aarch64_load_u32_constant(assembler, 11, 1 << 14)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(not_absolute_start)?;
        assembler.instruction(aarch64_cmp_x(2, 1)?)?;
        assembler.branch_cond(AARCH64_NE, not_absolute_end)?;
        aarch64_load_u32_constant(assembler, 11, 1 << 15)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(not_absolute_end)?;
        aarch64_context_emit_dispatch(assembler, reverse_initial)?;
        aarch64_context_emit_valid(assembler, invalid)?;
        assembler.branch_bit_set_w(8, 31, initial_event)?;
        assembler.branch(no_initial_event)?;
        assembler.bind(initial_event)?;
        aarch64_context_emit_ordered_suffix_update_best(assembler, complete)?;
        assembler.bind(no_initial_event)?;
        assembler.instruction(aarch64_context_and_low_w(6, 8, 30)?)?;
    }

    aarch64_context_pin_reverse_direct_tables(assembler, layout)?;
    assembler.bind(reverse_loop)?;
    assembler.instruction(aarch64_cmp_x(2, 9)?)?;
    assembler.branch_cond(AARCH64_LS, finished)?;
    assembler.branch_zero_w(6, finished)?;
    assembler.instruction(aarch64_sub_x_imm(2, 2, 1)?)?;
    aarch64_context_emit_reverse_transition_cell(assembler, layout)?;
    aarch64_context_emit_populated_transition_valid_mode(
        assembler,
        invalid,
        ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
    )?;
    assembler.instruction(aarch64_context_and_low_w(6, 8, 30)?)?;
    assembler.branch_bit_set_w(8, 31, event)?;
    assembler.branch(reverse_loop)?;

    assembler.bind(event)?;
    aarch64_context_emit_ordered_suffix_update_best(assembler, complete)?;
    assembler.branch(reverse_loop)?;

    assembler.bind(finished)?;
    assembler.instruction(aarch64_add_x_imm(2, 17, 1)?)?;
    assembler.branch(resume)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct Aarch64TerminalSuffixScannerLabels {
    vector: usize,
    single_vector: usize,
    scalar: usize,
    scalar_reject: usize,
    batch_primary_hit: usize,
    single_primary_hit: usize,
    batch_hit: usize,
    single_hit: usize,
    verify: usize,
}

fn aarch64_terminal_suffix_scanner_labels(
    assembler: &mut Aarch64Assembler,
) -> Result<Aarch64TerminalSuffixScannerLabels, ObjectError> {
    Ok(Aarch64TerminalSuffixScannerLabels {
        vector: assembler.label()?,
        single_vector: assembler.label()?,
        scalar: assembler.label()?,
        scalar_reject: assembler.label()?,
        batch_primary_hit: assembler.label()?,
        single_primary_hit: assembler.label()?,
        batch_hit: assembler.label()?,
        single_hit: assembler.label()?,
        verify: assembler.label()?,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the shared initial/budgeted suffix scanner is one emitted CFG"
)]
fn aarch64_context_emit_terminal_suffix_scanner(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    suffix: ContextTerminalSuffixSearch,
    required_offset: u8,
    labels: Aarch64TerminalSuffixScannerLabels,
    use_exact_asimd_lane: bool,
    exhausted: usize,
) -> Result<(), ObjectError> {
    assembler.bind(labels.vector)?;
    if matches!(
        layout.output,
        OutputContract::SelectedEnd | OutputContract::Span
    ) && let Some(distance) = suffix.bounded_scan_distance
    {
        let no_best = assembler.label()?;
        assembler.instruction(aarch64_context_load_x(8, 4, 8)?)?;
        assembler.instruction(aarch64_cmp_x(8, 7)?)?;
        assembler.branch_cond(AARCH64_EQ, no_best)?;
        assembler.instruction(aarch64_sub_x_reg(12, 2, 8)?)?;
        aarch64_load_u32_constant(assembler, 11, distance)?;
        assembler.instruction(aarch64_cmp_x(12, 11)?)?;
        assembler.branch_cond(AARCH64_HS, exhausted)?;
        assembler.bind(no_best)?;
    }
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    let batch_required =
        u16::from(required_offset)
            .checked_add(64)
            .ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 context suffix batch bound",
            ))?;
    assembler.instruction(aarch64_cmp_x_imm(12, batch_required)?)?;
    assembler.branch_cond(AARCH64_LO, labels.single_vector)?;
    let primary_candidates =
        aarch64_emit_start_filter_batch_candidates(assembler, suffix.primary, 1)?;
    aarch64_emit_candidate_batch_any(assembler, primary_candidates)?;
    assembler.branch_cond(AARCH64_NE, labels.batch_primary_hit)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 64)?)?;
    assembler.branch(labels.vector)?;

    assembler.bind(labels.batch_primary_hit)?;
    aarch64_emit_vector_filter_secondary_batch(assembler, suffix.vector_filter)?;
    aarch64_emit_candidate_batch_any(assembler, 24)?;
    assembler.branch_cond(
        AARCH64_NE,
        if use_exact_asimd_lane {
            labels.batch_hit
        } else {
            labels.scalar
        },
    )?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 64)?)?;
    assembler.branch(labels.vector)?;

    assembler.bind(labels.single_vector)?;
    let single_required =
        u16::from(required_offset)
            .checked_add(16)
            .ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 context suffix vector bound",
            ))?;
    assembler.instruction(aarch64_cmp_x_imm(12, single_required)?)?;
    assembler.branch_cond(AARCH64_LO, labels.scalar)?;
    aarch64_emit_start_filter_address(assembler, suffix.primary.scan_offset)?;
    assembler.instruction(aarch64_load_q(0, 12)?)?;
    aarch64_emit_start_filter_vector_candidates(assembler, suffix.primary, 0, 24, 1)?;
    aarch64_emit_candidate_any(assembler, 24)?;
    assembler.branch_cond(AARCH64_NE, labels.single_primary_hit)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
    assembler.branch(labels.vector)?;

    assembler.bind(labels.single_primary_hit)?;
    aarch64_emit_vector_filter_secondary_candidates_at(assembler, suffix.vector_filter, 0, 24)?;
    aarch64_emit_candidate_any(assembler, 24)?;
    assembler.branch_cond(
        AARCH64_NE,
        if use_exact_asimd_lane {
            labels.single_hit
        } else {
            labels.scalar
        },
    )?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
    assembler.branch(labels.vector)?;

    assembler.bind(labels.batch_hit)?;
    if use_exact_asimd_lane {
        aarch64_emit_first_candidate_in_batch(assembler, primary_candidates)?;
        assembler.branch(labels.verify)?;
    } else {
        assembler.branch(labels.scalar)?;
    }
    assembler.bind(labels.single_hit)?;
    if use_exact_asimd_lane {
        aarch64_emit_first_candidate_lane(assembler, 24)?;
        assembler.branch(labels.verify)?;
    } else {
        assembler.branch(labels.scalar)?;
    }

    assembler.bind(labels.scalar)?;
    aarch64_emit_start_filter_scalar_bound(assembler, required_offset, exhausted)?;
    for &column in suffix.vector_filter.columns() {
        aarch64_emit_scalar_filter_membership(assembler, column, labels.scalar_reject)?;
    }
    assembler.branch(labels.verify)?;
    assembler.bind(labels.scalar_reject)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(labels.vector)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "suffix scanning, verification, and replay share one emitted control-flow graph"
)]
fn aarch64_context_emit_terminal_suffix_search(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    suffix: ContextTerminalSuffixSearch,
    use_exact_asimd_lane: bool,
    no_match: usize,
    matched: usize,
    invalid: usize,
    prepass_entry: usize,
    forward_entry: usize,
) -> Result<(), ObjectError> {
    let scanner = aarch64_terminal_suffix_scanner_labels(assembler)?;
    let ordered_output = matches!(
        layout.output,
        OutputContract::SelectedEnd | OutputContract::Span
    );
    let exhausted = if ordered_output {
        assembler.label()?
    } else {
        no_match
    };
    if ordered_output {
        let scan = assembler.label()?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        assembler.instruction(aarch64_cmp_x_imm(
            12,
            u16::try_from(CONTEXT_ORDERED_SUFFIX_MIN_WINDOW_BYTES).unwrap(),
        )?)?;
        assembler.branch_cond(AARCH64_HS, scan)?;
        assembler.branch(prepass_entry)?;
        assembler.bind(scan)?;
    }
    let mut first_register = AARCH64_VECTOR_FILTER_FIRST_CONSTANT;
    for &column in suffix.vector_filter.columns() {
        aarch64_emit_start_filter_constants(assembler, column, first_register)?;
        first_register =
            first_register
                .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                    ObjectError::ArithmeticOverflow("AArch64 context suffix constants")
                })?)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 context suffix constants",
                ))?;
    }
    let required_offset = suffix
        .vector_filter
        .max_scan_offset()
        .max(suffix.minimum_width.saturating_sub(1));

    aarch64_context_emit_terminal_suffix_scanner(
        assembler,
        layout,
        suffix,
        required_offset,
        scanner,
        use_exact_asimd_lane,
        exhausted,
    )?;

    assembler.bind(scanner.verify)?;
    match layout.output {
        OutputContract::Exists => {
            let verified_match = assembler.label()?;
            aarch64_context_emit_exists_suffix_reverse(
                assembler,
                layout,
                suffix.minimum_width,
                scanner.vector,
                verified_match,
                invalid,
            )?;
            assembler.bind(verified_match)?;
            aarch64_context_emit_clear_result(assembler)?;
            assembler.branch(matched)?;
        }
        OutputContract::SelectedEnd | OutputContract::Span => {
            aarch64_context_emit_ordered_suffix_reverse(
                assembler,
                layout,
                suffix.minimum_width,
                scanner.vector,
                exhausted,
                invalid,
            )?;
            assembler.bind(exhausted)?;
            assembler.instruction(aarch64_context_load_x(8, 4, 8)?)?;
            assembler.instruction(aarch64_cmp_x(8, 7)?)?;
            assembler.branch_cond(AARCH64_EQ, no_match)?;
            assembler.instruction(aarch64_mov_x(2, 8)?)?;
            assembler.instruction(aarch64_mov_x(9, 8)?)?;
            assembler.instruction(aarch64_store_x(8, 4, 0)?)?;
            assembler.instruction(aarch64_store_x(7, 4, 8)?)?;
            assembler.instruction(aarch64_movz_w(
                10,
                u16::from(layout.output == OutputContract::Span && ENABLE_CONTEXT_KNOWN_SPAN_START),
            )?)?; // exact start tag
            assembler.branch(forward_entry)?;
        }
    }

    Ok(())
}

fn aarch64_context_emit_state_skip(
    assembler: &mut Aarch64Assembler,
    skip: ContextStateSkip,
    use_asimd: bool,
    scalar_step: usize,
) -> Result<(), ObjectError> {
    let landing = assembler.label()?;
    let replay = matches!(skip.membership, ContextStateMembership::Table { .. });
    if replay {
        assembler.instruction(aarch64_mov_x(11, 2)?)?;
    }
    let Some(filter) = skip.exit_filter else {
        assembler.instruction(aarch64_sub_x_imm(2, 3, 1)?)?;
        assembler.branch(landing)?;
        assembler.bind(landing)?;
        if !replay {
            assembler.branch(scalar_step)?;
            return Ok(());
        }
        assembler.instruction(aarch64_cmp_x(2, 11)?)?;
        assembler.branch_cond(AARCH64_EQ, scalar_step)?;
        assembler.instruction(aarch64_sub_x_imm(2, 2, 1)?)?;
        aarch64_load_u32_constant(assembler, 6, skip.canonical_state)?;
        assembler.branch(scalar_step)?;
        return Ok(());
    };
    let vector = assembler.label()?;
    let scalar = assembler.label()?;
    let rejected = assembler.label()?;
    let exhausted = assembler.label()?;
    if use_asimd {
        let first_register = AARCH64_STANDALONE_FILTER_FIRST_CONSTANT;
        aarch64_emit_start_filter_constants(assembler, filter, first_register)?;
        assembler.bind(vector)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        let required = u16::from(filter.scan_offset).checked_add(16).ok_or(
            ObjectError::ArithmeticOverflow("AArch64 context state-skip vector bound"),
        )?;
        assembler.instruction(aarch64_cmp_x_imm(12, required)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(assembler, filter.scan_offset)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        aarch64_emit_start_filter_vector_test(assembler, filter, 0, 24)?;
        assembler.branch_cond(AARCH64_NE, scalar)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(vector)?;
    } else {
        assembler.branch(scalar)?;
    }
    assembler.bind(scalar)?;
    aarch64_emit_start_filter_scalar_bound(assembler, filter.scan_offset, exhausted)?;
    aarch64_emit_scalar_filter_membership(assembler, filter, rejected)?;
    assembler.branch(landing)?;
    assembler.bind(rejected)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(scalar)?;
    assembler.bind(exhausted)?;
    assembler.instruction(aarch64_sub_x_imm(2, 3, 1)?)?;
    assembler.bind(landing)?;
    if !replay {
        assembler.branch(scalar_step)?;
        return Ok(());
    }
    assembler.instruction(aarch64_cmp_x(2, 11)?)?;
    assembler.branch_cond(AARCH64_EQ, scalar_step)?;
    assembler.instruction(aarch64_sub_x_imm(2, 2, 1)?)?;
    aarch64_load_u32_constant(assembler, 6, skip.canonical_state)?;
    assembler.branch(scalar_step)?;
    Ok(())
}

fn aarch64_context_emit_row_cell(
    assembler: &mut Aarch64Assembler,
    table_offset: u32,
    state: u8,
    symbol: u8,
    row_width: u16,
) -> Result<(), ObjectError> {
    aarch64_set_table_address(assembler, 15, table_offset)?;
    aarch64_load_u32_constant(assembler, 13, u32::from(row_width))?;
    assembler.instruction(aarch64_context_mul_x(16, state, 13)?)?;
    assembler.instruction(aarch64_add_x_reg(16, 16, symbol)?)?;
    assembler.instruction(aarch64_context_load_w_lsl2(8, 15, 16)?)?;
    Ok(())
}

fn aarch64_context_emit_direct_byte_cell(
    assembler: &mut Aarch64Assembler,
    state: u8,
    byte: u8,
) -> Result<(), ObjectError> {
    // x15 is pinned to the 256-cell rows for the duration of this loop.
    assembler.instruction(aarch64_context_add_x_lsl(16, byte, state, 8)?)?;
    assembler.instruction(aarch64_context_load_w_lsl2(8, 15, 16)?)?;
    Ok(())
}

fn aarch64_context_emit_direct_sentinel_cell(
    assembler: &mut Aarch64Assembler,
    state: u8,
) -> Result<(), ObjectError> {
    // x13 is pinned to one absolute-boundary cell per state.
    assembler.instruction(aarch64_context_load_w_lsl2(8, 13, state)?)?;
    Ok(())
}

fn aarch64_context_pin_forward_direct_tables(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    if let Some(sentinel) = layout.forward_byte_sentinel_offset {
        aarch64_set_table_address(assembler, 15, layout.forward_cells_offset)?;
        aarch64_set_table_address(assembler, 13, sentinel)?;
    }
    Ok(())
}

fn aarch64_context_pin_anchored_forward_direct_tables(
    assembler: &mut Aarch64Assembler,
    anchored: ContextAnchoredForwardLayout,
) -> Result<(), ObjectError> {
    if let Some(sentinel) = anchored.byte_sentinel_offset {
        aarch64_set_table_address(assembler, 15, anchored.cells_offset)?;
        aarch64_set_table_address(assembler, 13, sentinel)?;
    }
    Ok(())
}

fn aarch64_context_pin_reverse_direct_tables(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    if let Some(sentinel) = layout.reverse_byte_sentinel_offset {
        let cells = layout
            .reverse_cells_offset
            .ok_or(ObjectError::InvalidModule(
                "context direct-byte reverse transition has no rows",
            ))?;
        aarch64_set_table_address(assembler, 15, cells)?;
        aarch64_set_table_address(assembler, 13, sentinel)?;
    }
    Ok(())
}

fn aarch64_context_emit_forward_transition_cell_at(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    cells_offset: u32,
    byte_sentinel_offset: Option<u32>,
) -> Result<(), ObjectError> {
    let sentinel = assembler.label()?;
    let ready = assembler.label()?;
    assembler.instruction(aarch64_cmp_x(2, 1)?)?;
    assembler.branch_cond(AARCH64_EQ, sentinel)?;
    if byte_sentinel_offset.is_some() {
        assembler.instruction(aarch64_load_byte_reg(11, 0, 2)?)?;
        aarch64_context_emit_direct_byte_cell(assembler, 6, 11)?;
        assembler.branch(ready)?;
        assembler.bind(sentinel)?;
        aarch64_context_emit_direct_sentinel_cell(assembler, 6)?;
    } else {
        aarch64_context_emit_class_at(assembler, layout, 2, 11)?;
        aarch64_context_emit_row_cell(assembler, cells_offset, 6, 11, layout.row_width)?;
        assembler.branch(ready)?;
        assembler.bind(sentinel)?;
        assembler.instruction(aarch64_mov_x(11, 14)?)?;
        aarch64_context_emit_row_cell(assembler, cells_offset, 6, 11, layout.row_width)?;
    }
    assembler.bind(ready)?;
    Ok(())
}

fn aarch64_context_emit_forward_transition_cell(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    aarch64_context_emit_forward_transition_cell_at(
        assembler,
        layout,
        layout.forward_cells_offset,
        layout.forward_byte_sentinel_offset,
    )
}

fn aarch64_context_emit_anchored_forward_transition_cell(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    anchored: ContextAnchoredForwardLayout,
) -> Result<(), ObjectError> {
    aarch64_context_emit_forward_transition_cell_at(
        assembler,
        layout,
        anchored.cells_offset,
        anchored.byte_sentinel_offset,
    )
}

fn aarch64_context_emit_reverse_transition_cell(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
) -> Result<(), ObjectError> {
    let reverse_cells = layout
        .reverse_cells_offset
        .ok_or(ObjectError::InvalidModule(
            "context reverse transition has no rows",
        ))?;
    let sentinel = assembler.label()?;
    let ready = assembler.label()?;
    if layout.reverse_byte_sentinel_offset.is_some() {
        assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    }
    assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, sentinel)?;
    assembler.instruction(aarch64_sub_x_imm(12, 2, 1)?)?;
    if layout.reverse_byte_sentinel_offset.is_some() {
        assembler.instruction(aarch64_load_byte_reg(12, 0, 12)?)?;
        aarch64_context_emit_direct_byte_cell(assembler, 6, 12)?;
        assembler.branch(ready)?;
        assembler.bind(sentinel)?;
        aarch64_context_emit_direct_sentinel_cell(assembler, 6)?;
    } else {
        aarch64_context_emit_class_at(assembler, layout, 12, 12)?;
        assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
        aarch64_context_emit_row_cell(assembler, reverse_cells, 6, 12, layout.row_width)?;
        assembler.branch(ready)?;
        assembler.bind(sentinel)?;
        assembler.instruction(aarch64_mov_x(12, 14)?)?;
        assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
        aarch64_context_emit_row_cell(assembler, reverse_cells, 6, 12, layout.row_width)?;
    }
    assembler.bind(ready)?;
    Ok(())
}

fn aarch64_context_emit_dispatch(
    assembler: &mut Aarch64Assembler,
    table_offset: u32,
) -> Result<(), ObjectError> {
    aarch64_set_table_address(assembler, 15, table_offset)?;
    assembler.instruction(aarch64_context_load_w_lsl2(8, 15, 8)?)?;
    Ok(())
}

/// `AArch64` exact-start counterpart to the x86 sidecar CFG. x17 carries
/// fixed-point cumulative debt and w10 carries the per-candidate transition
/// cap; no platform-reserved register is used.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "candidate scanning, exact dispatch, bounded verification, and one-shot fallback form one CFG"
)]
fn aarch64_context_emit_anchored_forward_search(
    assembler: &mut Aarch64Assembler,
    layout: &ContextNativeLayout,
    search: ContextAnchoredForwardSearch,
    adaptive_guard: ContextAnchoredAdaptiveGuard,
    prefix_filter: Option<NativePrefixFilter>,
    boundary_pair: Option<ContextBoundaryPairExpression>,
    sve_filter_kind: Option<Aarch64SveFilterKind>,
    use_asimd: bool,
    use_exact_asimd_lane: bool,
    no_match: usize,
    matched: usize,
    invalid: usize,
    forward_entry: usize,
) -> Result<(), ObjectError> {
    let anchored = layout.anchored_forward.ok_or(ObjectError::InvalidModule(
        "context anchored search has no physical sidecar",
    ))?;
    let scan = assembler.label()?;
    let verify_loop = assembler.label()?;
    let event = assembler.label()?;
    let no_event = assembler.label()?;
    let resolved = assembler.label()?;
    let rejected = assembler.label()?;
    let resume_scan = assembler.label()?;
    let fallback = assembler.label()?;

    aarch64_context_emit_prefix_prepass(
        assembler,
        search.primary,
        search.vector_filter,
        boundary_pair,
        prefix_filter,
        Some(search.guarded_bytes),
        None,
        ContextPrepassRestart::CandidateBase,
        Some((layout, None)),
        Some((adaptive_guard, fallback)),
        sve_filter_kind,
        use_asimd,
        use_exact_asimd_lane,
        no_match,
        invalid,
        Some(scan),
    )?;

    // The exact main initial dispatch is already in x6; translate it to the
    // restart-free sidecar and reject impossible nullable/empty initials.
    aarch64_context_emit_anchored_initial_map(assembler, anchored, invalid)?;
    assembler.branch_bit_set_w(8, 0, invalid)?;
    assembler.branch_bit_set_w(8, 2, resume_scan)?;
    assembler.instruction(aarch64_store_x(7, 4, 8)?)?;

    // Reserve every whole verifier transition currently affordable, up to the
    // graph-derived cap. w10 retains the unconsumed transition count.
    aarch64_context_emit_anchored_transition_reserve(assembler, search, adaptive_guard, fallback)?;
    aarch64_context_pin_anchored_forward_direct_tables(assembler, anchored)?;

    assembler.bind(verify_loop)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    aarch64_context_emit_anchored_forward_transition_cell(assembler, layout, anchored)?;
    aarch64_context_emit_decode_populated_forward_transition_mode(
        assembler,
        invalid,
        ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
    )?;
    assembler.instruction(aarch64_sub_w_imm(10, 10, 1)?)?;
    assembler.branch_bit_set_w(12, 31, event)?;
    assembler.branch(no_event)?;
    assembler.bind(event)?;
    assembler.instruction(aarch64_store_x(2, 4, 8)?)?;
    assembler.bind(no_event)?;

    assembler.branch_bit_set_w(8, 1, resolved)?;
    assembler.branch_bit_set_w(8, 2, rejected)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, resolved)?;
    assembler.branch_zero_w(10, fallback)?;
    assembler.branch(verify_loop)?;

    assembler.bind(resolved)?;
    assembler.instruction(aarch64_context_load_x(8, 4, 8)?)?;
    assembler.instruction(aarch64_cmp_x(8, 7)?)?;
    assembler.branch_cond(AARCH64_EQ, rejected)?;
    if layout.output == OutputContract::SelectedEnd {
        assembler.instruction(aarch64_store_x(8, 4, 0)?)?;
    }
    assembler.branch(matched)?;

    assembler.bind(rejected)?;
    aarch64_context_emit_anchored_transition_refund(assembler, adaptive_guard)?;
    assembler.bind(resume_scan)?;
    assembler.instruction(aarch64_context_load_x(2, 4, 0)?)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.instruction(aarch64_store_x(7, 4, 8)?)?;
    assembler.branch(scan)?;

    assembler.bind(fallback)?;
    assembler.instruction(aarch64_context_load_x(2, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(2, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(7, 4, 8)?)?;
    assembler.instruction(aarch64_mov_x(9, 2)?)?;
    assembler.instruction(aarch64_movz_w(10, 0)?)?;
    assembler.branch(forward_entry)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the leaf ABI, forward selection and reverse reconstruction are one auditable CFG"
)]
fn lower_aarch64_context(
    layout: &ContextNativeLayout,
    terminal_suffix_search: Option<ContextTerminalSuffixSearch>,
    anchored_forward_search: Option<ContextAnchoredForwardSearch>,
    anchored_adaptive_guard: Option<ContextAnchoredAdaptiveGuard>,
    anchored_prefix_filter: Option<NativePrefixFilter>,
    anchored_boundary_pair: Option<ContextBoundaryPairExpression>,
    start_filter: Option<NativeStartFilter>,
    vector_filter: Option<NativeVectorFilter>,
    ordinary_boundary_pair: Option<ContextBoundaryPairExpression>,
    prefix_filter: Option<NativePrefixFilter>,
    prefix_fast_forward: Option<ContextPrefixFastForward>,
    known_span_start: Option<ContextKnownSpanStartGuard>,
    interior_guard: Option<ContextInteriorGuard>,
    state_skip: Option<ContextStateSkip>,
    empty_prefix_restart: bool,
    features: FeatureSet,
    operating_system: super::OperatingSystem,
    asimd_lane_index_offset: Option<u32>,
    sve2_match_tables: ContextSve2MatchTables,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>), ObjectError> {
    let mut assembler = Aarch64Assembler::new();
    let current_sentinel = assembler.label()?;
    let current_ready = assembler.label()?;
    let no_before = assembler.label()?;
    let before_ready = assembler.label()?;
    let not_absolute_start = assembler.label()?;
    let not_absolute_end = assembler.label()?;
    let initial_not_pending = assembler.label()?;
    let forward_loop = assembler.label()?;
    let forward_scalar_step = assembler.label()?;
    let forward_no_event = assembler.label()?;
    let forward_finish = assembler.label()?;
    let span_not_initial = assembler.label()?;
    let reverse_before_sentinel = assembler.label()?;
    let reverse_before_ready = assembler.label()?;
    let reverse_no_current = assembler.label()?;
    let reverse_not_absolute_start = assembler.label()?;
    let reverse_not_absolute_end = assembler.label()?;
    let reverse_no_initial_event = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let reverse_no_event = assembler.label()?;
    let reverse_finish = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid_initialized = assembler.label()?;
    let invalid_input = assembler.label()?;
    let done = assembler.label()?;
    let prepass_entry = assembler.label()?;
    let forward_entry = assembler.label()?;
    let forward_initialized = assembler.label()?;
    let anchored_prefix_scan = if start_filter.is_some() && empty_prefix_restart {
        Some(assembler.label()?)
    } else {
        None
    };
    let anchored_accelerated_fallback =
        if anchored_forward_search.is_some() && start_filter.is_some() {
            Some(assembler.label()?)
        } else {
            None
        };

    // Validate before touching output.
    assembler.instruction(aarch64_cmp_x_imm(1, 0)?)?;
    assembler.branch_cond(AARCH64_MI, invalid_input)?;
    assembler.instruction(aarch64_cmp_x(3, 1)?)?;
    assembler.branch_cond(AARCH64_HI, invalid_input)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HI, invalid_input)?;
    assembler.instruction(aarch64_cmp_x_imm(4, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, invalid_input)?;
    assembler.instruction(aarch64_context_and_low_w(8, 4, 3)?)?;
    assembler.branch_nonzero_w(8, invalid_input)?;
    assembler.instruction(aarch64_cmp_x_imm(0, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, invalid_input)?;

    if anchored_forward_search.is_some() {
        assembler.instruction(aarch64_mov_x(17, 2)?)?; // debt origin = window start
    }

    assembler.instruction(aarch64_store_x(2, 4, 0)?)?; // original start
    assembler.instruction(0x9280_0007)?; // movn x7, #0
    assembler.instruction(aarch64_store_x(7, 4, 8)?)?;
    assembler.instruction(aarch64_mov_x(9, 2)?)?;
    assembler.instruction(aarch64_movz_w(10, 0)?)?;

    let table_page = assembler.instruction(0x9000_0005)?;
    let table_page_offset = assembler.instruction(0x9100_00a5)?;
    aarch64_load_u32_constant(&mut assembler, 14, u32::from(layout.class_count))?;

    // ASIMD remains available for route shapes that SVE cannot lower and for
    // independent suffix kernels. The explicit mixed policy chooses SVE only
    // inside each supported primary prepass.
    let use_asimd = features.has(CpuFeature::Aarch64Asimd);
    let use_sve = aarch64_primary_scanner_uses_sve(aarch64_primary_scanner_isa(
        operating_system,
        features,
        true,
    ));
    let sve_filter_kind = |match_table_offset: Option<u32>| {
        use_sve.then(|| match match_table_offset {
            Some(match_table_offset) => Aarch64SveFilterKind::Sve2 { match_table_offset },
            None => Aarch64SveFilterKind::Sve,
        })
    };
    let use_exact_asimd_lane = asimd_lane_index_offset.is_some();
    if let Some(offset) = asimd_lane_index_offset {
        aarch64_emit_first_lane_constants(&mut assembler, offset)?;
    }
    if let Some(suffix) = terminal_suffix_search {
        aarch64_context_emit_terminal_suffix_search(
            &mut assembler,
            layout,
            suffix,
            use_exact_asimd_lane,
            no_match,
            matched,
            invalid_initialized,
            prepass_entry,
            forward_entry,
        )?;
    }
    assembler.bind(prepass_entry)?;
    if let Some(guard) = interior_guard {
        aarch64_context_emit_prefix_prepass(
            &mut assembler,
            guard.primary,
            guard.vector_filter,
            None,
            None,
            None,
            None,
            guard.restart,
            None,
            None,
            sve_filter_kind(sve2_match_tables.interior),
            use_asimd,
            use_exact_asimd_lane,
            no_match,
            invalid_initialized,
            None,
        )?;
    }
    if let Some(search) = anchored_forward_search {
        let adaptive_guard = anchored_adaptive_guard.ok_or(ObjectError::InvalidModule(
            "context anchored search has no adaptive guard",
        ))?;
        aarch64_context_emit_anchored_forward_search(
            &mut assembler,
            layout,
            search,
            adaptive_guard,
            anchored_prefix_filter,
            anchored_boundary_pair,
            sve_filter_kind(sve2_match_tables.anchored),
            use_asimd,
            use_exact_asimd_lane,
            no_match,
            matched,
            invalid_initialized,
            anchored_accelerated_fallback.unwrap_or(forward_entry),
        )?;
    }
    if let Some(fallback) = anchored_accelerated_fallback {
        assembler.bind(fallback)?;
    }
    if let Some(filter) = start_filter {
        if let Some(prefix_scan) = anchored_prefix_scan {
            assembler.bind(prefix_scan)?;
        }
        aarch64_context_emit_prefix_prepass(
            &mut assembler,
            filter,
            vector_filter,
            ordinary_boundary_pair,
            prefix_filter,
            prefix_fast_forward
                .map(|plan| plan.guaranteed_bytes)
                .or(known_span_start.map(|guard| guard.guarded_bytes)),
            known_span_start,
            ContextPrepassRestart::CandidateBase,
            (empty_prefix_restart || known_span_start.is_some()).then_some((
                layout,
                ENABLE_CONTEXT_PREFIX_DISPATCH_REUSE.then_some(forward_initialized),
            )),
            None,
            sve_filter_kind(sve2_match_tables.ordinary),
            use_asimd,
            use_exact_asimd_lane,
            no_match,
            invalid_initialized,
            None,
        )?;
    }

    assembler.bind(forward_entry)?;
    if let Some(raw) = layout.raw_pair_initial {
        aarch64_context_emit_raw_forward_initial(&mut assembler, layout, raw, invalid_initialized)?;
    } else {
        // Forward context key in w8.
        assembler.instruction(aarch64_cmp_x(2, 1)?)?;
        assembler.branch_cond(AARCH64_EQ, current_sentinel)?;
        aarch64_context_emit_class_at(&mut assembler, layout, 2, 8)?;
        assembler.branch(current_ready)?;
        assembler.bind(current_sentinel)?;
        assembler.instruction(aarch64_mov_x(8, 14)?)?;
        assembler.bind(current_ready)?;
        assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
        assembler.branch_cond(AARCH64_EQ, no_before)?;
        assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
        aarch64_context_emit_property_at(&mut assembler, layout, 11, 11)?;
        assembler.instruction(aarch64_context_lsl_w(11, 11, 9)?)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        aarch64_load_u32_constant(&mut assembler, 11, 1 << 13)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.branch(before_ready)?;
        assembler.bind(no_before)?;
        aarch64_load_u32_constant(&mut assembler, 11, 1 << 14)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(before_ready)?;
        assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
        assembler.branch_cond(AARCH64_NE, not_absolute_start)?;
        aarch64_load_u32_constant(&mut assembler, 11, 1 << 14)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(not_absolute_start)?;
        assembler.instruction(aarch64_cmp_x(2, 1)?)?;
        assembler.branch_cond(AARCH64_NE, not_absolute_end)?;
        aarch64_load_u32_constant(&mut assembler, 11, 1 << 15)?;
        assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
        assembler.bind(not_absolute_end)?;
        aarch64_context_emit_dispatch(&mut assembler, layout.forward_initial_offset)?;
        aarch64_context_emit_valid(&mut assembler, invalid_initialized)?;
        assembler.branch_bit_set_w(8, 31, invalid_initialized)?;
        aarch64_context_emit_decode_forward_checked(&mut assembler, invalid_initialized)?;
        aarch64_context_emit_forward_flags(&mut assembler, layout)?;
    }
    assembler.bind(forward_initialized)?;
    assembler.branch_bit_clear_w(8, 0, initial_not_pending)?;
    assembler.instruction(aarch64_store_x(2, 4, 8)?)?;
    assembler.instruction(aarch64_movz_w(10, 1)?)?;
    if layout.output == OutputContract::Exists {
        assembler.branch(forward_finish)?;
    } else {
        assembler.branch_bit_set_w(8, 1, forward_finish)?;
    }
    assembler.bind(initial_not_pending)?;
    aarch64_context_pin_forward_direct_tables(&mut assembler, layout)?;

    if let Some(plan) = prefix_fast_forward {
        let ordinary = assembler.label()?;
        // Keep the masked flags live in w11 for the shared ordinary/reentry
        // block while folding its zero compare into CBNZ.
        assembler.instruction(aarch64_context_and_low_w(11, 8, 3)?)?;
        assembler.branch_nonzero_w(11, ordinary)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, u16::from(plan.consumed_bytes))?)?;
        aarch64_load_u32_constant(&mut assembler, 6, plan.target_state)?;
        assembler.branch(forward_loop)?;
        assembler.bind(ordinary)?;
    }

    assembler.bind(forward_loop)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HS, forward_finish)?;
    assembler.branch_bit_set_w(8, 1, forward_finish)?;
    if let Some(prefix_scan) = anchored_prefix_scan {
        let active = assembler.label()?;
        assembler.branch_bit_clear_w(8, 2, active)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.branch(prefix_scan)?;
        assembler.bind(active)?;
    }
    if let Some(skip) = state_skip {
        match skip.membership {
            ContextStateMembership::Singleton(state) => {
                aarch64_load_u32_constant(&mut assembler, 11, state)?;
                assembler.instruction(aarch64_cmp_x(6, 11)?)?;
                assembler.branch_cond(AARCH64_NE, forward_scalar_step)?;
            }
            ContextStateMembership::Table { offset } => {
                aarch64_set_table_address(&mut assembler, 12, offset)?;
                assembler.instruction(aarch64_load_byte_reg(11, 12, 6)?)?;
                assembler.branch_zero_w(11, forward_scalar_step)?;
            }
        }
        aarch64_context_emit_state_skip(
            &mut assembler,
            skip,
            features.has(CpuFeature::Aarch64Asimd),
            forward_scalar_step,
        )?;
    }
    assembler.bind(forward_scalar_step)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    aarch64_context_emit_forward_transition_cell(&mut assembler, layout)?;
    aarch64_context_emit_decode_populated_forward_transition_mode(
        &mut assembler,
        invalid_initialized,
        ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
    )?;
    assembler.branch_bit_set_w(12, 31, forward_no_event)?;
    assembler.branch(forward_loop)?;
    assembler.bind(forward_no_event)?;
    assembler.instruction(aarch64_store_x(2, 4, 8)?)?;
    if layout.output == OutputContract::Exists {
        assembler.branch(forward_finish)?;
    } else {
        assembler.branch(forward_loop)?;
    }

    assembler.bind(forward_finish)?;
    // Load pending as a full word with LDR X8, [x4,#8].
    assembler.instruction(0xf940_0488)?;
    assembler.instruction(aarch64_cmp_x(8, 7)?)?;
    assembler.branch_cond(AARCH64_EQ, no_match)?;
    match layout.output {
        OutputContract::Exists => {
            aarch64_context_emit_clear_result(&mut assembler)?;
            assembler.branch(matched)?;
        }
        OutputContract::SelectedEnd => {
            assembler.instruction(aarch64_store_x(8, 4, 0)?)?;
            assembler.branch(matched)?;
        }
        OutputContract::Span => {
            assembler.instruction(aarch64_cmp_w_imm(10, 1)?)?;
            assembler.branch_cond(AARCH64_NE, span_not_initial)?;
            assembler.instruction(aarch64_store_x(9, 4, 0)?)?;
            assembler.branch(matched)?;
            assembler.bind(span_not_initial)?;
            if let Some(width) = layout.exact_match_width {
                aarch64_load_u64_constant(&mut assembler, 11, width)?;
                assembler.instruction(aarch64_cmp_x(8, 11)?)?;
                assembler.branch_cond(AARCH64_LO, invalid_initialized)?;
                assembler.instruction(aarch64_sub_x_reg(11, 8, 11)?)?;
                assembler.instruction(aarch64_cmp_x(11, 9)?)?;
                assembler.branch_cond(AARCH64_LO, invalid_initialized)?;
                assembler.instruction(aarch64_store_x(11, 4, 0)?)?;
                assembler.branch(matched)?;
            } else {
                let reverse_initial =
                    layout
                        .reverse_initial_offset
                        .ok_or(ObjectError::InvalidModule(
                            "context span lowering has no reverse dispatch",
                        ))?;
                assembler.instruction(aarch64_mov_x(2, 8)?)?; // cursor
                assembler.instruction(0x9280_0011)?; // candidate x17 = -1
                if let Some(raw) = layout.raw_pair_reverse_initial {
                    aarch64_context_emit_raw_reverse_initial(
                        &mut assembler,
                        layout,
                        raw,
                        invalid_initialized,
                    )?;
                    let no_raw_initial_event = assembler.label()?;
                    assembler.branch_bit_clear_w(8, 15, no_raw_initial_event)?;
                    assembler.instruction(aarch64_mov_x(17, 2)?)?;
                    assembler.bind(no_raw_initial_event)?;
                    aarch64_context_emit_decode_raw_reverse_payload(&mut assembler)?;
                } else {
                    assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
                    assembler.branch_cond(AARCH64_EQ, reverse_before_sentinel)?;
                    assembler.instruction(aarch64_sub_x_imm(11, 2, 1)?)?;
                    aarch64_context_emit_class_at(&mut assembler, layout, 11, 8)?;
                    assembler.branch(reverse_before_ready)?;
                    assembler.bind(reverse_before_sentinel)?;
                    assembler.instruction(aarch64_mov_x(8, 14)?)?;
                    assembler.bind(reverse_before_ready)?;
                    assembler.instruction(aarch64_cmp_x(2, 1)?)?;
                    assembler.branch_cond(AARCH64_EQ, reverse_no_current)?;
                    aarch64_context_emit_property_at(&mut assembler, layout, 2, 11)?;
                    assembler.instruction(aarch64_context_lsl_w(11, 11, 9)?)?;
                    assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
                    aarch64_load_u32_constant(&mut assembler, 11, 1 << 13)?;
                    assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
                    assembler.bind(reverse_no_current)?;
                    assembler.instruction(aarch64_cmp_x_imm(2, 0)?)?;
                    assembler.branch_cond(AARCH64_NE, reverse_not_absolute_start)?;
                    aarch64_load_u32_constant(&mut assembler, 11, 1 << 14)?;
                    assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
                    assembler.bind(reverse_not_absolute_start)?;
                    assembler.instruction(aarch64_cmp_x(2, 1)?)?;
                    assembler.branch_cond(AARCH64_NE, reverse_not_absolute_end)?;
                    aarch64_load_u32_constant(&mut assembler, 11, 1 << 15)?;
                    assembler.instruction(aarch64_context_orr_w(8, 8, 11)?)?;
                    assembler.bind(reverse_not_absolute_end)?;
                    aarch64_context_emit_dispatch(&mut assembler, reverse_initial)?;
                    aarch64_context_emit_valid(&mut assembler, invalid_initialized)?;
                    let reverse_initial_decoded = assembler.label()?;
                    assembler.branch_bit_set_w(8, 31, reverse_no_initial_event)?;
                    assembler.branch(reverse_initial_decoded)?;
                    assembler.bind(reverse_no_initial_event)?;
                    assembler.instruction(aarch64_mov_x(17, 2)?)?;
                    assembler.bind(reverse_initial_decoded)?;
                    assembler.instruction(aarch64_context_and_low_w(6, 8, 30)?)?; // payload
                }
                aarch64_context_pin_reverse_direct_tables(&mut assembler, layout)?;
                assembler.bind(reverse_loop)?;
                assembler.instruction(aarch64_cmp_x(2, 9)?)?;
                assembler.branch_cond(AARCH64_LS, reverse_finish)?;
                assembler.branch_zero_w(6, reverse_finish)?;
                assembler.instruction(aarch64_sub_x_imm(2, 2, 1)?)?;
                aarch64_context_emit_reverse_transition_cell(&mut assembler, layout)?;
                aarch64_context_emit_populated_transition_valid_mode(
                    &mut assembler,
                    invalid_initialized,
                    ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS,
                )?;
                assembler.instruction(aarch64_context_and_low_w(6, 8, 30)?)?;
                assembler.branch_bit_set_w(8, 31, reverse_no_event)?;
                assembler.branch(reverse_loop)?;
                assembler.bind(reverse_no_event)?;
                assembler.instruction(aarch64_mov_x(17, 2)?)?;
                assembler.branch(reverse_loop)?;
                assembler.bind(reverse_finish)?;
                assembler.instruction(aarch64_cmp_x(17, 7)?)?;
                assembler.branch_cond(AARCH64_EQ, invalid_initialized)?;
                assembler.instruction(aarch64_store_x(17, 4, 0)?)?;
                assembler.branch(matched)?;
            }
        }
    }

    assembler.bind(no_match)?;
    aarch64_context_emit_clear_result(&mut assembler)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.branch(done)?;
    assembler.bind(matched)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.branch(done)?;
    assembler.bind(invalid_initialized)?;
    aarch64_context_emit_clear_result(&mut assembler)?;
    assembler.bind(invalid_input)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.bind(done)?;
    assembler.instruction(0xd65f_03c0)?;
    let code = assembler.finish()?;
    Ok((
        code,
        vec![
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(table_page, "AArch64 context ADRP relocation offset")?,
                kind: RelocationKind::Aarch64Page21,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
            ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(table_page_offset, "AArch64 context ADD relocation offset")?,
                kind: RelocationKind::Aarch64PageOff12,
                symbol: PROGRAM_SYMBOL,
                addend: 0,
            },
        ],
    ))
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;
    use std::{fs, process::Command};

    use super::*;
    use crate::{
        CompileMode, CompileRequest, MatchResult, ObjectFormat, SearchWindow, compile, emit_object,
    };

    fn singleton_set(byte: u8) -> AnchoredByteSet {
        let mut words = [0_u64; 4];
        let index = usize::from(byte);
        words[index / 64] |= 1_u64 << (index % 64);
        AnchoredByteSet::from_words(words)
    }

    fn anchored_guard_for(
        pattern: &str,
        target: Target,
    ) -> (
        ContextAnchoredForwardSearch,
        ContextAnchoredAdaptiveGuard,
        usize,
    ) {
        let compiled = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let view = compiled.program().native_context_program_view().unwrap();
        let search = derive_context_anchored_forward_search(view)
            .unwrap()
            .expect("test pattern must admit anchored forward search");
        let plan = derive_context_prefix_predicates(
            view.anchored_prefix.sets(),
            search.primary,
            search.vector_filter,
            target.architecture,
        )
        .unwrap();
        let mut data = Vec::new();
        let installed =
            append_native_prefix_filter(&mut data, plan, usize::from(search.guarded_bytes))
                .unwrap();
        let predicate_count = installed.map_or(0, |filter| filter.predicates().len());
        let guard = derive_context_anchored_adaptive_guard(search, installed).unwrap();
        (search, guard, predicate_count)
    }

    fn adaptive_charge(
        debt: &mut u64,
        amount: u16,
        candidate: u64,
        guard: ContextAnchoredAdaptiveGuard,
    ) -> bool {
        *debt = debt.checked_add(u64::from(amount)).unwrap();
        *debt
            <= candidate
                .checked_add(u64::from(guard.initial_credit))
                .unwrap()
    }

    /// Target-neutral executable specification for the native reserve/refund
    /// protocol. The ISA emitters use different registers and instructions,
    /// but must produce this exact debt and same-candidate fallback behavior.
    #[derive(Clone, Copy, Debug)]
    struct AdaptiveReserveOracle {
        debt: u64,
        candidate: Option<u64>,
        remaining: u8,
    }

    impl AdaptiveReserveOracle {
        fn new(origin: u64) -> Self {
            Self {
                debt: origin,
                candidate: None,
                remaining: 0,
            }
        }

        fn charge(
            &mut self,
            amount: u16,
            candidate: u64,
            guard: ContextAnchoredAdaptiveGuard,
        ) -> bool {
            adaptive_charge(&mut self.debt, amount, candidate, guard)
        }

        fn reserve(
            &mut self,
            max_verify_bytes: u8,
            candidate: u64,
            guard: ContextAnchoredAdaptiveGuard,
        ) -> Result<u8, u64> {
            assert_eq!(self.remaining, 0, "attempt reservation overlapped");
            self.candidate = Some(candidate);
            let allowance = candidate
                .checked_add(u64::from(guard.initial_credit))
                .unwrap();
            let headroom = allowance.checked_sub(self.debt).unwrap();
            let affordable = headroom / u64::from(guard.transition_debt);
            self.remaining = u8::try_from(affordable.min(u64::from(max_verify_bytes))).unwrap();
            if self.remaining == 0 {
                return Err(candidate);
            }
            let reserve = u64::from(self.remaining)
                .checked_mul(u64::from(guard.transition_debt))
                .unwrap();
            self.debt = self.debt.checked_add(reserve).unwrap();
            Ok(self.remaining)
        }

        fn transition(&mut self) -> Result<(), u64> {
            let candidate = self.candidate.expect("transition without an attempt");
            if self.remaining == 0 {
                return Err(candidate);
            }
            self.remaining = self.remaining.checked_sub(1).unwrap();
            Ok(())
        }

        fn refund_no_match(&mut self, guard: ContextAnchoredAdaptiveGuard) {
            let refund = u64::from(self.remaining)
                .checked_mul(u64::from(guard.transition_debt))
                .unwrap();
            self.debt = self.debt.checked_sub(refund).unwrap();
            self.remaining = 0;
            self.candidate = None;
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the shared cross-target differential corpus is intentionally centralized"
    )]
    fn cases() -> Vec<(&'static str, OutputContract, &'static [u8])> {
        vec![
            ("(?m)^foo$", OutputContract::Span, b"x\nfoo\ny"),
            ("(?m)^a+$", OutputContract::Span, b"x\naaa\na\ny"),
            ("(?m)^a+$", OutputContract::SelectedEnd, b"x\naaa\na\ny"),
            ("(?m)^a+$", OutputContract::Exists, b"x\naaa\na\ny"),
            (
                "(?m)^(?:6Jc)+[2-6]ax[t-w]hp$",
                OutputContract::Span,
                b"!!!!!!!!!!!!!6Jc6Jc2axth!\n6Jc6Jc2axthp\n!!!!!!!!!!!!!!!!!!!!!!!!!",
            ),
            (
                "(?-u:\\b(?:cat|dog)\\b)",
                OutputContract::Span,
                b"!cat dog_ dog!",
            ),
            (
                "(?-u:\\b[a-z]+\\b)",
                OutputContract::Span,
                b"!cat dog_ eel!",
            ),
            (
                "(?-u:\\bcat(?:s|alog)+\\b)",
                OutputContract::Span,
                b"scatalog cat_ !catalog!",
            ),
            (
                "(?-u:\\bfoo(?:[0-9]*)\\b)",
                OutputContract::Span,
                b"!fooX!foo42? foo_ !foo!",
            ),
            (
                "(?-u:\\b[A-F][0-9_][x-z](?:[0-9]*)\\b)",
                OutputContract::Span,
                b"!A0x? F_y99! B2z_ C3y!",
            ),
            (
                "(?-u:\\b(?:abX|acY)\\b)",
                OutputContract::Span,
                b"!acX !abX! acY? abY",
            ),
            (
                "(?-u:\\b)zzzzzz(?:ab|a)(?s:.)*?",
                OutputContract::Span,
                b"!zzzzzzab!",
            ),
            (
                "(?-u:\\b)zzzzzz(?:a|ab)(?s:.)*?",
                OutputContract::Span,
                b"!zzzzzzab!",
            ),
            (
                "(?-u:\\b)zzzzzzz(?:ab|a)(?s:.)*?",
                OutputContract::Span,
                b"!zzzzzzxzzzzzzzab?",
            ),
            (
                "(?-u:\\b)[ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ](?s:.)*?",
                OutputContract::Span,
                b"!BBBBBB?ACEGIK!",
            ),
            (
                "(?-u:\\b)zzzzzza{65}(?s:.)*?",
                OutputContract::Span,
                b"!zzzzzzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            (
                "(?-u:\\b)[45Vjuv][45Vjuv](?s:.)+?",
                OutputContract::Span,
                b"00000000000000000000000000000000!V4x!",
            ),
            (
                "(?-u:\\b)[BDFHJLNPR][BDFHJLNPR][BDFHJLNPR][BDFHJLNPR][BDFHJLNPR][BDFHJLNPR](?s:.)*?",
                OutputContract::Span,
                concat!(
                    "##CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                    "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                    "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                    "!BBBBBBx!"
                )
                .as_bytes(),
            ),
            (
                "(?-u:\\b)aaaab+",
                OutputContract::Span,
                concat!(
                    "##xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "!aaaabbbb!"
                )
                .as_bytes(),
            ),
            (
                "(?-u:\\b)aaaab+?",
                OutputContract::Span,
                concat!(
                    "##xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "!aaaabbbb!"
                )
                .as_bytes(),
            ),
            (
                "(?-u:\\b)za{62}(?s:.)*?",
                OutputContract::Span,
                b"!zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?",
            ),
            (
                "(?-u:\\b)za{63}(?s:.)*?",
                OutputContract::Span,
                b"!zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?",
            ),
            (
                "(?-u:\\b)za{64}(?s:.)*?",
                OutputContract::Span,
                b"!zaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?",
            ),
            ("(?m)^foo$", OutputContract::SelectedEnd, b"xfoo\nfoo\nyfoo"),
            ("(?m:^$)", OutputContract::Span, b"x\n\ny"),
            ("(?m:^$)", OutputContract::SelectedEnd, b"\n"),
            ("\\A(?:ab|a)\\z", OutputContract::Span, b"ab"),
            ("\\A(?:ab|a)\\z", OutputContract::Exists, b"a"),
            ("(?-u:\\B[0-9]+\\B)", OutputContract::Span, b"a123b !45!"),
            (
                "(?-u:\\b(?:woua|qiaia)\\b)",
                OutputContract::Exists,
                b"!woua qiaia_ qiaia! xwoua?",
            ),
            (
                "(?-u:\\b(?:woua|qiaia)\\b)",
                OutputContract::SelectedEnd,
                b"!woua qiaia_ qiaia! xwoua?",
            ),
            (
                "(?-u:\\b(?:woua|qiaia)\\b)",
                OutputContract::Span,
                b"!woua qiaia_ qiaia! xwoua?",
            ),
            (
                "(?-u:\\b(?:(?:(?:(?:(?:(?:(?:[J-N])?M))+|[N-R]|q))*upaH))\\b)",
                OutputContract::Exists,
                b"!JMNMqupaH? xxupaH_ qMMupaH!",
            ),
            (
                "(?-u:\\b(?:(?:(?:(?:(?:(?:[K-M]|gHu|mF))+)*RhR4K)(?:[q-u]e)))\\b)",
                OutputContract::Exists,
                b"!gHugHuRhR4Kqe! mFRhR4Kte?",
            ),
            (
                "(?-u:\\b(?:(?:(?:(?:(?:(?:[n-r]){2,5}?)*?[2-4])){2,4}fpe7))\\b)",
                OutputContract::Span,
                b"!nn2nn2fpe7? xxnn2nn2fpe7_",
            ),
            (
                "(?-u:\\b(?:(?:(?:(?:(?:(?:7NGGByK))+?){1,2}?){1,3}?[S-U]))\\b)",
                OutputContract::Exists,
                b"x7NGGByKS! !7NGGByKS_!7NGGByK7NGGByKT!7NGGByKU",
            ),
            (
                "(?-u:\\b(?:a.*fpe7|bfpe7)\\b)",
                OutputContract::Span,
                b"a0!bfpe7!00fpe7",
            ),
            (
                "\\A[a-z]{1,4}RhR4K[q-u]e\\z",
                OutputContract::Span,
                b"xxRhR4Kqe",
            ),
            ("(?m)^.$", OutputContract::Span, b"\xff\nq"),
            ("\\A\\z", OutputContract::Span, b""),
        ]
    }

    #[test]
    fn contextual_boundary_pair_relation_exactly_reconstructs_initial_semantics()
    -> Result<(), ObjectError> {
        let cases = [
            ("(?m)^foo", OutputContract::Span),
            ("(?-u:\\bfoo)", OutputContract::SelectedEnd),
            ("(?-u:\\B[a-z]+)", OutputContract::Exists),
        ];
        for (pattern, output) in cases {
            let compiled = compile(
                CompileRequest::new(pattern, host_target())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let anchored = view
                .dfa
                .anchored_forward
                .expect("contextual compiler must publish the exact-start graph");
            let coaccessible = derive_context_anchored_coaccessible(anchored)?
                .expect("small test graph must fit the optional relation analysis");
            let relation = derive_context_boundary_pair_relation(view)?
                .expect("small contextual graph must admit its exact pair relation");

            assert!(relation.factors.len() <= CONTEXT_BOUNDARY_PAIR_MAX_FACTORS);
            let mut occupied_before = [0_u64; 4];
            for (factor_index, factor) in relation.factors.iter().enumerate() {
                assert!(factor.current_words.iter().any(|&word| word != 0));
                assert!(factor.before_words.iter().any(|&word| word != 0));
                assert!(
                    relation.factors[..factor_index]
                        .iter()
                        .all(|prior| prior.current_words != factor.current_words)
                );
                for (occupied, &row) in occupied_before.iter_mut().zip(&factor.before_words) {
                    assert_eq!(*occupied & row, 0, "previous-byte rows must be disjoint");
                    *occupied |= row;
                }
            }

            for before in u8::MIN..=u8::MAX {
                let before_index = usize::from(before);
                let before_class = usize::from(view.dfa.byte_classes[before_index]);
                let properties = *view
                    .dfa
                    .class_properties
                    .get(before_class)
                    .expect("byte class has semantic properties");
                for current in u8::MIN..=u8::MAX {
                    let current_class = u32::from(view.dfa.byte_classes[usize::from(current)]);
                    let context = view
                        .dfa
                        .initial_dispatch
                        .pack(current_class, properties, true, false, false)
                        .expect("interior context packs");
                    let expected = context_initial_is_coaccessible(
                        view.dfa,
                        anchored,
                        &coaccessible,
                        context,
                    )?;
                    assert_eq!(
                        relation.matches(before, current),
                        expected,
                        "{pattern:?} {output:?}: pair {before:#04x},{current:#04x}",
                    );
                }
            }

            for current in u8::MIN..=u8::MAX {
                let current_class = u32::from(view.dfa.byte_classes[usize::from(current)]);
                let context = view
                    .dfa
                    .initial_dispatch
                    .pack(current_class, 0, false, true, false)
                    .expect("absolute-start context packs");
                let expected =
                    context_initial_is_coaccessible(view.dfa, anchored, &coaccessible, context)?;
                assert_eq!(
                    relation.matches_absolute_start(current),
                    expected,
                    "{pattern:?} {output:?}: absolute start {current:#04x}",
                );
            }
        }
        Ok(())
    }

    #[test]
    fn contextual_boundary_pair_expression_is_exact_across_isa_tiers() -> Result<(), ObjectError> {
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let targets = [
            Target::x86_64_linux(),
            Target::x86_64_linux()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap(),
            Target::x86_64_linux().with_features(avx512).unwrap(),
            Target::aarch64_linux(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        ];
        for pattern in ["(?m)^foo", "(?-u:\\bfoo)"] {
            for target in targets {
                let compiled = compile(
                    CompileRequest::new(pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::Exists),
                )
                .unwrap();
                let view = compiled.program().native_context_program_view().unwrap();
                let relation = derive_context_boundary_pair_relation(view)?
                    .expect("representative contextual graph has a pair relation");
                let primary = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())?
                    .expect("representative contextual graph has a prefix scanner");
                let vector_filter =
                    derive_vector_filter(Some(primary), view.anchored_prefix.sets())?;
                let expression = lower_context_boundary_pair_expression(
                    &relation,
                    primary,
                    vector_filter,
                    target,
                )?;
                if pattern.contains("\\b") && target.architecture == Architecture::Aarch64 {
                    assert!(
                        expression.is_none(),
                        "the eight-endpoint word complement must transactionally decline the six-constant ASIMD relation bank",
                    );
                    continue;
                }
                let expression = expression.unwrap_or_else(|| {
                    panic!("no boundary-pair expression for {pattern:?} on {target:?}")
                });
                assert!(!expression.plan.rectangles().is_empty());
                for before in u8::MIN..=u8::MAX {
                    for current in u8::MIN..=u8::MAX {
                        let in_base = context_filter_contains(primary, current);
                        assert_eq!(
                            in_base
                                && native_prefix_relation_vector_contains(
                                    expression.plan,
                                    before,
                                    current,
                                ),
                            in_base && relation.matches(before, current),
                            "{pattern:?} {target:?}: {before:#04x},{current:#04x}",
                        );
                    }
                }
                assert_eq!(
                    expression
                        .plan
                        .rectangles()
                        .iter()
                        .any(|rectangle| rectangle.first.negated || rectangle.second.negated),
                    pattern.contains("\\b"),
                    "word-boundary complement selection on {target:?}",
                );
            }
        }
        Ok(())
    }

    #[test]
    fn contextual_boundary_pair_refinement_has_cross_isa_vector_code_shape() {
        let pattern = "(?-u:\\bfoo)";
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        for (features, final_intersection) in [
            (FeatureSet::EMPTY, [0x44, 0x21, 0xd8].as_slice()),
            (
                FeatureSet::of(CpuFeature::X86Avx2),
                [0x44, 0x21, 0xd8].as_slice(),
            ),
            (avx512, [0x4c, 0x21, 0xd8].as_slice()),
        ] {
            let target = Target::x86_64_linux().with_features(features).unwrap();
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            assert!(
                code.windows(3).any(|bytes| bytes == [0x48, 0xff, 0xca]),
                "pair load must address candidate-1 on {target:?}",
            );
            assert!(
                code.windows(final_intersection.len())
                    .any(|bytes| bytes == final_intersection),
                "pair mask must intersect the complete base mask on {target:?}",
            );
        }

        for target in [
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
            Target::aarch64_macos()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        ] {
            let compiled = compile(
                CompileRequest::new("(?m)^foo", target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            let words = compiled.module().sections()[TEXT_SECTION]
                .bytes()
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            assert!(words.contains(&aarch64_orr_16b(23, 24, 24).unwrap()));
            assert!(words.contains(&aarch64_sub_x_imm(2, 2, 1).unwrap()));
            assert!(words.contains(&aarch64_add_x_imm(2, 2, 1).unwrap()));
            assert!(words.contains(&aarch64_load_q(0, 12).unwrap()));
            assert!(words.contains(&aarch64_load_q(16, 12).unwrap()));
            assert!(words.contains(&crate::module::aarch64_and_16b(24, 24, 23).unwrap()));
        }
    }

    #[test]
    fn x86_transient_boundary_pair_restores_scanner_before_rejected_hit_resume()
    -> Result<(), ObjectError> {
        let pattern = r"(?-u:\b)qaaaaa(?:bc|b)(?s:.)*?";
        let mut haystack = vec![b'!'; 128];
        haystack[1..8].copy_from_slice(b"qaaaaax");
        haystack[65..73].copy_from_slice(b"qaaaaabc");
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        for (features, restored_test) in [
            (
                FeatureSet::EMPTY,
                [0x44, 0x89, 0xd8, 0x85, 0xc0, 0x0f, 0x85].as_slice(),
            ),
            (
                FeatureSet::of(CpuFeature::X86Avx2),
                [0x44, 0x89, 0xd8, 0x85, 0xc0, 0x0f, 0x85].as_slice(),
            ),
            (
                avx512,
                [0x4c, 0x89, 0xd8, 0x48, 0x85, 0xc0, 0x0f, 0x85].as_slice(),
            ),
        ] {
            let target = Target::x86_64_linux().with_features(features).unwrap();
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let relation = derive_context_boundary_pair_relation(view)?
                .expect("word-boundary sidecar must have an exact pair relation");
            let search = derive_context_anchored_forward_search(view)?
                .expect("false-prefix audit pattern must select the exact-start sidecar");
            let pair = lower_context_boundary_pair_expression(
                &relation,
                search.primary,
                search.vector_filter,
                target,
            )?
            .expect("word-boundary sidecar must select pair refinement");
            assert!(pair.transient_constants);
            assert!(pair.restore_scanner_constants);
            assert!(relation.matches(haystack[0], haystack[1]));
            assert_eq!(
                compiled
                    .search(&haystack, SearchWindow::new(1, 64))
                    .unwrap(),
                MatchResult::Span(None),
                "the first pair hit must be rejected after deeper verification",
            );
            assert_eq!(
                compiled
                    .search(&haystack, SearchWindow::new(1, haystack.len()))
                    .unwrap(),
                MatchResult::Span(Some((65, 73))),
                "scanner resume must retain the later valid candidate",
            );
            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            assert!(
                code.windows(restored_test.len())
                    .any(|bytes| bytes == restored_test),
                "restored full-lane mask test is absent on {target:?}",
            );
        }
        Ok(())
    }

    #[test]
    fn mandatory_interior_guards_cover_assertion_patterns() -> Result<(), ObjectError> {
        let patterns = [
            (
                "(?-u:\\b(?:(?:(?:(?:(?:(?:[K-M]|gHu|mF))+)*RhR4K)(?:[q-u]e)))\\b)",
                ContextPrepassRestart::OriginalStart,
            ),
            (
                "\\A[a-z]{1,4}RhR4K[q-u]e\\z",
                ContextPrepassRestart::OriginalStart,
            ),
        ];
        for (pattern, expected_restart) in patterns {
            let compiled = compile(
                CompileRequest::new(pattern, host_target())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let prefix = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())?
                .expect("test pattern has an anchored prefix");
            let guard = derive_context_interior_guard(view)?
                .filter(|guard| filter_selection_key(guard.primary) < filter_selection_key(prefix))
                .expect("mandatory interior should be more selective than the prefix");
            assert_eq!(guard.restart, expected_restart);
        }
        Ok(())
    }

    #[test]
    fn empty_prefix_restart_cost_uses_table_geometry() -> Result<(), ObjectError> {
        let patterns = [
            ("line", "(?m)^(?:6Jc)+[2-6]ax[t-w]hp$"),
            ("word", "(?-u:\\b(?:B7m){2,4}?[3-6]5\\b)"),
        ];
        for (name, pattern) in patterns {
            let compiled = compile(
                CompileRequest::new(pattern, host_target())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let prefix = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())?
                .expect("representative assertion pattern has a prefix");
            let plan = derive_context_state_skip(view)?.expect("assertion pattern has a kernel");
            let selected = use_empty_prefix_restart(view, prefix, Some(&plan));
            assert_eq!(selected, name == "word", "{name}: {plan:?}");
        }
        Ok(())
    }

    #[test]
    fn aarch64_prefix_supertransition_preserves_masked_flag_scratch() {
        let compiled = compile(
            CompileRequest::new("(?m)^foo$", Target::aarch64_macos())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        let view = compiled.program().native_context_program_view().unwrap();
        assert!(derive_context_prefix_fast_forward(view).is_some());
        let words = compiled.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect::<Vec<_>>();
        let masked_flags = aarch64_context_and_low_w(11, 8, 3).unwrap();
        assert!(
            words
                .windows(2)
                .any(|pair| { pair[0] == masked_flags && pair[1] & 0xff00_001f == 0x3500_000b }),
            "the fast-forward split must retain flags in w11 and fold only its zero compare",
        );
    }

    #[test]
    fn contextual_prefix_supertransition_is_a_complete_table_proof() {
        let patterns = [
            (
                "word",
                "(?-u:\\b(?:(?:(?:(?:(?:(?:7NGGByK))+?){1,2}?){1,3}?[S-U]))\\b)",
                OutputContract::Exists,
            ),
            (
                "line",
                "(?m)^(?:(?:(?:(?:SV){2,3}){2,4}?(?:gV|[5-9])))$",
                OutputContract::Span,
            ),
        ];
        for (name, pattern, output) in patterns {
            let compiled = compile(
                CompileRequest::new(pattern, host_target())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let plan = derive_context_prefix_fast_forward(view)
                .unwrap_or_else(|| panic!("{name} must have a proved prefix supertransition"));
            assert!(plan.guaranteed_bytes >= 6, "{name}: {plan:?}");
            assert!(plan.consumed_bytes >= 5, "{name}: {plan:?}");

            let class_count = usize::try_from(view.dfa.initial_dispatch.class_count).unwrap();
            let row_width = usize::try_from(view.dfa.initial_dispatch.row_width).unwrap();
            let mut first_classes = [false; 256];
            for byte in u8::MIN..=u8::MAX {
                let index = usize::from(byte);
                let set = view.anchored_prefix.sets()[0];
                if set.words()[index / 64] & (1_u64 << (index % 64)) != 0 {
                    first_classes[usize::from(view.dfa.byte_classes[index])] = true;
                }
            }
            let mut frontier = Vec::new();
            for entry in view.dfa.forward_initial {
                let class =
                    usize::try_from(entry.context & view.dfa.initial_dispatch.class_mask).unwrap();
                if class < class_count
                    && first_classes[class]
                    && context_prefix_state_is_safe(view, entry.state) == Some(true)
                    && !frontier.contains(&entry.state)
                {
                    frontier.push(entry.state);
                }
            }
            for &set in &view.anchored_prefix.sets()[1..=usize::from(plan.consumed_bytes)] {
                let mut next = Vec::new();
                for &state in &frontier {
                    let row = usize::try_from(state).unwrap() * row_width;
                    for byte in u8::MIN..=u8::MAX {
                        let index = usize::from(byte);
                        if set.words()[index / 64] & (1_u64 << (index % 64)) == 0 {
                            continue;
                        }
                        let class = usize::from(view.dfa.byte_classes[index]);
                        let cell = view.dfa.forward_cells[row + class];
                        assert!(!cell.accepted, "{name}: accepted while skipping");
                        assert_eq!(
                            context_prefix_state_is_safe(view, cell.next),
                            Some(true),
                            "{name}: unsafe state while skipping"
                        );
                        if !next.contains(&cell.next) {
                            next.push(cell.next);
                        }
                    }
                }
                frontier = next;
            }
            assert_eq!(frontier, vec![plan.target_state], "{name}: {plan:?}");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the randomized scalar oracle keeps generation and transition checks together"
    )]
    fn randomized_context_prefix_supertransition_matches_scalar_table() {
        let patterns = [
            ("(?-u:\\bfoo(?:[0-9]*)\\b)", OutputContract::Span),
            (
                "(?-u:\\b(?:(?:(?:(?:(?:(?:7NGGByK))+?){1,2}?){1,3}?[S-U]))\\b)",
                OutputContract::Exists,
            ),
            (
                "(?m)^(?:(?:(?:(?:SV){2,3}){2,4}?(?:gV|[5-9])))$",
                OutputContract::Span,
            ),
        ];
        let mut random = 0x243f_6a88_85a3_08d3_u64;
        let mut checked = 0_usize;
        for (pattern, output) in patterns {
            let compiled = compile(
                CompileRequest::new(pattern, host_target())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let plan = derive_context_prefix_fast_forward(view).unwrap();
            let width = usize::from(plan.guaranteed_bytes);
            let row_width = usize::try_from(view.dfa.initial_dispatch.row_width).unwrap();
            for iteration in 0..256_usize {
                let length = width + 1 + iteration % 57;
                let mut haystack = vec![0_u8; length];
                for byte in &mut haystack {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    *byte = random.to_le_bytes()[0];
                }
                let candidate = if iteration % 4 == 0 {
                    0
                } else {
                    1 + (iteration * 17) % (length - width)
                };
                for (offset, set) in view.anchored_prefix.sets().iter().copied().enumerate() {
                    let cardinality = usize::from(set.cardinality());
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    let selected = usize::try_from(random).unwrap_or(usize::MAX) % cardinality;
                    let mut ordinal = 0_usize;
                    for byte in u8::MIN..=u8::MAX {
                        let index = usize::from(byte);
                        if set.words()[index / 64] & (1_u64 << (index % 64)) == 0 {
                            continue;
                        }
                        if ordinal == selected {
                            haystack[candidate + offset] = byte;
                            break;
                        }
                        ordinal += 1;
                    }
                }

                let current_class =
                    u32::from(view.dfa.byte_classes[usize::from(haystack[candidate])]);
                let (properties, present) = if candidate == 0 {
                    (0, false)
                } else {
                    let class =
                        usize::from(view.dfa.byte_classes[usize::from(haystack[candidate - 1])]);
                    (view.dfa.class_properties[class], true)
                };
                let context = view
                    .dfa
                    .initial_dispatch
                    .pack(current_class, properties, present, candidate == 0, false)
                    .unwrap();
                let entry = view
                    .dfa
                    .forward_initial
                    .binary_search_by_key(&context, |entry| entry.context)
                    .ok()
                    .map(|index| view.dfa.forward_initial[index])
                    .unwrap();
                if context_prefix_state_is_safe(view, entry.state) != Some(true) {
                    continue;
                }
                let mut state = entry.state;
                for offset in 1..=usize::from(plan.consumed_bytes) {
                    let class = usize::from(
                        view.dfa.byte_classes[usize::from(haystack[candidate + offset])],
                    );
                    let row = usize::try_from(state).unwrap() * row_width;
                    let cell = view.dfa.forward_cells[row + class];
                    assert!(!cell.accepted, "{pattern:?} iteration {iteration}");
                    assert_eq!(
                        context_prefix_state_is_safe(view, cell.next),
                        Some(true),
                        "{pattern:?} iteration {iteration}"
                    );
                    state = cell.next;
                }
                assert_eq!(
                    state, plan.target_state,
                    "{pattern:?} iteration {iteration}"
                );
                checked += 1;
            }
        }
        assert!(checked >= 128, "only {checked} randomized active prefixes");
    }

    fn known_start_proof_contains(proof: ContextKnownSpanStartProof, byte: u8) -> bool {
        let index = usize::from(byte);
        proof.following_words[index / 64] & (1_u64 << (index % 64)) != 0
    }

    #[test]
    fn contextual_known_span_start_is_a_bounded_product_proof() {
        let word = compile(
            CompileRequest::new("(?-u:\\bfoo(?:[0-9]*)\\b)", host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let word_view = word.program().native_context_program_view().unwrap();
        let word_proof = derive_context_known_span_start(word_view).unwrap();
        assert_eq!(word_proof.guarded_bytes, 3);
        assert!(word_proof.accepts_haystack_end);
        assert!(known_start_proof_contains(word_proof, b'!'));
        assert!(known_start_proof_contains(word_proof, b'\n'));
        assert!(!known_start_proof_contains(word_proof, b'X'));
        assert!(!known_start_proof_contains(word_proof, b'0'));

        let line = compile(
            CompileRequest::new("(?m)^foo(?:[0-9]*)$", host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let line_proof =
            derive_context_known_span_start(line.program().native_context_program_view().unwrap())
                .unwrap();
        assert_eq!(line_proof.guarded_bytes, 3);
        assert!(line_proof.accepts_haystack_end);
        assert!(known_start_proof_contains(line_proof, b'\n'));
        assert!(!known_start_proof_contains(line_proof, b'X'));

        let unconditional = compile(
            CompileRequest::new("(?-u:\\bfoo.*)", host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let unconditional_proof = derive_context_known_span_start(
            unconditional
                .program()
                .native_context_program_view()
                .unwrap(),
        )
        .unwrap();
        assert!(
            unconditional_proof
                .following_words
                .iter()
                .all(|&word| word == u64::MAX)
        );
        assert!(unconditional_proof.accepts_haystack_end);

        let byte_sets = compile(
            CompileRequest::new("(?-u:\\b[A-F][0-9_][x-z](?:[0-9]*)\\b)", host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert!(
            derive_context_known_span_start(
                byte_sets.program().native_context_program_view().unwrap()
            )
            .is_some()
        );

        let correlated_false_positive = compile(
            CompileRequest::new("(?-u:\\b(?:abX|acY)\\b)", host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert!(
            derive_context_known_span_start(
                correlated_false_positive
                    .program()
                    .native_context_program_view()
                    .unwrap()
            )
            .is_none()
        );

        let limits = ContextKnownStartLimits::default();
        for constrained in [
            ContextKnownStartLimits {
                max_work: 0,
                ..limits
            },
            ContextKnownStartLimits {
                max_states: 0,
                ..limits
            },
            ContextKnownStartLimits {
                max_cells: 0,
                ..limits
            },
            ContextKnownStartLimits {
                max_memory_bytes: 0,
                ..limits
            },
        ] {
            assert!(derive_context_known_span_start_with_limits(word_view, constrained).is_none());
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "randomized graph setup and all candidate/window oracle checks stay together"
    )]
    fn randomized_known_span_start_guard_implies_candidate_start() {
        let patterns = [
            "(?-u:\\bfoo(?:[0-9]*)\\b)",
            "(?m)^foo(?:[0-9]*)$",
            "(?-u:\\b[A-F][0-9_][x-z](?:[0-9]*)\\b)",
        ];
        let mut random = 0x1319_8a2e_0370_7344_u64;
        let mut checked = 0_usize;
        let mut haystack_end_checked = 0_usize;
        for pattern in patterns {
            let compiled = compile(
                CompileRequest::new(pattern, host_target())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let proof = derive_context_known_span_start(view).unwrap();
            let width = usize::from(proof.guarded_bytes);
            let passing = (u8::MIN..=u8::MAX)
                .filter(|&byte| known_start_proof_contains(proof, byte))
                .collect::<Vec<_>>();
            for iteration in 0..192_usize {
                let length = width + 3 + iteration % 23;
                let mut haystack = vec![0_u8; length];
                for byte in &mut haystack {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    *byte = random.to_le_bytes()[0];
                }
                let candidate = if proof.accepts_haystack_end && iteration.is_multiple_of(8) {
                    length - width
                } else {
                    (iteration * 11) % (length - width)
                };
                for (offset, set) in view.anchored_prefix.sets().iter().copied().enumerate() {
                    let cardinality = usize::from(set.cardinality());
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    let selected = usize::try_from(random).unwrap_or(usize::MAX) % cardinality;
                    let mut ordinal = 0_usize;
                    for byte in u8::MIN..=u8::MAX {
                        let index = usize::from(byte);
                        if set.words()[index / 64] & (1_u64 << (index % 64)) == 0 {
                            continue;
                        }
                        if ordinal == selected {
                            haystack[candidate + offset] = byte;
                            break;
                        }
                        ordinal += 1;
                    }
                }
                let following = candidate + width;
                if following == haystack.len() {
                    if !proof.accepts_haystack_end {
                        continue;
                    }
                } else {
                    if passing.is_empty() {
                        continue;
                    }
                    haystack[following] = passing[iteration % passing.len()];
                }

                let current_class =
                    u32::from(view.dfa.byte_classes[usize::from(haystack[candidate])]);
                let (properties, present) = if candidate == 0 {
                    (0, false)
                } else {
                    let class =
                        usize::from(view.dfa.byte_classes[usize::from(haystack[candidate - 1])]);
                    (view.dfa.class_properties[class], true)
                };
                let context = view
                    .dfa
                    .initial_dispatch
                    .pack(current_class, properties, present, candidate == 0, false)
                    .unwrap();
                let entry = view
                    .dfa
                    .forward_initial
                    .binary_search_by_key(&context, |entry| entry.context)
                    .ok()
                    .map(|index| view.dfa.forward_initial[index])
                    .unwrap();
                let flags = view.dfa.forward_states[usize::try_from(entry.state).unwrap()];
                if flags.empty && !flags.pending {
                    continue;
                }

                for end in following..=haystack.len() {
                    let found = compiled
                        .search(&haystack, SearchWindow::new(candidate, end))
                        .unwrap();
                    let MatchResult::Span(Some((start, _))) = found else {
                        panic!(
                            "proved candidate did not match: {pattern:?} iteration {iteration} window {candidate}..{end}: {found:?}"
                        );
                    };
                    assert_eq!(start, candidate, "{pattern:?} iteration {iteration}");
                    checked += 1;
                    haystack_end_checked += usize::from(following == haystack.len());
                }
            }
        }
        assert!(checked >= 128, "only {checked} known-start oracle windows");
        assert!(
            haystack_end_checked >= 16,
            "only {haystack_end_checked} known-start haystack-end windows"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "suffix contract and graph-selection counterexamples form one audit"
    )]
    fn terminal_suffix_search_is_contract_and_graph_gated() -> Result<(), ObjectError> {
        let patterns = [
            "(?-u:\\b(?:woua|qiaia)\\b)",
            "(?-u:\\b(?:(?:(?:(?:(?:(?:(?:[J-N])?M))+|[N-R]|q))*upaH))\\b)",
        ];
        for pattern in patterns {
            for output in [OutputContract::Exists, OutputContract::SelectedEnd] {
                let compiled = compile(
                    CompileRequest::new(pattern, host_target())
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                let view = compiled.program().native_context_program_view().unwrap();
                let suffix = derive_context_terminal_suffix_search(view)?
                    .expect("selective aligned terminal suffix should use reverse verification");
                assert!(suffix.minimum_width >= 4);
                assert!(suffix.vector_filter.columns().len() >= 2);

                let compact = crate::context_native::build_context_native_layout(
                    view,
                    ContextNativeLimits::default(),
                )?;
                assert!(compact.reverse_cells_offset.is_none());
                assert!(compact.reverse_initial_offset.is_none());
                let verified = build_context_native_layout_with_reverse(
                    view,
                    ContextNativeLimits::default(),
                    true,
                )?;
                assert!(verified.reverse_cells_offset.is_some());
                assert!(verified.reverse_initial_offset.is_some());
            }
        }

        let span = compile(
            CompileRequest::new(patterns[0], host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert!(
            derive_context_terminal_suffix_search(
                span.program().native_context_program_view().unwrap()
            )?
            .is_some()
        );
        let selected_end = compile(
            CompileRequest::new(patterns[0], host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        assert!(
            derive_context_terminal_suffix_search(
                selected_end
                    .program()
                    .native_context_program_view()
                    .unwrap()
            )?
            .is_some()
        );
        let one_column = compile(
            CompileRequest::new("(?-u:\\b[a-z]+\\b)", host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        assert!(
            derive_context_terminal_suffix_search(
                one_column.program().native_context_program_view().unwrap()
            )?
            .is_none()
        );

        let selected = |pattern: &str, output: OutputContract| -> Result<bool, ObjectError> {
            let compiled = compile(
                CompileRequest::new(pattern, host_target())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let prefix = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())?;
            let prefix_vector = derive_vector_filter(prefix, view.anchored_prefix.sets())?;
            let interior = derive_context_interior_guard(view)?.filter(|guard| {
                prefix.is_none_or(|candidate| {
                    filter_selection_key(guard.primary) < filter_selection_key(candidate)
                })
            });
            let suffix = derive_context_terminal_suffix_search(view)?;
            Ok(suffix.is_some_and(|suffix| {
                use_context_terminal_suffix_search(
                    view.output,
                    suffix,
                    prefix,
                    prefix_vector,
                    interior,
                )
            }))
        };
        assert!(selected(
            "(?-u:\\b(?:woua|qiaia)\\b)",
            OutputContract::Exists
        )?);
        assert!(selected(
            "(?-u:\\b(?:(?:(?:(?:(?:(?:(?:[J-N])?M))+|[N-R]|q))*upaH))\\b)",
            OutputContract::Exists,
        )?);
        assert!(!selected(
            "(?-u:\\b(?:B7m){2,4}?[3-6]5\\b)",
            OutputContract::Exists
        )?);
        assert!(!selected(
            "(?-u:\\b(?:[2-6]{2,4})+?[a-d]\\b)",
            OutputContract::Exists
        )?);
        assert!(selected(
            "(?-u:\\b(?:(?:(?:(?:(?:(?:[n-r]){2,5}?)*?[2-4])){2,4}fpe7))\\b)",
            OutputContract::Span,
        )?);
        assert!(selected(
            "(?-u:\\b(?:a.*fpe7|bfpe7)\\b)",
            OutputContract::Span,
        )?);
        for pattern in [
            "(?-u:\\b(?:(?:(?:(?:(?:(?:[n-r]){2,5}?)*?[2-4])){2,4}fpe7))\\b)",
            "(?-u:\\b(?:a.*fpe7|bfpe7)\\b)",
        ] {
            assert_eq!(
                selected(pattern, OutputContract::SelectedEnd)?,
                selected(pattern, OutputContract::Span)?,
                "SelectedEnd and Span must share ordered-output profitability for {pattern:?}",
            );
        }
        Ok(())
    }

    #[test]
    fn terminal_suffix_vector_hit_extracts_the_isa_mask_carrier() -> Result<(), ObjectError> {
        // AVX-512 currently scalar-refines primary hits by policy. Exercise
        // the shared lazy-intersection CFG directly so a future profitability
        // change cannot silently route its K5 mask through the EAX-only path.
        let compiled = compile(
            CompileRequest::new(
                r"(?-u:\B(?:A[a-z]{0,16}fpez|qfpez))",
                Target::x86_64_linux(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        )
        .unwrap();
        let view = compiled.program().native_context_program_view().unwrap();
        let layout =
            build_context_native_layout_with_reverse(view, ContextNativeLimits::default(), true)?;
        let suffix = derive_context_terminal_suffix_search(view)?.unwrap();
        let required_offset = suffix
            .vector_filter
            .max_scan_offset()
            .max(suffix.minimum_width.saturating_sub(1));

        for (kind, extraction) in [
            (
                X86StartFilterKind::Sse2,
                &[0x0f, 0xbc, 0xc0, 0x48, 0x01, 0xc2][..],
            ),
            (
                X86StartFilterKind::Avx2,
                &[0x0f, 0xbc, 0xc0, 0x48, 0x01, 0xc2][..],
            ),
            (
                X86StartFilterKind::Avx512Bw,
                &[
                    0xc4, 0xe1, 0xfb, 0x93, 0xc5, // kmovq rax, k5
                    0x48, 0x0f, 0xbc, 0xc0, // bsfq rax, rax
                    0x48, 0x01, 0xc2, // candidate += first lane
                ][..],
            ),
        ] {
            let mut assembler = X86Assembler::new();
            let labels = x86_terminal_suffix_scanner_labels(&mut assembler)?;
            let exhausted = assembler.label()?;
            x86_emit_terminal_suffix_scanner(
                &mut assembler,
                kind,
                &layout,
                suffix,
                Some(suffix.vector_filter),
                required_offset,
                labels,
                exhausted,
            )?;
            assembler.bind(labels.verify)?;
            assembler.instruction(&[0xc3])?;
            assembler.bind(exhausted)?;
            assembler.instruction(&[0xc3])?;
            let code = assembler.finish()?;
            assert!(
                code.windows(extraction.len())
                    .any(|bytes| bytes == extraction),
                "terminal suffix selected the wrong candidate-mask carrier for {kind:?}",
            );
        }
        Ok(())
    }

    #[test]
    fn anchored_overlap_period_and_adaptive_cost_are_structural() {
        let a = singleton_set(b'a');
        let b = singleton_set(b'b');
        let c = singleton_set(b'c');
        assert_eq!(context_anchored_overlap_period(&[a, a, a, a]), Some(1));
        assert_eq!(context_anchored_overlap_period(&[a, b, a, b, a]), Some(2));
        assert_eq!(context_anchored_overlap_period(&[a, b, c]), None);
        assert_eq!(context_anchored_overlap_period(&[a]), None);

        let pattern =
            r"(?-u:\b)[ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ](?s:.)*?";
        let (search, guard, predicate_count) = anchored_guard_for(pattern, Target::x86_64_linux());
        assert!(
            search.cover_inflation > 0,
            "primary exact={} candidates={} offset={} guarded={}",
            search.primary.from_anchored_prefix,
            search.primary.candidate_bytes,
            search.primary.scan_offset,
            search.guarded_bytes,
        );
        assert_eq!(search.overlap_period, Some(1));
        let scanner_work = context_anchored_scanner_work(search).unwrap();
        let predicate_work = u16::try_from(predicate_count).unwrap();
        let expected_candidate_work = CONTEXT_ANCHORED_CANDIDATE_BASE_WORK
            .checked_add(predicate_work)
            .and_then(|work| {
                work.checked_add(
                    search
                        .cover_inflation
                        .div_ceil(CONTEXT_ANCHORED_COVER_BYTES_PER_WORK),
                )
            })
            .and_then(|work| {
                work.checked_add(context_anchored_overlap_work(
                    search.guarded_bytes,
                    search.overlap_period,
                ))
            })
            .unwrap();
        assert_eq!(
            guard.vector_debt,
            scanner_work
                .checked_mul(CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR)
                .unwrap()
        );
        assert_eq!(
            guard.candidate_debt,
            expected_candidate_work
                .checked_mul(CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR)
                .unwrap()
        );
        assert_eq!(
            guard.transition_debt,
            CONTEXT_ANCHORED_TRANSITION_WORK
                .checked_mul(CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR)
                .unwrap()
        );
        assert_eq!(
            guard.initial_credit,
            guard
                .vector_debt
                .checked_add(guard.candidate_debt)
                .and_then(|work| {
                    work.checked_add(
                        u16::from(search.max_verify_bytes)
                            .checked_mul(guard.transition_debt)
                            .unwrap(),
                    )
                })
                .unwrap()
        );
        assert_eq!(
            context_anchored_transition_reserve(search, guard).unwrap(),
            u16::from(search.max_verify_bytes)
                .checked_mul(guard.transition_debt)
                .unwrap(),
        );

        let mut period_two = search;
        period_two.overlap_period = Some(2);
        let period_two_guard = derive_context_anchored_adaptive_guard(period_two, None).unwrap();
        let mut aperiodic = search;
        aperiodic.overlap_period = None;
        aperiodic.cover_inflation = 0;
        let aperiodic_guard = derive_context_anchored_adaptive_guard(aperiodic, None).unwrap();
        assert!(guard.candidate_debt > period_two_guard.candidate_debt);
        assert!(period_two_guard.candidate_debt > aperiodic_guard.candidate_debt);

        let (multi_column, _, _) =
            anchored_guard_for(r"(?-u:\b)zzzzzz(?:ab|a)(?s:.)*?", Target::x86_64_linux());
        assert!(
            multi_column
                .vector_filter
                .is_some_and(|filter| filter.columns().len() > 1)
        );
        let mut primary_only = multi_column;
        primary_only.vector_filter = None;
        assert!(
            context_anchored_scanner_work(multi_column).unwrap()
                > context_anchored_scanner_work(primary_only).unwrap()
        );
        let multi_column_guard =
            derive_context_anchored_adaptive_guard(multi_column, None).unwrap();
        let primary_only_guard =
            derive_context_anchored_adaptive_guard(primary_only, None).unwrap();
        assert!(multi_column_guard.vector_debt > primary_only_guard.vector_debt);
        assert_eq!(
            multi_column_guard.candidate_debt,
            primary_only_guard.candidate_debt
        );
    }

    #[test]
    fn adaptive_reserve_refund_oracle_is_exact_and_falls_back_from_same_candidate() {
        let vector_debt = 2_u16
            .checked_mul(CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR)
            .unwrap();
        let candidate_debt = 3_u16
            .checked_mul(CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR)
            .unwrap();
        let transition_debt = CONTEXT_ANCHORED_TRANSITION_WORK
            .checked_mul(CONTEXT_ANCHORED_ADAPTIVE_DENOMINATOR)
            .unwrap();
        let guard = ContextAnchoredAdaptiveGuard {
            vector_debt,
            candidate_debt,
            transition_debt,
            initial_credit: vector_debt
                .checked_add(candidate_debt)
                .and_then(|work| {
                    work.checked_add(
                        u16::from(CONTEXT_ANCHORED_MAX_VERIFY_BYTES)
                            .checked_mul(transition_debt)
                            .unwrap(),
                    )
                })
                .unwrap(),
        };
        assert!(guard.transition_debt.is_power_of_two());

        // Exhaust every cap, affordable-headroom residue, and possible number
        // of used transitions. The reservation admits exactly the same prefix
        // as iterative prospective charging, and refund restores precisely the
        // debt for only the transitions that actually ran.
        let transition = u64::from(guard.transition_debt);
        let origin = 10_000_u64;
        for maximum in 1_u8..=CONTEXT_ANCHORED_MAX_VERIFY_BYTES {
            let maximum_debt = u64::from(maximum).checked_mul(transition).unwrap();
            for headroom in 0..=maximum_debt + transition - 1 {
                let allowance = origin.checked_add(headroom).unwrap();
                let candidate = allowance
                    .checked_sub(u64::from(guard.initial_credit))
                    .unwrap();

                let mut iterative_debt = origin;
                let mut iterative_count = 0_u8;
                while iterative_count < maximum
                    && iterative_debt.checked_add(transition).unwrap() <= allowance
                {
                    iterative_debt = iterative_debt.checked_add(transition).unwrap();
                    iterative_count = iterative_count.checked_add(1).unwrap();
                }
                let expected_count =
                    u8::try_from((headroom / transition).min(u64::from(maximum))).unwrap();
                assert_eq!(iterative_count, expected_count);

                let mut admitted = AdaptiveReserveOracle::new(origin);
                let reservation = admitted.reserve(maximum, candidate, guard);
                if expected_count == 0 {
                    assert_eq!(reservation, Err(candidate));
                    assert_eq!(admitted.debt, origin);
                    continue;
                }
                assert_eq!(reservation, Ok(expected_count));
                assert_eq!(admitted.debt, iterative_debt);

                for used in 0_u8..=expected_count {
                    let mut attempt = AdaptiveReserveOracle::new(origin);
                    assert_eq!(
                        attempt.reserve(maximum, candidate, guard),
                        Ok(expected_count)
                    );
                    for _ in 0..used {
                        attempt.transition().unwrap();
                    }
                    if used == expected_count {
                        assert_eq!(attempt.transition(), Err(candidate));
                    }
                    attempt.refund_no_match(guard);
                    assert_eq!(
                        attempt.debt,
                        origin + u64::from(used) * transition,
                        "maximum={maximum} headroom={headroom} used={used}",
                    );
                }
            }
        }

        // A nearby short rejection leaves enough rounded headroom for another
        // partial attempt, where a conservative full-maximum gate would have
        // abandoned the sidecar immediately.
        let mut dense = AdaptiveReserveOracle::new(0);
        assert!(dense.charge(guard.candidate_debt, 0, guard));
        assert_eq!(
            dense.reserve(CONTEXT_ANCHORED_MAX_VERIFY_BYTES, 0, guard),
            Ok(CONTEXT_ANCHORED_MAX_VERIFY_BYTES),
        );
        dense.transition().unwrap();
        dense.refund_no_match(guard);
        assert!(dense.charge(guard.candidate_debt, 1, guard));
        let second = dense
            .reserve(CONTEXT_ANCHORED_MAX_VERIFY_BYTES, 1, guard)
            .unwrap();
        assert!(second > 0 && second < CONTEXT_ANCHORED_MAX_VERIFY_BYTES);
    }

    #[test]
    fn adaptive_guard_is_emitted_for_every_isa_tier_and_table_shape() {
        let pattern =
            r"(?-u:\b)[ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ](?s:.)+?";
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let targets = [
            Target::x86_64_linux(),
            Target::x86_64_linux()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap(),
            Target::x86_64_linux().with_features(avx512).unwrap(),
            Target::aarch64_linux(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        ];
        for target in targets {
            let (search, guard, _) = anchored_guard_for(pattern, target);
            let maximum_reserve = context_anchored_transition_reserve(search, guard).unwrap();
            let shift = context_anchored_transition_shift(guard).unwrap();
            assert_eq!(
                maximum_reserve,
                u16::from(search.max_verify_bytes) * guard.transition_debt,
            );
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            match target.architecture {
                Architecture::X86_64 => {
                    assert!(code.windows(3).any(|bytes| bytes == [0x49, 0x89, 0xd4]));
                    for debt in [guard.vector_debt, guard.candidate_debt] {
                        let mut add = vec![0x49, 0x81, 0xc4];
                        add.extend_from_slice(&u32::from(debt).to_le_bytes());
                        assert!(code.windows(add.len()).any(|bytes| bytes == add));
                    }
                    let mut allowance = vec![0x4c, 0x8d, 0x9a];
                    allowance.extend_from_slice(&u32::from(guard.initial_credit).to_le_bytes());
                    assert!(
                        code.windows(allowance.len())
                            .any(|bytes| bytes == allowance)
                    );

                    let mut reserve_sequence = vec![0x4c, 0x8d, 0x9a];
                    reserve_sequence
                        .extend_from_slice(&u32::from(guard.initial_credit).to_le_bytes());
                    reserve_sequence.extend_from_slice(&[
                        0x4d, 0x29, 0xe3, // headroom = allowance - debt
                        0x49, 0xc1, 0xeb, shift, // affordable whole transitions
                        0x41, 0xbd,
                    ]);
                    reserve_sequence
                        .extend_from_slice(&u32::from(search.max_verify_bytes).to_le_bytes());
                    reserve_sequence.extend_from_slice(&[
                        0x4d, 0x39, 0xeb, // affordable vs maximum
                        0x4d, 0x0f, 0x42, 0xeb, // cap = min
                        0x45, 0x85, 0xed, // require at least one transition
                    ]);
                    assert!(
                        code.windows(reserve_sequence.len())
                            .any(|bytes| bytes == reserve_sequence),
                        "x86 candidate verifier must clamp an affordable reservation",
                    );

                    let precharge = [
                        0x4d, 0x89, 0xeb, // reserved transition count
                        0x49, 0xc1, 0xe3, shift, // convert to fixed-point debt
                        0x4d, 0x01, 0xdc, // precharge
                    ];
                    assert!(
                        code.windows(precharge.len())
                            .any(|bytes| bytes == precharge)
                    );
                    assert!(code.windows(3).any(|bytes| bytes == [0x41, 0xff, 0xcd]));

                    let refund = [
                        0x49, 0xc1, 0xe5, shift, // unused transitions to debt
                        0x4d, 0x29, 0xec, // refund
                    ];
                    assert!(
                        code.windows(refund.len()).any(|bytes| bytes == refund),
                        "x86 rejection must refund unused verifier capacity",
                    );

                    let mut old_loop_charge = vec![0x49, 0x81, 0xc4];
                    old_loop_charge
                        .extend_from_slice(&u32::from(guard.transition_debt).to_le_bytes());
                    old_loop_charge.extend_from_slice(&[0x49, 0x8b, 0x00, 0x48, 0x05]);
                    old_loop_charge
                        .extend_from_slice(&u32::from(guard.initial_credit).to_le_bytes());
                    old_loop_charge.extend_from_slice(&[0x49, 0x39, 0xc4]);
                    assert!(
                        !code
                            .windows(old_loop_charge.len())
                            .any(|bytes| bytes == old_loop_charge),
                        "x86 transition loop retained per-transition accounting",
                    );
                }
                Architecture::Aarch64 => {
                    let words = code
                        .chunks_exact(4)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                        .collect::<Vec<_>>();
                    assert!(words.contains(&aarch64_mov_x(17, 2).unwrap()));
                    assert!(
                        words.contains(&aarch64_add_x_imm(17, 17, guard.candidate_debt).unwrap())
                    );
                    if target.features.has(CpuFeature::Aarch64Asimd) {
                        assert!(
                            words.contains(&aarch64_add_x_imm(17, 17, guard.vector_debt).unwrap()),
                            "adaptive ASIMD code must charge vector refinement"
                        );
                    }
                    let reserve_prefix = [
                        aarch64_add_x_imm(12, 2, guard.initial_credit).unwrap(),
                        aarch64_sub_x_reg(12, 12, 17).unwrap(),
                        aarch64_lsr_x_imm(12, 12, shift).unwrap(),
                        aarch64_movz_w(10, u16::from(search.max_verify_bytes)).unwrap(),
                        aarch64_cmp_x(12, 10).unwrap(),
                        aarch64_csel_x(10, 12, 10, AARCH64_LO).unwrap(),
                    ];
                    let reserve = words
                        .windows(reserve_prefix.len() + 1)
                        .find(|actual| actual.starts_with(&reserve_prefix))
                        .expect("AArch64 candidate verifier must clamp an affordable reservation");
                    assert_eq!(
                        reserve[reserve_prefix.len()] & 0xff00_001f,
                        0x3400_000a,
                        "AArch64 empty reservation must use CBZ",
                    );
                    assert!(words.contains(&aarch64_context_add_x_lsl(17, 17, 10, shift).unwrap()));
                    assert!(words.contains(&aarch64_sub_w_imm(10, 10, 1).unwrap()));
                    assert!(
                        words.contains(&aarch64_context_sub_x_lsl(17, 17, 10, shift).unwrap()),
                        "AArch64 rejection must refund unused verifier capacity",
                    );
                    let old_loop_charge = [
                        aarch64_add_x_imm(17, 17, guard.transition_debt).unwrap(),
                        aarch64_context_load_x(12, 4, 0).unwrap(),
                        aarch64_add_x_imm(12, 12, guard.initial_credit).unwrap(),
                        aarch64_cmp_x(17, 12).unwrap(),
                    ];
                    assert!(
                        !words
                            .windows(old_loop_charge.len())
                            .any(|actual| actual == old_loop_charge),
                        "AArch64 transition loop retained per-transition accounting",
                    );
                }
            }
        }

        let small_pattern = r"(?-u:\b)zzzzzz(?:ab|a)(?s:.)*?";
        let small = compile(
            CompileRequest::new(small_pattern, host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let small_view = small.program().native_context_program_view().unwrap();
        assert!(
            derive_context_anchored_forward_search(small_view)
                .unwrap()
                .is_some()
        );
        let small_layout = build_context_native_layout_with_accelerators(
            small_view,
            ContextNativeLimits::default(),
            false,
            true,
        )
        .unwrap();
        assert!(
            small_layout
                .anchored_forward
                .expect("small anchored layout")
                .byte_sentinel_offset
                .is_some()
        );

        let quotiented = compile(
            CompileRequest::new(pattern, host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let quotiented_view = quotiented.program().native_context_program_view().unwrap();
        let quotiented_layout = build_context_native_layout_with_accelerators(
            quotiented_view,
            ContextNativeLimits::default(),
            false,
            true,
        )
        .unwrap();
        assert!(
            quotiented_layout
                .anchored_forward
                .expect("quotiented anchored layout")
                .byte_sentinel_offset
                .is_some(),
            "the semantic quotient now makes the selected direct-byte sidecar fit"
        );
        assert_eq!(
            quotiented
                .search(b"!AAAAAAx!", SearchWindow::new(0, 9))
                .unwrap(),
            MatchResult::Span(Some((1, 8))),
        );
    }

    #[test]
    fn adaptive_fallback_preserves_later_matches_empty_initials_and_priority() {
        let target = host_target();
        let cover_pattern =
            r"(?-u:\b)[ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ](?s:.)*?";
        let (cover_search, cover_guard, _) = anchored_guard_for(cover_pattern, target);
        assert!(cover_search.cover_inflation > 0);
        let mut cover_haystack = b"##".to_vec();
        cover_haystack.extend(std::iter::repeat_n(b'B', 96));
        cover_haystack.extend_from_slice(b"!AAAAAAx!");
        let window_start = 2_usize;
        let mut debt = u64::try_from(window_start).unwrap();
        let cover_fallback = (window_start..window_start + 96)
            .find(|&candidate| {
                !adaptive_charge(
                    &mut debt,
                    cover_guard.candidate_debt,
                    u64::try_from(candidate).unwrap(),
                    cover_guard,
                )
            })
            .expect("dense false cover must exhaust the adaptive allowance");
        assert!(cover_fallback < window_start + 96);
        let cover = compile(
            CompileRequest::new(cover_pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let full = cover
            .search(
                &cover_haystack,
                SearchWindow::new(window_start, cover_haystack.len()),
            )
            .unwrap();
        assert_eq!(
            cover
                .search(
                    &cover_haystack,
                    SearchWindow::new(cover_fallback, cover_haystack.len()),
                )
                .unwrap(),
            full
        );
        assert!(matches!(full, MatchResult::Span(Some(_))));

        let mut empty_haystack = b"##x".to_vec();
        empty_haystack.extend(std::iter::repeat_n(b'a', 96));
        empty_haystack.extend_from_slice(b"!aaaabbbb!");
        for (pattern, expected_width) in
            [(r"(?-u:\b)aaaab+", 8_usize), (r"(?-u:\b)aaaab+?", 5_usize)]
        {
            let (_, guard, _) = anchored_guard_for(pattern, target);
            let mut debt = u64::try_from(window_start).unwrap();
            let fallback = (3_usize..3 + 93)
                .find(|&candidate| {
                    !adaptive_charge(
                        &mut debt,
                        guard.candidate_debt,
                        u64::try_from(candidate).unwrap(),
                        guard,
                    )
                })
                .expect("dense empty initials must exhaust the adaptive allowance");
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let full = compiled
                .search(
                    &empty_haystack,
                    SearchWindow::new(window_start, empty_haystack.len()),
                )
                .unwrap();
            let fallback_result = compiled
                .search(
                    &empty_haystack,
                    SearchWindow::new(fallback, empty_haystack.len()),
                )
                .unwrap();
            assert_eq!(fallback_result, full);
            let MatchResult::Span(Some((start, end))) = full else {
                panic!("later valid match was lost: {full:?}");
            };
            assert_eq!(end.checked_sub(start), Some(expected_width));
        }
    }

    #[test]
    fn anchored_forward_search_is_graph_general_and_keeps_false_covers_sidecar_only()
    -> Result<(), ObjectError> {
        let patterns = [
            r"(?-u:\b)zzzzzz(?:ab|a)(?s:.)*?",
            r"(?-u:\b)[ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ][ACEGIKMOQ](?s:.)*?",
            r"(?-u:\b)zzzzzza{100}(?s:.)*?",
            r"(?-u:\b)[45Vjuv][45Vjuv](?s:.)+?",
        ];
        for pattern in patterns {
            let compiled = compile(
                CompileRequest::new(pattern, host_target())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            let view = compiled.program().native_context_program_view().unwrap();
            let ordinary = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())?;
            let ordinary_vector = derive_vector_filter(ordinary, view.anchored_prefix.sets())?;
            let interior = derive_context_interior_guard(view)?.filter(|guard| {
                ordinary.is_none_or(|prefix| {
                    filter_selection_key(guard.primary) < filter_selection_key(prefix)
                })
            });
            let suffix = derive_context_terminal_suffix_search(view)?.filter(|suffix| {
                use_context_terminal_suffix_search(
                    view.output,
                    *suffix,
                    ordinary,
                    ordinary_vector,
                    interior,
                )
            });
            assert!(suffix.is_none(), "suffix displaced sidecar for {pattern:?}");
            let search = derive_context_anchored_forward_search(view)?
                .unwrap_or_else(|| panic!("no anchored search for {pattern:?}"));
            assert!(search.guarded_bytes >= 3);
            let installed = build_context_native_layout_with_accelerators(
                view,
                ContextNativeLimits::default(),
                false,
                true,
            )?;
            assert!(installed.anchored_forward.is_some());

            if pattern.contains("ACEGIKMOQ") {
                assert!(!search.primary.from_anchored_prefix);
                let plan = derive_context_prefix_predicates(
                    view.anchored_prefix.sets(),
                    search.primary,
                    search.vector_filter,
                    host_target().architecture,
                )?;
                assert!(!plan.predicates().is_empty());
            }
        }

        let nullable = compile(
            CompileRequest::new(r"(?-u:\b)(?:|[45Vjuv][45Vjuv](?s:.)+?)", host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert!(
            derive_context_anchored_forward_search(
                nullable.program().native_context_program_view().unwrap()
            )?
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn anchored_forward_receipt_and_x86_saved_registers_follow_emitted_route() {
        // Eight fragmented exact alternatives exercise the complete ASIMD
        // constant allocation as well as the sidecar entry route.
        let pattern = r"(?-u:\b)[ACEGIKMO][ACEGIKMO](?s:.)+?";
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw);
        let targets = [
            (Target::x86_64_linux(), StartAccelerator::X86Sse2, false),
            (
                Target::x86_64_linux()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                StartAccelerator::X86Avx2,
                true,
            ),
            (
                Target::x86_64_linux().with_features(avx512).unwrap(),
                StartAccelerator::X86Avx512Bw,
                true,
            ),
            (Target::aarch64_linux(), StartAccelerator::Scalar, false),
            (
                Target::aarch64_linux()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
                StartAccelerator::Aarch64Asimd,
                false,
            ),
        ];
        for (target, expected, needs_vzeroupper) in targets {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap();
            assert_eq!(compiled.module().start_accelerator(), expected);
            assert_eq!(compiled.module().anchored_prefix_filter_bytes(), 3);
            if target.architecture == Architecture::X86_64 {
                let code = compiled.module().sections()[TEXT_SECTION].bytes();
                assert!(code.starts_with(&[0x41, 0x54, 0x41, 0x55]));
                assert!(code.ends_with(&[0x41, 0x5d, 0x41, 0x5c, 0xc3]));
                assert_eq!(
                    code.windows(3).any(|window| window == [0xc5, 0xf8, 0x77]),
                    needs_vzeroupper
                );
            } else if target.features.has(CpuFeature::Aarch64Asimd) {
                let words = compiled.module().sections()[TEXT_SECTION]
                    .bytes()
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert!(words.contains(&super::super::aarch64_movi_16b(23, b'O').unwrap()));
                assert!(
                    words.contains(
                        &super::super::aarch64_cmeq_16b(
                            super::super::AARCH64_EXACT_FILTER_SCRATCH,
                            0,
                            23,
                        )
                        .unwrap()
                    )
                );
                for preserved in 8_u8..=15 {
                    for &byte in b"ACEGIKMO" {
                        assert!(
                            !words.contains(
                                &super::super::aarch64_movi_16b(preserved, byte).unwrap()
                            ),
                            "sidecar writes ABI-preserved V{preserved}"
                        );
                    }
                }
                for source in [0_u8, 16, 17, 18, 19] {
                    for constant in 1_u8..=8 {
                        assert!(
                            !words.contains(
                                &super::super::aarch64_cmeq_16b(15, source, constant).unwrap()
                            ),
                            "sidecar retains the former ABI-clobbering V15 scratch"
                        );
                    }
                }
            }
        }

        // A graph that misses sidecar admission keeps the legacy x86 leaf
        // prologue rather than paying unconditional saved-register traffic.
        let ordinary = compile(
            CompileRequest::new(r"(?-u:\b)[a-z]+(?-u:\b)", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert!(
            ordinary.module().sections()[TEXT_SECTION]
                .bytes()
                .starts_with(&[0x48, 0x85, 0xf6])
        );
    }

    #[test]
    fn contextual_primary_filter_uses_variable_length_sve_when_supported() {
        let target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
            .unwrap();
        let compiled = compile(
            CompileRequest::new(r"(?-u:\b)z(?s:.)*?", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert_eq!(
            compiled.module().start_accelerator(),
            StartAccelerator::Aarch64Sve
        );
        let words = compiled.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        for word in [
            super::super::aarch64_sve_ptrue_b(),
            super::super::aarch64_sve_cntb(6).unwrap(),
            super::super::aarch64_sve_ld1b_vl(0, 12, 0).unwrap(),
            super::super::aarch64_sve_ld1b_vl(0, 12, 1).unwrap(),
            super::super::aarch64_sve_ld1b_vl(0, 12, 2).unwrap(),
            super::super::aarch64_sve_ld1b_vl(0, 12, 3).unwrap(),
            super::super::aarch64_sve_ptest_p0(4).unwrap(),
            super::super::aarch64_sve_addvl(2, 2, 4).unwrap(),
            super::super::aarch64_sve_addvl(2, 2, 1).unwrap(),
            super::super::aarch64_sve_whilelo_b(0, 2, 3).unwrap(),
            super::super::aarch64_sve_brkb_p0(2, 1).unwrap(),
            super::super::aarch64_sve_cntp_p0_p2(12).unwrap(),
        ] {
            assert!(
                words.contains(&word),
                "missing contextual SVE word {word:#010x}"
            );
        }

        let sve2 = compile(
            CompileRequest::new(
                r"(?-u:\b)z(?s:.)*?",
                Target::aarch64_linux()
                    .with_features(
                        FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
                    )
                    .unwrap(),
            )
            .mode(CompileMode::Optimizing)
            .output(OutputContract::Span),
        )
        .unwrap();
        assert_eq!(
            sve2.module().start_accelerator(),
            StartAccelerator::Aarch64Sve2
        );
        let sve2_words = sve2.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(sve2_words.contains(&super::super::aarch64_sve_ld1rqb(16, 12).unwrap()));
        assert!(sve2_words.contains(&super::super::aarch64_sve2_match_b(1, 0, 16).unwrap()));
        assert_ne!(compiled.object(), sve2.object());
    }

    #[test]
    fn contextual_sve_receipt_aggregates_every_emitted_prepass() {
        let target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2))
            .unwrap();
        let compile_span = |pattern| {
            compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Span),
            )
            .unwrap()
        };

        // The mandatory Z is an interior-only exact scanner: there is no
        // ordinary selective start before the unbounded wildcard.
        let interior_only = compile_span(r"(?-u:\b)(?s:.)*Z");
        assert_eq!(
            interior_only.module().start_accelerator(),
            StartAccelerator::Aarch64Sve2
        );
        let interior_words = interior_only.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(interior_words.contains(&super::super::aarch64_sve_ptrue_b()));
        assert!(interior_words.contains(&super::super::aarch64_sve2_match_b(1, 0, 16).unwrap()));

        // This graph has an exact mandatory interior Z (SVE2 MATCH) and a
        // non-exact ordinary [a-z] primary (base-SVE range compares). The
        // receipt reports the strongest tier among both emitted routes.
        let mixed = compile_span(r"(?-u:\b)[a-z]+Z(?s:.)*?");
        assert_eq!(
            mixed.module().start_accelerator(),
            StartAccelerator::Aarch64Sve2
        );
        let mixed_words = mixed.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            mixed_words
                .iter()
                .filter(|&&word| word == super::super::aarch64_sve_ptrue_b())
                .count(),
            3,
            "both prepasses have predicate-restoring entries and only SVE2 needs a setup predicate for LD1RQB"
        );
        assert_eq!(
            mixed_words
                .iter()
                .filter(|&&word| word == super::super::aarch64_sve_cntb(6).unwrap())
                .count(),
            2,
            "CNTB must remain invariant inside each of the two emitted prepasses"
        );
        assert!(mixed_words.contains(&super::super::aarch64_sve2_match_b(1, 0, 16).unwrap()));
        assert!(mixed_words.contains(&super::super::aarch64_sve_cmphs_b(1, 0, 16).unwrap()));
    }

    #[test]
    #[ignore = "links and executes ordinary/context ASIMD entries through an ABI sentinel wrapper"]
    #[allow(
        clippy::too_many_lines,
        reason = "object generation, the assembly ABI probe, and both entry-route assertions form one regression"
    )]
    fn linked_aarch64_asimd_entries_preserve_d8_and_d15() {
        if !cfg!(target_arch = "aarch64") {
            return;
        }

        let target = if cfg!(target_os = "macos") {
            Target::aarch64_macos()
        } else {
            Target::aarch64_linux()
        }
        .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
        .unwrap();
        let ordinary = compile(
            CompileRequest::new("[ACEGIKMO]", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        assert!(ordinary.program().native_dfa_view().is_some());
        let context = compile(
            CompileRequest::new(r"(?-u:\b)[ACEGIKMO][ACEGIKMO](?s:.)+?", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let context_view = context
            .program()
            .native_context_program_view()
            .expect("context ABI probe must retain the contextual DFA");
        assert!(
            derive_context_anchored_forward_search(context_view)
                .unwrap()
                .is_some(),
            "context ABI probe must emit the anchored sidecar route"
        );

        let mut ordinary_haystack = vec![b'x'; 160];
        ordinary_haystack[130] = b'O';
        assert_eq!(
            ordinary
                .search(&ordinary_haystack, SearchWindow::full(&ordinary_haystack),)
                .unwrap(),
            MatchResult::Span(Some((130, 131)))
        );
        let mut context_haystack = vec![b' '; 160];
        context_haystack[130..133].copy_from_slice(b"AOq");
        assert_eq!(
            context
                .search(&context_haystack, SearchWindow::full(&context_haystack),)
                .unwrap(),
            MatchResult::Span(Some((130, 133)))
        );

        let directory = std::env::temp_dir().join(format!(
            "fre-aot-aarch64-simd-abi-{}-{}",
            std::process::id(),
            if cfg!(target_os = "macos") {
                "macos"
            } else {
                "linux"
            }
        ));
        fs::create_dir_all(&directory).unwrap();
        let ordinary_object = directory.join("ordinary.o");
        let context_object = directory.join("context.o");
        fs::write(&ordinary_object, ordinary.object()).unwrap();
        fs::write(&context_object, context.object()).unwrap();

        let ordinary_bytes = ordinary_haystack
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let context_bytes = context_haystack
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let ordinary_symbol = ordinary.module().entry_symbol();
        let context_symbol = context.module().entry_symbol();
        let source = format!(
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n\
             typedef uint32_t (*regex_fn)(const unsigned char*,size_t,size_t,size_t,size_t*);\n\
             extern uint32_t fre_aot_aarch64_simd_abi_probe(const unsigned char*,size_t,size_t,size_t,size_t*,regex_fn);\n\
             extern uint32_t {ordinary_symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\n\
             extern uint32_t {context_symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\n\
             static const unsigned char ordinary_hay[] = {{{ordinary_bytes}}};\n\
             static const unsigned char context_hay[] = {{{context_bytes}}};\n\
             int main(void) {{ size_t r[2] = {{99,99}}; uint32_t s;\n\
             s=fre_aot_aarch64_simd_abi_probe(ordinary_hay,sizeof(ordinary_hay),0,sizeof(ordinary_hay),r,{ordinary_symbol});\n\
             if(s!=1||r[0]!=130||r[1]!=131)return 70;\n\
             r[0]=99;r[1]=99;\n\
             s=fre_aot_aarch64_simd_abi_probe(context_hay,sizeof(context_hay),0,sizeof(context_hay),r,{context_symbol});\n\
             if(s!=1||r[0]!=130||r[1]!=133)return 71;\n\
             puts(\"aarch64-simd-abi-preservation-ok\");return 0;}}\n"
        );
        let assembly = if cfg!(target_os = "macos") {
            ".section __TEXT,__text,regular,pure_instructions\n\
             .p2align 2\n\
             .globl _fre_aot_aarch64_simd_abi_probe\n\
             _fre_aot_aarch64_simd_abi_probe:\n\
             stp x29,x30,[sp,#-16]!\nmov x29,sp\nstp d8,d15,[sp,#-16]!\n\
             movz x9,#0xcdef\nmovk x9,#0x89ab,lsl #16\nmovk x9,#0x4567,lsl #32\nmovk x9,#0x0123,lsl #48\nfmov d8,x9\n\
             movz x10,#0x3210\nmovk x10,#0x7654,lsl #16\nmovk x10,#0xba98,lsl #32\nmovk x10,#0xfedc,lsl #48\nfmov d15,x10\n\
             blr x5\nmov w17,w0\n\
             fmov x9,d8\nmovz x10,#0xcdef\nmovk x10,#0x89ab,lsl #16\nmovk x10,#0x4567,lsl #32\nmovk x10,#0x0123,lsl #48\ncmp x9,x10\nb.ne 1f\n\
             fmov x9,d15\nmovz x10,#0x3210\nmovk x10,#0x7654,lsl #16\nmovk x10,#0xba98,lsl #32\nmovk x10,#0xfedc,lsl #48\ncmp x9,x10\nb.eq 2f\n\
             1:\nmov w17,#3\n2:\nldp d8,d15,[sp],#16\nldp x29,x30,[sp],#16\nmov w0,w17\nret\n"
        } else {
            ".text\n.p2align 2\n.global fre_aot_aarch64_simd_abi_probe\n.type fre_aot_aarch64_simd_abi_probe,%function\n\
             fre_aot_aarch64_simd_abi_probe:\n\
             stp x29,x30,[sp,#-16]!\nmov x29,sp\nstp d8,d15,[sp,#-16]!\n\
             movz x9,#0xcdef\nmovk x9,#0x89ab,lsl #16\nmovk x9,#0x4567,lsl #32\nmovk x9,#0x0123,lsl #48\nfmov d8,x9\n\
             movz x10,#0x3210\nmovk x10,#0x7654,lsl #16\nmovk x10,#0xba98,lsl #32\nmovk x10,#0xfedc,lsl #48\nfmov d15,x10\n\
             blr x5\nmov w17,w0\n\
             fmov x9,d8\nmovz x10,#0xcdef\nmovk x10,#0x89ab,lsl #16\nmovk x10,#0x4567,lsl #32\nmovk x10,#0x0123,lsl #48\ncmp x9,x10\nb.ne 1f\n\
             fmov x9,d15\nmovz x10,#0x3210\nmovk x10,#0x7654,lsl #16\nmovk x10,#0xba98,lsl #32\nmovk x10,#0xfedc,lsl #48\ncmp x9,x10\nb.eq 2f\n\
             1:\nmov w17,#3\n2:\nldp d8,d15,[sp],#16\nldp x29,x30,[sp],#16\nmov w0,w17\nret\n\
             .size fre_aot_aarch64_simd_abi_probe,.-fre_aot_aarch64_simd_abi_probe\n\
             .section .note.GNU-stack,\"\",%progbits\n"
        };
        let harness = directory.join("harness.c");
        let probe = directory.join("abi_probe.S");
        let executable = directory.join("harness");
        fs::write(&harness, source).unwrap();
        fs::write(&probe, assembly).unwrap();
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let output = Command::new(compiler)
            .arg("-O2")
            .arg("-std=c11")
            .arg(&harness)
            .arg(&probe)
            .arg(&ordinary_object)
            .arg(&context_object)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "aarch64-simd-abi-preservation-ok"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "derivation provenance and every target lowering are one cutoff proof"
    )]
    fn bounded_terminal_suffix_distance_is_graph_derived_and_lowered_on_every_isa()
    -> Result<(), ObjectError> {
        let finite_pattern = r"(?-u:\B(?:A[a-z]{0,16}fpez|qfpez))";
        let finite = compile(
            CompileRequest::new(finite_pattern, host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let view = finite.program().native_context_program_view().unwrap();
        assert_eq!(view.max_match_width, Some(21));
        assert_eq!(view.exact_match_width, None);
        let prefix = derive_anchored_prefix_start_filter(view.anchored_prefix.sets())?;
        let prefix_vector = derive_vector_filter(prefix, view.anchored_prefix.sets())?;
        let interior = derive_context_interior_guard(view)?.filter(|guard| {
            prefix.is_none_or(|candidate| {
                filter_selection_key(guard.primary) < filter_selection_key(candidate)
            })
        });
        let suffix = derive_context_terminal_suffix_search(view)?.unwrap();
        assert_eq!(suffix.minimum_width, 5);
        assert_eq!(suffix.bounded_scan_distance, Some(16));
        assert!(use_context_terminal_suffix_search(
            view.output,
            suffix,
            prefix,
            prefix_vector,
            interior,
        ));

        let unbounded = compile(
            CompileRequest::new(r"(?-u:\B(?:A[a-z]*fpez|qfpez))", host_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let unbounded_view = unbounded.program().native_context_program_view().unwrap();
        assert_eq!(unbounded_view.max_match_width, None);
        assert_eq!(
            derive_context_terminal_suffix_search(unbounded_view)?
                .unwrap()
                .bounded_scan_distance,
            None
        );

        for output in [OutputContract::SelectedEnd, OutputContract::Span] {
            let exact = compile(
                CompileRequest::new(r"(?-u:\B(?:Afpez|qfpez))", host_target())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let exact_view = exact.program().native_context_program_view().unwrap();
            assert_eq!(exact_view.exact_match_width, Some(5));
            assert!(derive_context_terminal_suffix_search(exact_view)?.is_none());
        }

        let x86_variants = [
            (FeatureSet::EMPTY, StartAccelerator::X86Sse2),
            (
                FeatureSet::of(CpuFeature::X86Avx2),
                StartAccelerator::X86Avx2,
            ),
            (
                FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw),
                StartAccelerator::X86Avx512Bw,
            ),
        ];
        for base_target in [Target::x86_64_linux(), Target::x86_64_macos()] {
            for (features, accelerator) in x86_variants {
                let target = base_target.with_features(features).unwrap();
                for output in [OutputContract::SelectedEnd, OutputContract::Span] {
                    let compiled = compile(
                        CompileRequest::new(finite_pattern, target)
                            .mode(CompileMode::Optimizing)
                            .output(output),
                    )
                    .unwrap();
                    assert_eq!(compiled.module().start_accelerator(), accelerator);
                    assert_eq!(compiled.module().required_runtime_program(), None);
                    let code = compiled.module().sections()[TEXT_SECTION].bytes();
                    assert!(
                        code.windows(6)
                            .any(|bytes| bytes == [0x48, 0x3d, 0x00, 0x01, 0x00, 0x00]),
                        "missing ordered 256-byte threshold for {output:?} on {target:?}",
                    );
                    assert!(
                        code.windows(10).any(|bytes| {
                            bytes == [0xb8, 0x10, 0x00, 0x00, 0x00, 0x49, 0x39, 0xc3, 0x0f, 0x83]
                        }),
                        "missing unsigned distance-16 cutoff for {output:?} on {target:?}",
                    );
                }
            }
        }
        for target in [Target::aarch64_linux(), Target::aarch64_macos()] {
            let target = target
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap();
            for output in [OutputContract::SelectedEnd, OutputContract::Span] {
                let compiled = compile(
                    CompileRequest::new(finite_pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                assert_eq!(
                    compiled.module().start_accelerator(),
                    StartAccelerator::Aarch64Asimd
                );
                assert_eq!(compiled.module().required_runtime_program(), None);
                let code = compiled.module().sections()[TEXT_SECTION].bytes();
                let words = code
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert!(
                    words.contains(&aarch64_cmp_x_imm(12, 256).unwrap()),
                    "missing ordered 256-byte threshold for {output:?} on {target:?}",
                );
                assert!(
                    code.windows(12).any(|bytes| {
                        bytes
                            == [
                                0x4c, 0x00, 0x08, 0xcb, // sub x12, x2, x8
                                0x0b, 0x02, 0x80, 0xd2, // mov x11, #16
                                0x9f, 0x01, 0x0b, 0xeb, // cmp x12, x11
                            ]
                    }),
                    "missing unsigned distance-16 cutoff for {output:?} on {target:?}",
                );
            }
        }
        Ok(())
    }

    #[test]
    fn contextual_x86_scanners_follow_target_feature_width() {
        let patterns = [
            (
                "(?-u:\\b(?:(?:(?:(?:(?:(?:7NGGByK))+?){1,2}?){1,3}?[S-U]))\\b)",
                OutputContract::Exists,
            ),
            (
                "(?-u:\\b(?:(?:(?:(?:(?:(?:[n-r]){2,5}?)*?[2-4])){2,4}fpe7))\\b)",
                OutputContract::Span,
            ),
        ];
        let variants = [
            (FeatureSet::EMPTY, StartAccelerator::X86Sse2),
            (
                FeatureSet::of(CpuFeature::X86Avx2),
                StartAccelerator::X86Avx2,
            ),
            (
                FeatureSet::of(CpuFeature::X86Avx512F).with(CpuFeature::X86Avx512Bw),
                StartAccelerator::X86Avx512Bw,
            ),
        ];
        for (features, accelerator) in variants {
            for (pattern, output) in patterns {
                let target = Target::x86_64_linux().with_features(features).unwrap();
                let compiled = compile(
                    CompileRequest::new(pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                assert_eq!(compiled.module().start_accelerator(), accelerator);
                let code = compiled.module().sections()[TEXT_SECTION].bytes();
                assert_eq!(
                    code.windows(3).any(|bytes| bytes == [0xc5, 0xf8, 0x77]),
                    features.has(CpuFeature::X86Avx2)
                        || (features.has(CpuFeature::X86Avx512F)
                            && features.has(CpuFeature::X86Avx512Bw)),
                    "{pattern:?} {accelerator:?}",
                );
            }
        }
    }

    #[test]
    fn contextual_x86_short_batch_is_avx2_specific_and_graph_gated() {
        assert_eq!(
            context_x86_short_batch_bytes(X86StartFilterKind::Avx2, true),
            Some(64)
        );
        assert_eq!(
            context_x86_short_batch_bytes(X86StartFilterKind::Avx2, false),
            None
        );
        assert_eq!(
            context_x86_short_batch_bytes(X86StartFilterKind::Sse2, true),
            None
        );
        assert_eq!(
            context_x86_short_batch_bytes(X86StartFilterKind::Avx512Bw, true),
            None
        );
    }

    #[test]
    fn aarch64_prefix_bitmap_clears_span_tag_scratch() {
        let pattern = "(?m)^(?:6Jc)+[2-6]ax[t-w]hp$";
        let reset_tag = aarch64_movz_w(10, 0).unwrap();
        let bitmap_index = aarch64_lsr_x_imm(10, 8, 6).unwrap();
        for base in [Target::aarch64_linux(), Target::aarch64_macos()] {
            for features in [FeatureSet::EMPTY, FeatureSet::of(CpuFeature::Aarch64Asimd)] {
                let target = base.with_features(features).unwrap();
                let compiled = compile(
                    CompileRequest::new(pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::Span),
                )
                .unwrap();
                let words = compiled.module().sections()[TEXT_SECTION]
                    .bytes()
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert!(
                    words.contains(&bitmap_index),
                    "regression pattern lost its bitmap predicate on {target:?}"
                );
                assert!(
                    words.iter().filter(|&&word| word == reset_tag).count() >= 2,
                    "prefix predicate scratch can reach the Span tag on {target:?}"
                );
            }
        }
    }

    #[test]
    fn contextual_raw_pair_initial_dispatch_has_exact_isa_loads() {
        let pattern = "(?-u:\\b(?:cat|dog)\\b)";
        let x86 = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let view = x86.program().native_context_program_view().unwrap();
        let layout =
            build_context_native_layout_with_reverse(view, ContextNativeLimits::default(), false)
                .unwrap();
        assert!(layout.raw_pair_initial.is_some());
        let x86_code = x86.module().sections()[TEXT_SECTION].bytes();
        assert!(
            x86_code
                .windows(5)
                .any(|bytes| bytes == [0x0f, 0xb7, 0x44, 0x17, 0xff]),
            "x86 interior context must form one raw adjacent-byte index",
        );
        assert!(
            x86_code
                .windows(5)
                .any(|bytes| bytes == [0x41, 0x0f, 0xb7, 0x84, 0x41]),
            "x86 raw dispatch must use a scaled halfword lookup",
        );
        let aarch64 = compile(
            CompileRequest::new(pattern, Target::aarch64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        let words = aarch64.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(words.contains(&aarch64_load_halfword_reg(8, 0, 11).unwrap()));
        assert!(words.contains(&aarch64_context_load_h_lsl1(8, 12, 8).unwrap()));

        let reverse_pattern = "(?-u:\\b(?:cat|dogs)\\b)";
        let x86_span = compile(
            CompileRequest::new(reverse_pattern, Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let reverse_view = x86_span.program().native_context_program_view().unwrap();
        assert!(reverse_view.exact_match_width.is_none());
        let reverse_layout = build_context_native_layout_with_reverse(
            reverse_view,
            ContextNativeLimits::default(),
            false,
        )
        .unwrap();
        assert!(reverse_layout.raw_pair_reverse_initial.is_some());
        let x86_span_code = x86_span.module().sections()[TEXT_SECTION].bytes();
        assert!(
            x86_span_code
                .windows(5)
                .filter(|bytes| *bytes == [0x41, 0x0f, 0xb7, 0x84, 0x41])
                .count()
                >= 2,
            "x86 Span must use scaled halfword lookup in both directions",
        );
        assert!(
            x86_span_code
                .windows(5)
                .any(|bytes| bytes == [0xa9, 0x00, 0x80, 0x00, 0x00]),
            "x86 raw reverse dispatch must test bit 15, not the sign bit",
        );

        let aarch64_span = compile(
            CompileRequest::new(reverse_pattern, Target::aarch64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .unwrap();
        let span_words = aarch64_span.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(
            span_words
                .iter()
                .filter(|&&word| word == aarch64_context_load_h_lsl1(8, 12, 8).unwrap())
                .count()
                >= 2,
            "AArch64 Span must use scaled halfword lookup in both directions",
        );
        assert!(
            span_words
                .iter()
                .any(|&word| word & 0xfff8_001f == 0x3778_0008),
            "AArch64 raw reverse dispatch must test bit 15 directly",
        );
    }

    #[test]
    fn contextual_direct_byte_helpers_have_exact_minimal_isa_shapes() {
        const OFFSET: u32 = 0x4433_2211;

        let mut x86_byte = X86Assembler::new();
        x86_emit_direct_byte_context_cell(&mut x86_byte, OFFSET).unwrap();
        assert_eq!(
            x86_byte.finish().unwrap(),
            [
                0x41, 0xc1, 0xe2, 0x08, // shl r10d, 8
                0x44, 0x01, 0xd0, // add eax, r10d
                0x41, 0x8b, 0x84, 0x81, 0x11, 0x22, 0x33, 0x44,
            ]
        );
        let mut x86_sentinel = X86Assembler::new();
        x86_emit_direct_sentinel_context_cell(&mut x86_sentinel, OFFSET).unwrap();
        assert_eq!(
            x86_sentinel.finish().unwrap(),
            [0x43, 0x8b, 0x84, 0x91, 0x11, 0x22, 0x33, 0x44]
        );

        let mut aarch64_forward = Aarch64Assembler::new();
        aarch64_context_emit_direct_byte_cell(&mut aarch64_forward, 6, 11).unwrap();
        assert_eq!(
            aarch64_forward.finish().unwrap(),
            [0x70, 0x21, 0x06, 0x8b, 0xe8, 0x79, 0x70, 0xb8]
        );
        let mut aarch64_reverse = Aarch64Assembler::new();
        aarch64_context_emit_direct_byte_cell(&mut aarch64_reverse, 6, 12).unwrap();
        assert_eq!(
            aarch64_reverse.finish().unwrap(),
            [0x90, 0x21, 0x06, 0x8b, 0xe8, 0x79, 0x70, 0xb8]
        );
        let mut aarch64_sentinel = Aarch64Assembler::new();
        aarch64_context_emit_direct_sentinel_cell(&mut aarch64_sentinel, 6).unwrap();
        assert_eq!(aarch64_sentinel.finish().unwrap(), [0xa8, 0x79, 0x66, 0xb8]);
    }

    #[test]
    fn populated_transition_trust_has_exact_checked_and_trusted_isa_shapes() {
        assert!(ENABLE_CONTEXT_TRUST_POPULATED_TRANSITIONS);

        let mut x86_checked = X86Assembler::new();
        let x86_checked_invalid = x86_checked.label().unwrap();
        x86_emit_decode_populated_forward_transition_mode(
            &mut x86_checked,
            x86_checked_invalid,
            false,
        )
        .unwrap();
        x86_checked.bind(x86_checked_invalid).unwrap();
        assert_eq!(
            x86_checked.finish().unwrap(),
            [
                0x41, 0x89, 0xc3, // preserve event bit
                0x25, 0xff, 0xff, 0xff, 0x0f, // forward payload
                0x85, 0xc0, // test nonzero payload
                0x74, 0x0b, // jz invalid
                0xff, 0xc8, // state + 1 -> state
                0x41, 0x89, 0xc2, // r10d = state
                0x44, 0x89, 0xd8, // eax = packed cell
                0xc1, 0xe8, 0x1c, // successor flags
            ]
        );
        let mut x86_trusted = X86Assembler::new();
        let x86_trusted_invalid = x86_trusted.label().unwrap();
        x86_emit_decode_populated_forward_transition_mode(
            &mut x86_trusted,
            x86_trusted_invalid,
            true,
        )
        .unwrap();
        x86_trusted.bind(x86_trusted_invalid).unwrap();
        assert_eq!(
            x86_trusted.finish().unwrap(),
            [
                0x41, 0x89, 0xc3, // preserve event bit
                0x25, 0xff, 0xff, 0xff, 0x0f, // forward payload
                0xff, 0xc8, // state + 1 -> state
                0x41, 0x89, 0xc2, // r10d = state
                0x44, 0x89, 0xd8, // eax = packed cell
                0xc1, 0xe8, 0x1c, // successor flags
            ]
        );
        let mut x86_reverse_checked = X86Assembler::new();
        let x86_reverse_invalid = x86_reverse_checked.label().unwrap();
        x86_emit_populated_transition_valid_mode(
            &mut x86_reverse_checked,
            x86_reverse_invalid,
            false,
        )
        .unwrap();
        x86_reverse_checked.bind(x86_reverse_invalid).unwrap();
        assert_eq!(
            x86_reverse_checked.finish().unwrap(),
            [0xa9, 0x00, 0x00, 0x00, 0x40, 0x74, 0]
        );
        let mut x86_reverse_trusted = X86Assembler::new();
        let x86_reverse_trusted_invalid = x86_reverse_trusted.label().unwrap();
        x86_emit_populated_transition_valid_mode(
            &mut x86_reverse_trusted,
            x86_reverse_trusted_invalid,
            true,
        )
        .unwrap();
        x86_reverse_trusted
            .bind(x86_reverse_trusted_invalid)
            .unwrap();
        assert!(x86_reverse_trusted.finish().unwrap().is_empty());

        let mut aarch64_checked = Aarch64Assembler::new();
        let aarch64_checked_invalid = aarch64_checked.label().unwrap();
        aarch64_context_emit_decode_populated_forward_transition_mode(
            &mut aarch64_checked,
            aarch64_checked_invalid,
            false,
        )
        .unwrap();
        aarch64_checked.bind(aarch64_checked_invalid).unwrap();
        let aarch64_checked = aarch64_checked.finish().unwrap();
        assert_eq!(aarch64_checked.len(), 5 * 4);
        let checked_words = aarch64_checked
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(checked_words[0], aarch64_mov_x(12, 8).unwrap());
        assert_eq!(
            checked_words[1],
            aarch64_context_and_low_w(6, 8, 28).unwrap()
        );
        assert_eq!(checked_words[2] & 0xff00_001f, 0x3400_0006);
        assert_eq!(checked_words[3], aarch64_sub_w_imm(6, 6, 1).unwrap());
        assert_eq!(
            checked_words[4],
            aarch64_lsr_x_imm(8, 8, CONTEXT_FORWARD_CELL_FLAGS_SHIFT).unwrap()
        );

        let mut aarch64_trusted = Aarch64Assembler::new();
        let aarch64_trusted_invalid = aarch64_trusted.label().unwrap();
        aarch64_context_emit_decode_populated_forward_transition_mode(
            &mut aarch64_trusted,
            aarch64_trusted_invalid,
            true,
        )
        .unwrap();
        aarch64_trusted.bind(aarch64_trusted_invalid).unwrap();
        let aarch64_trusted = aarch64_trusted.finish().unwrap();
        let trusted_words = aarch64_trusted
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(
            trusted_words,
            [
                aarch64_mov_x(12, 8).unwrap(),
                aarch64_context_and_low_w(6, 8, 28).unwrap(),
                aarch64_sub_w_imm(6, 6, 1).unwrap(),
                aarch64_lsr_x_imm(8, 8, CONTEXT_FORWARD_CELL_FLAGS_SHIFT).unwrap(),
            ]
        );
        let mut aarch64_reverse_checked = Aarch64Assembler::new();
        let aarch64_reverse_invalid = aarch64_reverse_checked.label().unwrap();
        aarch64_context_emit_populated_transition_valid_mode(
            &mut aarch64_reverse_checked,
            aarch64_reverse_invalid,
            false,
        )
        .unwrap();
        aarch64_reverse_checked
            .bind(aarch64_reverse_invalid)
            .unwrap();
        assert_eq!(aarch64_reverse_checked.finish().unwrap().len(), 4);
        let mut aarch64_reverse_trusted = Aarch64Assembler::new();
        let aarch64_reverse_trusted_invalid = aarch64_reverse_trusted.label().unwrap();
        aarch64_context_emit_populated_transition_valid_mode(
            &mut aarch64_reverse_trusted,
            aarch64_reverse_trusted_invalid,
            true,
        )
        .unwrap();
        aarch64_reverse_trusted
            .bind(aarch64_reverse_trusted_invalid)
            .unwrap();
        assert!(aarch64_reverse_trusted.finish().unwrap().is_empty());
    }

    #[test]
    fn contextual_modules_are_self_contained_on_every_supported_target() {
        let targets = [
            Target::x86_64_linux(),
            Target::x86_64_macos(),
            Target::aarch64_linux(),
            Target::aarch64_macos(),
        ];
        for target in targets {
            for (pattern, output, _) in cases() {
                let compiled = compile(
                    CompileRequest::new(pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                assert!(compiled.program().native_context_program_view().is_some());
                assert_eq!(compiled.module().required_runtime_program(), None);
                assert_eq!(compiled.module().symbols().len(), 2);
                assert!(
                    compiled
                        .module()
                        .relocations()
                        .iter()
                        .all(|relocation| relocation.symbol == PROGRAM_SYMBOL)
                );
                assert_eq!(
                    emit_object(
                        compiled.module(),
                        ObjectFormat::for_target(target),
                        usize::MAX,
                    )
                    .unwrap(),
                    compiled.object()
                );
            }
        }
    }

    fn host_target() -> Target {
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        return Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        return Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
        return if std::is_x86_feature_detected!("avx2") {
            Target::x86_64_macos()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap()
        } else {
            Target::x86_64_macos()
        };
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        return if std::is_x86_feature_detected!("avx2") {
            Target::x86_64_linux()
                .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                .unwrap()
        } else {
            Target::x86_64_linux()
        };
        #[allow(
            unreachable_code,
            reason = "the fallback keeps this test module type-checkable on unsupported hosts"
        )]
        Target::aarch64_macos()
    }

    #[allow(
        unreachable_code,
        reason = "the fallback keeps this test module type-checkable on unsupported hosts"
    )]
    fn host_differential_targets() -> Vec<Target> {
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        return vec![
            Target::aarch64_macos(),
            Target::aarch64_macos()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        ];
        #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
        return vec![
            Target::aarch64_linux(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        ];
        #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
        {
            let base = Target::x86_64_macos();
            let mut targets = vec![base];
            if std::is_x86_feature_detected!("avx2") {
                targets.push(
                    base.with_features(FeatureSet::of(CpuFeature::X86Avx2))
                        .unwrap(),
                );
            }
            return targets;
        }
        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        {
            let base = Target::x86_64_linux();
            let mut targets = vec![base];
            if std::is_x86_feature_detected!("avx2") {
                targets.push(
                    base.with_features(FeatureSet::of(CpuFeature::X86Avx2))
                        .unwrap(),
                );
            }
            return targets;
        }
        vec![Target::aarch64_macos()]
    }

    #[test]
    #[ignore = "links and executes the finite terminal-suffix cutoff boundary differential"]
    #[allow(
        clippy::too_many_lines,
        reason = "native bundle construction and every boundary expectation remain one audit unit"
    )]
    fn linked_host_bounded_terminal_suffix_cutoff_differential() {
        let target = host_target();
        let mut haystack = vec![b'!'; 1_400];
        haystack[100..110].copy_from_slice(b"!fpez!fpez");
        let equality = b"xAfpezabcdefghijklfpez";
        haystack[300..300 + equality.len()].copy_from_slice(equality);
        let earlier_update = b"xAqfpezabcdefghijkfpez";
        haystack[800..800 + earlier_update.len()].copy_from_slice(earlier_update);

        let patterns: [(&str, &[(usize, usize)]); 3] = [
            (
                r"(?-u:\B(?:A[a-z]{0,16}fpez|qfpez))",
                &[
                    (0, 280),
                    (20, 300),
                    (51, 306),
                    (50, 306),
                    (0, 306),
                    (67, 322),
                    (66, 322),
                    (0, 322),
                    (40, 322),
                    (301, 581),
                    (302, 581),
                    (0, 1_400),
                ],
            ),
            (
                r"(?-u:\B(?:A[a-z]{0,16}?fpez|qfpez))",
                &[
                    (0, 280),
                    (20, 300),
                    (51, 306),
                    (50, 306),
                    (0, 306),
                    (67, 322),
                    (66, 322),
                    (0, 322),
                    (40, 322),
                    (301, 581),
                    (302, 581),
                    (0, 1_400),
                ],
            ),
            (
                r"(?-u:\B(?:A[a-z]{16}fpez|qfpez))",
                &[
                    (0, 300),
                    (400, 807),
                    (400, 822),
                    (400, 1_400),
                    (801, 1_200),
                    (802, 1_200),
                    (823, 1_200),
                ],
            ),
        ];

        let directory = std::env::temp_dir().join(format!(
            "fre-aot-context-bounded-suffix-{}-{}",
            std::process::id(),
            if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            }
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut source = String::from(
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n\
             #define FAIL(i,w,s,x,y,es,ex,ey) do { fprintf(stderr,\"case %u window %u got %u/%zu/%zu expected %u/%zu/%zu\\n\",(unsigned)(i),(unsigned)(w),(unsigned)(s),(size_t)(x),(size_t)(y),(unsigned)(es),(size_t)(ex),(size_t)(ey)); return (int)(10+(i)); } while(0)\n",
        );
        writeln!(
            source,
            "static const unsigned char h[] = {{{}}};",
            haystack
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
        .unwrap();
        let mut body = String::from("int main(void) { size_t r[2]; uint32_t s;\n");
        let mut objects = Vec::new();
        for (pattern_index, (pattern, windows)) in patterns.iter().enumerate() {
            for (output_index, output) in [OutputContract::SelectedEnd, OutputContract::Span]
                .into_iter()
                .enumerate()
            {
                let case_index = pattern_index * 2 + output_index;
                let compiled = compile(
                    CompileRequest::new(*pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .unwrap();
                let view = compiled.program().native_context_program_view().unwrap();
                let prefix =
                    derive_anchored_prefix_start_filter(view.anchored_prefix.sets()).unwrap();
                let prefix_vector =
                    derive_vector_filter(prefix, view.anchored_prefix.sets()).unwrap();
                let interior = derive_context_interior_guard(view)
                    .unwrap()
                    .filter(|guard| {
                        prefix.is_none_or(|candidate| {
                            filter_selection_key(guard.primary) < filter_selection_key(candidate)
                        })
                    });
                let suffix = derive_context_terminal_suffix_search(view)
                    .unwrap()
                    .expect("audit pattern must derive a terminal suffix search");
                assert_eq!(view.max_match_width, Some(21));
                assert_eq!(suffix.minimum_width, 5);
                assert_eq!(suffix.bounded_scan_distance, Some(16));
                assert!(use_context_terminal_suffix_search(
                    view.output,
                    suffix,
                    prefix,
                    prefix_vector,
                    interior,
                ));

                let symbol = compiled.module().entry_symbol();
                writeln!(
                    source,
                    "extern uint32_t {symbol}(const unsigned char*, size_t, size_t, size_t, size_t*);"
                )
                .unwrap();
                let object = directory.join(format!("case-{case_index}.o"));
                fs::write(&object, compiled.object()).unwrap();
                objects.push(object);
                for (window_index, &(start, end)) in windows.iter().enumerate() {
                    let expected = compiled
                        .search(&haystack, SearchWindow::new(start, end))
                        .unwrap();
                    let (status, expected_start, expected_end) = match expected {
                        MatchResult::SelectedEnd(Some(end)) => (1_u32, end, end),
                        MatchResult::Span(Some((start, end))) => (1_u32, start, end),
                        MatchResult::SelectedEnd(None) | MatchResult::Span(None) => (0_u32, 0, 0),
                        other => panic!("unexpected result {other:?}"),
                    };
                    writeln!(
                        body,
                        "r[0]=99;r[1]=99;s={symbol}(h,sizeof(h),{start},{end},r);if(s!={status}||r[0]!={expected_start}||r[1]!={expected_end})FAIL({case_index},{window_index},s,r[0],r[1],{status},{expected_start},{expected_end});"
                    )
                    .unwrap();
                }
            }
        }

        // The equal-start candidate exactly at distance 16 is deliberately
        // skipped. Ordered replay must recover the greedy/lazy end choice.
        for output in [OutputContract::SelectedEnd, OutputContract::Span] {
            let greedy = compile(
                CompileRequest::new(patterns[0].0, target)
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let greedy_expected = match output {
                OutputContract::SelectedEnd => MatchResult::SelectedEnd(Some(322)),
                OutputContract::Span => MatchResult::Span(Some((301, 322))),
                OutputContract::Exists => unreachable!(),
            };
            assert_eq!(
                greedy.search(&haystack, SearchWindow::new(0, 322)).unwrap(),
                greedy_expected,
            );
            let lazy = compile(
                CompileRequest::new(patterns[1].0, target)
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let lazy_expected = match output {
                OutputContract::SelectedEnd => MatchResult::SelectedEnd(Some(306)),
                OutputContract::Span => MatchResult::Span(Some((301, 306))),
                OutputContract::Exists => unreachable!(),
            };
            assert_eq!(
                lazy.search(&haystack, SearchWindow::new(0, 322)).unwrap(),
                lazy_expected,
            );
            // The candidate at distance 15 can still begin one byte earlier
            // and must be reverse-verified before the cutoff is taken.
            let update = compile(
                CompileRequest::new(patterns[2].0, target)
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            let update_expected = match output {
                OutputContract::SelectedEnd => MatchResult::SelectedEnd(Some(822)),
                OutputContract::Span => MatchResult::Span(Some((801, 822))),
                OutputContract::Exists => unreachable!(),
            };
            assert_eq!(
                update
                    .search(&haystack, SearchWindow::new(400, 822))
                    .unwrap(),
                update_expected,
            );
        }

        body.push_str("puts(\"bounded-terminal-suffix-differential-ok\");return 0;}\n");
        source.push_str(&body);
        let harness = directory.join("harness.c");
        fs::write(&harness, source).unwrap();
        let executable = directory.join("harness");
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let output = Command::new(compiler)
            .arg("-O2")
            .arg("-std=c11")
            .arg(&harness)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "bounded-terminal-suffix-differential-ok"
        );
        println!("{}", directory.display());
    }

    #[test]
    #[ignore = "links and executes a C differential over every search window"]
    #[allow(
        clippy::too_many_lines,
        reason = "bundle construction and exact C expectations stay together for auditability"
    )]
    fn linked_host_context_differential() {
        for target in host_differential_targets() {
            linked_host_context_differential_for_target(target);
        }
    }

    #[test]
    #[ignore = "generates a base-SVE AArch64 Linux context differential bundle"]
    fn generate_aarch64_linux_sve_context_differential_bundle() {
        let directory = std::env::var_os("FRE_AOT_AARCH64_SVE_CONTEXT_BUNDLE").map_or_else(
            || {
                std::env::temp_dir().join(format!(
                    "fre-aot-aarch64-sve-context-bundle-{}",
                    std::process::id()
                ))
            },
            std::path::PathBuf::from,
        );
        build_context_differential_bundle(
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
                .unwrap(),
            directory,
            false,
        );
    }

    #[test]
    #[ignore = "generates an SVE2 AArch64 Linux context differential bundle"]
    fn generate_aarch64_linux_sve2_context_differential_bundle() {
        let directory = std::env::var_os("FRE_AOT_AARCH64_SVE2_CONTEXT_BUNDLE").map_or_else(
            || {
                std::env::temp_dir().join(format!(
                    "fre-aot-aarch64-sve2-context-bundle-{}",
                    std::process::id()
                ))
            },
            std::path::PathBuf::from,
        );
        build_context_differential_bundle(
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2))
                .unwrap(),
            directory,
            false,
        );
    }

    #[test]
    #[ignore = "generates a mixed ASIMD+SVE2 AArch64 Linux context differential bundle"]
    fn generate_aarch64_linux_mixed_sve2_context_differential_bundle() {
        let directory =
            std::env::var_os("FRE_AOT_AARCH64_MIXED_SVE2_CONTEXT_BUNDLE").map_or_else(
                || {
                    std::env::temp_dir().join(format!(
                        "fre-aot-aarch64-mixed-sve2-context-bundle-{}",
                        std::process::id()
                    ))
                },
                std::path::PathBuf::from,
            );
        build_context_differential_bundle(
            Target::aarch64_linux()
                .with_features(
                    FeatureSet::of(CpuFeature::Aarch64Asimd)
                        .with(CpuFeature::Aarch64Sve)
                        .with(CpuFeature::Aarch64Sve2),
                )
                .unwrap(),
            directory,
            false,
        );
    }

    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "native bundle construction and exact all-window expectations remain one audit unit"
    )]
    fn linked_host_context_differential_for_target(target: Target) {
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-context-native-{}-{}",
            std::process::id(),
            if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            }
        ));
        build_context_differential_bundle(target, directory, true);
    }

    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "native bundle construction and exact all-window expectations remain one audit unit"
    )]
    fn build_context_differential_bundle(
        target: Target,
        directory: std::path::PathBuf,
        execute: bool,
    ) {
        fs::create_dir_all(&directory).unwrap();
        let mut source = String::from(
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n\
             #define FAIL(c,i,a,b,s,x,y) do { fprintf(stderr,\"case %u window %zu..%zu status %u result %zu..%zu\\n\",(unsigned)(i),(size_t)(a),(size_t)(b),(unsigned)(s),(size_t)(x),(size_t)(y)); return (c); } while(0)\n",
        );
        let mut body = String::from("int main(void) { size_t r[2]; uint32_t s;\n");
        let mut objects = Vec::new();
        let mut first_symbol = None;
        let mut first_length = 0;
        let mut saw_sve = false;
        for (index, (pattern, output, haystack)) in cases().into_iter().enumerate() {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            assert!(compiled.program().native_context_program_view().is_some());
            assert_eq!(compiled.module().required_runtime_program(), None);
            saw_sve |= matches!(
                compiled.module().start_accelerator(),
                StartAccelerator::Aarch64Sve | StartAccelerator::Aarch64Sve2
            );
            let symbol = compiled.module().entry_symbol();
            first_symbol.get_or_insert_with(|| symbol.to_owned());
            if index == 0 {
                first_length = haystack.len();
            }
            writeln!(
                source,
                "extern uint32_t {symbol}(const unsigned char*, size_t, size_t, size_t, size_t*);"
            )
            .unwrap();
            let bytes = if haystack.is_empty() {
                "0".to_owned()
            } else {
                haystack
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            writeln!(
                source,
                "static const unsigned char h{index}[] = {{{bytes}}};"
            )
            .unwrap();
            let object = directory.join(format!("case-{index}.o"));
            fs::write(&object, compiled.object()).unwrap();
            objects.push(object);
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = compiled
                        .search(haystack, SearchWindow::new(start, end))
                        .unwrap();
                    writeln!(
                        body,
                        "r[0]=99;r[1]=99;s={symbol}(h{index},{},{start},{end},r);",
                        haystack.len()
                    )
                    .unwrap();
                    let condition = match expected {
                        MatchResult::Exists(found) => {
                            format!("s!={}||r[0]!=0||r[1]!=0", u8::from(found))
                        }
                        MatchResult::SelectedEnd(Some(selected)) => {
                            format!("s!=1||r[0]!={selected}||r[1]!={selected}")
                        }
                        MatchResult::SelectedEnd(None) | MatchResult::Span(None) => {
                            "s!=0||r[0]!=0||r[1]!=0".to_owned()
                        }
                        MatchResult::Span(Some((match_start, match_end))) => {
                            format!("s!=1||r[0]!={match_start}||r[1]!={match_end}")
                        }
                    };
                    writeln!(
                        body,
                        "if({condition}) FAIL({}, {index}, {start}, {end}, s, r[0], r[1]);",
                        index + 10
                    )
                    .unwrap();
                }
            }
        }
        let symbol = first_symbol.unwrap();
        if target.features.has(CpuFeature::Aarch64Sve) {
            assert!(saw_sve, "context differential bundle did not exercise SVE");
        }
        writeln!(
            body,
            "r[0]=99;r[1]=99;s={symbol}(h0,{first_length},2,1,r);if(s!=2||r[0]!=99||r[1]!=99)return 90;"
        )
        .unwrap();
        writeln!(
            body,
            "r[0]=99;r[1]=99;s={symbol}(h0,{first_length},0,{},r);if(s!=2||r[0]!=99||r[1]!=99)return 91;",
            first_length + 1
        )
        .unwrap();
        writeln!(
            body,
            "s={symbol}(h0,{first_length},0,{first_length},(size_t*)0);if(s!=2)return 92;"
        )
        .unwrap();
        writeln!(
            body,
            "r[0]=99;r[1]=99;s={symbol}((const unsigned char*)0,{first_length},0,{first_length},r);if(s!=2||r[0]!=99||r[1]!=99)return 93;"
        )
        .unwrap();
        writeln!(
            body,
            "r[0]=99;r[1]=99;s={symbol}((const unsigned char*)0,0,0,0,r);if(s!=2||r[0]!=99||r[1]!=99)return 94;"
        )
        .unwrap();
        writeln!(
            body,
            "r[0]=99;r[1]=99;s={symbol}(h0,{first_length},0,{first_length},(size_t*)((unsigned char*)r+1));if(s!=2||r[0]!=99||r[1]!=99)return 95;"
        )
        .unwrap();
        writeln!(
            body,
            "r[0]=99;r[1]=99;s={symbol}(h0,((size_t)1<<(sizeof(size_t)*8-1)),0,0,r);if(s!=2||r[0]!=99||r[1]!=99)return 96;"
        )
        .unwrap();
        body.push_str("puts(\"native-context-differential-ok\");return 0;}\n");
        source.push_str(&body);
        let harness = directory.join("harness.c");
        fs::write(&harness, source).unwrap();
        if !execute {
            println!("{}", directory.display());
            return;
        }
        let executable = directory.join("harness");
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let output = Command::new(compiler)
            .arg("-O2")
            .arg("-std=c11")
            .arg(&harness)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "native-context-differential-ok"
        );
        println!("{}", directory.display());
    }
}
