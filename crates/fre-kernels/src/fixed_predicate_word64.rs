//! Fixed-width byte-predicate matching with selective predicate finders and a
//! 64-bit Shift-And fallback.
//!
//! Construction accepts between one and 64 nonempty byte predicates. Each
//! predicate is supplied as inclusive byte ranges and is compiled into a full
//! byte-to-position mask table. An exact
//! one-or-two-byte predicate drives a monotone candidate stream when available.
//! Otherwise, a three-member predicate starts one `memchr3` stream and a
//! wider Four/Range/Set predicate may scan through its already-retained block
//! classifier when its compiler or runtime SIMD selection is vectorized.
//! Dense rejections by its paired predicate move to a retained intersected
//! vector stream, where the second classifier runs only for blocks with a
//! primary survivor. If such a block has no fallback member, the already-
//! retained fallback classifier may skip the following fallback-empty run.
//! Dense residual rejections move monotonically to Shift-And. Scalar-selected
//! and otherwise unsupported wider primaries begin directly in the retained
//! intersected stream.
//! Universal predicates are never rechecked. Every phase restarts after each
//! accepted word, allocates no operation memory, and materializes no spans.
//! On sufficiently long sources, the compact Count/span-sum projection may
//! instead discover a four-byte-or-wider exact predicate run from the retained
//! masks, screen with one native whole-literal finder, and verify the remaining
//! predicates. The source-independent mask-census amortization gate keeps
//! short and non-singleton plans on their incumbent path.

use core::{fmt, mem::size_of};

use fre_simd_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_CANDIDATE_BLOCK_BYTES, BYTE_SET_CLASSIFIER_BUILD_WORK,
    BYTE_SET_WIDE_BLOCK_BYTES, ByteSet256, ByteSetClassifier, VectorKind,
    classify_byte_delta_16, find_byte_delta, find_byte_set4,
    classify_byte_set1_16, classify_byte_set1_32, classify_byte_set2_16, classify_byte_set2_32,
    classify_byte_set3_16, classify_byte_set3_32, classify_byte_set4_16, classify_byte_set4_32,
};
use memchr::{memchr, memchr2, memchr3, memmem::Finder};

use crate::Window;
use crate::packed_ordered_literal_aggregate::byte_frequency_rank;

/// Stable identity for the fixed-predicate selective-finder-or-Shift-And strategy.
pub const PLAN_ID: &str =
    "fixed-predicate-word64.selective-predicate-or-shift-and.nonoverlap.v14";
/// Stable identity for the count reducer.
pub const COUNT_OPERATION_ID: &str = "fixed-predicate-word64.count.v13";
/// Stable identity for the matched-byte-sum reducer.
pub const SPAN_SUM_OPERATION_ID: &str = "fixed-predicate-word64.span-sum.v13";
/// Stable identity for allocation-free complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "fixed-predicate-word64.span-visit.v1";
/// Stable identity for the ordinary first-match search projection.
pub const SEARCH_PLAN_ID: &str = "fixed-predicate-word64.first-match.v10";
/// Stable identity for existence search.
const EXISTS_SEARCH_OPERATION_ID: &str = "fixed-predicate-word64.search.exists.v10";
/// Stable identity for the first accepting end projection.
const EARLIEST_END_SEARCH_OPERATION_ID: &str = "fixed-predicate-word64.search.earliest-end.v10";
/// Stable identity for the selected match end projection.
const SELECTED_END_SEARCH_OPERATION_ID: &str = "fixed-predicate-word64.search.selected-end.v10";
/// Stable identity for the selected span projection.
const SPAN_SEARCH_OPERATION_ID: &str = "fixed-predicate-word64.search.span.v10";
/// Version of the receipt-bearing fixed-predicate construction protocol.
pub const BUILD_ATTEMPT_ALGORITHM_VERSION: u32 = 12;
/// Version of the partial-actual fixed-predicate construction ledger.
pub const BUILD_ATTEMPT_ACCOUNTING_VERSION: u32 = 12;
/// Minimum fixed word width accepted by this closed kernel.
pub const MIN_WIDTH: usize = 1;
/// Maximum fixed word width representable by one Shift-And state.
pub const MAX_WIDTH: usize = 64;
/// Full byte-domain mask slots retained by the plan.
pub const MASK_SLOTS: usize = 256;

const MAX_MEMBERS_PER_RANGE: usize = 256;
const BUILD_FIXED_WORK: usize = 4;
const RANGE_FIXED_WORK: usize = 2;
const ANCHOR_MASK_DOMAIN: usize = 256;
const TRANSITION_WORK: usize = 6;
const FINDER_SCAN_BYTE_WORK: usize = 1;
const FINDER_CALL_WORK: usize = 1;
const ANCHOR_CANDIDATE_WORK: usize = 1;
const PREDICATE_CHECK_WORK: usize = 1;
const MATCH_WORK: usize = 3;
const REDUCE_FINAL_WORK: usize = 1;
// A value-only search with unlimited limits does not publish the prospective
// accounting, but it must still prove that every checked upper-bound
// intermediate and the final u64 work conversion would succeed. At most 63
// non-primary predicates plus finder service, calls and candidate accounting
// charge 66 units per window byte. One terminal finder call, one match and
// finalization add at most five more units.
const SEARCH_VALUE_PREFLIGHT_ANCHOR_WORK_FACTOR: usize = (MAX_WIDTH - 1) * PREDICATE_CHECK_WORK
    + FINDER_SCAN_BYTE_WORK
    + FINDER_CALL_WORK
    + ANCHOR_CANDIDATE_WORK;
const SEARCH_VALUE_PREFLIGHT_HYBRID_WORK_FACTOR: usize = TRANSITION_WORK
    + (MAX_WIDTH - 1 - 3) * PREDICATE_CHECK_WORK;
const SEARCH_VALUE_PREFLIGHT_WORK_FACTOR: usize = if SEARCH_VALUE_PREFLIGHT_ANCHOR_WORK_FACTOR
    >= SEARCH_VALUE_PREFLIGHT_HYBRID_WORK_FACTOR
{
    SEARCH_VALUE_PREFLIGHT_ANCHOR_WORK_FACTOR
} else {
    SEARCH_VALUE_PREFLIGHT_HYBRID_WORK_FACTOR
};
const SEARCH_VALUE_PREFLIGHT_WORK_SLOP: usize =
    FINDER_CALL_WORK + MATCH_WORK + REDUCE_FINAL_WORK;
const SEARCH_VALUE_PREFLIGHT_ARITHMETIC_MAX: usize =
    usize::MAX >> usize::BITS.saturating_sub(u64::BITS);
const SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES: usize =
    (SEARCH_VALUE_PREFLIGHT_ARITHMETIC_MAX - SEARCH_VALUE_PREFLIGHT_WORK_SLOP)
        / SEARCH_VALUE_PREFLIGHT_WORK_FACTOR;
const ADAPTIVE_FALLBACK_REJECTIONS: usize = 8;
// Compact Count has no published partial ledger and can afford a longer
// exact-anchor sample before making the one-way handoff. Eight adjacent
// candidates are too local to predict the remainder of a large source.
const COUNT_VALUE_ADAPTIVE_SAMPLE_REJECTIONS: usize = 64;
// A run of four exact predicate bytes is long enough for the native substring
// finder to screen materially more entropy than the one/two-byte incumbent.
// Discovering the run from the transposed mask table examines at most one full
// byte domain per pattern position. Require that fixed census to occupy no
// more than one eighth of the source before selecting this value-only route.
const COUNT_VALUE_LITERAL_RUN_MIN_BYTES: usize = 4;
const COUNT_VALUE_LITERAL_RUN_AMORTIZATION: usize = 8;
// Exact anchors and retained candidate streams may have only one authenticated
// 16-byte classification block. Do not infer wider economics for their handoff.
const ADAPTIVE_FALLBACK_MAX_MEAN_SKIP: usize = BYTE_SET_BLOCK_BYTES;
// Whole-slice leaves that demonstrably service at least 32-byte groups may use
// this wider initial-handoff grain. Each staged seeker authenticates that fact
// independently; memchr3 and 16-byte compiler leaves retain the narrow limit.
const GENERAL_PRIMARY_WIDE_MAX_MEAN_SKIP: usize = BYTE_SET_WIDE_BLOCK_BYTES;
// This is the same source-derived maximum used by K0's retained guard. Above
// it, a predicate admits more than one quarter of the byte domain and cannot
// justify a retained intersection.
const GENERAL_PRIMARY_MAX_CARDINALITY: usize = 64;

#[inline]
fn dense_rejection_burst(
    first_rejected_anchor: usize,
    rejected_anchor: usize,
    rejected_candidates: usize,
) -> Option<bool> {
    dense_rejection_burst_with_limit(
        first_rejected_anchor,
        rejected_anchor,
        rejected_candidates,
        ADAPTIVE_FALLBACK_MAX_MEAN_SKIP,
    )
}

#[inline]
fn dense_general_primary_rejection_burst(
    first_rejected_anchor: usize,
    rejected_anchor: usize,
    rejected_candidates: usize,
    max_mean_skip: usize,
) -> Option<bool> {
    dense_rejection_burst_with_limit(
        first_rejected_anchor,
        rejected_anchor,
        rejected_candidates,
        max_mean_skip,
    )
}

#[inline]
fn dense_rejection_burst_with_limit(
    first_rejected_anchor: usize,
    rejected_anchor: usize,
    rejected_candidates: usize,
    max_mean_skip: usize,
) -> Option<bool> {
    if rejected_candidates < ADAPTIVE_FALLBACK_REJECTIONS {
        return Some(false);
    }
    let span = rejected_anchor.checked_sub(first_rejected_anchor)?;
    let admitted_span = ADAPTIVE_FALLBACK_REJECTIONS
        .checked_sub(1)?
        .checked_mul(max_mean_skip)?;
    Some(span <= admitted_span)
}

#[inline]
fn dense_count_value_rejection_sample(
    first_rejected_anchor: usize,
    rejected_anchor: usize,
    rejected_candidates: usize,
) -> Option<bool> {
    if rejected_candidates < COUNT_VALUE_ADAPTIVE_SAMPLE_REJECTIONS {
        return Some(false);
    }
    let span = rejected_anchor.checked_sub(first_rejected_anchor)?;
    let admitted_span = rejected_candidates
        .checked_sub(1)?
        .checked_mul(ADAPTIVE_FALLBACK_MAX_MEAN_SKIP)?;
    Some(span <= admitted_span)
}

#[inline]
fn has_legal_start(input_bytes: usize, width: usize, start: usize) -> bool {
    input_bytes
        .checked_sub(width)
        .is_some_and(|last_start| start <= last_start)
}

fn hybrid_anchor_work_upper(
    input_bytes: usize,
    candidate_positions: usize,
    verification_positions: usize,
) -> Option<usize> {
    // The primary, byte-set and Shift-And phases are one-way. If `p` start
    // positions have been serviced before the Shift-And suffix, finder bytes,
    // calls and candidates are each at most `p`, and checks are at most
    // `p * verification_positions`. The prefix therefore costs at most
    // `p * (verification_positions + 3)`. In the retained intersection, the
    // fallback classifier remains logical finder service and the additional
    // primary-classifier lanes are predicate checks. Because the pair is
    // skipped during candidate verification, those lanes plus the remaining
    // checks stay within `p * verification_positions`. The suffix costs at
    // most `6 * (input_bytes - p)`. Maximizing over
    // `p <= candidate_positions` gives the closed expression below. The
    // caller separately charges match events and finalization.
    input_bytes
        .checked_mul(TRANSITION_WORK)?
        .checked_add(candidate_positions.checked_mul(verification_positions.saturating_sub(3))?)
}

/// Complete aggregate selected for one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Number of successive leftmost non-overlapping matches.
    Count,
    /// Sum of the widths of those matches.
    SpanSum,
    /// Visit every complete selected match.
    SpanVisit,
}

/// Match semantics authenticated by the plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchSemantics {
    /// Every position is one byte predicate and accepted words have one width.
    FixedBytePredicates,
}

/// Selection and restart rule implemented by the reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchSelection {
    /// Earliest start wins and the next search begins at the accepted end.
    LeftmostFirstNonOverlapping,
}

/// Concrete reducer selected by the immutable plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reducer {
    /// One exact anchor byte drives a monotone candidate stream.
    OneByteAnchor,
    /// Either of two exact anchor bytes drives a monotone candidate stream.
    TwoByteAnchor,
    /// No exact one-or-two-byte position exists. The complete identity's
    /// `primary_finder` and adaptive handoff distinguish a retained general
    /// predicate pair from direct Shift-And.
    ShiftAnd,
}

/// One exact one-or-two-byte anchor retained for ordered verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactAnchorIdentity {
    /// Concrete exact-anchor representation.
    pub reducer: Reducer,
    /// Fixed byte-predicate position.
    pub offset: u8,
    /// Exact member bytes. The second slot is zero for a one-byte anchor.
    pub bytes: [u8; 2],
}

/// Concrete finder representation retained for an adaptive handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveFinderKind {
    /// One exact byte, implemented by `memchr`.
    One,
    /// Two exact bytes, implemented by `memchr2`.
    Two,
    /// Three exact bytes, implemented by `memchr3`.
    Three,
    /// Four exact bytes, implemented by one fixed-width classifier.
    Four,
    /// One contiguous inclusive byte range.
    Range,
    /// One arbitrary compiled byte set.
    Set,
}

/// Complete retained identity for one adaptive predicate finder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdaptiveFinderIdentity {
    /// Concrete finder representation.
    pub kind: AdaptiveFinderKind,
    /// Fixed byte-predicate position serviced by the finder.
    pub offset: u8,
    /// Exact number of bytes admitted by the predicate.
    pub cardinality: u16,
}

/// Initial execution mode retained for one general primary predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneralPrimaryScanIdentity {
    /// Three exact bytes are staged through `memchr3`.
    Memchr3,
    /// One compiled whole-slice leaf stages a wider byte predicate.
    CompiledWholeSlice,
    /// The general pair begins directly in the intersected candidate stream.
    DirectCandidateStream,
}

/// Optional second-stage scan retained for one general predicate pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneralFallbackScanIdentity {
    /// After one classified candidate block contains primary members but no
    /// fallback members, skip the following maximal fallback-nonmember run.
    CompiledWholeSliceAfterEmptyBlock,
}

/// Adaptive phase sequence retained by one anchored plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveHandoffIdentity {
    /// No adaptive phase is reachable.
    Disabled,
    /// Dense primary rejection moves directly to Shift-And.
    DirectShiftAnd,
    /// One secondary finder is retained. With an exact primary, dense
    /// rejection hands off to an intersected stream. A three-member general
    /// primary begins with `memchr3`; a wider vector-classified primary may
    /// begin with its retained block classifier. Dense rejections hand off
    /// through this finder, while unsupported wider primaries begin in the
    /// intersected stream.
    Finder {
        /// Exact retained finder.
        finder: AdaptiveFinderIdentity,
        /// Whether a second dense rejection burst moves on to Shift-And.
        final_shift_and: bool,
    },
}

/// Immutable semantic and implementation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    /// Stable plan identifier.
    pub plan_id: &'static str,
    /// Stable operation identifier.
    pub operation_id: &'static str,
    /// Requested aggregate.
    pub operation: Operation,
    /// Authenticated language class.
    pub semantics: MatchSemantics,
    /// Match selection and restart rule.
    pub selection: MatchSelection,
    /// Exact fixed word width.
    pub width: usize,
    /// Authenticated reducer representation.
    pub reducer: Reducer,
    /// Fixed position used by an exact anchor or general primary finder. Raw
    /// Shift-And uses zero.
    pub anchor_offset: u8,
    /// Exact anchor bytes. The second slot is zero for a one-byte anchor; both
    /// are zero for a general pair or raw Shift-And.
    pub anchor_bytes: [u8; 2],
    /// General primary finder, absent for exact-anchor and raw Shift-And plans.
    pub primary_finder: Option<AdaptiveFinderIdentity>,
    /// Initial execution mode derived from the retained primary finder and its
    /// authenticated compiler or runtime SIMD selection.
    pub general_primary_scan: Option<GeneralPrimaryScanIdentity>,
    /// Optional fallback-empty skip mode derived from both retained finders.
    pub general_fallback_scan: Option<GeneralFallbackScanIdentity>,
    /// Secondary exact anchor checked before broader predicates.
    pub secondary_anchor: Option<ExactAnchorIdentity>,
    /// Maximum non-universal predicates checked per anchored candidate.
    pub verification_predicates: u32,
    /// Complete adaptive phase sequence retained by the plan.
    pub adaptive_handoff: AdaptiveHandoffIdentity,
}

/// Limits checked before any supplied range value is inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    /// Maximum number of fixed positions.
    pub max_positions: usize,
    /// Maximum total inclusive ranges across all positions.
    pub max_source_ranges: usize,
    /// Maximum prospectively charged construction work.
    pub max_build_work: u64,
    /// Maximum dynamic construction scratch; this kernel requires zero.
    pub max_scratch_bytes: usize,
    /// Maximum retained plan bytes.
    pub max_persistent_bytes: usize,
    /// Maximum simultaneous construction bytes.
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    /// Disable caller-selected caps while preserving the hard width bound and
    /// checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_positions: usize::MAX,
            max_source_ranges: usize::MAX,
            max_build_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_positions: MAX_WIDTH,
            max_source_ranges: 4_096,
            max_build_work: 2_000_000,
            max_scratch_bytes: 0,
            max_persistent_bytes: 16 * 1_048_576,
            max_peak_bytes: 16 * 1_048_576,
        }
    }
}

/// Auditable successful-construction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    /// Fixed word width.
    pub positions: usize,
    /// Total source ranges.
    pub source_ranges: usize,
    /// Zero writes required to initialize the byte-mask table.
    pub mask_zero_writes: usize,
    /// Position records visited.
    pub position_visits: usize,
    /// Source range records inspected.
    pub range_inspections: usize,
    /// Byte-to-position mask writes, including duplicate union writes.
    pub member_writes: usize,
    /// Full byte-domain mask cells inspected while selecting a fixed anchor.
    pub anchor_mask_reads: usize,
    /// Exact work used to build retained arbitrary-set predicate classifiers.
    /// Tiny and contiguous-range finders require zero classifier build work.
    pub adaptive_classifier_build_work: usize,
    /// Bound admitted before reading source range values.
    pub work_upper_bound: u64,
    /// Exact logical work charged by successful construction.
    pub work_charged: u64,
    /// Dynamic allocations; always zero.
    pub allocations: usize,
    /// Capacity-growth requests; always zero.
    pub reserves: usize,
    /// Temporary retained-data copies; always zero.
    pub temporary_copies: usize,
    /// Dynamic construction scratch; always zero.
    pub scratch_bytes: usize,
    /// Exact inline plan bytes retained.
    pub persistent_bytes: usize,
    /// Simultaneous construction bytes; equal to retained bytes.
    pub peak_bytes: usize,
}

/// Limits checked before any haystack byte is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    /// Maximum input bytes.
    pub max_input_bytes: usize,
    /// Maximum Shift-And transitions or logical anchor-scanner service bytes.
    pub max_transitions: usize,
    /// Maximum semantic match events.
    pub max_match_events: usize,
    /// Maximum count result.
    pub max_count: u64,
    /// Maximum matched-byte sum when span sum is requested.
    pub max_span_sum: u64,
    /// Maximum transition plus finalization steps.
    pub max_reducer_steps: usize,
    /// Maximum prospectively charged work.
    pub max_work: u64,
    /// Maximum dynamic operation scratch; this kernel requires zero.
    pub max_scratch_bytes: usize,
    /// Maximum retained plan bytes admitted during execution.
    pub max_persistent_bytes: usize,
    /// Maximum retained-plus-scratch operation peak.
    pub max_peak_bytes: usize,
}

/// Source-free admission for one prepared width-one Shift-And count operation.
///
/// Values of this type can only be produced by
/// [`FixedPredicateWord64Plan::prepare_width_one_shift_and_count`]. The private fields
/// bind the admitted input length and the resource-relevant immutable plan
/// shape so a token from an unrelated plan fails closed before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WidthOneShiftAndCountAdmission {
    input_bytes: usize,
    persistent_bytes: usize,
}

impl ReduceLimits {
    /// Disable caller-selected caps while retaining checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_transitions: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 256 * 1_048_576,
            max_transitions: 256 * 1_048_576,
            max_match_events: 128 * 1_048_576,
            max_count: 128 * 1_048_576,
            max_span_sum: 256 * 1_048_576,
            max_reducer_steps: 256 * 1_048_576 + 1,
            max_work: 2_000_000_000,
            max_scratch_bytes: 0,
            max_persistent_bytes: 16 * 1_048_576,
            max_peak_bytes: 16 * 1_048_576,
        }
    }
}

/// Prospective bounds checked before reduction begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    /// Complete input bytes.
    pub input_bytes: usize,
    /// Maximum Shift-And transitions or logical anchor-scanner service bytes.
    pub transitions: usize,
    /// Maximum logical bytes serviced by fixed-anchor finders. For adaptive
    /// plans this is an independent component maximum; it shares the joint
    /// `transitions` cap with `shift_and_transitions`.
    pub finder_scanned_bytes: usize,
    /// Maximum Shift-And transitions after any adaptive handoff. For adaptive
    /// plans this is an independent component maximum; it shares the joint
    /// `transitions` cap with `finder_scanned_bytes`.
    pub shift_and_transitions: usize,
    /// Maximum fixed-anchor finder invocations.
    pub finder_calls: usize,
    /// Maximum fixed-anchor candidates.
    pub anchor_candidates: usize,
    /// Maximum per-position predicate checks.
    pub predicate_checks: usize,
    /// Maximum fixed-width non-overlapping matches.
    pub match_events: usize,
    /// Same event bound represented in the count type.
    pub count: u64,
    /// Maximum possible matched-byte sum.
    pub span_sum: u64,
    /// Transition plus finalization steps.
    pub reducer_steps: usize,
    /// Complete prospectively charged work.
    pub work: u64,
    /// Dynamic operation allocations; always zero.
    pub allocations: usize,
    /// Capacity-growth requests; always zero.
    pub reserves: usize,
    /// Temporary retained-data copies; always zero.
    pub temporary_copies: usize,
    /// Dynamic operation scratch; always zero.
    pub scratch_bytes: usize,
    /// Exact retained plan bytes.
    pub persistent_bytes: usize,
    /// Retained-plus-scratch peak.
    pub peak_bytes: usize,
}

/// Exact counters after complete successful reduction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    /// Input bytes consumed.
    pub input_bytes: usize,
    /// Shift-And transitions or logical anchor-scanner service bytes.
    pub transitions: usize,
    /// Logical bytes serviced by fixed-anchor finders.
    pub finder_scanned_bytes: usize,
    /// Shift-And transitions after any adaptive handoff.
    pub shift_and_transitions: usize,
    /// Fixed-anchor finder invocations.
    pub finder_calls: usize,
    /// Fixed-anchor candidates visited.
    pub anchor_candidates: usize,
    /// Per-position predicate checks.
    pub predicate_checks: usize,
    /// Semantic match events.
    pub match_events: usize,
    /// Exact count result.
    pub count: u64,
    /// Exact matched-byte sum.
    pub matched_bytes: u64,
    /// Transition plus finalization steps.
    pub reducer_steps: usize,
    /// Exact work charged from structural counters.
    pub work_charged: u64,
    /// Dynamic operation allocations; always zero.
    pub allocations: usize,
    /// Capacity-growth requests; always zero.
    pub reserves: usize,
    /// Temporary retained-data copies; always zero.
    pub temporary_copies: usize,
    /// Dynamic operation scratch; always zero.
    pub scratch_bytes: usize,
    /// Retained plan bytes present during execution.
    pub persistent_bytes: usize,
    /// Retained-plus-scratch execution peak.
    pub peak_bytes: usize,
}

/// Upper bounds and actual counters for one result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    /// Stable operation and semantic identity.
    pub identity: OperationIdentity,
    /// Bounds admitted before reading the input.
    pub upper_bounds: ReduceUpperBounds,
    /// Counters published after complete success.
    pub actual: ReduceActualCounters,
}

/// Complete count result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    /// Leftmost non-overlapping match count.
    pub count: u64,
    /// Complete resource certificate.
    pub accounting: ReduceAccounting,
}

/// Complete checked matched-byte result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    /// Sum of every selected fixed-width match.
    pub span_sum: u64,
    /// Complete resource certificate.
    pub accounting: ReduceAccounting,
}

/// One complete non-overlapping match emitted by the reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteSpan {
    /// Inclusive match start.
    pub start: usize,
    /// Exclusive match end.
    pub end: usize,
}

/// Summary of one allocation-free complete-span traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanVisitResult {
    /// Number of complete spans emitted.
    pub matches: usize,
    /// Sum of emitted span widths.
    pub span_sum: u64,
    /// Complete resource certificate.
    pub accounting: ReduceAccounting,
}

/// First-match result projection selected for one ordinary search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchOperation {
    /// Whether any selected match exists.
    Exists,
    /// End of the first accepting match.
    EarliestEnd,
    /// End of the leftmost-first selected match.
    SelectedEnd,
    /// Complete leftmost-first selected span.
    Span,
}

/// Immutable semantic and implementation identity for ordinary search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchOperationIdentity {
    /// Stable search-plan identifier, separate from aggregate reduction.
    pub plan_id: &'static str,
    /// Stable operation identifier.
    pub operation_id: &'static str,
    /// Requested result projection.
    pub operation: SearchOperation,
    /// Authenticated language class.
    pub semantics: MatchSemantics,
    /// Match selection rule.
    pub selection: MatchSelection,
    /// Exact fixed word width.
    pub width: usize,
    /// Authenticated reducer representation.
    pub reducer: Reducer,
    /// Fixed position used by an exact anchor or general primary finder. Raw
    /// Shift-And uses zero.
    pub anchor_offset: u8,
    /// Exact anchor bytes. The second slot is zero for a one-byte anchor; both
    /// are zero for a general pair or raw Shift-And.
    pub anchor_bytes: [u8; 2],
    /// General primary finder, absent for exact-anchor and raw Shift-And plans.
    pub primary_finder: Option<AdaptiveFinderIdentity>,
    /// Initial execution mode derived from the retained primary finder and its
    /// authenticated compiler or runtime SIMD selection.
    pub general_primary_scan: Option<GeneralPrimaryScanIdentity>,
    /// Optional fallback-empty skip mode derived from both retained finders.
    pub general_fallback_scan: Option<GeneralFallbackScanIdentity>,
    /// Secondary exact anchor checked before broader predicates.
    pub secondary_anchor: Option<ExactAnchorIdentity>,
    /// Maximum non-universal predicates checked per anchored candidate.
    pub verification_predicates: u32,
    /// Complete adaptive phase sequence retained by the plan.
    pub adaptive_handoff: AdaptiveHandoffIdentity,
}

/// Per-search limits checked before any byte in the requested window is read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    /// Maximum prospectively charged first-match work.
    pub max_work: u64,
    /// Maximum dynamic operation scratch; ordinary search requires zero.
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    /// Disable caller-selected caps while retaining checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work: 100_000_000,
            max_scratch_bytes: 0,
        }
    }
}

/// Source-independent bounds admitted for one first-match search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchUpperBounds {
    /// Bytes in the requested window.
    pub window_bytes: usize,
    /// Shift-And transitions or logical anchor-finder service bytes.
    pub transitions: usize,
    /// Maximum logical bytes serviced by fixed-anchor finders. For adaptive
    /// plans this is an independent component maximum; it shares the joint
    /// `transitions` cap with `shift_and_transitions`.
    pub finder_scanned_bytes: usize,
    /// Maximum Shift-And transitions after any adaptive handoff. For adaptive
    /// plans this is an independent component maximum; it shares the joint
    /// `transitions` cap with `finder_scanned_bytes`.
    pub shift_and_transitions: usize,
    /// Maximum fixed-anchor finder invocations.
    pub finder_calls: usize,
    /// Maximum anchor candidates visited.
    pub candidate_events: usize,
    /// Maximum per-position predicate checks.
    pub predicate_checks: usize,
    /// Maximum selected match events; never more than one.
    pub match_events: usize,
    /// Complete prospectively charged work.
    pub work: u64,
    /// Dynamic operation scratch; always zero.
    pub scratch_bytes: usize,
}

/// Exact counters through the first match or complete window exhaustion.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SearchActualCounters {
    /// Bytes in the requested window.
    pub window_bytes: usize,
    /// Shift-And transitions or logical anchor-finder service bytes.
    pub transitions: usize,
    /// Logical bytes serviced by fixed-anchor finders.
    pub finder_scanned_bytes: usize,
    /// Shift-And transitions after any adaptive handoff.
    pub shift_and_transitions: usize,
    /// Fixed-anchor finder invocations.
    pub finder_calls: usize,
    /// Anchor candidates visited.
    pub candidate_events: usize,
    /// Per-position predicate checks.
    pub predicate_checks: usize,
    /// Selected match events; zero or one.
    pub match_events: usize,
    /// Exact charged work.
    pub work: u64,
    /// Dynamic operation scratch; always zero.
    pub scratch_bytes: usize,
}

/// Complete first-match search certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    /// Stable operation and semantic identity.
    pub identity: SearchOperationIdentity,
    /// Bounds admitted before reading the requested window.
    pub upper_bounds: SearchUpperBounds,
    /// Counters published after complete success.
    pub actual: SearchActualCounters,
}

/// Checked first-match search failure. No fallback is attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    /// The half-open request does not fit the original haystack.
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    /// Prospective search work exceeds the caller cap.
    WorkLimit { needed: u64, limit: u64 },
    /// Dynamic operation scratch exceeds the caller cap.
    ScratchLimit { needed: usize, limit: usize },
    /// Checked arithmetic failed.
    ArithmeticOverflow { computation: &'static str },
    /// A post-preflight invariant failed closed.
    InternalInvariant(&'static str),
}

impl fmt::Display for SearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "fixed-predicate search window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::WorkLimit { needed, limit } => write!(
                formatter,
                "fixed-predicate search needs {needed} work units, exceeding {limit}"
            ),
            Self::ScratchLimit { needed, limit } => write!(
                formatter,
                "fixed-predicate search needs {needed} scratch bytes, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { computation } => write!(
                formatter,
                "arithmetic overflow while computing {computation}"
            ),
            Self::InternalInvariant(detail) => write!(formatter, "internal invariant: {detail}"),
        }
    }
}

impl std::error::Error for SearchError {}

/// Checked construction failure. No plan is published on error.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    /// Fewer than two positions were supplied.
    WidthTooSmall { needed: usize, minimum: usize },
    /// More than 64 positions were supplied.
    WidthTooLarge { needed: usize, maximum: usize },
    /// Width exceeds the caller cap.
    PositionLimit { needed: usize, limit: usize },
    /// Source range count exceeds the caller cap.
    SourceRangesLimit { needed: usize, limit: usize },
    /// Prospective construction work exceeds the caller cap.
    WorkLimit { needed: u64, limit: u64 },
    /// Dynamic construction scratch exceeds the caller cap.
    ScratchLimit { needed: usize, limit: usize },
    /// Retained bytes exceed the caller cap.
    PersistentLimit { needed: usize, limit: usize },
    /// Construction peak exceeds the caller cap.
    PeakLimit { needed: usize, limit: usize },
    /// One position contains no ranges.
    EmptyPosition { position: usize },
    /// One inclusive range is reversed.
    ReversedRange {
        position: usize,
        range: usize,
        start: u8,
        end: u8,
    },
    /// Compatibility variant retained from the former ASCII-only contract.
    ///
    /// Full byte-domain ranges are now admitted, so current constructors do
    /// not emit this variant.
    NonAsciiRange {
        position: usize,
        range: usize,
        start: u8,
        end: u8,
    },
    /// Checked arithmetic failed.
    ArithmeticOverflow { computation: &'static str },
    /// A post-preflight invariant failed closed.
    InternalInvariant(&'static str),
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WidthTooSmall { needed, minimum } => {
                write!(formatter, "word width {needed} is below minimum {minimum}")
            }
            Self::WidthTooLarge { needed, maximum } => {
                write!(formatter, "word width {needed} exceeds maximum {maximum}")
            }
            Self::PositionLimit { needed, limit } => {
                write!(
                    formatter,
                    "word needs {needed} positions, exceeding {limit}"
                )
            }
            Self::SourceRangesLimit { needed, limit } => {
                write!(
                    formatter,
                    "word needs {needed} source ranges, exceeding {limit}"
                )
            }
            Self::WorkLimit { needed, limit } => {
                write!(
                    formatter,
                    "build needs {needed} work units, exceeding {limit}"
                )
            }
            Self::ScratchLimit { needed, limit } => {
                write!(
                    formatter,
                    "build needs {needed} scratch bytes, exceeding {limit}"
                )
            }
            Self::PersistentLimit { needed, limit } => {
                write!(
                    formatter,
                    "plan needs {needed} persistent bytes, exceeding {limit}"
                )
            }
            Self::PeakLimit { needed, limit } => {
                write!(formatter, "build peak is {needed} bytes, exceeding {limit}")
            }
            Self::EmptyPosition { position } => {
                write!(formatter, "word position {position} has no byte ranges")
            }
            Self::ReversedRange {
                position,
                range,
                start,
                end,
            } => write!(
                formatter,
                "word position {position} range {range} is reversed: {start}..={end}"
            ),
            Self::NonAsciiRange {
                position,
                range,
                start,
                end,
            } => write!(
                formatter,
                "word position {position} range {range} is outside ASCII: {start}..={end}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "arithmetic overflow while computing {computation}"
                )
            }
            Self::InternalInvariant(detail) => write!(formatter, "internal invariant: {detail}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Immutable identity and caller envelope for one fixed-predicate build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAttemptIdentity {
    pub plan_id: &'static str,
    pub limits: BuildLimits,
    pub algorithm_version: u32,
    pub accounting_version: u32,
}

/// Exact effects committed through the last admitted mask-construction step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BuildAttemptActual {
    pub mask_zero_writes: usize,
    pub position_visits: usize,
    pub range_inspections: usize,
    pub member_writes: usize,
    pub anchor_mask_reads: usize,
    pub adaptive_classifier_build_work: usize,
    pub work: u64,
    pub allocations: usize,
    pub reserves: usize,
    pub temporary_copies: usize,
    pub copied_bytes: usize,
    pub initialized_bytes: usize,
    pub live_persistent_bytes: usize,
    pub live_scratch_bytes: usize,
    pub peak_bytes: usize,
}

/// One success-or-failure fixed-predicate construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAttemptReceipt {
    identity: BuildAttemptIdentity,
    actual: BuildAttemptActual,
    accounting: Option<BuildAccounting>,
    published: bool,
}

impl BuildAttemptReceipt {
    #[must_use]
    pub const fn identity(&self) -> BuildAttemptIdentity {
        self.identity
    }

    #[must_use]
    pub const fn actual(&self) -> BuildAttemptActual {
        self.actual
    }

    #[must_use]
    pub const fn accounting(&self) -> Option<BuildAccounting> {
        self.accounting
    }

    #[must_use]
    pub const fn published(&self) -> bool {
        self.published
    }

    #[must_use]
    pub fn contains_actual(&self) -> bool {
        self.identity.plan_id == PLAN_ID
            && self.identity.algorithm_version == BUILD_ATTEMPT_ALGORITHM_VERSION
            && self.identity.accounting_version == BUILD_ATTEMPT_ACCOUNTING_VERSION
            && self.actual.work <= self.identity.limits.max_build_work
            && self.actual.allocations == 0
            && self.actual.reserves == 0
            && self.actual.temporary_copies == 0
            && self.actual.copied_bytes == 0
            && self.actual.adaptive_classifier_build_work
                <= BYTE_SET_CLASSIFIER_BUILD_WORK * 2
            && self.actual.adaptive_classifier_build_work % BYTE_SET_CLASSIFIER_BUILD_WORK == 0
            && self.actual.live_persistent_bytes <= self.identity.limits.max_persistent_bytes
            && self.actual.live_scratch_bytes <= self.identity.limits.max_scratch_bytes
            && self.actual.peak_bytes <= self.identity.limits.max_peak_bytes
    }

    fn closes_success(&self, accounting: BuildAccounting) -> bool {
        self.published
            && self.accounting == Some(accounting)
            && self.contains_actual()
            && self.actual.mask_zero_writes == accounting.mask_zero_writes
            && self.actual.position_visits == accounting.position_visits
            && self.actual.range_inspections == accounting.range_inspections
            && self.actual.member_writes == accounting.member_writes
            && self.actual.anchor_mask_reads == accounting.anchor_mask_reads
            && self.actual.adaptive_classifier_build_work
                == accounting.adaptive_classifier_build_work
            && self.actual.work == accounting.work_charged
            && self.actual.allocations == accounting.allocations
            && self.actual.reserves == accounting.reserves
            && self.actual.temporary_copies == accounting.temporary_copies
            && self.actual.live_persistent_bytes == accounting.persistent_bytes
            && self.actual.live_scratch_bytes == accounting.scratch_bytes
            && self.actual.peak_bytes == accounting.peak_bytes
    }

    fn closes_failure(&self) -> bool {
        !self.published && self.accounting.is_none() && self.contains_actual()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BuildFailureKind {
    WidthTooSmall,
    WidthTooLarge,
    PositionLimit,
    SourceRangesLimit,
    WorkLimit,
    ScratchLimit,
    PersistentLimit,
    PeakLimit,
    EmptyPosition,
    ReversedRange,
    NonAsciiRange,
    ArithmeticOverflow,
    InternalInvariant,
}

impl BuildFailureKind {
    const fn from_error(error: &BuildError) -> Self {
        match error {
            BuildError::WidthTooSmall { .. } => Self::WidthTooSmall,
            BuildError::WidthTooLarge { .. } => Self::WidthTooLarge,
            BuildError::PositionLimit { .. } => Self::PositionLimit,
            BuildError::SourceRangesLimit { .. } => Self::SourceRangesLimit,
            BuildError::WorkLimit { .. } => Self::WorkLimit,
            BuildError::ScratchLimit { .. } => Self::ScratchLimit,
            BuildError::PersistentLimit { .. } => Self::PersistentLimit,
            BuildError::PeakLimit { .. } => Self::PeakLimit,
            BuildError::EmptyPosition { .. } => Self::EmptyPosition,
            BuildError::ReversedRange { .. } => Self::ReversedRange,
            BuildError::NonAsciiRange { .. } => Self::NonAsciiRange,
            BuildError::ArithmeticOverflow { .. } => Self::ArithmeticOverflow,
            BuildError::InternalInvariant(_) => Self::InternalInvariant,
        }
    }
}

/// Terminal fixed-predicate construction failure with partial actuals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildAttemptError {
    source: BuildError,
    receipt: BuildAttemptReceipt,
    seal: BuildFailureKind,
}

impl BuildAttemptError {
    fn new(source: BuildError, identity: BuildAttemptIdentity, actual: BuildAttemptActual) -> Self {
        let seal = BuildFailureKind::from_error(&source);
        Self {
            source,
            receipt: BuildAttemptReceipt {
                identity,
                actual,
                accounting: None,
                published: false,
            },
            seal,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &BuildError {
        &self.source
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.seal == BuildFailureKind::from_error(&self.source) && self.receipt.closes_failure()
    }

    #[must_use]
    pub fn into_source(self) -> BuildError {
        self.source
    }
}

impl fmt::Display for BuildAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for BuildAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

struct BuildAttemptTracker {
    limits: BuildLimits,
    actual: BuildAttemptActual,
}

impl BuildAttemptTracker {
    const fn new(limits: BuildLimits) -> Self {
        Self {
            limits,
            actual: BuildAttemptActual {
                mask_zero_writes: 0,
                position_visits: 0,
                range_inspections: 0,
                member_writes: 0,
                anchor_mask_reads: 0,
                adaptive_classifier_build_work: 0,
                work: 0,
                allocations: 0,
                reserves: 0,
                temporary_copies: 0,
                copied_bytes: 0,
                initialized_bytes: 0,
                live_persistent_bytes: 0,
                live_scratch_bytes: 0,
                peak_bytes: 0,
            },
        }
    }

    fn charge(&mut self, units: usize) -> Result<(), BuildError> {
        let units = u64::try_from(units).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "actual build work conversion",
        })?;
        let needed = self
            .actual
            .work
            .checked_add(units)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual build work",
            })?;
        if needed > self.limits.max_build_work {
            return Err(BuildError::WorkLimit {
                needed,
                limit: self.limits.max_build_work,
            });
        }
        self.actual.work = needed;
        Ok(())
    }

    fn initialize_masks(&mut self) -> Result<(), BuildError> {
        self.charge(MASK_SLOTS)?;
        self.actual.mask_zero_writes = MASK_SLOTS;
        self.observe_initialization(MASK_SLOTS.checked_mul(size_of::<u64>()).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "mask zero initialized bytes",
            },
        )?)
    }

    fn visit_position(&mut self) -> Result<(), BuildError> {
        self.charge(1)?;
        self.actual.position_visits =
            self.actual
                .position_visits
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual position visits",
                })?;
        Ok(())
    }

    fn inspect_range(&mut self) -> Result<(), BuildError> {
        self.charge(RANGE_FIXED_WORK)?;
        self.actual.range_inspections =
            self.actual
                .range_inspections
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual range inspections",
                })?;
        Ok(())
    }

    fn write_member(&mut self) -> Result<(), BuildError> {
        self.charge(1)?;
        self.actual.member_writes =
            self.actual
                .member_writes
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual member writes",
                })?;
        self.observe_initialization(size_of::<u64>())
    }

    fn read_anchor_mask(&mut self) -> Result<(), BuildError> {
        self.charge(1)?;
        self.actual.anchor_mask_reads =
            self.actual
                .anchor_mask_reads
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "anchor mask read count",
                })?;
        Ok(())
    }

    fn build_adaptive_classifier(&mut self) -> Result<(), BuildError> {
        let needed = self
            .actual
            .adaptive_classifier_build_work
            .checked_add(BYTE_SET_CLASSIFIER_BUILD_WORK)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "adaptive classifier build work",
            })?;
        self.charge(BYTE_SET_CLASSIFIER_BUILD_WORK)?;
        self.actual.adaptive_classifier_build_work = needed;
        Ok(())
    }

    fn finish(&mut self, preflight: BuildPreflight) -> Result<(), BuildError> {
        self.charge(BUILD_FIXED_WORK)?;
        let mask_bytes =
            MASK_SLOTS
                .checked_mul(size_of::<u64>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "inline mask bytes",
                })?;
        let remaining_inline_bytes = preflight.persistent_bytes.checked_sub(mask_bytes).ok_or(
            BuildError::InternalInvariant("inline plan is smaller than its mask table"),
        )?;
        self.observe_initialization(remaining_inline_bytes)?;
        self.actual.live_persistent_bytes = preflight.persistent_bytes;
        self.actual.peak_bytes = preflight.peak_bytes;
        Ok(())
    }

    fn observe_initialization(&mut self, bytes: usize) -> Result<(), BuildError> {
        self.actual.initialized_bytes = self.actual.initialized_bytes.checked_add(bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "actual initialized bytes",
            },
        )?;
        Ok(())
    }
}

/// Checked reduction failure. No partial aggregate is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputLimit { needed: usize, limit: usize },
    TransitionsLimit { needed: usize, limit: usize },
    MatchEventsLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    ReducerStepsLimit { needed: usize, limit: usize },
    WorkLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
    InternalInvariant(&'static str),
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLimit { needed, limit } => {
                write!(formatter, "input needs {needed} bytes, exceeding {limit}")
            }
            Self::TransitionsLimit { needed, limit } => {
                write!(
                    formatter,
                    "reducer needs {needed} transitions, exceeding {limit}"
                )
            }
            Self::MatchEventsLimit { needed, limit } => {
                write!(
                    formatter,
                    "reducer may emit {needed} matches, exceeding {limit}"
                )
            }
            Self::CountLimit { needed, limit } => {
                write!(
                    formatter,
                    "reducer count may be {needed}, exceeding {limit}"
                )
            }
            Self::SpanSumLimit { needed, limit } => {
                write!(
                    formatter,
                    "reducer span sum may be {needed}, exceeding {limit}"
                )
            }
            Self::ReducerStepsLimit { needed, limit } => {
                write!(formatter, "reducer needs {needed} steps, exceeding {limit}")
            }
            Self::WorkLimit { needed, limit } => {
                write!(
                    formatter,
                    "reducer needs {needed} work units, exceeding {limit}"
                )
            }
            Self::ScratchLimit { needed, limit } => {
                write!(
                    formatter,
                    "reducer needs {needed} scratch bytes, exceeding {limit}"
                )
            }
            Self::PersistentLimit { needed, limit } => {
                write!(
                    formatter,
                    "reducer retains {needed} bytes, exceeding {limit}"
                )
            }
            Self::PeakLimit { needed, limit } => {
                write!(
                    formatter,
                    "reducer peak is {needed} bytes, exceeding {limit}"
                )
            }
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "arithmetic overflow while computing {computation}"
                )
            }
            Self::InternalInvariant(detail) => write!(formatter, "internal invariant: {detail}"),
        }
    }
}

impl std::error::Error for ReduceError {}

/// Owned, allocation-free fixed-predicate plan.
#[derive(Debug)]
pub struct FixedPredicateWord64Plan {
    masks: [u64; MASK_SLOTS],
    width: usize,
    accepting_bit: u64,
    nonuniversal_mask: u64,
    anchor: Anchor,
    primary_finder: Option<AdaptiveFallback>,
    secondary_anchor: Option<Anchor>,
    adaptive_fallback: Option<AdaptiveFallback>,
    build: BuildAccounting,
}

#[derive(Clone, Copy, Debug)]
struct AdaptiveFallback {
    offset: u8,
    cardinality: u16,
    finder: AdaptiveFinder,
}

#[derive(Clone, Copy, Debug)]
struct ExactLiteralRun {
    bytes: [u8; MAX_WIDTH],
    offset: usize,
    len: usize,
    position_mask: u64,
}

#[derive(Clone, Copy)]
enum GeneralPrimarySeeker<'a> {
    Memchr3([u8; 3]),
    CompiledWholeSlice(&'a AdaptiveFallback),
}

impl GeneralPrimarySeeker<'_> {
    #[inline]
    fn find(self, bytes: &[u8]) -> Option<usize> {
        match self {
            Self::Memchr3([first, second, third]) => memchr3(first, second, third, bytes),
            Self::CompiledWholeSlice(finder) => finder.find_member(bytes, true),
        }
    }

    const fn max_mean_skip(self) -> usize {
        match self {
            Self::Memchr3(_) => BYTE_SET_BLOCK_BYTES,
            Self::CompiledWholeSlice(finder) => finder.general_primary_max_mean_skip(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PrimaryPredicate<'a> {
    Exact(Anchor),
    General(&'a AdaptiveFallback),
}

impl PrimaryPredicate<'_> {
    const fn offset(self) -> Option<u8> {
        match self {
            Self::Exact(anchor) => anchor.offset(),
            Self::General(finder) => Some(finder.offset),
        }
    }

    const fn candidate_block_bytes(self) -> usize {
        match self {
            Self::Exact(_) => BYTE_SET_CANDIDATE_BLOCK_BYTES,
            Self::General(finder) => finder.candidate_block_bytes(),
        }
    }

    fn matches(self, byte: u8) -> Option<bool> {
        match self {
            Self::Exact(anchor) => anchor.matches(byte),
            Self::General(finder) => Some(finder.matches(byte)),
        }
    }

    fn classify_16(self, bytes: &[u8; BYTE_SET_BLOCK_BYTES]) -> Option<u16> {
        match self {
            Self::Exact(anchor) => anchor.classify_16(bytes),
            Self::General(finder) => Some(finder.classify_16(bytes)),
        }
    }

    fn classify_32(self, bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES]) -> Option<u32> {
        match self {
            Self::Exact(anchor) => anchor.classify_32(bytes),
            Self::General(finder) => finder.classify_32(bytes),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum AdaptiveFinder {
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Four([u8; 4]),
    Range { origin: u8, maximum_delta: u8 },
    Set(ByteSetClassifier),
}

impl AdaptiveFallback {
    #[cfg(test)]
    #[inline]
    fn cursor<'a>(&'a self, bytes: &'a [u8], anchor_end: usize) -> AdaptiveFinderCursor<'a> {
        AdaptiveFinderCursor::new(&self.finder, bytes, anchor_end)
    }

    #[inline]
    const fn classifier_build_work(&self) -> usize {
        match self.finder {
            AdaptiveFinder::Set(_) => BYTE_SET_CLASSIFIER_BUILD_WORK,
            AdaptiveFinder::One(_)
            | AdaptiveFinder::Two(_, _)
            | AdaptiveFinder::Three(_, _, _)
            | AdaptiveFinder::Four(_)
            | AdaptiveFinder::Range { .. } => 0,
        }
    }

    const fn identity(self) -> AdaptiveFinderIdentity {
        let kind = match self.finder {
            AdaptiveFinder::One(_) => AdaptiveFinderKind::One,
            AdaptiveFinder::Two(_, _) => AdaptiveFinderKind::Two,
            AdaptiveFinder::Three(_, _, _) => AdaptiveFinderKind::Three,
            AdaptiveFinder::Four(_) => AdaptiveFinderKind::Four,
            AdaptiveFinder::Range { .. } => AdaptiveFinderKind::Range,
            AdaptiveFinder::Set(_) => AdaptiveFinderKind::Set,
        };
        AdaptiveFinderIdentity {
            kind,
            offset: self.offset,
            cardinality: self.cardinality,
        }
    }

    #[inline]
    const fn candidate_block_bytes(&self) -> usize {
        match &self.finder {
            // The existing range classifier has one authenticated 16-byte
            // operation. It is deliberately not widened by this mechanism.
            AdaptiveFinder::Range { .. } => BYTE_SET_BLOCK_BYTES,
            AdaptiveFinder::Set(classifier) => classifier.candidate_block_bytes(),
            AdaptiveFinder::One(_)
            | AdaptiveFinder::Two(_, _)
            | AdaptiveFinder::Three(_, _, _)
            | AdaptiveFinder::Four(_) => BYTE_SET_CANDIDATE_BLOCK_BYTES,
        }
    }

    const fn general_primary_max_mean_skip(&self) -> usize {
        match &self.finder {
            // Every reviewed AArch64 whole-slice leaf groups at least 32 bytes;
            // the x86 and portable Four/Range loops remain 16-byte operations.
            AdaptiveFinder::Four(_)
            | AdaptiveFinder::Range { .. }
            | AdaptiveFinder::Set(_)
                if cfg!(target_arch = "aarch64") =>
            {
                GENERAL_PRIMARY_WIDE_MAX_MEAN_SKIP
            }
            // Other targets may use the wider Set limit only when their
            // retained direct candidate receipt independently exposes it.
            AdaptiveFinder::Set(classifier)
                if classifier.candidate_block_bytes() == BYTE_SET_WIDE_BLOCK_BYTES =>
            {
                GENERAL_PRIMARY_WIDE_MAX_MEAN_SKIP
            }
            AdaptiveFinder::One(_)
            | AdaptiveFinder::Two(_, _)
            | AdaptiveFinder::Three(_, _, _)
            | AdaptiveFinder::Four(_)
            | AdaptiveFinder::Range { .. }
            | AdaptiveFinder::Set(_) => ADAPTIVE_FALLBACK_MAX_MEAN_SKIP,
        }
    }

    #[inline]
    fn matches(&self, byte: u8) -> bool {
        match &self.finder {
            AdaptiveFinder::One(first) => byte == *first,
            AdaptiveFinder::Two(first, second) => byte == *first || byte == *second,
            AdaptiveFinder::Three(first, second, third) => {
                byte == *first || byte == *second || byte == *third
            }
            AdaptiveFinder::Four(members) => members.contains(&byte),
            AdaptiveFinder::Range {
                origin,
                maximum_delta,
            } => byte.wrapping_sub(*origin) <= *maximum_delta,
            AdaptiveFinder::Set(classifier) => classifier.set().contains(byte),
        }
    }

    const fn supports_vector_classified_run(&self) -> bool {
        match &self.finder {
            AdaptiveFinder::Four(_) => cfg!(any(
                all(
                    target_arch = "aarch64",
                    target_os = "linux",
                    target_endian = "little",
                    target_feature = "sve",
                    target_feature = "sve2"
                ),
                all(target_arch = "aarch64", target_feature = "neon"),
                all(target_arch = "x86_64", target_feature = "sse2")
            )),
            AdaptiveFinder::Range { .. } => cfg!(any(
                all(target_arch = "aarch64", target_feature = "neon"),
                all(target_arch = "x86_64", target_feature = "sse2")
            )),
            AdaptiveFinder::Set(classifier) => {
                !matches!(classifier.selection().vector, VectorKind::Scalar)
            }
            AdaptiveFinder::One(_)
            | AdaptiveFinder::Two(_, _)
            | AdaptiveFinder::Three(_, _, _) => false,
        }
    }

    const fn supports_classified_general_stage(&self) -> bool {
        self.supports_vector_classified_run()
    }

    #[inline]
    fn find_member(&self, bytes: &[u8], warm_first_byte: bool) -> Option<usize> {
        match &self.finder {
            AdaptiveFinder::One(byte) => return memchr(*byte, bytes),
            AdaptiveFinder::Two(first, second) => return memchr2(*first, *second, bytes),
            AdaptiveFinder::Three(first, second, third) => {
                return memchr3(*first, *second, *third, bytes);
            }
            AdaptiveFinder::Four(_) | AdaptiveFinder::Range { .. } | AdaptiveFinder::Set(_) => {}
        }

        let mut cursor = 0_usize;
        if warm_first_byte {
            let &first = bytes.first()?;
            if self.matches(first) {
                return Some(0);
            }
            cursor = 1;
        }
        let search = bytes.get(cursor..)?;
        let relative = match &self.finder {
            AdaptiveFinder::Four(members) => find_byte_set4(*members, search),
            AdaptiveFinder::Range {
                origin,
                maximum_delta,
            } => find_byte_delta(*origin, *maximum_delta, search),
            AdaptiveFinder::Set(classifier) => classifier.find_first_member(search),
            AdaptiveFinder::One(_)
            | AdaptiveFinder::Two(_, _)
            | AdaptiveFinder::Three(_, _, _) => unreachable!("small finders returned above"),
        }?;
        cursor.checked_add(relative)
    }

    #[inline]
    fn classify_16(&self, bytes: &[u8; BYTE_SET_BLOCK_BYTES]) -> u16 {
        match &self.finder {
            AdaptiveFinder::One(first) => classify_byte_set1_16(*first, bytes).member_mask(),
            AdaptiveFinder::Two(first, second) => {
                classify_byte_set2_16([*first, *second], bytes).member_mask()
            }
            AdaptiveFinder::Three(first, second, third) => {
                classify_byte_set3_16([*first, *second, *third], bytes).member_mask()
            }
            AdaptiveFinder::Four(members) => classify_byte_set4_16(*members, bytes).member_mask(),
            AdaptiveFinder::Range {
                origin,
                maximum_delta,
            } => classify_byte_delta_16(*origin, *maximum_delta, bytes).member_mask(),
            AdaptiveFinder::Set(classifier) => classifier.classify_16(bytes).member_mask(),
        }
    }

    #[inline]
    fn classify_32(&self, bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES]) -> Option<u32> {
        match &self.finder {
            AdaptiveFinder::One(first) => Some(classify_byte_set1_32(*first, bytes).member_mask()),
            AdaptiveFinder::Two(first, second) => {
                Some(classify_byte_set2_32([*first, *second], bytes).member_mask())
            }
            AdaptiveFinder::Three(first, second, third) => {
                Some(classify_byte_set3_32([*first, *second, *third], bytes).member_mask())
            }
            AdaptiveFinder::Four(members) => {
                Some(classify_byte_set4_32(*members, bytes).member_mask())
            }
            AdaptiveFinder::Range { .. } => None,
            AdaptiveFinder::Set(classifier) => Some(classifier.classify_32(bytes).member_mask()),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct AdaptiveFinderBlock {
    // Absolute coordinates let one classified block survive every monotone
    // restart within that block, including a jump after an accepted match.
    start: usize,
    end: usize,
    members: u16,
}

#[cfg(test)]
struct AdaptiveFinderCursor<'a> {
    finder: &'a AdaptiveFinder,
    bytes: &'a [u8],
    anchor_end: usize,
    block: AdaptiveFinderBlock,
    #[cfg(test)]
    classified_chunks: usize,
}

#[cfg(test)]
impl<'a> AdaptiveFinderCursor<'a> {
    fn new(finder: &'a AdaptiveFinder, bytes: &'a [u8], anchor_end: usize) -> Self {
        Self {
            finder,
            bytes,
            anchor_end,
            block: AdaptiveFinderBlock::default(),
            #[cfg(test)]
            classified_chunks: 0,
        }
    }

    #[inline]
    fn find(&mut self, cursor: usize) -> Option<usize> {
        let finder = self.finder;
        match finder {
            AdaptiveFinder::One(byte) => self
                .bytes
                .get(cursor..self.anchor_end)
                .and_then(|bytes| memchr(*byte, bytes))
                .and_then(|relative| cursor.checked_add(relative)),
            AdaptiveFinder::Two(first, second) => self
                .bytes
                .get(cursor..self.anchor_end)
                .and_then(|bytes| memchr2(*first, *second, bytes))
                .and_then(|relative| cursor.checked_add(relative)),
            AdaptiveFinder::Three(first, second, third) => self
                .bytes
                .get(cursor..self.anchor_end)
                .and_then(|bytes| memchr3(*first, *second, *third, bytes))
                .and_then(|relative| cursor.checked_add(relative)),
            AdaptiveFinder::Four(members) => {
                let members = *members;
                self.find_classified(
                    cursor,
                    |block| classify_byte_set4_16(members, block).member_mask(),
                    |byte| members.contains(&byte),
                )
            }
            AdaptiveFinder::Range {
                origin,
                maximum_delta,
            } => self.find_range(cursor, *origin, *maximum_delta),
            AdaptiveFinder::Set(classifier) => self.find_classified(
                cursor,
                |block| classifier.classify_16(block).member_mask(),
                |byte| classifier.set().contains(byte),
            ),
        }
    }

    #[inline]
    fn find_range(&self, mut cursor: usize, origin: u8, maximum_delta: u8) -> Option<usize> {
        while let Some(end) = cursor
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .filter(|&end| end <= self.anchor_end)
        {
            let block =
                <&[u8; BYTE_SET_BLOCK_BYTES]>::try_from(self.bytes.get(cursor..end)?).ok()?;
            let members = classify_byte_delta_16(origin, maximum_delta, block).member_mask();
            if members != 0 {
                let lane = usize::try_from(members.trailing_zeros()).ok()?;
                return cursor.checked_add(lane);
            }
            cursor = end;
        }
        self.bytes
            .get(cursor..self.anchor_end)?
            .iter()
            .position(|&byte| byte.wrapping_sub(origin) <= maximum_delta)
            .and_then(|relative| cursor.checked_add(relative))
    }

    #[inline]
    fn find_classified(
        &mut self,
        mut cursor: usize,
        mut classify_16: impl FnMut(&[u8; BYTE_SET_BLOCK_BYTES]) -> u16,
        mut contains: impl FnMut(u8) -> bool,
    ) -> Option<usize> {
        while cursor < self.anchor_end {
            // Phase cursors only move forward. Masking already-serviced lanes
            // therefore preserves the cached classification for later calls.
            if self.block.start <= cursor && cursor < self.block.end {
                let skipped = cursor.checked_sub(self.block.start)?;
                let members = self.block.members & (u16::MAX << skipped);
                if members != 0 {
                    let lane = usize::try_from(members.trailing_zeros()).ok()?;
                    return self.block.start.checked_add(lane);
                }
                cursor = self.block.end;
                continue;
            }

            let chunk_len = self
                .anchor_end
                .checked_sub(cursor)?
                .min(BYTE_SET_BLOCK_BYTES);
            let chunk_end = cursor.checked_add(chunk_len)?;
            let chunk = self.bytes.get(cursor..chunk_end)?;
            let members = if chunk_len == BYTE_SET_BLOCK_BYTES {
                let block = <&[u8; BYTE_SET_BLOCK_BYTES]>::try_from(chunk).ok()?;
                classify_16(block)
            } else {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0_u16, |members, (lane, &byte)| {
                        members | (u16::from(contains(byte)) << lane)
                    })
            };
            self.block = AdaptiveFinderBlock {
                start: cursor,
                end: chunk_end,
                members,
            };
            #[cfg(test)]
            {
                self.classified_chunks = self.classified_chunks.checked_add(1)?;
            }
        }
        None
    }

    #[cfg(test)]
    const fn classified_chunks(&self) -> usize {
        self.classified_chunks
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CandidateStreamBlock {
    // Candidate-start coordinates let both retained predicate masks survive
    // every monotone restart within a classified block. An empty primary mask
    // authenticates an empty fallback mask without reading the second source
    // slice.
    start: usize,
    end: usize,
    primary_members: u32,
    fallback_members: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GeneralPrimaryOutcome {
    Match,
    FallbackRejected,
    ResidualRejected,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RetainedSearchPhase {
    #[default]
    Primary,
    CandidateStream,
    CandidateStreamDrain,
    ShiftAnd,
    Exhausted,
}

/// Plan-and-source-bound continuation for monotone fixed-predicate iteration.
///
/// The state retains candidate masks across accepted-word restarts. Both the
/// exact plan instance and the immutable source are borrowed for the complete
/// continuation lifetime, so safe callers cannot reuse classified bytes after
/// changing either input. A terminal-window or expected-start change resets
/// only the retained search phase.
///
/// This capability is public only because the facade lives in another crate;
/// ordinary independent searches should use [`FixedPredicateWord64Plan::find_window`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct FixedPredicateWord64SearchCursor<'p, 'h> {
    plan: &'p FixedPredicateWord64Plan,
    haystack: &'h [u8],
    phase: RetainedSearchPhase,
    block: CandidateStreamBlock,
    window_end: usize,
    next_start: Option<usize>,
}

impl<'p, 'h> FixedPredicateWord64SearchCursor<'p, 'h> {
    const fn new(plan: &'p FixedPredicateWord64Plan, haystack: &'h [u8]) -> Self {
        Self {
            plan,
            haystack,
            phase: RetainedSearchPhase::Primary,
            block: CandidateStreamBlock {
                start: 0,
                end: 0,
                primary_members: 0,
                fallback_members: 0,
            },
            window_end: 0,
            next_start: None,
        }
    }

    fn reset(&mut self) {
        self.phase = RetainedSearchPhase::Primary;
        self.block = CandidateStreamBlock::default();
        self.window_end = 0;
        self.next_start = None;
    }

    fn prepare(&mut self, window: Window) {
        if self.next_start != Some(window.start()) || self.window_end != window.end() {
            self.reset();
            self.window_end = window.end();
            self.next_start = Some(window.start());
        }
    }

    fn retain_match(&mut self, end: usize) {
        self.next_start = Some(end);
    }

    fn exhaust(&mut self) {
        self.phase = RetainedSearchPhase::Exhausted;
        self.next_start = Some(self.window_end);
        self.block = CandidateStreamBlock::default();
    }

    /// Find one span while retaining monotone candidate-stream state across
    /// successive non-overlapping windows of this bound plan and source.
    ///
    /// A terminal-window or expected-start change resets the continuation to
    /// the ordinary cold primary phase. The plan and source cannot be replaced
    /// because they were borrowed when this capability was constructed.
    pub fn find_window(
        &mut self,
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_window_transaction(window, limits, false)
    }

    /// Search at or after `start` in the complete bound source.
    pub fn find_at(
        &mut self,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_window(Window::new(start, self.haystack.len()), limits)
    }

    /// The immutable source bound to this capability.
    #[must_use]
    pub const fn haystack(&self) -> &'h [u8] {
        self.haystack
    }

    fn find_window_transaction(
        &mut self,
        window: Window,
        limits: SearchLimits,
        inject_late_failure: bool,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let plan = self.plan;
        let haystack = self.haystack;
        let upper_bounds = plan.search_preflight(haystack.len(), window, limits)?;
        let mut next = *self;
        next.prepare(window);
        let (matched, actual) =
            plan.execute_first_match_with_cursor(haystack, window, upper_bounds, &mut next)?;
        let accounting = SearchAccounting {
            identity: plan.search_operation_identity(SearchOperation::Span),
            upper_bounds,
            actual,
        };
        if inject_late_failure {
            return Err(SearchError::InternalInvariant(
                "injected retained-cursor precommit failure",
            ));
        }
        *self = next;
        Ok((matched, accounting))
    }

    #[cfg(test)]
    fn find_window_with_late_failure(
        &mut self,
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_window_transaction(window, limits, true)
    }
}

struct CandidateStreamCursor<'a> {
    primary: PrimaryPredicate<'a>,
    fallback: &'a AdaptiveFallback,
    fallback_skip: bool,
    bytes: &'a [u8],
    legal_start_end: usize,
    block: CandidateStreamBlock,
    primary_classified_bytes: usize,
    fallback_classified_bytes: usize,
    #[cfg(test)]
    classified_chunks: usize,
}

impl<'a> CandidateStreamCursor<'a> {
    #[cfg(test)]
    fn new(
        primary: PrimaryPredicate<'a>,
        fallback: &'a AdaptiveFallback,
        bytes: &'a [u8],
        legal_start_end: usize,
    ) -> Self {
        Self::new_with_fallback_skip(primary, fallback, false, bytes, legal_start_end)
    }

    fn new_with_fallback_skip(
        primary: PrimaryPredicate<'a>,
        fallback: &'a AdaptiveFallback,
        fallback_skip: bool,
        bytes: &'a [u8],
        legal_start_end: usize,
    ) -> Self {
        Self {
            primary,
            fallback,
            fallback_skip,
            bytes,
            legal_start_end,
            block: CandidateStreamBlock::default(),
            primary_classified_bytes: 0,
            fallback_classified_bytes: 0,
            #[cfg(test)]
            classified_chunks: 0,
        }
    }

    fn with_block_and_fallback_skip(
        primary: PrimaryPredicate<'a>,
        fallback: &'a AdaptiveFallback,
        fallback_skip: bool,
        bytes: &'a [u8],
        legal_start_end: usize,
        block: CandidateStreamBlock,
    ) -> Self {
        Self {
            primary,
            fallback,
            fallback_skip,
            bytes,
            legal_start_end,
            block,
            primary_classified_bytes: 0,
            fallback_classified_bytes: 0,
            #[cfg(test)]
            classified_chunks: 0,
        }
    }

    const fn retained_block(&self) -> CandidateStreamBlock {
        self.block
    }

    #[inline]
    fn find(&mut self, mut cursor: usize) -> Option<usize> {
        if self.primary.offset()? == self.fallback.offset {
            return None;
        }
        while cursor < self.legal_start_end {
            if self.block.start <= cursor && cursor < self.block.end {
                if let Some(candidate) = self.find_retained_before(cursor, self.block.end) {
                    return Some(candidate);
                }
                cursor = self.block.end;
                continue;
            }

            let block_bytes = self
                .primary
                .candidate_block_bytes()
                .min(self.fallback.candidate_block_bytes());
            let remaining = self.legal_start_end.checked_sub(cursor)?;
            let chunk_len = if block_bytes == BYTE_SET_WIDE_BLOCK_BYTES
                && remaining < BYTE_SET_WIDE_BLOCK_BYTES
                && remaining >= BYTE_SET_BLOCK_BYTES
            {
                BYTE_SET_BLOCK_BYTES
            } else {
                remaining.min(block_bytes)
            };
            let chunk_end = cursor.checked_add(chunk_len)?;
            let primary_members = if chunk_len == BYTE_SET_WIDE_BLOCK_BYTES {
                self.classify_primary_32(cursor)?
            } else if chunk_len == BYTE_SET_BLOCK_BYTES {
                self.classify_primary_16(cursor)?
            } else {
                self.classify_primary_tail(cursor, chunk_len)?
            };
            self.primary_classified_bytes =
                self.primary_classified_bytes.checked_add(chunk_len)?;
            // The second predicate cannot contribute a candidate when the
            // first mask is empty. Keep its classifier entirely off that
            // block's path instead of unconditionally reading and classifying
            // a second source slice.
            let fallback_members = if primary_members == 0 {
                0
            } else {
                let members = if chunk_len == BYTE_SET_WIDE_BLOCK_BYTES {
                    self.classify_fallback_32(cursor)?
                } else if chunk_len == BYTE_SET_BLOCK_BYTES {
                    self.classify_fallback_16(cursor)?
                } else {
                    self.classify_fallback_tail(cursor, chunk_len)?
                };
                self.fallback_classified_bytes =
                    self.fallback_classified_bytes.checked_add(chunk_len)?;
                members
            };
            self.block = CandidateStreamBlock {
                start: cursor,
                end: chunk_end,
                primary_members,
                fallback_members,
            };
            #[cfg(test)]
            {
                self.classified_chunks = self.classified_chunks.checked_add(1)?;
            }
            if self.fallback_skip
                && primary_members != 0
                && fallback_members == 0
                && chunk_end < self.legal_start_end
            {
                let fallback_offset = usize::from(self.fallback.offset);
                let scan_start = chunk_end.checked_add(fallback_offset)?;
                let scan_end = self.legal_start_end.checked_add(fallback_offset)?;
                let search = self.bytes.get(scan_start..scan_end)?;
                let relative = self.fallback.find_member(search, false);
                let service = relative.unwrap_or(search.len());
                self.fallback_classified_bytes =
                    self.fallback_classified_bytes.checked_add(service)?;
                let relative = relative?;
                cursor = chunk_end.checked_add(relative)?;
            }
        }
        None
    }

    #[inline]
    fn find_retained_before(&self, cursor: usize, end: usize) -> Option<usize> {
        let terminal = end.min(self.block.end);
        if cursor < self.block.start || cursor >= terminal {
            return None;
        }
        let skipped = cursor.checked_sub(self.block.start)?;
        let retained = terminal.checked_sub(self.block.start)?;
        let unserviced = u32::MAX.checked_shl(u32::try_from(skipped).ok()?)?;
        let mask_bits = usize::try_from(u32::BITS).ok()?;
        let before_terminal = if retained == mask_bits {
            u32::MAX
        } else {
            1_u32
                .checked_shl(u32::try_from(retained).ok()?)?
                .wrapping_sub(1)
        };
        let candidates =
            self.block.primary_members & self.block.fallback_members & unserviced & before_terminal;
        if candidates == 0 {
            return None;
        }
        let lane = usize::try_from(candidates.trailing_zeros()).ok()?;
        self.block.start.checked_add(lane)
    }

    #[inline]
    fn classify_primary_16(&self, start: usize) -> Option<u32> {
        let primary_offset = usize::from(self.primary.offset()?);
        let primary = self.block_16(start.checked_add(primary_offset)?)?;
        Some(u32::from(self.primary.classify_16(primary)?))
    }

    #[inline]
    fn classify_fallback_16(&self, start: usize) -> Option<u32> {
        let fallback_offset = usize::from(self.fallback.offset);
        let fallback = self.block_16(start.checked_add(fallback_offset)?)?;
        Some(u32::from(self.fallback.classify_16(fallback)))
    }

    #[inline]
    fn classify_primary_32(&self, start: usize) -> Option<u32> {
        let primary_offset = usize::from(self.primary.offset()?);
        if self.primary.candidate_block_bytes() != BYTE_SET_WIDE_BLOCK_BYTES {
            return None;
        }
        let primary = self.block_32(start.checked_add(primary_offset)?)?;
        self.primary.classify_32(primary)
    }

    #[inline]
    fn classify_fallback_32(&self, start: usize) -> Option<u32> {
        let fallback_offset = usize::from(self.fallback.offset);
        if self.fallback.candidate_block_bytes() != BYTE_SET_WIDE_BLOCK_BYTES {
            return None;
        }
        let fallback = self.block_32(start.checked_add(fallback_offset)?)?;
        self.fallback.classify_32(fallback)
    }

    #[inline]
    fn classify_primary_tail(&self, start: usize, len: usize) -> Option<u32> {
        let primary_offset = usize::from(self.primary.offset()?);
        if len >= BYTE_SET_BLOCK_BYTES {
            return None;
        }
        let mut primary_members = 0_u32;
        for lane in 0..len {
            let candidate = start.checked_add(lane)?;
            let primary_byte = *self.bytes.get(candidate.checked_add(primary_offset)?)?;
            let lane_shift = u32::try_from(lane).ok()?;
            primary_members |= u32::from(self.primary.matches(primary_byte)?) << lane_shift;
        }
        Some(primary_members)
    }

    #[inline]
    fn classify_fallback_tail(&self, start: usize, len: usize) -> Option<u32> {
        let fallback_offset = usize::from(self.fallback.offset);
        if len >= BYTE_SET_BLOCK_BYTES {
            return None;
        }
        let mut fallback_members = 0_u32;
        for lane in 0..len {
            let candidate = start.checked_add(lane)?;
            let fallback_byte = *self.bytes.get(candidate.checked_add(fallback_offset)?)?;
            let lane_shift = u32::try_from(lane).ok()?;
            fallback_members |= u32::from(self.fallback.matches(fallback_byte)) << lane_shift;
        }
        Some(fallback_members)
    }

    #[inline]
    fn block_16(&self, start: usize) -> Option<&[u8; BYTE_SET_BLOCK_BYTES]> {
        let end = start.checked_add(BYTE_SET_BLOCK_BYTES)?;
        self.bytes.get(start..end)?.try_into().ok()
    }

    #[inline]
    fn block_32(&self, start: usize) -> Option<&[u8; BYTE_SET_WIDE_BLOCK_BYTES]> {
        let end = start.checked_add(BYTE_SET_WIDE_BLOCK_BYTES)?;
        self.bytes.get(start..end)?.try_into().ok()
    }

    const fn primary_classified_bytes(&self) -> usize {
        self.primary_classified_bytes
    }

    const fn fallback_classified_bytes(&self) -> usize {
        self.fallback_classified_bytes
    }

    #[cfg(test)]
    const fn classified_chunks(&self) -> usize {
        self.classified_chunks
    }

    #[cfg(test)]
    const fn block_bytes(&self) -> usize {
        let primary = self.primary.candidate_block_bytes();
        let fallback = self.fallback.candidate_block_bytes();
        if primary < fallback { primary } else { fallback }
    }
}

#[derive(Clone, Copy, Debug)]
struct FallbackCandidate {
    score: (usize, u8, usize),
    bytes: [u8; 4],
    set: ByteSet256,
    contiguous_range: Option<(u8, u8)>,
}

fn build_predicate_finder(
    candidate: FallbackCandidate,
    tracker: &mut BuildAttemptTracker,
) -> Result<AdaptiveFallback, BuildError> {
    let offset = u8::try_from(candidate.score.2)
        .map_err(|_| BuildError::InternalInvariant("predicate finder offset exceeded one byte"))?;
    let cardinality = u16::try_from(candidate.score.0).map_err(|_| {
        BuildError::InternalInvariant("predicate finder cardinality exceeded identity")
    })?;
    let finder = match candidate.score.0 {
        1 => AdaptiveFinder::One(candidate.bytes[0]),
        2 => AdaptiveFinder::Two(candidate.bytes[0], candidate.bytes[1]),
        3 => AdaptiveFinder::Three(
            candidate.bytes[0],
            candidate.bytes[1],
            candidate.bytes[2],
        ),
        _ => match candidate.contiguous_range {
            Some((origin, maximum_delta)) => AdaptiveFinder::Range {
                origin,
                maximum_delta,
            },
            None if candidate.score.0 == 4 => AdaptiveFinder::Four(candidate.bytes),
            None => {
                tracker.build_adaptive_classifier()?;
                AdaptiveFinder::Set(ByteSetClassifier::new(candidate.set))
            }
        },
    };
    Ok(AdaptiveFallback {
        offset,
        cardinality,
        finder,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Anchor {
    One { offset: u8, byte: u8 },
    Two { offset: u8, first: u8, second: u8 },
    ShiftAnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReducerUpper {
    transitions: usize,
    finder_scanned_bytes: usize,
    shift_and_transitions: usize,
    finder_calls: usize,
    anchor_candidates: usize,
    predicate_checks: usize,
    work: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SemanticUpper {
    match_events: usize,
    count: u64,
    span_sum: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AnchorActual {
    finder_scanned_bytes: usize,
    shift_and_transitions: usize,
    finder_calls: usize,
    anchor_candidates: usize,
    predicate_checks: usize,
    match_events: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ValueReduction {
    count: u64,
    matched_bytes: u64,
}

impl Anchor {
    const fn identity(self) -> (Reducer, u8, [u8; 2]) {
        match self {
            Self::One { offset, byte } => (Reducer::OneByteAnchor, offset, [byte, 0]),
            Self::Two {
                offset,
                first,
                second,
            } => (Reducer::TwoByteAnchor, offset, [first, second]),
            Self::ShiftAnd => (Reducer::ShiftAnd, 0, [0, 0]),
        }
    }

    const fn offset(self) -> Option<u8> {
        match self {
            Self::One { offset, .. } | Self::Two { offset, .. } => Some(offset),
            Self::ShiftAnd => None,
        }
    }

    const fn exact_identity(self) -> Option<ExactAnchorIdentity> {
        let (reducer, offset, bytes) = self.identity();
        match self {
            Self::One { .. } | Self::Two { .. } => Some(ExactAnchorIdentity {
                reducer,
                offset,
                bytes,
            }),
            Self::ShiftAnd => None,
        }
    }

    const fn matches(self, byte: u8) -> Option<bool> {
        match self {
            Self::One { byte: expected, .. } => Some(byte == expected),
            Self::Two { first, second, .. } => Some(byte == first || byte == second),
            Self::ShiftAnd => None,
        }
    }

    #[inline]
    fn classify_16(self, bytes: &[u8; BYTE_SET_BLOCK_BYTES]) -> Option<u16> {
        match self {
            Self::One { byte, .. } => Some(classify_byte_set1_16(byte, bytes).member_mask()),
            Self::Two { first, second, .. } => {
                Some(classify_byte_set2_16([first, second], bytes).member_mask())
            }
            Self::ShiftAnd => None,
        }
    }

    #[inline]
    fn classify_32(self, bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES]) -> Option<u32> {
        match self {
            Self::One { byte, .. } => Some(classify_byte_set1_32(byte, bytes).member_mask()),
            Self::Two { first, second, .. } => {
                Some(classify_byte_set2_32([first, second], bytes).member_mask())
            }
            Self::ShiftAnd => None,
        }
    }
}

/// Successful fixed-predicate construction and its closed receipt.
#[derive(Debug)]
pub struct BuildAttempt {
    plan: FixedPredicateWord64Plan,
    receipt: BuildAttemptReceipt,
}

impl BuildAttempt {
    #[must_use]
    pub const fn plan(&self) -> &FixedPredicateWord64Plan {
        &self.plan
    }

    #[must_use]
    pub const fn receipt(&self) -> &BuildAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt.closes_success(self.plan.build_accounting())
    }

    #[must_use]
    pub fn into_parts(self) -> (FixedPredicateWord64Plan, BuildAttemptReceipt) {
        (self.plan, self.receipt)
    }

    #[must_use]
    pub fn into_plan(self) -> FixedPredicateWord64Plan {
        self.plan
    }
}

#[derive(Clone, Copy)]
struct BuildPreflight {
    width: usize,
    source_ranges: usize,
    work_upper_bound: u64,
    persistent_bytes: usize,
    peak_bytes: usize,
}

fn preflight_build(
    positions: &[&[(u8, u8)]],
    limits: BuildLimits,
) -> Result<BuildPreflight, BuildError> {
    let width = positions.len();
    if width < MIN_WIDTH {
        return Err(BuildError::WidthTooSmall {
            needed: width,
            minimum: MIN_WIDTH,
        });
    }
    if width > MAX_WIDTH {
        return Err(BuildError::WidthTooLarge {
            needed: width,
            maximum: MAX_WIDTH,
        });
    }
    enforce_build_usize(width, limits.max_positions, BuildResource::Positions)?;

    let base_work = MASK_SLOTS
        .checked_add(width)
        .and_then(|work| work.checked_add(width.checked_mul(ANCHOR_MASK_DOMAIN)?))
        .and_then(|work| {
            work.checked_add(BYTE_SET_CLASSIFIER_BUILD_WORK.checked_mul(2)?)
        })
        .and_then(|work| work.checked_add(BUILD_FIXED_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "base build work",
        })?;
    enforce_build_work(base_work, limits.max_build_work)?;

    let scratch_bytes = 0;
    if scratch_bytes > limits.max_scratch_bytes {
        return Err(BuildError::ScratchLimit {
            needed: scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    let persistent_bytes = size_of::<FixedPredicateWord64Plan>();
    enforce_build_usize(
        persistent_bytes,
        limits.max_persistent_bytes,
        BuildResource::Persistent,
    )?;
    let peak_bytes = persistent_bytes;
    enforce_build_usize(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

    let source_ranges = positions.iter().try_fold(0_usize, |total, ranges| {
        total
            .checked_add(ranges.len())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "source range count",
            })
    })?;
    enforce_build_usize(
        source_ranges,
        limits.max_source_ranges,
        BuildResource::SourceRanges,
    )?;
    let per_range_work = RANGE_FIXED_WORK.checked_add(MAX_MEMBERS_PER_RANGE).ok_or(
        BuildError::ArithmeticOverflow {
            computation: "per-range work upper bound",
        },
    )?;
    let range_work =
        source_ranges
            .checked_mul(per_range_work)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "range work upper bound",
            })?;
    let work_upper = base_work
        .checked_add(range_work)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "build work upper bound",
        })?;
    let work_upper_bound = enforce_build_work(work_upper, limits.max_build_work)?;
    Ok(BuildPreflight {
        width,
        source_ranges,
        work_upper_bound,
        persistent_bytes,
        peak_bytes,
    })
}

fn compile_masks(
    positions: &[&[(u8, u8)]],
    tracker: &mut BuildAttemptTracker,
) -> Result<([u64; MASK_SLOTS], usize), BuildError> {
    let mut masks = [0_u64; MASK_SLOTS];
    tracker.initialize_masks()?;
    let mut member_writes = 0_usize;
    for (position, ranges) in positions.iter().enumerate() {
        tracker.visit_position()?;
        if ranges.is_empty() {
            return Err(BuildError::EmptyPosition { position });
        }
        let shift = u32::try_from(position).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "position shift conversion",
        })?;
        let bit = 1_u64
            .checked_shl(shift)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "position mask",
            })?;
        for (range, &(start, end)) in ranges.iter().enumerate() {
            tracker.inspect_range()?;
            if start > end {
                return Err(BuildError::ReversedRange {
                    position,
                    range,
                    start,
                    end,
                });
            }
            for byte in start..=end {
                let slot = masks
                    .get_mut(usize::from(byte))
                    .ok_or(BuildError::InternalInvariant("byte mask slot disappeared"))?;
                *slot |= bit;
                member_writes =
                    member_writes
                        .checked_add(1)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "member write count",
                        })?;
                tracker.write_member()?;
            }
        }
    }
    Ok((masks, member_writes))
}

fn select_anchor(
    masks: &[u64; MASK_SLOTS],
    width: usize,
    tracker: &mut BuildAttemptTracker,
) -> Result<
    (
        Anchor,
        Option<AdaptiveFallback>,
        Option<Anchor>,
        Option<AdaptiveFallback>,
        u64,
    ),
    BuildError,
> {
    let mut selected = Anchor::ShiftAnd;
    let mut selected_score = None;
    let mut secondary_anchor = None;
    let mut secondary_score = None;
    let mut fallback_first: Option<FallbackCandidate> = None;
    let mut fallback_second: Option<FallbackCandidate> = None;
    let mut nonuniversal_mask = 0_u64;
    for position in 0..width {
        let shift = u32::try_from(position).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "anchor position shift conversion",
        })?;
        let bit = 1_u64
            .checked_shl(shift)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "anchor position mask",
            })?;
        let mut bytes = [0_u8; 4];
        let mut members = 0_usize;
        let mut rank = 0_u8;
        let mut set_words = [0_u64; 4];
        let mut first_member = None;
        let mut last_member = 0_u8;
        for byte in 0_u8..=u8::MAX {
            tracker.read_anchor_mask()?;
            if masks[usize::from(byte)] & bit != 0 {
                first_member.get_or_insert(byte);
                last_member = byte;
                if let Some(slot) = bytes.get_mut(members) {
                    *slot = byte;
                }
                members = members
                    .checked_add(1)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "anchor member count",
                    })?;
                rank = rank.max(byte_frequency_rank(byte));
                let word = usize::from(byte >> 6);
                let member_bit = u32::from(byte & 63);
                set_words[word] |= 1_u64 << member_bit;
            }
        }
        let contiguous_range = first_member.and_then(|origin| {
            let maximum_delta = last_member.checked_sub(origin)?;
            (usize::from(maximum_delta).checked_add(1)? == members)
                .then_some((origin, maximum_delta))
        });
        if members < MASK_SLOTS {
            nonuniversal_mask |= bit;
            let fallback = FallbackCandidate {
                score: (members, rank, position),
                bytes,
                set: ByteSet256::from_words(set_words),
                contiguous_range,
            };
            if fallback_first.is_none_or(|prior| fallback.score < prior.score) {
                fallback_second = fallback_first;
                fallback_first = Some(fallback);
            } else if fallback_second.is_none_or(|prior| fallback.score < prior.score) {
                fallback_second = Some(fallback);
            }
        }
        if (1..=2).contains(&members) {
            let score = (rank, members);
            let offset = u8::try_from(position)
                .map_err(|_| BuildError::InternalInvariant("anchor offset exceeded one byte"))?;
            let candidate = if members == 1 {
                Anchor::One {
                    offset,
                    byte: bytes[0],
                }
            } else {
                Anchor::Two {
                    offset,
                    first: bytes[0],
                    second: bytes[1],
                }
            };
            if selected_score.is_some_and(|prior| score > prior) {
                if secondary_score.is_none_or(|prior| score <= prior) {
                    secondary_score = Some(score);
                    secondary_anchor = Some(candidate);
                }
                continue;
            }
            secondary_score = selected_score;
            secondary_anchor = selected.offset().map(|_| selected);
            selected_score = Some(score);
            selected = candidate;
        }
    }
    let exact_primary_offset = selected.offset().map(usize::from);
    // A general primary is retained only with a second independently selective
    // predicate. Three-member primaries begin with memchr3; supported wider
    // primaries scan through their already-retained classifier.
    let general_pair = match (exact_primary_offset, fallback_first, fallback_second) {
        (None, Some(primary), Some(secondary))
            if primary.score.0 <= GENERAL_PRIMARY_MAX_CARDINALITY
                && secondary.score.0 <= GENERAL_PRIMARY_MAX_CARDINALITY =>
        {
            Some((primary, secondary))
        }
        _ => None,
    };
    let primary_candidate = general_pair.map(|(primary, _)| primary);
    let primary_finder = primary_candidate
        .map(|primary| build_predicate_finder(primary, tracker))
        .transpose()?;
    let primary_offset = exact_primary_offset.or_else(|| {
        primary_finder
            .as_ref()
            .map(|finder| usize::from(finder.offset))
    });
    let fallback = match general_pair {
        Some((_, secondary)) => Some(secondary),
        None if exact_primary_offset.is_some() => [fallback_first, fallback_second]
            .into_iter()
            .flatten()
            .find(|candidate| Some(candidate.score.2) != primary_offset),
        None => None,
    };
    let verification_positions = match primary_offset {
        Some(position) => {
            let shift = u32::try_from(position).map_err(|_| {
                BuildError::InternalInvariant("primary anchor offset exceeded one word")
            })?;
            let primary = 1_u64
                .checked_shl(shift)
                .ok_or(BuildError::InternalInvariant(
                    "primary anchor bit exceeded one word",
                ))?;
            if nonuniversal_mask & primary == 0 {
                return Err(BuildError::InternalInvariant(
                    "primary anchor was not a non-universal predicate",
                ));
            }
            usize::try_from((nonuniversal_mask & !primary).count_ones()).map_err(|_| {
                BuildError::InternalInvariant("verification count did not fit usize")
            })?
        }
        None => 0,
    };
    let adaptive_fallback = match (primary_offset, fallback, verification_positions != 0) {
        (Some(_), Some(candidate), true) => {
            Some(build_predicate_finder(candidate, tracker)?)
        }
        _ => None,
    };
    Ok((
        selected,
        primary_finder,
        secondary_anchor,
        adaptive_fallback,
        nonuniversal_mask,
    ))
}

fn actual_build_work(
    width: usize,
    source_ranges: usize,
    member_writes: usize,
    anchor_mask_reads: usize,
    adaptive_classifier_work: usize,
) -> Result<u64, BuildError> {
    let work = source_ranges
        .checked_mul(RANGE_FIXED_WORK)
        .and_then(|range_work| MASK_SLOTS.checked_add(width)?.checked_add(range_work))
        .and_then(|work| work.checked_add(member_writes))
        .and_then(|work| work.checked_add(anchor_mask_reads))
        .and_then(|work| work.checked_add(adaptive_classifier_work))
        .and_then(|work| work.checked_add(BUILD_FIXED_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "actual build work",
        })?;
    u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "actual build work conversion",
    })
}

fn enforce_build_work(needed: usize, limit: u64) -> Result<u64, BuildError> {
    let needed = u64::try_from(needed).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "build work conversion",
    })?;
    if needed > limit {
        return Err(BuildError::WorkLimit { needed, limit });
    }
    Ok(needed)
}

impl FixedPredicateWord64Plan {
    /// Compile per-position inclusive byte ranges into one Shift-And table.
    ///
    /// `positions[i]` is the union of its inclusive `(start, end)` ranges.
    /// Shape, work and retained storage are admitted before any range tuple is
    /// read. The plan retains no caller slice.
    ///
    /// # Errors
    ///
    /// Returns a typed semantic, resource, arithmetic or invariant failure.
    pub fn build(positions: &[&[(u8, u8)]], limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_attempt(positions, limits)
            .map(BuildAttempt::into_plan)
            .map_err(BuildAttemptError::into_source)
    }

    /// Build while retaining exact success or partial-failure construction
    /// effects.
    #[allow(
        clippy::result_large_err,
        reason = "the terminal receipt remains inline so reporting a failed allocation never needs another allocation"
    )]
    pub fn build_attempt(
        positions: &[&[(u8, u8)]],
        limits: BuildLimits,
    ) -> Result<BuildAttempt, BuildAttemptError> {
        let identity = BuildAttemptIdentity {
            plan_id: PLAN_ID,
            limits,
            algorithm_version: BUILD_ATTEMPT_ALGORITHM_VERSION,
            accounting_version: BUILD_ATTEMPT_ACCOUNTING_VERSION,
        };
        let mut tracker = BuildAttemptTracker::new(limits);
        let result = (|| {
            let preflight = preflight_build(positions, limits)?;
            let (masks, member_writes) = compile_masks(positions, &mut tracker)?;
            let (
                anchor,
                primary_finder,
                secondary_anchor,
                adaptive_fallback,
                nonuniversal_mask,
            ) = select_anchor(&masks, preflight.width, &mut tracker)?;
            if tracker.actual.adaptive_classifier_build_work
                != primary_finder
                    .map_or(0, |finder| finder.classifier_build_work())
                    .checked_add(
                        adaptive_fallback.map_or(0, |fallback| fallback.classifier_build_work()),
                    )
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "retained predicate classifier build work",
                    })?
            {
                return Err(BuildError::InternalInvariant(
                    "adaptive classifier build work disagreed with retained finder",
                ));
            }
            tracker.finish(preflight)?;
            let independently_counted_work = actual_build_work(
                preflight.width,
                preflight.source_ranges,
                member_writes,
                tracker.actual.anchor_mask_reads,
                tracker.actual.adaptive_classifier_build_work,
            )?;
            if tracker.actual.work != independently_counted_work {
                return Err(BuildError::InternalInvariant(
                    "observed build work disagreed with independent exact count",
                ));
            }
            if tracker.actual.work > preflight.work_upper_bound {
                return Err(BuildError::InternalInvariant(
                    "actual build work exceeded admitted upper bound",
                ));
            }
            let accepting_shift = u32::try_from(preflight.width.checked_sub(1).ok_or(
                BuildError::InternalInvariant("validated width became empty"),
            )?)
            .map_err(|_| BuildError::ArithmeticOverflow {
                computation: "accepting shift conversion",
            })?;
            let accepting_bit =
                1_u64
                    .checked_shl(accepting_shift)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "accepting bit",
                    })?;
            let build = BuildAccounting {
                positions: preflight.width,
                source_ranges: preflight.source_ranges,
                mask_zero_writes: tracker.actual.mask_zero_writes,
                position_visits: tracker.actual.position_visits,
                range_inspections: tracker.actual.range_inspections,
                member_writes: tracker.actual.member_writes,
                anchor_mask_reads: tracker.actual.anchor_mask_reads,
                adaptive_classifier_build_work: tracker.actual.adaptive_classifier_build_work,
                work_upper_bound: preflight.work_upper_bound,
                work_charged: tracker.actual.work,
                allocations: tracker.actual.allocations,
                reserves: tracker.actual.reserves,
                temporary_copies: tracker.actual.temporary_copies,
                scratch_bytes: tracker.actual.live_scratch_bytes,
                persistent_bytes: tracker.actual.live_persistent_bytes,
                peak_bytes: tracker.actual.peak_bytes,
            };
            Ok(Self {
                masks,
                width: preflight.width,
                accepting_bit,
                nonuniversal_mask,
                anchor,
                primary_finder,
                secondary_anchor,
                adaptive_fallback,
                build,
            })
        })();
        match result {
            Ok(plan) => {
                let receipt = BuildAttemptReceipt {
                    identity,
                    actual: tracker.actual,
                    accounting: Some(plan.build),
                    published: true,
                };
                if !receipt.closes_success(plan.build) {
                    return Err(BuildAttemptError::new(
                        BuildError::InternalInvariant(
                            "fixed-predicate build success did not close its receipt",
                        ),
                        identity,
                        tracker.actual,
                    ));
                }
                Ok(BuildAttempt { plan, receipt })
            }
            Err(source) => Err(BuildAttemptError::new(source, identity, tracker.actual)),
        }
    }

    /// Exact word width.
    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    fn primary_finder_descriptor(&self) -> Option<PrimaryPredicate<'_>> {
        match self.primary_finder.as_ref() {
            Some(finder) => Some(PrimaryPredicate::General(finder)),
            None => self.anchor.offset().map(|_| PrimaryPredicate::Exact(self.anchor)),
        }
    }

    fn general_primary_staged(&self) -> Option<(usize, GeneralPrimarySeeker<'_>)> {
        let finder = self.primary_finder.as_ref()?;
        match &finder.finder {
            AdaptiveFinder::Three(first, second, third) => Some((
                usize::from(finder.offset),
                GeneralPrimarySeeker::Memchr3([*first, *second, *third]),
            )),
            _ if finder.supports_classified_general_stage() => Some((
                usize::from(finder.offset),
                GeneralPrimarySeeker::CompiledWholeSlice(finder),
            )),
            _ => None,
        }
    }

    const fn primary_offset(&self) -> Option<u8> {
        match self.primary_finder {
            Some(finder) => Some(finder.offset),
            None => self.anchor.offset(),
        }
    }

    const fn primary_finder_identity(&self) -> Option<AdaptiveFinderIdentity> {
        match self.primary_finder {
            Some(finder) => Some(finder.identity()),
            None => None,
        }
    }

    /// Derived initial execution mode for the retained general primary.
    #[must_use]
    pub const fn general_primary_scan_identity(&self) -> Option<GeneralPrimaryScanIdentity> {
        let Some(finder) = &self.primary_finder else {
            return None;
        };
        match &finder.finder {
            AdaptiveFinder::Three(_, _, _) => Some(GeneralPrimaryScanIdentity::Memchr3),
            _ if finder.supports_classified_general_stage() => {
                Some(GeneralPrimaryScanIdentity::CompiledWholeSlice)
            }
            _ => Some(GeneralPrimaryScanIdentity::DirectCandidateStream),
        }
    }

    /// Derived fallback-empty skip mode for the retained general pair.
    #[must_use]
    pub const fn general_fallback_scan_identity(&self) -> Option<GeneralFallbackScanIdentity> {
        if !matches!(
            self.general_primary_scan_identity(),
            Some(GeneralPrimaryScanIdentity::CompiledWholeSlice)
        ) {
            return None;
        }
        let Some(fallback) = &self.adaptive_fallback else {
            return None;
        };
        if !fallback.supports_vector_classified_run() {
            return None;
        }
        Some(GeneralFallbackScanIdentity::CompiledWholeSliceAfterEmptyBlock)
    }

    fn general_fallback_skip(&self) -> bool {
        self.general_fallback_scan_identity().is_some()
    }

    const fn reducer_identity(&self) -> (Reducer, u8, [u8; 2]) {
        match self.primary_finder {
            Some(finder) => (Reducer::ShiftAnd, finder.offset, [0, 0]),
            None => self.anchor.identity(),
        }
    }

    const fn is_raw_shift_and(&self) -> bool {
        self.primary_finder.is_none() && matches!(self.anchor, Anchor::ShiftAnd)
    }

    fn verification_positions(&self) -> Option<usize> {
        let offset = u32::from(self.primary_offset()?);
        let primary = 1_u64.checked_shl(offset)?;
        if self.nonuniversal_mask & primary == 0 {
            return None;
        }
        usize::try_from((self.nonuniversal_mask & !primary).count_ones()).ok()
    }

    const fn verification_predicate_identity_count(&self) -> u32 {
        match self.primary_offset() {
            Some(_) => {
                self.nonuniversal_mask.count_ones().saturating_sub(1)
            }
            None => 0,
        }
    }

    const fn secondary_anchor_identity(&self) -> Option<ExactAnchorIdentity> {
        match self.secondary_anchor {
            Some(anchor) => anchor.exact_identity(),
            None => None,
        }
    }

    const fn adaptive_handoff_identity(&self) -> AdaptiveHandoffIdentity {
        match self.adaptive_fallback {
            Some(fallback) => AdaptiveHandoffIdentity::Finder {
                finder: fallback.identity(),
                final_shift_and: true,
            },
            None => AdaptiveHandoffIdentity::Disabled,
        }
    }

    /// Maximum non-universal predicates checked for one anchored candidate.
    /// Full-domain predicates are excluded. Every retained finder is itself
    /// non-universal, so primary and fallback phases have the same maximum.
    /// Returns zero for a raw Shift-And plan, which has no anchor candidates.
    #[must_use]
    pub fn max_verification_predicates(&self) -> usize {
        self.verification_positions().unwrap_or(0)
    }

    /// Successful construction certificate.
    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Stable identity for one ordinary first-match search projection.
    #[must_use]
    pub const fn search_operation_identity(
        &self,
        operation: SearchOperation,
    ) -> SearchOperationIdentity {
        let operation_id = match operation {
            SearchOperation::Exists => EXISTS_SEARCH_OPERATION_ID,
            SearchOperation::EarliestEnd => EARLIEST_END_SEARCH_OPERATION_ID,
            SearchOperation::SelectedEnd => SELECTED_END_SEARCH_OPERATION_ID,
            SearchOperation::Span => SPAN_SEARCH_OPERATION_ID,
        };
        let (reducer, anchor_offset, anchor_bytes) = self.reducer_identity();
        SearchOperationIdentity {
            plan_id: SEARCH_PLAN_ID,
            operation_id,
            operation,
            semantics: MatchSemantics::FixedBytePredicates,
            selection: MatchSelection::LeftmostFirstNonOverlapping,
            width: self.width,
            reducer,
            anchor_offset,
            anchor_bytes,
            primary_finder: self.primary_finder_identity(),
            general_primary_scan: self.general_primary_scan_identity(),
            general_fallback_scan: self.general_fallback_scan_identity(),
            secondary_anchor: self.secondary_anchor_identity(),
            verification_predicates: self.verification_predicate_identity_count(),
            adaptive_handoff: self.adaptive_handoff_identity(),
        }
    }

    /// Whether a selected match exists wholly inside `window`.
    pub fn is_match_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let (matched, accounting) =
            self.search_window(haystack, window, limits, SearchOperation::Exists)?;
        Ok((matched.is_some(), accounting))
    }

    /// Return only whether a selected match exists wholly inside `window`.
    ///
    /// The compact success projection deliberately omits diagnostic accounting
    /// while retaining the reporting operation's exact preflight and error
    /// contract.
    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.search_window_value(haystack, window, limits)
            .map(|matched| matched.is_some())
    }

    /// Return the first accepting end wholly inside `window`.
    pub fn earliest_end_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let (matched, accounting) =
            self.search_window(haystack, window, limits, SearchOperation::EarliestEnd)?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    /// Return the selected leftmost-first end in the complete haystack.
    pub fn selected_end(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.selected_end_window(haystack, Window::full(haystack), limits)
    }

    /// Return the selected leftmost-first end wholly inside `window`.
    pub fn selected_end_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let (matched, accounting) =
            self.search_window(haystack, window, limits, SearchOperation::SelectedEnd)?;
        Ok((matched.map(|(_, end)| end), accounting))
    }

    /// Find the selected leftmost-first span in the complete haystack.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the selected leftmost-first span wholly inside `window`.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.search_window(haystack, window, limits, SearchOperation::Span)
    }

    /// Bind operation-local continuation state to this exact plan and one
    /// immutable source.
    ///
    /// The returned capability exposes no plan or source substitution point.
    /// This is intended for cross-crate iterator/session owners; independent
    /// search calls should use [`Self::find_window`].
    ///
    /// Safe code cannot mutate the source in place while the continuation is
    /// live:
    ///
    /// ```compile_fail
    /// use fre_kernels::{
    ///     FixedPredicateWord64BuildLimits, FixedPredicateWord64Plan,
    ///     FixedPredicateWord64SearchLimits, Window,
    /// };
    ///
    /// let literal = [(b'a', b'a')];
    /// let predicates: [&[(u8, u8)]; 1] = [&literal];
    /// let plan = FixedPredicateWord64Plan::build(
    ///     &predicates,
    ///     FixedPredicateWord64BuildLimits::unlimited(),
    /// ).unwrap();
    /// let mut source = b"aa".to_vec();
    /// let mut cursor = plan.search_cursor(&source);
    /// source[1] = b'b';
    /// let _ = cursor.find_window(
    ///     Window::full(&source),
    ///     FixedPredicateWord64SearchLimits::unlimited(),
    /// );
    /// ```
    ///
    /// The former free cursor method is deliberately absent, so a cursor
    /// cannot be supplied to a second plan:
    ///
    /// ```compile_fail
    /// use fre_kernels::{
    ///     FixedPredicateWord64BuildLimits, FixedPredicateWord64Plan,
    ///     FixedPredicateWord64SearchLimits, Window,
    /// };
    ///
    /// let a = [(b'a', b'a')];
    /// let b = [(b'b', b'b')];
    /// let pa: [&[(u8, u8)]; 1] = [&a];
    /// let pb: [&[(u8, u8)]; 1] = [&b];
    /// let first = FixedPredicateWord64Plan::build(
    ///     &pa,
    ///     FixedPredicateWord64BuildLimits::unlimited(),
    /// ).unwrap();
    /// let second = FixedPredicateWord64Plan::build(
    ///     &pb,
    ///     FixedPredicateWord64BuildLimits::unlimited(),
    /// ).unwrap();
    /// let source = b"ab";
    /// let mut cursor = first.search_cursor(source);
    /// let _ = second.find_window_with_cursor(
    ///     source,
    ///     Window::full(source),
    ///     FixedPredicateWord64SearchLimits::unlimited(),
    ///     &mut cursor,
    /// );
    /// ```
    #[doc(hidden)]
    #[must_use]
    pub const fn search_cursor<'p, 'h>(
        &'p self,
        haystack: &'h [u8],
    ) -> FixedPredicateWord64SearchCursor<'p, 'h> {
        FixedPredicateWord64SearchCursor::new(self, haystack)
    }

    /// Return only the selected span wholly inside `window`.
    ///
    /// The compact success projection deliberately omits diagnostic accounting
    /// while retaining the reporting operation's exact preflight and error
    /// contract.
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        self.search_window_value(haystack, window, limits)
    }

    fn search_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
        operation: SearchOperation,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let upper_bounds = self.search_preflight(haystack.len(), window, limits)?;
        let (matched, actual) = self.execute_first_match(haystack, window, upper_bounds)?;
        Ok((
            matched,
            SearchAccounting {
                identity: self.search_operation_identity(operation),
                upper_bounds,
                actual,
            },
        ))
    }

    fn search_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let slice = haystack.get(window.start()..window.end()).ok_or(
            SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            },
        )?;
        self.search_value_preflight_validated(slice.len(), limits)?;
        if self.primary_finder.is_some() {
            return if self.general_primary_staged().is_some() {
                self.first_general_primary_value(slice, window.start())
            } else {
                self.first_adaptive_fallback_value(slice, window.start(), 0)
            };
        }
        match self.anchor {
            Anchor::One { offset, byte } => {
                self.first_anchor_value(slice, window.start(), usize::from(offset), |bytes| {
                    memchr(byte, bytes)
                })
            }
            Anchor::Two {
                offset,
                first,
                second,
            } => self.first_anchor_value(slice, window.start(), usize::from(offset), |bytes| {
                memchr2(first, second, bytes)
            }),
            Anchor::ShiftAnd => self.first_shift_and_value(slice, window.start()),
        }
    }

    #[inline]
    #[allow(
        clippy::too_many_lines,
        reason = "the compact general-primary phase keeps outcome-typed one-way handoffs adjacent"
    )]
    fn first_general_primary_value(
        &self,
        slice: &[u8],
        window_start: usize,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let (primary_offset, seeker) = self.general_primary_staged().ok_or(
            SearchError::InternalInvariant("general primary lost its staged finder"),
        )?;
        let general_primary_max_mean_skip = seeker.max_mean_skip();
        let fallback = self.adaptive_fallback.as_ref().ok_or(
            SearchError::InternalInvariant("general primary lost its paired predicate finder"),
        )?;
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return Err(SearchError::InternalInvariant(
                "general primary duplicated its paired predicate",
            ));
        }
        let anchor_end = slice
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(primary_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = primary_offset.min(anchor_end);
        let mut fallback_burst_start = 0_usize;
        let mut fallback_rejections = 0_usize;
        let mut residual_burst_start = 0_usize;
        let mut residual_rejections = 0_usize;
        while cursor < anchor_end {
            let search = slice.get(cursor..anchor_end).ok_or(
                SearchError::InternalInvariant("general primary search escaped the input"),
            )?;
            let Some(relative) = seeker.find(search) else {
                break;
            };
            let anchor = cursor.checked_add(relative).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "general primary anchor position",
                },
            )?;
            let start = anchor.checked_sub(primary_offset).ok_or(
                SearchError::InternalInvariant("general primary preceded its fixed offset"),
            )?;
            match self
                .general_primary_outcome_value(
                    slice,
                    start,
                    primary_offset,
                    fallback,
                    fallback_offset,
                )
                .ok_or(SearchError::InternalInvariant(
                    "general primary verification failed",
                ))?
            {
                GeneralPrimaryOutcome::Match => {
                    let end = start.checked_add(self.width).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary match end",
                        },
                    )?;
                    let absolute_start = window_start.checked_add(start).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary absolute start",
                        },
                    )?;
                    let absolute_end = window_start.checked_add(end).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary absolute end",
                        },
                    )?;
                    return Ok(Some((absolute_start, absolute_end)));
                }
                GeneralPrimaryOutcome::FallbackRejected => {
                    residual_rejections = 0;
                    if fallback_rejections == 0 {
                        fallback_burst_start = anchor;
                    }
                    fallback_rejections = fallback_rejections.checked_add(1).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary fallback rejection burst",
                        },
                    )?;
                }
                GeneralPrimaryOutcome::ResidualRejected => {
                    fallback_rejections = 0;
                    if residual_rejections == 0 {
                        residual_burst_start = anchor;
                    }
                    residual_rejections = residual_rejections.checked_add(1).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary residual rejection burst",
                        },
                    )?;
                }
            }
            cursor = anchor.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "general primary rejected restart",
            })?;
            let first_untested_start = cursor.checked_sub(primary_offset).ok_or(
                SearchError::InternalInvariant("general primary handoff preceded its cursor"),
            )?;
            if fallback_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    fallback_burst_start,
                    anchor,
                    fallback_rejections,
                    general_primary_max_mean_skip,
                )
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "general primary fallback rejection density",
                })? {
                    return self.first_adaptive_fallback_value(
                        slice,
                        window_start,
                        first_untested_start,
                    );
                }
                fallback_rejections = 0;
            }
            if residual_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    residual_burst_start,
                    anchor,
                    residual_rejections,
                    general_primary_max_mean_skip,
                )
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "general primary residual rejection density",
                })? {
                    let remaining = slice.get(first_untested_start..).ok_or(
                        SearchError::InternalInvariant("general primary Shift-And escaped input"),
                    )?;
                    let absolute = window_start.checked_add(first_untested_start).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary Shift-And absolute start",
                        },
                    )?;
                    return self.first_shift_and_value(remaining, absolute);
                }
                residual_rejections = 0;
            }
        }
        Ok(None)
    }

    #[inline]
    fn first_shift_and_value(
        &self,
        slice: &[u8],
        window_start: usize,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        if slice.len() < self.width {
            return Ok(None);
        }
        let mut state = 0_u64;
        for (position, &byte) in slice.iter().enumerate() {
            state = (state.wrapping_shl(1) | 1) & self.masks[usize::from(byte)];
            if state & self.accepting_bit != 0 {
                let relative_end =
                    position
                        .checked_add(1)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "actual Shift-And match end",
                        })?;
                let relative_start =
                    relative_end
                        .checked_sub(self.width)
                        .ok_or(SearchError::InternalInvariant(
                            "Shift-And accepted before the fixed word width",
                        ))?;
                let start = window_start.checked_add(relative_start).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute Shift-And match start",
                    },
                )?;
                let end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute Shift-And match end",
                    },
                )?;
                return Ok(Some((start, end)));
            }
        }
        Ok(None)
    }

    #[inline]
    fn first_anchor_value(
        &self,
        slice: &[u8],
        window_start: usize,
        anchor_offset: usize,
        mut find: impl FnMut(&[u8]) -> Option<usize>,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let anchor_end = slice
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(anchor_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = anchor_offset.min(anchor_end);
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while cursor < anchor_end {
            let search = slice
                .get(cursor..anchor_end)
                .ok_or(SearchError::InternalInvariant(
                    "anchor search window escaped the input",
                ))?;
            let Some(relative) = find(search) else {
                break;
            };
            let anchor = cursor
                .checked_add(relative)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "actual anchor search position",
                })?;
            let start = anchor
                .checked_sub(anchor_offset)
                .ok_or(SearchError::InternalInvariant(
                    "anchor preceded its fixed offset",
                ))?;
            let is_match = self
                .anchor_candidate_matches_value(slice, start, anchor_offset)
                .ok_or(SearchError::InternalInvariant(
                    "compact anchor verification arithmetic failed after preflight",
                ))?;
            if is_match {
                let relative_end =
                    start
                        .checked_add(self.width)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "actual anchor match end",
                        })?;
                let absolute_start =
                    window_start
                        .checked_add(start)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "absolute anchor match start",
                        })?;
                let absolute_end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute anchor match end",
                    },
                )?;
                return Ok(Some((absolute_start, absolute_end)));
            }
            cursor = anchor
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "rejected anchor search restart",
                })?;
            if burst_rejections == 0 {
                burst_start = anchor;
            }
            burst_rejections =
                burst_rejections
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "adaptive anchor rejection burst",
                    })?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && self.adaptive_fallback.is_some()
                && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive anchor rejection density",
                    },
                )?
            {
                let fallback_start =
                    cursor
                        .checked_sub(anchor_offset)
                        .ok_or(SearchError::InternalInvariant(
                            "adaptive fallback preceded the first untested start",
                        ))?;
                return self.first_adaptive_fallback_value(slice, window_start, fallback_start);
            }
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                burst_rejections = 0;
            }
        }
        Ok(None)
    }

    #[inline]
    #[allow(
        clippy::too_many_lines,
        reason = "the compact one-way fallback keeps candidate-stream and final Shift-And transition arithmetic in one auditable operation"
    )]
    fn first_adaptive_fallback_value(
        &self,
        slice: &[u8],
        window_start: usize,
        first_untested_start: usize,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        if !has_legal_start(slice.len(), self.width, first_untested_start) {
            return Ok(None);
        }
        let Some(fallback) = self.adaptive_fallback.as_ref() else {
            let remaining =
                slice
                    .get(first_untested_start..)
                    .ok_or(SearchError::InternalInvariant(
                        "adaptive Shift-And fallback escaped the input",
                    ))?;
            let absolute = window_start.checked_add(first_untested_start).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive Shift-And fallback absolute start",
                },
            )?;
            return self.first_shift_and_value(remaining, absolute);
        };
        let primary = self.primary_finder_descriptor().ok_or(
            SearchError::InternalInvariant("adaptive candidate stream lost its primary anchor"),
        )?;
        let primary_offset = usize::from(primary.offset().ok_or(
            SearchError::InternalInvariant("adaptive primary lost its fixed offset"),
        )?);
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return Err(SearchError::InternalInvariant(
                "adaptive candidate stream duplicated the primary anchor",
            ));
        }
        let legal_start_end = slice
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(1))
            .unwrap_or(0);
        let mut cursor = first_untested_start.min(legal_start_end);
        let mut finder = CandidateStreamCursor::new_with_fallback_skip(
            primary,
            fallback,
            self.general_fallback_skip(),
            slice,
            legal_start_end,
        );
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        let mut drain_end = None;
        while cursor < legal_start_end {
            if drain_end.is_some_and(|end| cursor >= end) {
                let remaining = slice.get(cursor..).ok_or(SearchError::InternalInvariant(
                    "adaptive drained Shift-And fallback escaped input",
                ))?;
                let absolute = window_start.checked_add(cursor).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive drained Shift-And absolute start",
                    },
                )?;
                return self.first_shift_and_value(remaining, absolute);
            }
            let found = match drain_end {
                Some(end) => finder.find_retained_before(cursor, end),
                None => finder.find(cursor),
            };
            let Some(start) = found else {
                if let Some(end) = drain_end {
                    let remaining = slice.get(end..).ok_or(SearchError::InternalInvariant(
                        "adaptive retained-block Shift-And fallback escaped input",
                    ))?;
                    let absolute = window_start.checked_add(end).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "adaptive retained-block Shift-And absolute start",
                        },
                    )?;
                    return self.first_shift_and_value(remaining, absolute);
                }
                break;
            };
            if self
                .candidate_matches_value_skipping_pair(
                    slice,
                    start,
                    primary_offset,
                    fallback_offset,
                )
                .ok_or(SearchError::InternalInvariant(
                    "adaptive candidate-stream verification failed",
                ))?
            {
                let relative_end =
                    start
                        .checked_add(self.width)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "adaptive byte-set fallback match end",
                        })?;
                let absolute_start =
                    window_start
                        .checked_add(start)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "adaptive byte-set fallback absolute start",
                        })?;
                let absolute_end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive byte-set fallback absolute end",
                    },
                )?;
                return Ok(Some((absolute_start, absolute_end)));
            }
            cursor = start
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "adaptive candidate-stream rejection restart",
                })?;
            if burst_rejections == 0 {
                burst_start = start;
            }
            burst_rejections =
                burst_rejections
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "adaptive candidate-stream rejection burst",
                    })?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && dense_rejection_burst(burst_start, start, burst_rejections).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive candidate-stream rejection density",
                    },
                )?
            {
                drain_end = Some(finder.retained_block().end.min(legal_start_end));
                burst_rejections = 0;
                continue;
            }
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                burst_rejections = 0;
            }
        }
        Ok(None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the source-free preflight keeps every checked search bound adjacent"
    )]
    fn search_preflight(
        &self,
        haystack_len: usize,
        window: Window,
        limits: SearchLimits,
    ) -> Result<SearchUpperBounds, SearchError> {
        let window_bytes = Self::validated_search_window_bytes(haystack_len, window)?;
        self.search_preflight_validated(window_bytes, limits)
    }

    fn search_value_preflight_validated(
        &self,
        window_bytes: usize,
        limits: SearchLimits,
    ) -> Result<(), SearchError> {
        if limits == SearchLimits::unlimited()
            && window_bytes <= SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES
        {
            return Ok(());
        }
        self.search_preflight_validated(window_bytes, limits)
            .map(drop)
    }

    fn validated_search_window_bytes(
        haystack_len: usize,
        window: Window,
    ) -> Result<usize, SearchError> {
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        window
            .end()
            .checked_sub(window.start())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "search window width",
            })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the source-free preflight keeps every checked search bound adjacent"
    )]
    fn search_preflight_validated(
        &self,
        window_bytes: usize,
        limits: SearchLimits,
    ) -> Result<SearchUpperBounds, SearchError> {
        let candidate_events = window_bytes
            .checked_sub(self.width)
            .and_then(|last| last.checked_add(1))
            .unwrap_or(0);
        let match_events = usize::from(candidate_events != 0);
        let scratch_bytes = 0;
        if scratch_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ScratchLimit {
                needed: scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        let (
            transitions,
            finder_scanned_bytes,
            shift_and_transitions,
            finder_calls,
            candidate_events,
            predicate_checks,
            work,
        ) = match (self.anchor, self.primary_finder.is_some()) {
            (Anchor::ShiftAnd, false) => {
                let work = window_bytes
                    .checked_mul(TRANSITION_WORK)
                    .and_then(|work| work.checked_add(match_events.checked_mul(MATCH_WORK)?))
                    .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "Shift-And search work upper bound",
                    })?;
                (window_bytes, 0, window_bytes, 0, 0, 0, work)
            }
            (Anchor::One { .. } | Anchor::Two { .. }, false)
            | (Anchor::ShiftAnd, true) => {
                let finder_calls = if candidate_events == 0 {
                    0
                } else {
                    candidate_events
                        .checked_add(1)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "anchor search finder-call upper bound",
                        })?
                };
                let verification_positions =
                    self.verification_positions()
                        .ok_or(SearchError::InternalInvariant(
                            "anchored search lost its verification-position count",
                        ))?;
                let predicate_checks = candidate_events.checked_mul(verification_positions).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "anchor search predicate-check upper bound",
                    },
                )?;
                let anchor_work = candidate_events
                    .checked_mul(FINDER_SCAN_BYTE_WORK)
                    .and_then(|work| work.checked_add(finder_calls.checked_mul(FINDER_CALL_WORK)?))
                    .and_then(|work| {
                        work.checked_add(candidate_events.checked_mul(ANCHOR_CANDIDATE_WORK)?)
                    })
                    .and_then(|work| {
                        work.checked_add(predicate_checks.checked_mul(PREDICATE_CHECK_WORK)?)
                    })
                    .and_then(|work| work.checked_add(match_events.checked_mul(MATCH_WORK)?))
                    .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "anchor search work upper bound",
                    })?;
                let work = if self.adaptive_fallback.is_some() {
                    let hybrid_work = hybrid_anchor_work_upper(
                        window_bytes,
                        candidate_events,
                        verification_positions,
                    )
                    .and_then(|work| work.checked_add(match_events.checked_mul(MATCH_WORK)?))
                    .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "adaptive search work upper bound",
                    })?;
                    anchor_work.max(hybrid_work)
                } else {
                    anchor_work
                };
                (
                    if self.adaptive_fallback.is_some() {
                        window_bytes
                    } else {
                        candidate_events
                    },
                    candidate_events,
                    if self.adaptive_fallback.is_some() {
                        window_bytes
                    } else {
                        0
                    },
                    finder_calls,
                    candidate_events,
                    predicate_checks,
                    work,
                )
            }
            (Anchor::One { .. } | Anchor::Two { .. }, true) => {
                return Err(SearchError::InternalInvariant(
                    "general primary coexisted with an exact anchor",
                ));
            }
        };
        let work = u64::try_from(work).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "search work upper-bound conversion",
        })?;
        if work > limits.max_work {
            return Err(SearchError::WorkLimit {
                needed: work,
                limit: limits.max_work,
            });
        }
        Ok(SearchUpperBounds {
            window_bytes,
            transitions,
            finder_scanned_bytes,
            shift_and_transitions,
            finder_calls,
            candidate_events,
            predicate_checks,
            match_events,
            work,
            scratch_bytes,
        })
    }

    fn execute_first_match(
        &self,
        haystack: &[u8],
        window: Window,
        upper: SearchUpperBounds,
    ) -> Result<(Option<(usize, usize)>, SearchActualCounters), SearchError> {
        let slice =
            haystack
                .get(window.start()..window.end())
                .ok_or(SearchError::InternalInvariant(
                    "admitted fixed-predicate window disappeared",
                ))?;
        if self.primary_finder.is_some() {
            return self.execute_first_general_finder(slice, window.start(), upper);
        }
        match self.anchor {
            Anchor::One { offset, byte } => self.execute_first_anchor(
                slice,
                window.start(),
                upper,
                usize::from(offset),
                |bytes| memchr(byte, bytes),
            ),
            Anchor::Two {
                offset,
                first,
                second,
            } => self.execute_first_anchor(
                slice,
                window.start(),
                upper,
                usize::from(offset),
                |bytes| memchr2(first, second, bytes),
            ),
            Anchor::ShiftAnd => self.execute_first_shift_and(slice, window.start(), upper),
        }
    }

    fn execute_first_match_with_cursor(
        &self,
        haystack: &[u8],
        window: Window,
        upper: SearchUpperBounds,
        cursor: &mut FixedPredicateWord64SearchCursor<'_, '_>,
    ) -> Result<(Option<(usize, usize)>, SearchActualCounters), SearchError> {
        let mut actual = AnchorActual::default();
        if self.primary_finder.is_some()
            && self.general_primary_staged().is_none()
            && matches!(cursor.phase, RetainedSearchPhase::Primary)
        {
            cursor.phase = RetainedSearchPhase::CandidateStream;
            cursor.block = CandidateStreamBlock::default();
        } else if self.is_raw_shift_and() {
            cursor.phase = RetainedSearchPhase::ShiftAnd;
        }
        let matched = match cursor.phase {
            RetainedSearchPhase::Primary if self.general_primary_staged().is_some() => self
                .execute_retained_general_primary(haystack, window, cursor, &mut actual)?,
            RetainedSearchPhase::Primary => {
                self.execute_retained_primary(haystack, window, cursor, &mut actual)?
            }
            RetainedSearchPhase::CandidateStream | RetainedSearchPhase::CandidateStreamDrain => {
                self.execute_retained_candidate_stream(haystack, window, cursor, &mut actual)?
            }
            RetainedSearchPhase::ShiftAnd => {
                self.execute_retained_shift_and(haystack, window, cursor, &mut actual)?
            }
            RetainedSearchPhase::Exhausted => None,
        };
        let transitions = actual
            .finder_scanned_bytes
            .checked_add(actual.shift_and_transitions)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained fixed-predicate search transitions",
            })?;
        let search_actual = SearchActualCounters {
            window_bytes: upper.window_bytes,
            transitions,
            finder_scanned_bytes: actual.finder_scanned_bytes,
            shift_and_transitions: actual.shift_and_transitions,
            finder_calls: actual.finder_calls,
            candidate_events: actual.anchor_candidates,
            predicate_checks: actual.predicate_checks,
            match_events: actual.match_events,
            work: search_work(
                actual.finder_scanned_bytes,
                actual.shift_and_transitions,
                actual.finder_calls,
                actual.anchor_candidates,
                actual.predicate_checks,
                actual.match_events,
            )?,
            scratch_bytes: 0,
        };
        ensure_search_actual_within(search_actual, upper)?;
        Ok((matched, search_actual))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the retained general-primary phase keeps outcome-typed handoffs and cursor mutation adjacent"
    )]
    fn execute_retained_general_primary(
        &self,
        haystack: &[u8],
        window: Window,
        retained: &mut FixedPredicateWord64SearchCursor<'_, '_>,
        actual: &mut AnchorActual,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let (primary_offset, seeker) = self.general_primary_staged().ok_or(
            SearchError::InternalInvariant("retained general primary lost its staged finder"),
        )?;
        let general_primary_max_mean_skip = seeker.max_mean_skip();
        let fallback = self.adaptive_fallback.as_ref().ok_or(
            SearchError::InternalInvariant(
                "retained general primary lost its paired predicate finder",
            ),
        )?;
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return Err(SearchError::InternalInvariant(
                "retained general primary duplicated its paired predicate",
            ));
        }
        let legal_start_end = window
            .end()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(1))
            .unwrap_or(window.start());
        let anchor_end = legal_start_end.checked_add(primary_offset).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "retained general primary anchor end",
            },
        )?;
        let mut scan = window
            .start()
            .checked_add(primary_offset)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained general primary cursor",
            })?
            .min(anchor_end);
        let mut fallback_burst_start = 0_usize;
        let mut fallback_rejections = 0_usize;
        let mut residual_burst_start = 0_usize;
        let mut residual_rejections = 0_usize;
        while scan < anchor_end {
            let search = haystack.get(scan..anchor_end).ok_or(
                SearchError::InternalInvariant("retained general primary escaped the source"),
            )?;
            actual.finder_calls = actual.finder_calls.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "retained general primary finder calls",
                },
            )?;
            let Some(relative) = seeker.find(search) else {
                actual.finder_scanned_bytes = actual
                    .finder_scanned_bytes
                    .checked_add(search.len())
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained general primary terminal service",
                    })?;
                retained.exhaust();
                return Ok(None);
            };
            let service = relative.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "retained general primary service",
            })?;
            actual.finder_scanned_bytes = actual.finder_scanned_bytes.checked_add(service).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "retained general primary service bytes",
                },
            )?;
            let anchor = scan.checked_add(relative).ok_or(SearchError::ArithmeticOverflow {
                computation: "retained general primary anchor",
            })?;
            let start = anchor.checked_sub(primary_offset).ok_or(
                SearchError::InternalInvariant("retained general primary preceded its offset"),
            )?;
            actual.anchor_candidates = actual.anchor_candidates.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "retained general primary candidates",
                },
            )?;
            match self
                .general_primary_outcome(
                    haystack,
                    start,
                    primary_offset,
                    fallback,
                    fallback_offset,
                    &mut actual.predicate_checks,
                )
                .map_err(|error| search_error_from_reduce(&error))?
            {
                GeneralPrimaryOutcome::Match => {
                    let end = start.checked_add(self.width).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "retained general primary match end",
                        },
                    )?;
                    actual.match_events = actual.match_events.checked_add(1).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "retained general primary match events",
                        },
                    )?;
                    retained.phase = RetainedSearchPhase::Primary;
                    retained.retain_match(end);
                    return Ok(Some((start, end)));
                }
                GeneralPrimaryOutcome::FallbackRejected => {
                    residual_rejections = 0;
                    if fallback_rejections == 0 {
                        fallback_burst_start = anchor;
                    }
                    fallback_rejections = fallback_rejections.checked_add(1).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "retained general primary fallback rejection burst",
                        },
                    )?;
                }
                GeneralPrimaryOutcome::ResidualRejected => {
                    fallback_rejections = 0;
                    if residual_rejections == 0 {
                        residual_burst_start = anchor;
                    }
                    residual_rejections = residual_rejections.checked_add(1).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "retained general primary residual rejection burst",
                        },
                    )?;
                }
            }
            scan = anchor.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "retained general primary rejected restart",
            })?;
            let first_untested_start = scan.checked_sub(primary_offset).ok_or(
                SearchError::InternalInvariant("retained general primary handoff preceded cursor"),
            )?;
            if fallback_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    fallback_burst_start,
                    anchor,
                    fallback_rejections,
                    general_primary_max_mean_skip,
                )
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained general primary fallback rejection density",
                })? {
                    retained.phase = RetainedSearchPhase::CandidateStream;
                    retained.block = CandidateStreamBlock::default();
                    return self.execute_retained_candidate_stream_from(
                        haystack,
                        window,
                        first_untested_start,
                        retained,
                        actual,
                    );
                }
                fallback_rejections = 0;
            }
            if residual_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    residual_burst_start,
                    anchor,
                    residual_rejections,
                    general_primary_max_mean_skip,
                )
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained general primary residual rejection density",
                })? {
                    retained.phase = RetainedSearchPhase::ShiftAnd;
                    retained.block = CandidateStreamBlock::default();
                    return self.execute_retained_shift_and_from(
                        haystack,
                        window,
                        first_untested_start,
                        retained,
                        actual,
                    );
                }
                residual_rejections = 0;
            }
        }
        retained.exhaust();
        Ok(None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the retained primary phase keeps cursor mutation adjacent to every terminal, match, and monotone handoff edge"
    )]
    fn execute_retained_primary(
        &self,
        haystack: &[u8],
        window: Window,
        retained: &mut FixedPredicateWord64SearchCursor<'_, '_>,
        actual: &mut AnchorActual,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let anchor_offset = usize::from(self.anchor.offset().ok_or(
            SearchError::InternalInvariant("retained primary selected Shift-And"),
        )?);
        let legal_start_end = window
            .end()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(1))
            .unwrap_or(window.start());
        let anchor_end =
            legal_start_end
                .checked_add(anchor_offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained primary anchor end",
                })?;
        let mut scan = window
            .start()
            .checked_add(anchor_offset)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained primary cursor",
            })?
            .min(anchor_end);
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while scan < anchor_end {
            let search = haystack
                .get(scan..anchor_end)
                .ok_or(SearchError::InternalInvariant(
                    "retained primary search escaped the source",
                ))?;
            actual.finder_calls =
                actual
                    .finder_calls
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained primary finder calls",
                    })?;
            let relative = match self.anchor {
                Anchor::One { byte, .. } => memchr(byte, search),
                Anchor::Two { first, second, .. } => memchr2(first, second, search),
                Anchor::ShiftAnd => {
                    return Err(SearchError::InternalInvariant(
                        "retained primary changed to Shift-And",
                    ));
                }
            };
            let Some(relative) = relative else {
                actual.finder_scanned_bytes = actual
                    .finder_scanned_bytes
                    .checked_add(search.len())
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained primary terminal service",
                    })?;
                retained.exhaust();
                return Ok(None);
            };
            let service = relative
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained primary successful service",
                })?;
            actual.finder_scanned_bytes = actual.finder_scanned_bytes.checked_add(service).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "retained primary service bytes",
                },
            )?;
            let anchor = scan
                .checked_add(relative)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained primary anchor",
                })?;
            let start = anchor
                .checked_sub(anchor_offset)
                .ok_or(SearchError::InternalInvariant(
                    "retained primary preceded its offset",
                ))?;
            actual.anchor_candidates =
                actual
                    .anchor_candidates
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained primary candidates",
                    })?;
            if self
                .anchor_candidate_matches(
                    haystack,
                    start,
                    anchor_offset,
                    &mut actual.predicate_checks,
                )
                .map_err(|error| search_error_from_reduce(&error))?
            {
                let end = start
                    .checked_add(self.width)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained primary match end",
                    })?;
                actual.match_events =
                    actual
                        .match_events
                        .checked_add(1)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "retained primary match events",
                        })?;
                retained.phase = RetainedSearchPhase::Primary;
                retained.retain_match(end);
                return Ok(Some((start, end)));
            }
            scan = anchor
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained primary rejection restart",
                })?;
            if burst_rejections == 0 {
                burst_start = anchor;
            }
            burst_rejections =
                burst_rejections
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained primary rejection burst",
                    })?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && self.adaptive_fallback.is_some()
                && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "retained primary rejection density",
                    },
                )?
            {
                let first_untested_start =
                    scan.checked_sub(anchor_offset)
                        .ok_or(SearchError::InternalInvariant(
                            "retained candidate stream preceded the first untested start",
                        ))?;
                retained.phase = RetainedSearchPhase::CandidateStream;
                retained.block = CandidateStreamBlock::default();
                return self.execute_retained_candidate_stream_from(
                    haystack,
                    window,
                    first_untested_start,
                    retained,
                    actual,
                );
            }
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                burst_rejections = 0;
            }
        }
        retained.exhaust();
        Ok(None)
    }

    fn execute_retained_candidate_stream(
        &self,
        haystack: &[u8],
        window: Window,
        retained: &mut FixedPredicateWord64SearchCursor<'_, '_>,
        actual: &mut AnchorActual,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        self.execute_retained_candidate_stream_from(
            haystack,
            window,
            window.start(),
            retained,
            actual,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the retained two-mask phase keeps physical accounting and every cursor transition in one auditable state-machine arm"
    )]
    fn execute_retained_candidate_stream_from(
        &self,
        haystack: &[u8],
        window: Window,
        first_untested_start: usize,
        retained: &mut FixedPredicateWord64SearchCursor<'_, '_>,
        actual: &mut AnchorActual,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let Some(fallback) = self.adaptive_fallback.as_ref() else {
            return Err(SearchError::InternalInvariant(
                "retained candidate phase lost its fallback",
            ));
        };
        let primary = self.primary_finder_descriptor().ok_or(
            SearchError::InternalInvariant("retained candidate phase lost its primary"),
        )?;
        let primary_offset = usize::from(primary.offset().ok_or(
            SearchError::InternalInvariant("retained primary lost its fixed offset"),
        )?);
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return Err(SearchError::InternalInvariant(
                "retained candidate phase duplicated the primary",
            ));
        }
        let legal_start_end = window
            .end()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(1))
            .unwrap_or(window.start());
        let mut scan = first_untested_start.min(legal_start_end);
        let mut finder = CandidateStreamCursor::with_block_and_fallback_skip(
            primary,
            fallback,
            self.general_fallback_skip(),
            haystack,
            legal_start_end,
            retained.block,
        );
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while scan < legal_start_end {
            let drain_end = if matches!(retained.phase, RetainedSearchPhase::CandidateStreamDrain) {
                let end = retained.block.end.min(legal_start_end);
                if scan >= end {
                    retained.phase = RetainedSearchPhase::ShiftAnd;
                    retained.block = CandidateStreamBlock::default();
                    return self
                        .execute_retained_shift_and_from(haystack, window, scan, retained, actual);
                }
                Some(end)
            } else {
                None
            };
            actual.finder_calls =
                actual
                    .finder_calls
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained candidate-stream finder calls",
                    })?;
            let service_start = scan;
            let primary_before = finder.primary_classified_bytes();
            let fallback_before = finder.fallback_classified_bytes();
            let found = match drain_end {
                Some(end) => finder.find_retained_before(scan, end),
                None => finder.find(scan),
            };
            let newly_primary = finder
                .primary_classified_bytes()
                .checked_sub(primary_before)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained candidate-stream primary classification",
                })?;
            let newly_fallback = finder
                .fallback_classified_bytes()
                .checked_sub(fallback_before)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained candidate-stream fallback classification",
                })?;
            actual.finder_scanned_bytes = actual
                .finder_scanned_bytes
                .checked_add(newly_fallback)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained fallback-classifier service",
                })?;
            actual.predicate_checks = actual
                .predicate_checks
                .checked_add(newly_primary)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained primary-classifier checks",
                })?;
            retained.block = finder.retained_block();
            let Some(start) = found else {
                if let Some(end) = drain_end {
                    retained.phase = RetainedSearchPhase::ShiftAnd;
                    retained.block = CandidateStreamBlock::default();
                    return self
                        .execute_retained_shift_and_from(haystack, window, end, retained, actual);
                }
                retained.exhaust();
                return Ok(None);
            };
            if start < service_start {
                return Err(SearchError::InternalInvariant(
                    "retained candidate-stream service reversed",
                ));
            }
            actual.anchor_candidates =
                actual
                    .anchor_candidates
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained candidate-stream candidates",
                    })?;
            if self
                .candidate_matches_skipping_pair(
                    haystack,
                    start,
                    primary_offset,
                    fallback_offset,
                    &mut actual.predicate_checks,
                )
                .map_err(|error| search_error_from_reduce(&error))?
            {
                let end = start
                    .checked_add(self.width)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained candidate-stream match end",
                    })?;
                actual.match_events =
                    actual
                        .match_events
                        .checked_add(1)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "retained candidate-stream match events",
                        })?;
                retained.retain_match(end);
                return Ok(Some((start, end)));
            }
            scan = start
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained candidate-stream rejection restart",
                })?;
            if burst_rejections == 0 {
                burst_start = start;
            }
            burst_rejections =
                burst_rejections
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained candidate-stream rejection burst",
                    })?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && dense_rejection_burst(burst_start, start, burst_rejections).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "retained candidate-stream rejection density",
                    },
                )?
            {
                retained.phase = RetainedSearchPhase::CandidateStreamDrain;
                burst_rejections = 0;
                continue;
            }
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                burst_rejections = 0;
            }
        }
        retained.exhaust();
        Ok(None)
    }

    fn execute_retained_shift_and(
        &self,
        haystack: &[u8],
        window: Window,
        retained: &mut FixedPredicateWord64SearchCursor<'_, '_>,
        actual: &mut AnchorActual,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        self.execute_retained_shift_and_from(haystack, window, window.start(), retained, actual)
    }

    fn execute_retained_shift_and_from(
        &self,
        haystack: &[u8],
        window: Window,
        first_untested_start: usize,
        retained: &mut FixedPredicateWord64SearchCursor<'_, '_>,
        actual: &mut AnchorActual,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let remaining = haystack.get(first_untested_start..window.end()).ok_or(
            SearchError::InternalInvariant("retained Shift-And escaped the window"),
        )?;
        if remaining.len() < self.width {
            retained.exhaust();
            return Ok(None);
        }
        let mut state = 0_u64;
        for (position, &byte) in remaining.iter().enumerate() {
            actual.shift_and_transitions = actual.shift_and_transitions.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "retained Shift-And transitions",
                },
            )?;
            state = (state.wrapping_shl(1) | 1) & self.masks[usize::from(byte)];
            if state & self.accepting_bit == 0 {
                continue;
            }
            let end = first_untested_start
                .checked_add(position)
                .and_then(|position| position.checked_add(1))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained Shift-And match end",
                })?;
            let start = end
                .checked_sub(self.width)
                .ok_or(SearchError::InternalInvariant(
                    "retained Shift-And accepted before its width",
                ))?;
            actual.match_events =
                actual
                    .match_events
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "retained Shift-And match events",
                    })?;
            retained.phase = RetainedSearchPhase::ShiftAnd;
            retained.retain_match(end);
            return Ok(Some((start, end)));
        }
        retained.exhaust();
        Ok(None)
    }

    fn execute_first_shift_and(
        &self,
        slice: &[u8],
        window_start: usize,
        upper: SearchUpperBounds,
    ) -> Result<(Option<(usize, usize)>, SearchActualCounters), SearchError> {
        let mut state = 0_u64;
        let mut transitions = 0_usize;
        let mut matched = None;
        for (position, &byte) in slice.iter().enumerate() {
            transitions = transitions
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "actual Shift-And search transitions",
                })?;
            state = (state.wrapping_shl(1) | 1) & self.masks[usize::from(byte)];
            if state & self.accepting_bit != 0 {
                let relative_end =
                    position
                        .checked_add(1)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "actual Shift-And match end",
                        })?;
                let relative_start =
                    relative_end
                        .checked_sub(self.width)
                        .ok_or(SearchError::InternalInvariant(
                            "Shift-And accepted before the fixed word width",
                        ))?;
                let start = window_start.checked_add(relative_start).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute Shift-And match start",
                    },
                )?;
                let end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute Shift-And match end",
                    },
                )?;
                matched = Some((start, end));
                break;
            }
        }
        let actual = SearchActualCounters {
            window_bytes: slice.len(),
            transitions,
            finder_scanned_bytes: 0,
            shift_and_transitions: transitions,
            finder_calls: 0,
            candidate_events: 0,
            predicate_checks: 0,
            match_events: usize::from(matched.is_some()),
            work: search_work(0, transitions, 0, 0, 0, usize::from(matched.is_some()))?,
            scratch_bytes: 0,
        };
        ensure_search_actual_within(actual, upper)?;
        Ok((matched, actual))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the reporting general-primary phase keeps its exact ledger beside every handoff"
    )]
    fn execute_first_general_finder(
        &self,
        slice: &[u8],
        window_start: usize,
        upper: SearchUpperBounds,
    ) -> Result<(Option<(usize, usize)>, SearchActualCounters), SearchError> {
        let Some((primary_offset, seeker)) = self.general_primary_staged() else {
            return self.execute_first_direct_general_finder(slice, window_start, upper);
        };
        let general_primary_max_mean_skip = seeker.max_mean_skip();
        let fallback = self.adaptive_fallback.as_ref().ok_or(
            SearchError::InternalInvariant("general primary lost its paired predicate finder"),
        )?;
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return Err(SearchError::InternalInvariant(
                "general primary duplicated its paired predicate",
            ));
        }
        let mut finder_scanned_bytes = 0_usize;
        let mut shift_and_transitions = 0_usize;
        let mut finder_calls = 0_usize;
        let mut candidate_events = 0_usize;
        let mut predicate_checks = 0_usize;
        let anchor_end = slice
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(primary_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = primary_offset.min(anchor_end);
        let mut fallback_burst_start = 0_usize;
        let mut fallback_rejections = 0_usize;
        let mut residual_burst_start = 0_usize;
        let mut residual_rejections = 0_usize;
        let mut matched = None;
        while cursor < anchor_end {
            let search = slice.get(cursor..anchor_end).ok_or(
                SearchError::InternalInvariant("general primary search escaped the input"),
            )?;
            finder_calls = finder_calls.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "general primary finder calls",
                },
            )?;
            let Some(relative) = seeker.find(search) else {
                finder_scanned_bytes = finder_scanned_bytes.checked_add(search.len()).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "general primary terminal finder service",
                    },
                )?;
                break;
            };
            let service = relative.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "general primary finder service",
            })?;
            finder_scanned_bytes = finder_scanned_bytes.checked_add(service).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "general primary finder service bytes",
                },
            )?;
            let anchor = cursor.checked_add(relative).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "general primary anchor position",
                },
            )?;
            let start = anchor.checked_sub(primary_offset).ok_or(
                SearchError::InternalInvariant("general primary preceded its fixed offset"),
            )?;
            candidate_events = candidate_events.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "general primary candidate events",
                },
            )?;
            match self
                .general_primary_outcome(
                    slice,
                    start,
                    primary_offset,
                    fallback,
                    fallback_offset,
                    &mut predicate_checks,
                )
                .map_err(|error| search_error_from_reduce(&error))?
            {
                GeneralPrimaryOutcome::Match => {
                    let end = start.checked_add(self.width).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary match end",
                        },
                    )?;
                    matched = Some((
                        window_start.checked_add(start).ok_or(
                            SearchError::ArithmeticOverflow {
                                computation: "general primary absolute start",
                            },
                        )?,
                        window_start.checked_add(end).ok_or(
                            SearchError::ArithmeticOverflow {
                                computation: "general primary absolute end",
                            },
                        )?,
                    ));
                    break;
                }
                GeneralPrimaryOutcome::FallbackRejected => {
                    residual_rejections = 0;
                    if fallback_rejections == 0 {
                        fallback_burst_start = anchor;
                    }
                    fallback_rejections = fallback_rejections.checked_add(1).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary fallback rejection burst",
                        },
                    )?;
                }
                GeneralPrimaryOutcome::ResidualRejected => {
                    fallback_rejections = 0;
                    if residual_rejections == 0 {
                        residual_burst_start = anchor;
                    }
                    residual_rejections = residual_rejections.checked_add(1).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "general primary residual rejection burst",
                        },
                    )?;
                }
            }
            cursor = anchor.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "general primary rejected restart",
            })?;
            let first_untested_start = cursor.checked_sub(primary_offset).ok_or(
                SearchError::InternalInvariant("general primary handoff preceded its cursor"),
            )?;
            if fallback_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    fallback_burst_start,
                    anchor,
                    fallback_rejections,
                    general_primary_max_mean_skip,
                )
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "general primary fallback rejection density",
                })? {
                    matched = self.execute_first_adaptive_reporting(
                        slice,
                        window_start,
                        first_untested_start,
                        &mut finder_scanned_bytes,
                        &mut shift_and_transitions,
                        &mut finder_calls,
                        &mut candidate_events,
                        &mut predicate_checks,
                    )?;
                    break;
                }
                fallback_rejections = 0;
            }
            if residual_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    residual_burst_start,
                    anchor,
                    residual_rejections,
                    general_primary_max_mean_skip,
                )
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "general primary residual rejection density",
                })? {
                    matched = self.execute_first_shift_and_reporting(
                        slice,
                        window_start,
                        first_untested_start,
                        &mut shift_and_transitions,
                    )?;
                    break;
                }
                residual_rejections = 0;
            }
        }
        let match_events = usize::from(matched.is_some());
        let transitions = finder_scanned_bytes
            .checked_add(shift_and_transitions)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "general predicate search transitions",
            })?;
        let actual = SearchActualCounters {
            window_bytes: slice.len(),
            transitions,
            finder_scanned_bytes,
            shift_and_transitions,
            finder_calls,
            candidate_events,
            predicate_checks,
            match_events,
            work: search_work(
                finder_scanned_bytes,
                shift_and_transitions,
                finder_calls,
                candidate_events,
                predicate_checks,
                match_events,
            )?,
            scratch_bytes: 0,
        };
        ensure_search_actual_within(actual, upper)?;
        Ok((matched, actual))
    }

    fn execute_first_direct_general_finder(
        &self,
        slice: &[u8],
        window_start: usize,
        upper: SearchUpperBounds,
    ) -> Result<(Option<(usize, usize)>, SearchActualCounters), SearchError> {
        if self.primary_finder.is_none() || self.adaptive_fallback.is_none() {
            return Err(SearchError::InternalInvariant(
                "general primary lost its paired predicate finder",
            ));
        }
        let mut finder_scanned_bytes = 0_usize;
        let mut shift_and_transitions = 0_usize;
        let mut finder_calls = 0_usize;
        let mut candidate_events = 0_usize;
        let mut predicate_checks = 0_usize;
        let matched = self.execute_first_adaptive_reporting(
            slice,
            window_start,
            0,
            &mut finder_scanned_bytes,
            &mut shift_and_transitions,
            &mut finder_calls,
            &mut candidate_events,
            &mut predicate_checks,
        )?;
        let match_events = usize::from(matched.is_some());
        let transitions = finder_scanned_bytes
            .checked_add(shift_and_transitions)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "direct general-predicate search transitions",
            })?;
        let actual = SearchActualCounters {
            window_bytes: slice.len(),
            transitions,
            finder_scanned_bytes,
            shift_and_transitions,
            finder_calls,
            candidate_events,
            predicate_checks,
            match_events,
            work: search_work(
                finder_scanned_bytes,
                shift_and_transitions,
                finder_calls,
                candidate_events,
                predicate_checks,
                match_events,
            )?,
            scratch_bytes: 0,
        };
        ensure_search_actual_within(actual, upper)?;
        Ok((matched, actual))
    }

    fn execute_first_anchor(
        &self,
        slice: &[u8],
        window_start: usize,
        upper: SearchUpperBounds,
        anchor_offset: usize,
        mut find: impl FnMut(&[u8]) -> Option<usize>,
    ) -> Result<(Option<(usize, usize)>, SearchActualCounters), SearchError> {
        let anchor_end = slice
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(anchor_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = anchor_offset.min(anchor_end);
        let mut finder_scanned_bytes = 0_usize;
        let mut shift_and_transitions = 0_usize;
        let mut finder_calls = 0_usize;
        let mut candidate_events = 0_usize;
        let mut predicate_checks = 0_usize;
        let mut matched = None;
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while cursor < anchor_end {
            let search = slice
                .get(cursor..anchor_end)
                .ok_or(SearchError::InternalInvariant(
                    "anchor search window escaped the input",
                ))?;
            finder_calls = finder_calls
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "actual anchor search finder calls",
                })?;
            let Some(relative) = find(search) else {
                finder_scanned_bytes = finder_scanned_bytes.checked_add(search.len()).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "actual unsuccessful anchor search service bytes",
                    },
                )?;
                break;
            };
            finder_scanned_bytes =
                finder_scanned_bytes
                    .checked_add(relative.checked_add(1).ok_or(
                        SearchError::ArithmeticOverflow {
                            computation: "actual successful anchor search service",
                        },
                    )?)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "actual anchor search service bytes",
                    })?;
            let anchor = cursor
                .checked_add(relative)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "actual anchor search position",
                })?;
            let start = anchor
                .checked_sub(anchor_offset)
                .ok_or(SearchError::InternalInvariant(
                    "anchor preceded its fixed offset",
                ))?;
            candidate_events =
                candidate_events
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "actual anchor search candidates",
                    })?;
            let is_match = self
                .anchor_candidate_matches(slice, start, anchor_offset, &mut predicate_checks)
                .map_err(|error| search_error_from_reduce(&error))?;
            if is_match {
                let relative_end =
                    start
                        .checked_add(self.width)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "actual anchor match end",
                        })?;
                let absolute_start =
                    window_start
                        .checked_add(start)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "absolute anchor match start",
                        })?;
                let absolute_end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute anchor match end",
                    },
                )?;
                matched = Some((absolute_start, absolute_end));
                break;
            }
            cursor = anchor
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "rejected anchor search restart",
                })?;
            if burst_rejections == 0 {
                burst_start = anchor;
            }
            burst_rejections =
                burst_rejections
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting rejection burst",
                    })?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && self.adaptive_fallback.is_some()
                && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting rejection density",
                    },
                )?
            {
                let first_untested_start =
                    cursor
                        .checked_sub(anchor_offset)
                        .ok_or(SearchError::InternalInvariant(
                            "adaptive reporting fallback preceded the first untested start",
                        ))?;
                matched = self.execute_first_adaptive_reporting(
                    slice,
                    window_start,
                    first_untested_start,
                    &mut finder_scanned_bytes,
                    &mut shift_and_transitions,
                    &mut finder_calls,
                    &mut candidate_events,
                    &mut predicate_checks,
                )?;
                break;
            }
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                burst_rejections = 0;
            }
        }
        let match_events = usize::from(matched.is_some());
        let transitions = finder_scanned_bytes
            .checked_add(shift_and_transitions)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "adaptive reporting transitions",
            })?;
        let actual = SearchActualCounters {
            window_bytes: slice.len(),
            transitions,
            finder_scanned_bytes,
            shift_and_transitions,
            finder_calls,
            candidate_events,
            predicate_checks,
            match_events,
            work: search_work(
                finder_scanned_bytes,
                shift_and_transitions,
                finder_calls,
                candidate_events,
                predicate_checks,
                match_events,
            )?,
            scratch_bytes: 0,
        };
        ensure_search_actual_within(actual, upper)?;
        Ok((matched, actual))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the adaptive path updates one closed first-search ledger in place"
    )]
    fn execute_first_adaptive_reporting(
        &self,
        slice: &[u8],
        window_start: usize,
        first_untested_start: usize,
        finder_scanned_bytes: &mut usize,
        shift_and_transitions: &mut usize,
        finder_calls: &mut usize,
        candidate_events: &mut usize,
        predicate_checks: &mut usize,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        if !has_legal_start(slice.len(), self.width, first_untested_start) {
            return Ok(None);
        }
        let Some(fallback) = self.adaptive_fallback.as_ref() else {
            return self.execute_first_shift_and_reporting(
                slice,
                window_start,
                first_untested_start,
                shift_and_transitions,
            );
        };
        let primary = self
            .primary_finder_descriptor()
            .ok_or(SearchError::InternalInvariant(
                "adaptive reporting candidate stream lost its primary anchor",
            ))?;
        let primary_offset = usize::from(primary.offset().ok_or(
            SearchError::InternalInvariant("adaptive reporting primary lost its fixed offset"),
        )?);
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return Err(SearchError::InternalInvariant(
                "adaptive reporting candidate stream duplicated the primary anchor",
            ));
        }
        let legal_start_end = slice
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(1))
            .unwrap_or(0);
        let mut cursor = first_untested_start.min(legal_start_end);
        let mut finder = CandidateStreamCursor::new_with_fallback_skip(
            primary,
            fallback,
            self.general_fallback_skip(),
            slice,
            legal_start_end,
        );
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        let mut drain_end = None;
        while cursor < legal_start_end {
            if drain_end.is_some_and(|end| cursor >= end) {
                return self.execute_first_shift_and_reporting(
                    slice,
                    window_start,
                    cursor,
                    shift_and_transitions,
                );
            }
            *finder_calls = finder_calls
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting candidate-stream finder calls",
                })?;
            let service_start = cursor;
            let primary_before = finder.primary_classified_bytes();
            let fallback_before = finder.fallback_classified_bytes();
            let found = match drain_end {
                Some(end) => finder.find_retained_before(cursor, end),
                None => finder.find(cursor),
            };
            let newly_primary = finder
                .primary_classified_bytes()
                .checked_sub(primary_before)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting primary classification",
                })?;
            let newly_fallback = finder
                .fallback_classified_bytes()
                .checked_sub(fallback_before)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting fallback classification",
                })?;
            *finder_scanned_bytes = finder_scanned_bytes.checked_add(newly_fallback).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting fallback-classifier service",
                },
            )?;
            *predicate_checks = predicate_checks.checked_add(newly_primary).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting primary-classifier checks",
                },
            )?;
            let Some(start) = found else {
                if let Some(end) = drain_end {
                    return self.execute_first_shift_and_reporting(
                        slice,
                        window_start,
                        end,
                        shift_and_transitions,
                    );
                }
                break;
            };
            if start < service_start {
                return Err(SearchError::InternalInvariant(
                    "adaptive reporting candidate-stream service reversed",
                ));
            }
            *candidate_events =
                candidate_events
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting candidate-stream candidates",
                    })?;
            if self
                .candidate_matches_skipping_pair(
                    slice,
                    start,
                    primary_offset,
                    fallback_offset,
                    predicate_checks,
                )
                .map_err(|error| search_error_from_reduce(&error))?
            {
                let relative_end =
                    start
                        .checked_add(self.width)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "adaptive reporting byte-set match end",
                        })?;
                let absolute_start =
                    window_start
                        .checked_add(start)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "adaptive reporting byte-set absolute start",
                        })?;
                let absolute_end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting byte-set absolute end",
                    },
                )?;
                return Ok(Some((absolute_start, absolute_end)));
            }
            cursor = start
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting candidate-stream restart",
                })?;
            if burst_rejections == 0 {
                burst_start = start;
            }
            burst_rejections =
                burst_rejections
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting candidate-stream rejection burst",
                    })?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && dense_rejection_burst(burst_start, start, burst_rejections).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting candidate-stream rejection density",
                    },
                )?
            {
                drain_end = Some(finder.retained_block().end.min(legal_start_end));
                burst_rejections = 0;
                continue;
            }
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                burst_rejections = 0;
            }
        }
        Ok(None)
    }

    fn execute_first_shift_and_reporting(
        &self,
        slice: &[u8],
        window_start: usize,
        first_untested_start: usize,
        shift_and_transitions: &mut usize,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let remaining = slice
            .get(first_untested_start..)
            .ok_or(SearchError::InternalInvariant(
                "adaptive reporting Shift-And escaped input",
            ))?;
        if remaining.len() < self.width {
            return Ok(None);
        }
        let mut state = 0_u64;
        for (position, &byte) in remaining.iter().enumerate() {
            *shift_and_transitions =
                shift_and_transitions
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting Shift-And transitions",
                    })?;
            state = (state.wrapping_shl(1) | 1) & self.masks[usize::from(byte)];
            if state & self.accepting_bit == 0 {
                continue;
            }
            let relative_end = first_untested_start
                .checked_add(position)
                .and_then(|end| end.checked_add(1))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting Shift-And match end",
                })?;
            let relative_start =
                relative_end
                    .checked_sub(self.width)
                    .ok_or(SearchError::InternalInvariant(
                        "adaptive reporting Shift-And accepted before the fixed width",
                    ))?;
            let absolute_start = window_start.checked_add(relative_start).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting Shift-And absolute start",
                },
            )?;
            let absolute_end =
                window_start
                    .checked_add(relative_end)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting Shift-And absolute end",
                    })?;
            return Ok(Some((absolute_start, absolute_end)));
        }
        Ok(None)
    }

    /// Stable identity for one operation.
    #[must_use]
    pub const fn operation_identity(&self, operation: Operation) -> OperationIdentity {
        let operation_id = match operation {
            Operation::Count => COUNT_OPERATION_ID,
            Operation::SpanSum => SPAN_SUM_OPERATION_ID,
            Operation::SpanVisit => SPAN_VISIT_OPERATION_ID,
        };
        let (reducer, anchor_offset, anchor_bytes) = self.reducer_identity();
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id,
            operation,
            semantics: MatchSemantics::FixedBytePredicates,
            selection: MatchSelection::LeftmostFirstNonOverlapping,
            width: self.width,
            reducer,
            anchor_offset,
            anchor_bytes,
            primary_finder: self.primary_finder_identity(),
            general_primary_scan: self.general_primary_scan_identity(),
            general_fallback_scan: self.general_fallback_scan_identity(),
            secondary_anchor: self.secondary_anchor_identity(),
            verification_predicates: self.verification_predicate_identity_count(),
            adaptive_handoff: self.adaptive_handoff_identity(),
        }
    }

    /// Count successive leftmost non-overlapping matches.
    ///
    /// # Errors
    ///
    /// Returns a typed prospective resource or arithmetic failure.
    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), Operation::Count, limits)?;
        let actual = self.execute(haystack, upper_bounds)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.operation_identity(Operation::Count),
                upper_bounds,
                actual,
            },
        })
    }

    /// Return only a successfully admitted count without materializing exact
    /// execution accounting.
    ///
    /// `None` deliberately carries no terminal error. A caller that publishes
    /// errors must replay [`Self::count`] with the same arguments so failures
    /// retain the complete typed resource identity.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn count_value_success(&self, haystack: &[u8], limits: ReduceLimits) -> Option<u64> {
        if self.width == 1 {
            return self.width_one_value_success(haystack, Operation::Count, limits);
        }
        let upper_bounds = self
            .preflight(haystack.len(), Operation::Count, limits)
            .ok()?;
        self.execute_value(haystack, upper_bounds)
            .map(|value| value.count)
    }

    /// Admit a width-one Shift-And count once from the immutable input length
    /// and resource limits, without reading source bytes.
    ///
    /// `Ok(None)` means this plan has another width or anchor strategy. A typed
    /// refusal is exactly the refusal that [`Self::count`] would publish before
    /// source access for the same input length and limits.
    pub fn prepare_width_one_shift_and_count(
        &self,
        input_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<Option<WidthOneShiftAndCountAdmission>, ReduceError> {
        if self.width != 1 || !matches!(self.anchor, Anchor::ShiftAnd { .. }) {
            return Ok(None);
        }
        self.preflight(input_bytes, Operation::Count, limits)?;
        Ok(Some(WidthOneShiftAndCountAdmission {
            input_bytes,
            persistent_bytes: self.build.persistent_bytes,
        }))
    }

    /// Execute a previously admitted width-one count through the compact
    /// byte-membership leaf.
    ///
    /// `None` means the token does not authenticate this immutable plan and
    /// source length, or checked count arithmetic failed. Callers that expose a
    /// typed error replay [`Self::count`] with the original limits.
    #[must_use]
    #[inline]
    pub fn count_width_one_shift_and_prepared(
        &self,
        haystack: &[u8],
        admission: WidthOneShiftAndCountAdmission,
    ) -> Option<u64> {
        if self.width != 1
            || !matches!(self.anchor, Anchor::ShiftAnd { .. })
            || admission.input_bytes != haystack.len()
            || admission.persistent_bytes != self.build.persistent_bytes
        {
            return None;
        }
        self.width_one_count_value(haystack)
    }

    /// Sum the widths of successive leftmost non-overlapping matches.
    ///
    /// # Errors
    ///
    /// Returns a typed prospective resource or arithmetic failure.
    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let upper_bounds = self.preflight(haystack.len(), Operation::SpanSum, limits)?;
        let actual = self.execute(haystack, upper_bounds)?;
        Ok(SpanSumResult {
            span_sum: actual.matched_bytes,
            accounting: ReduceAccounting {
                identity: self.operation_identity(Operation::SpanSum),
                upper_bounds,
                actual,
            },
        })
    }

    /// Visit every complete successive leftmost non-overlapping match without
    /// allocating operation storage. All prospective limits are checked
    /// before source access or the first callback.
    ///
    /// # Errors
    ///
    /// Returns a typed prospective resource or arithmetic failure.
    pub fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        mut visitor: F,
    ) -> Result<SpanVisitResult, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let upper_bounds = self.preflight(haystack.len(), Operation::SpanVisit, limits)?;
        let actual = self.execute_with_visitor(haystack, upper_bounds, &mut visitor)?;
        Ok(SpanVisitResult {
            matches: actual.match_events,
            span_sum: actual.matched_bytes,
            accounting: ReduceAccounting {
                identity: self.operation_identity(Operation::SpanVisit),
                upper_bounds,
                actual,
            },
        })
    }

    /// Return only a successfully admitted span sum without materializing
    /// exact execution accounting.
    ///
    /// `None` deliberately carries no terminal error. A caller that publishes
    /// errors must replay [`Self::span_sum`] with the same arguments so
    /// failures retain the complete typed resource identity.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn span_sum_value_success(&self, haystack: &[u8], limits: ReduceLimits) -> Option<u64> {
        if self.width == 1 {
            return self.width_one_value_success(haystack, Operation::SpanSum, limits);
        }
        let upper_bounds = self
            .preflight(haystack.len(), Operation::SpanSum, limits)
            .ok()?;
        self.execute_value(haystack, upper_bounds)
            .map(|value| value.matched_bytes)
    }

    /// Admit the exact width-one envelope without materializing the much
    /// larger generic upper-bound record, then count direct byte-predicate
    /// membership. Diagnostic calls retain the receipt-bearing reducer; this
    /// projection is used only after every one of the same prospective limits
    /// has succeeded.
    #[inline]
    fn width_one_value_success(
        &self,
        haystack: &[u8],
        operation: Operation,
        limits: ReduceLimits,
    ) -> Option<u64> {
        let input_bytes = haystack.len();
        if input_bytes > limits.max_input_bytes
            || input_bytes > limits.max_transitions
            || input_bytes > limits.max_match_events
        {
            return None;
        }
        let semantic_upper = u64::try_from(input_bytes).ok()?;
        if semantic_upper > limits.max_count
            || (operation == Operation::SpanSum && semantic_upper > limits.max_span_sum)
        {
            return None;
        }
        let reducer_steps = input_bytes.checked_add(REDUCE_FINAL_WORK)?;
        if reducer_steps > limits.max_reducer_steps {
            return None;
        }
        let work = match self.anchor {
            Anchor::One { .. } | Anchor::Two { .. } if input_bytes == 0 => REDUCE_FINAL_WORK,
            Anchor::One { .. } | Anchor::Two { .. } => input_bytes
                .checked_mul(6)?
                .checked_add(FINDER_CALL_WORK + REDUCE_FINAL_WORK)?,
            Anchor::ShiftAnd => input_bytes
                .checked_mul(TRANSITION_WORK + MATCH_WORK)?
                .checked_add(REDUCE_FINAL_WORK)?,
        };
        if u64::try_from(work).ok()? > limits.max_work
            || self.build.persistent_bytes > limits.max_persistent_bytes
            || self.build.persistent_bytes > limits.max_peak_bytes
        {
            return None;
        }

        self.width_one_count_value(haystack)
    }

    #[inline]
    fn width_one_count_value(&self, haystack: &[u8]) -> Option<u64> {
        match self.anchor {
            Anchor::One { byte, .. } => {
                self.scan_anchor_value(haystack, 0, |bytes| memchr(byte, bytes))
            }
            Anchor::Two { first, second, .. } => {
                self.scan_anchor_value(haystack, 0, |bytes| memchr2(first, second, bytes))
            }
            Anchor::ShiftAnd => {
                let mut count = 0_u64;
                for &byte in haystack {
                    if self.masks[usize::from(byte)] & 1 != 0 {
                        count = count.checked_add(1)?;
                    }
                }
                Some(count)
            }
        }
    }

    fn preflight(
        &self,
        input_bytes: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        enforce_reduce_usize(input_bytes, limits.max_input_bytes, ReduceResource::Input)?;
        let reducer = self.reducer_upper(input_bytes)?;
        enforce_reduce_usize(
            reducer.transitions,
            limits.max_transitions,
            ReduceResource::Transitions,
        )?;
        let semantic = self.semantic_upper(input_bytes, operation, limits)?;
        let reducer_steps = reducer.transitions.checked_add(REDUCE_FINAL_WORK).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "reducer step bound",
            },
        )?;
        enforce_reduce_usize(
            reducer_steps,
            limits.max_reducer_steps,
            ReduceResource::ReducerSteps,
        )?;
        let work_usize = reducer
            .work
            .checked_add(semantic.match_events.checked_mul(MATCH_WORK).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "match-event work bound",
                },
            )?)
            .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "reducer work upper bound",
            })?;
        let work = u64::try_from(work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "reducer work upper bound conversion",
        })?;
        if work > limits.max_work {
            return Err(ReduceError::WorkLimit {
                needed: work,
                limit: limits.max_work,
            });
        }
        let scratch_bytes = 0;
        if scratch_bytes > limits.max_scratch_bytes {
            return Err(ReduceError::ScratchLimit {
                needed: scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        let persistent_bytes = self.build.persistent_bytes;
        enforce_reduce_usize(
            persistent_bytes,
            limits.max_persistent_bytes,
            ReduceResource::Persistent,
        )?;
        let peak_bytes = persistent_bytes;
        enforce_reduce_usize(peak_bytes, limits.max_peak_bytes, ReduceResource::Peak)?;
        Ok(ReduceUpperBounds {
            input_bytes,
            transitions: reducer.transitions,
            finder_scanned_bytes: reducer.finder_scanned_bytes,
            shift_and_transitions: reducer.shift_and_transitions,
            finder_calls: reducer.finder_calls,
            anchor_candidates: reducer.anchor_candidates,
            predicate_checks: reducer.predicate_checks,
            match_events: semantic.match_events,
            count: semantic.count,
            span_sum: semantic.span_sum,
            reducer_steps,
            work,
            allocations: 0,
            reserves: 0,
            temporary_copies: 0,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the source-free bound keeps anchor, classified-finder service, and Shift-And component maxima adjacent"
    )]
    fn reducer_upper(&self, input_bytes: usize) -> Result<ReducerUpper, ReduceError> {
        match (self.anchor, self.primary_finder.is_some()) {
            (Anchor::One { .. } | Anchor::Two { .. }, false)
            | (Anchor::ShiftAnd, true) => {
                let candidate_positions = match input_bytes.checked_sub(self.width) {
                    Some(last_start) => {
                        last_start
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "anchor candidate-position bound",
                            })?
                    }
                    None => 0,
                };
                let finder_calls = if candidate_positions == 0 {
                    0
                } else {
                    candidate_positions
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "anchor finder-call bound",
                        })?
                };
                let predicate_checks = candidate_positions
                    .checked_mul(self.verification_positions().ok_or(
                        ReduceError::InternalInvariant(
                            "anchored reducer lost its verification-position count",
                        ),
                    )?)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "anchor predicate-check bound",
                    })?;
                let anchor_work = candidate_positions
                    .checked_mul(FINDER_SCAN_BYTE_WORK)
                    .and_then(|value| {
                        value.checked_add(finder_calls.checked_mul(FINDER_CALL_WORK)?)
                    })
                    .and_then(|value| {
                        value.checked_add(candidate_positions.checked_mul(ANCHOR_CANDIDATE_WORK)?)
                    })
                    .and_then(|value| {
                        value.checked_add(predicate_checks.checked_mul(PREDICATE_CHECK_WORK)?)
                    })
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "anchor reducer work bound",
                    })?;
                let verification_positions =
                    self.verification_positions()
                        .ok_or(ReduceError::InternalInvariant(
                            "anchored reducer lost its verification-position count",
                        ))?;
                let work = if self.adaptive_fallback.is_some() {
                    let hybrid_work = hybrid_anchor_work_upper(
                        input_bytes,
                        candidate_positions,
                        verification_positions,
                    )
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer work bound",
                    })?;
                    anchor_work.max(hybrid_work)
                } else {
                    anchor_work
                };
                Ok(ReducerUpper {
                    transitions: if self.adaptive_fallback.is_some() {
                        input_bytes
                    } else {
                        candidate_positions
                    },
                    finder_scanned_bytes: candidate_positions,
                    shift_and_transitions: if self.adaptive_fallback.is_some() {
                        input_bytes
                    } else {
                        0
                    },
                    finder_calls,
                    anchor_candidates: candidate_positions,
                    predicate_checks,
                    work,
                })
            }
            (Anchor::ShiftAnd, false) => Ok(ReducerUpper {
                transitions: input_bytes,
                finder_scanned_bytes: 0,
                shift_and_transitions: input_bytes,
                finder_calls: 0,
                anchor_candidates: 0,
                predicate_checks: 0,
                work: input_bytes.checked_mul(TRANSITION_WORK).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "Shift-And reducer work bound",
                    },
                )?,
            }),
            (Anchor::One { .. } | Anchor::Two { .. }, true) => {
                Err(ReduceError::InternalInvariant(
                    "general primary coexisted with an exact anchor",
                ))
            }
        }
    }

    fn semantic_upper(
        &self,
        input_bytes: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<SemanticUpper, ReduceError> {
        let match_events =
            input_bytes
                .checked_div(self.width)
                .ok_or(ReduceError::InternalInvariant(
                    "validated word width became zero",
                ))?;
        enforce_reduce_usize(
            match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        )?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match bound as count",
        })?;
        if count > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: count,
                limit: limits.max_count,
            });
        }
        let width = u64::try_from(self.width).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "word width as u64",
        })?;
        let span_sum = count
            .checked_mul(width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "span-sum upper bound",
            })?;
        if matches!(operation, Operation::SpanSum | Operation::SpanVisit)
            && span_sum > limits.max_span_sum
        {
            return Err(ReduceError::SpanSumLimit {
                needed: span_sum,
                limit: limits.max_span_sum,
            });
        }
        Ok(SemanticUpper {
            match_events,
            count,
            span_sum,
        })
    }

    fn execute(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        self.execute_with_visitor(haystack, upper_bounds, &mut |_| {})
    }

    fn execute_with_visitor<F>(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        if self.primary_finder.is_some() {
            let mut actual = AnchorActual::default();
            if self.general_primary_staged().is_some() {
                self.scan_general_primary_reporting(haystack, &mut actual, visitor)?;
            } else {
                self.scan_adaptive_reporting(haystack, 0, &mut actual, visitor)?;
            }
            return self.finish_anchor_actual(haystack.len(), upper_bounds, actual);
        }
        match self.anchor {
            Anchor::One { offset, byte } => {
                self.execute_anchor(
                    haystack,
                    upper_bounds,
                    usize::from(offset),
                    |bytes| memchr(byte, bytes),
                    visitor,
                )
            }
            Anchor::Two {
                offset,
                first,
                second,
            } => self.execute_anchor(
                haystack,
                upper_bounds,
                usize::from(offset),
                |bytes| memchr2(first, second, bytes),
                visitor,
            ),
            Anchor::ShiftAnd => self.execute_shift_and(haystack, upper_bounds, visitor),
        }
    }

    #[inline]
    fn execute_value(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
    ) -> Option<ValueReduction> {
        let count = if let Some(literal) = self.amortized_exact_literal_run(haystack.len()) {
            self.scan_exact_literal_run_value(haystack, &literal)?
        } else if self.primary_finder.is_some() {
            if self.general_primary_staged().is_some() {
                self.scan_general_primary_value(haystack)?
            } else {
                self.scan_adaptive_fallback_value(haystack, 0)?
            }
        } else {
            match self.anchor {
                Anchor::One { offset, byte } => self.scan_anchor_value(
                    haystack,
                    usize::from(offset),
                    |bytes| memchr(byte, bytes),
                )?,
                Anchor::Two {
                    offset,
                    first,
                    second,
                } => self.scan_anchor_value(haystack, usize::from(offset), |bytes| {
                    memchr2(first, second, bytes)
                })?,
                Anchor::ShiftAnd => self.scan_shift_and_value(haystack)?,
            }
        };
        let width = u64::try_from(self.width).ok()?;
        let matched_bytes = count.checked_mul(width)?;
        let match_events = usize::try_from(count).ok()?;
        (upper_bounds.input_bytes == haystack.len()
            && match_events <= upper_bounds.match_events
            && count <= upper_bounds.count
            && matched_bytes <= upper_bounds.span_sum)
            .then_some(ValueReduction {
                count,
                matched_bytes,
            })
    }

    #[inline]
    fn amortized_exact_literal_run(&self, input_bytes: usize) -> Option<ExactLiteralRun> {
        let has_singleton_anchor = matches!(self.anchor, Anchor::One { .. })
            || matches!(self.secondary_anchor, Some(Anchor::One { .. }));
        if self.width < COUNT_VALUE_LITERAL_RUN_MIN_BYTES || !has_singleton_anchor {
            return None;
        }
        let census = self.width.checked_mul(MASK_SLOTS)?;
        if census.checked_mul(COUNT_VALUE_LITERAL_RUN_AMORTIZATION)? > input_bytes {
            return None;
        }

        let mut best = ExactLiteralRun {
            bytes: [0; MAX_WIDTH],
            offset: 0,
            len: 0,
            position_mask: 0,
        };
        let mut current = ExactLiteralRun {
            bytes: [0; MAX_WIDTH],
            offset: 0,
            len: 0,
            position_mask: 0,
        };
        for position in 0..self.width {
            let shift = u32::try_from(position).ok()?;
            let bit = 1_u64.checked_shl(shift)?;
            let mut member = None;
            for byte in 0_u16..=u16::from(u8::MAX) {
                let byte = u8::try_from(byte).ok()?;
                if self.masks[usize::from(byte)] & bit == 0 {
                    continue;
                }
                if member.replace(byte).is_some() {
                    member = None;
                    break;
                }
            }
            let Some(byte) = member else {
                current.len = 0;
                current.position_mask = 0;
                continue;
            };
            if current.len == 0 {
                current.offset = position;
            }
            *current.bytes.get_mut(current.len)? = byte;
            current.len = current.len.checked_add(1)?;
            current.position_mask |= bit;
            if current.len > best.len {
                best = current;
            }
        }
        (best.len >= COUNT_VALUE_LITERAL_RUN_MIN_BYTES).then_some(best)
    }

    #[inline]
    fn scan_exact_literal_run_value(
        &self,
        haystack: &[u8],
        literal: &ExactLiteralRun,
    ) -> Option<u64> {
        if literal.len < COUNT_VALUE_LITERAL_RUN_MIN_BYTES
            || literal.offset.checked_add(literal.len)? > self.width
        {
            return None;
        }
        let last_start = haystack.len().checked_sub(self.width)?;
        let search_end = last_start
            .checked_add(literal.offset)?
            .checked_add(literal.len)?;
        let needle = literal.bytes.get(..literal.len)?;
        let finder = Finder::new(needle);
        let mut cursor = literal.offset;
        let mut count = 0_u64;
        while cursor < search_end {
            let Some(relative) = finder.find(haystack.get(cursor..search_end)?) else {
                break;
            };
            let anchor = cursor.checked_add(relative)?;
            let start = anchor.checked_sub(literal.offset)?;
            if self.candidate_matches_value_skipping_mask(haystack, start, literal.position_mask)? {
                count = count.checked_add(1)?;
                cursor = anchor.checked_add(self.width)?;
            } else {
                cursor = anchor.checked_add(1)?;
            }
        }
        Some(count)
    }

    #[inline]
    fn candidate_matches_value_skipping_mask(
        &self,
        haystack: &[u8],
        start: usize,
        skipped: u64,
    ) -> Option<bool> {
        let end = start.checked_add(self.width)?;
        let candidate = haystack.get(start..end)?;
        let mut remaining = self.nonuniversal_mask & !skipped;
        while remaining != 0 {
            let bit = remaining & remaining.wrapping_neg();
            let position = usize::try_from(remaining.trailing_zeros()).ok()?;
            remaining &= remaining - 1;
            let byte = *candidate.get(position)?;
            if self.masks[usize::from(byte)] & bit == 0 {
                return Some(false);
            }
        }
        Some(true)
    }

    #[inline]
    fn scan_shift_and_value(&self, haystack: &[u8]) -> Option<u64> {
        if haystack.len() < self.width {
            return Some(0);
        }
        let mut state = 0_u64;
        let mut count = 0_u64;
        for &byte in haystack {
            state = (state.wrapping_shl(1) | 1) & self.masks[usize::from(byte)];
            if state & self.accepting_bit != 0 {
                count = count.checked_add(1)?;
                state = 0;
            }
        }
        Some(count)
    }

    #[inline]
    fn scan_general_primary_value(&self, haystack: &[u8]) -> Option<u64> {
        let (primary_offset, seeker) = self.general_primary_staged()?;
        let general_primary_max_mean_skip = seeker.max_mean_skip();
        let fallback = self.adaptive_fallback.as_ref()?;
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return None;
        }
        let anchor_end = haystack
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(primary_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = primary_offset.min(anchor_end);
        let mut count = 0_u64;
        let mut fallback_burst_start = 0_usize;
        let mut fallback_rejections = 0_usize;
        let mut residual_burst_start = 0_usize;
        let mut residual_rejections = 0_usize;
        while cursor < anchor_end {
            let search = haystack.get(cursor..anchor_end)?;
            let Some(relative) = seeker.find(search) else {
                break;
            };
            let anchor = cursor.checked_add(relative)?;
            let start = anchor.checked_sub(primary_offset)?;
            match self.general_primary_outcome_value(
                haystack,
                start,
                primary_offset,
                fallback,
                fallback_offset,
            )? {
                GeneralPrimaryOutcome::Match => {
                    count = count.checked_add(1)?;
                    cursor = anchor.checked_add(self.width)?;
                    fallback_rejections = 0;
                    residual_rejections = 0;
                    continue;
                }
                GeneralPrimaryOutcome::FallbackRejected => {
                    residual_rejections = 0;
                    if fallback_rejections == 0 {
                        fallback_burst_start = anchor;
                    }
                    fallback_rejections = fallback_rejections.checked_add(1)?;
                }
                GeneralPrimaryOutcome::ResidualRejected => {
                    fallback_rejections = 0;
                    if residual_rejections == 0 {
                        residual_burst_start = anchor;
                    }
                    residual_rejections = residual_rejections.checked_add(1)?;
                }
            }
            cursor = anchor.checked_add(1)?;
            let first_untested_start = cursor.checked_sub(primary_offset)?;
            if fallback_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    fallback_burst_start,
                    anchor,
                    fallback_rejections,
                    general_primary_max_mean_skip,
                )? {
                    return count.checked_add(
                        self.scan_adaptive_fallback_value(haystack, first_untested_start)?,
                    );
                }
                fallback_rejections = 0;
            }
            if residual_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    residual_burst_start,
                    anchor,
                    residual_rejections,
                    general_primary_max_mean_skip,
                )? {
                    return count.checked_add(
                        self.scan_shift_and_value(haystack.get(first_untested_start..)?)?,
                    );
                }
                residual_rejections = 0;
            }
        }
        Some(count)
    }

    #[inline]
    fn scan_anchor_value(
        &self,
        haystack: &[u8],
        anchor_offset: usize,
        mut find: impl FnMut(&[u8]) -> Option<usize>,
    ) -> Option<u64> {
        let anchor_end = haystack
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(anchor_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = anchor_offset.min(anchor_end);
        let mut count = 0_u64;
        while cursor < anchor_end {
            let search = haystack.get(cursor..anchor_end)?;
            let Some(relative) = find(search) else {
                break;
            };
            let anchor = cursor.checked_add(relative)?;
            let start = anchor.checked_sub(anchor_offset)?;
            if self.anchor_candidate_matches_value(haystack, start, anchor_offset)? {
                count = count.checked_add(1)?;
                cursor = anchor.checked_add(self.width)?;
            } else {
                cursor = anchor.checked_add(1)?;
                if self.adaptive_fallback.is_some() {
                    return self.scan_anchor_value_after_rejection_sample(
                        haystack,
                        anchor_offset,
                        anchor_end,
                        cursor,
                        count,
                        anchor,
                        find,
                    );
                }
            }
        }
        Some(count)
    }

    #[inline]
    fn scan_anchor_value_after_rejection_sample(
        &self,
        haystack: &[u8],
        anchor_offset: usize,
        anchor_end: usize,
        mut cursor: usize,
        mut count: u64,
        sample_start: usize,
        mut find: impl FnMut(&[u8]) -> Option<usize>,
    ) -> Option<u64> {
        let mut sampled_rejections = 1_usize;
        while cursor < anchor_end {
            let search = haystack.get(cursor..anchor_end)?;
            let Some(relative) = find(search) else {
                break;
            };
            let anchor = cursor.checked_add(relative)?;
            let start = anchor.checked_sub(anchor_offset)?;
            if self.anchor_candidate_matches_value(haystack, start, anchor_offset)? {
                count = count.checked_add(1)?;
                cursor = anchor.checked_add(self.width)?;
            } else {
                cursor = anchor.checked_add(1)?;
                sampled_rejections = sampled_rejections.checked_add(1)?;
                // Sampling every 64th rejection bounds bookkeeping on sparse
                // streams while delaying a newly-profitable handoff by at most
                // one small candidate block.
                if sampled_rejections.is_multiple_of(COUNT_VALUE_ADAPTIVE_SAMPLE_REJECTIONS)
                    && dense_count_value_rejection_sample(
                        sample_start,
                        anchor,
                        sampled_rejections,
                    )?
                {
                    let fallback_start = cursor.checked_sub(anchor_offset)?;
                    return count
                        .checked_add(self.scan_adaptive_fallback_value(haystack, fallback_start)?);
                }
            }
        }
        Some(count)
    }

    #[inline]
    fn scan_adaptive_fallback_value(
        &self,
        haystack: &[u8],
        first_untested_start: usize,
    ) -> Option<u64> {
        if !has_legal_start(haystack.len(), self.width, first_untested_start) {
            return Some(0);
        }
        let Some(fallback) = self.adaptive_fallback.as_ref() else {
            return self.scan_shift_and_value(haystack.get(first_untested_start..)?);
        };
        let primary = self.primary_finder_descriptor()?;
        let primary_offset = usize::from(primary.offset()?);
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return None;
        }
        let legal_start_end = haystack
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(1))
            .unwrap_or(0);
        let mut cursor = first_untested_start.min(legal_start_end);
        let mut finder = CandidateStreamCursor::new_with_fallback_skip(
            primary,
            fallback,
            self.general_fallback_skip(),
            haystack,
            legal_start_end,
        );
        let mut count = 0_u64;
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        let mut drain_end = None;
        while cursor < legal_start_end {
            if drain_end.is_some_and(|end| cursor >= end) {
                return count.checked_add(self.scan_shift_and_value(haystack.get(cursor..)?)?);
            }
            let found = match drain_end {
                Some(end) => finder.find_retained_before(cursor, end),
                None => finder.find(cursor),
            };
            let Some(start) = found else {
                if let Some(end) = drain_end {
                    return count.checked_add(self.scan_shift_and_value(haystack.get(end..)?)?);
                }
                break;
            };
            if self.candidate_matches_value_skipping_pair(
                haystack,
                start,
                primary_offset,
                fallback_offset,
            )? {
                count = count.checked_add(1)?;
                cursor = start.checked_add(self.width)?;
                burst_rejections = 0;
            } else {
                cursor = start.checked_add(1)?;
                if burst_rejections == 0 {
                    burst_start = start;
                }
                burst_rejections = burst_rejections.checked_add(1)?;
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                    && dense_rejection_burst(burst_start, start, burst_rejections)?
                {
                    drain_end = Some(finder.retained_block().end.min(legal_start_end));
                    burst_rejections = 0;
                    continue;
                }
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                    burst_rejections = 0;
                }
            }
        }
        Some(count)
    }

    #[inline]
    fn candidate_matches_value_skipping_pair(
        &self,
        haystack: &[u8],
        start: usize,
        primary_offset: usize,
        fallback_offset: usize,
    ) -> Option<bool> {
        let end = start.checked_add(self.width)?;
        let candidate = haystack.get(start..end)?;
        if usize::from(self.primary_offset()?) != primary_offset
            || primary_offset == fallback_offset
        {
            return None;
        }
        let primary_shift = u32::try_from(primary_offset).ok()?;
        let fallback_shift = u32::try_from(fallback_offset).ok()?;
        let primary_bit = 1_u64.checked_shl(primary_shift)?;
        let fallback_bit = 1_u64.checked_shl(fallback_shift)?;
        if self.nonuniversal_mask & primary_bit == 0 || self.nonuniversal_mask & fallback_bit == 0 {
            return None;
        }
        let mut remaining = self.nonuniversal_mask & !primary_bit & !fallback_bit;
        if let Some(secondary) = self.secondary_anchor {
            let secondary_offset = usize::from(secondary.offset()?);
            if secondary_offset != primary_offset && secondary_offset != fallback_offset {
                if !secondary.matches(*candidate.get(secondary_offset)?)? {
                    return Some(false);
                }
                let secondary_shift = u32::try_from(secondary_offset).ok()?;
                remaining &= !1_u64.checked_shl(secondary_shift)?;
            }
        }
        while remaining != 0 {
            let bit = remaining & remaining.wrapping_neg();
            let position = usize::try_from(remaining.trailing_zeros()).ok()?;
            remaining &= remaining - 1;
            let byte = *candidate.get(position)?;
            if self.masks[usize::from(byte)] & bit == 0 {
                return Some(false);
            }
        }
        Some(true)
    }

    #[inline]
    fn general_primary_outcome_value(
        &self,
        haystack: &[u8],
        start: usize,
        primary_offset: usize,
        fallback: &AdaptiveFallback,
        fallback_offset: usize,
    ) -> Option<GeneralPrimaryOutcome> {
        let fallback_byte = *haystack.get(start.checked_add(fallback_offset)?)?;
        if !fallback.matches(fallback_byte) {
            return Some(GeneralPrimaryOutcome::FallbackRejected);
        }
        if self.candidate_matches_value_skipping_pair(
            haystack,
            start,
            primary_offset,
            fallback_offset,
        )? {
            Some(GeneralPrimaryOutcome::Match)
        } else {
            Some(GeneralPrimaryOutcome::ResidualRejected)
        }
    }

    #[inline]
    fn anchor_candidate_matches_value(
        &self,
        haystack: &[u8],
        start: usize,
        anchor_offset: usize,
    ) -> Option<bool> {
        let end = start.checked_add(self.width)?;
        let candidate = haystack.get(start..end)?;
        let secondary = self.secondary_anchor;
        let secondary_offset = secondary.and_then(Anchor::offset).map(usize::from);
        if let Some(anchor) = secondary {
            let position = secondary_offset?;
            if position == anchor_offset {
                return None;
            }
            if !anchor.matches(*candidate.get(position)?)? {
                return Some(false);
            }
        }
        let anchor_shift = u32::try_from(anchor_offset).ok()?;
        let mut remaining = self.nonuniversal_mask & !1_u64.checked_shl(anchor_shift)?;
        if let Some(position) = secondary_offset {
            let shift = u32::try_from(position).ok()?;
            remaining &= !1_u64.checked_shl(shift)?;
        }
        if let Some(fallback) = self.adaptive_fallback.as_ref() {
            let position = usize::from(fallback.offset);
            if position != anchor_offset && Some(position) != secondary_offset {
                let shift = u32::try_from(position).ok()?;
                let bit = 1_u64.checked_shl(shift)?;
                if remaining & bit == 0 {
                    return None;
                }
                if self.masks[usize::from(*candidate.get(position)?)] & bit == 0 {
                    return Some(false);
                }
                remaining &= !bit;
            }
        }
        while remaining != 0 {
            let bit = remaining & remaining.wrapping_neg();
            let position = usize::try_from(remaining.trailing_zeros()).ok()?;
            remaining &= remaining - 1;
            let byte = *candidate.get(position)?;
            if self.masks[usize::from(byte)] & bit == 0 {
                return Some(false);
            }
        }
        Some(true)
    }

    fn execute_shift_and<F>(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let mut state = 0_u64;
        let mut match_events = 0_usize;
        for (position, &byte) in haystack.iter().enumerate() {
            let mask = self.masks[usize::from(byte)];
            state = (state.wrapping_shl(1) | 1) & mask;
            if state & self.accepting_bit != 0 {
                match_events =
                    match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual match event count",
                        })?;
                let end = position
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual Shift-And match end",
                    })?;
                let start = end.checked_sub(self.width).ok_or(
                    ReduceError::InternalInvariant(
                        "Shift-And accepted before the fixed word width",
                    ),
                )?;
                visitor(CompleteSpan { start, end });
                state = 0;
            }
        }
        let transitions = haystack.len();
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual count conversion",
        })?;
        let width = u64::try_from(self.width).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual word width conversion",
        })?;
        let matched_bytes = count
            .checked_mul(width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual matched bytes",
            })?;
        let reducer_steps =
            transitions
                .checked_add(REDUCE_FINAL_WORK)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual reducer steps",
                })?;
        let work_usize = transitions
            .checked_mul(TRANSITION_WORK)
            .and_then(|work| work.checked_add(match_events.checked_mul(MATCH_WORK)?))
            .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual reducer work",
            })?;
        let work_charged =
            u64::try_from(work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual reducer work conversion",
            })?;
        let actual = ReduceActualCounters {
            input_bytes: haystack.len(),
            transitions,
            finder_scanned_bytes: 0,
            shift_and_transitions: transitions,
            finder_calls: 0,
            anchor_candidates: 0,
            predicate_checks: 0,
            match_events,
            count,
            matched_bytes,
            reducer_steps,
            work_charged,
            allocations: 0,
            reserves: 0,
            temporary_copies: 0,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        };
        if !actual_within_upper(actual, upper_bounds) {
            return Err(ReduceError::InternalInvariant(
                "actual counters exceeded prospective upper bounds",
            ));
        }
        Ok(actual)
    }

    fn execute_anchor<F, V>(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
        anchor_offset: usize,
        find: F,
        visitor: &mut V,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(&[u8]) -> Option<usize>,
        V: FnMut(CompleteSpan),
    {
        let actual = self.scan_anchor(haystack, anchor_offset, find, visitor)?;
        self.finish_anchor_actual(haystack.len(), upper_bounds, actual)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the general primary reducer keeps outcome-typed one-way handoffs in one closed ledger"
    )]
    fn scan_general_primary_reporting<F>(
        &self,
        haystack: &[u8],
        actual: &mut AnchorActual,
        visitor: &mut F,
    ) -> Result<(), ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let (primary_offset, seeker) = self.general_primary_staged().ok_or(
            ReduceError::InternalInvariant("general reducer lost its staged primary"),
        )?;
        let general_primary_max_mean_skip = seeker.max_mean_skip();
        let fallback = self.adaptive_fallback.as_ref().ok_or(
            ReduceError::InternalInvariant("general reducer lost its paired predicate finder"),
        )?;
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return Err(ReduceError::InternalInvariant(
                "general reducer duplicated its paired predicate",
            ));
        }
        let anchor_end = haystack
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(primary_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = primary_offset.min(anchor_end);
        let mut fallback_burst_start = 0_usize;
        let mut fallback_rejections = 0_usize;
        let mut residual_burst_start = 0_usize;
        let mut residual_rejections = 0_usize;
        while cursor < anchor_end {
            let search = haystack
                .get(cursor..anchor_end)
                .ok_or(ReduceError::InternalInvariant(
                    "general reducer primary escaped the input",
                ))?;
            actual.finder_calls = actual.finder_calls.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "general reducer primary finder calls",
                },
            )?;
            let Some(relative) = seeker.find(search) else {
                actual.finder_scanned_bytes = actual
                    .finder_scanned_bytes
                    .checked_add(search.len())
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "general reducer terminal finder service",
                    })?;
                break;
            };
            let service = relative.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
                computation: "general reducer primary finder service",
            })?;
            actual.finder_scanned_bytes = actual.finder_scanned_bytes.checked_add(service).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "general reducer primary service bytes",
                },
            )?;
            let anchor = cursor.checked_add(relative).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "general reducer primary anchor",
                },
            )?;
            let start = anchor.checked_sub(primary_offset).ok_or(
                ReduceError::InternalInvariant("general reducer primary preceded its offset"),
            )?;
            actual.anchor_candidates = actual.anchor_candidates.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "general reducer primary candidates",
                },
            )?;
            match self.general_primary_outcome(
                haystack,
                start,
                primary_offset,
                fallback,
                fallback_offset,
                &mut actual.predicate_checks,
            )? {
                GeneralPrimaryOutcome::Match => {
                    actual.match_events = actual.match_events.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "general reducer primary match events",
                        },
                    )?;
                    let end = start.checked_add(self.width).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "general reducer primary match end",
                        },
                    )?;
                    visitor(CompleteSpan { start, end });
                    cursor = anchor.checked_add(self.width).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "general reducer accepted restart",
                        },
                    )?;
                    fallback_rejections = 0;
                    residual_rejections = 0;
                    continue;
                }
                GeneralPrimaryOutcome::FallbackRejected => {
                    residual_rejections = 0;
                    if fallback_rejections == 0 {
                        fallback_burst_start = anchor;
                    }
                    fallback_rejections = fallback_rejections.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "general reducer fallback rejection burst",
                        },
                    )?;
                }
                GeneralPrimaryOutcome::ResidualRejected => {
                    fallback_rejections = 0;
                    if residual_rejections == 0 {
                        residual_burst_start = anchor;
                    }
                    residual_rejections = residual_rejections.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "general reducer residual rejection burst",
                        },
                    )?;
                }
            }
            cursor = anchor.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
                computation: "general reducer rejected restart",
            })?;
            let first_untested_start = cursor.checked_sub(primary_offset).ok_or(
                ReduceError::InternalInvariant("general reducer handoff preceded its cursor"),
            )?;
            if fallback_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    fallback_burst_start,
                    anchor,
                    fallback_rejections,
                    general_primary_max_mean_skip,
                )
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "general reducer fallback rejection density",
                })? {
                    return self.scan_adaptive_reporting(
                        haystack,
                        first_untested_start,
                        actual,
                        visitor,
                    );
                }
                fallback_rejections = 0;
            }
            if residual_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                if dense_general_primary_rejection_burst(
                    residual_burst_start,
                    anchor,
                    residual_rejections,
                    general_primary_max_mean_skip,
                )
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "general reducer residual rejection density",
                })? {
                    return self.scan_shift_and_reporting_suffix(
                        haystack,
                        first_untested_start,
                        actual,
                        visitor,
                    );
                }
                residual_rejections = 0;
            }
        }
        Ok(())
    }

    fn scan_anchor<F, V>(
        &self,
        haystack: &[u8],
        anchor_offset: usize,
        mut find: F,
        visitor: &mut V,
    ) -> Result<AnchorActual, ReduceError>
    where
        F: FnMut(&[u8]) -> Option<usize>,
        V: FnMut(CompleteSpan),
    {
        let anchor_end = haystack
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(anchor_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = anchor_offset.min(anchor_end);
        let mut actual = AnchorActual::default();
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while cursor < anchor_end {
            let search = haystack
                .get(cursor..anchor_end)
                .ok_or(ReduceError::InternalInvariant(
                    "anchor search window escaped the input",
                ))?;
            actual.finder_calls =
                actual
                    .finder_calls
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual anchor finder calls",
                    })?;
            let Some(relative) = find(search) else {
                actual.finder_scanned_bytes = actual
                    .finder_scanned_bytes
                    .checked_add(search.len())
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual unsuccessful anchor service bytes",
                    })?;
                break;
            };
            let service = relative
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual successful anchor service bytes",
                })?;
            actual.finder_scanned_bytes = actual.finder_scanned_bytes.checked_add(service).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "actual anchor service bytes",
                },
            )?;
            let anchor = cursor
                .checked_add(relative)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual anchor position",
                })?;
            let start = anchor
                .checked_sub(anchor_offset)
                .ok_or(ReduceError::InternalInvariant(
                    "anchor position preceded its fixed offset",
                ))?;
            actual.anchor_candidates =
                actual
                    .anchor_candidates
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual anchor candidates",
                    })?;
            let matched = self.anchor_candidate_matches(
                haystack,
                start,
                anchor_offset,
                &mut actual.predicate_checks,
            )?;
            if matched {
                actual.match_events =
                    actual
                        .match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual anchor match events",
                        })?;
                let end = start.checked_add(self.width).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "actual anchor match end",
                    },
                )?;
                visitor(CompleteSpan { start, end });
                cursor = anchor
                    .checked_add(self.width)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "accepted anchor restart",
                    })?;
                burst_rejections = 0;
            } else {
                cursor = anchor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "rejected anchor restart",
                    })?;
                if burst_rejections == 0 {
                    burst_start = anchor;
                }
                burst_rejections =
                    burst_rejections
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "adaptive reducer rejection burst",
                        })?;
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                    && self.adaptive_fallback.is_some()
                    && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "adaptive reducer rejection density",
                        },
                    )?
                {
                    let first_untested_start =
                        cursor
                            .checked_sub(anchor_offset)
                            .ok_or(ReduceError::InternalInvariant(
                                "adaptive reducer fallback preceded the first untested start",
                            ))?;
                    self.scan_adaptive_reporting(
                        haystack,
                        first_untested_start,
                        &mut actual,
                        visitor,
                    )?;
                    break;
                }
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                    burst_rejections = 0;
                }
            }
        }
        Ok(actual)
    }

    fn scan_adaptive_reporting<F>(
        &self,
        haystack: &[u8],
        first_untested_start: usize,
        actual: &mut AnchorActual,
        visitor: &mut F,
    ) -> Result<(), ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        if !has_legal_start(haystack.len(), self.width, first_untested_start) {
            return Ok(());
        }
        let Some(fallback) = self.adaptive_fallback.as_ref() else {
            return self.scan_shift_and_reporting_suffix(
                haystack,
                first_untested_start,
                actual,
                visitor,
            );
        };
        let primary = self
            .primary_finder_descriptor()
            .ok_or(ReduceError::InternalInvariant(
                "adaptive reducer candidate stream lost its primary anchor",
            ))?;
        let primary_offset = usize::from(primary.offset().ok_or(
            ReduceError::InternalInvariant("adaptive reducer primary lost its fixed offset"),
        )?);
        let fallback_offset = usize::from(fallback.offset);
        if primary_offset == fallback_offset {
            return Err(ReduceError::InternalInvariant(
                "adaptive reducer candidate stream duplicated the primary anchor",
            ));
        }
        let legal_start_end = haystack
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(1))
            .unwrap_or(0);
        let mut cursor = first_untested_start.min(legal_start_end);
        let mut finder = CandidateStreamCursor::new_with_fallback_skip(
            primary,
            fallback,
            self.general_fallback_skip(),
            haystack,
            legal_start_end,
        );
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        let mut drain_end = None;
        while cursor < legal_start_end {
            if drain_end.is_some_and(|end| cursor >= end) {
                return self.scan_shift_and_reporting_suffix(haystack, cursor, actual, visitor);
            }
            actual.finder_calls =
                actual
                    .finder_calls
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer candidate-stream finder calls",
                    })?;
            let service_start = cursor;
            let primary_before = finder.primary_classified_bytes();
            let fallback_before = finder.fallback_classified_bytes();
            let found = match drain_end {
                Some(end) => finder.find_retained_before(cursor, end),
                None => finder.find(cursor),
            };
            let newly_primary = finder
                .primary_classified_bytes()
                .checked_sub(primary_before)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer primary classification",
                })?;
            let newly_fallback = finder
                .fallback_classified_bytes()
                .checked_sub(fallback_before)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer fallback classification",
                })?;
            actual.finder_scanned_bytes = actual
                .finder_scanned_bytes
                .checked_add(newly_fallback)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer fallback-classifier service",
                })?;
            actual.predicate_checks = actual
                .predicate_checks
                .checked_add(newly_primary)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer primary-classifier checks",
                })?;
            let Some(start) = found else {
                if let Some(end) = drain_end {
                    return self.scan_shift_and_reporting_suffix(haystack, end, actual, visitor);
                }
                break;
            };
            if start < service_start {
                return Err(ReduceError::InternalInvariant(
                    "adaptive reducer candidate-stream service reversed",
                ));
            }
            actual.anchor_candidates =
                actual
                    .anchor_candidates
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer candidate-stream candidates",
                    })?;
            if self.candidate_matches_skipping_pair(
                haystack,
                start,
                primary_offset,
                fallback_offset,
                &mut actual.predicate_checks,
            )? {
                actual.match_events =
                    actual
                        .match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "adaptive reducer byte-set match events",
                        })?;
                let end = start.checked_add(self.width).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer byte-set match end",
                    },
                )?;
                visitor(CompleteSpan { start, end });
                cursor = start
                    .checked_add(self.width)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer candidate-stream accepted restart",
                    })?;
                burst_rejections = 0;
            } else {
                cursor = start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer candidate-stream rejected restart",
                    })?;
                if burst_rejections == 0 {
                    burst_start = start;
                }
                burst_rejections =
                    burst_rejections
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "adaptive reducer candidate-stream rejection burst",
                        })?;
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                    && dense_rejection_burst(burst_start, start, burst_rejections).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "adaptive reducer candidate-stream rejection density",
                        },
                    )?
                {
                    drain_end = Some(finder.retained_block().end.min(legal_start_end));
                    burst_rejections = 0;
                    continue;
                }
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                    burst_rejections = 0;
                }
            }
        }
        Ok(())
    }

    fn scan_shift_and_reporting_suffix<F>(
        &self,
        haystack: &[u8],
        first_untested_start: usize,
        actual: &mut AnchorActual,
        visitor: &mut F,
    ) -> Result<(), ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let remaining =
            haystack
                .get(first_untested_start..)
                .ok_or(ReduceError::InternalInvariant(
                    "adaptive reducer Shift-And escaped input",
                ))?;
        if remaining.len() < self.width {
            return Ok(());
        }
        let mut state = 0_u64;
        for (position, &byte) in remaining.iter().enumerate() {
            actual.shift_and_transitions = actual.shift_and_transitions.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer Shift-And transitions",
                },
            )?;
            state = (state.wrapping_shl(1) | 1) & self.masks[usize::from(byte)];
            if state & self.accepting_bit != 0 {
                actual.match_events =
                    actual
                        .match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "adaptive reducer Shift-And match events",
                        })?;
                let end = first_untested_start
                    .checked_add(position)
                    .and_then(|end| end.checked_add(1))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer Shift-And match end",
                    })?;
                let start = end.checked_sub(self.width).ok_or(
                    ReduceError::InternalInvariant(
                        "adaptive Shift-And accepted before the fixed word width",
                    ),
                )?;
                visitor(CompleteSpan { start, end });
                state = 0;
            }
        }
        Ok(())
    }

    #[inline]
    fn anchor_candidate_matches(
        &self,
        haystack: &[u8],
        start: usize,
        anchor_offset: usize,
        predicate_checks: &mut usize,
    ) -> Result<bool, ReduceError> {
        let end = start
            .checked_add(self.width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual predicate candidate end",
            })?;
        let candidate = haystack
            .get(start..end)
            .ok_or(ReduceError::InternalInvariant(
                "fixed predicate candidate escaped the input",
            ))?;
        let secondary = self.secondary_anchor;
        let secondary_offset = secondary.and_then(Anchor::offset).map(usize::from);
        if let Some(anchor) = secondary {
            let position = secondary_offset.ok_or(ReduceError::InternalInvariant(
                "secondary anchor selected Shift-And",
            ))?;
            if position == anchor_offset {
                return Err(ReduceError::InternalInvariant(
                    "secondary anchor duplicated the primary anchor",
                ));
            }
            *predicate_checks =
                predicate_checks
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual predicate checks",
                    })?;
            if !anchor
                .matches(
                    *candidate
                        .get(position)
                        .ok_or(ReduceError::InternalInvariant(
                            "fixed predicate candidate escaped the input",
                        ))?,
                )
                .ok_or(ReduceError::InternalInvariant(
                    "secondary anchor selected Shift-And",
                ))?
            {
                return Ok(false);
            }
        }
        let anchor_shift =
            u32::try_from(anchor_offset).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "primary anchor verification shift",
            })?;
        let mut remaining = self.nonuniversal_mask
            & !1_u64
                .checked_shl(anchor_shift)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "primary anchor verification bit",
                })?;
        if let Some(position) = secondary_offset {
            let shift = u32::try_from(position).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "secondary anchor verification shift",
            })?;
            remaining &= !1_u64
                .checked_shl(shift)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "secondary anchor verification bit",
                })?;
        }
        if let Some(fallback) = self.adaptive_fallback.as_ref() {
            let position = usize::from(fallback.offset);
            if position != anchor_offset && Some(position) != secondary_offset {
                let shift =
                    u32::try_from(position).map_err(|_| ReduceError::ArithmeticOverflow {
                        computation: "adaptive fallback verification shift",
                    })?;
                let bit = 1_u64
                    .checked_shl(shift)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "adaptive fallback verification bit",
                    })?;
                if remaining & bit == 0 {
                    return Err(ReduceError::InternalInvariant(
                        "adaptive fallback was not a remaining predicate",
                    ));
                }
                if !self.anchor_candidate_position_matches_bit(
                    candidate,
                    position,
                    bit,
                    predicate_checks,
                )? {
                    return Ok(false);
                }
                remaining &= !bit;
            }
        }
        while remaining != 0 {
            let bit = remaining & remaining.wrapping_neg();
            let position = usize::try_from(remaining.trailing_zeros()).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "predicate verification position",
                }
            })?;
            remaining &= remaining - 1;
            if !self.anchor_candidate_position_matches_bit(
                candidate,
                position,
                bit,
                predicate_checks,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn candidate_matches_skipping_pair(
        &self,
        haystack: &[u8],
        start: usize,
        primary_offset: usize,
        fallback_offset: usize,
        predicate_checks: &mut usize,
    ) -> Result<bool, ReduceError> {
        let end = start
            .checked_add(self.width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "adaptive predicate candidate end",
            })?;
        let candidate = haystack
            .get(start..end)
            .ok_or(ReduceError::InternalInvariant(
                "adaptive predicate candidate escaped the input",
            ))?;
        let retained_primary_offset = usize::from(self.primary_offset().ok_or(
            ReduceError::InternalInvariant("adaptive fallback lost its primary anchor"),
        )?);
        if retained_primary_offset != primary_offset || primary_offset == fallback_offset {
            return Err(ReduceError::InternalInvariant(
                "adaptive candidate stream has inconsistent anchor offsets",
            ));
        }
        let primary_shift =
            u32::try_from(primary_offset).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "adaptive primary verification shift",
            })?;
        let fallback_shift =
            u32::try_from(fallback_offset).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "adaptive fallback verification shift",
            })?;
        let primary_bit =
            1_u64
                .checked_shl(primary_shift)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "adaptive primary verification bit",
                })?;
        let fallback_bit =
            1_u64
                .checked_shl(fallback_shift)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "adaptive fallback verification bit",
                })?;
        if self.nonuniversal_mask & primary_bit == 0 || self.nonuniversal_mask & fallback_bit == 0 {
            return Err(ReduceError::InternalInvariant(
                "adaptive candidate stream skipped a universal predicate",
            ));
        }
        let mut remaining = self.nonuniversal_mask & !primary_bit & !fallback_bit;
        if let Some(secondary) = self.secondary_anchor {
            let secondary_offset = usize::from(secondary.offset().ok_or(
                ReduceError::InternalInvariant("adaptive secondary selected Shift-And"),
            )?);
            if secondary_offset != primary_offset && secondary_offset != fallback_offset {
                *predicate_checks =
                    predicate_checks
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual predicate checks",
                        })?;
                if !secondary
                    .matches(*candidate.get(secondary_offset).ok_or(
                        ReduceError::InternalInvariant("adaptive secondary escaped the candidate"),
                    )?)
                    .ok_or(ReduceError::InternalInvariant(
                        "adaptive secondary selected Shift-And",
                    ))?
                {
                    return Ok(false);
                }
                let secondary_shift = u32::try_from(secondary_offset).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive secondary verification shift",
                    }
                })?;
                remaining &=
                    !1_u64
                        .checked_shl(secondary_shift)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "adaptive secondary verification bit",
                        })?;
            }
        }
        while remaining != 0 {
            let bit = remaining & remaining.wrapping_neg();
            let position = usize::try_from(remaining.trailing_zeros()).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "adaptive predicate verification position",
                }
            })?;
            remaining &= remaining - 1;
            if !self.anchor_candidate_position_matches_bit(
                candidate,
                position,
                bit,
                predicate_checks,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn general_primary_outcome(
        &self,
        haystack: &[u8],
        start: usize,
        primary_offset: usize,
        fallback: &AdaptiveFallback,
        fallback_offset: usize,
        predicate_checks: &mut usize,
    ) -> Result<GeneralPrimaryOutcome, ReduceError> {
        let fallback_position = start.checked_add(fallback_offset).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "general primary fallback position",
            },
        )?;
        let fallback_byte = *haystack.get(fallback_position).ok_or(
            ReduceError::InternalInvariant("general primary fallback escaped the input"),
        )?;
        *predicate_checks = predicate_checks.checked_add(1).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "general primary fallback predicate checks",
            },
        )?;
        if !fallback.matches(fallback_byte) {
            return Ok(GeneralPrimaryOutcome::FallbackRejected);
        }
        if self.candidate_matches_skipping_pair(
            haystack,
            start,
            primary_offset,
            fallback_offset,
            predicate_checks,
        )? {
            Ok(GeneralPrimaryOutcome::Match)
        } else {
            Ok(GeneralPrimaryOutcome::ResidualRejected)
        }
    }

    fn anchor_candidate_position_matches_bit(
        &self,
        candidate: &[u8],
        position: usize,
        bit: u64,
        predicate_checks: &mut usize,
    ) -> Result<bool, ReduceError> {
        *predicate_checks =
            predicate_checks
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual predicate checks",
                })?;
        let byte = *candidate
            .get(position)
            .ok_or(ReduceError::InternalInvariant(
                "fixed predicate candidate escaped the input",
            ))?;
        Ok(self.masks[usize::from(byte)] & bit != 0)
    }

    fn finish_anchor_actual(
        &self,
        input_bytes: usize,
        upper_bounds: ReduceUpperBounds,
        actual: AnchorActual,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let transitions = actual
            .finder_scanned_bytes
            .checked_add(actual.shift_and_transitions)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "adaptive reducer transitions",
            })?;
        let count =
            u64::try_from(actual.match_events).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual anchor count conversion",
            })?;
        let width = u64::try_from(self.width).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual anchor word width conversion",
        })?;
        let matched_bytes = count
            .checked_mul(width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual anchor matched bytes",
            })?;
        let reducer_steps =
            transitions
                .checked_add(REDUCE_FINAL_WORK)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual anchor reducer steps",
                })?;
        let work_usize = actual
            .finder_scanned_bytes
            .checked_mul(FINDER_SCAN_BYTE_WORK)
            .and_then(|work| {
                work.checked_add(actual.shift_and_transitions.checked_mul(TRANSITION_WORK)?)
            })
            .and_then(|work| work.checked_add(actual.finder_calls.checked_mul(FINDER_CALL_WORK)?))
            .and_then(|work| {
                work.checked_add(
                    actual
                        .anchor_candidates
                        .checked_mul(ANCHOR_CANDIDATE_WORK)?,
                )
            })
            .and_then(|work| {
                work.checked_add(actual.predicate_checks.checked_mul(PREDICATE_CHECK_WORK)?)
            })
            .and_then(|work| work.checked_add(actual.match_events.checked_mul(MATCH_WORK)?))
            .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual anchor reducer work",
            })?;
        let work_charged =
            u64::try_from(work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual anchor reducer work conversion",
            })?;
        let counters = ReduceActualCounters {
            input_bytes,
            transitions,
            finder_scanned_bytes: actual.finder_scanned_bytes,
            shift_and_transitions: actual.shift_and_transitions,
            finder_calls: actual.finder_calls,
            anchor_candidates: actual.anchor_candidates,
            predicate_checks: actual.predicate_checks,
            match_events: actual.match_events,
            count,
            matched_bytes,
            reducer_steps,
            work_charged,
            allocations: 0,
            reserves: 0,
            temporary_copies: 0,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        };
        if !actual_within_upper(counters, upper_bounds) {
            return Err(ReduceError::InternalInvariant(
                "actual anchor counters exceeded prospective upper bounds",
            ));
        }
        Ok(counters)
    }
}

fn actual_within_upper(actual: ReduceActualCounters, upper: ReduceUpperBounds) -> bool {
    let transitions_close = actual
        .finder_scanned_bytes
        .checked_add(actual.shift_and_transitions)
        == Some(actual.transitions);
    let reconstructed_work = actual
        .finder_scanned_bytes
        .checked_mul(FINDER_SCAN_BYTE_WORK)
        .and_then(|work| {
            work.checked_add(actual.shift_and_transitions.checked_mul(TRANSITION_WORK)?)
        })
        .and_then(|work| work.checked_add(actual.finder_calls.checked_mul(FINDER_CALL_WORK)?))
        .and_then(|work| {
            work.checked_add(
                actual
                    .anchor_candidates
                    .checked_mul(ANCHOR_CANDIDATE_WORK)?,
            )
        })
        .and_then(|work| {
            work.checked_add(actual.predicate_checks.checked_mul(PREDICATE_CHECK_WORK)?)
        })
        .and_then(|work| work.checked_add(actual.match_events.checked_mul(MATCH_WORK)?))
        .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
        .and_then(|work| u64::try_from(work).ok());
    transitions_close
        && reconstructed_work == Some(actual.work_charged)
        && actual.input_bytes <= upper.input_bytes
        && actual.transitions <= upper.transitions
        && actual.finder_scanned_bytes <= upper.finder_scanned_bytes
        && actual.shift_and_transitions <= upper.shift_and_transitions
        && actual.finder_calls <= upper.finder_calls
        && actual.anchor_candidates <= upper.anchor_candidates
        && actual.predicate_checks <= upper.predicate_checks
        && actual.match_events <= upper.match_events
        && actual.count <= upper.count
        && actual.matched_bytes <= upper.span_sum
        && actual.reducer_steps <= upper.reducer_steps
        && actual.work_charged <= upper.work
        && actual.allocations <= upper.allocations
        && actual.reserves <= upper.reserves
        && actual.temporary_copies <= upper.temporary_copies
        && actual.scratch_bytes <= upper.scratch_bytes
        && actual.persistent_bytes <= upper.persistent_bytes
        && actual.peak_bytes <= upper.peak_bytes
}

fn search_work(
    finder_scanned_bytes: usize,
    shift_and_transitions: usize,
    finder_calls: usize,
    candidate_events: usize,
    predicate_checks: usize,
    match_events: usize,
) -> Result<u64, SearchError> {
    let work = finder_scanned_bytes
        .checked_mul(FINDER_SCAN_BYTE_WORK)
        .and_then(|work| work.checked_add(shift_and_transitions.checked_mul(TRANSITION_WORK)?))
        .and_then(|work| work.checked_add(finder_calls.checked_mul(FINDER_CALL_WORK)?))
        .and_then(|work| work.checked_add(candidate_events.checked_mul(ANCHOR_CANDIDATE_WORK)?))
        .and_then(|work| work.checked_add(predicate_checks.checked_mul(PREDICATE_CHECK_WORK)?))
        .and_then(|work| work.checked_add(match_events.checked_mul(MATCH_WORK)?))
        .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "actual fixed-predicate search work",
        })?;
    u64::try_from(work).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "actual fixed-predicate search work conversion",
    })
}

fn ensure_search_actual_within(
    actual: SearchActualCounters,
    upper: SearchUpperBounds,
) -> Result<(), SearchError> {
    let transitions_close = actual
        .finder_scanned_bytes
        .checked_add(actual.shift_and_transitions)
        == Some(actual.transitions);
    let work_closes = search_work(
        actual.finder_scanned_bytes,
        actual.shift_and_transitions,
        actual.finder_calls,
        actual.candidate_events,
        actual.predicate_checks,
        actual.match_events,
    )? == actual.work;
    if transitions_close
        && work_closes
        && actual.window_bytes == upper.window_bytes
        && actual.transitions <= upper.transitions
        && actual.finder_scanned_bytes <= upper.finder_scanned_bytes
        && actual.shift_and_transitions <= upper.shift_and_transitions
        && actual.finder_calls <= upper.finder_calls
        && actual.candidate_events <= upper.candidate_events
        && actual.predicate_checks <= upper.predicate_checks
        && actual.match_events <= upper.match_events
        && actual.work <= upper.work
        && actual.scratch_bytes <= upper.scratch_bytes
    {
        Ok(())
    } else {
        Err(SearchError::InternalInvariant(
            "actual fixed-predicate search counters exceeded prospective bounds",
        ))
    }
}

fn search_error_from_reduce(error: &ReduceError) -> SearchError {
    match error {
        ReduceError::ArithmeticOverflow { computation } => {
            SearchError::ArithmeticOverflow { computation }
        }
        ReduceError::InternalInvariant(detail) => SearchError::InternalInvariant(detail),
        _ => SearchError::InternalInvariant(
            "fixed-predicate candidate verification returned a reduction-only resource error",
        ),
    }
}

#[derive(Clone, Copy)]
enum BuildResource {
    Positions,
    SourceRanges,
    Persistent,
    Peak,
}

fn enforce_build_usize(
    needed: usize,
    limit: usize,
    resource: BuildResource,
) -> Result<(), BuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::Positions => BuildError::PositionLimit { needed, limit },
        BuildResource::SourceRanges => BuildError::SourceRangesLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

#[derive(Clone, Copy)]
enum ReduceResource {
    Input,
    Transitions,
    MatchEvents,
    ReducerSteps,
    Persistent,
    Peak,
}

fn enforce_reduce_usize(
    needed: usize,
    limit: usize,
    resource: ReduceResource,
) -> Result<(), ReduceError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        ReduceResource::Input => ReduceError::InputLimit { needed, limit },
        ReduceResource::Transitions => ReduceError::TransitionsLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::ReducerSteps => ReduceError::ReducerStepsLimit { needed, limit },
        ReduceResource::Persistent => ReduceError::PersistentLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[(u8, u8)] = &[(b'A', b'A'), (b'a', b'a')];
    const B: &[(u8, u8)] = &[(b'B', b'B'), (b'b', b'b')];
    const LOWER_A: &[(u8, u8)] = &[(b'a', b'a')];
    const X: &[(u8, u8)] = &[(b'x', b'x')];

    fn ab_plan() -> FixedPredicateWord64Plan {
        FixedPredicateWord64Plan::build(&[A, B], BuildLimits::unlimited()).unwrap()
    }

    #[test]
    fn adaptive_rejection_density_tracks_path_specific_scan_grains() {
        assert_eq!(
            ADAPTIVE_FALLBACK_MAX_MEAN_SKIP,
            BYTE_SET_BLOCK_BYTES
        );
        assert_eq!(
            GENERAL_PRIMARY_WIDE_MAX_MEAN_SKIP,
            BYTE_SET_WIDE_BLOCK_BYTES
        );
        assert_eq!(
            GeneralPrimarySeeker::Memchr3([1, 2, 3]).max_mean_skip(),
            BYTE_SET_BLOCK_BYTES
        );
        let four = AdaptiveFallback {
            offset: 0,
            cardinality: 4,
            finder: AdaptiveFinder::Four([1, 2, 3, 4]),
        };
        assert_eq!(
            GeneralPrimarySeeker::CompiledWholeSlice(&four).max_mean_skip(),
            if cfg!(target_arch = "aarch64") {
                BYTE_SET_WIDE_BLOCK_BYTES
            } else {
                BYTE_SET_BLOCK_BYTES
            }
        );
        let narrow_boundary = (ADAPTIVE_FALLBACK_REJECTIONS - 1)
            .checked_mul(BYTE_SET_BLOCK_BYTES)
            .unwrap();
        assert_eq!(
            dense_rejection_burst(100, 100 + narrow_boundary, ADAPTIVE_FALLBACK_REJECTIONS),
            Some(true)
        );
        assert_eq!(
            dense_rejection_burst(
                100,
                100 + narrow_boundary + 1,
                ADAPTIVE_FALLBACK_REJECTIONS
            ),
            Some(false)
        );
        let count_value_boundary = (COUNT_VALUE_ADAPTIVE_SAMPLE_REJECTIONS - 1)
            .checked_mul(BYTE_SET_BLOCK_BYTES)
            .unwrap();
        assert_eq!(
            dense_count_value_rejection_sample(
                100,
                100 + count_value_boundary,
                COUNT_VALUE_ADAPTIVE_SAMPLE_REJECTIONS
            ),
            Some(true)
        );
        assert_eq!(
            dense_count_value_rejection_sample(
                100,
                100 + count_value_boundary + 1,
                COUNT_VALUE_ADAPTIVE_SAMPLE_REJECTIONS
            ),
            Some(false)
        );
        assert_eq!(
            dense_count_value_rejection_sample(
                100,
                100 + count_value_boundary,
                COUNT_VALUE_ADAPTIVE_SAMPLE_REJECTIONS - 1
            ),
            Some(false)
        );
        let general_boundary = (ADAPTIVE_FALLBACK_REJECTIONS - 1)
            .checked_mul(BYTE_SET_WIDE_BLOCK_BYTES)
            .unwrap();
        assert_eq!(
            dense_general_primary_rejection_burst(
                100,
                100 + general_boundary,
                ADAPTIVE_FALLBACK_REJECTIONS,
                GENERAL_PRIMARY_WIDE_MAX_MEAN_SKIP
            ),
            Some(true)
        );
        assert_eq!(
            dense_general_primary_rejection_burst(
                100,
                100 + general_boundary + 1,
                ADAPTIVE_FALLBACK_REJECTIONS,
                GENERAL_PRIMARY_WIDE_MAX_MEAN_SKIP
            ),
            Some(false)
        );
        assert_eq!(
            dense_rejection_burst(
                100,
                100 + narrow_boundary,
                ADAPTIVE_FALLBACK_REJECTIONS - 1
            ),
            Some(false)
        );
    }

    fn naive_count(haystack: &[u8], predicates: &[&[(u8, u8)]]) -> u64 {
        let mut at = 0_usize;
        let mut count = 0_u64;
        while let Some(end) = at.checked_add(predicates.len()) {
            let Some(candidate) = haystack.get(at..end) else {
                break;
            };
            let matched = candidate.iter().zip(predicates).all(|(&byte, ranges)| {
                ranges
                    .iter()
                    .any(|&(start, end)| start <= byte && byte <= end)
            });
            if matched {
                count = count.checked_add(1).unwrap();
                at = end;
            } else {
                at = at.checked_add(1).unwrap();
            }
        }
        count
    }

    fn naive_spans(haystack: &[u8], predicates: &[&[(u8, u8)]]) -> Vec<CompleteSpan> {
        let mut at = 0_usize;
        let mut spans = Vec::new();
        while let Some(end) = at.checked_add(predicates.len()) {
            let Some(candidate) = haystack.get(at..end) else {
                break;
            };
            let matched = candidate.iter().zip(predicates).all(|(&byte, ranges)| {
                ranges
                    .iter()
                    .any(|&(start, end)| start <= byte && byte <= end)
            });
            if matched {
                spans.push(CompleteSpan { start: at, end });
                at = end;
            } else {
                at = at.checked_add(1).unwrap();
            }
        }
        spans
    }

    #[test]
    fn span_visit_matches_oracle_across_fixed_predicate_reducers() {
        const FULL: &[(u8, u8)] = &[(0, u8::MAX)];
        const BROAD: &[(u8, u8)] = &[(0, 0x7e)];
        const FOUR: &[(u8, u8)] = &[(b'W', b'Z')];
        const THREE: &[(u8, u8)] = &[(b'a', b'c')];
        let cases: [(FixedPredicateWord64Plan, &[u8], &[&[(u8, u8)]]); 3] = [
            (ab_plan(), b"xABabABy", &[A, B]),
            (
                FixedPredicateWord64Plan::build(&[FULL, FULL], BuildLimits::unlimited()).unwrap(),
                b"abcdefg",
                &[FULL, FULL],
            ),
            (
                FixedPredicateWord64Plan::build(
                    &[BROAD, FOUR, BROAD, THREE],
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                b"!W!a-xx?X?b!Y!c-tail",
                &[BROAD, FOUR, BROAD, THREE],
            ),
        ];

        for (plan, haystack, predicates) in cases {
            let expected = naive_spans(haystack, predicates);
            let mut actual_spans = Vec::new();
            let result = plan
                .visit_spans(haystack, ReduceLimits::unlimited(), |span| {
                    actual_spans.push(span);
                })
                .unwrap();
            assert_eq!(actual_spans, expected);
            assert_eq!(result.matches, expected.len());
            assert_eq!(
                result.span_sum,
                u64::try_from(expected.len() * predicates.len()).unwrap()
            );
            assert_eq!(result.accounting.identity.operation, Operation::SpanVisit);
            assert_eq!(
                result.accounting.identity.operation_id,
                SPAN_VISIT_OPERATION_ID
            );
            assert_ne!(
                result.accounting.identity.operation_id,
                SPAN_SUM_OPERATION_ID
            );
            assert_eq!(result.accounting.actual.allocations, 0);
            assert_eq!(result.accounting.actual.reserves, 0);
            assert_eq!(result.accounting.actual.scratch_bytes, 0);
        }
    }

    #[test]
    fn span_visit_refuses_before_first_callback() {
        let plan = ab_plan();
        let mut callbacks = 0_usize;
        let error = plan
            .visit_spans(
                b"abab",
                ReduceLimits {
                    max_span_sum: 3,
                    ..ReduceLimits::unlimited()
                },
                |_| callbacks += 1,
            )
            .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(matches!(
            error,
            ReduceError::SpanSumLimit {
                needed: 4,
                limit: 3
            }
        ));
    }

    fn adaptive_finder_contains(finder: &AdaptiveFinder, byte: u8) -> bool {
        match finder {
            AdaptiveFinder::One(first) => byte == *first,
            AdaptiveFinder::Two(first, second) => byte == *first || byte == *second,
            AdaptiveFinder::Three(first, second, third) => {
                byte == *first || byte == *second || byte == *third
            }
            AdaptiveFinder::Four(members) => members.contains(&byte),
            AdaptiveFinder::Range {
                origin,
                maximum_delta,
            } => byte.wrapping_sub(*origin) <= *maximum_delta,
            AdaptiveFinder::Set(classifier) => classifier.set().contains(byte),
        }
    }

    fn reference_adaptive_find(
        finder: &AdaptiveFinder,
        bytes: &[u8],
        cursor: usize,
        end: usize,
    ) -> Option<usize> {
        bytes
            .get(cursor..end)?
            .iter()
            .position(|&byte| adaptive_finder_contains(finder, byte))
            .and_then(|relative| cursor.checked_add(relative))
    }

    fn assert_resumable_finder_sequence(
        finder: &AdaptiveFinder,
        bytes: &[u8],
        end: usize,
        jump_seed: usize,
    ) {
        let mut finder_cursor = AdaptiveFinderCursor::new(finder, bytes, end);
        let mut cursor = 0_usize;
        let mut step = 0_usize;
        loop {
            let expected = reference_adaptive_find(finder, bytes, cursor, end);
            let actual = finder_cursor.find(cursor);
            assert_eq!(
                actual, expected,
                "cursor={cursor}, end={end}, bytes={bytes:?}"
            );
            let Some(found) = actual else {
                break;
            };
            let jump = (jump_seed.wrapping_add(step) % 7).checked_add(1).unwrap();
            cursor = found.saturating_add(jump).min(end);
            step = step.checked_add(1).unwrap();
        }
    }

    fn reference_candidate_stream_find(
        primary: PrimaryPredicate<'_>,
        fallback: &AdaptiveFallback,
        bytes: &[u8],
        cursor: usize,
        legal_start_end: usize,
    ) -> Option<usize> {
        let primary_offset = usize::from(primary.offset()?);
        let fallback_offset = usize::from(fallback.offset);
        (cursor..legal_start_end).find(|&start| {
            let primary_byte = bytes[start.checked_add(primary_offset).unwrap()];
            let fallback_byte = bytes[start.checked_add(fallback_offset).unwrap()];
            primary.matches(primary_byte) == Some(true) && fallback.matches(fallback_byte)
        })
    }

    fn assert_candidate_stream_sequence(
        primary: PrimaryPredicate<'_>,
        fallback: &AdaptiveFallback,
        bytes: &[u8],
        legal_start_end: usize,
        jump_seed: usize,
    ) {
        let mut stream = CandidateStreamCursor::new(primary, fallback, bytes, legal_start_end);
        let mut cursor = 0_usize;
        let mut step = 0_usize;
        loop {
            let expected =
                reference_candidate_stream_find(primary, fallback, bytes, cursor, legal_start_end);
            let actual = stream.find(cursor);
            assert_eq!(actual, expected, "cursor={cursor}, bytes={bytes:?}");
            let Some(found) = actual else {
                break;
            };
            let jump = jump_seed
                .wrapping_add(step)
                .checked_rem(11)
                .and_then(|jump| jump.checked_add(1))
                .unwrap();
            cursor = found.saturating_add(jump).min(legal_start_end);
            step = step.checked_add(1).unwrap();
        }
    }

    #[test]
    fn fixed_anchor_matches_exhaustive_short_reference_and_restarts_on_accept() {
        let plan = ab_plan();
        let alphabet = [b'A', b'a', b'B', b'b', b'x'];
        for length in 0..=5 {
            let cases = alphabet.len().pow(u32::try_from(length).unwrap());
            for mut ordinal in 0..cases {
                let mut haystack = vec![0_u8; length];
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                let expected = naive_count(&haystack, &[A, B]);
                let count = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
                let sum = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(count.count, expected, "haystack={haystack:?}");
                assert_eq!(sum.span_sum, expected.checked_mul(2).unwrap());
                assert_eq!(
                    plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                    Some(expected),
                    "compact count haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
                    expected.checked_mul(2),
                    "compact span sum haystack={haystack:?}"
                );
                assert!(actual_within_upper(
                    count.accounting.actual,
                    count.accounting.upper_bounds
                ));
                assert!(actual_within_upper(
                    sum.accounting.actual,
                    sum.accounting.upper_bounds
                ));
            }
        }
        assert_eq!(
            plan.count(b"aBaB", ReduceLimits::unlimited())
                .unwrap()
                .count,
            2
        );
        assert_eq!(
            plan.count(b"aaB", ReduceLimits::unlimited()).unwrap().count,
            1
        );
        assert_eq!(
            plan.count(&[b'a', 0xFF, b'b', b'a', b'b'], ReduceLimits::unlimited())
                .unwrap()
                .count,
            1
        );
        assert_eq!(
            plan.count(&[b'a', 0x80, b'b'], ReduceLimits::unlimited())
                .unwrap()
                .count,
            0
        );

        let dense =
            FixedPredicateWord64Plan::build(&[LOWER_A, LOWER_A, LOWER_A], BuildLimits::unlimited())
                .unwrap();
        assert_eq!(
            dense
                .count(b"aaaaaa", ReduceLimits::unlimited())
                .unwrap()
                .count,
            2
        );
        assert_eq!(
            dense
                .count(b"aaaaa", ReduceLimits::unlimited())
                .unwrap()
                .count,
            1
        );
        assert_eq!(
            dense.count_value_success(b"aaaaaa", ReduceLimits::unlimited()),
            Some(2)
        );
        assert_eq!(
            dense.span_sum_value_success(b"aaaaa", ReduceLimits::unlimited()),
            Some(3)
        );
    }

    #[test]
    fn amortized_exact_literal_run_matches_receipt_bearing_reducer() {
        const LOWER: &[(u8, u8)] = &[(b'a', b'z')];
        const S: &[(u8, u8)] = &[(b's', b's')];
        const H: &[(u8, u8)] = &[(b'h', b'h')];
        const I: &[(u8, u8)] = &[(b'i', b'i')];
        const N: &[(u8, u8)] = &[(b'n', b'n')];
        const G: &[(u8, u8)] = &[(b'g', b'g')];
        let predicates = [LOWER, S, H, I, N, G];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        let mut haystack = vec![b'!'; 32_768];
        for start in (31..haystack.len() - predicates.len()).step_by(997) {
            haystack[start..start + predicates.len()].copy_from_slice(b"ashing");
        }
        // Exercise false literal candidates and adjacent accepted words.
        haystack[4_000..4_006].copy_from_slice(b"!shing");
        haystack[8_000..8_012].copy_from_slice(b"ashingbshing");

        let literal = plan
            .amortized_exact_literal_run(haystack.len())
            .expect("long exact suffix should amortize its mask census");
        assert_eq!(literal.offset, 1);
        assert_eq!(&literal.bytes[..literal.len], b"shing");
        let expected = plan
            .count(&haystack, ReduceLimits::unlimited())
            .unwrap()
            .count;
        assert_eq!(expected, naive_count(&haystack, &predicates));
        assert_eq!(
            plan.count_value_success(&haystack, ReduceLimits::unlimited()),
            Some(expected)
        );
        assert_eq!(
            plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
            expected.checked_mul(u64::try_from(predicates.len()).unwrap())
        );

        let below_amortization = plan
            .width
            .checked_mul(MASK_SLOTS)
            .and_then(|value| value.checked_mul(COUNT_VALUE_LITERAL_RUN_AMORTIZATION))
            .and_then(|value| value.checked_sub(1))
            .unwrap();
        assert!(
            plan.amortized_exact_literal_run(below_amortization)
                .is_none()
        );

        let folded =
            FixedPredicateWord64Plan::build(&[A, B, A, B], BuildLimits::unlimited()).unwrap();
        assert!(folded.amortized_exact_literal_run(usize::MAX).is_none());
    }

    #[test]
    fn general_predicate_pair_matches_exhaustive_short_reference_and_resets_on_accept() {
        const LEFT: &[(u8, u8)] = &[(b'a', b'c')];
        const RIGHT: &[(u8, u8)] = &[(b'd', b'f')];
        let predicates = [LEFT, RIGHT];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        let alphabet = [b'a', b'b', b'c', b'd', b'e', b'f', b'x'];
        assert_eq!(
            plan.operation_identity(Operation::Count).reducer,
            Reducer::ShiftAnd
        );
        assert!(
            plan.operation_identity(Operation::Count)
                .primary_finder
                .is_some()
        );
        for length in 0..=5 {
            let cases = alphabet.len().pow(u32::try_from(length).unwrap());
            for mut ordinal in 0..cases {
                let mut haystack = vec![0_u8; length];
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                let expected = naive_count(&haystack, &predicates);
                let count = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
                let sum = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(count.count, expected, "haystack={haystack:?}");
                assert_eq!(sum.span_sum, expected.checked_mul(2).unwrap());
                assert_eq!(
                    plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                    Some(expected),
                    "compact count haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
                    expected.checked_mul(2),
                    "compact span sum haystack={haystack:?}"
                );
                assert_eq!(
                    count.accounting.actual.transitions,
                    count
                        .accounting
                        .actual
                        .finder_scanned_bytes
                        .checked_add(count.accounting.actual.shift_and_transitions)
                        .unwrap()
                );
                assert!(actual_within_upper(
                    count.accounting.actual,
                    count.accounting.upper_bounds
                ));
            }
        }
    }

    #[test]
    fn one_byte_anchor_compact_values_match_exhaustive_reference() {
        const LEFT: &[(u8, u8)] = &[(b'b', b'd')];
        const ANCHOR: &[(u8, u8)] = &[(b'a', b'a')];
        const RIGHT: &[(u8, u8)] = &[(b'c', b'e')];
        let predicates = [LEFT, ANCHOR, RIGHT];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            plan.operation_identity(Operation::Count).reducer,
            Reducer::OneByteAnchor
        );
        let alphabet = [b'a', b'b', b'c', b'd', b'e', b'x', 0xFF];
        for length in 0..=6 {
            let cases = alphabet.len().pow(u32::try_from(length).unwrap());
            for mut ordinal in 0..cases {
                let mut haystack = vec![0_u8; length];
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                let expected = naive_count(&haystack, &predicates);
                assert_eq!(
                    plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                    Some(expected),
                    "compact count haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
                    expected.checked_mul(3),
                    "compact span sum haystack={haystack:?}"
                );
                assert_eq!(
                    plan.count(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected,
                    "receipt count haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn secondary_exact_anchor_rejects_false_candidates_before_broad_predicates() {
        const LOWER: &[(u8, u8)] = &[(b'a', b'z')];
        const S: &[(u8, u8)] = &[(b's', b's')];
        const H: &[(u8, u8)] = &[(b'h', b'h')];
        const I: &[(u8, u8)] = &[(b'i', b'i')];
        const N: &[(u8, u8)] = &[(b'n', b'n')];
        const G: &[(u8, u8)] = &[(b'g', b'g')];
        let predicates = [LOWER, S, H, I, N, G];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        let identity = plan.operation_identity(Operation::Count);
        assert_eq!(identity.reducer, Reducer::OneByteAnchor);
        assert_eq!(identity.anchor_offset, 5);
        assert_eq!(identity.anchor_bytes, [b'g', 0]);
        assert_eq!(
            identity.secondary_anchor,
            Some(ExactAnchorIdentity {
                reducer: Reducer::OneByteAnchor,
                offset: 2,
                bytes: [b'h', 0],
            })
        );
        assert_eq!(identity.verification_predicates, 5);
        assert_eq!(
            plan.secondary_anchor,
            Some(Anchor::One {
                offset: 2,
                byte: b'h',
            })
        );

        // Each primary `g` anchor fails the selective `h` check immediately.
        // The preceding broad [a-z] predicate is never consulted.
        let haystack = b"aaaaagaaaaag";
        let counted = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
        assert_eq!(counted.count, 0);
        assert_eq!(counted.accounting.actual.anchor_candidates, 2);
        assert_eq!(counted.accounting.actual.predicate_checks, 2);
        assert_eq!(
            plan.count_value_success(haystack, ReduceLimits::unlimited()),
            Some(0)
        );
        assert_eq!(
            plan.span_sum_value_success(haystack, ReduceLimits::unlimited()),
            Some(0)
        );

        let matching = b"ashing bshing zshing";
        let expected = naive_count(matching, &predicates);
        assert_eq!(expected, 3);
        assert_eq!(
            plan.count_value_success(matching, ReduceLimits::unlimited()),
            Some(expected)
        );
        assert_eq!(
            plan.span_sum_value_success(matching, ReduceLimits::unlimited()),
            expected.checked_mul(6)
        );
    }

    #[test]
    fn count_value_anchor_sample_matches_random_and_phased_byte_oracle() {
        const LOWER: &[(u8, u8)] = &[(b'a', b'z')];
        const S: &[(u8, u8)] = &[(b's', b's')];
        const H: &[(u8, u8)] = &[(b'h', b'h')];
        const I: &[(u8, u8)] = &[(b'i', b'i')];
        const N: &[(u8, u8)] = &[(b'n', b'n')];
        const G: &[(u8, u8)] = &[(b'g', b'g')];
        const T_FOLD: &[(u8, u8)] = &[(b'T', b'T'), (b't', b't')];
        const W_FOLD: &[(u8, u8)] = &[(b'W', b'W'), (b'w', b'w')];
        const A_FOLD: &[(u8, u8)] = &[(b'A', b'A'), (b'a', b'a')];
        const I_FOLD: &[(u8, u8)] = &[(b'I', b'I'), (b'i', b'i')];
        const N_FOLD: &[(u8, u8)] = &[(b'N', b'N'), (b'n', b'n')];
        let shing = [LOWER, S, H, I, N, G];
        let twain = [T_FOLD, W_FOLD, A_FOLD, I_FOLD, N_FOLD];
        let cases: [(&[&[(u8, u8)]], &[u8], &[u8], &[u8], u8); 2] = [
            (shing.as_slice(), b"ahaaag", b"ashing", b"aaaaaaaaaaaaaaaag", b'h'),
            (twain.as_slice(), b"xwxxx", b"Twain", b"xxxxxxxxxxxxxxxxw", b'n'),
        ];
        let mut random = 0x9E37_79B9_7F4A_7C15_u64;

        for (predicates, false_unit, match_unit, sparse_unit, fallback_byte) in cases {
            let plan = FixedPredicateWord64Plan::build(predicates, BuildLimits::unlimited())
                .expect("sampled anchor plan");
            assert!(plan.adaptive_fallback.is_some());
            let identity = plan.operation_identity(Operation::Count);
            for case in 0..512_usize {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let length = 256 + usize::try_from(random % 2_049).unwrap();
                let mut haystack = vec![0_u8; length];
                let unit = match case % 5 {
                    1 => Some(false_unit),
                    2 => Some(match_unit),
                    3 => Some(sparse_unit),
                    _ => None,
                };
                if let Some(unit) = unit {
                    for (index, byte) in haystack.iter_mut().enumerate() {
                        *byte = unit[index % unit.len()];
                    }
                } else if case % 5 == 4 {
                    haystack.fill(fallback_byte);
                    let island = false_unit.len().checked_mul(8).unwrap().min(length);
                    for (index, byte) in haystack[..island].iter_mut().enumerate() {
                        *byte = false_unit[index % false_unit.len()];
                    }
                } else {
                    for byte in &mut haystack {
                        random = random
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(1_442_695_040_888_963_407);
                        *byte = random.to_le_bytes()[0];
                    }
                }
                let invalid = [0xF0, 0x28, 0x8C, 0x28, 0xFF];
                let invalid_at = length / 2;
                haystack[invalid_at..invalid_at + invalid.len()].copy_from_slice(&invalid);

                let expected = naive_count(&haystack, predicates);
                assert_eq!(
                    plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                    Some(expected),
                    "case={case} bytes={length} predicates={predicates:?}"
                );
                let receipted = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(receipted.count, expected);
                assert_eq!(receipted.accounting.identity, identity);
                assert!(actual_within_upper(
                    receipted.accounting.actual,
                    receipted.accounting.upper_bounds
                ));
            }
        }
    }

    #[test]
    fn partially_overlapping_predicates_match_the_reference() {
        const LEFT: &[(u8, u8)] = &[(b'a', b'b')];
        const RIGHT: &[(u8, u8)] = &[(b'b', b'c')];
        let predicates = [LEFT, RIGHT];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        let alphabet = [b'a', b'b', b'c', b'x'];
        for length in 0..=5 {
            let cases = alphabet.len().pow(u32::try_from(length).unwrap());
            for mut ordinal in 0..cases {
                let mut haystack = vec![0_u8; length];
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                assert_eq!(
                    plan.count(&haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    naive_count(&haystack, &predicates),
                    "haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn sherlock_shape_accepts_all_cases_for_count_and_span_sum() {
        const S: &[(u8, u8)] = &[(b'S', b'S'), (b's', b's')];
        const H: &[(u8, u8)] = &[(b'H', b'H'), (b'h', b'h')];
        const E: &[(u8, u8)] = &[(b'E', b'E'), (b'e', b'e')];
        const R: &[(u8, u8)] = &[(b'R', b'R'), (b'r', b'r')];
        const L: &[(u8, u8)] = &[(b'L', b'L'), (b'l', b'l')];
        const O: &[(u8, u8)] = &[(b'O', b'O'), (b'o', b'o')];
        const C: &[(u8, u8)] = &[(b'C', b'C'), (b'c', b'c')];
        const K: &[(u8, u8)] = &[(b'K', b'K'), (b'k', b'k')];
        const SPACE: &[(u8, u8)] = &[(b' ', b' ')];
        const M: &[(u8, u8)] = &[(b'M', b'M'), (b'm', b'm')];
        let positions = [S, H, E, R, L, O, C, K, SPACE, H, O, L, M, E, S];
        let plan = FixedPredicateWord64Plan::build(&positions, BuildLimits::unlimited()).unwrap();
        let haystack = b"xSHERLOCK HOLMES--sherlock holmes--Sherlock HolmEsx";
        let count = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
        let sum = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        assert_eq!(count.count, 3);
        assert_eq!(sum.span_sum, 45);
        assert_eq!(plan.width(), 15);
        assert_eq!(count.accounting.identity.width, 15);
        assert_eq!(count.accounting.identity.reducer, Reducer::TwoByteAnchor);
        assert_eq!(count.accounting.identity.anchor_offset, 7);
        assert_eq!(count.accounting.identity.anchor_bytes, [b'K', b'k']);
        assert!(count.accounting.actual.transitions <= haystack.len());
        assert!(count.accounting.actual.predicate_checks > 0);
        assert_eq!(count.accounting.actual.input_bytes, haystack.len());
        assert_eq!(count.accounting.actual.match_events, 3);
        assert_eq!(
            plan.count_value_success(haystack, ReduceLimits::unlimited()),
            Some(3)
        );
        assert_eq!(
            plan.span_sum_value_success(haystack, ReduceLimits::unlimited()),
            Some(45)
        );
    }

    #[test]
    fn width_and_range_semantic_boundaries_are_closed() {
        let no_positions: [&[(u8, u8)]; 0] = [];
        assert!(matches!(
            FixedPredicateWord64Plan::build(&no_positions, BuildLimits::unlimited()),
            Err(BuildError::WidthTooSmall { needed: 0, .. })
        ));
        let width_one = FixedPredicateWord64Plan::build(&[A], BuildLimits::unlimited()).unwrap();
        assert_eq!(
            width_one
                .count(b"aba", ReduceLimits::unlimited())
                .unwrap()
                .count,
            2
        );
        let empty: &[(u8, u8)] = &[];
        assert!(matches!(
            FixedPredicateWord64Plan::build(&[A, empty], BuildLimits::unlimited()),
            Err(BuildError::EmptyPosition { position: 1 })
        ));
        let reversed: &[(u8, u8)] = &[(5, 4)];
        assert!(matches!(
            FixedPredicateWord64Plan::build(&[A, reversed], BuildLimits::unlimited()),
            Err(BuildError::ReversedRange {
                position: 1,
                range: 0,
                start: 5,
                end: 4
            })
        ));
        let full_byte_range: &[(u8, u8)] = &[(0x7F, 0xFF)];
        let full_byte =
            FixedPredicateWord64Plan::build(&[A, full_byte_range], BuildLimits::unlimited())
                .unwrap();
        assert_eq!(
            full_byte
                .count(&[b'a', 0x80, b'a', 0xFF], ReduceLimits::unlimited())
                .unwrap()
                .count,
            2
        );

        let width_63 = [X; 63];
        let plan_63 = FixedPredicateWord64Plan::build(&width_63, BuildLimits::unlimited()).unwrap();
        assert_eq!(plan_63.width(), 63);
        assert_eq!(
            plan_63
                .count(&[b'x'; 63], ReduceLimits::unlimited())
                .unwrap()
                .count,
            1
        );

        let positions = [X; MAX_WIDTH];
        let plan = FixedPredicateWord64Plan::build(&positions, BuildLimits::unlimited()).unwrap();
        assert_eq!(plan.width(), MAX_WIDTH);
        assert_eq!(
            plan.count(&[b'x'; MAX_WIDTH], ReduceLimits::unlimited())
                .unwrap()
                .count,
            1
        );
        let too_wide = [X; MAX_WIDTH + 1];
        assert!(matches!(
            FixedPredicateWord64Plan::build(&too_wide, BuildLimits::unlimited()),
            Err(BuildError::WidthTooLarge {
                needed,
                maximum: MAX_WIDTH
            }) if needed == MAX_WIDTH + 1
        ));
    }

    #[test]
    fn width_one_value_projection_closes_every_prospective_limit() {
        const FULL: &[(u8, u8)] = &[(0, u8::MAX)];
        let one = FixedPredicateWord64Plan::build(&[LOWER_A], BuildLimits::unlimited()).unwrap();
        let two = FixedPredicateWord64Plan::build(&[A], BuildLimits::unlimited()).unwrap();
        let shift_and = FixedPredicateWord64Plan::build(&[FULL], BuildLimits::unlimited()).unwrap();
        let haystack = [b'a', b'A', b'x', 0, u8::MAX];

        for (plan, expected, expected_work) in [
            (&one, 1_u64, 32_u64),
            (&two, 2, 32),
            (&shift_and, 5, 46),
        ] {
            let diagnostic = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
            let upper = diagnostic.accounting.upper_bounds;
            assert_eq!(upper.work, expected_work);
            let exact = ReduceLimits {
                max_input_bytes: upper.input_bytes,
                max_transitions: upper.transitions,
                max_match_events: upper.match_events,
                max_count: upper.count,
                max_span_sum: upper.span_sum,
                max_reducer_steps: upper.reducer_steps,
                max_work: upper.work,
                max_scratch_bytes: upper.scratch_bytes,
                max_persistent_bytes: upper.persistent_bytes,
                max_peak_bytes: upper.peak_bytes,
            };
            assert_eq!(plan.count_value_success(&haystack, exact), Some(expected));
            let prepared = plan
                .prepare_width_one_shift_and_count(haystack.len(), exact)
                .unwrap();
            if core::ptr::eq(plan, &shift_and) {
                let prepared = prepared.expect("width-one Shift-And plan prepares");
                assert_eq!(
                    plan.count_width_one_shift_and_prepared(&haystack, prepared),
                    Some(expected)
                );
                assert_eq!(
                    plan.count_width_one_shift_and_prepared(
                        &haystack[..haystack.len() - 1],
                        prepared
                    ),
                    None,
                    "prepared input length is immutable"
                );
            } else {
                assert_eq!(prepared, None, "anchored width-one plan stays incumbent");
            }
            assert_eq!(
                plan.span_sum_value_success(&haystack, exact),
                Some(expected)
            );
            assert_eq!(
                plan.count_value_success(
                    &haystack,
                    ReduceLimits {
                        max_span_sum: 0,
                        ..exact
                    }
                ),
                Some(expected),
                "Count does not admit a SpanSum-only ceiling"
            );

            macro_rules! one_below {
                ($field:ident) => {{
                    assert!(exact.$field > 0, "{} must be positive", stringify!($field));
                    let one_below = ReduceLimits {
                        $field: exact.$field - 1,
                        ..exact
                    };
                    assert_eq!(
                        plan.span_sum_value_success(&haystack, one_below),
                        None,
                        "width-one projection admitted one-below {}",
                        stringify!($field)
                    );
                    assert!(
                        plan.span_sum(&haystack, one_below).is_err(),
                        "diagnostic path admitted one-below {}",
                        stringify!($field)
                    );
                }};
            }
            one_below!(max_input_bytes);
            one_below!(max_transitions);
            one_below!(max_match_events);
            one_below!(max_count);
            one_below!(max_span_sum);
            one_below!(max_reducer_steps);
            one_below!(max_work);
            one_below!(max_persistent_bytes);
            one_below!(max_peak_bytes);

            macro_rules! prepared_one_below {
                ($field:ident) => {{
                    assert!(exact.$field > 0, "{} must be positive", stringify!($field));
                    let one_below = ReduceLimits {
                        $field: exact.$field - 1,
                        ..exact
                    };
                    if core::ptr::eq(plan, &shift_and) {
                        let expected_error = plan
                            .count(&haystack, one_below)
                            .expect_err("diagnostic count must refuse one-below");
                        assert_eq!(
                            plan.prepare_width_one_shift_and_count(haystack.len(), one_below)
                                .expect_err("prepared count must refuse one-below"),
                            expected_error,
                            "prepared refusal differs for {}",
                            stringify!($field)
                        );
                    } else {
                        assert_eq!(
                            plan.prepare_width_one_shift_and_count(haystack.len(), one_below)
                                .unwrap(),
                            None
                        );
                    }
                }};
            }
            prepared_one_below!(max_input_bytes);
            prepared_one_below!(max_transitions);
            prepared_one_below!(max_match_events);
            prepared_one_below!(max_count);
            prepared_one_below!(max_reducer_steps);
            prepared_one_below!(max_work);
            prepared_one_below!(max_persistent_bytes);
            prepared_one_below!(max_peak_bytes);
        }

        let width_two = FixedPredicateWord64Plan::build(&[LOWER_A, LOWER_A], BuildLimits::unlimited())
            .unwrap();
        assert_eq!(
            width_two
                .prepare_width_one_shift_and_count(haystack.len(), ReduceLimits::unlimited())
                .unwrap(),
            None
        );
    }

    #[test]
    fn build_limits_accept_exact_and_refuse_one_below() {
        let baseline = ab_plan();
        let accounting = baseline.build_accounting();
        assert_eq!(accounting.positions, 2);
        assert_eq!(accounting.source_ranges, 4);
        assert_eq!(accounting.allocations, 0);
        assert_eq!(accounting.reserves, 0);
        assert_eq!(accounting.temporary_copies, 0);
        assert_eq!(accounting.scratch_bytes, 0);
        // P=2, R=4 and every range has one member. Construction additionally
        // reads all 256 byte-domain mask cells for each position to select the
        // smallest exact anchor. This two-position plan needs no adaptive
        // classifier because direct anchor verification is bounded by one
        // predicate check per candidate. The source-independent prospective
        // envelope includes two arbitrary classifiers because source values
        // are not read until after admission.
        assert_eq!(accounting.anchor_mask_reads, 512);
        #[cfg(any(
            feature = "static-dispatch",
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
        ))]
        assert_eq!(accounting.work_upper_bound, 2_322);
        #[cfg(not(any(
            feature = "static-dispatch",
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
        )))]
        assert_eq!(accounting.work_upper_bound, 2_320);
        assert_eq!(accounting.adaptive_classifier_build_work, 0);
        assert_eq!(accounting.work_charged, 786);
        assert!(accounting.work_charged <= accounting.work_upper_bound);

        let exact = BuildLimits {
            max_positions: accounting.positions,
            max_source_ranges: accounting.source_ranges,
            max_build_work: accounting.work_upper_bound,
            max_scratch_bytes: accounting.scratch_bytes,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
        };
        FixedPredicateWord64Plan::build(&[A, B], exact).unwrap();

        let cases = [
            (
                BuildLimits {
                    max_positions: exact.max_positions - 1,
                    ..exact
                },
                "positions",
            ),
            (
                BuildLimits {
                    max_source_ranges: exact.max_source_ranges - 1,
                    ..exact
                },
                "ranges",
            ),
            (
                BuildLimits {
                    max_build_work: exact.max_build_work - 1,
                    ..exact
                },
                "work",
            ),
            (
                BuildLimits {
                    max_persistent_bytes: exact.max_persistent_bytes - 1,
                    ..exact
                },
                "persistent",
            ),
            (
                BuildLimits {
                    max_peak_bytes: exact.max_peak_bytes - 1,
                    ..exact
                },
                "peak",
            ),
        ];
        for (limits, resource) in cases {
            let error = FixedPredicateWord64Plan::build(&[A, B], limits).unwrap_err();
            match resource {
                "positions" => assert!(matches!(error, BuildError::PositionLimit { .. })),
                "ranges" => assert!(matches!(error, BuildError::SourceRangesLimit { .. })),
                "work" => assert!(matches!(error, BuildError::WorkLimit { .. })),
                "persistent" => assert!(matches!(error, BuildError::PersistentLimit { .. })),
                "peak" => assert!(matches!(error, BuildError::PeakLimit { .. })),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn build_attempt_receipts_close_success_partial_failure_and_preflight_refusal() {
        let attempt =
            FixedPredicateWord64Plan::build_attempt(&[A, B], BuildLimits::unlimited()).unwrap();
        assert!(attempt.closes());
        let receipt = *attempt.receipt();
        let identity = receipt.identity();
        assert_eq!(identity.plan_id, PLAN_ID);
        assert_eq!(identity.algorithm_version, BUILD_ATTEMPT_ALGORITHM_VERSION);
        assert_eq!(
            identity.accounting_version,
            BUILD_ATTEMPT_ACCOUNTING_VERSION
        );
        let accounting = attempt.plan().build_accounting();
        let actual = receipt.actual();
        assert!(receipt.published());
        assert_eq!(receipt.accounting(), Some(accounting));
        assert_eq!(actual.work, accounting.work_charged);
        assert_eq!(actual.mask_zero_writes, MASK_SLOTS);
        assert_eq!(actual.position_visits, 2);
        assert_eq!(actual.range_inspections, 4);
        assert_eq!(actual.member_writes, 4);
        assert_eq!(actual.copied_bytes, 0);
        assert_eq!(
            actual.initialized_bytes,
            accounting.persistent_bytes + actual.member_writes * size_of::<u64>()
        );

        let reversed: &[(u8, u8)] = &[(5, 4)];
        let failure =
            FixedPredicateWord64Plan::build_attempt(&[A, reversed], BuildLimits::unlimited())
                .unwrap_err();
        assert!(matches!(
            failure.source(),
            BuildError::ReversedRange {
                position: 1,
                range: 0,
                start: 5,
                end: 4
            }
        ));
        assert!(failure.closes());
        let partial = failure.receipt().actual();
        assert!(!failure.receipt().published());
        assert_eq!(failure.receipt().accounting(), None);
        assert_eq!(partial.mask_zero_writes, MASK_SLOTS);
        assert_eq!(partial.position_visits, 2);
        assert_eq!(partial.range_inspections, 3);
        assert_eq!(partial.member_writes, 2);
        assert_eq!(
            partial.initialized_bytes,
            (MASK_SLOTS + partial.member_writes) * size_of::<u64>()
        );

        let persistent_bytes = accounting.persistent_bytes;
        let refusal = FixedPredicateWord64Plan::build_attempt(
            &[A, B],
            BuildLimits {
                max_persistent_bytes: persistent_bytes - 1,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(matches!(
            refusal.source(),
            BuildError::PersistentLimit { .. }
        ));
        assert!(refusal.closes());
        assert_eq!(refusal.receipt().actual(), BuildAttemptActual::default());
    }

    #[test]
    fn reduce_limits_accept_exact_and_refuse_every_nonzero_one_below() {
        let plan = ab_plan();
        let haystack = b"xxaBxxABxxab";
        let baseline = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = baseline.accounting.upper_bounds;
        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_transitions: upper.transitions,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_reducer_steps: upper.reducer_steps,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        let exact_result = plan.span_sum(haystack, exact).unwrap();
        assert_eq!(exact_result.span_sum, 6);
        assert_eq!(plan.count_value_success(haystack, exact), Some(3));
        assert_eq!(plan.span_sum_value_success(haystack, exact), Some(6));
        assert!(actual_within_upper(
            exact_result.accounting.actual,
            exact_result.accounting.upper_bounds
        ));
        assert_eq!(exact_result.accounting.upper_bounds.allocations, 0);
        assert_eq!(exact_result.accounting.upper_bounds.reserves, 0);
        assert_eq!(exact_result.accounting.upper_bounds.temporary_copies, 0);
        assert_eq!(exact_result.accounting.actual.allocations, 0);
        assert_eq!(exact_result.accounting.actual.reserves, 0);
        assert_eq!(exact_result.accounting.actual.temporary_copies, 0);
        // The rightmost two-byte predicate is the authenticated anchor. The
        // The prospective bound covers both every valid anchored start and a
        // one-way adaptive Shift-And suffix. The actual sparse stream never
        // activates that suffix.
        assert_eq!(upper.transitions, 12);
        assert_eq!(upper.finder_scanned_bytes, 11);
        assert_eq!(upper.shift_and_transitions, 12);
        assert_eq!(upper.anchor_candidates, 11);
        assert_eq!(upper.predicate_checks, 11);
        assert_eq!(upper.match_events, 6);
        assert_eq!(upper.span_sum, 12);
        assert_eq!(upper.reducer_steps, 13);
        assert_eq!(upper.work, 91);
        assert_eq!(exact_result.accounting.actual.match_events, 3);
        assert_eq!(exact_result.accounting.actual.matched_bytes, 6);
        assert_eq!(exact_result.accounting.actual.work_charged, 28);

        let count_limits = ReduceLimits {
            max_span_sum: 0,
            ..exact
        };
        assert_eq!(plan.count(haystack, count_limits).unwrap().count, 3);

        macro_rules! assert_one_below {
            ($field:ident, $variant:ident) => {
                let one_below = ReduceLimits {
                    $field: exact.$field - 1,
                    ..exact
                };
                assert_eq!(
                    plan.span_sum_value_success(haystack, one_below),
                    None,
                    "compact path admitted one-below {}",
                    stringify!($field)
                );
                assert!(matches!(
                    plan.span_sum(haystack, one_below),
                    Err(ReduceError::$variant { .. })
                ));
            };
        }
        assert_one_below!(max_input_bytes, InputLimit);
        assert_one_below!(max_transitions, TransitionsLimit);
        assert_one_below!(max_match_events, MatchEventsLimit);
        assert_one_below!(max_count, CountLimit);
        assert_one_below!(max_span_sum, SpanSumLimit);
        assert_one_below!(max_reducer_steps, ReducerStepsLimit);
        assert_one_below!(max_work, WorkLimit);
        assert_one_below!(max_persistent_bytes, PersistentLimit);
        assert_one_below!(max_peak_bytes, PeakLimit);
    }

    #[test]
    fn inclusive_full_byte_ranges_union_without_allocation() {
        const FIRST: &[(u8, u8)] = &[(0, 2), (2, 3)];
        const SECOND: &[(u8, u8)] = &[(b'a', b'c'), (0x80, 0xFF)];
        let plan =
            FixedPredicateWord64Plan::build(&[FIRST, SECOND], BuildLimits::unlimited()).unwrap();
        let result = plan
            .count(
                &[0, b'a', 2, b'b', 2, 0xFF, 3, 0x80, 4, b'a'],
                ReduceLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(result.count, 4);
        assert_eq!(plan.build_accounting().allocations, 0);
        assert_eq!(plan.build_accounting().reserves, 0);
        assert_eq!(plan.build_accounting().temporary_copies, 0);
        assert_eq!(result.accounting.upper_bounds.scratch_bytes, 0);
    }

    fn naive_find_window(
        haystack: &[u8],
        predicates: &[&[(u8, u8)]],
        window: Window,
    ) -> Option<(usize, usize)> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return None;
        }
        let width = predicates.len();
        let last = window.end().checked_sub(width)?;
        for start in window.start()..=last {
            let end = start.checked_add(width)?;
            let candidate = haystack.get(start..end)?;
            if candidate.iter().zip(predicates).all(|(&byte, ranges)| {
                ranges
                    .iter()
                    .any(|&(range_start, range_end)| range_start <= byte && byte <= range_end)
            }) {
                return Some((start, end));
            }
        }
        None
    }

    fn assert_search_case(
        plan: &FixedPredicateWord64Plan,
        predicates: &[&[(u8, u8)]],
        haystack: &[u8],
        window: Window,
    ) {
        let expected = naive_find_window(haystack, predicates, window);
        let limits = SearchLimits::unlimited();

        let (found, span_accounting) = plan.find_window(haystack, window, limits).unwrap();
        assert_eq!(
            found, expected,
            "span haystack={haystack:?}, window={window:?}"
        );
        assert_eq!(
            plan.find_window_value(haystack, window, limits).unwrap(),
            expected,
            "compact span haystack={haystack:?}, window={window:?}"
        );
        assert_eq!(span_accounting.identity.operation, SearchOperation::Span);

        let (exists, exists_accounting) = plan.is_match_window(haystack, window, limits).unwrap();
        assert_eq!(exists, expected.is_some());
        assert_eq!(
            plan.is_match_window_value(haystack, window, limits)
                .unwrap(),
            expected.is_some()
        );
        assert_eq!(
            exists_accounting.identity.operation,
            SearchOperation::Exists
        );

        let (earliest_end, earliest_accounting) =
            plan.earliest_end_window(haystack, window, limits).unwrap();
        assert_eq!(earliest_end, expected.map(|(_, end)| end));
        assert_eq!(
            earliest_accounting.identity.operation,
            SearchOperation::EarliestEnd
        );

        let (selected_end, selected_accounting) =
            plan.selected_end_window(haystack, window, limits).unwrap();
        assert_eq!(selected_end, expected.map(|(_, end)| end));
        assert_eq!(
            selected_accounting.identity.operation,
            SearchOperation::SelectedEnd
        );

        for accounting in [
            span_accounting,
            exists_accounting,
            earliest_accounting,
            selected_accounting,
        ] {
            assert_eq!(accounting.identity.plan_id, SEARCH_PLAN_ID);
            assert_eq!(accounting.identity.width, predicates.len());
            assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
            assert_eq!(accounting.actual.scratch_bytes, 0);
            ensure_search_actual_within(accounting.actual, accounting.upper_bounds).unwrap();
        }
    }

    #[test]
    fn first_match_search_matches_exhaustive_oracle_for_every_window_and_reducer() {
        const SINGLE: &[(u8, u8)] = &[(b'a', b'a')];
        const TWO: &[(u8, u8)] = &[(0, 0), (0x80, 0x80)];
        const BROAD: &[(u8, u8)] = &[(0, 0), (b'a', b'a'), (0x80, 0x80), (0xFF, 0xFF)];
        let alphabet = [0, b'a', 0x80, 0xFF];

        for width in 1..=4 {
            let mut one = vec![BROAD; width];
            one[width / 2] = SINGLE;
            let mut two = vec![BROAD; width];
            two[width / 2] = TWO;
            let shift = vec![BROAD; width];
            let broad_reducer = Reducer::ShiftAnd;
            for (predicates, expected_reducer, expected_general_primary) in [
                (one.as_slice(), Reducer::OneByteAnchor, false),
                (two.as_slice(), Reducer::TwoByteAnchor, false),
                (shift.as_slice(), broad_reducer, width > 1),
            ] {
                let plan =
                    FixedPredicateWord64Plan::build(predicates, BuildLimits::unlimited()).unwrap();
                assert_eq!(
                    plan.search_operation_identity(SearchOperation::Span)
                        .reducer,
                    expected_reducer
                );
                assert_eq!(
                    plan.search_operation_identity(SearchOperation::Span)
                        .primary_finder
                        .is_some(),
                    expected_general_primary
                );
                for length in 0_usize..=7 {
                    let cases = alphabet.len().pow(u32::try_from(length).unwrap());
                    for mut ordinal in 0..cases {
                        let mut haystack = vec![0_u8; length];
                        for byte in &mut haystack {
                            *byte = alphabet[ordinal % alphabet.len()];
                            ordinal /= alphabet.len();
                        }
                        for start in 0..=length {
                            for end in start..=length {
                                assert_search_case(
                                    &plan,
                                    predicates,
                                    &haystack,
                                    Window::new(start, end),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn first_match_search_work_limits_and_errors_are_projection_invariant() {
        const SINGLE: &[(u8, u8)] = &[(b'Q', b'Q')];
        const TWO: &[(u8, u8)] = &[(b'Q', b'Q'), (0x80, 0x80)];
        const BROAD: &[(u8, u8)] = &[(0, 2), (b'a', b'z'), (0x80, 0xFF)];
        let cases: [(&[&[(u8, u8)]], &[u8]); 3] = [
            (&[BROAD, SINGLE, BROAD], b"near-Q-nope-Qhit"),
            (&[BROAD, TWO, BROAD], b"near\x80nopeQhit"),
            (&[BROAD, BROAD, BROAD], b"---abc---"),
        ];
        for (predicates, haystack) in cases {
            let plan =
                FixedPredicateWord64Plan::build(predicates, BuildLimits::unlimited()).unwrap();
            let window = Window::full(haystack);
            let (_, accepted) = plan
                .find_window(haystack, window, SearchLimits::unlimited())
                .unwrap();
            for max_work in 0..=accepted.upper_bounds.work.saturating_add(1) {
                let limits = SearchLimits {
                    max_work,
                    max_scratch_bytes: 0,
                };
                let expected_success = max_work >= accepted.upper_bounds.work;
                let reporting_span = plan.find_window(haystack, window, limits);
                let compact_span = plan.find_window_value(haystack, window, limits);
                let reporting_exists = plan.is_match_window(haystack, window, limits);
                let compact_exists = plan.is_match_window_value(haystack, window, limits);
                let earliest = plan.earliest_end_window(haystack, window, limits);
                let selected = plan.selected_end_window(haystack, window, limits);
                assert_eq!(reporting_span.is_ok(), expected_success);
                assert_eq!(compact_span.is_ok(), expected_success);
                assert_eq!(reporting_exists.is_ok(), expected_success);
                assert_eq!(compact_exists.is_ok(), expected_success);
                assert_eq!(earliest.is_ok(), expected_success);
                assert_eq!(selected.is_ok(), expected_success);
                if !expected_success {
                    let expected = SearchError::WorkLimit {
                        needed: accepted.upper_bounds.work,
                        limit: max_work,
                    };
                    assert_eq!(reporting_span.unwrap_err(), expected);
                    assert_eq!(compact_span.unwrap_err(), expected);
                    assert_eq!(reporting_exists.unwrap_err(), expected);
                    assert_eq!(compact_exists.unwrap_err(), expected);
                    assert_eq!(earliest.unwrap_err(), expected);
                    assert_eq!(selected.unwrap_err(), expected);
                }
            }
        }

        let plan = FixedPredicateWord64Plan::build(&[BROAD], BuildLimits::unlimited()).unwrap();
        for window in [Window::new(2, 1), Window::new(0, 4)] {
            let reporting = plan.find_window(b"abc", window, SearchLimits::unlimited());
            let compact = plan.find_window_value(b"abc", window, SearchLimits::unlimited());
            let reporting_error = reporting.unwrap_err();
            let compact_error = compact.unwrap_err();
            assert_eq!(reporting_error, compact_error);
            assert!(matches!(compact_error, SearchError::InvalidWindow { .. }));
        }
    }

    #[test]
    fn first_match_unlimited_value_preflight_threshold_proves_arithmetic() {
        assert_eq!(SEARCH_VALUE_PREFLIGHT_WORK_FACTOR, 66);
        assert_eq!(SEARCH_VALUE_PREFLIGHT_WORK_SLOP, 5);
        assert_eq!(
            (u128::from(u32::MAX) - 5) / 66,
            65_075_261,
        );
        assert_eq!(
            (u128::from(u64::MAX) - 5) / 66,
            279_496_122_328_932_600,
        );
        match usize::BITS {
            32 => assert_eq!(SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES, 65_075_261),
            64 => assert_eq!(
                SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES,
                279_496_122_328_932_600,
            ),
            _ => {}
        }

        let admitted_work = SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES
            .checked_mul(SEARCH_VALUE_PREFLIGHT_WORK_FACTOR)
            .and_then(|work| work.checked_add(SEARCH_VALUE_PREFLIGHT_WORK_SLOP))
            .unwrap();
        assert!(u64::try_from(admitted_work).is_ok());
        let first_unproved = SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES
            .checked_add(1)
            .unwrap()
            .checked_mul(SEARCH_VALUE_PREFLIGHT_WORK_FACTOR)
            .and_then(|work| work.checked_add(SEARCH_VALUE_PREFLIGHT_WORK_SLOP));
        assert!(first_unproved.is_none_or(|work| u64::try_from(work).is_err()));
    }

    #[test]
    fn first_match_unlimited_value_preflight_covers_plan_shapes_and_overflow() {
        const FULL: &[(u8, u8)] = &[(0, u8::MAX)];
        const SINGLE: &[(u8, u8)] = &[(b'Q', b'Q')];
        const THREE: &[(u8, u8)] = &[(b'J', b'L')];
        const BROAD: &[(u8, u8)] = &[(0, 0x7E)];
        const FOUR: &[(u8, u8)] = &[
            (b'B', b'B'),
            (b'D', b'D'),
            (b'F', b'F'),
            (b'H', b'H'),
        ];
        const SIX: &[(u8, u8)] = &[
            (b'J', b'J'),
            (b'L', b'L'),
            (b'N', b'N'),
            (b'P', b'P'),
            (b'R', b'R'),
            (b'T', b'T'),
        ];

        let raw = FixedPredicateWord64Plan::build(&[FULL], BuildLimits::unlimited()).unwrap();
        assert!(raw.is_raw_shift_and());
        let exact =
            FixedPredicateWord64Plan::build(&[FULL, SINGLE, FULL], BuildLimits::unlimited())
                .unwrap();
        assert!(matches!(exact.anchor, Anchor::One { .. }));
        assert!(exact.adaptive_fallback.is_none());
        let adaptive = FixedPredicateWord64Plan::build(
            &[SINGLE, THREE, BROAD, BROAD, BROAD, BROAD],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(adaptive.adaptive_fallback.is_some());
        let general =
            FixedPredicateWord64Plan::build(&[FOUR, SIX], BuildLimits::unlimited()).unwrap();
        assert!(general.primary_finder.is_some());

        let mut maximum_verification = vec![BROAD; MAX_WIDTH];
        maximum_verification[MAX_WIDTH / 2] = SINGLE;
        let maximum_verification = FixedPredicateWord64Plan::build(
            maximum_verification.as_slice(),
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            maximum_verification.max_verification_predicates(),
            MAX_WIDTH - 1,
        );
        assert!(maximum_verification.adaptive_fallback.is_some());

        let threshold_window = Window::new(0, SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES);
        for plan in [&raw, &exact, &adaptive, &general, &maximum_verification] {
            plan.search_preflight(
                SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES,
                threshold_window,
                SearchLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(
                plan.search_value_preflight_validated(
                    SEARCH_VALUE_PREFLIGHT_MAX_WINDOW_BYTES,
                    SearchLimits::unlimited(),
                ),
                Ok(()),
            );
        }

        let raw_overflow_window = SEARCH_VALUE_PREFLIGHT_ARITHMETIC_MAX
            .checked_sub(MATCH_WORK + REDUCE_FINAL_WORK)
            .unwrap()
            .checked_div(TRANSITION_WORK)
            .and_then(|window| window.checked_add(1))
            .unwrap();
        let overflow_window = Window::new(0, raw_overflow_window);
        let reporting = raw.search_preflight(
            raw_overflow_window,
            overflow_window,
            SearchLimits::unlimited(),
        );
        let compact = raw.search_value_preflight_validated(
            raw_overflow_window,
            SearchLimits::unlimited(),
        );
        assert_eq!(compact, reporting.clone().map(drop));
        assert!(matches!(reporting, Err(SearchError::ArithmeticOverflow { .. })));
    }

    #[test]
    fn first_match_search_closes_width_anchor_and_byte_domain_boundaries() {
        const SINGLE: &[(u8, u8)] = &[(0xFF, 0xFF)];
        const TWO: &[(u8, u8)] = &[(0, 0), (0xFF, 0xFF)];
        const MULTI: &[(u8, u8)] = &[(0, 3), (0x40, 0x42), (0x80, 0x82), (0xFE, 0xFF)];

        for width in [63, 64] {
            let predicates = vec![MULTI; width];
            let plan =
                FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
            let mut haystack = vec![0x80; width + 4];
            haystack[2..2 + width].fill(0xFF);
            assert_search_case(
                &plan,
                &predicates,
                &haystack,
                Window::new(1, haystack.len() - 1),
            );
        }

        for anchor_offset in [0, 3, 7] {
            let mut predicates = vec![MULTI; 8];
            predicates[anchor_offset] = SINGLE;
            let plan =
                FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
            let identity = plan.search_operation_identity(SearchOperation::Span);
            assert_eq!(identity.reducer, Reducer::OneByteAnchor);
            assert_eq!(usize::from(identity.anchor_offset), anchor_offset);
            let mut haystack = vec![0x80; 24];
            haystack[5 + anchor_offset] = 0xFF;
            assert_search_case(&plan, &predicates, &haystack, Window::full(&haystack));
        }

        let two_predicates = [MULTI, MULTI, TWO, MULTI];
        let two =
            FixedPredicateWord64Plan::build(&two_predicates, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            two.search_operation_identity(SearchOperation::Span).reducer,
            Reducer::TwoByteAnchor
        );
        for haystack in [
            &[0, 0, 0, 0][..],
            &[0x80, 0x80, 0xFF, 0x80][..],
            &[0x80, 0x80, 1, 0x80, 0x80, 0x80, 0, 0x80][..],
            &[0x80, 0x80, 0x80][..],
        ] {
            assert_search_case(&two, &two_predicates, haystack, Window::full(haystack));
        }
    }

    #[test]
    fn general_pair_preserves_high_byte_width64_and_truncated_window_semantics() {
        const THREE_HIGH: &[(u8, u8)] = &[(0x80, 0x80), (0xfe, 0xff)];
        const FOUR_HIGH: &[(u8, u8)] = &[(0x90, 0x93)];
        const BROAD: &[(u8, u8)] = &[(0, 0x7e)];
        let mut predicates = vec![BROAD; 64];
        predicates[0] = FOUR_HIGH;
        predicates[63] = THREE_HIGH;
        let plan =
            FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        let identity = plan.search_operation_identity(SearchOperation::Span);
        assert_eq!(identity.reducer, Reducer::ShiftAnd);
        assert_eq!(identity.anchor_offset, 63);
        assert_eq!(
            identity.primary_finder,
            Some(AdaptiveFinderIdentity {
                kind: AdaptiveFinderKind::Three,
                offset: 63,
                cardinality: 3,
            })
        );

        let mut haystack = vec![0_u8; 140];
        for start in [3_usize, 72] {
            haystack[start] = 0x91;
            haystack[start + 63] = 0xff;
        }
        for window in [
            Window::full(&haystack),
            Window::new(1, haystack.len()),
            Window::new(3, 67),
            Window::new(4, haystack.len()),
            Window::new(72, 136),
            Window::new(73, haystack.len()),
        ] {
            assert_search_case(&plan, &predicates, &haystack, window);
        }
        assert_eq!(
            plan.count(&haystack, ReduceLimits::unlimited())
                .unwrap()
                .count,
            2
        );
        assert_eq!(
            plan.count_value_success(&haystack, ReduceLimits::unlimited()),
            Some(2)
        );
    }

    #[test]
    fn adaptive_byte_set_fallback_preserves_full_domain_and_dense_semantics() {
        const ASCII: &[(u8, u8)] = &[(0, 0x7F)];
        const ASCII_FIVE: &[(u8, u8)] = &[
            (b'B', b'B'),
            (b'D', b'D'),
            (b'F', b'F'),
            (b'H', b'H'),
            (b'J', b'J'),
        ];
        const ASCII_RANGE: &[(u8, u8)] = &[(b'A', b'D')];
        const HIGH_FIVE: &[(u8, u8)] = &[
            (b'a', b'a'),
            (b'b', b'b'),
            (b'c', b'c'),
            (b'd', b'd'),
            (0xFF, 0xFF),
        ];
        const HIGH_ANCHOR: &[(u8, u8)] = &[(0xFF, 0xFF)];
        const FULL: &[(u8, u8)] = &[(0, 0xFF)];

        for fallback_predicate in [ASCII_FIVE, HIGH_FIVE, ASCII_RANGE] {
            let predicates = [ASCII, fallback_predicate, ASCII, ASCII, HIGH_ANCHOR, FULL];
            let plan =
                FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
            let fallback = plan
                .adaptive_fallback
                .expect("a non-primary predicate supplies the adaptive classifier");
            assert_eq!(fallback.offset, 1);
            match fallback.finder {
                AdaptiveFinder::Range {
                    origin,
                    maximum_delta,
                } => {
                    assert_eq!(fallback_predicate, ASCII_RANGE);
                    assert_eq!((origin, maximum_delta), (b'A', 3));
                }
                AdaptiveFinder::Set(classifier) => {
                    assert_ne!(fallback_predicate, ASCII_RANGE);
                    assert_eq!(
                        classifier.set().contains(0xFF),
                        fallback_predicate == HIGH_FIVE
                    );
                }
                AdaptiveFinder::One(_)
                | AdaptiveFinder::Two(_, _)
                | AdaptiveFinder::Three(_, _, _)
                | AdaptiveFinder::Four(_) => {
                    panic!("five-member fallback used a tiny finder")
                }
            }
            assert_eq!(
                plan.build_accounting().adaptive_classifier_build_work,
                if fallback_predicate == ASCII_RANGE {
                    0
                } else {
                    BYTE_SET_CLASSIFIER_BUILD_WORK
                }
            );

            let no_match = vec![0xFF; 256];
            assert_eq!(
                plan.count_value_success(&no_match, ReduceLimits::unlimited()),
                Some(0)
            );
            assert_eq!(
                plan.find_window_value(
                    &no_match,
                    Window::full(&no_match),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                None
            );
            let reporting_count = plan.count(&no_match, ReduceLimits::unlimited()).unwrap();
            let (reporting_match, reporting_search) = plan
                .find_window(
                    &no_match,
                    Window::full(&no_match),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(reporting_count.count, 0);
            assert_eq!(reporting_match, None);
            assert_eq!(
                reporting_count.accounting.actual.transitions,
                reporting_count
                    .accounting
                    .actual
                    .finder_scanned_bytes
                    .checked_add(reporting_count.accounting.actual.shift_and_transitions)
                    .unwrap()
            );
            assert_eq!(
                reporting_search.actual.transitions,
                reporting_search
                    .actual
                    .finder_scanned_bytes
                    .checked_add(reporting_search.actual.shift_and_transitions)
                    .unwrap()
            );
            assert_eq!(
                reporting_count.accounting.actual.shift_and_transitions > 0,
                fallback_predicate == HIGH_FIVE
            );
            assert_eq!(
                reporting_search.actual.shift_and_transitions > 0,
                fallback_predicate == HIGH_FIVE
            );
            assert!(actual_within_upper(
                reporting_count.accounting.actual,
                reporting_count.accounting.upper_bounds,
            ));
            ensure_search_actual_within(reporting_search.actual, reporting_search.upper_bounds)
                .unwrap();

            let mut haystack = no_match;
            for start in [4_usize, 100, 196] {
                haystack[start] = b'Q';
                haystack[start + 1] = if fallback_predicate == HIGH_FIVE {
                    0xFF
                } else {
                    b'B'
                };
                haystack[start + 2] = b'Q';
                haystack[start + 3] = b'Q';
                haystack[start + 4] = 0xFF;
                haystack[start + 5] = 0xFF;
            }
            let expected = naive_count(&haystack, &predicates);
            assert_eq!(expected, 3);
            assert_eq!(
                plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                Some(expected)
            );
            assert_eq!(
                plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
                expected.checked_mul(6)
            );
            assert_eq!(
                plan.count(&haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                expected
            );
            for window in [
                Window::full(&haystack),
                Window::new(20, haystack.len()),
                Window::new(101, 196),
                Window::new(195, 201),
            ] {
                assert_search_case(&plan, &predicates, &haystack, window);
            }
        }
    }

    #[test]
    fn adaptive_finder_selects_tiny_range_and_set_representations() {
        const PRIMARY: &[(u8, u8)] = &[(0x7F, 0x7F)];
        const ONE: &[(u8, u8)] = &[(0, 0)];
        const TWO: &[(u8, u8)] = &[(0, 1)];
        const THREE: &[(u8, u8)] = &[(0, 2)];
        const FOUR: &[(u8, u8)] = &[(0, 0), (2, 2), (4, 4), (6, 6)];
        const BROAD: &[(u8, u8)] = &[(0, 0x7E)];

        for (predicate, expected_members) in [(ONE, 1), (TWO, 2), (THREE, 3), (FOUR, 4)] {
            let positions = [BROAD, predicate, BROAD, BROAD, PRIMARY];
            let plan =
                FixedPredicateWord64Plan::build(&positions, BuildLimits::unlimited()).unwrap();
            let fallback = plan.adaptive_fallback.expect("tiny fallback was retained");
            assert_eq!(fallback.offset, 1);
            assert!(matches!(
                (fallback.finder, expected_members),
                (AdaptiveFinder::One(0), 1)
                    | (AdaptiveFinder::Two(0, 1), 2)
                    | (AdaptiveFinder::Three(0, 1, 2), 3)
                    | (AdaptiveFinder::Four([0, 2, 4, 6]), 4)
            ));
            assert_eq!(plan.max_verification_predicates(), 4);
            assert_eq!(plan.build.adaptive_classifier_build_work, 0);
        }

        let mut set_words = [0_u64; 4];
        for byte in [4_u8, 129, 255] {
            set_words[usize::from(byte >> 6)] |= 1_u64 << u32::from(byte & 63);
        }
        let finders = [
            (AdaptiveFinder::One(0), 0_u8, 1_u16),
            (AdaptiveFinder::Two(0, 1), 1, 2),
            (AdaptiveFinder::Three(0, 1, 2), 2, 3),
            (AdaptiveFinder::Four([0, 1, 2, 3]), 3, 4),
            (
                AdaptiveFinder::Range {
                    origin: b'A',
                    maximum_delta: 3,
                },
                b'D',
                4,
            ),
            (
                AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(set_words))),
                255,
                3,
            ),
        ];
        for (finder, member, cardinality) in finders {
            let fallback = AdaptiveFallback {
                offset: 0,
                cardinality,
                finder,
            };
            for position in [0_usize, 15, 16, 31, 32, 39] {
                let mut bytes = [0x55_u8; 40];
                bytes[position] = member;
                let mut cursor = fallback.cursor(&bytes, bytes.len());
                assert_eq!(cursor.find(0), Some(position));
            }
            let bytes = [0x55; 40];
            let mut cursor = fallback.cursor(&bytes, bytes.len());
            assert_eq!(cursor.find(0), None);
        }
    }

    #[test]
    fn identities_distinguish_complete_adaptive_strategy() {
        const PRIMARY: &[(u8, u8)] = &[(0x7F, 0x7F)];
        const BROAD: &[(u8, u8)] = &[(0, 0x7E)];
        const FOUR: &[(u8, u8)] = &[(0, 0), (2, 2), (4, 4), (6, 6)];
        const RANGE: &[(u8, u8)] = &[(0, 3)];
        const SET: &[(u8, u8)] = &[(0, 0), (2, 2), (4, 4), (6, 6), (8, 8)];
        let build = |fallback| {
            FixedPredicateWord64Plan::build(
                &[BROAD, fallback, BROAD, BROAD, PRIMARY],
                BuildLimits::unlimited(),
            )
            .unwrap()
        };
        let four = build(FOUR);
        let range = build(RANGE);
        let set = build(SET);
        let four_identity = four.operation_identity(Operation::Count);
        let range_identity = range.operation_identity(Operation::Count);
        let set_identity = set.operation_identity(Operation::Count);

        for identity in [four_identity, range_identity, set_identity] {
            assert_eq!(identity.reducer, Reducer::OneByteAnchor);
            assert_eq!(identity.anchor_offset, 4);
            assert_eq!(identity.anchor_bytes, [0x7F, 0]);
            assert_eq!(identity.primary_finder, None);
            assert_eq!(identity.general_primary_scan, None);
            assert_eq!(identity.general_fallback_scan, None);
            assert_eq!(identity.secondary_anchor, None);
            assert_eq!(identity.verification_predicates, 4);
        }
        let adaptive_finder = |identity: OperationIdentity| match identity.adaptive_handoff {
            AdaptiveHandoffIdentity::Finder {
                finder,
                final_shift_and: true,
            } => finder,
            other => panic!("expected finder-to-Shift-And identity, got {other:?}"),
        };
        assert_eq!(
            adaptive_finder(four_identity),
            AdaptiveFinderIdentity {
                kind: AdaptiveFinderKind::Four,
                offset: 1,
                cardinality: 4,
            }
        );
        assert_eq!(
            adaptive_finder(range_identity),
            AdaptiveFinderIdentity {
                kind: AdaptiveFinderKind::Range,
                offset: 1,
                cardinality: 4,
            }
        );
        let set_finder = adaptive_finder(set_identity);
        assert_eq!(set_finder.kind, AdaptiveFinderKind::Set);
        assert_eq!(set_finder.offset, 1);
        assert_eq!(set_finder.cardinality, 5);
        assert_ne!(four_identity, range_identity);
        assert_ne!(four_identity, set_identity);
        assert_ne!(range_identity, set_identity);
        assert_eq!(
            four.search_operation_identity(SearchOperation::Span)
                .adaptive_handoff,
            four_identity.adaptive_handoff
        );
    }

    #[test]
    fn identity_disables_adaptation_without_verification_predicates() {
        const PRIMARY: &[(u8, u8)] = &[(b'Q', b'Q')];
        const FULL: &[(u8, u8)] = &[(0, 0xFF)];
        let plan =
            FixedPredicateWord64Plan::build(&[FULL, PRIMARY, FULL, FULL], BuildLimits::unlimited())
                .unwrap();
        let aggregate = plan.operation_identity(Operation::Count);
        let search = plan.search_operation_identity(SearchOperation::Span);
        assert_eq!(aggregate.verification_predicates, 0);
        assert_eq!(aggregate.primary_finder, None);
        assert_eq!(aggregate.general_primary_scan, None);
        assert_eq!(aggregate.general_fallback_scan, None);
        assert_eq!(aggregate.secondary_anchor, None);
        assert_eq!(
            aggregate.adaptive_handoff,
            AdaptiveHandoffIdentity::Disabled
        );
        assert_eq!(search.verification_predicates, 0);
        assert_eq!(search.primary_finder, None);
        assert_eq!(search.general_primary_scan, None);
        assert_eq!(search.general_fallback_scan, None);
        assert_eq!(search.secondary_anchor, None);
        assert_eq!(search.adaptive_handoff, AdaptiveHandoffIdentity::Disabled);
    }

    #[test]
    fn identity_authenticates_general_primary_and_secondary_finders() {
        const THREE: &[(u8, u8)] = &[(b'a', b'c')];
        const FOUR: &[(u8, u8)] = &[(b'W', b'Z')];
        const BROAD: &[(u8, u8)] = &[(0, 0x7e)];
        let plan = FixedPredicateWord64Plan::build(
            &[BROAD, FOUR, BROAD, THREE],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let aggregate = plan.operation_identity(Operation::Count);
        let search = plan.search_operation_identity(SearchOperation::Span);
        let expected_primary = AdaptiveFinderIdentity {
            kind: AdaptiveFinderKind::Three,
            offset: 3,
            cardinality: 3,
        };
        let expected_secondary = AdaptiveFinderIdentity {
            kind: AdaptiveFinderKind::Range,
            offset: 1,
            cardinality: 4,
        };
        assert_eq!(aggregate.reducer, Reducer::ShiftAnd);
        assert_eq!(aggregate.anchor_offset, 3);
        assert_eq!(aggregate.anchor_bytes, [0, 0]);
        assert_eq!(aggregate.primary_finder, Some(expected_primary));
        assert_eq!(
            plan.general_primary_scan_identity(),
            Some(GeneralPrimaryScanIdentity::Memchr3)
        );
        assert_eq!(
            aggregate.general_primary_scan,
            plan.general_primary_scan_identity()
        );
        assert_eq!(
            search.general_primary_scan,
            plan.general_primary_scan_identity()
        );
        assert_eq!(aggregate.secondary_anchor, None);
        assert_eq!(aggregate.verification_predicates, 3);
        assert_eq!(search.primary_finder, Some(expected_primary));
        assert_eq!(plan.general_fallback_scan_identity(), None);
        assert_eq!(
            aggregate.general_fallback_scan,
            plan.general_fallback_scan_identity()
        );
        assert_eq!(
            search.general_fallback_scan,
            plan.general_fallback_scan_identity()
        );
        assert_eq!(
            aggregate.adaptive_handoff,
            AdaptiveHandoffIdentity::Finder {
                finder: expected_secondary,
                final_shift_and: true,
            }
        );
        assert_eq!(search.adaptive_handoff, aggregate.adaptive_handoff);
    }

    #[test]
    fn derived_scan_modes_do_not_expand_hot_accounting() {
        assert!(size_of::<GeneralPrimaryScanIdentity>() <= 1);
        assert!(size_of::<GeneralFallbackScanIdentity>() <= 1);
        assert!(size_of::<OperationIdentity>() <= 256);
        assert!(size_of::<SearchOperationIdentity>() <= 256);
        assert!(size_of::<FixedPredicateWord64Plan>() <= 4_096);
    }

    #[test]
    fn operation_identities_stage_all_byte_domains_under_the_same_vector_selection() {
        const ASCII: &[(u8, u8)] = &[
            (b'A', b'A'),
            (b'C', b'C'),
            (b'E', b'E'),
            (b'G', b'G'),
        ];
        const HIGH: &[(u8, u8)] = &[(0x80, 0x80), (0x82, 0x82), (0x84, 0x84), (0x86, 0x86)];
        let ascii = FixedPredicateWord64Plan::build(&[ASCII, ASCII], BuildLimits::unlimited())
            .unwrap();
        let high =
            FixedPredicateWord64Plan::build(&[HIGH, HIGH], BuildLimits::unlimited()).unwrap();

        for plan in [&ascii, &high] {
            let aggregate = plan.operation_identity(Operation::Count);
            let search = plan.search_operation_identity(SearchOperation::Span);
            assert_eq!(
                aggregate.general_primary_scan,
                plan.general_primary_scan_identity()
            );
            assert_eq!(
                aggregate.general_fallback_scan,
                plan.general_fallback_scan_identity()
            );
            assert_eq!(search.general_primary_scan, aggregate.general_primary_scan);
            assert_eq!(
                search.general_fallback_scan,
                aggregate.general_fallback_scan
            );
        }

        assert_eq!(
            high.general_primary_scan_identity(),
            ascii.general_primary_scan_identity()
        );
        assert_eq!(
            high.general_fallback_scan_identity(),
            ascii.general_fallback_scan_identity()
        );
    }

    #[test]
    fn general_pair_cardinality_boundary_selects_staged_and_direct_kernel_routes() {
        const SELECTIVE: &[(u8, u8)] = &[(b'a', b'c')];
        const FOUR: &[(u8, u8)] = &[(0, 3)];
        const AT_LIMIT: &[(u8, u8)] = &[(0, 63)];
        const OVER_LIMIT: &[(u8, u8)] = &[(0, 64)];
        const BROAD: &[(u8, u8)] = &[(0, 0x7e)];
        const FULL: &[(u8, u8)] = &[(0, 0xff)];
        let admitted =
            FixedPredicateWord64Plan::build(&[SELECTIVE, AT_LIMIT], BuildLimits::unlimited())
                .unwrap();
        assert_eq!(
            admitted
                .operation_identity(Operation::Count)
                .primary_finder
                .unwrap()
                .kind,
            AdaptiveFinderKind::Three
        );

        for predicates in [&[FOUR, FOUR][..], &[AT_LIMIT, AT_LIMIT][..]] {
            let plan =
                FixedPredicateWord64Plan::build(predicates, BuildLimits::unlimited()).unwrap();
            let identity = plan.operation_identity(Operation::Count);
            assert_eq!(identity.reducer, Reducer::ShiftAnd);
            assert_ne!(identity.primary_finder.unwrap().kind, AdaptiveFinderKind::Three);
            assert!(matches!(
                identity.adaptive_handoff,
                AdaptiveHandoffIdentity::Finder { .. }
            ));
        }

        for predicates in [
            &[SELECTIVE, FULL][..],
            &[SELECTIVE, OVER_LIMIT][..],
            &[OVER_LIMIT, OVER_LIMIT][..],
            &[BROAD, BROAD][..],
        ] {
            let plan =
                FixedPredicateWord64Plan::build(predicates, BuildLimits::unlimited()).unwrap();
            let identity = plan.operation_identity(Operation::Count);
            assert_eq!(identity.reducer, Reducer::ShiftAnd);
            assert_eq!(identity.primary_finder, None);
            assert_eq!(identity.adaptive_handoff, AdaptiveHandoffIdentity::Disabled);
        }
    }

    #[test]
    fn wider_general_pair_covers_search_retained_and_aggregate_surfaces() {
        const LEFT: &[(u8, u8)] = &[(1, 1), (3, 3), (5, 5), (7, 7)];
        const RIGHT: &[(u8, u8)] = &[(2, 2), (4, 4), (6, 6), (8, 8)];
        let predicates = [LEFT, RIGHT];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        let identity = plan.operation_identity(Operation::Count);
        assert_eq!(identity.reducer, Reducer::ShiftAnd);
        assert_eq!(
            identity.primary_finder.unwrap().kind,
            AdaptiveFinderKind::Four
        );
        assert_eq!(
            identity.general_primary_scan,
            plan.general_primary_scan_identity()
        );
        assert_eq!(
            identity.general_fallback_scan,
            plan.general_fallback_scan_identity()
        );
        let search_identity = plan.search_operation_identity(SearchOperation::Span);
        assert_eq!(
            search_identity.general_primary_scan,
            identity.general_primary_scan
        );
        assert_eq!(
            search_identity.general_fallback_scan,
            identity.general_fallback_scan
        );
        assert!(matches!(
            identity.adaptive_handoff,
            AdaptiveHandoffIdentity::Finder { .. }
        ));

        let haystack = [9_u8, 1, 2, 3, 4, 9, 5, 6, 7, 8];
        assert_search_case(&plan, &predicates, &haystack, Window::full(&haystack));

        let mut retained = plan.search_cursor(&haystack);
        let (first, first_accounting) = retained
            .find_window(Window::full(&haystack), SearchLimits::unlimited())
            .unwrap();
        assert_eq!(first, Some((1, 3)));
        assert!(first_accounting.actual.finder_scanned_bytes > 0);
        assert_eq!(
            retained.phase,
            match plan.general_primary_scan_identity() {
                Some(GeneralPrimaryScanIdentity::CompiledWholeSlice) => {
                    RetainedSearchPhase::Primary
                }
                Some(GeneralPrimaryScanIdentity::DirectCandidateStream) => {
                    RetainedSearchPhase::CandidateStream
                }
                other => panic!("unexpected wider primary scan mode: {other:?}"),
            }
        );
        assert_eq!(
            retained
                .find_window(
                    Window::new(3, haystack.len()),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((3, 5))
        );

        let count = plan
            .count(&haystack, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(count.count, 4);
        assert_eq!(
            plan.count_value_success(&haystack, ReduceLimits::unlimited()),
            Some(4)
        );
        let span = plan
            .span_sum(&haystack, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(span.span_sum, 8);
        assert_eq!(
            plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
            Some(8)
        );
        assert!(actual_within_upper(
            count.accounting.actual,
            count.accounting.upper_bounds
        ));
        assert!(actual_within_upper(
            span.accounting.actual,
            span.accounting.upper_bounds
        ));
    }

    #[test]
    fn classified_general_fallback_skip_threads_every_plan_surface() {
        const FOUR: &[(u8, u8)] = &[
            (b'B', b'B'),
            (b'D', b'D'),
            (b'F', b'F'),
            (b'H', b'H'),
        ];
        const RANGE: &[(u8, u8)] = &[(b'B', b'E')];
        const SET: &[(u8, u8)] = &[
            (b'B', b'B'),
            (b'D', b'D'),
            (b'F', b'F'),
            (b'H', b'H'),
            (b'X', b'X'),
        ];
        const FALLBACK: &[(u8, u8)] = &[
            (b'J', b'J'),
            (b'L', b'L'),
            (b'N', b'N'),
            (b'P', b'P'),
            (b'R', b'R'),
            (b'T', b'T'),
        ];

        for (primary_ranges, expected_kind) in [
            (FOUR, AdaptiveFinderKind::Four),
            (RANGE, AdaptiveFinderKind::Range),
            (SET, AdaptiveFinderKind::Set),
        ] {
            let predicates = [primary_ranges, FALLBACK];
            let plan =
                FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
            let primary = plan.primary_finder.as_ref().unwrap();
            let fallback = plan.adaptive_fallback.as_ref().unwrap();
            assert_eq!(primary.identity().kind, expected_kind);
            assert!(primary.matches(b'B'));
            assert!(fallback.matches(b'J'));
            assert_ne!(primary.offset, fallback.offset);

            let last_rejected_start = (ADAPTIVE_FALLBACK_REJECTIONS - 1) * 3;
            let candidate_stream_start = last_rejected_start + 1;
            let decoy_start = candidate_stream_start + 2;
            let target = candidate_stream_start + BYTE_SET_BLOCK_BYTES + 80;
            let legal_start_end = target + 1;
            let mut haystack = vec![0xff; legal_start_end + plan.width() - 1];
            for rejected in 0..ADAPTIVE_FALLBACK_REJECTIONS {
                let start = rejected * 3;
                haystack[start + usize::from(primary.offset)] = b'B';
            }
            haystack[decoy_start + usize::from(primary.offset)] = b'B';
            haystack[target + usize::from(primary.offset)] = b'B';
            haystack[target + usize::from(fallback.offset)] = b'J';
            let expected = Some((target, target + plan.width()));

            assert_eq!(
                plan.find_window_value(
                    &haystack,
                    Window::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                expected
            );
            let (reported, search) = plan
                .find_window(
                    &haystack,
                    Window::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(reported, expected);

            let mut retained = plan.search_cursor(&haystack);
            let (resumed, retained_accounting) = retained
                .find_window(Window::full(&haystack), SearchLimits::unlimited())
                .unwrap();
            assert_eq!(resumed, expected);

            let count = plan
                .count(&haystack, ReduceLimits::unlimited())
                .unwrap();
            let span = plan
                .span_sum(&haystack, ReduceLimits::unlimited())
                .unwrap();
            assert_eq!(count.count, 1);
            assert_eq!(span.span_sum, u64::try_from(plan.width()).unwrap());
            assert_eq!(
                plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                Some(1)
            );
            assert_eq!(
                plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
                Some(u64::try_from(plan.width()).unwrap())
            );

            if plan.general_fallback_scan_identity().is_some() {
                assert_eq!(
                    plan.general_primary_scan_identity(),
                    Some(GeneralPrimaryScanIdentity::CompiledWholeSlice)
                );
                assert_eq!(retained.phase, RetainedSearchPhase::CandidateStream);
                assert!(retained.block.start <= target && target < retained.block.end);
                assert!(
                    search.actual.finder_scanned_bytes > search.actual.predicate_checks,
                    "search did not account the fallback-empty bulk skip for {expected_kind:?}"
                );
                assert!(
                    retained_accounting.actual.finder_scanned_bytes
                        > retained_accounting.actual.predicate_checks,
                    "retained search did not account the fallback-empty bulk skip for {expected_kind:?}"
                );
                assert!(
                    count.accounting.actual.finder_scanned_bytes
                        > count.accounting.actual.predicate_checks,
                    "count did not account the fallback-empty bulk skip for {expected_kind:?}"
                );
                assert!(
                    span.accounting.actual.finder_scanned_bytes
                        > span.accounting.actual.predicate_checks,
                    "span sum did not account the fallback-empty bulk skip for {expected_kind:?}"
                );
            }
        }
    }

    #[test]
    fn classified_adaptive_finder_reuses_member_lanes_across_monotone_restarts() {
        let mut set_words = [0_u64; 4];
        for byte in [b'A', b'C', 0xFF] {
            set_words[usize::from(byte >> 6)] |= 1_u64 << u32::from(byte & 63);
        }
        let finders = [
            AdaptiveFinder::Four([b'A', b'B', b'C', b'D']),
            AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(set_words))),
        ];
        let bytes = [b'A'; 40];

        for finder in &finders {
            let mut cursor = AdaptiveFinderCursor::new(finder, &bytes, bytes.len());
            for position in 0..bytes.len() {
                assert_eq!(cursor.find(position), Some(position));
                assert_eq!(
                    cursor.classified_chunks(),
                    position / BYTE_SET_BLOCK_BYTES + 1
                );
            }
            assert_eq!(cursor.find(bytes.len()), None);
            assert_eq!(cursor.classified_chunks(), 3);

            let mut cursor = AdaptiveFinderCursor::new(finder, &bytes, bytes.len());
            for (position, expected_chunks) in [(0, 1), (7, 1), (15, 1), (23, 2), (39, 3)] {
                assert_eq!(cursor.find(position), Some(position));
                assert_eq!(cursor.classified_chunks(), expected_chunks);
            }
        }
    }

    #[test]
    fn candidate_stream_intersection_matches_scalar_for_all_fallback_kinds_and_alignments() {
        let mut set_words = [0_u64; 4];
        for byte in [4_u8, 17, 64, 129, 200, 255] {
            set_words[usize::from(byte >> 6)] |= 1_u64 << u32::from(byte & 63);
        }
        let finders = [
            AdaptiveFinder::One(0),
            AdaptiveFinder::Two(0, 255),
            AdaptiveFinder::Three(1, 127, 254),
            AdaptiveFinder::Four([1, 64, 127, 254]),
            AdaptiveFinder::Range {
                origin: 73,
                maximum_delta: 31,
            },
            AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(set_words))),
        ];
        let primaries = [
            PrimaryPredicate::Exact(Anchor::One {
                offset: 2,
                byte: 17,
            }),
            PrimaryPredicate::Exact(Anchor::Two {
                offset: 2,
                first: 17,
                second: 200,
            }),
        ];
        let mut random = 0xd1b5_4a32_d192_ed03_u64;
        let mut padded = [0_u8; 128 + 31];
        for alignment in 0..=31 {
            for byte in &mut padded {
                random = random
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
                *byte = random.to_le_bytes()[0];
            }
            let bytes = &padded[alignment..alignment + 128];
            let legal_start_end = 121;
            for primary in primaries {
                for (finder_index, finder) in finders.iter().enumerate() {
                    let fallback = AdaptiveFallback {
                        offset: 6,
                        cardinality: 1,
                        finder: *finder,
                    };
                    assert_candidate_stream_sequence(
                        primary,
                        &fallback,
                        bytes,
                        legal_start_end,
                        alignment.wrapping_add(finder_index),
                    );
                }
            }
        }
    }

    #[test]
    fn candidate_stream_wide_remainders_cover_general_pair_search_surfaces() {
        const LEFT: &[(u8, u8)] = &[
            (1, 1),
            (65, 65),
            (255, 255),
        ];
        const RIGHT: &[(u8, u8)] = &[
            (2, 2),
            (18, 18),
            (66, 66),
            (130, 130),
            (200, 200),
            (254, 254),
        ];
        let predicates = [LEFT, RIGHT];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        let primary = plan.primary_finder.as_ref().unwrap();
        let fallback = plan.adaptive_fallback.as_ref().unwrap();
        assert!(matches!(primary.finder, AdaptiveFinder::Three(1, 65, 255)));
        assert!(matches!(fallback.finder, AdaptiveFinder::Set(_)));
        if primary.candidate_block_bytes() != BYTE_SET_WIDE_BLOCK_BYTES
            || fallback.candidate_block_bytes() != BYTE_SET_WIDE_BLOCK_BYTES
        {
            return;
        }

        for remainder in 17_usize..=31 {
            for candidate_positions in [
                remainder,
                BYTE_SET_WIDE_BLOCK_BYTES.checked_add(remainder).unwrap(),
            ] {
                for window_start in [0_usize, 7] {
                    let window_end = window_start
                        .checked_add(candidate_positions)
                        .and_then(|end| end.checked_add(plan.width().checked_sub(1).unwrap()))
                        .unwrap();
                    let mut haystack = vec![0_u8; window_end.checked_add(5).unwrap()];
                    let expected_start = window_start
                        .checked_add(candidate_positions.checked_sub(1).unwrap())
                        .unwrap();
                    let expected_end = expected_start.checked_add(plan.width()).unwrap();
                    haystack[expected_start] = 1;
                    haystack[expected_start + 1] = 2;
                    let window = Window::new(window_start, window_end);

                    assert_search_case(&plan, &predicates, &haystack, window);

                    let mut retained = plan.search_cursor(&haystack);
                    let (matched, accounting) = retained
                        .find_window(window, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(
                        matched,
                        Some((expected_start, expected_end)),
                        "retained candidate_positions={candidate_positions}, window_start={window_start}"
                    );
                    assert_eq!(
                        accounting.actual.finder_scanned_bytes,
                        candidate_positions,
                        "retained candidate_positions={candidate_positions}, window_start={window_start}"
                    );

                    let active = &haystack[window_start..window_end];
                    let mut stream = CandidateStreamCursor::new(
                        PrimaryPredicate::General(primary),
                        fallback,
                        active,
                        candidate_positions,
                    );
                    assert_eq!(
                        stream.find(0),
                        Some(candidate_positions - 1),
                        "stream candidate_positions={candidate_positions}, window_start={window_start}"
                    );
                    assert_eq!(stream.primary_classified_bytes(), candidate_positions);
                    assert_eq!(
                        stream.fallback_classified_bytes(),
                        remainder - BYTE_SET_BLOCK_BYTES
                    );
                    assert_eq!(
                        stream.classified_chunks(),
                        if candidate_positions < BYTE_SET_WIDE_BLOCK_BYTES {
                            2
                        } else {
                            3
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn candidate_stream_reuses_both_masks_across_rejections_and_accepted_jumps() {
        let primary = PrimaryPredicate::Exact(Anchor::One {
            offset: 0,
            byte: b'A',
        });
        let fallback = AdaptiveFallback {
            offset: 1,
            cardinality: 4,
            finder: AdaptiveFinder::Four([b'A', b'B', b'C', b'D']),
        };
        let bytes = [b'A'; 96];
        let legal_start_end = 80;
        let mut stream = CandidateStreamCursor::new(primary, &fallback, &bytes, legal_start_end);
        let block_bytes = stream.block_bytes();
        for position in 0..block_bytes {
            assert_eq!(stream.find(position), Some(position));
            assert_eq!(stream.classified_chunks(), 1);
            assert_eq!(stream.primary_classified_bytes(), block_bytes);
            assert_eq!(stream.fallback_classified_bytes(), block_bytes);
        }
        for position in (block_bytes..legal_start_end).step_by(7) {
            let prior_end = stream.block.end;
            let prior_chunks = stream.classified_chunks();
            assert_eq!(stream.find(position), Some(position));
            let expected_chunks = if position < prior_end {
                prior_chunks
            } else {
                prior_chunks + 1
            };
            assert_eq!(stream.classified_chunks(), expected_chunks);
        }
    }

    #[test]
    fn candidate_stream_skips_fallback_classification_for_empty_primary_blocks() {
        let primary = PrimaryPredicate::Exact(Anchor::One {
            offset: 0,
            byte: b'A',
        });
        let fallback = AdaptiveFallback {
            offset: 1,
            cardinality: 4,
            finder: AdaptiveFinder::Four([b'A', b'B', b'C', b'D']),
        };
        let bytes = [b'z'; 96];
        let legal_start_end = 80;
        let mut stream = CandidateStreamCursor::new(primary, &fallback, &bytes, legal_start_end);
        assert_eq!(stream.find(0), None);
        assert_eq!(stream.primary_classified_bytes(), legal_start_end);
        assert_eq!(stream.fallback_classified_bytes(), 0);
    }

    #[test]
    fn fallback_classifier_skip_resumes_at_exact_candidate_across_boundaries() {
        const PRIMARY_BYTE: u8 = b'P';
        const FALLBACK_BYTE: u8 = b'Q';

        for (primary_offset, fallback_offset) in [(0_u8, 1_u8), (1, 0)] {
            let primary_finder = AdaptiveFallback {
                offset: primary_offset,
                cardinality: 4,
                finder: AdaptiveFinder::Four([PRIMARY_BYTE, b'U', b'V', b'W']),
            };
            let fallback = AdaptiveFallback {
                offset: fallback_offset,
                cardinality: 4,
                finder: AdaptiveFinder::Range {
                    origin: FALLBACK_BYTE,
                    maximum_delta: 3,
                },
            };
            let primary = PrimaryPredicate::General(&primary_finder);

            for alignment in 0_usize..=31 {
                for (distance, trailing_candidates) in
                    [(0_usize, 16_usize), (15, 16), (16, 16), (31, 16), (32, 16), (63, 1)]
                {
                    let block_bytes = BYTE_SET_BLOCK_BYTES;
                    let target = block_bytes.checked_add(distance).unwrap();
                    let legal_start_end = target.checked_add(trailing_candidates).unwrap();
                    let source_len = legal_start_end
                        .checked_add(usize::from(primary_offset.max(fallback_offset)))
                        .unwrap();
                    let mut backing = vec![PRIMARY_BYTE; alignment + source_len];
                    let bytes = &mut backing[alignment..];
                    bytes[target + usize::from(fallback_offset)] = FALLBACK_BYTE;

                    assert_eq!(
                        reference_candidate_stream_find(
                            primary,
                            &fallback,
                            bytes,
                            0,
                            legal_start_end,
                        ),
                        Some(target)
                    );
                    let mut stream = CandidateStreamCursor::new_with_fallback_skip(
                        primary,
                        &fallback,
                        true,
                        bytes,
                        legal_start_end,
                    );
                    assert_eq!(stream.block_bytes(), BYTE_SET_BLOCK_BYTES);
                    assert_eq!(
                        stream.find(0),
                        Some(target),
                        "alignment={alignment} primary_offset={primary_offset} fallback_offset={fallback_offset} distance={distance}"
                    );
                    let resumed_block = trailing_candidates.min(BYTE_SET_BLOCK_BYTES);
                    assert_eq!(
                        stream.primary_classified_bytes(),
                        block_bytes + resumed_block
                    );
                    assert_eq!(
                        stream.fallback_classified_bytes(),
                        block_bytes + distance + resumed_block,
                        "the classifier must charge skipped candidates but not its stopping member"
                    );
                    assert_eq!(stream.classified_chunks(), 2);
                }
            }
        }
    }

    #[test]
    fn fallback_classifier_skip_terminal_and_high_byte_runs_charge_logical_service() {
        const PRIMARY_BYTE: u8 = b'P';

        for (primary_offset, fallback_offset) in [(0_u8, 1_u8), (1, 0)] {
            let primary_finder = AdaptiveFallback {
                offset: primary_offset,
                cardinality: 4,
                finder: AdaptiveFinder::Four([PRIMARY_BYTE, b'U', b'V', b'W']),
            };
            let fallback = AdaptiveFallback {
                offset: fallback_offset,
                cardinality: 4,
                finder: AdaptiveFinder::Range {
                    origin: b'Q',
                    maximum_delta: 3,
                },
            };
            let primary = PrimaryPredicate::General(&primary_finder);
            let legal_start_end = BYTE_SET_BLOCK_BYTES + 65;
            let source_len = legal_start_end
                .checked_add(usize::from(primary_offset.max(fallback_offset)))
                .unwrap();
            let bytes = vec![PRIMARY_BYTE; source_len];
            let mut stream = CandidateStreamCursor::new_with_fallback_skip(
                primary,
                &fallback,
                true,
                &bytes,
                legal_start_end,
            );
            assert_eq!(stream.find(0), None);
            assert_eq!(stream.primary_classified_bytes(), BYTE_SET_BLOCK_BYTES);
            assert_eq!(stream.fallback_classified_bytes(), legal_start_end);
            assert_eq!(stream.classified_chunks(), 1);

            let mut illegal = vec![PRIMARY_BYTE; source_len + 1];
            illegal[legal_start_end + usize::from(fallback_offset)] = b'Q';
            let mut stream = CandidateStreamCursor::new_with_fallback_skip(
                primary,
                &fallback,
                true,
                &illegal,
                legal_start_end,
            );
            assert_eq!(
                stream.find(0),
                None,
                "a fallback member at illegal candidate end must stay excluded"
            );
            assert_eq!(stream.primary_classified_bytes(), BYTE_SET_BLOCK_BYTES);
            assert_eq!(stream.fallback_classified_bytes(), legal_start_end);
        }

        let primary_finder = AdaptiveFallback {
            offset: 0,
            cardinality: 4,
            finder: AdaptiveFinder::Four([PRIMARY_BYTE, b'U', b'V', b'W']),
        };
        let fallback = AdaptiveFallback {
            offset: 1,
            cardinality: 4,
            finder: AdaptiveFinder::Range {
                origin: b'Q',
                maximum_delta: 3,
            },
        };
        let legal_start_end = BYTE_SET_BLOCK_BYTES + 65;
        let mut bytes = vec![PRIMARY_BYTE; legal_start_end + 1];
        bytes[BYTE_SET_BLOCK_BYTES + 1..legal_start_end + 1].fill(0xff);
        let mut stream = CandidateStreamCursor::new_with_fallback_skip(
            PrimaryPredicate::General(&primary_finder),
            &fallback,
            true,
            &bytes,
            legal_start_end,
        );
        assert_eq!(stream.find(0), None);
        assert_eq!(stream.primary_classified_bytes(), BYTE_SET_BLOCK_BYTES);
        assert_eq!(stream.fallback_classified_bytes(), legal_start_end);
        assert_eq!(stream.classified_chunks(), 1);
    }

    #[test]
    fn retained_candidate_block_drains_before_fallback_classifier_restart() {
        const PRIMARY_BYTE: u8 = b'P';
        const FALLBACK_BYTE: u8 = b'Q';
        let primary_finder = AdaptiveFallback {
            offset: 0,
            cardinality: 4,
            finder: AdaptiveFinder::Four([PRIMARY_BYTE, FALLBACK_BYTE, b'R', b'S']),
        };
        let fallback = AdaptiveFallback {
            offset: 1,
            cardinality: 4,
            finder: AdaptiveFinder::Range {
                origin: FALLBACK_BYTE,
                maximum_delta: 3,
            },
        };
        let block_bytes = BYTE_SET_BLOCK_BYTES;
        let late_distance = 5_usize;
        let late = block_bytes * 2 + late_distance;
        let legal_start_end = late + BYTE_SET_BLOCK_BYTES;
        let mut bytes = vec![PRIMARY_BYTE; legal_start_end + 1];
        bytes[4] = FALLBACK_BYTE;
        bytes[late + 1] = FALLBACK_BYTE;
        let primary_members = if block_bytes == usize::try_from(u32::BITS).unwrap() {
            u32::MAX
        } else {
            (1_u32 << block_bytes) - 1
        };
        let retained = CandidateStreamBlock {
            start: 0,
            end: block_bytes,
            primary_members,
            fallback_members: 1_u32 << 3,
        };
        let mut stream = CandidateStreamCursor::with_block_and_fallback_skip(
            PrimaryPredicate::General(&primary_finder),
            &fallback,
            true,
            &bytes,
            legal_start_end,
            retained,
        );

        assert_eq!(stream.find(0), Some(3));
        assert_eq!(stream.primary_classified_bytes(), 0);
        assert_eq!(stream.fallback_classified_bytes(), 0);
        assert_eq!(stream.classified_chunks(), 0);

        assert_eq!(stream.find(4), Some(late));
        assert_eq!(
            stream.fallback_classified_bytes(),
            stream.primary_classified_bytes() + late_distance
        );
        assert_eq!(stream.classified_chunks(), 2);
    }

    #[test]
    fn absent_general_primary_uses_one_memchr3_service() {
        const SMALL: &[(u8, u8)] = &[(0, 2)];
        let predicates = [SMALL, SMALL];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        assert!(plan.primary_finder.is_some());
        let haystack = [0xff; 64];
        let (matched, accounting) = plan
            .find_window(
                &haystack,
                Window::new(0, haystack.len()),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(matched, None);
        assert_eq!(accounting.actual.finder_scanned_bytes, 63);
        assert_eq!(accounting.actual.predicate_checks, 0);
        assert_eq!(accounting.actual.transitions, 63);
        assert_eq!(accounting.actual.finder_calls, 1);
        assert!(accounting.actual.work <= accounting.upper_bounds.work);
    }

    #[test]
    fn range_candidate_stream_never_widens_beyond_its_fixed_classifier() {
        let fallback = AdaptiveFallback {
            offset: 1,
            cardinality: 8,
            finder: AdaptiveFinder::Range {
                origin: b'A',
                maximum_delta: 7,
            },
        };
        let bytes = [b'A'; 64];
        let stream = CandidateStreamCursor::new(
            PrimaryPredicate::Exact(Anchor::One {
                offset: 0,
                byte: b'A',
            }),
            &fallback,
            &bytes,
            63,
        );
        assert_eq!(stream.block_bytes(), BYTE_SET_BLOCK_BYTES);

        let general_range = AdaptiveFallback {
            offset: 0,
            cardinality: 8,
            finder: AdaptiveFinder::Range {
                origin: b'A',
                maximum_delta: 7,
            },
        };
        let wide_secondary = AdaptiveFallback {
            offset: 1,
            cardinality: 4,
            finder: AdaptiveFinder::Four([b'A', b'B', b'C', b'D']),
        };
        let stream = CandidateStreamCursor::new(
            PrimaryPredicate::General(&general_range),
            &wide_secondary,
            &bytes,
            63,
        );
        assert_eq!(stream.block_bytes(), BYTE_SET_BLOCK_BYTES);
    }

    #[test]
    fn general_pair_stream_survives_sixty_four_accepted_restarts() {
        const FALLBACK: &[(u8, u8)] = &[(b'A', b'D')];
        const VERIFY: &[(u8, u8)] = &[(0, 0x7f)];
        const PRIMARY: &[(u8, u8)] = &[(b'Q', b'S')];
        let predicates = [FALLBACK, VERIFY, PRIMARY];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            plan.operation_identity(Operation::Count).reducer,
            Reducer::ShiftAnd
        );
        assert!(
            plan.operation_identity(Operation::Count)
                .primary_finder
                .is_some()
        );
        assert!(matches!(
            plan.adaptive_fallback.map(|fallback| fallback.finder),
            Some(AdaptiveFinder::Range { .. })
        ));

        let mut haystack = Vec::new();
        for _ in 0..ADAPTIVE_FALLBACK_REJECTIONS {
            haystack.extend_from_slice(&[0xff, b'!', b'Q']);
        }
        for _ in 0..64 {
            haystack.extend_from_slice(b"A!Q");
        }

        let expected = naive_count(&haystack, &predicates);
        assert_eq!(expected, 64);
        assert_eq!(
            plan.count_value_success(&haystack, ReduceLimits::unlimited()),
            Some(expected)
        );
        let result = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
        assert_eq!(result.count, expected);
        assert!(result.accounting.actual.finder_scanned_bytes > 0);
        assert!(
            result.accounting.actual.finder_scanned_bytes
                <= result.accounting.upper_bounds.finder_scanned_bytes
        );

        let mut retained = plan.search_cursor(&haystack);
        let mut start = 0_usize;
        let mut spans = Vec::new();
        let mut second_classification = None;
        loop {
            let (matched, accounting) = retained
                .find_window(
                    Window::new(start, haystack.len()),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            let Some(span) = matched else {
                break;
            };
            if spans.len() == 1 {
                second_classification = Some(accounting.actual.finder_scanned_bytes);
            }
            spans.push(span);
            start = span.1;
        }
        assert_eq!(spans.len(), 64);
        assert_eq!(second_classification, Some(0));
        assert!(spans.windows(2).all(|pair| pair[0].1 == pair[1].0));

        let mut noncontiguous = plan.search_cursor(&haystack);
        let first = noncontiguous
            .find_window(Window::full(&haystack), SearchLimits::unlimited())
            .unwrap()
            .0
            .unwrap();
        let skipped_start = first.1.checked_add(1).unwrap();
        let expected = plan
            .find_window(
                &haystack,
                Window::new(skipped_start, haystack.len()),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0;
        let actual = noncontiguous
            .find_window(
                Window::new(skipped_start, haystack.len()),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0;
        assert_eq!(actual, expected);

        let other_source = plan.search_cursor(b"A!Q");
        assert_eq!(other_source.phase, RetainedSearchPhase::Primary);
        assert_eq!(other_source.block, CandidateStreamBlock::default());
    }

    #[test]
    fn candidate_stream_capabilities_keep_distinct_plans_independent() {
        const PRIMARY: &[(u8, u8)] = &[(b'B', b'E')];
        const VERIFY: &[(u8, u8)] = &[(0, 0xff)];
        const FALLBACK_J: &[(u8, u8)] = &[(b'J', b'M'), (b'X', b'X')];
        const FALLBACK_N: &[(u8, u8)] = &[(b'N', b'Q'), (b'Y', b'Y')];
        let predicates_j = [PRIMARY, VERIFY, FALLBACK_J];
        let predicates_n = [PRIMARY, VERIFY, FALLBACK_N];
        let plan_j =
            FixedPredicateWord64Plan::build(&predicates_j, BuildLimits::unlimited()).unwrap();
        let plan_n =
            FixedPredicateWord64Plan::build(&predicates_n, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            plan_j.operation_identity(Operation::Count).reducer,
            Reducer::ShiftAnd
        );
        assert!(
            plan_j
                .operation_identity(Operation::Count)
                .primary_finder
                .is_some()
        );
        assert_eq!(
            plan_n.operation_identity(Operation::Count).reducer,
            Reducer::ShiftAnd
        );
        assert!(
            plan_n
                .operation_identity(Operation::Count)
                .primary_finder
                .is_some()
        );
        assert_eq!(
            plan_j.general_primary_scan_identity(),
            plan_n.general_primary_scan_identity()
        );
        assert_eq!(
            plan_j.general_fallback_scan_identity(),
            plan_n.general_fallback_scan_identity()
        );

        let primary_j = plan_j.primary_finder.as_ref().unwrap();
        let fallback_j = plan_j.adaptive_fallback.as_ref().unwrap();
        let primary_n = plan_n.primary_finder.as_ref().unwrap();
        let fallback_n = plan_n.adaptive_fallback.as_ref().unwrap();
        assert_eq!(primary_j.offset, primary_n.offset);
        assert_eq!(fallback_j.offset, fallback_n.offset);
        assert_ne!(fallback_j.offset, primary_j.offset);
        assert_ne!(fallback_n.offset, primary_n.offset);

        let last_rejected_start = (ADAPTIVE_FALLBACK_REJECTIONS - 1) * 3;
        let candidate_stream_start = last_rejected_start + 1;
        let decoy_start = candidate_stream_start + 2;
        let first_j = candidate_stream_start + BYTE_SET_BLOCK_BYTES + 80;
        let first_n = first_j + 3;
        let second_j = first_n + 3;
        let second_n = second_j + 3;
        let legal_start_end = second_n + 1;
        let mut haystack = vec![0xff; legal_start_end + plan_j.width() - 1];
        for rejected in 0..ADAPTIVE_FALLBACK_REJECTIONS {
            let start = rejected * 3;
            haystack[start + usize::from(primary_j.offset)] = b'B';
        }
        haystack[decoy_start + usize::from(primary_j.offset)] = b'B';
        for (start, member) in [
            (first_j, b'J'),
            (first_n, b'N'),
            (second_j, b'J'),
            (second_n, b'N'),
        ] {
            haystack[start + usize::from(primary_j.offset)] = b'B';
            haystack[start + usize::from(fallback_j.offset)] = member;
        }

        let mut cursor_j = plan_j.search_cursor(&haystack);
        let mut cursor_n = plan_n.search_cursor(&haystack);
        assert_eq!(cursor_j.haystack.as_ptr(), cursor_n.haystack.as_ptr());

        let full = Window::full(&haystack);
        let (found_j, accounting_j) = cursor_j
            .find_window(full, SearchLimits::unlimited())
            .unwrap();
        let (found_n, accounting_n) = cursor_n
            .find_window(full, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(found_j, Some((first_j, first_j + plan_j.width())));
        assert_eq!(found_n, Some((first_n, first_n + plan_n.width())));
        assert!(accounting_j.actual.finder_scanned_bytes > 0);
        assert!(accounting_n.actual.finder_scanned_bytes > 0);
        if plan_j.general_fallback_scan_identity().is_some() {
            assert_eq!(cursor_j.phase, RetainedSearchPhase::CandidateStream);
            assert_eq!(cursor_n.phase, RetainedSearchPhase::CandidateStream);
            assert!(
                accounting_j.actual.finder_scanned_bytes > accounting_j.actual.predicate_checks
            );
            assert!(
                accounting_n.actual.finder_scanned_bytes > accounting_n.actual.predicate_checks
            );
        }

        let (next_j, _) = cursor_j
            .find_window(
                Window::new(found_j.unwrap().1, haystack.len()),
                SearchLimits::unlimited(),
            )
            .unwrap();
        let (next_n, _) = cursor_n
            .find_window(
                Window::new(found_n.unwrap().1, haystack.len()),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(next_j, Some((second_j, second_j + plan_j.width())));
        assert_eq!(next_n, Some((second_n, second_n + plan_n.width())));
    }

    #[test]
    fn general_pair_same_address_mutation_uses_a_fresh_source_binding() {
        const LEFT: &[(u8, u8)] = &[(b'A', b'C'), (b'F', b'F'), (b'H', b'H')];
        const RIGHT: &[(u8, u8)] = &[(b'J', b'L'), (b'N', b'N'), (b'P', b'P'), (b'R', b'R')];
        let plan =
            FixedPredicateWord64Plan::build(&[LEFT, RIGHT], BuildLimits::unlimited()).unwrap();
        assert_eq!(
            plan.operation_identity(Operation::Count).reducer,
            Reducer::ShiftAnd
        );
        assert!(
            plan.operation_identity(Operation::Count)
                .primary_finder
                .is_some()
        );
        assert!(plan.general_primary_scan_identity().is_some());
        let primary = plan.primary_finder.as_ref().unwrap();
        let fallback = plan.adaptive_fallback.as_ref().unwrap();
        assert!(primary.matches(b'B'));
        assert!(primary.matches(b'C'));
        assert!(fallback.matches(b'J'));
        assert!(fallback.matches(b'L'));

        let last_rejected_start = (ADAPTIVE_FALLBACK_REJECTIONS - 1) * 3;
        let candidate_stream_start = last_rejected_start + 1;
        let decoy_start = candidate_stream_start + 2;
        let first_old = candidate_stream_start + BYTE_SET_BLOCK_BYTES + 80;
        let second_old = first_old + 6;
        let first_new = first_old + 3;
        let second_new = second_old + 3;
        let legal_start_end = second_new + 1;
        let make_haystack = |primary_byte: u8, fallback_byte: u8, targets: [usize; 2]| {
            let mut bytes = vec![0xff; legal_start_end + plan.width() - 1];
            for rejected in 0..ADAPTIVE_FALLBACK_REJECTIONS {
                let start = rejected * 3;
                bytes[start + usize::from(primary.offset)] = primary_byte;
            }
            bytes[decoy_start + usize::from(primary.offset)] = primary_byte;
            for target in targets {
                bytes[target + usize::from(primary.offset)] = primary_byte;
                bytes[target + usize::from(fallback.offset)] = fallback_byte;
            }
            bytes
        };

        let mut haystack = make_haystack(b'B', b'J', [first_old, second_old]);
        let address = haystack.as_ptr();
        {
            let mut cursor = plan.search_cursor(&haystack);
            let (first, accounting) = cursor
                .find_window(Window::full(&haystack), SearchLimits::unlimited())
                .unwrap();
            assert_eq!(first, Some((first_old, first_old + plan.width())));
            if plan.general_fallback_scan_identity().is_some() {
                assert_eq!(cursor.phase, RetainedSearchPhase::CandidateStream);
                assert!(accounting.actual.finder_scanned_bytes > accounting.actual.predicate_checks);
            }
            assert_eq!(
                cursor
                    .find_window(
                        Window::new(first.unwrap().1, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0,
                Some((second_old, second_old + plan.width()))
            );
        }
        let mutated = make_haystack(b'C', b'L', [first_new, second_new]);
        haystack.copy_from_slice(&mutated);
        assert_eq!(haystack.as_ptr(), address);
        let mut rebound = plan.search_cursor(&haystack);
        let (first, accounting) = rebound
            .find_window(Window::full(&haystack), SearchLimits::unlimited())
            .unwrap();
        assert_eq!(first, Some((first_new, first_new + plan.width())));
        if plan.general_fallback_scan_identity().is_some() {
            assert_eq!(rebound.phase, RetainedSearchPhase::CandidateStream);
            assert!(accounting.actual.finder_scanned_bytes > accounting.actual.predicate_checks);
        }
        assert_eq!(
            rebound
                .find_window(
                    Window::new(first.unwrap().1, haystack.len()),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((second_new, second_new + plan.width()))
        );
    }

    #[test]
    fn general_pair_drain_covers_before_at_and_after_handoff_boundary() {
        const FALLBACK: &[(u8, u8)] = &[(b'A', b'Z')];
        const VERIFY: &[(u8, u8)] = &[(0, 0x7f)];
        const PRIMARY: &[(u8, u8)] = &[(b'Q', b'S')];
        const DRAIN_BOUNDARY: usize = 54;
        let predicates = [FALLBACK, VERIFY, PRIMARY];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            plan.operation_identity(Operation::Count).reducer,
            Reducer::ShiftAnd
        );
        assert!(
            plan.operation_identity(Operation::Count)
                .primary_finder
                .is_some()
        );

        for target in [DRAIN_BOUNDARY - 1, DRAIN_BOUNDARY, DRAIN_BOUNDARY + 1] {
            let mut haystack = Vec::new();
            for _ in 0..ADAPTIVE_FALLBACK_REJECTIONS {
                haystack.extend_from_slice(&[0xff, b'!', b'Q']);
            }
            for _ in 0..ADAPTIVE_FALLBACK_REJECTIONS {
                haystack.extend_from_slice(&[b'A', 0xff, b'Q']);
            }
            haystack.resize(96, b'z');
            haystack[target..target + 3].copy_from_slice(b"A!Q");

            let mut cursor = plan.search_cursor(&haystack);
            let (matched, accounting) = cursor
                .find_window(Window::full(&haystack), SearchLimits::unlimited())
                .unwrap();
            assert_eq!(matched, Some((target, target + 3)), "target={target}");
            assert_eq!(
                plan.find_window_value(
                    &haystack,
                    Window::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                Some((target, target + 3)),
                "compact target={target}"
            );
            assert!(accounting.actual.finder_scanned_bytes > 0);
            assert!(accounting.actual.transitions <= accounting.upper_bounds.transitions);
            assert!(accounting.actual.predicate_checks <= accounting.upper_bounds.predicate_checks);

            if target == DRAIN_BOUNDARY - 1 {
                assert_eq!(cursor.phase, RetainedSearchPhase::CandidateStreamDrain);
                assert_eq!(cursor.block.end, DRAIN_BOUNDARY);
                let crossing_end = target + 3;
                assert!(crossing_end > DRAIN_BOUNDARY);
                assert_eq!(
                    cursor
                        .find_window(
                            Window::new(crossing_end, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0,
                    None,
                    "a match crossing the drain boundary must not duplicate covered starts"
                );
            }

            assert_eq!(naive_count(&haystack, &predicates), 1, "target={target}");
            assert_eq!(
                plan.count(&haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count,
                1,
                "target={target}"
            );
            assert_eq!(
                plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                Some(1),
                "compact target={target}"
            );

            let mut rebound = plan.search_cursor(&haystack);
            assert_eq!(
                rebound
                    .find_window(Window::full(&haystack), SearchLimits::unlimited())
                    .unwrap()
                    .0,
                Some((target, target + 3)),
                "a fresh binding after early drop must restart cold"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one admission test keeps reporting search, retained recovery, and both reducer projections on the same handoff witness"
    )]
    fn candidate_stream_exact_limits_one_below_and_refusal_recovery_are_closed() {
        const FALLBACK: &[(u8, u8)] = &[(b'A', b'D')];
        const VERIFY: &[(u8, u8)] = &[(0, 0x7f)];
        const PRIMARY: &[(u8, u8)] = &[(b'Q', b'S')];
        let predicates = [FALLBACK, VERIFY, PRIMARY];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        assert_eq!(
            plan.operation_identity(Operation::Count).reducer,
            Reducer::ShiftAnd
        );
        assert!(
            plan.operation_identity(Operation::Count)
                .primary_finder
                .is_some()
        );
        let mut haystack = Vec::new();
        for _ in 0..ADAPTIVE_FALLBACK_REJECTIONS {
            haystack.extend_from_slice(&[0xff, b'!', b'Q']);
        }
        for _ in 0..ADAPTIVE_FALLBACK_REJECTIONS {
            haystack.extend_from_slice(&[b'A', 0xff, b'Q']);
        }
        for _ in 0..64 {
            haystack.extend_from_slice(b"A!Q");
        }

        let full = Window::full(&haystack);
        let (expected_first, search_baseline) = plan
            .find_window(&haystack, full, SearchLimits::unlimited())
            .unwrap();
        let expected_first = expected_first.unwrap();
        assert_eq!(expected_first, (48, 51));
        assert!(search_baseline.actual.finder_scanned_bytes > 0);
        let search_upper = search_baseline.upper_bounds;
        let exact_search = SearchLimits {
            max_work: search_upper.work,
            max_scratch_bytes: search_upper.scratch_bytes,
        };
        let one_below_search_work = search_upper.work.checked_sub(1).unwrap();
        assert!(matches!(
            plan.find_window(
                &haystack,
                full,
                SearchLimits {
                    max_work: one_below_search_work,
                    ..exact_search
                }
            ),
            Err(SearchError::WorkLimit { needed, limit })
                if needed == search_upper.work && limit == one_below_search_work
        ));

        let mut retained = plan.search_cursor(&haystack);
        let cold_before_failure = (
            retained.phase,
            retained.block,
            retained.window_end,
            retained.next_start,
        );
        assert_eq!(
            retained.find_window_with_late_failure(full, exact_search),
            Err(SearchError::InternalInvariant(
                "injected retained-cursor precommit failure"
            ))
        );
        assert_eq!(
            (
                retained.phase,
                retained.block,
                retained.window_end,
                retained.next_start,
            ),
            cold_before_failure,
            "a late failure must not publish partially advanced cold state"
        );
        let (first, first_accounting) = retained.find_window(full, exact_search).unwrap();
        assert_eq!(first, Some(expected_first));
        assert!(first_accounting.actual.finder_scanned_bytes > 0);
        assert_eq!(retained.phase, RetainedSearchPhase::CandidateStreamDrain);

        let next_window = Window::new(expected_first.1, haystack.len());
        let next_upper = plan
            .find_window(&haystack, next_window, SearchLimits::unlimited())
            .unwrap()
            .1
            .upper_bounds;
        let exact_next = SearchLimits {
            max_work: next_upper.work,
            max_scratch_bytes: next_upper.scratch_bytes,
        };
        let before_refusal = (
            retained.phase,
            retained.block,
            retained.window_end,
            retained.next_start,
        );
        let one_below_next_work = next_upper.work.checked_sub(1).unwrap();
        assert!(matches!(
            retained.find_window(
                next_window,
                SearchLimits {
                    max_work: one_below_next_work,
                    ..exact_next
                }
            ),
            Err(SearchError::WorkLimit { .. })
        ));
        assert_eq!(
            (
                retained.phase,
                retained.block,
                retained.window_end,
                retained.next_start,
            ),
            before_refusal,
            "preflight refusal must not consume or reset retained candidate masks"
        );
        assert_eq!(
            retained.find_window_with_late_failure(next_window, exact_next),
            Err(SearchError::InternalInvariant(
                "injected retained-cursor precommit failure"
            ))
        );
        assert_eq!(
            (
                retained.phase,
                retained.block,
                retained.window_end,
                retained.next_start,
            ),
            before_refusal,
            "a late failure must not consume a live retained block"
        );
        let (second, second_accounting) = retained.find_window(next_window, exact_next).unwrap();
        assert_eq!(second, Some((51, 54)));
        assert_eq!(
            second_accounting.actual.finder_scanned_bytes, 0,
            "recovery after refusal must reuse the still-live two-mask block"
        );

        let exact_reduce_limits = |upper: ReduceUpperBounds| ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_transitions: upper.transitions,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_reducer_steps: upper.reducer_steps,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };

        let count_baseline = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
        assert_eq!(count_baseline.count, 64);
        assert!(count_baseline.accounting.actual.finder_scanned_bytes > 0);
        let count_upper = count_baseline.accounting.upper_bounds;
        let exact_count = exact_reduce_limits(count_upper);
        let one_below_count = ReduceLimits {
            max_work: count_upper.work.checked_sub(1).unwrap(),
            ..exact_count
        };
        assert_eq!(plan.count_value_success(&haystack, one_below_count), None);
        assert!(matches!(
            plan.count(&haystack, one_below_count),
            Err(ReduceError::WorkLimit { .. })
        ));
        let recovered_count = plan.count(&haystack, exact_count).unwrap();
        assert_eq!(recovered_count.count, 64);
        assert!(recovered_count.accounting.actual.finder_scanned_bytes > 0);

        let span_baseline = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
        assert_eq!(span_baseline.span_sum, 192);
        assert!(span_baseline.accounting.actual.finder_scanned_bytes > 0);
        let span_upper = span_baseline.accounting.upper_bounds;
        let exact_span = exact_reduce_limits(span_upper);
        let one_below_span = ReduceLimits {
            max_work: span_upper.work.checked_sub(1).unwrap(),
            ..exact_span
        };
        assert_eq!(plan.span_sum_value_success(&haystack, one_below_span), None);
        assert!(matches!(
            plan.span_sum(&haystack, one_below_span),
            Err(ReduceError::WorkLimit { .. })
        ));
        let recovered_span = plan.span_sum(&haystack, exact_span).unwrap();
        assert_eq!(recovered_span.span_sum, 192);
        assert!(recovered_span.accounting.actual.finder_scanned_bytes > 0);
    }

    #[test]
    fn resumable_adaptive_finder_matches_exhaustive_small_reference() {
        let mut set_words = [0_u64; 4];
        for byte in [4_u8, 129, 255] {
            set_words[usize::from(byte >> 6)] |= 1_u64 << u32::from(byte & 63);
        }
        let finders = [
            AdaptiveFinder::One(0),
            AdaptiveFinder::Two(0, 2),
            AdaptiveFinder::Three(0, 2, 255),
            AdaptiveFinder::Four([0, 2, 4, 255]),
            AdaptiveFinder::Range {
                origin: b'A',
                maximum_delta: 3,
            },
            AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(set_words))),
        ];
        let alphabet = [0_u8, 2, 4, b'A', 255];

        for length in 0..=6 {
            let cases = alphabet.len().pow(u32::try_from(length).unwrap());
            for case in 0..cases {
                let mut ordinal = case;
                let mut bytes = vec![0_u8; length];
                for byte in &mut bytes {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                for finder in &finders {
                    assert_resumable_finder_sequence(finder, &bytes, bytes.len(), case);
                    assert_resumable_finder_sequence(
                        finder,
                        &bytes,
                        bytes.len(),
                        case.wrapping_add(3),
                    );
                }
            }
        }
    }

    #[test]
    fn resumable_adaptive_finder_matches_random_monotone_reference() {
        let mut set_words = [0_u64; 4];
        for byte in [4_u8, 17, 64, 129, 200, 255] {
            set_words[usize::from(byte >> 6)] |= 1_u64 << u32::from(byte & 63);
        }
        let finders = [
            AdaptiveFinder::One(0),
            AdaptiveFinder::Two(0, 255),
            AdaptiveFinder::Three(1, 127, 254),
            AdaptiveFinder::Four([1, 64, 127, 254]),
            AdaptiveFinder::Range {
                origin: 73,
                maximum_delta: 31,
            },
            AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(set_words))),
        ];
        let mut random = 0xA076_1D64_78BD_642F_u64;

        for case in 0..512_usize {
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let length = usize::try_from(random % 129).unwrap();
            let mut bytes = vec![0_u8; length];
            for byte in &mut bytes {
                random = random
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *byte = random.to_le_bytes()[0];
            }
            random = random
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let end = usize::try_from(random % u64::try_from(length + 1).unwrap()).unwrap();
            for finder in &finders {
                assert_resumable_finder_sequence(finder, &bytes, end, case);
            }
        }
    }

    #[test]
    fn resumable_range_and_set_phases_preserve_random_plan_accounting() {
        const ASCII: &[(u8, u8)] = &[(0, 0x7F)];
        const RANGE: &[(u8, u8)] = &[(b'A', b'D')];
        const FOUR: &[(u8, u8)] = &[(b'a', b'a'), (b'c', b'c'), (b'e', b'e'), (0xFF, 0xFF)];
        const SET: &[(u8, u8)] = &[
            (b'a', b'a'),
            (b'c', b'c'),
            (b'e', b'e'),
            (0x80, 0x80),
            (0xFF, 0xFF),
        ];
        const PRIMARY: &[(u8, u8)] = &[(0xFF, 0xFF)];
        const FULL: &[(u8, u8)] = &[(0, 0xFF)];
        let range_positions = [ASCII, RANGE, ASCII, ASCII, PRIMARY, FULL];
        let four_positions = [ASCII, FOUR, ASCII, ASCII, PRIMARY, FULL];
        let set_positions = [ASCII, SET, ASCII, ASCII, PRIMARY, FULL];
        let mut random = 0xE703_7ED1_A0B4_28DB_u64;

        for (predicates, expected_finder) in [
            (range_positions.as_slice(), "range"),
            (four_positions.as_slice(), "four"),
            (set_positions.as_slice(), "set"),
        ] {
            let plan =
                FixedPredicateWord64Plan::build(predicates, BuildLimits::unlimited()).unwrap();
            let fallback = plan.adaptive_fallback.as_ref().unwrap();
            assert!(matches!(
                (&fallback.finder, expected_finder),
                (AdaptiveFinder::Four(_), "four")
                    | (AdaptiveFinder::Range { .. }, "range")
                    | (AdaptiveFinder::Set(_), "set")
            ));
            for case in 0..256_usize {
                random = random
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
                let length = usize::try_from(random % 129).unwrap();
                let mut haystack = vec![0_u8; length];
                if case % 4 == 0 {
                    haystack.fill(0xFF);
                } else {
                    for byte in &mut haystack {
                        random = random
                            .wrapping_mul(2_862_933_555_777_941_757)
                            .wrapping_add(3_037_000_493);
                        *byte = random.to_le_bytes()[0];
                    }
                }

                let expected = naive_count(&haystack, predicates);
                assert_eq!(
                    plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                    Some(expected)
                );
                assert_eq!(
                    plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
                    expected.checked_mul(u64::try_from(plan.width()).unwrap())
                );
                let count = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
                let span = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(count.count, expected);
                assert_eq!(
                    span.span_sum,
                    expected * u64::try_from(plan.width()).unwrap()
                );
                assert_eq!(
                    count.accounting.actual.transitions,
                    count
                        .accounting
                        .actual
                        .finder_scanned_bytes
                        .checked_add(count.accounting.actual.shift_and_transitions)
                        .unwrap()
                );
                assert!(actual_within_upper(
                    count.accounting.actual,
                    count.accounting.upper_bounds
                ));
                assert!(actual_within_upper(
                    span.accounting.actual,
                    span.accounting.upper_bounds
                ));
                assert_search_case(&plan, predicates, &haystack, Window::full(&haystack));

                random = random
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
                let start = usize::try_from(random % u64::try_from(length + 1).unwrap()).unwrap();
                random = random
                    .wrapping_mul(2_862_933_555_777_941_757)
                    .wrapping_add(3_037_000_493);
                let end = start
                    + usize::try_from(
                        random % u64::try_from(length.checked_sub(start).unwrap() + 1).unwrap(),
                    )
                    .unwrap();
                assert_search_case(&plan, predicates, &haystack, Window::new(start, end));
            }
        }
    }

    #[test]
    fn verification_count_excludes_universal_positions_at_auto_boundary() {
        const PRIMARY: &[(u8, u8)] = &[(0x7F, 0x7F)];
        const VERIFY: &[(u8, u8)] = &[(b'A', b'Z')];
        const FULL: &[(u8, u8)] = &[(0, 0xFF)];

        for expected in [0_usize, 15, 16] {
            let mut predicates = vec![FULL; 64];
            predicates[32] = PRIMARY;
            for position in (0..64).filter(|&position| position != 32).take(expected) {
                predicates[position] = VERIFY;
            }
            let plan =
                FixedPredicateWord64Plan::build(predicates.as_slice(), BuildLimits::unlimited())
                    .unwrap();
            assert_eq!(plan.max_verification_predicates(), expected);
            assert_eq!(plan.adaptive_fallback.is_some(), expected != 0);
        }
    }

    #[test]
    fn adaptive_classifier_charge_is_structural_and_failure_atomic() {
        let limited = BuildLimits {
            max_build_work: u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK - 1).unwrap(),
            ..BuildLimits::unlimited()
        };
        let mut refused = BuildAttemptTracker::new(limited);
        assert!(matches!(
            refused.build_adaptive_classifier(),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK).unwrap()
                    && limit == limited.max_build_work
        ));
        assert_eq!(refused.actual.work, 0);
        assert_eq!(refused.actual.adaptive_classifier_build_work, 0);

        let mut accepted = BuildAttemptTracker::new(BuildLimits {
            max_build_work: u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK).unwrap(),
            ..BuildLimits::unlimited()
        });
        accepted.build_adaptive_classifier().unwrap();
        assert_eq!(
            accepted.actual.work,
            u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK).unwrap()
        );
        assert_eq!(
            accepted.actual.adaptive_classifier_build_work,
            BYTE_SET_CLASSIFIER_BUILD_WORK
        );
    }

    #[test]
    fn general_pair_accounts_staged_and_direct_set_classifiers_transactionally() {
        const THREE_LEFT: &[(u8, u8)] = &[
            (1, 1),
            (65, 65),
            (255, 255),
        ];
        const SET_LEFT: &[(u8, u8)] = &[
            (1, 1),
            (17, 17),
            (65, 65),
            (129, 129),
            (255, 255),
        ];
        const ASCII_SET_LEFT: &[(u8, u8)] =
            &[(1, 1), (17, 17), (33, 33), (65, 65), (97, 97)];
        const RIGHT: &[(u8, u8)] = &[
            (2, 2),
            (18, 18),
            (66, 66),
            (130, 130),
            (200, 200),
            (254, 254),
        ];
        const ASCII_RIGHT: &[(u8, u8)] =
            &[(2, 2), (18, 18), (34, 34), (66, 66), (98, 98), (126, 126)];
        for (left, right, primary_kind, classifier_count) in [
            (THREE_LEFT, RIGHT, AdaptiveFinderKind::Three, 1_usize),
            (SET_LEFT, RIGHT, AdaptiveFinderKind::Set, 2_usize),
            (
                ASCII_SET_LEFT,
                ASCII_RIGHT,
                AdaptiveFinderKind::Set,
                2_usize,
            ),
        ] {
            let positions = [left, right];
            let baseline =
                FixedPredicateWord64Plan::build(&positions, BuildLimits::unlimited()).unwrap();
            let accounting = baseline.build_accounting();
            let identity = baseline.operation_identity(Operation::Count);
            assert_eq!(identity.reducer, Reducer::ShiftAnd);
            assert_eq!(identity.primary_finder.unwrap().kind, primary_kind);
            let expected_classifier_work = BYTE_SET_CLASSIFIER_BUILD_WORK * classifier_count;
            assert_eq!(
                accounting.adaptive_classifier_build_work,
                expected_classifier_work
            );
            let expected_primary_scan = match baseline.primary_finder.as_ref() {
                Some(AdaptiveFallback {
                    finder: AdaptiveFinder::Three(_, _, _),
                    ..
                }) => GeneralPrimaryScanIdentity::Memchr3,
                Some(finder) if finder.supports_classified_general_stage() => {
                    GeneralPrimaryScanIdentity::CompiledWholeSlice
                }
                Some(_) => GeneralPrimaryScanIdentity::DirectCandidateStream,
                None => panic!("general pair lost its primary finder"),
            };
            assert_eq!(
                baseline.general_primary_scan_identity(),
                Some(expected_primary_scan)
            );
            let expected_fallback_skip = matches!(
                expected_primary_scan,
                GeneralPrimaryScanIdentity::CompiledWholeSlice
            ) && baseline
                .adaptive_fallback
                .as_ref()
                .is_some_and(AdaptiveFallback::supports_vector_classified_run);
            assert_eq!(
                baseline.general_fallback_scan_identity().is_some(),
                expected_fallback_skip
            );
            let exact = FixedPredicateWord64Plan::build_attempt(
                &positions,
                BuildLimits {
                    max_build_work: accounting.work_upper_bound,
                    ..BuildLimits::unlimited()
                },
            )
            .unwrap();
            assert!(exact.closes());
            assert_eq!(
                exact
                    .plan()
                    .build_accounting()
                    .adaptive_classifier_build_work,
                expected_classifier_work
            );
            assert_eq!(
                exact.plan().general_primary_scan_identity(),
                Some(expected_primary_scan)
            );

            let one_below = accounting.work_upper_bound.checked_sub(1).unwrap();
            let refused = FixedPredicateWord64Plan::build_attempt(
                &positions,
                BuildLimits {
                    max_build_work: one_below,
                    ..BuildLimits::unlimited()
                },
            )
            .unwrap_err();
            assert!(matches!(
                refused.source(),
                BuildError::WorkLimit { needed, limit }
                    if *needed == accounting.work_upper_bound && *limit == one_below
            ));
            assert!(refused.closes());
            assert_eq!(refused.receipt().actual(), BuildAttemptActual::default());
        }

        let both_ascii = FixedPredicateWord64Plan::build(
            &[ASCII_SET_LEFT, ASCII_RIGHT],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(both_ascii.general_primary_scan_identity().is_some());
        if let Some(fallback) = both_ascii.adaptive_fallback.as_ref() {
            for value in 0_u8..=u8::MAX {
                assert_eq!(
                    fallback.find_member(&[value], false).is_some(),
                    fallback.matches(value),
                    "fallback classifier search disagreed at byte {value}"
                );
            }
        }
    }

    #[test]
    fn adaptive_phase_boundaries_skip_impossible_trailing_work() {
        const PRIMARY: &[(u8, u8)] = &[(0x7F, 0x7F)];
        const FALLBACK: &[(u8, u8)] = &[(0x7F, 0x81)];
        const BROAD: &[(u8, u8)] = &[(0, 0x7E)];
        let positions = [PRIMARY, FALLBACK, BROAD, BROAD, BROAD, BROAD];
        let plan = FixedPredicateWord64Plan::build(&positions, BuildLimits::unlimited()).unwrap();
        assert!(matches!(
            plan.adaptive_fallback.map(|fallback| fallback.finder),
            Some(AdaptiveFinder::Three(0x7F, 0x80, 0x81))
        ));

        for (candidate_positions, expected_finder, expected_shift) in [
            (8_usize, 8_usize, 0_usize),
            (9, 9, 0),
            (16, 16, 0),
            // The final candidate-stream block already classified start 16.
            // Drain it before Shift-And so the two phases never charge the
            // same source suffix; its accepted word needs no trailing scan.
            (17, 17, 0),
        ] {
            let input_bytes = candidate_positions + plan.width() - 1;
            let mut haystack = vec![0x7F; input_bytes];
            let expected_span = if candidate_positions == 17 {
                haystack[18..22].fill(0);
                Some((16, 22))
            } else {
                None
            };
            let expected_count = u64::from(expected_span.is_some());

            assert_eq!(
                plan.find_window_value(
                    &haystack,
                    Window::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
                expected_span
            );
            assert_eq!(
                plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                Some(expected_count)
            );

            let (span, search) = plan
                .find_window(
                    &haystack,
                    Window::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            let count = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
            assert_eq!(span, expected_span);
            assert_eq!(count.count, expected_count);
            assert_eq!(
                (
                    search.actual.finder_scanned_bytes,
                    search.actual.shift_and_transitions,
                ),
                (expected_finder, expected_shift)
            );
            assert_eq!(
                (
                    count.accounting.actual.finder_scanned_bytes,
                    count.accounting.actual.shift_and_transitions,
                ),
                (expected_finder, expected_shift)
            );
            ensure_search_actual_within(search.actual, search.upper_bounds).unwrap();
            assert!(actual_within_upper(
                count.accounting.actual,
                count.accounting.upper_bounds,
            ));
        }
    }
}
