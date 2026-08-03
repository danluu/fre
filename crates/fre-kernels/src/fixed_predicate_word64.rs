//! Fixed-width byte-predicate matching with exact anchors, adaptive
//! non-universal predicate finders, and a 64-bit Shift-And fallback.
//!
//! Construction accepts between one and 64 nonempty byte predicates. Each
//! predicate is supplied as inclusive byte ranges and is compiled into a full
//! byte-to-position mask table. An exact
//! one-or-two-byte predicate drives a monotone candidate stream when available.
//! A dense rejection burst moves monotonically to a second retained
//! non-universal predicate and then, if needed, to Shift-And. Universal
//! predicates are never rechecked. Plans without an exact anchor use
//! Shift-And directly. Every phase restarts after each accepted word,
//! allocates no operation memory, and materializes no spans.

use core::{fmt, mem::size_of};

use fre_simd_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSet256, ByteSetClassifier,
    classify_byte_delta_16, classify_byte_set4_16,
};
use memchr::{memchr, memchr2, memchr3};

use crate::Window;
use crate::packed_ordered_literal_aggregate::byte_frequency_rank;

/// Stable identity for the fixed-predicate anchor-or-Shift-And strategy.
pub const PLAN_ID: &str =
    "fixed-predicate-word64.adaptive-fixed-anchor-or-shift-and.nonoverlap.v10";
/// Stable identity for the count reducer.
pub const COUNT_OPERATION_ID: &str = "fixed-predicate-word64.count.v9";
/// Stable identity for the matched-byte-sum reducer.
pub const SPAN_SUM_OPERATION_ID: &str = "fixed-predicate-word64.span-sum.v9";
/// Stable identity for the ordinary first-match search projection.
pub const SEARCH_PLAN_ID: &str = "fixed-predicate-word64.first-match.v6";
/// Stable identity for existence search.
const EXISTS_SEARCH_OPERATION_ID: &str = "fixed-predicate-word64.search.exists.v6";
/// Stable identity for the first accepting end projection.
const EARLIEST_END_SEARCH_OPERATION_ID: &str =
    "fixed-predicate-word64.search.earliest-end.v6";
/// Stable identity for the selected match end projection.
const SELECTED_END_SEARCH_OPERATION_ID: &str =
    "fixed-predicate-word64.search.selected-end.v6";
/// Stable identity for the selected span projection.
const SPAN_SEARCH_OPERATION_ID: &str = "fixed-predicate-word64.search.span.v6";
/// Version of the receipt-bearing fixed-predicate construction protocol.
pub const BUILD_ATTEMPT_ALGORITHM_VERSION: u32 = 10;
/// Version of the partial-actual fixed-predicate construction ledger.
pub const BUILD_ATTEMPT_ACCOUNTING_VERSION: u32 = 10;
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
const ADAPTIVE_FALLBACK_REJECTIONS: usize = 8;
const ADAPTIVE_FALLBACK_MAX_MEAN_SKIP: usize = BYTE_SET_BLOCK_BYTES;

#[inline]
fn dense_rejection_burst(
    first_rejected_anchor: usize,
    rejected_anchor: usize,
    rejected_candidates: usize,
) -> Option<bool> {
    if rejected_candidates < ADAPTIVE_FALLBACK_REJECTIONS {
        return Some(false);
    }
    let span = rejected_anchor.checked_sub(first_rejected_anchor)?;
    let admitted_span = ADAPTIVE_FALLBACK_REJECTIONS
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
    // `p * (verification_positions + 3)`;
    // the suffix costs at most `6 * (input_bytes - p)`. Maximizing over
    // `p <= candidate_positions` gives the closed expression below. The
    // caller separately charges match events and finalization.
    input_bytes
        .checked_mul(TRANSITION_WORK)?
        .checked_add(
            candidate_positions.checked_mul(verification_positions.saturating_sub(3))?,
        )
}

/// Complete aggregate selected for one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Number of successive leftmost non-overlapping matches.
    Count,
    /// Sum of the widths of those matches.
    SpanSum,
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
    /// No one-or-two-byte position exists, so reduction uses Shift-And.
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

/// Adaptive phase sequence retained by one anchored plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveHandoffIdentity {
    /// No adaptive phase is reachable.
    Disabled,
    /// Dense primary rejection moves directly to Shift-And.
    DirectShiftAnd,
    /// Dense primary rejection moves to a retained predicate finder.
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
    /// Fixed position used by an anchor reducer, or zero for Shift-And.
    pub anchor_offset: u8,
    /// Exact anchor bytes. The second slot is zero for a one-byte anchor.
    pub anchor_bytes: [u8; 2],
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
    /// Exact work used to build an arbitrary-set adaptive classifier.
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
    /// Fixed position used by an anchor reducer, or zero for Shift-And.
    pub anchor_offset: u8,
    /// Exact anchor bytes. The second slot is zero for a one-byte anchor.
    pub anchor_bytes: [u8; 2],
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
            && matches!(
                self.actual.adaptive_classifier_build_work,
                0 | BYTE_SET_CLASSIFIER_BUILD_WORK
            )
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
enum AdaptiveFinder {
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Four([u8; 4]),
    Range { origin: u8, maximum_delta: u8 },
    Set(ByteSetClassifier),
}

impl AdaptiveFallback {
    #[inline]
    fn cursor<'a>(
        &'a self,
        bytes: &'a [u8],
        anchor_end: usize,
    ) -> AdaptiveFinderCursor<'a> {
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
}

#[derive(Clone, Copy, Debug, Default)]
struct AdaptiveFinderBlock {
    // Absolute coordinates let one classified block survive every monotone
    // restart within that block, including a jump after an accepted match.
    start: usize,
    end: usize,
    members: u16,
}

struct AdaptiveFinderCursor<'a> {
    finder: &'a AdaptiveFinder,
    bytes: &'a [u8],
    anchor_end: usize,
    block: AdaptiveFinderBlock,
    #[cfg(test)]
    classified_chunks: usize,
}

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
    fn find_range(
        &self,
        mut cursor: usize,
        origin: u8,
        maximum_delta: u8,
    ) -> Option<usize> {
        while let Some(end) = cursor
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .filter(|&end| end <= self.anchor_end)
        {
            let block = <&[u8; BYTE_SET_BLOCK_BYTES]>::try_from(
                self.bytes.get(cursor..end)?,
            )
            .ok()?;
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

#[derive(Clone, Copy, Debug)]
struct FallbackCandidate {
    score: (usize, u8, usize),
    bytes: [u8; 4],
    set: ByteSet256,
    contiguous_range: Option<(u8, u8)>,
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
        .and_then(|work| work.checked_add(BYTE_SET_CLASSIFIER_BUILD_WORK))
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
) -> Result<(Anchor, Option<Anchor>, Option<AdaptiveFallback>, u64), BuildError> {
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
    let primary_offset = selected.offset().map(usize::from);
    let fallback = [fallback_first, fallback_second]
        .into_iter()
        .flatten()
        .find(|candidate| Some(candidate.score.2) != primary_offset);
    let verification_positions = match primary_offset {
        Some(position) => {
            let shift = u32::try_from(position).map_err(|_| {
                BuildError::InternalInvariant("primary anchor offset exceeded one word")
            })?;
            let primary = 1_u64.checked_shl(shift).ok_or(
                BuildError::InternalInvariant("primary anchor bit exceeded one word"),
            )?;
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
            let offset = u8::try_from(candidate.score.2).map_err(|_| {
                BuildError::InternalInvariant("adaptive fallback offset exceeded one byte")
            })?;
            let cardinality = u16::try_from(candidate.score.0).map_err(|_| {
                BuildError::InternalInvariant("adaptive fallback cardinality exceeded identity")
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
            Some(AdaptiveFallback {
                offset,
                cardinality,
                finder,
            })
        }
        _ => None,
    };
    Ok((
        selected,
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
    adaptive_fallback_work: usize,
) -> Result<u64, BuildError> {
    let work = source_ranges
        .checked_mul(RANGE_FIXED_WORK)
        .and_then(|range_work| MASK_SLOTS.checked_add(width)?.checked_add(range_work))
        .and_then(|work| work.checked_add(member_writes))
        .and_then(|work| work.checked_add(anchor_mask_reads))
        .and_then(|work| work.checked_add(adaptive_fallback_work))
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
            let (anchor, secondary_anchor, adaptive_fallback, nonuniversal_mask) =
                select_anchor(&masks, preflight.width, &mut tracker)?;
            if tracker.actual.adaptive_classifier_build_work
                != adaptive_fallback.map_or(0, |fallback| fallback.classifier_build_work())
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

    fn verification_positions(&self) -> Option<usize> {
        let offset = u32::from(self.anchor.offset()?);
        let primary = 1_u64.checked_shl(offset)?;
        if self.nonuniversal_mask & primary == 0 {
            return None;
        }
        usize::try_from((self.nonuniversal_mask & !primary).count_ones()).ok()
    }

    const fn verification_predicate_identity_count(&self) -> u32 {
        match self.anchor {
            Anchor::One { .. } | Anchor::Two { .. } => {
                self.nonuniversal_mask.count_ones().saturating_sub(1)
            }
            Anchor::ShiftAnd => 0,
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
    /// Returns zero for a Shift-And plan, which has no anchor candidates.
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
        let (reducer, anchor_offset, anchor_bytes) = self.anchor.identity();
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
        let _ = self.search_preflight(haystack.len(), window, limits)?;
        let slice = haystack.get(window.start()..window.end()).ok_or(
            SearchError::InternalInvariant("admitted fixed-predicate window disappeared"),
        )?;
        match self.anchor {
            Anchor::One { offset, byte } => self.first_anchor_value(
                slice,
                window.start(),
                usize::from(offset),
                |bytes| memchr(byte, bytes),
            ),
            Anchor::Two {
                offset,
                first,
                second,
            } => self.first_anchor_value(
                slice,
                window.start(),
                usize::from(offset),
                |bytes| memchr2(first, second, bytes),
            ),
            Anchor::ShiftAnd => self.first_shift_and_value(slice, window.start()),
        }
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
                let relative_end = position.checked_add(1).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "actual Shift-And match end",
                    },
                )?;
                let relative_start = relative_end.checked_sub(self.width).ok_or(
                    SearchError::InternalInvariant(
                        "Shift-And accepted before the fixed word width",
                    ),
                )?;
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
            let search = slice.get(cursor..anchor_end).ok_or(
                SearchError::InternalInvariant("anchor search window escaped the input"),
            )?;
            let Some(relative) = find(search) else {
                break;
            };
            let anchor = cursor.checked_add(relative).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "actual anchor search position",
                },
            )?;
            let start = anchor.checked_sub(anchor_offset).ok_or(
                SearchError::InternalInvariant("anchor preceded its fixed offset"),
            )?;
            let is_match = self
                .anchor_candidate_matches_value(slice, start, anchor_offset)
                .ok_or(SearchError::InternalInvariant(
                    "compact anchor verification arithmetic failed after preflight",
                ))?;
            if is_match {
                let relative_end = start.checked_add(self.width).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "actual anchor match end",
                    },
                )?;
                let absolute_start = window_start.checked_add(start).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute anchor match start",
                    },
                )?;
                let absolute_end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute anchor match end",
                    },
                )?;
                return Ok(Some((absolute_start, absolute_end)));
            }
            cursor = anchor.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "rejected anchor search restart",
            })?;
            if burst_rejections == 0 {
                burst_start = anchor;
            }
            burst_rejections = burst_rejections.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive anchor rejection burst",
                },
            )?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && self.adaptive_fallback.is_some()
                && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive anchor rejection density",
                    },
                )?
            {
                let fallback_start = cursor.checked_sub(anchor_offset).ok_or(
                    SearchError::InternalInvariant(
                        "adaptive fallback preceded the first untested start",
                    ),
                )?;
                return self.first_adaptive_fallback_value(
                    slice,
                    window_start,
                    fallback_start,
                );
            }
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                burst_rejections = 0;
            }
        }
        Ok(None)
    }

    #[inline]
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
            let remaining = slice.get(first_untested_start..).ok_or(
                SearchError::InternalInvariant("adaptive Shift-And fallback escaped the input"),
            )?;
            let absolute = window_start.checked_add(first_untested_start).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive Shift-And fallback absolute start",
                },
            )?;
            return self.first_shift_and_value(remaining, absolute);
        };
        let fallback_offset = usize::from(fallback.offset);
        let anchor_end = slice
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(fallback_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = first_untested_start
            .checked_add(fallback_offset)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "adaptive byte-set fallback cursor",
            })?
            .min(anchor_end);
        let mut finder = fallback.cursor(slice, anchor_end);
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while cursor < anchor_end {
            let Some(anchor) = finder.find(cursor) else {
                break;
            };
            let start = anchor.checked_sub(fallback_offset).ok_or(
                SearchError::InternalInvariant("adaptive byte-set fallback preceded its offset"),
            )?;
            if self
                .candidate_matches_value_skipping(slice, start, fallback_offset)
                .ok_or(SearchError::InternalInvariant(
                    "adaptive byte-set fallback verification failed",
                ))?
            {
                let relative_end = start.checked_add(self.width).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive byte-set fallback match end",
                    },
                )?;
                let absolute_start = window_start.checked_add(start).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive byte-set fallback absolute start",
                    },
                )?;
                let absolute_end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive byte-set fallback absolute end",
                    },
                )?;
                return Ok(Some((absolute_start, absolute_end)));
            }
            cursor = anchor.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "adaptive byte-set rejection restart",
            })?;
            if burst_rejections == 0 {
                burst_start = anchor;
            }
            burst_rejections = burst_rejections.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive byte-set rejection burst",
                },
            )?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive byte-set rejection density",
                },
                )?
            {
                let shift_start = cursor.checked_sub(fallback_offset).ok_or(
                    SearchError::InternalInvariant(
                        "adaptive Shift-And fallback preceded the first untested start",
                    ),
                )?;
                let remaining = slice.get(shift_start..).ok_or(
                    SearchError::InternalInvariant("adaptive Shift-And fallback escaped input"),
                )?;
                let absolute = window_start.checked_add(shift_start).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive Shift-And fallback absolute start",
                    },
                )?;
                return self.first_shift_and_value(remaining, absolute);
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
        if window.start() > window.end() || window.end() > haystack_len {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len,
            });
        }
        let window_bytes = window.end().checked_sub(window.start()).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "search window width",
            },
        )?;
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
        ) = match self.anchor {
                Anchor::ShiftAnd => {
                    let work = window_bytes
                        .checked_mul(TRANSITION_WORK)
                        .and_then(|work| {
                            work.checked_add(match_events.checked_mul(MATCH_WORK)?)
                        })
                        .and_then(|work| work.checked_add(REDUCE_FINAL_WORK))
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "Shift-And search work upper bound",
                        })?;
                    (window_bytes, 0, window_bytes, 0, 0, 0, work)
                }
                Anchor::One { .. } | Anchor::Two { .. } => {
                    let finder_calls = if candidate_events == 0 {
                        0
                    } else {
                        candidate_events.checked_add(1).ok_or(
                            SearchError::ArithmeticOverflow {
                                computation: "anchor search finder-call upper bound",
                            },
                        )?
                    };
                    let verification_positions = self.verification_positions().ok_or(
                        SearchError::InternalInvariant(
                            "anchored search lost its verification-position count",
                        ),
                    )?;
                    let predicate_checks = candidate_events
                        .checked_mul(verification_positions)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "anchor search predicate-check upper bound",
                        })?;
                    let anchor_work = candidate_events
                        .checked_mul(FINDER_SCAN_BYTE_WORK)
                        .and_then(|work| {
                            work.checked_add(finder_calls.checked_mul(FINDER_CALL_WORK)?)
                        })
                        .and_then(|work| {
                            work.checked_add(
                                candidate_events.checked_mul(ANCHOR_CANDIDATE_WORK)?,
                            )
                        })
                        .and_then(|work| {
                            work.checked_add(
                                predicate_checks.checked_mul(PREDICATE_CHECK_WORK)?,
                            )
                        })
                        .and_then(|work| {
                            work.checked_add(match_events.checked_mul(MATCH_WORK)?)
                        })
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
                        .and_then(|work| {
                            work.checked_add(match_events.checked_mul(MATCH_WORK)?)
                        })
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
        let slice = haystack.get(window.start()..window.end()).ok_or(
            SearchError::InternalInvariant("admitted fixed-predicate window disappeared"),
        )?;
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
            transitions = transitions.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "actual Shift-And search transitions",
                },
            )?;
            state = (state.wrapping_shl(1) | 1) & self.masks[usize::from(byte)];
            if state & self.accepting_bit != 0 {
                let relative_end = position.checked_add(1).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "actual Shift-And match end",
                    },
                )?;
                let relative_start = relative_end.checked_sub(self.width).ok_or(
                    SearchError::InternalInvariant(
                        "Shift-And accepted before the fixed word width",
                    ),
                )?;
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
            work: search_work(
                0,
                transitions,
                0,
                0,
                0,
                usize::from(matched.is_some()),
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
            let search = slice.get(cursor..anchor_end).ok_or(
                SearchError::InternalInvariant("anchor search window escaped the input"),
            )?;
            finder_calls = finder_calls.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "actual anchor search finder calls",
                },
            )?;
            let Some(relative) = find(search) else {
                finder_scanned_bytes = finder_scanned_bytes.checked_add(search.len()).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "actual unsuccessful anchor search service bytes",
                    },
                )?;
                break;
            };
            finder_scanned_bytes = finder_scanned_bytes
                .checked_add(relative.checked_add(1).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "actual successful anchor search service",
                    },
                )?)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "actual anchor search service bytes",
                })?;
            let anchor = cursor.checked_add(relative).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "actual anchor search position",
                },
            )?;
            let start = anchor.checked_sub(anchor_offset).ok_or(
                SearchError::InternalInvariant("anchor preceded its fixed offset"),
            )?;
            candidate_events = candidate_events.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "actual anchor search candidates",
                },
            )?;
            let is_match = self
                .anchor_candidate_matches(slice, start, anchor_offset, &mut predicate_checks)
                .map_err(|error| search_error_from_reduce(&error))?;
            if is_match {
                let relative_end = start.checked_add(self.width).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "actual anchor match end",
                    },
                )?;
                let absolute_start = window_start.checked_add(start).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute anchor match start",
                    },
                )?;
                let absolute_end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "absolute anchor match end",
                    },
                )?;
                matched = Some((absolute_start, absolute_end));
                break;
            }
            cursor = anchor.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "rejected anchor search restart",
            })?;
            if burst_rejections == 0 {
                burst_start = anchor;
            }
            burst_rejections = burst_rejections.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting rejection burst",
                },
            )?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && self.adaptive_fallback.is_some()
                && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting rejection density",
                    },
                )?
            {
                let first_untested_start = cursor.checked_sub(anchor_offset).ok_or(
                    SearchError::InternalInvariant(
                        "adaptive reporting fallback preceded the first untested start",
                    ),
                )?;
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
        let transitions = finder_scanned_bytes.checked_add(shift_and_transitions).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "adaptive reporting transitions",
            },
        )?;
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
        let fallback_offset = usize::from(fallback.offset);
        let anchor_end = slice
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(fallback_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = first_untested_start
            .checked_add(fallback_offset)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "adaptive reporting byte-set cursor",
            })?
            .min(anchor_end);
        let mut finder = fallback.cursor(slice, anchor_end);
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while cursor < anchor_end {
            *finder_calls = finder_calls.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting byte-set finder calls",
                },
            )?;
            let service_start = cursor;
            let Some(anchor) = finder.find(cursor) else {
                let terminal_service = anchor_end.checked_sub(service_start).ok_or(
                    SearchError::InternalInvariant(
                        "adaptive reporting finder service reversed",
                    ),
                )?;
                *finder_scanned_bytes = finder_scanned_bytes.checked_add(terminal_service).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting byte-set terminal service",
                    },
                )?;
                break;
            };
            let service = anchor
                .checked_sub(service_start)
                .and_then(|relative| relative.checked_add(1))
                .ok_or(SearchError::InternalInvariant(
                    "adaptive reporting finder service reversed",
                ))?;
            *finder_scanned_bytes = finder_scanned_bytes.checked_add(service).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting byte-set service bytes",
                },
            )?;
            let start = anchor.checked_sub(fallback_offset).ok_or(
                SearchError::InternalInvariant(
                    "adaptive reporting byte-set anchor preceded its offset",
                ),
            )?;
            *candidate_events = candidate_events.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting byte-set candidates",
                },
            )?;
            if self
                .candidate_matches_skipping(slice, start, fallback_offset, predicate_checks)
                .map_err(|error| search_error_from_reduce(&error))?
            {
                let relative_end = start.checked_add(self.width).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting byte-set match end",
                    },
                )?;
                let absolute_start = window_start.checked_add(start).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting byte-set absolute start",
                    },
                )?;
                let absolute_end = window_start.checked_add(relative_end).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "adaptive reporting byte-set absolute end",
                    },
                )?;
                return Ok(Some((absolute_start, absolute_end)));
            }
            cursor = anchor.checked_add(1).ok_or(SearchError::ArithmeticOverflow {
                computation: "adaptive reporting byte-set restart",
            })?;
            if burst_rejections == 0 {
                burst_start = anchor;
            }
            burst_rejections = burst_rejections.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting byte-set rejection burst",
                },
            )?;
            if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting byte-set rejection density",
                },
                )?
            {
                let shift_start = cursor.checked_sub(fallback_offset).ok_or(
                    SearchError::InternalInvariant(
                        "adaptive reporting Shift-And preceded the first untested start",
                    ),
                )?;
                return self.execute_first_shift_and_reporting(
                    slice,
                    window_start,
                    shift_start,
                    shift_and_transitions,
                );
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
        let remaining = slice.get(first_untested_start..).ok_or(
            SearchError::InternalInvariant("adaptive reporting Shift-And escaped input"),
        )?;
        if remaining.len() < self.width {
            return Ok(None);
        }
        let mut state = 0_u64;
        for (position, &byte) in remaining.iter().enumerate() {
            *shift_and_transitions = shift_and_transitions.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting Shift-And transitions",
                },
            )?;
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
            let relative_start = relative_end.checked_sub(self.width).ok_or(
                SearchError::InternalInvariant(
                    "adaptive reporting Shift-And accepted before the fixed width",
                ),
            )?;
            let absolute_start = window_start.checked_add(relative_start).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting Shift-And absolute start",
                },
            )?;
            let absolute_end = window_start.checked_add(relative_end).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "adaptive reporting Shift-And absolute end",
                },
            )?;
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
        };
        let (reducer, anchor_offset, anchor_bytes) = self.anchor.identity();
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

    fn reducer_upper(&self, input_bytes: usize) -> Result<ReducerUpper, ReduceError> {
        match self.anchor {
            Anchor::One { .. } | Anchor::Two { .. } => {
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
                let verification_positions = self.verification_positions().ok_or(
                    ReduceError::InternalInvariant(
                        "anchored reducer lost its verification-position count",
                    ),
                )?;
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
            Anchor::ShiftAnd => Ok(ReducerUpper {
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
        if operation == Operation::SpanSum && span_sum > limits.max_span_sum {
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
        match self.anchor {
            Anchor::One { offset, byte } => {
                self.execute_anchor(haystack, upper_bounds, usize::from(offset), |bytes| {
                    memchr(byte, bytes)
                })
            }
            Anchor::Two {
                offset,
                first,
                second,
            } => self.execute_anchor(haystack, upper_bounds, usize::from(offset), |bytes| {
                memchr2(first, second, bytes)
            }),
            Anchor::ShiftAnd => self.execute_shift_and(haystack, upper_bounds),
        }
    }

    #[inline]
    fn execute_value(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
    ) -> Option<ValueReduction> {
        let count = match self.anchor {
            Anchor::One { offset, byte } => {
                self.scan_anchor_value(haystack, usize::from(offset), |bytes| memchr(byte, bytes))?
            }
            Anchor::Two {
                offset,
                first,
                second,
            } => self.scan_anchor_value(haystack, usize::from(offset), |bytes| {
                memchr2(first, second, bytes)
            })?,
            Anchor::ShiftAnd => self.scan_shift_and_value(haystack)?,
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
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
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
                burst_rejections = 0;
            } else {
                cursor = anchor.checked_add(1)?;
                if burst_rejections == 0 {
                    burst_start = anchor;
                }
                burst_rejections = burst_rejections.checked_add(1)?;
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                    && self.adaptive_fallback.is_some()
                    && dense_rejection_burst(burst_start, anchor, burst_rejections)?
                {
                    let fallback_start = cursor.checked_sub(anchor_offset)?;
                    return count
                        .checked_add(self.scan_adaptive_fallback_value(haystack, fallback_start)?);
                }
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                    burst_rejections = 0;
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
        let fallback_offset = usize::from(fallback.offset);
        let anchor_end = haystack
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(fallback_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = first_untested_start
            .checked_add(fallback_offset)?
            .min(anchor_end);
        let mut finder = fallback.cursor(haystack, anchor_end);
        let mut count = 0_u64;
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while cursor < anchor_end {
            let Some(anchor) = finder.find(cursor) else {
                break;
            };
            let start = anchor.checked_sub(fallback_offset)?;
            if self.candidate_matches_value_skipping(haystack, start, fallback_offset)? {
                count = count.checked_add(1)?;
                cursor = anchor.checked_add(self.width)?;
                burst_rejections = 0;
            } else {
                cursor = anchor.checked_add(1)?;
                if burst_rejections == 0 {
                    burst_start = anchor;
                }
                burst_rejections = burst_rejections.checked_add(1)?;
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                    && dense_rejection_burst(burst_start, anchor, burst_rejections)?
                {
                    let shift_start = cursor.checked_sub(fallback_offset)?;
                    return count
                        .checked_add(self.scan_shift_and_value(haystack.get(shift_start..)?)?);
                }
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                    burst_rejections = 0;
                }
            }
        }
        Some(count)
    }

    #[inline]
    fn candidate_matches_value_skipping(
        &self,
        haystack: &[u8],
        start: usize,
        skipped_offset: usize,
    ) -> Option<bool> {
        let end = start.checked_add(self.width)?;
        let candidate = haystack.get(start..end)?;
        let skipped_shift = u32::try_from(skipped_offset).ok()?;
        let mut remaining = self.nonuniversal_mask & !1_u64.checked_shl(skipped_shift)?;
        let primary_offset = usize::from(self.anchor.offset()?);
        if primary_offset == skipped_offset {
            return None;
        }
        if !self.anchor.matches(*candidate.get(primary_offset)?)? {
            return Some(false);
        }
        let primary_shift = u32::try_from(primary_offset).ok()?;
        remaining &= !1_u64.checked_shl(primary_shift)?;
        if let Some(secondary) = self.secondary_anchor {
            let secondary_offset = usize::from(secondary.offset()?);
            if secondary_offset != skipped_offset {
                if secondary_offset == primary_offset {
                    return None;
                }
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

    fn execute_shift_and(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut state = 0_u64;
        let mut match_events = 0_usize;
        for &byte in haystack {
            let mask = self.masks[usize::from(byte)];
            state = (state.wrapping_shl(1) | 1) & mask;
            if state & self.accepting_bit != 0 {
                match_events =
                    match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual match event count",
                        })?;
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

    fn execute_anchor(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
        anchor_offset: usize,
        find: impl FnMut(&[u8]) -> Option<usize>,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let actual = self.scan_anchor(haystack, anchor_offset, find)?;
        self.finish_anchor_actual(haystack.len(), upper_bounds, actual)
    }

    fn scan_anchor(
        &self,
        haystack: &[u8],
        anchor_offset: usize,
        mut find: impl FnMut(&[u8]) -> Option<usize>,
    ) -> Result<AnchorActual, ReduceError> {
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
                burst_rejections = burst_rejections.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer rejection burst",
                    },
                )?;
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                    && self.adaptive_fallback.is_some()
                    && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "adaptive reducer rejection density",
                        },
                    )?
                {
                    let first_untested_start = cursor.checked_sub(anchor_offset).ok_or(
                        ReduceError::InternalInvariant(
                            "adaptive reducer fallback preceded the first untested start",
                        ),
                    )?;
                    self.scan_adaptive_reporting(
                        haystack,
                        first_untested_start,
                        &mut actual,
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

    fn scan_adaptive_reporting(
        &self,
        haystack: &[u8],
        first_untested_start: usize,
        actual: &mut AnchorActual,
    ) -> Result<(), ReduceError> {
        if !has_legal_start(haystack.len(), self.width, first_untested_start) {
            return Ok(());
        }
        let Some(fallback) = self.adaptive_fallback.as_ref() else {
            return self.scan_shift_and_reporting_suffix(
                haystack,
                first_untested_start,
                actual,
            );
        };
        let fallback_offset = usize::from(fallback.offset);
        let anchor_end = haystack
            .len()
            .checked_sub(self.width)
            .and_then(|last_start| last_start.checked_add(fallback_offset))
            .and_then(|last_anchor| last_anchor.checked_add(1))
            .unwrap_or(0);
        let mut cursor = first_untested_start
            .checked_add(fallback_offset)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "adaptive reducer byte-set cursor",
            })?
            .min(anchor_end);
        let mut finder = fallback.cursor(haystack, anchor_end);
        let mut burst_start = 0_usize;
        let mut burst_rejections = 0_usize;
        while cursor < anchor_end {
            actual.finder_calls = actual.finder_calls.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer byte-set finder calls",
                },
            )?;
            let service_start = cursor;
            let Some(anchor) = finder.find(cursor) else {
                let terminal_service = anchor_end.checked_sub(service_start).ok_or(
                    ReduceError::InternalInvariant(
                        "adaptive reducer finder service reversed",
                    ),
                )?;
                actual.finder_scanned_bytes = actual
                    .finder_scanned_bytes
                    .checked_add(terminal_service)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer byte-set terminal service",
                    })?;
                break;
            };
            let service = anchor
                .checked_sub(service_start)
                .and_then(|relative| relative.checked_add(1))
                .ok_or(ReduceError::InternalInvariant(
                    "adaptive reducer finder service reversed",
                ))?;
            actual.finder_scanned_bytes = actual
                .finder_scanned_bytes
                .checked_add(service)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer byte-set service bytes",
                })?;
            let start = anchor
                .checked_sub(fallback_offset)
                .ok_or(ReduceError::InternalInvariant(
                    "adaptive reducer byte-set anchor preceded its offset",
                ))?;
            actual.anchor_candidates = actual.anchor_candidates.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer byte-set candidates",
                },
            )?;
            if self.candidate_matches_skipping(
                haystack,
                start,
                fallback_offset,
                &mut actual.predicate_checks,
            )? {
                actual.match_events = actual.match_events.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer byte-set match events",
                    },
                )?;
                cursor = anchor.checked_add(self.width).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer byte-set accepted restart",
                    },
                )?;
                burst_rejections = 0;
            } else {
                cursor = anchor.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer byte-set rejected restart",
                })?;
                if burst_rejections == 0 {
                    burst_start = anchor;
                }
                burst_rejections = burst_rejections.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer byte-set rejection burst",
                    },
                )?;
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS
                    && dense_rejection_burst(burst_start, anchor, burst_rejections).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer byte-set rejection density",
                    },
                    )?
                {
                    let shift_start = cursor.checked_sub(fallback_offset).ok_or(
                        ReduceError::InternalInvariant(
                            "adaptive reducer Shift-And preceded the first untested start",
                        ),
                    )?;
                    return self.scan_shift_and_reporting_suffix(haystack, shift_start, actual);
                }
                if burst_rejections == ADAPTIVE_FALLBACK_REJECTIONS {
                    burst_rejections = 0;
                }
            }
        }
        Ok(())
    }

    fn scan_shift_and_reporting_suffix(
        &self,
        haystack: &[u8],
        first_untested_start: usize,
        actual: &mut AnchorActual,
    ) -> Result<(), ReduceError> {
        let remaining = haystack.get(first_untested_start..).ok_or(
            ReduceError::InternalInvariant("adaptive reducer Shift-And escaped input"),
        )?;
        if remaining.len() < self.width {
            return Ok(());
        }
        let mut state = 0_u64;
        for &byte in remaining {
            actual.shift_and_transitions = actual.shift_and_transitions.checked_add(1).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "adaptive reducer Shift-And transitions",
                },
            )?;
            state = (state.wrapping_shl(1) | 1) & self.masks[usize::from(byte)];
            if state & self.accepting_bit != 0 {
                actual.match_events = actual.match_events.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive reducer Shift-And match events",
                    },
                )?;
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
        let anchor_shift = u32::try_from(anchor_offset).map_err(|_| {
            ReduceError::ArithmeticOverflow {
                computation: "primary anchor verification shift",
            }
        })?;
        let mut remaining = self.nonuniversal_mask & !1_u64.checked_shl(anchor_shift).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "primary anchor verification bit",
            },
        )?;
        if let Some(position) = secondary_offset {
            let shift = u32::try_from(position).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "secondary anchor verification shift",
                }
            })?;
            remaining &= !1_u64.checked_shl(shift).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "secondary anchor verification bit",
                },
            )?;
        }
        if let Some(fallback) = self.adaptive_fallback.as_ref() {
            let position = usize::from(fallback.offset);
            if position != anchor_offset && Some(position) != secondary_offset {
                let shift = u32::try_from(position).map_err(|_| {
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive fallback verification shift",
                    }
                })?;
                let bit = 1_u64.checked_shl(shift).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive fallback verification bit",
                    },
                )?;
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

    fn candidate_matches_skipping(
        &self,
        haystack: &[u8],
        start: usize,
        skipped_offset: usize,
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
        let skipped_shift = u32::try_from(skipped_offset).map_err(|_| {
            ReduceError::ArithmeticOverflow {
                computation: "adaptive fallback verification shift",
            }
        })?;
        let mut remaining = self.nonuniversal_mask & !1_u64.checked_shl(skipped_shift).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "adaptive fallback verification bit",
            },
        )?;
        let primary_offset = usize::from(self.anchor.offset().ok_or(
            ReduceError::InternalInvariant("adaptive fallback lost its primary anchor"),
        )?);
        if primary_offset == skipped_offset {
            return Err(ReduceError::InternalInvariant(
                "adaptive fallback duplicated the primary anchor",
            ));
        }
        *predicate_checks = predicate_checks.checked_add(1).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "actual predicate checks",
            },
        )?;
        if !self
            .anchor
            .matches(*candidate.get(primary_offset).ok_or(
                ReduceError::InternalInvariant("adaptive primary escaped the candidate"),
            )?)
            .ok_or(ReduceError::InternalInvariant(
                "adaptive primary selected Shift-And",
            ))?
        {
            return Ok(false);
        }
        let primary_shift = u32::try_from(primary_offset).map_err(|_| {
            ReduceError::ArithmeticOverflow {
                computation: "adaptive primary verification shift",
            }
        })?;
        remaining &= !1_u64.checked_shl(primary_shift).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "adaptive primary verification bit",
            },
        )?;
        if let Some(secondary) = self.secondary_anchor {
            let secondary_offset = usize::from(secondary.offset().ok_or(
                ReduceError::InternalInvariant("adaptive secondary selected Shift-And"),
            )?);
            if secondary_offset != skipped_offset {
                if secondary_offset == primary_offset {
                    return Err(ReduceError::InternalInvariant(
                        "adaptive secondary duplicated the primary anchor",
                    ));
                }
                *predicate_checks = predicate_checks.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "actual predicate checks",
                    },
                )?;
                if !secondary
                    .matches(*candidate.get(secondary_offset).ok_or(
                        ReduceError::InternalInvariant(
                            "adaptive secondary escaped the candidate",
                        ),
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
                remaining &= !1_u64.checked_shl(secondary_shift).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "adaptive secondary verification bit",
                    },
                )?;
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
                work.checked_add(
                    actual
                        .shift_and_transitions
                        .checked_mul(TRANSITION_WORK)?,
                )
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
            work.checked_add(actual.anchor_candidates.checked_mul(ANCHOR_CANDIDATE_WORK)?)
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
        .and_then(|work| {
            work.checked_add(shift_and_transitions.checked_mul(TRANSITION_WORK)?)
        })
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
            assert_eq!(actual, expected, "cursor={cursor}, end={end}, bytes={bytes:?}");
            let Some(found) = actual else {
                break;
            };
            let jump = (jump_seed.wrapping_add(step) % 7).checked_add(1).unwrap();
            cursor = found.saturating_add(jump).min(end);
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
    fn shift_and_fallback_matches_exhaustive_short_reference_and_resets_on_accept() {
        const LEFT: &[(u8, u8)] = &[(b'a', b'c')];
        const RIGHT: &[(u8, u8)] = &[(b'd', b'f')];
        let predicates = [LEFT, RIGHT];
        let plan = FixedPredicateWord64Plan::build(&predicates, BuildLimits::unlimited()).unwrap();
        let alphabet = [b'a', b'b', b'c', b'd', b'e', b'f', b'x'];
        assert_eq!(
            plan.operation_identity(Operation::Count).reducer,
            Reducer::ShiftAnd
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
                assert_eq!(count.accounting.actual.transitions, haystack.len());
                assert_eq!(count.accounting.actual.finder_calls, 0);
                assert_eq!(count.accounting.actual.anchor_candidates, 0);
                assert_eq!(count.accounting.actual.predicate_checks, 0);
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
        let anchor = FixedPredicateWord64Plan::build(&[A], BuildLimits::unlimited()).unwrap();
        let shift_and = FixedPredicateWord64Plan::build(&[FULL], BuildLimits::unlimited()).unwrap();
        let haystack = [b'a', b'A', b'x', 0, u8::MAX];

        for (plan, expected, expected_work) in [(&anchor, 2_u64, 32_u64), (&shift_and, 5, 46)] {
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
        }
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
        // predicate check per candidate.
        assert_eq!(accounting.anchor_mask_reads, 512);
        assert_eq!(accounting.work_upper_bound, 2_063);
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
        assert_eq!(found, expected, "span haystack={haystack:?}, window={window:?}");
        assert_eq!(
            plan.find_window_value(haystack, window, limits).unwrap(),
            expected,
            "compact span haystack={haystack:?}, window={window:?}"
        );
        assert_eq!(span_accounting.identity.operation, SearchOperation::Span);

        let (exists, exists_accounting) =
            plan.is_match_window(haystack, window, limits).unwrap();
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

        let (selected_end, selected_accounting) = plan
            .selected_end_window(haystack, window, limits)
            .unwrap();
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
            for (predicates, expected_reducer) in [
                (one.as_slice(), Reducer::OneByteAnchor),
                (two.as_slice(), Reducer::TwoByteAnchor),
                (shift.as_slice(), Reducer::ShiftAnd),
            ] {
                let plan = FixedPredicateWord64Plan::build(
                    predicates,
                    BuildLimits::unlimited(),
                )
                .unwrap();
                assert_eq!(
                    plan.search_operation_identity(SearchOperation::Span)
                        .reducer,
                    expected_reducer
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
    fn first_match_search_closes_width_anchor_and_byte_domain_boundaries() {
        const SINGLE: &[(u8, u8)] = &[(0xFF, 0xFF)];
        const TWO: &[(u8, u8)] = &[(0, 0), (0xFF, 0xFF)];
        const MULTI: &[(u8, u8)] = &[(0, 3), (0x40, 0x42), (0x80, 0x82), (0xFE, 0xFF)];

        for width in [63, 64] {
            let predicates = vec![MULTI; width];
            let plan = FixedPredicateWord64Plan::build(
                &predicates,
                BuildLimits::unlimited(),
            )
            .unwrap();
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
            let plan = FixedPredicateWord64Plan::build(
                &predicates,
                BuildLimits::unlimited(),
            )
            .unwrap();
            let identity = plan.search_operation_identity(SearchOperation::Span);
            assert_eq!(identity.reducer, Reducer::OneByteAnchor);
            assert_eq!(usize::from(identity.anchor_offset), anchor_offset);
            let mut haystack = vec![0x80; 24];
            haystack[5 + anchor_offset] = 0xFF;
            assert_search_case(
                &plan,
                &predicates,
                &haystack,
                Window::full(&haystack),
            );
        }

        let two_predicates = [MULTI, MULTI, TWO, MULTI];
        let two = FixedPredicateWord64Plan::build(
            &two_predicates,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            two.search_operation_identity(SearchOperation::Span)
                .reducer,
            Reducer::TwoByteAnchor
        );
        for haystack in [
            &[0, 0, 0, 0][..],
            &[0x80, 0x80, 0xFF, 0x80][..],
            &[0x80, 0x80, 1, 0x80, 0x80, 0x80, 0, 0x80][..],
            &[0x80, 0x80, 0x80][..],
        ] {
            assert_search_case(
                &two,
                &two_predicates,
                haystack,
                Window::full(haystack),
            );
        }
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
            let predicates = [
                ASCII,
                fallback_predicate,
                ASCII,
                ASCII,
                HIGH_ANCHOR,
                FULL,
            ];
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
            let reporting_count = plan
                .count(&no_match, ReduceLimits::unlimited())
                .unwrap();
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
                    .checked_add(
                        reporting_count
                            .accounting
                            .actual
                            .shift_and_transitions
                    )
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
                AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(
                    set_words,
                ))),
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
            four
                .search_operation_identity(SearchOperation::Span)
                .adaptive_handoff,
            four_identity.adaptive_handoff
        );
    }

    #[test]
    fn identity_disables_adaptation_without_verification_predicates() {
        const PRIMARY: &[(u8, u8)] = &[(b'Q', b'Q')];
        const FULL: &[(u8, u8)] = &[(0, 0xFF)];
        let plan = FixedPredicateWord64Plan::build(
            &[FULL, PRIMARY, FULL, FULL],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let aggregate = plan.operation_identity(Operation::Count);
        let search = plan.search_operation_identity(SearchOperation::Span);
        assert_eq!(aggregate.verification_predicates, 0);
        assert_eq!(aggregate.secondary_anchor, None);
        assert_eq!(aggregate.adaptive_handoff, AdaptiveHandoffIdentity::Disabled);
        assert_eq!(search.verification_predicates, 0);
        assert_eq!(search.secondary_anchor, None);
        assert_eq!(search.adaptive_handoff, AdaptiveHandoffIdentity::Disabled);
    }

    #[test]
    fn classified_adaptive_finder_reuses_member_lanes_across_monotone_restarts() {
        let mut set_words = [0_u64; 4];
        for byte in [b'A', b'C', 0xFF] {
            set_words[usize::from(byte >> 6)] |= 1_u64 << u32::from(byte & 63);
        }
        let finders = [
            AdaptiveFinder::Four([b'A', b'B', b'C', b'D']),
            AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(
                set_words,
            ))),
        ];
        let bytes = [b'A'; 40];

        for finder in &finders {
            let mut cursor = AdaptiveFinderCursor::new(finder, &bytes, bytes.len());
            for position in 0..bytes.len() {
                assert_eq!(cursor.find(position), Some(position));
                assert_eq!(cursor.classified_chunks(), position / BYTE_SET_BLOCK_BYTES + 1);
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
            AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(
                set_words,
            ))),
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
            AdaptiveFinder::Set(ByteSetClassifier::new(ByteSet256::from_words(
                set_words,
            ))),
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
        const FOUR: &[(u8, u8)] = &[
            (b'a', b'a'),
            (b'c', b'c'),
            (b'e', b'e'),
            (0xFF, 0xFF),
        ];
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
                let span = plan
                    .span_sum(&haystack, ReduceLimits::unlimited())
                    .unwrap();
                assert_eq!(count.count, expected);
                assert_eq!(span.span_sum, expected * u64::try_from(plan.width()).unwrap());
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
                assert_search_case(
                    &plan,
                    predicates,
                    &haystack,
                    Window::full(&haystack),
                );

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
                assert_search_case(
                    &plan,
                    predicates,
                    &haystack,
                    Window::new(start, end),
                );
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
            for position in (0..64)
                .filter(|&position| position != 32)
                .take(expected)
            {
                predicates[position] = VERIFY;
            }
            let plan = FixedPredicateWord64Plan::build(
                predicates.as_slice(),
                BuildLimits::unlimited(),
            )
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
    fn adaptive_phase_boundaries_skip_impossible_trailing_work() {
        const PRIMARY: &[(u8, u8)] = &[(0x7F, 0x7F)];
        const FALLBACK: &[(u8, u8)] = &[(0x7F, 0x81)];
        const BROAD: &[(u8, u8)] = &[(0, 0x7E)];
        let positions = [PRIMARY, FALLBACK, BROAD, BROAD, BROAD, BROAD];
        let plan =
            FixedPredicateWord64Plan::build(&positions, BuildLimits::unlimited()).unwrap();
        assert!(matches!(
            plan.adaptive_fallback.map(|fallback| fallback.finder),
            Some(AdaptiveFinder::Three(0x7F, 0x80, 0x81))
        ));

        for (candidate_positions, expected_finder, expected_shift) in
            [(8_usize, 8_usize, 0_usize), (9, 9, 0), (16, 16, 0), (17, 16, 6)]
        {
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
