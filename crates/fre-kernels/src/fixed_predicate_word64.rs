//! Fixed-width byte-predicate matching with an exact anchor when one
//! exists and one 64-bit Shift-And state otherwise.
//!
//! Construction accepts between one and 64 nonempty byte predicates. Each
//! predicate is supplied as inclusive byte ranges and is compiled into a full
//! byte-to-position mask table. An exact
//! one-or-two-byte predicate drives a monotone candidate stream when available;
//! otherwise reduction performs one Shift-And transition per haystack byte.
//! Both reducers restart after each accepted word, allocate no operation
//! memory, and materialize no spans.

use core::{fmt, mem::size_of};

use memchr::{memchr, memchr2};

use crate::packed_ordered_literal_aggregate::byte_frequency_rank;

/// Stable identity for the fixed-predicate anchor-or-Shift-And strategy.
pub const PLAN_ID: &str = "fixed-predicate-word64.fixed-anchor-or-shift-and.nonoverlap.v4";
/// Stable identity for the count reducer.
pub const COUNT_OPERATION_ID: &str = "fixed-predicate-word64.count.v3";
/// Stable identity for the matched-byte-sum reducer.
pub const SPAN_SUM_OPERATION_ID: &str = "fixed-predicate-word64.span-sum.v3";
/// Version of the receipt-bearing fixed-predicate construction protocol.
pub const BUILD_ATTEMPT_ALGORITHM_VERSION: u32 = 4;
/// Version of the partial-actual fixed-predicate construction ledger.
pub const BUILD_ATTEMPT_ACCOUNTING_VERSION: u32 = 4;
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
    anchor: Anchor,
    build: BuildAccounting,
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
) -> Result<Anchor, BuildError> {
    let mut selected = Anchor::ShiftAnd;
    let mut selected_score = None;
    for position in 0..width {
        let shift = u32::try_from(position).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "anchor position shift conversion",
        })?;
        let bit = 1_u64
            .checked_shl(shift)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "anchor position mask",
            })?;
        let mut bytes = [0_u8; 2];
        let mut members = 0_usize;
        for byte in 0_u8..=u8::MAX {
            tracker.read_anchor_mask()?;
            if masks[usize::from(byte)] & bit != 0 {
                if let Some(slot) = bytes.get_mut(members) {
                    *slot = byte;
                }
                members = members
                    .checked_add(1)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "anchor member count",
                    })?;
            }
        }
        if (1..=2).contains(&members) {
            let rank = bytes[..members]
                .iter()
                .copied()
                .map(byte_frequency_rank)
                .max()
                .ok_or(BuildError::InternalInvariant(
                    "nonempty anchor lost its frequency rank",
                ))?;
            let score = (rank, members);
            if selected_score.is_some_and(|prior| score > prior) {
                continue;
            }
            selected_score = Some(score);
            selected = if members == 1 {
                Anchor::One {
                    offset: u8::try_from(position).map_err(|_| {
                        BuildError::InternalInvariant("anchor offset exceeded one byte")
                    })?,
                    byte: bytes[0],
                }
            } else {
                Anchor::Two {
                    offset: u8::try_from(position).map_err(|_| {
                        BuildError::InternalInvariant("anchor offset exceeded one byte")
                    })?,
                    first: bytes[0],
                    second: bytes[1],
                }
            };
        }
    }
    Ok(selected)
}

fn actual_build_work(
    width: usize,
    source_ranges: usize,
    member_writes: usize,
    anchor_mask_reads: usize,
) -> Result<u64, BuildError> {
    let work = source_ranges
        .checked_mul(RANGE_FIXED_WORK)
        .and_then(|range_work| MASK_SLOTS.checked_add(width)?.checked_add(range_work))
        .and_then(|work| work.checked_add(member_writes))
        .and_then(|work| work.checked_add(anchor_mask_reads))
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
            let anchor = select_anchor(&masks, preflight.width, &mut tracker)?;
            tracker.finish(preflight)?;
            let independently_counted_work = actual_build_work(
                preflight.width,
                preflight.source_ranges,
                member_writes,
                tracker.actual.anchor_mask_reads,
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
                anchor,
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

    /// Successful construction certificate.
    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
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
                    .checked_mul(self.width.checked_sub(1).ok_or(
                        ReduceError::InternalInvariant("validated word width became zero"),
                    )?)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "anchor predicate-check bound",
                    })?;
                let work = candidate_positions
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
                Ok(ReducerUpper {
                    transitions: input_bytes,
                    finder_calls,
                    anchor_candidates: candidate_positions,
                    predicate_checks,
                    work,
                })
            }
            Anchor::ShiftAnd => Ok(ReducerUpper {
                transitions: input_bytes,
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
            }
        }
        Some(count)
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
        for (position, &byte) in candidate.iter().enumerate() {
            if position == anchor_offset {
                continue;
            }
            let shift = u32::try_from(position).ok()?;
            let bit = 1_u64.checked_shl(shift)?;
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
            } else {
                cursor = anchor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "rejected anchor restart",
                    })?;
            }
        }
        Ok(actual)
    }

    #[inline]
    fn anchor_candidate_matches(
        &self,
        haystack: &[u8],
        start: usize,
        anchor_offset: usize,
        predicate_checks: &mut usize,
    ) -> Result<bool, ReduceError> {
        for position in 0..self.width {
            if position == anchor_offset {
                continue;
            }
            *predicate_checks =
                predicate_checks
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual predicate checks",
                    })?;
            let index = start
                .checked_add(position)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual predicate position",
                })?;
            let byte = *haystack.get(index).ok_or(ReduceError::InternalInvariant(
                "fixed predicate candidate escaped the input",
            ))?;
            let shift = u32::try_from(position).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual predicate bit shift",
            })?;
            let bit = 1_u64
                .checked_shl(shift)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual predicate bit",
                })?;
            if self.masks[usize::from(byte)] & bit == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn finish_anchor_actual(
        &self,
        input_bytes: usize,
        upper_bounds: ReduceUpperBounds,
        actual: AnchorActual,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let transitions = actual.finder_scanned_bytes;
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
    actual.input_bytes <= upper.input_bytes
        && actual.transitions <= upper.transitions
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
        // smallest exact anchor, without allocating.
        assert_eq!(accounting.anchor_mask_reads, 512);
        assert_eq!(accounting.work_upper_bound, 1_806);
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
        // prospective bound admits every valid start; actual service skips
        // past each accepted non-overlapping word.
        assert_eq!(upper.transitions, 12);
        assert_eq!(upper.anchor_candidates, 11);
        assert_eq!(upper.predicate_checks, 11);
        assert_eq!(upper.match_events, 6);
        assert_eq!(upper.span_sum, 12);
        assert_eq!(upper.reducer_steps, 13);
        assert_eq!(upper.work, 64);
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
}
