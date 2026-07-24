//! Fixed-width byte-predicate matching with one 64-bit Shift-And state.
//!
//! Construction accepts between two and 64 nonempty byte predicates. Each
//! predicate is supplied as inclusive ASCII-byte ranges and is compiled into
//! a byte-to-position mask table. Reduction performs exactly one state
//! transition per haystack byte, resets after each accepted word, allocates no
//! operation memory, and materializes no spans.

use core::{fmt, mem::size_of};

/// Stable identity for the fixed-predicate Shift-And strategy.
pub const PLAN_ID: &str = "fixed-predicate-word64.shift-and.ascii.nonoverlap.v1";
/// Stable identity for the count reducer.
pub const COUNT_OPERATION_ID: &str = "fixed-predicate-word64.count.v1";
/// Stable identity for the matched-byte-sum reducer.
pub const SPAN_SUM_OPERATION_ID: &str = "fixed-predicate-word64.span-sum.v1";
/// Minimum fixed word width accepted by this closed kernel.
pub const MIN_WIDTH: usize = 2;
/// Maximum fixed word width representable by one Shift-And state.
pub const MAX_WIDTH: usize = 64;

const MASK_SLOTS: usize = 128;
const MAX_MEMBERS_PER_RANGE: usize = 128;
const BUILD_FIXED_WORK: usize = 4;
const RANGE_FIXED_WORK: usize = 2;
const TRANSITION_WORK: usize = 6;
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
    /// Maximum Shift-And transitions.
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
    /// One transition for every input byte.
    pub transitions: usize,
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
    /// Shift-And state transitions.
    pub transitions: usize,
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
    /// One otherwise ordered range contains a non-ASCII byte.
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
    build: BuildAccounting,
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

fn compile_masks(positions: &[&[(u8, u8)]]) -> Result<([u64; MASK_SLOTS], usize), BuildError> {
    let mut masks = [0_u64; MASK_SLOTS];
    let mut member_writes = 0_usize;
    for (position, ranges) in positions.iter().enumerate() {
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
            if start > end {
                return Err(BuildError::ReversedRange {
                    position,
                    range,
                    start,
                    end,
                });
            }
            if !start.is_ascii() || !end.is_ascii() {
                return Err(BuildError::NonAsciiRange {
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
            }
        }
    }
    Ok((masks, member_writes))
}

fn actual_build_work(
    width: usize,
    source_ranges: usize,
    member_writes: usize,
) -> Result<u64, BuildError> {
    let work = source_ranges
        .checked_mul(RANGE_FIXED_WORK)
        .and_then(|range_work| MASK_SLOTS.checked_add(width)?.checked_add(range_work))
        .and_then(|work| work.checked_add(member_writes))
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
        let preflight = preflight_build(positions, limits)?;
        let (masks, member_writes) = compile_masks(positions)?;
        let work_charged =
            actual_build_work(preflight.width, preflight.source_ranges, member_writes)?;
        if work_charged > preflight.work_upper_bound {
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
            mask_zero_writes: MASK_SLOTS,
            position_visits: preflight.width,
            range_inspections: preflight.source_ranges,
            member_writes,
            work_upper_bound: preflight.work_upper_bound,
            work_charged,
            allocations: 0,
            reserves: 0,
            temporary_copies: 0,
            scratch_bytes: 0,
            persistent_bytes: preflight.persistent_bytes,
            peak_bytes: preflight.peak_bytes,
        };
        Ok(Self {
            masks,
            width: preflight.width,
            accepting_bit,
            build,
        })
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
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id,
            operation,
            semantics: MatchSemantics::FixedBytePredicates,
            selection: MatchSelection::LeftmostFirstNonOverlapping,
            width: self.width,
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

    fn preflight(
        &self,
        input_bytes: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        enforce_reduce_usize(input_bytes, limits.max_input_bytes, ReduceResource::Input)?;
        let transitions = input_bytes;
        enforce_reduce_usize(
            transitions,
            limits.max_transitions,
            ReduceResource::Transitions,
        )?;
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
        let reducer_steps =
            transitions
                .checked_add(REDUCE_FINAL_WORK)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reducer step bound",
                })?;
        enforce_reduce_usize(
            reducer_steps,
            limits.max_reducer_steps,
            ReduceResource::ReducerSteps,
        )?;
        let work_usize = transitions
            .checked_mul(TRANSITION_WORK)
            .and_then(|work| work.checked_add(match_events.checked_mul(MATCH_WORK)?))
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
            transitions,
            match_events,
            count,
            span_sum,
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

    fn execute(
        &self,
        haystack: &[u8],
        upper_bounds: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut state = 0_u64;
        let mut match_events = 0_usize;
        for &byte in haystack {
            let mask = self.masks.get(usize::from(byte)).copied().unwrap_or(0);
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
}

fn actual_within_upper(actual: ReduceActualCounters, upper: ReduceUpperBounds) -> bool {
    actual.input_bytes <= upper.input_bytes
        && actual.transitions <= upper.transitions
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
    fn shift_and_matches_exhaustive_short_reference_and_resets_on_accept() {
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
        assert_eq!(count.accounting.actual.transitions, haystack.len());
        assert_eq!(count.accounting.actual.input_bytes, haystack.len());
        assert_eq!(count.accounting.actual.match_events, 3);
    }

    #[test]
    fn width_and_range_semantic_boundaries_are_closed() {
        let no_positions: [&[(u8, u8)]; 0] = [];
        assert!(matches!(
            FixedPredicateWord64Plan::build(&no_positions, BuildLimits::unlimited()),
            Err(BuildError::WidthTooSmall { needed: 0, .. })
        ));
        assert!(matches!(
            FixedPredicateWord64Plan::build(&[A], BuildLimits::unlimited()),
            Err(BuildError::WidthTooSmall { needed: 1, .. })
        ));
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
        let non_ascii: &[(u8, u8)] = &[(0x7F, 0x80)];
        assert!(matches!(
            FixedPredicateWord64Plan::build(&[A, non_ascii], BuildLimits::unlimited()),
            Err(BuildError::NonAsciiRange {
                position: 1,
                range: 0,
                start: 0x7F,
                end: 0x80
            })
        ));

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
    fn build_limits_accept_exact_and_refuse_one_below() {
        let baseline = ab_plan();
        let accounting = baseline.build_accounting();
        assert_eq!(accounting.positions, 2);
        assert_eq!(accounting.source_ranges, 4);
        assert_eq!(accounting.allocations, 0);
        assert_eq!(accounting.reserves, 0);
        assert_eq!(accounting.temporary_copies, 0);
        assert_eq!(accounting.scratch_bytes, 0);
        // P=2, R=4 and every range has one member: U=128+P+130R+4,
        // while A=128+P+2R+B+4 with B=4.
        assert_eq!(accounting.work_upper_bound, 654);
        assert_eq!(accounting.work_charged, 146);
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
        // N=12, W=2, M=6 and m=3: U=6N+3M+1 and A=6N+3m+1.
        assert_eq!(upper.transitions, 12);
        assert_eq!(upper.match_events, 6);
        assert_eq!(upper.span_sum, 12);
        assert_eq!(upper.reducer_steps, 13);
        assert_eq!(upper.work, 91);
        assert_eq!(exact_result.accounting.actual.match_events, 3);
        assert_eq!(exact_result.accounting.actual.matched_bytes, 6);
        assert_eq!(exact_result.accounting.actual.work_charged, 82);

        let count_limits = ReduceLimits {
            max_span_sum: 0,
            ..exact
        };
        assert_eq!(plan.count(haystack, count_limits).unwrap().count, 3);

        macro_rules! assert_one_below {
            ($field:ident, $variant:ident) => {
                assert!(matches!(
                    plan.span_sum(
                        haystack,
                        ReduceLimits {
                            $field: exact.$field - 1,
                            ..exact
                        }
                    ),
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
    fn inclusive_ascii_ranges_union_without_allocation_and_high_bytes_mismatch() {
        const FIRST: &[(u8, u8)] = &[(0, 2), (2, 3)];
        const SECOND: &[(u8, u8)] = &[(b'a', b'c')];
        let plan =
            FixedPredicateWord64Plan::build(&[FIRST, SECOND], BuildLimits::unlimited()).unwrap();
        let result = plan
            .count(
                &[0, b'a', 2, b'b', 0xFF, b'c', 3, b'c', 4, b'a'],
                ReduceLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(result.count, 3);
        assert_eq!(plan.build_accounting().allocations, 0);
        assert_eq!(plan.build_accounting().reserves, 0);
        assert_eq!(plan.build_accounting().temporary_copies, 0);
        assert_eq!(result.accounting.upper_bounds.scratch_bytes, 0);
    }
}
