//! Direct whole-operation reduction for one canonical Unicode scalar class or
//! its nonempty repetition.
//!
//! Construction copies a sorted, disjoint sequence of inclusive scalar
//! ranges into a compact ASCII bitmap plus non-ASCII `(u32, u32)` pairs.
//! Execution walks the requested byte window once. Every valid UTF-8 scalar
//! start is decoded exactly once, invalid bytes advance by one byte and never
//! match, and membership is one bitmap test or a binary search over the
//! immutable non-ASCII ranges. Exact-one and lazy-one-or-more emit every
//! matching scalar. Greedy-one-or-more emits one match for each maximal run of
//! matching scalars. Non-nullable bounded and lower-bounded repetitions use
//! the same fixed deterministic run reducer: it retains only the current
//! scalar count and byte sum, never a boundary-indexed state set.
//!
//! For `N` input bytes and `R` retained non-ASCII ranges, execution takes
//! `O(N log(R + 1))` work, retains `O(R)` bytes, and uses no dynamic scratch.

use core::{fmt, mem::size_of};

use crate::Window;

/// Stable identity for the scalar-stream implementation.
pub const PLAN_ID: &str = "unicode-scalar-aggregate.ascii-runs-utf8-stream-ranges.v2";
/// Stable identity for the deterministic nonempty run reducer.
pub const RUN_PLAN_ID: &str = "unicode-scalar-aggregate.ascii-runs-utf8-stream-ranges.run-plus.v2";
/// Stable identity for symbolic counted/lower-bounded repetition.
pub const REPEATED_RUN_PLAN_ID: &str =
    "unicode-scalar-aggregate.ascii-runs-utf8-stream-ranges.run-counted.v1";
/// Stable identity for the match-count reducer.
pub const COUNT_OPERATION_ID: &str = "unicode-scalar-aggregate.count.valid-scalar.v1";
/// Stable identity for the matched-byte-sum reducer.
pub const SPAN_SUM_OPERATION_ID: &str = "unicode-scalar-aggregate.span-sum.valid-scalar.v1";
/// Stable identity for greedy/lazy nonempty run counting.
pub const RUN_COUNT_OPERATION_ID: &str = "unicode-scalar-aggregate.count.run-plus.v1";
/// Stable identity for greedy/lazy nonempty run matched-byte summation.
pub const RUN_SPAN_SUM_OPERATION_ID: &str = "unicode-scalar-aggregate.span-sum.run-plus.v1";
/// Stable identity for counted/lower-bounded repetition counting.
pub const REPEATED_RUN_COUNT_OPERATION_ID: &str =
    "unicode-scalar-aggregate.count.run-counted.v1";
/// Stable identity for counted/lower-bounded matched-byte summation.
pub const REPEATED_RUN_SPAN_SUM_OPERATION_ID: &str =
    "unicode-scalar-aggregate.span-sum.run-counted.v1";

/// Complete reducer selected for one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Count,
    SpanSum,
}

/// Root HIR shape reduced by the scalar stream.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Repetition {
    /// One scalar-class atom.
    ExactlyOne,
    /// Greedy `CLASS+`: one match per maximal matching run.
    OneOrMoreGreedy,
    /// Lazy `CLASS+?`: one match per matching scalar.
    OneOrMoreLazy,
    /// A non-nullable repetition not represented by the two common `+`
    /// variants. `maximum == None` denotes an unbounded upper limit.
    RepeatedGreedy {
        minimum: u32,
        maximum: Option<u32>,
    },
    /// Lazy form of [`Repetition::RepeatedGreedy`].
    RepeatedLazy {
        minimum: u32,
        maximum: Option<u32>,
    },
}

impl Repetition {
    /// Whether this shape uses the deterministic nonempty run reducer.
    #[must_use]
    pub const fn is_run(self) -> bool {
        !matches!(self, Self::ExactlyOne)
    }

    const fn is_repeated(self) -> bool {
        matches!(
            self,
            Self::RepeatedGreedy { .. } | Self::RepeatedLazy { .. }
        )
    }

    const fn bounds(self) -> Option<(u32, Option<u32>, bool)> {
        match self {
            Self::ExactlyOne => None,
            Self::OneOrMoreGreedy => Some((1, None, true)),
            Self::OneOrMoreLazy => Some((1, None, false)),
            Self::RepeatedGreedy { minimum, maximum } => Some((minimum, maximum, true)),
            Self::RepeatedLazy { minimum, maximum } => Some((minimum, maximum, false)),
        }
    }
}

/// UTF-8 and iteration semantics certified by this plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarSemantics {
    /// Canonical UTF-8 scalars match by HIR class membership. Invalid,
    /// overlong, truncated and surrogate encodings never match and advance
    /// the search by one byte.
    RustBytesUnicodeUtf8False,
}

/// Stable semantic and implementation identity for one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub operation: Operation,
    pub scalar_semantics: ScalarSemantics,
    pub repetition: Repetition,
    pub non_overlapping: bool,
}

impl OperationIdentity {
    #[must_use]
    pub const fn for_operation(operation: Operation) -> Self {
        Self::for_repetition(operation, Repetition::ExactlyOne)
    }

    /// Return the immutable identity for an exact atom or proved `+` root.
    #[must_use]
    pub const fn for_repetition(operation: Operation, repetition: Repetition) -> Self {
        let operation_id = match (repetition.is_run(), repetition.is_repeated(), operation) {
            (false, _, Operation::Count) => COUNT_OPERATION_ID,
            (false, _, Operation::SpanSum) => SPAN_SUM_OPERATION_ID,
            (true, false, Operation::Count) => RUN_COUNT_OPERATION_ID,
            (true, false, Operation::SpanSum) => RUN_SPAN_SUM_OPERATION_ID,
            (true, true, Operation::Count) => REPEATED_RUN_COUNT_OPERATION_ID,
            (true, true, Operation::SpanSum) => REPEATED_RUN_SPAN_SUM_OPERATION_ID,
        };
        Self {
            plan_id: if repetition.is_repeated() {
                REPEATED_RUN_PLAN_ID
            } else if repetition.is_run() {
                RUN_PLAN_ID
            } else {
                PLAN_ID
            },
            operation_id,
            operation,
            scalar_semantics: ScalarSemantics::RustBytesUnicodeUtf8False,
            repetition,
            non_overlapping: true,
        }
    }
}

/// Limits checked while constructing one scalar-class plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_source_ranges: usize::MAX,
            max_build_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_ranges: 1 << 16,
            max_build_work: 1 << 20,
            max_scratch_bytes: 1 << 20,
            max_persistent_bytes: 1 << 20,
            max_peak_bytes: 2 << 20,
        }
    }
}

/// Auditable construction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub source_ranges: usize,
    pub retained_non_ascii_ranges: usize,
    pub ascii_scalars: usize,
    /// Root atom/repetition shape retained in the executable plan.
    pub repetition: Repetition,
    pub range_payload_bytes: usize,
    pub work: usize,
    pub temporary_capacity_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Limits checked before a scalar-stream traversal begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_decode_byte_checks: usize,
    pub max_membership_tests: usize,
    pub max_range_comparisons: usize,
    /// Maximum deterministic reducer transitions after scalar decoding.
    pub max_reducer_steps: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_work: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_decode_byte_checks: usize::MAX,
            max_membership_tests: usize::MAX,
            max_range_comparisons: usize::MAX,
            max_reducer_steps: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_decode_byte_checks: 512 << 20,
            max_membership_tests: 128 << 20,
            max_range_comparisons: 2 << 30,
            max_reducer_steps: (128 << 20) + 1,
            max_match_events: 128 << 20,
            max_count: 128 << 20,
            max_span_sum: 128 << 20,
            max_work: usize::MAX,
            max_scratch_bytes: 0,
            max_peak_bytes: 2 << 20,
        }
    }
}

/// Bounds checked before traversal and attached to a successful result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub decode_byte_checks: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub binary_search_comparisons_per_scalar: usize,
    pub reducer_steps: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact structural counters after a complete successful traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes_advanced: usize,
    pub decode_byte_checks: usize,
    pub valid_scalars: usize,
    pub invalid_bytes: usize,
    /// ASCII bytes consumed by maximal-run reduction before the general
    /// UTF-8 decoder. This is also the exact number of ASCII bitmap tests.
    pub ascii_run_bytes: usize,
    pub ascii_bitmap_tests: usize,
    pub non_ascii_membership_tests: usize,
    pub range_comparisons: usize,
    pub reducer_steps: usize,
    pub run_flushes: usize,
    pub match_events: usize,
    pub count: u64,
    pub matched_bytes: u64,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Upper bounds and exact counters for one result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub window: Window,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

/// Checked construction failure. No partial plan is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass,
    InvalidRepetition {
        minimum: u32,
        maximum: Option<u32>,
    },
    ReversedRange { start: char, end: char },
    NonCanonicalRanges,
    RangeLimit { needed: usize, limit: usize },
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { additional: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyClass => f.write_str("Unicode scalar plan needs a nonempty class"),
            Self::InvalidRepetition { minimum, maximum } => write!(
                f,
                "Unicode scalar repetition must be non-nullable and ordered, got {minimum}..={maximum:?}"
            ),
            Self::ReversedRange { start, end } => {
                write!(f, "Unicode scalar range {start:?}..={end:?} is reversed")
            }
            Self::NonCanonicalRanges => {
                f.write_str("Unicode scalar ranges are not sorted, disjoint and non-adjacent")
            }
            Self::RangeLimit { needed, limit } => {
                write!(f, "Unicode class needs {needed} ranges, limit is {limit}")
            }
            Self::WorkLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode class build needs {needed} work, limit is {limit}"
                )
            }
            Self::ScratchLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode class build needs {needed} scratch bytes, limit is {limit}"
                )
            }
            Self::PersistentLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode class plan needs {needed} bytes, limit is {limit}"
                )
            }
            Self::PeakLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode class build peak is {needed} bytes, limit is {limit}"
                )
            }
            Self::AllocationFailed { additional } => {
                write!(f, "failed to reserve {additional} Unicode scalar ranges")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Checked operation failure. No partial result is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    InputBytesLimit {
        needed: usize,
        limit: usize,
    },
    DecodeByteChecksLimit {
        needed: usize,
        limit: usize,
    },
    MembershipTestsLimit {
        needed: usize,
        limit: usize,
    },
    RangeComparisonsLimit {
        needed: usize,
        limit: usize,
    },
    ReducerStepsLimit {
        needed: usize,
        limit: usize,
    },
    MatchEventsLimit {
        needed: usize,
        limit: usize,
    },
    CountLimit {
        needed: u64,
        limit: u64,
    },
    SpanSumLimit {
        needed: u64,
        limit: u64,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "invalid Unicode scalar window {start}..{end} for haystack length {haystack_len}"
            ),
            Self::InputBytesLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode scalar scan needs {needed} input bytes, limit is {limit}"
                )
            }
            Self::DecodeByteChecksLimit { needed, limit } => write!(
                f,
                "Unicode scalar scan may need {needed} decode byte checks, limit is {limit}"
            ),
            Self::MembershipTestsLimit { needed, limit } => write!(
                f,
                "Unicode scalar scan may need {needed} membership tests, limit is {limit}"
            ),
            Self::RangeComparisonsLimit { needed, limit } => write!(
                f,
                "Unicode scalar scan may need {needed} range comparisons, limit is {limit}"
            ),
            Self::ReducerStepsLimit { needed, limit } => write!(
                f,
                "Unicode scalar reducer may need {needed} transitions, limit is {limit}"
            ),
            Self::MatchEventsLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode scalar scan may emit {needed} matches, limit is {limit}"
                )
            }
            Self::CountLimit { needed, limit } => {
                write!(f, "Unicode scalar count may be {needed}, limit is {limit}")
            }
            Self::SpanSumLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode scalar span sum may be {needed}, limit is {limit}"
                )
            }
            Self::WorkLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode scalar scan may need {needed} work, limit is {limit}"
                )
            }
            Self::ScratchLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode scalar scan needs {needed} scratch bytes, limit is {limit}"
                )
            }
            Self::PeakLimit { needed, limit } => {
                write!(
                    f,
                    "Unicode scalar scan peak is {needed} bytes, limit is {limit}"
                )
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarRange {
    start: u32,
    end: u32,
}

/// Owned, non-`Clone` plan for one canonical Unicode scalar class.
#[derive(Debug)]
pub struct UnicodeScalarAggregatePlan {
    ascii: [u64; 2],
    non_ascii: Box<[ScalarRange]>,
    repetition: Repetition,
    build: BuildAccounting,
}

impl UnicodeScalarAggregatePlan {
    /// Copy one canonical sequence of inclusive scalar ranges.
    pub fn build(
        ranges: impl IntoIterator<Item = (char, char)>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_with_repetition(ranges, Repetition::ExactlyOne, limits)
    }

    /// Copy a canonical scalar class for a proved nonempty unbounded root
    /// repetition.
    pub fn build_one_or_more(
        ranges: impl IntoIterator<Item = (char, char)>,
        greedy: bool,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let repetition = if greedy {
            Repetition::OneOrMoreGreedy
        } else {
            Repetition::OneOrMoreLazy
        };
        Self::build_with_repetition(ranges, repetition, limits)
    }

    /// Copy a canonical scalar class for a proved non-nullable root
    /// repetition. This keeps counted repetition symbolic instead of
    /// expanding the class into UTF-8 paths or repeated automaton states.
    pub fn build_repeated(
        ranges: impl IntoIterator<Item = (char, char)>,
        minimum: u32,
        maximum: Option<u32>,
        greedy: bool,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        if minimum == 0 || maximum.is_some_and(|maximum| maximum < minimum) {
            return Err(BuildError::InvalidRepetition { minimum, maximum });
        }
        let repetition = match (minimum, maximum, greedy) {
            (1, None, true) => Repetition::OneOrMoreGreedy,
            (1, None, false) => Repetition::OneOrMoreLazy,
            (_, _, true) => Repetition::RepeatedGreedy { minimum, maximum },
            (_, _, false) => Repetition::RepeatedLazy { minimum, maximum },
        };
        Self::build_with_repetition(ranges, repetition, limits)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps canonical validation and all checked storage accounting in one auditable transaction"
    )]
    fn build_with_repetition(
        ranges: impl IntoIterator<Item = (char, char)>,
        repetition: Repetition,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        let mut ascii = [0_u64; 2];
        let mut non_ascii = Vec::<ScalarRange>::new();
        let mut source_ranges = 0_usize;
        let mut ascii_scalars = 0_usize;
        let mut work = 0_usize;
        let mut previous_end = None::<u32>;

        for (start, end) in ranges {
            if start > end {
                return Err(BuildError::ReversedRange { start, end });
            }
            let start = u32::from(start);
            let end = u32::from(end);
            if previous_end.is_some_and(|previous| start <= previous.saturating_add(1)) {
                return Err(BuildError::NonCanonicalRanges);
            }
            previous_end = Some(end);
            source_ranges = checked_add(source_ranges, 1, "source range count")?;
            enforce_build(
                source_ranges,
                limits.max_source_ranges,
                BuildResource::Ranges,
            )?;
            work = checked_add(work, 1, "range validation work")?;

            if start <= 0x7F {
                let ascii_end = end.min(0x7F);
                let mut scalar = start;
                loop {
                    let index = usize::try_from(scalar / 64).map_err(|_| {
                        BuildError::ArithmeticOverflow {
                            computation: "ASCII bitmap index",
                        }
                    })?;
                    let shift = scalar % 64;
                    ascii[index] |= 1_u64 << shift;
                    ascii_scalars = checked_add(ascii_scalars, 1, "ASCII population")?;
                    work = checked_add(work, 1, "ASCII bitmap build work")?;
                    if scalar == ascii_end {
                        break;
                    }
                    scalar = scalar
                        .checked_add(1)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "ASCII scalar progression",
                        })?;
                }
            }
            if end > 0x7F {
                let retained = ScalarRange {
                    start: start.max(0x80),
                    end,
                };
                non_ascii
                    .try_reserve(1)
                    .map_err(|_| BuildError::AllocationFailed { additional: 1 })?;
                non_ascii.push(retained);
                work = checked_add(work, 1, "range copy work")?;
            }
            enforce_build(work, limits.max_build_work, BuildResource::Work)?;
        }
        if source_ranges == 0 {
            return Err(BuildError::EmptyClass);
        }
        if repetition.is_run() {
            work = checked_add(work, 1, "repetition configuration work")?;
            enforce_build(work, limits.max_build_work, BuildResource::Work)?;
        }

        let range_payload_bytes = non_ascii
            .len()
            .checked_mul(size_of::<ScalarRange>())
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "range payload bytes",
            })?;
        let temporary_capacity_bytes = non_ascii
            .capacity()
            .checked_mul(size_of::<ScalarRange>())
            .ok_or(BuildError::ArithmeticOverflow {
            computation: "temporary range capacity bytes",
        })?;
        let persistent_bytes = size_of::<Self>().checked_add(range_payload_bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "persistent scalar plan bytes",
            },
        )?;
        let peak_bytes = persistent_bytes
            .checked_add(temporary_capacity_bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "scalar plan construction peak",
            })?;
        enforce_build(
            temporary_capacity_bytes,
            limits.max_scratch_bytes,
            BuildResource::Scratch,
        )?;
        enforce_build(
            persistent_bytes,
            limits.max_persistent_bytes,
            BuildResource::Persistent,
        )?;
        enforce_build(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

        let retained_non_ascii_ranges = non_ascii.len();
        let build = BuildAccounting {
            source_ranges,
            retained_non_ascii_ranges,
            ascii_scalars,
            repetition,
            range_payload_bytes,
            work,
            temporary_capacity_bytes,
            scratch_bytes: temporary_capacity_bytes,
            persistent_bytes,
            peak_bytes,
        };
        Ok(Self {
            ascii,
            non_ascii: non_ascii.into_boxed_slice(),
            repetition,
            build,
        })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity::for_repetition(Operation::Count, self.repetition)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        OperationIdentity::for_repetition(Operation::SpanSum, self.repetition)
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        self.count_in(haystack, Window::full(haystack), limits)
    }

    pub fn count_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack, window, Operation::Count, limits)?;
        let actual = self.execute(haystack, window, upper_bounds)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                window,
                upper_bounds,
                actual,
            },
        })
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        self.span_sum_in(haystack, Window::full(haystack), limits)
    }

    pub fn span_sum_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let upper_bounds = self.preflight(haystack, window, Operation::SpanSum, limits)?;
        let actual = self.execute(haystack, window, upper_bounds)?;
        Ok(SpanSumResult {
            span_sum: actual.matched_bytes,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                window,
                upper_bounds,
                actual,
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "preflight keeps every operation upper bound and its matching limit check adjacent"
    )]
    fn preflight(
        &self,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let input_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "window byte length",
                })?;
        let decode_byte_checks =
            input_bytes
                .checked_mul(4)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "decode byte check upper bound",
                })?;
        let binary_search_comparisons_per_scalar =
            binary_search_comparison_bound(self.non_ascii.len())
                .checked_add(usize::from(
                    self.repetition.is_run() && !self.non_ascii.is_empty(),
                ))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cached range comparison upper bound",
                })?;
        let membership_tests = input_bytes;
        let range_comparisons = input_bytes
            .checked_mul(binary_search_comparisons_per_scalar)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "range comparison upper bound",
            })?;
        let reducer_steps = if self.repetition.is_run() {
            input_bytes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "run reducer transition upper bound",
                })?
        } else {
            0
        };
        let match_events = input_bytes;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "count upper bound",
        })?;
        let span_sum = u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "span sum upper bound",
        })?;
        let work = decode_byte_checks
            .checked_add(membership_tests)
            .and_then(|value| value.checked_add(range_comparisons))
            .and_then(|value| value.checked_add(reducer_steps))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution work upper bound",
            })?;
        let scratch_bytes = 0;
        let persistent_bytes = self.build.persistent_bytes;
        let peak_bytes = persistent_bytes;
        let upper = ReduceUpperBounds {
            input_bytes,
            decode_byte_checks,
            membership_tests,
            range_comparisons,
            binary_search_comparisons_per_scalar,
            reducer_steps,
            match_events,
            count,
            span_sum,
            work,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        };
        enforce_reduce(
            input_bytes,
            limits.max_input_bytes,
            ReduceResource::InputBytes,
        )?;
        enforce_reduce(
            decode_byte_checks,
            limits.max_decode_byte_checks,
            ReduceResource::DecodeByteChecks,
        )?;
        enforce_reduce(
            membership_tests,
            limits.max_membership_tests,
            ReduceResource::MembershipTests,
        )?;
        enforce_reduce(
            range_comparisons,
            limits.max_range_comparisons,
            ReduceResource::RangeComparisons,
        )?;
        enforce_reduce(
            reducer_steps,
            limits.max_reducer_steps,
            ReduceResource::ReducerSteps,
        )?;
        enforce_reduce(
            match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        )?;
        if count > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: count,
                limit: limits.max_count,
            });
        }
        if operation == Operation::SpanSum && span_sum > limits.max_span_sum {
            return Err(ReduceError::SpanSumLimit {
                needed: span_sum,
                limit: limits.max_span_sum,
            });
        }
        enforce_reduce(work, limits.max_work, ReduceResource::Work)?;
        enforce_reduce(
            scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(peak_bytes, limits.max_peak_bytes, ReduceResource::Peak)?;
        Ok(upper)
    }

    #[allow(
        clippy::too_many_lines,
        clippy::arithmetic_side_effects,
        reason = "the single streaming loop keeps UTF-8 progression, reduction and exact structural accounting visibly coupled; its only unchecked local arithmetic advances within the current slice or subtracts an earlier cursor"
    )]
    fn execute(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        match self.repetition {
            Repetition::ExactlyOne => {
                self.execute_mode::<false, false, false, false>(
                    haystack,
                    window,
                    upper,
                    1,
                    Some(1),
                )
            }
            Repetition::OneOrMoreGreedy if self.non_ascii.is_empty() => {
                self.execute_mode::<true, true, false, false>(haystack, window, upper, 1, None)
            }
            Repetition::OneOrMoreGreedy => {
                self.execute_mode::<true, true, true, false>(haystack, window, upper, 1, None)
            }
            Repetition::OneOrMoreLazy if self.non_ascii.is_empty() => {
                self.execute_mode::<true, false, false, false>(haystack, window, upper, 1, None)
            }
            Repetition::OneOrMoreLazy => {
                self.execute_mode::<true, false, true, false>(haystack, window, upper, 1, None)
            }
            repetition
                @ (Repetition::RepeatedGreedy { .. } | Repetition::RepeatedLazy { .. }) =>
            {
                let (minimum, maximum, greedy) = repetition
                    .bounds()
                    .expect("repeated variants always have bounds");
                if greedy {
                    if self.non_ascii.is_empty() {
                        self.execute_mode::<true, true, false, true>(
                            haystack, window, upper, minimum, maximum,
                        )
                    } else {
                        self.execute_mode::<true, true, true, true>(
                            haystack, window, upper, minimum, maximum,
                        )
                    }
                } else if self.non_ascii.is_empty() {
                    self.execute_mode::<true, false, false, true>(
                        haystack, window, upper, minimum, maximum,
                    )
                } else {
                    self.execute_mode::<true, false, true, true>(
                        haystack, window, upper, minimum, maximum,
                    )
                }
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        clippy::arithmetic_side_effects,
        reason = "the monomorphized streaming loop keeps UTF-8 progression, reduction and exact structural accounting visibly coupled while removing all repetition-mode branches from execution"
    )]
    fn execute_mode<
        const RUN: bool,
        const GREEDY: bool,
        const CACHE_RANGE: bool,
        const GENERAL_REPETITION: bool,
    >(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
        minimum: u32,
        maximum: Option<u32>,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let local = &haystack[window.start()..window.end()];
        let mut position = 0_usize;
        let mut pending_run_bytes = 0_u64;
        let mut pending_run_scalars = 0_u64;
        let mut cached_non_ascii_range = None::<usize>;
        let mut actual = ReduceActualCounters {
            input_bytes_advanced: 0,
            decode_byte_checks: 0,
            valid_scalars: 0,
            invalid_bytes: 0,
            ascii_run_bytes: 0,
            ascii_bitmap_tests: 0,
            non_ascii_membership_tests: 0,
            range_comparisons: 0,
            reducer_steps: 0,
            run_flushes: 0,
            match_events: 0,
            count: 0,
            matched_bytes: 0,
            work: 0,
            scratch_bytes: 0,
        };
        while position < local.len() {
            // ASCII is both one byte wide and always a valid UTF-8 scalar.
            // Reduce a maximal run without constructing a `DecodedScalar` or
            // performing checked accounting for every byte. The bitmap test
            // remains pointwise, so arbitrary scalar classes and match
            // positions retain exactly the same semantics.
            if local[position].is_ascii() {
                let run_start = position;
                let mut run_matches = 0_usize;
                while position < local.len() {
                    let byte = local[position];
                    if !byte.is_ascii() {
                        break;
                    }
                    let word = self.ascii[usize::from(byte / 64)];
                    let matched = word & (1_u64 << (byte % 64)) != 0;
                    if GENERAL_REPETITION {
                        if matched {
                            reduce_repeated_scalar(
                                &mut actual,
                                &mut pending_run_bytes,
                                &mut pending_run_scalars,
                                1,
                                minimum,
                                maximum,
                                GREEDY,
                            )?;
                        } else {
                            finish_repeated_run(
                                &mut actual,
                                &mut pending_run_bytes,
                                &mut pending_run_scalars,
                                minimum,
                                GREEDY,
                            )?;
                        }
                    } else if GREEDY {
                        if matched {
                            pending_run_bytes = pending_run_bytes.checked_add(1).ok_or(
                                ReduceError::ArithmeticOverflow {
                                    computation: "pending greedy ASCII-run bytes",
                                },
                            )?;
                        } else {
                            flush_greedy_run(&mut actual, &mut pending_run_bytes)?;
                        }
                    } else if matched {
                        // At most one match is recorded per byte in this run,
                        // so this cannot exceed the enclosing slice length.
                        run_matches += 1;
                    }
                    // `position < local.len()` proves this addition cannot
                    // overflow and remains within the slice boundary.
                    position += 1;
                }
                let run_bytes = position - run_start;
                actual.decode_byte_checks = actual
                    .decode_byte_checks
                    .checked_add(run_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual ASCII-run decode byte checks",
                    })?;
                actual.valid_scalars = actual.valid_scalars.checked_add(run_bytes).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "actual ASCII-run valid scalars",
                    },
                )?;
                actual.ascii_run_bytes = actual.ascii_run_bytes.checked_add(run_bytes).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "actual ASCII-run bytes",
                    },
                )?;
                actual.ascii_bitmap_tests = actual
                    .ascii_bitmap_tests
                    .checked_add(run_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual ASCII-run bitmap tests",
                    })?;
                if RUN {
                    actual.reducer_steps = actual.reducer_steps.checked_add(run_bytes).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual ASCII-run reducer transitions",
                        },
                    )?;
                }
                if !GREEDY && !GENERAL_REPETITION {
                    actual.match_events = actual.match_events.checked_add(run_matches).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual ASCII-run match events",
                        },
                    )?;
                    let run_matches = u64::try_from(run_matches).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "actual ASCII-run matches",
                        }
                    })?;
                    actual.count = actual.count.checked_add(run_matches).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual ASCII-run count",
                        },
                    )?;
                    actual.matched_bytes = actual.matched_bytes.checked_add(run_matches).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual ASCII-run matched bytes",
                        },
                    )?;
                }
                continue;
            }
            if RUN {
                actual.reducer_steps =
                    actual
                        .reducer_steps
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual run reducer transitions",
                        })?;
            }
            let decoded = decode_scalar(&local[position..]);
            actual.decode_byte_checks = actual
                .decode_byte_checks
                .checked_add(decoded.byte_checks)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual decode byte checks",
                })?;
            let matched =
                if let Some(scalar) = decoded.scalar {
                    actual.valid_scalars = actual.valid_scalars.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual valid scalars",
                        },
                    )?;
                    // The maximal ASCII-run branch above proves that every
                    // successfully decoded scalar here is non-ASCII.
                    debug_assert!(scalar > 0x7F);
                    actual.non_ascii_membership_tests = actual
                        .non_ascii_membership_tests
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual non-ASCII membership tests",
                        })?;
                    let (contains, comparisons) = if CACHE_RANGE {
                        self.contains_non_ascii_run(scalar, &mut cached_non_ascii_range)?
                    } else {
                        self.contains_non_ascii(scalar)?
                    };
                    actual.range_comparisons = actual
                        .range_comparisons
                        .checked_add(comparisons)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual range comparisons",
                        })?;
                    contains
                } else {
                    actual.invalid_bytes = actual.invalid_bytes.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual invalid bytes",
                        },
                    )?;
                    false
                };
            if matched {
                let width =
                    u64::try_from(decoded.width).map_err(|_| ReduceError::ArithmeticOverflow {
                        computation: "matched scalar width",
                    })?;
                if GENERAL_REPETITION {
                    reduce_repeated_scalar(
                        &mut actual,
                        &mut pending_run_bytes,
                        &mut pending_run_scalars,
                        width,
                        minimum,
                        maximum,
                        GREEDY,
                    )?;
                } else if GREEDY {
                    pending_run_bytes = pending_run_bytes.checked_add(width).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "pending greedy run bytes",
                        },
                    )?;
                } else {
                    record_match(&mut actual, width)?;
                }
            } else if GENERAL_REPETITION {
                finish_repeated_run(
                    &mut actual,
                    &mut pending_run_bytes,
                    &mut pending_run_scalars,
                    minimum,
                    GREEDY,
                )?;
            } else if GREEDY {
                flush_greedy_run(&mut actual, &mut pending_run_bytes)?;
            }
            position =
                position
                    .checked_add(decoded.width)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "scalar stream position",
                    })?;
        }
        if RUN {
            actual.reducer_steps =
                actual
                    .reducer_steps
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "final run reducer transition",
                    })?;
        }
        if GENERAL_REPETITION {
            finish_repeated_run(
                &mut actual,
                &mut pending_run_bytes,
                &mut pending_run_scalars,
                minimum,
                GREEDY,
            )?;
        } else if GREEDY {
            flush_greedy_run(&mut actual, &mut pending_run_bytes)?;
        }
        actual.input_bytes_advanced = position;
        let membership_tests = actual
            .ascii_bitmap_tests
            .checked_add(actual.non_ascii_membership_tests)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual membership tests",
            })?;
        actual.work = actual
            .decode_byte_checks
            .checked_add(membership_tests)
            .and_then(|value| value.checked_add(actual.range_comparisons))
            .and_then(|value| value.checked_add(actual.reducer_steps))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual execution work",
            })?;
        debug_assert!(actual.input_bytes_advanced <= upper.input_bytes);
        debug_assert!(actual.decode_byte_checks <= upper.decode_byte_checks);
        debug_assert_eq!(actual.ascii_run_bytes, actual.ascii_bitmap_tests);
        debug_assert!(membership_tests <= upper.membership_tests);
        debug_assert!(actual.range_comparisons <= upper.range_comparisons);
        debug_assert!(actual.reducer_steps <= upper.reducer_steps);
        debug_assert!(actual.match_events <= upper.match_events);
        debug_assert!(actual.count <= upper.count);
        debug_assert!(actual.matched_bytes <= upper.span_sum);
        debug_assert!(actual.work <= upper.work);
        Ok(actual)
    }

    fn contains_non_ascii(&self, scalar: u32) -> Result<(bool, usize), ReduceError> {
        let mut low = 0_usize;
        let mut high = self.non_ascii.len();
        let mut comparisons = 0_usize;
        while low < high {
            comparisons = comparisons
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "binary search comparisons",
                })?;
            let width = high
                .checked_sub(low)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "binary search width",
                })?;
            let middle = low
                .checked_add(width / 2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "binary search midpoint",
                })?;
            let range = self
                .non_ascii
                .get(middle)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "binary search range access",
                })?;
            if scalar < range.start {
                high = middle;
            } else if scalar > range.end {
                low = middle
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "binary search lower bound",
                    })?;
            } else {
                return Ok((true, comparisons));
            }
        }
        Ok((false, comparisons))
    }

    fn contains_non_ascii_run(
        &self,
        scalar: u32,
        cached_range: &mut Option<usize>,
    ) -> Result<(bool, usize), ReduceError> {
        let mut comparisons = 0_usize;
        if let Some(index) = *cached_range {
            comparisons = 1;
            let range = self
                .non_ascii
                .get(index)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cached non-ASCII range access",
                })?;
            if scalar >= range.start && scalar <= range.end {
                return Ok((true, comparisons));
            }
            *cached_range = None;
        }

        let mut low = 0_usize;
        let mut high = self.non_ascii.len();
        while low < high {
            comparisons = comparisons
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cached binary search comparisons",
                })?;
            let width = high
                .checked_sub(low)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cached binary search width",
                })?;
            let middle = low
                .checked_add(width / 2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cached binary search midpoint",
                })?;
            let range = self
                .non_ascii
                .get(middle)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cached binary search range access",
                })?;
            if scalar < range.start {
                high = middle;
            } else if scalar > range.end {
                low = middle
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "cached binary search lower bound",
                    })?;
            } else {
                *cached_range = Some(middle);
                return Ok((true, comparisons));
            }
        }
        Ok((false, comparisons))
    }
}

fn record_match(actual: &mut ReduceActualCounters, width: u64) -> Result<(), ReduceError> {
    actual.match_events =
        actual
            .match_events
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual match events",
            })?;
    actual.count = actual
        .count
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
    actual.matched_bytes =
        actual
            .matched_bytes
            .checked_add(width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual matched bytes",
            })?;
    Ok(())
}

fn flush_greedy_run(
    actual: &mut ReduceActualCounters,
    pending_run_bytes: &mut u64,
) -> Result<(), ReduceError> {
    if *pending_run_bytes == 0 {
        return Ok(());
    }
    record_match(actual, *pending_run_bytes)?;
    actual.run_flushes =
        actual
            .run_flushes
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual greedy run flushes",
            })?;
    *pending_run_bytes = 0;
    Ok(())
}

fn reduce_repeated_scalar(
    actual: &mut ReduceActualCounters,
    pending_bytes: &mut u64,
    pending_scalars: &mut u64,
    width: u64,
    minimum: u32,
    maximum: Option<u32>,
    greedy: bool,
) -> Result<(), ReduceError> {
    *pending_bytes = pending_bytes
        .checked_add(width)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "pending repeated-run bytes",
        })?;
    *pending_scalars = pending_scalars
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "pending repeated-run scalars",
        })?;
    let complete = if greedy {
        maximum.is_some_and(|maximum| *pending_scalars == u64::from(maximum))
    } else {
        *pending_scalars == u64::from(minimum)
    };
    if complete {
        record_match(actual, *pending_bytes)?;
        actual.run_flushes = actual.run_flushes.checked_add(1).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "actual repeated-run flushes",
            },
        )?;
        *pending_bytes = 0;
        *pending_scalars = 0;
    }
    Ok(())
}

fn finish_repeated_run(
    actual: &mut ReduceActualCounters,
    pending_bytes: &mut u64,
    pending_scalars: &mut u64,
    minimum: u32,
    greedy: bool,
) -> Result<(), ReduceError> {
    if greedy && *pending_scalars >= u64::from(minimum) {
        record_match(actual, *pending_bytes)?;
        actual.run_flushes = actual.run_flushes.checked_add(1).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "actual repeated-run terminal flushes",
            },
        )?;
    }
    *pending_bytes = 0;
    *pending_scalars = 0;
    Ok(())
}

#[derive(Clone, Copy)]
enum BuildResource {
    Ranges,
    Work,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(required: usize, limit: usize, resource: BuildResource) -> Result<(), BuildError> {
    if required <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::Ranges => BuildError::RangeLimit {
            needed: required,
            limit,
        },
        BuildResource::Work => BuildError::WorkLimit {
            needed: required,
            limit,
        },
        BuildResource::Scratch => BuildError::ScratchLimit {
            needed: required,
            limit,
        },
        BuildResource::Persistent => BuildError::PersistentLimit {
            needed: required,
            limit,
        },
        BuildResource::Peak => BuildError::PeakLimit {
            needed: required,
            limit,
        },
    })
}

#[derive(Clone, Copy)]
enum ReduceResource {
    InputBytes,
    DecodeByteChecks,
    MembershipTests,
    RangeComparisons,
    ReducerSteps,
    MatchEvents,
    Work,
    Scratch,
    Peak,
}

fn enforce_reduce(
    required: usize,
    limit: usize,
    resource: ReduceResource,
) -> Result<(), ReduceError> {
    if required <= limit {
        return Ok(());
    }
    Err(match resource {
        ReduceResource::InputBytes => ReduceError::InputBytesLimit {
            needed: required,
            limit,
        },
        ReduceResource::DecodeByteChecks => ReduceError::DecodeByteChecksLimit {
            needed: required,
            limit,
        },
        ReduceResource::MembershipTests => ReduceError::MembershipTestsLimit {
            needed: required,
            limit,
        },
        ReduceResource::RangeComparisons => ReduceError::RangeComparisonsLimit {
            needed: required,
            limit,
        },
        ReduceResource::ReducerSteps => ReduceError::ReducerStepsLimit {
            needed: required,
            limit,
        },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit {
            needed: required,
            limit,
        },
        ReduceResource::Work => ReduceError::WorkLimit {
            needed: required,
            limit,
        },
        ReduceResource::Scratch => ReduceError::ScratchLimit {
            needed: required,
            limit,
        },
        ReduceResource::Peak => ReduceError::PeakLimit {
            needed: required,
            limit,
        },
    })
}

fn checked_add(left: usize, right: usize, computation: &'static str) -> Result<usize, BuildError> {
    left.checked_add(right)
        .ok_or(BuildError::ArithmeticOverflow { computation })
}

const fn binary_search_comparison_bound(mut ranges: usize) -> usize {
    let mut comparisons = 0_usize;
    while ranges != 0 {
        comparisons = comparisons.saturating_add(1);
        ranges /= 2;
    }
    comparisons
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedScalar {
    scalar: Option<u32>,
    width: usize,
    byte_checks: usize,
}

fn decode_scalar(bytes: &[u8]) -> DecodedScalar {
    let Some(&first) = bytes.first() else {
        return DecodedScalar {
            scalar: None,
            width: 1,
            byte_checks: 0,
        };
    };
    if first <= 0x7F {
        return DecodedScalar {
            scalar: Some(u32::from(first)),
            width: 1,
            byte_checks: 1,
        };
    }
    if (0xC2..=0xDF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(2));
        };
        if !is_continuation(second) {
            return invalid(2);
        }
        let scalar = (u32::from(first & 0x1F) << 6) | u32::from(second & 0x3F);
        return DecodedScalar {
            scalar: Some(scalar),
            width: 2,
            byte_checks: 2,
        };
    }
    if (0xE0..=0xEF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(3));
        };
        let second_ok = match first {
            0xE0 => (0xA0..=0xBF).contains(&second),
            0xED => (0x80..=0x9F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid(bytes.len().min(3));
        };
        if !is_continuation(third) {
            return invalid(3);
        }
        let scalar = (u32::from(first & 0x0F) << 12)
            | (u32::from(second & 0x3F) << 6)
            | u32::from(third & 0x3F);
        return DecodedScalar {
            scalar: Some(scalar),
            width: 3,
            byte_checks: 3,
        };
    }
    if (0xF0..=0xF4).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(4));
        };
        let second_ok = match first {
            0xF0 => (0x90..=0xBF).contains(&second),
            0xF4 => (0x80..=0x8F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid(bytes.len().min(4));
        };
        if !is_continuation(third) {
            return invalid(3);
        }
        let Some(&fourth) = bytes.get(3) else {
            return invalid(bytes.len().min(4));
        };
        if !is_continuation(fourth) {
            return invalid(4);
        }
        let scalar = (u32::from(first & 0x07) << 18)
            | (u32::from(second & 0x3F) << 12)
            | (u32::from(third & 0x3F) << 6)
            | u32::from(fourth & 0x3F);
        return DecodedScalar {
            scalar: Some(scalar),
            width: 4,
            byte_checks: 4,
        };
    }
    invalid(1)
}

const fn invalid(byte_checks: usize) -> DecodedScalar {
    DecodedScalar {
        scalar: None,
        width: 1,
        byte_checks,
    }
}

const fn is_continuation(byte: u8) -> bool {
    byte & 0xC0 == 0x80
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;

    use super::{
        BuildError, BuildLimits, PLAN_ID, ReduceError, ReduceLimits, Repetition,
        UnicodeScalarAggregatePlan, binary_search_comparison_bound,
    };
    use crate::Window;

    fn dot_plan() -> UnicodeScalarAggregatePlan {
        UnicodeScalarAggregatePlan::build(
            [
                ('\0', '\u{9}'),
                ('\u{B}', '\u{D7FF}'),
                ('\u{E000}', '\u{10FFFF}'),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn class_plan() -> UnicodeScalarAggregatePlan {
        UnicodeScalarAggregatePlan::build(
            [('A', 'Z'), ('a', 'z'), ('\u{3B1}', '\u{3C9}'), ('雪', '雪')],
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn any_scalar_plan() -> UnicodeScalarAggregatePlan {
        UnicodeScalarAggregatePlan::build(
            [('\0', '\u{D7FF}'), ('\u{E000}', '\u{10FFFF}')],
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    fn words(alphabet: &[u8], maximum_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    #[test]
    fn arbitrary_bytes_and_invalid_progression_match_rust_unicode_dot() {
        let alphabet = [0x00, b'\n', b'a', 0x80, 0xC2, 0xE2, 0xF0, 0xFF];
        for (pattern, plan) in [(".", dot_plan()), ("(?s:.)", any_scalar_plan())] {
            let regex = RegexBuilder::new(pattern).unicode(true).build().unwrap();
            for haystack in words(&alphabet, 5) {
                let expected = regex.find_iter(&haystack).collect::<Vec<_>>();
                let expected_count = u64::try_from(expected.len()).unwrap();
                let expected_sum = expected
                    .iter()
                    .try_fold(0_u64, |sum, matched| {
                        sum.checked_add(u64::try_from(matched.len()).ok()?)
                    })
                    .unwrap();
                let count = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
                let sum = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(
                    count.count, expected_count,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
                assert_eq!(
                    sum.span_sum, expected_sum,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn representative_class_and_every_window_match_rust() {
        let plan = class_plan();
        let regex = RegexBuilder::new("[A-Za-zα-ω雪]")
            .unicode(true)
            .build()
            .unwrap();
        let haystack = b"\xFFAz\xCE\xB1\xE9\x9B\xAA\x80\xF0\x9F\x92\xA9";
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let local = &haystack[start..end];
                let expected = regex.find_iter(local).collect::<Vec<_>>();
                let expected_count = u64::try_from(expected.len()).unwrap();
                let expected_sum = expected
                    .iter()
                    .map(|matched| u64::try_from(matched.len()).unwrap())
                    .sum::<u64>();
                let count = plan
                    .count_in(haystack, Window::new(start, end), ReduceLimits::unlimited())
                    .unwrap();
                let sum = plan
                    .span_sum_in(haystack, Window::new(start, end), ReduceLimits::unlimited())
                    .unwrap();
                assert_eq!(count.count, expected_count, "window={start}..{end}");
                assert_eq!(sum.span_sum, expected_sum, "window={start}..{end}");
            }
        }
    }

    #[test]
    fn greedy_and_lazy_one_or_more_match_rust_on_runs_and_invalid_bytes() {
        let ranges = [('A', 'Z'), ('a', 'z'), ('\u{3B1}', '\u{3C9}'), ('雪', '雪')];
        let haystacks: [&[u8]; 8] = [
            b"",
            b"---",
            b"abc",
            b"abc--XYZ",
            b"\xFFabc\x80XYZ",
            b"\xCE\xB1\xCE\xB2!\xCE\xB3",
            b"\xE9\x9B\xAA\xE9\x9B\xAA?A",
            b"A\xE2\x82z",
        ];
        for (greedy, pattern, expected_repetition) in [
            (true, "[A-Za-zα-ω雪]+", Repetition::OneOrMoreGreedy),
            (false, "[A-Za-zα-ω雪]+?", Repetition::OneOrMoreLazy),
        ] {
            let plan = UnicodeScalarAggregatePlan::build_one_or_more(
                ranges,
                greedy,
                BuildLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(plan.build_accounting().repetition, expected_repetition);
            assert_eq!(plan.count_identity().repetition, expected_repetition);
            let regex = RegexBuilder::new(pattern).unicode(true).build().unwrap();
            for haystack in haystacks {
                let expected = regex.find_iter(haystack).collect::<Vec<_>>();
                let expected_count = u64::try_from(expected.len()).unwrap();
                let expected_sum = expected
                    .iter()
                    .map(|matched| u64::try_from(matched.len()).unwrap())
                    .sum::<u64>();
                let count = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
                let sum = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(
                    count.count, expected_count,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
                assert_eq!(
                    sum.span_sum, expected_sum,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
                assert_eq!(count.accounting.actual.scratch_bytes, 0);
            }
            let windowed = b"x\xCE\xB1\xCE\xB2!\xE9\x9B\xAAz";
            for start in 0..=windowed.len() {
                for end in start..=windowed.len() {
                    let local = &windowed[start..end];
                    let expected = regex.find_iter(local).collect::<Vec<_>>();
                    let expected_count = u64::try_from(expected.len()).unwrap();
                    let expected_sum = expected
                        .iter()
                        .map(|matched| u64::try_from(matched.len()).unwrap())
                        .sum::<u64>();
                    let count = plan
                        .count_in(windowed, Window::new(start, end), ReduceLimits::unlimited())
                        .unwrap();
                    let sum = plan
                        .span_sum_in(windowed, Window::new(start, end), ReduceLimits::unlimited())
                        .unwrap();
                    assert_eq!(
                        count.count, expected_count,
                        "pattern={pattern:?} window={start}..{end}"
                    );
                    assert_eq!(
                        sum.span_sum, expected_sum,
                        "pattern={pattern:?} window={start}..{end}"
                    );
                }
            }
        }
    }

    #[test]
    fn nonnullable_counted_repetitions_match_rust_and_scale_linearly() {
        let ranges = [('A', 'Z'), ('a', 'z'), ('α', 'ω'), ('雪', '雪')];
        let haystacks: [&[u8]; 7] = [
            b"",
            b"a-abc-abcde",
            b"\xFFab\x80cdefZ",
            b"--abcd",
            b"abcd--",
            b"----",
            "αβγ!雪雪雪雪雪".as_bytes(),
        ];
        for (minimum, maximum, greedy, pattern) in [
            (2, Some(4), true, "[A-Za-zα-ω雪]{2,4}"),
            (2, Some(4), false, "[A-Za-zα-ω雪]{2,4}?"),
            (3, None, true, "[A-Za-zα-ω雪]{3,}"),
            (2, Some(2), true, "[A-Za-zα-ω雪]{2}"),
        ] {
            let plan = UnicodeScalarAggregatePlan::build_repeated(
                ranges,
                minimum,
                maximum,
                greedy,
                BuildLimits::unlimited(),
            )
            .unwrap();
            let regex = RegexBuilder::new(pattern).unicode(true).build().unwrap();
            for haystack in haystacks {
                let expected = regex.find_iter(haystack).collect::<Vec<_>>();
                let expected_count = u64::try_from(expected.len()).unwrap();
                let expected_sum = expected
                    .iter()
                    .map(|matched| u64::try_from(matched.len()).unwrap())
                    .sum::<u64>();
                assert_eq!(
                    plan.count(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected_count,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    expected_sum,
                    "pattern={pattern:?} haystack={haystack:?}"
                );
            }
        }

        let window_plan = UnicodeScalarAggregatePlan::build_repeated(
            ranges,
            2,
            Some(4),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let window_regex = RegexBuilder::new("[A-Za-zα-ω雪]{2,4}")
            .unicode(true)
            .build()
            .unwrap();
        let windowed = b"x\xCE\xB1\xCE\xB2!\xFF\xE9\x9B\xAA\xE9\x9B\xAAz";
        for start in 0..=windowed.len() {
            for end in start..=windowed.len() {
                let expected = window_regex
                    .find_iter(&windowed[start..end])
                    .collect::<Vec<_>>();
                let expected_count = u64::try_from(expected.len()).unwrap();
                let expected_sum = expected
                    .iter()
                    .map(|matched| u64::try_from(matched.len()).unwrap())
                    .sum::<u64>();
                assert_eq!(
                    window_plan
                        .count_in(windowed, Window::new(start, end), ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected_count,
                    "window={start}..{end}"
                );
                assert_eq!(
                    window_plan
                        .span_sum_in(
                            windowed,
                            Window::new(start, end),
                            ReduceLimits::unlimited(),
                        )
                        .unwrap()
                        .span_sum,
                    expected_sum,
                    "window={start}..{end}"
                );
            }
        }

        let plan = UnicodeScalarAggregatePlan::build_repeated(
            ranges,
            2,
            Some(4),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(plan.count_identity().plan_id, REPEATED_RUN_PLAN_ID);
        assert_eq!(
            plan.count_identity().operation_id,
            REPEATED_RUN_COUNT_OPERATION_ID
        );
        assert_eq!(
            plan.span_sum_identity().operation_id,
            REPEATED_RUN_SPAN_SUM_OPERATION_ID
        );
        assert_ne!(plan.count_identity().plan_id, RUN_PLAN_ID);
        let unit = b"abcd!\xCE\xB1\xCE\xB2\xFF-";
        let rows = [8_usize, 16, 32].map(|copies| {
            plan.count(&unit.repeat(copies), ReduceLimits::unlimited())
                .unwrap()
                .accounting
                .actual
        });
        for pair in rows.windows(2) {
            assert_eq!(
                pair[1].input_bytes_advanced,
                pair[0].input_bytes_advanced * 2
            );
            assert_eq!(
                pair[1].decode_byte_checks,
                pair[0].decode_byte_checks * 2
            );
            assert_eq!(
                pair[1].range_comparisons,
                pair[0].range_comparisons * 2
            );
            assert_eq!(
                pair[1].reducer_steps - 1,
                (pair[0].reducer_steps - 1) * 2
            );
            assert_eq!(pair[1].match_events, pair[0].match_events * 2);
            assert_eq!(pair[1].scratch_bytes, 0);
        }
        assert!(matches!(
            UnicodeScalarAggregatePlan::build_repeated(
                ranges,
                0,
                Some(4),
                true,
                BuildLimits::unlimited()
            ),
            Err(BuildError::InvalidRepetition { .. })
        ));
    }

    #[test]
    fn run_reducer_limit_and_n_2n_4n_structure_are_exact() {
        let ranges = [('A', 'Z'), ('α', 'ω')];
        let plan =
            UnicodeScalarAggregatePlan::build_one_or_more(ranges, true, BuildLimits::unlimited())
                .unwrap();
        let build = plan.build_accounting();
        let error = UnicodeScalarAggregatePlan::build_one_or_more(
            ranges,
            true,
            BuildLimits {
                max_build_work: build.work - 1,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(matches!(error, BuildError::WorkLimit { .. }));
        assert_ne!(plan.count_identity().plan_id, PLAN_ID);
        let unit = b"AA!\xCE\xB1\xCE\xB2?\xFF";
        let mut rows = Vec::new();
        for copies in [8_usize, 16, 32] {
            let haystack = unit.repeat(copies);
            rows.push(
                plan.count(&haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .accounting,
            );
        }
        for pair in rows.windows(2) {
            let left = pair[0].actual;
            let right = pair[1].actual;
            assert_eq!(right.input_bytes_advanced, left.input_bytes_advanced * 2);
            assert_eq!(right.decode_byte_checks, left.decode_byte_checks * 2);
            assert_eq!(right.valid_scalars, left.valid_scalars * 2);
            assert_eq!(right.invalid_bytes, left.invalid_bytes * 2);
            assert_eq!(right.range_comparisons, left.range_comparisons * 2);
            assert_eq!(right.reducer_steps - 1, (left.reducer_steps - 1) * 2);
            assert_eq!(right.match_events, left.match_events * 2);
            assert_eq!(right.run_flushes, left.run_flushes * 2);
            assert_eq!(right.scratch_bytes, 0);
        }
        let upper = rows[0].upper_bounds;
        assert!(upper.reducer_steps > 0);
        let error = plan
            .count(
                &unit.repeat(8),
                ReduceLimits {
                    max_reducer_steps: upper.reducer_steps - 1,
                    ..ReduceLimits::unlimited()
                },
            )
            .unwrap_err();
        assert!(matches!(error, ReduceError::ReducerStepsLimit { .. }));
    }

    #[test]
    fn malformed_overlong_surrogate_truncated_and_out_of_range_never_match() {
        let plan = dot_plan();
        let cases: [&[u8]; 9] = [
            b"\x80",
            b"\xC0\x80",
            b"\xC2",
            b"\xE0\x80\x80",
            b"\xED\xA0\x80",
            b"\xE2\x82",
            b"\xF0\x80\x80\x80",
            b"\xF4\x90\x80\x80",
            b"\xF0\x9F\x92",
        ];
        for haystack in cases {
            let result = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
            assert_eq!(result.count, 0, "haystack={haystack:?}");
            assert_eq!(result.accounting.actual.valid_scalars, 0);
            assert_eq!(result.accounting.actual.invalid_bytes, haystack.len());
        }
        let mixed = plan
            .count(
                b"\xFFa\x80\xE9\x9B\xAA\xF4\x90\x80\x80z",
                ReduceLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(mixed.count, 3);
        assert_eq!(mixed.accounting.actual.valid_scalars, 3);
        assert_eq!(mixed.accounting.actual.invalid_bytes, 6);
    }

    #[test]
    fn empty_class_noncanonical_ranges_and_invalid_windows_are_typed() {
        let empty = RegexBuilder::new("").unicode(true).build().unwrap();
        let arbitrary_bytes = b"\xFF\x80a";
        assert_eq!(
            empty.find_iter(arbitrary_bytes).count(),
            arbitrary_bytes.len() + 1
        );
        assert_eq!(
            UnicodeScalarAggregatePlan::build([], BuildLimits::unlimited()).unwrap_err(),
            BuildError::EmptyClass
        );
        assert_eq!(
            UnicodeScalarAggregatePlan::build([('z', 'a')], BuildLimits::unlimited()).unwrap_err(),
            BuildError::ReversedRange {
                start: 'z',
                end: 'a'
            }
        );
        for ranges in [vec![('a', 'z'), ('z', '雪')], vec![('b', 'z'), ('a', 'a')]] {
            assert_eq!(
                UnicodeScalarAggregatePlan::build(ranges, BuildLimits::unlimited()).unwrap_err(),
                BuildError::NonCanonicalRanges
            );
        }
        let plan = dot_plan();
        assert!(matches!(
            plan.count_in(b"abc", Window::new(2, 1), ReduceLimits::unlimited()),
            Err(ReduceError::InvalidWindow { .. })
        ));
        assert!(matches!(
            plan.count_in(b"abc", Window::new(0, 4), ReduceLimits::unlimited()),
            Err(ReduceError::InvalidWindow { .. })
        ));
    }

    #[test]
    fn every_nonzero_build_limit_has_an_exact_and_one_below_boundary() {
        let ranges = [('A', 'Z'), ('a', 'z'), ('\u{3B1}', '\u{3C9}'), ('雪', '雪')];
        let baseline = UnicodeScalarAggregatePlan::build(ranges, BuildLimits::unlimited())
            .unwrap()
            .build_accounting();
        let exact = BuildLimits {
            max_source_ranges: baseline.source_ranges,
            max_build_work: baseline.work,
            max_scratch_bytes: baseline.scratch_bytes,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        UnicodeScalarAggregatePlan::build(ranges, exact).unwrap();

        let cases = [
            (
                BuildLimits {
                    max_source_ranges: baseline.source_ranges.checked_sub(1).unwrap(),
                    ..BuildLimits::unlimited()
                },
                "ranges",
            ),
            (
                BuildLimits {
                    max_build_work: baseline.work.checked_sub(1).unwrap(),
                    ..BuildLimits::unlimited()
                },
                "work",
            ),
            (
                BuildLimits {
                    max_scratch_bytes: baseline.scratch_bytes.checked_sub(1).unwrap(),
                    ..BuildLimits::unlimited()
                },
                "scratch",
            ),
            (
                BuildLimits {
                    max_persistent_bytes: baseline.persistent_bytes.checked_sub(1).unwrap(),
                    ..BuildLimits::unlimited()
                },
                "persistent",
            ),
            (
                BuildLimits {
                    max_peak_bytes: baseline.peak_bytes.checked_sub(1).unwrap(),
                    ..BuildLimits::unlimited()
                },
                "peak",
            ),
        ];
        for (limits, expected) in cases {
            let error = UnicodeScalarAggregatePlan::build(ranges, limits).unwrap_err();
            let actual = match error {
                BuildError::RangeLimit { .. } => "ranges",
                BuildError::WorkLimit { .. } => "work",
                BuildError::ScratchLimit { .. } => "scratch",
                BuildError::PersistentLimit { .. } => "persistent",
                BuildError::PeakLimit { .. } => "peak",
                other => panic!("unexpected build error: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
    }

    fn reduce_error_dimension(error: ReduceError) -> &'static str {
        match error {
            ReduceError::InputBytesLimit { .. } => "input",
            ReduceError::DecodeByteChecksLimit { .. } => "decode",
            ReduceError::MembershipTestsLimit { .. } => "membership",
            ReduceError::RangeComparisonsLimit { .. } => "comparisons",
            ReduceError::ReducerStepsLimit { .. } => "reducer",
            ReduceError::MatchEventsLimit { .. } => "events",
            ReduceError::CountLimit { .. } => "count",
            ReduceError::SpanSumLimit { .. } => "span",
            ReduceError::WorkLimit { .. } => "work",
            ReduceError::PeakLimit { .. } => "peak",
            other => panic!("unexpected reduce error: {other:?}"),
        }
    }

    #[test]
    fn every_nonzero_reduce_limit_has_an_exact_and_one_below_boundary() {
        let plan = class_plan();
        let haystack = b"Az\xCE\xB1\xE9\x9B\xAA\xFF";
        let baseline = plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .unwrap()
            .accounting
            .upper_bounds;
        let exact = ReduceLimits {
            max_input_bytes: baseline.input_bytes,
            max_decode_byte_checks: baseline.decode_byte_checks,
            max_membership_tests: baseline.membership_tests,
            max_range_comparisons: baseline.range_comparisons,
            max_reducer_steps: baseline.reducer_steps,
            max_match_events: baseline.match_events,
            max_count: baseline.count,
            max_span_sum: baseline.span_sum,
            max_work: baseline.work,
            max_scratch_bytes: baseline.scratch_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        plan.span_sum(haystack, exact).unwrap();

        let cases = [
            (
                ReduceLimits {
                    max_input_bytes: baseline.input_bytes.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "input",
            ),
            (
                ReduceLimits {
                    max_decode_byte_checks: baseline.decode_byte_checks.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "decode",
            ),
            (
                ReduceLimits {
                    max_membership_tests: baseline.membership_tests.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "membership",
            ),
            (
                ReduceLimits {
                    max_range_comparisons: baseline.range_comparisons.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "comparisons",
            ),
            (
                ReduceLimits {
                    max_match_events: baseline.match_events.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "events",
            ),
            (
                ReduceLimits {
                    max_count: baseline.count.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "count",
            ),
            (
                ReduceLimits {
                    max_span_sum: baseline.span_sum.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "span",
            ),
            (
                ReduceLimits {
                    max_work: baseline.work.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "work",
            ),
            (
                ReduceLimits {
                    max_peak_bytes: baseline.peak_bytes.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                "peak",
            ),
        ];
        for (limits, expected) in cases {
            let error = plan.span_sum(haystack, limits).unwrap_err();
            let actual = reduce_error_dimension(error);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn structural_counters_double_with_n_and_scratch_stays_zero() {
        let plan = class_plan();
        let unit = b"Az\xCE\xB1\xE9\x9B\xAA\xFF\xF0\x9F\x92\xA9";
        let once = plan.count(unit, ReduceLimits::unlimited()).unwrap();
        let twice_haystack = [unit.as_slice(), unit.as_slice()].concat();
        let twice = plan
            .count(&twice_haystack, ReduceLimits::unlimited())
            .unwrap();
        let left = once.accounting.actual;
        let right = twice.accounting.actual;
        assert_eq!(right.input_bytes_advanced, left.input_bytes_advanced * 2);
        assert_eq!(right.decode_byte_checks, left.decode_byte_checks * 2);
        assert_eq!(right.valid_scalars, left.valid_scalars * 2);
        assert_eq!(right.invalid_bytes, left.invalid_bytes * 2);
        assert_eq!(right.ascii_run_bytes, left.ascii_run_bytes * 2);
        assert_eq!(right.ascii_bitmap_tests, left.ascii_bitmap_tests * 2);
        assert_eq!(
            right.non_ascii_membership_tests,
            left.non_ascii_membership_tests * 2
        );
        assert_eq!(right.range_comparisons, left.range_comparisons * 2);
        assert_eq!(right.match_events, left.match_events * 2);
        assert_eq!(right.work, left.work * 2);
        assert_eq!(left.scratch_bytes, 0);
        assert_eq!(right.scratch_bytes, 0);
    }

    #[test]
    fn ascii_runs_preserve_match_position_and_scale_at_n_2n_4n() {
        let plan = class_plan();
        let cases: [(&[u8], u64); 3] = [
            (b"A0123456789", 1),
            (b"0123456789Z", 1),
            (b"0123456789!", 0),
        ];
        for (unit, matches_per_unit) in cases {
            for scale in [1_usize, 2, 4] {
                let haystack = unit.repeat(scale);
                let expected = matches_per_unit * u64::try_from(scale).unwrap();
                let count = plan.count(&haystack, ReduceLimits::unlimited()).unwrap();
                let sum = plan.span_sum(&haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(count.count, expected);
                assert_eq!(sum.span_sum, expected);
                let actual = count.accounting.actual;
                assert_eq!(actual.input_bytes_advanced, haystack.len());
                assert_eq!(actual.decode_byte_checks, haystack.len());
                assert_eq!(actual.valid_scalars, haystack.len());
                assert_eq!(actual.invalid_bytes, 0);
                assert_eq!(actual.ascii_run_bytes, haystack.len());
                assert_eq!(actual.ascii_bitmap_tests, haystack.len());
                assert_eq!(actual.non_ascii_membership_tests, 0);
                assert_eq!(actual.range_comparisons, 0);
                assert_eq!(actual.work, haystack.len() * 2);
                assert_eq!(actual.scratch_bytes, 0);
            }
        }
    }

    #[test]
    fn worst_case_range_scaling_is_logarithmic_and_comparisons_are_exact() {
        for exponent in 0..=9_u32 {
            let range_count = (1_usize << exponent).checked_sub(1).unwrap().max(1);
            let ranges = (0..range_count)
                .map(|index| {
                    let scalar = 0x1000_u32
                        .checked_add(u32::try_from(index).unwrap() * 2)
                        .unwrap();
                    let ch = char::from_u32(scalar).unwrap();
                    (ch, ch)
                })
                .collect::<Vec<_>>();
            let plan = UnicodeScalarAggregatePlan::build(ranges, BuildLimits::unlimited()).unwrap();
            let result = plan
                .count("\u{10FFFF}".as_bytes(), ReduceLimits::unlimited())
                .unwrap();
            let expected = binary_search_comparison_bound(range_count);
            assert_eq!(result.accounting.actual.range_comparisons, expected);
            assert_eq!(
                result
                    .accounting
                    .upper_bounds
                    .binary_search_comparisons_per_scalar,
                expected
            );
            assert!(expected <= usize::try_from(exponent).unwrap().saturating_add(1));
        }
    }
}
