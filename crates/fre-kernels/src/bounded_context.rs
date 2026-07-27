//! Linear whole-match count and span-sum reduction for bounded byte context.
//!
//! The admitted byte language is
//! `HEAD{H} SEP+ ANY{0,A} LITERAL ANY{0,B} SEP+ TAIL{T}`. `HEAD`, `SEP`, and
//! `TAIL` are canonical inline byte classes, `H,T >= 2`, the separators are
//! disjoint from both fixed classes, and the literal is nonempty, starts
//! outside `SEP`, and cannot overlap itself. Those facts permit three linear
//! streams: suffix-interval discovery, one native literal-finder traversal,
//! and monotone prefix resolution. No input position is paired with program
//! states, so execution is `O(N + Q)`, never `O(N*Q)`.
//!
//! A distinct direct plan admits `LEFT MIDDLE{0,A} LITERAL RIGHT` with
//! one-byte endpoint classes, `LEFT` and `RIGHT` disjoint from `MIDDLE`, and
//! every literal byte in `MIDDLE`. It scans maximal middle runs once and tests
//! only the suffix before a right endpoint. Those tests consume disjoint
//! `LITERAL+RIGHT` regions, bounding literal-byte comparisons by input length.
//! A caller-captured SIMD context can additionally retain Auto directional
//! scanners for ASCII prefix, separator/middle, and tail classes on OS-usable
//! SVE. Each vector entry follows a 16-member scalar proof, and prospective
//! accounting includes its exact compiled storage, construction work, and
//! maximum failed-load recovery classifications. Legacy constructors and
//! non-SVE or non-ASCII classes retain their scalar paths.
//!
//! rebar-row:curated/10-bounded-repeat/context@rust/regex
//! rebar-row:imported/leipzig/ing-whitespace@rust/regex

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactBoxOrUsize, copy_exact, zeroed_exact};
use fre_simd_kernels::{
    ASCII_NARROW_BYTES, ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD, AsciiByteSet,
    AsciiByteSetRunScanner, DispatchPolicy, Feature, SelectionReceipt, SimdDispatchContext,
};
use memchr::memmem::{Finder, FinderBuilder};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "bounded-context-count.literal-interval-stream.v1";
pub const COUNT_OPERATION_ID: &str = "bounded-context-count.count.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "bounded-context-count.span-sum.v1";
pub const BOUNDED_AFFIX_PLAN_ID: &str = "bounded-affix-count.direct.v1";

const INTERVAL_BYTES: usize = 12;
const MIN_FIXED_WIDTH: u32 = 2;
// One complete ASCII-domain table pass, one paired-direction selection, and
// one immutable selection receipt.
const SIMD_RUN_SCANNER_BUILD_WORK: usize = 128 + 1 + 1;
// A failed run scan classifies its boundary once before the scalar control
// loop consumes that same byte, in addition to the scanner's recovery lanes.
const SIMD_RUN_MAX_RESCAN_INSPECTIONS: usize = ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD + 1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ByteClass {
    words: [u64; 4],
}

impl ByteClass {
    fn from_ranges<I>(
        ranges: I,
        role: &'static str,
        budget: &mut BuildTraversalBudget<'_>,
    ) -> Result<(Self, usize), BuildError>
    where
        I: IntoIterator<Item = (u8, u8)>,
    {
        let mut class = Self::default();
        let mut previous_end = None;
        let mut range_count = 0_usize;
        for (start, end) in ranges {
            budget.charge_range()?;
            range_count = range_count
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "per-class source range count",
                })?;
            if start > end {
                return Err(BuildError::ReversedRange { role, start, end });
            }
            if previous_end.is_some_and(|previous| previous >= start) {
                return Err(BuildError::NonCanonicalRanges { role });
            }
            previous_end = Some(end);
            let first_word = usize::from(start) >> 6;
            let last_word = usize::from(end) >> 6;
            for word in first_word..=last_word {
                let first_bit = if word == first_word {
                    u32::from(start) & 63
                } else {
                    0
                };
                let last_bit = if word == last_word {
                    u32::from(end) & 63
                } else {
                    63
                };
                let left =
                    u64::MAX
                        .checked_shl(first_bit)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "byte-class left mask",
                        })?;
                let right_shift =
                    63_u32
                        .checked_sub(last_bit)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "byte-class right shift",
                        })?;
                let right =
                    u64::MAX
                        .checked_shr(right_shift)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "byte-class right mask",
                        })?;
                class.words[word] |= left & right;
            }
        }
        Ok((class, range_count))
    }

    fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte) >> 6;
        let bit = u32::from(byte) & 63;
        self.words[word] & (1_u64 << bit) != 0
    }

    fn overlaps(self, other: Self) -> bool {
        self.words
            .iter()
            .zip(other.words)
            .any(|(left, right)| left & right != 0)
    }

    fn is_empty(self) -> bool {
        self.words.iter().all(|&word| word == 0)
    }

    fn ascii_set(self) -> Option<AsciiByteSet> {
        (self.words[2] == 0 && self.words[3] == 0)
            .then(|| AsciiByteSet::from_words([self.words[0], self.words[1]]))
    }
}

#[derive(Debug)]
struct RunScanners {
    prefix: Option<AsciiByteSetRunScanner>,
    separator: Option<AsciiByteSetRunScanner>,
    tail: Option<AsciiByteSetRunScanner>,
}

impl RunScanners {
    fn selection(scanner: Option<&AsciiByteSetRunScanner>) -> Option<SelectionReceipt> {
        scanner.map(AsciiByteSetRunScanner::selection)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub prefix_width: u32,
    pub left_gap_max: u32,
    pub right_gap_max: u32,
    pub tail_width: u32,
    pub greedy: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_literal_bytes: usize,
    pub max_repeat_bound: u32,
    pub max_gap_bound: u32,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_source_ranges: 256,
            max_literal_bytes: 1 << 20,
            max_repeat_bound: 1_000,
            max_gap_bound: 1_000,
            max_build_work: 16 << 20,
            max_scratch_bytes: 8 << 20,
            max_persistent_bytes: 16 << 20,
            max_peak_bytes: 24 << 20,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub prefix_ranges: usize,
    pub separator_ranges: usize,
    pub tail_ranges: usize,
    pub source_ranges: usize,
    pub literal_bytes: usize,
    pub prefix_width: u32,
    pub left_gap_max: u32,
    pub right_gap_max: u32,
    pub tail_width: u32,
    pub work: usize,
    pub temporary_capacity_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_work: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_work: 1 << 29,
            max_match_events: 128 << 20,
            max_count: 128 << 20,
            max_scratch_bytes: 512 << 20,
            max_peak_bytes: 640 << 20,
        }
    }
}

/// Operation-specific limits for checked whole-match span summation.
///
/// This has the same layout as [`ReduceLimits`], but gives the output bound
/// its correct semantic name instead of overloading the Count limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumLimits {
    pub max_input_bytes: usize,
    pub max_work: usize,
    pub max_match_events: usize,
    pub max_span_sum: u64,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl SpanSumLimits {
    /// Project the shared facade limit record into its operation-specific
    /// interpretation without changing the retained record's layout.
    #[must_use]
    pub const fn from_shared(limits: ReduceLimits) -> Self {
        Self {
            max_input_bytes: limits.max_input_bytes,
            max_work: limits.max_work,
            max_match_events: limits.max_match_events,
            max_span_sum: limits.max_count,
            max_scratch_bytes: limits.max_scratch_bytes,
            max_peak_bytes: limits.max_peak_bytes,
        }
    }

    const fn count_preflight(self) -> ReduceLimits {
        ReduceLimits {
            max_input_bytes: self.max_input_bytes,
            max_work: self.max_work,
            max_match_events: self.max_match_events,
            max_count: u64::MAX,
            max_scratch_bytes: self.max_scratch_bytes,
            max_peak_bytes: self.max_peak_bytes,
        }
    }
}

impl Default for SpanSumLimits {
    fn default() -> Self {
        Self::from_shared(ReduceLimits::default())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub literal_bytes: usize,
    pub interval_records: usize,
    pub interval_bytes: usize,
    pub inspections: usize,
    pub branches: usize,
    pub comparisons: usize,
    pub state_writes: usize,
    pub work: usize,
    pub match_events: usize,
    pub count: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub suffix_intervals: usize,
    /// Literal candidates whose bytes were tested by this plan.
    ///
    /// The interval-stream plan obtains these candidates from its literal
    /// finder. The bounded-affix plan obtains them from suffixes immediately
    /// before a right endpoint. The counter deliberately describes attempts,
    /// not successful equality tests.
    pub literal_attempts: usize,
    pub successful_literals: usize,
    pub prefix_candidates: usize,
    pub match_events: usize,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumUpperBounds {
    pub input_bytes: usize,
    pub literal_bytes: usize,
    pub interval_records: usize,
    pub interval_bytes: usize,
    pub inspections: usize,
    pub branches: usize,
    pub comparisons: usize,
    pub state_writes: usize,
    pub work: usize,
    pub match_events: usize,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumActualCounters {
    pub suffix_intervals: usize,
    pub literal_attempts: usize,
    pub successful_literals: usize,
    pub prefix_candidates: usize,
    pub match_events: usize,
    pub span_sum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: SpanSumUpperBounds,
    pub actual: SpanSumActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub span_sum: u64,
    pub accounting: SpanSumAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass {
        role: &'static str,
    },
    EmptyLiteral,
    FixedWidthTooSmall {
        role: &'static str,
        needed: u32,
        minimum: u32,
    },
    RepeatLimit {
        needed: u32,
        limit: u32,
    },
    GapLimit {
        needed: u32,
        limit: u32,
    },
    RangeLimit {
        needed: usize,
        limit: usize,
    },
    LiteralLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    ReversedRange {
        role: &'static str,
        start: u8,
        end: u8,
    },
    NonCanonicalRanges {
        role: &'static str,
    },
    OverlappingSeparator {
        role: &'static str,
    },
    LiteralStartsInSeparator {
        byte: u8,
    },
    LiteralOutsideMiddle {
        byte: u8,
    },
    OverlappingLiteral {
        repeated_first: u8,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bounded-context construction failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

struct BuildTraversalBudget<'a> {
    source_ranges: usize,
    work: usize,
    max_source_ranges: usize,
    max_work: usize,
    actual_work: &'a mut u64,
}

impl<'a> BuildTraversalBudget<'a> {
    fn new(
        literal_bytes: usize,
        limits: BuildLimits,
        actual_work: &'a mut u64,
    ) -> Result<Self, BuildError> {
        let work = literal_bytes
            .checked_mul(8)
            .and_then(|value| value.checked_add(64))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work",
            })?;
        if work > limits.max_build_work {
            return Err(BuildError::WorkLimit {
                needed: work,
                limit: limits.max_build_work,
            });
        }
        *actual_work = u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "actual bounded-context work as u64",
        })?;
        Ok(Self {
            source_ranges: 0,
            work,
            max_source_ranges: limits.max_source_ranges,
            max_work: limits.max_build_work,
            actual_work,
        })
    }

    fn charge_range(&mut self) -> Result<(), BuildError> {
        let source_ranges =
            self.source_ranges
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "source range count",
                })?;
        if source_ranges > self.max_source_ranges {
            return Err(BuildError::RangeLimit {
                needed: source_ranges,
                limit: self.max_source_ranges,
            });
        }
        let work = self
            .work
            .checked_add(6)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work",
            })?;
        if work > self.max_work {
            return Err(BuildError::WorkLimit {
                needed: work,
                limit: self.max_work,
            });
        }
        self.source_ranges = source_ranges;
        self.work = work;
        *self.actual_work = u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "actual bounded-context work as u64",
        })?;
        Ok(())
    }

    fn charge(&mut self, amount: usize) -> Result<(), BuildError> {
        let work = self
            .work
            .checked_add(amount)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work",
            })?;
        if work > self.max_work {
            return Err(BuildError::WorkLimit {
                needed: work,
                limit: self.max_work,
            });
        }
        self.work = work;
        *self.actual_work = u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "actual bounded-context work as u64",
        })?;
        Ok(())
    }

    const fn into_totals(self) -> (usize, usize) {
        (self.source_ranges, self.work)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
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
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bounded-context reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Debug)]
pub struct BoundedContextPlan {
    prefix: ByteClass,
    separator: ByteClass,
    tail: ByteClass,
    finder: Finder<'static>,
    prefix_width: u32,
    left_gap_max: u32,
    right_gap_max: u32,
    tail_width: u32,
    build: BuildAccounting,
    bounded_affix: bool,
    run_scanners: ExactBoxOrUsize<RunScanners>,
}

impl BoundedContextPlan {
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "construction keeps the complete admitted shape, fail-closed resource preflight, and accounting in one auditable transaction"
    )]
    pub fn build<Prefix, Separator, Tail>(
        prefix: Prefix,
        separator: Separator,
        tail: Tail,
        literal: &[u8],
        prefix_width: u32,
        left_gap_max: u32,
        right_gap_max: u32,
        tail_width: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        Prefix: IntoIterator<Item = (u8, u8)>,
        Separator: IntoIterator<Item = (u8, u8)>,
        Tail: IntoIterator<Item = (u8, u8)>,
    {
        Self::build_attempt(
            prefix,
            separator,
            tail,
            literal,
            prefix_width,
            left_gap_max,
            right_gap_max,
            tail_width,
            limits,
        )
        .map(DirectBuildAttempt::into_plan)
        .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the bounded-context route with exact observed construction effects.
    #[allow(
        clippy::too_many_arguments,
        reason = "the admitted bounded-context shape has four independent bounds and three classes"
    )]
    pub fn build_attempt<Prefix, Separator, Tail>(
        prefix: Prefix,
        separator: Separator,
        tail: Tail,
        literal: &[u8],
        prefix_width: u32,
        left_gap_max: u32,
        right_gap_max: u32,
        tail_width: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        Prefix: IntoIterator<Item = (u8, u8)>,
        Separator: IntoIterator<Item = (u8, u8)>,
        Tail: IntoIterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(
            None,
            prefix,
            separator,
            tail,
            literal,
            prefix_width,
            left_gap_max,
            right_gap_max,
            tail_width,
            limits,
        )
    }

    /// Build with one caller-captured capability snapshot and retain Auto
    /// directional scanners for eligible ASCII classes on OS-usable SVE.
    #[allow(
        clippy::too_many_arguments,
        reason = "the admitted bounded-context shape has four independent bounds and three classes"
    )]
    pub fn build_with_dispatch<Prefix, Separator, Tail>(
        dispatch: SimdDispatchContext,
        prefix: Prefix,
        separator: Separator,
        tail: Tail,
        literal: &[u8],
        prefix_width: u32,
        left_gap_max: u32,
        right_gap_max: u32,
        tail_width: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        Prefix: IntoIterator<Item = (u8, u8)>,
        Separator: IntoIterator<Item = (u8, u8)>,
        Tail: IntoIterator<Item = (u8, u8)>,
    {
        Self::build_attempt_with_dispatch(
            dispatch,
            prefix,
            separator,
            tail,
            literal,
            prefix_width,
            left_gap_max,
            right_gap_max,
            tail_width,
            limits,
        )
        .map(DirectBuildAttempt::into_plan)
        .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build with a pre-captured dispatch context while retaining exact
    /// successful or partial terminal effects.
    #[allow(
        clippy::too_many_arguments,
        reason = "the admitted bounded-context shape has four independent bounds and three classes"
    )]
    pub fn build_attempt_with_dispatch<Prefix, Separator, Tail>(
        dispatch: SimdDispatchContext,
        prefix: Prefix,
        separator: Separator,
        tail: Tail,
        literal: &[u8],
        prefix_width: u32,
        left_gap_max: u32,
        right_gap_max: u32,
        tail_width: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        Prefix: IntoIterator<Item = (u8, u8)>,
        Separator: IntoIterator<Item = (u8, u8)>,
        Tail: IntoIterator<Item = (u8, u8)>,
    {
        Self::build_attempt_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            prefix,
            separator,
            tail,
            literal,
            prefix_width,
            left_gap_max,
            right_gap_max,
            tail_width,
            limits,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "construction keeps the complete admitted shape, exact attempt accounting, optional scanner compilation, and publication adjacent"
    )]
    fn build_attempt_inner<Prefix, Separator, Tail>(
        dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
        prefix: Prefix,
        separator: Separator,
        tail: Tail,
        literal: &[u8],
        prefix_width: u32,
        left_gap_max: u32,
        right_gap_max: u32,
        tail_width: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        Prefix: IntoIterator<Item = (u8, u8)>,
        Separator: IntoIterator<Item = (u8, u8)>,
        Tail: IntoIterator<Item = (u8, u8)>,
    {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            if literal.is_empty() {
                return Err(BuildError::EmptyLiteral);
            }
            for (role, width) in [("prefix", prefix_width), ("tail", tail_width)] {
                if width < MIN_FIXED_WIDTH {
                    return Err(BuildError::FixedWidthTooSmall {
                        role,
                        needed: width,
                        minimum: MIN_FIXED_WIDTH,
                    });
                }
                if width > limits.max_repeat_bound {
                    return Err(BuildError::RepeatLimit {
                        needed: width,
                        limit: limits.max_repeat_bound,
                    });
                }
            }
            for gap in [left_gap_max, right_gap_max] {
                if gap > limits.max_gap_bound {
                    return Err(BuildError::GapLimit {
                        needed: gap,
                        limit: limits.max_gap_bound,
                    });
                }
            }
            if literal.len() > limits.max_literal_bytes {
                return Err(BuildError::LiteralLimit {
                    needed: literal.len(),
                    limit: limits.max_literal_bytes,
                });
            }
            let base_persistent_bytes = size_of::<Self>().checked_add(literal.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                },
            )?;
            let base_peak_bytes = base_persistent_bytes.checked_add(literal.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "construction peak bytes",
                },
            )?;
            if literal.len() > limits.max_scratch_bytes {
                return Err(BuildError::ScratchLimit {
                    needed: literal.len(),
                    limit: limits.max_scratch_bytes,
                });
            }
            if base_persistent_bytes > limits.max_persistent_bytes {
                return Err(BuildError::PersistentLimit {
                    needed: base_persistent_bytes,
                    limit: limits.max_persistent_bytes,
                });
            }
            if base_peak_bytes > limits.max_peak_bytes {
                return Err(BuildError::PeakLimit {
                    needed: base_peak_bytes,
                    limit: limits.max_peak_bytes,
                });
            }

            // Each actual yielded range is charged before validation or bitmap
            // mutation. In particular, a caller-provided iterator's `len` or size
            // hint is never trusted for either admission or accounting.
            let mut budget = BuildTraversalBudget::new(literal.len(), limits, &mut actual.work)?;
            let (prefix_class, prefix_ranges) =
                ByteClass::from_ranges(prefix, "prefix", &mut budget)?;
            let (separator_class, separator_ranges) =
                ByteClass::from_ranges(separator, "separator", &mut budget)?;
            let (tail_class, tail_ranges) = ByteClass::from_ranges(tail, "tail", &mut budget)?;
            if prefix_class.is_empty() {
                return Err(BuildError::EmptyClass { role: "prefix" });
            }
            if separator_class.is_empty() {
                return Err(BuildError::EmptyClass { role: "separator" });
            }
            if tail_class.is_empty() {
                return Err(BuildError::EmptyClass { role: "tail" });
            }
            if separator_class.overlaps(prefix_class) {
                return Err(BuildError::OverlappingSeparator { role: "prefix" });
            }
            if separator_class.overlaps(tail_class) {
                return Err(BuildError::OverlappingSeparator { role: "tail" });
            }
            if separator_class.contains(literal[0]) {
                return Err(BuildError::LiteralStartsInSeparator { byte: literal[0] });
            }
            if literal[1..].contains(&literal[0]) {
                return Err(BuildError::OverlappingLiteral {
                    repeated_first: literal[0],
                });
            }
            let scanner_count = [
                run_scanner_eligible(dispatch, prefix_class),
                run_scanner_eligible(dispatch, separator_class),
                run_scanner_eligible(dispatch, tail_class),
            ]
            .into_iter()
            .map(usize::from)
            .sum::<usize>();
            let scanner_bytes = usize::from(scanner_count != 0)
                .checked_mul(size_of::<RunScanners>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "retained run scanner bytes",
                })?;
            let persistent_bytes = base_persistent_bytes.checked_add(scanner_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent bytes with run scanners",
                },
            )?;
            let peak_bytes = persistent_bytes.checked_add(literal.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "construction peak bytes with run scanners",
                },
            )?;
            if persistent_bytes > limits.max_persistent_bytes {
                return Err(BuildError::PersistentLimit {
                    needed: persistent_bytes,
                    limit: limits.max_persistent_bytes,
                });
            }
            if peak_bytes > limits.max_peak_bytes {
                return Err(BuildError::PeakLimit {
                    needed: peak_bytes,
                    limit: limits.max_peak_bytes,
                });
            }
            budget.charge(
                scanner_count
                    .checked_mul(SIMD_RUN_SCANNER_BUILD_WORK)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "run scanner build work",
                    })?,
            )?;
            let run_scanners = build_run_scanners(
                dispatch,
                Some(prefix_class),
                Some(separator_class),
                Some(tail_class),
            );
            debug_assert_eq!(run_scanners.is_some(), scanner_count != 0);
            let (source_ranges, work) = budget.into_totals();
            let owned = copy_exact(literal).map_err(|error| {
                allocation_build_error(error, "retained literal", literal.len())
            })?;
            actual.allocations = 1;
            actual.allocated_bytes = literal.len();
            actual.copied_bytes = literal.len();
            actual.initialized_bytes = literal.len();
            actual.peak_bytes = literal.len();
            let run_scanners = retain_run_scanners(run_scanners).map_err(|error| {
                allocation_build_error(error, "retained run scanners", scanner_bytes)
            })?;
            if scanner_bytes != 0 {
                actual.allocations =
                    actual
                        .allocations
                        .checked_add(1)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "bounded-context allocation count",
                        })?;
                actual.allocated_bytes = actual.allocated_bytes.checked_add(scanner_bytes).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "bounded-context allocated bytes",
                    },
                )?;
                actual.initialized_bytes = actual
                    .initialized_bytes
                    .checked_add(scanner_bytes)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "bounded-context initialized bytes",
                    })?;
                actual.peak_bytes = actual.peak_bytes.checked_add(scanner_bytes).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "bounded-context allocation peak",
                    },
                )?;
            }
            let finder = FinderBuilder::new().build_forward_owned(owned.into_boxed_slice());
            let plan = Self {
                prefix: prefix_class,
                separator: separator_class,
                tail: tail_class,
                finder,
                prefix_width,
                left_gap_max,
                right_gap_max,
                tail_width,
                build: BuildAccounting {
                    prefix_ranges,
                    separator_ranges,
                    tail_ranges,
                    source_ranges,
                    literal_bytes: literal.len(),
                    prefix_width,
                    left_gap_max,
                    right_gap_max,
                    tail_width,
                    work,
                    temporary_capacity_bytes: literal.len(),
                    persistent_bytes,
                    peak_bytes,
                },
                bounded_affix: false,
                run_scanners,
            };
            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(size_of::<Self>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "published bounded-context inline initialized bytes",
                })?;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = actual.peak_bytes.max(persistent_bytes);
            Ok(plan)
        })();
        match result {
            Ok(plan) => Ok(DirectBuildAttempt::new(plan, actual)),
            Err(source) => {
                actual.live_persistent_bytes = 0;
                Err(DirectBuildAttemptError::new(source, actual))
            }
        }
    }

    /// Build `LEFT MIDDLE{0,max} LITERAL RIGHT` for byte-mode Count/SpanSum.
    #[allow(
        clippy::too_many_lines,
        reason = "fail-closed affix construction keeps quota, class, copy, and identity checks together"
    )]
    pub fn build_bounded_affix<Left, Middle, Right>(
        left: Left,
        middle: Middle,
        right: Right,
        literal: &[u8],
        middle_max: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        Left: IntoIterator<Item = (u8, u8)>,
        Middle: IntoIterator<Item = (u8, u8)>,
        Right: IntoIterator<Item = (u8, u8)>,
    {
        Self::build_bounded_affix_attempt(left, middle, right, literal, middle_max, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the bounded-affix route with exact observed construction effects.
    #[allow(
        clippy::too_many_lines,
        reason = "fail-closed affix construction keeps exact attempt accounting with quota and publication"
    )]
    pub fn build_bounded_affix_attempt<Left, Middle, Right>(
        left: Left,
        middle: Middle,
        right: Right,
        literal: &[u8],
        middle_max: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        Left: IntoIterator<Item = (u8, u8)>,
        Middle: IntoIterator<Item = (u8, u8)>,
        Right: IntoIterator<Item = (u8, u8)>,
    {
        Self::build_bounded_affix_attempt_inner(
            None, left, middle, right, literal, middle_max, limits,
        )
    }

    /// Build the bounded-affix route with one caller-captured capability
    /// snapshot and an Auto scanner for an eligible ASCII middle class.
    pub fn build_bounded_affix_with_dispatch<Left, Middle, Right>(
        dispatch: SimdDispatchContext,
        left: Left,
        middle: Middle,
        right: Right,
        literal: &[u8],
        middle_max: u32,
        limits: BuildLimits,
    ) -> Result<Self, BuildError>
    where
        Left: IntoIterator<Item = (u8, u8)>,
        Middle: IntoIterator<Item = (u8, u8)>,
        Right: IntoIterator<Item = (u8, u8)>,
    {
        Self::build_bounded_affix_attempt_with_dispatch(
            dispatch, left, middle, right, literal, middle_max, limits,
        )
        .map(DirectBuildAttempt::into_plan)
        .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the dispatched bounded-affix route with exact observed
    /// construction effects.
    pub fn build_bounded_affix_attempt_with_dispatch<Left, Middle, Right>(
        dispatch: SimdDispatchContext,
        left: Left,
        middle: Middle,
        right: Right,
        literal: &[u8],
        middle_max: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        Left: IntoIterator<Item = (u8, u8)>,
        Middle: IntoIterator<Item = (u8, u8)>,
        Right: IntoIterator<Item = (u8, u8)>,
    {
        Self::build_bounded_affix_attempt_inner(
            Some((dispatch, DispatchPolicy::Auto)),
            left,
            middle,
            right,
            literal,
            middle_max,
            limits,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "fail-closed affix construction keeps exact attempt accounting, optional scanner compilation, quota, and publication together"
    )]
    fn build_bounded_affix_attempt_inner<Left, Middle, Right>(
        dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
        left: Left,
        middle: Middle,
        right: Right,
        literal: &[u8],
        middle_max: u32,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        Left: IntoIterator<Item = (u8, u8)>,
        Middle: IntoIterator<Item = (u8, u8)>,
        Right: IntoIterator<Item = (u8, u8)>,
    {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            if literal.is_empty() {
                return Err(BuildError::EmptyLiteral);
            }
            if middle_max > limits.max_gap_bound {
                return Err(BuildError::GapLimit {
                    needed: middle_max,
                    limit: limits.max_gap_bound,
                });
            }
            if literal.len() > limits.max_literal_bytes {
                return Err(BuildError::LiteralLimit {
                    needed: literal.len(),
                    limit: limits.max_literal_bytes,
                });
            }
            let base_persistent_bytes = size_of::<Self>().checked_add(literal.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "bounded-affix persistent bytes",
                },
            )?;
            let base_peak_bytes = base_persistent_bytes.checked_add(literal.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "bounded-affix construction peak bytes",
                },
            )?;
            if literal.len() > limits.max_scratch_bytes {
                return Err(BuildError::ScratchLimit {
                    needed: literal.len(),
                    limit: limits.max_scratch_bytes,
                });
            }
            if base_persistent_bytes > limits.max_persistent_bytes {
                return Err(BuildError::PersistentLimit {
                    needed: base_persistent_bytes,
                    limit: limits.max_persistent_bytes,
                });
            }
            if base_peak_bytes > limits.max_peak_bytes {
                return Err(BuildError::PeakLimit {
                    needed: base_peak_bytes,
                    limit: limits.max_peak_bytes,
                });
            }
            let mut budget = BuildTraversalBudget::new(literal.len(), limits, &mut actual.work)?;
            let (left, left_ranges) = ByteClass::from_ranges(left, "left", &mut budget)?;
            let (middle, middle_ranges) = ByteClass::from_ranges(middle, "middle", &mut budget)?;
            let (right, right_ranges) = ByteClass::from_ranges(right, "right", &mut budget)?;
            if left.is_empty() {
                return Err(BuildError::EmptyClass { role: "left" });
            }
            if middle.is_empty() {
                return Err(BuildError::EmptyClass { role: "middle" });
            }
            if right.is_empty() {
                return Err(BuildError::EmptyClass { role: "right" });
            }
            if middle.overlaps(left) {
                return Err(BuildError::OverlappingSeparator {
                    role: "bounded-affix left/middle",
                });
            }
            if middle.overlaps(right) {
                return Err(BuildError::OverlappingSeparator {
                    role: "bounded-affix right/middle",
                });
            }
            if let Some(&byte) = literal.iter().find(|&&byte| !middle.contains(byte)) {
                return Err(BuildError::LiteralOutsideMiddle { byte });
            }
            let scanner_count = usize::from(run_scanner_eligible(dispatch, middle));
            let scanner_bytes = usize::from(scanner_count != 0)
                .checked_mul(size_of::<RunScanners>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "bounded-affix retained run scanner bytes",
                })?;
            let persistent_bytes = base_persistent_bytes.checked_add(scanner_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "bounded-affix persistent bytes with run scanner",
                },
            )?;
            let peak_bytes = persistent_bytes.checked_add(literal.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "bounded-affix construction peak with run scanner",
                },
            )?;
            if persistent_bytes > limits.max_persistent_bytes {
                return Err(BuildError::PersistentLimit {
                    needed: persistent_bytes,
                    limit: limits.max_persistent_bytes,
                });
            }
            if peak_bytes > limits.max_peak_bytes {
                return Err(BuildError::PeakLimit {
                    needed: peak_bytes,
                    limit: limits.max_peak_bytes,
                });
            }
            budget.charge(
                scanner_count
                    .checked_mul(SIMD_RUN_SCANNER_BUILD_WORK)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "bounded-affix run scanner build work",
                    })?,
            )?;
            let copy_charged_work =
                budget
                    .work
                    .checked_add(literal.len())
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "bounded-affix literal copy work",
                    })?;
            if copy_charged_work > limits.max_build_work {
                return Err(BuildError::WorkLimit {
                    needed: copy_charged_work,
                    limit: limits.max_build_work,
                });
            }
            budget.work = copy_charged_work;
            *budget.actual_work =
                u64::try_from(copy_charged_work).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "actual bounded-affix work as u64",
                })?;
            let run_scanners = build_run_scanners(dispatch, None, Some(middle), None);
            debug_assert_eq!(run_scanners.is_some(), scanner_count != 0);
            let (source_ranges, work) = budget.into_totals();
            let owned = copy_exact(literal).map_err(|error| {
                allocation_build_error(error, "bounded-affix literal", literal.len())
            })?;
            actual.allocations = 1;
            actual.allocated_bytes = literal.len();
            actual.copied_bytes = literal.len();
            actual.initialized_bytes = literal.len();
            actual.peak_bytes = literal.len();
            let run_scanners = retain_run_scanners(run_scanners).map_err(|error| {
                allocation_build_error(error, "bounded-affix retained run scanner", scanner_bytes)
            })?;
            if scanner_bytes != 0 {
                actual.allocations =
                    actual
                        .allocations
                        .checked_add(1)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "bounded-affix allocation count",
                        })?;
                actual.allocated_bytes = actual.allocated_bytes.checked_add(scanner_bytes).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "bounded-affix allocated bytes",
                    },
                )?;
                actual.initialized_bytes = actual
                    .initialized_bytes
                    .checked_add(scanner_bytes)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "bounded-affix initialized bytes",
                    })?;
                actual.peak_bytes = actual.peak_bytes.checked_add(scanner_bytes).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "bounded-affix allocation peak",
                    },
                )?;
            }
            let finder = FinderBuilder::new().build_forward_owned(owned.into_boxed_slice());
            let plan = Self {
                prefix: left,
                separator: middle,
                tail: right,
                finder,
                prefix_width: 1,
                left_gap_max: middle_max,
                right_gap_max: 0,
                tail_width: 1,
                build: BuildAccounting {
                    prefix_ranges: left_ranges,
                    separator_ranges: middle_ranges,
                    tail_ranges: right_ranges,
                    source_ranges,
                    literal_bytes: literal.len(),
                    prefix_width: 1,
                    left_gap_max: middle_max,
                    right_gap_max: 0,
                    tail_width: 1,
                    work,
                    temporary_capacity_bytes: literal.len(),
                    persistent_bytes,
                    peak_bytes,
                },
                bounded_affix: true,
                run_scanners,
            };
            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(size_of::<Self>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "published bounded-affix inline initialized bytes",
                })?;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = actual.peak_bytes.max(persistent_bytes);
            Ok(plan)
        })();
        match result {
            Ok(plan) => Ok(DirectBuildAttempt::new(plan, actual)),
            Err(source) => {
                actual.live_persistent_bytes = 0;
                Err(DirectBuildAttemptError::new(source, actual))
            }
        }
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Immutable selection retained for prefix runs, when this dispatched
    /// general-context plan admitted one.
    #[must_use]
    pub fn prefix_run_scanner_selection(&self) -> Option<SelectionReceipt> {
        RunScanners::selection(self.prefix_run_scanner())
    }

    /// Immutable selection retained for separator runs. In a bounded-affix
    /// plan this is the middle-run scanner.
    #[must_use]
    pub fn separator_run_scanner_selection(&self) -> Option<SelectionReceipt> {
        RunScanners::selection(self.separator_run_scanner())
    }

    /// Immutable selection retained for tail runs, when this dispatched
    /// general-context plan admitted one.
    #[must_use]
    pub fn tail_run_scanner_selection(&self) -> Option<SelectionReceipt> {
        RunScanners::selection(self.tail_run_scanner())
    }

    fn prefix_run_scanner(&self) -> Option<&AsciiByteSetRunScanner> {
        self.run_scanners
            .boxed()
            .and_then(|scanners| scanners.prefix.as_ref())
    }

    fn separator_run_scanner(&self) -> Option<&AsciiByteSetRunScanner> {
        self.run_scanners
            .boxed()
            .and_then(|scanners| scanners.separator.as_ref())
    }

    fn tail_run_scanner(&self) -> Option<&AsciiByteSetRunScanner> {
        self.run_scanners
            .boxed()
            .and_then(|scanners| scanners.tail.as_ref())
    }

    fn run_scanner_recovery_bound(&self, input_bytes: usize) -> Result<usize, ReduceError> {
        let scanner_streams = if self.bounded_affix {
            usize::from(self.separator_run_scanner().is_some())
        } else {
            usize::from(self.prefix_run_scanner().is_some())
                .checked_add(
                    usize::from(self.separator_run_scanner().is_some())
                        .checked_mul(2)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "separator run scanner stream count",
                        })?,
                )
                .and_then(|value| value.checked_add(usize::from(self.tail_run_scanner().is_some())))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-context run scanner stream count",
                })?
        };
        // Every vector entry is preceded by a disjoint 16-member scalar proof.
        // Thus each stream can enter the scanner at most floor(N/16) times.
        let run_events = input_bytes / ASCII_NARROW_BYTES;
        run_events
            .checked_mul(scanner_streams)
            .and_then(|value| value.checked_mul(SIMD_RUN_MAX_RESCAN_INSPECTIONS))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "run scanner recovery classification bound",
            })
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        self.identity(COUNT_OPERATION_ID)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        self.identity(SPAN_SUM_OPERATION_ID)
    }

    const fn identity(&self, operation_id: &'static str) -> OperationIdentity {
        OperationIdentity {
            plan_id: if self.bounded_affix {
                BOUNDED_AFFIX_PLAN_ID
            } else {
                PLAN_ID
            },
            operation_id,
            prefix_width: self.prefix_width,
            left_gap_max: self.left_gap_max,
            right_gap_max: self.right_gap_max,
            tail_width: self.tail_width,
            greedy: true,
            non_overlapping: true,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        if self.bounded_affix {
            return self.count_bounded_affix(haystack, limits);
        }
        let upper_bounds = self.preflight(haystack.len(), limits)?;
        let scratch = zeroed_exact(upper_bounds.scratch_bytes).map_err(|error| {
            allocation_reduce_error(error, "suffix interval table", upper_bounds.scratch_bytes)
        })?;
        let actual = self.execute_with(haystack, scratch, |_start, _end| {})?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: SpanSumLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        if self.bounded_affix {
            return self.span_sum_bounded_affix(haystack, limits);
        }
        let upper_bounds = self.span_sum_preflight(haystack.len(), limits)?;
        let scratch = zeroed_exact(upper_bounds.scratch_bytes).map_err(|error| {
            allocation_reduce_error(error, "suffix interval table", upper_bounds.scratch_bytes)
        })?;
        let mut span_sum = 0_u64;
        let mut span_error = None;
        let actual = self.execute_with(haystack, scratch, |start, end| {
            if span_error.is_none() {
                match checked_span_sum(span_sum, start, end, "bounded-context span sum") {
                    Ok(next) => span_sum = next,
                    Err(error) => span_error = Some(error),
                }
            }
        })?;
        if let Some(error) = span_error {
            return Err(error);
        }
        if span_sum > limits.max_span_sum {
            return Err(ReduceError::SpanSumLimit {
                needed: span_sum,
                limit: limits.max_span_sum,
            });
        }
        Ok(SpanSumResult {
            span_sum,
            accounting: SpanSumAccounting {
                identity: self.span_sum_identity(),
                upper_bounds,
                actual: SpanSumActualCounters {
                    suffix_intervals: actual.suffix_intervals,
                    literal_attempts: actual.literal_attempts,
                    successful_literals: actual.successful_literals,
                    prefix_candidates: actual.prefix_candidates,
                    match_events: actual.match_events,
                    span_sum,
                },
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the bounded endpoint scan keeps selection and checked output publication adjacent"
    )]
    fn count_bounded_affix(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CountResult, ReduceError> {
        if haystack.len() > limits.max_input_bytes {
            return Err(ReduceError::InputLimit {
                needed: haystack.len(),
                limit: limits.max_input_bytes,
            });
        }
        if self.build.persistent_bytes > limits.max_peak_bytes {
            return Err(ReduceError::PeakLimit {
                needed: self.build.persistent_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        let literal = self.finder.needle();
        let upper_bounds = self.bounded_affix_preflight(haystack.len(), literal.len(), limits)?;
        let middle_max =
            usize::try_from(self.left_gap_max).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "bounded-affix middle maximum",
            })?;
        let mut cursor = 0_usize;
        let mut middle_run = 0_usize;
        let mut next_match_start = 0_usize;
        let mut literal_attempts = 0_usize;
        let mut successful_literals = 0_usize;
        let mut prefix_candidates = 0_usize;
        let mut count = 0_u64;
        while cursor < haystack.len() {
            let byte = haystack[cursor];
            if self.separator.contains(byte) {
                let run = self.separator_run_scanner().map_or(1, |scanner| {
                    scan_hot_member_run(haystack, cursor, self.separator, scanner)
                });
                debug_assert!(run != 0);
                middle_run =
                    middle_run
                        .checked_add(run)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix middle run",
                        })?;
                cursor = cursor
                    .checked_add(run)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "bounded-affix scan cursor",
                    })?;
                continue;
            }
            let mut selected = false;
            if self.tail.contains(byte) && middle_run >= literal.len() {
                literal_attempts =
                    literal_attempts
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix literal attempts",
                        })?;
                let literal_start =
                    cursor
                        .checked_sub(literal.len())
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix literal start",
                        })?;
                if haystack[literal_start..cursor] == *literal {
                    successful_literals = successful_literals.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix successful literal count",
                        },
                    )?;
                    let middle_len = middle_run.checked_sub(literal.len()).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix middle length",
                        },
                    )?;
                    let start = cursor
                        .checked_sub(middle_run)
                        .and_then(|value| value.checked_sub(1));
                    if middle_len <= middle_max
                        && start.is_some_and(|start| self.prefix.contains(haystack[start]))
                    {
                        prefix_candidates = prefix_candidates.checked_add(1).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "bounded-affix prefix candidate count",
                            },
                        )?;
                        selected = start.is_some_and(|start| start >= next_match_start);
                    }
                }
            }
            if selected {
                let needed_events = usize::try_from(count)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "bounded-affix match events",
                    })?;
                if needed_events > limits.max_match_events {
                    return Err(ReduceError::MatchEventsLimit {
                        needed: needed_events,
                        limit: limits.max_match_events,
                    });
                }
                count = count
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "bounded-affix count",
                    })?;
                if count > limits.max_count {
                    return Err(ReduceError::CountLimit {
                        needed: count,
                        limit: limits.max_count,
                    });
                }
                next_match_start =
                    cursor
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix next match start",
                        })?;
            }
            middle_run = 0;
            cursor = cursor
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-affix candidate cursor",
                })?;
        }
        let events = usize::try_from(count).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "bounded-affix final event count",
        })?;
        Ok(CountResult {
            count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds,
                actual: ReduceActualCounters {
                    suffix_intervals: 0,
                    literal_attempts,
                    successful_literals,
                    prefix_candidates,
                    match_events: events,
                    count,
                },
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the operation-specific endpoint scan preserves Count's exact frame while sealing SpanSum into its own receipt"
    )]
    fn span_sum_bounded_affix(
        &self,
        haystack: &[u8],
        limits: SpanSumLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        if haystack.len() > limits.max_input_bytes {
            return Err(ReduceError::InputLimit {
                needed: haystack.len(),
                limit: limits.max_input_bytes,
            });
        }
        if self.build.persistent_bytes > limits.max_peak_bytes {
            return Err(ReduceError::PeakLimit {
                needed: self.build.persistent_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        let literal = self.finder.needle();
        let upper_bounds =
            self.bounded_affix_span_sum_preflight(haystack.len(), literal.len(), limits)?;
        let middle_max =
            usize::try_from(self.left_gap_max).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "bounded-affix middle maximum",
            })?;
        let mut cursor = 0_usize;
        let mut middle_run = 0_usize;
        let mut next_match_start = 0_usize;
        let mut literal_attempts = 0_usize;
        let mut successful_literals = 0_usize;
        let mut prefix_candidates = 0_usize;
        let mut match_events = 0_usize;
        let mut span_sum = 0_u64;
        while cursor < haystack.len() {
            let byte = haystack[cursor];
            if self.separator.contains(byte) {
                let run = self.separator_run_scanner().map_or(1, |scanner| {
                    scan_hot_member_run(haystack, cursor, self.separator, scanner)
                });
                debug_assert!(run != 0);
                middle_run =
                    middle_run
                        .checked_add(run)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix middle run",
                        })?;
                cursor = cursor
                    .checked_add(run)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "bounded-affix scan cursor",
                    })?;
                continue;
            }
            let mut selected_start = None;
            if self.tail.contains(byte) && middle_run >= literal.len() {
                literal_attempts =
                    literal_attempts
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix literal attempts",
                        })?;
                let literal_start =
                    cursor
                        .checked_sub(literal.len())
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix literal start",
                        })?;
                if haystack[literal_start..cursor] == *literal {
                    successful_literals = successful_literals.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix successful literal count",
                        },
                    )?;
                    let middle_len = middle_run.checked_sub(literal.len()).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix middle length",
                        },
                    )?;
                    let start = cursor
                        .checked_sub(middle_run)
                        .and_then(|value| value.checked_sub(1));
                    if middle_len <= middle_max
                        && start.is_some_and(|start| self.prefix.contains(haystack[start]))
                    {
                        prefix_candidates = prefix_candidates.checked_add(1).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "bounded-affix prefix candidate count",
                            },
                        )?;
                        selected_start = start.filter(|&start| start >= next_match_start);
                    }
                }
            }
            if let Some(start) = selected_start {
                match_events =
                    match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "bounded-affix match events",
                        })?;
                if match_events > limits.max_match_events {
                    return Err(ReduceError::MatchEventsLimit {
                        needed: match_events,
                        limit: limits.max_match_events,
                    });
                }
                let end = cursor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "bounded-affix next match start",
                    })?;
                span_sum = checked_span_sum(span_sum, start, end, "bounded-affix span sum")?;
                if span_sum > limits.max_span_sum {
                    return Err(ReduceError::SpanSumLimit {
                        needed: span_sum,
                        limit: limits.max_span_sum,
                    });
                }
                next_match_start = end;
            }
            middle_run = 0;
            cursor = cursor
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-affix candidate cursor",
                })?;
        }
        Ok(SpanSumResult {
            span_sum,
            accounting: SpanSumAccounting {
                identity: self.span_sum_identity(),
                upper_bounds,
                actual: SpanSumActualCounters {
                    suffix_intervals: 0,
                    literal_attempts,
                    successful_literals,
                    prefix_candidates,
                    match_events,
                    span_sum,
                },
            },
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the prospective certificate derives and enforces every named dimension before execution"
    )]
    fn bounded_affix_preflight(
        &self,
        input_bytes: usize,
        literal_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let candidate_denominator =
            literal_bytes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-affix candidate denominator",
                })?;
        // `RIGHT` is disjoint from `MIDDLE`, and every literal byte is in
        // `MIDDLE`. An attempted suffix therefore consumes at least the
        // literal bytes plus its terminating right byte; attempts cannot
        // overlap. This bounds both slice comparisons and prefix probes.
        let suffix_candidates = input_bytes.checked_div(candidate_denominator).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "bounded-affix candidate bound",
            },
        )?;
        let scanner_recovery = self.run_scanner_recovery_bound(input_bytes)?;
        let inspections = input_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(suffix_candidates))
            .and_then(|value| value.checked_add(scanner_recovery))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "bounded-affix inspections",
            })?;
        let literal_comparisons = suffix_candidates.checked_mul(literal_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "bounded-affix literal comparisons",
            },
        )?;
        let comparisons = inspections.checked_add(literal_comparisons).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "bounded-affix comparisons",
            },
        )?;
        let branches =
            comparisons
                .checked_add(input_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-affix branches",
                })?;
        let state_writes = input_bytes
            .checked_mul(3)
            .and_then(|value| {
                suffix_candidates
                    .checked_mul(5)
                    .and_then(|term| value.checked_add(term))
            })
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "bounded-affix state writes",
            })?;
        let work = inspections
            .checked_add(comparisons)
            .and_then(|value| value.checked_add(branches))
            .and_then(|value| value.checked_add(state_writes))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "bounded-affix work",
            })?;
        if work > limits.max_work {
            return Err(ReduceError::WorkLimit {
                needed: work,
                limit: limits.max_work,
            });
        }
        let event_denominator =
            literal_bytes
                .checked_add(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-affix event denominator",
                })?;
        let event_bound =
            input_bytes
                .checked_div(event_denominator)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bounded-affix event bound",
                })?;
        if event_bound > limits.max_match_events {
            return Err(ReduceError::MatchEventsLimit {
                needed: event_bound,
                limit: limits.max_match_events,
            });
        }
        let count_bound =
            u64::try_from(event_bound).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "bounded-affix count bound",
            })?;
        if count_bound > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: count_bound,
                limit: limits.max_count,
            });
        }
        Ok(ReduceUpperBounds {
            input_bytes,
            literal_bytes,
            interval_records: 0,
            interval_bytes: 0,
            inspections,
            branches,
            comparisons,
            state_writes,
            work,
            match_events: event_bound,
            count: count_bound,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        })
    }

    fn bounded_affix_span_sum_preflight(
        &self,
        input_bytes: usize,
        literal_bytes: usize,
        limits: SpanSumLimits,
    ) -> Result<SpanSumUpperBounds, ReduceError> {
        let count =
            self.bounded_affix_preflight(input_bytes, literal_bytes, limits.count_preflight())?;
        span_sum_upper_bounds(count, limits.max_span_sum)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the upper-bound certificate computes and validates every named resource dimension together"
    )]
    fn preflight(
        &self,
        input_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let u32_max = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
        if input_bytes > limits.max_input_bytes || input_bytes > u32_max {
            return Err(ReduceError::InputLimit {
                needed: input_bytes,
                limit: limits.max_input_bytes.min(u32_max),
            });
        }
        let literal_bytes = self.finder.needle().len();
        let tail_width =
            usize::try_from(self.tail_width).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "tail width as usize",
            })?;
        let interval_records = input_bytes
            .checked_div(
                tail_width
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "interval denominator",
                    })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "interval record bound",
            })?;
        let interval_bytes = interval_records.checked_mul(INTERVAL_BYTES).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "interval bytes",
            },
        )?;
        let scanner_recovery = self.run_scanner_recovery_bound(input_bytes)?;
        let inspections = input_bytes
            .checked_mul(3)
            .and_then(|value| value.checked_add(literal_bytes))
            .and_then(|value| value.checked_add(scanner_recovery))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "inspection bound",
            })?;
        let branches = input_bytes
            .checked_mul(8)
            .and_then(|value| {
                literal_bytes
                    .checked_mul(4)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(16))
            .and_then(|value| value.checked_add(scanner_recovery))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "branch bound",
            })?;
        let comparisons = input_bytes
            .checked_mul(6)
            .and_then(|value| {
                literal_bytes
                    .checked_mul(4)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(8))
            .and_then(|value| value.checked_add(scanner_recovery))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "comparison bound",
            })?;
        let state_writes = input_bytes
            .checked_mul(4)
            .and_then(|value| {
                literal_bytes
                    .checked_mul(2)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(16))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "state-write bound",
            })?;
        let work = input_bytes
            .checked_mul(21)
            .and_then(|value| {
                literal_bytes
                    .checked_mul(11)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| {
                interval_bytes
                    .checked_mul(3)
                    .and_then(|term| value.checked_add(term))
            })
            .and_then(|value| value.checked_add(40))
            .and_then(|value| {
                scanner_recovery
                    .checked_mul(3)
                    .and_then(|term| value.checked_add(term))
            })
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution work",
            })?;
        let minimum_match_bytes = usize::try_from(self.prefix_width)
            .ok()
            .and_then(|prefix| prefix.checked_add(1))
            .and_then(|value| value.checked_add(literal_bytes))
            .and_then(|value| value.checked_add(1))
            .and_then(|value| {
                usize::try_from(self.tail_width)
                    .ok()
                    .and_then(|tail| value.checked_add(tail))
            })
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "minimum match bytes",
            })?;
        let match_events = input_bytes.checked_div(minimum_match_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "match event bound",
            },
        )?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "count bound",
        })?;
        let peak_bytes = self
            .build
            .persistent_bytes
            .checked_add(interval_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "execution peak bytes",
            })?;
        enforce_reduce(work, limits.max_work, ReduceResource::Work)?;
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
        enforce_reduce(
            interval_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(peak_bytes, limits.max_peak_bytes, ReduceResource::Peak)?;
        Ok(ReduceUpperBounds {
            input_bytes,
            literal_bytes,
            interval_records,
            interval_bytes,
            inspections,
            branches,
            comparisons,
            state_writes,
            work,
            match_events,
            count,
            scratch_bytes: interval_bytes,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes,
        })
    }

    fn span_sum_preflight(
        &self,
        input_bytes: usize,
        limits: SpanSumLimits,
    ) -> Result<SpanSumUpperBounds, ReduceError> {
        let count = self.preflight(input_bytes, limits.count_preflight())?;
        span_sum_upper_bounds(count, limits.max_span_sum)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the three monotone streams share state whose ordering establishes the linear-time and non-overlap proof"
    )]
    fn execute_with(
        &self,
        haystack: &[u8],
        mut intervals: Vec<u8>,
        mut observe: impl FnMut(usize, usize),
    ) -> Result<ReduceActualCounters, ReduceError> {
        let interval_count = self.write_suffix_intervals(haystack, &mut intervals)?;
        let mut interval_cursor = 0_usize;
        let mut latest_interval = None;
        let mut prefix_scanner = PrefixScanner::default();
        let mut pending_prefix = self.next_prefix(haystack, &mut prefix_scanner)?;
        let mut latest_good: Option<GoodLiteral> = None;
        let mut literal_attempts = 0_usize;
        let mut successful_literals = 0_usize;
        let mut prefix_candidates = usize::from(pending_prefix.is_some());
        let mut match_events = 0_usize;

        for literal_start in self.finder.find_iter(haystack) {
            literal_attempts =
                literal_attempts
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "literal attempt count",
                    })?;
            let literal_end = literal_start
                .checked_add(self.finder.needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "literal end",
                })?;
            let right_gap = usize::try_from(self.right_gap_max).map_err(|_| {
                ReduceError::ArithmeticOverflow {
                    computation: "right gap as usize",
                }
            })?;
            let suffix_upper = literal_end.saturating_add(right_gap).min(haystack.len());
            while interval_cursor < interval_count {
                let interval = read_interval(&intervals, interval_cursor)?;
                if interval.start > suffix_upper {
                    break;
                }
                latest_interval = Some(interval);
                interval_cursor =
                    interval_cursor
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "interval cursor",
                        })?;
            }
            let Some(interval) = latest_interval else {
                continue;
            };
            let suffix_start = suffix_upper.min(interval.end.saturating_sub(1));
            if suffix_start < literal_end || suffix_start < interval.start {
                continue;
            }
            let good = GoodLiteral {
                start: literal_start,
                match_end: interval.match_end,
            };
            successful_literals =
                successful_literals
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "successful literal count",
                    })?;

            while pending_prefix.is_some_and(|candidate| candidate.upper < good.start) {
                let Some(candidate) = pending_prefix.take() else {
                    break;
                };
                if let Some(selected) = latest_good.filter(|selected| {
                    selected.start >= candidate.lower && selected.start <= candidate.upper
                }) {
                    match_events =
                        match_events
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "match event count",
                            })?;
                    observe(candidate.start, selected.match_end);
                    prefix_scanner.skip_to(selected.match_end);
                    latest_good = None;
                }
                pending_prefix = self.next_prefix(haystack, &mut prefix_scanner)?;
                prefix_candidates = prefix_candidates
                    .checked_add(usize::from(pending_prefix.is_some()))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "prefix candidate count",
                    })?;
            }
            latest_good = Some(good);
        }

        while let Some(candidate) = pending_prefix.take() {
            if let Some(selected) = latest_good.filter(|selected| {
                selected.start >= candidate.lower && selected.start <= candidate.upper
            }) {
                match_events =
                    match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "final match event count",
                        })?;
                observe(candidate.start, selected.match_end);
                prefix_scanner.skip_to(selected.match_end);
                latest_good = None;
            }
            pending_prefix = self.next_prefix(haystack, &mut prefix_scanner)?;
            prefix_candidates = prefix_candidates
                .checked_add(usize::from(pending_prefix.is_some()))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "final prefix candidate count",
                })?;
        }
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
        Ok(ReduceActualCounters {
            suffix_intervals: interval_count,
            literal_attempts,
            successful_literals,
            prefix_candidates,
            match_events,
            count,
        })
    }

    fn write_suffix_intervals(
        &self,
        haystack: &[u8],
        storage: &mut [u8],
    ) -> Result<usize, ReduceError> {
        let tail_width =
            usize::try_from(self.tail_width).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "tail width as usize",
            })?;
        let mut cursor = 0_usize;
        let mut records = 0_usize;
        while cursor < haystack.len() {
            if !self.separator.contains(haystack[cursor]) {
                cursor = cursor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "suffix scan cursor",
                    })?;
                continue;
            }
            let start = cursor;
            if let Some(scanner) = self.separator_run_scanner() {
                let run = scan_hot_member_run(haystack, cursor, self.separator, scanner);
                debug_assert!(run != 0);
                cursor = cursor
                    .checked_add(run)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "separator run cursor",
                    })?;
            } else {
                while cursor < haystack.len() && self.separator.contains(haystack[cursor]) {
                    cursor = cursor
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "separator run cursor",
                        })?;
                }
            }
            let end = cursor;
            if cursor < haystack.len() && self.tail.contains(haystack[cursor]) {
                if let Some(scanner) = self.tail_run_scanner() {
                    let run = scan_hot_member_run(haystack, cursor, self.tail, scanner);
                    debug_assert!(run != 0);
                    cursor = cursor
                        .checked_add(run)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "tail run cursor",
                        })?;
                } else {
                    while cursor < haystack.len() && self.tail.contains(haystack[cursor]) {
                        cursor = cursor
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "tail run cursor",
                            })?;
                    }
                }
            }
            if cursor.saturating_sub(end) >= tail_width {
                let match_end =
                    end.checked_add(tail_width)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "suffix match end",
                        })?;
                write_interval(
                    storage,
                    records,
                    Interval {
                        start,
                        end,
                        match_end,
                    },
                )?;
                records = records
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "suffix interval count",
                    })?;
            }
        }
        Ok(records)
    }

    fn next_prefix(
        &self,
        haystack: &[u8],
        scanner: &mut PrefixScanner,
    ) -> Result<Option<PrefixCandidate>, ReduceError> {
        let width =
            usize::try_from(self.prefix_width).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "prefix width as usize",
            })?;
        while scanner.cursor < haystack.len() {
            let byte = haystack[scanner.cursor];
            if self.prefix.contains(byte) {
                let run = self.prefix_run_scanner().map_or(1, |run_scanner| {
                    scan_hot_member_run(haystack, scanner.cursor, self.prefix, run_scanner)
                });
                debug_assert!(run != 0);
                scanner.prefix_run =
                    scanner
                        .prefix_run
                        .checked_add(run)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "prefix run length",
                        })?;
                scanner.cursor =
                    scanner
                        .cursor
                        .checked_add(run)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "prefix scan cursor",
                        })?;
                continue;
            }
            if self.separator.contains(byte) {
                let separator_start = scanner.cursor;
                if let Some(run_scanner) = self.separator_run_scanner() {
                    let run =
                        scan_hot_member_run(haystack, scanner.cursor, self.separator, run_scanner);
                    debug_assert!(run != 0);
                    scanner.cursor =
                        scanner
                            .cursor
                            .checked_add(run)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "prefix separator cursor",
                            })?;
                } else {
                    while scanner.cursor < haystack.len()
                        && self.separator.contains(haystack[scanner.cursor])
                    {
                        scanner.cursor = scanner.cursor.checked_add(1).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "prefix separator cursor",
                            },
                        )?;
                    }
                }
                let separator_end = scanner.cursor;
                let prefix_run = core::mem::take(&mut scanner.prefix_run);
                if prefix_run >= width {
                    let start = separator_start.checked_sub(width).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "prefix candidate start",
                        },
                    )?;
                    let left_gap = usize::try_from(self.left_gap_max).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "left gap as usize",
                        }
                    })?;
                    let upper = separator_end.saturating_add(left_gap).min(haystack.len());
                    return Ok(Some(PrefixCandidate {
                        start,
                        lower: separator_end,
                        upper,
                    }));
                }
                continue;
            }
            scanner.prefix_run = 0;
            scanner.cursor =
                scanner
                    .cursor
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "prefix nonclass cursor",
                    })?;
        }
        Ok(None)
    }

    #[cfg(test)]
    fn with_test_run_scanners(mut self, prefix: bool, separator: bool, tail: bool) -> Self {
        let scanner = |enabled: bool, class: ByteClass| {
            enabled.then(|| {
                AsciiByteSetRunScanner::new(
                    class
                        .ascii_set()
                        .expect("the test requests scanners only for ASCII classes"),
                )
            })
        };
        let scanners = RunScanners {
            prefix: scanner(prefix, self.prefix),
            separator: scanner(separator, self.separator),
            tail: scanner(tail, self.tail),
        };
        let scanner_count = usize::from(prefix)
            .checked_add(usize::from(separator))
            .and_then(|value| value.checked_add(usize::from(tail)))
            .expect("three test scanner roles fit usize");
        let scanner_bytes = size_of::<RunScanners>();
        self.run_scanners =
            retain_run_scanners(Some(scanners)).expect("test scanner retention must allocate");
        self.build.work = self
            .build
            .work
            .checked_add(
                scanner_count
                    .checked_mul(SIMD_RUN_SCANNER_BUILD_WORK)
                    .expect("test scanner work fits"),
            )
            .expect("test build work fits");
        self.build.persistent_bytes = self
            .build
            .persistent_bytes
            .checked_add(scanner_bytes)
            .expect("test persistent bytes fit");
        self.build.peak_bytes = self
            .build
            .peak_bytes
            .checked_add(scanner_bytes)
            .expect("test peak bytes fit");
        self
    }

    #[cfg(test)]
    fn spans_for_test(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<Vec<(usize, usize)>, ReduceError> {
        let upper = self.preflight(haystack.len(), limits)?;
        let scratch = zeroed_exact(upper.scratch_bytes).map_err(|error| {
            allocation_reduce_error(error, "test suffix interval table", upper.scratch_bytes)
        })?;
        let mut spans = Vec::new();
        let _ = self.execute_with(haystack, scratch, |start, end| {
            spans.push((start, end));
        })?;
        Ok(spans)
    }
}

fn run_scanner_eligible(
    dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
    class: ByteClass,
) -> bool {
    class.ascii_set().is_some()
        && dispatch
            .is_some_and(|(context, _)| context.capabilities().usable().contains(Feature::ArmSve))
}

fn build_run_scanner(
    dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
    class: Option<ByteClass>,
) -> Option<AsciiByteSetRunScanner> {
    let class = class?;
    if !run_scanner_eligible(dispatch, class) {
        return None;
    }
    let (context, policy) = dispatch.expect("scanner eligibility requires a dispatch context");
    Some(
        context
            .ascii_byte_set_run_scanner(
                class
                    .ascii_set()
                    .expect("scanner eligibility proves one ASCII class"),
                policy,
            )
            .expect("the caller supplied an authentic compatible dispatch policy"),
    )
}

fn build_run_scanners(
    dispatch: Option<(SimdDispatchContext, DispatchPolicy)>,
    prefix: Option<ByteClass>,
    separator: Option<ByteClass>,
    tail: Option<ByteClass>,
) -> Option<RunScanners> {
    let scanners = RunScanners {
        prefix: build_run_scanner(dispatch, prefix),
        separator: build_run_scanner(dispatch, separator),
        tail: build_run_scanner(dispatch, tail),
    };
    (scanners.prefix.is_some() || scanners.separator.is_some() || scanners.tail.is_some())
        .then_some(scanners)
}

fn retain_run_scanners(
    scanners: Option<RunScanners>,
) -> Result<ExactBoxOrUsize<RunScanners>, CopyError> {
    match scanners {
        Some(scanners) => ExactBoxOrUsize::try_from_boxed(scanners),
        None => ExactBoxOrUsize::try_from_usize(0),
    }
}

fn scan_hot_member_run(
    haystack: &[u8],
    start: usize,
    class: ByteClass,
    scanner: &AsciiByteSetRunScanner,
) -> usize {
    let remaining = &haystack[start..];
    debug_assert!(remaining.first().is_some_and(|&byte| class.contains(byte)));
    let mut proof = 1_usize;
    for &byte in remaining[1..]
        .iter()
        .take(ASCII_NARROW_BYTES.saturating_sub(1))
    {
        if !class.contains(byte) {
            return proof;
        }
        proof = proof
            .checked_add(1)
            .expect("the fixed scalar proof length fits usize");
    }
    if proof < ASCII_NARROW_BYTES || proof == remaining.len() {
        return proof;
    }
    proof
        .checked_add(scanner.scan_forward(&remaining[proof..]).member_run_len())
        .expect("a run within one source slice fits usize")
}

fn span_sum_upper_bounds(
    count: ReduceUpperBounds,
    max_span_sum: u64,
) -> Result<SpanSumUpperBounds, ReduceError> {
    // Selected matches are non-overlapping, so their total width cannot
    // exceed the complete input width. This is known before source access.
    let span_sum =
        u64::try_from(count.input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "span-sum upper bound",
        })?;
    if span_sum > max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: span_sum,
            limit: max_span_sum,
        });
    }
    Ok(SpanSumUpperBounds {
        input_bytes: count.input_bytes,
        literal_bytes: count.literal_bytes,
        interval_records: count.interval_records,
        interval_bytes: count.interval_bytes,
        inspections: count.inspections,
        branches: count.branches,
        comparisons: count.comparisons,
        state_writes: count.state_writes,
        work: count.work,
        match_events: count.match_events,
        span_sum,
        scratch_bytes: count.scratch_bytes,
        persistent_bytes: count.persistent_bytes,
        peak_bytes: count.peak_bytes,
    })
}

fn checked_span_sum(
    prior: u64,
    start: usize,
    end: usize,
    computation: &'static str,
) -> Result<u64, ReduceError> {
    let width = end
        .checked_sub(start)
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    let width =
        u64::try_from(width).map_err(|_| ReduceError::ArithmeticOverflow { computation })?;
    prior
        .checked_add(width)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

#[derive(Clone, Copy)]
struct Interval {
    start: usize,
    end: usize,
    match_end: usize,
}

#[derive(Clone, Copy)]
struct GoodLiteral {
    start: usize,
    match_end: usize,
}

#[derive(Clone, Copy)]
struct PrefixCandidate {
    start: usize,
    lower: usize,
    upper: usize,
}

#[derive(Default)]
struct PrefixScanner {
    cursor: usize,
    prefix_run: usize,
}

impl PrefixScanner {
    fn skip_to(&mut self, position: usize) {
        self.cursor = self.cursor.max(position);
        self.prefix_run = 0;
    }
}

fn write_interval(storage: &mut [u8], index: usize, interval: Interval) -> Result<(), ReduceError> {
    let offset = index
        .checked_mul(INTERVAL_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval write offset",
        })?;
    let end = offset
        .checked_add(INTERVAL_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval write end",
        })?;
    let record = storage
        .get_mut(offset..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval capacity proof",
        })?;
    write_interval_field(record, 0, interval.start)?;
    write_interval_field(record, 4, interval.end)?;
    write_interval_field(record, 8, interval.match_end)?;
    Ok(())
}

fn write_interval_field(record: &mut [u8], offset: usize, field: usize) -> Result<(), ReduceError> {
    let value = u32::try_from(field).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "interval field as u32",
    })?;
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval field write end",
        })?;
    let destination = record
        .get_mut(offset..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval field write capacity",
        })?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_interval(storage: &[u8], index: usize) -> Result<Interval, ReduceError> {
    let offset = index
        .checked_mul(INTERVAL_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval read offset",
        })?;
    let end = offset
        .checked_add(INTERVAL_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval read end",
        })?;
    let record = storage
        .get(offset..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval read capacity",
        })?;
    Ok(Interval {
        start: read_interval_field(record, 0)?,
        end: read_interval_field(record, 4)?,
        match_end: read_interval_field(record, 8)?,
    })
}

fn read_interval_field(record: &[u8], start: usize) -> Result<usize, ReduceError> {
    let end = start
        .checked_add(size_of::<u32>())
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval field read end",
        })?;
    let source = record
        .get(start..end)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "interval field read capacity",
        })?;
    let bytes: [u8; 4] = source
        .try_into()
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "interval field width",
        })?;
    usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "interval field as usize",
    })
}

fn allocation_build_error(
    error: CopyError,
    structure: &'static str,
    additional: usize,
) -> BuildError {
    match error {
        CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
            computation: "exact literal allocation layout",
        },
        CopyError::AllocationFailed => BuildError::AllocationFailed {
            structure,
            additional,
        },
    }
}

fn allocation_reduce_error(
    error: CopyError,
    structure: &'static str,
    additional: usize,
) -> ReduceError {
    match error {
        CopyError::LayoutOverflow => ReduceError::ArithmeticOverflow {
            computation: "exact suffix allocation layout",
        },
        CopyError::AllocationFailed => ReduceError::AllocationFailed {
            structure,
            additional,
        },
    }
}

#[derive(Clone, Copy)]
enum ReduceResource {
    Work,
    MatchEvents,
    Scratch,
    Peak,
}

fn enforce_reduce(
    needed: usize,
    limit: usize,
    resource: ReduceResource,
) -> Result<(), ReduceError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;

    use super::{
        BOUNDED_AFFIX_PLAN_ID, BoundedContextPlan, BuildError, BuildLimits, ReduceError,
        ReduceLimits, RunScanners, SIMD_RUN_MAX_RESCAN_INSPECTIONS, SIMD_RUN_SCANNER_BUILD_WORK,
        SPAN_SUM_OPERATION_ID, SpanSumLimits,
    };

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn count_and_span_sum_records_preserve_the_fixed_frame_envelope() {
        assert_eq!(core::mem::size_of::<ReduceLimits>(), 48);
        assert_eq!(core::mem::size_of::<super::ReduceUpperBounds>(), 112);
        assert_eq!(core::mem::size_of::<super::ReduceActualCounters>(), 48);
        assert_eq!(core::mem::size_of::<super::ReduceAccounting>(), 216);
        assert_eq!(core::mem::size_of::<super::CountResult>(), 224);
        // `Finder` deliberately has target-specific SIMD state and alignment
        // (144 bytes on AArch64; 288 bytes aligned to 32 on x86-64 in the
        // locked memchr release). Keep the FRE-owned part exact, account for
        // the dependency's trailing alignment, and enforce the largest
        // supported frame.
        let finder_bytes = core::mem::size_of::<memchr::memmem::Finder<'static>>();
        let finder_align = core::mem::align_of::<memchr::memmem::Finder<'static>>();
        let plan_bytes = core::mem::size_of::<BoundedContextPlan>();
        let plan_align = core::mem::align_of::<BoundedContextPlan>();
        assert_eq!(plan_align, finder_align);
        assert_eq!(
            plan_bytes,
            (finder_bytes + 224).next_multiple_of(plan_align)
        );
        assert!(plan_bytes <= 512);

        assert_eq!(core::mem::size_of::<SpanSumLimits>(), 48);
        assert_eq!(core::mem::size_of::<super::SpanSumUpperBounds>(), 112);
        assert_eq!(core::mem::size_of::<super::SpanSumActualCounters>(), 48);
        assert_eq!(core::mem::size_of::<super::SpanSumAccounting>(), 216);
        assert_eq!(core::mem::size_of::<super::SpanSumResult>(), 224);
    }

    #[test]
    fn build_attempt_reports_exact_success_and_partial_traversal_failure() {
        let attempt = BoundedContextPlan::build_attempt(
            [(b'a', b'z')],
            [(b' ', b' ')],
            [(b'a', b'z')],
            b"R",
            2,
            2,
            2,
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let actual = attempt.actual();
        let plan = attempt.into_plan();
        let build = plan.build_accounting();
        assert_eq!(actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(actual.allocations, 1);
        assert_eq!(actual.allocated_bytes, build.literal_bytes);
        assert_eq!(actual.copied_bytes, build.literal_bytes);
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.persistent_bytes);

        let failure = BoundedContextPlan::build_attempt(
            [(b'a', b'z')],
            [(b'z', b'a')],
            [(b'a', b'z')],
            b"R",
            2,
            2,
            2,
            2,
            BuildLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(
            failure.source(),
            BuildError::ReversedRange {
                role: "separator",
                start: b'z',
                end: b'a'
            }
        ));
        let partial = failure.actual();
        assert_eq!(partial.work, 84);
        assert_eq!(partial.allocations, 0);
        assert_eq!(partial.allocated_bytes, 0);
        assert_eq!(partial.copied_bytes, 0);
        assert_eq!(partial.initialized_bytes, 0);
        assert_eq!(partial.live_persistent_bytes, 0);
        assert_eq!(partial.peak_bytes, 0);

        let affix = BoundedContextPlan::build_bounded_affix_attempt(
            [(b' ', b' ')],
            [(b'a', b'z')],
            [(b' ', b' ')],
            b"ing",
            12,
            BuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            affix.actual().work,
            u64::try_from(affix.into_plan().build_accounting().work).unwrap()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one construction test closes scanner selections, exact effects, identities, and all one-below resource boundaries"
    )]
    fn dispatched_build_charges_one_exact_bundle_and_each_ascii_sve_scanner() {
        use fre_simd_kernels::{Feature, SimdDispatchContext};

        let dispatch = SimdDispatchContext::capture();
        let sve_usable = dispatch.capabilities().usable().contains(Feature::ArmSve);
        let baseline = BoundedContextPlan::build_attempt(
            [(b'a', b'z')],
            [(b' ', b' ')],
            [(b'0', b'9')],
            b"R",
            2,
            2,
            2,
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let dispatched = BoundedContextPlan::build_attempt_with_dispatch(
            dispatch,
            [(b'a', b'z')],
            [(b' ', b' ')],
            [(b'0', b'9')],
            b"R",
            2,
            2,
            2,
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let baseline_actual = baseline.actual();
        let baseline = baseline.into_plan();
        let dispatched_actual = dispatched.actual();
        let dispatched = dispatched.into_plan();
        let selections = [
            dispatched.prefix_run_scanner_selection(),
            dispatched.separator_run_scanner_selection(),
            dispatched.tail_run_scanner_selection(),
        ];
        assert_eq!(
            selections.into_iter().flatten().count(),
            if sve_usable { 3 } else { 0 }
        );
        for selection in selections.into_iter().flatten() {
            assert_eq!(selection.policy, fre_simd_kernels::DispatchPolicy::Auto);
            assert_eq!(selection.selection_input_bytes, 16);
        }
        let scanner_work = usize::from(sve_usable)
            .checked_mul(3 * SIMD_RUN_SCANNER_BUILD_WORK)
            .unwrap();
        let scanner_bytes = usize::from(sve_usable) * core::mem::size_of::<RunScanners>();
        let baseline_build = baseline.build_accounting();
        let dispatched_build = dispatched.build_accounting();
        assert_eq!(dispatched_build.work, baseline_build.work + scanner_work);
        assert_eq!(
            dispatched_build.persistent_bytes,
            baseline_build.persistent_bytes + scanner_bytes
        );
        assert_eq!(
            dispatched_build.peak_bytes,
            baseline_build.peak_bytes + scanner_bytes
        );
        assert_eq!(
            dispatched_actual.allocations,
            baseline_actual.allocations + usize::from(sve_usable)
        );
        assert_eq!(
            dispatched_actual.allocated_bytes,
            baseline_actual.allocated_bytes + scanner_bytes
        );
        assert_eq!(
            dispatched_actual.initialized_bytes,
            dispatched_build.persistent_bytes
        );
        assert_eq!(
            dispatched_actual.live_persistent_bytes,
            dispatched_build.persistent_bytes
        );
        assert_eq!(
            dispatched_actual.peak_bytes,
            dispatched_build.persistent_bytes
        );
        assert_eq!(dispatched.count_identity(), baseline.count_identity());

        let rebuild = |limits| {
            BoundedContextPlan::build_with_dispatch(
                dispatch,
                [(b'a', b'z')],
                [(b' ', b' ')],
                [(b'0', b'9')],
                b"R",
                2,
                2,
                2,
                2,
                limits,
            )
        };
        assert!(
            rebuild(BuildLimits {
                max_build_work: dispatched_build.work,
                max_persistent_bytes: dispatched_build.persistent_bytes,
                max_peak_bytes: dispatched_build.peak_bytes,
                ..BuildLimits::default()
            })
            .is_ok()
        );
        assert!(matches!(
            rebuild(BuildLimits {
                max_build_work: dispatched_build.work - 1,
                ..BuildLimits::default()
            }),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == dispatched_build.work && limit == dispatched_build.work - 1
        ));
        assert!(matches!(
            rebuild(BuildLimits {
                max_persistent_bytes: dispatched_build.persistent_bytes - 1,
                ..BuildLimits::default()
            }),
            Err(BuildError::PersistentLimit { needed, limit })
                if needed == dispatched_build.persistent_bytes
                    && limit == dispatched_build.persistent_bytes - 1
        ));
        assert!(matches!(
            rebuild(BuildLimits {
                max_peak_bytes: dispatched_build.peak_bytes - 1,
                ..BuildLimits::default()
            }),
            Err(BuildError::PeakLimit { needed, limit })
                if needed == dispatched_build.peak_bytes
                    && limit == dispatched_build.peak_bytes - 1
        ));
    }

    #[test]
    fn dispatched_non_ascii_middle_preserves_the_scalar_affix_path() {
        use fre_simd_kernels::SimdDispatchContext;

        let scalar = BoundedContextPlan::build_bounded_affix(
            [(b'x', b'x')],
            [(0x80, 0x80)],
            [(b'y', b'y')],
            b"\x80",
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let dispatched = BoundedContextPlan::build_bounded_affix_with_dispatch(
            SimdDispatchContext::capture(),
            [(b'x', b'x')],
            [(0x80, 0x80)],
            [(b'y', b'y')],
            b"\x80",
            2,
            BuildLimits::default(),
        )
        .unwrap();
        assert!(dispatched.prefix_run_scanner_selection().is_none());
        assert!(dispatched.separator_run_scanner_selection().is_none());
        assert!(dispatched.tail_run_scanner_selection().is_none());
        assert_eq!(dispatched.build_accounting(), scalar.build_accounting());
        assert_eq!(dispatched.count_identity(), scalar.count_identity());
        assert_eq!(
            dispatched
                .count(b"x\x80\x80y", ReduceLimits::default())
                .unwrap(),
            scalar
                .count(b"x\x80\x80y", ReduceLimits::default())
                .unwrap()
        );
    }

    #[derive(Clone)]
    struct DeceptiveRanges<'a> {
        ranges: &'a [(u8, u8)],
        cursor: usize,
        reported_len: usize,
    }

    impl<'a> DeceptiveRanges<'a> {
        const fn new(ranges: &'a [(u8, u8)], reported_len: usize) -> Self {
            Self {
                ranges,
                cursor: 0,
                reported_len,
            }
        }
    }

    impl Iterator for DeceptiveRanges<'_> {
        type Item = (u8, u8);

        fn next(&mut self) -> Option<Self::Item> {
            let next = self.ranges.get(self.cursor).copied();
            self.cursor = self.cursor.saturating_add(usize::from(next.is_some()));
            next
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let claimed = self.reported_len.saturating_sub(self.cursor);
            (claimed, Some(claimed))
        }
    }

    impl ExactSizeIterator for DeceptiveRanges<'_> {}

    fn plan() -> BoundedContextPlan {
        BoundedContextPlan::build(
            [(b'a', b'z')],
            [(b' ', b' ')],
            [(b'a', b'z')],
            b"R",
            4,
            2,
            2,
            4,
            BuildLimits::default(),
        )
        .unwrap()
    }

    fn oracle(pattern: &str, haystack: &[u8]) -> Vec<(usize, usize)> {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect()
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one differential keeps both bounded-context execution shapes and every accounting projection under the same adversarial inputs"
    )]
    fn retained_run_scanners_preserve_general_and_affix_results_and_receipts() {
        let scalar = plan();
        let accelerated = plan().with_test_run_scanners(true, true, true);
        let mut general = Vec::new();
        general.extend(core::iter::repeat_n(b'a', 97));
        general.extend(core::iter::repeat_n(b' ', 131));
        general.extend_from_slice(b"R");
        general.extend(core::iter::repeat_n(b' ', 73));
        general.extend(core::iter::repeat_n(b'z', 89));
        general.extend_from_slice(b"!\xFF");
        general.extend_from_slice(b"aaaa R zzzz");
        for haystack in [
            general.as_slice(),
            b"aaaa R zzzz",
            b"\xFFaaaa  R  zzzz\xFF",
            b"no bounded context here",
            b"",
        ] {
            let scalar_count = scalar.count(haystack, ReduceLimits::default()).unwrap();
            let accelerated_count = accelerated
                .count(haystack, ReduceLimits::default())
                .unwrap();
            assert_eq!(accelerated_count.count, scalar_count.count);
            assert_eq!(
                accelerated_count.accounting.identity,
                scalar_count.accounting.identity
            );
            assert_eq!(
                accelerated_count.accounting.actual,
                scalar_count.accounting.actual
            );
            let scalar_upper = scalar_count.accounting.upper_bounds;
            let accelerated_upper = accelerated_count.accounting.upper_bounds;
            let run_events = haystack.len() / fre_simd_kernels::ASCII_NARROW_BYTES;
            let recovery = run_events * 4 * SIMD_RUN_MAX_RESCAN_INSPECTIONS;
            assert_eq!(
                (
                    accelerated_upper.input_bytes,
                    accelerated_upper.literal_bytes,
                    accelerated_upper.interval_records,
                    accelerated_upper.interval_bytes,
                    accelerated_upper.state_writes,
                    accelerated_upper.match_events,
                    accelerated_upper.count,
                    accelerated_upper.scratch_bytes,
                ),
                (
                    scalar_upper.input_bytes,
                    scalar_upper.literal_bytes,
                    scalar_upper.interval_records,
                    scalar_upper.interval_bytes,
                    scalar_upper.state_writes,
                    scalar_upper.match_events,
                    scalar_upper.count,
                    scalar_upper.scratch_bytes,
                )
            );
            assert_eq!(
                accelerated_upper.inspections,
                scalar_upper.inspections + recovery
            );
            assert_eq!(
                accelerated_upper.comparisons,
                scalar_upper.comparisons + recovery
            );
            assert_eq!(accelerated_upper.branches, scalar_upper.branches + recovery);
            assert_eq!(accelerated_upper.work, scalar_upper.work + 3 * recovery);
            assert_eq!(
                accelerated_upper.persistent_bytes,
                scalar_upper.persistent_bytes + core::mem::size_of::<RunScanners>()
            );
            assert_eq!(
                accelerated_upper.peak_bytes,
                scalar_upper.peak_bytes + core::mem::size_of::<RunScanners>()
            );
            assert_eq!(
                accelerated.spans_for_test(haystack, ReduceLimits::default()),
                scalar.spans_for_test(haystack, ReduceLimits::default())
            );
            let scalar_span = scalar.span_sum(haystack, SpanSumLimits::default()).unwrap();
            let accelerated_span = accelerated
                .span_sum(haystack, SpanSumLimits::default())
                .unwrap();
            assert_eq!(accelerated_span.span_sum, scalar_span.span_sum);
            assert_eq!(
                accelerated_span.accounting.identity,
                scalar_span.accounting.identity
            );
            assert_eq!(
                accelerated_span.accounting.actual,
                scalar_span.accounting.actual
            );
            assert_eq!(
                accelerated_span.accounting.upper_bounds.work,
                scalar_span.accounting.upper_bounds.work + 3 * recovery
            );
            assert_eq!(
                accelerated_span.accounting.upper_bounds.span_sum,
                scalar_span.accounting.upper_bounds.span_sum
            );
        }

        let scalar_affix = BoundedContextPlan::build_bounded_affix(
            [(b'x', b'x')],
            [(b'a', b'b')],
            [(b'y', b'y')],
            b"ab",
            300,
            BuildLimits::default(),
        )
        .unwrap();
        let accelerated_affix = BoundedContextPlan::build_bounded_affix(
            [(b'x', b'x')],
            [(b'a', b'b')],
            [(b'y', b'y')],
            b"ab",
            300,
            BuildLimits::default(),
        )
        .unwrap()
        .with_test_run_scanners(false, true, false);
        let mut affix = Vec::new();
        affix.push(b'x');
        affix.extend(core::iter::repeat_n(b'a', 257));
        affix.extend_from_slice(b"aby\xFFxaby");
        for haystack in [affix.as_slice(), b"xaby", b"x\xFFaby", b""] {
            let scalar_count = scalar_affix
                .count(haystack, ReduceLimits::default())
                .unwrap();
            let accelerated_count = accelerated_affix
                .count(haystack, ReduceLimits::default())
                .unwrap();
            assert_eq!(accelerated_count.count, scalar_count.count);
            assert_eq!(
                accelerated_count.accounting.actual,
                scalar_count.accounting.actual
            );
            assert_eq!(
                accelerated_count.accounting.identity,
                scalar_count.accounting.identity
            );
            assert!(
                accelerated_count.accounting.actual.match_events
                    <= accelerated_count.accounting.upper_bounds.match_events
            );
            let scalar_span = scalar_affix
                .span_sum(haystack, SpanSumLimits::default())
                .unwrap();
            let accelerated_span = accelerated_affix
                .span_sum(haystack, SpanSumLimits::default())
                .unwrap();
            assert_eq!(accelerated_span.span_sum, scalar_span.span_sum);
            assert_eq!(
                accelerated_span.accounting.actual,
                scalar_span.accounting.actual
            );
            assert!(
                accelerated_span.accounting.actual.match_events
                    <= accelerated_span.accounting.upper_bounds.match_events
            );
            assert!(
                accelerated_span.accounting.actual.span_sum
                    <= accelerated_span.accounting.upper_bounds.span_sum
            );
        }
    }

    #[test]
    fn deceptive_exact_size_iterator_is_charged_by_actual_yields() {
        // The prefix advertises one range but yields two. Along with the one
        // separator and one tail range, exact construction therefore needs
        // four ranges and 8*1 + 6*4 + 64 = 96 work units.
        let prefix = [(b'a', b'a'), (b'c', b'c')];
        let build = |limits| {
            BoundedContextPlan::build(
                DeceptiveRanges::new(&prefix, 1),
                [(b' ', b' ')],
                [(b'x', b'z')],
                b"R",
                2,
                2,
                2,
                2,
                limits,
            )
        };
        let exact_limits = BuildLimits {
            max_source_ranges: 4,
            max_build_work: 96,
            ..BuildLimits::default()
        };
        let exact = build(exact_limits).unwrap();
        assert_eq!(exact.build_accounting().prefix_ranges, 2);
        assert_eq!(exact.build_accounting().source_ranges, 4);
        assert_eq!(exact.build_accounting().work, 96);

        assert!(matches!(
            build(BuildLimits {
                max_source_ranges: 3,
                ..exact_limits
            }),
            Err(BuildError::RangeLimit {
                needed: 4,
                limit: 3
            })
        ));
        assert!(matches!(
            build(BuildLimits {
                max_build_work: 95,
                ..exact_limits
            }),
            Err(BuildError::WorkLimit {
                needed: 96,
                limit: 95
            })
        ));
    }

    fn assert_span_sum_limit_boundaries(
        plan: &BoundedContextPlan,
        haystack: &[u8],
        expected_span_sum: u64,
    ) {
        let span = plan.span_sum(haystack, SpanSumLimits::default()).unwrap();
        assert_eq!(span.accounting.actual.span_sum, expected_span_sum);
        assert_eq!(span.accounting.actual.match_events, 1);
        assert_eq!(span.accounting.identity.plan_id, super::PLAN_ID);
        assert_eq!(span.accounting.identity.operation_id, SPAN_SUM_OPERATION_ID);
        let upper = span.accounting.upper_bounds;
        let exact = SpanSumLimits {
            max_input_bytes: upper.input_bytes,
            max_work: upper.work,
            max_match_events: upper.match_events,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        let below_input = upper.input_bytes.checked_sub(1).unwrap();
        let below_work = upper.work.checked_sub(1).unwrap();
        let below_events = upper.match_events.checked_sub(1).unwrap();
        let below_span_sum = upper.span_sum.checked_sub(1).unwrap();
        let below_scratch = upper.scratch_bytes.checked_sub(1).unwrap();
        let below_peak = upper.peak_bytes.checked_sub(1).unwrap();
        assert_eq!(
            plan.span_sum(haystack, exact).unwrap().span_sum,
            expected_span_sum
        );
        assert!(matches!(
            plan.span_sum(
                haystack,
                SpanSumLimits {
                    max_input_bytes: below_input,
                    ..exact
                }
            ),
            Err(ReduceError::InputLimit { needed, limit })
                if needed == upper.input_bytes && limit == below_input
        ));
        assert!(matches!(
            plan.span_sum(
                haystack,
                SpanSumLimits {
                    max_work: below_work,
                    ..exact
                }
            ),
            Err(ReduceError::WorkLimit { needed, limit })
                if needed == upper.work && limit == below_work
        ));
        assert!(matches!(
            plan.span_sum(
                haystack,
                SpanSumLimits {
                    max_match_events: below_events,
                    ..exact
                }
            ),
            Err(ReduceError::MatchEventsLimit { needed, limit })
                if needed == upper.match_events && limit == below_events
        ));
        assert!(matches!(
            plan.span_sum(
                haystack,
                SpanSumLimits {
                    max_span_sum: below_span_sum,
                    ..exact
                }
            ),
            Err(ReduceError::SpanSumLimit { needed, limit })
                if needed == upper.span_sum && limit == below_span_sum
        ));
        assert!(matches!(
            plan.span_sum(
                haystack,
                SpanSumLimits {
                    max_scratch_bytes: below_scratch,
                    ..exact
                }
            ),
            Err(ReduceError::ScratchLimit { needed, limit })
                if needed == upper.scratch_bytes && limit == below_scratch
        ));
        assert!(matches!(
            plan.span_sum(
                haystack,
                SpanSumLimits {
                    max_peak_bytes: below_peak,
                    ..exact
                }
            ),
            Err(ReduceError::PeakLimit { needed, limit })
                if needed == upper.peak_bytes && limit == below_peak
        ));
    }

    #[test]
    fn rebar_row_curated_10_bounded_repeat_context_exact_limit_and_one_below() {
        // rebar-row:curated/10-bounded-repeat/context@rust/regex
        // Hand witness (not SUT-derived): for `[a-z]{2} +.{0,2}R.{0,2} +[a-z]{2}`
        // on `aa R bb`, N=7, L=1, T=2, S=12*floor(7/3)=24, hence
        // W=21*7+11*1+3*24+40=270. Limit 270 admits span 0..7/count 1;
        // limit 269 refuses before allocation or input inspection.
        let witness = BoundedContextPlan::build(
            [(b'a', b'z')],
            [(b' ', b' ')],
            [(b'a', b'z')],
            b"R",
            2,
            2,
            2,
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let haystack = b"aa R bb";
        let exact = witness
            .count(
                haystack,
                ReduceLimits {
                    max_work: 270,
                    ..ReduceLimits::default()
                },
            )
            .unwrap();
        assert_eq!(exact.count, 1);
        assert_eq!(
            witness
                .span_sum(haystack, SpanSumLimits::default())
                .unwrap()
                .span_sum,
            7
        );
        assert_span_sum_limit_boundaries(&witness, haystack, 7);
        assert_eq!(
            witness
                .spans_for_test(haystack, ReduceLimits::default())
                .unwrap(),
            vec![(0, 7)]
        );
        let needed = exact.accounting.upper_bounds.work;
        let refused = witness.count(
            haystack,
            ReduceLimits {
                max_work: needed - 1,
                ..ReduceLimits::default()
            },
        );
        assert!(matches!(refused, Err(ReduceError::WorkLimit { .. })));
    }

    #[test]
    fn rebar_row_curated_10_bounded_repeat_context_complete_spans_cover_bytes() {
        // rebar-row:curated/10-bounded-repeat/context@rust/regex
        let plan = plan();
        let pattern = r"[a-z]{4} +.{0,2}R.{0,2} +[a-z]{4}";
        for haystack in [
            b"aaaa R bbbb".as_slice(),
            b"xx aaaa 12R34 bbbb yy cccc R dddd".as_slice(),
            b"aaaa \xFFR\xFE bbbb".as_slice(),
            b"aaaa 12R345 bbbb".as_slice(),
            b"aaaa 12R34 bbb".as_slice(),
        ] {
            let expected = oracle(pattern, haystack);
            assert_eq!(
                plan.spans_for_test(haystack, ReduceLimits::default())
                    .unwrap(),
                expected
            );
            assert_eq!(
                plan.span_sum(haystack, SpanSumLimits::default())
                    .unwrap()
                    .span_sum,
                expected
                    .iter()
                    .map(|(start, end)| u64::try_from(end - start).unwrap())
                    .sum::<u64>()
            );
        }
    }

    #[test]
    fn rebar_row_curated_10_bounded_repeat_context_linear_scaling_bounds() {
        // rebar-row:curated/10-bounded-repeat/context@rust/regex
        // For the ledger adversary L=1,T=2:
        // W(32)=1083, W(64)=2151, W(128)=4251. Compiler/build traversal is
        // C<=9Q+64, so Q/2Q/4Q at 64/128/256 are <=640/1216/2368.
        for (n, expected) in [(32, 1083), (64, 2151), (128, 4251)] {
            let interval_bytes = 12 * (n / 3);
            assert_eq!(21 * n + 11 + 3 * interval_bytes + 40, expected);
        }
    }

    fn bounded_affix(limits: BuildLimits) -> Result<BoundedContextPlan, BuildError> {
        BoundedContextPlan::build_bounded_affix(
            [(b'\t', b'\r'), (b' ', b' ')],
            [(b'A', b'Z'), (b'a', b'z')],
            [(b'\t', b'\r'), (b' ', b' ')],
            b"ing",
            12,
            limits,
        )
    }

    fn assert_bounded_affix_count_and_build_limits(
        plan: &BoundedContextPlan,
        haystack: &[u8],
        expected_count: u64,
    ) {
        let count = plan.count(haystack, ReduceLimits::default()).unwrap();
        let exact_work = count.accounting.upper_bounds.work;
        let below_work = exact_work.checked_sub(1).unwrap();
        assert_eq!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_work: exact_work,
                    ..ReduceLimits::default()
                }
            )
            .unwrap()
            .count,
            expected_count
        );
        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_work: below_work,
                    ..ReduceLimits::default()
                }
            ),
            Err(ReduceError::WorkLimit { needed, limit })
                if needed == exact_work && limit == below_work
        ));

        let exact_build = plan.build_accounting().work;
        let below_build = exact_build.checked_sub(1).unwrap();
        assert!(
            bounded_affix(BuildLimits {
                max_build_work: exact_build,
                ..BuildLimits::default()
            })
            .is_ok()
        );
        assert!(matches!(
            bounded_affix(BuildLimits {
                max_build_work: below_build,
                ..BuildLimits::default()
            }),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == exact_build && limit == below_build
        ));
    }

    #[test]
    fn bounded_affix_matches_oracle_and_precharges_exact_limits() {
        let plan = bounded_affix(BuildLimits::default()).unwrap();
        let oracle = RegexBuilder::new(r"\s[A-Za-z]{0,12}ing\s")
            .unicode(false)
            .build()
            .unwrap();
        let haystack = b" ing  walking\t thing\n012ing x \xFFing\r";
        let expected = u64::try_from(oracle.find_iter(haystack).count()).unwrap();
        let expected_span_sum = oracle
            .find_iter(haystack)
            .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
            .sum::<u64>();
        let default = plan.count(haystack, ReduceLimits::default()).unwrap();
        assert_eq!(default.count, expected);
        let span_sum = plan.span_sum(haystack, SpanSumLimits::default()).unwrap();
        assert_eq!(span_sum.span_sum, expected_span_sum);
        assert_eq!(span_sum.accounting.actual.span_sum, expected_span_sum);
        assert_eq!(
            span_sum.accounting.actual.match_events,
            usize::try_from(expected).unwrap()
        );
        assert_eq!(
            span_sum.accounting.identity.operation_id,
            SPAN_SUM_OPERATION_ID
        );
        assert_eq!(span_sum.accounting.identity.plan_id, BOUNDED_AFFIX_PLAN_ID);
        let shared_delimiter = b" ing ing ";
        let shared = plan
            .count(shared_delimiter, ReduceLimits::default())
            .unwrap();
        assert_eq!(
            shared.count,
            u64::try_from(oracle.find_iter(shared_delimiter).count()).unwrap()
        );
        assert_eq!(shared.accounting.actual.literal_attempts, 2);
        assert_eq!(shared.accounting.actual.successful_literals, 2);
        assert_eq!(shared.accounting.actual.prefix_candidates, 2);
        assert_eq!(shared.accounting.actual.match_events, 1);
        let shared_span = plan
            .span_sum(shared_delimiter, SpanSumLimits::default())
            .unwrap();
        assert_eq!(shared_span.span_sum, 5);
        assert_eq!(shared_span.accounting.actual.match_events, 1);
        assert_eq!(shared_span.accounting.actual.span_sum, 5);

        let adjacent = b" ing \ting ";
        let adjacent_span = plan.span_sum(adjacent, SpanSumLimits::default()).unwrap();
        assert_eq!(adjacent_span.span_sum, 10);
        assert_eq!(adjacent_span.accounting.actual.match_events, 2);
        assert_eq!(adjacent_span.accounting.actual.span_sum, 10);

        let covered = b" ing  walking\t";
        let covered_span = plan
            .span_sum(
                covered,
                SpanSumLimits {
                    max_input_bytes: covered.len(),
                    max_work: usize::MAX,
                    max_match_events: 2,
                    max_span_sum: 14,
                    max_scratch_bytes: 0,
                    max_peak_bytes: usize::MAX,
                },
            )
            .unwrap();
        assert_eq!(covered_span.span_sum, 14);
        assert_eq!(covered_span.accounting.upper_bounds.span_sum, 14);
        assert_eq!(covered_span.accounting.actual.span_sum, 14);
        assert_eq!(covered_span.accounting.actual.match_events, 2);
        assert!(matches!(
            plan.span_sum(
                covered,
                SpanSumLimits {
                    max_span_sum: 13,
                    ..SpanSumLimits::default()
                }
            ),
            Err(ReduceError::SpanSumLimit {
                needed: 14,
                limit: 13
            })
        ));
        assert!(
            default.accounting.actual.literal_attempts
                >= default.accounting.actual.successful_literals
        );
        assert!(
            default.accounting.actual.successful_literals
                >= default.accounting.actual.prefix_candidates
        );
        assert!(
            default.accounting.actual.prefix_candidates >= default.accounting.actual.match_events
        );
        let failed_suffix = plan.count(b" abc ", ReduceLimits::default()).unwrap();
        assert_eq!(failed_suffix.count, 0);
        assert_eq!(failed_suffix.accounting.actual.literal_attempts, 1);
        assert_eq!(failed_suffix.accounting.actual.successful_literals, 0);
        assert_ne!(
            default.accounting.upper_bounds.inspections,
            default.accounting.upper_bounds.branches
        );
        assert_bounded_affix_count_and_build_limits(&plan, haystack, expected);
        assert!(span_sum.span_sum <= u64::try_from(haystack.len()).unwrap());
    }

    #[test]
    fn bounded_affix_count_and_span_sum_match_exhaustive_byte_oracle() {
        let plan = BoundedContextPlan::build_bounded_affix(
            [(b'x', b'x')],
            [(b'a', b'b')],
            [(b'y', b'y')],
            b"ab",
            2,
            BuildLimits::default(),
        )
        .unwrap();
        let oracle = RegexBuilder::new(r"x[ab]{0,2}aby")
            .unicode(false)
            .build()
            .unwrap();
        let alphabet = [b'x', b'a', b'b', b'y', b'z', 0xFF];
        for length in 0..=6_u32 {
            for mut ordinal in 0..alphabet.len().pow(length) {
                let mut haystack = vec![0_u8; usize::try_from(length).unwrap()];
                for byte in &mut haystack {
                    *byte = alphabet[ordinal % alphabet.len()];
                    ordinal /= alphabet.len();
                }
                let expected = oracle.find_iter(&haystack).collect::<Vec<_>>();
                let expected_count = u64::try_from(expected.len()).unwrap();
                let expected_span_sum = expected
                    .iter()
                    .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                    .sum::<u64>();
                let count = plan.count(&haystack, ReduceLimits::default()).unwrap();
                let span_sum = plan.span_sum(&haystack, SpanSumLimits::default()).unwrap();
                assert_eq!(count.count, expected_count, "haystack={haystack:?}");
                assert_eq!(
                    span_sum.span_sum, expected_span_sum,
                    "haystack={haystack:?}"
                );
                assert_eq!(
                    span_sum.accounting.actual.span_sum, expected_span_sum,
                    "haystack={haystack:?}"
                );
                assert_eq!(
                    span_sum.accounting.actual.match_events,
                    usize::try_from(expected_count).unwrap(),
                    "haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    #[ignore = "manual release-mode scalar/Auto SVE qualification"]
    #[allow(
        clippy::too_many_lines,
        reason = "the ignored qualification keeps the affix and general-context scenarios under one paired timing harness"
    )]
    fn measure_bounded_context_auto_run_scanners() {
        use fre_simd_kernels::{Feature, SimdDispatchContext};
        use std::hint::black_box;
        use std::time::{Duration, Instant};

        #[allow(
            clippy::too_many_arguments,
            reason = "the parseable paired timing record carries its scenario metadata beside both measured closures"
        )]
        fn measure(
            scenario: &str,
            variant: &str,
            scanner_count: usize,
            build_work_delta: usize,
            batches: u32,
            calls_per_batch: u32,
            mut scalar: impl FnMut() -> u64,
            mut automatic: impl FnMut() -> u64,
        ) {
            let mut scalar_elapsed = Duration::ZERO;
            let mut automatic_elapsed = Duration::ZERO;
            let mut scalar_checksum = 0_u64;
            let mut automatic_checksum = 0_u64;
            for batch in 0..batches {
                let mut time_scalar = || {
                    let start = Instant::now();
                    for _ in 0..calls_per_batch {
                        scalar_checksum =
                            scalar_checksum.wrapping_add(black_box(scalar()).wrapping_add(1));
                    }
                    scalar_elapsed += start.elapsed();
                };
                let mut time_automatic = || {
                    let start = Instant::now();
                    for _ in 0..calls_per_batch {
                        automatic_checksum =
                            automatic_checksum.wrapping_add(black_box(automatic()).wrapping_add(1));
                    }
                    automatic_elapsed += start.elapsed();
                };
                if batch & 1 == 0 {
                    time_scalar();
                    time_automatic();
                } else {
                    time_automatic();
                    time_scalar();
                }
            }
            assert_eq!(automatic_checksum, scalar_checksum);
            eprintln!(
                "BOUNDED_CONTEXT_AUTO_RUN_BENCH scenario={scenario} policy=auto \
                 variant={variant} scanner_count={scanner_count} \
                 build_work_delta={build_work_delta} scalar_ns={} auto_ns={} \
                 auto_over_scalar={:.6} checksum={automatic_checksum}",
                scalar_elapsed.as_nanos(),
                automatic_elapsed.as_nanos(),
                automatic_elapsed.as_secs_f64() / scalar_elapsed.as_secs_f64(),
            );
        }

        let dispatch = SimdDispatchContext::capture();
        assert!(
            dispatch.capabilities().usable().contains(Feature::ArmSve),
            "this qualification benchmark requires an OS-usable SVE host"
        );

        let scalar_affix = BoundedContextPlan::build_bounded_affix(
            [(b'x', b'x')],
            [(b'a', b'b')],
            [(b'y', b'y')],
            b"ab",
            512,
            BuildLimits::default(),
        )
        .unwrap();
        let automatic_affix = BoundedContextPlan::build_bounded_affix_with_dispatch(
            dispatch,
            [(b'x', b'x')],
            [(b'a', b'b')],
            [(b'y', b'y')],
            b"ab",
            512,
            BuildLimits::default(),
        )
        .unwrap();
        let mut affix_haystack = Vec::new();
        for _ in 0..1_024 {
            affix_haystack.push(b'x');
            affix_haystack.extend(core::iter::repeat_n(b'a', 256));
            affix_haystack.extend_from_slice(b"aby!");
        }
        let affix_variant = automatic_affix
            .separator_run_scanner_selection()
            .expect("OS-usable SVE must retain the ASCII middle scanner")
            .variant_id;
        measure(
            "bounded_affix_middle_258",
            affix_variant,
            1,
            automatic_affix.build_accounting().work - scalar_affix.build_accounting().work,
            9,
            32,
            || {
                scalar_affix
                    .count(black_box(&affix_haystack), ReduceLimits::default())
                    .unwrap()
                    .count
            },
            || {
                automatic_affix
                    .count(black_box(&affix_haystack), ReduceLimits::default())
                    .unwrap()
                    .count
            },
        );

        let scalar_context = BoundedContextPlan::build(
            [(b'A', b'A')],
            [(b' ', b' ')],
            [(b'z', b'z')],
            b"R",
            4,
            2,
            2,
            4,
            BuildLimits::default(),
        )
        .unwrap();
        let automatic_context = BoundedContextPlan::build_with_dispatch(
            dispatch,
            [(b'A', b'A')],
            [(b' ', b' ')],
            [(b'z', b'z')],
            b"R",
            4,
            2,
            2,
            4,
            BuildLimits::default(),
        )
        .unwrap();
        let mut context_haystack = Vec::new();
        for _ in 0..1_024 {
            context_haystack.extend(core::iter::repeat_n(b'A', 64));
            context_haystack.extend(core::iter::repeat_n(b' ', 64));
            context_haystack.push(b'R');
            context_haystack.extend(core::iter::repeat_n(b' ', 64));
            context_haystack.extend(core::iter::repeat_n(b'z', 64));
            context_haystack.push(b'!');
        }
        let context_variant = automatic_context
            .separator_run_scanner_selection()
            .expect("OS-usable SVE must retain the ASCII separator scanner")
            .variant_id;
        measure(
            "general_prefix_separator_tail_64",
            context_variant,
            3,
            automatic_context.build_accounting().work - scalar_context.build_accounting().work,
            9,
            32,
            || {
                scalar_context
                    .count(black_box(&context_haystack), ReduceLimits::default())
                    .unwrap()
                    .count
            },
            || {
                automatic_context
                    .count(black_box(&context_haystack), ReduceLimits::default())
                    .unwrap()
                    .count
            },
        );
    }

    #[test]
    fn bounded_affix_overflow_precedes_work_limit() {
        let plan = bounded_affix(BuildLimits::default()).unwrap();
        assert!(matches!(
            plan.bounded_affix_preflight(
                usize::MAX,
                3,
                ReduceLimits {
                    max_work: 0,
                    ..ReduceLimits::default()
                }
            ),
            Err(ReduceError::ArithmeticOverflow { .. })
        ));
    }
}
