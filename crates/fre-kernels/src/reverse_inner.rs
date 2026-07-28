//! Required-literal reduction for ordered alternatives of
//! `UNICODE_CLASS+ ASCII_LITERAL UNICODE_CLASS+`.
//!
//! Admission requires the same canonical Unicode scalar class on both sides
//! of every alternative, greedy nonempty repetitions, and one nonempty ASCII
//! literal per branch whose scalars all belong to the class. For any maximal
//! class run containing a literal strictly inside the run, greedy backtracking
//! can select a viable literal occurrence and both repetitions together cover
//! the complete run. Every successful alternative therefore has the same
//! whole-match span: that maximal run. Source-order priority can change an
//! internal path or capture, but not count or matched-byte sum.
//!
//! Literal occurrences identify candidate runs through monotone `memmem`
//! streams. A candidate's maximal run is recovered with bounded reverse and
//! forward UTF-8 decoding. The strict interior is searched from
//! `run_start + 1`, rather than by consuming a non-overlapping occurrence
//! iterator. That detail is required for overlap completeness: class `a`,
//! literal `aa`, and run `aaaa` has its only viable occurrence at offset one.
//! Candidate runs are disjoint, so scalar decoding is linear in source bytes;
//! the fixed number of literal streams contributes another linear factor.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all resource and index arithmetic is checked before use; bitmap shifts use proved 0..=63 operands"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::{CopyError, ExactVec, copy_exact};
use memchr::memmem::{Finder, FinderBuilder};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError, Window};

/// Stable identity of the admitted theorem and physical reducer.
pub const PLAN_ID: &str = "reverse-inner.unicode-class-plus-ascii-literal-class-plus.v1";
/// Stable identity of complete non-overlapping match counting.
pub const COUNT_OPERATION_ID: &str = "reverse-inner.count.maximal-unicode-class-run.v1";
/// Stable identity of complete matched-byte summation.
pub const SPAN_SUM_OPERATION_ID: &str = "reverse-inner.span-sum.maximal-unicode-class-run.v1";
/// Hard inline bound for independently retained literal streams.
pub const MAX_LITERALS: usize = 16;

const BUILD_FIXED_WORK: usize = 16;
const BUILD_RANGE_WORK: usize = 4;
const BUILD_LITERAL_FIXED_WORK: usize = 3;
const BUILD_LITERAL_BYTE_WORK: usize = 5;
const REDUCE_FIXED_WORK: usize = 16;
const FINDER_CALL_WORK: usize = 4;
const RUN_WORK: usize = 8;
const MATCH_WORK: usize = 4;
const MEMBERSHIP_WORK: usize = 2;

/// Complete operation selected before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Count,
    SpanSum,
}

/// UTF-8, priority, greediness, and iteration contract proved by admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Semantics {
    /// Rust byte-regex Unicode scalar classes with `utf8(false)`. Invalid
    /// encodings never belong to the class and each invalid byte is a barrier.
    RustBytesUnicodeUtf8False,
}

/// Stable semantic and physical identity for one selected operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each theorem premise is independently authenticated at the facade boundary"
)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub operation: Operation,
    pub semantics: Semantics,
    pub source_ranges: usize,
    pub literal_count: usize,
    pub literal_bytes: usize,
    /// Source-order-sensitive fingerprint of literal lengths and bytes.
    pub literal_fingerprint: u64,
    pub unicode: bool,
    pub greedy: bool,
    pub leftmost_first: bool,
    pub non_overlapping: bool,
}

/// Limits checked before any persistent allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_source_ranges: usize,
    pub max_literals: usize,
    pub max_literal_bytes: usize,
    pub max_total_literal_bytes: usize,
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
            max_literals: usize::MAX,
            max_literal_bytes: usize::MAX,
            max_total_literal_bytes: usize::MAX,
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
            max_literals: MAX_LITERALS,
            max_literal_bytes: 1 << 16,
            max_total_literal_bytes: 1 << 20,
            max_build_work: 1 << 24,
            max_scratch_bytes: 0,
            max_persistent_bytes: 1 << 24,
            max_peak_bytes: 1 << 24,
        }
    }
}

/// Auditable exact-capacity construction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub source_ranges: usize,
    pub retained_non_ascii_ranges: usize,
    pub retained_range_capacity: usize,
    pub ascii_scalars: usize,
    pub literal_count: usize,
    pub literal_bytes: usize,
    pub literal_fingerprint: u64,
    pub work: usize,
    pub allocations: usize,
    pub allocated_bytes: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Limits checked from source-free full-window bounds before source access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_finder_calls: usize,
    pub max_finder_scanned_bytes: usize,
    pub max_decode_byte_checks: usize,
    pub max_membership_tests: usize,
    pub max_range_comparisons: usize,
    pub max_run_events: usize,
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
            max_finder_calls: usize::MAX,
            max_finder_scanned_bytes: usize::MAX,
            max_decode_byte_checks: usize::MAX,
            max_membership_tests: usize::MAX,
            max_range_comparisons: usize::MAX,
            max_run_events: usize::MAX,
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
            max_input_bytes: 512 << 20,
            max_finder_calls: 1 << 31,
            max_finder_scanned_bytes: 64 << 30,
            max_decode_byte_checks: 4 << 30,
            max_membership_tests: 1 << 30,
            max_range_comparisons: 64 << 30,
            max_run_events: 1 << 30,
            max_match_events: 1 << 30,
            max_count: 1 << 30,
            max_span_sum: u64::MAX,
            max_work: 128 << 30,
            max_scratch_bytes: 0,
            max_peak_bytes: 1 << 24,
        }
    }
}

/// Source-free full-window resource envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub literal_occurrence_positions: usize,
    pub outer_finder_calls: usize,
    pub inner_finder_calls: usize,
    pub finder_calls: usize,
    pub finder_scanned_bytes: usize,
    pub decode_byte_checks: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub run_events: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact structural counters observed by one completed reduction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes: usize,
    pub outer_finder_calls: usize,
    pub inner_finder_calls: usize,
    pub finder_calls: usize,
    pub finder_scanned_bytes: usize,
    pub outer_candidates: usize,
    pub inner_candidates: usize,
    pub decode_byte_checks: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub run_events: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Complete execution certificate.
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

/// Semantic refusal or checked construction-resource failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass,
    ReversedRange {
        start: char,
        end: char,
    },
    NonCanonicalRanges,
    EmptyLiteralSet,
    TooManyLiterals {
        needed: usize,
        limit: usize,
    },
    EmptyLiteral {
        index: usize,
    },
    NonAsciiLiteral {
        index: usize,
        byte: u8,
    },
    LiteralScalarOutsideClass {
        index: usize,
        byte: u8,
    },
    SourceRangesLimit {
        needed: usize,
        limit: usize,
    },
    LiteralBytesLimit {
        needed: usize,
        limit: usize,
    },
    TotalLiteralBytesLimit {
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
    AllocationFailed {
        structure: &'static str,
        bytes: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "reverse-inner build failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

/// Checked execution refusal. No partial aggregate is published.
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
    FinderCallsLimit {
        needed: usize,
        limit: usize,
    },
    FinderScannedBytesLimit {
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
    RunEventsLimit {
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
    AccountingInvariant {
        resource: &'static str,
        actual: u64,
        upper: u64,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "reverse-inner reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScalarRange {
    start: u32,
    end: u32,
}

/// Owned, deliberately non-`Clone` plan.
#[derive(Debug)]
pub struct ReverseInnerPlan {
    ascii: [u64; 2],
    non_ascii: ExactVec<ScalarRange>,
    finders: ExactVec<Finder<'static>>,
    build: BuildAccounting,
}

impl ReverseInnerPlan {
    /// Build from one canonical scalar class and source-ordered literals.
    pub fn build<I>(ranges: I, literals: &[&[u8]], limits: BuildLimits) -> Result<Self, BuildError>
    where
        I: ExactSizeIterator<Item = (char, char)> + Clone,
    {
        Self::build_attempt(ranges, literals, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build while retaining exact successful or partial terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "validation, exact-capacity allocations, publication, and terminal effects remain one auditable transaction"
    )]
    pub fn build_attempt<I>(
        ranges: I,
        literals: &[&[u8]],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: ExactSizeIterator<Item = (char, char)> + Clone,
    {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            let source_ranges = ranges.len();
            if source_ranges == 0 {
                return Err(BuildError::EmptyClass);
            }
            enforce_build(
                source_ranges,
                limits.max_source_ranges,
                BuildResource::SourceRanges,
            )?;
            if literals.is_empty() {
                return Err(BuildError::EmptyLiteralSet);
            }
            let literal_limit = limits.max_literals.min(MAX_LITERALS);
            if literals.len() > literal_limit {
                return Err(BuildError::TooManyLiterals {
                    needed: literals.len(),
                    limit: literal_limit,
                });
            }

            let mut ascii = [0_u64; 2];
            let mut retained_non_ascii_ranges = 0_usize;
            let mut ascii_scalars = 0_usize;
            let mut previous_end = None::<u32>;
            let mut work = BUILD_FIXED_WORK;
            for (start, end) in ranges.clone() {
                if start > end {
                    return Err(BuildError::ReversedRange { start, end });
                }
                let start = u32::from(start);
                let end = u32::from(end);
                if previous_end.is_some_and(|previous| start <= previous.saturating_add(1)) {
                    return Err(BuildError::NonCanonicalRanges);
                }
                previous_end = Some(end);
                work = checked_add_build(work, BUILD_RANGE_WORK, "range validation work")?;
                if start <= 0x7F {
                    let ascii_end = end.min(0x7F);
                    insert_ascii_range(&mut ascii, start, ascii_end)?;
                    ascii_scalars = checked_add_build(
                        ascii_scalars,
                        usize::try_from(ascii_end - start + 1).map_err(|_| {
                            BuildError::ArithmeticOverflow {
                                computation: "ASCII scalar population",
                            }
                        })?,
                        "ASCII scalar population",
                    )?;
                }
                if end > 0x7F {
                    retained_non_ascii_ranges = checked_add_build(
                        retained_non_ascii_ranges,
                        1,
                        "retained non-ASCII range count",
                    )?;
                }
            }

            let mut literal_bytes = 0_usize;
            let mut literal_fingerprint = 0xcbf2_9ce4_8422_2325_u64;
            for (index, literal) in literals.iter().enumerate() {
                if literal.is_empty() {
                    return Err(BuildError::EmptyLiteral { index });
                }
                if literal.len() > limits.max_literal_bytes {
                    return Err(BuildError::LiteralBytesLimit {
                        needed: literal.len(),
                        limit: limits.max_literal_bytes,
                    });
                }
                literal_bytes =
                    checked_add_build(literal_bytes, literal.len(), "literal byte total")?;
                for &byte in *literal {
                    if !byte.is_ascii() {
                        return Err(BuildError::NonAsciiLiteral { index, byte });
                    }
                    if !ascii_contains(ascii, byte) {
                        return Err(BuildError::LiteralScalarOutsideClass { index, byte });
                    }
                    literal_fingerprint ^= u64::from(byte);
                    literal_fingerprint = literal_fingerprint.wrapping_mul(0x100_0000_01b3);
                }
                literal_fingerprint ^=
                    u64::try_from(literal.len()).map_err(|_| BuildError::ArithmeticOverflow {
                        computation: "literal length fingerprint",
                    })?;
                literal_fingerprint = literal_fingerprint.wrapping_mul(0x100_0000_01b3);
                let byte_work = literal.len().checked_mul(BUILD_LITERAL_BYTE_WORK).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "literal byte build work",
                    },
                )?;
                work = work
                    .checked_add(BUILD_LITERAL_FIXED_WORK)
                    .and_then(|value| value.checked_add(byte_work))
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "literal build work",
                    })?;
            }
            if literal_bytes > limits.max_total_literal_bytes {
                return Err(BuildError::TotalLiteralBytesLimit {
                    needed: literal_bytes,
                    limit: limits.max_total_literal_bytes,
                });
            }
            actual.work = u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "build work as u64",
            })?;
            enforce_build(work, limits.max_build_work, BuildResource::Work)?;

            let range_capacity_bytes = source_ranges.checked_mul(size_of::<ScalarRange>()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "range capacity bytes",
                },
            )?;
            let finder_capacity_bytes = literals
                .len()
                .checked_mul(size_of::<Finder<'static>>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "finder capacity bytes",
                })?;
            let allocated_bytes = range_capacity_bytes
                .checked_add(finder_capacity_bytes)
                .and_then(|value| value.checked_add(literal_bytes))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent allocated bytes",
                })?;
            let allocations = usize::from(source_ranges != 0)
                .checked_add(usize::from(!literals.is_empty()))
                .and_then(|value| value.checked_add(literals.len()))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent allocation count",
                })?;
            let persistent_bytes = size_of::<Self>().checked_add(allocated_bytes).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent plan bytes",
                },
            )?;
            let scratch_bytes = 0_usize;
            let peak_bytes = persistent_bytes;
            enforce_build(
                scratch_bytes,
                limits.max_scratch_bytes,
                BuildResource::Scratch,
            )?;
            enforce_build(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

            let mut non_ascii = ExactVec::try_with_capacity(source_ranges).map_err(|error| {
                allocation_error("Unicode scalar ranges", range_capacity_bytes, error)
            })?;
            record_allocation(&mut actual, range_capacity_bytes)?;
            for (start, end) in ranges {
                let start = u32::from(start);
                let end = u32::from(end);
                if end > 0x7F {
                    non_ascii
                        .try_push(ScalarRange {
                            start: start.max(0x80),
                            end,
                        })
                        .map_err(|_| BuildError::ArithmeticOverflow {
                            computation: "exact non-ASCII range capacity",
                        })?;
                    record_initialization(&mut actual, size_of::<ScalarRange>(), true)?;
                }
            }

            let mut finders = ExactVec::try_with_capacity(literals.len()).map_err(|error| {
                allocation_error("literal finder array", finder_capacity_bytes, error)
            })?;
            record_allocation(&mut actual, finder_capacity_bytes)?;
            for literal in literals {
                let owned = copy_exact(literal)
                    .map_err(|error| allocation_error("literal bytes", literal.len(), error))?;
                record_allocation(&mut actual, literal.len())?;
                record_initialization(&mut actual, literal.len(), true)?;
                let finder = FinderBuilder::new().build_forward_owned(owned.into_boxed_slice());
                finders
                    .try_push(finder)
                    .map_err(|_| BuildError::ArithmeticOverflow {
                        computation: "exact finder capacity",
                    })?;
                record_initialization(&mut actual, size_of::<Finder<'static>>(), false)?;
            }

            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(size_of::<Self>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "published plan initialized bytes",
                })?;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = actual.peak_bytes.max(persistent_bytes);
            debug_assert_eq!(actual.allocations, allocations);
            debug_assert_eq!(actual.allocated_bytes, allocated_bytes);
            let build = BuildAccounting {
                source_ranges,
                retained_non_ascii_ranges,
                retained_range_capacity: source_ranges,
                ascii_scalars,
                literal_count: literals.len(),
                literal_bytes,
                literal_fingerprint,
                work,
                allocations,
                allocated_bytes,
                scratch_bytes,
                persistent_bytes,
                peak_bytes,
            };
            Ok(Self {
                ascii,
                non_ascii,
                finders,
                build,
            })
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

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        self.identity(Operation::Count)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        self.identity(Operation::SpanSum)
    }

    const fn identity(&self, operation: Operation) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id: match operation {
                Operation::Count => COUNT_OPERATION_ID,
                Operation::SpanSum => SPAN_SUM_OPERATION_ID,
            },
            operation,
            semantics: Semantics::RustBytesUnicodeUtf8False,
            source_ranges: self.build.source_ranges,
            literal_count: self.build.literal_count,
            literal_bytes: self.build.literal_bytes,
            literal_fingerprint: self.build.literal_fingerprint,
            unicode: true,
            greedy: true,
            leftmost_first: true,
            non_overlapping: true,
        }
    }

    /// Publish the source-free full-window envelope.
    pub fn full_window_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        derive_upper_bounds(self.build, &self.finders, input_bytes)
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
        let upper = self.preflight(haystack, window, Operation::Count, limits)?;
        let actual = self.execute(haystack, window, Operation::Count, upper)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                window,
                upper_bounds: upper,
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
        let upper = self.preflight(haystack, window, Operation::SpanSum, limits)?;
        let actual = self.execute(haystack, window, Operation::SpanSum, upper)?;
        Ok(SpanSumResult {
            span_sum: actual.span_sum,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                window,
                upper_bounds: upper,
                actual,
            },
        })
    }

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
        let upper = derive_upper_bounds(self.build, &self.finders, input_bytes)?;
        enforce_reduce(
            upper.input_bytes,
            limits.max_input_bytes,
            ReduceResource::InputBytes,
        )?;
        enforce_reduce(
            upper.finder_calls,
            limits.max_finder_calls,
            ReduceResource::FinderCalls,
        )?;
        enforce_reduce(
            upper.finder_scanned_bytes,
            limits.max_finder_scanned_bytes,
            ReduceResource::FinderScannedBytes,
        )?;
        enforce_reduce(
            upper.decode_byte_checks,
            limits.max_decode_byte_checks,
            ReduceResource::DecodeByteChecks,
        )?;
        enforce_reduce(
            upper.membership_tests,
            limits.max_membership_tests,
            ReduceResource::MembershipTests,
        )?;
        enforce_reduce(
            upper.range_comparisons,
            limits.max_range_comparisons,
            ReduceResource::RangeComparisons,
        )?;
        enforce_reduce(
            upper.run_events,
            limits.max_run_events,
            ReduceResource::RunEvents,
        )?;
        enforce_reduce(
            upper.match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        )?;
        if upper.count > limits.max_count {
            return Err(ReduceError::CountLimit {
                needed: upper.count,
                limit: limits.max_count,
            });
        }
        if operation == Operation::SpanSum && upper.span_sum > limits.max_span_sum {
            return Err(ReduceError::SpanSumLimit {
                needed: upper.span_sum,
                limit: limits.max_span_sum,
            });
        }
        enforce_reduce(upper.work, limits.max_work, ReduceResource::Work)?;
        enforce_reduce(
            upper.scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(
            upper.peak_bytes,
            limits.max_peak_bytes,
            ReduceResource::Peak,
        )?;
        Ok(upper)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the monotone literal streams, maximal-run validation, and cumulative exact counters are kept adjacent"
    )]
    fn execute(
        &self,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut actual = ReduceActualCounters {
            input_bytes: upper.input_bytes,
            work: REDUCE_FIXED_WORK,
            ..ReduceActualCounters::default()
        };
        let mut cursors = [window.start(); MAX_LITERALS];
        let mut cached = [None::<usize>; MAX_LITERALS];
        let mut exhausted = [false; MAX_LITERALS];

        loop {
            for (index, finder) in self.finders.iter().enumerate() {
                if cached[index].is_some() || exhausted[index] {
                    continue;
                }
                let cursor = cursors[index].max(window.start());
                let remaining =
                    window
                        .end()
                        .checked_sub(cursor)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "outer finder remaining bytes",
                        })?;
                if remaining < finder.needle().len() {
                    exhausted[index] = true;
                    continue;
                }
                let search =
                    haystack
                        .get(cursor..window.end())
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "outer finder search window",
                        })?;
                let relative = find_and_charge(finder, search, false, &mut actual)?;
                if let Some(relative) = relative {
                    let absolute =
                        cursor
                            .checked_add(relative)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "outer finder absolute candidate",
                            })?;
                    cached[index] = Some(absolute);
                    cursors[index] =
                        absolute
                            .checked_add(1)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "overlapping outer finder progress",
                            })?;
                    actual.outer_candidates =
                        checked_add_reduce(actual.outer_candidates, 1, "outer candidate count")?;
                } else {
                    exhausted[index] = true;
                }
            }

            let Some((candidate_index, candidate_start)) = cached
                .iter()
                .take(self.finders.len())
                .enumerate()
                .filter_map(|(index, candidate)| candidate.map(|start| (index, start)))
                .min_by_key(|&(index, start)| (start, index))
            else {
                break;
            };
            let candidate_end = candidate_start
                .checked_add(self.finders[candidate_index].needle().len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate literal end",
                })?;
            let run_start =
                self.scan_run_backward(haystack, window.start(), candidate_start, &mut actual)?;
            let run_end =
                self.scan_run_forward(haystack, candidate_end, window.end(), &mut actual)?;
            actual.run_events = checked_add_reduce(actual.run_events, 1, "candidate run count")?;
            actual.work = checked_add_reduce(actual.work, RUN_WORK, "candidate run work")?;

            let interior_start =
                run_start
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "strict run interior start",
                    })?;
            let mut matched = false;
            if interior_start < run_end {
                for finder in &self.finders {
                    let remaining = run_end.checked_sub(interior_start).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "strict run interior bytes",
                        },
                    )?;
                    if remaining < finder.needle().len() {
                        continue;
                    }
                    let search = haystack.get(interior_start..run_end).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "strict interior finder window",
                        },
                    )?;
                    if let Some(relative) = find_and_charge(finder, search, true, &mut actual)? {
                        actual.inner_candidates = checked_add_reduce(
                            actual.inner_candidates,
                            1,
                            "inner literal candidate count",
                        )?;
                        let start = interior_start.checked_add(relative).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "inner literal absolute start",
                            },
                        )?;
                        let end = start.checked_add(finder.needle().len()).ok_or(
                            ReduceError::ArithmeticOverflow {
                                computation: "inner literal absolute end",
                            },
                        )?;
                        if end < run_end {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if matched {
                actual.match_events =
                    checked_add_reduce(actual.match_events, 1, "match event count")?;
                actual.count =
                    actual
                        .count
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "match count",
                        })?;
                if operation == Operation::SpanSum {
                    let width =
                        run_end
                            .checked_sub(run_start)
                            .ok_or(ReduceError::ArithmeticOverflow {
                                computation: "matched run width",
                            })?;
                    actual.span_sum = actual
                        .span_sum
                        .checked_add(u64::try_from(width).map_err(|_| {
                            ReduceError::ArithmeticOverflow {
                                computation: "matched run width as u64",
                            }
                        })?)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "matched byte sum",
                        })?;
                }
                actual.work = checked_add_reduce(actual.work, MATCH_WORK, "match work")?;
            }

            for index in 0..self.finders.len() {
                let discarded = cached[index].is_some_and(|start| start < run_end);
                if discarded {
                    cached[index] = None;
                }
                cursors[index] = cursors[index].max(run_end);
                if discarded && cursors[index] < window.end() {
                    exhausted[index] = false;
                }
            }
        }

        actual.finder_calls = actual
            .outer_finder_calls
            .checked_add(actual.inner_finder_calls)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "total finder calls",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    fn scan_run_backward(
        &self,
        haystack: &[u8],
        floor: usize,
        mut end: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<usize, ReduceError> {
        while end > floor {
            let decoded = decode_previous_scalar(haystack, floor, end)?;
            charge_decode(decoded.byte_checks, actual)?;
            let Some(scalar) = decoded.scalar else {
                break;
            };
            if !self.contains(scalar, actual)? {
                break;
            }
            end = end
                .checked_sub(decoded.width)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "reverse scalar progress",
                })?;
        }
        Ok(end)
    }

    fn scan_run_forward(
        &self,
        haystack: &[u8],
        mut start: usize,
        ceiling: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<usize, ReduceError> {
        while start < ceiling {
            let bytes = haystack
                .get(start..ceiling)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "forward scalar decode window",
                })?;
            let decoded = decode_scalar(bytes);
            charge_decode(decoded.byte_checks, actual)?;
            let Some(scalar) = decoded.scalar else {
                break;
            };
            if !self.contains(scalar, actual)? {
                break;
            }
            start = start
                .checked_add(decoded.width)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "forward scalar progress",
                })?;
        }
        Ok(start)
    }

    fn contains(
        &self,
        scalar: u32,
        actual: &mut ReduceActualCounters,
    ) -> Result<bool, ReduceError> {
        actual.membership_tests =
            checked_add_reduce(actual.membership_tests, 1, "membership tests")?;
        actual.work = checked_add_reduce(actual.work, MEMBERSHIP_WORK, "membership work")?;
        if scalar <= 0x7F {
            actual.range_comparisons =
                checked_add_reduce(actual.range_comparisons, 1, "ASCII membership comparison")?;
            return Ok(ascii_contains(
                self.ascii,
                u8::try_from(scalar).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "ASCII scalar conversion",
                })?,
            ));
        }
        let mut low = 0_usize;
        let mut high = self.non_ascii.len();
        while low < high {
            actual.range_comparisons =
                checked_add_reduce(actual.range_comparisons, 1, "range comparisons")?;
            let middle = low + (high - low) / 2;
            let range = self.non_ascii[middle];
            if scalar < range.start {
                high = middle;
            } else if scalar > range.end {
                low = middle
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "range binary-search progress",
                    })?;
            } else {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Copy)]
enum BuildResource {
    SourceRanges,
    Work,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(needed: usize, limit: usize, resource: BuildResource) -> Result<(), BuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::SourceRanges => BuildError::SourceRangesLimit { needed, limit },
        BuildResource::Work => BuildError::WorkLimit { needed, limit },
        BuildResource::Scratch => BuildError::ScratchLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

#[derive(Clone, Copy)]
enum ReduceResource {
    InputBytes,
    FinderCalls,
    FinderScannedBytes,
    DecodeByteChecks,
    MembershipTests,
    RangeComparisons,
    RunEvents,
    MatchEvents,
    Work,
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
        ReduceResource::InputBytes => ReduceError::InputBytesLimit { needed, limit },
        ReduceResource::FinderCalls => ReduceError::FinderCallsLimit { needed, limit },
        ReduceResource::FinderScannedBytes => {
            ReduceError::FinderScannedBytesLimit { needed, limit }
        }
        ReduceResource::DecodeByteChecks => ReduceError::DecodeByteChecksLimit { needed, limit },
        ReduceResource::MembershipTests => ReduceError::MembershipTestsLimit { needed, limit },
        ReduceResource::RangeComparisons => ReduceError::RangeComparisonsLimit { needed, limit },
        ReduceResource::RunEvents => ReduceError::RunEventsLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the source-free proof keeps every named resource term in one auditable derivation"
)]
fn derive_upper_bounds(
    build: BuildAccounting,
    finders: &[Finder<'static>],
    input_bytes: usize,
) -> Result<ReduceUpperBounds, ReduceError> {
    let mut literal_occurrence_positions = 0_usize;
    let mut outer_finder_calls = 0_usize;
    let mut outer_finder_scanned_bytes = 0_usize;
    for finder in finders {
        let literal_bytes = finder.needle().len();
        let positions = input_bytes
            .checked_sub(literal_bytes)
            .map_or(0, |remaining| remaining.saturating_add(1));
        literal_occurrence_positions = checked_add_reduce(
            literal_occurrence_positions,
            positions,
            "literal occurrence positions",
        )?;
        outer_finder_calls = checked_add_reduce(
            outer_finder_calls,
            positions.saturating_add(1),
            "outer finder calls",
        )?;
        let overlap_service = positions
            .checked_mul(literal_bytes.saturating_sub(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "outer overlapping finder service",
            })?;
        outer_finder_scanned_bytes = outer_finder_scanned_bytes
            .checked_add(input_bytes)
            .and_then(|value| value.checked_add(overlap_service))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "outer finder scanned bytes",
            })?;
    }
    let run_events = literal_occurrence_positions.min(input_bytes);
    let inner_finder_calls =
        run_events
            .checked_mul(finders.len())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "inner finder calls",
            })?;
    let finder_calls = outer_finder_calls.checked_add(inner_finder_calls).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "total finder calls",
        },
    )?;
    // Candidate maximal runs are disjoint. Each literal's strict-interior
    // searches therefore cover at most N bytes in total.
    let inner_finder_scanned_bytes =
        input_bytes
            .checked_mul(finders.len())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "inner finder scanned bytes",
            })?;
    let finder_scanned_bytes = outer_finder_scanned_bytes
        .checked_add(inner_finder_scanned_bytes)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "total finder scanned bytes",
        })?;
    // Reverse decoding may inspect a lead/continuation sequence twice while
    // validating it. Eight byte checks per source byte safely covers both
    // directions, malformed prefixes, and the fixed literal holes.
    let decode_byte_checks =
        input_bytes
            .checked_mul(16)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "decode byte-check bound",
            })?;
    // A nonmember scalar can terminate candidate runs on both sides. Member
    // scalars belong to one disjoint run, so two tests per input byte is a
    // complete source-independent bound.
    let membership_tests = input_bytes
        .checked_mul(2)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "membership-test bound",
        })?;
    let comparisons_per_membership =
        binary_search_comparison_bound(build.retained_non_ascii_ranges).max(1);
    let range_comparisons = membership_tests
        .checked_mul(comparisons_per_membership)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "range-comparison bound",
        })?;
    let match_events = run_events;
    let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "count upper bound as u64",
    })?;
    let span_sum = u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "span-sum upper bound as u64",
    })?;
    let work = REDUCE_FIXED_WORK
        .checked_add(finder_scanned_bytes)
        .and_then(|value| value.checked_add(finder_calls.checked_mul(FINDER_CALL_WORK)?))
        .and_then(|value| value.checked_add(decode_byte_checks))
        .and_then(|value| value.checked_add(membership_tests.checked_mul(MEMBERSHIP_WORK)?))
        .and_then(|value| value.checked_add(range_comparisons))
        .and_then(|value| value.checked_add(run_events.checked_mul(RUN_WORK)?))
        .and_then(|value| value.checked_add(match_events.checked_mul(MATCH_WORK)?))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "total reduction work",
        })?;
    Ok(ReduceUpperBounds {
        input_bytes,
        literal_occurrence_positions,
        outer_finder_calls,
        inner_finder_calls,
        finder_calls,
        finder_scanned_bytes,
        decode_byte_checks,
        membership_tests,
        range_comparisons,
        run_events,
        match_events,
        count,
        span_sum,
        work,
        scratch_bytes: 0,
        persistent_bytes: build.persistent_bytes,
        peak_bytes: build.persistent_bytes,
    })
}

fn find_and_charge(
    finder: &Finder<'_>,
    search: &[u8],
    inner: bool,
    actual: &mut ReduceActualCounters,
) -> Result<Option<usize>, ReduceError> {
    if inner {
        actual.inner_finder_calls =
            checked_add_reduce(actual.inner_finder_calls, 1, "inner finder calls")?;
    } else {
        actual.outer_finder_calls =
            checked_add_reduce(actual.outer_finder_calls, 1, "outer finder calls")?;
    }
    actual.work = checked_add_reduce(actual.work, FINDER_CALL_WORK, "finder call work")?;
    let found = finder.find(search);
    let service =
        match found {
            Some(relative) => relative.checked_add(finder.needle().len()).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "successful finder service",
                },
            )?,
            None => search.len(),
        };
    actual.finder_scanned_bytes =
        checked_add_reduce(actual.finder_scanned_bytes, service, "finder scanned bytes")?;
    actual.work = checked_add_reduce(actual.work, service, "finder scanned work")?;
    Ok(found)
}

fn charge_decode(byte_checks: usize, actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.decode_byte_checks =
        checked_add_reduce(actual.decode_byte_checks, byte_checks, "decode byte checks")?;
    actual.work = checked_add_reduce(actual.work, byte_checks, "decode work")?;
    Ok(())
}

fn verify_actual(
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(), ReduceError> {
    verify("input bytes", actual.input_bytes, upper.input_bytes)?;
    verify(
        "outer finder calls",
        actual.outer_finder_calls,
        upper.outer_finder_calls,
    )?;
    verify(
        "inner finder calls",
        actual.inner_finder_calls,
        upper.inner_finder_calls,
    )?;
    verify("finder calls", actual.finder_calls, upper.finder_calls)?;
    verify(
        "finder scanned bytes",
        actual.finder_scanned_bytes,
        upper.finder_scanned_bytes,
    )?;
    verify(
        "decode byte checks",
        actual.decode_byte_checks,
        upper.decode_byte_checks,
    )?;
    verify(
        "membership tests",
        actual.membership_tests,
        upper.membership_tests,
    )?;
    verify(
        "range comparisons",
        actual.range_comparisons,
        upper.range_comparisons,
    )?;
    verify("run events", actual.run_events, upper.run_events)?;
    verify("match events", actual.match_events, upper.match_events)?;
    verify("count", actual.count, upper.count)?;
    verify("span sum", actual.span_sum, upper.span_sum)?;
    verify("work", actual.work, upper.work)?;
    verify("scratch bytes", actual.scratch_bytes, upper.scratch_bytes)
}

fn verify<T>(resource: &'static str, actual: T, upper: T) -> Result<(), ReduceError>
where
    T: Copy + Ord + TryInto<u64>,
{
    if actual <= upper {
        return Ok(());
    }
    Err(ReduceError::AccountingInvariant {
        resource,
        actual: actual
            .try_into()
            .map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "actual accounting value as u64",
            })?,
        upper: upper
            .try_into()
            .map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "upper accounting value as u64",
            })?,
    })
}

fn record_allocation(
    actual: &mut DirectBuildAttemptActual,
    bytes: usize,
) -> Result<(), BuildError> {
    if bytes == 0 {
        return Ok(());
    }
    actual.allocations =
        actual
            .allocations
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual allocation count",
            })?;
    actual.allocated_bytes =
        actual
            .allocated_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual allocated bytes",
            })?;
    actual.live_persistent_bytes =
        actual
            .live_persistent_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual live persistent bytes",
            })?;
    actual.peak_bytes = actual.peak_bytes.max(actual.live_persistent_bytes);
    Ok(())
}

fn record_initialization(
    actual: &mut DirectBuildAttemptActual,
    bytes: usize,
    copied: bool,
) -> Result<(), BuildError> {
    actual.initialized_bytes =
        actual
            .initialized_bytes
            .checked_add(bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual initialized bytes",
            })?;
    if copied {
        actual.copied_bytes =
            actual
                .copied_bytes
                .checked_add(bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual copied bytes",
                })?;
    }
    Ok(())
}

fn allocation_error(structure: &'static str, bytes: usize, _error: CopyError) -> BuildError {
    BuildError::AllocationFailed { structure, bytes }
}

fn insert_ascii_range(words: &mut [u64; 2], start: u32, end: u32) -> Result<(), BuildError> {
    let first = usize::try_from(start / 64).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "ASCII range first word",
    })?;
    let last = usize::try_from(end / 64).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "ASCII range last word",
    })?;
    for (word, target) in words
        .iter_mut()
        .enumerate()
        .take(last.saturating_add(1))
        .skip(first)
    {
        let low = if word == first { start & 63 } else { 0 };
        let high = if word == last { end & 63 } else { 63 };
        *target |= (u64::MAX << low) & (u64::MAX >> (63 - high));
    }
    Ok(())
}

fn ascii_contains(words: [u64; 2], byte: u8) -> bool {
    let word = usize::from(byte) >> 6;
    let bit = u32::from(byte) & 63;
    words[word] & (1_u64 << bit) != 0
}

fn checked_add_build(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, BuildError> {
    left.checked_add(right)
        .ok_or(BuildError::ArithmeticOverflow { computation })
}

fn checked_add_reduce(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
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

fn decode_previous_scalar(
    haystack: &[u8],
    floor: usize,
    end: usize,
) -> Result<DecodedScalar, ReduceError> {
    let last = end.checked_sub(1).ok_or(ReduceError::ArithmeticOverflow {
        computation: "previous scalar final byte",
    })?;
    let last_byte = *haystack.get(last).ok_or(ReduceError::ArithmeticOverflow {
        computation: "previous scalar final-byte read",
    })?;
    if last_byte <= 0x7F {
        return Ok(DecodedScalar {
            scalar: Some(u32::from(last_byte)),
            width: 1,
            byte_checks: 1,
        });
    }
    if !is_continuation(last_byte) {
        return Ok(invalid_scalar(1));
    }

    let minimum = end.saturating_sub(4).max(floor);
    let mut lead = last;
    let mut prefix_checks = 1_usize;
    while lead > minimum {
        lead = lead.checked_sub(1).ok_or(ReduceError::ArithmeticOverflow {
            computation: "previous scalar lead search",
        })?;
        prefix_checks = checked_add_reduce(prefix_checks, 1, "reverse lead byte checks")?;
        let byte = *haystack.get(lead).ok_or(ReduceError::ArithmeticOverflow {
            computation: "previous scalar lead-byte read",
        })?;
        if is_continuation(byte) {
            continue;
        }
        let bytes = haystack
            .get(lead..end)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "previous scalar candidate window",
            })?;
        let decoded = decode_scalar(bytes);
        let byte_checks = prefix_checks.checked_add(decoded.byte_checks).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "reverse scalar byte checks",
            },
        )?;
        if decoded.scalar.is_some() && decoded.width == bytes.len() {
            return Ok(DecodedScalar {
                byte_checks,
                ..decoded
            });
        }
        return Ok(invalid_scalar(byte_checks));
    }
    Ok(invalid_scalar(prefix_checks))
}

fn decode_scalar(bytes: &[u8]) -> DecodedScalar {
    let Some(&first) = bytes.first() else {
        return invalid_scalar(0);
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
            return invalid_scalar(bytes.len().min(2));
        };
        if !is_continuation(second) {
            return invalid_scalar(2);
        }
        return DecodedScalar {
            scalar: Some((u32::from(first & 0x1F) << 6) | u32::from(second & 0x3F)),
            width: 2,
            byte_checks: 2,
        };
    }
    if (0xE0..=0xEF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid_scalar(bytes.len().min(3));
        };
        let second_ok = match first {
            0xE0 => (0xA0..=0xBF).contains(&second),
            0xED => (0x80..=0x9F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid_scalar(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid_scalar(bytes.len().min(3));
        };
        if !is_continuation(third) {
            return invalid_scalar(3);
        }
        return DecodedScalar {
            scalar: Some(
                (u32::from(first & 0x0F) << 12)
                    | (u32::from(second & 0x3F) << 6)
                    | u32::from(third & 0x3F),
            ),
            width: 3,
            byte_checks: 3,
        };
    }
    if (0xF0..=0xF4).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid_scalar(bytes.len().min(4));
        };
        let second_ok = match first {
            0xF0 => (0x90..=0xBF).contains(&second),
            0xF4 => (0x80..=0x8F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid_scalar(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid_scalar(bytes.len().min(4));
        };
        if !is_continuation(third) {
            return invalid_scalar(3);
        }
        let Some(&fourth) = bytes.get(3) else {
            return invalid_scalar(bytes.len().min(4));
        };
        if !is_continuation(fourth) {
            return invalid_scalar(4);
        }
        return DecodedScalar {
            scalar: Some(
                (u32::from(first & 0x07) << 18)
                    | (u32::from(second & 0x3F) << 12)
                    | (u32::from(third & 0x3F) << 6)
                    | u32::from(fourth & 0x3F),
            ),
            width: 4,
            byte_checks: 4,
        };
    }
    invalid_scalar(1)
}

const fn invalid_scalar(byte_checks: usize) -> DecodedScalar {
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
    use regex::bytes::{Regex, RegexBuilder};

    use super::{
        BuildError, BuildLimits, COUNT_OPERATION_ID, ReduceError, ReduceLimits, ReverseInnerPlan,
        SPAN_SUM_OPERATION_ID,
    };
    use crate::Window;

    const ASCII_LETTERS: [(char, char); 2] = [('A', 'Z'), ('a', 'z')];
    const SMALL_CLASS: [(char, char); 2] = [('a', 'b'), ('λ', 'λ')];
    const SMALL_LITERALS: [&[u8]; 2] = [b"aa", b"b"];
    const SMALL_PATTERN: &str = r"(?:[abλ]+aa[abλ]+|[abλ]+b[abλ]+)";

    fn plan(ranges: &[(char, char)], literals: &[&[u8]]) -> ReverseInnerPlan {
        ReverseInnerPlan::build(ranges.iter().copied(), literals, BuildLimits::unlimited())
            .expect("eligible reverse-inner plan")
    }

    fn oracle(pattern: &str) -> Regex {
        RegexBuilder::new(pattern)
            .unicode(true)
            .build()
            .expect("oracle regex")
    }

    fn oracle_aggregates(regex: &Regex, haystack: &[u8]) -> (u64, u64) {
        regex
            .find_iter(haystack)
            .fold((0_u64, 0_u64), |(count, sum), matched| {
                (
                    count.checked_add(1).expect("small oracle count"),
                    sum.checked_add(
                        u64::try_from(matched.end() - matched.start()).expect("small oracle width"),
                    )
                    .expect("small oracle sum"),
                )
            })
    }

    fn assert_matches_oracle(plan: &ReverseInnerPlan, regex: &Regex, haystack: &[u8]) {
        let expected = oracle_aggregates(regex, haystack);
        let count = plan
            .count(haystack, ReduceLimits::unlimited())
            .expect("count reduction");
        let span_sum = plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .expect("span-sum reduction");
        assert_eq!(
            (count.count, span_sum.span_sum),
            expected,
            "haystack={haystack:?}"
        );
        assert_eq!(count.accounting.identity.operation_id, COUNT_OPERATION_ID);
        assert_eq!(
            span_sum.accounting.identity.operation_id,
            SPAN_SUM_OPERATION_ID
        );
    }

    #[test]
    fn overlap_complete_strict_interior_and_near_misses() {
        let plan = plan(&[('a', 'a')], &[b"aa"]);
        let regex = oracle(r"a+aaa+");
        for haystack in [
            b"".as_slice(),
            b"a",
            b"aa",
            b"aaa",
            b"aaaa",
            b"aaaaa",
            b"xaaaax",
            b"aaaxaaaa",
            b"aaaa\xffaaaa",
        ] {
            assert_matches_oracle(&plan, &regex, haystack);
        }
        let accepted = plan
            .span_sum(b"aaaa", ReduceLimits::unlimited())
            .expect("overlapping interior candidate");
        assert_eq!(accepted.span_sum, 4);
        assert_eq!(accepted.accounting.actual.match_events, 1);
    }

    #[test]
    fn factored_tom_shape_matches_maximal_letter_runs() {
        let plan = plan(&ASCII_LETTERS, &[b"herloc", b"olme"]);
        let regex = oracle(r"(?:[A-Za-z]+herloc[A-Za-z]+|[A-Za-z]+olme[A-Za-z]+)");
        for haystack in [
            b"sherlock holmes".as_slice(),
            b"herlocx xherloc xherlocy",
            b"olmes xolme xolmey",
            b"sherlock\xffholmes",
            b"--sherlock--holmes--",
            b"sherloc holme",
        ] {
            assert_matches_oracle(&plan, &regex, haystack);
        }
    }

    #[test]
    fn exhaustive_small_token_language_matches_regex_oracle() {
        fn visit(
            depth: usize,
            maximum: usize,
            tokens: &[&[u8]],
            haystack: &mut Vec<u8>,
            plan: &ReverseInnerPlan,
            regex: &Regex,
        ) {
            assert_matches_oracle(plan, regex, haystack);
            if depth == maximum {
                return;
            }
            for token in tokens {
                let old_len = haystack.len();
                haystack.extend_from_slice(token);
                visit(depth + 1, maximum, tokens, haystack, plan, regex);
                haystack.truncate(old_len);
            }
        }

        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let regex = oracle(SMALL_PATTERN);
        let tokens: [&[u8]; 5] = [b"a", b"b", b"x", "λ".as_bytes(), b"\xff"];
        let mut haystack = Vec::new();
        visit(0, 6, &tokens, &mut haystack, &plan, &regex);
    }

    #[test]
    fn deterministic_random_bytes_match_regex_oracle() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let regex = oracle(SMALL_PATTERN);
        let tokens: [&[u8]; 8] = [
            b"a",
            b"b",
            b"x",
            b"-",
            "λ".as_bytes(),
            "β".as_bytes(),
            b"\xff",
            b"\x80",
        ];
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        for case in 0..4_096_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let token_count = usize::try_from(state & 63).expect("small token count");
            let mut haystack = Vec::new();
            for _ in 0..token_count {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let index =
                    usize::try_from(state % u64::try_from(tokens.len()).expect("small token set"))
                        .expect("small token index");
                haystack.extend_from_slice(tokens[index]);
            }
            let expected = oracle_aggregates(&regex, &haystack);
            let count = plan
                .count(&haystack, ReduceLimits::unlimited())
                .unwrap_or_else(|error| panic!("case {case} count failed: {error:?}"));
            let sum = plan
                .span_sum(&haystack, ReduceLimits::unlimited())
                .unwrap_or_else(|error| panic!("case {case} sum failed: {error:?}"));
            assert_eq!(
                (count.count, sum.span_sum),
                expected,
                "case={case} haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn byte_windows_include_split_utf8_and_invalid_boundaries() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let regex = oracle(SMALL_PATTERN);
        let haystack = b"\xff\x80\xce\xbbaab\xce\xbbxbaaab\xce\xbb\xff";
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let expected = oracle_aggregates(&regex, &haystack[start..end]);
                let window = Window::new(start, end);
                let count = plan
                    .count_in(haystack, window, ReduceLimits::unlimited())
                    .expect("window count");
                let sum = plan
                    .span_sum_in(haystack, window, ReduceLimits::unlimited())
                    .expect("window span sum");
                assert_eq!(
                    (count.count, sum.span_sum),
                    expected,
                    "window={start}..{end}"
                );
            }
        }
        assert!(matches!(
            plan.count_in(
                haystack,
                Window::new(2, haystack.len() + 1),
                ReduceLimits::unlimited()
            ),
            Err(ReduceError::InvalidWindow { .. })
        ));
    }

    #[test]
    fn invalid_utf8_is_a_nonmember_barrier() {
        let ranges = [('A', 'Z'), ('a', 'z'), ('λ', 'λ')];
        let plan = plan(&ranges, &[b"herloc"]);
        let regex = oracle(r"[A-Za-zλ]+herloc[A-Za-zλ]+");
        for haystack in [
            b"\xffsherlock\x80".as_slice(),
            b"sher\xfflock",
            b"\xf0\x80\x80\x80sherlock",
            b"\xed\xa0\x80sherlock\xce\xbb",
            b"\xce\xbbsherlock\xce\xbb",
            b"\xce\x80sherlock",
            b"sherlock\xce",
        ] {
            assert_matches_oracle(&plan, &regex, haystack);
        }
    }

    #[test]
    fn build_receipt_exact_limits_and_one_below() {
        let literals: [&[u8]; 2] = [b"herloc", b"olme"];
        let baseline = ReverseInnerPlan::build_attempt(
            ASCII_LETTERS.iter().copied(),
            &literals,
            BuildLimits::unlimited(),
        )
        .expect("baseline build");
        let build = baseline.into_plan().build_accounting();
        let exact = BuildLimits {
            max_source_ranges: build.source_ranges,
            max_literals: build.literal_count,
            max_literal_bytes: 6,
            max_total_literal_bytes: build.literal_bytes,
            max_build_work: build.work,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        };
        let attempt =
            ReverseInnerPlan::build_attempt(ASCII_LETTERS.iter().copied(), &literals, exact)
                .expect("exact-limit build");
        let (plan, actual) = attempt.into_parts();
        assert_eq!(plan.build_accounting(), build);
        assert_eq!(actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(actual.allocations, build.allocations);
        assert_eq!(actual.allocated_bytes, build.allocated_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.peak_bytes);

        let work_error = ReverseInnerPlan::build_attempt(
            ASCII_LETTERS.iter().copied(),
            &literals,
            BuildLimits {
                max_build_work: build.work - 1,
                ..exact
            },
        )
        .expect_err("one-below work must fail");
        assert_eq!(
            work_error.source(),
            &BuildError::WorkLimit {
                needed: build.work,
                limit: build.work - 1
            }
        );
        assert_eq!(work_error.actual().work, u64::try_from(build.work).unwrap());
        assert_eq!(work_error.actual().allocations, 0);

        assert!(matches!(
            ReverseInnerPlan::build(
                ASCII_LETTERS.iter().copied(),
                &literals,
                BuildLimits {
                    max_persistent_bytes: build.persistent_bytes - 1,
                    ..exact
                }
            ),
            Err(BuildError::PersistentLimit { .. })
        ));
    }

    fn exact_reduce_limits(upper: super::ReduceUpperBounds) -> ReduceLimits {
        ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_finder_calls: upper.finder_calls,
            max_finder_scanned_bytes: upper.finder_scanned_bytes,
            max_decode_byte_checks: upper.decode_byte_checks,
            max_membership_tests: upper.membership_tests,
            max_range_comparisons: upper.range_comparisons,
            max_run_events: upper.run_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    #[test]
    fn reduce_receipt_exact_limits_and_one_below() {
        let plan = plan(&SMALL_CLASS, &SMALL_LITERALS);
        let haystack = b"\xff\xce\xbbaaab\xce\xbb-xbaaabx-\x80aaaa";
        let upper = plan
            .full_window_upper_bounds(haystack.len())
            .expect("full-window bounds");
        let exact = exact_reduce_limits(upper);
        let count = plan.count(haystack, exact).expect("exact-limit count");
        let sum = plan
            .span_sum(haystack, exact)
            .expect("exact-limit span sum");
        let expected = oracle_aggregates(&oracle(SMALL_PATTERN), haystack);
        assert_eq!((count.count, sum.span_sum), expected);
        assert_eq!(count.accounting.upper_bounds, upper);
        assert_eq!(sum.accounting.upper_bounds, upper);

        assert!(matches!(
            plan.count(
                haystack,
                ReduceLimits {
                    max_finder_calls: upper.finder_calls - 1,
                    ..exact
                }
            ),
            Err(ReduceError::FinderCallsLimit { .. })
        ));
        assert!(matches!(
            plan.span_sum(
                haystack,
                ReduceLimits {
                    max_work: upper.work - 1,
                    ..exact
                }
            ),
            Err(ReduceError::WorkLimit { .. })
        ));
    }

    #[test]
    fn construction_refuses_unsound_shapes() {
        assert!(matches!(
            ReverseInnerPlan::build(
                core::iter::empty::<(char, char)>(),
                &[b"a"],
                BuildLimits::unlimited()
            ),
            Err(BuildError::EmptyClass)
        ));
        assert!(matches!(
            ReverseInnerPlan::build([('a', 'z')].into_iter(), &[], BuildLimits::unlimited()),
            Err(BuildError::EmptyLiteralSet)
        ));
        assert!(matches!(
            ReverseInnerPlan::build([('a', 'z')].into_iter(), &[b""], BuildLimits::unlimited()),
            Err(BuildError::EmptyLiteral { .. })
        ));
        assert!(matches!(
            ReverseInnerPlan::build(
                [('a', 'z')].into_iter(),
                &["λ".as_bytes()],
                BuildLimits::unlimited()
            ),
            Err(BuildError::NonAsciiLiteral { .. })
        ));
        assert!(matches!(
            ReverseInnerPlan::build([('a', 'z')].into_iter(), &[b"A"], BuildLimits::unlimited()),
            Err(BuildError::LiteralScalarOutsideClass { .. })
        ));
        assert!(matches!(
            ReverseInnerPlan::build(
                [('a', 'z'), ('z', 'λ')].into_iter(),
                &[b"a"],
                BuildLimits::unlimited()
            ),
            Err(BuildError::NonCanonicalRanges)
        ));
    }
}
