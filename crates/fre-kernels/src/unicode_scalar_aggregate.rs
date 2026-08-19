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

use fre_exact_alloc::{CopyError, ExactBoxOrUsize};
use memchr::{memchr, memchr2, memchr3};
use fre_simd_kernels::{
    ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier, AsciiSelection, DispatchPolicy,
    BYTE_SET_CLASSIFIER_BUILD_WORK, BYTE_SET_WIDE_BLOCK_BYTES, ByteSet256, ByteSetClassifier,
    Feature, FeatureSet, SimdDispatchContext,
};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError, Window};

/// Stable identity for the scalar-stream implementation.
pub const PLAN_ID: &str = "unicode-scalar-aggregate.ascii-runs-utf8-stream-ranges.v2";
/// Stable identity for the SVE2-gated fixed-32 ASCII block owner.
pub const DISPATCHED_PLAN_ID: &str =
    "unicode-scalar-aggregate.ascii-block32.sve2-only-utf8-fallback.v1";
/// Stable identity for the deterministic nonempty run reducer.
pub const RUN_PLAN_ID: &str = "unicode-scalar-aggregate.ascii-runs-utf8-stream-ranges.run-plus.v2";
/// Stable identity for direct selected-span search over one positive root
/// Unicode scalar-class repetition.
pub const SEARCH_PLAN_ID: &str = "unicode-scalar-run-search.leading-byte-cardinality-ranges.v4";
/// Stable identity for selected-span search.
pub const SEARCH_OPERATION_ID: &str = "unicode-scalar-run-search.selected-span.v1";
/// Stable identity for existence search.
pub const SEARCH_EXISTS_OPERATION_ID: &str = "unicode-scalar-run-search.exists.v1";
/// Stable identity for earliest-end search.
pub const SEARCH_EARLIEST_END_OPERATION_ID: &str = "unicode-scalar-run-search.earliest-end.v1";
/// Stable identity for allocation-free Count over one retained leading-byte
/// cursor, with a generic dense-match cutover to the embedded scalar owner.
pub const CURSOR_COUNT_PLAN_ID: &str =
    "unicode-scalar-aggregate.leading-byte-cursor-dense-cutover.v1";
/// Stable identity for the cursor Count reduction.
pub const CURSOR_COUNT_OPERATION_ID: &str =
    "unicode-scalar-aggregate.count.leading-byte-cursor.v1";
/// Number of bytes that can begin a valid Unicode scalar: all 128 ASCII
/// bytes plus the 51 canonical multi-byte leads `0xC2..=0xF4`.
pub const LEGAL_SCALAR_START_BYTE_COUNT: usize = 179;
/// Construction-only selectivity ceiling for the Count cursor. At most half
/// of the legal scalar-start byte domain may enter the cursor; broader masks
/// retain the already-built scalar owner instead.
pub const CURSOR_COUNT_MAX_LEADING_BYTE_COUNT: usize =
    LEGAL_SCALAR_START_BYTE_COUNT / 2;
/// Exact byte-value probes used to select a sparse or fixed-table leading
/// search during construction.
pub const SEARCH_LEADING_SELECTION_WORK: usize = 256;
// `search_upper_bounds` can charge at most one scalar leading probe, one
// fixed-block byte, four decode checks, one membership test, one reducer step,
// and `usize::BITS + 1` range comparisons per input byte. A fixed block can
// round its physical byte count up by at most 31 bytes. Below this threshold,
// every checked upper-bound intermediate is therefore representable.
const SEARCH_VALUE_PREFLIGHT_BLOCK_SLOP: usize = BYTE_SET_WIDE_BLOCK_BYTES - 1;
const SEARCH_VALUE_PREFLIGHT_WORK_FACTOR: usize = size_of::<usize>() * 8 + 9;
const SEARCH_VALUE_PREFLIGHT_MAX_INPUT_BYTES: usize =
    (usize::MAX - SEARCH_VALUE_PREFLIGHT_BLOCK_SLOP) / SEARCH_VALUE_PREFLIGHT_WORK_FACTOR;
// One batch spans enough accepted matches to amortize the cursor setup while
// remaining small relative to the long sparse sources this route serves.
// A batch whose selected spans occupy at most one wide classification block
// per match is dense enough that the embedded scalar owner bounds subsequent
// per-match restart overhead more tightly. The decision depends only on the
// observed generic match stream and is one-way.
const CURSOR_COUNT_DENSE_SAMPLE_MATCHES: usize = 64;
const CURSOR_COUNT_DENSE_MAX_MEAN_BYTES: usize = BYTE_SET_WIDE_BLOCK_BYTES;
/// Stable identity for symbolic counted/lower-bounded repetition.
pub(crate) const REPEATED_RUN_PLAN_ID: &str =
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
pub(crate) const REPEATED_RUN_COUNT_OPERATION_ID: &str =
    "unicode-scalar-aggregate.count.run-counted.v1";
/// Stable identity for counted/lower-bounded matched-byte summation.
pub(crate) const REPEATED_RUN_SPAN_SUM_OPERATION_ID: &str =
    "unicode-scalar-aggregate.span-sum.run-counted.v1";

const SIMD_ASCII_CLASSIFIER_BUILD_WORK: usize = 128 + 2 + 2;

/// Complete reducer selected for one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    Count,
    SpanSum,
}

/// Physical ASCII classification implementation retained by the plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReduceImplementation {
    /// Scalar UTF-8 stream with bitmap membership.
    Scalar,
    /// Fixed-32 ASCII block classification with UTF-8 fallback.
    DispatchedAsciiBlock32,
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
    RepeatedGreedy { minimum: u32, maximum: Option<u32> },
    /// Lazy form of [`Repetition::RepeatedGreedy`].
    RepeatedLazy { minimum: u32, maximum: Option<u32> },
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

    /// Return the distinct fixed-32 exactly-one identity.
    #[must_use]
    pub const fn for_dispatched_operation(operation: Operation) -> Self {
        dispatched_identity(operation)
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
    /// Work used to compile the retained fixed-width ASCII classifier.
    pub ascii_classifier_build_work: usize,
    /// Initialized bytes occupied by the retained classifier value.
    pub ascii_classifier_bytes: usize,
    /// Exact dispatched-owner allocation, excluding its scalar range payload.
    pub dispatched_owner_bytes: usize,
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
    /// Maximum number of non-overlapping fixed-32 classifier invocations.
    pub ascii_block_classifications: usize,
    /// Maximum physical bytes presented to fixed-32 classifier invocations.
    pub ascii_block_classification_bytes: usize,
    /// Maximum speculative lanes classified beyond a consumed ASCII prefix.
    pub ascii_block_lookahead_bytes: usize,
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

/// Source-free admission for one prepared full-window Count operation.
///
/// Values of this type can only be produced by a Unicode scalar aggregate
/// plan. The private fields bind the admitted input length, implementation and
/// every immutable plan dimension that contributes to the reduction envelope.
/// A token from another resource shape therefore fails closed before source
/// access, while a token from an equivalent shape remains safe because Count
/// still executes the receiving plan's own scalar class and repetition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountAdmission {
    input_bytes: usize,
    implementation: ReduceImplementation,
    repetition: Repetition,
    retained_non_ascii_ranges: usize,
    persistent_bytes: usize,
    upper: ReduceUpperBounds,
}

impl CountAdmission {
    const fn new(
        input_bytes: usize,
        implementation: ReduceImplementation,
        build: BuildAccounting,
        upper: ReduceUpperBounds,
    ) -> Self {
        Self {
            input_bytes,
            implementation,
            repetition: build.repetition,
            retained_non_ascii_ranges: build.retained_non_ascii_ranges,
            persistent_bytes: build.persistent_bytes,
            upper,
        }
    }

    fn authenticates(
        self,
        haystack: &[u8],
        implementation: ReduceImplementation,
        build: BuildAccounting,
    ) -> bool {
        self.input_bytes == haystack.len()
            && self.implementation == implementation
            && self.repetition == build.repetition
            && self.retained_non_ascii_ranges == build.retained_non_ascii_ranges
            && self.persistent_bytes == build.persistent_bytes
    }
}

/// Exact structural counters after a complete successful traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes_advanced: usize,
    /// Exact number of non-overlapping fixed-32 classifier invocations.
    pub ascii_block_classifications: usize,
    /// Exact physical bytes presented to fixed-32 classifier invocations.
    pub ascii_block_classification_bytes: usize,
    /// Exact speculative lanes classified beyond a consumed ASCII prefix.
    pub ascii_block_lookahead_bytes: usize,
    pub decode_byte_checks: usize,
    pub valid_scalars: usize,
    pub invalid_bytes: usize,
    /// ASCII bytes consumed by maximal-run reduction before the general
    /// UTF-8 decoder. This is also the exact number of ASCII bitmap tests.
    pub ascii_run_bytes: usize,
    /// Logical ASCII member tests. Speculative fixed-block lanes are reported
    /// separately by `ascii_block_lookahead_bytes`.
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ValueReduction {
    count: u64,
    matched_bytes: u64,
}

trait ExecutionMeter: Sized {
    type Output;

    fn new() -> Self;

    fn update(
        &mut self,
        update: impl FnOnce(&mut ReduceActualCounters) -> Result<(), ReduceError>,
    ) -> Result<(), ReduceError>;

    fn finish_scalar(
        self,
        value: ValueReduction,
        input_bytes_advanced: usize,
        upper: ReduceUpperBounds,
    ) -> Result<Self::Output, ReduceError>;

    fn finish_dispatched(
        self,
        value: ValueReduction,
        input_bytes_advanced: usize,
        upper: ReduceUpperBounds,
    ) -> Result<Self::Output, ReduceError>;
}

struct FullExecutionMeter {
    actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Default)]
struct NoExecutionMeter;

/// Upper bounds and exact counters for one result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub window: Window,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

/// Derive the complete source-free reduction envelope for one implementation.
fn derive_reduce_upper_bounds(
    build: BuildAccounting,
    input_bytes: usize,
    implementation: ReduceImplementation,
) -> Result<ReduceUpperBounds, ReduceError> {
    let ascii_block_classifications = match implementation {
        ReduceImplementation::Scalar => 0,
        ReduceImplementation::DispatchedAsciiBlock32 => input_bytes / ASCII_WIDE_BYTES,
    };
    let ascii_block_classification_bytes = ascii_block_classifications
        .checked_mul(ASCII_WIDE_BYTES)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "ASCII block classification byte upper bound",
        })?;
    let ascii_block_lookahead_bytes = ascii_block_classification_bytes;
    let decode_byte_checks = input_bytes
        .checked_mul(4)
        .and_then(|checks| checks.checked_add(ascii_block_lookahead_bytes))
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "decode byte check upper bound",
        })?;
    let binary_search_comparisons_per_scalar =
        binary_search_comparison_bound(build.retained_non_ascii_ranges)
            .checked_add(
                usize::from(build.repetition.is_run() && build.retained_non_ascii_ranges != 0)
                    .checked_mul(2)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "cached range comparison allowance",
                    })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "cached range comparison upper bound",
            })?;
    let membership_tests = input_bytes.checked_add(ascii_block_lookahead_bytes).ok_or(
        ReduceError::ArithmeticOverflow {
            computation: "membership test upper bound",
        },
    )?;
    let range_comparisons = input_bytes
        .checked_mul(binary_search_comparisons_per_scalar)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "range comparison upper bound",
        })?;
    let reducer_steps = if build.repetition.is_run() {
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
    Ok(ReduceUpperBounds {
        input_bytes,
        ascii_block_classifications,
        ascii_block_classification_bytes,
        ascii_block_lookahead_bytes,
        decode_byte_checks,
        membership_tests,
        range_comparisons,
        binary_search_comparisons_per_scalar,
        reducer_steps,
        match_events,
        count,
        span_sum,
        work,
        scratch_bytes: 0,
        persistent_bytes: build.persistent_bytes,
        peak_bytes: build.persistent_bytes,
    })
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

const fn empty_actual_counters() -> ReduceActualCounters {
    ReduceActualCounters {
        input_bytes_advanced: 0,
        ascii_block_classifications: 0,
        ascii_block_classification_bytes: 0,
        ascii_block_lookahead_bytes: 0,
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
    }
}

impl ExecutionMeter for FullExecutionMeter {
    type Output = ReduceActualCounters;

    #[inline]
    fn new() -> Self {
        Self {
            actual: empty_actual_counters(),
        }
    }

    #[inline]
    fn update(
        &mut self,
        update: impl FnOnce(&mut ReduceActualCounters) -> Result<(), ReduceError>,
    ) -> Result<(), ReduceError> {
        update(&mut self.actual)
    }

    fn finish_scalar(
        mut self,
        value: ValueReduction,
        input_bytes_advanced: usize,
        upper: ReduceUpperBounds,
    ) -> Result<Self::Output, ReduceError> {
        self.actual.input_bytes_advanced = input_bytes_advanced;
        self.actual.count = value.count;
        self.actual.matched_bytes = value.matched_bytes;
        let membership_tests = self
            .actual
            .ascii_bitmap_tests
            .checked_add(self.actual.non_ascii_membership_tests)
            .and_then(|tests| tests.checked_add(self.actual.ascii_block_lookahead_bytes))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual membership tests",
            })?;
        self.actual.work = self
            .actual
            .decode_byte_checks
            .checked_add(membership_tests)
            .and_then(|work| work.checked_add(self.actual.range_comparisons))
            .and_then(|work| work.checked_add(self.actual.reducer_steps))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual execution work",
            })?;
        debug_assert!(self.actual.input_bytes_advanced <= upper.input_bytes);
        debug_assert!(self.actual.ascii_block_classifications <= upper.ascii_block_classifications);
        debug_assert!(
            self.actual.ascii_block_classification_bytes <= upper.ascii_block_classification_bytes
        );
        debug_assert!(self.actual.ascii_block_lookahead_bytes <= upper.ascii_block_lookahead_bytes);
        debug_assert!(self.actual.decode_byte_checks <= upper.decode_byte_checks);
        debug_assert_eq!(self.actual.ascii_run_bytes, self.actual.ascii_bitmap_tests);
        debug_assert!(membership_tests <= upper.membership_tests);
        debug_assert!(self.actual.range_comparisons <= upper.range_comparisons);
        debug_assert!(self.actual.reducer_steps <= upper.reducer_steps);
        debug_assert!(self.actual.match_events <= upper.match_events);
        debug_assert_eq!(
            u64::try_from(self.actual.match_events).ok(),
            Some(value.count)
        );
        debug_assert!(value.count <= upper.count);
        debug_assert!(value.matched_bytes <= upper.span_sum);
        debug_assert!(self.actual.work <= upper.work);
        Ok(self.actual)
    }

    fn finish_dispatched(
        mut self,
        value: ValueReduction,
        input_bytes_advanced: usize,
        upper: ReduceUpperBounds,
    ) -> Result<Self::Output, ReduceError> {
        self.actual.input_bytes_advanced = input_bytes_advanced;
        self.actual.count = value.count;
        self.actual.matched_bytes = value.matched_bytes;
        let membership_tests = self
            .actual
            .ascii_bitmap_tests
            .checked_add(self.actual.non_ascii_membership_tests)
            .and_then(|tests| tests.checked_add(self.actual.ascii_block_lookahead_bytes))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual dispatched membership tests",
            })?;
        self.actual.work = self
            .actual
            .decode_byte_checks
            .checked_add(membership_tests)
            .and_then(|work| work.checked_add(self.actual.range_comparisons))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual dispatched execution work",
            })?;
        debug_assert!(self.actual.input_bytes_advanced <= upper.input_bytes);
        debug_assert!(self.actual.ascii_block_classifications <= upper.ascii_block_classifications);
        debug_assert!(
            self.actual.ascii_block_classification_bytes <= upper.ascii_block_classification_bytes
        );
        debug_assert!(self.actual.ascii_block_lookahead_bytes <= upper.ascii_block_lookahead_bytes);
        debug_assert!(self.actual.decode_byte_checks <= upper.decode_byte_checks);
        debug_assert_eq!(self.actual.ascii_run_bytes, self.actual.ascii_bitmap_tests);
        debug_assert!(membership_tests <= upper.membership_tests);
        debug_assert!(self.actual.range_comparisons <= upper.range_comparisons);
        debug_assert_eq!(self.actual.reducer_steps, 0);
        debug_assert!(self.actual.match_events <= upper.match_events);
        debug_assert_eq!(
            u64::try_from(self.actual.match_events).ok(),
            Some(value.count)
        );
        debug_assert!(value.count <= upper.count);
        debug_assert!(value.matched_bytes <= upper.span_sum);
        debug_assert!(self.actual.work <= upper.work);
        Ok(self.actual)
    }
}

#[allow(
    clippy::inline_always,
    reason = "the zero-sized meter must disappear completely from each value-only specialization"
)]
impl ExecutionMeter for NoExecutionMeter {
    type Output = ValueReduction;

    #[inline(always)]
    fn new() -> Self {
        Self
    }

    #[inline(always)]
    fn update(
        &mut self,
        _update: impl FnOnce(&mut ReduceActualCounters) -> Result<(), ReduceError>,
    ) -> Result<(), ReduceError> {
        Ok(())
    }

    #[inline(always)]
    fn finish_scalar(
        self,
        value: ValueReduction,
        input_bytes_advanced: usize,
        upper: ReduceUpperBounds,
    ) -> Result<Self::Output, ReduceError> {
        debug_assert!(input_bytes_advanced <= upper.input_bytes);
        debug_assert!(value.count <= upper.count);
        debug_assert!(value.matched_bytes <= upper.span_sum);
        Ok(value)
    }

    #[inline(always)]
    fn finish_dispatched(
        self,
        value: ValueReduction,
        input_bytes_advanced: usize,
        upper: ReduceUpperBounds,
    ) -> Result<Self::Output, ReduceError> {
        debug_assert!(input_bytes_advanced <= upper.input_bytes);
        debug_assert!(value.count <= upper.count);
        debug_assert!(value.matched_bytes <= upper.span_sum);
        Ok(value)
    }
}

/// Checked construction failure. No partial plan is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass,
    /// The distinct fixed-32 owner requires an authentic OS-usable SVE2
    /// capability snapshot.
    AsciiClassifierDispatchUnavailable,
    InvalidRepetition {
        minimum: u32,
        maximum: Option<u32>,
    },
    ReversedRange {
        start: char,
        end: char,
    },
    NonCanonicalRanges,
    RangeLimit {
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
        additional: usize,
    },
    DispatchedOwnerAllocationFailed {
        bytes: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyClass => f.write_str("Unicode scalar plan needs a nonempty class"),
            Self::AsciiClassifierDispatchUnavailable => {
                f.write_str("Unicode scalar fixed-32 owner requires OS-usable SVE2")
            }
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
            Self::DispatchedOwnerAllocationFailed { bytes } => write!(
                f,
                "failed to allocate {bytes} bytes for the dispatched Unicode scalar owner"
            ),
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

/// SVE2-gated owner for exactly-one count and span-sum reduction.
///
/// The exact allocation retains the incumbent scalar proof and its immutable
/// SVE2-only classifier together. The public handle stays one word wide, while the
/// distinct identity prevents the fixed-block accounting from being confused
/// with the incumbent pointwise scalar implementation.
#[derive(Debug)]
pub struct DispatchedUnicodeScalarAggregatePlan {
    owner: RetainedDispatchedUnicodeScalarOwner,
}

#[derive(Debug)]
struct DispatchedUnicodeScalarOwner {
    plan: UnicodeScalarAggregatePlan,
    classifier: AsciiByteSetClassifier,
}

type RetainedDispatchedUnicodeScalarOwner = ExactBoxOrUsize<DispatchedUnicodeScalarOwner>;

impl UnicodeScalarAggregatePlan {
    /// Copy one canonical sequence of inclusive scalar ranges.
    pub fn build(
        ranges: impl IntoIterator<Item = (char, char)>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt(ranges, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Copy one canonical scalar class with exact observed construction effects.
    pub fn build_attempt(
        ranges: impl IntoIterator<Item = (char, char)>,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        Self::build_with_repetition_attempt(ranges, Repetition::ExactlyOne, limits)
    }

    /// Copy a canonical scalar class for a proved nonempty unbounded root
    /// repetition.
    pub fn build_one_or_more(
        ranges: impl IntoIterator<Item = (char, char)>,
        greedy: bool,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_one_or_more_attempt(ranges, greedy, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Copy a proved nonempty unbounded scalar repetition with exact effects.
    pub fn build_one_or_more_attempt(
        ranges: impl IntoIterator<Item = (char, char)>,
        greedy: bool,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let repetition = if greedy {
            Repetition::OneOrMoreGreedy
        } else {
            Repetition::OneOrMoreLazy
        };
        Self::build_with_repetition_attempt(ranges, repetition, limits)
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
        Self::build_repeated_attempt(ranges, minimum, maximum, greedy, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Copy a symbolic non-nullable repetition with exact observed effects.
    pub fn build_repeated_attempt(
        ranges: impl IntoIterator<Item = (char, char)>,
        minimum: u32,
        maximum: Option<u32>,
        greedy: bool,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        if minimum == 0 || maximum.is_some_and(|maximum| maximum < minimum) {
            return Err(DirectBuildAttemptError::new(
                BuildError::InvalidRepetition { minimum, maximum },
                DirectBuildAttemptActual::default(),
            ));
        }
        let repetition = match (minimum, maximum, greedy) {
            (1, None, true) => Repetition::OneOrMoreGreedy,
            (1, None, false) => Repetition::OneOrMoreLazy,
            (_, _, true) => Repetition::RepeatedGreedy { minimum, maximum },
            (_, _, false) => Repetition::RepeatedLazy { minimum, maximum },
        };
        Self::build_with_repetition_attempt(ranges, repetition, limits)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps canonical validation and all checked storage accounting in one auditable transaction"
    )]
    fn build_with_repetition_attempt(
        ranges: impl IntoIterator<Item = (char, char)>,
        repetition: Repetition,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let mut actual = DirectBuildAttemptActual::default();
        let mut live_capacity_bytes = 0_usize;
        let result = (|| {
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
                actual.work = u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "actual scalar build work as u64",
                })?;

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
                        actual.work =
                            u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
                                computation: "actual scalar build work as u64",
                            })?;
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
                    let before_capacity = non_ascii.capacity();
                    non_ascii
                        .try_reserve(1)
                        .map_err(|_| BuildError::AllocationFailed { additional: 1 })?;
                    let after_capacity = non_ascii.capacity();
                    if after_capacity > before_capacity {
                        let allocation_bytes = after_capacity
                            .checked_mul(size_of::<ScalarRange>())
                            .ok_or(BuildError::ArithmeticOverflow {
                                computation: "observed non-ASCII allocation bytes",
                            })?;
                        actual.allocations = actual.allocations.checked_add(1).ok_or(
                            BuildError::ArithmeticOverflow {
                                computation: "actual scalar allocation count",
                            },
                        )?;
                        actual.allocated_bytes = actual
                            .allocated_bytes
                            .checked_add(allocation_bytes)
                            .ok_or(BuildError::ArithmeticOverflow {
                                computation: "cumulative scalar allocated bytes",
                            })?;
                        live_capacity_bytes = allocation_bytes;
                        actual.peak_bytes = actual.peak_bytes.max(live_capacity_bytes);
                    }
                    non_ascii.push(retained);
                    actual.copied_bytes = actual
                        .copied_bytes
                        .checked_add(size_of::<ScalarRange>())
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "actual scalar copied bytes",
                        })?;
                    actual.initialized_bytes = actual
                        .initialized_bytes
                        .checked_add(size_of::<ScalarRange>())
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "actual scalar initialized bytes",
                        })?;
                    work = checked_add(work, 1, "range copy work")?;
                    actual.work =
                        u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
                            computation: "actual scalar build work as u64",
                        })?;
                }
                enforce_build(work, limits.max_build_work, BuildResource::Work)?;
            }
            if source_ranges == 0 {
                return Err(BuildError::EmptyClass);
            }
            if repetition.is_run() {
                work = checked_add(work, 1, "repetition configuration work")?;
                actual.work = u64::try_from(work).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "actual scalar build work as u64",
                })?;
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
                ascii_classifier_build_work: 0,
                ascii_classifier_bytes: 0,
                dispatched_owner_bytes: 0,
                temporary_capacity_bytes,
                scratch_bytes: temporary_capacity_bytes,
                persistent_bytes,
                peak_bytes,
            };
            let plan = Self {
                ascii,
                non_ascii: non_ascii.into_boxed_slice(),
                repetition,
                build,
            };
            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(size_of::<Self>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "published scalar inline initialized bytes",
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

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity::for_repetition(Operation::Count, self.repetition)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        OperationIdentity::for_repetition(Operation::SpanSum, self.repetition)
    }

    /// Publish the scalar plan's exact source-free full-window envelope.
    pub fn full_window_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        derive_reduce_upper_bounds(self.build, input_bytes, ReduceImplementation::Scalar)
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        self.count_in(haystack, Window::full(haystack), limits)
    }

    /// Admit one full-window Count from an immutable input length and resource
    /// policy without reading source bytes.
    ///
    /// A successful token retains the exact upper envelope already checked by
    /// ordinary Count preflight. It may subsequently be reused for byte slices
    /// of that length.
    pub fn prepare_count(
        &self,
        input_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<CountAdmission, ReduceError> {
        let upper = self.preflight_input_bytes(
            input_bytes,
            Operation::Count,
            limits,
            ReduceImplementation::Scalar,
        )?;
        Ok(CountAdmission::new(
            input_bytes,
            ReduceImplementation::Scalar,
            self.build,
            upper,
        ))
    }

    /// Execute a previously admitted full-window Count.
    ///
    /// `None` means the token does not authenticate this plan's
    /// resource-relevant shape and input length, or value execution reached an
    /// unexpected checked failure. A caller that publishes typed errors must
    /// replay [`Self::count`] with the token's original limits.
    #[must_use]
    #[inline]
    pub fn count_prepared(&self, haystack: &[u8], admission: CountAdmission) -> Option<u64> {
        if !admission.authenticates(haystack, ReduceImplementation::Scalar, self.build) {
            return None;
        }
        self.execute_value(haystack, Window::full(haystack), admission.upper)
            .ok()
            .map(|value| value.count)
    }

    /// Return only a successfully admitted count without constructing complete
    /// execution accounting.
    ///
    /// `None` deliberately carries no terminal error. A caller that publishes
    /// errors must replay [`Self::count`] with the same arguments.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn count_value_success(&self, haystack: &[u8], limits: ReduceLimits) -> Option<u64> {
        self.count_value_in_success(haystack, Window::full(haystack), limits)
    }

    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn count_value_in_success(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Option<u64> {
        let upper = self
            .preflight(haystack, window, Operation::Count, limits, false)
            .ok()?;
        self.execute_value(haystack, window, upper)
            .ok()
            .map(|value| value.count)
    }

    pub fn count_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<CountResult, ReduceError> {
        let upper_bounds = self.preflight(haystack, window, Operation::Count, limits, false)?;
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

    /// Return only a successfully admitted span sum without constructing
    /// complete execution accounting.
    ///
    /// `None` deliberately carries no terminal error. A caller that publishes
    /// errors must replay [`Self::span_sum`] with the same arguments.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn span_sum_value_success(&self, haystack: &[u8], limits: ReduceLimits) -> Option<u64> {
        self.span_sum_value_in_success(haystack, Window::full(haystack), limits)
    }

    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn span_sum_value_in_success(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Option<u64> {
        let upper = self
            .preflight(haystack, window, Operation::SpanSum, limits, false)
            .ok()?;
        self.execute_value(haystack, window, upper)
            .ok()
            .map(|value| value.matched_bytes)
    }

    pub fn span_sum_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let upper_bounds = self.preflight(haystack, window, Operation::SpanSum, limits, false)?;
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
        ascii_blocks: bool,
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
        let implementation = if ascii_blocks {
            ReduceImplementation::DispatchedAsciiBlock32
        } else {
            ReduceImplementation::Scalar
        };
        self.preflight_input_bytes(input_bytes, operation, limits, implementation)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "source-free preflight keeps every operation upper bound and its matching limit check adjacent"
    )]
    fn preflight_input_bytes(
        &self,
        input_bytes: usize,
        operation: Operation,
        limits: ReduceLimits,
        implementation: ReduceImplementation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let upper = derive_reduce_upper_bounds(self.build, input_bytes, implementation)?;
        let decode_byte_checks = upper.decode_byte_checks;
        let membership_tests = upper.membership_tests;
        let range_comparisons = upper.range_comparisons;
        let reducer_steps = upper.reducer_steps;
        let match_events = upper.match_events;
        let count = upper.count;
        let span_sum = upper.span_sum;
        let work = upper.work;
        let scratch_bytes = upper.scratch_bytes;
        let peak_bytes = upper.peak_bytes;
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
        self.execute_with_meter::<FullExecutionMeter>(haystack, window, upper)
    }

    #[inline]
    fn execute_value(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
    ) -> Result<ValueReduction, ReduceError> {
        self.execute_with_meter::<NoExecutionMeter>(haystack, window, upper)
    }

    #[inline]
    fn execute_with_meter<M: ExecutionMeter>(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
    ) -> Result<M::Output, ReduceError> {
        match self.repetition {
            Repetition::ExactlyOne => self.execute_mode::<M, false, false, false, false>(
                haystack,
                window,
                upper,
                1,
                Some(1),
            ),
            Repetition::OneOrMoreGreedy if self.non_ascii.is_empty() => {
                self.execute_mode::<M, true, true, false, false>(haystack, window, upper, 1, None)
            }
            Repetition::OneOrMoreGreedy => {
                self.execute_mode::<M, true, true, true, false>(haystack, window, upper, 1, None)
            }
            Repetition::OneOrMoreLazy if self.non_ascii.is_empty() => {
                self.execute_mode::<M, true, false, false, false>(haystack, window, upper, 1, None)
            }
            Repetition::OneOrMoreLazy => {
                self.execute_mode::<M, true, false, true, false>(haystack, window, upper, 1, None)
            }
            repetition @ (Repetition::RepeatedGreedy { .. } | Repetition::RepeatedLazy { .. }) => {
                let (minimum, maximum, greedy) = repetition
                    .bounds()
                    .expect("repeated variants always have bounds");
                if greedy {
                    if self.non_ascii.is_empty() {
                        self.execute_mode::<M, true, true, false, true>(
                            haystack, window, upper, minimum, maximum,
                        )
                    } else {
                        self.execute_mode::<M, true, true, true, true>(
                            haystack, window, upper, minimum, maximum,
                        )
                    }
                } else if self.non_ascii.is_empty() {
                    self.execute_mode::<M, true, false, false, true>(
                        haystack, window, upper, minimum, maximum,
                    )
                } else {
                    self.execute_mode::<M, true, false, true, true>(
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
        M: ExecutionMeter,
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
    ) -> Result<M::Output, ReduceError> {
        let local = &haystack[window.start()..window.end()];
        let mut position = 0_usize;
        let mut pending_run_bytes = 0_u64;
        let mut pending_run_scalars = 0_u64;
        let mut cached_non_ascii_range = None::<usize>;
        let mut previous_non_ascii_scalar = None::<u32>;
        let mut monotone_range_cursor = true;
        let mut value = ValueReduction::default();
        let mut meter = M::new();
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
                                &mut value,
                                &mut meter,
                                &mut pending_run_bytes,
                                &mut pending_run_scalars,
                                1,
                                minimum,
                                maximum,
                                GREEDY,
                            )?;
                        } else {
                            finish_repeated_run(
                                &mut value,
                                &mut meter,
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
                            flush_greedy_run(&mut value, &mut meter, &mut pending_run_bytes)?;
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
                meter.update(|actual| {
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
                    Ok(())
                })?;
                if !GREEDY && !GENERAL_REPETITION {
                    record_ascii_matches(&mut value, &mut meter, run_matches)?;
                }
                continue;
            }
            if RUN {
                meter.update(|actual| {
                    actual.reducer_steps = actual.reducer_steps.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual run reducer transitions",
                        },
                    )?;
                    Ok(())
                })?;
            }
            let decoded = decode_scalar(&local[position..]);
            meter.update(|actual| {
                actual.decode_byte_checks = actual
                    .decode_byte_checks
                    .checked_add(decoded.byte_checks)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual decode byte checks",
                    })?;
                Ok(())
            })?;
            let matched = if let Some(scalar) = decoded.scalar {
                meter.update(|actual| {
                    actual.valid_scalars = actual.valid_scalars.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual valid scalars",
                        },
                    )?;
                    actual.non_ascii_membership_tests = actual
                        .non_ascii_membership_tests
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual non-ASCII membership tests",
                        })?;
                    Ok(())
                })?;
                // The maximal ASCII-run branch above proves that every
                // successfully decoded scalar here is non-ASCII.
                debug_assert!(scalar > 0x7F);
                if CACHE_RANGE && monotone_range_cursor {
                    let nondecreasing =
                        previous_non_ascii_scalar.is_none_or(|previous| scalar >= previous);
                    previous_non_ascii_scalar = Some(scalar);
                    if nondecreasing {
                        self.contains_non_ascii_run(
                            scalar,
                            &mut cached_non_ascii_range,
                            &mut meter,
                        )?
                    } else {
                        monotone_range_cursor = false;
                        cached_non_ascii_range = None;
                        self.contains_non_ascii_cached(
                            scalar,
                            &mut cached_non_ascii_range,
                            &mut meter,
                        )?
                    }
                } else if CACHE_RANGE {
                    self.contains_non_ascii_cached(scalar, &mut cached_non_ascii_range, &mut meter)?
                } else {
                    self.contains_non_ascii(scalar, &mut meter)?
                }
            } else {
                meter.update(|actual| {
                    actual.invalid_bytes = actual.invalid_bytes.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual invalid bytes",
                        },
                    )?;
                    Ok(())
                })?;
                false
            };
            if matched {
                let width =
                    u64::try_from(decoded.width).map_err(|_| ReduceError::ArithmeticOverflow {
                        computation: "matched scalar width",
                    })?;
                if GENERAL_REPETITION {
                    reduce_repeated_scalar(
                        &mut value,
                        &mut meter,
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
                    record_match(&mut value, &mut meter, width)?;
                }
            } else if GENERAL_REPETITION {
                finish_repeated_run(
                    &mut value,
                    &mut meter,
                    &mut pending_run_bytes,
                    &mut pending_run_scalars,
                    minimum,
                    GREEDY,
                )?;
            } else if GREEDY {
                flush_greedy_run(&mut value, &mut meter, &mut pending_run_bytes)?;
            }
            position =
                position
                    .checked_add(decoded.width)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "scalar stream position",
                    })?;
        }
        if RUN {
            meter.update(|actual| {
                actual.reducer_steps =
                    actual
                        .reducer_steps
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "final run reducer transition",
                        })?;
                Ok(())
            })?;
        }
        if GENERAL_REPETITION {
            finish_repeated_run(
                &mut value,
                &mut meter,
                &mut pending_run_bytes,
                &mut pending_run_scalars,
                minimum,
                GREEDY,
            )?;
        } else if GREEDY {
            flush_greedy_run(&mut value, &mut meter, &mut pending_run_bytes)?;
        }
        meter.finish_scalar(value, position, upper)
    }

    #[allow(
        clippy::inline_always,
        reason = "membership charging must disappear from the value-only scalar loop"
    )]
    #[inline(always)]
    fn contains_non_ascii<M: ExecutionMeter>(
        &self,
        scalar: u32,
        meter: &mut M,
    ) -> Result<bool, ReduceError> {
        let mut low = 0_usize;
        let mut high = self.non_ascii.len();
        while low < high {
            record_range_comparison(meter, "binary search comparisons")?;
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
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[allow(
        clippy::inline_always,
        reason = "cached membership charging must disappear from the value-only scalar loop"
    )]
    #[inline(always)]
    fn contains_non_ascii_run<M: ExecutionMeter>(
        &self,
        scalar: u32,
        cached_range: &mut Option<usize>,
        meter: &mut M,
    ) -> Result<bool, ReduceError> {
        if let Some(index) = *cached_range {
            if let Some(range) = self.non_ascii.get(index) {
                record_range_comparison(meter, "cached non-ASCII range comparison")?;
                if scalar >= range.start && scalar <= range.end {
                    return Ok(true);
                }
                if scalar < range.start {
                    return Ok(false);
                }
                let next = index
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "cached non-ASCII range successor",
                    })?;
                *cached_range = Some(next);
                if let Some(range) = self.non_ascii.get(next) {
                    record_range_comparison(meter, "monotone range comparisons")?;
                    if scalar < range.start {
                        return Ok(false);
                    }
                    if scalar <= range.end {
                        return Ok(true);
                    }
                } else {
                    return Ok(false);
                }
            } else if index == self.non_ascii.len() {
                return Ok(false);
            }
        }

        let mut low = 0_usize;
        let mut high = self.non_ascii.len();
        while low < high {
            record_range_comparison(meter, "cached binary search comparisons")?;
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
            if scalar <= range.end {
                high = middle;
            } else {
                low = middle
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "cached binary search lower bound",
                    })?;
            }
        }
        *cached_range = Some(low);
        let contains = self
            .non_ascii
            .get(low)
            .is_some_and(|range| scalar >= range.start);
        Ok(contains)
    }

    #[allow(
        clippy::inline_always,
        reason = "cached membership charging must disappear from the value-only scalar loop"
    )]
    #[inline(always)]
    fn contains_non_ascii_cached<M: ExecutionMeter>(
        &self,
        scalar: u32,
        cached_range: &mut Option<usize>,
        meter: &mut M,
    ) -> Result<bool, ReduceError> {
        if let Some(index) = *cached_range {
            record_range_comparison(meter, "cached non-ASCII range comparison")?;
            let range = self
                .non_ascii
                .get(index)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "cached non-ASCII range access",
                })?;
            if scalar >= range.start && scalar <= range.end {
                return Ok(true);
            }
            *cached_range = None;
        }

        let mut low = 0_usize;
        let mut high = self.non_ascii.len();
        while low < high {
            record_range_comparison(meter, "cached binary search comparisons")?;
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
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl DispatchedUnicodeScalarAggregatePlan {
    /// Whether this authentic host snapshot can retain the fixed-32 owner.
    #[must_use]
    pub fn classifier_usable(dispatch: SimdDispatchContext) -> bool {
        ascii_block_policy(dispatch).is_some()
    }

    /// Build the SVE2-gated exactly-one owner from one capability snapshot.
    pub fn build_with_dispatch(
        dispatch: SimdDispatchContext,
        ranges: impl IntoIterator<Item = (char, char)>,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt_with_dispatch(dispatch, ranges, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build the distinct fixed-32 owner with exact observed effects.
    #[allow(
        clippy::too_many_lines,
        reason = "the dispatched envelope keeps source-free capability/storage checks, scalar error mapping, classifier construction, and exact owner publication adjacent"
    )]
    pub fn build_attempt_with_dispatch(
        dispatch: SimdDispatchContext,
        ranges: impl IntoIterator<Item = (char, char)>,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let empty_actual = DirectBuildAttemptActual::default();
        if !Self::classifier_usable(dispatch) {
            return Err(DirectBuildAttemptError::new(
                BuildError::AsciiClassifierDispatchUnavailable,
                empty_actual,
            ));
        }
        let owner_bytes = size_of::<DispatchedUnicodeScalarOwner>();
        let dispatched_inline_bytes =
            size_of::<Self>()
                .checked_add(owner_bytes)
                .ok_or(DirectBuildAttemptError::new(
                    BuildError::ArithmeticOverflow {
                        computation: "dispatched Unicode scalar inline bytes",
                    },
                    empty_actual,
                ))?;
        let storage_delta = dispatched_inline_bytes
            .checked_sub(size_of::<UnicodeScalarAggregatePlan>())
            .ok_or(DirectBuildAttemptError::new(
                BuildError::ArithmeticOverflow {
                    computation: "dispatched Unicode scalar storage delta",
                },
                empty_actual,
            ))?;
        for result in [
            enforce_build(
                dispatched_inline_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            ),
            enforce_build(
                dispatched_inline_bytes,
                limits.max_peak_bytes,
                BuildResource::Peak,
            ),
        ] {
            if let Err(source) = result {
                return Err(DirectBuildAttemptError::new(source, empty_actual));
            }
        }
        let scalar_work_limit = limits
            .max_build_work
            .checked_sub(SIMD_ASCII_CLASSIFIER_BUILD_WORK)
            .ok_or(DirectBuildAttemptError::new(
                BuildError::WorkLimit {
                    needed: SIMD_ASCII_CLASSIFIER_BUILD_WORK,
                    limit: limits.max_build_work,
                },
                empty_actual,
            ))?;
        let scalar_limits = BuildLimits {
            max_build_work: scalar_work_limit,
            max_persistent_bytes: limits
                .max_persistent_bytes
                .checked_sub(storage_delta)
                .expect("the dispatched inline preflight proves the storage reservation"),
            max_peak_bytes: limits.max_peak_bytes,
            ..limits
        };
        let attempt = match UnicodeScalarAggregatePlan::build_attempt(ranges, scalar_limits) {
            Ok(attempt) => attempt,
            Err(error) => {
                let actual = error.actual();
                let source = match error.into_source() {
                    BuildError::WorkLimit { needed, .. } => BuildError::WorkLimit {
                        needed: needed.checked_add(SIMD_ASCII_CLASSIFIER_BUILD_WORK).ok_or(
                            DirectBuildAttemptError::new(
                                BuildError::ArithmeticOverflow {
                                    computation: "dispatched Unicode scalar build work refusal",
                                },
                                actual,
                            ),
                        )?,
                        limit: limits.max_build_work,
                    },
                    BuildError::PersistentLimit { needed, .. } => BuildError::PersistentLimit {
                        needed: needed.checked_add(storage_delta).ok_or(
                            DirectBuildAttemptError::new(
                                BuildError::ArithmeticOverflow {
                                    computation: "dispatched Unicode scalar persistent refusal",
                                },
                                actual,
                            ),
                        )?,
                        limit: limits.max_persistent_bytes,
                    },
                    BuildError::PeakLimit { needed, .. } => BuildError::PeakLimit {
                        needed,
                        limit: limits.max_peak_bytes,
                    },
                    source => source,
                };
                return Err(DirectBuildAttemptError::new(source, actual));
            }
        };
        let (plan, actual) = attempt.into_parts();
        build_dispatched_unicode_scalar_owner(
            dispatch,
            plan,
            actual,
            storage_delta,
            owner_bytes,
            limits.max_peak_bytes,
        )
    }

    #[must_use]
    pub fn build_accounting(&self) -> BuildAccounting {
        self.plan().build_accounting()
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity::for_dispatched_operation(Operation::Count)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        OperationIdentity::for_dispatched_operation(Operation::SpanSum)
    }

    /// Publish the dispatched plan's exact source-free full-window envelope,
    /// including fixed-32 classifier lookahead.
    pub fn full_window_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        derive_reduce_upper_bounds(
            self.build_accounting(),
            input_bytes,
            ReduceImplementation::DispatchedAsciiBlock32,
        )
    }

    /// Immutable SVE2-only decisions retained for fixed-16 and fixed-32 blocks.
    #[must_use]
    pub fn classifier_selection(&self) -> AsciiSelection {
        self.classifier().selection()
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        self.count_in(haystack, Window::full(haystack), limits)
    }

    /// Admit one full-window dispatched Count from an immutable input length
    /// and resource policy without reading source bytes.
    pub fn prepare_count(
        &self,
        input_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<CountAdmission, ReduceError> {
        let build = self.build_accounting();
        let upper = self.plan().preflight_input_bytes(
            input_bytes,
            Operation::Count,
            limits,
            ReduceImplementation::DispatchedAsciiBlock32,
        )?;
        Ok(CountAdmission::new(
            input_bytes,
            ReduceImplementation::DispatchedAsciiBlock32,
            build,
            upper,
        ))
    }

    /// Execute a previously admitted full-window dispatched Count.
    ///
    /// `None` requests ordinary replay when the input length or retained
    /// resource shape differs, or value execution reaches a checked failure.
    #[must_use]
    #[inline]
    pub fn count_prepared(&self, haystack: &[u8], admission: CountAdmission) -> Option<u64> {
        if !admission.authenticates(
            haystack,
            ReduceImplementation::DispatchedAsciiBlock32,
            self.build_accounting(),
        ) {
            return None;
        }
        self.plan()
            .execute_exactly_one_value_with_classifier(
                haystack,
                Window::full(haystack),
                admission.upper,
                self.classifier(),
            )
            .ok()
            .map(|value| value.count)
    }

    /// Return only a successfully admitted dispatched count without
    /// constructing complete execution accounting.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn count_value_success(&self, haystack: &[u8], limits: ReduceLimits) -> Option<u64> {
        self.count_value_in_success(haystack, Window::full(haystack), limits)
    }

    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn count_value_in_success(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Option<u64> {
        let upper = self
            .plan()
            .preflight(haystack, window, Operation::Count, limits, true)
            .ok()?;
        self.plan()
            .execute_exactly_one_value_with_classifier(haystack, window, upper, self.classifier())
            .ok()
            .map(|value| value.count)
    }

    pub fn count_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<CountResult, ReduceError> {
        let upper_bounds =
            self.plan()
                .preflight(haystack, window, Operation::Count, limits, true)?;
        let actual = self.plan().execute_exactly_one_with_classifier(
            haystack,
            window,
            upper_bounds,
            self.classifier(),
        )?;
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

    /// Return only a successfully admitted dispatched span sum without
    /// constructing complete execution accounting.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn span_sum_value_success(&self, haystack: &[u8], limits: ReduceLimits) -> Option<u64> {
        self.span_sum_value_in_success(haystack, Window::full(haystack), limits)
    }

    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn span_sum_value_in_success(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Option<u64> {
        let upper = self
            .plan()
            .preflight(haystack, window, Operation::SpanSum, limits, true)
            .ok()?;
        self.plan()
            .execute_exactly_one_value_with_classifier(haystack, window, upper, self.classifier())
            .ok()
            .map(|value| value.matched_bytes)
    }

    pub fn span_sum_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let upper_bounds =
            self.plan()
                .preflight(haystack, window, Operation::SpanSum, limits, true)?;
        let actual = self.plan().execute_exactly_one_with_classifier(
            haystack,
            window,
            upper_bounds,
            self.classifier(),
        )?;
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

    fn plan(&self) -> &UnicodeScalarAggregatePlan {
        &self.owner().plan
    }

    fn classifier(&self) -> &AsciiByteSetClassifier {
        &self.owner().classifier
    }

    fn owner(&self) -> &DispatchedUnicodeScalarOwner {
        self.owner
            .boxed()
            .expect("the dispatched Unicode scalar plan retains its exact owner")
    }
}

const fn dispatched_identity(operation: Operation) -> OperationIdentity {
    OperationIdentity {
        plan_id: DISPATCHED_PLAN_ID,
        operation_id: match operation {
            Operation::Count => COUNT_OPERATION_ID,
            Operation::SpanSum => SPAN_SUM_OPERATION_ID,
        },
        operation,
        scalar_semantics: ScalarSemantics::RustBytesUnicodeUtf8False,
        repetition: Repetition::ExactlyOne,
        non_overlapping: true,
    }
}

fn ascii_block_policy(dispatch: SimdDispatchContext) -> Option<DispatchPolicy> {
    if !cfg!(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little"
    )) {
        return None;
    }
    let sve2 = FeatureSet::EMPTY
        .with(Feature::ArmSve)
        .with(Feature::ArmSve2);
    if !dispatch.capabilities().usable().contains_all(sve2) {
        return None;
    }
    #[cfg(feature = "static-dispatch-arm-41-d84")]
    {
        Some(DispatchPolicy::Auto)
    }
    #[cfg(all(
        feature = "static-dispatch",
        not(feature = "static-dispatch-arm-41-d84")
    ))]
    {
        None
    }
    #[cfg(not(feature = "static-dispatch"))]
    {
        Some(DispatchPolicy::AllowOnly(sve2))
    }
}

#[inline(never)]
fn build_dispatched_unicode_scalar_owner(
    dispatch: SimdDispatchContext,
    mut plan: UnicodeScalarAggregatePlan,
    mut actual: DirectBuildAttemptActual,
    storage_delta: usize,
    owner_bytes: usize,
    max_peak_bytes: usize,
) -> Result<
    DirectBuildAttempt<DispatchedUnicodeScalarAggregatePlan>,
    DirectBuildAttemptError<BuildError>,
> {
    let result = (|| {
        let work = plan
            .build
            .work
            .checked_add(SIMD_ASCII_CLASSIFIER_BUILD_WORK)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "dispatched Unicode scalar build work",
            })?;
        let persistent_bytes = plan
            .build
            .persistent_bytes
            .checked_add(storage_delta)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "dispatched Unicode scalar persistent bytes",
            })?;
        let peak_bytes = plan.build.peak_bytes.max(persistent_bytes);
        enforce_build(peak_bytes, max_peak_bytes, BuildResource::Peak)?;
        actual.work = actual
            .work
            .checked_add(
                u64::try_from(SIMD_ASCII_CLASSIFIER_BUILD_WORK).map_err(|_| {
                    BuildError::ArithmeticOverflow {
                        computation: "ASCII classifier build work as u64",
                    }
                })?,
            )
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual dispatched Unicode scalar build work",
            })?;
        let policy =
            ascii_block_policy(dispatch).expect("the dispatched build proved OS-usable SVE2");
        let classifier = dispatch
            .ascii_byte_set_classifier(AsciiByteSet::from_words(plan.ascii), policy)
            .expect("the SVE2-only policy removes every incompatible wide implementation");
        plan.build.work = work;
        plan.build.ascii_classifier_build_work = SIMD_ASCII_CLASSIFIER_BUILD_WORK;
        plan.build.ascii_classifier_bytes = size_of::<AsciiByteSetClassifier>();
        plan.build.dispatched_owner_bytes = owner_bytes;
        plan.build.persistent_bytes = persistent_bytes;
        plan.build.peak_bytes = peak_bytes;
        let owner = DispatchedUnicodeScalarOwner { plan, classifier };
        let owner = RetainedDispatchedUnicodeScalarOwner::try_from_boxed(owner).map_err(
            |error| match error {
                CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
                    computation: "dispatched Unicode scalar owner allocation layout",
                },
                CopyError::AllocationFailed => {
                    BuildError::DispatchedOwnerAllocationFailed { bytes: owner_bytes }
                }
            },
        )?;
        actual.allocations =
            actual
                .allocations
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual dispatched Unicode scalar allocation count",
                })?;
        actual.allocated_bytes = actual.allocated_bytes.checked_add(owner_bytes).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "actual dispatched Unicode scalar allocated bytes",
            },
        )?;
        actual.initialized_bytes = persistent_bytes;
        actual.live_persistent_bytes = persistent_bytes;
        actual.peak_bytes = actual.peak_bytes.max(persistent_bytes);
        Ok(DispatchedUnicodeScalarAggregatePlan { owner })
    })();
    match result {
        Ok(plan) => Ok(DirectBuildAttempt::new(plan, actual)),
        Err(source) => {
            actual.live_persistent_bytes = 0;
            Err(DirectBuildAttemptError::new(source, actual))
        }
    }
}

impl UnicodeScalarAggregatePlan {
    #[allow(
        clippy::too_many_lines,
        clippy::arithmetic_side_effects,
        reason = "the fixed-block loop keeps mask-prefix consumption, scalar UTF-8 fallback, non-overlapping block scheduling, and exact physical accounting visibly coupled"
    )]
    fn execute_exactly_one_with_classifier(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
        classifier: &AsciiByteSetClassifier,
    ) -> Result<ReduceActualCounters, ReduceError> {
        self.execute_exactly_one_with_classifier_meter::<FullExecutionMeter>(
            haystack, window, upper, classifier,
        )
    }

    #[inline]
    fn execute_exactly_one_value_with_classifier(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
        classifier: &AsciiByteSetClassifier,
    ) -> Result<ValueReduction, ReduceError> {
        self.execute_exactly_one_with_classifier_meter::<NoExecutionMeter>(
            haystack, window, upper, classifier,
        )
    }

    #[allow(
        clippy::too_many_lines,
        clippy::arithmetic_side_effects,
        reason = "the fixed-block loop keeps mask-prefix consumption, scalar UTF-8 fallback, non-overlapping block scheduling, and exact physical accounting visibly coupled"
    )]
    fn execute_exactly_one_with_classifier_meter<M: ExecutionMeter>(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ReduceUpperBounds,
        classifier: &AsciiByteSetClassifier,
    ) -> Result<M::Output, ReduceError> {
        debug_assert_eq!(self.repetition, Repetition::ExactlyOne);
        let local = &haystack[window.start()..window.end()];
        let mut position = 0_usize;
        let mut scalar_fallback_end = 0_usize;
        let mut ascii_matches = 0_usize;
        let mut value = ValueReduction::default();
        let mut meter = M::new();
        while position < local.len() {
            if position >= scalar_fallback_end && local.len() - position >= ASCII_WIDE_BYTES {
                let block_end = position + ASCII_WIDE_BYTES;
                let block: &[u8; ASCII_WIDE_BYTES] = local[position..block_end]
                    .try_into()
                    .expect("the fixed-block extent was checked");
                let masks = classifier.classify_32(block);
                let ascii_prefix = usize::from(masks.leading_ascii_len());
                let lookahead = ASCII_WIDE_BYTES - ascii_prefix;
                let member_count = usize::try_from(masks.ascii_prefix_member_mask().count_ones())
                    .map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "ASCII block member count",
                })?;
                // Blocks never overlap and every prefix is within its block.
                // Preflight proved all N- and B-bounded accumulators fit.
                meter.update(|actual| {
                    actual.ascii_block_classifications += 1;
                    actual.ascii_block_classification_bytes += ASCII_WIDE_BYTES;
                    actual.ascii_block_lookahead_bytes += lookahead;
                    actual.decode_byte_checks += ASCII_WIDE_BYTES;
                    actual.valid_scalars += ascii_prefix;
                    actual.ascii_run_bytes += ascii_prefix;
                    actual.ascii_bitmap_tests += ascii_prefix;
                    Ok(())
                })?;
                ascii_matches += member_count;
                position += ascii_prefix;
                if ascii_prefix == ASCII_WIDE_BYTES {
                    scalar_fallback_end = position;
                    continue;
                }
                // One mixed block is enough evidence that repeated wide
                // probes may only add work. Preserve the exact consumed ASCII
                // prefix, then use the incumbent scalar decoder to EOF.
                scalar_fallback_end = local.len();
            }

            if local[position].is_ascii() {
                let run_start = position;
                let run_limit = if position < scalar_fallback_end {
                    scalar_fallback_end
                } else {
                    local.len()
                };
                let mut run_matches = 0_usize;
                while position < run_limit {
                    let byte = local[position];
                    if !byte.is_ascii() {
                        break;
                    }
                    let word = self.ascii[usize::from(byte / 64)];
                    run_matches += usize::from(word & (1_u64 << (byte % 64)) != 0);
                    position += 1;
                }
                let run_bytes = position - run_start;
                // These logical runs partition bytes not consumed by a block
                // prefix, so the same preflight N-bound covers every sum.
                meter.update(|actual| {
                    actual.decode_byte_checks += run_bytes;
                    actual.valid_scalars += run_bytes;
                    actual.ascii_run_bytes += run_bytes;
                    actual.ascii_bitmap_tests += run_bytes;
                    Ok(())
                })?;
                ascii_matches += run_matches;
                continue;
            }

            let decoded = decode_scalar_inline(&local[position..]);
            meter.update(|actual| {
                actual.decode_byte_checks = actual
                    .decode_byte_checks
                    .checked_add(decoded.byte_checks)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual scalar-fallback decode checks",
                    })?;
                Ok(())
            })?;
            let matched = if let Some(scalar) = decoded.scalar {
                meter.update(|actual| {
                    actual.valid_scalars = actual.valid_scalars.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual scalar-fallback valid scalars",
                        },
                    )?;
                    actual.non_ascii_membership_tests = actual
                        .non_ascii_membership_tests
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual scalar-fallback non-ASCII membership tests",
                        })?;
                    Ok(())
                })?;
                debug_assert!(scalar > 0x7F);
                self.contains_non_ascii(scalar, &mut meter)?
            } else {
                meter.update(|actual| {
                    actual.invalid_bytes = actual.invalid_bytes.checked_add(1).ok_or(
                        ReduceError::ArithmeticOverflow {
                            computation: "actual scalar-fallback invalid bytes",
                        },
                    )?;
                    Ok(())
                })?;
                false
            };
            if matched {
                record_match(
                    &mut value,
                    &mut meter,
                    u64::try_from(decoded.width).map_err(|_| ReduceError::ArithmeticOverflow {
                        computation: "scalar-fallback matched width",
                    })?,
                )?;
            }
            position += decoded.width;
        }
        record_ascii_matches(&mut value, &mut meter, ascii_matches)?;
        meter.finish_dispatched(value, position, upper)
    }
}

#[allow(
    clippy::inline_always,
    reason = "the no-op comparison charge must disappear at every value-only range probe"
)]
#[inline(always)]
fn record_range_comparison<M: ExecutionMeter>(
    meter: &mut M,
    computation: &'static str,
) -> Result<(), ReduceError> {
    meter.update(|actual| {
        actual.range_comparisons = actual
            .range_comparisons
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow { computation })?;
        Ok(())
    })
}

#[allow(
    clippy::inline_always,
    reason = "value-only ASCII reduction must not retain a structural-meter call"
)]
#[inline(always)]
fn record_ascii_matches<M: ExecutionMeter>(
    value: &mut ValueReduction,
    meter: &mut M,
    matches: usize,
) -> Result<(), ReduceError> {
    meter.update(|actual| {
        actual.match_events =
            actual
                .match_events
                .checked_add(matches)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual ASCII block match events",
                })?;
        Ok(())
    })?;
    let matches = u64::try_from(matches).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "actual ASCII block matches as u64",
    })?;
    value.count = value
        .count
        .checked_add(matches)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual ASCII block count",
        })?;
    value.matched_bytes =
        value
            .matched_bytes
            .checked_add(matches)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual ASCII block matched bytes",
            })?;
    Ok(())
}

#[allow(
    clippy::inline_always,
    reason = "value-only scalar reduction must not retain a structural-meter call"
)]
#[inline(always)]
fn record_match<M: ExecutionMeter>(
    value: &mut ValueReduction,
    meter: &mut M,
    width: u64,
) -> Result<(), ReduceError> {
    meter.update(|actual| {
        actual.match_events =
            actual
                .match_events
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual match events",
                })?;
        Ok(())
    })?;
    value.count = value
        .count
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
    value.matched_bytes =
        value
            .matched_bytes
            .checked_add(width)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual matched bytes",
            })?;
    Ok(())
}

#[allow(
    clippy::inline_always,
    reason = "the selected run specialization must contain its compact flush directly"
)]
#[inline(always)]
fn flush_greedy_run<M: ExecutionMeter>(
    value: &mut ValueReduction,
    meter: &mut M,
    pending_run_bytes: &mut u64,
) -> Result<(), ReduceError> {
    if *pending_run_bytes == 0 {
        return Ok(());
    }
    record_match(value, meter, *pending_run_bytes)?;
    meter.update(|actual| {
        actual.run_flushes =
            actual
                .run_flushes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual greedy run flushes",
                })?;
        Ok(())
    })?;
    *pending_run_bytes = 0;
    Ok(())
}

#[allow(
    clippy::inline_always,
    clippy::too_many_arguments,
    reason = "the selected repetition specialization must inline its explicit fixed run state"
)]
#[inline(always)]
fn reduce_repeated_scalar<M: ExecutionMeter>(
    value: &mut ValueReduction,
    meter: &mut M,
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
        record_match(value, meter, *pending_bytes)?;
        meter.update(|actual| {
            actual.run_flushes =
                actual
                    .run_flushes
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual repeated-run flushes",
                    })?;
            Ok(())
        })?;
        *pending_bytes = 0;
        *pending_scalars = 0;
    }
    Ok(())
}

#[allow(
    clippy::inline_always,
    reason = "the selected repetition specialization must contain its terminal flush directly"
)]
#[inline(always)]
fn finish_repeated_run<M: ExecutionMeter>(
    value: &mut ValueReduction,
    meter: &mut M,
    pending_bytes: &mut u64,
    pending_scalars: &mut u64,
    minimum: u32,
    greedy: bool,
) -> Result<(), ReduceError> {
    if greedy && *pending_scalars >= u64::from(minimum) {
        record_match(value, meter, *pending_bytes)?;
        meter.update(|actual| {
            actual.run_flushes =
                actual
                    .run_flushes
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual repeated-run terminal flushes",
                    })?;
            Ok(())
        })?;
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
pub(crate) struct DecodedScalar {
    pub(crate) scalar: Option<u32>,
    pub(crate) width: usize,
    pub(crate) byte_checks: usize,
}

#[inline(never)]
pub(crate) fn decode_scalar(bytes: &[u8]) -> DecodedScalar {
    decode_scalar_inline(bytes)
}

// The dispatched exactly-one path is also the small-input path: below one
// fixed block it reaches the scalar decoder without using the retained SIMD
// classifier. Keep that decoder in the caller so unrelated ThinLTO
// monomorphizations or identical-code folding cannot add a cold text-page
// transition to a two- to four-byte operation. The general repetition path
// continues through the out-of-line wrapper above.
#[inline(always)]
fn decode_scalar_inline(bytes: &[u8]) -> DecodedScalar {
    match decode_scalar_with(bytes, || Ok::<(), core::convert::Infallible>(())) {
        Ok(decoded) => decoded,
        Err(never) => match never {},
    }
}

/// Decode one scalar with a prospective charge immediately before every
/// source-byte access. The callback permits finite-work callers to stop at an
/// exact byte boundary without duplicating or hiding a read in UTF-8 library
/// machinery.
#[allow(
    clippy::too_many_lines,
    reason = "keeping every explicit UTF-8 byte access in one decoder makes prospective charging auditable"
)]
pub(crate) fn decode_scalar_with<E>(
    bytes: &[u8],
    mut before_read: impl FnMut() -> Result<(), E>,
) -> Result<DecodedScalar, E> {
    if bytes.is_empty() {
        return Ok(DecodedScalar {
            scalar: None,
            width: 1,
            byte_checks: 0,
        });
    }
    before_read()?;
    let first = bytes[0];
    if first <= 0x7F {
        return Ok(DecodedScalar {
            scalar: Some(u32::from(first)),
            width: 1,
            byte_checks: 1,
        });
    }
    if (0xC2..=0xDF).contains(&first) {
        let Some(second) = bytes.get(1) else {
            return Ok(invalid(1));
        };
        before_read()?;
        let second = *second;
        if !is_continuation(second) {
            return Ok(invalid(2));
        }
        let scalar = (u32::from(first & 0x1F) << 6) | u32::from(second & 0x3F);
        return Ok(DecodedScalar {
            scalar: Some(scalar),
            width: 2,
            byte_checks: 2,
        });
    }
    if (0xE0..=0xEF).contains(&first) {
        let Some(second) = bytes.get(1) else {
            return Ok(invalid(1));
        };
        before_read()?;
        let second = *second;
        let second_ok = match first {
            0xE0 => (0xA0..=0xBF).contains(&second),
            0xED => (0x80..=0x9F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return Ok(invalid(2));
        }
        let Some(third) = bytes.get(2) else {
            return Ok(invalid(2));
        };
        before_read()?;
        let third = *third;
        if !is_continuation(third) {
            return Ok(invalid(3));
        }
        let scalar = (u32::from(first & 0x0F) << 12)
            | (u32::from(second & 0x3F) << 6)
            | u32::from(third & 0x3F);
        return Ok(DecodedScalar {
            scalar: Some(scalar),
            width: 3,
            byte_checks: 3,
        });
    }
    if (0xF0..=0xF4).contains(&first) {
        let Some(second) = bytes.get(1) else {
            return Ok(invalid(1));
        };
        before_read()?;
        let second = *second;
        let second_ok = match first {
            0xF0 => (0x90..=0xBF).contains(&second),
            0xF4 => (0x80..=0x8F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return Ok(invalid(2));
        }
        let Some(third) = bytes.get(2) else {
            return Ok(invalid(2));
        };
        before_read()?;
        let third = *third;
        if !is_continuation(third) {
            return Ok(invalid(3));
        }
        let Some(fourth) = bytes.get(3) else {
            return Ok(invalid(3));
        };
        before_read()?;
        let fourth = *fourth;
        if !is_continuation(fourth) {
            return Ok(invalid(4));
        }
        let scalar = (u32::from(first & 0x07) << 18)
            | (u32::from(second & 0x3F) << 12)
            | (u32::from(third & 0x3F) << 6)
            | u32::from(fourth & 0x3F);
        return Ok(DecodedScalar {
            scalar: Some(scalar),
            width: 4,
            byte_checks: 4,
        });
    }
    Ok(invalid(1))
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

/// Direct-search operation selected by a Unicode scalar-run plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchOperation {
    SelectedSpan,
    Exists,
    EarliestEnd,
}

/// Immutable identity for one direct Unicode scalar-run search operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchOperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub operation: SearchOperation,
    pub scalar_semantics: ScalarSemantics,
    pub repetition: Repetition,
    pub non_overlapping: bool,
}

impl SearchOperationIdentity {
    const fn new(operation: SearchOperation, repetition: Repetition) -> Self {
        let operation_id = match operation {
            SearchOperation::SelectedSpan => SEARCH_OPERATION_ID,
            SearchOperation::Exists => SEARCH_EXISTS_OPERATION_ID,
            SearchOperation::EarliestEnd => SEARCH_EARLIEST_END_OPERATION_ID,
        };
        Self {
            plan_id: SEARCH_PLAN_ID,
            operation_id,
            operation,
            scalar_semantics: ScalarSemantics::RustBytesUnicodeUtf8False,
            repetition,
            non_overlapping: true,
        }
    }
}

/// Complete construction accounting for a direct scalar-run search owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchBuildAccounting {
    pub scalar: BuildAccounting,
    pub leading_byte_derivation_work: usize,
    pub leading_byte_classifier_build_work: usize,
    pub leading_byte_classifier_bytes: usize,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Source-independent upper bounds for one suffix search.
/// `leading_scalar_probes` counts logical bytes examined by a sparse memchr
/// leaf, scalar tail probes after specialized complete blocks, or scalar front
/// probes made around general fixed-width classifier blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchUpperBounds {
    pub input_bytes: usize,
    pub leading_scalar_probes: usize,
    pub leading_block_classifications: usize,
    pub leading_block_classification_bytes: usize,
    pub decode_byte_checks: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub reducer_steps: usize,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact structural counters for one successful suffix search. Sparse native
/// searches charge each disjoint logical byte through the found byte, or the
/// complete searched suffix when absent; physical block traffic is reported
/// separately only by the classifier leaf.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SearchActualCounters {
    pub input_bytes_advanced: usize,
    pub leading_scalar_probes: usize,
    pub leading_block_classifications: usize,
    pub leading_block_classification_bytes: usize,
    pub decode_byte_checks: usize,
    pub valid_scalars: usize,
    pub invalid_bytes: usize,
    pub ascii_membership_tests: usize,
    pub non_ascii_membership_tests: usize,
    pub range_comparisons: usize,
    pub reducer_steps: usize,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Complete accounting for one direct scalar-run search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchAccounting {
    pub identity: SearchOperationIdentity,
    pub window: Window,
    pub upper_bounds: SearchUpperBounds,
    pub actual: SearchActualCounters,
}

/// Complete source-free envelope for Count through one retained leading-byte
/// cursor and its embedded scalar cutover owner.
///
/// A monotone cursor can examine a logical source byte at most twice: a greedy
/// selected match may inspect its first rejecting scalar before publishing the
/// preceding end, and the next restart can inspect that scalar once more. The
/// retained block masks themselves never move backward. The factor-two fields
/// below therefore cover the complete cursor prefix. They also cover any
/// one-way scalar suffix, whose pointwise per-byte bounds are no larger. The
/// separately retained scalar upper bound authenticates that suffix owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorCountUpperBounds {
    pub input_bytes: usize,
    pub leading_scalar_probes: usize,
    pub leading_block_classifications: usize,
    pub leading_block_classification_bytes: usize,
    pub decode_byte_checks: usize,
    pub membership_tests: usize,
    pub range_comparisons: usize,
    pub reducer_steps: usize,
    pub search_calls: usize,
    pub match_events: usize,
    pub count: u64,
    pub work: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    /// Full-window scalar bound retained before source access. Execution can
    /// safely project it onto the semantic cutover suffix. A greedy cursor may
    /// already have decoded the suffix's first rejecting scalar before it
    /// publishes the preceding match end.
    pub scalar_cutover: ReduceUpperBounds,
}

/// Exact operation-level counters for one successful cursor Count.
///
/// Candidate classification and decoding remain value-only. Their complete
/// prospective envelope is published in [`CursorCountUpperBounds`], while
/// these counters expose every externally visible control-flow effect without
/// adding per-candidate instrumentation to the optimized path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CursorCountActualCounters {
    pub input_bytes_advanced: usize,
    /// Length of the semantic prefix whose matches are owned by the cursor.
    /// This is a handoff partition, not a physical-read count: greedy search
    /// can decode the first rejecting scalar in the suffix before publishing
    /// the preceding match end.
    pub cursor_semantic_prefix_bytes: usize,
    /// Length of the semantic suffix delegated to the scalar reducer. It is
    /// disjoint from `cursor_semantic_prefix_bytes` as match ownership, even
    /// when the cursor has already probed its first scalar.
    pub scalar_semantic_suffix_bytes: usize,
    pub search_calls: usize,
    pub cursor_match_events: usize,
    pub dense_samples: usize,
    pub dense_cutover: bool,
    pub count: u64,
    /// Exact externally visible search-call plus match-event effects only.
    /// This excludes classification, decoding, membership, range, and scalar
    /// suffix work and must never be substituted for total facade work.
    pub control_work: usize,
}

/// Upper bounds and exact control counters for one cursor Count result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorCountAccounting {
    pub identity: OperationIdentity,
    pub window: Window,
    pub upper_bounds: CursorCountUpperBounds,
    pub actual: CursorCountActualCounters,
}

/// Result of one complete leading-byte cursor Count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorCountResult {
    pub count: u64,
    pub accounting: CursorCountAccounting,
}

/// Limits checked before one direct scalar-run search touches its source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_work: usize,
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work: usize::MAX,
            max_scratch_bytes: 0,
        }
    }
}

/// Checked direct scalar-run search failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for SearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Unicode scalar-run search failed: {self:?}")
    }
}

impl std::error::Error for SearchError {}

/// Native search plan for one positive root Unicode scalar-class repetition.
///
/// The leading-byte search is a conservative prefilter: every valid UTF-8
/// encoding of a member scalar has its first byte in this set, but candidates
/// are always decoded and checked against the exact retained scalar ranges.
/// Sets of one to three bytes use the corresponding native memchr primitive.
/// Sets of four to sixteen bytes use one compiler-static SVE2 table leaf when
/// available, while other profiles retain the general classifier.
#[derive(Debug)]
pub struct UnicodeScalarSearchPlan {
    scalar: UnicodeScalarAggregatePlan,
    leading: ByteSetClassifier,
    leading_search: LeadingByteSearch,
    build: SearchBuildAccounting,
}

/// Construction-selected owner for Unicode scalar Count.
///
/// Both variants retain the one scalar plan materialized by the attempt. A
/// broad leading-byte mask publishes that plan directly, without allocating
/// or initializing a cursor wrapper or classifier.
#[derive(Debug)]
pub enum CursorCountBuild {
    Cursor {
        plan: UnicodeScalarSearchPlan,
        leading_byte_count: usize,
    },
    Scalar {
        plan: UnicodeScalarAggregatePlan,
        leading_byte_count: usize,
    },
}

impl CursorCountBuild {
    /// Exact cardinality of the conservative leading-byte mask derived from
    /// the retained canonical scalar ranges.
    #[must_use]
    pub const fn leading_byte_count(&self) -> usize {
        match self {
            Self::Cursor {
                leading_byte_count,
                ..
            }
            | Self::Scalar {
                leading_byte_count,
                ..
            } => *leading_byte_count,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeadingByteSearch {
    Classifier,
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    Small([u8; 16]),
}

impl LeadingByteSearch {
    const fn uses_block_classification(self) -> bool {
        match self {
            Self::Classifier => true,
            #[cfg(all(
                feature = "static-dispatch-arm-41-d84",
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_feature = "sve",
                target_feature = "sve2"
            ))]
            Self::Small(_) => true,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct UnicodeScalarSearchCursorState {
    cached_non_ascii_range: Option<usize>,
    leading_block_base: usize,
    leading_block_mask: u32,
    restart_floor: usize,
    leading_block_valid: bool,
}

/// Search continuation bound by immutable borrows to exactly one plan and
/// one haystack. Source-derived masks cannot outlive either borrow.
/// The inline state remains smaller than the facade's established cursor cap.
#[derive(Clone, Copy, Debug)]
pub struct UnicodeScalarSearchCursor<'p, 'h> {
    plan: &'p UnicodeScalarSearchPlan,
    haystack: &'h [u8],
    state: UnicodeScalarSearchCursorState,
}

impl UnicodeScalarSearchPlan {
    /// Build a direct search owner for one canonical positive scalar-class
    /// repetition and one already-authenticated dispatch snapshot.
    pub fn build_repeated_with_dispatch(
        dispatch: SimdDispatchContext,
        ranges: impl IntoIterator<Item = (char, char)>,
        minimum: u32,
        maximum: Option<u32>,
        greedy: bool,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_repeated_attempt_with_dispatch(
            dispatch, ranges, minimum, maximum, greedy, limits,
        )
        .map(DirectBuildAttempt::into_plan)
        .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build a direct search owner while retaining the exact observed effects
    /// from scalar materialization through allocation-free wrapper
    /// publication.
    #[allow(
        clippy::too_many_lines,
        reason = "the attempt boundary keeps nested scalar effects, allocation-free search derivation, resource refusals, and final publication in one auditable transaction"
    )]
    pub fn build_repeated_attempt_with_dispatch(
        dispatch: SimdDispatchContext,
        ranges: impl IntoIterator<Item = (char, char)>,
        minimum: u32,
        maximum: Option<u32>,
        greedy: bool,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let attempt = Self::build_repeated_routed_attempt_with_dispatch(
            dispatch,
            ranges,
            minimum,
            maximum,
            greedy,
            LEGAL_SCALAR_START_BYTE_COUNT,
            limits,
        )?;
        let (selection, actual) = attempt.into_parts();
        let CursorCountBuild::Cursor { plan, .. } = selection else {
            unreachable!("every canonical scalar class fits the legal start-byte domain")
        };
        Ok(DirectBuildAttempt::new(plan, actual))
    }

    /// Build the Count owner selected by the fixed source-independent
    /// leading-byte cardinality gate. Broad masks publish the already-built
    /// scalar plan; selective masks retain the cursor wrapper.
    pub fn build_repeated_count_attempt_with_dispatch(
        dispatch: SimdDispatchContext,
        ranges: impl IntoIterator<Item = (char, char)>,
        minimum: u32,
        maximum: Option<u32>,
        greedy: bool,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<CursorCountBuild>, DirectBuildAttemptError<BuildError>> {
        Self::build_repeated_routed_attempt_with_dispatch(
            dispatch,
            ranges,
            minimum,
            maximum,
            greedy,
            CURSOR_COUNT_MAX_LEADING_BYTE_COUNT,
            limits,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the private routed attempt keeps scalar ownership, exact selection work, wrapper construction, and every terminal effect in one transaction"
    )]
    fn build_repeated_routed_attempt_with_dispatch(
        dispatch: SimdDispatchContext,
        ranges: impl IntoIterator<Item = (char, char)>,
        minimum: u32,
        maximum: Option<u32>,
        greedy: bool,
        max_leading_byte_count: usize,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<CursorCountBuild>, DirectBuildAttemptError<BuildError>> {
        let attempt = UnicodeScalarAggregatePlan::build_repeated_attempt(
            ranges, minimum, maximum, greedy, limits,
        )?;
        let (scalar, mut actual) = attempt.into_parts();
        let result = (|| {
            let scalar_build = scalar.build_accounting();
            debug_assert_eq!(actual.work, u64::try_from(scalar_build.work).unwrap_or(u64::MAX));
            debug_assert_eq!(actual.live_persistent_bytes, scalar_build.persistent_bytes);
            let (leading_set, leading_byte_derivation_work) = scalar.leading_byte_set()?;
            let (leading_search, leading_byte_count) =
                select_leading_byte_search_and_cardinality(leading_set);
            let leading_byte_derivation_work = leading_byte_derivation_work
                .checked_add(SEARCH_LEADING_SELECTION_WORK)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "Unicode scalar leading-search selection work",
                })?;
            actual.work = actual
                .work
                .checked_add(u64::try_from(leading_byte_derivation_work).map_err(|_| {
                    BuildError::ArithmeticOverflow {
                        computation: "actual Unicode scalar leading-search work as u64",
                    }
                })?)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual Unicode scalar leading-search work",
                })?;

            let routed_scalar_work = scalar_build
                .work
                .checked_add(leading_byte_derivation_work)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "Unicode scalar Count routing work",
                })?;
            enforce_build(
                routed_scalar_work,
                limits.max_build_work,
                BuildResource::Work,
            )?;
            if leading_byte_count > max_leading_byte_count {
                let mut scalar = scalar;
                scalar.build.work = routed_scalar_work;
                debug_assert_eq!(
                    actual.work,
                    u64::try_from(scalar.build.work).unwrap_or(u64::MAX)
                );
                return Ok(CursorCountBuild::Scalar {
                    plan: scalar,
                    leading_byte_count,
                });
            }

            let leading = dispatch
                .byte_set_classifier(leading_set, DispatchPolicy::Auto)
                .expect("automatic byte-set dispatch always retains a fallback");
            let leading_byte_classifier_bytes = size_of::<ByteSetClassifier>();
            let leading_byte_classifier_build_work = BYTE_SET_CLASSIFIER_BUILD_WORK;
            actual.work = actual
                .work
                .checked_add(
                    u64::try_from(leading_byte_classifier_build_work).map_err(|_| {
                        BuildError::ArithmeticOverflow {
                            computation: "actual Unicode scalar classifier work as u64",
                        }
                    })?,
                )
                .and_then(|work| work.checked_add(1))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual Unicode scalar search build work",
                })?;
            let work = routed_scalar_work
                .checked_add(leading_byte_classifier_build_work)
                .and_then(|work| work.checked_add(1))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "Unicode scalar search build work",
                })?;
            debug_assert_eq!(actual.work, u64::try_from(work).unwrap_or(u64::MAX));
            enforce_build(work, limits.max_build_work, BuildResource::Work)?;

            let wrapper_bytes = size_of::<Self>()
                .checked_sub(size_of::<UnicodeScalarAggregatePlan>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "Unicode scalar search wrapper bytes",
                })?;
            let persistent_bytes = scalar_build
                .persistent_bytes
                .checked_add(wrapper_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "Unicode scalar search persistent bytes",
                })?;
            let scratch_bytes = scalar_build.scratch_bytes;
            let peak_bytes = scalar_build.peak_bytes.max(persistent_bytes);
            enforce_build(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;
            let build = SearchBuildAccounting {
                scalar: scalar_build,
                leading_byte_derivation_work,
                leading_byte_classifier_build_work,
                leading_byte_classifier_bytes,
                work,
                scratch_bytes,
                persistent_bytes,
                peak_bytes,
            };
            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(wrapper_bytes)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual Unicode scalar search initialized bytes",
                })?;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = actual.peak_bytes.max(persistent_bytes);
            Ok(CursorCountBuild::Cursor {
                plan: Self {
                    scalar,
                    leading,
                    leading_search,
                    build,
                },
                leading_byte_count,
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
    pub const fn build_accounting(&self) -> SearchBuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn repetition(&self) -> Repetition {
        self.scalar.repetition
    }

    #[must_use]
    pub fn has_non_ascii_members(&self) -> bool {
        !self.scalar.non_ascii.is_empty()
    }

    #[must_use]
    pub const fn selected_identity(&self) -> SearchOperationIdentity {
        SearchOperationIdentity::new(SearchOperation::SelectedSpan, self.scalar.repetition)
    }

    #[must_use]
    pub const fn exists_identity(&self) -> SearchOperationIdentity {
        SearchOperationIdentity::new(SearchOperation::Exists, self.scalar.repetition)
    }

    #[must_use]
    pub const fn earliest_end_identity(&self) -> SearchOperationIdentity {
        SearchOperationIdentity::new(SearchOperation::EarliestEnd, self.scalar.repetition)
    }

    /// Identity for Count through the retained leading-byte cursor.
    #[must_use]
    pub const fn cursor_count_identity(&self) -> OperationIdentity {
        OperationIdentity {
            plan_id: CURSOR_COUNT_PLAN_ID,
            operation_id: CURSOR_COUNT_OPERATION_ID,
            operation: Operation::Count,
            scalar_semantics: ScalarSemantics::RustBytesUnicodeUtf8False,
            repetition: self.scalar.repetition,
            non_overlapping: true,
        }
    }

    pub fn search_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<SearchUpperBounds, SearchError> {
        let leading_scalar_probes = input_bytes;
        let (leading_block_classifications, leading_block_classification_bytes) =
            if self.leading_search.uses_block_classification() {
                let classifications = input_bytes
                    .checked_add(BYTE_SET_WIDE_BLOCK_BYTES.saturating_sub(1))
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "Unicode scalar search block count numerator",
                    })?
                    / BYTE_SET_WIDE_BLOCK_BYTES;
                let bytes = classifications.checked_mul(BYTE_SET_WIDE_BLOCK_BYTES).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "Unicode scalar search block bytes",
                    },
                )?;
                (classifications, bytes)
            } else {
                (0, 0)
            };
        let decode_byte_checks = input_bytes.checked_mul(4).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "Unicode scalar search decode checks",
            },
        )?;
        let membership_tests = input_bytes;
        let comparisons_per_scalar = binary_search_comparison_bound(
            self.build.scalar.retained_non_ascii_ranges,
        )
        .checked_add(1)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "Unicode scalar search cached comparison bound",
        })?;
        let range_comparisons = input_bytes.checked_mul(comparisons_per_scalar).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "Unicode scalar search range comparisons",
            },
        )?;
        let reducer_steps = input_bytes;
        let work = leading_scalar_probes
            .checked_add(leading_block_classification_bytes)
            .and_then(|work| work.checked_add(decode_byte_checks))
            .and_then(|work| work.checked_add(membership_tests))
            .and_then(|work| work.checked_add(range_comparisons))
            .and_then(|work| work.checked_add(reducer_steps))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "Unicode scalar search work",
            })?;
        Ok(SearchUpperBounds {
            input_bytes,
            leading_scalar_probes,
            leading_block_classifications,
            leading_block_classification_bytes,
            decode_byte_checks,
            membership_tests,
            range_comparisons,
            reducer_steps,
            work,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        })
    }

    /// Derive the complete source-free envelope for Count through one
    /// monotone leading-byte cursor, including its optional scalar cutover.
    pub fn cursor_count_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<CursorCountUpperBounds, ReduceError> {
        let twice_input = input_bytes
            .checked_mul(2)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count doubled input bytes",
            })?;
        let leading_scalar_probes = twice_input;
        let (leading_block_classifications, leading_block_classification_bytes) =
            if self.leading_search.uses_block_classification() {
                let classifications = input_bytes
                    .checked_add(BYTE_SET_WIDE_BLOCK_BYTES.saturating_sub(1))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "Unicode scalar cursor Count block numerator",
                    })?
                    / BYTE_SET_WIDE_BLOCK_BYTES;
                let bytes = classifications.checked_mul(BYTE_SET_WIDE_BLOCK_BYTES).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "Unicode scalar cursor Count block bytes",
                    },
                )?;
                (classifications, bytes)
            } else {
                (0, 0)
            };
        let decode_byte_checks = twice_input
            .checked_mul(4)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count decode checks",
            })?;
        let membership_tests = twice_input;
        let scalar_cutover = derive_reduce_upper_bounds(
            self.build.scalar,
            input_bytes,
            ReduceImplementation::Scalar,
        )?;
        let cursor_comparisons_per_scalar =
            binary_search_comparison_bound(self.build.scalar.retained_non_ascii_ranges)
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "Unicode scalar cursor Count comparison allowance",
                })?;
        let comparisons_per_scalar = cursor_comparisons_per_scalar
            .max(scalar_cutover.binary_search_comparisons_per_scalar);
        let range_comparisons = twice_input.checked_mul(comparisons_per_scalar).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count range comparisons",
            },
        )?;
        let reducer_steps = twice_input
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count reducer steps",
            })?;
        let search_calls = input_bytes
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count search calls",
            })?;
        let match_events = input_bytes;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "Unicode scalar cursor Count result bound",
        })?;
        let work = leading_scalar_probes
            .checked_add(leading_block_classification_bytes)
            .and_then(|work| work.checked_add(decode_byte_checks))
            .and_then(|work| work.checked_add(membership_tests))
            .and_then(|work| work.checked_add(range_comparisons))
            .and_then(|work| work.checked_add(reducer_steps))
            .and_then(|work| work.checked_add(search_calls))
            .and_then(|work| work.checked_add(match_events))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count work",
            })?;
        Ok(CursorCountUpperBounds {
            input_bytes,
            leading_scalar_probes,
            leading_block_classifications,
            leading_block_classification_bytes,
            decode_byte_checks,
            membership_tests,
            range_comparisons,
            reducer_steps,
            search_calls,
            match_events,
            count,
            work,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
            scalar_cutover,
        })
    }

    /// Count every leftmost-first non-overlapping selected span through the
    /// retained leading-byte cursor.
    pub fn count_with_cursor(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CursorCountResult, ReduceError> {
        self.count_with_cursor_in(haystack, Window::full(haystack), limits)
    }

    /// Value-only counterpart to [`Self::count_with_cursor`].
    pub fn count_with_cursor_value(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<u64, ReduceError> {
        self.count_with_cursor_value_in(haystack, Window::full(haystack), limits)
    }

    /// Count within one validated byte window and publish exact operation
    /// control counters beside the complete prospective envelope.
    pub fn count_with_cursor_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<CursorCountResult, ReduceError> {
        let upper_bounds = self.preflight_cursor_count(haystack, window, limits)?;
        let (count, actual) = self.execute_cursor_count(haystack, window, upper_bounds)?;
        Ok(CursorCountResult {
            count,
            accounting: CursorCountAccounting {
                identity: self.cursor_count_identity(),
                window,
                upper_bounds,
                actual,
            },
        })
    }

    /// Value-only Count within one validated byte window.
    pub fn count_with_cursor_value_in(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<u64, ReduceError> {
        let upper_bounds = self.preflight_cursor_count(haystack, window, limits)?;
        self.execute_cursor_count(haystack, window, upper_bounds)
            .map(|(count, _)| count)
    }

    fn preflight_cursor_count(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ReduceLimits,
    ) -> Result<CursorCountUpperBounds, ReduceError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(ReduceError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let input_bytes = window.end().checked_sub(window.start()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count window bytes",
            },
        )?;
        let upper = self.cursor_count_upper_bounds(input_bytes)?;
        enforce_reduce(
            input_bytes,
            limits.max_input_bytes,
            ReduceResource::InputBytes,
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
            upper.reducer_steps,
            limits.max_reducer_steps,
            ReduceResource::ReducerSteps,
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
        enforce_reduce(upper.work, limits.max_work, ReduceResource::Work)?;
        enforce_reduce(
            upper.scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        )?;
        enforce_reduce(upper.peak_bytes, limits.max_peak_bytes, ReduceResource::Peak)?;
        Ok(upper)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the complete cursor Count preflight proves every monotone restart, count, dense-sample, and control-work increment"
    )]
    fn execute_cursor_count(
        &self,
        haystack: &[u8],
        window: Window,
        upper: CursorCountUpperBounds,
    ) -> Result<(u64, CursorCountActualCounters), ReduceError> {
        let mut cursor = self.search_cursor(haystack);
        let mut restart = window.start();
        let mut count = 0_u64;
        let mut search_calls = 0_usize;
        let mut cursor_match_events = 0_usize;
        let mut dense_samples = 0_usize;
        let mut sample_start = 0_usize;
        let mut sample_matches = 0_usize;
        let mut dense_cutover = false;
        let mut scalar_semantic_suffix_bytes = 0_usize;

        loop {
            search_calls += 1;
            let Some((start, end)) = cursor.find_at_value_preflighted(restart, window.end()) else {
                break;
            };
            debug_assert!(start >= restart && end > start && end <= window.end());
            count += 1;
            cursor_match_events += 1;
            if sample_matches == 0 {
                sample_start = start;
            }
            sample_matches += 1;
            restart = end;

            if sample_matches == CURSOR_COUNT_DENSE_SAMPLE_MATCHES {
                dense_samples += 1;
                let sampled_bytes = end - sample_start;
                let dense_bytes = CURSOR_COUNT_DENSE_SAMPLE_MATCHES
                    * CURSOR_COUNT_DENSE_MAX_MEAN_BYTES;
                if sampled_bytes <= dense_bytes {
                    dense_cutover = true;
                    scalar_semantic_suffix_bytes = window.end() - restart;
                    let suffix = self.scalar.execute_value(
                        haystack,
                        Window::new(restart, window.end()),
                        upper.scalar_cutover,
                    )?;
                    count += suffix.count;
                    break;
                }
                sample_matches = 0;
            }
        }

        let input_bytes = window.end() - window.start();
        let cursor_semantic_prefix_bytes = input_bytes - scalar_semantic_suffix_bytes;
        let match_events = usize::try_from(count).map_err(|_| {
            ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count actual match events",
            }
        })?;
        let control_work = search_calls.checked_add(match_events).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "Unicode scalar cursor Count actual control work",
            },
        )?;
        debug_assert!(search_calls <= upper.search_calls);
        debug_assert!(match_events <= upper.match_events);
        debug_assert!(count <= upper.count);
        debug_assert!(control_work <= upper.search_calls.saturating_add(upper.match_events));
        Ok((
            count,
            CursorCountActualCounters {
                input_bytes_advanced: input_bytes,
                cursor_semantic_prefix_bytes,
                scalar_semantic_suffix_bytes,
                search_calls,
                cursor_match_events,
                dense_samples,
                dense_cutover,
                count,
                control_work,
            },
        ))
    }

    #[must_use]
    pub const fn search_cursor<'p, 'h>(
        &'p self,
        haystack: &'h [u8],
    ) -> UnicodeScalarSearchCursor<'p, 'h> {
        UnicodeScalarSearchCursor {
            plan: self,
            haystack,
            state: UnicodeScalarSearchCursorState {
                cached_non_ascii_range: None,
                leading_block_base: 0,
                leading_block_mask: 0,
                restart_floor: 0,
                leading_block_valid: false,
            },
        }
    }

    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let mut cursor = self.search_cursor(haystack);
        cursor.search_window::<true>(window, limits, SearchOperation::SelectedSpan)
    }

    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        let mut cursor = self.search_cursor(haystack);
        cursor.search_window_value::<true>(window, limits)
    }

    pub fn is_match_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        let mut cursor = self.search_cursor(haystack);
        cursor
            .search_window::<false>(window, limits, SearchOperation::Exists)
            .map(|(matched, accounting)| (matched.is_some(), accounting))
    }

    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        let mut cursor = self.search_cursor(haystack);
        cursor
            .search_window_value::<false>(window, limits)
            .map(|matched| matched.is_some())
    }

    pub fn shortest_match_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        let mut cursor = self.search_cursor(haystack);
        cursor
            .search_window::<false>(window, limits, SearchOperation::EarliestEnd)
            .map(|(matched, accounting)| (matched.map(|(_, end)| end), accounting))
    }

    pub fn shortest_match_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<usize>, SearchError> {
        let mut cursor = self.search_cursor(haystack);
        cursor
            .search_window_value::<false>(window, limits)
            .map(|matched| matched.map(|(_, end)| end))
    }

    fn preflight(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<SearchUpperBounds, SearchError> {
        let input_bytes = Self::validated_window_bytes(haystack, window)?;
        self.preflight_validated(input_bytes, limits)
    }

    fn preflight_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<(), SearchError> {
        let input_bytes = Self::validated_window_bytes(haystack, window)?;
        if limits == SearchLimits::unlimited()
            && input_bytes <= SEARCH_VALUE_PREFLIGHT_MAX_INPUT_BYTES
        {
            return Ok(());
        }
        self.preflight_validated(input_bytes, limits).map(drop)
    }

    fn validated_window_bytes(haystack: &[u8], window: Window) -> Result<usize, SearchError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(SearchError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        window.end().checked_sub(window.start()).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "Unicode scalar search window bytes",
            },
        )
    }

    fn preflight_validated(
        &self,
        input_bytes: usize,
        limits: SearchLimits,
    ) -> Result<SearchUpperBounds, SearchError> {
        let upper = self.search_upper_bounds(input_bytes)?;
        if upper.work > limits.max_work {
            return Err(SearchError::WorkLimit {
                needed: upper.work,
                limit: limits.max_work,
            });
        }
        if upper.scratch_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ScratchLimit {
                needed: upper.scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        Ok(upper)
    }
}

impl UnicodeScalarAggregatePlan {
    fn leading_byte_set(&self) -> Result<(ByteSet256, usize), BuildError> {
        let mut words = [self.ascii[0], self.ascii[1], 0, 0];
        let mut work = 2_usize;
        for range in &self.non_ascii {
            for byte in 0xC2_u8..=0xF4 {
                work = work.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
                    computation: "Unicode scalar leading-byte derivation work",
                })?;
                let (start, end) = utf8_lead_scalar_interval(byte);
                if range.start <= end && range.end >= start {
                    let word_index = usize::from(byte / 64);
                    let bit = u32::from(byte % 64);
                    words[word_index] |= 1_u64 << bit;
                }
            }
        }
        Ok((ByteSet256::from_words(words), work))
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the search preflight bounds every comparison count and binary-search index"
    )]
    fn search_contains_non_ascii<const METERED: bool>(
        &self,
        scalar: u32,
        cached: &mut Option<usize>,
        actual: &mut SearchActualCounters,
    ) -> bool {
        if let Some(index) = *cached
            && let Some(range) = self.non_ascii.get(index)
        {
            if METERED {
                actual.range_comparisons += 1;
            }
            if scalar >= range.start && scalar <= range.end {
                return true;
            }
        }
        let mut low = 0_usize;
        let mut high = self.non_ascii.len();
        while low < high {
            if METERED {
                actual.range_comparisons += 1;
            }
            let middle = low + (high - low) / 2;
            let range = self.non_ascii[middle];
            if scalar < range.start {
                high = middle;
            } else if scalar > range.end {
                low = middle + 1;
            } else {
                *cached = Some(middle);
                return true;
            }
        }
        *cached = None;
        false
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the complete byte domain bounds the member count to 256"
)]
fn select_leading_byte_search_and_cardinality(
    set: ByteSet256,
) -> (LeadingByteSearch, usize) {
    let mut selected = [0_u8; 16];
    let mut count = 0_usize;
    for value in 0_u16..=u16::from(u8::MAX) {
        let byte = u8::try_from(value).expect("the enumerated byte domain fits u8");
        if set.contains(byte) {
            if let Some(slot) = selected.get_mut(count) {
                *slot = byte;
            }
            count += 1;
        }
    }
    let search = match count {
        1 => LeadingByteSearch::One(selected[0]),
        2 => LeadingByteSearch::Two(selected[0], selected[1]),
        3 => LeadingByteSearch::Three(selected[0], selected[1], selected[2]),
        #[cfg(all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ))]
        4..=16 => {
            let duplicate = selected[0];
            selected[count..].fill(duplicate);
            LeadingByteSearch::Small(selected)
        }
        #[cfg(not(all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        )))]
        4..=16 => LeadingByteSearch::Classifier,
        _ => LeadingByteSearch::Classifier,
    };
    (search, count)
}

impl<'h> UnicodeScalarSearchCursor<'_, 'h> {
    #[must_use]
    pub const fn haystack(&self) -> &'h [u8] {
        self.haystack
    }

    pub fn find_at(
        &mut self,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        self.search_window::<true>(
            Window::new(start, self.haystack.len()),
            limits,
            SearchOperation::SelectedSpan,
        )
    }

    pub fn find_at_value(
        &mut self,
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        self.search_window_value::<true>(Window::new(start, self.haystack.len()), limits)
    }

    /// Execute one already-preflighted monotone selected-span restart. The
    /// enclosing Count owner proves the complete window and all arithmetic
    /// before the first source read, so this leaf cannot introduce a late
    /// resource refusal between match events.
    fn find_at_value_preflighted(
        &mut self,
        start: usize,
        end: usize,
    ) -> Option<(usize, usize)> {
        let window = Window::new(start, end);
        let mut state = self.state_for_start(start);
        let (matched, _) = self.execute::<false, true>(window, &mut state);
        Self::publish_restart_floor(&mut state, start, matched);
        self.state = state;
        matched
    }

    fn state_for_start(&self, start: usize) -> UnicodeScalarSearchCursorState {
        let mut state = self.state;
        if start < state.restart_floor {
            state.leading_block_base = 0;
            state.leading_block_mask = 0;
            state.leading_block_valid = false;
        }
        state
    }

    fn publish_restart_floor(
        state: &mut UnicodeScalarSearchCursorState,
        requested_start: usize,
        matched: Option<(usize, usize)>,
    ) {
        state.restart_floor = matched.map_or(requested_start, |(start, _)| start);
    }

    fn search_window_value<const SELECTED: bool>(
        &mut self,
        window: Window,
        limits: SearchLimits,
    ) -> Result<Option<(usize, usize)>, SearchError> {
        self.plan.preflight_value(self.haystack, window, limits)?;
        let mut state = self.state_for_start(window.start());
        let (matched, _) = self.execute::<false, SELECTED>(window, &mut state);
        Self::publish_restart_floor(&mut state, window.start(), matched);
        self.state = state;
        Ok(matched)
    }

    fn search_window<const SELECTED: bool>(
        &mut self,
        window: Window,
        limits: SearchLimits,
        operation: SearchOperation,
    ) -> Result<(Option<(usize, usize)>, SearchAccounting), SearchError> {
        let upper_bounds = self.plan.preflight(self.haystack, window, limits)?;
        let mut state = self.state_for_start(window.start());
        let (matched, mut actual) = self.execute::<true, SELECTED>(window, &mut state);
        actual.work = actual
            .leading_scalar_probes
            .checked_add(actual.leading_block_classification_bytes)
            .and_then(|work| work.checked_add(actual.decode_byte_checks))
            .and_then(|work| {
                work.checked_add(
                    actual
                        .ascii_membership_tests
                        .checked_add(actual.non_ascii_membership_tests)?,
                )
            })
            .and_then(|work| work.checked_add(actual.range_comparisons))
            .and_then(|work| work.checked_add(actual.reducer_steps))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "Unicode scalar search actual work",
            })?;
        debug_assert!(actual.leading_scalar_probes <= upper_bounds.leading_scalar_probes);
        debug_assert!(
            actual.leading_block_classifications <= upper_bounds.leading_block_classifications
        );
        debug_assert!(
            actual.leading_block_classification_bytes
                <= upper_bounds.leading_block_classification_bytes
        );
        debug_assert!(actual.decode_byte_checks <= upper_bounds.decode_byte_checks);
        debug_assert!(
            actual
                .ascii_membership_tests
                .checked_add(actual.non_ascii_membership_tests)
                .is_some_and(|tests| tests <= upper_bounds.membership_tests)
        );
        debug_assert!(actual.range_comparisons <= upper_bounds.range_comparisons);
        debug_assert!(actual.reducer_steps <= upper_bounds.reducer_steps);
        debug_assert!(actual.work <= upper_bounds.work);
        Self::publish_restart_floor(&mut state, window.start(), matched);
        self.state = state;
        let identity = match operation {
            SearchOperation::SelectedSpan => self.plan.selected_identity(),
            SearchOperation::Exists => self.plan.exists_identity(),
            SearchOperation::EarliestEnd => self.plan.earliest_end_identity(),
        };
        Ok((
            matched,
            SearchAccounting {
                identity,
                window,
                upper_bounds,
                actual,
            },
        ))
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "preflight proves every cursor and counter increment within the checked source window and its source-independent bounds"
    )]
    fn execute<const METERED: bool, const SELECTED: bool>(
        &self,
        window: Window,
        state: &mut UnicodeScalarSearchCursorState,
    ) -> (Option<(usize, usize)>, SearchActualCounters) {
        let (minimum, maximum, greedy) = self
            .plan
            .scalar
            .repetition
            .bounds()
            .expect("a search plan always retains a positive repetition");
        let minimum = usize::try_from(minimum).expect("u32 repetition fits usize");
        let maximum = maximum.map(|value| usize::try_from(value).expect("u32 fits usize"));
        let mut actual = SearchActualCounters::default();
        let mut position = window.start();
        let mut first = true;
        while position < window.end() {
            if !first {
                let Some(candidate) = self.next_leading::<METERED>(
                    position,
                    window.end(),
                    state,
                    &mut actual,
                ) else {
                    actual.input_bytes_advanced = window.end() - window.start();
                    return (None, actual);
                };
                position = candidate;
            }
            first = false;
            let decoded = decode_scalar(&self.haystack[position..window.end()]);
            if METERED {
                actual.decode_byte_checks += decoded.byte_checks;
                actual.reducer_steps += 1;
            }
            let member = self.decoded_member::<METERED>(decoded, state, &mut actual);
            if !member {
                position += decoded.width;
                continue;
            }

            let start = position;
            let mut count = 1_usize;
            position += decoded.width;
            if !SELECTED && count == minimum {
                actual.input_bytes_advanced = position - window.start();
                return (Some((start, position)), actual);
            }
            if SELECTED && !greedy && count == minimum {
                actual.input_bytes_advanced = position - window.start();
                return (Some((start, position)), actual);
            }
            if SELECTED && greedy && maximum == Some(count) {
                actual.input_bytes_advanced = position - window.start();
                return (Some((start, position)), actual);
            }
            while position < window.end() {
                let decoded = decode_scalar(&self.haystack[position..window.end()]);
                if METERED {
                    actual.decode_byte_checks += decoded.byte_checks;
                    actual.reducer_steps += 1;
                }
                if !self.decoded_member::<METERED>(decoded, state, &mut actual) {
                    let end = position;
                    position += decoded.width;
                    if SELECTED && greedy && count >= minimum {
                        actual.input_bytes_advanced = position - window.start();
                        return (Some((start, end)), actual);
                    }
                    break;
                }
                count += 1;
                position += decoded.width;
                if !SELECTED && count == minimum {
                    actual.input_bytes_advanced = position - window.start();
                    return (Some((start, position)), actual);
                }
                if SELECTED {
                    let selected_count = if greedy {
                        maximum == Some(count)
                    } else {
                        count == minimum
                    };
                    if selected_count {
                        actual.input_bytes_advanced = position - window.start();
                        return (Some((start, position)), actual);
                    }
                }
            }
            if SELECTED && greedy && count >= minimum {
                actual.input_bytes_advanced = position - window.start();
                return (Some((start, position)), actual);
            }
        }
        actual.input_bytes_advanced = position.saturating_sub(window.start());
        (None, actual)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "fixed block extents and bit lanes are checked before every operation"
    )]
    fn next_leading<const METERED: bool>(
        &self,
        position: usize,
        end: usize,
        state: &mut UnicodeScalarSearchCursorState,
        actual: &mut SearchActualCounters,
    ) -> Option<usize> {
        let searched = &self.haystack[position..end];
        let sparse_relative = match &self.plan.leading_search {
            LeadingByteSearch::One(first) => memchr(*first, searched),
            LeadingByteSearch::Two(first, second) => memchr2(*first, *second, searched),
            LeadingByteSearch::Three(first, second, third) => {
                memchr3(*first, *second, *third, searched)
            }
            #[cfg(all(
                feature = "static-dispatch-arm-41-d84",
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_feature = "sve",
                target_feature = "sve2"
            ))]
            LeadingByteSearch::Small(match_values) => {
                return self.next_leading_small::<METERED>(
                    position,
                    end,
                    match_values,
                    state,
                    actual,
                );
            }
            LeadingByteSearch::Classifier => {
                return self.next_leading_classifier::<METERED>(position, end, state, actual);
            }
        };
        if METERED {
            actual.leading_scalar_probes +=
                sparse_relative.map_or(searched.len(), |relative| relative + 1);
        }
        sparse_relative.and_then(|relative| position.checked_add(relative))
    }

    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "fixed block extents and bit lanes are checked before every operation"
    )]
    fn next_leading_small<const METERED: bool>(
        &self,
        mut position: usize,
        end: usize,
        match_values: &[u8; 16],
        state: &mut UnicodeScalarSearchCursorState,
        actual: &mut SearchActualCounters,
    ) -> Option<usize> {
        while position < end {
            if state.leading_block_valid {
                let block_end = state.leading_block_base + BYTE_SET_WIDE_BLOCK_BYTES;
                if position >= state.leading_block_base && position < block_end {
                    let offset = position - state.leading_block_base;
                    let allowed = u32::MAX.checked_shl(u32::try_from(offset).ok()?).unwrap_or(0);
                    let candidates = state.leading_block_mask & allowed;
                    if candidates != 0 {
                        let lane = usize::try_from(candidates.trailing_zeros()).ok()?;
                        state.leading_block_mask &= !(1_u32 << lane);
                        return state.leading_block_base.checked_add(lane);
                    }
                    position = block_end;
                    state.leading_block_valid = false;
                    continue;
                }
                state.leading_block_valid = false;
            }

            let remaining = end - position;
            let complete_bytes = remaining - remaining % BYTE_SET_WIDE_BLOCK_BYTES;
            if complete_bytes != 0 {
                // Avoid paying the fixed-block launch cost when the value-only
                // search is already positioned on a possible scalar start.
                if !METERED && self.plan.leading.set().contains(self.haystack[position]) {
                    return Some(position);
                }
                let searched = &self.haystack[position..position + complete_bytes];
                if let Some((relative, mask)) =
                    fre_simd_kernels::find_byte_values16_32_block(match_values, searched)
                {
                    let blocks = relative / BYTE_SET_WIDE_BLOCK_BYTES + 1;
                    let classified_bytes = blocks * BYTE_SET_WIDE_BLOCK_BYTES;
                    if METERED {
                        actual.leading_block_classifications += blocks;
                        actual.leading_block_classification_bytes += classified_bytes;
                    }
                    state.leading_block_base = position + relative;
                    state.leading_block_mask = mask.member_mask();
                    state.leading_block_valid = true;
                    position = state.leading_block_base;
                    continue;
                }
                let blocks = complete_bytes / BYTE_SET_WIDE_BLOCK_BYTES;
                if METERED {
                    actual.leading_block_classifications += blocks;
                    actual.leading_block_classification_bytes += complete_bytes;
                }
                position += complete_bytes;
                continue;
            }
            if METERED {
                actual.leading_scalar_probes += 1;
            }
            if self.plan.leading.set().contains(self.haystack[position]) {
                return Some(position);
            }
            position += 1;
        }
        None
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "fixed block extents and bit lanes are checked before every operation"
    )]
    fn next_leading_classifier<const METERED: bool>(
        &self,
        mut position: usize,
        end: usize,
        state: &mut UnicodeScalarSearchCursorState,
        actual: &mut SearchActualCounters,
    ) -> Option<usize> {
        while position < end {
            if state.leading_block_valid {
                let block_end = state.leading_block_base + BYTE_SET_WIDE_BLOCK_BYTES;
                if position >= state.leading_block_base && position < block_end {
                    let offset = position - state.leading_block_base;
                    let allowed = u32::MAX.checked_shl(u32::try_from(offset).ok()?).unwrap_or(0);
                    let candidates = state.leading_block_mask & allowed;
                    if candidates != 0 {
                        let lane = usize::try_from(candidates.trailing_zeros()).ok()?;
                        state.leading_block_mask &= !(1_u32 << lane);
                        return state.leading_block_base.checked_add(lane);
                    }
                    position = block_end;
                    state.leading_block_valid = false;
                    continue;
                }
                state.leading_block_valid = false;
            }

            if METERED {
                actual.leading_scalar_probes += 1;
            }
            if self.plan.leading.set().contains(self.haystack[position]) {
                return Some(position);
            }
            if end - position >= BYTE_SET_WIDE_BLOCK_BYTES {
                let block_end = position + BYTE_SET_WIDE_BLOCK_BYTES;
                let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = self.haystack[position..block_end]
                    .try_into()
                    .expect("the leading-byte block extent was checked");
                let mask = self.plan.leading.classify_32(block).member_mask();
                if METERED {
                    actual.leading_block_classifications += 1;
                    actual.leading_block_classification_bytes += BYTE_SET_WIDE_BLOCK_BYTES;
                }
                state.leading_block_base = position;
                state.leading_block_mask = mask;
                state.leading_block_valid = true;
                continue;
            }
            position += 1;
        }
        None
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the search preflight bounds each scalar and membership counter increment"
    )]
    fn decoded_member<const METERED: bool>(
        &self,
        decoded: DecodedScalar,
        state: &mut UnicodeScalarSearchCursorState,
        actual: &mut SearchActualCounters,
    ) -> bool {
        let Some(scalar) = decoded.scalar else {
            if METERED {
                actual.invalid_bytes += 1;
            }
            return false;
        };
        if METERED {
            actual.valid_scalars += 1;
        }
        if scalar <= 0x7F {
            if METERED {
                actual.ascii_membership_tests += 1;
            }
            let scalar = usize::try_from(scalar).expect("ASCII scalar fits usize");
            return self.plan.scalar.ascii[scalar / 64] & (1_u64 << (scalar % 64)) != 0;
        }
        if METERED {
            actual.non_ascii_membership_tests += 1;
        }
        self.plan.scalar.search_contains_non_ascii::<METERED>(
            scalar,
            &mut state.cached_non_ascii_range,
            actual,
        )
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::match_same_arms,
    reason = "matched UTF-8 leading bytes have fixed scalar intervals below Unicode maximum"
)]
fn utf8_lead_scalar_interval(byte: u8) -> (u32, u32) {
    match byte {
        0xC2..=0xDF => {
            let start = (u32::from(byte) & 0x1F) << 6;
            (start, start + 0x3F)
        }
        0xE0 => (0x0800, 0x0FFF),
        0xE1..=0xEC => {
            let start = (u32::from(byte) & 0x0F) << 12;
            (start, start + 0x0FFF)
        }
        0xED => (0xD000, 0xD7FF),
        0xEE..=0xEF => {
            let start = (u32::from(byte) & 0x0F) << 12;
            (start, start + 0x0FFF)
        }
        0xF0 => (0x1_0000, 0x3_FFFF),
        0xF1..=0xF3 => {
            let start = (u32::from(byte) & 0x07) << 18;
            (start, start + 0x3_FFFF)
        }
        0xF4 => (0x10_0000, 0x10_FFFF),
        _ => (1, 0),
    }
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;

    use super::{
        BuildError, BuildLimits, CURSOR_COUNT_DENSE_MAX_MEAN_BYTES,
        CURSOR_COUNT_DENSE_SAMPLE_MATCHES, CURSOR_COUNT_MAX_LEADING_BYTE_COUNT,
        CURSOR_COUNT_OPERATION_ID, CURSOR_COUNT_PLAN_ID, CursorCountBuild,
        DISPATCHED_PLAN_ID, DecodedScalar,
        DispatchedUnicodeScalarAggregatePlan, LeadingByteSearch, NoExecutionMeter, Operation,
        PLAN_ID, REPEATED_RUN_COUNT_OPERATION_ID, REPEATED_RUN_PLAN_ID,
        REPEATED_RUN_SPAN_SUM_OPERATION_ID, RUN_PLAN_ID, ReduceActualCounters, ReduceError,
        ReduceLimits, Repetition, SEARCH_LEADING_SELECTION_WORK, SEARCH_PLAN_ID,
        SEARCH_VALUE_PREFLIGHT_BLOCK_SLOP,
        SEARCH_VALUE_PREFLIGHT_MAX_INPUT_BYTES, SEARCH_VALUE_PREFLIGHT_WORK_FACTOR,
        SIMD_ASCII_CLASSIFIER_BUILD_WORK, SearchError, SearchLimits, UnicodeScalarAggregatePlan,
        UnicodeScalarSearchPlan, ValueReduction, binary_search_comparison_bound, decode_scalar,
        decode_scalar_inline, decode_scalar_with,
    };
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    use super::select_leading_byte_search_and_cardinality;
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    use fre_simd_kernels::{BYTE_SET_WIDE_BLOCK_BYTES, ByteSet256};
    use crate::{
        ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier, DispatchPolicy, Feature,
        SimdDispatchContext, Window,
    };

    #[test]
    fn inline_decoder_matches_general_decoder_at_utf8_boundaries() {
        let valid = [
            (
                b"A".as_slice(),
                DecodedScalar {
                    scalar: Some(u32::from('A')),
                    width: 1,
                    byte_checks: 1,
                },
            ),
            (
                "Δ".as_bytes(),
                DecodedScalar {
                    scalar: Some(u32::from('Δ')),
                    width: 2,
                    byte_checks: 2,
                },
            ),
            (
                "雪".as_bytes(),
                DecodedScalar {
                    scalar: Some(u32::from('雪')),
                    width: 3,
                    byte_checks: 3,
                },
            ),
            (
                "🦀".as_bytes(),
                DecodedScalar {
                    scalar: Some(u32::from('🦀')),
                    width: 4,
                    byte_checks: 4,
                },
            ),
        ];
        for (bytes, expected) in valid {
            assert_eq!(decode_scalar(bytes), expected);
            assert_eq!(decode_scalar_inline(bytes), expected);
        }

        let malformed = [
            (&[][..], 0),
            (&[0x80][..], 1),
            (&[0xC2][..], 1),
            (&[0xC2, b' '][..], 2),
            (&[0xE0][..], 1),
            (&[0xE0, 0xA0][..], 2),
            (&[0xE0, 0x80, 0x80][..], 2),
            (&[0xED, 0xA0, 0x80][..], 2),
            (&[0xF0][..], 1),
            (&[0xF0, 0x90][..], 2),
            (&[0xF0, 0x90, 0x80][..], 3),
            (&[0xF4, 0x90, 0x80, 0x80][..], 2),
            (&[0xF5, 0x80, 0x80, 0x80][..], 1),
        ];
        for (bytes, byte_checks) in malformed {
            let expected = DecodedScalar {
                scalar: None,
                width: 1,
                byte_checks,
            };
            assert_eq!(decode_scalar(bytes), expected);
            assert_eq!(decode_scalar_inline(bytes), expected);
        }
    }

    #[test]
    fn shared_decoder_charges_immediately_before_each_exact_byte_access() {
        for bytes in [
            "🦀".as_bytes(),
            &[0xE0, 0x80, 0x80],
            &[0xF0, 0x90, 0x80],
            &[0xF5, 0x80, 0x80, 0x80],
        ] {
            let mut charged = 0_usize;
            let decoded = decode_scalar_with(bytes, || {
                charged += 1;
                Ok::<(), ()>(())
            })
            .unwrap();
            assert_eq!(charged, decoded.byte_checks, "bytes={bytes:?}");
        }

        let mut charged = 0_usize;
        assert_eq!(
            decode_scalar_with("🦀".as_bytes(), || {
                if charged == 2 {
                    return Err(charged);
                }
                charged += 1;
                Ok(())
            }),
            Err(2)
        );
        assert_eq!(charged, 2);
    }

    #[test]
    #[ignore = "native qualification benchmark; requires Linux/AArch64 with OS-usable SVE2"]
    fn benchmark_unicode_scalar_ascii_classifier_ceiling() {
        use std::{hint::black_box, time::Instant};

        const ITERATIONS: usize = 128;
        const HAYSTACK_BYTES: usize = 1 << 20;
        let iterations = f64::from(u32::try_from(ITERATIONS).expect("small iteration count"));

        let dispatch = SimdDispatchContext::capture();
        assert!(
            dispatch.capabilities().usable().contains(Feature::ArmSve2),
            "benchmark requires OS-usable SVE2"
        );
        let plan = UnicodeScalarAggregatePlan::build(
            [('0', '9'), ('A', 'Z'), ('_', '_'), ('a', 'z')],
            BuildLimits::unlimited(),
        )
        .expect("ASCII Unicode-scalar plan");
        let set = AsciiByteSet::from_words(plan.ascii);
        let classifier = dispatch
            .ascii_byte_set_classifier(set, DispatchPolicy::Auto)
            .expect("automatic classifier retains a fallback");
        let corpus = b"abc_XYZ0123 !-\t";
        let haystack: Vec<u8> = corpus
            .iter()
            .copied()
            .cycle()
            .take(HAYSTACK_BYTES)
            .collect();
        let expected = plan
            .count(&haystack, ReduceLimits::unlimited())
            .expect("scalar Unicode-scalar count")
            .count;

        let started = Instant::now();
        let mut scalar_checksum = 0_u64;
        for _ in 0..ITERATIONS {
            scalar_checksum = scalar_checksum.wrapping_add(black_box(
                plan.count(black_box(&haystack), black_box(ReduceLimits::unlimited()))
                    .expect("scalar Unicode-scalar benchmark")
                    .count,
            ));
        }
        let scalar_ns = started.elapsed().as_secs_f64() * 1_000_000_000.0 / iterations;

        let started = Instant::now();
        let mut classifier_checksum = 0_u64;
        for _ in 0..ITERATIONS {
            let mut count = 0_u64;
            let mut chunks = black_box(haystack.as_slice()).chunks_exact(ASCII_WIDE_BYTES);
            for chunk in &mut chunks {
                let block: &[u8; ASCII_WIDE_BYTES] =
                    chunk.try_into().expect("exact classifier chunk");
                count = count.wrapping_add(u64::from(classifier.count_32(block)));
            }
            for &byte in chunks.remainder() {
                count = count.wrapping_add(u64::from(set.contains(byte)));
            }
            classifier_checksum = classifier_checksum.wrapping_add(black_box(count));
        }
        let classifier_ns = started.elapsed().as_secs_f64() * 1_000_000_000.0 / iterations;
        assert_eq!(scalar_checksum, classifier_checksum);
        assert_eq!(
            scalar_checksum,
            expected.wrapping_mul(u64::try_from(ITERATIONS).expect("small iteration count"))
        );
        println!(
            "UNICODE_SCALAR_ASCII_CLASSIFIER_BENCH iterations={ITERATIONS} \
             haystack_bytes={HAYSTACK_BYTES} scalar_ns={scalar_ns:.6} \
             classifier_ns={classifier_ns:.6} classifier_over_scalar={:.9} \
             wide_selection={:?}",
            classifier_ns / scalar_ns,
            classifier.selection().wide()
        );
    }

    fn classifier_actual(
        plan: &UnicodeScalarAggregatePlan,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let classifier = AsciiByteSetClassifier::new(AsciiByteSet::from_words(plan.ascii));
        let upper = plan.preflight(haystack, window, operation, limits, true)?;
        plan.execute_exactly_one_with_classifier(haystack, window, upper, &classifier)
    }

    fn classifier_value(
        plan: &UnicodeScalarAggregatePlan,
        haystack: &[u8],
        window: Window,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Option<ValueReduction> {
        let classifier = AsciiByteSetClassifier::new(AsciiByteSet::from_words(plan.ascii));
        let upper = plan
            .preflight(haystack, window, operation, limits, true)
            .ok()?;
        plan.execute_exactly_one_value_with_classifier(haystack, window, upper, &classifier)
            .ok()
    }

    #[test]
    fn dispatched_gate_precedes_range_access_without_sve2() {
        let dispatch = SimdDispatchContext::capture();
        if DispatchedUnicodeScalarAggregatePlan::classifier_usable(dispatch) {
            return;
        }
        let ranges = core::iter::from_fn(|| -> Option<(char, char)> {
            panic!("the unavailable dispatched gate touched its source")
        });
        let error = DispatchedUnicodeScalarAggregatePlan::build_attempt_with_dispatch(
            dispatch,
            ranges,
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert_eq!(
            error.source(),
            &BuildError::AsciiClassifierDispatchUnavailable
        );
        assert_eq!(error.actual(), crate::DirectBuildAttemptActual::default());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one conditional authentic-host test closes selection, owner layout, exact effects, identities, and all three build boundaries"
    )]
    fn authentic_dispatched_owner_has_exact_build_and_storage_accounting() {
        let dispatch = SimdDispatchContext::capture();
        if !DispatchedUnicodeScalarAggregatePlan::classifier_usable(dispatch) {
            return;
        }
        let ranges = [('0', '9'), ('A', 'Z'), ('_', '_'), ('a', 'z'), ('α', 'ω')];
        let baseline_attempt =
            UnicodeScalarAggregatePlan::build_attempt(ranges, BuildLimits::unlimited()).unwrap();
        let baseline_actual = baseline_attempt.actual();
        let baseline = baseline_attempt.into_plan();
        let dispatched_attempt = DispatchedUnicodeScalarAggregatePlan::build_attempt_with_dispatch(
            dispatch,
            ranges,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let dispatched_actual = dispatched_attempt.actual();
        let dispatched = dispatched_attempt.into_plan();
        let baseline_build = baseline.build_accounting();
        let build = dispatched.build_accounting();
        let owner_bytes = core::mem::size_of::<super::DispatchedUnicodeScalarOwner>();
        let storage_delta = core::mem::size_of::<DispatchedUnicodeScalarAggregatePlan>()
            .checked_add(owner_bytes)
            .unwrap()
            .checked_sub(core::mem::size_of::<UnicodeScalarAggregatePlan>())
            .unwrap();
        assert_eq!(
            build.work,
            baseline_build.work + SIMD_ASCII_CLASSIFIER_BUILD_WORK
        );
        assert_eq!(
            build.ascii_classifier_build_work,
            SIMD_ASCII_CLASSIFIER_BUILD_WORK
        );
        assert_eq!(
            build.ascii_classifier_bytes,
            core::mem::size_of::<AsciiByteSetClassifier>()
        );
        assert_eq!(build.dispatched_owner_bytes, owner_bytes);
        assert_eq!(
            build.persistent_bytes,
            baseline_build.persistent_bytes + storage_delta
        );
        assert_eq!(
            build.peak_bytes,
            baseline_build.peak_bytes.max(build.persistent_bytes)
        );
        assert_eq!(dispatched_actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(
            dispatched_actual.allocations,
            baseline_actual.allocations + 1
        );
        assert_eq!(
            dispatched_actual.allocated_bytes,
            baseline_actual.allocated_bytes + owner_bytes
        );
        assert_eq!(dispatched_actual.copied_bytes, baseline_actual.copied_bytes);
        assert_eq!(dispatched_actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(
            dispatched_actual.live_persistent_bytes,
            build.persistent_bytes
        );
        assert!(dispatched_actual.peak_bytes <= build.peak_bytes);
        assert_eq!(dispatched.count_identity().plan_id, DISPATCHED_PLAN_ID);
        assert_ne!(dispatched.count_identity(), baseline.count_identity());
        assert_ne!(dispatched.span_sum_identity(), baseline.span_sum_identity());
        let selection = dispatched.classifier_selection().wide();
        assert!(selection.required.contains(Feature::ArmSve));
        assert!(selection.required.contains(Feature::ArmSve2));

        let rebuild = |limits| {
            DispatchedUnicodeScalarAggregatePlan::build_with_dispatch(dispatch, ranges, limits)
        };
        assert!(
            rebuild(BuildLimits {
                max_build_work: build.work,
                max_persistent_bytes: build.persistent_bytes,
                max_peak_bytes: build.peak_bytes,
                ..BuildLimits::unlimited()
            })
            .is_ok()
        );
        assert!(matches!(
            rebuild(BuildLimits {
                max_build_work: build.work - 1,
                ..BuildLimits::unlimited()
            }),
            Err(BuildError::WorkLimit { needed, limit })
                if needed == build.work && limit == build.work - 1
        ));
        assert!(matches!(
            rebuild(BuildLimits {
                max_persistent_bytes: build.persistent_bytes - 1,
                ..BuildLimits::unlimited()
            }),
            Err(BuildError::PersistentLimit { needed, limit })
                if needed == build.persistent_bytes
                    && limit == build.persistent_bytes - 1
        ));
        assert!(matches!(
            rebuild(BuildLimits {
                max_peak_bytes: build.peak_bytes - 1,
                ..BuildLimits::unlimited()
            }),
            Err(BuildError::PeakLimit { needed, limit })
                if needed == build.peak_bytes && limit == build.peak_bytes - 1
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixed-block equivalence test covers exact widths, every dangerous boundary lane, crossing UTF-8, malformed input, windows, physical bounds, and one-below limits"
    )]
    fn fixed_ascii_blocks_preserve_exactly_one_utf8_semantics_and_physical_limits() {
        let plan = UnicodeScalarAggregatePlan::build(
            [
                ('0', '9'),
                ('A', 'Z'),
                ('_', '_'),
                ('a', 'z'),
                ('α', 'ω'),
                ('雪', '雪'),
            ],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut cases = Vec::<Vec<u8>>::new();
        for length in [0_usize, 1, 31, 32, 33, 63, 64, 65] {
            cases.push(b"aZ_0!?".iter().copied().cycle().take(length).collect());
        }
        for lane in [0_usize, 1, 15, 16, 29, 30, 31] {
            let mut bytes = b"aZ_0!?"
                .iter()
                .copied()
                .cycle()
                .take(96)
                .collect::<Vec<_>>();
            bytes[lane] = 0xFF;
            cases.push(bytes);
        }
        for lane in [29_usize, 30, 31] {
            for scalar in ["α", "雪", "🦀"] {
                let mut bytes = vec![b'a'; lane];
                bytes.extend_from_slice(scalar.as_bytes());
                bytes.extend_from_slice(&[b'Z'; 80]);
                cases.push(bytes);
            }
        }
        cases.extend([
            b"\xC0\x80a\xED\xA0\x80Z\xF4\x90\x80\x80_\xE2\x82".repeat(8),
            [("α".as_bytes()), &[b'a'; 30]].concat().repeat(4),
        ]);

        for haystack in &cases {
            let scalar_count = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
            let scalar_sum = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
            let block_count = classifier_actual(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits::unlimited(),
            )
            .unwrap();
            let block_sum = classifier_actual(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::SpanSum,
                ReduceLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(
                block_count.count, scalar_count.count,
                "haystack={haystack:?}"
            );
            assert_eq!(
                block_sum.matched_bytes, scalar_sum.span_sum,
                "haystack={haystack:?}"
            );
            let compact_count = classifier_value(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits::unlimited(),
            )
            .expect("admitted fixed-block compact count");
            let compact_sum = classifier_value(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::SpanSum,
                ReduceLimits::unlimited(),
            )
            .expect("admitted fixed-block compact span sum");
            assert_eq!(compact_count.count, scalar_count.count);
            assert_eq!(compact_sum.matched_bytes, scalar_sum.span_sum);
            let scalar_upper = scalar_count.accounting.upper_bounds;
            let block_upper = plan
                .preflight(
                    haystack,
                    Window::full(haystack),
                    Operation::Count,
                    ReduceLimits::unlimited(),
                    true,
                )
                .unwrap();
            let physical_bound = haystack.len() / ASCII_WIDE_BYTES * ASCII_WIDE_BYTES;
            assert_eq!(block_upper.ascii_block_classification_bytes, physical_bound);
            assert_eq!(
                block_upper.decode_byte_checks,
                scalar_upper.decode_byte_checks + physical_bound
            );
            assert_eq!(
                block_upper.membership_tests,
                scalar_upper.membership_tests + physical_bound
            );
            assert_eq!(block_upper.work, scalar_upper.work + physical_bound * 2);
            assert_eq!(
                block_count.ascii_block_classification_bytes,
                block_count.ascii_block_classifications * ASCII_WIDE_BYTES
            );
            assert!(
                block_count.ascii_block_classification_bytes
                    <= block_upper.ascii_block_classification_bytes
            );
            assert!(
                block_count.ascii_block_lookahead_bytes
                    <= block_count.ascii_block_classification_bytes
            );
            assert_eq!(block_count.ascii_run_bytes, block_count.ascii_bitmap_tests);
            assert!(block_count.decode_byte_checks <= block_upper.decode_byte_checks);
            assert!(block_count.work <= block_upper.work);
        }

        let mixed_then_ascii = [vec![b'a'; 8], "α".as_bytes().to_vec(), vec![b'Z'; 256]].concat();
        let mixed_scalar = plan
            .count(&mixed_then_ascii, ReduceLimits::unlimited())
            .unwrap();
        let mixed_blocks = classifier_actual(
            &plan,
            &mixed_then_ascii,
            Window::full(&mixed_then_ascii),
            Operation::Count,
            ReduceLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(mixed_blocks.count, mixed_scalar.count);
        assert_eq!(mixed_blocks.ascii_block_classifications, 1);
        assert_eq!(
            mixed_blocks.ascii_block_classification_bytes,
            ASCII_WIDE_BYTES
        );

        let all_ascii = vec![b'a'; ASCII_WIDE_BYTES * 4];
        let all_ascii_blocks = classifier_actual(
            &plan,
            &all_ascii,
            Window::full(&all_ascii),
            Operation::Count,
            ReduceLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(all_ascii_blocks.ascii_block_classifications, 4);

        let crossing = [vec![b'x'; 31], "雪".as_bytes().to_vec(), vec![b'Z'; 65]].concat();
        for start in [0_usize, 1, 29, 30, 31, 32] {
            for end in [32_usize, 33, 34, crossing.len()] {
                if start > end || end > crossing.len() {
                    continue;
                }
                let window = Window::new(start, end);
                let scalar = plan
                    .count_in(&crossing, window, ReduceLimits::unlimited())
                    .unwrap();
                let blocks = classifier_actual(
                    &plan,
                    &crossing,
                    window,
                    Operation::Count,
                    ReduceLimits::unlimited(),
                )
                .unwrap();
                assert_eq!(blocks.count, scalar.count, "window={start}..{end}");
                assert_eq!(blocks.input_bytes_advanced, end - start);
            }
        }

        let haystack = &cases[cases.len() - 1];
        let upper = plan
            .preflight(
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits::unlimited(),
                true,
            )
            .unwrap();
        assert!(
            classifier_actual(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits {
                    max_decode_byte_checks: upper.decode_byte_checks,
                    max_membership_tests: upper.membership_tests,
                    max_work: upper.work,
                    ..ReduceLimits::unlimited()
                },
            )
            .is_ok()
        );
        assert!(
            classifier_value(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits {
                    max_decode_byte_checks: upper.decode_byte_checks,
                    max_membership_tests: upper.membership_tests,
                    max_work: upper.work,
                    ..ReduceLimits::unlimited()
                },
            )
            .is_some()
        );
        assert_eq!(
            classifier_value(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits {
                    max_decode_byte_checks: upper.decode_byte_checks - 1,
                    ..ReduceLimits::unlimited()
                },
            ),
            None
        );
        assert!(matches!(
            classifier_actual(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits {
                    max_decode_byte_checks: upper.decode_byte_checks - 1,
                    ..ReduceLimits::unlimited()
                },
            ),
            Err(ReduceError::DecodeByteChecksLimit { needed, limit })
                if needed == upper.decode_byte_checks
                    && limit == upper.decode_byte_checks - 1
        ));
        assert!(matches!(
            classifier_actual(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits {
                    max_membership_tests: upper.membership_tests - 1,
                    ..ReduceLimits::unlimited()
                },
            ),
            Err(ReduceError::MembershipTestsLimit { needed, limit })
                if needed == upper.membership_tests
                    && limit == upper.membership_tests - 1
        ));
        assert!(matches!(
            classifier_actual(
                &plan,
                haystack,
                Window::full(haystack),
                Operation::Count,
                ReduceLimits {
                    max_work: upper.work - 1,
                    ..ReduceLimits::unlimited()
                },
            ),
            Err(ReduceError::WorkLimit { needed, limit })
                if needed == upper.work && limit == upper.work - 1
        ));
    }

    #[test]
    fn build_attempt_reports_exact_success_and_partial_range_failure() {
        let attempt = UnicodeScalarAggregatePlan::build_attempt(
            [('a', 'c'), ('\u{80}', '\u{81}')],
            BuildLimits::unlimited(),
        )
        .unwrap();
        let actual = attempt.actual();
        let plan = attempt.into_plan();
        let build = plan.build_accounting();
        assert_eq!(actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(actual.copied_bytes, build.range_payload_bytes);
        assert_eq!(
            actual.initialized_bytes,
            build
                .range_payload_bytes
                .checked_add(core::mem::size_of::<UnicodeScalarAggregatePlan>())
                .unwrap()
        );
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert!(actual.allocations > 0);
        assert!(actual.allocated_bytes >= build.temporary_capacity_bytes);
        assert!(actual.peak_bytes >= build.persistent_bytes);

        let failure = UnicodeScalarAggregatePlan::build_attempt(
            [('\u{80}', '\u{80}'), ('z', 'a')],
            BuildLimits::unlimited(),
        )
        .unwrap_err();
        assert!(matches!(
            failure.source(),
            BuildError::ReversedRange {
                start: 'z',
                end: 'a'
            }
        ));
        let partial = failure.actual();
        assert_eq!(partial.work, 2);
        assert_eq!(partial.allocations, 1);
        assert!(partial.allocated_bytes >= core::mem::size_of::<super::ScalarRange>());
        assert_eq!(
            partial.copied_bytes,
            core::mem::size_of::<super::ScalarRange>()
        );
        assert_eq!(
            partial.initialized_bytes,
            core::mem::size_of::<super::ScalarRange>()
        );
        assert_eq!(partial.live_persistent_bytes, 0);
        assert!(partial.peak_bytes > 0);
    }

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
    fn prepared_count_preserves_full_window_semantics_and_refusals() {
        let ranges = [('A', 'Z'), ('a', 'z'), ('\u{3B1}', '\u{3C9}'), ('雪', '雪')];
        let plans_and_haystacks = [
            (
                UnicodeScalarAggregatePlan::build(ranges, BuildLimits::unlimited()).unwrap(),
                b"A\xFF\x80\xE9\x9B\xAA1z".to_vec(),
            ),
            (
                UnicodeScalarAggregatePlan::build_one_or_more(
                    ranges,
                    true,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                b"AA!\xCE\xB1\xCE\xB2?\xFFz".repeat(16),
            ),
            (
                UnicodeScalarAggregatePlan::build_repeated(
                    ranges,
                    2,
                    Some(4),
                    false,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                b"AzA!\xE9\x9B\xAA\xE9\x9B\xAA\x80".repeat(512),
            ),
        ];
        for (plan, haystack) in plans_and_haystacks {
            let upper = plan.full_window_upper_bounds(haystack.len()).unwrap();
            let exact = ReduceLimits {
                max_input_bytes: upper.input_bytes,
                max_decode_byte_checks: upper.decode_byte_checks,
                max_membership_tests: upper.membership_tests,
                max_range_comparisons: upper.range_comparisons,
                max_reducer_steps: upper.reducer_steps,
                max_match_events: upper.match_events,
                max_count: upper.count,
                max_span_sum: 0,
                max_work: upper.work,
                max_scratch_bytes: upper.scratch_bytes,
                max_peak_bytes: upper.peak_bytes,
            };
            let ordinary = plan.count(&haystack, exact).unwrap().count;
            let admission = plan.prepare_count(haystack.len(), exact).unwrap();
            assert_eq!(plan.count_prepared(&haystack, admission), Some(ordinary));
            assert_eq!(
                plan.count_prepared(&haystack[..haystack.len() - 1], admission),
                None
            );
        }

        let plan = UnicodeScalarAggregatePlan::build_one_or_more(
            [('A', 'Z'), ('a', 'z'), ('\u{3B1}', '\u{3C9}'), ('雪', '雪')],
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = b"Az\xCE\xB1\xE9\x9B\xAA\xFF";
        let upper = plan.full_window_upper_bounds(haystack.len()).unwrap();
        let one_below = [
            ReduceLimits {
                max_input_bytes: upper.input_bytes - 1,
                ..ReduceLimits::unlimited()
            },
            ReduceLimits {
                max_decode_byte_checks: upper.decode_byte_checks - 1,
                ..ReduceLimits::unlimited()
            },
            ReduceLimits {
                max_membership_tests: upper.membership_tests - 1,
                ..ReduceLimits::unlimited()
            },
            ReduceLimits {
                max_range_comparisons: upper.range_comparisons - 1,
                ..ReduceLimits::unlimited()
            },
            ReduceLimits {
                max_reducer_steps: upper.reducer_steps - 1,
                ..ReduceLimits::unlimited()
            },
            ReduceLimits {
                max_match_events: upper.match_events - 1,
                ..ReduceLimits::unlimited()
            },
            ReduceLimits {
                max_count: upper.count - 1,
                ..ReduceLimits::unlimited()
            },
            ReduceLimits {
                max_work: upper.work - 1,
                ..ReduceLimits::unlimited()
            },
            ReduceLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..ReduceLimits::unlimited()
            },
        ];
        for limits in one_below {
            assert_eq!(
                plan.prepare_count(haystack.len(), limits).unwrap_err(),
                plan.count(haystack, limits).unwrap_err()
            );
        }
        let span_starved = ReduceLimits {
            max_span_sum: 0,
            ..ReduceLimits::unlimited()
        };
        assert!(plan.prepare_count(haystack.len(), span_starved).is_ok());

        let repeated_admission = plan
            .prepare_count(haystack.len(), ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(class_plan().count_prepared(haystack, repeated_admission), None);
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
                assert_eq!(
                    plan.count_value_success(&haystack, ReduceLimits::unlimited()),
                    Some(expected_count),
                    "compact count pattern={pattern:?} haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum_value_success(&haystack, ReduceLimits::unlimited()),
                    Some(expected_sum),
                    "compact span sum pattern={pattern:?} haystack={haystack:?}"
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
                let window = Window::new(start, end);
                assert_eq!(
                    plan.count_value_in_success(haystack, window, ReduceLimits::unlimited()),
                    Some(expected_count),
                    "compact count window={start}..{end}"
                );
                assert_eq!(
                    plan.span_sum_value_in_success(haystack, window, ReduceLimits::unlimited()),
                    Some(expected_sum),
                    "compact span sum window={start}..{end}"
                );
            }
        }
    }

    #[test]
    fn compact_values_cover_every_repetition_specialization_on_first_and_steady_calls() {
        let cases = [
            (
                vec![('A', 'Z'), ('a', 'z')],
                b"ab--cdef\xFFghijk--z".as_slice(),
            ),
            (
                vec![('A', 'Z'), ('a', 'z'), ('α', 'ω'), ('雪', '雪')],
                b"ab--\xCE\xB1\xCE\xB2\xFF\xE9\x9B\xAA\xE9\x9B\xAAz".as_slice(),
            ),
        ];
        for (ranges, haystack) in cases {
            let plans = [
                UnicodeScalarAggregatePlan::build(ranges.clone(), BuildLimits::unlimited())
                    .unwrap(),
                UnicodeScalarAggregatePlan::build_one_or_more(
                    ranges.clone(),
                    true,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                UnicodeScalarAggregatePlan::build_one_or_more(
                    ranges.clone(),
                    false,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                UnicodeScalarAggregatePlan::build_repeated(
                    ranges.clone(),
                    2,
                    Some(4),
                    true,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                UnicodeScalarAggregatePlan::build_repeated(
                    ranges.clone(),
                    2,
                    Some(4),
                    false,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                UnicodeScalarAggregatePlan::build_repeated(
                    ranges.clone(),
                    3,
                    None,
                    true,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
                UnicodeScalarAggregatePlan::build_repeated(
                    ranges,
                    3,
                    None,
                    false,
                    BuildLimits::unlimited(),
                )
                .unwrap(),
            ];
            for plan in plans {
                let expected_count = plan
                    .count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count;
                let expected_sum = plan
                    .span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum;
                for _ in 0..2 {
                    assert_eq!(
                        plan.count_value_success(haystack, ReduceLimits::unlimited()),
                        Some(expected_count),
                        "compact count repetition={:?}",
                        plan.build_accounting().repetition
                    );
                    assert_eq!(
                        plan.span_sum_value_success(haystack, ReduceLimits::unlimited()),
                        Some(expected_sum),
                        "compact span sum repetition={:?}",
                        plan.build_accounting().repetition
                    );
                }
            }
        }
        assert_eq!(core::mem::size_of::<NoExecutionMeter>(), 0);
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
    fn nonnullable_counted_repetitions_match_rust() {
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
    }

    #[test]
    fn nonnullable_counted_repetitions_match_rust_in_every_window() {
        let ranges = [('A', 'Z'), ('a', 'z'), ('α', 'ω'), ('雪', '雪')];
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
                        .span_sum_in(windowed, Window::new(start, end), ReduceLimits::unlimited(),)
                        .unwrap()
                        .span_sum,
                    expected_sum,
                    "window={start}..{end}"
                );
            }
        }
    }

    #[test]
    fn nonnullable_counted_repetitions_have_exact_identity_and_linear_work() {
        let ranges = [('A', 'Z'), ('a', 'z'), ('α', 'ω'), ('雪', '雪')];
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
            assert_eq!(pair[1].decode_byte_checks, pair[0].decode_byte_checks * 2);
            // The monotone prefix contributes two fixed comparisons. After
            // the first descent, every repeated unit uses the same local-cache
            // work.
            assert_eq!(
                pair[1].range_comparisons - 2,
                (pair[0].range_comparisons - 2) * 2
            );
            assert_eq!(pair[1].reducer_steps - 1, (pair[0].reducer_steps - 1) * 2);
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
    fn counted_runs_switch_to_the_local_cache_after_a_descent() {
        let ranges = [('α', 'α'), ('γ', 'γ'), ('ε', 'ε'), ('η', 'η'), ('ι', 'ι')];
        let run = UnicodeScalarAggregatePlan::build_repeated(
            ranges,
            2,
            Some(4),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let point = UnicodeScalarAggregatePlan::build(ranges, BuildLimits::unlimited()).unwrap();
        let haystack = format!("αγεηι{}", "α".repeat(128));
        let run_result = run
            .count(haystack.as_bytes(), ReduceLimits::unlimited())
            .unwrap();
        let point_result = point
            .count(haystack.as_bytes(), ReduceLimits::unlimited())
            .unwrap();
        let regex = RegexBuilder::new("[αγεηι]{2,4}")
            .unicode(true)
            .build()
            .unwrap();

        assert_eq!(
            run_result.count,
            u64::try_from(regex.find_iter(haystack.as_bytes()).count()).unwrap()
        );
        assert!(
            run_result.accounting.actual.range_comparisons
                <= point_result.accounting.actual.range_comparisons
        );
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
        let exact_limits = ReduceLimits {
            max_reducer_steps: upper.reducer_steps,
            ..ReduceLimits::unlimited()
        };
        assert_eq!(
            plan.count_value_success(&unit.repeat(8), exact_limits),
            Some(rows[0].actual.count)
        );
        let one_below = ReduceLimits {
            max_reducer_steps: upper.reducer_steps - 1,
            ..ReduceLimits::unlimited()
        };
        assert_eq!(plan.count_value_success(&unit.repeat(8), one_below), None);
        let error = plan.count(&unit.repeat(8), one_below).unwrap_err();
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
            assert_eq!(
                plan.count_value_success(haystack, ReduceLimits::unlimited()),
                Some(0),
                "haystack={haystack:?}"
            );
            assert_eq!(
                plan.span_sum_value_success(haystack, ReduceLimits::unlimited()),
                Some(0),
                "haystack={haystack:?}"
            );
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
        assert_eq!(
            plan.count_value_in_success(b"abc", Window::new(2, 1), ReduceLimits::unlimited()),
            None
        );
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
    #[allow(
        clippy::too_many_lines,
        reason = "the single boundary table checks exact and one-below behavior for every independently limited resource"
    )]
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
        let exact_sum = plan.span_sum(haystack, exact).unwrap().span_sum;
        let exact_count = plan.count(haystack, exact).unwrap().count;
        assert_eq!(
            plan.span_sum_value_success(haystack, exact),
            Some(exact_sum)
        );
        assert_eq!(plan.count_value_success(haystack, exact), Some(exact_count));

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
            assert_eq!(
                plan.span_sum_value_success(haystack, limits),
                None,
                "compact span sum accepted one-below {expected}"
            );
            if expected == "span" {
                assert_eq!(
                    plan.count_value_success(haystack, limits),
                    Some(exact_count),
                    "count must not enforce span-sum limits"
                );
            } else {
                assert_eq!(
                    plan.count_value_success(haystack, limits),
                    None,
                    "compact count accepted one-below {expected}"
                );
            }
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

    fn greek_search_plan(greedy: bool) -> UnicodeScalarSearchPlan {
        UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            [('Α', 'Ω'), ('α', 'ω')],
            2,
            Some(6),
            greedy,
            BuildLimits::unlimited(),
        )
        .unwrap()
    }

    #[test]
    fn scalar_run_search_matches_pinned_bytes_regex_at_every_start() {
        for (greedy, pattern) in [
            (true, r"[Α-Ωα-ω]{2,6}"),
            (false, r"[Α-Ωα-ω]{2,6}?"),
        ] {
            let plan = greek_search_plan(greedy);
            assert_eq!(plan.selected_identity().plan_id, SEARCH_PLAN_ID);
            let upstream = RegexBuilder::new(pattern).build().unwrap();
            for haystack in [
                b"".as_slice(),
                b"plain ASCII without candidates".as_slice(),
                "--αβγδεζη--ΩΑ--xαβ--".as_bytes(),
                b"\x80\xce\xb1\xce\xb2\xed\xa0\x80\xce\xb3\xce\xb4",
                b"\xce\xb1\xce\xb2\xf0\x9f\x92\xce\xb3\xce\xb4",
            ] {
                for start in 0..=haystack.len() {
                    let expected = upstream
                        .find_at(haystack, start)
                        .map(|matched| (matched.start(), matched.end()));
                    let actual = plan
                        .find_window(
                            haystack,
                            Window::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0;
                    assert_eq!(actual, expected, "pattern={pattern:?} start={start}");
                    assert_eq!(
                        plan.find_window_value(
                            haystack,
                            Window::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap(),
                        actual,
                    );
                    let exists = plan
                        .is_match_window(
                            haystack,
                            Window::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0;
                    assert_eq!(
                        plan.is_match_window_value(
                            haystack,
                            Window::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap(),
                        exists,
                    );
                    let shortest = plan
                        .shortest_match_window(
                            haystack,
                            Window::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0;
                    assert_eq!(shortest, upstream.shortest_match_at(haystack, start));
                    assert_eq!(
                        plan.shortest_match_window_value(
                            haystack,
                            Window::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap(),
                        shortest,
                    );
                }
            }
        }
    }

    #[test]
    fn scalar_run_sparse_native_leaves_cover_one_and_three_leading_bytes() {
        let cases: &[(&[(char, char)], &str, LeadingByteSearch)] = &[
            (
                &[('\u{80}', '\u{BF}')],
                r"[\u{80}-\u{BF}]{2,4}",
                LeadingByteSearch::One(0xC2),
            ),
            (
                &[('\u{80}', '\u{13F}')],
                r"[\u{80}-\u{13F}]{2,4}",
                LeadingByteSearch::Three(0xC2, 0xC3, 0xC4),
            ),
        ];
        for &(ranges, pattern, expected_search) in cases {
            let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
                SimdDispatchContext::capture(),
                ranges.iter().copied(),
                2,
                Some(4),
                true,
                BuildLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(plan.leading_search, expected_search, "pattern={pattern:?}");
            assert_eq!(
                plan.search_upper_bounds(128)
                    .unwrap()
                    .leading_block_classifications,
                0,
            );
            let upstream = RegexBuilder::new(pattern).build().unwrap();
            for haystack in [
                b"plain ASCII".as_slice(),
                "--\u{80}\u{81}\u{13f}--\u{c0}\u{ff}--".as_bytes(),
                b"\xc2\x80\xc2\x81\x80\xc4\xbf\xc3\x80",
            ] {
                for start in 0..=haystack.len() {
                    let expected = upstream
                        .find_at(haystack, start)
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(
                        plan.find_window_value(
                            haystack,
                            Window::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap(),
                        expected,
                        "pattern={pattern:?} start={start}",
                    );
                }
            }
        }
    }

    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    #[test]
    fn leading_search_small_table_boundary_is_sixteen_values() {
        let sixteen = select_leading_byte_search_and_cardinality(ByteSet256::from_words([
            (1_u64 << 16) - 1,
            0,
            0,
            0,
        ]))
        .0;
        let LeadingByteSearch::Small(values) = sixteen else {
            panic!("sixteen values did not select the fixed table");
        };
        assert_eq!(values, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(
            select_leading_byte_search_and_cardinality(ByteSet256::from_words([
                (1_u64 << 17) - 1,
                0,
                0,
                0,
            ]))
            .0,
            LeadingByteSearch::Classifier,
        );
    }

    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    #[test]
    fn scalar_run_small_table_value_head_probe_preserves_exact_search() {
        let ranges = [
            ('\u{80}', '\u{80}'),
            ('\u{340}', '\u{340}'),
            ('\u{380}', '\u{380}'),
            ('\u{1000}', '\u{1000}'),
            ('\u{2000}', '\u{2000}'),
            ('\u{A000}', '\u{A000}'),
            ('\u{10000}', '\u{10000}'),
        ];
        let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            ranges,
            2,
            Some(4),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(matches!(plan.leading_search, LeadingByteSearch::Small(_)));

        let mut dense = vec![b'x'];
        dense.extend_from_slice("\u{80}\u{80}".as_bytes());
        dense.resize(96, b'x');
        let window = Window::full(&dense);
        let (selected, accounting) = plan
            .find_window(&dense, window, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(selected, Some((1, 5)));
        assert_eq!(accounting.actual.leading_block_classifications, 1);
        assert_eq!(
            accounting.actual.leading_block_classification_bytes,
            BYTE_SET_WIDE_BLOCK_BYTES,
        );
        assert_eq!(accounting.actual.leading_scalar_probes, 0);

        let mut cursor = plan.search_cursor(&dense);
        assert_eq!(
            cursor.find_at_value(0, SearchLimits::unlimited()).unwrap(),
            selected,
        );
        assert!(!cursor.state.leading_block_valid);
        assert!(
            plan.is_match_window_value(&dense, window, SearchLimits::unlimited())
                .unwrap(),
        );
        assert_eq!(
            plan.shortest_match_window_value(&dense, window, SearchLimits::unlimited())
                .unwrap(),
            Some(5),
        );

        let mut decoy = vec![b'x'];
        decoy.extend_from_slice("\u{81}xx\u{80}\u{80}".as_bytes());
        decoy.resize(96, b'x');
        for start in [0, 2] {
            let window = Window::new(start, decoy.len());
            let expected = plan
                .find_window(&decoy, window, SearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(expected, Some((5, 9)));
            assert_eq!(
                plan.find_window_value(&decoy, window, SearchLimits::unlimited())
                    .unwrap(),
                expected,
                "start={start}",
            );
            assert!(
                plan.is_match_window_value(&decoy, window, SearchLimits::unlimited())
                    .unwrap(),
                "start={start}",
            );
        }

        let absent = vec![b'x'; 96];
        let absent_window = Window::full(&absent);
        assert_eq!(
            plan.find_window_value(&absent, absent_window, SearchLimits::unlimited())
                .unwrap(),
            None,
        );
        assert!(
            !plan
                .is_match_window_value(&absent, absent_window, SearchLimits::unlimited())
                .unwrap(),
        );
    }

    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    #[test]
    fn scalar_run_small_table_retains_full_mask_and_invalidates_backward_restart() {
        let ranges = [
            ('\u{80}', '\u{80}'),
            ('\u{340}', '\u{340}'),
            ('\u{380}', '\u{380}'),
            ('\u{1000}', '\u{1000}'),
            ('\u{2000}', '\u{2000}'),
            ('\u{A000}', '\u{A000}'),
            ('\u{10000}', '\u{10000}'),
        ];
        let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            ranges,
            2,
            Some(4),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(matches!(plan.leading_search, LeadingByteSearch::Small(_)));

        let mut haystack = vec![b'x'; 96];
        haystack.extend_from_slice("\u{81}xx\u{80}\u{80}".as_bytes());
        haystack.extend_from_slice(&[b'x'; 40]);
        haystack.extend_from_slice("\u{1000}\u{1000}".as_bytes());

        let mut cursor = plan.search_cursor(&haystack);
        for start in [0, 0, 32, 96] {
            assert_eq!(
                cursor
                    .find_at_value(start, SearchLimits::unlimited())
                    .unwrap(),
                Some((100, 104)),
                "start={start}",
            );
        }
        assert_eq!(
            cursor
                .find_at_value(104, SearchLimits::unlimited())
                .unwrap(),
            Some((144, 150)),
        );
        assert_eq!(
            cursor
                .find_at_value(0, SearchLimits::unlimited())
                .unwrap(),
            Some((100, 104)),
        );

        let (matched, accounting) = plan
            .find_window(
                &haystack,
                Window::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(matched, Some((100, 104)));
        assert_eq!(accounting.actual.leading_block_classifications, 4);
        assert_eq!(accounting.actual.leading_block_classification_bytes, 128);
        assert_eq!(accounting.actual.leading_scalar_probes, 0);

        let absent = vec![b'x'; 70];
        let (matched, accounting) = plan
            .find_window(
                &absent,
                Window::full(&absent),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(matched, None);
        assert_eq!(accounting.actual.leading_block_classifications, 2);
        assert_eq!(accounting.actual.leading_block_classification_bytes, 64);
        assert_eq!(accounting.actual.leading_scalar_probes, 5);
    }

    #[test]
    fn scalar_run_cursor_reuses_only_its_bound_plan_and_immutable_source() {
        let greek = greek_search_plan(true);
        let cyrillic = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            [('А', 'я')],
            2,
            Some(6),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = "--αβγδεζη--абвг--".as_bytes();
        let mut greek_cursor = greek.search_cursor(haystack);
        let mut cyrillic_cursor = cyrillic.search_cursor(haystack);
        assert_eq!(
            greek_cursor
                .find_at_value(0, SearchLimits::unlimited())
                .unwrap(),
            Some((2, 14))
        );
        assert_eq!(
            cyrillic_cursor
                .find_at_value(0, SearchLimits::unlimited())
                .unwrap(),
            Some((18, 26))
        );

        let mut reused = "--αβ--".as_bytes().to_vec();
        let allocation = reused.as_ptr();
        {
            let mut cursor = greek.search_cursor(&reused);
            assert!(
                cursor
                    .find_at_value(0, SearchLimits::unlimited())
                    .unwrap()
                    .is_some()
            );
        }
        reused.copy_from_slice(b"--------");
        assert_eq!(reused.as_ptr(), allocation);
        let mut rebound = greek.search_cursor(&reused);
        assert_eq!(
            rebound
                .find_at_value(0, SearchLimits::unlimited())
                .unwrap(),
            None
        );
    }

    #[test]
    fn scalar_run_search_bulk_filter_and_preflight_are_exactly_bounded() {
        let plan = greek_search_plan(true);
        let haystack = vec![b'x'; 257];
        let upper = plan.search_upper_bounds(haystack.len()).unwrap();
        assert_eq!(upper.leading_block_classifications, 0);
        assert_eq!(upper.leading_block_classification_bytes, 0);
        let mut cursor = plan.search_cursor(&haystack);
        let initial_state = cursor.state;
        assert_eq!(
            cursor.find_at(haystack.len() + 1, SearchLimits::unlimited()),
            Err(SearchError::InvalidWindow {
                start: haystack.len() + 1,
                end: haystack.len(),
                haystack_len: haystack.len(),
            }),
        );
        assert_eq!(cursor.state, initial_state);
        assert_eq!(
            cursor.find_at_value(haystack.len() + 1, SearchLimits::unlimited()),
            Err(SearchError::InvalidWindow {
                start: haystack.len() + 1,
                end: haystack.len(),
                haystack_len: haystack.len(),
            }),
        );
        assert_eq!(cursor.state, initial_state);
        assert_eq!(
            cursor.search_window_value::<true>(
                Window::new(0, haystack.len() + 1),
                SearchLimits::unlimited(),
            ),
            Err(SearchError::InvalidWindow {
                start: 0,
                end: haystack.len() + 1,
                haystack_len: haystack.len(),
            }),
        );
        assert_eq!(cursor.state, initial_state);
        let refused = SearchLimits {
            max_work: upper.work - 1,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            cursor.find_at(0, refused),
            Err(SearchError::WorkLimit {
                needed: upper.work,
                limit: upper.work - 1,
            })
        );
        assert_eq!(cursor.state, initial_state);
        assert_eq!(
            cursor.find_at_value(0, refused),
            Err(SearchError::WorkLimit {
                needed: upper.work,
                limit: upper.work - 1,
            })
        );
        assert_eq!(cursor.state, initial_state);
        assert_eq!(
            cursor.find_at_value(
                0,
                SearchLimits {
                    max_work: upper.work,
                    max_scratch_bytes: 0,
                },
            ),
            Ok(None),
        );
        let (matched, accounting) = cursor.find_at(0, SearchLimits::unlimited()).unwrap();
        assert_eq!(matched, None);
        assert_eq!(accounting.actual.leading_scalar_probes, haystack.len() - 1);
        assert_eq!(accounting.actual.leading_block_classifications, 0);
        assert_eq!(accounting.actual.leading_block_classification_bytes, 0);
        assert!(accounting.actual.work <= accounting.upper_bounds.work);
    }

    #[test]
    fn scalar_run_unlimited_value_preflight_threshold_proves_all_upper_arithmetic() {
        assert_eq!(SEARCH_VALUE_PREFLIGHT_BLOCK_SLOP, 31);
        assert_eq!(
            SEARCH_VALUE_PREFLIGHT_WORK_FACTOR,
            usize::try_from(usize::BITS).unwrap().checked_add(9).unwrap(),
        );
        SEARCH_VALUE_PREFLIGHT_MAX_INPUT_BYTES
            .checked_mul(SEARCH_VALUE_PREFLIGHT_WORK_FACTOR)
            .and_then(|work| work.checked_add(SEARCH_VALUE_PREFLIGHT_BLOCK_SLOP))
            .unwrap();
        assert!(
            SEARCH_VALUE_PREFLIGHT_MAX_INPUT_BYTES
                .checked_add(1)
                .unwrap()
                .checked_mul(SEARCH_VALUE_PREFLIGHT_WORK_FACTOR)
                .and_then(|work| work.checked_add(SEARCH_VALUE_PREFLIGHT_BLOCK_SLOP))
                .is_none()
        );

        let sparse = greek_search_plan(true);
        assert!(!sparse.leading_search.uses_block_classification());
        sparse
            .search_upper_bounds(SEARCH_VALUE_PREFLIGHT_MAX_INPUT_BYTES)
            .unwrap();
        let block = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            [('\u{80}', '\u{D7FF}'), ('\u{E000}', char::MAX)],
            2,
            Some(6),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(block.leading_search.uses_block_classification());
        block
            .search_upper_bounds(SEARCH_VALUE_PREFLIGHT_MAX_INPUT_BYTES)
            .unwrap();
    }

    #[test]
    fn scalar_run_classifier_cursor_invalidates_consumed_masks_for_earlier_restarts() {
        let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            [('\u{80}', '\u{D7FF}'), ('\u{E000}', char::MAX)],
            2,
            Some(6),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut haystack = vec![b'x'; 8];
        haystack.extend_from_slice("αβ".as_bytes());
        haystack.extend_from_slice(&[b'x'; 40]);
        let mut cursor = plan.search_cursor(&haystack);
        for start in [0, 0, 4, 8] {
            assert_eq!(
                cursor
                    .find_at_value(start, SearchLimits::unlimited())
                    .unwrap(),
                Some((8, 12)),
                "start={start}",
            );
        }
        assert_eq!(
            cursor
                .find_at_value(12, SearchLimits::unlimited())
                .unwrap(),
            None,
        );
        assert_eq!(
            cursor
                .find_at_value(0, SearchLimits::unlimited())
                .unwrap(),
            Some((8, 12)),
        );

        let upper = plan.search_upper_bounds(haystack.len()).unwrap();
        assert!(upper.leading_block_classifications > 0);
        let (_, accounting) = plan
            .find_window(
                &haystack,
                Window::full(&haystack),
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert!(accounting.actual.leading_block_classifications > 0);
    }

    #[test]
    fn scalar_cursor_count_route_is_exact_at_89_and_reuses_scalar_at_90() {
        assert_eq!(CURSOR_COUNT_MAX_LEADING_BYTE_COUNT, 89);
        let dispatch = SimdDispatchContext::capture();
        let exact = UnicodeScalarSearchPlan::build_repeated_count_attempt_with_dispatch(
            dispatch,
            [('\0', 'W'), ('\u{80}', '\u{80}')],
            1,
            None,
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert!(matches!(
            exact.into_plan(),
            CursorCountBuild::Cursor {
                leading_byte_count: 89,
                ..
            }
        ));

        let scalar_attempt = UnicodeScalarAggregatePlan::build_one_or_more_attempt(
            [('\0', 'X'), ('\u{80}', '\u{80}')],
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let scalar_actual = scalar_attempt.actual();
        let scalar_build = scalar_attempt.into_plan().build_accounting();
        let broad = UnicodeScalarSearchPlan::build_repeated_count_attempt_with_dispatch(
            dispatch,
            [('\0', 'X'), ('\u{80}', '\u{80}')],
            1,
            None,
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let broad_actual = broad.actual();
        let CursorCountBuild::Scalar {
            plan,
            leading_byte_count,
        } = broad.into_plan()
        else {
            panic!("90 leading bytes retained a cursor wrapper")
        };
        assert_eq!(leading_byte_count, 90);
        let build = plan.build_accounting();
        let routing_work = SEARCH_LEADING_SELECTION_WORK + 2 + 51;
        assert_eq!(build.work, scalar_build.work + routing_work);
        assert!(scalar_actual.allocations > 0);
        assert!(scalar_actual.allocated_bytes > 0);
        assert_eq!(broad_actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(broad_actual.allocations, scalar_actual.allocations);
        assert_eq!(broad_actual.allocated_bytes, scalar_actual.allocated_bytes);
        assert_eq!(broad_actual.copied_bytes, scalar_actual.copied_bytes);
        assert_eq!(broad_actual.initialized_bytes, scalar_actual.initialized_bytes);
        assert_eq!(broad_actual.live_persistent_bytes, scalar_actual.live_persistent_bytes);
        assert_eq!(broad_actual.peak_bytes, scalar_actual.peak_bytes);
        assert_eq!(build.persistent_bytes, scalar_build.persistent_bytes);
        assert_eq!(build.peak_bytes, scalar_build.peak_bytes);

        let exact_limits = BuildLimits {
            max_build_work: build.work,
            max_persistent_bytes: scalar_build.persistent_bytes,
            max_peak_bytes: scalar_build.peak_bytes,
            ..BuildLimits::unlimited()
        };
        let exact_quota = UnicodeScalarSearchPlan::build_repeated_count_attempt_with_dispatch(
            dispatch,
            [('\0', 'X'), ('\u{80}', '\u{80}')],
            1,
            None,
            true,
            exact_limits,
        )
        .unwrap();
        assert_eq!(exact_quota.actual(), broad_actual);
        assert!(matches!(
            exact_quota.into_plan(),
            CursorCountBuild::Scalar {
                leading_byte_count: 90,
                ..
            }
        ));

        let one_below = UnicodeScalarSearchPlan::build_repeated_count_attempt_with_dispatch(
            dispatch,
            [('\0', 'X'), ('\u{80}', '\u{80}')],
            1,
            None,
            true,
            BuildLimits {
                max_build_work: build.work - 1,
                max_persistent_bytes: scalar_build.persistent_bytes,
                max_peak_bytes: scalar_build.peak_bytes,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert_eq!(
            one_below.source(),
            &BuildError::WorkLimit {
                needed: build.work,
                limit: build.work - 1,
            }
        );
        let refused = one_below.actual();
        assert_eq!(refused.work, broad_actual.work);
        assert_eq!(refused.allocations, scalar_actual.allocations);
        assert_eq!(refused.allocated_bytes, scalar_actual.allocated_bytes);
        assert_eq!(refused.copied_bytes, scalar_actual.copied_bytes);
        assert_eq!(refused.initialized_bytes, scalar_actual.initialized_bytes);
        assert_eq!(refused.live_persistent_bytes, 0);
        assert_eq!(refused.peak_bytes, scalar_actual.peak_bytes);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one boundary table keeps exact success effects and every post-scalar wrapper refusal visibly coupled"
    )]
    fn scalar_run_search_build_attempt_is_exact_across_wrapper_boundaries() {
        let ranges = [('Α', 'Ω'), ('α', 'ω')];
        let dispatch = SimdDispatchContext::capture();
        let scalar_actual = UnicodeScalarAggregatePlan::build_repeated_attempt(
            ranges,
            2,
            Some(6),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap()
        .actual();
        let attempt = UnicodeScalarSearchPlan::build_repeated_attempt_with_dispatch(
            dispatch,
            ranges,
            2,
            Some(6),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let success_actual = attempt.actual();
        let (plan, actual) = attempt.into_parts();
        let build = plan.build_accounting();
        assert_eq!(actual, success_actual);
        assert_eq!(actual.work, u64::try_from(build.work).unwrap());
        assert_eq!(actual.allocations, scalar_actual.allocations);
        assert_eq!(actual.allocated_bytes, scalar_actual.allocated_bytes);
        assert_eq!(actual.copied_bytes, scalar_actual.copied_bytes);
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(
            actual.peak_bytes,
            scalar_actual.peak_bytes.max(build.persistent_bytes),
        );
        assert!(actual.peak_bytes <= build.peak_bytes);
        assert_eq!(
            UnicodeScalarSearchPlan::build_repeated_with_dispatch(
                dispatch,
                ranges,
                2,
                Some(6),
                true,
                BuildLimits::unlimited(),
            )
            .unwrap()
            .build_accounting(),
            build,
        );

        assert!(build.work > build.scalar.work);
        assert!(build.persistent_bytes > build.scalar.persistent_bytes);
        assert!(build.peak_bytes > build.scalar.peak_bytes);
        let assert_post_scalar_refusal = |refused: crate::DirectBuildAttemptActual| {
            assert_eq!(refused.work, u64::try_from(build.work).unwrap());
            assert_eq!(refused.allocations, scalar_actual.allocations);
            assert_eq!(refused.allocated_bytes, scalar_actual.allocated_bytes);
            assert_eq!(refused.copied_bytes, scalar_actual.copied_bytes);
            assert_eq!(refused.initialized_bytes, scalar_actual.initialized_bytes);
            assert_eq!(refused.live_persistent_bytes, 0);
            assert_eq!(refused.peak_bytes, scalar_actual.peak_bytes);
        };

        let work_error = UnicodeScalarSearchPlan::build_repeated_attempt_with_dispatch(
            dispatch,
            ranges,
            2,
            Some(6),
            true,
            BuildLimits {
                max_build_work: build.work - 1,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert_eq!(
            work_error.source(),
            &BuildError::WorkLimit {
                needed: build.work,
                limit: build.work - 1,
            },
        );
        assert_post_scalar_refusal(work_error.actual());

        let persistent_error = UnicodeScalarSearchPlan::build_repeated_attempt_with_dispatch(
            dispatch,
            ranges,
            2,
            Some(6),
            true,
            BuildLimits {
                max_persistent_bytes: build.persistent_bytes - 1,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert_eq!(
            persistent_error.source(),
            &BuildError::PersistentLimit {
                needed: build.persistent_bytes,
                limit: build.persistent_bytes - 1,
            },
        );
        assert_post_scalar_refusal(persistent_error.actual());

        let peak_error = UnicodeScalarSearchPlan::build_repeated_attempt_with_dispatch(
            dispatch,
            ranges,
            2,
            Some(6),
            true,
            BuildLimits {
                max_peak_bytes: build.peak_bytes - 1,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert_eq!(
            peak_error.source(),
            &BuildError::PeakLimit {
                needed: build.peak_bytes,
                limit: build.peak_bytes - 1,
            },
        );
        assert_post_scalar_refusal(peak_error.actual());
    }

    fn exact_cursor_count_limits(
        plan: &UnicodeScalarSearchPlan,
        input_bytes: usize,
    ) -> ReduceLimits {
        let upper = plan.cursor_count_upper_bounds(input_bytes).unwrap();
        ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_decode_byte_checks: upper.decode_byte_checks,
            max_membership_tests: upper.membership_tests,
            max_range_comparisons: upper.range_comparisons,
            max_reducer_steps: upper.reducer_steps,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: u64::MAX,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }

    #[test]
    fn scalar_cursor_count_matches_pinned_bytes_regex_across_unrelated_families() {
        let cases = [
            (
                vec![('+', '+'), ('<', '>')],
                1,
                Some(1),
                true,
                r"[+<=>]",
                b"plain + math <= bytes > and \x80 invalid\xff".as_slice(),
            ),
            (
                vec![('Α', 'Ω'), ('α', 'ω')],
                1,
                None,
                true,
                r"[Α-Ωα-ω]+",
                "--αβγ--plain--ΩΑ--δ--".as_bytes(),
            ),
            (
                vec![('Α', 'Ω'), ('α', 'ω')],
                1,
                None,
                false,
                r"[Α-Ωα-ω]+?",
                "--αβγ--plain--ΩΑ--δ--".as_bytes(),
            ),
            (
                vec![('А', 'я')],
                2,
                Some(6),
                true,
                r"[А-Яа-я]{2,6}",
                "xxПривет--мир--Я--данные--".as_bytes(),
            ),
        ];
        for (ranges, minimum, maximum, greedy, pattern, haystack) in cases {
            let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
                SimdDispatchContext::capture(),
                ranges,
                minimum,
                maximum,
                greedy,
                BuildLimits::unlimited(),
            )
            .unwrap();
            let expected = u64::try_from(
                RegexBuilder::new(pattern)
                    .build()
                    .unwrap()
                    .find_iter(haystack)
                    .count(),
            )
            .unwrap();
            let result = plan
                .count_with_cursor(haystack, ReduceLimits::unlimited())
                .unwrap();
            assert_eq!(result.count, expected, "pattern={pattern:?}");
            assert_eq!(result.accounting.actual.count, expected);
            assert_eq!(
                plan.count_with_cursor_value(haystack, ReduceLimits::unlimited())
                    .unwrap(),
                expected,
            );
            assert_eq!(
                result.accounting.identity.plan_id,
                CURSOR_COUNT_PLAN_ID,
            );
            assert_eq!(
                result.accounting.identity.operation_id,
                CURSOR_COUNT_OPERATION_ID,
            );
            assert_eq!(result.accounting.identity.operation, Operation::Count);
            assert_eq!(
                result.accounting.actual.input_bytes_advanced,
                haystack.len(),
            );
            assert!(
                result.accounting.actual.search_calls
                    <= result.accounting.upper_bounds.search_calls,
            );
        }
    }

    #[test]
    fn scalar_cursor_count_dense_cutover_is_exact_and_one_way() {
        let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            [('a', 'a')],
            1,
            Some(1),
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let haystack = vec![b'a'; 4096];
        let result = plan
            .count_with_cursor(&haystack, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(result.count, u64::try_from(haystack.len()).unwrap());
        assert!(result.accounting.actual.dense_cutover);
        assert_eq!(result.accounting.actual.dense_samples, 1);
        assert_eq!(
            result.accounting.actual.cursor_match_events,
            CURSOR_COUNT_DENSE_SAMPLE_MATCHES,
        );
        assert_eq!(
            result.accounting.actual.search_calls,
            CURSOR_COUNT_DENSE_SAMPLE_MATCHES,
        );
        assert_eq!(
            result.accounting.actual.cursor_semantic_prefix_bytes,
            CURSOR_COUNT_DENSE_SAMPLE_MATCHES,
        );
        assert_eq!(
            result.accounting.actual.scalar_semantic_suffix_bytes,
            haystack.len() - CURSOR_COUNT_DENSE_SAMPLE_MATCHES,
        );
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "fixed test dimensions construct the exact density threshold and its two adjacent boundaries"
    )]
    fn scalar_cursor_count_greedy_handoff_closes_adjacent_density_boundaries() {
        let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            [('a', 'a')],
            1,
            None,
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let threshold =
            CURSOR_COUNT_DENSE_SAMPLE_MATCHES * CURSOR_COUNT_DENSE_MAX_MEAN_BYTES;
        for (sampled_bytes, expect_cutover) in [
            (threshold - 1, true),
            (threshold, true),
            (threshold + 1, false),
        ] {
            let ordinary_gap = CURSOR_COUNT_DENSE_MAX_MEAN_BYTES - 1;
            let base_sampled_bytes = CURSOR_COUNT_DENSE_SAMPLE_MATCHES
                + (CURSOR_COUNT_DENSE_SAMPLE_MATCHES - 1) * ordinary_gap;
            let first_gap_extra = sampled_bytes - base_sampled_bytes;
            let mut haystack = Vec::new();
            for index in 0..CURSOR_COUNT_DENSE_SAMPLE_MATCHES {
                haystack.push(b'a');
                if index + 1 != CURSOR_COUNT_DENSE_SAMPLE_MATCHES {
                    let gap = ordinary_gap + usize::from(index == 0) * first_gap_extra;
                    haystack.extend(core::iter::repeat_n(b'!', gap));
                }
            }
            assert_eq!(haystack.len(), sampled_bytes);
            // Greedy search decodes this rejecting byte before publishing the
            // 64th match end. When cutover fires, the scalar owner begins its
            // semantic suffix at that same already-probed byte.
            haystack.extend_from_slice(b"!aaaa");
            let expected = u64::try_from(
                RegexBuilder::new("a+")
                    .build()
                    .unwrap()
                    .find_iter(&haystack)
                    .count(),
            )
            .unwrap();
            let result = plan
                .count_with_cursor(&haystack, ReduceLimits::unlimited())
                .unwrap();
            assert_eq!(expected, 65);
            assert_eq!(result.count, expected, "sampled_bytes={sampled_bytes}");
            assert_eq!(
                result.accounting.actual.dense_cutover,
                expect_cutover,
                "sampled_bytes={sampled_bytes}",
            );
            assert_eq!(result.accounting.actual.dense_samples, 1);
            if expect_cutover {
                assert_eq!(
                    result.accounting.actual.cursor_match_events,
                    CURSOR_COUNT_DENSE_SAMPLE_MATCHES,
                );
                assert_eq!(
                    result.accounting.actual.search_calls,
                    CURSOR_COUNT_DENSE_SAMPLE_MATCHES,
                );
                assert_eq!(
                    result.accounting.actual.cursor_semantic_prefix_bytes,
                    sampled_bytes,
                );
                assert_eq!(
                    result.accounting.actual.scalar_semantic_suffix_bytes,
                    haystack.len() - sampled_bytes,
                );
            } else {
                assert_eq!(
                    result.accounting.actual.cursor_match_events,
                    usize::try_from(expected).unwrap(),
                );
                assert_eq!(
                    result.accounting.actual.search_calls,
                    usize::try_from(expected).unwrap() + 1,
                );
                assert_eq!(
                    result.accounting.actual.cursor_semantic_prefix_bytes,
                    haystack.len(),
                );
                assert_eq!(result.accounting.actual.scalar_semantic_suffix_bytes, 0);
            }
            assert_eq!(
                result.accounting.actual.control_work,
                result.accounting.actual.search_calls + usize::try_from(expected).unwrap(),
            );
        }
    }

    #[test]
    fn scalar_cursor_count_windowed_malformed_oracle_closes_bounded_repetitions() {
        let haystack = [
            0xFF, b'x', 0xCE, 0xB1, 0xCE, 0xB2, 0xCE, 0xB3, b'-', 0x80, 0xCE, 0xA9,
            0xCE, 0x91, 0xE2, 0x82,
        ];
        let windows = [
            Window::new(0, haystack.len()),
            Window::new(3, haystack.len()),
            Window::new(0, 7),
            Window::new(3, 13),
            Window::new(5, 11),
        ];
        for (minimum, maximum, greedy, pattern) in [
            (2, Some(4), false, r"[Α-Ωα-ω]{2,4}?"),
            (3, Some(5), true, r"[Α-Ωα-ω]{3,5}"),
        ] {
            let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
                SimdDispatchContext::capture(),
                [('Α', 'Ω'), ('α', 'ω')],
                minimum,
                maximum,
                greedy,
                BuildLimits::unlimited(),
            )
            .unwrap();
            let oracle = RegexBuilder::new(pattern).build().unwrap();
            for window in windows {
                let local = &haystack[window.start()..window.end()];
                let expected = u64::try_from(oracle.find_iter(local).count()).unwrap();
                let result = plan
                    .count_with_cursor_in(&haystack, window, ReduceLimits::unlimited())
                    .unwrap();
                assert_eq!(
                    result.count, expected,
                    "pattern={pattern:?}, window={window:?}",
                );
                assert_eq!(result.accounting.actual.input_bytes_advanced, local.len());
                assert_eq!(
                    result
                        .accounting
                        .actual
                        .cursor_semantic_prefix_bytes
                        .checked_add(result.accounting.actual.scalar_semantic_suffix_bytes),
                    Some(local.len()),
                );
                assert!(!result.accounting.actual.dense_cutover);
                assert_eq!(
                    plan.count_with_cursor_value_in(
                        &haystack,
                        window,
                        ReduceLimits::unlimited(),
                    )
                    .unwrap(),
                    expected,
                );
            }
        }
    }

    #[test]
    fn scalar_cursor_count_sparse_stream_retains_cursor_to_eof() {
        let plan = UnicodeScalarSearchPlan::build_repeated_with_dispatch(
            SimdDispatchContext::capture(),
            [('Α', 'Ω'), ('α', 'ω')],
            1,
            None,
            true,
            BuildLimits::unlimited(),
        )
        .unwrap();
        let mut haystack = vec![b'x'; 4096];
        haystack.extend_from_slice("--αβ--".as_bytes());
        haystack.extend(core::iter::repeat_n(b'x', 4096));
        let result = plan
            .count_with_cursor(&haystack, ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(result.count, 1);
        assert!(!result.accounting.actual.dense_cutover);
        assert_eq!(result.accounting.actual.scalar_semantic_suffix_bytes, 0);
        assert_eq!(
            result.accounting.actual.cursor_semantic_prefix_bytes,
            haystack.len(),
        );
        assert_eq!(result.accounting.actual.cursor_match_events, 1);
        assert_eq!(result.accounting.actual.search_calls, 2);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the single boundary table checks exact and one-below behavior for every independently limited cursor Count resource"
    )]
    fn scalar_cursor_count_prospective_limits_fail_before_execution() {
        let plan = greek_search_plan(true);
        let haystack = "xxαβγ--plain--ΩΑ--δ--".as_bytes();
        let exact = exact_cursor_count_limits(&plan, haystack.len());
        let exact_result = plan.count_with_cursor(haystack, exact).unwrap();
        assert_eq!(exact_result.count, 2);

        let cases = [
            (
                ReduceLimits {
                    max_input_bytes: exact.max_input_bytes - 1,
                    ..exact
                },
                "input",
            ),
            (
                ReduceLimits {
                    max_decode_byte_checks: exact.max_decode_byte_checks - 1,
                    ..exact
                },
                "decode",
            ),
            (
                ReduceLimits {
                    max_membership_tests: exact.max_membership_tests - 1,
                    ..exact
                },
                "membership",
            ),
            (
                ReduceLimits {
                    max_range_comparisons: exact.max_range_comparisons - 1,
                    ..exact
                },
                "ranges",
            ),
            (
                ReduceLimits {
                    max_reducer_steps: exact.max_reducer_steps - 1,
                    ..exact
                },
                "reducer",
            ),
            (
                ReduceLimits {
                    max_match_events: exact.max_match_events - 1,
                    ..exact
                },
                "events",
            ),
            (
                ReduceLimits {
                    max_count: exact.max_count - 1,
                    ..exact
                },
                "count",
            ),
            (
                ReduceLimits {
                    max_work: exact.max_work - 1,
                    ..exact
                },
                "work",
            ),
            (
                ReduceLimits {
                    max_peak_bytes: exact.max_peak_bytes - 1,
                    ..exact
                },
                "peak",
            ),
        ];
        for (limits, expected) in cases {
            let error = plan.count_with_cursor(haystack, limits).unwrap_err();
            let actual = match error {
                ReduceError::InputBytesLimit { .. } => "input",
                ReduceError::DecodeByteChecksLimit { .. } => "decode",
                ReduceError::MembershipTestsLimit { .. } => "membership",
                ReduceError::RangeComparisonsLimit { .. } => "ranges",
                ReduceError::ReducerStepsLimit { .. } => "reducer",
                ReduceError::MatchEventsLimit { .. } => "events",
                ReduceError::CountLimit { .. } => "count",
                ReduceError::WorkLimit { .. } => "work",
                ReduceError::PeakLimit { .. } => "peak",
                other => panic!("unexpected cursor Count error: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
        assert!(matches!(
            plan.count_with_cursor_in(
                haystack,
                Window::new(1, haystack.len() + 1),
                ReduceLimits::unlimited(),
            ),
            Err(ReduceError::InvalidWindow { .. }),
        ));
        assert!(matches!(
            plan.cursor_count_upper_bounds(usize::MAX),
            Err(ReduceError::ArithmeticOverflow { .. }),
        ));
    }
}
