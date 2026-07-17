//! Bounded operation-specific native kernels below the FRE planner.
//!
//! The first plan is an exact-literal substring search backed by `memchr`'s
//! native/SIMD-aware `memmem::Finder`. It is a shared native primitive, not a
//! pattern-specialized JIT. The dependency documents worst-case
//! `O(needle.len() + haystack.len())` time and constant search space.

#![forbid(unsafe_code)]

use core::fmt;

use fre_exact_alloc::CopyError;
use memchr::memmem::{Finder, FinderBuilder};

mod bounded_class_sequence;
mod fixed_class_sandwich;
mod forward_anchored;
mod literal_aggregate;
mod literal_set;
mod ordered_literal_aggregate;
mod packed_literal_set;
mod packed_ordered_literal_aggregate;
mod prefix_class_alternation;
mod required_literal;
mod sparse_ordered_literal_aggregate;
mod unicode_scalar_aggregate;

pub use bounded_class_sequence::{
    BoundedClassSequencePlan, BuildAccounting as BoundedClassSequenceBuildAccounting,
    BuildError as BoundedClassSequenceBuildError, BuildLimits as BoundedClassSequenceBuildLimits,
    COUNT_OPERATION_ID as BOUNDED_CLASS_SEQUENCE_COUNT_OPERATION_ID,
    CountResult as BoundedClassSequenceCountResult,
    OperationIdentity as BoundedClassSequenceOperationIdentity,
    PLAN_ID as BOUNDED_CLASS_SEQUENCE_PLAN_ID,
    ReduceAccounting as BoundedClassSequenceReduceAccounting,
    ReduceActualCounters as BoundedClassSequenceActualCounters,
    ReduceError as BoundedClassSequenceReduceError,
    ReduceLimits as BoundedClassSequenceReduceLimits,
    ReduceUpperBounds as BoundedClassSequenceUpperBounds,
};

pub use fixed_class_sandwich::{
    BuildAccounting as FixedClassSandwichBuildAccounting,
    BuildError as FixedClassSandwichBuildError, BuildLimits as FixedClassSandwichBuildLimits,
    COUNT_OPERATION_ID as FIXED_CLASS_SANDWICH_COUNT_OPERATION_ID,
    CountResult as FixedClassSandwichCountResult, FixedClassSandwichPlan,
    Operation as FixedClassSandwichOperation,
    OperationIdentity as FixedClassSandwichOperationIdentity,
    PLAN_ID as FIXED_CLASS_SANDWICH_PLAN_ID,
    ReduceAccounting as FixedClassSandwichReduceAccounting,
    ReduceActualCounters as FixedClassSandwichActualCounters,
    ReduceError as FixedClassSandwichReduceError, ReduceLimits as FixedClassSandwichReduceLimits,
    ReduceUpperBounds as FixedClassSandwichUpperBounds,
    SPAN_SUM_OPERATION_ID as FIXED_CLASS_SANDWICH_SPAN_SUM_OPERATION_ID,
    Semantics as FixedClassSandwichSemantics, SpanSumResult as FixedClassSandwichSpanSumResult,
};
pub use forward_anchored::{
    ABSOLUTE_END_FIXED_PLAN_ID, AbsoluteEndFixedPlan, Anchors as ForwardAnchoredAnchors,
    BuildAccounting as ForwardAnchoredBuildAccounting, BuildError as ForwardAnchoredBuildError,
    BuildLimits as ForwardAnchoredBuildLimits, ByteClass as ForwardAnchoredByteClass,
    ClassImplementation as ForwardClassImplementation, ForwardAnchoredPlan,
    PLAN_ID as FORWARD_ANCHORED_PLAN_ID, SearchAccounting as ForwardAnchoredSearchAccounting,
    SearchError as ForwardAnchoredSearchError, SearchLimits as ForwardAnchoredSearchLimits,
};

pub use literal_aggregate::{
    BoundarySemantics as LiteralAggregateBoundarySemantics,
    BuildAccounting as LiteralAggregateBuildAccounting, BuildError as LiteralAggregateBuildError,
    BuildLimits as LiteralAggregateBuildLimits,
    COUNT_OPERATION_ID as LITERAL_AGGREGATE_COUNT_OPERATION_ID,
    CountResult as LiteralAggregateCountResult, LiteralAggregatePlan,
    Operation as LiteralAggregateOperation, OperationIdentity as LiteralAggregateOperationIdentity,
    PLAN_ID as LITERAL_AGGREGATE_PLAN_ID, ReduceAccounting as LiteralAggregateReduceAccounting,
    ReduceActualCounters as LiteralAggregateActualCounters,
    ReduceError as LiteralAggregateReduceError, ReduceLimits as LiteralAggregateReduceLimits,
    ReduceUpperBounds as LiteralAggregateUpperBounds,
    SPAN_SUM_OPERATION_ID as LITERAL_AGGREGATE_SPAN_SUM_OPERATION_ID,
    SpanSumResult as LiteralAggregateSpanSumResult,
};

pub use literal_set::{
    LiteralSetAccounting, LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError,
    LiteralSetPlan, LiteralSetSearchLimits,
};
pub use ordered_literal_aggregate::{
    ALGORITHM_ID as ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    BoundarySemantics as OrderedLiteralAggregateBoundarySemantics,
    BuildAccounting as OrderedLiteralAggregateBuildAccounting,
    BuildError as OrderedLiteralAggregateBuildError,
    BuildLimits as OrderedLiteralAggregateBuildLimits,
    COUNT_PLAN_ID as ORDERED_LITERAL_COUNT_PLAN_ID,
    CacheIdentity as OrderedLiteralAggregateCacheIdentity,
    CountResult as OrderedLiteralCountResult,
    IterationSemantics as OrderedLiteralAggregateIterationSemantics,
    MatchSemantics as OrderedLiteralAggregateMatchSemantics,
    Operation as OrderedLiteralAggregateOperation, OrderedLiteralCountPlan,
    OrderedLiteralSpanSumPlan, ReduceAccounting as OrderedLiteralAggregateReduceAccounting,
    ReduceActualCounters as OrderedLiteralAggregateActualCounters,
    ReduceError as OrderedLiteralAggregateReduceError,
    ReduceLimits as OrderedLiteralAggregateReduceLimits,
    ReduceUpperBounds as OrderedLiteralAggregateUpperBounds,
    SPAN_SUM_PLAN_ID as ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    Semantics as OrderedLiteralAggregateSemantics, SpanSumResult as OrderedLiteralSpanSumResult,
};
pub use packed_literal_set::{
    PackedLiteralSetAccounting, PackedLiteralSetBuildAccounting, PackedLiteralSetBuildLimits,
    PackedLiteralSetError, PackedLiteralSetPlan, PackedLiteralSetSearchLimits,
};
pub use packed_ordered_literal_aggregate::{
    AHO_CORASICK_PACKAGE_CHECKSUM as PACKED_ORDERED_LITERAL_AHO_CORASICK_CHECKSUM,
    AHO_CORASICK_VERSION as PACKED_ORDERED_LITERAL_AHO_CORASICK_VERSION,
    ALGORITHM_ID as PACKED_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    BuildAccounting as PackedOrderedLiteralAggregateBuildAccounting,
    BuildError as PackedOrderedLiteralAggregateBuildError,
    BuildLimits as PackedOrderedLiteralAggregateBuildLimits,
    CERTIFIED_MAX_PATTERN_BYTES as PACKED_ORDERED_LITERAL_CERTIFIED_MAX_PATTERN_BYTES,
    CERTIFIED_MAX_PATTERNS as PACKED_ORDERED_LITERAL_CERTIFIED_MAX_PATTERNS,
    CERTIFIED_MAX_TOTAL_PATTERN_BYTES as PACKED_ORDERED_LITERAL_CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
    COUNT_PLAN_ID as PACKED_ORDERED_LITERAL_COUNT_PLAN_ID,
    CacheIdentity as PackedOrderedLiteralAggregateCacheIdentity,
    CountResult as PackedOrderedLiteralCountResult, PackedOrderedLiteralCountPlan,
    PackedOrderedLiteralSpanSumPlan,
    ReduceAccounting as PackedOrderedLiteralAggregateReduceAccounting,
    ReduceActualCounters as PackedOrderedLiteralAggregateActualCounters,
    ReduceError as PackedOrderedLiteralAggregateReduceError,
    ReduceLimits as PackedOrderedLiteralAggregateReduceLimits,
    ReduceUpperBounds as PackedOrderedLiteralAggregateUpperBounds,
    SPAN_SUM_PLAN_ID as PACKED_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    SpanSumResult as PackedOrderedLiteralSpanSumResult,
};
pub use prefix_class_alternation::{
    BuildAccounting as PrefixClassAlternationBuildAccounting,
    BuildError as PrefixClassAlternationBuildError,
    BuildLimits as PrefixClassAlternationBuildLimits,
    COUNT_OPERATION_ID as PREFIX_CLASS_ALTERNATION_COUNT_OPERATION_ID,
    CountResult as PrefixClassAlternationCountResult,
    OperationIdentity as PrefixClassAlternationOperationIdentity,
    PLAN_ID as PREFIX_CLASS_ALTERNATION_PLAN_ID, PrefixClassAlternationPlan,
    ReduceAccounting as PrefixClassAlternationReduceAccounting,
    ReduceActualCounters as PrefixClassAlternationActualCounters,
    ReduceError as PrefixClassAlternationReduceError,
    ReduceLimits as PrefixClassAlternationReduceLimits,
    ReduceUpperBounds as PrefixClassAlternationUpperBounds,
};
pub use required_literal::{
    Anchors as RequiredLiteralAnchors, BuildAccounting as RequiredLiteralBuildAccounting,
    BuildError as RequiredLiteralBuildError, BuildLimits as RequiredLiteralBuildLimits,
    ByteClass as RequiredLiteralByteClass, PLAN_ID as REQUIRED_LITERAL_PLAN_ID,
    RequiredLiteralPlan, SearchAccounting as RequiredLiteralSearchAccounting,
    SearchError as RequiredLiteralSearchError, SearchLimits as RequiredLiteralSearchLimits,
};
pub use sparse_ordered_literal_aggregate::{
    ALGORITHM_ID as SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    BoundarySemantics as SparseOrderedLiteralAggregateBoundarySemantics,
    BuildAccounting as SparseOrderedLiteralAggregateBuildAccounting,
    BuildError as SparseOrderedLiteralAggregateBuildError,
    BuildLimits as SparseOrderedLiteralAggregateBuildLimits,
    COUNT_PLAN_ID as SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
    CacheIdentity as SparseOrderedLiteralAggregateCacheIdentity,
    CountResult as SparseOrderedLiteralCountResult,
    IterationSemantics as SparseOrderedLiteralAggregateIterationSemantics,
    MatchSemantics as SparseOrderedLiteralAggregateMatchSemantics,
    Operation as SparseOrderedLiteralAggregateOperation,
    ReduceAccounting as SparseOrderedLiteralAggregateReduceAccounting,
    ReduceActualCounters as SparseOrderedLiteralAggregateActualCounters,
    ReduceError as SparseOrderedLiteralAggregateReduceError,
    ReduceLimits as SparseOrderedLiteralAggregateReduceLimits,
    ReduceUpperBounds as SparseOrderedLiteralAggregateUpperBounds,
    SPAN_SUM_PLAN_ID as SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    Semantics as SparseOrderedLiteralAggregateSemantics,
    SpanSumResult as SparseOrderedLiteralSpanSumResult, SparseOrderedLiteralCountPlan,
    SparseOrderedLiteralSpanSumPlan,
};
pub use unicode_scalar_aggregate::{
    BuildAccounting as UnicodeScalarAggregateBuildAccounting,
    BuildError as UnicodeScalarAggregateBuildError,
    BuildLimits as UnicodeScalarAggregateBuildLimits,
    COUNT_OPERATION_ID as UNICODE_SCALAR_AGGREGATE_COUNT_OPERATION_ID,
    CountResult as UnicodeScalarAggregateCountResult, Operation as UnicodeScalarAggregateOperation,
    OperationIdentity as UnicodeScalarAggregateOperationIdentity,
    PLAN_ID as UNICODE_SCALAR_AGGREGATE_PLAN_ID,
    RUN_COUNT_OPERATION_ID as UNICODE_SCALAR_RUN_AGGREGATE_COUNT_OPERATION_ID,
    RUN_PLAN_ID as UNICODE_SCALAR_RUN_AGGREGATE_PLAN_ID,
    RUN_SPAN_SUM_OPERATION_ID as UNICODE_SCALAR_RUN_AGGREGATE_SPAN_SUM_OPERATION_ID,
    ReduceAccounting as UnicodeScalarAggregateReduceAccounting,
    ReduceActualCounters as UnicodeScalarAggregateActualCounters,
    ReduceError as UnicodeScalarAggregateReduceError,
    ReduceLimits as UnicodeScalarAggregateReduceLimits,
    ReduceUpperBounds as UnicodeScalarAggregateUpperBounds,
    Repetition as UnicodeScalarAggregateRepetition,
    SPAN_SUM_OPERATION_ID as UNICODE_SCALAR_AGGREGATE_SPAN_SUM_OPERATION_ID,
    ScalarSemantics as UnicodeScalarAggregateSemantics,
    SpanSumResult as UnicodeScalarAggregateSpanSumResult, UnicodeScalarAggregatePlan,
};

/// Hard limits for building one exact-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralBuildLimits {
    /// Maximum copied needle bytes.
    pub max_needle_bytes: usize,
}

impl Default for LiteralBuildLimits {
    fn default() -> Self {
        Self {
            max_needle_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Per-search limits for a linear exact-literal invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSearchLimits {
    /// Maximum `needle bytes + searched haystack bytes` linear terms.
    pub max_linear_terms: usize,
}

impl LiteralSearchLimits {
    /// No caller-selected limit. Address-space arithmetic remains checked.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_linear_terms: usize::MAX,
        }
    }
}

impl Default for LiteralSearchLimits {
    fn default() -> Self {
        Self {
            max_linear_terms: 128 * 1024 * 1024,
        }
    }
}

/// Half-open byte range searched within the original haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window {
    start: usize,
    end: usize,
}

impl Window {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn full(haystack: &[u8]) -> Self {
        Self {
            start: 0,
            end: haystack.len(),
        }
    }

    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// Exact accounting/certificate inputs for one literal search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralAccounting {
    /// Needle length used by the linear bound.
    pub needle_bytes: usize,
    /// Searched haystack range length used by the linear bound.
    pub searched_bytes: usize,
    /// Checked sum of the two linear terms.
    pub linear_terms: usize,
    /// Search scratch bytes required by the plan contract.
    pub scratch_bytes: usize,
}

/// Exact literal build or search failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LiteralError {
    NeedleLimit {
        needed: usize,
        limit: usize,
    },
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    LinearTermLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    /// The exact owned-needle allocation failed.
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
}

impl fmt::Display for LiteralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedleLimit { needed, limit } => {
                write!(f, "literal needs {needed} needle bytes, exceeding {limit}")
            }
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "literal window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::LinearTermLimit { needed, limit } => write!(
                f,
                "literal search needs {needed} linear terms, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(f, "failed to allocate {additional} bytes for {structure}"),
        }
    }
}

impl std::error::Error for LiteralError {}

/// Immutable exact-literal plan with an owned preprocessed finder.
#[derive(Debug)]
pub struct LiteralPlan {
    finder: Finder<'static>,
    needle_bytes: usize,
}

impl LiteralPlan {
    /// Copy and preprocess one byte needle.
    ///
    /// # Errors
    ///
    /// Returns [`LiteralError::NeedleLimit`] before construction if the
    /// declared payload cap is too small. Allocation failure is returned as a
    /// typed error; this plan deliberately does not implement `Clone` because
    /// cloning its owned finder would introduce an unmetered allocation.
    pub fn new(needle: &[u8], limits: LiteralBuildLimits) -> Result<Self, LiteralError> {
        if needle.len() > limits.max_needle_bytes {
            return Err(LiteralError::NeedleLimit {
                needed: needle.len(),
                limit: limits.max_needle_bytes,
            });
        }
        let owned = copy_literal_exact(needle)?;
        Ok(Self {
            finder: FinderBuilder::new().build_forward_owned(owned),
            needle_bytes: needle.len(),
        })
    }

    /// Logical persistent pattern payload bytes.
    #[must_use]
    pub const fn storage_bytes(&self) -> usize {
        self.needle_bytes
    }

    /// The preprocessed needle.
    #[must_use]
    pub fn needle(&self) -> &[u8] {
        self.finder.needle()
    }

    /// Find the first occurrence in a full haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked resource/arithmetic error before invoking the native
    /// primitive.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: LiteralSearchLimits,
    ) -> Result<(Option<(usize, usize)>, LiteralAccounting), LiteralError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the first occurrence wholly inside a range.
    ///
    /// # Errors
    ///
    /// Returns [`LiteralError::InvalidWindow`] or a checked limit/arithmetic
    /// error before invoking the native primitive.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSearchLimits,
    ) -> Result<(Option<(usize, usize)>, LiteralAccounting), LiteralError> {
        if window.start > window.end || window.end > haystack.len() {
            return Err(LiteralError::InvalidWindow {
                start: window.start,
                end: window.end,
                haystack_len: haystack.len(),
            });
        }
        let searched_bytes =
            window
                .end
                .checked_sub(window.start)
                .ok_or(LiteralError::ArithmeticOverflow {
                    computation: "literal window length",
                })?;
        let linear_terms = searched_bytes.checked_add(self.needle_bytes).ok_or(
            LiteralError::ArithmeticOverflow {
                computation: "literal linear terms",
            },
        )?;
        if linear_terms > limits.max_linear_terms {
            return Err(LiteralError::LinearTermLimit {
                needed: linear_terms,
                limit: limits.max_linear_terms,
            });
        }
        let accounting = LiteralAccounting {
            needle_bytes: self.needle_bytes,
            searched_bytes,
            linear_terms,
            scratch_bytes: 0,
        };
        let relative = self.finder.find(&haystack[window.start..window.end]);
        let matched =
            relative
                .map(|relative| {
                    let start = window.start.checked_add(relative).ok_or(
                        LiteralError::ArithmeticOverflow {
                            computation: "literal match start",
                        },
                    )?;
                    let end = start.checked_add(self.needle_bytes).ok_or(
                        LiteralError::ArithmeticOverflow {
                            computation: "literal match end",
                        },
                    )?;
                    Ok((start, end))
                })
                .transpose()?;
        Ok((matched, accounting))
    }
}

fn copy_literal_exact(needle: &[u8]) -> Result<Vec<u8>, LiteralError> {
    #[cfg(test)]
    exact_literal_copy_probe::record();
    #[cfg(test)]
    if let Some(error) = exact_literal_copy_probe::take_failure() {
        return Err(map_literal_copy_error(error, needle.len()));
    }
    fre_exact_alloc::copy_exact(needle).map_err(|error| map_literal_copy_error(error, needle.len()))
}

const fn map_literal_copy_error(error: CopyError, needle_len: usize) -> LiteralError {
    match error {
        CopyError::LayoutOverflow => LiteralError::ArithmeticOverflow {
            computation: "exact literal allocation layout",
        },
        CopyError::AllocationFailed => LiteralError::AllocationFailed {
            structure: "exact literal needle",
            additional: needle_len,
        },
    }
}

#[cfg(test)]
mod exact_literal_copy_probe {
    use std::cell::Cell;

    use fre_exact_alloc::CopyError;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static FAILURE: Cell<Option<CopyError>> = const { Cell::new(None) };
    }

    pub(super) fn record() {
        CALLS.set(CALLS.get().checked_add(1).expect("test probe overflow"));
    }

    pub(super) fn reset() {
        CALLS.set(0);
        FAILURE.set(None);
    }

    pub(super) fn calls() -> usize {
        CALLS.get()
    }

    pub(super) fn fail_next(error: CopyError) {
        FAILURE.set(Some(error));
    }

    pub(super) fn take_failure() -> Option<CopyError> {
        let failure = FAILURE.get();
        FAILURE.set(None);
        failure
    }
}

#[cfg(test)]
mod tests {
    use fre_exact_alloc::CopyError;

    use super::{
        LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits, Window,
        copy_literal_exact, exact_literal_copy_probe,
    };

    #[test]
    fn literals_and_empty_needles_keep_exact_offsets() {
        let plan = LiteralPlan::new(b"aba", LiteralBuildLimits::default()).unwrap();
        let (matched, accounting) = plan
            .find(b"zzababa", LiteralSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((2, 5)));
        assert_eq!(accounting.needle_bytes, 3);
        assert_eq!(accounting.searched_bytes, 7);

        let empty = LiteralPlan::new(b"", LiteralBuildLimits::default()).unwrap();
        assert_eq!(
            empty
                .find_window(b"abc", Window::new(2, 3), LiteralSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((2, 2))
        );
    }

    #[test]
    fn exact_literal_plan_owns_the_fallibly_copied_needle() {
        let plan = {
            let source = b"temporary needle".to_vec();
            LiteralPlan::new(&source, LiteralBuildLimits::default()).unwrap()
        };
        assert_eq!(plan.needle(), b"temporary needle");
        assert_eq!(
            plan.find(
                b"a temporary needle survives",
                LiteralSearchLimits::unlimited()
            )
            .unwrap()
            .0,
            Some((2, 18))
        );
    }

    #[test]
    fn ranges_do_not_match_across_their_end() {
        let plan = LiteralPlan::new(b"bc", LiteralBuildLimits::default()).unwrap();
        assert_eq!(
            plan.find_window(b"abcd", Window::new(0, 2), LiteralSearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
    }

    #[test]
    fn every_declared_limit_fails_before_search() {
        exact_literal_copy_probe::reset();
        assert!(matches!(
            LiteralPlan::new(
                b"ab",
                LiteralBuildLimits {
                    max_needle_bytes: 1
                }
            ),
            Err(LiteralError::NeedleLimit { .. })
        ));
        assert_eq!(exact_literal_copy_probe::calls(), 0);
        let plan = LiteralPlan::new(b"ab", LiteralBuildLimits::default()).unwrap();
        assert!(matches!(
            plan.find(
                b"haystack",
                LiteralSearchLimits {
                    max_linear_terms: 1
                }
            ),
            Err(LiteralError::LinearTermLimit { .. })
        ));
    }

    #[test]
    fn exact_literal_copy_has_exact_capacity() {
        for len in [0_usize, 1, 2, 3, 7, 8, 15, 16, 31, 32, 255, 256, 4096] {
            let source: Vec<u8> = (0_u8..=u8::MAX).cycle().take(len).collect();
            exact_literal_copy_probe::reset();
            let owned = copy_literal_exact(&source).unwrap();
            assert_eq!(exact_literal_copy_probe::calls(), 1);
            assert_eq!(owned, source);
            assert_eq!(owned.capacity(), len);
        }
    }

    #[test]
    fn exact_literal_copy_failures_are_typed_without_retry() {
        for (injected, expected) in [
            (
                CopyError::LayoutOverflow,
                LiteralError::ArithmeticOverflow {
                    computation: "exact literal allocation layout",
                },
            ),
            (
                CopyError::AllocationFailed,
                LiteralError::AllocationFailed {
                    structure: "exact literal needle",
                    additional: 6,
                },
            ),
        ] {
            exact_literal_copy_probe::reset();
            exact_literal_copy_probe::fail_next(injected);
            assert_eq!(
                LiteralPlan::new(b"needle", LiteralBuildLimits::default()).unwrap_err(),
                expected
            );
            assert_eq!(exact_literal_copy_probe::calls(), 1);
        }
    }
}
