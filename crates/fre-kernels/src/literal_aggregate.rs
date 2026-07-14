//! Whole-haystack reducers for one exact byte literal.
//!
//! Nonempty needles traverse one pinned `memchr::memmem::Finder::find_iter`.
//! That iterator's public contract is non-overlapping, worst-case
//! `O(needle.len() + haystack.len())` time, and worst-case constant space.
//! This plan does not restart a black-box search on successive suffixes.
//!
//! Empty matching is deliberately a separate Unicode-disabled byte-boundary
//! formula: a haystack of `N` bytes has `N + 1` empty matches and zero matched
//! bytes. The operation identity records that scope explicitly.

use core::{fmt, mem::size_of};

use memchr::memmem::{Finder, FinderBuilder};

/// Stable identity for the exact-literal whole-haystack strategy.
pub const PLAN_ID: &str = "exact-literal-aggregate.memmem-find-iter.v1";
/// Stable identity for the match-count reducer.
pub const COUNT_OPERATION_ID: &str = "exact-literal-aggregate.count.byte-boundary.v1";
/// Stable identity for the checked matched-byte span-sum reducer.
pub const SPAN_SUM_OPERATION_ID: &str = "exact-literal-aggregate.span-sum.byte-boundary.v1";

/// Complete reducer selected for one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Number of successive non-overlapping matches.
    Count,
    /// Sum of `end - start` for every successive non-overlapping match.
    SpanSum,
}

/// Empty-match advancement semantics certified by this plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundarySemantics {
    /// Unicode is disabled and every byte boundary, including both ends,
    /// admits an empty match.
    EveryByteBoundaryUnicodeOff,
}

/// Stable semantic and implementation identity for one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    /// Whole-haystack implementation strategy.
    pub plan_id: &'static str,
    /// Operation-specific stable identifier.
    pub operation_id: &'static str,
    /// Reducer result requested by the caller.
    pub operation: Operation,
    /// Explicit empty-match boundary profile.
    pub boundary_semantics: BoundarySemantics,
    /// Whether successive matches are non-overlapping.
    pub non_overlapping: bool,
}

impl OperationIdentity {
    /// Return the immutable identity for one reducer.
    #[must_use]
    pub const fn for_operation(operation: Operation) -> Self {
        let operation_id = match operation {
            Operation::Count => COUNT_OPERATION_ID,
            Operation::SpanSum => SPAN_SUM_OPERATION_ID,
        };
        Self {
            plan_id: PLAN_ID,
            operation_id,
            operation,
            boundary_semantics: BoundarySemantics::EveryByteBoundaryUnicodeOff,
            non_overlapping: true,
        }
    }
}

/// Limits checked while constructing one owned literal reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    /// Maximum logical needle payload.
    pub max_needle_bytes: usize,
    /// Maximum abstract preprocessing units.
    pub max_build_work: u64,
    /// Maximum observed temporary allocation capacity.
    pub max_scratch_bytes: usize,
    /// Maximum retained inline plan plus owned needle payload.
    pub max_persistent_bytes: usize,
    /// Maximum conservative construction peak.
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    /// Disable caller-selected caps while retaining checked arithmetic and
    /// fallible initial reservation.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_needle_bytes: usize::MAX,
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
            max_needle_bytes: 32 * 1024 * 1024,
            max_build_work: 64 * 1024 * 1024,
            max_scratch_bytes: 32 * 1024 * 1024,
            max_persistent_bytes: 64 * 1024 * 1024,
            max_peak_bytes: 96 * 1024 * 1024,
        }
    }
}

/// Auditable construction certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    /// Logical retained needle bytes.
    pub needle_bytes: usize,
    /// Actual temporary `Vec` capacity observed after fallible reservation.
    pub temporary_capacity_bytes: usize,
    /// Abstract preprocessing upper bound.
    pub work_upper_bound: u64,
    /// Temporary allocation capacity charged during construction.
    pub scratch_bytes: usize,
    /// Inline plan size plus exact boxed needle payload.
    pub persistent_bytes: usize,
    /// Conservative persistent-plus-temporary construction peak.
    pub peak_bytes: usize,
}

/// Limits checked before the whole-haystack iterator or empty formula starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    /// Maximum abstract `needle bytes + haystack bytes` linear terms.
    pub max_linear_terms: usize,
    /// Maximum possible semantic match events.
    pub max_match_events: usize,
    /// Maximum possible count result.
    pub max_count: u64,
    /// Maximum possible span-sum result when span sum is requested.
    pub max_span_sum: u64,
    /// Maximum iterator/reducer control steps.
    pub max_reducer_steps: usize,
    /// Maximum caller-visible dynamic operation scratch.
    pub max_scratch_bytes: usize,
    /// Maximum retained-plan plus operation-scratch peak.
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    /// Disable caller-selected caps while retaining checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_linear_terms: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_linear_terms: 128 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: 128 * 1024 * 1024,
            max_reducer_steps: 64 * 1024 * 1024 + 1,
            max_scratch_bytes: 0,
            max_peak_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Preflight upper bounds for one complete reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    /// Haystack bytes covered by the whole operation.
    pub haystack_bytes: usize,
    /// Needle bytes covered by the linear iterator contract.
    pub needle_bytes: usize,
    /// Checked sum of the abstract linear terms.
    pub linear_terms: usize,
    /// Maximum number of semantic non-overlapping match events.
    pub match_events: usize,
    /// Same maximum represented in the public count result type.
    pub count: u64,
    /// Maximum sum of matched byte lengths.
    pub span_sum: u64,
    /// Maximum calls to iterator `next`, or one direct-formula step.
    pub reducer_steps: usize,
    /// Caller-visible dynamic operation scratch.
    pub scratch_bytes: usize,
    /// Retained plan bytes present during the operation.
    pub persistent_bytes: usize,
    /// Persistent-plus-operation-scratch peak.
    pub peak_bytes: usize,
}

/// Structural counters observed after a successful complete reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    /// Semantic matches represented by the reduction.
    pub match_events: usize,
    /// Calls made to the pinned iterator's `next` method.
    pub iterator_next_calls: usize,
    /// Direct formula evaluations; one for an empty needle, otherwise zero.
    pub empty_formula_evaluations: usize,
    /// Checked count result represented as an actual counter.
    pub count: u64,
    /// Checked matched bytes represented by all selected spans.
    pub matched_bytes: u64,
}

/// Upper bounds and actual counters for one published result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    /// Operation and byte-boundary semantics.
    pub identity: OperationIdentity,
    /// Bounds checked before any traversal or formula evaluation.
    pub upper_bounds: ReduceUpperBounds,
    /// Counters observed only after complete success.
    pub actual: ReduceActualCounters,
}

/// Complete match-count result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    /// Number of non-overlapping byte matches.
    pub count: u64,
    /// Complete resource certificate and structural counters.
    pub accounting: ReduceAccounting,
}

/// Complete checked matched-byte span-sum result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    /// Sum of `end - start` for all non-overlapping byte matches.
    pub span_sum: u64,
    /// Complete resource certificate and structural counters.
    pub accounting: ReduceAccounting,
}

/// Checked construction failure. No plan is published on error.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    /// Logical needle payload exceeds its cap.
    NeedleLimit { needed: usize, limit: usize },
    /// Abstract preprocessing work exceeds its cap.
    WorkLimit { needed: u64, limit: u64 },
    /// Observed temporary capacity exceeds its cap.
    ScratchLimit { needed: usize, limit: usize },
    /// Retained plan bytes exceed their cap.
    PersistentLimit { needed: usize, limit: usize },
    /// Conservative construction peak exceeds its cap.
    PeakLimit { needed: usize, limit: usize },
    /// Initial needle reservation failed.
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    /// Checked resource arithmetic overflowed.
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedleLimit { needed, limit } => {
                write!(f, "needle needs {needed} bytes, exceeding {limit}")
            }
            Self::WorkLimit { needed, limit } => {
                write!(f, "build needs {needed} work units, exceeding {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(f, "build needs {needed} scratch bytes, exceeding {limit}")
            }
            Self::PersistentLimit { needed, limit } => {
                write!(f, "plan needs {needed} persistent bytes, exceeding {limit}")
            }
            Self::PeakLimit { needed, limit } => {
                write!(f, "build peak is {needed} bytes, exceeding {limit}")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(f, "failed to reserve {additional} bytes for {structure}"),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Checked operation failure. No partial reducer value is published.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    /// Abstract linear terms exceed their cap.
    LinearTermsLimit { needed: usize, limit: usize },
    /// Possible semantic events exceed their cap.
    MatchEventsLimit { needed: usize, limit: usize },
    /// Possible count result exceeds its cap.
    CountLimit { needed: u64, limit: u64 },
    /// Possible requested span sum exceeds its cap.
    SpanSumLimit { needed: u64, limit: u64 },
    /// Possible iterator/formula steps exceed their cap.
    ReducerStepsLimit { needed: usize, limit: usize },
    /// Operation scratch exceeds its cap.
    ScratchLimit { needed: usize, limit: usize },
    /// Operation peak exceeds its cap.
    PeakLimit { needed: usize, limit: usize },
    /// Checked resource or result arithmetic overflowed.
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinearTermsLimit { needed, limit } => {
                write!(f, "reducer needs {needed} linear terms, exceeding {limit}")
            }
            Self::MatchEventsLimit { needed, limit } => {
                write!(f, "reducer may emit {needed} events, exceeding {limit}")
            }
            Self::CountLimit { needed, limit } => {
                write!(f, "reducer count may be {needed}, exceeding {limit}")
            }
            Self::SpanSumLimit { needed, limit } => {
                write!(f, "reducer span sum may be {needed}, exceeding {limit}")
            }
            Self::ReducerStepsLimit { needed, limit } => {
                write!(f, "reducer needs {needed} control steps, exceeding {limit}")
            }
            Self::ScratchLimit { needed, limit } => {
                write!(f, "reducer needs {needed} scratch bytes, exceeding {limit}")
            }
            Self::PeakLimit { needed, limit } => {
                write!(f, "reducer peak is {needed} bytes, exceeding {limit}")
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for ReduceError {}

/// Owned, deliberately non-`Clone` exact-literal whole-operation plan.
#[derive(Debug)]
pub struct LiteralAggregatePlan {
    finder: Finder<'static>,
    build: BuildAccounting,
}

impl LiteralAggregatePlan {
    /// Copy and preprocess one exact byte literal.
    ///
    /// # Errors
    ///
    /// Returns a typed arithmetic, allocation, or resource error without
    /// publishing a partial plan.
    pub fn build(needle: &[u8], limits: BuildLimits) -> Result<Self, BuildError> {
        let needle_u64 =
            u64::try_from(needle.len()).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "needle length as u64",
            })?;
        let work_upper_bound = needle_u64
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "build work upper bound",
            })?;
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(needle.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent plan bytes",
                })?;

        if needle.len() > limits.max_needle_bytes {
            return Err(BuildError::NeedleLimit {
                needed: needle.len(),
                limit: limits.max_needle_bytes,
            });
        }
        if work_upper_bound > limits.max_build_work {
            return Err(BuildError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_build_work,
            });
        }
        if persistent_bytes > limits.max_persistent_bytes {
            return Err(BuildError::PersistentLimit {
                needed: persistent_bytes,
                limit: limits.max_persistent_bytes,
            });
        }

        let minimum_peak =
            persistent_bytes
                .checked_add(needle.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "minimum construction peak",
                })?;
        if needle.len() > limits.max_scratch_bytes {
            return Err(BuildError::ScratchLimit {
                needed: needle.len(),
                limit: limits.max_scratch_bytes,
            });
        }
        if minimum_peak > limits.max_peak_bytes {
            return Err(BuildError::PeakLimit {
                needed: minimum_peak,
                limit: limits.max_peak_bytes,
            });
        }

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(needle.len())
            .map_err(|_| BuildError::AllocationFailed {
                structure: "literal aggregate needle",
                additional: needle.len(),
            })?;
        let temporary_capacity_bytes = owned.capacity();
        let peak_bytes = persistent_bytes
            .checked_add(temporary_capacity_bytes)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual construction peak",
            })?;
        if temporary_capacity_bytes > limits.max_scratch_bytes {
            return Err(BuildError::ScratchLimit {
                needed: temporary_capacity_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        if peak_bytes > limits.max_peak_bytes {
            return Err(BuildError::PeakLimit {
                needed: peak_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        owned.extend_from_slice(needle);
        let finder = FinderBuilder::new().build_forward_owned(owned.into_boxed_slice());
        let build = BuildAccounting {
            needle_bytes: needle.len(),
            temporary_capacity_bytes,
            work_upper_bound,
            scratch_bytes: temporary_capacity_bytes,
            persistent_bytes,
            peak_bytes,
        };
        Ok(Self { finder, build })
    }

    /// Preprocessed exact byte literal.
    #[must_use]
    pub fn needle(&self) -> &[u8] {
        self.finder.needle()
    }

    /// Construction certificate retained by this plan.
    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Stable count-operation identity.
    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        OperationIdentity::for_operation(Operation::Count)
    }

    /// Stable span-sum-operation identity.
    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        OperationIdentity::for_operation(Operation::SpanSum)
    }

    /// Reduce the entire haystack to a non-overlapping match count.
    ///
    /// # Errors
    ///
    /// Returns only preflight resource/arithmetic failures. Traversal starts
    /// after every bound has passed, and a partial count is never returned.
    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        let identity = self.count_identity();
        let upper_bounds = self.preflight(haystack.len(), Operation::Count, limits)?;
        let actual = self.execute(haystack, upper_bounds)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity,
                upper_bounds,
                actual,
            },
        })
    }

    /// Reduce the entire haystack to the checked sum of selected match lengths.
    ///
    /// # Errors
    ///
    /// Returns only preflight resource/arithmetic failures. Traversal starts
    /// after every bound has passed, and a partial sum is never returned.
    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        let identity = self.span_sum_identity();
        let upper_bounds = self.preflight(haystack.len(), Operation::SpanSum, limits)?;
        let actual = self.execute(haystack, upper_bounds)?;
        Ok(SpanSumResult {
            span_sum: actual.matched_bytes,
            accounting: ReduceAccounting {
                identity,
                upper_bounds,
                actual,
            },
        })
    }

    fn preflight(
        &self,
        haystack_len: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let upper = compute_upper_bounds(
            haystack_len,
            self.needle().len(),
            self.build.persistent_bytes,
        )?;
        if upper.linear_terms > limits.max_linear_terms {
            return Err(ReduceError::LinearTermsLimit {
                needed: upper.linear_terms,
                limit: limits.max_linear_terms,
            });
        }
        if upper.match_events > limits.max_match_events {
            return Err(ReduceError::MatchEventsLimit {
                needed: upper.match_events,
                limit: limits.max_match_events,
            });
        }
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
        if upper.reducer_steps > limits.max_reducer_steps {
            return Err(ReduceError::ReducerStepsLimit {
                needed: upper.reducer_steps,
                limit: limits.max_reducer_steps,
            });
        }
        if upper.scratch_bytes > limits.max_scratch_bytes {
            return Err(ReduceError::ScratchLimit {
                needed: upper.scratch_bytes,
                limit: limits.max_scratch_bytes,
            });
        }
        if upper.peak_bytes > limits.max_peak_bytes {
            return Err(ReduceError::PeakLimit {
                needed: upper.peak_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        Ok(upper)
    }

    fn execute(
        &self,
        haystack: &[u8],
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        if self.needle().is_empty() {
            return Ok(ReduceActualCounters {
                match_events: upper.match_events,
                iterator_next_calls: 0,
                empty_formula_evaluations: 1,
                count: upper.count,
                matched_bytes: 0,
            });
        }

        let mut match_events = 0_usize;
        let mut iterator_next_calls = 0_usize;
        let mut iterator = self.finder.find_iter(haystack);
        loop {
            iterator_next_calls =
                iterator_next_calls
                    .checked_add(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "actual iterator calls",
                    })?;
            if iterator.next().is_none() {
                break;
            }
            match_events = match_events
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual match events",
                })?;
        }
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual count as u64",
        })?;
        let needle_u64 =
            u64::try_from(self.needle().len()).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "needle length as u64",
            })?;
        let matched_bytes =
            count
                .checked_mul(needle_u64)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual span sum",
                })?;
        debug_assert!(match_events <= upper.match_events);
        debug_assert!(iterator_next_calls <= upper.reducer_steps);
        debug_assert!(matched_bytes <= upper.span_sum);
        Ok(ReduceActualCounters {
            match_events,
            iterator_next_calls,
            empty_formula_evaluations: 0,
            count,
            matched_bytes,
        })
    }
}

fn compute_upper_bounds(
    haystack_len: usize,
    needle_len: usize,
    persistent_bytes: usize,
) -> Result<ReduceUpperBounds, ReduceError> {
    let linear_terms =
        haystack_len
            .checked_add(needle_len)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "aggregate linear terms",
            })?;
    let match_events = if needle_len == 0 {
        haystack_len
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "Unicode-off empty byte boundaries",
            })?
    } else {
        haystack_len
            .checked_div(needle_len)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "nonempty match event quotient",
            })?
    };
    let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "count upper bound as u64",
    })?;
    let needle_u64 = u64::try_from(needle_len).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "needle length as u64",
    })?;
    let span_sum = count
        .checked_mul(needle_u64)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "span sum upper bound",
        })?;
    let reducer_steps = if needle_len == 0 {
        1
    } else {
        match_events
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "iterator call upper bound",
            })?
    };
    let scratch_bytes = 0;
    let peak_bytes =
        persistent_bytes
            .checked_add(scratch_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "operation peak bytes",
            })?;
    Ok(ReduceUpperBounds {
        haystack_bytes: haystack_len,
        needle_bytes: needle_len,
        linear_terms,
        match_events,
        count,
        span_sum,
        reducer_steps,
        scratch_bytes,
        persistent_bytes,
        peak_bytes,
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use regex::bytes::{Regex, RegexBuilder};

    use super::{
        BoundarySemantics, BuildError, BuildLimits, LiteralAggregatePlan, Operation, ReduceError,
        ReduceLimits, compute_upper_bounds,
    };

    fn plan(needle: &[u8]) -> LiteralAggregatePlan {
        LiteralAggregatePlan::build(needle, BuildLimits::unlimited()).unwrap()
    }

    fn regex(needle: &[u8]) -> Regex {
        let mut pattern = String::new();
        for &byte in needle {
            write!(&mut pattern, "\\x{byte:02X}").unwrap();
        }
        RegexBuilder::new(&pattern).unicode(false).build().unwrap()
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
    fn empty_is_explicit_unicode_off_byte_boundary_formula() {
        let plan = plan(b"");
        let count = plan.count(b"\xFFa\x80", ReduceLimits::unlimited()).unwrap();
        let spans = plan
            .span_sum(b"\xFFa\x80", ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(count.count, 4);
        assert_eq!(spans.span_sum, 0);
        assert_eq!(count.accounting.actual.iterator_next_calls, 0);
        assert_eq!(count.accounting.actual.empty_formula_evaluations, 1);
        assert_eq!(count.accounting.actual.match_events, 4);
        assert_eq!(count.accounting.identity.operation, Operation::Count);
        assert_eq!(spans.accounting.identity.operation, Operation::SpanSum);
        assert_eq!(
            count.accounting.identity.boundary_semantics,
            BoundarySemantics::EveryByteBoundaryUnicodeOff
        );
    }

    #[test]
    fn nonempty_iteration_is_leftmost_nonoverlapping_for_arbitrary_bytes() {
        let overlapping = plan(b"aba");
        let count = overlapping
            .count(b"ababa", ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(count.count, 1);
        assert_eq!(count.accounting.actual.iterator_next_calls, 2);

        let repeated = plan(b"aa");
        let spans = repeated
            .span_sum(b"aaaaa", ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(spans.span_sum, 4);
        assert_eq!(spans.accounting.actual.match_events, 2);

        let arbitrary = plan(b"\xFF\x00");
        assert_eq!(
            arbitrary
                .count(b"\xFF\x00\xFF\x00\x80", ReduceLimits::unlimited())
                .unwrap()
                .count,
            2
        );
    }

    #[test]
    fn exhaustive_differential_matches_regex_1_12_4_byte_mode() {
        let alphabet = [0x00, b'a', 0x80, 0xFF];
        let needles = words(&alphabet, 3);
        let haystacks = words(&alphabet, 5);
        assert_eq!(needles.len(), 85);
        assert_eq!(haystacks.len(), 1_365);
        for needle in needles {
            let plan = plan(&needle);
            let regex = regex(&needle);
            for haystack in &haystacks {
                let mut expected_count = 0_u64;
                let mut expected_span_sum = 0_u64;
                for matched in regex.find_iter(haystack) {
                    expected_count = expected_count.checked_add(1).unwrap();
                    let length = u64::try_from(matched.len()).unwrap();
                    expected_span_sum = expected_span_sum.checked_add(length).unwrap();
                }
                let count = plan.count(haystack, ReduceLimits::unlimited()).unwrap();
                let span_sum = plan.span_sum(haystack, ReduceLimits::unlimited()).unwrap();
                assert_eq!(
                    count.count, expected_count,
                    "needle={needle:?} hay={haystack:?}"
                );
                assert_eq!(
                    span_sum.span_sum, expected_span_sum,
                    "needle={needle:?} hay={haystack:?}"
                );
                assert_eq!(count.accounting.actual.count, expected_count);
                assert_eq!(span_sum.accounting.actual.matched_bytes, expected_span_sum);
            }
        }
    }

    #[test]
    fn every_nonzero_build_limit_has_an_exact_and_one_below_boundary() {
        let baseline = plan(b"needle").build_accounting();
        let exact = BuildLimits {
            max_needle_bytes: baseline.needle_bytes,
            max_build_work: baseline.work_upper_bound,
            max_scratch_bytes: baseline.scratch_bytes,
            max_persistent_bytes: baseline.persistent_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert!(LiteralAggregatePlan::build(b"needle", exact).is_ok());

        let cases = [
            (
                BuildLimits {
                    max_needle_bytes: baseline.needle_bytes - 1,
                    ..BuildLimits::unlimited()
                },
                "needle",
            ),
            (
                BuildLimits {
                    max_build_work: baseline.work_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
                "work",
            ),
            (
                BuildLimits {
                    max_scratch_bytes: baseline.scratch_bytes - 1,
                    ..BuildLimits::unlimited()
                },
                "scratch",
            ),
            (
                BuildLimits {
                    max_persistent_bytes: baseline.persistent_bytes - 1,
                    ..BuildLimits::unlimited()
                },
                "persistent",
            ),
            (
                BuildLimits {
                    max_peak_bytes: baseline.peak_bytes - 1,
                    ..BuildLimits::unlimited()
                },
                "peak",
            ),
        ];
        for (limits, expected) in cases {
            let error = LiteralAggregatePlan::build(b"needle", limits).unwrap_err();
            let actual = match error {
                BuildError::NeedleLimit { .. } => "needle",
                BuildError::WorkLimit { .. } => "work",
                BuildError::ScratchLimit { .. } => "scratch",
                BuildError::PersistentLimit { .. } => "persistent",
                BuildError::PeakLimit { .. } => "peak",
                other => panic!("unexpected build error: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn every_nonzero_operation_limit_has_an_exact_and_one_below_boundary() {
        let plan = plan(b"ab");
        let haystack = b"abababab";
        let baseline = plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .unwrap()
            .accounting
            .upper_bounds;
        let exact = ReduceLimits {
            max_linear_terms: baseline.linear_terms,
            max_match_events: baseline.match_events,
            max_count: baseline.count,
            max_span_sum: baseline.span_sum,
            max_reducer_steps: baseline.reducer_steps,
            max_scratch_bytes: baseline.scratch_bytes,
            max_peak_bytes: baseline.peak_bytes,
        };
        assert!(plan.span_sum(haystack, exact).is_ok());

        let cases = [
            (
                ReduceLimits {
                    max_linear_terms: baseline.linear_terms - 1,
                    ..ReduceLimits::unlimited()
                },
                "linear",
            ),
            (
                ReduceLimits {
                    max_match_events: baseline.match_events - 1,
                    ..ReduceLimits::unlimited()
                },
                "events",
            ),
            (
                ReduceLimits {
                    max_count: baseline.count - 1,
                    ..ReduceLimits::unlimited()
                },
                "count",
            ),
            (
                ReduceLimits {
                    max_span_sum: baseline.span_sum - 1,
                    ..ReduceLimits::unlimited()
                },
                "span",
            ),
            (
                ReduceLimits {
                    max_reducer_steps: baseline.reducer_steps - 1,
                    ..ReduceLimits::unlimited()
                },
                "steps",
            ),
            (
                ReduceLimits {
                    max_peak_bytes: baseline.peak_bytes - 1,
                    ..ReduceLimits::unlimited()
                },
                "peak",
            ),
        ];
        for (limits, expected) in cases {
            let error = plan.span_sum(haystack, limits).unwrap_err();
            let actual = match error {
                ReduceError::LinearTermsLimit { .. } => "linear",
                ReduceError::MatchEventsLimit { .. } => "events",
                ReduceError::CountLimit { .. } => "count",
                ReduceError::SpanSumLimit { .. } => "span",
                ReduceError::ReducerStepsLimit { .. } => "steps",
                ReduceError::PeakLimit { .. } => "peak",
                other => panic!("unexpected reduce error: {other:?}"),
            };
            assert_eq!(actual, expected);
        }

        let count_only = ReduceLimits {
            max_span_sum: 0,
            ..ReduceLimits::unlimited()
        };
        assert_eq!(plan.count(haystack, count_only).unwrap().count, 4);
    }

    #[test]
    fn arithmetic_boundaries_and_scaling_are_checked_before_execution() {
        assert!(matches!(
            compute_upper_bounds(usize::MAX, 0, 0),
            Err(ReduceError::ArithmeticOverflow {
                computation: "Unicode-off empty byte boundaries"
            })
        ));
        assert!(matches!(
            compute_upper_bounds(usize::MAX, 1, 0),
            Err(ReduceError::ArithmeticOverflow {
                computation: "aggregate linear terms"
            })
        ));

        let sparse = plan(b"xyz");
        let one = sparse
            .count(&vec![b'a'; 1_024], ReduceLimits::unlimited())
            .unwrap();
        let two = sparse
            .count(&vec![b'a'; 2_048], ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(one.accounting.actual.match_events, 0);
        assert_eq!(two.accounting.actual.match_events, 0);
        assert_eq!(one.accounting.actual.iterator_next_calls, 1);
        assert_eq!(two.accounting.actual.iterator_next_calls, 1);
        assert_eq!(one.accounting.upper_bounds.linear_terms, 1_027);
        assert_eq!(two.accounting.upper_bounds.linear_terms, 2_051);

        let dense = plan(b"a");
        assert_eq!(
            dense
                .count(&vec![b'a'; 2_048], ReduceLimits::unlimited())
                .unwrap()
                .accounting
                .actual
                .match_events,
            2_048
        );
    }
}
