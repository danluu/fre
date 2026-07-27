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

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

/// Stable identity for the exact-literal whole-haystack strategy.
pub const PLAN_ID: &str = "exact-literal-aggregate.memmem-find-iter.v1";
/// Version of the exact-literal reduction algorithm.
pub const ALGORITHM_VERSION: u32 = 1;
/// Version of the exact-literal prospective/actual attempt protocol.
pub const ACCOUNTING_VERSION: u32 = 1;
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

/// Permitted action after this exact-literal route is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclaredFallback {
    /// A resource refusal or fault is terminal; no alternate reducer may read
    /// source.
    None,
}

/// Opaque, word-sized construction provenance bound by an embedding facade.
///
/// The private word is deliberately omitted from `Debug` so execution
/// diagnostics cannot disclose an address-space value. Standalone kernel
/// plans retain the unbound token.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct PlanOrigin(usize);

impl PlanOrigin {
    /// The origin used by standalone kernel plans.
    #[must_use]
    pub const fn unbound() -> Self {
        Self(0)
    }

    /// Create a nonzero opaque token from an embedding construction address.
    #[must_use]
    pub const fn from_external_address(address: usize) -> Option<Self> {
        if address == 0 {
            None
        } else {
            Some(Self(address))
        }
    }

    /// Whether an embedding construction has bound this token.
    #[must_use]
    pub const fn is_bound(self) -> bool {
        self.0 != 0
    }
}

impl fmt::Debug for PlanOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PlanOrigin")
            .field(&if self.is_bound() { "bound" } else { "unbound" })
            .finish()
    }
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
    /// Exact reduction algorithm version.
    pub algorithm_version: u32,
    /// Prospective/actual attempt-accounting version.
    pub accounting_version: u32,
    /// Declared post-publication fallback policy.
    pub declared_fallback: DeclaredFallback,
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
            algorithm_version: ALGORITHM_VERSION,
            accounting_version: ACCOUNTING_VERSION,
            declared_fallback: DeclaredFallback::None,
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
    /// Dynamic allocations performed by the reduction itself.
    pub operation_allocations: usize,
    /// Retained plan bytes present during the operation.
    pub persistent_bytes: usize,
    /// Persistent-plus-operation-scratch peak.
    pub peak_bytes: usize,
}

impl ReduceUpperBounds {
    /// Check every cumulative actual dimension against this pre-source
    /// prospective envelope.
    #[must_use]
    pub fn contains(&self, actual: &ReduceActualCounters) -> bool {
        ensure_actual_is_bounded(actual, self).is_ok()
    }
}

/// Cumulative structural counters retained by every admitted attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReduceActualCounters {
    /// Semantic matches represented by the reduction.
    pub match_events: usize,
    /// Calls made to the pinned iterator's `next` method.
    pub iterator_next_calls: usize,
    /// Direct formula evaluations; one for an empty needle, otherwise zero.
    pub empty_formula_evaluations: usize,
    /// Total iterator/formula control steps committed so far.
    pub reducer_steps: usize,
    /// Checked count result represented as an actual counter.
    pub count: u64,
    /// Checked matched bytes represented by all selected spans.
    pub matched_bytes: u64,
    /// Dynamic allocations performed by the reduction itself.
    pub operation_allocations: usize,
    /// Caller-visible dynamic operation scratch actually retained.
    pub scratch_bytes: usize,
    /// Retained plan bytes present after execution starts.
    pub persistent_bytes: usize,
    /// Actual retained-plan plus operation-scratch peak.
    pub peak_bytes: usize,
}

/// Upper bounds and actual counters for one published result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    /// Operation and byte-boundary semantics.
    pub identity: OperationIdentity,
    /// Exact source size and caller limits bound before admission.
    pub invocation: ReduceInvocation,
    /// Bounds checked before any traversal or formula evaluation.
    pub upper_bounds: ReduceUpperBounds,
    /// Counters observed only after complete success.
    pub actual: ReduceActualCounters,
    /// Allocation count duplicated at the attempt boundary.
    pub actual_allocations: usize,
}

impl ReduceAccounting {
    /// Check the immutable route and invocation retained by this successful
    /// accounting.
    #[must_use]
    pub fn authenticates(&self, identity: OperationIdentity, invocation: ReduceInvocation) -> bool {
        self.identity == identity && self.invocation == invocation
    }

    /// Check every successful cumulative actual dimension against P.
    #[must_use]
    pub fn retains_bounded_actual(&self) -> bool {
        self.actual_allocations == self.actual.operation_allocations
            && self.upper_bounds.contains(&self.actual)
    }

    /// Verify that successful accounting closes the same immutable attempt
    /// receipt.
    #[must_use]
    pub fn closes_receipt(&self, receipt: &ReduceAttemptReceipt) -> bool {
        receipt.identity == self.identity
            && receipt.invocation == self.invocation
            && receipt.prospective == Some(self.upper_bounds)
            && receipt.actual == self.actual
            && receipt.actual_allocations == self.actual_allocations
            && self.retains_bounded_actual()
            && receipt.retains_bounded_actual()
    }
}

/// Exact whole-haystack invocation bound before prospective computation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceInvocation {
    /// Number of source bytes in this whole-haystack operation.
    pub haystack_bytes: usize,
    /// Exact construction accounting of the live immutable literal plan.
    pub build: BuildAccounting,
    /// Opaque external construction origin bound by the facade, or zero for a
    /// standalone kernel plan.
    pub plan_origin: PlanOrigin,
    /// Caller-selected operation limits.
    pub limits: ReduceLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptFailurePhase {
    Preflight,
    Execution,
    CountPublication,
    SpanSumPublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureSignature {
    PreflightLimit(PreflightGate),
    PreflightArithmetic(ArithmeticStage),
    PreflightInvariant(ReceiptInvariantStage),
    ExecutionEscape(EffectDimension),
    ExecutionArithmetic(ArithmeticStage),
    ExecutionInvariant(ReceiptInvariantStage),
    CountPublicationInvariant,
    SpanSumPublicationInvariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptFailureSeal {
    Valid(FailureSignature),
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArithmeticStage {
    AggregateLinearTerms,
    EmptyByteBoundaries,
    NonemptyMatchQuotient,
    CountUpperBound,
    NeedleLength,
    SpanSumUpperBound,
    IteratorCallUpperBound,
    OperationPeak,
    ActualIteratorCalls,
    ActualReducerSteps,
    ActualMatchEvents,
    ActualCount,
    ActualSpanSum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectDimension {
    MatchEvents,
    IteratorNextCalls,
    EmptyFormulaEvaluations,
    ReducerSteps,
    Count,
    MatchedBytes,
    OperationAllocations,
    ScratchBytes,
    PersistentBytes,
    PeakBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptInvariantStage {
    ConstructionBinding,
    ExecutionBeforeProspective,
    ExecutionBinding,
    EffectBeforeProspective,
    ReducerStepDecompositionOverflow,
    ReducerStepDecomposition,
    MatchEventCount,
    NeedleWidth,
    MatchedBytes,
}

/// Identity, invocation, published prospective, and cumulative actual ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAttemptReceipt {
    pub identity: OperationIdentity,
    pub invocation: ReduceInvocation,
    /// Absent only until source-free prospective computation completes.
    pub prospective: Option<ReduceUpperBounds>,
    /// Every execution effect committed before the terminal outcome.
    pub actual: ReduceActualCounters,
    /// Duplicate allocation count authenticated at the attempt boundary.
    pub actual_allocations: usize,
}

impl ReduceAttemptReceipt {
    /// Check the immutable route and invocation bound by this receipt.
    #[must_use]
    pub fn authenticates(&self, identity: OperationIdentity, invocation: ReduceInvocation) -> bool {
        self.identity == identity && self.invocation == invocation
    }

    /// Check P=None=>A=0 and, after publication, every cumulative A<=P
    /// dimension in release builds.
    #[must_use]
    pub fn retains_bounded_actual(&self) -> bool {
        self.actual_allocations == self.actual.operation_allocations
            && self.prospective.map_or_else(
                || self.actual == ReduceActualCounters::default(),
                |prospective| prospective.contains(&self.actual),
            )
    }

    /// Authenticate the canonical operation identity, exact construction
    /// formulas, exact published P (when present), and release P/A invariant.
    #[must_use]
    pub fn authenticates_canonical(&self) -> bool {
        if self.identity != OperationIdentity::for_operation(self.identity.operation)
            || !build_accounting_is_canonical(self.invocation.build)
            || !self.retains_bounded_actual()
        {
            return false;
        }
        self.prospective.is_none_or(|prospective| {
            compute_upper_bounds(
                self.invocation.haystack_bytes,
                self.invocation.build.needle_bytes,
                self.invocation.build.persistent_bytes,
            )
            .is_ok_and(|expected| expected == prospective)
        })
    }

    /// Check that a typed terminal error is possible at the stage represented
    /// by this receipt. This is a structural plausibility check; complete
    /// terminal authentication additionally requires the private failure seal
    /// retained by [`ReduceAttemptError::closes`].
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive closure keeps every public failure variant and receipt phase adjacent"
    )]
    pub fn closes_error(&self, error: &ReduceError) -> bool {
        self.source_closes_error(error)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one exhaustive closure keeps every public failure variant and receipt phase adjacent"
    )]
    fn source_closes_error(&self, error: &ReduceError) -> bool {
        if !self.authenticates_canonical() {
            return false;
        }
        let zero_actual =
            self.actual == ReduceActualCounters::default() && self.actual_allocations == 0;
        match (error, self.prospective) {
            (ReduceError::LinearTermsLimit { needed, limit }, Some(prospective)) => {
                zero_actual
                    && earlier_preflight_gates_admitted(
                        self.identity.operation,
                        prospective,
                        self.invocation.limits,
                        PreflightGate::LinearTerms,
                    )
                    && *needed == prospective.linear_terms
                    && *limit == self.invocation.limits.max_linear_terms
                    && needed > limit
            }
            (ReduceError::MatchEventsLimit { needed, limit }, Some(prospective)) => {
                zero_actual
                    && earlier_preflight_gates_admitted(
                        self.identity.operation,
                        prospective,
                        self.invocation.limits,
                        PreflightGate::MatchEvents,
                    )
                    && *needed == prospective.match_events
                    && *limit == self.invocation.limits.max_match_events
                    && needed > limit
            }
            (ReduceError::CountLimit { needed, limit }, Some(prospective)) => {
                zero_actual
                    && earlier_preflight_gates_admitted(
                        self.identity.operation,
                        prospective,
                        self.invocation.limits,
                        PreflightGate::Count,
                    )
                    && *needed == prospective.count
                    && *limit == self.invocation.limits.max_count
                    && needed > limit
            }
            (ReduceError::SpanSumLimit { needed, limit }, Some(prospective)) => {
                zero_actual
                    && self.identity.operation == Operation::SpanSum
                    && earlier_preflight_gates_admitted(
                        self.identity.operation,
                        prospective,
                        self.invocation.limits,
                        PreflightGate::SpanSum,
                    )
                    && *needed == prospective.span_sum
                    && *limit == self.invocation.limits.max_span_sum
                    && needed > limit
            }
            (ReduceError::ReducerStepsLimit { needed, limit }, Some(prospective)) => {
                zero_actual
                    && earlier_preflight_gates_admitted(
                        self.identity.operation,
                        prospective,
                        self.invocation.limits,
                        PreflightGate::ReducerSteps,
                    )
                    && *needed == prospective.reducer_steps
                    && *limit == self.invocation.limits.max_reducer_steps
                    && needed > limit
            }
            (ReduceError::ScratchLimit { needed, limit }, Some(prospective)) => {
                zero_actual
                    && earlier_preflight_gates_admitted(
                        self.identity.operation,
                        prospective,
                        self.invocation.limits,
                        PreflightGate::Scratch,
                    )
                    && *needed == prospective.scratch_bytes
                    && *limit == self.invocation.limits.max_scratch_bytes
                    && needed > limit
            }
            (ReduceError::PeakLimit { needed, limit }, Some(prospective)) => {
                zero_actual
                    && earlier_preflight_gates_admitted(
                        self.identity.operation,
                        prospective,
                        self.invocation.limits,
                        PreflightGate::Peak,
                    )
                    && *needed == prospective.peak_bytes
                    && *limit == self.invocation.limits.max_peak_bytes
                    && needed > limit
            }
            (
                ReduceError::ActualEscapedProspective {
                    dimension,
                    actual,
                    prospective: reported,
                },
                Some(prospective),
            ) => {
                earlier_preflight_gates_admitted(
                    self.identity.operation,
                    prospective,
                    self.invocation.limits,
                    PreflightGate::Execution,
                ) && actual > reported
                    && attempted_dimension_limit(dimension, prospective) == Some(*reported)
                    && exact_next_charge(dimension, *actual, self.actual, prospective)
            }
            (ReduceError::ArithmeticOverflow { .. }, None) => {
                zero_actual
                    && compute_upper_bounds(
                        self.invocation.haystack_bytes,
                        self.invocation.build.needle_bytes,
                        self.invocation.build.persistent_bytes,
                    )
                    .is_err_and(|expected| &expected == error)
            }
            (ReduceError::ArithmeticOverflow { computation }, Some(prospective)) => {
                earlier_preflight_gates_admitted(
                    self.identity.operation,
                    prospective,
                    self.invocation.limits,
                    PreflightGate::Execution,
                ) && execution_overflow_closes(computation, self.actual, prospective)
            }
            (ReduceError::ReceiptInvariant { detail }, prospective) => {
                receipt_invariant_closes(detail, prospective, self.actual, zero_actual)
            }
            _ => false,
        }
    }
}

impl FailureSignature {
    fn from_source(phase: AttemptFailurePhase, source: &ReduceError) -> Option<Self> {
        match (phase, source) {
            (AttemptFailurePhase::Preflight, ReduceError::LinearTermsLimit { .. }) => {
                Some(Self::PreflightLimit(PreflightGate::LinearTerms))
            }
            (AttemptFailurePhase::Preflight, ReduceError::MatchEventsLimit { .. }) => {
                Some(Self::PreflightLimit(PreflightGate::MatchEvents))
            }
            (AttemptFailurePhase::Preflight, ReduceError::CountLimit { .. }) => {
                Some(Self::PreflightLimit(PreflightGate::Count))
            }
            (AttemptFailurePhase::Preflight, ReduceError::SpanSumLimit { .. }) => {
                Some(Self::PreflightLimit(PreflightGate::SpanSum))
            }
            (AttemptFailurePhase::Preflight, ReduceError::ReducerStepsLimit { .. }) => {
                Some(Self::PreflightLimit(PreflightGate::ReducerSteps))
            }
            (AttemptFailurePhase::Preflight, ReduceError::ScratchLimit { .. }) => {
                Some(Self::PreflightLimit(PreflightGate::Scratch))
            }
            (AttemptFailurePhase::Preflight, ReduceError::PeakLimit { .. }) => {
                Some(Self::PreflightLimit(PreflightGate::Peak))
            }
            (AttemptFailurePhase::Preflight, ReduceError::ArithmeticOverflow { computation }) => {
                arithmetic_stage(computation).map(Self::PreflightArithmetic)
            }
            (AttemptFailurePhase::Preflight, ReduceError::ReceiptInvariant { detail }) => {
                receipt_invariant_stage(detail).map(Self::PreflightInvariant)
            }
            (
                AttemptFailurePhase::Execution,
                ReduceError::ActualEscapedProspective { dimension, .. },
            ) => effect_dimension(dimension).map(Self::ExecutionEscape),
            (AttemptFailurePhase::Execution, ReduceError::ArithmeticOverflow { computation }) => {
                arithmetic_stage(computation).map(Self::ExecutionArithmetic)
            }
            (AttemptFailurePhase::Execution, ReduceError::ReceiptInvariant { detail }) => {
                receipt_invariant_stage(detail).map(Self::ExecutionInvariant)
            }
            (
                AttemptFailurePhase::CountPublication,
                ReduceError::ReceiptInvariant {
                    detail: "count success did not close its identity/invocation/P/A receipt",
                },
            ) => Some(Self::CountPublicationInvariant),
            (
                AttemptFailurePhase::SpanSumPublication,
                ReduceError::ReceiptInvariant {
                    detail: "span-sum success did not close its identity/invocation/P/A receipt",
                },
            ) => Some(Self::SpanSumPublicationInvariant),
            _ => None,
        }
    }

    fn matches(self, source: &ReduceError) -> bool {
        let phase = match self {
            Self::PreflightLimit(_)
            | Self::PreflightArithmetic(_)
            | Self::PreflightInvariant(_) => AttemptFailurePhase::Preflight,
            Self::ExecutionEscape(_)
            | Self::ExecutionArithmetic(_)
            | Self::ExecutionInvariant(_) => AttemptFailurePhase::Execution,
            Self::CountPublicationInvariant => AttemptFailurePhase::CountPublication,
            Self::SpanSumPublicationInvariant => AttemptFailurePhase::SpanSumPublication,
        };
        Self::from_source(phase, source) == Some(self)
    }
}

fn arithmetic_stage(computation: &str) -> Option<ArithmeticStage> {
    match computation {
        "aggregate linear terms" => Some(ArithmeticStage::AggregateLinearTerms),
        "Unicode-off empty byte boundaries" => Some(ArithmeticStage::EmptyByteBoundaries),
        "nonempty match event quotient" => Some(ArithmeticStage::NonemptyMatchQuotient),
        "count upper bound as u64" => Some(ArithmeticStage::CountUpperBound),
        "needle length as u64" => Some(ArithmeticStage::NeedleLength),
        "span sum upper bound" => Some(ArithmeticStage::SpanSumUpperBound),
        "iterator call upper bound" => Some(ArithmeticStage::IteratorCallUpperBound),
        "operation peak bytes" => Some(ArithmeticStage::OperationPeak),
        "actual iterator calls" => Some(ArithmeticStage::ActualIteratorCalls),
        "actual reducer steps" => Some(ArithmeticStage::ActualReducerSteps),
        "actual match events" => Some(ArithmeticStage::ActualMatchEvents),
        "actual count" => Some(ArithmeticStage::ActualCount),
        "actual span sum" => Some(ArithmeticStage::ActualSpanSum),
        _ => None,
    }
}

fn effect_dimension(dimension: &str) -> Option<EffectDimension> {
    match dimension {
        "match events" => Some(EffectDimension::MatchEvents),
        "iterator next calls" => Some(EffectDimension::IteratorNextCalls),
        "empty formula evaluations" => Some(EffectDimension::EmptyFormulaEvaluations),
        "reducer steps" => Some(EffectDimension::ReducerSteps),
        "count" => Some(EffectDimension::Count),
        "matched bytes" => Some(EffectDimension::MatchedBytes),
        "operation allocations" => Some(EffectDimension::OperationAllocations),
        "scratch bytes" => Some(EffectDimension::ScratchBytes),
        "persistent bytes" => Some(EffectDimension::PersistentBytes),
        "peak bytes" => Some(EffectDimension::PeakBytes),
        _ => None,
    }
}

fn receipt_invariant_stage(detail: &str) -> Option<ReceiptInvariantStage> {
    match detail {
        "invocation construction origin/accounting differs from the live literal plan" => {
            Some(ReceiptInvariantStage::ConstructionBinding)
        }
        "execution started before prospective publication" => {
            Some(ReceiptInvariantStage::ExecutionBeforeProspective)
        }
        "execution identity or source length differs from admitted invocation" => {
            Some(ReceiptInvariantStage::ExecutionBinding)
        }
        "actual effect was charged before prospective publication" => {
            Some(ReceiptInvariantStage::EffectBeforeProspective)
        }
        "actual reducer-step decomposition overflowed" => {
            Some(ReceiptInvariantStage::ReducerStepDecompositionOverflow)
        }
        "actual iterator/formula steps do not sum to reducer steps" => {
            Some(ReceiptInvariantStage::ReducerStepDecomposition)
        }
        "actual match events do not equal the checked count" => {
            Some(ReceiptInvariantStage::MatchEventCount)
        }
        "published needle length does not fit its span arithmetic" => {
            Some(ReceiptInvariantStage::NeedleWidth)
        }
        "actual count and needle width do not equal matched bytes" => {
            Some(ReceiptInvariantStage::MatchedBytes)
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreflightGate {
    LinearTerms,
    MatchEvents,
    Count,
    SpanSum,
    ReducerSteps,
    Scratch,
    Peak,
    Execution,
}

fn earlier_preflight_gates_admitted(
    operation: Operation,
    prospective: ReduceUpperBounds,
    limits: ReduceLimits,
    gate: PreflightGate,
) -> bool {
    if matches!(gate, PreflightGate::LinearTerms) {
        return true;
    }
    if prospective.linear_terms > limits.max_linear_terms {
        return false;
    }
    if matches!(gate, PreflightGate::MatchEvents) {
        return true;
    }
    if prospective.match_events > limits.max_match_events {
        return false;
    }
    if matches!(gate, PreflightGate::Count) {
        return true;
    }
    if prospective.count > limits.max_count {
        return false;
    }
    if matches!(gate, PreflightGate::SpanSum) {
        return true;
    }
    if operation == Operation::SpanSum && prospective.span_sum > limits.max_span_sum {
        return false;
    }
    if matches!(gate, PreflightGate::ReducerSteps) {
        return true;
    }
    if prospective.reducer_steps > limits.max_reducer_steps {
        return false;
    }
    if matches!(gate, PreflightGate::Scratch) {
        return true;
    }
    if prospective.scratch_bytes > limits.max_scratch_bytes {
        return false;
    }
    if matches!(gate, PreflightGate::Peak) {
        return true;
    }
    prospective.peak_bytes <= limits.max_peak_bytes
}

fn exact_next_charge(
    dimension: &str,
    attempted: u128,
    actual: ReduceActualCounters,
    prospective: ReduceUpperBounds,
) -> bool {
    let needle = prospective.needle_bytes;
    let nonempty = needle != 0 && actual.empty_formula_evaluations == 0;
    let at_iterator_charge = nonempty
        && actual.iterator_next_calls == actual.match_events
        && actual.reducer_steps == actual.iterator_next_calls;
    let at_match_charge = nonempty
        && actual.iterator_next_calls == actual.match_events.saturating_add(1)
        && actual.reducer_steps == actual.iterator_next_calls
        && u64::try_from(actual.match_events) == Ok(actual.count);
    let expected = match dimension {
        "match events" if at_match_charge => actual.match_events.checked_add(1).map(usize_to_u128),
        "iterator next calls" if at_iterator_charge => {
            actual.iterator_next_calls.checked_add(1).map(usize_to_u128)
        }
        "empty formula evaluations"
            if needle == 0
                && actual
                    == ReduceActualCounters {
                        scratch_bytes: prospective.scratch_bytes,
                        persistent_bytes: prospective.persistent_bytes,
                        peak_bytes: prospective.peak_bytes,
                        ..ReduceActualCounters::default()
                    } =>
        {
            Some(1)
        }
        "reducer steps" if at_iterator_charge => {
            actual.reducer_steps.checked_add(1).map(usize_to_u128)
        }
        "count" if at_match_charge => actual.count.checked_add(1).map(u128::from),
        "matched bytes" if at_match_charge => u64::try_from(needle)
            .ok()
            .and_then(|width| actual.matched_bytes.checked_add(width))
            .map(u128::from),
        // The initial resource publication assigns the exact prospective
        // value, so a canonical receipt can never report an escaping charge.
        "operation allocations" if actual == ReduceActualCounters::default() => actual
            .operation_allocations
            .checked_add(1)
            .map(usize_to_u128),
        // Initial resource publication assigns exact P, so no resource byte
        // dimension has an authenticated escaping next charge.
        _ => None,
    };
    expected == Some(attempted)
}

fn execution_overflow_closes(
    computation: &str,
    actual: ReduceActualCounters,
    prospective: ReduceUpperBounds,
) -> bool {
    let nonempty = prospective.needle_bytes != 0 && actual.empty_formula_evaluations == 0;
    let at_iterator_charge = nonempty
        && actual.iterator_next_calls == actual.match_events
        && actual.reducer_steps == actual.iterator_next_calls;
    let at_match_charge = nonempty
        && actual.iterator_next_calls == actual.match_events.saturating_add(1)
        && actual.reducer_steps == actual.iterator_next_calls
        && u64::try_from(actual.match_events) == Ok(actual.count);
    match computation {
        "needle length as u64" => {
            actual.match_events == 0
                && actual.iterator_next_calls == 0
                && actual.empty_formula_evaluations == 0
                && actual.reducer_steps == 0
                && u64::try_from(prospective.needle_bytes).is_err()
        }
        "actual iterator calls" => {
            at_iterator_charge && actual.iterator_next_calls.checked_add(1).is_none()
        }
        "actual reducer steps" => {
            at_iterator_charge && actual.reducer_steps.checked_add(1).is_none()
        }
        "actual match events" => at_match_charge && actual.match_events.checked_add(1).is_none(),
        "actual count" => at_match_charge && actual.count.checked_add(1).is_none(),
        "actual span sum" => {
            at_match_charge
                && u64::try_from(prospective.needle_bytes)
                    .ok()
                    .is_some_and(|width| actual.matched_bytes.checked_add(width).is_none())
        }
        _ => false,
    }
}

fn receipt_invariant_closes(
    detail: &str,
    prospective: Option<ReduceUpperBounds>,
    actual: ReduceActualCounters,
    zero_actual: bool,
) -> bool {
    match detail {
        "invocation construction origin/accounting differs from the live literal plan"
        | "execution started before prospective publication"
        | "actual effect was charged before prospective publication" => {
            prospective.is_none() && zero_actual
        }
        "execution identity or source length differs from admitted invocation" => true,
        "actual reducer-step decomposition overflowed" => actual
            .iterator_next_calls
            .checked_add(actual.empty_formula_evaluations)
            .is_none(),
        "actual iterator/formula steps do not sum to reducer steps" => actual
            .iterator_next_calls
            .checked_add(actual.empty_formula_evaluations)
            .is_some_and(|steps| steps != actual.reducer_steps),
        "actual match events do not equal the checked count" => {
            u64::try_from(actual.match_events) != Ok(actual.count)
        }
        "published needle length does not fit its span arithmetic" => {
            prospective.is_some_and(|prospective| u64::try_from(prospective.needle_bytes).is_err())
        }
        "actual count and needle width do not equal matched bytes" => prospective
            .and_then(|prospective| u64::try_from(prospective.needle_bytes).ok())
            .is_some_and(|needle| actual.count.checked_mul(needle) != Some(actual.matched_bytes)),
        "count success did not close its identity/invocation/P/A receipt"
        | "span-sum success did not close its identity/invocation/P/A receipt" => {
            prospective.is_some()
        }
        _ => false,
    }
}

fn build_accounting_is_canonical(build: BuildAccounting) -> bool {
    let Some(work_upper_bound) = u64::try_from(build.needle_bytes)
        .ok()
        .and_then(|needle| needle.checked_add(1))
    else {
        return false;
    };
    let Some(persistent_bytes) = size_of::<LiteralAggregatePlan>().checked_add(build.needle_bytes)
    else {
        return false;
    };
    let Some(peak_bytes) = persistent_bytes.checked_add(build.temporary_capacity_bytes) else {
        return false;
    };
    build.work_upper_bound == work_upper_bound
        && (build.needle_bytes != 0 || build.temporary_capacity_bytes == 0)
        && build.temporary_capacity_bytes >= build.needle_bytes
        && build.scratch_bytes == build.temporary_capacity_bytes
        && build.persistent_bytes == persistent_bytes
        && build.peak_bytes == peak_bytes
}

fn attempted_dimension_limit(dimension: &str, prospective: ReduceUpperBounds) -> Option<u128> {
    match dimension {
        "match events" => u128::try_from(prospective.match_events).ok(),
        "iterator next calls" | "empty formula evaluations" | "reducer steps" => {
            u128::try_from(prospective.reducer_steps).ok()
        }
        "count" => Some(u128::from(prospective.count)),
        "matched bytes" => Some(u128::from(prospective.span_sum)),
        "operation allocations" => u128::try_from(prospective.operation_allocations).ok(),
        "scratch bytes" => u128::try_from(prospective.scratch_bytes).ok(),
        "persistent bytes" => u128::try_from(prospective.persistent_bytes).ok(),
        "peak bytes" => u128::try_from(prospective.peak_bytes).ok(),
        _ => None,
    }
}

/// Complete match-count result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    /// Number of non-overlapping byte matches.
    pub count: u64,
    /// Complete resource certificate and structural counters.
    pub accounting: ReduceAccounting,
}

/// Successful match-count attempt and its complete receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountAttempt {
    result: CountResult,
    receipt: ReduceAttemptReceipt,
}

impl CountAttempt {
    /// Completed count result retained by this authenticated attempt.
    #[must_use]
    pub const fn result(&self) -> &CountResult {
        &self.result
    }

    /// Independent identity/invocation/P/A receipt for this success.
    #[must_use]
    pub const fn receipt(&self) -> &ReduceAttemptReceipt {
        &self.receipt
    }

    /// Consume the authenticated attempt into its result and receipt.
    #[must_use]
    pub const fn into_parts(self) -> (CountResult, ReduceAttemptReceipt) {
        (self.result, self.receipt)
    }

    /// Verify the result and receipt are the same authenticated success.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt.authenticates_canonical()
            && self.receipt.identity == OperationIdentity::for_operation(Operation::Count)
            && self.result.accounting.identity == OperationIdentity::for_operation(Operation::Count)
            && self.result.accounting.closes_receipt(&self.receipt)
            && self.result.count == self.receipt.actual.count
    }
}

/// Complete checked matched-byte span-sum result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    /// Sum of `end - start` for all non-overlapping byte matches.
    pub span_sum: u64,
    /// Complete resource certificate and structural counters.
    pub accounting: ReduceAccounting,
}

/// Successful span-sum attempt and its complete receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumAttempt {
    result: SpanSumResult,
    receipt: ReduceAttemptReceipt,
}

impl SpanSumAttempt {
    /// Completed span-sum result retained by this authenticated attempt.
    #[must_use]
    pub const fn result(&self) -> &SpanSumResult {
        &self.result
    }

    /// Independent identity/invocation/P/A receipt for this success.
    #[must_use]
    pub const fn receipt(&self) -> &ReduceAttemptReceipt {
        &self.receipt
    }

    /// Consume the authenticated attempt into its result and receipt.
    #[must_use]
    pub const fn into_parts(self) -> (SpanSumResult, ReduceAttemptReceipt) {
        (self.result, self.receipt)
    }

    /// Verify the result and receipt are the same authenticated success.
    #[must_use]
    pub fn closes(&self) -> bool {
        self.receipt.authenticates_canonical()
            && self.receipt.identity == OperationIdentity::for_operation(Operation::SpanSum)
            && self.result.accounting.identity
                == OperationIdentity::for_operation(Operation::SpanSum)
            && self.result.accounting.closes_receipt(&self.receipt)
            && self.result.span_sum == self.receipt.actual.matched_bytes
    }
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
    /// An attempted cumulative charge would exceed the published prospective.
    ActualEscapedProspective {
        dimension: &'static str,
        actual: u128,
        prospective: u128,
    },
    /// Identity, invocation, or P/A evidence failed closed at publication.
    ReceiptInvariant { detail: &'static str },
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
            Self::ActualEscapedProspective {
                dimension,
                actual,
                prospective,
            } => write!(
                f,
                "actual {dimension} {actual} exceeds prospective {prospective}"
            ),
            Self::ReceiptInvariant { detail } => {
                write!(
                    f,
                    "exact-literal attempt receipt invariant failed: {detail}"
                )
            }
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for ReduceError {}

/// Terminal refusal retaining the exact identity, invocation, P, and bounded A.
///
/// Public code can inspect but cannot rewrite or reassemble the sealed
/// source/receipt pair:
///
/// ```compile_fail,E0616
/// use fre_kernels::LiteralAggregateReduceAttemptError;
///
/// fn rewrite(error: &mut LiteralAggregateReduceAttemptError) {
///     error.source = error.source().clone();
/// }
/// ```
///
/// ```compile_fail,E0616
/// use fre_kernels::LiteralAggregateReduceAttemptError;
///
/// fn retarget(error: &mut LiteralAggregateReduceAttemptError) {
///     error.receipt.identity = error.receipt().identity;
/// }
/// ```
///
/// ```compile_fail,E0451
/// use fre_kernels::{
///     LiteralAggregateReduceAttemptError, LiteralAggregateReduceAttemptReceipt,
///     LiteralAggregateReduceError,
/// };
///
/// fn forge(
///     source: LiteralAggregateReduceError,
///     receipt: LiteralAggregateReduceAttemptReceipt,
/// ) -> LiteralAggregateReduceAttemptError {
///     LiteralAggregateReduceAttemptError { source, receipt }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReduceAttemptError {
    source: ReduceError,
    receipt: ReduceAttemptReceipt,
    seal: AttemptFailureSeal,
}

impl ReduceAttemptError {
    /// Typed selected-plan failure retained by this attempt.
    #[must_use]
    pub const fn source(&self) -> &ReduceError {
        &self.source
    }

    /// Identity/invocation/P/A receipt as it stood before the failed effect.
    #[must_use]
    pub const fn receipt(&self) -> &ReduceAttemptReceipt {
        &self.receipt
    }

    /// Check the complete public source/receipt terminal closure.
    #[must_use]
    pub fn closes(&self) -> bool {
        matches!(
            self.seal,
            AttemptFailureSeal::Valid(signature) if signature.matches(&self.source)
        ) && self.receipt.closes_error(&self.source)
    }
}

/// Owned, deliberately non-`Clone` exact-literal whole-operation plan.
#[derive(Debug)]
pub struct LiteralAggregatePlan {
    finder: Finder<'static>,
    build: BuildAccounting,
    plan_origin: PlanOrigin,
}

impl LiteralAggregatePlan {
    /// Copy and preprocess one exact byte literal.
    ///
    /// # Errors
    ///
    /// Returns a typed arithmetic, allocation, or resource error without
    /// publishing a partial plan.
    pub fn build(needle: &[u8], limits: BuildLimits) -> Result<Self, BuildError> {
        Self::build_attempt(needle, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Copy and preprocess one exact byte literal with exact observed effects.
    #[allow(
        clippy::too_many_lines,
        reason = "the literal attempt keeps legacy error precedence, observed reservation accounting, and publication in one transaction"
    )]
    pub fn build_attempt(
        needle: &[u8],
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            let needle_u64 =
                u64::try_from(needle.len()).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "needle length as u64",
                })?;
            let work_upper_bound =
                needle_u64
                    .checked_add(1)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "build work upper bound",
                    })?;
            let persistent_bytes = size_of::<Self>().checked_add(needle.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent plan bytes",
                },
            )?;

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

            let minimum_peak = persistent_bytes.checked_add(needle.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "minimum construction peak",
                },
            )?;
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
            if temporary_capacity_bytes != 0 {
                actual.allocations = 1;
                actual.allocated_bytes = temporary_capacity_bytes;
                actual.peak_bytes = temporary_capacity_bytes;
            }
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
            actual.work = u64::try_from(owned.len())
                .map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "actual literal copy work as u64",
                })?
                .checked_add(1)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "actual literal preprocessing work",
                })?;
            actual.copied_bytes = owned.len();
            actual.initialized_bytes = owned.len();
            let finder = FinderBuilder::new().build_forward_owned(owned.into_boxed_slice());
            let build = BuildAccounting {
                needle_bytes: needle.len(),
                temporary_capacity_bytes,
                work_upper_bound,
                scratch_bytes: temporary_capacity_bytes,
                persistent_bytes,
                peak_bytes,
            };
            let plan = Self {
                finder,
                build,
                plan_origin: PlanOrigin::unbound(),
            };
            actual.initialized_bytes = actual
                .initialized_bytes
                .checked_add(size_of::<Self>())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "published literal inline initialized bytes",
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

    /// Bind one nonzero allocation-free external construction origin.
    ///
    /// Returns `false` when `origin` is zero or this plan was already bound.
    pub fn bind_external_origin(&mut self, origin: PlanOrigin) -> bool {
        if !origin.is_bound() || self.plan_origin.is_bound() {
            return false;
        }
        self.plan_origin = origin;
        true
    }

    /// Opaque external construction origin, or zero for standalone plans.
    #[must_use]
    pub const fn external_origin(&self) -> PlanOrigin {
        self.plan_origin
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
        self.count_attempt(haystack, limits)
            .map(|attempt| attempt.result)
            .map_err(|error| error.source)
    }

    /// Reduce the whole haystack while retaining an authenticated success or
    /// failure receipt.
    ///
    /// # Errors
    ///
    /// Every error retains the exact identity/invocation, optional published
    /// prospective, and all bounded cumulative actual effects.
    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free error is the one complete identity/invocation/P/A receipt"
    )]
    pub fn count_attempt(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CountAttempt, ReduceAttemptError> {
        let identity = self.count_identity();
        let invocation = ReduceInvocation {
            haystack_bytes: haystack.len(),
            build: self.build,
            plan_origin: self.plan_origin,
            limits,
        };
        let mut receipt = ReduceAttemptReceipt {
            identity,
            invocation,
            prospective: None,
            actual: ReduceActualCounters::default(),
            actual_allocations: 0,
        };
        let upper_bounds = match self.preflight(&mut receipt) {
            Ok(upper) => upper,
            Err(source) => {
                return Err(attempt_error(
                    source,
                    receipt,
                    identity,
                    invocation,
                    AttemptFailurePhase::Preflight,
                ));
            }
        };
        if let Err(source) = self.execute(haystack, &mut receipt) {
            return Err(attempt_error(
                source,
                receipt,
                identity,
                invocation,
                AttemptFailurePhase::Execution,
            ));
        }
        let actual = receipt.actual;
        let result = CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity,
                invocation,
                upper_bounds,
                actual,
                actual_allocations: receipt.actual_allocations,
            },
        };
        let attempt = CountAttempt { result, receipt };
        if attempt.closes() {
            Ok(attempt)
        } else {
            Err(attempt_error(
                ReduceError::ReceiptInvariant {
                    detail: "count success did not close its identity/invocation/P/A receipt",
                },
                attempt.receipt,
                identity,
                invocation,
                AttemptFailurePhase::CountPublication,
            ))
        }
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
        self.span_sum_attempt(haystack, limits)
            .map(|attempt| attempt.result)
            .map_err(|error| error.source)
    }

    /// Reduce the whole haystack to a span sum while retaining an authenticated
    /// success or failure receipt.
    ///
    /// # Errors
    ///
    /// Every error retains the exact identity/invocation, optional published
    /// prospective, and all bounded cumulative actual effects.
    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free error is the one complete identity/invocation/P/A receipt"
    )]
    pub fn span_sum_attempt(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumAttempt, ReduceAttemptError> {
        let identity = self.span_sum_identity();
        let invocation = ReduceInvocation {
            haystack_bytes: haystack.len(),
            build: self.build,
            plan_origin: self.plan_origin,
            limits,
        };
        let mut receipt = ReduceAttemptReceipt {
            identity,
            invocation,
            prospective: None,
            actual: ReduceActualCounters::default(),
            actual_allocations: 0,
        };
        let upper_bounds = match self.preflight(&mut receipt) {
            Ok(upper) => upper,
            Err(source) => {
                return Err(attempt_error(
                    source,
                    receipt,
                    identity,
                    invocation,
                    AttemptFailurePhase::Preflight,
                ));
            }
        };
        if let Err(source) = self.execute(haystack, &mut receipt) {
            return Err(attempt_error(
                source,
                receipt,
                identity,
                invocation,
                AttemptFailurePhase::Execution,
            ));
        }
        let actual = receipt.actual;
        let result = SpanSumResult {
            span_sum: actual.matched_bytes,
            accounting: ReduceAccounting {
                identity,
                invocation,
                upper_bounds,
                actual,
                actual_allocations: receipt.actual_allocations,
            },
        };
        let attempt = SpanSumAttempt { result, receipt };
        if attempt.closes() {
            Ok(attempt)
        } else {
            Err(attempt_error(
                ReduceError::ReceiptInvariant {
                    detail: "span-sum success did not close its identity/invocation/P/A receipt",
                },
                attempt.receipt,
                identity,
                invocation,
                AttemptFailurePhase::SpanSumPublication,
            ))
        }
    }

    fn preflight(
        &self,
        receipt: &mut ReduceAttemptReceipt,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        if receipt.invocation.build != self.build
            || receipt.invocation.plan_origin != self.plan_origin
        {
            return Err(ReduceError::ReceiptInvariant {
                detail: "invocation construction origin/accounting differs from the live literal plan",
            });
        }
        let upper = compute_upper_bounds(
            receipt.invocation.haystack_bytes,
            self.needle().len(),
            self.build.persistent_bytes,
        )?;
        // Publication is deliberately before the first caller-selected limit
        // check. Every post-P refusal therefore retains exact P and zero A.
        receipt.prospective = Some(upper);
        let operation = receipt.identity.operation;
        let limits = receipt.invocation.limits;
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
        receipt: &mut ReduceAttemptReceipt,
    ) -> Result<(), ReduceError> {
        self.execute_with_observer(haystack, receipt, |_| Ok(()))
    }

    fn execute_with_observer(
        &self,
        haystack: &[u8],
        receipt: &mut ReduceAttemptReceipt,
        mut after_match: impl FnMut(&ReduceActualCounters) -> Result<(), ReduceError>,
    ) -> Result<(), ReduceError> {
        let Some(upper) = receipt.prospective else {
            return Err(ReduceError::ReceiptInvariant {
                detail: "execution started before prospective publication",
            });
        };
        if receipt.invocation.haystack_bytes != haystack.len()
            || receipt.identity != OperationIdentity::for_operation(receipt.identity.operation)
        {
            return Err(ReduceError::ReceiptInvariant {
                detail: "execution identity or source length differs from admitted invocation",
            });
        }
        commit_actual(receipt, |actual| {
            actual.operation_allocations = 0;
            actual.scratch_bytes = upper.scratch_bytes;
            actual.persistent_bytes = upper.persistent_bytes;
            actual.peak_bytes = upper.peak_bytes;
            Ok(())
        })?;

        if self.needle().is_empty() {
            commit_actual(receipt, |actual| {
                actual.match_events = upper.match_events;
                actual.empty_formula_evaluations = 1;
                actual.reducer_steps = 1;
                actual.count = upper.count;
                actual.matched_bytes = 0;
                Ok(())
            })?;
            return after_match(&receipt.actual);
        }

        let needle_u64 =
            u64::try_from(self.needle().len()).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "needle length as u64",
            })?;
        let mut iterator = self.finder.find_iter(haystack);
        loop {
            commit_actual(receipt, |actual| {
                actual.iterator_next_calls = actual.iterator_next_calls.checked_add(1).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "actual iterator calls",
                    },
                )?;
                actual.reducer_steps =
                    actual
                        .reducer_steps
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual reducer steps",
                        })?;
                Ok(())
            })?;
            if iterator.next().is_none() {
                break;
            }
            commit_actual(receipt, |actual| {
                actual.match_events =
                    actual
                        .match_events
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual match events",
                        })?;
                actual.count =
                    actual
                        .count
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "actual count",
                        })?;
                actual.matched_bytes = actual.matched_bytes.checked_add(needle_u64).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "actual span sum",
                    },
                )?;
                Ok(())
            })?;
            after_match(&receipt.actual)?;
        }
        ensure_actual_is_bounded(&receipt.actual, &upper)
    }
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the complete Copy receipt is consumed into the allocation-free terminal error"
)]
fn attempt_error(
    source: ReduceError,
    receipt: ReduceAttemptReceipt,
    identity: OperationIdentity,
    invocation: ReduceInvocation,
    phase: AttemptFailurePhase,
) -> ReduceAttemptError {
    let signature = if receipt.authenticates(identity, invocation)
        && identity == OperationIdentity::for_operation(identity.operation)
        && receipt.source_closes_error(&source)
    {
        FailureSignature::from_source(phase, &source)
    } else {
        None
    };
    let seal = signature.map_or(AttemptFailureSeal::Invalid, AttemptFailureSeal::Valid);
    ReduceAttemptError {
        source,
        receipt,
        seal,
    }
}

fn commit_actual(
    receipt: &mut ReduceAttemptReceipt,
    update: impl FnOnce(&mut ReduceActualCounters) -> Result<(), ReduceError>,
) -> Result<(), ReduceError> {
    let Some(prospective) = receipt.prospective else {
        return Err(ReduceError::ReceiptInvariant {
            detail: "actual effect was charged before prospective publication",
        });
    };
    let mut next = receipt.actual;
    update(&mut next)?;
    ensure_actual_is_bounded(&next, &prospective)?;
    receipt.actual = next;
    receipt.actual_allocations = next.operation_allocations;
    Ok(())
}

fn ensure_dimension(
    dimension: &'static str,
    actual: u128,
    prospective: u128,
) -> Result<(), ReduceError> {
    if actual > prospective {
        Err(ReduceError::ActualEscapedProspective {
            dimension,
            actual,
            prospective,
        })
    } else {
        Ok(())
    }
}

fn ensure_actual_is_bounded(
    actual: &ReduceActualCounters,
    prospective: &ReduceUpperBounds,
) -> Result<(), ReduceError> {
    for (dimension, actual, prospective) in [
        (
            "match events",
            usize_to_u128(actual.match_events),
            usize_to_u128(prospective.match_events),
        ),
        (
            "iterator next calls",
            usize_to_u128(actual.iterator_next_calls),
            usize_to_u128(prospective.reducer_steps),
        ),
        (
            "empty formula evaluations",
            usize_to_u128(actual.empty_formula_evaluations),
            usize_to_u128(prospective.reducer_steps),
        ),
        (
            "reducer steps",
            usize_to_u128(actual.reducer_steps),
            usize_to_u128(prospective.reducer_steps),
        ),
        (
            "count",
            u128::from(actual.count),
            u128::from(prospective.count),
        ),
        (
            "matched bytes",
            u128::from(actual.matched_bytes),
            u128::from(prospective.span_sum),
        ),
        (
            "operation allocations",
            usize_to_u128(actual.operation_allocations),
            usize_to_u128(prospective.operation_allocations),
        ),
        (
            "scratch bytes",
            usize_to_u128(actual.scratch_bytes),
            usize_to_u128(prospective.scratch_bytes),
        ),
        (
            "persistent bytes",
            usize_to_u128(actual.persistent_bytes),
            usize_to_u128(prospective.persistent_bytes),
        ),
        (
            "peak bytes",
            usize_to_u128(actual.peak_bytes),
            usize_to_u128(prospective.peak_bytes),
        ),
    ] {
        ensure_dimension(dimension, actual, prospective)?;
    }
    let Some(steps) = actual
        .iterator_next_calls
        .checked_add(actual.empty_formula_evaluations)
    else {
        return Err(ReduceError::ReceiptInvariant {
            detail: "actual reducer-step decomposition overflowed",
        });
    };
    if steps != actual.reducer_steps {
        return Err(ReduceError::ReceiptInvariant {
            detail: "actual iterator/formula steps do not sum to reducer steps",
        });
    }
    if u64::try_from(actual.match_events) != Ok(actual.count) {
        return Err(ReduceError::ReceiptInvariant {
            detail: "actual match events do not equal the checked count",
        });
    }
    let needle =
        u64::try_from(prospective.needle_bytes).map_err(|_| ReduceError::ReceiptInvariant {
            detail: "published needle length does not fit its span arithmetic",
        })?;
    if actual.count.checked_mul(needle) != Some(actual.matched_bytes) {
        return Err(ReduceError::ReceiptInvariant {
            detail: "actual count and needle width do not equal matched bytes",
        });
    }
    Ok(())
}

fn usize_to_u128(value: usize) -> u128 {
    u128::try_from(value).unwrap_or(u128::MAX)
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
    let operation_allocations = 0;
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
        operation_allocations,
        persistent_bytes,
        peak_bytes,
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use regex::bytes::{Regex, RegexBuilder};

    use super::{
        ACCOUNTING_VERSION, ALGORITHM_VERSION, AttemptFailurePhase, BoundarySemantics, BuildError,
        BuildLimits, DeclaredFallback, LiteralAggregatePlan, Operation, OperationIdentity,
        PlanOrigin, ReduceActualCounters, ReduceAttemptError, ReduceAttemptReceipt, ReduceError,
        ReduceInvocation, ReduceLimits, attempt_error, commit_actual, compute_upper_bounds,
    };
    use crate::{ASCII_WIDE_BYTES, AsciiByteSet, DispatchPolicy, Feature, SimdDispatchContext};

    fn plan(needle: &[u8]) -> LiteralAggregatePlan {
        LiteralAggregatePlan::build(needle, BuildLimits::unlimited()).unwrap()
    }

    #[test]
    #[ignore = "native qualification benchmark; requires Linux/AArch64 with OS-usable SVE2"]
    fn benchmark_width_one_classifier_count_ceiling() {
        use std::{hint::black_box, time::Instant};

        const ITERATIONS: usize = 128;
        const HAYSTACK_BYTES: usize = 1 << 20;

        let dispatch = SimdDispatchContext::capture();
        assert!(
            dispatch.capabilities().usable().contains(Feature::ArmSve2),
            "benchmark requires OS-usable SVE2"
        );
        let plan = plan(b"x");
        let set = AsciiByteSet::from_words([0, 1_u64 << (b'x' - 64)]);
        let classifier = dispatch
            .ascii_byte_set_classifier(set, DispatchPolicy::Auto)
            .expect("automatic classifier retains a fallback");
        let corpus = b"xabcx-xyz_x0x!";
        let haystack: Vec<u8> = corpus
            .iter()
            .copied()
            .cycle()
            .take(HAYSTACK_BYTES)
            .collect();
        let expected = plan
            .count(&haystack, ReduceLimits::unlimited())
            .expect("literal aggregate count")
            .count;

        let started = Instant::now();
        let mut aggregate_checksum = 0_u64;
        for _ in 0..ITERATIONS {
            aggregate_checksum = aggregate_checksum.wrapping_add(black_box(
                plan.count(black_box(&haystack), black_box(ReduceLimits::unlimited()))
                    .expect("literal aggregate benchmark")
                    .count,
            ));
        }
        let aggregate_ns = started.elapsed().as_secs_f64() * 1_000_000_000.0 / ITERATIONS as f64;

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
                count = count.wrapping_add(u64::from(byte == b'x'));
            }
            classifier_checksum = classifier_checksum.wrapping_add(black_box(count));
        }
        let classifier_ns = started.elapsed().as_secs_f64() * 1_000_000_000.0 / ITERATIONS as f64;
        assert_eq!(aggregate_checksum, classifier_checksum);
        assert_eq!(
            aggregate_checksum,
            expected.wrapping_mul(u64::try_from(ITERATIONS).expect("small iteration count"))
        );
        println!(
            "LITERAL_AGGREGATE_BYTE_CLASSIFIER_BENCH iterations={ITERATIONS} \
             haystack_bytes={HAYSTACK_BYTES} aggregate_ns={aggregate_ns:.6} \
             classifier_ns={classifier_ns:.6} classifier_over_aggregate={:.9} \
             wide_selection={:?}",
            classifier_ns / aggregate_ns,
            classifier.selection().wide()
        );
    }

    #[test]
    fn build_attempt_reports_exact_success_and_preflight_failure_effects() {
        let needle = b"needle";
        let attempt =
            LiteralAggregatePlan::build_attempt(needle, BuildLimits::unlimited()).unwrap();
        let actual = attempt.actual();
        let (plan, repeated) = attempt.into_parts();
        assert_eq!(actual, repeated);
        let build = plan.build_accounting();
        assert_eq!(actual.work, u64::try_from(needle.len()).unwrap() + 1);
        assert_eq!(actual.allocations, 1);
        assert_eq!(actual.allocated_bytes, build.temporary_capacity_bytes);
        assert_eq!(actual.copied_bytes, needle.len());
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(
            actual.peak_bytes,
            build.temporary_capacity_bytes.max(build.persistent_bytes)
        );

        let failure = LiteralAggregatePlan::build_attempt(
            needle,
            BuildLimits {
                max_build_work: 0,
                ..BuildLimits::unlimited()
            },
        )
        .unwrap_err();
        assert!(matches!(failure.source(), BuildError::WorkLimit { .. }));
        assert_eq!(failure.actual(), crate::DirectBuildAttemptActual::default());
    }

    fn initial_receipt(
        reducer: &LiteralAggregatePlan,
        operation: Operation,
        haystack_bytes: usize,
        limits: ReduceLimits,
    ) -> ReduceAttemptReceipt {
        ReduceAttemptReceipt {
            identity: OperationIdentity::for_operation(operation),
            invocation: ReduceInvocation {
                haystack_bytes,
                build: reducer.build_accounting(),
                plan_origin: reducer.external_origin(),
                limits,
            },
            prospective: None,
            actual: ReduceActualCounters::default(),
            actual_allocations: 0,
        }
    }

    #[test]
    fn external_origin_is_word_sized_masked_and_single_assignment() {
        assert_eq!(
            core::mem::size_of::<PlanOrigin>(),
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            format!("{:?}", PlanOrigin::unbound()),
            "PlanOrigin(\"unbound\")"
        );
        let origin = PlanOrigin::from_external_address(0xDEAD_BEEF).unwrap();
        assert!(origin.is_bound());
        assert_eq!(format!("{origin:?}"), "PlanOrigin(\"bound\")");
        assert!(!format!("{origin:?}").contains("dead"));

        let mut reducer = plan(b"needle");
        assert!(!reducer.external_origin().is_bound());
        assert!(reducer.bind_external_origin(origin));
        assert_eq!(reducer.external_origin(), origin);
        assert!(!reducer.bind_external_origin(origin));
        assert!(!reducer.bind_external_origin(PlanOrigin::unbound()));
        let attempt = reducer
            .count_attempt(b"needle", ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(attempt.receipt.invocation.plan_origin, origin);
        assert!(attempt.closes());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one mutation matrix keeps every public source stage and receipt field adjacent"
    )]
    fn public_terminal_closure_rejects_source_stage_and_receipt_field_mutations() {
        let reducer = plan(b"a");
        let haystack = b"aaa";
        let success = reducer
            .count_attempt(haystack, ReduceLimits::unlimited())
            .unwrap();
        let upper = success.receipt.prospective.unwrap();
        let limit_errors = [
            reducer
                .count_attempt(
                    haystack,
                    ReduceLimits {
                        max_linear_terms: upper.linear_terms - 1,
                        ..ReduceLimits::unlimited()
                    },
                )
                .unwrap_err(),
            reducer
                .count_attempt(
                    haystack,
                    ReduceLimits {
                        max_match_events: upper.match_events - 1,
                        ..ReduceLimits::unlimited()
                    },
                )
                .unwrap_err(),
            reducer
                .count_attempt(
                    haystack,
                    ReduceLimits {
                        max_count: upper.count - 1,
                        ..ReduceLimits::unlimited()
                    },
                )
                .unwrap_err(),
            reducer
                .count_attempt(
                    haystack,
                    ReduceLimits {
                        max_reducer_steps: upper.reducer_steps - 1,
                        ..ReduceLimits::unlimited()
                    },
                )
                .unwrap_err(),
            reducer
                .count_attempt(
                    haystack,
                    ReduceLimits {
                        max_peak_bytes: upper.peak_bytes - 1,
                        ..ReduceLimits::unlimited()
                    },
                )
                .unwrap_err(),
            reducer
                .span_sum_attempt(
                    haystack,
                    ReduceLimits {
                        max_span_sum: upper.span_sum - 1,
                        ..ReduceLimits::unlimited()
                    },
                )
                .unwrap_err(),
        ];
        for error in limit_errors {
            assert!(error.closes(), "{error:?}");

            let mut source_field = error.clone();
            match &mut source_field.source {
                ReduceError::LinearTermsLimit { needed, .. }
                | ReduceError::MatchEventsLimit { needed, .. }
                | ReduceError::ReducerStepsLimit { needed, .. }
                | ReduceError::PeakLimit { needed, .. } => *needed += 1,
                ReduceError::CountLimit { needed, .. }
                | ReduceError::SpanSumLimit { needed, .. } => *needed += 1,
                source => panic!("unexpected limit source {source:?}"),
            }
            assert!(!source_field.closes());

            let mut partial_actual = error.clone();
            partial_actual.receipt.actual.match_events = 1;
            assert!(!partial_actual.closes());

            let mut identity = error.clone();
            identity.receipt.identity.operation_id = "forged-operation";
            assert!(!identity.closes());

            let mut build = error.clone();
            build.receipt.invocation.build.peak_bytes += 1;
            assert!(!build.closes());

            let mut prospective = error.clone();
            prospective
                .receipt
                .prospective
                .as_mut()
                .unwrap()
                .linear_terms += 1;
            assert!(!prospective.closes());

            let mut allocation = error;
            allocation.receipt.actual_allocations = 1;
            assert!(!allocation.closes());
        }

        // Seal one genuine failed next charge. The attempted allocation is
        // exactly 0 + 1 against P=0; commit_actual leaves A unchanged, and the
        // terminal binds that execution phase and typed effect.
        let identity = reducer.count_identity();
        let invocation = ReduceInvocation {
            haystack_bytes: haystack.len(),
            build: reducer.build_accounting(),
            plan_origin: reducer.external_origin(),
            limits: ReduceLimits::unlimited(),
        };
        let mut escaped_receipt = initial_receipt(
            &reducer,
            Operation::Count,
            haystack.len(),
            invocation.limits,
        );
        reducer.preflight(&mut escaped_receipt).unwrap();
        let escaped_source = commit_actual(&mut escaped_receipt, |actual| {
            actual.operation_allocations += 1;
            Ok(())
        })
        .unwrap_err();
        let sealed_escape = attempt_error(
            escaped_source,
            escaped_receipt,
            identity,
            invocation,
            AttemptFailurePhase::Execution,
        );
        assert!(sealed_escape.closes());
        let mut wrong_delta = sealed_escape.clone();
        let ReduceError::ActualEscapedProspective { actual, .. } = &mut wrong_delta.source else {
            unreachable!()
        };
        *actual += 1;
        assert!(!wrong_delta.closes());
        let mut wrong_effect = sealed_escape.clone();
        let ReduceError::ActualEscapedProspective { dimension, .. } = &mut wrong_effect.source
        else {
            unreachable!()
        };
        *dimension = "scratch bytes";
        assert!(!wrong_effect.closes());
        let mut full_success_escape = sealed_escape.clone();
        full_success_escape.receipt.actual = success.receipt.actual;
        full_success_escape.receipt.actual_allocations = success.receipt.actual_allocations;
        assert!(!full_success_escape.closes());
        let wrong_phase = ReduceAttemptError {
            source: sealed_escape.source.clone(),
            receipt: success.receipt,
            seal: sealed_escape.seal,
        };
        assert!(!wrong_phase.closes());

        // A public caller cannot repackage a success-sealed receipt as any
        // failure, even when the bare source looks structurally plausible.
        let escaped = ReduceAttemptError {
            source: ReduceError::ActualEscapedProspective {
                dimension: "match events",
                actual: u128::try_from(upper.match_events).unwrap() + 1,
                prospective: u128::try_from(upper.match_events).unwrap(),
            },
            receipt: success.receipt,
            seal: super::AttemptFailureSeal::Invalid,
        };
        assert!(!escaped.closes());
        let mut wrong_dimension = escaped.clone();
        let ReduceError::ActualEscapedProspective { dimension, .. } = &mut wrong_dimension.source
        else {
            unreachable!()
        };
        *dimension = "unknown";
        assert!(!wrong_dimension.closes());
        let mut nonescaping = escaped.clone();
        let ReduceError::ActualEscapedProspective {
            actual,
            prospective,
            ..
        } = &mut nonescaping.source
        else {
            unreachable!()
        };
        *actual = *prospective;
        assert!(!nonescaping.closes());

        let receipt_invariant = ReduceAttemptError {
            source: ReduceError::ReceiptInvariant { detail: "injected" },
            receipt: success.receipt,
            seal: super::AttemptFailureSeal::Invalid,
        };
        assert!(!receipt_invariant.closes());
        let postpublication_overflow = ReduceAttemptError {
            source: ReduceError::ArithmeticOverflow {
                computation: "injected",
            },
            receipt: success.receipt,
            seal: super::AttemptFailureSeal::Invalid,
        };
        assert!(!postpublication_overflow.closes());

        let empty = plan(b"");
        let identity = empty.count_identity();
        let invocation = ReduceInvocation {
            haystack_bytes: usize::MAX,
            build: empty.build_accounting(),
            plan_origin: empty.external_origin(),
            limits: ReduceLimits::unlimited(),
        };
        let mut receipt = initial_receipt(
            &empty,
            Operation::Count,
            invocation.haystack_bytes,
            invocation.limits,
        );
        let source = empty.preflight(&mut receipt).unwrap_err();
        let prepublication_overflow = attempt_error(
            source,
            receipt,
            identity,
            invocation,
            AttemptFailurePhase::Preflight,
        );
        assert!(prepublication_overflow.closes());
        let mut arbitrary_computation = prepublication_overflow.clone();
        let ReduceError::ArithmeticOverflow { computation } = &mut arbitrary_computation.source
        else {
            unreachable!()
        };
        *computation = "injected";
        assert!(!arbitrary_computation.closes());
        let mut prepublication_actual = prepublication_overflow;
        prepublication_actual
            .receipt
            .actual
            .empty_formula_evaluations = 1;
        assert!(!prepublication_actual.closes());

        let impossible_scratch = ReduceAttemptError {
            source: ReduceError::ScratchLimit {
                needed: 0,
                limit: 0,
            },
            receipt: success.receipt,
            seal: super::AttemptFailureSeal::Invalid,
        };
        assert!(!impossible_scratch.closes());

        // Limit precedence is authenticated, not merely a plausible later
        // one-below field. Linear terms wins when both first and second gates
        // refuse, and relabeling that sealed source as match-events fails.
        let multiple_limits = ReduceLimits {
            max_linear_terms: upper.linear_terms - 1,
            max_match_events: upper.match_events - 1,
            ..ReduceLimits::unlimited()
        };
        let precedence = reducer
            .count_attempt(haystack, multiple_limits)
            .unwrap_err();
        assert!(matches!(
            precedence.source,
            ReduceError::LinearTermsLimit { .. }
        ));
        assert!(precedence.closes());
        let mut later_gate = precedence.clone();
        later_gate.source = ReduceError::MatchEventsLimit {
            needed: upper.match_events,
            limit: multiple_limits.max_match_events,
        };
        assert!(!later_gate.closes());

        // A sealed refusal cannot be converted into a successful public
        // attempt or made plausible by copying a complete success A.
        let mut full_success_actual = precedence.clone();
        full_success_actual.receipt.actual = success.receipt.actual;
        full_success_actual.receipt.actual_allocations = success.receipt.actual_allocations;
        assert!(!full_success_actual.closes());
        let failure_as_success = super::CountAttempt {
            result: success.result,
            receipt: precedence.receipt,
        };
        assert!(!failure_as_success.closes());
    }

    #[test]
    fn successful_attempts_require_canonical_identity_build_p_and_success_phase() {
        let reducer = plan(b"a");
        let haystack = b"aaa";
        let count = reducer
            .count_attempt(haystack, ReduceLimits::unlimited())
            .unwrap();
        let span = reducer
            .span_sum_attempt(haystack, ReduceLimits::unlimited())
            .unwrap();
        assert!(count.closes());
        assert!(span.closes());

        let mut cross_operation = count;
        let span_identity = OperationIdentity::for_operation(Operation::SpanSum);
        cross_operation.receipt.identity = span_identity;
        cross_operation.result.accounting.identity = span_identity;
        assert!(!cross_operation.closes());

        let mut noncanonical_identity = count;
        noncanonical_identity.receipt.identity.operation_id = "forged-operation";
        noncanonical_identity
            .result
            .accounting
            .identity
            .operation_id = "forged-operation";
        assert!(!noncanonical_identity.closes());

        let mut noncanonical_build = count;
        for build in [
            &mut noncanonical_build.receipt.invocation.build,
            &mut noncanonical_build.result.accounting.invocation.build,
        ] {
            build.temporary_capacity_bytes = 0;
            build.scratch_bytes = 0;
            build.peak_bytes = build.persistent_bytes;
        }
        assert!(!noncanonical_build.closes());

        let mut noncanonical_prospective = count;
        noncanonical_prospective
            .receipt
            .prospective
            .as_mut()
            .unwrap()
            .linear_terms += 1;
        noncanonical_prospective
            .result
            .accounting
            .upper_bounds
            .linear_terms += 1;
        assert!(!noncanonical_prospective.closes());

        let mut span_as_count = span;
        let count_identity = OperationIdentity::for_operation(Operation::Count);
        span_as_count.receipt.identity = count_identity;
        span_as_count.result.accounting.identity = count_identity;
        assert!(!span_as_count.closes());

        let empty = plan(b"");
        let mut forged_empty_capacity =
            empty.count_attempt(b"", ReduceLimits::unlimited()).unwrap();
        for build in [
            &mut forged_empty_capacity.receipt.invocation.build,
            &mut forged_empty_capacity.result.accounting.invocation.build,
        ] {
            build.temporary_capacity_bytes = 1;
            build.scratch_bytes = 1;
            build.peak_bytes = build.persistent_bytes + 1;
        }
        assert!(!forged_empty_capacity.closes());
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
        let count_attempt = plan
            .count_attempt(b"\xFFa\x80", ReduceLimits::unlimited())
            .unwrap();
        let span_attempt = plan
            .span_sum_attempt(b"\xFFa\x80", ReduceLimits::unlimited())
            .unwrap();
        assert!(count_attempt.closes());
        assert!(span_attempt.closes());
        let count = count_attempt.result;
        let spans = span_attempt.result;
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
        assert_eq!(
            count.accounting.identity.algorithm_version,
            ALGORITHM_VERSION
        );
        assert_eq!(
            count.accounting.identity.accounting_version,
            ACCOUNTING_VERSION
        );
        assert_eq!(
            count.accounting.identity.declared_fallback,
            DeclaredFallback::None
        );
        assert_eq!(
            count_attempt.receipt.prospective,
            Some(count.accounting.upper_bounds)
        );
        assert_eq!(
            span_attempt.receipt.prospective,
            Some(spans.accounting.upper_bounds)
        );
        assert_eq!(count_attempt.receipt.actual_allocations, 0);
        assert_eq!(span_attempt.receipt.actual_allocations, 0);
        assert!(count_attempt.receipt.retains_bounded_actual());
        assert!(span_attempt.receipt.retains_bounded_actual());
    }

    #[test]
    fn nonempty_iteration_is_leftmost_nonoverlapping_for_arbitrary_bytes() {
        let overlapping = plan(b"aba");
        let count_attempt = overlapping
            .count_attempt(b"ababa", ReduceLimits::unlimited())
            .unwrap();
        assert!(count_attempt.closes());
        let count = count_attempt.result;
        assert_eq!(count.count, 1);
        assert_eq!(count.accounting.actual.iterator_next_calls, 2);

        let repeated = plan(b"aa");
        let spans = repeated
            .span_sum(b"aaaaa", ReduceLimits::unlimited())
            .unwrap();
        assert_eq!(spans.span_sum, 4);
        assert_eq!(spans.accounting.actual.match_events, 2);

        let arbitrary = plan(b"\xFF\x00");
        let arbitrary_count = arbitrary
            .count_attempt(b"\xFF\x00\xFF\x00\x80", ReduceLimits::unlimited())
            .unwrap();
        assert!(arbitrary_count.closes());
        assert_eq!(arbitrary_count.result.count, 2);
        assert_eq!(arbitrary_count.receipt.actual_allocations, 0);
        assert!(arbitrary_count.receipt.retains_bounded_actual());
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
    #[allow(
        clippy::too_many_lines,
        reason = "the exact and one-below matrix covers every independently enforced resource"
    )]
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
        let exact_span = plan.span_sum_attempt(haystack, exact).unwrap();
        assert!(exact_span.closes());
        assert_eq!(exact_span.receipt.prospective, Some(baseline));
        assert!(exact_span.receipt.retains_bounded_actual());

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
            let error = plan.span_sum_attempt(haystack, limits).unwrap_err();
            let actual = match error.source {
                ReduceError::LinearTermsLimit { .. } => "linear",
                ReduceError::MatchEventsLimit { .. } => "events",
                ReduceError::CountLimit { .. } => "count",
                ReduceError::SpanSumLimit { .. } => "span",
                ReduceError::ReducerStepsLimit { .. } => "steps",
                ReduceError::PeakLimit { .. } => "peak",
                other => panic!("unexpected reduce error: {other:?}"),
            };
            assert_eq!(actual, expected);
            assert_eq!(error.receipt.prospective, Some(baseline));
            assert_eq!(error.receipt.actual, ReduceActualCounters::default());
            assert_eq!(error.receipt.actual_allocations, 0);
            assert!(error.receipt.retains_bounded_actual());
            assert!(error.receipt.authenticates(
                OperationIdentity::for_operation(Operation::SpanSum),
                ReduceInvocation {
                    haystack_bytes: haystack.len(),
                    build: plan.build_accounting(),
                    plan_origin: plan.external_origin(),
                    limits,
                }
            ));
        }

        let count_only = ReduceLimits {
            max_span_sum: 0,
            ..ReduceLimits::unlimited()
        };
        let count_attempt = plan.count_attempt(haystack, count_only).unwrap();
        assert_eq!(count_attempt.result.count, 4);
        assert!(count_attempt.closes());

        let count_cases = [
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
        for (limits, expected) in count_cases {
            let error = plan.count_attempt(haystack, limits).unwrap_err();
            let actual = match error.source {
                ReduceError::LinearTermsLimit { .. } => "linear",
                ReduceError::MatchEventsLimit { .. } => "events",
                ReduceError::CountLimit { .. } => "count",
                ReduceError::ReducerStepsLimit { .. } => "steps",
                ReduceError::PeakLimit { .. } => "peak",
                other => panic!("unexpected count error: {other:?}"),
            };
            assert_eq!(actual, expected);
            assert_eq!(error.receipt.prospective, Some(baseline));
            assert_eq!(error.receipt.actual, ReduceActualCounters::default());
            assert_eq!(error.receipt.actual_allocations, 0);
            assert!(error.receipt.retains_bounded_actual());
            assert!(error.receipt.authenticates(
                OperationIdentity::for_operation(Operation::Count),
                ReduceInvocation {
                    haystack_bytes: haystack.len(),
                    build: plan.build_accounting(),
                    plan_origin: plan.external_origin(),
                    limits,
                }
            ));
        }

        let empty = LiteralAggregatePlan::build(b"", BuildLimits::unlimited()).unwrap();
        for operation in [Operation::Count, Operation::SpanSum] {
            let mut limits = ReduceLimits::unlimited();
            limits.max_linear_terms = haystack.len() - 1;
            let error = match operation {
                Operation::Count => empty.count_attempt(haystack, limits).unwrap_err(),
                Operation::SpanSum => empty.span_sum_attempt(haystack, limits).unwrap_err(),
            };
            assert!(matches!(error.source, ReduceError::LinearTermsLimit { .. }));
            assert!(error.receipt.prospective.is_some());
            assert_eq!(error.receipt.actual, ReduceActualCounters::default());
            assert_eq!(error.receipt.actual_allocations, 0);
            assert!(error.receipt.retains_bounded_actual());
        }
    }

    #[test]
    fn prepublication_arithmetic_failures_retain_no_p_and_zero_a() {
        for (reducer, operation) in [
            (plan(b""), Operation::SpanSum),
            (plan(b"x"), Operation::Count),
        ] {
            let identity = OperationIdentity::for_operation(operation);
            let invocation = ReduceInvocation {
                haystack_bytes: usize::MAX,
                build: reducer.build_accounting(),
                plan_origin: reducer.external_origin(),
                limits: ReduceLimits::unlimited(),
            };
            let mut receipt = initial_receipt(&reducer, operation, usize::MAX, invocation.limits);
            let source = reducer.preflight(&mut receipt).unwrap_err();
            let error = attempt_error(
                source,
                receipt,
                identity,
                invocation,
                AttemptFailurePhase::Preflight,
            );
            assert!(matches!(
                error.source,
                ReduceError::ArithmeticOverflow { .. }
            ));
            assert_eq!(error.receipt.prospective, None);
            assert_eq!(error.receipt.actual, ReduceActualCounters::default());
            assert_eq!(error.receipt.actual_allocations, 0);
            assert!(error.receipt.authenticates(identity, invocation));
            assert!(error.receipt.retains_bounded_actual());
        }
    }

    #[test]
    fn injected_execution_faults_retain_nonzero_bounded_partial_a() {
        let reducer = plan(b"ab");
        let haystack = b"abab";
        let identity = reducer.count_identity();
        let invocation = ReduceInvocation {
            haystack_bytes: haystack.len(),
            build: reducer.build_accounting(),
            plan_origin: reducer.external_origin(),
            limits: ReduceLimits::unlimited(),
        };
        let mut receipt = initial_receipt(
            &reducer,
            Operation::Count,
            haystack.len(),
            invocation.limits,
        );
        let prospective = reducer.preflight(&mut receipt).unwrap();
        let source = reducer
            .execute_with_observer(haystack, &mut receipt, |actual| {
                if actual.match_events == 1 {
                    Err(ReduceError::ArithmeticOverflow {
                        computation: "injected post-match fault",
                    })
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        let error = attempt_error(
            source,
            receipt,
            identity,
            invocation,
            AttemptFailurePhase::Execution,
        );
        assert!(!error.closes());
        assert!(matches!(
            error.source,
            ReduceError::ArithmeticOverflow {
                computation: "injected post-match fault"
            }
        ));
        assert_eq!(error.receipt.prospective, Some(prospective));
        assert_eq!(error.receipt.actual.match_events, 1);
        assert_eq!(error.receipt.actual.iterator_next_calls, 1);
        assert_eq!(error.receipt.actual.reducer_steps, 1);
        assert_eq!(error.receipt.actual.count, 1);
        assert_eq!(error.receipt.actual.matched_bytes, 2);
        assert_eq!(error.receipt.actual_allocations, 0);
        assert!(error.receipt.retains_bounded_actual());

        let empty = plan(b"");
        let empty_identity = empty.span_sum_identity();
        let empty_invocation = ReduceInvocation {
            haystack_bytes: haystack.len(),
            build: empty.build_accounting(),
            plan_origin: empty.external_origin(),
            limits: ReduceLimits::unlimited(),
        };
        let mut empty_receipt = initial_receipt(
            &empty,
            Operation::SpanSum,
            haystack.len(),
            empty_invocation.limits,
        );
        let empty_prospective = empty.preflight(&mut empty_receipt).unwrap();
        let source = empty
            .execute_with_observer(haystack, &mut empty_receipt, |_| {
                Err(ReduceError::ArithmeticOverflow {
                    computation: "injected post-formula fault",
                })
            })
            .unwrap_err();
        let error = attempt_error(
            source,
            empty_receipt,
            empty_identity,
            empty_invocation,
            AttemptFailurePhase::Execution,
        );
        assert!(!error.closes());
        assert_eq!(error.receipt.prospective, Some(empty_prospective));
        assert_eq!(error.receipt.actual.empty_formula_evaluations, 1);
        assert_eq!(error.receipt.actual.reducer_steps, 1);
        assert_eq!(
            error.receipt.actual.match_events,
            haystack.len().checked_add(1).unwrap()
        );
        assert_eq!(error.receipt.actual.matched_bytes, 0);
        assert!(error.receipt.retains_bounded_actual());
    }

    #[test]
    fn release_containment_rejects_every_forged_actual_dimension_before_commit() {
        let reducer = plan(b"ab");
        let haystack = b"abababab";
        let success = reducer
            .span_sum_attempt(haystack, ReduceLimits::unlimited())
            .unwrap();
        assert!(success.closes());
        let prospective = success.receipt.prospective.unwrap();
        let original = success.receipt;

        macro_rules! forged {
            ($update:expr) => {{
                let mut receipt = original;
                ($update)(&mut receipt);
                assert!(!receipt.retains_bounded_actual());
            }};
        }
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.match_events = prospective.match_events + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.iterator_next_calls = prospective.reducer_steps + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.empty_formula_evaluations = prospective.reducer_steps + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.reducer_steps = prospective.reducer_steps + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.count = prospective.count + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.matched_bytes = prospective.span_sum + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.operation_allocations = 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.scratch_bytes = prospective.scratch_bytes + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.persistent_bytes = prospective.persistent_bytes + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual.peak_bytes = prospective.peak_bytes + 1;
        });
        forged!(|receipt: &mut ReduceAttemptReceipt| {
            receipt.actual_allocations = 1;
        });

        let mut bounded = original;
        let before = bounded;
        let error = commit_actual(&mut bounded, |actual| {
            actual.operation_allocations = 1;
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(
            error,
            ReduceError::ActualEscapedProspective {
                dimension: "operation allocations",
                actual: 1,
                prospective: 0,
            }
        ));
        assert_eq!(bounded, before);
        assert!(bounded.retains_bounded_actual());
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
