//! Explicit HIR-certified literal-anchor execution.
//!
//! This facade is intentionally separate from the ordinary aggregate planner.
//! It either uses a complete byte-literal candidate stream plus the common
//! priority automaton as the semantic verifier, or chooses that common sparse
//! automaton before it reads the haystack. It never examines a benchmark name,
//! fixture, hash, expected value, or timing signal.

#![allow(
    clippy::result_large_err,
    reason = "terminal construction and run errors retain the typed leaf failure instead of allocating an unaccounted wrapper"
)]

use core::{cmp::Ordering, fmt, mem::size_of};

use fre_automata::{
    Automaton, CompileError, K0Workspace, SearchAccounting, SearchError, SearchLimits,
    SearchWindow, Span, WorkspaceLimits,
};
use fre_exact_alloc::{CopyError, ExactVec};
use fre_kernels::{
    ByteCandidateBuildAccounting, ByteCandidateBuildAttempt, ByteCandidateBuildLimits,
    ByteCandidatePlan, ByteCandidateScanAttemptError, ByteCandidateScanLimits,
    ByteCandidateScanReceipt, ByteCandidateScanUpperBounds, LiteralAnchor,
    LiteralAnchorOffsetBounds, LiteralAnchorRecovery, LiteralCandidate,
};
use fre_lower::{
    FactError, FactOperation, FactOutput, FactProof, HirFacts, LowerError, OperationSemantics,
    StringEncoding, analyze_facts, lower_raw,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseAttemptError, ParseRequest, RustProfile,
};

use super::forced_priority::{
    PriorityAggregateBuildError, PriorityAggregateBuildLimits, PriorityAggregateBuilder,
    PriorityAggregateCountRegex, PriorityAggregateExecutionReceipt, PriorityAggregateOperation,
    PriorityAggregateRunError, PriorityAggregateRunLimits, PriorityAggregateSpanSumRegex,
};
use fre_automata::{ForcedExecution, PriorityTarget};

/// Stable schema for the explicit literal-anchor facade receipts.
pub const LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION: u32 = 1;
/// Stable identity for this candidate-to-priority-automaton bridge.
pub const LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID: &str = "fre.literal-anchor-aggregate.facade.v1";

/// One facade-owned anchor mapping attempt for every primitive candidate.
///
/// The primitive's event work does not include callback work owned by this
/// bridge. This fixed logical charge covers the mandatory retained-anchor
/// lookup and recovery attempt, whether the recovered range is usable or is
/// rejected at a haystack boundary.
const CANDIDATE_RECOVERY_WORK_PER_EVENT: u64 = 1;

/// Fixed bridge work per recovered record for ordered grouping and monotone
/// cursor/output reduction after the separately charged insertion sort.
const CANDIDATE_REDUCER_WORK_PER_RECOVERED: u64 = 2;

/// Construction limits owned by the literal-anchor bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralAnchorAggregateBuildLimits {
    /// Limits passed unchanged to the immutable byte-candidate primitive.
    pub candidate: ByteCandidateBuildLimits,
    /// Maximum required alternatives retained as one anchor group.
    pub max_anchors: usize,
    /// Maximum one anchored verifier window admitted from HIR context facts.
    pub max_verifier_window_bytes: usize,
    /// Maximum bytes retained by the immutable anchor mapping.
    pub max_anchor_metadata_bytes: usize,
}

impl Default for LiteralAnchorAggregateBuildLimits {
    fn default() -> Self {
        Self {
            candidate: ByteCandidateBuildLimits::default(),
            max_anchors: 4_096,
            max_verifier_window_bytes: 64 * 1024,
            max_anchor_metadata_bytes: 256 * 1024,
        }
    }
}

/// Per-run limits for the candidate hot operation.
///
/// Candidate admission limits are selector bounds: when a complete
/// source-length-only envelope is too dense or proof-large, the facade uses
/// its already prepared common sparse plan before reading a source byte.
/// `common` remains the exact hard-limit authority for that fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralAnchorAggregateRunLimits {
    /// Primitive scan limits checked before the stream slices the haystack.
    pub candidate_scan: ByteCandidateScanLimits,
    /// Per-start K0 semantic-verifier limits.
    pub verifier: SearchLimits,
    /// Maximum candidate events admitted to the candidate route.
    pub max_candidate_events: usize,
    /// Exact temporary queue-byte ceiling for recovered candidates.
    pub max_pending_bytes: usize,
    /// Combined candidate queue and reusable verifier-workspace ceiling.
    pub max_total_scratch_bytes: usize,
    /// Maximum insertion-sort work for recovered-start ordering.
    pub max_reorder_work: u64,
    /// Maximum distinct recovered starts verified in one operation.
    pub max_verifier_calls: usize,
    /// Maximum total K0 verifier work admitted before source access.
    pub max_verifier_work: u64,
    /// Maximum aggregate scan, reorder, and verifier work.
    pub max_total_work: u64,
    /// Shared value bound for both the candidate and common routes.
    pub max_output: u64,
    /// Exact run limits for the prebuilt common sparse fallback.
    pub common: PriorityAggregateRunLimits,
}

impl LiteralAnchorAggregateRunLimits {
    /// Accept every representable candidate envelope. Arithmetic and leaf
    /// safety checks remain active.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            candidate_scan: ByteCandidateScanLimits::unlimited(),
            verifier: SearchLimits::unlimited(),
            max_candidate_events: usize::MAX,
            max_pending_bytes: usize::MAX,
            max_total_scratch_bytes: usize::MAX,
            max_reorder_work: u64::MAX,
            max_verifier_calls: usize::MAX,
            max_verifier_work: u64::MAX,
            max_total_work: u64::MAX,
            max_output: u64::MAX,
            common: PriorityAggregateRunLimits::unlimited(),
        }
    }
}

impl Default for LiteralAnchorAggregateRunLimits {
    fn default() -> Self {
        Self {
            candidate_scan: ByteCandidateScanLimits::default(),
            verifier: SearchLimits::default(),
            max_candidate_events: 16 * 1024,
            max_pending_bytes: 4 * 1024 * 1024,
            max_total_scratch_bytes: 16 * 1024 * 1024,
            max_reorder_work: 32_000_000,
            max_verifier_calls: 16 * 1024,
            max_verifier_work: 1_000_000_000,
            max_total_work: 2_000_000_000,
            max_output: u64::MAX,
            common: PriorityAggregateRunLimits::default(),
        }
    }
}

/// Why the common sparse automaton was selected instead of a byte stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LiteralAnchorFallbackReason {
    /// Canonical HIR did not publish a positive required-literal proof.
    RequiredProofUnavailable,
    /// Every proven required group was empty, unbounded, or lacked an exact
    /// reverse start offset.
    BoundedAnchorProofUnavailable,
    /// Current canonical HIR intentionally refuses Unicode simple-fold origin;
    /// choosing a folded trie would therefore overclaim provenance.
    UnicodeFoldProvenanceUnavailable,
    /// The byte candidate primitive declined or could not build a stream.
    CandidateConstructionUnavailable,
    /// The source-length-only envelope is dense or exceeds the candidate
    /// route's checked run envelope.
    DenseOrProofLarge,
    /// Candidate-envelope arithmetic could not be represented.
    CandidateEnvelopeOverflow,
}

/// Route fixed at construction or selected before input access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiteralAnchorAggregateRoute {
    /// A structural Two-Way or sparse-trie candidate stream with priority K0
    /// start verification.
    ByteCandidate,
    /// The prepared common sparse priority automaton.
    CommonSparse(LiteralAnchorFallbackReason),
}

/// Immutable attribution retained for an admitted byte candidate group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralAnchorCandidateBuildReport {
    anchor_count: usize,
    anchor_metadata_bytes: usize,
    maximum_verifier_window_bytes: usize,
    byte_candidate: ByteCandidateBuildAccounting,
}

impl LiteralAnchorCandidateBuildReport {
    /// Number of source-order alternatives mapped to literal anchors.
    #[must_use]
    pub const fn anchor_count(self) -> usize {
        self.anchor_count
    }

    /// Exact retained payload for the anchor mapping.
    #[must_use]
    pub const fn anchor_metadata_bytes(self) -> usize {
        self.anchor_metadata_bytes
    }

    /// Largest proof-derived K0 window needed for one candidate.
    #[must_use]
    pub const fn maximum_verifier_window_bytes(self) -> usize {
        self.maximum_verifier_window_bytes
    }

    /// Immutable byte-stream construction receipt.
    #[must_use]
    pub const fn byte_candidate(self) -> ByteCandidateBuildAccounting {
        self.byte_candidate
    }
}

/// Construction report for an explicit literal-anchor artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralAnchorAggregateBuildReport {
    schema_version: u32,
    accounting_id: &'static str,
    operation: PriorityAggregateOperation,
    route: LiteralAnchorAggregateRoute,
    candidate: Option<LiteralAnchorCandidateBuildReport>,
}

impl LiteralAnchorAggregateBuildReport {
    #[must_use]
    pub const fn operation(self) -> PriorityAggregateOperation {
        self.operation
    }

    #[must_use]
    pub const fn route(self) -> LiteralAnchorAggregateRoute {
        self.route
    }

    #[must_use]
    pub const fn candidate(self) -> Option<LiteralAnchorCandidateBuildReport> {
        self.candidate
    }

    /// Check the immutable identity and route/report relationship.
    #[must_use]
    pub fn closes(self) -> bool {
        let candidate_closes = self.candidate.is_none_or(|candidate| {
            let accounting = candidate.byte_candidate;
            candidate.anchor_count != 0
                && candidate
                    .anchor_count
                    .checked_mul(size_of::<LiteralAnchor>())
                    == Some(candidate.anchor_metadata_bytes)
                && accounting.patterns == candidate.anchor_count
                && accounting.pattern_bytes >= accounting.patterns
                && accounting.pattern_byte_reads <= accounting.pattern_byte_reads_upper_bound
                && accounting.states <= accounting.states_upper_bound
                && accounting.transitions <= accounting.transitions_upper_bound
                && accounting.outputs <= accounting.outputs_upper_bound
                && accounting.work <= accounting.work_upper_bound
                && accounting.persistent_bytes <= accounting.persistent_bytes_upper_bound
                && accounting.peak_bytes <= accounting.peak_bytes_upper_bound
                && accounting.allocations <= accounting.allocations_upper_bound
        });
        matches!(
            (self.route, self.candidate),
            (LiteralAnchorAggregateRoute::ByteCandidate, Some(_))
                | (LiteralAnchorAggregateRoute::CommonSparse(_), None)
        ) && self.schema_version == LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION
            && self.accounting_id == LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID
            && candidate_closes
    }
}

/// Explicit construction failure. Candidate ineligibility is deliberately not
/// an error: the prebuilt common sparse artifact remains correct and bounded.
#[derive(Debug)]
#[non_exhaustive]
pub enum LiteralAnchorAggregateBuildError {
    Common(PriorityAggregateBuildError),
    Syntax(ParseAttemptError),
    NonRustCanonicalPattern,
    Facts(FactError),
    CaptureErasureNotProven,
    Lower(LowerError),
    Automaton(CompileError),
}

impl fmt::Display for LiteralAnchorAggregateBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Common(error) => write!(formatter, "common sparse construction: {error}"),
            Self::Syntax(error) => write!(formatter, "literal-anchor syntax analysis: {error}"),
            Self::NonRustCanonicalPattern => {
                formatter.write_str("literal-anchor facade requires a canonical Rust pattern")
            }
            Self::Facts(error) => write!(formatter, "literal-anchor HIR facts: {error}"),
            Self::CaptureErasureNotProven => {
                formatter.write_str("whole-match literal-anchor reduction cannot erase captures")
            }
            Self::Lower(error) => write!(formatter, "literal-anchor lowering: {error}"),
            Self::Automaton(error) => write!(formatter, "literal-anchor automaton: {error}"),
        }
    }
}

impl std::error::Error for LiteralAnchorAggregateBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Common(error) => Some(error),
            Self::Syntax(error) => Some(error),
            Self::Facts(error) => Some(error),
            Self::Lower(error) => Some(error),
            Self::Automaton(error) => Some(error),
            Self::NonRustCanonicalPattern | Self::CaptureErasureNotProven => None,
        }
    }
}

/// Builder whose selection inputs are only source, Rust profile, capability,
/// canonical HIR facts, and checked limits.
#[derive(Clone, Debug)]
pub struct LiteralAnchorAggregateBuilder {
    pattern: String,
    profile: RustProfile,
    priority_limits: PriorityAggregateBuildLimits,
    anchor_limits: LiteralAnchorAggregateBuildLimits,
    target: PriorityTarget,
}

impl LiteralAnchorAggregateBuilder {
    /// Start with the pinned Rust bytes profile.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            priority_limits: PriorityAggregateBuildLimits::default(),
            anchor_limits: LiteralAnchorAggregateBuildLimits::default(),
            target: PriorityTarget::portable(),
        }
    }

    /// Bind the complete Rust syntax/profile input.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Replace parse, fact, lowering, and common-automaton limits.
    #[must_use]
    pub const fn priority_limits(mut self, limits: PriorityAggregateBuildLimits) -> Self {
        self.priority_limits = limits;
        self
    }

    /// Replace literal-anchor construction limits.
    #[must_use]
    pub const fn anchor_limits(mut self, limits: LiteralAnchorAggregateBuildLimits) -> Self {
        self.anchor_limits = limits;
        self
    }

    /// Bind target capabilities. The candidate route itself is portable K0;
    /// the target applies to its common sparse fallback.
    #[must_use]
    pub const fn target(mut self, target: PriorityTarget) -> Self {
        self.target = target;
        self
    }

    /// Build an explicit complete Count reducer.
    pub fn build_count(
        self,
    ) -> Result<LiteralAnchorAggregateCountRegex, LiteralAnchorAggregateBuildError> {
        let common = PriorityAggregateBuilder::new(self.pattern.clone())
            .profile(self.profile.clone())
            .limits(self.priority_limits)
            .build_count(ForcedExecution::Sparse, self.target)
            .map_err(LiteralAnchorAggregateBuildError::Common)?;
        let candidate = build_candidate(
            &self.pattern,
            &self.profile,
            &self.priority_limits,
            self.anchor_limits,
            PriorityAggregateOperation::Count,
        )?;
        Ok(match candidate {
            CandidateBuild::Admitted(plan, candidate_report) => LiteralAnchorAggregateCountRegex {
                plan: LiteralAnchorCountPlan::Candidate { plan, common },
                report: LiteralAnchorAggregateBuildReport {
                    schema_version: LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION,
                    accounting_id: LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID,
                    operation: PriorityAggregateOperation::Count,
                    route: LiteralAnchorAggregateRoute::ByteCandidate,
                    candidate: Some(candidate_report),
                },
            },
            CandidateBuild::Fallback(reason) => LiteralAnchorAggregateCountRegex {
                plan: LiteralAnchorCountPlan::Common { common },
                report: LiteralAnchorAggregateBuildReport {
                    schema_version: LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION,
                    accounting_id: LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID,
                    operation: PriorityAggregateOperation::Count,
                    route: LiteralAnchorAggregateRoute::CommonSparse(reason),
                    candidate: None,
                },
            },
        })
    }

    /// Build an explicit complete matched-byte-sum reducer.
    pub fn build_span_sum(
        self,
    ) -> Result<LiteralAnchorAggregateSpanSumRegex, LiteralAnchorAggregateBuildError> {
        let common = PriorityAggregateBuilder::new(self.pattern.clone())
            .profile(self.profile.clone())
            .limits(self.priority_limits)
            .build_span_sum(ForcedExecution::Sparse, self.target)
            .map_err(LiteralAnchorAggregateBuildError::Common)?;
        let candidate = build_candidate(
            &self.pattern,
            &self.profile,
            &self.priority_limits,
            self.anchor_limits,
            PriorityAggregateOperation::SpanSum,
        )?;
        Ok(match candidate {
            CandidateBuild::Admitted(plan, candidate_report) => {
                LiteralAnchorAggregateSpanSumRegex {
                    plan: LiteralAnchorSpanSumPlan::Candidate { plan, common },
                    report: LiteralAnchorAggregateBuildReport {
                        schema_version: LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION,
                        accounting_id: LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID,
                        operation: PriorityAggregateOperation::SpanSum,
                        route: LiteralAnchorAggregateRoute::ByteCandidate,
                        candidate: Some(candidate_report),
                    },
                }
            }
            CandidateBuild::Fallback(reason) => LiteralAnchorAggregateSpanSumRegex {
                plan: LiteralAnchorSpanSumPlan::Common { common },
                report: LiteralAnchorAggregateBuildReport {
                    schema_version: LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION,
                    accounting_id: LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID,
                    operation: PriorityAggregateOperation::SpanSum,
                    route: LiteralAnchorAggregateRoute::CommonSparse(reason),
                    candidate: None,
                },
            },
        })
    }
}

/// Candidate-run P/A receipt. The primitive stream authenticates its own
/// scan receipt; verifier totals include the one pre-source workspace setup
/// plus calls actually made on recovered starts, and the same original
/// haystack is used for assertion context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralAnchorCandidateExecutionReceipt {
    operation: PriorityAggregateOperation,
    scan: ByteCandidateScanReceipt,
    pending_bytes: usize,
    pending_allocation_attempts: usize,
    verifier_logical_scratch_bytes: usize,
    verifier_scratch_bytes: usize,
    verifier_scratch_limit: usize,
    total_scratch_bytes: usize,
    total_scratch_limit: usize,
    recovery_work_upper_bound: u64,
    recovery_work: u64,
    reorder_work_upper_bound: u64,
    reorder_work: u64,
    recovered_candidates: usize,
    reducer_work_upper_bound: u64,
    reducer_work: u64,
    verifier_calls_upper_bound: usize,
    verifier_calls: usize,
    verifier_per_call_work_upper_bound: u64,
    verifier_work_upper_bound: u64,
    verifier_work: u64,
    verifier_setup_work: u64,
    verifier_setup_allocated_bytes: usize,
    verifier_setup_initialized_bytes: usize,
    verifier_invocation_setup_work: u64,
    verifier_transition_work: u64,
    verifier_scratch_clear_bytes_upper_bound: usize,
    verifier_scratch_clear_bytes: usize,
    verifier_boundaries_upper_bound: usize,
    verifier_boundaries: usize,
    total_work_upper_bound: u64,
    total_work: u64,
    selected_matches: usize,
    selected_span_bytes: u64,
    value: u64,
}

impl LiteralAnchorCandidateExecutionReceipt {
    #[must_use]
    pub const fn scan(&self) -> ByteCandidateScanReceipt {
        self.scan
    }

    #[must_use]
    pub const fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Exact allocation attempts for the fixed-capacity pending queue.
    #[must_use]
    pub const fn pending_allocation_attempts(&self) -> usize {
        self.pending_allocation_attempts
    }

    /// Exact logical workspace payload admitted before allocator capacity
    /// rounding; this is the input to the verifier scratch gate.
    #[must_use]
    pub const fn verifier_logical_scratch_bytes(&self) -> usize {
        self.verifier_logical_scratch_bytes
    }

    /// Reused K0 workspace payload allocated before source access.
    #[must_use]
    pub const fn verifier_scratch_bytes(&self) -> usize {
        self.verifier_scratch_bytes
    }

    /// Caller limit which bound the actual retained K0 workspace payload.
    #[must_use]
    pub const fn verifier_scratch_limit(&self) -> usize {
        self.verifier_scratch_limit
    }

    /// Exact queue plus retained K0 workspace payload for this operation.
    #[must_use]
    pub const fn total_scratch_bytes(&self) -> usize {
        self.total_scratch_bytes
    }

    /// Caller limit which bounded the combined queue and K0 workspace.
    #[must_use]
    pub const fn total_scratch_limit(&self) -> usize {
        self.total_scratch_limit
    }

    /// Fixed bridge work for primitive-event anchor recovery attempts.
    #[must_use]
    pub const fn recovery_work(&self) -> u64 {
        self.recovery_work
    }

    #[must_use]
    pub const fn recovery_work_upper_bound(&self) -> u64 {
        self.recovery_work_upper_bound
    }

    #[must_use]
    pub const fn reorder_work_upper_bound(&self) -> u64 {
        self.reorder_work_upper_bound
    }

    #[must_use]
    pub const fn reorder_work(&self) -> u64 {
        self.reorder_work
    }

    /// Number of anchor recoveries which survived boundary validation.
    #[must_use]
    pub const fn recovered_candidates(&self) -> usize {
        self.recovered_candidates
    }

    /// Grouping and monotone-reduction work after candidate ordering.
    #[must_use]
    pub const fn reducer_work(&self) -> u64 {
        self.reducer_work
    }

    #[must_use]
    pub const fn reducer_work_upper_bound(&self) -> u64 {
        self.reducer_work_upper_bound
    }

    #[must_use]
    pub const fn verifier_calls(&self) -> usize {
        self.verifier_calls
    }

    #[must_use]
    pub const fn verifier_calls_upper_bound(&self) -> usize {
        self.verifier_calls_upper_bound
    }

    /// Conservative reusable K0 work bound for one recovered start.
    #[must_use]
    pub const fn verifier_per_call_work_upper_bound(&self) -> u64 {
        self.verifier_per_call_work_upper_bound
    }

    #[must_use]
    pub const fn verifier_work(&self) -> u64 {
        self.verifier_work
    }

    #[must_use]
    pub const fn verifier_work_upper_bound(&self) -> u64 {
        self.verifier_work_upper_bound
    }

    /// One-time K0 workspace construction work charged before source access.
    #[must_use]
    pub const fn verifier_setup_work(&self) -> u64 {
        self.verifier_setup_work
    }

    /// Workspace payload retained by the pre-source K0 construction.
    #[must_use]
    pub const fn verifier_setup_allocated_bytes(&self) -> usize {
        self.verifier_setup_allocated_bytes
    }

    /// Workspace payload initialized during pre-source K0 construction.
    #[must_use]
    pub const fn verifier_setup_initialized_bytes(&self) -> usize {
        self.verifier_setup_initialized_bytes
    }

    /// Reused K0 setup work accumulated across verifier invocations.
    #[must_use]
    pub const fn verifier_invocation_setup_work(&self) -> u64 {
        self.verifier_invocation_setup_work
    }

    /// K0 state/edge transition work accumulated across verifier invocations.
    #[must_use]
    pub const fn verifier_transition_work(&self) -> u64 {
        self.verifier_transition_work
    }

    /// Actual workspace bytes logically cleared by reused verifier calls.
    #[must_use]
    pub const fn verifier_scratch_clear_bytes(&self) -> usize {
        self.verifier_scratch_clear_bytes
    }

    #[must_use]
    pub const fn verifier_boundaries(&self) -> usize {
        self.verifier_boundaries
    }

    #[must_use]
    pub const fn verifier_boundaries_upper_bound(&self) -> usize {
        self.verifier_boundaries_upper_bound
    }

    #[must_use]
    pub const fn total_work(&self) -> u64 {
        self.total_work
    }

    #[must_use]
    pub const fn total_work_upper_bound(&self) -> u64 {
        self.total_work_upper_bound
    }

    #[must_use]
    pub const fn selected_matches(&self) -> usize {
        self.selected_matches
    }

    #[must_use]
    pub const fn selected_span_bytes(&self) -> u64 {
        self.selected_span_bytes
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Check every counter against the source-length-only envelope admitted
    /// before the candidate stream inspected the haystack.
    #[must_use]
    pub fn closes(&self) -> bool {
        let scan_actual = self.scan.actual;
        let scan_upper = self.scan.upper;
        let value_closes = match self.operation {
            PriorityAggregateOperation::Count => {
                u64::try_from(self.selected_matches) == Ok(self.value)
            }
            PriorityAggregateOperation::SpanSum => {
                self.value == self.selected_span_bytes
                    && u64::try_from(scan_actual.input_bytes)
                        .is_ok_and(|input_bytes| self.selected_span_bytes <= input_bytes)
            }
        };
        let pending_bytes = scan_upper
            .candidate_events
            .checked_mul(size_of::<PendingCandidate>());
        let recovery_work = usize_to_u64(scan_actual.candidate_events)
            .and_then(|events| events.checked_mul(CANDIDATE_RECOVERY_WORK_PER_EVENT));
        let reducer_work = usize_to_u64(self.recovered_candidates)
            .and_then(|events| events.checked_mul(CANDIDATE_REDUCER_WORK_PER_RECOVERED));
        let total_work = usize_to_u64(scan_actual.work)
            .and_then(|work| work.checked_add(self.recovery_work))
            .and_then(|work| work.checked_add(self.reorder_work))
            .and_then(|work| work.checked_add(self.reducer_work))
            .and_then(|work| work.checked_add(self.verifier_work));
        let verifier_work = self
            .verifier_setup_work
            .checked_add(self.verifier_invocation_setup_work)
            .and_then(|work| work.checked_add(self.verifier_transition_work));
        let selected_span_within_input = u64::try_from(scan_actual.input_bytes)
            .is_ok_and(|input_bytes| self.selected_span_bytes <= input_bytes);
        scan_actual.input_bytes == scan_upper.input_bytes
            && scan_actual.candidate_starts <= scan_upper.candidate_starts
            && scan_actual.source_byte_reads <= scan_upper.source_byte_reads
            && scan_actual.transition_probes <= scan_upper.transition_probes
            && scan_actual.candidate_events <= scan_upper.candidate_events
            && scan_actual.work <= scan_upper.work
            && scan_actual.scratch_bytes <= scan_upper.scratch_bytes
            && self.pending_bytes.checked_add(self.verifier_scratch_bytes)
                == Some(self.total_scratch_bytes)
            && pending_bytes == Some(self.pending_bytes)
            && self.pending_allocation_attempts == usize::from(self.pending_bytes != 0)
            && self.verifier_scratch_bytes <= self.verifier_scratch_limit
            && self.total_scratch_bytes <= self.total_scratch_limit
            && recovery_work == Some(self.recovery_work)
            && self.recovery_work <= self.recovery_work_upper_bound
            && self.reorder_work <= self.reorder_work_upper_bound
            && self.recovered_candidates <= scan_actual.candidate_events
            && self.selected_matches <= self.verifier_calls
            && self.verifier_calls <= self.recovered_candidates
            && reducer_work == Some(self.reducer_work)
            && self.reducer_work <= self.reducer_work_upper_bound
            && self.verifier_calls <= self.verifier_calls_upper_bound
            && self.verifier_work <= self.verifier_work_upper_bound
            && verifier_work == Some(self.verifier_work)
            && self.verifier_setup_allocated_bytes == self.verifier_scratch_bytes
            && self.verifier_setup_initialized_bytes == self.verifier_logical_scratch_bytes
            && self.verifier_logical_scratch_bytes <= self.verifier_scratch_bytes
            && self.verifier_scratch_clear_bytes <= self.verifier_scratch_clear_bytes_upper_bound
            && self.verifier_boundaries <= self.verifier_boundaries_upper_bound
            && total_work == Some(self.total_work)
            && self.total_work <= self.total_work_upper_bound
            && selected_span_within_input
            && value_closes
    }

    fn closes_with(&self, limits: LiteralAnchorAggregateRunLimits) -> bool {
        let upper = self.scan.upper;
        let effective_workspace_limit = limits
            .max_total_scratch_bytes
            .saturating_sub(self.pending_bytes)
            .min(limits.verifier.max_scratch_bytes);
        self.closes()
            && upper.input_bytes <= limits.candidate_scan.max_input_bytes
            && upper.candidate_starts <= limits.candidate_scan.max_candidate_starts
            && upper.source_byte_reads <= limits.candidate_scan.max_source_byte_reads
            && upper.transition_probes <= limits.candidate_scan.max_transition_probes
            && upper.candidate_events <= limits.candidate_scan.max_candidate_events
            && upper.work <= limits.candidate_scan.max_work
            && upper.scratch_bytes <= limits.candidate_scan.max_scratch_bytes
            && upper.candidate_events <= limits.max_candidate_events
            && self.pending_bytes <= limits.max_pending_bytes
            && self.verifier_logical_scratch_bytes <= limits.verifier.max_scratch_bytes
            && self.verifier_scratch_bytes <= limits.verifier.max_scratch_bytes
            && self.total_scratch_bytes <= limits.max_total_scratch_bytes
            && self.verifier_scratch_limit == effective_workspace_limit
            && self.total_scratch_limit == limits.max_total_scratch_bytes
            && self.reorder_work_upper_bound <= limits.max_reorder_work
            && self.verifier_calls_upper_bound <= limits.max_verifier_calls
            && self.verifier_per_call_work_upper_bound <= limits.verifier.max_work
            && self.verifier_work_upper_bound <= limits.max_verifier_work
            && self.total_work_upper_bound <= limits.max_total_work
            && self.value <= limits.max_output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LiteralAnchorAggregateExecutionAuthentication {
    schema_version: u32,
    accounting_id: &'static str,
    build: LiteralAnchorAggregateBuildReport,
    limits: LiteralAnchorAggregateRunLimits,
    operation: PriorityAggregateOperation,
    route: LiteralAnchorAggregateRoute,
    value: u64,
    candidate: Option<LiteralAnchorCandidateExecutionReceipt>,
    common: Option<PriorityAggregateExecutionReceipt>,
}

/// Successful result for either the candidate or common route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralAnchorAggregateExecutionReceipt {
    schema_version: u32,
    accounting_id: &'static str,
    build: LiteralAnchorAggregateBuildReport,
    limits: LiteralAnchorAggregateRunLimits,
    operation: PriorityAggregateOperation,
    route: LiteralAnchorAggregateRoute,
    value: u64,
    candidate: Option<LiteralAnchorCandidateExecutionReceipt>,
    common: Option<PriorityAggregateExecutionReceipt>,
    authentication: LiteralAnchorAggregateExecutionAuthentication,
}

impl LiteralAnchorAggregateExecutionAuthentication {
    fn authenticates(&self, receipt: &LiteralAnchorAggregateExecutionReceipt) -> bool {
        self.schema_version == receipt.schema_version
            && self.accounting_id == receipt.accounting_id
            && self.build == receipt.build
            && self.limits == receipt.limits
            && self.operation == receipt.operation
            && self.route == receipt.route
            && self.value == receipt.value
            && self.candidate == receipt.candidate
            && self.common == receipt.common
    }
}

impl LiteralAnchorAggregateExecutionReceipt {
    #[must_use]
    pub const fn operation(&self) -> PriorityAggregateOperation {
        self.operation
    }

    /// Immutable HIR/candidate or common-route construction attribution.
    #[must_use]
    pub const fn build_report(&self) -> LiteralAnchorAggregateBuildReport {
        self.build
    }

    /// Exact run limits admitted for this completed operation.
    #[must_use]
    pub const fn limits(&self) -> LiteralAnchorAggregateRunLimits {
        self.limits
    }

    #[must_use]
    pub const fn route(&self) -> LiteralAnchorAggregateRoute {
        self.route
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn candidate(&self) -> Option<&LiteralAnchorCandidateExecutionReceipt> {
        self.candidate.as_ref()
    }

    #[must_use]
    pub const fn common(&self) -> Option<&PriorityAggregateExecutionReceipt> {
        self.common.as_ref()
    }

    #[must_use]
    pub fn closes(&self) -> bool {
        let authentication_closes = self.authentication.authenticates(self);
        let build_route_closes = match (self.build.route(), self.route) {
            (
                LiteralAnchorAggregateRoute::ByteCandidate,
                LiteralAnchorAggregateRoute::ByteCandidate
                | LiteralAnchorAggregateRoute::CommonSparse(_),
            ) => true,
            (
                LiteralAnchorAggregateRoute::CommonSparse(build_reason),
                LiteralAnchorAggregateRoute::CommonSparse(run_reason),
            ) => build_reason == run_reason,
            _ => false,
        };
        let route_closes = match (&self.route, &self.candidate, &self.common) {
            (LiteralAnchorAggregateRoute::ByteCandidate, Some(candidate), None) => {
                candidate.operation == self.operation
                    && candidate.closes_with(self.limits)
                    && candidate.value() == self.value
            }
            (LiteralAnchorAggregateRoute::CommonSparse(_), None, Some(common)) => {
                common.closes()
                    && common.value() == self.value
                    && common.operation() == self.operation
                    && common.execution() == ForcedExecution::Sparse
            }
            _ => false,
        };
        self.schema_version == LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION
            && self.accounting_id == LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID
            && self.build.closes()
            && self.build.operation() == self.operation
            && build_route_closes
            && self.value <= self.limits.max_output
            && authentication_closes
            && route_closes
    }
}

fn finish_execution_receipt(
    build: LiteralAnchorAggregateBuildReport,
    limits: LiteralAnchorAggregateRunLimits,
    operation: PriorityAggregateOperation,
    route: LiteralAnchorAggregateRoute,
    value: u64,
    candidate: Option<LiteralAnchorCandidateExecutionReceipt>,
    common: Option<PriorityAggregateExecutionReceipt>,
) -> Result<LiteralAnchorAggregateExecutionReceipt, LiteralAnchorAggregateRunError> {
    let authentication = LiteralAnchorAggregateExecutionAuthentication {
        schema_version: LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION,
        accounting_id: LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID,
        build,
        limits,
        operation,
        route,
        value,
        candidate: candidate.clone(),
        common: common.clone(),
    };
    let receipt = LiteralAnchorAggregateExecutionReceipt {
        schema_version: LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION,
        accounting_id: LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID,
        build,
        limits,
        operation,
        route,
        value,
        candidate,
        common,
        authentication,
    };
    if !receipt.closes() {
        return Err(LiteralAnchorAggregateRunError::ReceiptNotClosed);
    }
    Ok(receipt)
}

/// Candidate execution failed after the candidate route had begun consuming
/// source. The facade never silently changes to another route in this state.
#[derive(Debug)]
#[non_exhaustive]
pub enum LiteralAnchorAggregateRunError {
    Common(PriorityAggregateRunError),
    CandidateScan(ByteCandidateScanAttemptError),
    CandidateRecoveryInvariant,
    CandidateQueueAllocation(CopyError),
    CandidateQueueOverflow,
    CandidateArithmeticOverflow { computation: &'static str },
    Verifier(SearchError),
    OutputLimit { needed: u64, limit: u64 },
    ReceiptNotClosed,
}

impl fmt::Display for LiteralAnchorAggregateRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Common(error) => write!(formatter, "common sparse execution: {error}"),
            Self::CandidateScan(error) => write!(formatter, "literal candidate scan: {error}"),
            Self::CandidateRecoveryInvariant => {
                formatter.write_str("literal candidate violated its retained anchor proof")
            }
            Self::CandidateQueueAllocation(error) => {
                write!(formatter, "literal candidate queue allocation: {error}")
            }
            Self::CandidateQueueOverflow => {
                formatter.write_str("literal candidate queue exceeded its admitted exact capacity")
            }
            Self::CandidateArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "literal candidate arithmetic overflow while computing {computation}"
                )
            }
            Self::Verifier(error) => {
                write!(formatter, "literal candidate semantic verifier: {error}")
            }
            Self::OutputLimit { needed, limit } => {
                write!(
                    formatter,
                    "literal-anchor output needs {needed}, limit is {limit}"
                )
            }
            Self::ReceiptNotClosed => {
                formatter.write_str("literal-anchor execution receipt did not close")
            }
        }
    }
}

impl std::error::Error for LiteralAnchorAggregateRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Common(error) => Some(error),
            Self::CandidateScan(error) => Some(error),
            Self::CandidateQueueAllocation(error) => Some(error),
            Self::Verifier(error) => Some(error),
            Self::CandidateRecoveryInvariant
            | Self::CandidateQueueOverflow
            | Self::CandidateArithmeticOverflow { .. }
            | Self::OutputLimit { .. }
            | Self::ReceiptNotClosed => None,
        }
    }
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the common receipt-bearing plan would add a construction allocation outside its existing exact priority ledger"
)]
enum LiteralAnchorCountPlan {
    Candidate {
        plan: CandidatePlan,
        common: PriorityAggregateCountRegex,
    },
    Common {
        common: PriorityAggregateCountRegex,
    },
}

/// Explicit Count artifact. It is never considered by the automatic
/// aggregate planner.
#[derive(Debug)]
pub struct LiteralAnchorAggregateCountRegex {
    plan: LiteralAnchorCountPlan,
    report: LiteralAnchorAggregateBuildReport,
}

impl LiteralAnchorAggregateCountRegex {
    #[must_use]
    pub const fn build_report(&self) -> &LiteralAnchorAggregateBuildReport {
        &self.report
    }

    /// Execute the construction-fixed candidate route, or the common sparse
    /// route selected before source access.
    pub fn count(
        &self,
        haystack: &[u8],
        limits: LiteralAnchorAggregateRunLimits,
    ) -> Result<LiteralAnchorAggregateExecutionReceipt, LiteralAnchorAggregateRunError> {
        match &self.plan {
            LiteralAnchorCountPlan::Candidate { plan, common } => execute_candidate_or_common(
                plan,
                common,
                haystack,
                limits,
                self.report,
                PriorityAggregateOperation::Count,
                PriorityAggregateCountRegex::count,
            ),
            LiteralAnchorCountPlan::Common { common } => execute_common(
                common,
                haystack,
                limits,
                self.report,
                PriorityAggregateOperation::Count,
                self.report.route(),
                PriorityAggregateCountRegex::count,
            ),
        }
    }
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the common receipt-bearing plan would add a construction allocation outside its existing exact priority ledger"
)]
enum LiteralAnchorSpanSumPlan {
    Candidate {
        plan: CandidatePlan,
        common: PriorityAggregateSpanSumRegex,
    },
    Common {
        common: PriorityAggregateSpanSumRegex,
    },
}

/// Explicit matched-byte-sum artifact. It is never considered by the
/// automatic aggregate planner.
#[derive(Debug)]
pub struct LiteralAnchorAggregateSpanSumRegex {
    plan: LiteralAnchorSpanSumPlan,
    report: LiteralAnchorAggregateBuildReport,
}

impl LiteralAnchorAggregateSpanSumRegex {
    #[must_use]
    pub const fn build_report(&self) -> &LiteralAnchorAggregateBuildReport {
        &self.report
    }

    /// Execute the construction-fixed candidate route, or the common sparse
    /// route selected before source access.
    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: LiteralAnchorAggregateRunLimits,
    ) -> Result<LiteralAnchorAggregateExecutionReceipt, LiteralAnchorAggregateRunError> {
        match &self.plan {
            LiteralAnchorSpanSumPlan::Candidate { plan, common } => execute_candidate_or_common(
                plan,
                common,
                haystack,
                limits,
                self.report,
                PriorityAggregateOperation::SpanSum,
                PriorityAggregateSpanSumRegex::span_sum,
            ),
            LiteralAnchorSpanSumPlan::Common { common } => execute_common(
                common,
                haystack,
                limits,
                self.report,
                PriorityAggregateOperation::SpanSum,
                self.report.route(),
                PriorityAggregateSpanSumRegex::span_sum,
            ),
        }
    }
}

#[derive(Debug)]
struct CandidatePlan {
    stream: ByteCandidatePlan,
    anchors: ExactVec<LiteralAnchor>,
    automaton: Automaton,
    maximum_verifier_window_bytes: usize,
}

#[allow(
    clippy::large_enum_variant,
    reason = "candidate construction retains its immutable automaton and exact primitive allocation instead of adding an unaccounted box"
)]
enum CandidateBuild {
    Admitted(CandidatePlan, LiteralAnchorCandidateBuildReport),
    Fallback(LiteralAnchorFallbackReason),
}

#[derive(Clone, Copy)]
struct GroupShape {
    maximum_verifier_window_bytes: usize,
    shortest_literal_bytes: usize,
    total_literal_bytes: usize,
    has_unicode_scalar: bool,
}

#[allow(
    clippy::too_many_lines,
    reason = "candidate proof selection keeps parse, HIR facts, literal construction, and lowering in one auditable prepublication transaction"
)]
fn build_candidate(
    pattern: &str,
    profile: &RustProfile,
    priority_limits: &PriorityAggregateBuildLimits,
    anchor_limits: LiteralAnchorAggregateBuildLimits,
    operation: PriorityAggregateOperation,
) -> Result<CandidateBuild, LiteralAnchorAggregateBuildError> {
    let mut request = ParseRequest::rust(
        pattern.to_owned(),
        CompatibilityProfile::RustBytes(profile.clone()),
    )
    .with_admission(priority_limits.admission)
    .with_safety_envelope(priority_limits.syntax_safety);
    let _ = request.bind_attempt_source_owner();
    let attempt =
        fre_syntax::parse_attempt(request).map_err(LiteralAnchorAggregateBuildError::Syntax)?;
    let (record, _) = attempt.into_parts();
    let CanonicalPattern::Rust(rust) = record.pattern else {
        return Err(LiteralAnchorAggregateBuildError::NonRustCanonicalPattern);
    };
    let facts = analyze_facts(&rust, fact_operation(operation), priority_limits.facts)
        .map_err(LiteralAnchorAggregateBuildError::Facts)?;
    if !facts.captures().erasure_permitted() {
        return Err(LiteralAnchorAggregateBuildError::CaptureErasureNotProven);
    }
    let Some(group) = select_group(&facts, anchor_limits) else {
        return Ok(CandidateBuild::Fallback(fallback_for_facts(&facts)));
    };
    if group.1.has_unicode_scalar && facts.unicode().simple_fold_origin().as_proven().is_none() {
        return Ok(CandidateBuild::Fallback(
            LiteralAnchorFallbackReason::UnicodeFoldProvenanceUnavailable,
        ));
    }
    let (selected, shape) = group;
    let anchor_bytes = selected
        .alternatives()
        .len()
        .checked_mul(size_of::<LiteralAnchor>())
        .ok_or(LiteralAnchorAggregateBuildError::Facts(
            FactError::ArithmeticOverflow {
                computation: "literal-anchor metadata bytes",
            },
        ))?;
    if anchor_bytes > anchor_limits.max_anchor_metadata_bytes {
        return Ok(CandidateBuild::Fallback(
            LiteralAnchorFallbackReason::CandidateConstructionUnavailable,
        ));
    }
    let Ok(mut patterns) = ExactVec::try_with_capacity(selected.alternatives().len()) else {
        return Ok(CandidateBuild::Fallback(
            LiteralAnchorFallbackReason::CandidateConstructionUnavailable,
        ));
    };
    let Ok(mut anchors) = ExactVec::try_with_capacity(selected.alternatives().len()) else {
        return Ok(CandidateBuild::Fallback(
            LiteralAnchorFallbackReason::CandidateConstructionUnavailable,
        ));
    };
    for (index, required) in selected.alternatives().iter().enumerate() {
        let context = required.context();
        let before = context.before();
        let after = context.after();
        let Some(before_maximum) = before.maximum() else {
            return Ok(CandidateBuild::Fallback(
                LiteralAnchorFallbackReason::BoundedAnchorProofUnavailable,
            ));
        };
        let Some(after_maximum) = after.maximum() else {
            return Ok(CandidateBuild::Fallback(
                LiteralAnchorFallbackReason::BoundedAnchorProofUnavailable,
            ));
        };
        let Ok(before) = LiteralAnchorOffsetBounds::new(before.minimum(), before_maximum) else {
            return Err(LiteralAnchorAggregateBuildError::Facts(
                FactError::InternalInvariant {
                    detail: "canonical required-anchor prefix bounds were inverted",
                },
            ));
        };
        let Ok(after) = LiteralAnchorOffsetBounds::new(after.minimum(), after_maximum) else {
            return Err(LiteralAnchorAggregateBuildError::Facts(
                FactError::InternalInvariant {
                    detail: "canonical required-anchor suffix bounds were inverted",
                },
            ));
        };
        patterns.try_push(required.bytes()).map_err(|_| {
            LiteralAnchorAggregateBuildError::Facts(FactError::InternalInvariant {
                detail: "literal-anchor pattern census diverged before primitive construction",
            })
        })?;
        anchors
            .try_push(LiteralAnchor::new(index, before, after))
            .map_err(|_| {
                LiteralAnchorAggregateBuildError::Facts(FactError::InternalInvariant {
                    detail: "literal-anchor mapping census diverged before primitive construction",
                })
            })?;
    }
    let stream = match ByteCandidatePlan::build(patterns.as_slice(), anchor_limits.candidate) {
        Ok(ByteCandidateBuildAttempt::Admitted(stream)) => stream,
        Ok(ByteCandidateBuildAttempt::DenseFallback(_)) | Err(_) => {
            return Ok(CandidateBuild::Fallback(
                LiteralAnchorFallbackReason::CandidateConstructionUnavailable,
            ));
        }
    };
    let lowered = lower_raw(
        &rust,
        OperationSemantics::CaptureFree,
        priority_limits.lowering,
    )
    .map_err(LiteralAnchorAggregateBuildError::Lower)?;
    let automaton = Automaton::from_raw(lowered.into_plan(), priority_limits.lowering.automata)
        .map_err(LiteralAnchorAggregateBuildError::Automaton)?
        .with_line_terminator(profile.options.line_terminator);
    let report = LiteralAnchorCandidateBuildReport {
        anchor_count: anchors.len(),
        anchor_metadata_bytes: anchor_bytes,
        maximum_verifier_window_bytes: shape.maximum_verifier_window_bytes,
        byte_candidate: stream.build_accounting(),
    };
    Ok(CandidateBuild::Admitted(
        CandidatePlan {
            stream,
            anchors,
            automaton,
            maximum_verifier_window_bytes: shape.maximum_verifier_window_bytes,
        },
        report,
    ))
}

fn fact_operation(operation: PriorityAggregateOperation) -> FactOperation {
    FactOperation::new(match operation {
        PriorityAggregateOperation::Count => FactOutput::Count,
        PriorityAggregateOperation::SpanSum => FactOutput::SpanSum,
    })
}

fn fallback_for_facts(facts: &HirFacts) -> LiteralAnchorFallbackReason {
    match facts.required() {
        FactProof::Proven(_) => LiteralAnchorFallbackReason::BoundedAnchorProofUnavailable,
        FactProof::Unknown | FactProof::Refused(_) => {
            LiteralAnchorFallbackReason::RequiredProofUnavailable
        }
    }
}

fn select_group(
    facts: &HirFacts,
    limits: LiteralAnchorAggregateBuildLimits,
) -> Option<(&fre_lower::RequiredAlternatives, GroupShape)> {
    let groups = facts.required().as_proven()?;
    let mut selected = None;
    for group in groups {
        let Some(shape) = group_shape(group, limits) else {
            continue;
        };
        let replace = match selected {
            None => true,
            Some((_, current)) => group_score(shape) > group_score(current),
        };
        if replace {
            selected = Some((group, shape));
        }
    }
    selected
}

fn group_shape(
    group: &fre_lower::RequiredAlternatives,
    limits: LiteralAnchorAggregateBuildLimits,
) -> Option<GroupShape> {
    let alternatives = group.alternatives();
    if alternatives.is_empty() || alternatives.len() > limits.max_anchors {
        return None;
    }
    let mut maximum_verifier_window_bytes = 0usize;
    let mut shortest_literal_bytes = usize::MAX;
    let mut total_literal_bytes = 0usize;
    let mut has_unicode_scalar = false;
    for required in alternatives {
        let bytes = required.bytes();
        if bytes.is_empty() {
            return None;
        }
        let context = required.context();
        let before = context.before();
        let after = context.after();
        if !before.is_exact() {
            return None;
        }
        let after_maximum = after.maximum()?;
        let window = before
            .minimum()
            .checked_add(bytes.len())?
            .checked_add(after_maximum)?;
        maximum_verifier_window_bytes = maximum_verifier_window_bytes.max(window);
        shortest_literal_bytes = shortest_literal_bytes.min(bytes.len());
        total_literal_bytes = total_literal_bytes.checked_add(bytes.len())?;
        has_unicode_scalar |= matches!(required.encoding(), StringEncoding::UnicodeScalar);
    }
    if maximum_verifier_window_bytes > limits.max_verifier_window_bytes {
        return None;
    }
    Some(GroupShape {
        maximum_verifier_window_bytes,
        shortest_literal_bytes,
        total_literal_bytes,
        has_unicode_scalar,
    })
}

fn group_score(shape: GroupShape) -> (usize, core::cmp::Reverse<usize>, core::cmp::Reverse<usize>) {
    (
        shape.shortest_literal_bytes,
        core::cmp::Reverse(shape.maximum_verifier_window_bytes),
        core::cmp::Reverse(shape.total_literal_bytes),
    )
}

#[derive(Clone, Copy, Debug)]
struct PendingCandidate {
    candidate: LiteralCandidate,
    recovery: LiteralAnchorRecovery,
    recovered_start: usize,
}

#[derive(Clone, Copy)]
struct CandidateAdmission {
    scan_upper: ByteCandidateScanUpperBounds,
    pending_bytes: usize,
    verifier_logical_scratch_bytes: usize,
    recovery_work_upper_bound: u64,
    reorder_work_upper_bound: u64,
    reducer_work_upper_bound: u64,
    verifier_calls_upper_bound: usize,
    verifier_per_call_work_upper_bound: u64,
    verifier_work_upper_bound: u64,
    verifier_scratch_clear_bytes_upper_bound: usize,
    verifier_boundaries_upper_bound: usize,
    total_work_upper_bound: u64,
}

enum CandidateDisposition {
    Admit(CandidateAdmission),
    Common(LiteralAnchorFallbackReason),
}

fn execute_candidate_or_common<C, F>(
    candidate: &CandidatePlan,
    common: &C,
    haystack: &[u8],
    limits: LiteralAnchorAggregateRunLimits,
    build: LiteralAnchorAggregateBuildReport,
    operation: PriorityAggregateOperation,
    common_run: F,
) -> Result<LiteralAnchorAggregateExecutionReceipt, LiteralAnchorAggregateRunError>
where
    F: FnOnce(
        &C,
        &[u8],
        PriorityAggregateRunLimits,
    ) -> Result<PriorityAggregateExecutionReceipt, PriorityAggregateRunError>,
{
    match candidate_admission(candidate, haystack.len(), operation, limits) {
        CandidateDisposition::Admit(admission) => {
            execute_candidate(candidate, haystack, limits, build, operation, admission)
        }
        CandidateDisposition::Common(reason) => execute_common(
            common,
            haystack,
            limits,
            build,
            operation,
            LiteralAnchorAggregateRoute::CommonSparse(reason),
            common_run,
        ),
    }
}

fn execute_common<C, F>(
    common: &C,
    haystack: &[u8],
    mut limits: LiteralAnchorAggregateRunLimits,
    build: LiteralAnchorAggregateBuildReport,
    operation: PriorityAggregateOperation,
    route: LiteralAnchorAggregateRoute,
    common_run: F,
) -> Result<LiteralAnchorAggregateExecutionReceipt, LiteralAnchorAggregateRunError>
where
    F: FnOnce(
        &C,
        &[u8],
        PriorityAggregateRunLimits,
    ) -> Result<PriorityAggregateExecutionReceipt, PriorityAggregateRunError>,
{
    limits.common.max_output = limits.max_output;
    let common = common_run(common, haystack, limits.common)
        .map_err(LiteralAnchorAggregateRunError::Common)?;
    finish_execution_receipt(
        build,
        limits,
        operation,
        route,
        common.value(),
        None,
        Some(common),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the source-independent admission proof keeps every exact candidate, scratch, and verifier gate in one auditable transaction"
)]
fn candidate_admission(
    plan: &CandidatePlan,
    input_bytes: usize,
    operation: PriorityAggregateOperation,
    limits: LiteralAnchorAggregateRunLimits,
) -> CandidateDisposition {
    let Ok(scan_upper) = plan.stream.scan_upper_bounds(input_bytes) else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    if scan_exceeds_limits(scan_upper, limits.candidate_scan) {
        return CandidateDisposition::Common(LiteralAnchorFallbackReason::DenseOrProofLarge);
    }
    let Some(pending_bytes) = scan_upper
        .candidate_events
        .checked_mul(size_of::<PendingCandidate>())
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(reorder_work_upper_bound) = reorder_work_upper_bound(scan_upper.candidate_events)
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Ok(per_verifier_work) = plan
        .automaton
        .conservative_reused_work_bound(plan.maximum_verifier_window_bytes)
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Ok(workspace_layout) = plan.automaton.workspace_layout() else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(recovery_work_upper_bound) = usize_to_u64(scan_upper.candidate_events)
        .and_then(|events| events.checked_mul(CANDIDATE_RECOVERY_WORK_PER_EVENT))
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(reducer_work_upper_bound) = usize_to_u64(scan_upper.candidate_events)
        .and_then(|events| events.checked_mul(CANDIDATE_REDUCER_WORK_PER_RECOVERED))
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(verifier_boundaries_upper_bound) = plan
        .maximum_verifier_window_bytes
        .checked_add(1)
        .and_then(|boundaries| scan_upper.candidate_events.checked_mul(boundaries))
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(verifier_scratch_clear_bytes_upper_bound) = scan_upper
        .candidate_events
        .checked_mul(workspace_layout.logical_bytes())
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(total_scratch_bytes) = pending_bytes.checked_add(workspace_layout.logical_bytes())
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(verifier_call_work_upper_bound) = usize_to_u64(scan_upper.candidate_events)
        .and_then(|events| events.checked_mul(per_verifier_work))
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(verifier_work_upper_bound) = workspace_layout
        .construction_work()
        .checked_add(verifier_call_work_upper_bound)
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    let Some(total_work_upper_bound) = usize_to_u64(scan_upper.work)
        .and_then(|scan| scan.checked_add(recovery_work_upper_bound))
        .and_then(|scan| scan.checked_add(reorder_work_upper_bound))
        .and_then(|work| work.checked_add(reducer_work_upper_bound))
        .and_then(|work| work.checked_add(verifier_work_upper_bound))
    else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    // Keep the candidate public limit contract equal to the common reducer's
    // conservative whole-operation bound, even though an admitted nonempty
    // anchor could prove a tighter Count bound.
    let output_bound = match operation {
        PriorityAggregateOperation::Count => input_bytes.checked_add(1).and_then(usize_to_u64),
        PriorityAggregateOperation::SpanSum => usize_to_u64(input_bytes),
    };
    let Some(output_bound) = output_bound else {
        return CandidateDisposition::Common(
            LiteralAnchorFallbackReason::CandidateEnvelopeOverflow,
        );
    };
    if output_bound > limits.max_output
        || scan_upper.candidate_events > limits.max_candidate_events
        || pending_bytes > limits.max_pending_bytes
        || workspace_layout.logical_bytes() > limits.verifier.max_scratch_bytes
        || total_scratch_bytes > limits.max_total_scratch_bytes
        || reorder_work_upper_bound > limits.max_reorder_work
        || scan_upper.candidate_events > limits.max_verifier_calls
        || per_verifier_work > limits.verifier.max_work
        || verifier_work_upper_bound > limits.max_verifier_work
        || total_work_upper_bound > limits.max_total_work
    {
        return CandidateDisposition::Common(LiteralAnchorFallbackReason::DenseOrProofLarge);
    }
    CandidateDisposition::Admit(CandidateAdmission {
        scan_upper,
        pending_bytes,
        verifier_logical_scratch_bytes: workspace_layout.logical_bytes(),
        recovery_work_upper_bound,
        reorder_work_upper_bound,
        reducer_work_upper_bound,
        verifier_calls_upper_bound: scan_upper.candidate_events,
        verifier_per_call_work_upper_bound: per_verifier_work,
        verifier_work_upper_bound,
        verifier_scratch_clear_bytes_upper_bound,
        verifier_boundaries_upper_bound,
        total_work_upper_bound,
    })
}

fn scan_exceeds_limits(
    upper: ByteCandidateScanUpperBounds,
    limits: ByteCandidateScanLimits,
) -> bool {
    upper.input_bytes > limits.max_input_bytes
        || upper.candidate_starts > limits.max_candidate_starts
        || upper.source_byte_reads > limits.max_source_byte_reads
        || upper.transition_probes > limits.max_transition_probes
        || upper.candidate_events > limits.max_candidate_events
        || upper.work > limits.max_work
        || upper.scratch_bytes > limits.max_scratch_bytes
}

#[allow(
    clippy::too_many_lines,
    reason = "the hot operation keeps preflight, source scanning, ordered reduction, and terminal receipt closure in one allocation-auditable routine"
)]
fn execute_candidate(
    plan: &CandidatePlan,
    haystack: &[u8],
    limits: LiteralAnchorAggregateRunLimits,
    build: LiteralAnchorAggregateBuildReport,
    operation: PriorityAggregateOperation,
    admission: CandidateAdmission,
) -> Result<LiteralAnchorAggregateExecutionReceipt, LiteralAnchorAggregateRunError> {
    let mut pending = ExactVec::try_with_capacity(admission.scan_upper.candidate_events)
        .map_err(LiteralAnchorAggregateRunError::CandidateQueueAllocation)?;
    let workspace_scratch_limit = limits
        .max_total_scratch_bytes
        .saturating_sub(admission.pending_bytes)
        .min(limits.verifier.max_scratch_bytes);
    let workspace_limits = WorkspaceLimits {
        max_setup_work: plan
            .automaton
            .workspace_layout()
            .map_err(LiteralAnchorAggregateRunError::Verifier)?
            .construction_work(),
        max_scratch_bytes: workspace_scratch_limit,
    };
    let mut workspace = K0Workspace::new(&plan.automaton, workspace_limits)
        .map_err(LiteralAnchorAggregateRunError::Verifier)?;
    let verifier_scratch_bytes = workspace.retained_bytes();
    let total_scratch_bytes = admission
        .pending_bytes
        .checked_add(verifier_scratch_bytes)
        .ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor total scratch bytes",
            },
        )?;
    if verifier_scratch_bytes > workspace_scratch_limit
        || total_scratch_bytes > limits.max_total_scratch_bytes
    {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    let verifier = plan.automaton.prepare::<Span>();
    let verifier_setup = workspace.construction_accounting();
    let verifier_setup_work = verifier_setup.work();
    let mut verifier_work = verifier_setup_work;
    if verifier_work > admission.verifier_work_upper_bound {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    let verifier_limits = SearchLimits {
        max_work: limits.verifier.max_work,
        max_scratch_bytes: workspace_scratch_limit,
    };
    let mut recovery_failure = false;
    let scan = plan
        .stream
        .scan(haystack, limits.candidate_scan, |candidate| {
            let Some(anchor) = plan.anchors.get(candidate.pattern_index()).copied() else {
                recovery_failure = true;
                return;
            };
            let recovery = match anchor.recover(candidate, haystack.len()) {
                Ok(Some(recovery)) => recovery,
                Ok(None) => return,
                Err(_) => {
                    recovery_failure = true;
                    return;
                }
            };
            let start_bounds = recovery.start_bounds();
            if !start_bounds.is_exact() {
                recovery_failure = true;
                return;
            }
            if pending
                .try_push(PendingCandidate {
                    candidate,
                    recovery,
                    recovered_start: start_bounds.min(),
                })
                .is_err()
            {
                recovery_failure = true;
            }
        })
        .map_err(LiteralAnchorAggregateRunError::CandidateScan)?;
    if recovery_failure {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    let recovery_work = usize_to_u64(scan.actual.candidate_events)
        .and_then(|events| events.checked_mul(CANDIDATE_RECOVERY_WORK_PER_EVENT))
        .ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor candidate recovery work",
            },
        )?;
    if recovery_work > admission.recovery_work_upper_bound {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    let reorder_work = sort_pending(pending.as_mut_slice())?;
    if reorder_work > admission.reorder_work_upper_bound {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    let recovered_candidates = pending.len();
    let reducer_work = usize_to_u64(recovered_candidates)
        .and_then(|events| events.checked_mul(CANDIDATE_REDUCER_WORK_PER_RECOVERED))
        .ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor monotone reducer work",
            },
        )?;
    if reducer_work > admission.reducer_work_upper_bound {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    let mut cursor = 0usize;
    let mut index = 0usize;
    let mut verifier_calls = 0usize;
    let mut verifier_actual = VerifierInvocationAccounting::default();
    let mut selected_matches = 0usize;
    let mut selected_span_bytes = 0u64;
    while index < pending.len() {
        let start = pending[index].recovered_start;
        let mut group_end = index.checked_add(1).ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor first recovered-start group end",
            },
        )?;
        let mut latest_end = pending[index].recovery.end_bounds().max();
        while group_end < pending.len() && pending[group_end].recovered_start == start {
            latest_end = latest_end.max(pending[group_end].recovery.end_bounds().max());
            group_end = group_end.checked_add(1).ok_or(
                LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                    computation: "literal-anchor recovered-start group end",
                },
            )?;
        }
        if start >= cursor {
            let report = verifier
                .search_window_with_workspace(
                    haystack,
                    SearchWindow::new(start, latest_end),
                    &mut workspace,
                    verifier_limits,
                )
                .map_err(LiteralAnchorAggregateRunError::Verifier)?;
            verifier_calls = verifier_calls.checked_add(1).ok_or(
                LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                    computation: "literal-anchor verifier calls",
                },
            )?;
            add_search_accounting(report.accounting(), &mut verifier_actual)?;
            verifier_work = verifier_setup_work
                .checked_add(verifier_actual.work)
                .ok_or(
                    LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                        computation: "literal-anchor aggregate verifier work",
                    },
                )?;
            if verifier_work > admission.verifier_work_upper_bound {
                return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
            }
            if let Some(span) = report.into_output().filter(|span| span.start() == start)
                && span_matches_group(span.start(), span.end(), &pending[index..group_end])
            {
                if span.end() <= span.start() {
                    return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
                }
                selected_matches = selected_matches.checked_add(1).ok_or(
                    LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                        computation: "literal-anchor selected matches",
                    },
                )?;
                let span_bytes = span
                    .end()
                    .checked_sub(span.start())
                    .ok_or(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant)?;
                selected_span_bytes = selected_span_bytes
                    .checked_add(usize_to_u64(span_bytes).ok_or(
                        LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                            computation: "literal-anchor selected span conversion",
                        },
                    )?)
                    .ok_or(
                        LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                            computation: "literal-anchor selected span sum",
                        },
                    )?;
                cursor = span.end();
            }
        }
        index = group_end;
    }
    if verifier_calls > admission.verifier_calls_upper_bound {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    if verifier_actual.boundaries > admission.verifier_boundaries_upper_bound {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    if verifier_actual.scratch_clear_bytes > admission.verifier_scratch_clear_bytes_upper_bound {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    let value = match operation {
        PriorityAggregateOperation::Count => usize_to_u64(selected_matches).ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor selected match conversion",
            },
        )?,
        PriorityAggregateOperation::SpanSum => selected_span_bytes,
    };
    if value > limits.max_output {
        return Err(LiteralAnchorAggregateRunError::OutputLimit {
            needed: value,
            limit: limits.max_output,
        });
    }
    let total_work = usize_to_u64(scan.actual.work)
        .and_then(|work| work.checked_add(recovery_work))
        .and_then(|work| work.checked_add(reorder_work))
        .and_then(|work| work.checked_add(reducer_work))
        .and_then(|work| work.checked_add(verifier_work))
        .ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor total work",
            },
        )?;
    if total_work > admission.total_work_upper_bound {
        return Err(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant);
    }
    let candidate = LiteralAnchorCandidateExecutionReceipt {
        operation,
        scan,
        pending_bytes: admission.pending_bytes,
        pending_allocation_attempts: usize::from(admission.pending_bytes != 0),
        verifier_logical_scratch_bytes: admission.verifier_logical_scratch_bytes,
        verifier_scratch_bytes,
        verifier_scratch_limit: workspace_scratch_limit,
        total_scratch_bytes,
        total_scratch_limit: limits.max_total_scratch_bytes,
        recovery_work_upper_bound: admission.recovery_work_upper_bound,
        recovery_work,
        reorder_work_upper_bound: admission.reorder_work_upper_bound,
        reorder_work,
        recovered_candidates,
        reducer_work_upper_bound: admission.reducer_work_upper_bound,
        reducer_work,
        verifier_calls_upper_bound: admission.verifier_calls_upper_bound,
        verifier_calls,
        verifier_per_call_work_upper_bound: admission.verifier_per_call_work_upper_bound,
        verifier_work_upper_bound: admission.verifier_work_upper_bound,
        verifier_work,
        verifier_setup_work,
        verifier_setup_allocated_bytes: verifier_setup.allocated_bytes(),
        verifier_setup_initialized_bytes: verifier_setup.initialized_bytes(),
        verifier_invocation_setup_work: verifier_actual.setup_work,
        verifier_transition_work: verifier_actual.transition_work,
        verifier_scratch_clear_bytes_upper_bound: admission
            .verifier_scratch_clear_bytes_upper_bound,
        verifier_scratch_clear_bytes: verifier_actual.scratch_clear_bytes,
        verifier_boundaries_upper_bound: admission.verifier_boundaries_upper_bound,
        verifier_boundaries: verifier_actual.boundaries,
        total_work_upper_bound: admission.total_work_upper_bound,
        total_work,
        selected_matches,
        selected_span_bytes,
        value,
    };
    finish_execution_receipt(
        build,
        limits,
        operation,
        LiteralAnchorAggregateRoute::ByteCandidate,
        value,
        Some(candidate),
        None,
    )
}

fn span_matches_group(start: usize, end: usize, group: &[PendingCandidate]) -> bool {
    group.iter().any(|pending| {
        let recovery = pending.recovery;
        let start_bounds = recovery.start_bounds();
        let end_bounds = recovery.end_bounds();
        start == start_bounds.min()
            && start_bounds.is_exact()
            && end >= end_bounds.min()
            && end <= end_bounds.max()
            && pending.candidate.start() >= start
            && pending.candidate.end() <= end
    })
}

#[derive(Default)]
struct VerifierInvocationAccounting {
    work: u64,
    setup_work: u64,
    transition_work: u64,
    scratch_clear_bytes: usize,
    boundaries: usize,
}

fn add_search_accounting(
    accounting: SearchAccounting,
    total: &mut VerifierInvocationAccounting,
) -> Result<(), LiteralAnchorAggregateRunError> {
    let setup = accounting.setup();
    let scratch_clear_bytes = setup
        .initialized_bytes()
        .checked_sub(setup.allocated_bytes())
        .ok_or(LiteralAnchorAggregateRunError::CandidateRecoveryInvariant)?;
    total.work = total.work.checked_add(accounting.work()).ok_or(
        LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
            computation: "literal-anchor verifier work",
        },
    )?;
    total.setup_work = total
        .setup_work
        .checked_add(accounting.setup_work())
        .ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor verifier invocation setup work",
            },
        )?;
    total.transition_work = total
        .transition_work
        .checked_add(accounting.transition_work())
        .ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor verifier transition work",
            },
        )?;
    total.scratch_clear_bytes = total
        .scratch_clear_bytes
        .checked_add(scratch_clear_bytes)
        .ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor verifier scratch clear bytes",
            },
        )?;
    total.boundaries = total
        .boundaries
        .checked_add(accounting.boundaries())
        .ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor verifier boundaries",
            },
        )?;
    Ok(())
}

fn sort_pending(values: &mut [PendingCandidate]) -> Result<u64, LiteralAnchorAggregateRunError> {
    let mut work = 0u64;
    for index in 1..values.len() {
        let value = values[index];
        let mut cursor = index;
        while let Some(prior) = cursor.checked_sub(1) {
            work = work.checked_add(1).ok_or(
                LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                    computation: "literal-anchor reorder comparison",
                },
            )?;
            if pending_cmp(values[prior], value) != Ordering::Greater {
                break;
            }
            values[cursor] = values[prior];
            work = work.checked_add(1).ok_or(
                LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                    computation: "literal-anchor reorder move",
                },
            )?;
            cursor = prior;
        }
        values[cursor] = value;
        work = work.checked_add(1).ok_or(
            LiteralAnchorAggregateRunError::CandidateArithmeticOverflow {
                computation: "literal-anchor reorder placement",
            },
        )?;
    }
    Ok(work)
}

fn pending_cmp(left: PendingCandidate, right: PendingCandidate) -> Ordering {
    left.recovered_start
        .cmp(&right.recovered_start)
        .then_with(|| left.candidate.end().cmp(&right.candidate.end()))
        .then_with(|| {
            left.candidate
                .pattern_index()
                .cmp(&right.candidate.pattern_index())
        })
}

fn reorder_work_upper_bound(events: usize) -> Option<u64> {
    let events = usize_to_u64(events)?;
    if events == 0 {
        return Some(0);
    }
    let shifts = events.checked_mul(events.checked_sub(1)?)?.checked_div(2)?;
    shifts.checked_mul(2)?.checked_add(events)
}

fn usize_to_u64(value: usize) -> Option<u64> {
    u64::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::{
        ForcedExecution, LiteralAnchorAggregateBuildLimits, LiteralAnchorAggregateBuilder,
        LiteralAnchorAggregateCountRegex, LiteralAnchorAggregateRoute,
        LiteralAnchorAggregateRunError, LiteralAnchorAggregateRunLimits, PriorityAggregateBuilder,
        PriorityAggregateRunLimits, PriorityTarget,
    };

    #[test]
    fn candidate_route_preserves_word_context_and_nonoverlap() {
        let regex = LiteralAnchorAggregateBuilder::new(r"\bcat\b")
            .build_count()
            .expect("build");
        assert!(matches!(
            regex.build_report().route(),
            LiteralAnchorAggregateRoute::ByteCandidate
        ));
        let receipt = regex
            .count(
                b"cat scatter cat!",
                LiteralAnchorAggregateRunLimits::unlimited(),
            )
            .expect("count");
        assert_eq!(receipt.value(), 2);
        assert!(receipt.closes());
    }

    #[test]
    fn candidate_route_uses_priority_endpoint_selection() {
        let regex = LiteralAnchorAggregateBuilder::new(r"a(?:b{1,2}|b)")
            .build_span_sum()
            .expect("build");
        let receipt = regex
            .span_sum(b"abb ab", LiteralAnchorAggregateRunLimits::unlimited())
            .expect("span sum");
        assert_eq!(receipt.value(), 5);
        assert!(receipt.closes());
    }

    #[test]
    fn dense_run_uses_common_sparse_before_candidate_scan() {
        let regex = LiteralAnchorAggregateBuilder::new("a")
            .build_count()
            .expect("build");
        let mut limits = LiteralAnchorAggregateRunLimits::unlimited();
        limits.max_candidate_events = 0;
        let receipt = regex.count(b"aaa", limits).expect("count");
        assert!(matches!(
            receipt.route(),
            LiteralAnchorAggregateRoute::CommonSparse(_)
        ));
        assert_eq!(receipt.value(), 3);
        assert!(receipt.closes());
    }

    #[test]
    fn boundary_ineligible_occurrence_is_dropped_before_verification() {
        // The finite whole-string alternatives are deliberately excluded so
        // HIR's independently required internal `abc` anchor is selected.
        let anchor_limits = LiteralAnchorAggregateBuildLimits {
            max_anchors: 1,
            ..LiteralAnchorAggregateBuildLimits::default()
        };
        let regex = LiteralAnchorAggregateBuilder::new("[ab]abc")
            .anchor_limits(anchor_limits)
            .build_count()
            .expect("build");
        assert!(matches!(
            regex.build_report().route(),
            LiteralAnchorAggregateRoute::ByteCandidate
        ));
        let receipt = regex
            .count(b"abcaabc", LiteralAnchorAggregateRunLimits::unlimited())
            .expect("count");
        assert_eq!(receipt.value(), 1);
        assert!(receipt.closes());
    }

    #[test]
    fn source_length_gate_falls_back_before_candidate_execution() {
        let regex = LiteralAnchorAggregateBuilder::new("a")
            .build_count()
            .expect("build");
        let mut limits = LiteralAnchorAggregateRunLimits::unlimited();
        limits.candidate_scan.max_input_bytes = 0;
        let receipt = regex.count(b"a", limits).expect("count");
        assert!(matches!(
            receipt.route(),
            LiteralAnchorAggregateRoute::CommonSparse(_)
        ));
        assert_eq!(receipt.value(), 1);
        assert!(receipt.closes());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the table-free test intentionally makes every candidate gate's exact and one-below pair visible together"
    )]
    fn candidate_admission_limits_have_exact_and_one_below_boundaries() {
        let regex = LiteralAnchorAggregateBuilder::new("a")
            .build_count()
            .expect("build");
        let source = b"aaaa";
        let baseline = regex
            .count(source, LiteralAnchorAggregateRunLimits::unlimited())
            .expect("baseline");
        assert!(matches!(
            baseline.route(),
            LiteralAnchorAggregateRoute::ByteCandidate
        ));
        let candidate = baseline.candidate().expect("candidate receipt");
        let scan = candidate.scan();

        assert_usize_boundary(&regex, source, scan.upper.input_bytes, |limits, value| {
            limits.candidate_scan.max_input_bytes = value;
        });
        assert_usize_boundary(
            &regex,
            source,
            scan.upper.candidate_starts,
            |limits, value| {
                limits.candidate_scan.max_candidate_starts = value;
            },
        );
        assert_usize_boundary(
            &regex,
            source,
            scan.upper.source_byte_reads,
            |limits, value| {
                limits.candidate_scan.max_source_byte_reads = value;
            },
        );
        assert_usize_boundary(
            &regex,
            source,
            scan.upper.transition_probes,
            |limits, value| {
                limits.candidate_scan.max_transition_probes = value;
            },
        );
        assert_usize_boundary(
            &regex,
            source,
            scan.upper.candidate_events,
            |limits, value| {
                limits.candidate_scan.max_candidate_events = value;
            },
        );
        assert_usize_boundary(
            &regex,
            source,
            scan.upper.candidate_events,
            |limits, value| {
                limits.max_candidate_events = value;
            },
        );
        assert_usize_boundary(&regex, source, scan.upper.work, |limits, value| {
            limits.candidate_scan.max_work = value;
        });
        assert_usize_boundary(
            &regex,
            source,
            candidate.pending_bytes(),
            |limits, value| {
                limits.max_pending_bytes = value;
            },
        );
        assert_usize_boundary(
            &regex,
            source,
            candidate.total_scratch_bytes(),
            |limits, value| {
                limits.max_total_scratch_bytes = value;
            },
        );
        assert_usize_boundary(
            &regex,
            source,
            candidate.verifier_calls_upper_bound(),
            |limits, value| {
                limits.max_verifier_calls = value;
            },
        );
        assert_usize_boundary(
            &regex,
            source,
            candidate.verifier_logical_scratch_bytes(),
            |limits, value| {
                limits.verifier.max_scratch_bytes = value;
            },
        );
        assert_u64_boundary(
            &regex,
            source,
            candidate.reorder_work_upper_bound(),
            |limits, value| {
                limits.max_reorder_work = value;
            },
        );
        assert_u64_boundary(
            &regex,
            source,
            candidate.verifier_per_call_work_upper_bound(),
            |limits, value| {
                limits.verifier.max_work = value;
            },
        );
        assert_u64_boundary(
            &regex,
            source,
            candidate.verifier_work_upper_bound(),
            |limits, value| {
                limits.max_verifier_work = value;
            },
        );
        assert_u64_boundary(
            &regex,
            source,
            candidate.total_work_upper_bound(),
            |limits, value| {
                limits.max_total_work = value;
            },
        );

        let mut exact_output = LiteralAnchorAggregateRunLimits::unlimited();
        exact_output.max_output = u64::try_from(source.len() + 1).expect("count bound");
        assert!(matches!(
            regex
                .count(source, exact_output)
                .expect("exact count output")
                .route(),
            LiteralAnchorAggregateRoute::ByteCandidate
        ));
        exact_output.max_output -= 1;
        assert!(matches!(
            regex.count(source, exact_output),
            Err(LiteralAnchorAggregateRunError::Common(_))
        ));
    }

    #[test]
    fn span_sum_output_limit_uses_the_common_exact_boundary() {
        let regex = LiteralAnchorAggregateBuilder::new("a")
            .build_span_sum()
            .expect("build");
        let source = b"aaaa";
        let mut exact = LiteralAnchorAggregateRunLimits::unlimited();
        exact.max_output = u64::try_from(source.len()).expect("span bound");
        let receipt = regex.span_sum(source, exact).expect("exact span output");
        assert_eq!(receipt.value(), 4);
        assert!(matches!(
            receipt.route(),
            LiteralAnchorAggregateRoute::ByteCandidate
        ));
        exact.max_output -= 1;
        assert!(matches!(
            regex.span_sum(source, exact),
            Err(LiteralAnchorAggregateRunError::Common(_))
        ));
    }

    #[test]
    fn plan_owner_initialization_is_not_reused_workspace_clearing() {
        let source = b"aaaa";
        let baseline = LiteralAnchorAggregateBuilder::new("a")
            .build_count()
            .expect("baseline build")
            .count(source, LiteralAnchorAggregateRunLimits::unlimited())
            .expect("baseline count");
        let baseline_candidate = baseline.candidate().expect("baseline candidate receipt");
        assert_eq!(baseline_candidate.verifier_scratch_clear_bytes(), 0);
        assert!(baseline.closes());

        // A fresh plan may try to publish its immutable start-filter owner on
        // the first verifier call. The exact aggregate scratch envelope admits
        // only the mandatory queue and workspace, so K0 must decline that
        // optional owner without misreporting its initialization as a clear.
        let fresh = LiteralAnchorAggregateBuilder::new("a")
            .build_count()
            .expect("fresh build");
        let mut exact = LiteralAnchorAggregateRunLimits::unlimited();
        exact.max_total_scratch_bytes = baseline_candidate.total_scratch_bytes();
        let receipt = fresh.count(source, exact).expect("exact scratch count");
        let candidate = receipt.candidate().expect("fresh candidate receipt");
        assert_eq!(
            candidate.total_scratch_bytes(),
            exact.max_total_scratch_bytes
        );
        assert_eq!(candidate.verifier_scratch_clear_bytes(), 0);
        assert!(receipt.closes());
    }

    #[test]
    fn empty_candidate_stream_stays_on_the_admitted_route() {
        let regex = LiteralAnchorAggregateBuilder::new("a")
            .build_count()
            .expect("build");
        let receipt = regex
            .count(b"", LiteralAnchorAggregateRunLimits::unlimited())
            .expect("empty count");
        assert!(matches!(
            receipt.route(),
            LiteralAnchorAggregateRoute::ByteCandidate
        ));
        let candidate = receipt.candidate().expect("candidate receipt");
        assert_eq!(candidate.scan().actual.candidate_events, 0);
        assert_eq!(candidate.pending_allocation_attempts(), 0);
        assert!(receipt.closes());
    }

    #[test]
    fn unicode_fold_and_malformed_bytes_use_common_semantics() {
        let regex = LiteralAnchorAggregateBuilder::new(r"(?i)k")
            .build_count()
            .expect("build");
        assert!(matches!(
            regex.build_report().route(),
            LiteralAnchorAggregateRoute::CommonSparse(_)
        ));
        let receipt = regex
            .count(
                b"kK\xff\xe2\x84\xaa",
                LiteralAnchorAggregateRunLimits::unlimited(),
            )
            .expect("count");
        assert_eq!(receipt.value(), 3);
        assert!(receipt.closes());
    }

    #[test]
    fn held_out_context_fold_and_two_way_cases_match_common_sparse() {
        assert_count_and_sum_parity(r"(?m)^cat$", b"cat\nscatter\ncat\ncatx\n");
        assert_count_and_sum_parity(r"(?i-u:cat)", b"CAT cat CaT dog");
        assert_count_and_sum_parity(r".{3}needle", b"xxxneedle--yyyyneedle");
        assert_count_and_sum_parity(r"[ab]{1,3}needle[0-9]{1,4}", b"abneedle12 bbbneedle7");
        assert_count_and_sum_parity("a", b"\xffa\x80aa");
        assert_count_and_sum_parity(r"(?i)k", b"kK\xff\xe2\x84\xaa");
        assert_count_and_sum_parity(
            "abcdefghijklmnopqrstuvwxyz0123456789",
            b"xxabcdefghijklmnopqrstuvwxyz0123456789yyabcdefghijklmnopqrstuvwxyz0123456789",
        );
    }

    #[test]
    fn generated_small_sources_match_common_priority_reducers() {
        for pattern in [
            "a",
            "a(?:b{1,2}|b)",
            "a(?:b{1,2}?|b)",
            "(?:a+b|a)",
            "(?:a|)",
            r"\bcat\b",
            ".abc",
            "(?:ab|ba)c",
        ] {
            let candidate_count = LiteralAnchorAggregateBuilder::new(pattern)
                .build_count()
                .expect("candidate count build");
            let candidate_sum = LiteralAnchorAggregateBuilder::new(pattern)
                .build_span_sum()
                .expect("candidate span build");
            let common_count = PriorityAggregateBuilder::new(pattern)
                .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
                .expect("common count build");
            let common_sum = PriorityAggregateBuilder::new(pattern)
                .build_span_sum(ForcedExecution::Sparse, PriorityTarget::portable())
                .expect("common sum build");
            for source in sources(b"abc tx", 4) {
                let candidate_count = candidate_count
                    .count(&source, LiteralAnchorAggregateRunLimits::unlimited())
                    .expect("candidate count");
                let candidate_sum = candidate_sum
                    .span_sum(&source, LiteralAnchorAggregateRunLimits::unlimited())
                    .expect("candidate span sum");
                let common_count = common_count
                    .count(&source, PriorityAggregateRunLimits::unlimited())
                    .expect("common count");
                let common_sum = common_sum
                    .span_sum(&source, PriorityAggregateRunLimits::unlimited())
                    .expect("common span sum");
                assert_eq!(
                    candidate_count.value(),
                    common_count.value(),
                    "{pattern:?} {source:?}"
                );
                assert_eq!(
                    candidate_sum.value(),
                    common_sum.value(),
                    "{pattern:?} {source:?}"
                );
                assert!(candidate_count.closes(), "{pattern:?} {source:?}");
                assert!(candidate_sum.closes(), "{pattern:?} {source:?}");
            }
        }
    }

    fn sources(alphabet: &[u8], maximum_length: usize) -> Vec<Vec<u8>> {
        let mut output = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..maximum_length {
            let mut next = Vec::new();
            for prefix in frontier {
                for &byte in alphabet {
                    let mut source = prefix.clone();
                    source.push(byte);
                    output.push(source.clone());
                    next.push(source);
                }
            }
            frontier = next;
        }
        output
    }

    fn assert_usize_boundary(
        regex: &LiteralAnchorAggregateCountRegex,
        source: &[u8],
        exact: usize,
        set: impl Fn(&mut LiteralAnchorAggregateRunLimits, usize),
    ) {
        assert!(exact > 0, "boundary must have a one-below case");
        let mut limits = LiteralAnchorAggregateRunLimits::unlimited();
        set(&mut limits, exact);
        assert!(matches!(
            regex
                .count(source, limits)
                .expect("exact candidate route")
                .route(),
            LiteralAnchorAggregateRoute::ByteCandidate
        ));
        set(
            &mut limits,
            exact.checked_sub(1).expect("nonzero exact boundary"),
        );
        let fallback = regex.count(source, limits).expect("one-below common route");
        assert!(matches!(
            fallback.route(),
            LiteralAnchorAggregateRoute::CommonSparse(_)
        ));
        assert!(fallback.candidate().is_none());
        assert!(fallback.closes());
    }

    fn assert_u64_boundary(
        regex: &LiteralAnchorAggregateCountRegex,
        source: &[u8],
        exact: u64,
        set: impl Fn(&mut LiteralAnchorAggregateRunLimits, u64),
    ) {
        assert!(exact > 0, "boundary must have a one-below case");
        let mut limits = LiteralAnchorAggregateRunLimits::unlimited();
        set(&mut limits, exact);
        assert!(matches!(
            regex
                .count(source, limits)
                .expect("exact candidate route")
                .route(),
            LiteralAnchorAggregateRoute::ByteCandidate
        ));
        set(
            &mut limits,
            exact.checked_sub(1).expect("nonzero exact boundary"),
        );
        let fallback = regex.count(source, limits).expect("one-below common route");
        assert!(matches!(
            fallback.route(),
            LiteralAnchorAggregateRoute::CommonSparse(_)
        ));
        assert!(fallback.candidate().is_none());
        assert!(fallback.closes());
    }

    fn assert_count_and_sum_parity(pattern: &str, source: &[u8]) {
        let candidate_count = LiteralAnchorAggregateBuilder::new(pattern)
            .build_count()
            .expect("candidate count build");
        let candidate_sum = LiteralAnchorAggregateBuilder::new(pattern)
            .build_span_sum()
            .expect("candidate span build");
        let common_count = PriorityAggregateBuilder::new(pattern)
            .build_count(ForcedExecution::Sparse, PriorityTarget::portable())
            .expect("common count build");
        let common_sum = PriorityAggregateBuilder::new(pattern)
            .build_span_sum(ForcedExecution::Sparse, PriorityTarget::portable())
            .expect("common span build");
        let candidate_count = candidate_count
            .count(source, LiteralAnchorAggregateRunLimits::unlimited())
            .expect("candidate count");
        let candidate_sum = candidate_sum
            .span_sum(source, LiteralAnchorAggregateRunLimits::unlimited())
            .expect("candidate sum");
        let common_count = common_count
            .count(source, PriorityAggregateRunLimits::unlimited())
            .expect("common count");
        let common_sum = common_sum
            .span_sum(source, PriorityAggregateRunLimits::unlimited())
            .expect("common sum");
        assert_eq!(candidate_count.value(), common_count.value(), "{pattern:?}");
        assert_eq!(candidate_sum.value(), common_sum.value(), "{pattern:?}");
        assert!(candidate_count.closes(), "{pattern:?}");
        assert!(candidate_sum.closes(), "{pattern:?}");
    }
}
