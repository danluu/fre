//! Explicit forced integration for the P1 prioritized-automata substrate.
//!
//! This module is deliberately separate from [`super::AggregateBuilder`].
//! It cannot participate in automatic selection, and every requested route is
//! either prepared exactly or refused before an executable artifact is
//! published.

#![allow(
    clippy::result_large_err,
    reason = "terminal errors retain exact receipt, route, limit, and preflight evidence without an unaccounted post-failure allocation"
)]

use core::{fmt, mem::size_of};

use fre_automata::{
    ActionCapabilities, Automaton, CompileError, DirectCount, DirectReduceLimits,
    DirectReduceReport, DirectSpanSum, EmptyMatchProgress, ExecutionActual, ExecutionProspective,
    ForcedExecution, MatchLengthProof, PatternAction, PatternOrdinal, PlanStats,
    PreparationAccounting, PreparationError, PreparationLimits, PreparedPriorityAutomaton,
    PriorityAutomataFacts, PriorityExecutionKernel, PriorityTarget, ReduceError, StateRole,
};
use fre_lower::{
    CheckedWidth, DeterministicCertificate, FactError, FactIdentity, FactLimits, FactOperation,
    FactOptionalProofs, FactOutput, FactProof, FactProspective, FactRefusal, FactStats, HirFacts,
    LowerError, LowerLimits, LowerStats, OperationSemantics, analyze_facts, lower_raw,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ParseAttemptError, ParseAttemptReceipt, ParseAttemptTerminal, ParseRequest, ParseSummary,
    RustConstructor, RustProfile, SafetyEnvelope,
};

/// Schema for explicit forced-priority construction and execution receipts.
pub const PRIORITY_AGGREGATE_SCHEMA_VERSION: u32 = 6;
/// Stable accounting identity for the facade bridge.
pub const PRIORITY_AGGREGATE_ACCOUNTING_ID: &str = "fre.priority-aggregate.facade.v6";

/// Whole-match value fixed before syntax parsing begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateOperation {
    /// Count complete non-overlapping matches.
    Count,
    /// Sum complete non-overlapping match lengths.
    SpanSum,
}

impl PriorityAggregateOperation {
    const fn fact_operation(self, execution: ForcedExecution) -> FactOperation {
        let optional_proofs = match execution {
            // Sparse evaluation consumes only core width and structural facts.
            ForcedExecution::Sparse => FactOptionalProofs::CoreOnly,
            // Finite-route preparation requires assertion context to derive a
            // checked static horizon or authenticate an input-bounded sparse
            // fallback.
            ForcedExecution::FiniteHorizon => FactOptionalProofs::AssertionContext,
            // Tagged variable-width reverse construction consumes assertion
            // context but does not rely on the incumbent ordered-subset
            // certificate or complete finite-language materialization.
            ForcedExecution::FullDfa | ForcedExecution::LazyDfa => {
                FactOptionalProofs::AssertionContext
            }
            _ => FactOptionalProofs::Complete,
        };
        FactOperation::capture_erased(match self {
            Self::Count => FactOutput::Count,
            Self::SpanSum => FactOutput::SpanSum,
        })
        .with_optional_proofs(optional_proofs)
    }
}

/// Limits for the integration-owned accept-action sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateBridgeLimits {
    pub max_work: u64,
    pub max_action_bytes: usize,
    pub max_peak_bytes: usize,
    pub max_pattern_terminals: usize,
    pub max_allocation_attempts: usize,
}

impl Default for PriorityAggregateBridgeLimits {
    fn default() -> Self {
        Self {
            max_work: 1_000_000,
            max_action_bytes: 32 * 1024 * 1024,
            max_peak_bytes: 32 * 1024 * 1024,
            max_pattern_terminals: 1,
            max_allocation_attempts: 1,
        }
    }
}

/// Complete checked limits for one explicit forced construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PriorityAggregateBuildLimits {
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    pub source_owner: PriorityAggregateSourceOwnerLimits,
    pub facts: FactLimits,
    pub lowering: LowerLimits,
    pub bridge: PriorityAggregateBridgeLimits,
    pub preparation: PreparationLimits,
}

/// Limits for the allocation-backed syntax source owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateSourceOwnerLimits {
    pub max_allocation_bytes: usize,
    pub max_handle_bytes: usize,
    pub max_allocation_attempts: usize,
}

impl Default for PriorityAggregateSourceOwnerLimits {
    fn default() -> Self {
        Self {
            max_allocation_bytes: ParseRequest::attempt_source_owner_allocation_bytes(),
            max_handle_bytes: ParseRequest::attempt_source_owner_handle_bytes()
                .checked_mul(2)
                .expect("two syntax source-owner handles fit in usize"),
            max_allocation_attempts: 1,
        }
    }
}

/// Exact stable-owner allocation and inline handle accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateSourceOwnerAccounting {
    allocation_bytes: usize,
    handle_bytes: usize,
    allocation_attempts: usize,
}

impl PriorityAggregateSourceOwnerAccounting {
    #[must_use]
    pub const fn allocation_bytes(self) -> usize {
        self.allocation_bytes
    }

    #[must_use]
    pub const fn handle_bytes(self) -> usize {
        self.handle_bytes
    }

    #[must_use]
    pub const fn allocation_attempts(self) -> usize {
        self.allocation_attempts
    }

    fn closes_against(self, limits: PriorityAggregateSourceOwnerLimits) -> bool {
        self.allocation_bytes == ParseRequest::attempt_source_owner_allocation_bytes()
            && ParseRequest::attempt_source_owner_handle_bytes().checked_mul(2)
                == Some(self.handle_bytes)
            && self.allocation_attempts == 1
            && self.allocation_bytes <= limits.max_allocation_bytes
            && self.handle_bytes <= limits.max_handle_bytes
            && self.allocation_attempts <= limits.max_allocation_attempts
    }
}

/// Source-independent bridge bounds admitted before the sidecar is built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateBridgeProspective {
    pub work: u64,
    pub action_bytes: usize,
    pub peak_bytes: usize,
    pub pattern_terminals: usize,
    pub allocation_attempts: usize,
}

/// Exact integration-owned action-sidecar construction counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateBridgeAccounting {
    prospective: PriorityAggregateBridgeProspective,
    work: u64,
    action_bytes: usize,
    peak_bytes: usize,
    pattern_terminals: usize,
    allocation_attempts: usize,
}

impl PriorityAggregateBridgeAccounting {
    #[must_use]
    pub const fn prospective(self) -> PriorityAggregateBridgeProspective {
        self.prospective
    }

    #[must_use]
    pub const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn action_bytes(self) -> usize {
        self.action_bytes
    }

    #[must_use]
    pub const fn peak_bytes(self) -> usize {
        self.peak_bytes
    }

    #[must_use]
    pub const fn pattern_terminals(self) -> usize {
        self.pattern_terminals
    }

    #[must_use]
    pub const fn allocation_attempts(self) -> usize {
        self.allocation_attempts
    }

    /// Whether exact bridge effects close against their pre-effect bounds.
    #[must_use]
    pub const fn closes(self) -> bool {
        self.work == self.prospective.work
            && self.action_bytes == self.prospective.action_bytes
            && self.peak_bytes == self.prospective.peak_bytes
            && self.pattern_terminals == self.prospective.pattern_terminals
            && self.allocation_attempts == self.prospective.allocation_attempts
    }

    const fn closes_against(self, limits: PriorityAggregateBridgeLimits) -> bool {
        self.closes()
            && self.prospective.work <= limits.max_work
            && self.prospective.action_bytes <= limits.max_action_bytes
            && self.prospective.peak_bytes <= limits.max_peak_bytes
            && self.prospective.pattern_terminals <= limits.max_pattern_terminals
            && self.prospective.allocation_attempts <= limits.max_allocation_attempts
    }
}

/// One separately authenticated successful syntax stage.
#[derive(Debug, Eq, PartialEq)]
pub struct PriorityAggregateSyntaxEvidence {
    key: CacheKey,
    admission: AdmissionStatus,
    summary: ParseSummary,
    receipt: ParseAttemptReceipt,
    source_owner: PriorityAggregateSourceOwnerAccounting,
}

impl PriorityAggregateSyntaxEvidence {
    #[must_use]
    pub const fn key(&self) -> &CacheKey {
        &self.key
    }

    #[must_use]
    pub const fn admission(&self) -> AdmissionStatus {
        self.admission
    }

    #[must_use]
    pub const fn summary(&self) -> &ParseSummary {
        &self.summary
    }

    #[must_use]
    pub const fn receipt(&self) -> &ParseAttemptReceipt {
        &self.receipt
    }

    #[must_use]
    pub const fn source_owner(&self) -> PriorityAggregateSourceOwnerAccounting {
        self.source_owner
    }

    /// Whether the syntax receipt closes over this exact cache-key owner.
    #[must_use]
    pub fn closes(&self) -> bool {
        let actual = self.receipt.actual;
        let expected_admission = match self.key.admission {
            AdmissionPolicy::Strict(_) => AdmissionStatus::UpstreamOraclePending,
            AdmissionPolicy::Quota(_) => AdmissionStatus::QuotaChecked,
        };
        let summary_work = self
            .receipt
            .prospective
            .and_then(|prospective| prospective.source_bytes.checked_add(actual.observed_work));
        self.receipt.terminal == ParseAttemptTerminal::Success
            && self.receipt.identity.authenticates_key(&self.key)
            && self.receipt.authenticates_canonical()
            && self.receipt.prospective.is_some()
            && self.admission == expected_admission
            && actual.source_admission_checks == 1
            && actual.configuration_checks == 1
            && actual.opaque_parser_invocations >= 1
            && actual.hir_nodes == self.summary.hir_nodes
            && actual.literal_bytes == self.summary.literal_bytes
            && actual.class_ranges == self.summary.class_ranges
            && actual.captures == self.summary.captures
            && actual.repetitions == self.summary.repetitions
            && actual.max_depth == self.summary.max_depth
            && summary_work == Some(self.summary.parse_work)
    }
}

/// Compact optional usize proof retained without the fact report's dynamic
/// strings and alternatives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateUsizeProof {
    Proven(usize),
    Unknown,
    Refused(FactRefusal),
}

/// Compact ordered-subset proof retained at publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateDeterminismProof {
    Proven(DeterministicCertificate),
    Unknown,
    Refused(FactRefusal),
}

/// Compact assertion-context proof retained by assertion-aware Full/Lazy
/// route envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateAssertionProof {
    Proven {
        count: usize,
        maximum_look_behind_bytes: usize,
        maximum_look_ahead_bytes: usize,
        requires_stream_end: bool,
    },
    Unknown,
    Refused(FactRefusal),
}

impl PriorityAggregateAssertionProof {
    const fn is_proven_against(self, prospective: FactProspective, limits: FactLimits) -> bool {
        match self {
            Self::Proven { count, .. } => {
                count <= prospective.assertions() && count <= limits.max_assertions
            }
            Self::Unknown | Self::Refused(_) => false,
        }
    }

    const fn is_consistent_with(self, prospective: FactProspective, limits: FactLimits) -> bool {
        match self {
            Self::Proven { count, .. } => {
                count <= prospective.assertions() && count <= limits.max_assertions
            }
            Self::Unknown | Self::Refused(_) => true,
        }
    }

    const fn requires_stream_end(self) -> bool {
        matches!(
            self,
            Self::Proven {
                requires_stream_end: true,
                ..
            }
        )
    }
}

/// Operation-aware fact P/A and the exact proof projections consumed by the
/// forced bridge. Dynamic finite languages and required alternatives are
/// dropped before the executable artifact is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateFactReceipt {
    identity: FactIdentity,
    operation: FactOperation,
    width: CheckedWidth,
    capture_count: usize,
    capture_erasure_permitted: bool,
    finite_decision_horizon: PriorityAggregateUsizeProof,
    subset_determinism: PriorityAggregateDeterminismProof,
    assertion_context: PriorityAggregateAssertionProof,
    prospective: FactProspective,
    actual: FactStats,
}

impl PriorityAggregateFactReceipt {
    fn from_facts(facts: &HirFacts) -> Self {
        let finite_decision_horizon = match facts.finite_decision_horizon_bytes() {
            FactProof::Proven(value) => PriorityAggregateUsizeProof::Proven(*value),
            FactProof::Unknown => PriorityAggregateUsizeProof::Unknown,
            FactProof::Refused(reason) => PriorityAggregateUsizeProof::Refused(*reason),
        };
        let subset_determinism = match facts.determinism().subset() {
            FactProof::Proven(value) => PriorityAggregateDeterminismProof::Proven(*value),
            FactProof::Unknown => PriorityAggregateDeterminismProof::Unknown,
            FactProof::Refused(reason) => PriorityAggregateDeterminismProof::Refused(*reason),
        };
        let assertion_context = match facts.assertions().possible() {
            FactProof::Proven(assertions) => PriorityAggregateAssertionProof::Proven {
                count: assertions.len(),
                maximum_look_behind_bytes: facts.assertions().maximum_look_behind_bytes(),
                maximum_look_ahead_bytes: facts.assertions().maximum_look_ahead_bytes(),
                requires_stream_end: facts.assertions().requires_stream_end(),
            },
            FactProof::Unknown => PriorityAggregateAssertionProof::Unknown,
            FactProof::Refused(reason) => PriorityAggregateAssertionProof::Refused(*reason),
        };
        Self {
            identity: facts.identity(),
            operation: facts.operation(),
            width: facts.width(),
            capture_count: facts.captures().captures().len(),
            capture_erasure_permitted: facts.captures().erasure_permitted(),
            finite_decision_horizon,
            subset_determinism,
            assertion_context,
            prospective: facts.prospective(),
            actual: facts.stats(),
        }
    }

    #[must_use]
    pub const fn identity(self) -> FactIdentity {
        self.identity
    }

    #[must_use]
    pub const fn operation(self) -> FactOperation {
        self.operation
    }

    #[must_use]
    pub const fn width(self) -> CheckedWidth {
        self.width
    }

    #[must_use]
    pub const fn capture_count(self) -> usize {
        self.capture_count
    }

    #[must_use]
    pub const fn capture_erasure_permitted(self) -> bool {
        self.capture_erasure_permitted
    }

    #[must_use]
    pub const fn finite_decision_horizon(self) -> PriorityAggregateUsizeProof {
        self.finite_decision_horizon
    }

    /// Static reducer-ring width derived from the maximum complete-match
    /// width. This is intentionally separate from the streaming decision
    /// horizon, which may be unknown for an end-of-stream assertion.
    #[must_use]
    pub const fn static_retention_width_bytes(self) -> PriorityAggregateUsizeProof {
        match self.width.maximum() {
            Some(bytes) => PriorityAggregateUsizeProof::Proven(bytes),
            None => PriorityAggregateUsizeProof::Unknown,
        }
    }

    #[must_use]
    pub const fn subset_determinism(self) -> PriorityAggregateDeterminismProof {
        self.subset_determinism
    }

    #[must_use]
    pub const fn assertion_context(self) -> PriorityAggregateAssertionProof {
        self.assertion_context
    }

    #[must_use]
    pub const fn prospective(self) -> FactProspective {
        self.prospective
    }

    #[must_use]
    pub const fn actual(self) -> FactStats {
        self.actual
    }

    fn closes_against(self, limits: FactLimits) -> bool {
        let prospective = self.prospective;
        let actual = self.actual;
        self.identity.authenticates_current()
            && actual.work() <= prospective.work()
            && actual.peak_stack_items() <= prospective.peak_stack_items()
            && actual.hir_nodes() == prospective.hir_nodes()
            && actual.retained_bytes() <= prospective.retained_bytes()
            && actual.temporary_bytes() <= prospective.temporary_bytes()
            && actual.peak_bytes() <= prospective.peak_bytes()
            && actual.allocation_attempts() <= prospective.allocation_attempts()
            && actual.finite_strings() <= prospective.finite_strings()
            && actual.finite_string_bytes() <= prospective.finite_string_bytes()
            && actual.required_groups() <= prospective.required_groups()
            && actual.required_alternatives() <= prospective.required_alternatives()
            && actual.required_bytes() <= prospective.required_bytes()
            && prospective.work() <= limits.max_work
            && prospective.peak_stack_items() <= limits.max_stack_items
            && prospective.hir_nodes() <= limits.max_hir_nodes
            && prospective.retained_bytes() <= limits.max_retained_bytes
            && prospective.temporary_bytes() <= limits.max_temporary_bytes
            && prospective.peak_bytes() <= limits.max_peak_bytes
            && prospective.allocation_attempts() <= limits.max_allocation_attempts
            && actual.finite_strings() <= limits.max_finite_strings
            && actual.finite_string_bytes() <= limits.max_finite_string_bytes
            && actual.required_groups() <= limits.max_required_groups
            && actual.required_alternatives() <= limits.max_required_alternatives
            && actual.required_bytes() <= limits.max_required_bytes
            && self
                .assertion_context
                .is_consistent_with(prospective, limits)
    }
}

/// Structural proof required in addition to leaf route preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateRouteProof {
    /// Sparse priority evaluation requires no optional positive HIR proof.
    Sparse,
    /// The exact finite decision horizon proved by HIR analysis.
    FiniteHorizon { maximum_bytes: usize },
    /// A finite-width route which requires the complete source/end-of-stream.
    ///
    /// It uses the static reducer ring bounded by `maximum_match_bytes`, but
    /// deliberately makes no streaming decision-horizon claim.
    FiniteRetentionAtStreamEnd { maximum_match_bytes: usize },
    /// No static match-width maximum exists, so each execution binds its
    /// sparse-equivalent suffix storage to the preflighted input length.
    /// This is a construction classification, not a numeric decision-horizon
    /// claim.
    InputBoundedHorizon,
    /// A positive ordered-subset determinism certificate was present.
    Deterministic,
    /// A Full/Lazy route with authenticated assertion context.
    ///
    /// `minimum_bytes` may be zero only when the separately authenticated
    /// concrete kernel is the corresponding tagged reverse transducer. The
    /// classic fixed-width DFA kernels retain their positive exact-width
    /// eligibility requirement.
    AssertionContext { minimum_bytes: usize },
}

/// A resource owned by the facade bridge rather than a leaf compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateBridgeResource {
    Work,
    ActionBytes,
    PeakBytes,
    PatternTerminals,
    AllocationAttempts,
}

/// Stable syntax-owner resource checked before its allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateSourceOwnerResource {
    AllocationBytes,
    HandleBytes,
    AllocationAttempts,
}

impl fmt::Display for PriorityAggregateBridgeResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Work => "action-sidecar work",
            Self::ActionBytes => "action-sidecar bytes",
            Self::PeakBytes => "action-sidecar peak bytes",
            Self::PatternTerminals => "single-pattern terminals",
            Self::AllocationAttempts => "action-sidecar allocation attempts",
        })
    }
}

/// An optional positive HIR proof required by a requested route was absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateProofRefusal {
    FiniteDecisionHorizon,
    FiniteDecisionHorizonMatchesWidth,
    OrderedSubsetDeterminism,
    ExactNonEmptyMatchWidth,
    AssertionContext,
}

/// Terminal construction failure. No variant contains an executable plan.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the exact failed parse request and receipt remain inline instead of adding an unaccounted terminal allocation"
)]
#[non_exhaustive]
pub enum PriorityAggregateBuildError {
    Syntax(ParseAttemptError),
    NonRustCanonicalPattern,
    UnsupportedBytesEmptyProgress {
        syntax: PriorityAggregateSyntaxEvidence,
    },
    UnsupportedExecution {
        execution: ForcedExecution,
    },
    Facts(FactError),
    CaptureErasureNotProven,
    MissingRouteProof {
        execution: ForcedExecution,
        proof: PriorityAggregateProofRefusal,
    },
    Lower(LowerError),
    NormalizedLoweringRequiresIntrinsicLength {
        normalized_repetitions: usize,
    },
    SourceOwnerResourceLimit {
        resource: PriorityAggregateSourceOwnerResource,
        needed: usize,
        limit: usize,
    },
    SourceOwnerAlreadyBound,
    BridgeResourceLimit {
        resource: PriorityAggregateBridgeResource,
        needed: u64,
        limit: u64,
    },
    BridgeArithmeticOverflow {
        computation: &'static str,
    },
    BridgeAllocationFailed {
        bytes: usize,
    },
    InvalidAcceptTerminalCount {
        terminals: usize,
    },
    Automaton(CompileError),
    Preparation(PreparationError),
    BuildReportNotClosed,
}

impl fmt::Display for PriorityAggregateBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(source) => write!(formatter, "forced-priority syntax: {source}"),
            Self::NonRustCanonicalPattern => {
                formatter.write_str("forced-priority construction requires canonical Rust HIR")
            }
            Self::UnsupportedBytesEmptyProgress { .. } => formatter.write_str(
                "forced-priority construction requires byte-progress empty-match semantics",
            ),
            Self::UnsupportedExecution { execution } => {
                write!(formatter, "unsupported forced-priority route {execution:?}")
            }
            Self::Facts(source) => write!(formatter, "forced-priority HIR facts: {source}"),
            Self::CaptureErasureNotProven => formatter
                .write_str("forced-priority whole-match reducer lacks a capture-erasure proof"),
            Self::MissingRouteProof { execution, proof } => write!(
                formatter,
                "forced-priority route {execution:?} lacks required HIR proof {proof:?}"
            ),
            Self::Lower(source) => write!(formatter, "forced-priority lowering: {source}"),
            Self::NormalizedLoweringRequiresIntrinsicLength {
                normalized_repetitions,
            } => write!(
                formatter,
                "forced-priority lowering normalized {normalized_repetitions} nullable root repetitions, but the immutable preparer requires a declared HIR width"
            ),
            Self::SourceOwnerResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "forced-priority syntax owner needs {needed} {resource:?}, exceeding {limit}"
            ),
            Self::SourceOwnerAlreadyBound => {
                formatter.write_str("forced-priority syntax request owner was already bound")
            }
            Self::BridgeResourceLimit {
                resource,
                needed,
                limit,
            } => write!(
                formatter,
                "forced-priority bridge needs {needed} {resource}, exceeding {limit}"
            ),
            Self::BridgeArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "forced-priority bridge overflow computing {computation}"
                )
            }
            Self::BridgeAllocationFailed { bytes } => write!(
                formatter,
                "forced-priority bridge could not allocate {bytes} action bytes"
            ),
            Self::InvalidAcceptTerminalCount { terminals } => write!(
                formatter,
                "forced-priority single-pattern lowering emitted {terminals} accept terminals"
            ),
            Self::Automaton(source) => {
                write!(formatter, "forced-priority automaton validation: {source}")
            }
            Self::Preparation(source) => {
                write!(formatter, "forced-priority route preparation: {source}")
            }
            Self::BuildReportNotClosed => {
                formatter.write_str("forced-priority build report did not close")
            }
        }
    }
}

impl std::error::Error for PriorityAggregateBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(source) => Some(source),
            Self::Facts(source) => Some(source),
            Self::Lower(source) => Some(source),
            Self::Automaton(source) => Some(source),
            Self::Preparation(source) => Some(source),
            Self::NonRustCanonicalPattern
            | Self::UnsupportedBytesEmptyProgress { .. }
            | Self::UnsupportedExecution { .. }
            | Self::CaptureErasureNotProven
            | Self::MissingRouteProof { .. }
            | Self::NormalizedLoweringRequiresIntrinsicLength { .. }
            | Self::SourceOwnerResourceLimit { .. }
            | Self::SourceOwnerAlreadyBound
            | Self::BridgeResourceLimit { .. }
            | Self::BridgeArithmeticOverflow { .. }
            | Self::BridgeAllocationFailed { .. }
            | Self::InvalidAcceptTerminalCount { .. }
            | Self::BuildReportNotClosed => None,
        }
    }
}

/// Successful component ledgers for one explicit forced construction.
#[derive(Debug, Eq, PartialEq)]
pub struct PriorityAggregateBuildReport {
    schema_version: u32,
    accounting_id: &'static str,
    syntax: PriorityAggregateSyntaxEvidence,
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: PriorityAggregateBuildLimits,
    facts: PriorityAggregateFactReceipt,
    lowering: LowerStats,
    automaton: PlanStats,
    bridge: PriorityAggregateBridgeAccounting,
    pattern_action: PatternAction,
    empty_progress: EmptyMatchProgress,
    line_terminator: u8,
    declared_match_length: MatchLengthProof,
    route_proof: PriorityAggregateRouteProof,
    kernel: PriorityExecutionKernel,
    static_reducer_retention_bytes: Option<usize>,
    preparation: PreparationAccounting,
}

impl PriorityAggregateBuildReport {
    #[must_use]
    pub const fn syntax(&self) -> &PriorityAggregateSyntaxEvidence {
        &self.syntax
    }

    #[must_use]
    pub const fn operation(&self) -> PriorityAggregateOperation {
        self.operation
    }

    #[must_use]
    pub const fn execution(&self) -> ForcedExecution {
        self.execution
    }

    #[must_use]
    pub const fn target(&self) -> PriorityTarget {
        self.target
    }

    #[must_use]
    pub const fn limits(&self) -> PriorityAggregateBuildLimits {
        self.limits
    }

    #[must_use]
    pub const fn facts(&self) -> PriorityAggregateFactReceipt {
        self.facts
    }

    #[must_use]
    pub const fn lowering(&self) -> LowerStats {
        self.lowering
    }

    #[must_use]
    pub const fn automaton(&self) -> PlanStats {
        self.automaton
    }

    #[must_use]
    pub const fn bridge(&self) -> PriorityAggregateBridgeAccounting {
        self.bridge
    }

    #[must_use]
    pub const fn pattern_action(&self) -> PatternAction {
        self.pattern_action
    }

    #[must_use]
    pub const fn empty_progress(&self) -> EmptyMatchProgress {
        self.empty_progress
    }

    #[must_use]
    pub const fn line_terminator(&self) -> u8 {
        self.line_terminator
    }

    #[must_use]
    pub const fn declared_match_length(&self) -> MatchLengthProof {
        self.declared_match_length
    }

    #[must_use]
    pub const fn route_proof(&self) -> PriorityAggregateRouteProof {
        self.route_proof
    }

    /// Concrete prepared kernel authenticated beneath the requested route.
    #[must_use]
    pub const fn kernel(&self) -> PriorityExecutionKernel {
        self.kernel
    }

    /// Exact source-independent reducer suffix retention used by the concrete
    /// prepared plan, when the plan has a finite static ring.
    #[must_use]
    pub const fn static_reducer_retention_bytes(&self) -> Option<usize> {
        self.static_reducer_retention_bytes
    }

    #[must_use]
    pub const fn preparation(&self) -> PreparationAccounting {
        self.preparation
    }

    /// Whether every independently meaningful successful component closes.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the report deliberately keeps all independent source, fact, bridge, and preparation closure checks adjacent"
    )]
    pub fn closes(&self) -> bool {
        let route_proof_matches = match (self.execution, self.route_proof, self.kernel) {
            (
                ForcedExecution::Sparse,
                PriorityAggregateRouteProof::Sparse,
                PriorityExecutionKernel::SparseReverse,
            ) => self.static_reducer_retention_bytes.is_none(),
            (
                ForcedExecution::FiniteHorizon,
                PriorityAggregateRouteProof::FiniteHorizon { maximum_bytes },
                PriorityExecutionKernel::FiniteHorizonReverse,
            ) => {
                self.facts.finite_decision_horizon()
                    == PriorityAggregateUsizeProof::Proven(maximum_bytes)
                    && matches!(
                        self.facts.width(),
                        CheckedWidth::NonEmpty {
                            maximum: Some(retention_bytes),
                            ..
                        } if retention_bytes <= maximum_bytes
                    )
                    && self.static_reducer_retention_bytes == self.facts.width().maximum()
            }
            (
                ForcedExecution::FiniteHorizon,
                PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
                    maximum_match_bytes,
                },
                PriorityExecutionKernel::FiniteHorizonReverse,
            ) => {
                self.facts.width().maximum() == Some(maximum_match_bytes)
                    && self.facts.finite_decision_horizon() == PriorityAggregateUsizeProof::Unknown
                    && self
                        .facts
                        .assertion_context()
                        .is_proven_against(self.facts.prospective(), self.limits.facts)
                    && self.facts.assertion_context().requires_stream_end()
                    && self.static_reducer_retention_bytes == Some(maximum_match_bytes)
            }
            (
                ForcedExecution::FiniteHorizon,
                PriorityAggregateRouteProof::InputBoundedHorizon,
                PriorityExecutionKernel::InputBoundedReverse,
            ) => {
                self.facts
                    .assertion_context()
                    .is_proven_against(self.facts.prospective(), self.limits.facts)
                    && matches!(
                        self.facts.width(),
                        CheckedWidth::NonEmpty { maximum: None, .. }
                    )
                    && self.static_reducer_retention_bytes.is_none()
            }
            (
                ForcedExecution::FullDfa,
                PriorityAggregateRouteProof::Deterministic,
                PriorityExecutionKernel::FullDfa,
            )
            | (
                ForcedExecution::LazyDfa,
                PriorityAggregateRouteProof::Deterministic,
                PriorityExecutionKernel::LazyDfa,
            ) => {
                matches!(
                    self.facts.subset_determinism(),
                    PriorityAggregateDeterminismProof::Proven(_)
                ) && matches!(
                    self.facts.width(),
                    CheckedWidth::NonEmpty {
                        minimum,
                        maximum: Some(maximum)
                    } if minimum == maximum && maximum != 0
                ) && self.static_reducer_retention_bytes.is_none()
            }
            (
                ForcedExecution::FullDfa,
                PriorityAggregateRouteProof::AssertionContext { minimum_bytes },
                PriorityExecutionKernel::FullTaggedReverse,
            )
            | (
                ForcedExecution::LazyDfa,
                PriorityAggregateRouteProof::AssertionContext { minimum_bytes },
                PriorityExecutionKernel::LazyTaggedReverse,
            ) => {
                self.facts
                    .assertion_context()
                    .is_proven_against(self.facts.prospective(), self.limits.facts)
                    && matches!(
                        self.facts.width(),
                        CheckedWidth::NonEmpty { minimum, .. } if minimum == minimum_bytes
                    )
                    && self.static_reducer_retention_bytes.is_none()
            }
            (
                ForcedExecution::FullDfa,
                PriorityAggregateRouteProof::AssertionContext { minimum_bytes },
                PriorityExecutionKernel::FullDfa,
            )
            | (
                ForcedExecution::LazyDfa,
                PriorityAggregateRouteProof::AssertionContext { minimum_bytes },
                PriorityExecutionKernel::LazyDfa,
            ) => {
                self.facts
                    .assertion_context()
                    .is_proven_against(self.facts.prospective(), self.limits.facts)
                    && matches!(
                        self.facts.width(),
                        CheckedWidth::NonEmpty {
                            minimum,
                            maximum: Some(maximum)
                        } if minimum == minimum_bytes && minimum == maximum && minimum != 0
                    )
                    && self.static_reducer_retention_bytes.is_none()
            }
            _ => false,
        };
        let syntax_fact_identity = self.facts.operation().erases_captures()
            && self.facts.capture_count() == 0
            && u64::try_from(self.facts.actual().hir_nodes())
                == Ok(self.syntax.summary().hir_nodes);
        let lowering_automaton_identity = self.lowering.erased_captures()
            == usize::try_from(self.syntax.summary().captures).unwrap_or(usize::MAX)
            && u64::try_from(self.lowering.normalized_nullable_repetitions())
                .is_ok_and(|count| count <= self.syntax.summary().hir_nodes)
            && !self.lowering.utf8_start_guarded()
            && self.lowering.states() == self.automaton.states()
            && self.lowering.edges() == self.automaton.edges()
            && self
                .automaton
                .zero_width_edges()
                .checked_add(self.automaton.consuming_edges())
                == Some(self.automaton.edges())
            && self.lowering.work() <= self.limits.lowering.max_work
            && self.lowering.peak_stack_items() <= self.limits.lowering.max_stack_items
            && self.automaton.states() <= self.limits.lowering.automata.max_states
            && self.automaton.edges() <= self.limits.lowering.automata.max_edges
            && self.automaton.storage_bytes() <= self.limits.lowering.automata.max_storage_bytes
            && self.automaton.validation_work()
                <= self.limits.lowering.automata.max_validation_work;
        let expected_bridge_work = u64::try_from(self.automaton.states())
            .ok()
            .and_then(|states| states.checked_mul(2));
        let expected_action_bytes = self
            .automaton
            .states()
            .checked_mul(size_of::<Option<PatternAction>>());
        let bridge_identity = expected_bridge_work == Some(self.bridge.work())
            && expected_action_bytes == Some(self.bridge.action_bytes())
            && self.bridge.peak_bytes() == self.bridge.action_bytes()
            && self.bridge.pattern_terminals() == 1
            && self.bridge.allocation_attempts() == 1
            && self.preparation.pattern_terminals == self.bridge.pattern_terminals();
        let base_prepared_bytes = self
            .automaton
            .storage_bytes()
            .checked_add(self.bridge.action_bytes());
        self.schema_version == PRIORITY_AGGREGATE_SCHEMA_VERSION
            && self.accounting_id == PRIORITY_AGGREGATE_ACCOUNTING_ID
            && self.syntax.closes()
            && self
                .syntax
                .source_owner()
                .closes_against(self.limits.source_owner)
            && self.facts.operation() == self.operation.fact_operation(self.execution)
            && self.facts.capture_erasure_permitted()
            && self.facts.closes_against(self.limits.facts)
            && syntax_fact_identity
            && lowering_automaton_identity
            && self.declared_match_length == match_length_from_width(self.facts.width())
            && route_proof_matches
            && validate_requested_target(self.execution, self.target).is_ok()
            && validate_selected_kernel(self.execution, self.target, self.kernel).is_ok()
            && self.bridge.closes_against(self.limits.bridge)
            && bridge_identity
            && self.pattern_action == single_pattern_action()
            && self.empty_progress == EmptyMatchProgress::Byte
            && rust_bytes_line_terminator(self.syntax.key()) == Some(self.line_terminator)
            && preparation_closes_against(self.preparation, self.limits.preparation)
            && base_prepared_bytes.is_some_and(|bytes| bytes <= self.preparation.persistent_bytes)
    }
}

fn rust_bytes_line_terminator(key: &CacheKey) -> Option<u8> {
    match &key.profile {
        CompatibilityProfile::RustBytes(profile) => Some(profile.options.line_terminator),
        CompatibilityProfile::RustText(_) | CompatibilityProfile::Re2(_) => None,
    }
}

fn preparation_closes_against(
    accounting: PreparationAccounting,
    limits: PreparationLimits,
) -> bool {
    let prospective = accounting.prospective;
    prospective.pattern_terminals == accounting.pattern_terminals
        && prospective.dfa_states == accounting.dfa_states
        && prospective.transition_cells == accounting.transition_cells
        && prospective.subset_items == accounting.subset_items
        && prospective.tagged_dispatch_states == accounting.tagged_dispatch_states
        && prospective.tagged_dispatch_cells == accounting.tagged_dispatch_cells
        && prospective.tagged_candidate_items == accounting.tagged_candidate_items
        && prospective.work == accounting.work
        && prospective.persistent_bytes == accounting.persistent_bytes
        && prospective.peak_bytes == accounting.peak_bytes
        && prospective.allocation_attempts == accounting.allocation_attempts
        && prospective.pattern_terminals <= limits.max_pattern_terminals
        && prospective.dfa_states <= limits.max_dfa_states
        && prospective.transition_cells <= limits.max_transition_cells
        && prospective.subset_items <= limits.max_subset_items
        && prospective.tagged_dispatch_states <= limits.max_tagged_dispatch_states
        && prospective.tagged_dispatch_cells <= limits.max_tagged_dispatch_cells
        && prospective.tagged_candidate_items <= limits.max_tagged_candidate_items
        && prospective.work <= limits.max_work
        && prospective.persistent_bytes <= limits.max_persistent_bytes
        && prospective.peak_bytes <= limits.max_peak_bytes
        && prospective.allocation_attempts <= limits.max_allocation_attempts
}

/// Builder whose inputs are limited to source, profile, and checked limits.
#[derive(Clone, Debug)]
pub struct PriorityAggregateBuilder {
    pattern: String,
    profile: RustProfile,
    limits: PriorityAggregateBuildLimits,
}

impl PriorityAggregateBuilder {
    /// Start with the pinned single-pattern Rust bytes profile.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: PriorityAggregateBuildLimits::default(),
        }
    }

    /// Bind the complete pinned Rust constructor profile.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Replace all syntax, fact, lowering, bridge, and preparation limits.
    #[must_use]
    pub const fn limits(mut self, limits: PriorityAggregateBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Prepare exactly `execution` for complete Count.
    pub fn build_count(
        self,
        execution: ForcedExecution,
        target: PriorityTarget,
    ) -> Result<PriorityAggregateCountRegex, PriorityAggregateBuildError> {
        let mut common = self.build_common(PriorityAggregateOperation::Count, execution, target)?;
        let automata = common
            .automata
            .take()
            .expect("forced-priority common build retains its unpublished automaton");
        let plan = automata
            .prepare_forced::<DirectCount>(execution, target, common.limits.preparation)
            .map_err(PriorityAggregateBuildError::Preparation)?;
        validate_selected_kernel(execution, target, plan.kernel())?;
        let report = common.finish(
            plan.preparation_accounting(),
            plan.kernel(),
            plan.static_reducer_retention_bytes(),
        );
        if !report.closes() {
            return Err(PriorityAggregateBuildError::BuildReportNotClosed);
        }
        Ok(PriorityAggregateCountRegex { plan, report })
    }

    /// Prepare exactly `execution` for complete `SpanSum`.
    pub fn build_span_sum(
        self,
        execution: ForcedExecution,
        target: PriorityTarget,
    ) -> Result<PriorityAggregateSpanSumRegex, PriorityAggregateBuildError> {
        let mut common =
            self.build_common(PriorityAggregateOperation::SpanSum, execution, target)?;
        let automata = common
            .automata
            .take()
            .expect("forced-priority common build retains its unpublished automaton");
        let plan = automata
            .prepare_forced::<DirectSpanSum>(execution, target, common.limits.preparation)
            .map_err(PriorityAggregateBuildError::Preparation)?;
        validate_selected_kernel(execution, target, plan.kernel())?;
        let report = common.finish(
            plan.preparation_accounting(),
            plan.kernel(),
            plan.static_reducer_retention_bytes(),
        );
        if !report.closes() {
            return Err(PriorityAggregateBuildError::BuildReportNotClosed);
        }
        Ok(PriorityAggregateSpanSumRegex { plan, report })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the forced bridge keeps parse, facts, lowering, sidecar, and publication in one auditable order"
    )]
    fn build_common(
        self,
        operation: PriorityAggregateOperation,
        execution: ForcedExecution,
        target: PriorityTarget,
    ) -> Result<CommonBuild, PriorityAggregateBuildError> {
        validate_requested_target(execution, target)?;
        let bytes_empty_progress = bytes_empty_progress_is_byte(&self.profile);
        let profile = CompatibilityProfile::RustBytes(self.profile.clone());
        let mut request = ParseRequest::rust(self.pattern, profile)
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety);
        let source_owner = bind_source_owner(&mut request, self.limits.source_owner)?;
        let attempt =
            fre_syntax::parse_attempt(request).map_err(PriorityAggregateBuildError::Syntax)?;
        let (record, receipt) = attempt.into_parts();
        let fre_syntax::ParseRecord {
            key,
            admission_status,
            summary,
            pattern,
        } = record;
        let CanonicalPattern::Rust(rust) = pattern else {
            return Err(PriorityAggregateBuildError::NonRustCanonicalPattern);
        };
        let syntax = PriorityAggregateSyntaxEvidence {
            key,
            admission: admission_status,
            summary,
            receipt,
            source_owner,
        };
        if !bytes_empty_progress {
            return Err(PriorityAggregateBuildError::UnsupportedBytesEmptyProgress { syntax });
        }
        let fact_operation = operation.fact_operation(execution);
        let facts = analyze_facts(&rust, fact_operation, self.limits.facts)
            .map_err(PriorityAggregateBuildError::Facts)?;
        if !facts.captures().erasure_permitted() {
            return Err(PriorityAggregateBuildError::CaptureErasureNotProven);
        }
        let route_proof = route_proof(&facts, execution)?;
        let fact_receipt = PriorityAggregateFactReceipt::from_facts(&facts);
        let declared_match_length = match_length_from_width(facts.width());
        let lowered = lower_raw(&rust, OperationSemantics::CaptureFree, self.limits.lowering)
            .map_err(PriorityAggregateBuildError::Lower)?;
        let lowering = lowered.stats();
        let raw = lowered.into_plan();
        let action_shape = inspect_single_pattern_action_shape(&raw.roles, self.limits.bridge)?;
        let automaton = Automaton::from_raw(raw, self.limits.lowering.automata)
            .map_err(PriorityAggregateBuildError::Automaton)?
            .with_line_terminator(self.profile.options.line_terminator);
        let (actions, bridge) = build_single_pattern_actions(action_shape, self.limits.bridge)?;
        let automaton_stats = automaton.stats();
        let automata = PriorityAutomataFacts::new(
            automaton,
            actions,
            declared_match_length,
            EmptyMatchProgress::Byte,
        );
        Ok(CommonBuild {
            syntax,
            operation,
            execution,
            target,
            limits: self.limits,
            facts: fact_receipt,
            lowering,
            automaton: automaton_stats,
            bridge,
            pattern_action: single_pattern_action(),
            empty_progress: EmptyMatchProgress::Byte,
            line_terminator: self.profile.options.line_terminator,
            declared_match_length,
            route_proof,
            automata: Some(automata),
        })
    }
}

fn bytes_empty_progress_is_byte(profile: &RustProfile) -> bool {
    match &profile.constructor {
        RustConstructor::RegexBuilder {
            bytes_utf8_empty, ..
        } => !bytes_utf8_empty,
        RustConstructor::RebarMeta { utf8_empty, .. } => !utf8_empty,
        RustConstructor::RegexSetBuilder { .. } => false,
    }
}

fn validate_requested_target(
    execution: ForcedExecution,
    target: PriorityTarget,
) -> Result<(), PriorityAggregateBuildError> {
    if !target.supports_execution(execution) {
        return Err(PriorityAggregateBuildError::Preparation(
            PreparationError::UnsupportedTarget { execution },
        ));
    }
    let required = ActionCapabilities::MATCH.union(ActionCapabilities::DIRECT_REDUCE);
    if !target.actions.contains(required) {
        return Err(PriorityAggregateBuildError::Preparation(
            PreparationError::UnsupportedTargetAction {
                required,
                available: target.actions,
            },
        ));
    }
    Ok(())
}

fn validate_selected_kernel(
    execution: ForcedExecution,
    target: PriorityTarget,
    kernel: PriorityExecutionKernel,
) -> Result<(), PriorityAggregateBuildError> {
    if !target.supports_kernel(kernel) {
        return Err(PriorityAggregateBuildError::Preparation(
            PreparationError::UnsupportedTargetKernel { execution, kernel },
        ));
    }
    Ok(())
}

fn bind_source_owner(
    request: &mut ParseRequest,
    limits: PriorityAggregateSourceOwnerLimits,
) -> Result<PriorityAggregateSourceOwnerAccounting, PriorityAggregateBuildError> {
    let allocation_bytes = ParseRequest::attempt_source_owner_allocation_bytes();
    let handle_bytes = ParseRequest::attempt_source_owner_handle_bytes()
        .checked_mul(2)
        .ok_or(PriorityAggregateBuildError::BridgeArithmeticOverflow {
            computation: "syntax source-owner handle bytes",
        })?;
    for (resource, needed, limit) in [
        (
            PriorityAggregateSourceOwnerResource::AllocationBytes,
            allocation_bytes,
            limits.max_allocation_bytes,
        ),
        (
            PriorityAggregateSourceOwnerResource::HandleBytes,
            handle_bytes,
            limits.max_handle_bytes,
        ),
        (
            PriorityAggregateSourceOwnerResource::AllocationAttempts,
            1,
            limits.max_allocation_attempts,
        ),
    ] {
        if needed > limit {
            return Err(PriorityAggregateBuildError::SourceOwnerResourceLimit {
                resource,
                needed,
                limit,
            });
        }
    }
    let bound = request
        .bind_attempt_source_owner()
        .ok_or(PriorityAggregateBuildError::SourceOwnerAlreadyBound)?;
    if bound != allocation_bytes {
        return Err(PriorityAggregateBuildError::BridgeArithmeticOverflow {
            computation: "syntax source-owner allocation identity",
        });
    }
    Ok(PriorityAggregateSourceOwnerAccounting {
        allocation_bytes,
        handle_bytes,
        allocation_attempts: 1,
    })
}

fn route_proof(
    facts: &HirFacts,
    execution: ForcedExecution,
) -> Result<PriorityAggregateRouteProof, PriorityAggregateBuildError> {
    match execution {
        ForcedExecution::Sparse => Ok(PriorityAggregateRouteProof::Sparse),
        ForcedExecution::FiniteHorizon => {
            match facts.width() {
                CheckedWidth::NonEmpty { maximum: None, .. } => {
                    match facts.assertions().possible() {
                        FactProof::Proven(_) => {
                            Ok(PriorityAggregateRouteProof::InputBoundedHorizon)
                        }
                        FactProof::Unknown | FactProof::Refused(_) => {
                            Err(PriorityAggregateBuildError::MissingRouteProof {
                                execution,
                                proof: PriorityAggregateProofRefusal::AssertionContext,
                            })
                        }
                    }
                }
                CheckedWidth::NonEmpty {
                    maximum: Some(maximum_match_bytes),
                    ..
                } => match facts.finite_decision_horizon_bytes() {
                    FactProof::Proven(maximum_bytes) if maximum_match_bytes <= *maximum_bytes => {
                        Ok(PriorityAggregateRouteProof::FiniteHorizon {
                            maximum_bytes: *maximum_bytes,
                        })
                    }
                    FactProof::Proven(_) => Err(PriorityAggregateBuildError::MissingRouteProof {
                        execution,
                        proof: PriorityAggregateProofRefusal::FiniteDecisionHorizonMatchesWidth,
                    }),
                    // A stream-end assertion cannot make a streaming decision,
                    // but the complete-source executor still has a static
                    // match-width ring. Keep that structural fact separate
                    // from whether its optional positioned context is present.
                    FactProof::Unknown if facts.assertions().requires_stream_end() => {
                        match facts.assertions().possible() {
                            FactProof::Proven(_) => {
                                Ok(PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
                                    maximum_match_bytes,
                                })
                            }
                            FactProof::Unknown | FactProof::Refused(_) => {
                                Err(PriorityAggregateBuildError::MissingRouteProof {
                                    execution,
                                    proof: PriorityAggregateProofRefusal::AssertionContext,
                                })
                            }
                        }
                    }
                    FactProof::Unknown | FactProof::Refused(_) => {
                        Err(PriorityAggregateBuildError::MissingRouteProof {
                            execution,
                            proof: PriorityAggregateProofRefusal::FiniteDecisionHorizon,
                        })
                    }
                },
                CheckedWidth::EmptyLanguage => {
                    Err(PriorityAggregateBuildError::MissingRouteProof {
                        execution,
                        proof: PriorityAggregateProofRefusal::FiniteDecisionHorizon,
                    })
                }
            }
        }
        ForcedExecution::FullDfa | ForcedExecution::LazyDfa => {
            let CheckedWidth::NonEmpty { minimum, .. } = facts.width() else {
                return Err(PriorityAggregateBuildError::MissingRouteProof {
                    execution,
                    proof: PriorityAggregateProofRefusal::ExactNonEmptyMatchWidth,
                });
            };
            match facts.assertions().possible() {
                FactProof::Proven(_) => Ok(PriorityAggregateRouteProof::AssertionContext {
                    minimum_bytes: minimum,
                }),
                FactProof::Unknown | FactProof::Refused(_) => {
                    Err(PriorityAggregateBuildError::MissingRouteProof {
                        execution,
                        proof: PriorityAggregateProofRefusal::AssertionContext,
                    })
                }
            }
        }
        _ => Err(PriorityAggregateBuildError::UnsupportedExecution { execution }),
    }
}

fn match_length_from_width(width: fre_lower::CheckedWidth) -> MatchLengthProof {
    match width {
        fre_lower::CheckedWidth::EmptyLanguage => MatchLengthProof::Empty,
        fre_lower::CheckedWidth::NonEmpty {
            minimum: _,
            maximum: None,
        } => MatchLengthProof::Unbounded,
        fre_lower::CheckedWidth::NonEmpty {
            minimum,
            maximum: Some(maximum),
        } if minimum == maximum => MatchLengthProof::Exact(minimum),
        fre_lower::CheckedWidth::NonEmpty {
            minimum,
            maximum: Some(maximum),
        } => MatchLengthProof::Finite {
            minimum_bytes: minimum,
            maximum_bytes: maximum,
        },
    }
}

#[derive(Clone, Copy)]
struct SinglePatternActionShape {
    states: usize,
    accept: usize,
    prospective: PriorityAggregateBridgeProspective,
}

fn inspect_single_pattern_action_shape(
    roles: &[StateRole],
    limits: PriorityAggregateBridgeLimits,
) -> Result<SinglePatternActionShape, PriorityAggregateBuildError> {
    let states_work = u64::try_from(roles.len()).map_err(|_| {
        PriorityAggregateBuildError::BridgeArithmeticOverflow {
            computation: "action-sidecar work",
        }
    })?;
    let work = states_work.checked_mul(2).ok_or(
        PriorityAggregateBuildError::BridgeArithmeticOverflow {
            computation: "action-sidecar inspection and fill work",
        },
    )?;
    let action_bytes = roles
        .len()
        .checked_mul(size_of::<Option<PatternAction>>())
        .ok_or(PriorityAggregateBuildError::BridgeArithmeticOverflow {
            computation: "action-sidecar bytes",
        })?;
    let prospective = PriorityAggregateBridgeProspective {
        work,
        action_bytes,
        peak_bytes: action_bytes,
        pattern_terminals: 1,
        allocation_attempts: 1,
    };
    check_bridge_limit(PriorityAggregateBridgeResource::Work, work, limits.max_work)?;
    check_bridge_limit(
        PriorityAggregateBridgeResource::ActionBytes,
        usize_to_u64(action_bytes, "action-sidecar byte limit")?,
        usize_to_u64(limits.max_action_bytes, "action-sidecar byte limit")?,
    )?;
    check_bridge_limit(
        PriorityAggregateBridgeResource::PeakBytes,
        usize_to_u64(action_bytes, "action-sidecar peak limit")?,
        usize_to_u64(limits.max_peak_bytes, "action-sidecar peak limit")?,
    )?;
    check_bridge_limit(
        PriorityAggregateBridgeResource::PatternTerminals,
        1,
        usize_to_u64(
            limits.max_pattern_terminals,
            "action-sidecar terminal limit",
        )?,
    )?;
    check_bridge_limit(
        PriorityAggregateBridgeResource::AllocationAttempts,
        1,
        usize_to_u64(
            limits.max_allocation_attempts,
            "action-sidecar allocation limit",
        )?,
    )?;

    let mut terminals = 0usize;
    let mut accept = None;
    for (index, role) in roles.iter().enumerate() {
        if *role == StateRole::Accept {
            terminals = terminals.checked_add(1).ok_or(
                PriorityAggregateBuildError::BridgeArithmeticOverflow {
                    computation: "accept-terminal count",
                },
            )?;
            accept = Some(index);
        }
    }
    if terminals != 1 {
        return Err(PriorityAggregateBuildError::InvalidAcceptTerminalCount { terminals });
    }
    let accept =
        accept.ok_or(PriorityAggregateBuildError::InvalidAcceptTerminalCount { terminals })?;
    Ok(SinglePatternActionShape {
        states: roles.len(),
        accept,
        prospective,
    })
}

fn build_single_pattern_actions(
    shape: SinglePatternActionShape,
    _limits: PriorityAggregateBridgeLimits,
) -> Result<
    (
        Vec<Option<PatternAction>>,
        PriorityAggregateBridgeAccounting,
    ),
    PriorityAggregateBuildError,
> {
    let action = single_pattern_action();
    let mut actions = Vec::new();
    actions.try_reserve_exact(shape.states).map_err(|_| {
        PriorityAggregateBuildError::BridgeAllocationFailed {
            bytes: shape.prospective.action_bytes,
        }
    })?;
    for index in 0..shape.states {
        actions.push((index == shape.accept).then_some(action));
    }
    if actions.capacity() != actions.len() {
        return Err(PriorityAggregateBuildError::BridgeAllocationFailed {
            bytes: actions
                .capacity()
                .saturating_mul(size_of::<Option<PatternAction>>()),
        });
    }
    let accounting = PriorityAggregateBridgeAccounting {
        prospective: shape.prospective,
        work: shape.prospective.work,
        action_bytes: shape.prospective.action_bytes,
        peak_bytes: shape.prospective.peak_bytes,
        pattern_terminals: 1,
        allocation_attempts: 1,
    };
    Ok((actions, accounting))
}

const fn single_pattern_action() -> PatternAction {
    PatternAction::new(
        PatternOrdinal::new(0),
        ActionCapabilities::MATCH.union(ActionCapabilities::DIRECT_REDUCE),
    )
}

fn usize_to_u64(
    value: usize,
    computation: &'static str,
) -> Result<u64, PriorityAggregateBuildError> {
    u64::try_from(value)
        .map_err(|_| PriorityAggregateBuildError::BridgeArithmeticOverflow { computation })
}

fn check_bridge_limit(
    resource: PriorityAggregateBridgeResource,
    needed: u64,
    limit: u64,
) -> Result<(), PriorityAggregateBuildError> {
    if needed > limit {
        return Err(PriorityAggregateBuildError::BridgeResourceLimit {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

struct CommonBuild {
    syntax: PriorityAggregateSyntaxEvidence,
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: PriorityAggregateBuildLimits,
    facts: PriorityAggregateFactReceipt,
    lowering: LowerStats,
    automaton: PlanStats,
    bridge: PriorityAggregateBridgeAccounting,
    pattern_action: PatternAction,
    empty_progress: EmptyMatchProgress,
    line_terminator: u8,
    declared_match_length: MatchLengthProof,
    route_proof: PriorityAggregateRouteProof,
    automata: Option<PriorityAutomataFacts>,
}

impl CommonBuild {
    fn finish(
        self,
        preparation: PreparationAccounting,
        kernel: PriorityExecutionKernel,
        static_reducer_retention_bytes: Option<usize>,
    ) -> PriorityAggregateBuildReport {
        PriorityAggregateBuildReport {
            schema_version: PRIORITY_AGGREGATE_SCHEMA_VERSION,
            accounting_id: PRIORITY_AGGREGATE_ACCOUNTING_ID,
            syntax: self.syntax,
            operation: self.operation,
            execution: self.execution,
            target: self.target,
            limits: self.limits,
            facts: self.facts,
            lowering: self.lowering,
            automaton: self.automaton,
            bridge: self.bridge,
            pattern_action: self.pattern_action,
            empty_progress: self.empty_progress,
            line_terminator: self.line_terminator,
            declared_match_length: self.declared_match_length,
            route_proof: self.route_proof,
            kernel,
            static_reducer_retention_bytes,
            preparation,
        }
    }
}

/// Terminal execution failure with the exact facade request retained.
///
/// The immutable leaf currently returns only its typed error after a failed
/// execution, so this facade does not claim unavailable leaf prospective or
/// partial-actual evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorityAggregateRunError {
    pub operation: PriorityAggregateOperation,
    pub execution: ForcedExecution,
    pub limits: PriorityAggregateRunLimits,
    pub source: PriorityAggregateRunFailure,
}

impl fmt::Display for PriorityAggregateRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "forced-priority {:?}/{:?} execution: {}",
            self.operation, self.execution, self.source
        )
    }
}

impl std::error::Error for PriorityAggregateRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Exact facade output refusal or leaf execution terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PriorityAggregateRunFailure {
    BuildReportNotClosed,
    BuildPlanIdentityMismatch,
    ExecutionReceiptNotClosed,
    OutputLimit {
        operation: PriorityAggregateOperation,
        needed: u64,
        limit: u64,
    },
    Execution(ReduceError),
}

impl fmt::Display for PriorityAggregateRunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuildReportNotClosed => {
                formatter.write_str("forced-priority build report no longer closes")
            }
            Self::BuildPlanIdentityMismatch => formatter
                .write_str("forced-priority prepared plan no longer matches its build report"),
            Self::ExecutionReceiptNotClosed => {
                formatter.write_str("forced-priority execution receipt did not close")
            }
            Self::OutputLimit {
                operation,
                needed,
                limit,
            } => write!(
                formatter,
                "forced-priority {operation:?} output bound {needed} exceeds {limit}"
            ),
            Self::Execution(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for PriorityAggregateRunFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Execution(source) => Some(source),
            Self::BuildReportNotClosed
            | Self::BuildPlanIdentityMismatch
            | Self::ExecutionReceiptNotClosed
            | Self::OutputLimit { .. } => None,
        }
    }
}

/// Execution limits plus the typed artifact's pre-source output ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriorityAggregateRunLimits {
    pub execution: DirectReduceLimits,
    pub max_output: u64,
}

impl PriorityAggregateRunLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            execution: DirectReduceLimits::unlimited(),
            max_output: u64::MAX,
        }
    }
}

impl Default for PriorityAggregateRunLimits {
    fn default() -> Self {
        Self {
            execution: DirectReduceLimits::default(),
            max_output: u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PriorityAggregateExecutionBuildBinding {
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: PriorityAggregateBuildLimits,
    facts: PriorityAggregateFactReceipt,
    lowering: LowerStats,
    automaton: PlanStats,
    bridge: PriorityAggregateBridgeAccounting,
    pattern_action: PatternAction,
    empty_progress: EmptyMatchProgress,
    line_terminator: u8,
    declared_match_length: MatchLengthProof,
    route_proof: PriorityAggregateRouteProof,
    kernel: PriorityExecutionKernel,
    static_reducer_retention_bytes: Option<usize>,
    preparation: PreparationAccounting,
    source_owner: PriorityAggregateSourceOwnerAccounting,
    syntax_source_bytes: u64,
    syntax_source_capacity_bytes: usize,
    syntax_hir_nodes: u64,
    syntax_captures: u64,
    syntax_line_terminator: Option<u8>,
}

impl PriorityAggregateExecutionBuildBinding {
    fn from_report(report: &PriorityAggregateBuildReport) -> Self {
        Self {
            operation: report.operation,
            execution: report.execution,
            target: report.target,
            limits: report.limits,
            facts: report.facts,
            lowering: report.lowering,
            automaton: report.automaton,
            bridge: report.bridge,
            pattern_action: report.pattern_action,
            empty_progress: report.empty_progress,
            line_terminator: report.line_terminator,
            declared_match_length: report.declared_match_length,
            route_proof: report.route_proof,
            kernel: report.kernel,
            static_reducer_retention_bytes: report.static_reducer_retention_bytes,
            preparation: report.preparation,
            source_owner: report.syntax.source_owner,
            syntax_source_bytes: report.syntax.receipt.identity.source_bytes,
            syntax_source_capacity_bytes: report.syntax.receipt.identity.source_capacity_bytes(),
            syntax_hir_nodes: report.syntax.summary.hir_nodes,
            syntax_captures: report.syntax.summary.captures,
            syntax_line_terminator: rust_bytes_line_terminator(report.syntax.key()),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the private execution binding repeats the public route proof checks so retained receipts can authenticate independently"
    )]
    fn closes(self) -> bool {
        let route_matches = match (self.execution, self.route_proof, self.kernel) {
            (
                ForcedExecution::Sparse,
                PriorityAggregateRouteProof::Sparse,
                PriorityExecutionKernel::SparseReverse,
            ) => self.static_reducer_retention_bytes.is_none(),
            (
                ForcedExecution::FiniteHorizon,
                PriorityAggregateRouteProof::FiniteHorizon { maximum_bytes },
                PriorityExecutionKernel::FiniteHorizonReverse,
            ) => {
                self.facts.finite_decision_horizon()
                    == PriorityAggregateUsizeProof::Proven(maximum_bytes)
                    && matches!(
                        self.facts.width(),
                        CheckedWidth::NonEmpty {
                            maximum: Some(retention_bytes),
                            ..
                        } if retention_bytes <= maximum_bytes
                    )
                    && self.static_reducer_retention_bytes == self.facts.width().maximum()
            }
            (
                ForcedExecution::FiniteHorizon,
                PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
                    maximum_match_bytes,
                },
                PriorityExecutionKernel::FiniteHorizonReverse,
            ) => {
                self.facts.width().maximum() == Some(maximum_match_bytes)
                    && self.facts.finite_decision_horizon() == PriorityAggregateUsizeProof::Unknown
                    && self
                        .facts
                        .assertion_context()
                        .is_proven_against(self.facts.prospective(), self.limits.facts)
                    && self.facts.assertion_context().requires_stream_end()
                    && self.static_reducer_retention_bytes == Some(maximum_match_bytes)
            }
            (
                ForcedExecution::FiniteHorizon,
                PriorityAggregateRouteProof::InputBoundedHorizon,
                PriorityExecutionKernel::InputBoundedReverse,
            ) => {
                self.facts
                    .assertion_context()
                    .is_proven_against(self.facts.prospective(), self.limits.facts)
                    && matches!(
                        self.facts.width(),
                        CheckedWidth::NonEmpty { maximum: None, .. }
                    )
                    && self.static_reducer_retention_bytes.is_none()
            }
            (
                ForcedExecution::FullDfa,
                PriorityAggregateRouteProof::Deterministic,
                PriorityExecutionKernel::FullDfa,
            )
            | (
                ForcedExecution::LazyDfa,
                PriorityAggregateRouteProof::Deterministic,
                PriorityExecutionKernel::LazyDfa,
            ) => {
                matches!(
                    self.facts.subset_determinism(),
                    PriorityAggregateDeterminismProof::Proven(_)
                ) && matches!(
                    self.facts.width(),
                    CheckedWidth::NonEmpty {
                        minimum,
                        maximum: Some(maximum)
                    } if minimum == maximum && maximum != 0
                ) && self.static_reducer_retention_bytes.is_none()
            }
            (
                ForcedExecution::FullDfa,
                PriorityAggregateRouteProof::AssertionContext { minimum_bytes },
                PriorityExecutionKernel::FullTaggedReverse,
            )
            | (
                ForcedExecution::LazyDfa,
                PriorityAggregateRouteProof::AssertionContext { minimum_bytes },
                PriorityExecutionKernel::LazyTaggedReverse,
            ) => {
                self.facts
                    .assertion_context()
                    .is_proven_against(self.facts.prospective(), self.limits.facts)
                    && matches!(
                        self.facts.width(),
                        CheckedWidth::NonEmpty { minimum, .. } if minimum == minimum_bytes
                    )
                    && self.static_reducer_retention_bytes.is_none()
            }
            (
                ForcedExecution::FullDfa,
                PriorityAggregateRouteProof::AssertionContext { minimum_bytes },
                PriorityExecutionKernel::FullDfa,
            )
            | (
                ForcedExecution::LazyDfa,
                PriorityAggregateRouteProof::AssertionContext { minimum_bytes },
                PriorityExecutionKernel::LazyDfa,
            ) => {
                self.facts
                    .assertion_context()
                    .is_proven_against(self.facts.prospective(), self.limits.facts)
                    && matches!(
                        self.facts.width(),
                        CheckedWidth::NonEmpty {
                            minimum,
                            maximum: Some(maximum)
                        } if minimum == minimum_bytes && minimum == maximum && minimum != 0
                    )
                    && self.static_reducer_retention_bytes.is_none()
            }
            _ => false,
        };
        let expected_bridge_work = u64::try_from(self.automaton.states())
            .ok()
            .and_then(|states| states.checked_mul(2));
        let expected_action_bytes = self
            .automaton
            .states()
            .checked_mul(size_of::<Option<PatternAction>>());
        let source_capacity_closes = usize::try_from(self.syntax_source_bytes)
            .is_ok_and(|bytes| bytes <= self.syntax_source_capacity_bytes);
        self.facts.operation() == self.operation.fact_operation(self.execution)
            && self.facts.capture_erasure_permitted()
            && self.facts.closes_against(self.limits.facts)
            && u64::try_from(self.facts.actual().hir_nodes()) == Ok(self.syntax_hir_nodes)
            && self.facts.operation().erases_captures()
            && self.facts.capture_count() == 0
            && u64::try_from(self.lowering.erased_captures()) == Ok(self.syntax_captures)
            && u64::try_from(self.lowering.normalized_nullable_repetitions())
                .is_ok_and(|count| count <= self.syntax_hir_nodes)
            && !self.lowering.utf8_start_guarded()
            && self.lowering.states() == self.automaton.states()
            && self.lowering.edges() == self.automaton.edges()
            && self.lowering.work() <= self.limits.lowering.max_work
            && self.lowering.peak_stack_items() <= self.limits.lowering.max_stack_items
            && self.automaton.states() <= self.limits.lowering.automata.max_states
            && self.automaton.edges() <= self.limits.lowering.automata.max_edges
            && self.automaton.storage_bytes() <= self.limits.lowering.automata.max_storage_bytes
            && self.automaton.validation_work() <= self.limits.lowering.automata.max_validation_work
            && self.bridge.closes_against(self.limits.bridge)
            && expected_bridge_work == Some(self.bridge.work())
            && expected_action_bytes == Some(self.bridge.action_bytes())
            && self.bridge.peak_bytes() == self.bridge.action_bytes()
            && self.bridge.pattern_terminals() == 1
            && self.bridge.allocation_attempts() == 1
            && self.pattern_action == single_pattern_action()
            && self.empty_progress == EmptyMatchProgress::Byte
            && self.declared_match_length == match_length_from_width(self.facts.width())
            && route_matches
            && validate_requested_target(self.execution, self.target).is_ok()
            && validate_selected_kernel(self.execution, self.target, self.kernel).is_ok()
            && preparation_closes_against(self.preparation, self.limits.preparation)
            && self.preparation.pattern_terminals == self.bridge.pattern_terminals()
            && self.preparation.peak_bytes >= self.preparation.persistent_bytes
            && self.source_owner.closes_against(self.limits.source_owner)
            && source_capacity_closes
            && self.syntax_line_terminator == Some(self.line_terminator)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PriorityAggregateExecutionAuthentication {
    schema_version: u32,
    accounting_id: &'static str,
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    limits: PriorityAggregateRunLimits,
    build: PriorityAggregateExecutionBuildBinding,
    preparation: PreparationAccounting,
    prospective: ExecutionProspective,
    actual: ExecutionActual,
    input_bounded_source_bytes: Option<usize>,
    value: u64,
}

/// Value plus the separately authenticated preparation and execution ledgers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorityAggregateExecutionReceipt {
    schema_version: u32,
    accounting_id: &'static str,
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    limits: PriorityAggregateRunLimits,
    build: PriorityAggregateExecutionBuildBinding,
    preparation: PreparationAccounting,
    prospective: ExecutionProspective,
    actual: ExecutionActual,
    input_bounded_source_bytes: Option<usize>,
    value: u64,
    authentication: PriorityAggregateExecutionAuthentication,
}

impl PriorityAggregateExecutionAuthentication {
    fn authenticates(self, receipt: &PriorityAggregateExecutionReceipt) -> bool {
        self.schema_version == receipt.schema_version
            && self.accounting_id == receipt.accounting_id
            && self.operation == receipt.operation
            && self.execution == receipt.execution
            && self.limits == receipt.limits
            && self.build == receipt.build
            && self.preparation == receipt.preparation
            && self.prospective == receipt.prospective
            && self.actual == receipt.actual
            && self.input_bounded_source_bytes == receipt.input_bounded_source_bytes
            && self.value == receipt.value
    }
}

impl PriorityAggregateExecutionReceipt {
    #[must_use]
    pub const fn operation(&self) -> PriorityAggregateOperation {
        self.operation
    }

    #[must_use]
    pub const fn execution(&self) -> ForcedExecution {
        self.execution
    }

    /// Concrete prepared kernel authenticated beneath the requested route.
    #[must_use]
    pub const fn kernel(&self) -> PriorityExecutionKernel {
        self.build.kernel
    }

    #[must_use]
    pub const fn limits(&self) -> PriorityAggregateRunLimits {
        self.limits
    }

    #[must_use]
    pub const fn preparation(&self) -> PreparationAccounting {
        self.preparation
    }

    #[must_use]
    pub const fn prospective(&self) -> ExecutionProspective {
        self.prospective
    }

    #[must_use]
    pub const fn actual(&self) -> ExecutionActual {
        self.actual
    }

    /// Exact input length bound recorded only for the sparse-equivalent
    /// input-bounded fallback.
    #[must_use]
    pub const fn input_bounded_source_bytes(&self) -> Option<usize> {
        self.input_bounded_source_bytes
    }

    /// Exact static reducer retention inherited from the authenticated build.
    #[must_use]
    pub const fn static_reducer_retention_bytes(&self) -> Option<usize> {
        self.build.static_reducer_retention_bytes
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Whether successful actual counters close against their exact preflight.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the receipt intentionally keeps source, output, dynamic-route, and P/A closure conditions together"
    )]
    pub fn closes(&self) -> bool {
        let actual = self.actual;
        let prospective = self.prospective;
        let preparation = self.preparation;
        let authentication_closes = self.authentication.authenticates(self);
        let output_upper_bound = output_upper_bound(self.operation, actual.source_bytes);
        let output_closes = match self.operation {
            PriorityAggregateOperation::Count => {
                u64::try_from(actual.match_events) == Ok(self.value)
                    && output_upper_bound.is_some_and(|bound| bound <= self.limits.max_output)
            }
            PriorityAggregateOperation::SpanSum => {
                self.value == actual.selected_span_bytes
                    && output_upper_bound.is_some_and(|bound| bound <= self.limits.max_output)
            }
        };
        let source_boundaries = actual.source_bytes.checked_add(1);
        let execution_limits_close = prospective.work_upper_bound <= self.limits.execution.max_work
            && prospective.scratch_bytes <= self.limits.execution.max_scratch_bytes
            && prospective.boundary_rows <= self.limits.execution.max_boundary_rows
            && prospective.match_events_upper_bound <= self.limits.execution.max_match_events
            && prospective.dfa_states_capacity <= self.limits.execution.max_dfa_states
            && prospective.dfa_cells_capacity <= self.limits.execution.max_dfa_cells
            && prospective.subset_items_capacity <= self.limits.execution.max_subset_items
            && prospective.tagged_dispatch_states_capacity
                <= self.limits.execution.max_tagged_dispatch_states
            && prospective.tagged_dispatch_cells_capacity
                <= self.limits.execution.max_tagged_dispatch_cells
            && prospective.tagged_candidate_items_capacity
                <= self.limits.execution.max_tagged_candidate_items
            && prospective.tagged_cache_cells_capacity
                <= self.limits.execution.max_tagged_cache_cells
            && prospective.allocation_attempts <= self.limits.execution.max_allocation_attempts;
        let tagged_capacities_zero = prospective.tagged_dispatch_states_capacity == 0
            && prospective.tagged_dispatch_cells_capacity == 0
            && prospective.tagged_candidate_items_capacity == 0
            && prospective.tagged_cache_cells_capacity == 0;
        let tagged_actual_zero = actual.tagged_dispatch_states == 0
            && actual.tagged_dispatch_cells == 0
            && actual.tagged_candidate_items == 0
            && actual.tagged_cache_cells == 0
            && actual.tagged_state_evaluations == 0
            && actual.tagged_edge_visits == 0
            && actual.tagged_cache_hits == 0
            && actual.tagged_cache_misses == 0
            && actual.tagged_cache_inserts == 0
            && actual.tagged_cache_evictions == 0;
        let sparse_actual_zero = actual.sparse_root_evaluations == 0
            && actual.sparse_closure_visits == 0
            && actual.sparse_edge_visits == 0;
        let tagged_static_program_closes = prospective.tagged_dispatch_states_capacity > 0
            && prospective.tagged_dispatch_cells_capacity > 0
            && prospective.tagged_candidate_items_capacity > 0
            && prospective.tagged_dispatch_states_capacity == preparation.tagged_dispatch_states
            && prospective.tagged_dispatch_cells_capacity == preparation.tagged_dispatch_cells
            && prospective.tagged_candidate_items_capacity == preparation.tagged_candidate_items
            && actual.tagged_dispatch_states == prospective.tagged_dispatch_states_capacity
            && actual.tagged_dispatch_cells == prospective.tagged_dispatch_cells_capacity
            && actual.tagged_candidate_items == prospective.tagged_candidate_items_capacity;
        let sparse_like_counters_close = prospective.dfa_states_capacity == 0
            && prospective.dfa_cells_capacity == 0
            && prospective.subset_items_capacity == 0
            && actual.dfa_states == 0
            && actual.dfa_cells == 0
            && actual.subset_items == 0
            && actual.dfa_transitions == 0
            && actual.lazy_cache_hits == 0
            && actual.lazy_cache_misses == 0
            && actual.lazy_cache_inserts == 0
            && actual.lazy_cache_evictions == 0
            && tagged_capacities_zero
            && tagged_actual_zero
            && actual.suffix_reducer_steps == prospective.boundary_rows;
        let input_bounded_source_closes = match self.build.kernel {
            PriorityExecutionKernel::InputBoundedReverse => {
                self.input_bounded_source_bytes == Some(actual.source_bytes)
                    && actual.source_bytes.checked_add(1) == Some(prospective.boundary_rows)
                    && actual.boundary_rows == prospective.boundary_rows
                    && self.build.static_reducer_retention_bytes.is_none()
            }
            _ => self.input_bounded_source_bytes.is_none(),
        };
        let route_counters_close = match self.build.kernel {
            PriorityExecutionKernel::SparseReverse
            | PriorityExecutionKernel::FiniteHorizonReverse
            | PriorityExecutionKernel::InputBoundedReverse => sparse_like_counters_close,
            PriorityExecutionKernel::FullDfa => {
                actual.dfa_states == prospective.dfa_states_capacity
                    && actual.dfa_cells == prospective.dfa_cells_capacity
                    && actual.subset_items == prospective.subset_items_capacity
                    && tagged_capacities_zero
                    && tagged_actual_zero
                    && actual.suffix_reducer_steps == 0
            }
            PriorityExecutionKernel::LazyDfa => {
                actual.dfa_states <= prospective.dfa_states_capacity
                    && actual.dfa_cells <= prospective.dfa_cells_capacity
                    && actual.subset_items <= prospective.subset_items_capacity
                    && tagged_capacities_zero
                    && tagged_actual_zero
                    && actual.suffix_reducer_steps == 0
            }
            PriorityExecutionKernel::FullTaggedReverse => {
                prospective.dfa_states_capacity == 0
                    && prospective.dfa_cells_capacity == 0
                    && prospective.subset_items_capacity == 0
                    && actual.dfa_states == 0
                    && actual.dfa_cells == 0
                    && actual.subset_items == 0
                    && actual.dfa_transitions == 0
                    && actual.lazy_cache_hits == 0
                    && actual.lazy_cache_misses == 0
                    && actual.lazy_cache_inserts == 0
                    && actual.lazy_cache_evictions == 0
                    && sparse_actual_zero
                    && tagged_static_program_closes
                    && prospective.tagged_cache_cells_capacity == 0
                    && actual.tagged_cache_cells == 0
                    && actual.tagged_cache_hits == 0
                    && actual.tagged_cache_misses == 0
                    && actual.tagged_cache_inserts == 0
                    && actual.tagged_cache_evictions == 0
                    && actual.tagged_state_evaluations > 0
                    && actual.suffix_reducer_steps == prospective.boundary_rows
            }
            PriorityExecutionKernel::LazyTaggedReverse => {
                prospective.dfa_states_capacity == 0
                    && prospective.dfa_cells_capacity == 0
                    && prospective.subset_items_capacity == 0
                    && actual.dfa_states == 0
                    && actual.dfa_cells == 0
                    && actual.subset_items == 0
                    && actual.dfa_transitions == 0
                    && actual.lazy_cache_hits == 0
                    && actual.lazy_cache_misses == 0
                    && actual.lazy_cache_inserts == 0
                    && actual.lazy_cache_evictions == 0
                    && sparse_actual_zero
                    && tagged_static_program_closes
                    && actual.tagged_cache_cells == prospective.tagged_cache_cells_capacity
                    && (actual.source_bytes == 0 || prospective.tagged_cache_cells_capacity > 0)
                    && actual.tagged_cache_inserts == actual.tagged_cache_misses
                    && actual.tagged_cache_evictions <= actual.tagged_cache_inserts
                    && actual.tagged_state_evaluations > 0
                    && actual.suffix_reducer_steps == prospective.boundary_rows
            }
            _ => false,
        };
        self.schema_version == PRIORITY_AGGREGATE_SCHEMA_VERSION
            && self.accounting_id == PRIORITY_AGGREGATE_ACCOUNTING_ID
            && authentication_closes
            && self.build.closes()
            && self.build.operation == self.operation
            && self.build.execution == self.execution
            && self.build.preparation == self.preparation
            && preparation_closes_against(preparation, self.build.limits.preparation)
            && execution_limits_close
            && prospective.tagged_execution_class.is_none()
            && prospective.tagged_state_evaluations_upper_bound == 0
            && prospective.tagged_edge_visits_upper_bound == 0
            && prospective.tagged_map_capacity == 0
            && prospective.tagged_group_capacity == 0
            && prospective.tagged_group_publications_upper_bound == 0
            && prospective.tagged_owner_capacity == 0
            && actual.tagged_map_publications == 0
            && actual.tagged_group_publications == 0
            && actual.tagged_peak_maps == 0
            && actual.tagged_peak_groups == 0
            && source_boundaries == Some(prospective.boundary_rows)
            && actual.boundary_rows == prospective.boundary_rows
            && prospective.match_events_upper_bound == prospective.boundary_rows
            && actual.work <= prospective.work_upper_bound
            && actual.scratch_bytes == prospective.scratch_bytes
            && actual.match_events <= prospective.match_events_upper_bound
            && actual.empty_match_events <= actual.match_events
            && u64::try_from(actual.source_bytes)
                .is_ok_and(|bytes| actual.selected_span_bytes <= bytes)
            && actual.dfa_states <= prospective.dfa_states_capacity
            && actual.dfa_cells <= prospective.dfa_cells_capacity
            && actual.subset_items <= prospective.subset_items_capacity
            && actual.tagged_dispatch_states <= prospective.tagged_dispatch_states_capacity
            && actual.tagged_dispatch_cells <= prospective.tagged_dispatch_cells_capacity
            && actual.tagged_candidate_items <= prospective.tagged_candidate_items_capacity
            && actual.tagged_cache_cells <= prospective.tagged_cache_cells_capacity
            && actual.allocation_attempts == prospective.allocation_attempts
            && actual.selected_ordinal_sum == 0
            && input_bounded_source_closes
            && route_counters_close
            && output_closes
    }
}

/// Explicit forced Count artifact.
#[derive(Debug)]
pub struct PriorityAggregateCountRegex {
    plan: PreparedPriorityAutomaton<DirectCount>,
    report: PriorityAggregateBuildReport,
}

impl PriorityAggregateCountRegex {
    #[must_use]
    pub const fn build_report(&self) -> &PriorityAggregateBuildReport {
        &self.report
    }

    /// Execute the exact route fixed at construction.
    pub fn count(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateRunLimits,
    ) -> Result<PriorityAggregateExecutionReceipt, PriorityAggregateRunError> {
        run(&self.plan, &self.report, haystack, limits, |report| {
            *report.output()
        })
    }
}

/// Explicit forced `SpanSum` artifact.
#[derive(Debug)]
pub struct PriorityAggregateSpanSumRegex {
    plan: PreparedPriorityAutomaton<DirectSpanSum>,
    report: PriorityAggregateBuildReport,
}

impl PriorityAggregateSpanSumRegex {
    #[must_use]
    pub const fn build_report(&self) -> &PriorityAggregateBuildReport {
        &self.report
    }

    /// Execute the exact route fixed at construction.
    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateRunLimits,
    ) -> Result<PriorityAggregateExecutionReceipt, PriorityAggregateRunError> {
        run(&self.plan, &self.report, haystack, limits, |report| {
            *report.output()
        })
    }
}

fn run<O, F>(
    plan: &PreparedPriorityAutomaton<O>,
    build: &PriorityAggregateBuildReport,
    haystack: &[u8],
    limits: PriorityAggregateRunLimits,
    value: F,
) -> Result<PriorityAggregateExecutionReceipt, PriorityAggregateRunError>
where
    O: fre_automata::DirectReduceValue<Output = u64>,
    F: FnOnce(&DirectReduceReport<u64>) -> u64,
{
    let execution = plan.execution();
    if !build.closes() {
        return Err(PriorityAggregateRunError {
            operation: build.operation,
            execution,
            limits,
            source: PriorityAggregateRunFailure::BuildReportNotClosed,
        });
    }
    if execution != build.execution
        || plan.kernel() != build.kernel
        || plan.static_reducer_retention_bytes() != build.static_reducer_retention_bytes
        || plan.preparation_accounting() != build.preparation
    {
        return Err(PriorityAggregateRunError {
            operation: build.operation,
            execution,
            limits,
            source: PriorityAggregateRunFailure::BuildPlanIdentityMismatch,
        });
    }
    let build_binding = PriorityAggregateExecutionBuildBinding::from_report(build);
    if !build_binding.closes() {
        return Err(PriorityAggregateRunError {
            operation: build.operation,
            execution,
            limits,
            source: PriorityAggregateRunFailure::BuildReportNotClosed,
        });
    }
    preflight_output_limit(build.operation, haystack.len(), limits).map_err(|source| {
        PriorityAggregateRunError {
            operation: build.operation,
            execution,
            limits,
            source,
        }
    })?;
    let report = plan
        .execute_forced(haystack, limits.execution)
        .map_err(|source| PriorityAggregateRunError {
            operation: build.operation,
            execution,
            limits,
            source: PriorityAggregateRunFailure::Execution(source),
        })?;
    let prospective = report.prospective();
    let actual = report.actual();
    let value = value(&report);
    let input_bounded_source_bytes = match plan.kernel() {
        PriorityExecutionKernel::InputBoundedReverse => Some(haystack.len()),
        _ => None,
    };
    let authentication = PriorityAggregateExecutionAuthentication {
        schema_version: PRIORITY_AGGREGATE_SCHEMA_VERSION,
        accounting_id: PRIORITY_AGGREGATE_ACCOUNTING_ID,
        operation: build.operation,
        execution,
        limits,
        build: build_binding,
        preparation: build.preparation,
        prospective,
        actual,
        input_bounded_source_bytes,
        value,
    };
    let receipt = PriorityAggregateExecutionReceipt {
        schema_version: PRIORITY_AGGREGATE_SCHEMA_VERSION,
        accounting_id: PRIORITY_AGGREGATE_ACCOUNTING_ID,
        operation: build.operation,
        execution,
        limits,
        build: build_binding,
        preparation: build.preparation,
        prospective,
        actual,
        input_bounded_source_bytes,
        value,
        authentication,
    };
    if !receipt.closes() {
        return Err(PriorityAggregateRunError {
            operation: build.operation,
            execution,
            limits,
            source: PriorityAggregateRunFailure::ExecutionReceiptNotClosed,
        });
    }
    Ok(receipt)
}

fn output_upper_bound(operation: PriorityAggregateOperation, haystack_bytes: usize) -> Option<u64> {
    match operation {
        PriorityAggregateOperation::Count => haystack_bytes
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok()),
        PriorityAggregateOperation::SpanSum => u64::try_from(haystack_bytes).ok(),
    }
}

fn preflight_output_limit(
    operation: PriorityAggregateOperation,
    haystack_bytes: usize,
    limits: PriorityAggregateRunLimits,
) -> Result<(), PriorityAggregateRunFailure> {
    let computation = match operation {
        PriorityAggregateOperation::Count => "forced facade count output bound",
        PriorityAggregateOperation::SpanSum => "forced facade span-sum output bound",
    };
    let bound = output_upper_bound(operation, haystack_bytes).ok_or(
        PriorityAggregateRunFailure::Execution(ReduceError::ArithmeticOverflow { computation }),
    )?;
    if bound > limits.max_output {
        return Err(PriorityAggregateRunFailure::OutputLimit {
            operation,
            needed: bound,
            limit: limits.max_output,
        });
    }
    Ok(())
}
