use core::{fmt, ops::Range};
use std::sync::Arc;

use fre_aggregate::{
    AdmittedCount, AdmittedSpanSum, AdmittedSpans, CompiledRegex, RustByteProfile, SpanIter,
};
use fre_kernels::{
    LiteralAggregateBuildAccounting, LiteralAggregateBuildError, LiteralAggregateBuildLimits,
    LiteralAggregateCountResult, LiteralAggregateOperationIdentity, LiteralAggregatePlan,
    LiteralAggregateReduceAccounting, LiteralAggregateReduceError, LiteralAggregateReduceLimits,
    LiteralAggregateSpanSumResult, OrderedLiteralAggregateBuildAccounting,
    OrderedLiteralAggregateBuildError, OrderedLiteralAggregateBuildLimits,
    OrderedLiteralAggregateActualCounters, OrderedLiteralAggregateReduceError,
    OrderedLiteralAggregateReduceLimits, OrderedLiteralAggregateUpperBounds,
    OrderedLiteralCountPlan, OrderedLiteralSpanSumPlan,
    ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID, ORDERED_LITERAL_COUNT_PLAN_ID,
    ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{Hir, HirKind};

use crate::{
    AggregateCompileAccounting, AggregateCompileLimits, AggregateEngineError,
    AggregateExecutionAccounting, AggregateOperationCertificate, AggregateOperationLimits,
    AggregatePlanId, Match,
};

pub use fre_aggregate::Strategy as AggregateStrategy;

/// Stable schema for aggregate facade reports and cache identities.
pub const AGGREGATE_EXPLAIN_SCHEMA_VERSION: u32 = 5;

/// Whole-match operation fixed before an aggregate plan is constructed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateOperation {
    /// Compile a reusable whole-match artifact. Construction is the measured
    /// operation; complete match counting exists only to verify the artifact.
    Compile,
    /// Complete Rust-compatible non-overlapping match spans.
    Spans,
    /// Number of complete non-overlapping matches.
    Count,
    /// Checked sum of every complete match's byte length (`count-spans`).
    SpanSum,
}

/// Construction-time aggregate plan policy.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregatePlanSelection {
    /// Select an exact-literal plan, then a bounded finite-language plan when
    /// canonical HIR proves eligibility; otherwise construct continuation.
    #[default]
    Auto,
    /// Require the direct canonical exact-literal proof.
    ForceExactLiteral,
    /// Skip exact-literal inspection and require the continuation program.
    ForceContinuation,
}

/// Operation plan family chosen at construction time.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregatePlanKind {
    /// SIMD-aware `memmem::Finder::find_iter` whole-operation reducer.
    ExactLiteral,
    /// Bounded finite-language extraction plus a linear reversed dense
    /// Aho-Corasick/DP whole-operation reducer.
    FiniteOrderedLiterals,
    /// Bounded prioritized continuation program from `fre-aggregate`.
    ContinuationProgram,
}

/// Stable identity for the selected operation-specific implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregatePlanIdentity {
    /// Exact-literal plan plus count/span-sum operation identity.
    ExactLiteral(AggregateExactLiteralIdentity),
    /// Operation-typed ordered finite-language implementation identity. The
    /// exact source/profile remains in the enclosing cache identity.
    FiniteOrderedLiterals(AggregateFiniteLiteralIdentity),
    /// Semantic continuation-program identity.
    Continuation(AggregateContinuationIdentity),
}

/// Stable identity of the ordered finite-language aggregate implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFiniteLiteralIdentity {
    pub algorithm_id: &'static str,
    pub operation_plan_id: &'static str,
    pub operation: AggregateOperation,
}

/// Semantic proof attached to an exact-literal facade identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateExactLiteralSemantics {
    /// Rust bytes with Unicode disabled, including the separately certified
    /// empty-needle every-byte-boundary formula.
    UnicodeOffByteBoundaries,
    /// Rust bytes with Unicode syntax enabled, restricted to one nonempty
    /// canonical UTF-8 literal and case folding disabled.
    UnicodeOnNonemptyUtf8Literal,
}

/// Facade identity separating the two exact-literal semantic proofs even when
/// they use the same native reducer implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateExactLiteralIdentity {
    /// Profile-specific semantic proof selected during construction.
    pub semantics: AggregateExactLiteralSemantics,
    /// Native kernel and operation identity.
    pub kernel: LiteralAggregateOperationIdentity,
}

/// Profile proof attached to a continuation-program facade identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateContinuationSemantics {
    /// Rust bytes with Unicode disabled and empty matches at every byte
    /// boundary.
    UnicodeOffByteBoundaries,
    /// Rust bytes with Unicode enabled, `utf8(false)` and
    /// `utf8_empty(false)`, restricted to canonical HIR whose consuming and
    /// assertion transitions are byte-stable.
    UnicodeOnByteStableHir,
}

/// Facade identity that prevents the same byte program from erasing the
/// constructor profile that justified it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateContinuationIdentity {
    /// Profile-specific semantic proof selected during construction.
    pub semantics: AggregateContinuationSemantics,
    /// Stable identity of the lowered continuation program.
    pub program: AggregatePlanId,
}

/// Capture policy in every currently exposed aggregate cache identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateCaptureSemantics {
    /// Capture annotations are erased only because all outputs are whole-match
    /// values. No capture group value or history is exposed.
    ErasedForWholeMatchOnly,
}

/// Complete construction accounting for the selected plan family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateBuildAccounting {
    /// Exact-literal kernel construction certificate.
    ExactLiteral(LiteralAggregateBuildAccounting),
    /// Finite-language extraction result compiled into the ordered reducer.
    FiniteOrderedLiterals(AggregateFiniteLiteralBuildAccounting),
    /// Continuation compiler construction certificate.
    Continuation(AggregateCompileAccounting),
}

/// Construction accounting at the finite-language facade seam. Materialized
/// words remain live while the kernel is built, so their observed capacities
/// are included in the combined construction peak.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFiniteLiteralBuildAccounting {
    pub extraction_work: u64,
    pub combined_work_upper_bound: u64,
    pub words: usize,
    pub word_bytes: usize,
    pub materialized_capacity_bytes: usize,
    pub combined_peak_bytes: usize,
    pub kernel: OrderedLiteralAggregateBuildAccounting,
}

/// Construction limits whose complete values participate in cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateBuildLimits {
    /// Exact-upstream-pending strict mode or an explicit FRE quota mode.
    pub admission: AdmissionPolicy,
    /// Non-configurable implementation safety envelope used during parsing.
    pub syntax_safety: SafetyEnvelope,
    /// Maximum allocation-free direct-root literal inspection work.
    pub max_literal_planner_work: usize,
    /// Maximum words materialized by bounded finite-language extraction.
    pub max_finite_language_words: usize,
    /// Maximum total payload bytes materialized by finite-language extraction.
    pub max_finite_language_bytes: usize,
    /// Maximum traversal, allocation, and copy work used by extraction.
    pub max_finite_planner_work: u64,
    /// Complete exact-literal kernel construction limits.
    pub exact_literal: LiteralAggregateBuildLimits,
    /// Complete ordered finite-language construction limits.
    pub finite_ordered_literals: OrderedLiteralAggregateBuildLimits,
    /// Complete bounded continuation-program compiler limits.
    pub continuation: AggregateCompileLimits,
}

impl Default for AggregateBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_literal_planner_work: 4_096,
            max_finite_language_words: 4_096,
            max_finite_language_bytes: 4 << 20,
            max_finite_planner_work: 8_000_000,
            exact_literal: LiteralAggregateBuildLimits::default(),
            finite_ordered_literals: OrderedLiteralAggregateBuildLimits::default(),
            continuation: AggregateCompileLimits::default(),
        }
    }
}

/// Complete per-invocation limits. All plan families remain visible so an
/// `Auto` build cannot hide a policy change when its selected plan changes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateRunLimits {
    /// Exact-literal whole-operation reducer limits.
    pub exact_literal: LiteralAggregateReduceLimits,
    /// Ordered finite-language whole-operation reducer limits.
    pub finite_ordered_literals: OrderedLiteralAggregateReduceLimits,
    /// Continuation whole-operation limits.
    pub continuation: AggregateOperationLimits,
}

/// Auditable construction facts for one operation-specific aggregate plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateBuildReport {
    /// Report schema.
    pub schema_version: u32,
    /// Full syntax/cache input, including original pattern and profile. The
    /// shared allocation is created during construction, never reducer timing.
    pub syntax_key: Arc<CacheKey>,
    /// What syntax parsing established about constructor admission.
    pub admission: AdmissionStatus,
    /// Exact syntax counters before capture erasure.
    pub syntax: ParseSummary,
    /// Operation selected before compilation.
    pub operation: AggregateOperation,
    /// Requested construction-time plan policy.
    pub selection: AggregatePlanSelection,
    /// Plan family selected before publication.
    pub plan: AggregatePlanKind,
    /// Continuation storage strategy, absent for an exact-literal plan.
    pub continuation_strategy: Option<AggregateStrategy>,
    /// The only capture treatment admitted by these whole-match APIs.
    pub capture_semantics: AggregateCaptureSemantics,
    /// Plan-selection work through the selected proof. This is zero when
    /// forced continuation skips inspection.
    pub planner_work: usize,
    /// Transparent capture-node visits charged by the selected plan builder.
    pub capture_erasure_work: usize,
    /// Capture annotations removed without changing whole-match semantics.
    pub captures_erased: usize,
    /// Exact construction accounting for the selected plan.
    pub build: AggregateBuildAccounting,
    /// Stable operation-specific selected-plan identity.
    pub plan_identity: AggregatePlanIdentity,
    /// Selected plan's retained capacity/persistent bytes.
    pub retained_capacity_bytes: usize,
}

/// Complete equality key for a compiled aggregate operation invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateCacheIdentity {
    pub schema_version: u32,
    pub syntax_key: Arc<CacheKey>,
    pub operation: AggregateOperation,
    pub selection: AggregatePlanSelection,
    pub plan: AggregatePlanKind,
    pub continuation_strategy: Option<AggregateStrategy>,
    pub capture_semantics: AggregateCaptureSemantics,
    pub plan_identity: AggregatePlanIdentity,
    pub build_limits: AggregateBuildLimits,
    pub execution_limits: AggregateRunLimits,
}

/// Why a forced exact-literal construction was semantically ineligible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateLiteralIneligibility {
    /// Complete span materialization is not implemented by this reducer.
    SpanOperation,
    /// After peeling only direct root captures, canonical HIR was not one
    /// `Literal` or `Empty` node.
    CanonicalRootNotLiteralOrEmpty,
    /// Unicode-enabled direct execution admits only one nonempty canonical
    /// literal; captures and every other HIR root remain outside scope.
    UnicodeCanonicalRootNotNonemptyLiteral,
    /// Unicode-enabled empty matching remains outside this narrowly promoted
    /// admission even though the pinned bytes oracle advances by bytes.
    UnicodeEmptyOutsideAdmission,
    /// Unicode-enabled exact-literal admission does not certify case folding.
    UnicodeCaseInsensitiveOutsideAdmission,
    /// A local Unicode-disable group produced a raw-byte literal outside the
    /// nonempty valid-UTF-8 literal proof.
    UnicodeLiteralNotUtf8,
}

/// Aggregate construction failure retaining the requested operation/policy.
#[derive(Debug)]
#[non_exhaustive]
pub enum AggregateBuildError {
    /// Syntax/profile/admission failure.
    Syntax {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: fre_syntax::ParseError,
    },
    /// Allocation-free exact-literal inspection crossed its explicit work cap.
    LiteralPlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
    },
    /// Bounded finite-language extraction exhausted its explicit work cap.
    FinitePlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: u64,
        limit: u64,
    },
    /// A finite-language planner buffer could not be reserved.
    FinitePlannerAllocationFailed {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        structure: &'static str,
        additional: usize,
    },
    /// A forced exact-literal request was not semantically eligible.
    ExactLiteralIneligible {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        reason: AggregateLiteralIneligibility,
    },
    /// Exact-literal kernel construction failed after plan selection.
    ExactLiteralBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: LiteralAggregateBuildError,
    },
    /// Ordered finite-language construction failed after plan selection.
    FiniteOrderedLiteralBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: OrderedLiteralAggregateBuildError,
    },
    /// Bounded continuation compiler refusal.
    ContinuationCompile {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        strategy: AggregateStrategy,
        source: AggregateEngineError,
    },
    /// Parser summary and selected bounded traversal accounting disagreed.
    InternalInvariant {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        detail: &'static str,
    },
}

impl fmt::Display for AggregateBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} syntax construction failed: {source}"
            ),
            Self::LiteralPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} exact-literal inspection needs {needed} work units, limit is {limit}"
            ),
            Self::FinitePlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} finite-language extraction needs {needed} work units, limit is {limit}"
            ),
            Self::FinitePlannerAllocationFailed {
                operation,
                selection,
                structure,
                additional,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} finite-language extraction could not reserve {additional} items for {structure}"
            ),
            Self::ExactLiteralIneligible {
                operation,
                selection,
                reason,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} is not an exact-literal plan: {reason:?}"
            ),
            Self::ExactLiteralBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} exact-literal construction failed: {source}"
            ),
            Self::FiniteOrderedLiteralBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} ordered finite-language construction failed: {source}"
            ),
            Self::ContinuationCompile {
                operation,
                selection,
                strategy,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?}/{strategy:?} continuation compilation failed: {source}"
            ),
            Self::InternalInvariant {
                operation,
                selection,
                detail,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} facade invariant failed: {detail}"
            ),
        }
    }
}

impl std::error::Error for AggregateBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax { source, .. } => Some(source),
            Self::ExactLiteralBuild { source, .. } => Some(source),
            Self::FiniteOrderedLiteralBuild { source, .. } => Some(source),
            Self::ContinuationCompile { source, .. } => Some(source),
            Self::LiteralPlannerWorkLimit { .. }
            | Self::FinitePlannerWorkLimit { .. }
            | Self::FinitePlannerAllocationFailed { .. }
            | Self::ExactLiteralIneligible { .. }
            | Self::InternalInvariant { .. } => None,
        }
    }
}

/// Typed selected-plan execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateExecutionSource {
    /// Exact-literal whole-operation refusal.
    ExactLiteral(LiteralAggregateReduceError),
    /// Ordered finite-language whole-operation refusal.
    FiniteOrderedLiterals(OrderedLiteralAggregateReduceError),
    /// Continuation whole-operation refusal.
    Continuation(AggregateEngineError),
    /// Facade conversion or selected-plan invariant failure.
    InternalInvariant(&'static str),
}

impl fmt::Display for AggregateExecutionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactLiteral(source) => source.fmt(f),
            Self::FiniteOrderedLiterals(source) => source.fmt(f),
            Self::Continuation(source) => source.fmt(f),
            Self::InternalInvariant(detail) => {
                write!(f, "aggregate facade execution invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for AggregateExecutionSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ExactLiteral(source) => Some(source),
            Self::FiniteOrderedLiterals(source) => Some(source),
            Self::Continuation(source) => Some(source),
            Self::InternalInvariant(_) => None,
        }
    }
}

/// Whole-operation failure. No alternate plan or strategy is attempted after
/// this error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateExecutionError {
    /// Complete attempted cache identity, including every execution limit.
    pub identity: Box<AggregateCacheIdentity>,
    /// Typed bounded selected-plan failure.
    pub source: AggregateExecutionSource,
}

impl fmt::Display for AggregateExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "aggregate {:?}/{:?}/{:?} execution failed: {}",
            self.identity.operation, self.identity.plan, self.identity.plan_identity, self.source
        )
    }
}

impl std::error::Error for AggregateExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Selected-plan execution details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateExecutionDetails {
    /// Exact-literal upper bounds, counters, and operation identity.
    ExactLiteral(LiteralAggregateReduceAccounting),
    /// Ordered finite-language bounds and exact post-operation counters. The
    /// plan identity is carried by the enclosing cache identity.
    FiniteOrderedLiterals {
        upper_bounds: OrderedLiteralAggregateUpperBounds,
        actual: OrderedLiteralAggregateActualCounters,
    },
    /// Continuation whole-operation certificate and exact counters.
    Continuation {
        certificate: AggregateOperationCertificate,
        accounting: AggregateExecutionAccounting,
    },
}

/// Exact execution facts and the complete cache identity used for the call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateExecutionReport {
    pub identity: AggregateCacheIdentity,
    pub details: AggregateExecutionDetails,
}

/// Builder shared by all whole-match aggregate operations.
#[derive(Clone, Debug)]
pub struct AggregateBuilder {
    pattern: String,
    profile: RustProfile,
    limits: AggregateBuildLimits,
    selection: AggregatePlanSelection,
    strategy: AggregateStrategy,
}

impl AggregateBuilder {
    /// Start from the pinned Rust byte profile. Unicode defaults to enabled;
    /// exact literals and byte-stable continuation HIR are admitted in that
    /// mode; variable-width Unicode transitions remain typed refusals.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: AggregateBuildLimits::default(),
            selection: AggregatePlanSelection::Auto,
            strategy: AggregateStrategy::ReverseSequentialRows,
        }
    }

    /// Select the complete Rust release-stack and constructor identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set Unicode syntax mode. `true` admits nonempty exact literals and the
    /// separately certified byte-stable continuation subset.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Set Rust-regex case-insensitive syntax lowering before HIR compilation.
    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    /// Replace all checked construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: AggregateBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Select exact-literal auto/forced behavior before parsing and planning.
    #[must_use]
    pub const fn plan_selection(mut self, selection: AggregatePlanSelection) -> Self {
        self.selection = selection;
        self
    }

    /// Select the continuation storage strategy. Exact-literal reports and
    /// identities never contain this value.
    #[must_use]
    pub const fn strategy(mut self, strategy: AggregateStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Compile a reusable artifact whose construction boundary includes
    /// syntax parsing, plan selection, lowering, allocation and publication.
    /// [`AggregateCompileRegex::verify_count`] is deliberately separate so a
    /// compile benchmark can keep semantic verification outside its timer.
    pub fn build_compile(self) -> Result<AggregateCompileRegex, AggregateBuildError> {
        self.build(AggregateOperation::Compile)
            .map(AggregateCompileRegex)
    }

    /// Compile a complete non-overlapping span operation.
    pub fn build_spans(self) -> Result<AggregateSpansRegex, AggregateBuildError> {
        self.build(AggregateOperation::Spans)
            .map(AggregateSpansRegex)
    }

    /// Compile a complete match-count operation.
    pub fn build_count(self) -> Result<AggregateCountRegex, AggregateBuildError> {
        self.build(AggregateOperation::Count)
            .map(AggregateCountRegex)
    }

    /// Compile a complete matched-byte-sum (`count-spans`) operation.
    pub fn build_span_sum(self) -> Result<AggregateSpanSumRegex, AggregateBuildError> {
        self.build(AggregateOperation::SpanSum)
            .map(AggregateSpanSumRegex)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "construction keeps eligibility, no-fallback selection, and both auditable reports together"
    )]
    fn build(self, operation: AggregateOperation) -> Result<AggregatePlan, AggregateBuildError> {
        let selection = self.selection;
        let strategy = self.strategy;
        let limits = self.limits;
        let unicode = self.profile.options.unicode;
        let case_insensitive = self.profile.options.case_insensitive;
        if selection == AggregatePlanSelection::ForceExactLiteral
            && operation == AggregateOperation::Spans
        {
            return Err(AggregateBuildError::ExactLiteralIneligible {
                operation,
                selection,
                reason: AggregateLiteralIneligibility::SpanOperation,
            });
        }
        let profile = CompatibilityProfile::RustBytes(self.profile);
        let request = fre_syntax::ParseRequest::rust(self.pattern, profile)
            .with_admission(limits.admission)
            .with_safety_envelope(limits.syntax_safety);
        let parsed = fre_syntax::parse(request).map_err(|source| AggregateBuildError::Syntax {
            operation,
            selection,
            source,
        })?;
        let syntax_key = Arc::new(parsed.key);
        let admission = parsed.admission_status;
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(AggregateBuildError::InternalInvariant {
                operation,
                selection,
                detail: "Rust bytes request produced a non-Rust canonical pattern",
            });
        };
        let expected_nodes = usize::try_from(syntax.hir_nodes).map_err(|_| {
            AggregateBuildError::InternalInvariant {
                operation,
                selection,
                detail: "syntax node count does not fit usize",
            }
        })?;
        let expected_captures = usize::try_from(syntax.captures).map_err(|_| {
            AggregateBuildError::InternalInvariant {
                operation,
                selection,
                detail: "syntax capture count does not fit usize",
            }
        })?;

        let inspection = match (selection, operation) {
            (AggregatePlanSelection::ForceContinuation, _) | (_, AggregateOperation::Spans) => None,
            _ if unicode && case_insensitive => {
                if selection == AggregatePlanSelection::ForceExactLiteral {
                    return Err(AggregateBuildError::ExactLiteralIneligible {
                        operation,
                        selection,
                        reason:
                            AggregateLiteralIneligibility::UnicodeCaseInsensitiveOutsideAdmission,
                    });
                }
                None
            }
            _ => Some(
                inspect_exact_literal(
                    &rust.hir,
                    limits.max_literal_planner_work,
                    if unicode {
                        LiteralInspectionMode::UnicodeOnNonempty
                    } else {
                        LiteralInspectionMode::UnicodeOff
                    },
                )
                .map_err(|error| match error {
                    LiteralInspectionError::WorkLimit { needed, limit } => {
                        AggregateBuildError::LiteralPlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit,
                        }
                    }
                    LiteralInspectionError::Overflow => AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "exact-literal inspection accounting overflow",
                    },
                })?,
            ),
        };

        if let Some(LiteralInspection::Eligible {
            needle,
            work,
            captures,
        }) = inspection
        {
            if work != expected_nodes || captures != expected_captures {
                return Err(AggregateBuildError::InternalInvariant {
                    operation,
                    selection,
                    detail: "syntax summary differs from exact-literal inspection",
                });
            }
            let engine =
                LiteralAggregatePlan::build(needle, limits.exact_literal).map_err(|source| {
                    AggregateBuildError::ExactLiteralBuild {
                        operation,
                        selection,
                        source,
                    }
                })?;
            let build = engine.build_accounting();
            let kernel_identity = match operation {
                AggregateOperation::Compile | AggregateOperation::Count => engine.count_identity(),
                AggregateOperation::SpanSum => engine.span_sum_identity(),
                AggregateOperation::Spans => {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "span operation selected exact-literal reducer",
                    });
                }
            };
            let plan_identity =
                AggregatePlanIdentity::ExactLiteral(AggregateExactLiteralIdentity {
                    semantics: if unicode {
                        AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
                    } else {
                        AggregateExactLiteralSemantics::UnicodeOffByteBoundaries
                    },
                    kernel: kernel_identity,
                });
            let report = AggregateBuildReport {
                schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                syntax_key,
                admission,
                syntax,
                operation,
                selection,
                plan: AggregatePlanKind::ExactLiteral,
                continuation_strategy: None,
                capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                planner_work: work,
                capture_erasure_work: captures,
                captures_erased: captures,
                build: AggregateBuildAccounting::ExactLiteral(build),
                plan_identity,
                retained_capacity_bytes: build.persistent_bytes,
            };
            return Ok(AggregatePlan {
                engine: AggregateEngine::ExactLiteral(engine),
                limits,
                report,
            });
        }

        let planner_work = match inspection {
            Some(LiteralInspection::Ineligible { work, reason }) => {
                if selection == AggregatePlanSelection::ForceExactLiteral {
                    return Err(AggregateBuildError::ExactLiteralIneligible {
                        operation,
                        selection,
                        reason,
                    });
                }
                work
            }
            None => 0,
            Some(LiteralInspection::Eligible { .. }) => {
                return Err(AggregateBuildError::InternalInvariant {
                    operation,
                    selection,
                    detail: "eligible exact literal was not constructed",
                });
            }
        };
        if selection == AggregatePlanSelection::Auto
            && operation != AggregateOperation::Spans
            && !unicode
        {
            let extraction = crate::finite::extract(
                &rust.hir,
                limits.max_finite_language_words,
                limits.max_finite_language_bytes,
                u64::try_from(planner_work).unwrap_or(u64::MAX),
                limits.max_finite_planner_work,
            )
            .map_err(|error| match error {
                crate::BuildError::PlannerWorkLimit { needed, limit } => {
                    AggregateBuildError::FinitePlannerWorkLimit {
                        operation,
                        selection,
                        needed,
                        limit,
                    }
                }
                crate::BuildError::AllocationFailed {
                    structure,
                    additional,
                } => AggregateBuildError::FinitePlannerAllocationFailed {
                    operation,
                    selection,
                    structure,
                    additional,
                },
                crate::BuildError::InternalInvariant(detail) => {
                    AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail,
                    }
                }
                _ => AggregateBuildError::InternalInvariant {
                    operation,
                    selection,
                    detail: "finite-language extraction returned an unrelated facade error",
                },
            })?;
            if let Some(words) = extraction.words {
                let planner_work = usize::try_from(extraction.work).map_err(|_| {
                    AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "finite-language planner work does not fit usize",
                    }
                })?;
                let capture_erasure_work = expected_captures.checked_mul(2).ok_or(
                    AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "finite-language capture accounting overflow",
                    },
                )?;
                let words_capacity_bytes = words
                    .capacity()
                    .checked_mul(core::mem::size_of::<Vec<u8>>())
                    .and_then(|bytes| {
                        words.iter().try_fold(bytes, |total, word| {
                            total.checked_add(word.capacity())
                        })
                    })
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "finite-language materialized capacity overflow",
                    })?;
                let mut kernel_limits = limits.finite_ordered_literals;
                kernel_limits.max_build_work = kernel_limits
                    .max_build_work
                    .checked_sub(extraction.work)
                    .ok_or(AggregateBuildError::FiniteOrderedLiteralBuild {
                        operation,
                        selection,
                        source: OrderedLiteralAggregateBuildError::WorkLimit {
                            needed: extraction.work,
                            limit: limits.finite_ordered_literals.max_build_work,
                        },
                    })?;
                kernel_limits.max_peak_bytes = kernel_limits
                    .max_peak_bytes
                    .checked_sub(words_capacity_bytes)
                    .ok_or(AggregateBuildError::FiniteOrderedLiteralBuild {
                        operation,
                        selection,
                        source: OrderedLiteralAggregateBuildError::PeakLimit {
                            needed: words_capacity_bytes,
                            limit: limits.finite_ordered_literals.max_peak_bytes,
                        },
                    })?;
                let (engine, kernel_build, operation_plan_id) = match operation {
                    AggregateOperation::Count => {
                        let plan = OrderedLiteralCountPlan::build(
                            &words,
                            kernel_limits,
                        )
                        .map_err(|source| AggregateBuildError::FiniteOrderedLiteralBuild {
                            operation,
                            selection,
                            source,
                        })?;
                        let build = plan.build_accounting();
                        (
                            AggregateEngine::FiniteOrderedCount(plan),
                            build,
                            ORDERED_LITERAL_COUNT_PLAN_ID,
                        )
                    }
                    AggregateOperation::SpanSum => {
                        let plan = OrderedLiteralSpanSumPlan::build(
                            &words,
                            kernel_limits,
                        )
                        .map_err(|source| AggregateBuildError::FiniteOrderedLiteralBuild {
                            operation,
                            selection,
                            source,
                        })?;
                        let build = plan.build_accounting();
                        (
                            AggregateEngine::FiniteOrderedSpanSum(plan),
                            build,
                            ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
                        )
                    }
                    AggregateOperation::Spans => {
                        return Err(AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "span operation selected finite reducer",
                        });
                    }
                };
                let combined_work_upper_bound = extraction
                    .work
                    .checked_add(kernel_build.build_work_upper_bound)
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "finite-language combined construction work overflow",
                    })?;
                let combined_peak_bytes = words_capacity_bytes
                    .checked_add(kernel_build.peak_bytes)
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "finite-language combined construction peak overflow",
                    })?;
                if combined_peak_bytes > limits.finite_ordered_literals.max_peak_bytes {
                    return Err(AggregateBuildError::FiniteOrderedLiteralBuild {
                        operation,
                        selection,
                        source: OrderedLiteralAggregateBuildError::PeakLimit {
                            needed: combined_peak_bytes,
                            limit: limits.finite_ordered_literals.max_peak_bytes,
                        },
                    });
                }
                let build = AggregateFiniteLiteralBuildAccounting {
                    extraction_work: extraction.work,
                    combined_work_upper_bound,
                    words: kernel_build.patterns,
                    word_bytes: kernel_build.pattern_bytes,
                    materialized_capacity_bytes: words_capacity_bytes,
                    combined_peak_bytes,
                    kernel: kernel_build,
                };
                let report = AggregateBuildReport {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key,
                    admission,
                    syntax,
                    operation,
                    selection,
                    plan: AggregatePlanKind::FiniteOrderedLiterals,
                    continuation_strategy: None,
                    capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                    planner_work,
                    capture_erasure_work,
                    captures_erased: expected_captures,
                    build: AggregateBuildAccounting::FiniteOrderedLiterals(build),
                    plan_identity: AggregatePlanIdentity::FiniteOrderedLiterals(
                        AggregateFiniteLiteralIdentity {
                            algorithm_id: ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                            operation_plan_id,
                            operation,
                        },
                    ),
                    retained_capacity_bytes: build.kernel.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine,
                    limits,
                    report,
                });
            }
        }
        let continuation_profile = if unicode {
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE
        } else {
            RustByteProfile::PINNED_1_12_4
        };
        let engine = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &rust.hir,
            continuation_profile,
            limits.continuation,
        )
        .map_err(|source| AggregateBuildError::ContinuationCompile {
            operation,
            selection,
            strategy,
            source,
        })?;
        let compile = engine.compile_accounting();
        if compile.hir_nodes != expected_nodes || compile.captures_erased != expected_captures {
            return Err(AggregateBuildError::InternalInvariant {
                operation,
                selection,
                detail: "syntax summary differs from aggregate compiler traversal",
            });
        }
        let report = AggregateBuildReport {
            schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
            syntax_key,
            admission,
            syntax,
            operation,
            selection,
            plan: AggregatePlanKind::ContinuationProgram,
            continuation_strategy: Some(strategy),
            capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
            planner_work,
            capture_erasure_work: compile.capture_erasure_work,
            captures_erased: compile.captures_erased,
            build: AggregateBuildAccounting::Continuation(compile),
            plan_identity: AggregatePlanIdentity::Continuation(AggregateContinuationIdentity {
                semantics: if unicode {
                    AggregateContinuationSemantics::UnicodeOnByteStableHir
                } else {
                    AggregateContinuationSemantics::UnicodeOffByteBoundaries
                },
                program: engine.plan_id(),
            }),
            retained_capacity_bytes: compile.program_bytes,
        };
        Ok(AggregatePlan {
            engine: AggregateEngine::Continuation(engine),
            limits,
            report,
        })
    }
}

#[derive(Debug)]
enum AggregateEngine {
    ExactLiteral(LiteralAggregatePlan),
    FiniteOrderedCount(OrderedLiteralCountPlan),
    FiniteOrderedSpanSum(OrderedLiteralSpanSumPlan),
    Continuation(CompiledRegex),
}

#[derive(Debug)]
struct AggregatePlan {
    engine: AggregateEngine,
    limits: AggregateBuildLimits,
    report: AggregateBuildReport,
}

impl AggregatePlan {
    const fn operation(&self) -> AggregateOperation {
        self.report.operation
    }

    const fn build_report(&self) -> &AggregateBuildReport {
        &self.report
    }

    fn cache_identity(&self, execution_limits: AggregateRunLimits) -> AggregateCacheIdentity {
        AggregateCacheIdentity {
            schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
            syntax_key: Arc::clone(&self.report.syntax_key),
            operation: self.operation(),
            selection: self.report.selection,
            plan: self.report.plan,
            continuation_strategy: self.report.continuation_strategy,
            capture_semantics: self.report.capture_semantics,
            plan_identity: self.report.plan_identity,
            build_limits: self.limits,
            execution_limits,
        }
    }

    fn execution_error(
        &self,
        execution_limits: AggregateRunLimits,
        source: AggregateExecutionSource,
    ) -> AggregateExecutionError {
        AggregateExecutionError {
            identity: Box::new(self.cache_identity(execution_limits)),
            source,
        }
    }

    fn execution_report(
        &self,
        execution_limits: AggregateRunLimits,
        details: AggregateExecutionDetails,
    ) -> AggregateExecutionReport {
        AggregateExecutionReport {
            identity: self.cache_identity(execution_limits),
            details,
        }
    }

    fn full_range(haystack: &[u8]) -> Range<usize> {
        0..haystack.len()
    }

    fn execute_count(
        &self,
        haystack: &[u8],
        limits: AggregateRunLimits,
    ) -> Result<AggregateCountExecution, AggregateExecutionError> {
        match &self.engine {
            AggregateEngine::ExactLiteral(engine) => engine
                .count(haystack, limits.exact_literal)
                .map(AggregateCountExecution::ExactLiteral)
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::ExactLiteral(source))
                }),
            AggregateEngine::FiniteOrderedCount(engine) => engine
                .count(haystack, limits.finite_ordered_literals)
                .map(|result| AggregateCountExecution::FiniteOrderedLiterals {
                    value: result.count,
                    upper_bounds: result.accounting.upper_bounds,
                    actual: result.accounting.actual,
                })
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::FiniteOrderedLiterals(source),
                    )
                }),
            AggregateEngine::FiniteOrderedSpanSum(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "count operation retained a span-sum finite plan",
                ),
            )),
            AggregateEngine::Continuation(engine) => {
                let strategy = self.report.continuation_strategy.ok_or_else(|| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::InternalInvariant(
                            "continuation count plan lacks storage strategy",
                        ),
                    )
                })?;
                let admitted = engine
                    .admit_count(
                        haystack,
                        Self::full_range(haystack),
                        strategy,
                        limits.continuation,
                    )
                    .map_err(|source| {
                        self.execution_error(limits, AggregateExecutionSource::Continuation(source))
                    })?;
                let value = u64::try_from(admitted.value()).map_err(|_| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::InternalInvariant(
                            "continuation count does not fit u64",
                        ),
                    )
                })?;
                Ok(AggregateCountExecution::Continuation { admitted, value })
            }
        }
    }

    fn execute_span_sum(
        &self,
        haystack: &[u8],
        limits: AggregateRunLimits,
    ) -> Result<AggregateSpanSumExecution, AggregateExecutionError> {
        match &self.engine {
            AggregateEngine::ExactLiteral(engine) => engine
                .span_sum(haystack, limits.exact_literal)
                .map(AggregateSpanSumExecution::ExactLiteral)
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::ExactLiteral(source))
                }),
            AggregateEngine::FiniteOrderedSpanSum(engine) => engine
                .span_sum(haystack, limits.finite_ordered_literals)
                .map(|result| AggregateSpanSumExecution::FiniteOrderedLiterals {
                    value: result.span_sum,
                    upper_bounds: result.accounting.upper_bounds,
                    actual: result.accounting.actual,
                })
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::FiniteOrderedLiterals(source),
                    )
                }),
            AggregateEngine::FiniteOrderedCount(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span-sum operation retained a count finite plan",
                ),
            )),
            AggregateEngine::Continuation(engine) => {
                let strategy = self.report.continuation_strategy.ok_or_else(|| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::InternalInvariant(
                            "continuation span-sum plan lacks storage strategy",
                        ),
                    )
                })?;
                let admitted = engine
                    .admit_span_sum(
                        haystack,
                        Self::full_range(haystack),
                        strategy,
                        limits.continuation,
                    )
                    .map_err(|source| {
                        self.execution_error(limits, AggregateExecutionSource::Continuation(source))
                    })?;
                let value = u64::try_from(admitted.value()).map_err(|_| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::InternalInvariant(
                            "continuation span sum does not fit u64",
                        ),
                    )
                })?;
                Ok(AggregateSpanSumExecution::Continuation { admitted, value })
            }
        }
    }
}

enum AggregateCountExecution {
    ExactLiteral(LiteralAggregateCountResult),
    FiniteOrderedLiterals {
        value: u64,
        upper_bounds: OrderedLiteralAggregateUpperBounds,
        actual: OrderedLiteralAggregateActualCounters,
    },
    Continuation { admitted: AdmittedCount, value: u64 },
}

impl AggregateCountExecution {
    const fn value(&self) -> u64 {
        match self {
            Self::ExactLiteral(result) => result.count,
            Self::FiniteOrderedLiterals { value, .. } => *value,
            Self::Continuation { value, .. } => *value,
        }
    }

    fn into_details(self) -> AggregateExecutionDetails {
        match self {
            Self::ExactLiteral(result) => {
                AggregateExecutionDetails::ExactLiteral(result.accounting)
            }
            Self::FiniteOrderedLiterals {
                upper_bounds,
                actual,
                ..
            } => AggregateExecutionDetails::FiniteOrderedLiterals {
                upper_bounds,
                actual,
            },
            Self::Continuation { admitted, .. } => AggregateExecutionDetails::Continuation {
                certificate: admitted.certificate().clone(),
                accounting: admitted.accounting(),
            },
        }
    }
}

enum AggregateSpanSumExecution {
    ExactLiteral(LiteralAggregateSpanSumResult),
    FiniteOrderedLiterals {
        value: u64,
        upper_bounds: OrderedLiteralAggregateUpperBounds,
        actual: OrderedLiteralAggregateActualCounters,
    },
    Continuation {
        admitted: AdmittedSpanSum,
        value: u64,
    },
}

impl AggregateSpanSumExecution {
    const fn value(&self) -> u64 {
        match self {
            Self::ExactLiteral(result) => result.span_sum,
            Self::FiniteOrderedLiterals { value, .. } => *value,
            Self::Continuation { value, .. } => *value,
        }
    }

    fn into_details(self) -> AggregateExecutionDetails {
        match self {
            Self::ExactLiteral(result) => {
                AggregateExecutionDetails::ExactLiteral(result.accounting)
            }
            Self::FiniteOrderedLiterals {
                upper_bounds,
                actual,
                ..
            } => AggregateExecutionDetails::FiniteOrderedLiterals {
                upper_bounds,
                actual,
            },
            Self::Continuation { admitted, .. } => AggregateExecutionDetails::Continuation {
                certificate: admitted.certificate().clone(),
                accounting: admitted.accounting(),
            },
        }
    }
}

enum LiteralInspection<'a> {
    Eligible {
        needle: &'a [u8],
        work: usize,
        captures: usize,
    },
    Ineligible {
        work: usize,
        reason: AggregateLiteralIneligibility,
    },
}

#[derive(Clone, Copy)]
enum LiteralInspectionMode {
    UnicodeOff,
    UnicodeOnNonempty,
}

enum LiteralInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

fn inspect_exact_literal(
    mut hir: &Hir,
    limit: usize,
    mode: LiteralInspectionMode,
) -> Result<LiteralInspection<'_>, LiteralInspectionError> {
    let mut work = 0_usize;
    let mut captures = 0_usize;
    loop {
        let needed = work
            .checked_add(1)
            .ok_or(LiteralInspectionError::Overflow)?;
        if needed > limit {
            return Err(LiteralInspectionError::WorkLimit { needed, limit });
        }
        work = needed;
        if matches!(mode, LiteralInspectionMode::UnicodeOnNonempty) {
            return match hir.kind() {
                HirKind::Literal(literal) if !literal.0.is_empty() => {
                    if core::str::from_utf8(literal.0.as_ref()).is_err() {
                        Ok(LiteralInspection::Ineligible {
                            work,
                            reason: AggregateLiteralIneligibility::UnicodeLiteralNotUtf8,
                        })
                    } else {
                        Ok(LiteralInspection::Eligible {
                            needle: literal.0.as_ref(),
                            work,
                            captures: 0,
                        })
                    }
                }
                HirKind::Empty | HirKind::Literal(_) => Ok(LiteralInspection::Ineligible {
                    work,
                    reason: AggregateLiteralIneligibility::UnicodeEmptyOutsideAdmission,
                }),
                _ => Ok(LiteralInspection::Ineligible {
                    work,
                    reason: AggregateLiteralIneligibility::UnicodeCanonicalRootNotNonemptyLiteral,
                }),
            };
        }
        match hir.kind() {
            HirKind::Capture(capture) => {
                captures = captures
                    .checked_add(1)
                    .ok_or(LiteralInspectionError::Overflow)?;
                hir = capture.sub.as_ref();
            }
            HirKind::Empty => {
                return Ok(LiteralInspection::Eligible {
                    needle: b"",
                    work,
                    captures,
                });
            }
            HirKind::Literal(literal) => {
                return Ok(LiteralInspection::Eligible {
                    needle: literal.0.as_ref(),
                    work,
                    captures,
                });
            }
            _ => {
                return Ok(LiteralInspection::Ineligible {
                    work,
                    reason: AggregateLiteralIneligibility::CanonicalRootNotLiteralOrEmpty,
                });
            }
        }
    }
}

/// Reusable production compile artifact with an explicit verification seam.
///
/// The retained plan is complete when this value is returned: no parser,
/// lowerer, planner or plan allocation is deferred until verification.
#[derive(Debug)]
pub struct AggregateCompileRegex(AggregatePlan);

impl AggregateCompileRegex {
    /// Complete construction report and retained-plan identity.
    #[must_use]
    pub const fn build_report(&self) -> &AggregateBuildReport {
        self.0.build_report()
    }

    /// Complete cache identity for later use under the supplied run policy.
    #[must_use]
    pub fn cache_identity(&self, limits: AggregateRunLimits) -> AggregateCacheIdentity {
        self.0.cache_identity(limits)
    }

    /// Untimed semantic verification for compile-model qualification.
    ///
    /// This traverses the complete original haystack with the already
    /// published plan and performs no compilation or fallback.
    pub fn verify_count(
        &self,
        haystack: &[u8],
        limits: AggregateRunLimits,
    ) -> Result<AggregateCountResult, AggregateExecutionError> {
        let execution = self.0.execute_count(haystack, limits)?;
        let value = execution.value();
        let details = execution.into_details();
        let report = self.0.execution_report(limits, details);
        Ok(AggregateCountResult { value, report })
    }
}

/// Compiled complete-span operation.
#[derive(Debug)]
pub struct AggregateSpansRegex(AggregatePlan);

impl AggregateSpansRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateBuildReport {
        self.0.build_report()
    }

    #[must_use]
    pub fn cache_identity(&self, limits: AggregateRunLimits) -> AggregateCacheIdentity {
        self.0.cache_identity(limits)
    }

    /// Execute once on the complete original haystack. Absolute anchors are
    /// therefore never reinterpreted relative to a repeatedly sliced suffix.
    pub fn spans(
        &self,
        haystack: &[u8],
        limits: AggregateRunLimits,
    ) -> Result<AggregateSpans, AggregateExecutionError> {
        let AggregateEngine::Continuation(engine) = &self.0.engine else {
            return Err(self.0.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span operation retained a non-continuation plan",
                ),
            ));
        };
        let strategy = self.0.report.continuation_strategy.ok_or_else(|| {
            self.0.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "continuation span plan lacks storage strategy",
                ),
            )
        })?;
        let admitted = engine
            .admit_spans(
                haystack,
                AggregatePlan::full_range(haystack),
                strategy,
                limits.continuation,
            )
            .map_err(|source| {
                self.0
                    .execution_error(limits, AggregateExecutionSource::Continuation(source))
            })?;
        let details = AggregateExecutionDetails::Continuation {
            certificate: admitted.certificate().clone(),
            accounting: admitted.accounting(),
        };
        let report = self.0.execution_report(limits, details);
        Ok(AggregateSpans { admitted, report })
    }
}

/// Fully admitted immutable whole-match span sequence.
#[derive(Debug)]
pub struct AggregateSpans {
    admitted: AdmittedSpans,
    report: AggregateExecutionReport,
}

impl AggregateSpans {
    #[must_use]
    pub fn iter(&self) -> AggregateSpanIter<'_> {
        AggregateSpanIter {
            inner: self.admitted.iter(),
        }
    }

    #[must_use]
    pub const fn report(&self) -> &AggregateExecutionReport {
        &self.report
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.admitted.as_slice().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.admitted.as_slice().is_empty()
    }
}

impl<'a> IntoIterator for &'a AggregateSpans {
    type Item = Match;
    type IntoIter = AggregateSpanIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Infallible facade iterator over a fully admitted immutable sequence.
#[derive(Clone, Debug)]
pub struct AggregateSpanIter<'a> {
    inner: SpanIter<'a>,
}

impl Iterator for AggregateSpanIter<'_> {
    type Item = Match;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|span| Match {
            start: span.start,
            end: span.end,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for AggregateSpanIter<'_> {}
impl core::iter::FusedIterator for AggregateSpanIter<'_> {}

/// Compiled complete match-count operation.
#[derive(Debug)]
pub struct AggregateCountRegex(AggregatePlan);

impl AggregateCountRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateBuildReport {
        self.0.build_report()
    }

    #[must_use]
    pub fn cache_identity(&self, limits: AggregateRunLimits) -> AggregateCacheIdentity {
        self.0.cache_identity(limits)
    }

    /// Count the complete non-overlapping sequence on the original haystack.
    pub fn count(
        &self,
        haystack: &[u8],
        limits: AggregateRunLimits,
    ) -> Result<AggregateCountResult, AggregateExecutionError> {
        let execution = self.0.execute_count(haystack, limits)?;
        let value = execution.value();
        let details = execution.into_details();
        let report = self.0.execution_report(limits, details);
        Ok(AggregateCountResult { value, report })
    }

    /// Count through the same selected plan and complete preflight as
    /// [`Self::count`], but return only the reducer value. A successful call
    /// does not construct an [`AggregateExecutionReport`], cache identity, or
    /// clone the source-key `Arc`. Failures retain the complete typed identity.
    pub fn count_value(
        &self,
        haystack: &[u8],
        limits: AggregateRunLimits,
    ) -> Result<u64, AggregateExecutionError> {
        self.0
            .execute_count(haystack, limits)
            .map(|execution| execution.value())
    }
}

/// Complete match count and execution certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateCountResult {
    value: u64,
    report: AggregateExecutionReport,
}

impl AggregateCountResult {
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn report(&self) -> &AggregateExecutionReport {
        &self.report
    }
}

/// Compiled complete matched-byte-sum operation.
#[derive(Debug)]
pub struct AggregateSpanSumRegex(AggregatePlan);

impl AggregateSpanSumRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateBuildReport {
        self.0.build_report()
    }

    #[must_use]
    pub fn cache_identity(&self, limits: AggregateRunLimits) -> AggregateCacheIdentity {
        self.0.cache_identity(limits)
    }

    /// Sum complete non-overlapping match lengths on the original haystack.
    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: AggregateRunLimits,
    ) -> Result<AggregateSpanSumResult, AggregateExecutionError> {
        let execution = self.0.execute_span_sum(haystack, limits)?;
        let value = execution.value();
        let details = execution.into_details();
        let report = self.0.execution_report(limits, details);
        Ok(AggregateSpanSumResult { value, report })
    }

    /// Sum spans through the same selected plan and complete preflight as
    /// [`Self::span_sum`], but return only the reducer value. A successful call
    /// does not construct an [`AggregateExecutionReport`], cache identity, or
    /// clone the source-key `Arc`. Failures retain the complete typed identity.
    pub fn span_sum_value(
        &self,
        haystack: &[u8],
        limits: AggregateRunLimits,
    ) -> Result<u64, AggregateExecutionError> {
        self.0
            .execute_span_sum(haystack, limits)
            .map(|execution| execution.value())
    }
}

/// Complete matched-byte sum and execution certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateSpanSumResult {
    value: u64,
    report: AggregateExecutionReport,
}

impl AggregateSpanSumResult {
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn report(&self) -> &AggregateExecutionReport {
        &self.report
    }
}
