use core::{fmt, ops::Range};
use std::sync::Arc;

use fre_aggregate::{
    AdmittedCount, AdmittedSpanSum, AdmittedSpans, CompiledRegex, RustByteProfile, SpanIter,
};
use fre_kernels::{
    FixedClassSandwichBuildAccounting, FixedClassSandwichBuildError, FixedClassSandwichBuildLimits,
    FixedClassSandwichCountResult, FixedClassSandwichOperationIdentity, FixedClassSandwichPlan,
    FixedClassSandwichReduceAccounting, FixedClassSandwichReduceError,
    FixedClassSandwichReduceLimits, FixedClassSandwichSemantics, FixedClassSandwichSpanSumResult,
    LiteralAggregateBuildAccounting, LiteralAggregateBuildError, LiteralAggregateBuildLimits,
    LiteralAggregateCountResult, LiteralAggregateOperationIdentity, LiteralAggregatePlan,
    LiteralAggregateReduceAccounting, LiteralAggregateReduceError, LiteralAggregateReduceLimits,
    LiteralAggregateSpanSumResult, ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    ORDERED_LITERAL_COUNT_PLAN_ID, ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    OrderedLiteralAggregateActualCounters, OrderedLiteralAggregateBuildAccounting,
    OrderedLiteralAggregateBuildError, OrderedLiteralAggregateBuildLimits,
    OrderedLiteralAggregateReduceError, OrderedLiteralAggregateReduceLimits,
    OrderedLiteralAggregateUpperBounds, OrderedLiteralCountPlan, OrderedLiteralSpanSumPlan,
    UnicodeScalarAggregateBuildAccounting, UnicodeScalarAggregateBuildError,
    UnicodeScalarAggregateBuildLimits, UnicodeScalarAggregateCountResult,
    UnicodeScalarAggregateOperationIdentity, UnicodeScalarAggregatePlan,
    UnicodeScalarAggregateReduceAccounting, UnicodeScalarAggregateReduceError,
    UnicodeScalarAggregateReduceLimits, UnicodeScalarAggregateRepetition,
    UnicodeScalarAggregateSpanSumResult,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{
    Class, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange, Hir, HirKind,
};

use crate::{
    AggregateCompileAccounting, AggregateCompileLimits, AggregateEngineError,
    AggregateExecutionAccounting, AggregateOperationCertificate, AggregateOperationLimits,
    AggregatePlanId, BuildError, Match, finite,
};

pub use fre_aggregate::Strategy as AggregateStrategy;

/// Stable schema for aggregate facade reports and cache identities.
pub const AGGREGATE_EXPLAIN_SCHEMA_VERSION: u32 = 13;

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
    /// Select an exact-literal, direct-Unicode, or finite-language plan when
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
    /// Direct Unicode scalar class/run stream over compact canonical ranges.
    /// This is not the continuation state engine.
    UnicodeScalarClass,
    /// Direct bounded circular-window reducer for
    /// `PREFIX MIDDLE{N} SUFFIX` class/literal sequences after transparent
    /// whole-match capture erasure.
    FixedClassSandwich,
    /// Ordered finite HIR lowered to one reversed shared-transition DFA and a
    /// bounded initial/progressed reducer ring.
    FiniteLiteralDfa,
    /// Bounded prioritized continuation program from `fre-aggregate`.
    ContinuationProgram,
}

/// Stable identity for the selected operation-specific implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregatePlanIdentity {
    /// Exact-literal plan plus count/span-sum operation identity.
    ExactLiteral(AggregateExactLiteralIdentity),
    /// Root Unicode scalar-class proof plus native reducer identity.
    UnicodeScalar(AggregateUnicodeScalarIdentity),
    /// Fixed-width three-atom class sequence plus native reducer identity.
    FixedClassSandwich(AggregateFixedClassSandwichIdentity),
    /// Finite-language DFA identity; the syntax key retains exact source and
    /// profile identity, including order, duplicates and arbitrary bytes.
    FiniteLiteral(AggregateFiniteLiteralIdentity),
    /// Semantic continuation-program identity.
    Continuation(AggregateContinuationIdentity),
}

/// Operation-specific identity for the shared finite-language reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFiniteLiteralIdentity {
    pub semantics: AggregateFiniteLiteralSemantics,
    pub algorithm: &'static str,
    pub operation: &'static str,
}

/// Profile proof attached to the shared finite-language reducer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateFiniteLiteralSemantics {
    /// Rust bytes with Unicode disabled and empty matches at byte boundaries.
    UnicodeOffByteBoundaries,
    /// Rust bytes with Unicode enabled and `utf8(false)`, restricted to an
    /// exactly enumerated language of nonempty valid UTF-8 words. Every word
    /// starts with ASCII or a UTF-8 leading byte and ends on a scalar boundary.
    UnicodeOnNonemptyUtf8Words,
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

/// Profile and HIR-shape proof attached to the direct scalar reducer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateUnicodeScalarSemantics {
    /// Rust bytes with Unicode enabled and `utf8(false)`, restricted to one
    /// canonical nonempty root scalar class after transparent captures.
    UnicodeOnRootClassUtf8False,
    /// Rust bytes with Unicode enabled and `utf8(false)`, restricted to a
    /// canonical scalar class under one greedy nonempty unbounded repetition.
    UnicodeOnRootClassOneOrMoreGreedyUtf8False,
    /// The same proof for lazy `CLASS+?`, which emits one scalar per match.
    UnicodeOnRootClassOneOrMoreLazyUtf8False,
    /// Rust bytes with Unicode enabled and `utf8(false)`, restricted to one
    /// greedy nullable unbounded root scalar-class repetition for span-sum.
    /// Its positive spans are exactly those of greedy `CLASS+`; the additional
    /// empty matches contribute zero to the aggregate.
    UnicodeOnRootClassZeroOrMoreGreedySpanSumUtf8False,
    /// Rust bytes with Unicode enabled and `utf8(false)`, restricted to a
    /// canonical scalar class under one non-nullable counted or
    /// lower-bounded repetition. Bounds remain symbolic in the direct
    /// deterministic reducer.
    UnicodeOnRootClassRepeatedUtf8False,
    /// Rust bytes with Unicode enabled and `utf8(false)`, restricted to an
    /// ordered alternation of one-capture fixed repetitions over one identical
    /// scalar class. Descending consecutive bounds are equivalent to one
    /// greedy bounded repetition, and exactly one user capture participates
    /// in every nonempty match.
    UnicodeOnUniformCapturedAlternationRepeatedUtf8False,
}

/// Facade identity for the construction-selected direct scalar reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateUnicodeScalarIdentity {
    pub semantics: AggregateUnicodeScalarSemantics,
    /// User capture groups proved to participate in every emitted match.
    /// Group zero is deliberately excluded.
    pub participating_captures_per_match: usize,
    pub kernel: UnicodeScalarAggregateOperationIdentity,
}

/// Profile proof attached to the fixed class-sandwich reducer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateFixedClassSandwichSemantics {
    /// Rust bytes with Unicode disabled; each admitted unit is one byte.
    UnicodeOffByteClasses,
    /// Rust bytes with Unicode enabled and `utf8(false)`; admitted units are
    /// valid decoded scalars and malformed bytes break the pending window.
    UnicodeOnScalarClassesUtf8False,
}

/// Facade identity for the construction-selected fixed class reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedClassSandwichIdentity {
    pub semantics: AggregateFixedClassSandwichSemantics,
    pub kernel: FixedClassSandwichOperationIdentity,
}

/// Profile proof attached to a continuation-program facade identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateContinuationSemantics {
    /// Rust bytes with Unicode disabled and empty matches at every byte
    /// boundary.
    UnicodeOffByteBoundaries,
    /// Rust bytes with Unicode enabled, `utf8(false)` and `utf8_empty(false)`.
    /// Scalar classes use canonical UTF-8 paths; raw byte HIR stays byte
    /// oriented. Positive Unicode word-boundary plans additionally make a
    /// typed admission refusal on malformed UTF-8.
    UnicodeOnUtf8ScalarHir,
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
    /// Compact scalar-range plan construction certificate.
    UnicodeScalar(UnicodeScalarAggregateBuildAccounting),
    /// Bounded class-sandwich construction certificate.
    FixedClassSandwich(FixedClassSandwichBuildAccounting),
    /// Shared reversed DFA construction certificate.
    FiniteLiteral(OrderedLiteralAggregateBuildAccounting),
    /// Continuation compiler construction certificate.
    Continuation(AggregateCompileAccounting),
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
    /// Maximum allocation-free root scalar-class structural inspection work.
    /// One unit is charged for every HIR node and canonical scalar range
    /// examined by selection.
    pub max_unicode_scalar_planner_work: usize,
    /// Maximum structural HIR/range inspection work for the fixed-width
    /// class-sandwich specialization.
    pub max_fixed_class_sandwich_planner_work: usize,
    /// Maximum checked work for finite-language shape analysis and expansion.
    pub max_finite_planner_work: u64,
    /// Complete exact-literal kernel construction limits.
    pub exact_literal: LiteralAggregateBuildLimits,
    /// Complete compact scalar-range construction limits.
    pub unicode_scalar: UnicodeScalarAggregateBuildLimits,
    /// Complete bounded fixed-class construction limits.
    pub fixed_class_sandwich: FixedClassSandwichBuildLimits,
    /// Complete bounded reversed-DFA construction limits.
    pub finite_literal: OrderedLiteralAggregateBuildLimits,
    /// Complete bounded continuation-program compiler limits.
    pub continuation: AggregateCompileLimits,
}

impl Default for AggregateBuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_literal_planner_work: 4_096,
            max_unicode_scalar_planner_work: 4_096,
            max_fixed_class_sandwich_planner_work: 4_096,
            max_finite_planner_work: 8_000_000,
            exact_literal: LiteralAggregateBuildLimits::default(),
            unicode_scalar: UnicodeScalarAggregateBuildLimits::default(),
            fixed_class_sandwich: FixedClassSandwichBuildLimits::default(),
            finite_literal: OrderedLiteralAggregateBuildLimits::default(),
            continuation: AggregateCompileLimits::default(),
        }
    }
}

/// Complete per-invocation limits. Both plan families remain visible so an
/// `Auto` build cannot hide a policy change when its selected plan changes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateRunLimits {
    /// Exact-literal whole-operation reducer limits.
    pub exact_literal: LiteralAggregateReduceLimits,
    /// Direct Unicode scalar-stream limits.
    pub unicode_scalar: UnicodeScalarAggregateReduceLimits,
    /// Direct fixed-class circular-window limits.
    pub fixed_class_sandwich: FixedClassSandwichReduceLimits,
    /// Shared finite-language DFA reducer limits.
    pub finite_literal: OrderedLiteralAggregateReduceLimits,
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
    /// Direct-root exact-literal inspection work. This is zero when forced
    /// continuation skips inspection.
    pub planner_work: usize,
    /// Root Unicode scalar-class structural inspection work. This is zero when
    /// scalar inspection is skipped; otherwise it records the attempted HIR
    /// and canonical-range inspection even when continuation is selected. It
    /// is not an executed-CPU-instruction count.
    pub unicode_scalar_planner_work: usize,
    /// Fixed-class sandwich structural inspection work, including every HIR
    /// node and canonical range examined through transparent captures.
    pub fixed_class_sandwich_planner_work: usize,
    /// Checked finite-language analysis/expansion work, or zero when skipped.
    /// This remains nonzero when `Auto` proves a finite language but a typed
    /// caller limit rejects the optional DFA preflight and continuation is
    /// selected. A rejected DFA publishes neither build accounting nor plan
    /// identity; its caller-bounded preflight is not double-counted as work of
    /// the selected continuation artifact.
    pub finite_planner_work: u64,
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
    /// Allocation-free root scalar-class inspection crossed its structural
    /// work cap.
    UnicodeScalarPlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
    },
    /// Fixed class-sandwich inspection crossed its structural work cap.
    FixedClassSandwichPlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
    },
    /// Finite-language extraction crossed its explicit work cap.
    FinitePlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: u64,
        limit: u64,
    },
    /// A checked finite-language planner allocation failed.
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
    /// Compact Unicode scalar-class construction failed after selection.
    UnicodeScalarBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: UnicodeScalarAggregateBuildError,
    },
    /// Fixed class-sandwich construction failed after selection.
    FixedClassSandwichBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: FixedClassSandwichBuildError,
    },
    /// Reversed finite-language DFA construction failed after selection.
    FiniteLiteralBuild {
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
    #[allow(
        clippy::too_many_lines,
        reason = "each typed construction refusal retains operation, policy and owned source context"
    )]
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
            Self::UnicodeScalarPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} Unicode scalar inspection needs {needed} structural work units, limit is {limit}"
            ),
            Self::FixedClassSandwichPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} fixed class-sandwich inspection needs {needed} structural work units, limit is {limit}"
            ),
            Self::FinitePlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} finite-language planning needs {needed} work units, limit is {limit}"
            ),
            Self::FinitePlannerAllocationFailed {
                operation,
                selection,
                structure,
                additional,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} failed to reserve {additional} entries for {structure}"
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
            Self::UnicodeScalarBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} Unicode scalar construction failed: {source}"
            ),
            Self::FixedClassSandwichBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} fixed class-sandwich construction failed: {source}"
            ),
            Self::FiniteLiteralBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} finite-language DFA construction failed: {source}"
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
            Self::UnicodeScalarBuild { source, .. } => Some(source),
            Self::FixedClassSandwichBuild { source, .. } => Some(source),
            Self::FiniteLiteralBuild { source, .. } => Some(source),
            Self::ContinuationCompile { source, .. } => Some(source),
            Self::LiteralPlannerWorkLimit { .. }
            | Self::UnicodeScalarPlannerWorkLimit { .. }
            | Self::FixedClassSandwichPlannerWorkLimit { .. }
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
    /// Direct Unicode scalar-stream refusal.
    UnicodeScalar(UnicodeScalarAggregateReduceError),
    /// Direct fixed class-sandwich refusal.
    FixedClassSandwich(FixedClassSandwichReduceError),
    /// Shared finite-language DFA whole-operation refusal.
    FiniteLiteral(OrderedLiteralAggregateReduceError),
    /// Continuation whole-operation refusal.
    Continuation(AggregateEngineError),
    /// Facade conversion or selected-plan invariant failure.
    InternalInvariant(&'static str),
}

impl fmt::Display for AggregateExecutionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactLiteral(source) => source.fmt(f),
            Self::UnicodeScalar(source) => source.fmt(f),
            Self::FixedClassSandwich(source) => source.fmt(f),
            Self::FiniteLiteral(source) => source.fmt(f),
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
            Self::UnicodeScalar(source) => Some(source),
            Self::FixedClassSandwich(source) => Some(source),
            Self::FiniteLiteral(source) => Some(source),
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
    /// Direct scalar stream's complete bounds and structural counters.
    UnicodeScalar(UnicodeScalarAggregateReduceAccounting),
    /// Fixed class-sandwich bounds, counters, and operation identity.
    FixedClassSandwich(FixedClassSandwichReduceAccounting),
    /// Finite-language structural upper bounds and exact counters. The build
    /// report and syntax key retain the immutable DFA and language identity.
    FiniteLiteral {
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

/// `Auto` treats the finite DFA as an optional specialization only when its
/// checked preflight reaches a caller-selected resource ceiling. Errors that
/// can indicate a broken proof, arithmetic bug, allocator failure, or an
/// unrepresentable construction stay visible instead of being disguised by a
/// continuation retry.
fn finite_build_limit_allows_continuation(source: &OrderedLiteralAggregateBuildError) -> bool {
    matches!(
        source,
        OrderedLiteralAggregateBuildError::PatternLimit { .. }
            | OrderedLiteralAggregateBuildError::PatternBytesLimit { .. }
            | OrderedLiteralAggregateBuildError::IdentityBytesLimit { .. }
            | OrderedLiteralAggregateBuildError::TrieStatesLimit { .. }
            | OrderedLiteralAggregateBuildError::DfaCellsLimit { .. }
            | OrderedLiteralAggregateBuildError::WorkLimit { .. }
            | OrderedLiteralAggregateBuildError::ScratchLimit { .. }
            | OrderedLiteralAggregateBuildError::PersistentLimit { .. }
            | OrderedLiteralAggregateBuildError::PeakLimit { .. }
    )
}

impl AggregateBuilder {
    /// Start from the pinned Rust byte profile. Unicode defaults to enabled;
    /// exact literals and bounded UTF-8 scalar continuation HIR are admitted
    /// in that mode.
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
    /// separately certified UTF-8 scalar continuation subset.
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
                unicode_scalar_planner_work: 0,
                fixed_class_sandwich_planner_work: 0,
                finite_planner_work: 0,
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

        let scalar_inspection = if unicode
            && selection == AggregatePlanSelection::Auto
            && operation != AggregateOperation::Spans
        {
            Some(
                inspect_unicode_scalar_class(
                    &rust.hir,
                    limits.max_unicode_scalar_planner_work,
                    operation == AggregateOperation::SpanSum,
                )
                .map_err(|error| match error {
                    UnicodeScalarInspectionError::WorkLimit { needed, limit } => {
                        AggregateBuildError::UnicodeScalarPlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit,
                        }
                    }
                    UnicodeScalarInspectionError::Overflow => {
                        AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "Unicode scalar inspection accounting overflow",
                        }
                    }
                })?,
            )
        } else {
            None
        };
        let unicode_scalar_planner_work = match scalar_inspection {
            Some(UnicodeScalarInspection::Eligible {
                class,
                repetition,
                semantics,
                participating_captures_per_match,
                work,
                hir_nodes,
                captures,
                nullable_greedy_span_sum,
            }) => {
                if hir_nodes != expected_nodes || captures != expected_captures {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "syntax summary differs from Unicode scalar inspection",
                    });
                }
                if nullable_greedy_span_sum
                    && (operation != AggregateOperation::SpanSum
                        || repetition != UnicodeScalarAggregateRepetition::OneOrMoreGreedy)
                {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "nullable scalar repetition escaped its span-sum proof",
                    });
                }
                let ranges = || {
                    class
                        .ranges()
                        .iter()
                        .map(|range| (range.start(), range.end()))
                };
                let engine = match repetition {
                    UnicodeScalarAggregateRepetition::ExactlyOne => {
                        UnicodeScalarAggregatePlan::build(ranges(), limits.unicode_scalar)
                    }
                    UnicodeScalarAggregateRepetition::OneOrMoreGreedy => {
                        UnicodeScalarAggregatePlan::build_one_or_more(
                            ranges(),
                            true,
                            limits.unicode_scalar,
                        )
                    }
                    UnicodeScalarAggregateRepetition::OneOrMoreLazy => {
                        UnicodeScalarAggregatePlan::build_one_or_more(
                            ranges(),
                            false,
                            limits.unicode_scalar,
                        )
                    }
                    UnicodeScalarAggregateRepetition::RepeatedGreedy { minimum, maximum } => {
                        UnicodeScalarAggregatePlan::build_repeated(
                            ranges(),
                            minimum,
                            maximum,
                            true,
                            limits.unicode_scalar,
                        )
                    }
                    UnicodeScalarAggregateRepetition::RepeatedLazy { minimum, maximum } => {
                        UnicodeScalarAggregatePlan::build_repeated(
                            ranges(),
                            minimum,
                            maximum,
                            false,
                            limits.unicode_scalar,
                        )
                    }
                }
                .map_err(|source| AggregateBuildError::UnicodeScalarBuild {
                    operation,
                    selection,
                    source,
                })?;
                let build = engine.build_accounting();
                let kernel = match operation {
                    AggregateOperation::Compile | AggregateOperation::Count => {
                        engine.count_identity()
                    }
                    AggregateOperation::SpanSum => engine.span_sum_identity(),
                    AggregateOperation::Spans => {
                        return Err(AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "span iteration selected Unicode scalar reducer",
                        });
                    }
                };
                let report = AggregateBuildReport {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key,
                    admission,
                    syntax,
                    operation,
                    selection,
                    plan: AggregatePlanKind::UnicodeScalarClass,
                    continuation_strategy: None,
                    capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                    planner_work,
                    unicode_scalar_planner_work: work,
                    fixed_class_sandwich_planner_work: 0,
                    finite_planner_work: 0,
                    capture_erasure_work: captures,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::UnicodeScalar(build),
                    plan_identity: AggregatePlanIdentity::UnicodeScalar(
                        AggregateUnicodeScalarIdentity {
                            semantics: if nullable_greedy_span_sum {
                                AggregateUnicodeScalarSemantics::UnicodeOnRootClassZeroOrMoreGreedySpanSumUtf8False
                            } else {
                                semantics
                            },
                            participating_captures_per_match,
                            kernel,
                        },
                    ),
                    retained_capacity_bytes: build.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::UnicodeScalar(engine),
                    limits,
                    report,
                });
            }
            Some(UnicodeScalarInspection::Ineligible { work }) => work,
            None => 0,
        };
        let fixed_class_inspection = if selection == AggregatePlanSelection::Auto
            && operation != AggregateOperation::Spans
        {
            Some(
                inspect_fixed_class_sandwich(
                    &rust.hir,
                    unicode,
                    limits.max_fixed_class_sandwich_planner_work,
                )
                .map_err(|error| match error {
                    FixedClassSandwichInspectionError::WorkLimit { needed, limit } => {
                        AggregateBuildError::FixedClassSandwichPlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit,
                        }
                    }
                    FixedClassSandwichInspectionError::Overflow => {
                        AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "fixed class-sandwich inspection accounting overflow",
                        }
                    }
                })?,
            )
        } else {
            None
        };
        let fixed_class_sandwich_planner_work = match fixed_class_inspection {
            Some(FixedClassSandwichInspection::Eligible {
                prefix,
                middle,
                suffix,
                middle_repetitions,
                semantics,
                work,
                hir_nodes,
                captures,
            }) => {
                if hir_nodes != expected_nodes || captures != expected_captures {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "syntax summary differs from fixed class-sandwich inspection",
                    });
                }
                let engine = FixedClassSandwichPlan::build_ranges(
                    prefix.ranges(),
                    middle.ranges(),
                    suffix.ranges(),
                    semantics,
                    middle_repetitions,
                    limits.fixed_class_sandwich,
                )
                .map_err(|source| {
                    AggregateBuildError::FixedClassSandwichBuild {
                        operation,
                        selection,
                        source,
                    }
                })?;
                let build = engine.build_accounting();
                let kernel = match operation {
                    AggregateOperation::Compile | AggregateOperation::Count => {
                        engine.count_identity()
                    }
                    AggregateOperation::SpanSum => engine.span_sum_identity(),
                    AggregateOperation::Spans => {
                        return Err(AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "span iteration selected fixed class-sandwich reducer",
                        });
                    }
                };
                let report = AggregateBuildReport {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key,
                    admission,
                    syntax,
                    operation,
                    selection,
                    plan: AggregatePlanKind::FixedClassSandwich,
                    continuation_strategy: None,
                    capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                    planner_work,
                    unicode_scalar_planner_work,
                    fixed_class_sandwich_planner_work: work,
                    finite_planner_work: 0,
                    capture_erasure_work: captures,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::FixedClassSandwich(build),
                    plan_identity: AggregatePlanIdentity::FixedClassSandwich(
                        AggregateFixedClassSandwichIdentity {
                            semantics: match semantics {
                                FixedClassSandwichSemantics::RustBytesUnicodeOff => {
                                    AggregateFixedClassSandwichSemantics::UnicodeOffByteClasses
                                }
                                FixedClassSandwichSemantics::RustBytesUnicodeUtf8False => {
                                    AggregateFixedClassSandwichSemantics::UnicodeOnScalarClassesUtf8False
                                }
                            },
                            kernel,
                        },
                    ),
                    retained_capacity_bytes: build.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::FixedClassSandwich(engine),
                    limits,
                    report,
                });
            }
            Some(FixedClassSandwichInspection::Ineligible { work }) => work,
            None => 0,
        };
        let finite = if selection == AggregatePlanSelection::Auto
            && operation != AggregateOperation::Spans
        {
            Some(
                finite::extract(
                    &rust.hir,
                    limits.finite_literal.max_patterns,
                    limits.finite_literal.max_pattern_bytes,
                    0,
                    limits.max_finite_planner_work,
                )
                .map_err(|error| match error {
                    BuildError::PlannerWorkLimit { needed, limit } => {
                        AggregateBuildError::FinitePlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit,
                        }
                    }
                    BuildError::AllocationFailed {
                        structure,
                        additional,
                    } => AggregateBuildError::FinitePlannerAllocationFailed {
                        operation,
                        selection,
                        structure,
                        additional,
                    },
                    _ => AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "finite-language planner returned an unrelated facade error",
                    },
                })?,
            )
        } else {
            None
        };
        let finite_planner_work = finite.as_ref().map_or(0, |result| result.work);
        let finite_words = finite
            .and_then(|result| result.words)
            .filter(|words| !unicode || unicode_finite_words_preserve_scalar_boundaries(words));
        if let Some(words) = finite_words {
            let capture_erasure_work =
                expected_captures
                    .checked_mul(2)
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "finite capture-erasure accounting overflow",
                    })?;
            let finite_build = match operation {
                AggregateOperation::Compile | AggregateOperation::Count => {
                    OrderedLiteralCountPlan::build(&words, limits.finite_literal).map(|engine| {
                        let build = engine.build_accounting();
                        (
                            AggregateEngine::FiniteCount(engine),
                            build,
                            ORDERED_LITERAL_COUNT_PLAN_ID,
                        )
                    })
                }
                AggregateOperation::SpanSum => {
                    OrderedLiteralSpanSumPlan::build(&words, limits.finite_literal).map(|engine| {
                        let build = engine.build_accounting();
                        (
                            AggregateEngine::FiniteSpanSum(engine),
                            build,
                            ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
                        )
                    })
                }
                AggregateOperation::Spans => {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "span materialization selected finite reducer",
                    });
                }
            };
            match finite_build {
                Ok((engine, build, operation_id)) => {
                    let report = AggregateBuildReport {
                        schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                        syntax_key,
                        admission,
                        syntax,
                        operation,
                        selection,
                        plan: AggregatePlanKind::FiniteLiteralDfa,
                        continuation_strategy: None,
                        capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                        planner_work,
                        unicode_scalar_planner_work,
                        fixed_class_sandwich_planner_work,
                        finite_planner_work,
                        capture_erasure_work,
                        captures_erased: expected_captures,
                        build: AggregateBuildAccounting::FiniteLiteral(build),
                        plan_identity: AggregatePlanIdentity::FiniteLiteral(
                            AggregateFiniteLiteralIdentity {
                                semantics: if unicode {
                                    AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
                                } else {
                                    AggregateFiniteLiteralSemantics::UnicodeOffByteBoundaries
                                },
                                algorithm: ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                                operation: operation_id,
                            },
                        ),
                        retained_capacity_bytes: build.persistent_bytes,
                    };
                    return Ok(AggregatePlan {
                        engine,
                        limits,
                        report,
                    });
                }
                Err(source) if finite_build_limit_allows_continuation(&source) => {}
                Err(source) => {
                    return Err(AggregateBuildError::FiniteLiteralBuild {
                        operation,
                        selection,
                        source,
                    });
                }
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
            unicode_scalar_planner_work,
            fixed_class_sandwich_planner_work,
            finite_planner_work,
            capture_erasure_work: compile.capture_erasure_work,
            captures_erased: compile.captures_erased,
            build: AggregateBuildAccounting::Continuation(compile),
            plan_identity: AggregatePlanIdentity::Continuation(AggregateContinuationIdentity {
                semantics: if unicode {
                    AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir
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

fn unicode_finite_words_preserve_scalar_boundaries(words: &[Vec<u8>]) -> bool {
    !words.is_empty()
        && words
            .iter()
            .all(|word| !word.is_empty() && core::str::from_utf8(word).is_ok())
}

#[derive(Debug)]
enum AggregateEngine {
    ExactLiteral(LiteralAggregatePlan),
    UnicodeScalar(UnicodeScalarAggregatePlan),
    FixedClassSandwich(FixedClassSandwichPlan),
    FiniteCount(OrderedLiteralCountPlan),
    FiniteSpanSum(OrderedLiteralSpanSumPlan),
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

    fn cache_identity(&self, execution_limits: &AggregateRunLimits) -> AggregateCacheIdentity {
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
            execution_limits: *execution_limits,
        }
    }

    fn execution_error(
        &self,
        execution_limits: &AggregateRunLimits,
        source: AggregateExecutionSource,
    ) -> AggregateExecutionError {
        AggregateExecutionError {
            identity: Box::new(self.cache_identity(execution_limits)),
            source,
        }
    }

    fn execution_report(
        &self,
        execution_limits: &AggregateRunLimits,
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
        limits: &AggregateRunLimits,
    ) -> Result<AggregateCountExecution, AggregateExecutionError> {
        match &self.engine {
            AggregateEngine::ExactLiteral(engine) => engine
                .count(haystack, limits.exact_literal)
                .map(AggregateCountExecution::ExactLiteral)
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::ExactLiteral(source))
                }),
            AggregateEngine::UnicodeScalar(engine) => engine
                .count(haystack, limits.unicode_scalar)
                .map(AggregateCountExecution::UnicodeScalar)
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::UnicodeScalar(source))
                }),
            AggregateEngine::FixedClassSandwich(engine) => engine
                .count(haystack, limits.fixed_class_sandwich)
                .map(AggregateCountExecution::FixedClassSandwich)
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::FixedClassSandwich(source),
                    )
                }),
            AggregateEngine::FiniteCount(engine) => engine
                .count(haystack, limits.finite_literal)
                .map(|result| AggregateCountExecution::FiniteLiteral {
                    value: result.count,
                    upper_bounds: result.accounting.upper_bounds,
                    actual: result.accounting.actual,
                })
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::FiniteLiteral(source))
                }),
            AggregateEngine::FiniteSpanSum(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "count operation retained a finite span-sum plan",
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
        limits: &AggregateRunLimits,
    ) -> Result<AggregateSpanSumExecution, AggregateExecutionError> {
        match &self.engine {
            AggregateEngine::ExactLiteral(engine) => engine
                .span_sum(haystack, limits.exact_literal)
                .map(AggregateSpanSumExecution::ExactLiteral)
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::ExactLiteral(source))
                }),
            AggregateEngine::UnicodeScalar(engine) => engine
                .span_sum(haystack, limits.unicode_scalar)
                .map(AggregateSpanSumExecution::UnicodeScalar)
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::UnicodeScalar(source))
                }),
            AggregateEngine::FixedClassSandwich(engine) => engine
                .span_sum(haystack, limits.fixed_class_sandwich)
                .map(AggregateSpanSumExecution::FixedClassSandwich)
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::FixedClassSandwich(source),
                    )
                }),
            AggregateEngine::FiniteSpanSum(engine) => engine
                .span_sum(haystack, limits.finite_literal)
                .map(|result| AggregateSpanSumExecution::FiniteLiteral {
                    value: result.span_sum,
                    upper_bounds: result.accounting.upper_bounds,
                    actual: result.accounting.actual,
                })
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::FiniteLiteral(source))
                }),
            AggregateEngine::FiniteCount(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span-sum operation retained a finite count plan",
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
    UnicodeScalar(UnicodeScalarAggregateCountResult),
    FixedClassSandwich(FixedClassSandwichCountResult),
    FiniteLiteral {
        value: u64,
        upper_bounds: OrderedLiteralAggregateUpperBounds,
        actual: OrderedLiteralAggregateActualCounters,
    },
    Continuation {
        admitted: AdmittedCount,
        value: u64,
    },
}

impl AggregateCountExecution {
    const fn value(&self) -> u64 {
        match self {
            Self::ExactLiteral(result) => result.count,
            Self::UnicodeScalar(result) => result.count,
            Self::FixedClassSandwich(result) => result.count,
            Self::FiniteLiteral { value, .. } | Self::Continuation { value, .. } => *value,
        }
    }

    fn into_details(self) -> AggregateExecutionDetails {
        match self {
            Self::ExactLiteral(result) => {
                AggregateExecutionDetails::ExactLiteral(result.accounting)
            }
            Self::UnicodeScalar(result) => {
                AggregateExecutionDetails::UnicodeScalar(result.accounting)
            }
            Self::FixedClassSandwich(result) => {
                AggregateExecutionDetails::FixedClassSandwich(result.accounting)
            }
            Self::FiniteLiteral {
                upper_bounds,
                actual,
                ..
            } => AggregateExecutionDetails::FiniteLiteral {
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
    UnicodeScalar(UnicodeScalarAggregateSpanSumResult),
    FixedClassSandwich(FixedClassSandwichSpanSumResult),
    FiniteLiteral {
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
            Self::UnicodeScalar(result) => result.span_sum,
            Self::FixedClassSandwich(result) => result.span_sum,
            Self::FiniteLiteral { value, .. } | Self::Continuation { value, .. } => *value,
        }
    }

    fn into_details(self) -> AggregateExecutionDetails {
        match self {
            Self::ExactLiteral(result) => {
                AggregateExecutionDetails::ExactLiteral(result.accounting)
            }
            Self::UnicodeScalar(result) => {
                AggregateExecutionDetails::UnicodeScalar(result.accounting)
            }
            Self::FixedClassSandwich(result) => {
                AggregateExecutionDetails::FixedClassSandwich(result.accounting)
            }
            Self::FiniteLiteral {
                upper_bounds,
                actual,
                ..
            } => AggregateExecutionDetails::FiniteLiteral {
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

enum UnicodeScalarInspection<'a> {
    Eligible {
        class: &'a ClassUnicode,
        repetition: UnicodeScalarAggregateRepetition,
        semantics: AggregateUnicodeScalarSemantics,
        participating_captures_per_match: usize,
        work: usize,
        hir_nodes: usize,
        captures: usize,
        nullable_greedy_span_sum: bool,
    },
    Ineligible {
        work: usize,
    },
}

enum UnicodeScalarInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

#[derive(Clone, Copy)]
enum FixedClassAtom<'a> {
    Bytes(&'a ClassBytes),
    Unicode(&'a ClassUnicode),
    Singleton(u32),
}

impl<'a> FixedClassAtom<'a> {
    fn ranges(self) -> FixedClassRanges<'a> {
        match self {
            Self::Bytes(class) => FixedClassRanges::Bytes(class.ranges().iter()),
            Self::Unicode(class) => FixedClassRanges::Unicode(class.ranges().iter()),
            Self::Singleton(scalar) => FixedClassRanges::Singleton(Some(scalar)),
        }
    }

    fn range_count(self) -> usize {
        match self {
            Self::Bytes(class) => class.ranges().len(),
            Self::Unicode(class) => class.ranges().len(),
            Self::Singleton(_) => 1,
        }
    }
}

enum FixedClassRanges<'a> {
    Bytes(core::slice::Iter<'a, ClassBytesRange>),
    Unicode(core::slice::Iter<'a, ClassUnicodeRange>),
    Singleton(Option<u32>),
}

impl Iterator for FixedClassRanges<'_> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Bytes(ranges) => ranges
                .next()
                .map(|range| (u32::from(range.start()), u32::from(range.end()))),
            Self::Unicode(ranges) => ranges
                .next()
                .map(|range| (u32::from(range.start()), u32::from(range.end()))),
            Self::Singleton(scalar) => scalar.take().map(|value| (value, value)),
        }
    }
}

enum FixedClassSandwichInspection<'a> {
    Eligible {
        prefix: FixedClassAtom<'a>,
        middle: FixedClassAtom<'a>,
        suffix: FixedClassAtom<'a>,
        middle_repetitions: u32,
        semantics: FixedClassSandwichSemantics,
        work: usize,
        hir_nodes: usize,
        captures: usize,
    },
    Ineligible {
        work: usize,
    },
}

enum FixedClassSandwichInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

fn inspect_fixed_class_sandwich(
    hir: &Hir,
    unicode: bool,
    limit: usize,
) -> Result<FixedClassSandwichInspection<'_>, FixedClassSandwichInspectionError> {
    let mut work = 0_usize;
    let mut hir_nodes = 0_usize;
    let mut captures = 0_usize;
    let hir = peel_fixed_class_captures(hir, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(FixedClassSandwichInspection::Ineligible { work });
    };
    let [prefix_hir, middle_hir, suffix_hir] = parts.as_slice() else {
        return Ok(FixedClassSandwichInspection::Ineligible { work });
    };

    let prefix_hir =
        peel_fixed_class_captures(prefix_hir, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let Some(prefix) = inspect_fixed_class_atom(prefix_hir, unicode) else {
        return Ok(FixedClassSandwichInspection::Ineligible { work });
    };

    let middle_hir =
        peel_fixed_class_captures(middle_hir, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let HirKind::Repetition(repeated) = middle_hir.kind() else {
        return Ok(FixedClassSandwichInspection::Ineligible { work });
    };
    let Some(maximum) = repeated.max else {
        return Ok(FixedClassSandwichInspection::Ineligible { work });
    };
    if repeated.min == 0 || repeated.min != maximum {
        return Ok(FixedClassSandwichInspection::Ineligible { work });
    }

    let repeated_hir = peel_fixed_class_captures(
        repeated.sub.as_ref(),
        &mut work,
        &mut hir_nodes,
        &mut captures,
        limit,
    )?;
    let Some(middle) = inspect_fixed_class_atom(repeated_hir, unicode) else {
        return Ok(FixedClassSandwichInspection::Ineligible { work });
    };

    let suffix_hir =
        peel_fixed_class_captures(suffix_hir, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let Some(suffix) = inspect_fixed_class_atom(suffix_hir, unicode) else {
        return Ok(FixedClassSandwichInspection::Ineligible { work });
    };

    for atom in [prefix, middle, suffix] {
        for _ in 0..atom.range_count() {
            charge_fixed_class_inspection_work(&mut work, limit)?;
        }
    }
    Ok(FixedClassSandwichInspection::Eligible {
        prefix,
        middle,
        suffix,
        middle_repetitions: repeated.min,
        semantics: if unicode {
            FixedClassSandwichSemantics::RustBytesUnicodeUtf8False
        } else {
            FixedClassSandwichSemantics::RustBytesUnicodeOff
        },
        work,
        hir_nodes,
        captures,
    })
}

fn peel_fixed_class_captures<'a>(
    mut hir: &'a Hir,
    work: &mut usize,
    hir_nodes: &mut usize,
    captures: &mut usize,
    limit: usize,
) -> Result<&'a Hir, FixedClassSandwichInspectionError> {
    loop {
        charge_fixed_class_inspection_work(work, limit)?;
        *hir_nodes = (*hir_nodes)
            .checked_add(1)
            .ok_or(FixedClassSandwichInspectionError::Overflow)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        *captures = (*captures)
            .checked_add(1)
            .ok_or(FixedClassSandwichInspectionError::Overflow)?;
        hir = capture.sub.as_ref();
    }
}

fn inspect_fixed_class_atom(hir: &Hir, unicode: bool) -> Option<FixedClassAtom<'_>> {
    match (unicode, hir.kind()) {
        (false, HirKind::Class(Class::Bytes(class))) if !class.ranges().is_empty() => {
            Some(FixedClassAtom::Bytes(class))
        }
        (true, HirKind::Class(Class::Unicode(class))) if !class.ranges().is_empty() => {
            Some(FixedClassAtom::Unicode(class))
        }
        (false, HirKind::Literal(literal)) if literal.0.len() == 1 => {
            Some(FixedClassAtom::Singleton(u32::from(literal.0[0])))
        }
        (true, HirKind::Literal(literal)) => {
            let text = core::str::from_utf8(literal.0.as_ref()).ok()?;
            let mut scalars = text.chars();
            let scalar = scalars.next()?;
            if scalars.next().is_none() {
                Some(FixedClassAtom::Singleton(u32::from(scalar)))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn charge_fixed_class_inspection_work(
    work: &mut usize,
    limit: usize,
) -> Result<(), FixedClassSandwichInspectionError> {
    let needed = work
        .checked_add(1)
        .ok_or(FixedClassSandwichInspectionError::Overflow)?;
    if needed > limit {
        return Err(FixedClassSandwichInspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

fn inspect_unicode_scalar_class(
    mut hir: &Hir,
    limit: usize,
    allow_nullable_greedy_span_sum: bool,
) -> Result<UnicodeScalarInspection<'_>, UnicodeScalarInspectionError> {
    if let HirKind::Alternation(alternatives) = hir.kind() {
        return inspect_uniform_captured_scalar_alternation(alternatives, limit);
    }
    let mut work = 0_usize;
    let mut hir_nodes = 0_usize;
    let mut captures = 0_usize;
    let mut repetition = UnicodeScalarAggregateRepetition::ExactlyOne;
    let mut saw_repetition = false;
    let mut nullable_greedy_span_sum = false;
    loop {
        charge_unicode_scalar_inspection_work(&mut work, limit)?;
        hir_nodes = hir_nodes
            .checked_add(1)
            .ok_or(UnicodeScalarInspectionError::Overflow)?;
        match hir.kind() {
            HirKind::Capture(capture) => {
                captures = captures
                    .checked_add(1)
                    .ok_or(UnicodeScalarInspectionError::Overflow)?;
                hir = capture.sub.as_ref();
            }
            HirKind::Repetition(repeated) if !saw_repetition && repeated.min > 0 => {
                repetition = match (repeated.min, repeated.max, repeated.greedy) {
                    (1, None, true) => UnicodeScalarAggregateRepetition::OneOrMoreGreedy,
                    (1, None, false) => UnicodeScalarAggregateRepetition::OneOrMoreLazy,
                    (minimum, maximum, true) => {
                        UnicodeScalarAggregateRepetition::RepeatedGreedy { minimum, maximum }
                    }
                    (minimum, maximum, false) => {
                        UnicodeScalarAggregateRepetition::RepeatedLazy { minimum, maximum }
                    }
                };
                saw_repetition = true;
                hir = repeated.sub.as_ref();
            }
            HirKind::Repetition(repeated)
                if !saw_repetition
                    && allow_nullable_greedy_span_sum
                    && repeated.min == 0
                    && repeated.max.is_none()
                    && repeated.greedy =>
            {
                // Greedy `CLASS*` and `CLASS+` have identical positive
                // leftmost-first spans. Only `CLASS*` emits additional empty
                // matches, and those add zero to span-sum. Keep the kernel
                // identity truthful by using its one-or-more reducer while the
                // facade identity records this operation-specific proof.
                repetition = UnicodeScalarAggregateRepetition::OneOrMoreGreedy;
                saw_repetition = true;
                nullable_greedy_span_sum = true;
                hir = repeated.sub.as_ref();
            }
            HirKind::Class(Class::Unicode(class)) => {
                if repetition.is_run() {
                    if class.ranges().is_empty() {
                        return Ok(UnicodeScalarInspection::Ineligible { work });
                    }
                    charge_unicode_scalar_inspection_work(&mut work, limit)?;
                    return Ok(UnicodeScalarInspection::Eligible {
                        class,
                        repetition,
                        semantics: match repetition {
                            UnicodeScalarAggregateRepetition::ExactlyOne => {
                                AggregateUnicodeScalarSemantics::UnicodeOnRootClassUtf8False
                            }
                            UnicodeScalarAggregateRepetition::OneOrMoreGreedy => {
                                AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreGreedyUtf8False
                            }
                            UnicodeScalarAggregateRepetition::OneOrMoreLazy => {
                                AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreLazyUtf8False
                            }
                            UnicodeScalarAggregateRepetition::RepeatedGreedy { .. }
                            | UnicodeScalarAggregateRepetition::RepeatedLazy { .. } => {
                                AggregateUnicodeScalarSemantics::UnicodeOnRootClassRepeatedUtf8False
                            }
                        },
                        participating_captures_per_match: captures,
                        work,
                        hir_nodes,
                        captures,
                        nullable_greedy_span_sum,
                    });
                }
                for range in class.ranges() {
                    charge_unicode_scalar_inspection_work(&mut work, limit)?;
                    if !range.end().is_ascii() && range.start() != range.end() {
                        return Ok(UnicodeScalarInspection::Eligible {
                            class,
                            repetition,
                            semantics: AggregateUnicodeScalarSemantics::UnicodeOnRootClassUtf8False,
                            participating_captures_per_match: captures,
                            work,
                            hir_nodes,
                            captures,
                            nullable_greedy_span_sum,
                        });
                    }
                }
                return Ok(UnicodeScalarInspection::Ineligible { work });
            }
            _ => return Ok(UnicodeScalarInspection::Ineligible { work }),
        }
    }
}

fn inspect_uniform_captured_scalar_alternation(
    alternatives: &[Hir],
    limit: usize,
) -> Result<UnicodeScalarInspection<'_>, UnicodeScalarInspectionError> {
    let mut work = 0_usize;
    let mut hir_nodes = 1_usize;
    let mut captures = 0_usize;
    charge_unicode_scalar_inspection_work(&mut work, limit)?;
    if alternatives.len() < 2 {
        return Ok(UnicodeScalarInspection::Ineligible { work });
    }

    let mut shared_class = None::<&ClassUnicode>;
    let mut maximum = None::<u32>;
    let mut previous = None::<u32>;
    for alternative in alternatives {
        charge_unicode_scalar_inspection_work(&mut work, limit)?;
        hir_nodes = hir_nodes
            .checked_add(1)
            .ok_or(UnicodeScalarInspectionError::Overflow)?;
        let HirKind::Capture(capture) = alternative.kind() else {
            return Ok(UnicodeScalarInspection::Ineligible { work });
        };
        captures = captures
            .checked_add(1)
            .ok_or(UnicodeScalarInspectionError::Overflow)?;

        charge_unicode_scalar_inspection_work(&mut work, limit)?;
        hir_nodes = hir_nodes
            .checked_add(1)
            .ok_or(UnicodeScalarInspectionError::Overflow)?;
        let HirKind::Repetition(repeated) = capture.sub.kind() else {
            return Ok(UnicodeScalarInspection::Ineligible { work });
        };
        if repeated.min == 0 || repeated.max != Some(repeated.min) || !repeated.greedy {
            return Ok(UnicodeScalarInspection::Ineligible { work });
        }
        if let Some(previous) = previous {
            if previous.checked_sub(1) != Some(repeated.min) {
                return Ok(UnicodeScalarInspection::Ineligible { work });
            }
        } else {
            maximum = Some(repeated.min);
        }
        previous = Some(repeated.min);

        charge_unicode_scalar_inspection_work(&mut work, limit)?;
        hir_nodes = hir_nodes
            .checked_add(1)
            .ok_or(UnicodeScalarInspectionError::Overflow)?;
        let HirKind::Class(Class::Unicode(class)) = repeated.sub.kind() else {
            return Ok(UnicodeScalarInspection::Ineligible { work });
        };
        if class.ranges().is_empty() {
            return Ok(UnicodeScalarInspection::Ineligible { work });
        }
        if class.ranges().iter().any(|range| {
            (range.start() <= '\n' && '\n' <= range.end())
                || (range.start() <= '\r' && '\r' <= range.end())
        }) {
            return Ok(UnicodeScalarInspection::Ineligible { work });
        }
        for _ in class.ranges() {
            charge_unicode_scalar_inspection_work(&mut work, limit)?;
        }
        if shared_class.is_some_and(|shared| shared != class) {
            return Ok(UnicodeScalarInspection::Ineligible { work });
        }
        shared_class.get_or_insert(class);
    }

    let Some(class) = shared_class else {
        return Ok(UnicodeScalarInspection::Ineligible { work });
    };
    let Some(minimum) = previous else {
        return Ok(UnicodeScalarInspection::Ineligible { work });
    };
    Ok(UnicodeScalarInspection::Eligible {
        class,
        repetition: UnicodeScalarAggregateRepetition::RepeatedGreedy { minimum, maximum },
        semantics:
            AggregateUnicodeScalarSemantics::UnicodeOnUniformCapturedAlternationRepeatedUtf8False,
        participating_captures_per_match: 1,
        work,
        hir_nodes,
        captures,
        nullable_greedy_span_sum: false,
    })
}

fn charge_unicode_scalar_inspection_work(
    work: &mut usize,
    limit: usize,
) -> Result<(), UnicodeScalarInspectionError> {
    let needed = work
        .checked_add(1)
        .ok_or(UnicodeScalarInspectionError::Overflow)?;
    if needed > limit {
        return Err(UnicodeScalarInspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
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
    pub fn cache_identity(
        &self,
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> AggregateCacheIdentity {
        self.0.cache_identity(limits.borrow())
    }

    /// Untimed semantic verification for compile-model qualification.
    ///
    /// This traverses the complete original haystack with the already
    /// published plan and performs no compilation or fallback.
    pub fn verify_count(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<AggregateCountResult, AggregateExecutionError> {
        let limits = limits.borrow();
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
    pub fn cache_identity(
        &self,
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> AggregateCacheIdentity {
        self.0.cache_identity(limits.borrow())
    }

    /// Execute once on the complete original haystack. Absolute anchors are
    /// therefore never reinterpreted relative to a repeatedly sliced suffix.
    pub fn spans(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<AggregateSpans, AggregateExecutionError> {
        let limits = limits.borrow();
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
        Ok(AggregateSpans {
            admitted,
            report,
            haystack_len: haystack.len(),
        })
    }
}

/// Fully admitted immutable whole-match span sequence.
#[derive(Debug)]
pub struct AggregateSpans {
    admitted: AdmittedSpans,
    report: AggregateExecutionReport,
    haystack_len: usize,
}

impl AggregateSpans {
    #[must_use]
    pub fn iter(&self) -> AggregateSpanIter<'_> {
        AggregateSpanIter {
            inner: self.admitted.iter(),
        }
    }

    /// Partition the complete original haystack into ordered rejected gaps
    /// and selected matches.
    ///
    /// Empty matches remain explicit. The rejected gap following an empty
    /// match is what advances to the next eligible UTF-8 or byte boundary, so
    /// this is a stable equivalent of the behavioral contract exercised by
    /// `regex`'s feature-gated `Pattern` searcher tests. Constructing and
    /// advancing this iterator performs no allocation.
    #[must_use]
    pub fn search_steps(&self) -> AggregateSearchStepIter<'_> {
        AggregateSearchStepIter {
            inner: self.admitted.iter(),
            haystack_len: self.haystack_len,
            cursor: 0,
            pending_match: None,
            finished: false,
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

    pub(crate) fn span_at(&self, index: usize) -> Option<Match> {
        self.admitted.as_slice().get(index).map(|span| Match {
            start: span.start,
            end: span.end,
        })
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

/// One item in a complete search partition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AggregateSearchStep {
    /// A selected non-overlapping match, including an empty match.
    Match(Match),
    /// A maximal unmatched gap between selected matches.
    Reject(Match),
}

impl AggregateSearchStep {
    /// The half-open byte span in the original haystack.
    #[must_use]
    pub const fn span(self) -> Match {
        match self {
            Self::Match(span) | Self::Reject(span) => span,
        }
    }

    /// Whether this step is a selected match rather than a rejected gap.
    #[must_use]
    pub const fn is_match(self) -> bool {
        matches!(self, Self::Match(_))
    }
}

/// Allocation-free iterator over a fully admitted search partition.
#[derive(Clone, Debug)]
pub struct AggregateSearchStepIter<'a> {
    inner: SpanIter<'a>,
    haystack_len: usize,
    cursor: usize,
    pending_match: Option<Match>,
    finished: bool,
}

impl Iterator for AggregateSearchStepIter<'_> {
    type Item = AggregateSearchStep;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if let Some(matched) = self.pending_match.take() {
            self.cursor = matched.end;
            return Some(AggregateSearchStep::Match(matched));
        }
        if let Some(span) = self.inner.next() {
            let matched = Match {
                start: span.start,
                end: span.end,
            };
            debug_assert!(matched.start >= self.cursor);
            if matched.start > self.cursor {
                let rejected = Match {
                    start: self.cursor,
                    end: matched.start,
                };
                self.cursor = matched.start;
                self.pending_match = Some(matched);
                return Some(AggregateSearchStep::Reject(rejected));
            }
            self.cursor = matched.end;
            return Some(AggregateSearchStep::Match(matched));
        }
        if self.cursor < self.haystack_len {
            let rejected = Match {
                start: self.cursor,
                end: self.haystack_len,
            };
            self.cursor = self.haystack_len;
            self.finished = true;
            return Some(AggregateSearchStep::Reject(rejected));
        }
        self.finished = true;
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.finished {
            return (0, Some(0));
        }
        let matches = self
            .inner
            .len()
            .saturating_add(usize::from(self.pending_match.is_some()));
        let upper = matches
            .checked_mul(2)
            .and_then(|steps| steps.checked_add(1));
        (matches, upper)
    }
}

impl core::iter::FusedIterator for AggregateSearchStepIter<'_> {}

/// Compiled complete match-count operation.
#[derive(Debug)]
pub struct AggregateCountRegex(AggregatePlan);

impl AggregateCountRegex {
    #[must_use]
    pub const fn build_report(&self) -> &AggregateBuildReport {
        self.0.build_report()
    }

    #[must_use]
    pub fn cache_identity(
        &self,
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> AggregateCacheIdentity {
        self.0.cache_identity(limits.borrow())
    }

    /// Count the complete non-overlapping sequence on the original haystack.
    pub fn count(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<AggregateCountResult, AggregateExecutionError> {
        let limits = limits.borrow();
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
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<u64, AggregateExecutionError> {
        let limits = limits.borrow();
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
    pub fn cache_identity(
        &self,
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> AggregateCacheIdentity {
        self.0.cache_identity(limits.borrow())
    }

    /// Sum complete non-overlapping match lengths on the original haystack.
    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<AggregateSpanSumResult, AggregateExecutionError> {
        let limits = limits.borrow();
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
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<u64, AggregateExecutionError> {
        let limits = limits.borrow();
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

#[cfg(test)]
mod tests {
    use super::{
        OrderedLiteralAggregateBuildError, UnicodeScalarInspectionError,
        charge_unicode_scalar_inspection_work, finite_build_limit_allows_continuation,
    };

    #[test]
    fn unicode_scalar_inspection_overflow_leaves_counter_unchanged() {
        let mut work = usize::MAX;
        assert!(matches!(
            charge_unicode_scalar_inspection_work(&mut work, usize::MAX),
            Err(UnicodeScalarInspectionError::Overflow)
        ));
        assert_eq!(work, usize::MAX);
    }

    #[test]
    fn finite_auto_fallback_classifies_only_caller_resource_limits() {
        for limit in [
            OrderedLiteralAggregateBuildError::PatternLimit {
                needed: 2,
                limit: 1,
            },
            OrderedLiteralAggregateBuildError::PatternBytesLimit {
                needed: 2,
                limit: 1,
            },
            OrderedLiteralAggregateBuildError::IdentityBytesLimit {
                needed: 2,
                limit: 1,
            },
            OrderedLiteralAggregateBuildError::TrieStatesLimit {
                needed: 2,
                limit: 1,
            },
            OrderedLiteralAggregateBuildError::DfaCellsLimit {
                needed: 2,
                limit: 1,
            },
            OrderedLiteralAggregateBuildError::WorkLimit {
                needed: 2,
                limit: 1,
            },
            OrderedLiteralAggregateBuildError::ScratchLimit {
                needed: 2,
                limit: 1,
            },
            OrderedLiteralAggregateBuildError::PersistentLimit {
                needed: 2,
                limit: 1,
            },
            OrderedLiteralAggregateBuildError::PeakLimit {
                needed: 2,
                limit: 1,
            },
        ] {
            assert!(finite_build_limit_allows_continuation(&limit));
        }

        for hard_error in [
            OrderedLiteralAggregateBuildError::EmptyPatternSet,
            OrderedLiteralAggregateBuildError::RepresentationLimit {
                structure: "test",
                needed: 2,
            },
            OrderedLiteralAggregateBuildError::AllocationFailed {
                structure: "test",
                additional: 1,
            },
            OrderedLiteralAggregateBuildError::InternalInvariant { detail: "test" },
            OrderedLiteralAggregateBuildError::ArithmeticOverflow {
                computation: "test",
            },
        ] {
            assert!(!finite_build_limit_allows_continuation(&hard_error));
        }
    }
}
