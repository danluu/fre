use core::{fmt, ops::Range};
use std::sync::Arc;

use fre_aggregate::{
    AdmittedCount, AdmittedSpanSum, AdmittedSpans, CompiledRegex, RustByteProfile, SpanIter,
};
use fre_kernels::{
    BOUNDED_SEPARATED_FIELDS_MAX_ALTERNATIVES, BOUNDED_SEPARATED_FIELDS_MAX_ATOMS,
    BOUNDED_SEPARATED_FIELDS_MAX_FIELDS, BoundedClassSequenceBuildAccounting,
    BoundedClassSequenceBuildError, BoundedClassSequenceBuildLimits,
    BoundedClassSequenceCountResult, BoundedClassSequenceOperationIdentity,
    BoundedClassSequencePlan, BoundedClassSequenceReduceAccounting,
    BoundedClassSequenceReduceError, BoundedClassSequenceReduceLimits,
    BoundedContextBuildAccounting, BoundedContextBuildError, BoundedContextBuildLimits,
    BoundedContextCountResult, BoundedContextOperationIdentity, BoundedContextPlan,
    BoundedContextReduceAccounting, BoundedContextReduceError, BoundedContextReduceLimits,
    BoundedSeparatedFieldsAlternativeSource, BoundedSeparatedFieldsAtomSource,
    BoundedSeparatedFieldsBuildAccounting, BoundedSeparatedFieldsBuildError,
    BoundedSeparatedFieldsBuildLimits, BoundedSeparatedFieldsCountResult,
    BoundedSeparatedFieldsFieldSource, BoundedSeparatedFieldsOperationIdentity,
    BoundedSeparatedFieldsPlan, BoundedSeparatedFieldsReduceAccounting,
    BoundedSeparatedFieldsReduceError, BoundedSeparatedFieldsReduceLimits,
    FixedClassSandwichBuildAccounting, FixedClassSandwichBuildError, FixedClassSandwichBuildLimits,
    FixedClassSandwichCountResult, FixedClassSandwichOperationIdentity, FixedClassSandwichPlan,
    FixedClassSandwichReduceAccounting, FixedClassSandwichReduceError,
    FixedClassSandwichReduceLimits, FixedClassSandwichSemantics, FixedClassSandwichSpanSumResult,
    GraphemeScalarDfaBuildAccounting, GraphemeScalarDfaBuildError, GraphemeScalarDfaBuildLimits,
    GraphemeScalarDfaCountResult, GraphemeScalarDfaOperationIdentity, GraphemeScalarDfaPlan,
    GraphemeScalarDfaReduceAccounting, GraphemeScalarDfaReduceError, GraphemeScalarDfaReduceLimits,
    GraphemeScalarDfaRole, LiteralAggregateBuildAccounting, LiteralAggregateBuildError,
    LiteralAggregateBuildLimits, LiteralAggregateCountResult, LiteralAggregateOperationIdentity,
    LiteralAggregatePlan, LiteralAggregateReduceAccounting, LiteralAggregateReduceError,
    LiteralAggregateReduceLimits, LiteralAggregateSpanSumResult,
    ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID, ORDERED_LITERAL_COUNT_PLAN_ID,
    ORDERED_LITERAL_SPAN_SUM_PLAN_ID, OrderedLiteralAggregateActualCounters,
    OrderedLiteralAggregateBuildAccounting, OrderedLiteralAggregateBuildError,
    OrderedLiteralAggregateBuildLimits, OrderedLiteralAggregateReduceError,
    OrderedLiteralAggregateReduceLimits, OrderedLiteralAggregateUpperBounds,
    OrderedLiteralCountPlan, OrderedLiteralSpanSumPlan, PrefixClassAlternationBuildAccounting,
    PrefixClassAlternationBuildError, PrefixClassAlternationBuildLimits,
    PrefixClassAlternationCountResult, PrefixClassAlternationOperationIdentity,
    PrefixClassAlternationPlan, PrefixClassAlternationReduceAccounting,
    PrefixClassAlternationReduceError, PrefixClassAlternationReduceLimits,
    SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID, SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
    SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID, SparseOrderedLiteralAggregateActualCounters,
    SparseOrderedLiteralAggregateBuildAccounting, SparseOrderedLiteralAggregateBuildError,
    SparseOrderedLiteralAggregateBuildLimits, SparseOrderedLiteralAggregateReduceError,
    SparseOrderedLiteralAggregateReduceLimits, SparseOrderedLiteralAggregateUpperBounds,
    SparseOrderedLiteralCountPlan, SparseOrderedLiteralSpanSumPlan,
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
    AggregatePlanId, BuildError, Match, finite, finite_root, grapheme_scalar,
};

pub use fre_aggregate::Strategy as AggregateStrategy;

/// Stable schema for aggregate facade reports and cache identities.
pub const AGGREGATE_EXPLAIN_SCHEMA_VERSION: u32 = 21;

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
    /// Direct ordered scalar-property grammar with constant phase state.
    GraphemeScalarDfa,
    /// Linear count reducer for a greedy bounded sequence of deterministic
    /// `HEAD BODY+ TRAIL*` byte-class units.
    BoundedClassSequence,
    /// Constant-frontier count reducer for a fixed number of identical,
    /// one-byte-separator-delimited bounded byte-class fields.
    BoundedSeparatedFields,
    /// Two ordered literal-prefix/greedy-byte-class alternatives merged from
    /// persistent monotone occurrence streams.
    PrefixClassAlternation,
    /// Linear literal-interval stream for a fixed-class/bounded-gap context.
    BoundedContext,
    /// Ordered finite HIR lowered to one reversed shared dense or sparse
    /// automaton and a bounded initial/progressed reducer ring.
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
    /// Ordered scalar-property grammar plus native reducer identity.
    GraphemeScalarDfa(AggregateGraphemeScalarDfaIdentity),
    /// Unicode-off compound byte-class sequence plus count identity.
    BoundedClassSequence(BoundedClassSequenceOperationIdentity),
    /// Unicode-off bounded separated-field proof plus count identity.
    BoundedSeparatedFields(AggregateBoundedSeparatedFieldsIdentity),
    /// Unicode-off two-branch prefix/class proof and native count identity.
    PrefixClassAlternation(AggregatePrefixClassAlternationIdentity),
    /// Bounded byte-context proof plus native count identity.
    BoundedContext(AggregateBoundedContextIdentity),
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

/// Canonical-HIR proof attached to the ordered scalar reducer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateGraphemeScalarDfaSemantics {
    /// Rust bytes with Unicode enabled and `utf8(false)`: captures are
    /// transparent and HIR exactly proves the ordered CRLF/control/
    /// Prepend-Hangul-RI-EP-tail/Any scalar grammar.
    UnicodeOnOrderedScalarGrammarUtf8False,
}

/// Facade identity for the construction-selected ordered scalar reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateGraphemeScalarDfaIdentity {
    pub semantics: AggregateGraphemeScalarDfaSemantics,
    pub kernel: GraphemeScalarDfaOperationIdentity,
}

/// Facade identity for the Unicode-off two-branch prefix/class reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregatePrefixClassAlternationIdentity {
    pub kernel: PrefixClassAlternationOperationIdentity,
}

/// Facade identity for the Unicode-off bounded separated-field reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateBoundedSeparatedFieldsIdentity {
    pub kernel: BoundedSeparatedFieldsOperationIdentity,
}

/// Facade identity for the Unicode-off bounded-context count reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateBoundedContextIdentity {
    pub kernel: BoundedContextOperationIdentity,
}

/// Profile proof attached to a continuation-program facade identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AggregateContinuationSemantics {
    /// Rust bytes with Unicode disabled and empty matches at every byte
    /// boundary.
    UnicodeOffByteBoundaries,
    /// Rust bytes with Unicode enabled, `utf8(false)` and `utf8_empty(false)`.
    /// Scalar classes use compact canonical-scalar transitions with bounded
    /// UTF-8 decoding; raw byte HIR stays byte oriented. Positive Unicode
    /// word-boundary plans additionally make a typed admission refusal on
    /// malformed UTF-8.
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
    /// Ordered scalar-property classifier construction certificate.
    GraphemeScalarDfa(GraphemeScalarDfaBuildAccounting),
    /// Allocation-free bounded compound byte-class construction certificate.
    BoundedClassSequence(BoundedClassSequenceBuildAccounting),
    /// Allocation-free bounded separated-field construction certificate.
    BoundedSeparatedFields(BoundedSeparatedFieldsBuildAccounting),
    /// Two-branch prefix/class construction certificate.
    PrefixClassAlternation(PrefixClassAlternationBuildAccounting),
    /// Bounded-context construction certificate.
    BoundedContext(BoundedContextBuildAccounting),
    /// Shared reversed DFA construction certificate.
    FiniteLiteral(OrderedLiteralAggregateBuildAccounting),
    /// Sparse shared reversed automaton construction certificate. This is the
    /// same finite-language semantic family with a different transition
    /// representation selected only after the dense cell cap is exceeded.
    SparseFiniteLiteral(SparseOrderedLiteralAggregateBuildAccounting),
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
    /// Maximum structural HIR/range inspection work for fixed-width class
    /// sandwiches.
    pub max_fixed_class_sandwich_planner_work: usize,
    /// Maximum allocation-free HIR/range/membership inspection work for the
    /// direct bounded-affix specialization. This is independent of the legacy
    /// bounded-context selector so adding the specialization cannot consume a
    /// caller's previously sufficient bounded-context budget.
    pub max_bounded_affix_planner_work: usize,
    /// Maximum structural HIR/range inspection work for the ordered scalar
    /// grammar specialization.
    pub max_grapheme_scalar_dfa_planner_work: usize,
    /// Maximum structural HIR/range/disjointness inspection work for bounded
    /// compound byte-class sequences. This separate quota preserves every
    /// request previously admitted at its exact fixed-sandwich limit.
    pub max_bounded_class_sequence_planner_work: usize,
    /// Maximum structural HIR/range/equality inspection work for bounded
    /// separator-delimited fields. This independent quota preserves requests
    /// admitted at every pre-existing selector's exact limit.
    pub max_bounded_separated_fields_planner_work: usize,
    /// Maximum allocation-free structural inspection work for the two-branch
    /// prefix/class specialization.
    pub max_prefix_class_alternation_planner_work: usize,
    /// Maximum allocation-free HIR/range inspection work for bounded context.
    pub max_bounded_context_planner_work: usize,
    /// Maximum checked work for finite-language shape analysis and expansion.
    pub max_finite_planner_work: u64,
    /// Complete exact-literal kernel construction limits.
    pub exact_literal: LiteralAggregateBuildLimits,
    /// Complete compact scalar-range construction limits.
    pub unicode_scalar: UnicodeScalarAggregateBuildLimits,
    /// Complete bounded fixed-class construction limits.
    pub fixed_class_sandwich: FixedClassSandwichBuildLimits,
    /// Complete ordered scalar-grammar construction limits.
    pub grapheme_scalar_dfa: GraphemeScalarDfaBuildLimits,
    /// Complete inline bounded class-sequence construction limits.
    pub bounded_class_sequence: BoundedClassSequenceBuildLimits,
    /// Complete inline bounded separated-field construction limits.
    pub bounded_separated_fields: BoundedSeparatedFieldsBuildLimits,
    /// Complete two-branch prefix/class construction limits.
    pub prefix_class_alternation: PrefixClassAlternationBuildLimits,
    /// Complete bounded-context construction limits.
    pub bounded_context: BoundedContextBuildLimits,
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
            max_bounded_affix_planner_work: 4_096,
            max_grapheme_scalar_dfa_planner_work: 1 << 20,
            max_bounded_class_sequence_planner_work: 4_096,
            max_bounded_separated_fields_planner_work: 4_096,
            max_prefix_class_alternation_planner_work: 4_096,
            max_bounded_context_planner_work: 4_096,
            max_finite_planner_work: 8_000_000,
            exact_literal: LiteralAggregateBuildLimits::default(),
            unicode_scalar: UnicodeScalarAggregateBuildLimits::default(),
            fixed_class_sandwich: FixedClassSandwichBuildLimits::default(),
            grapheme_scalar_dfa: GraphemeScalarDfaBuildLimits::default(),
            bounded_class_sequence: BoundedClassSequenceBuildLimits::default(),
            bounded_separated_fields: BoundedSeparatedFieldsBuildLimits::default(),
            prefix_class_alternation: PrefixClassAlternationBuildLimits::default(),
            bounded_context: BoundedContextBuildLimits::default(),
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
    /// Direct ordered scalar-grammar reducer limits.
    pub grapheme_scalar_dfa: GraphemeScalarDfaReduceLimits,
    /// Direct bounded class-sequence count limits.
    pub bounded_class_sequence: BoundedClassSequenceReduceLimits,
    /// Direct bounded separated-field count limits.
    pub bounded_separated_fields: BoundedSeparatedFieldsReduceLimits,
    /// Direct two-branch prefix/class count limits.
    pub prefix_class_alternation: PrefixClassAlternationReduceLimits,
    /// Direct bounded-context literal interval-stream limits.
    pub bounded_context: BoundedContextReduceLimits,
    /// Shared finite-language dense/sparse reducer limits. For sparse plans,
    /// `max_total_work` also bounds edge lookups, edge comparisons and failure
    /// steps individually because each is a component of that total.
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
    /// Fixed-class structural inspection work, including every HIR node and
    /// canonical range examined through transparent captures.
    pub fixed_class_sandwich_planner_work: usize,
    /// Charged direct bounded-affix inspection work, including an ineligible
    /// inspection followed by another plan.
    pub bounded_affix_planner_work: usize,
    /// Ordered scalar-grammar HIR/range inspection work.
    pub grapheme_scalar_dfa_planner_work: usize,
    /// Bounded compound-class structural inspection work, including every
    /// HIR/range visit and admitted disjointness-comparison upper bound.
    pub bounded_class_sequence_planner_work: usize,
    /// Bounded separated-field structural inspection work, including every
    /// HIR/range visit and repeated/final field equality-comparison bound.
    pub bounded_separated_fields_planner_work: usize,
    /// Two-branch prefix/class structural inspection work. Every HIR node,
    /// literal byte, class range and self-overlap comparison is included.
    pub prefix_class_alternation_planner_work: usize,
    /// Bounded-context structural inspection work.
    pub bounded_context_planner_work: usize,
    /// Checked finite-language root inspection and, for the dense route,
    /// analysis/expansion work; zero when finite inspection is skipped.
    /// This remains nonzero when `Auto` proves a finite language but a typed
    /// caller limit rejects the optional dense/sparse automaton preflight and
    /// continuation is selected. A rejected automaton publishes neither build
    /// accounting nor plan identity; its caller-bounded preflight is not
    /// double-counted as work of the selected continuation artifact.
    pub finite_planner_work: u64,
    /// Transparent capture-node visits charged by the selected plan builder.
    pub capture_erasure_work: usize,
    /// Capture annotations removed without changing whole-match semantics.
    pub captures_erased: usize,
    /// Exact construction accounting for the selected plan.
    pub build: AggregateBuildAccounting,
    /// Stable operation-specific selected-plan identity.
    pub plan_identity: AggregatePlanIdentity,
    /// Construction-owned copy that prevents a caller from transplanting a
    /// different bounded separated-field resource certificate into this
    /// report while retaining the original compiled artifact.
    sealed_bounded_separated_fields_identity: Option<AggregateBoundedSeparatedFieldsIdentity>,
    /// Selected plan's retained capacity/persistent bytes.
    pub retained_capacity_bytes: usize,
}

impl AggregateBuildReport {
    /// Check that the public bounded-separated discriminators and private
    /// construction seal form one closed identity state. A report is valid
    /// either when every bounded discriminator and the seal are absent, or
    /// when all four are present and the public resource certificate exactly
    /// matches the immutable construction certificate.
    #[must_use]
    pub fn has_closed_bounded_separated_fields_identity(&self) -> bool {
        match (
            self.plan,
            self.build,
            self.plan_identity,
            self.sealed_bounded_separated_fields_identity,
        ) {
            (
                AggregatePlanKind::BoundedSeparatedFields,
                AggregateBuildAccounting::BoundedSeparatedFields(build),
                AggregatePlanIdentity::BoundedSeparatedFields(identity),
                Some(sealed),
            ) => {
                identity == sealed
                    && build == sealed.kernel.build_accounting()
                    && self.retained_capacity_bytes == build.persistent_bytes
            }
            (plan, build, identity, None) => {
                plan != AggregatePlanKind::BoundedSeparatedFields
                    && !matches!(build, AggregateBuildAccounting::BoundedSeparatedFields(_))
                    && !matches!(identity, AggregatePlanIdentity::BoundedSeparatedFields(_))
            }
            _ => false,
        }
    }

    /// Check that a bounded separated-field identity is the exact immutable
    /// certificate published with this construction report.
    #[must_use]
    pub fn authenticates_bounded_separated_fields_identity(
        &self,
        identity: AggregateBoundedSeparatedFieldsIdentity,
    ) -> bool {
        matches!(
            self.sealed_bounded_separated_fields_identity,
            Some(sealed) if sealed == identity
        )
    }
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
    /// Direct bounded-affix inspection crossed its independent structural
    /// work cap.
    BoundedAffixPlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
    },
    /// Ordered scalar-grammar inspection crossed its structural work cap.
    GraphemeScalarDfaPlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
    },
    /// Bounded compound byte-class inspection crossed its independent
    /// structural work cap.
    BoundedClassSequencePlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
    },
    /// Bounded separated-field inspection crossed its independent structural
    /// work cap.
    BoundedSeparatedFieldsPlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
    },
    /// Prefix/class alternation inspection crossed its structural work cap.
    PrefixClassAlternationPlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
    },
    /// Bounded-context inspection crossed its structural work cap.
    BoundedContextPlannerWorkLimit {
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
    /// Ordered scalar-property classifier construction failed after selection.
    GraphemeScalarDfaBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: GraphemeScalarDfaBuildError,
    },
    /// Bounded compound byte-class construction failed after selection.
    BoundedClassSequenceBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: BoundedClassSequenceBuildError,
    },
    /// Bounded separated-field construction failed after selection.
    BoundedSeparatedFieldsBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: BoundedSeparatedFieldsBuildError,
    },
    /// Prefix/class alternation construction failed after selection.
    PrefixClassAlternationBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: PrefixClassAlternationBuildError,
    },
    /// Bounded-context construction failed after selection.
    BoundedContextBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: BoundedContextBuildError,
    },
    /// Reversed finite-language DFA construction failed after selection.
    FiniteLiteralBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: OrderedLiteralAggregateBuildError,
    },
    /// Sparse reversed finite-language automaton construction failed after
    /// selection. Caller-selected resource refusals remain optional in
    /// `Auto`; allocator, arithmetic, representation and proof failures do
    /// not get disguised by a continuation retry.
    SparseFiniteLiteralBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        source: SparseOrderedLiteralAggregateBuildError,
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
            Self::BoundedAffixPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} bounded-affix inspection needs {needed} structural work units, limit is {limit}"
            ),
            Self::GraphemeScalarDfaPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} ordered scalar-grammar inspection needs {needed} structural work units, limit is {limit}"
            ),
            Self::BoundedClassSequencePlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} bounded class-sequence inspection needs {needed} structural work units, limit is {limit}"
            ),
            Self::BoundedSeparatedFieldsPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} bounded separated-field inspection needs {needed} structural work units, limit is {limit}"
            ),
            Self::PrefixClassAlternationPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} prefix/class alternation inspection needs {needed} structural work units, limit is {limit}"
            ),
            Self::BoundedContextPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} bounded-context inspection needs {needed} structural work units, limit is {limit}"
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
            Self::GraphemeScalarDfaBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} ordered scalar-grammar construction failed: {source}"
            ),
            Self::BoundedClassSequenceBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} bounded class-sequence construction failed: {source}"
            ),
            Self::BoundedSeparatedFieldsBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} bounded separated-field construction failed: {source}"
            ),
            Self::PrefixClassAlternationBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} prefix/class alternation construction failed: {source}"
            ),
            Self::BoundedContextBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} bounded-context construction failed: {source}"
            ),
            Self::FiniteLiteralBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} finite-language DFA construction failed: {source}"
            ),
            Self::SparseFiniteLiteralBuild {
                operation,
                selection,
                source,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} sparse finite-language construction failed: {source}"
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
            Self::GraphemeScalarDfaBuild { source, .. } => Some(source),
            Self::BoundedClassSequenceBuild { source, .. } => Some(source),
            Self::BoundedSeparatedFieldsBuild { source, .. } => Some(source),
            Self::PrefixClassAlternationBuild { source, .. } => Some(source),
            Self::BoundedContextBuild { source, .. } => Some(source),
            Self::FiniteLiteralBuild { source, .. } => Some(source),
            Self::SparseFiniteLiteralBuild { source, .. } => Some(source),
            Self::ContinuationCompile { source, .. } => Some(source),
            Self::LiteralPlannerWorkLimit { .. }
            | Self::UnicodeScalarPlannerWorkLimit { .. }
            | Self::FixedClassSandwichPlannerWorkLimit { .. }
            | Self::BoundedAffixPlannerWorkLimit { .. }
            | Self::GraphemeScalarDfaPlannerWorkLimit { .. }
            | Self::BoundedClassSequencePlannerWorkLimit { .. }
            | Self::BoundedSeparatedFieldsPlannerWorkLimit { .. }
            | Self::PrefixClassAlternationPlannerWorkLimit { .. }
            | Self::BoundedContextPlannerWorkLimit { .. }
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
    /// Direct ordered scalar-grammar refusal.
    GraphemeScalarDfa(GraphemeScalarDfaReduceError),
    /// Direct bounded class-sequence refusal.
    BoundedClassSequence(BoundedClassSequenceReduceError),
    /// Direct bounded separated-field refusal.
    BoundedSeparatedFields(BoundedSeparatedFieldsReduceError),
    /// Direct two-branch prefix/class refusal.
    PrefixClassAlternation(PrefixClassAlternationReduceError),
    /// Direct bounded-context refusal.
    BoundedContext(BoundedContextReduceError),
    /// Shared finite-language DFA whole-operation refusal.
    FiniteLiteral(OrderedLiteralAggregateReduceError),
    /// Sparse shared finite-language automaton whole-operation refusal.
    SparseFiniteLiteral(SparseOrderedLiteralAggregateReduceError),
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
            Self::GraphemeScalarDfa(source) => source.fmt(f),
            Self::BoundedClassSequence(source) => source.fmt(f),
            Self::BoundedSeparatedFields(source) => source.fmt(f),
            Self::PrefixClassAlternation(source) => source.fmt(f),
            Self::BoundedContext(source) => source.fmt(f),
            Self::FiniteLiteral(source) => source.fmt(f),
            Self::SparseFiniteLiteral(source) => source.fmt(f),
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
            Self::GraphemeScalarDfa(source) => Some(source),
            Self::BoundedClassSequence(source) => Some(source),
            Self::BoundedSeparatedFields(source) => Some(source),
            Self::PrefixClassAlternation(source) => Some(source),
            Self::BoundedContext(source) => Some(source),
            Self::FiniteLiteral(source) => Some(source),
            Self::SparseFiniteLiteral(source) => Some(source),
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
    /// Ordered scalar-grammar bounds, counters, and operation identity.
    GraphemeScalarDfa(GraphemeScalarDfaReduceAccounting),
    /// Bounded class-sequence bounds, counters, and operation identity.
    BoundedClassSequence(BoundedClassSequenceReduceAccounting),
    /// Bounded separated-field bounds, counters, and operation identity.
    BoundedSeparatedFields(BoundedSeparatedFieldsReduceAccounting),
    /// Prefix/class stream bounds, counters, and identity.
    PrefixClassAlternation(PrefixClassAlternationReduceAccounting),
    /// Bounded-context bounds, counters, and operation identity.
    BoundedContext(BoundedContextReduceAccounting),
    /// Finite-language structural upper bounds and exact counters. The build
    /// report and syntax key retain the immutable DFA and language identity.
    FiniteLiteral {
        upper_bounds: OrderedLiteralAggregateUpperBounds,
        actual: OrderedLiteralAggregateActualCounters,
    },
    /// Sparse finite-language structural bounds and exact counters.
    SparseFiniteLiteral {
        upper_bounds: SparseOrderedLiteralAggregateUpperBounds,
        actual: SparseOrderedLiteralAggregateActualCounters,
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

/// Sparse construction reuses the existing finite-language quota envelope.
/// A sparse edge is one packed `u32` cell, so the frozen dense-cell ceiling is
/// also a conservative sparse-edge ceiling; no quota is introduced or raised.
const fn sparse_finite_build_limits(
    limits: OrderedLiteralAggregateBuildLimits,
) -> SparseOrderedLiteralAggregateBuildLimits {
    SparseOrderedLiteralAggregateBuildLimits {
        max_patterns: limits.max_patterns,
        max_pattern_bytes: limits.max_pattern_bytes,
        max_identity_bytes: limits.max_identity_bytes,
        max_trie_states: limits.max_trie_states,
        max_sparse_edges: limits.max_dfa_cells,
        max_build_work: limits.max_build_work,
        max_scratch_bytes: limits.max_scratch_bytes,
        max_persistent_bytes: limits.max_persistent_bytes,
        max_peak_bytes: limits.max_peak_bytes,
    }
}

fn sparse_finite_build_limit_allows_continuation(
    source: &SparseOrderedLiteralAggregateBuildError,
) -> bool {
    matches!(
        source,
        SparseOrderedLiteralAggregateBuildError::PatternLimit { .. }
            | SparseOrderedLiteralAggregateBuildError::PatternBytesLimit { .. }
            | SparseOrderedLiteralAggregateBuildError::IdentityBytesLimit { .. }
            | SparseOrderedLiteralAggregateBuildError::TrieStatesLimit { .. }
            | SparseOrderedLiteralAggregateBuildError::SparseEdgesLimit { .. }
            | SparseOrderedLiteralAggregateBuildError::WorkLimit { .. }
            | SparseOrderedLiteralAggregateBuildError::ScratchLimit { .. }
            | SparseOrderedLiteralAggregateBuildError::PersistentLimit { .. }
            | SparseOrderedLiteralAggregateBuildError::PeakLimit { .. }
    )
}

/// Execution also stays inside the existing finite-language quota envelope.
/// Every sparse structural counter is a component of total work, so the
/// ordered reducer's total-work ceiling is a safe ceiling for components that
/// have no dense analogue. The adapter publishes an exact sparse total-work
/// bound when this representation is selected.
fn sparse_finite_reduce_limits(
    limits: OrderedLiteralAggregateReduceLimits,
) -> SparseOrderedLiteralAggregateReduceLimits {
    let total_work = u64::try_from(limits.max_total_work).unwrap_or(u64::MAX);
    SparseOrderedLiteralAggregateReduceLimits {
        max_transitions: limits.max_transitions,
        max_edge_lookups: limits.max_total_work,
        max_edge_search_checks: total_work,
        max_failure_steps: limits.max_total_work,
        max_match_events: limits.max_match_events,
        max_count: limits.max_count,
        max_span_sum: limits.max_span_sum,
        max_reducer_steps: limits.max_reducer_steps,
        max_ring_initializations: limits.max_ring_initializations,
        max_total_work: total_work,
        max_scratch_bytes: limits.max_scratch_bytes,
        max_peak_bytes: limits.max_peak_bytes,
    }
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
        let grapheme_profile = self.profile == RustProfile::rebar_1_12_4();
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
        let minimum_match_bytes = rust.hir.properties().minimum_len();
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
                bounded_affix_planner_work: 0,
                grapheme_scalar_dfa_planner_work: 0,
                bounded_class_sequence_planner_work: 0,
                bounded_separated_fields_planner_work: 0,
                prefix_class_alternation_planner_work: 0,
                bounded_context_planner_work: 0,
                finite_planner_work: 0,
                capture_erasure_work: captures,
                captures_erased: captures,
                build: AggregateBuildAccounting::ExactLiteral(build),
                plan_identity,
                sealed_bounded_separated_fields_identity: None,
                retained_capacity_bytes: build.persistent_bytes,
            };
            return Ok(AggregatePlan {
                engine: AggregateEngine::ExactLiteral(engine),
                minimum_match_bytes,
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
                    bounded_affix_planner_work: 0,
                    grapheme_scalar_dfa_planner_work: 0,
                    bounded_class_sequence_planner_work: 0,
                    bounded_separated_fields_planner_work: 0,
                    prefix_class_alternation_planner_work: 0,
                    bounded_context_planner_work: 0,
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
                    sealed_bounded_separated_fields_identity: None,
                    retained_capacity_bytes: build.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::UnicodeScalar(engine),
                    minimum_match_bytes,
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
                    bounded_affix_planner_work: 0,
                    grapheme_scalar_dfa_planner_work: 0,
                    bounded_class_sequence_planner_work: 0,
                    bounded_separated_fields_planner_work: 0,
                    prefix_class_alternation_planner_work: 0,
                    bounded_context_planner_work: 0,
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
                    sealed_bounded_separated_fields_identity: None,
                    retained_capacity_bytes: build.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::FixedClassSandwich(engine),
                    minimum_match_bytes,
                    limits,
                    report,
                });
            }
            Some(FixedClassSandwichInspection::Ineligible { work }) => work,
            None => 0,
        };
        let grapheme_scalar_inspection = if grapheme_profile
            && unicode
            && !case_insensitive
            && selection == AggregatePlanSelection::Auto
            && operation == AggregateOperation::Count
        {
            Some(
                grapheme_scalar::inspect(&rust.hir, limits.max_grapheme_scalar_dfa_planner_work)
                    .map_err(|error| match error {
                        grapheme_scalar::InspectionError::WorkLimit { needed, limit } => {
                            AggregateBuildError::GraphemeScalarDfaPlannerWorkLimit {
                                operation,
                                selection,
                                needed,
                                limit,
                            }
                        }
                        grapheme_scalar::InspectionError::Overflow => {
                            AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "ordered scalar-grammar inspection accounting overflow",
                            }
                        }
                    })?,
            )
        } else {
            None
        };
        let grapheme_scalar_dfa_planner_work = if let Some(
            grapheme_scalar::InspectionOutcome::Eligible(inspection),
        ) = grapheme_scalar_inspection
        {
            if inspection.hir_nodes != expected_nodes || inspection.captures != expected_captures {
                return Err(AggregateBuildError::InternalInvariant {
                    operation,
                    selection,
                    detail: "syntax summary differs from ordered scalar-grammar inspection",
                });
            }
            let classes = inspection.classes;
            let range_counts = [
                1,
                1,
                classes.control.ranges().len(),
                classes.prepend.ranges().len(),
                classes.l.ranges().len(),
                classes.v.ranges().len(),
                classes.lv.ranges().len(),
                classes.lvt.ranges().len(),
                classes.t.ranges().len(),
                classes.ri.ranges().len(),
                classes.extended_pictographic.ranges().len(),
                classes.extend.ranges().len(),
                1,
                classes.spacing_mark_ranges,
                classes.generic.ranges().len(),
                classes.tail.ranges().len(),
                classes.any.ranges().len(),
            ];
            let source_ranges = range_counts.into_iter().try_fold(0_usize, |total, count| {
                total
                    .checked_add(count)
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "ordered scalar-grammar source range count overflow",
                    })
            })?;
            let ranges = core::iter::once((GraphemeScalarDfaRole::Cr, '\r', '\r'))
                .chain(core::iter::once((GraphemeScalarDfaRole::Lf, '\n', '\n')))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::Control,
                    classes.control,
                ))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::Prepend,
                    classes.prepend,
                ))
                .chain(tagged_grapheme_ranges(GraphemeScalarDfaRole::L, classes.l))
                .chain(tagged_grapheme_ranges(GraphemeScalarDfaRole::V, classes.v))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::Lv,
                    classes.lv,
                ))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::Lvt,
                    classes.lvt,
                ))
                .chain(tagged_grapheme_ranges(GraphemeScalarDfaRole::T, classes.t))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::Ri,
                    classes.ri,
                ))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::ExtendedPictographic,
                    classes.extended_pictographic,
                ))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::Extend,
                    classes.extend,
                ))
                .chain(core::iter::once((
                    GraphemeScalarDfaRole::Zwj,
                    '\u{200D}',
                    '\u{200D}',
                )))
                .chain(grapheme_scalar::spacing_mark_ranges(&classes).map(|range| {
                    (
                        GraphemeScalarDfaRole::SpacingMark,
                        range.start(),
                        range.end(),
                    )
                }))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::GenericCore,
                    classes.generic,
                ))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::Tail,
                    classes.tail,
                ))
                .chain(tagged_grapheme_ranges(
                    GraphemeScalarDfaRole::Any,
                    classes.any,
                ));
            let engine = GraphemeScalarDfaPlan::build_from_counted_iter(
                source_ranges,
                ranges,
                limits.grapheme_scalar_dfa,
            )
            .map_err(|source| AggregateBuildError::GraphemeScalarDfaBuild {
                operation,
                selection,
                source,
            })?;
            let build = engine.build_accounting();
            let report = AggregateBuildReport {
                schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                syntax_key,
                admission,
                syntax,
                operation,
                selection,
                plan: AggregatePlanKind::GraphemeScalarDfa,
                continuation_strategy: None,
                capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                planner_work,
                unicode_scalar_planner_work,
                fixed_class_sandwich_planner_work,
                bounded_affix_planner_work: 0,
                grapheme_scalar_dfa_planner_work: inspection.work,
                bounded_class_sequence_planner_work: 0,
                bounded_separated_fields_planner_work: 0,
                prefix_class_alternation_planner_work: 0,
                bounded_context_planner_work: 0,
                finite_planner_work: 0,
                capture_erasure_work: inspection.captures,
                captures_erased: inspection.captures,
                build: AggregateBuildAccounting::GraphemeScalarDfa(build),
                plan_identity: AggregatePlanIdentity::GraphemeScalarDfa(
                    AggregateGraphemeScalarDfaIdentity {
                        semantics: AggregateGraphemeScalarDfaSemantics::UnicodeOnOrderedScalarGrammarUtf8False,
                        kernel: engine.count_identity(),
                    },
                ),
                sealed_bounded_separated_fields_identity: None,
                retained_capacity_bytes: build.persistent_bytes,
            };
            return Ok(AggregatePlan {
                engine: AggregateEngine::GraphemeScalarDfa(engine),
                minimum_match_bytes,
                limits,
                report,
            });
        } else if let Some(grapheme_scalar::InspectionOutcome::Ineligible {
            work,
            hir_nodes,
            captures,
        }) = grapheme_scalar_inspection
        {
            if hir_nodes != expected_nodes || captures != expected_captures {
                return Err(AggregateBuildError::InternalInvariant {
                    operation,
                    selection,
                    detail: "syntax summary differs from ineligible ordered scalar-grammar inspection",
                });
            }
            work
        } else {
            0
        };
        let bounded_class_sequence_inspection = if !unicode
            && selection == AggregatePlanSelection::Auto
            && operation == AggregateOperation::Count
        {
            Some(
                inspect_bounded_class_sequence(
                    &rust.hir,
                    limits.max_bounded_class_sequence_planner_work,
                )
                .map_err(|error| match error {
                    BoundedClassSequenceInspectionError::WorkLimit { needed, limit } => {
                        AggregateBuildError::BoundedClassSequencePlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit,
                        }
                    }
                    BoundedClassSequenceInspectionError::Overflow => {
                        AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "bounded class-sequence inspection accounting overflow",
                        }
                    }
                })?,
            )
        } else {
            None
        };
        let bounded_class_sequence_planner_work = match bounded_class_sequence_inspection {
            Some(BoundedClassSequenceInspection::Eligible {
                head,
                body,
                trail,
                minimum,
                maximum,
                work,
                hir_nodes,
                captures,
            }) => {
                if hir_nodes != expected_nodes || captures != expected_captures {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "syntax summary differs from bounded class-sequence inspection",
                    });
                }
                let engine = BoundedClassSequencePlan::build(
                    head.ranges(),
                    body.ranges(),
                    trail.ranges(),
                    minimum,
                    maximum,
                    limits.bounded_class_sequence,
                )
                .map_err(|source| {
                    AggregateBuildError::BoundedClassSequenceBuild {
                        operation,
                        selection,
                        source,
                    }
                })?;
                let build = engine.build_accounting();
                let report = AggregateBuildReport {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key,
                    admission,
                    syntax,
                    operation,
                    selection,
                    plan: AggregatePlanKind::BoundedClassSequence,
                    continuation_strategy: None,
                    capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                    planner_work,
                    unicode_scalar_planner_work,
                    fixed_class_sandwich_planner_work,
                    bounded_affix_planner_work: 0,
                    grapheme_scalar_dfa_planner_work,
                    bounded_class_sequence_planner_work: work,
                    bounded_separated_fields_planner_work: 0,
                    prefix_class_alternation_planner_work: 0,
                    bounded_context_planner_work: 0,
                    finite_planner_work: 0,
                    capture_erasure_work: captures,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::BoundedClassSequence(build),
                    plan_identity: AggregatePlanIdentity::BoundedClassSequence(
                        engine.count_identity(),
                    ),
                    sealed_bounded_separated_fields_identity: None,
                    retained_capacity_bytes: build.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::BoundedClassSequence(engine),
                    minimum_match_bytes,
                    limits,
                    report,
                });
            }
            Some(BoundedClassSequenceInspection::Ineligible { work }) => work,
            None => 0,
        };
        let bounded_separated_fields_inspection = if !unicode
            && !case_insensitive
            && selection == AggregatePlanSelection::Auto
            && operation == AggregateOperation::Count
        {
            Some(
                inspect_bounded_separated_fields(
                    &rust.hir,
                    limits.max_bounded_separated_fields_planner_work,
                )
                .map_err(|error| match error {
                    BoundedSeparatedFieldsInspectionError::WorkLimit { needed, limit } => {
                        AggregateBuildError::BoundedSeparatedFieldsPlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit,
                        }
                    }
                    BoundedSeparatedFieldsInspectionError::Overflow => {
                        AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "bounded separated-field inspection accounting overflow",
                        }
                    }
                })?,
            )
        } else {
            None
        };
        let bounded_separated_fields_planner_work = match bounded_separated_fields_inspection {
            Some(BoundedSeparatedFieldsInspection::Eligible {
                field,
                separator,
                fields,
                work,
                hir_nodes,
                captures,
            }) => {
                if hir_nodes != expected_nodes || captures != expected_captures {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "syntax summary differs from bounded separated-field inspection",
                    });
                }
                let Some(field_source) = field.kernel_source() else {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "eligible bounded separated-field source was not representable",
                    });
                };
                let engine = BoundedSeparatedFieldsPlan::build(
                    field_source,
                    separator,
                    fields,
                    limits.bounded_separated_fields,
                )
                .map_err(|source| {
                    AggregateBuildError::BoundedSeparatedFieldsBuild {
                        operation,
                        selection,
                        source,
                    }
                })?;
                let build = engine.build_accounting();
                let plan_identity = AggregateBoundedSeparatedFieldsIdentity {
                    kernel: engine.count_identity(),
                };
                let report = AggregateBuildReport {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key,
                    admission,
                    syntax,
                    operation,
                    selection,
                    plan: AggregatePlanKind::BoundedSeparatedFields,
                    continuation_strategy: None,
                    capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                    planner_work,
                    unicode_scalar_planner_work,
                    fixed_class_sandwich_planner_work,
                    bounded_affix_planner_work: 0,
                    grapheme_scalar_dfa_planner_work,
                    bounded_class_sequence_planner_work,
                    bounded_separated_fields_planner_work: work,
                    prefix_class_alternation_planner_work: 0,
                    bounded_context_planner_work: 0,
                    finite_planner_work: 0,
                    capture_erasure_work: captures,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::BoundedSeparatedFields(build),
                    plan_identity: AggregatePlanIdentity::BoundedSeparatedFields(plan_identity),
                    sealed_bounded_separated_fields_identity: Some(plan_identity),
                    retained_capacity_bytes: build.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::BoundedSeparatedFields(engine),
                    minimum_match_bytes,
                    limits,
                    report,
                });
            }
            Some(BoundedSeparatedFieldsInspection::Ineligible { work }) => work,
            None => 0,
        };
        let prefix_class_selection_bound = prefix_class_selection_work(&syntax);
        let prefix_class_inspection = if !unicode
            && !case_insensitive
            && selection == AggregatePlanSelection::Auto
            && matches!(
                operation,
                AggregateOperation::Compile | AggregateOperation::Count
            )
            && prefix_class_selection_bound
                .is_some_and(|work| work <= limits.max_prefix_class_alternation_planner_work)
        {
            Some(
                inspect_prefix_class_alternation(
                    &rust.hir,
                    limits.max_prefix_class_alternation_planner_work,
                )
                .map_err(|error| match error {
                    PrefixClassInspectionError::WorkLimit { needed, limit } => {
                        AggregateBuildError::PrefixClassAlternationPlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit,
                        }
                    }
                    PrefixClassInspectionError::Overflow => {
                        AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "prefix/class alternation inspection accounting overflow",
                        }
                    }
                })?,
            )
        } else {
            None
        };
        let prefix_class_alternation_planner_work = match prefix_class_inspection {
            Some(PrefixClassInspection::Eligible {
                prefixes,
                classes,
                work,
                hir_nodes,
                captures,
            }) => {
                if hir_nodes != expected_nodes || captures != expected_captures {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "syntax summary differs from prefix/class inspection",
                    });
                }
                let engine = PrefixClassAlternationPlan::build(
                    prefixes,
                    [
                        classes[0]
                            .ranges()
                            .iter()
                            .copied()
                            .map(class_bytes_range_tuple),
                        classes[1]
                            .ranges()
                            .iter()
                            .copied()
                            .map(class_bytes_range_tuple),
                    ],
                    limits.prefix_class_alternation,
                )
                .map_err(|source| {
                    AggregateBuildError::PrefixClassAlternationBuild {
                        operation,
                        selection,
                        source,
                    }
                })?;
                let build = engine.build_accounting();
                let report = AggregateBuildReport {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key,
                    admission,
                    syntax,
                    operation,
                    selection,
                    plan: AggregatePlanKind::PrefixClassAlternation,
                    continuation_strategy: None,
                    capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                    planner_work,
                    unicode_scalar_planner_work,
                    fixed_class_sandwich_planner_work,
                    bounded_affix_planner_work: 0,
                    grapheme_scalar_dfa_planner_work,
                    bounded_class_sequence_planner_work,
                    bounded_separated_fields_planner_work,
                    prefix_class_alternation_planner_work: work,
                    bounded_context_planner_work: 0,
                    finite_planner_work: 0,
                    capture_erasure_work: captures,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::PrefixClassAlternation(build),
                    plan_identity: AggregatePlanIdentity::PrefixClassAlternation(
                        AggregatePrefixClassAlternationIdentity {
                            kernel: engine.count_identity(),
                        },
                    ),
                    sealed_bounded_separated_fields_identity: None,
                    retained_capacity_bytes: build.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::PrefixClassAlternation(engine),
                    minimum_match_bytes,
                    limits,
                    report,
                });
            }
            Some(PrefixClassInspection::Ineligible { work }) => work,
            None => 0,
        };
        let bounded_affix_planner_work;
        if !unicode
            && !case_insensitive
            && selection == AggregatePlanSelection::Auto
            && operation == AggregateOperation::Count
        {
            let affix = inspect_bounded_affix(&rust.hir, limits.max_bounded_affix_planner_work)
                .map_err(|error| match error {
                    BoundedContextInspectionError::WorkLimit { needed, limit } => {
                        AggregateBuildError::BoundedAffixPlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit,
                        }
                    }
                    BoundedContextInspectionError::Overflow => {
                        AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "bounded-affix inspection accounting overflow",
                        }
                    }
                })?;
            match affix {
                BoundedAffixInspection::Eligible {
                    left,
                    middle,
                    right,
                    literal,
                    middle_max,
                    work,
                    hir_nodes,
                } => {
                    if hir_nodes != expected_nodes || expected_captures != 0 {
                        return Err(AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "syntax summary differs from bounded-affix inspection",
                        });
                    }
                    let engine = BoundedContextPlan::build_bounded_affix(
                        left.ranges()
                            .iter()
                            .map(|range| (range.start(), range.end())),
                        middle
                            .ranges()
                            .iter()
                            .map(|range| (range.start(), range.end())),
                        right
                            .ranges()
                            .iter()
                            .map(|range| (range.start(), range.end())),
                        literal,
                        middle_max,
                        limits.bounded_context,
                    )
                    .map_err(|source| {
                        AggregateBuildError::BoundedContextBuild {
                            operation,
                            selection,
                            source,
                        }
                    })?;
                    let build = engine.build_accounting();
                    let report = AggregateBuildReport {
                        schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                        syntax_key,
                        admission,
                        syntax,
                        operation,
                        selection,
                        plan: AggregatePlanKind::BoundedContext,
                        continuation_strategy: None,
                        capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                        planner_work,
                        unicode_scalar_planner_work,
                        fixed_class_sandwich_planner_work,
                        bounded_affix_planner_work: work,
                        grapheme_scalar_dfa_planner_work,
                        bounded_class_sequence_planner_work,
                        bounded_separated_fields_planner_work,
                        prefix_class_alternation_planner_work,
                        bounded_context_planner_work: 0,
                        finite_planner_work: 0,
                        capture_erasure_work: 0,
                        captures_erased: 0,
                        build: AggregateBuildAccounting::BoundedContext(build),
                        plan_identity: AggregatePlanIdentity::BoundedContext(
                            AggregateBoundedContextIdentity {
                                kernel: engine.count_identity(),
                            },
                        ),
                        sealed_bounded_separated_fields_identity: None,
                        retained_capacity_bytes: build.persistent_bytes,
                    };
                    return Ok(AggregatePlan {
                        engine: AggregateEngine::BoundedContext(engine),
                        minimum_match_bytes,
                        limits,
                        report,
                    });
                }
                BoundedAffixInspection::Ineligible { work } => {
                    bounded_affix_planner_work = work;
                }
            }
        } else {
            bounded_affix_planner_work = 0;
        }
        let bounded_context_inspection = if !unicode
            && !case_insensitive
            && selection == AggregatePlanSelection::Auto
            && matches!(
                operation,
                AggregateOperation::Compile | AggregateOperation::Count
            ) {
            Some(
                inspect_bounded_context(&rust.hir, limits.max_bounded_context_planner_work)
                    .map_err(|error| match error {
                        BoundedContextInspectionError::WorkLimit { needed, limit } => {
                            AggregateBuildError::BoundedContextPlannerWorkLimit {
                                operation,
                                selection,
                                needed,
                                limit,
                            }
                        }
                        BoundedContextInspectionError::Overflow => {
                            AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "bounded-context inspection accounting overflow",
                            }
                        }
                    })?,
            )
        } else {
            None
        };
        let bounded_context_planner_work = match bounded_context_inspection {
            Some(BoundedContextInspection::Eligible {
                prefix,
                separator,
                tail,
                literal,
                prefix_width,
                left_gap_max,
                right_gap_max,
                tail_width,
                work,
                hir_nodes,
                captures,
            }) => {
                if hir_nodes != expected_nodes || captures != expected_captures {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "syntax summary differs from bounded-context inspection",
                    });
                }
                let engine = BoundedContextPlan::build(
                    prefix
                        .ranges()
                        .iter()
                        .map(|range| (range.start(), range.end())),
                    separator
                        .ranges()
                        .iter()
                        .map(|range| (range.start(), range.end())),
                    tail.ranges()
                        .iter()
                        .map(|range| (range.start(), range.end())),
                    literal,
                    prefix_width,
                    left_gap_max,
                    right_gap_max,
                    tail_width,
                    limits.bounded_context,
                )
                .map_err(|source| AggregateBuildError::BoundedContextBuild {
                    operation,
                    selection,
                    source,
                })?;
                let build = engine.build_accounting();
                let report = AggregateBuildReport {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key,
                    admission,
                    syntax,
                    operation,
                    selection,
                    plan: AggregatePlanKind::BoundedContext,
                    continuation_strategy: None,
                    capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                    planner_work,
                    unicode_scalar_planner_work,
                    fixed_class_sandwich_planner_work,
                    bounded_affix_planner_work,
                    grapheme_scalar_dfa_planner_work,
                    bounded_class_sequence_planner_work,
                    bounded_separated_fields_planner_work,
                    prefix_class_alternation_planner_work,
                    bounded_context_planner_work: work,
                    finite_planner_work: 0,
                    capture_erasure_work: captures,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::BoundedContext(build),
                    plan_identity: AggregatePlanIdentity::BoundedContext(
                        AggregateBoundedContextIdentity {
                            kernel: engine.count_identity(),
                        },
                    ),
                    sealed_bounded_separated_fields_identity: None,
                    retained_capacity_bytes: build.persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::BoundedContext(engine),
                    minimum_match_bytes,
                    limits,
                    report,
                });
            }
            Some(BoundedContextInspection::Ineligible { work }) => work,
            None => 0,
        };
        let inspect_finite =
            selection == AggregatePlanSelection::Auto && operation != AggregateOperation::Spans;
        let root_finite = if inspect_finite {
            Some(
                finite_root::inspect(&rust.hir, unicode, limits.max_finite_planner_work).map_err(
                    |error| match error {
                        finite_root::InspectionError::WorkLimit { needed, limit } => {
                            AggregateBuildError::FinitePlannerWorkLimit {
                                operation,
                                selection,
                                needed,
                                limit,
                            }
                        }
                        finite_root::InspectionError::Overflow => {
                            AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "root finite-language inspection accounting overflow",
                            }
                        }
                    },
                )?,
            )
        } else {
            None
        };
        let mut finite_planner_work = match &root_finite {
            Some(finite_root::Inspection::Eligible(proof)) => proof.work,
            Some(finite_root::Inspection::Ineligible { work }) => *work,
            None => 0,
        };
        let mut sparse_refused = false;
        if let Some(finite_root::Inspection::Eligible(proof)) = &root_finite
            && proof.should_use_sparse(limits.finite_literal)
        {
            if proof.hir_nodes != expected_nodes || expected_captures != 0 {
                return Err(AggregateBuildError::InternalInvariant {
                    operation,
                    selection,
                    detail: "syntax summary differs from root finite-language inspection",
                });
            }
            let sparse_limits = sparse_finite_build_limits(limits.finite_literal);
            let materialized = match proof.materialize_patterns(
                limits.max_finite_planner_work,
                sparse_limits.max_scratch_bytes,
                sparse_limits.max_peak_bytes,
            ) {
                Ok(materialized) => {
                    finite_planner_work = materialized.work;
                    Ok(materialized.patterns)
                }
                Err(finite_root::MaterializationError::WorkLimit { needed, limit }) => {
                    return Err(AggregateBuildError::FinitePlannerWorkLimit {
                        operation,
                        selection,
                        needed,
                        limit,
                    });
                }
                Err(finite_root::MaterializationError::AllocationFailed { additional }) => {
                    return Err(AggregateBuildError::FinitePlannerAllocationFailed {
                        operation,
                        selection,
                        structure: "root literal pointer source",
                        additional,
                    });
                }
                Err(finite_root::MaterializationError::ScratchLimit { needed, limit }) => {
                    Err(SparseOrderedLiteralAggregateBuildError::ScratchLimit { needed, limit })
                }
                Err(finite_root::MaterializationError::PeakLimit { needed, limit }) => {
                    Err(SparseOrderedLiteralAggregateBuildError::PeakLimit { needed, limit })
                }
                Err(finite_root::MaterializationError::Overflow) => {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "root literal source materialization accounting overflow",
                    });
                }
            };
            let sparse_build = match materialized {
                Err(source) => Err(source),
                Ok(patterns) => match operation {
                    AggregateOperation::Compile | AggregateOperation::Count => {
                        SparseOrderedLiteralCountPlan::build(patterns, sparse_limits).map(
                            |engine| {
                                let build = engine.build_accounting();
                                (
                                    AggregateEngine::SparseFiniteCount(engine),
                                    build,
                                    SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
                                )
                            },
                        )
                    }
                    AggregateOperation::SpanSum => {
                        SparseOrderedLiteralSpanSumPlan::build(patterns, sparse_limits).map(
                            |engine| {
                                let build = engine.build_accounting();
                                (
                                    AggregateEngine::SparseFiniteSpanSum(engine),
                                    build,
                                    SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
                                )
                            },
                        )
                    }
                    AggregateOperation::Spans => {
                        return Err(AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "span materialization selected sparse finite reducer",
                        });
                    }
                },
            };
            match sparse_build {
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
                        bounded_affix_planner_work,
                        grapheme_scalar_dfa_planner_work,
                        bounded_class_sequence_planner_work,
                        bounded_separated_fields_planner_work,
                        prefix_class_alternation_planner_work,
                        bounded_context_planner_work,
                        finite_planner_work,
                        capture_erasure_work: 0,
                        captures_erased: 0,
                        build: AggregateBuildAccounting::SparseFiniteLiteral(build),
                        plan_identity: AggregatePlanIdentity::FiniteLiteral(
                            AggregateFiniteLiteralIdentity {
                                semantics: if unicode {
                                    AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
                                } else {
                                    AggregateFiniteLiteralSemantics::UnicodeOffByteBoundaries
                                },
                                algorithm: SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
                                operation: operation_id,
                            },
                        ),
                        sealed_bounded_separated_fields_identity: None,
                        retained_capacity_bytes: build.persistent_bytes,
                    };
                    return Ok(AggregatePlan {
                        engine,
                        minimum_match_bytes,
                        limits,
                        report,
                    });
                }
                Err(source) if sparse_finite_build_limit_allows_continuation(&source) => {
                    sparse_refused = true;
                }
                Err(source) => {
                    return Err(AggregateBuildError::SparseFiniteLiteralBuild {
                        operation,
                        selection,
                        source,
                    });
                }
            }
        }
        let finite = if inspect_finite && !sparse_refused {
            Some(
                finite::extract(
                    &rust.hir,
                    limits.finite_literal.max_patterns,
                    limits.finite_literal.max_pattern_bytes,
                    finite_planner_work,
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
        if let Some(result) = &finite {
            finite_planner_work = result.work;
        }
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
                        bounded_affix_planner_work,
                        grapheme_scalar_dfa_planner_work,
                        bounded_class_sequence_planner_work,
                        bounded_separated_fields_planner_work,
                        prefix_class_alternation_planner_work,
                        bounded_context_planner_work,
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
                        sealed_bounded_separated_fields_identity: None,
                        retained_capacity_bytes: build.persistent_bytes,
                    };
                    return Ok(AggregatePlan {
                        engine,
                        minimum_match_bytes,
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
            bounded_affix_planner_work,
            grapheme_scalar_dfa_planner_work,
            bounded_class_sequence_planner_work,
            bounded_separated_fields_planner_work,
            prefix_class_alternation_planner_work,
            bounded_context_planner_work,
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
            sealed_bounded_separated_fields_identity: None,
            retained_capacity_bytes: compile.program_bytes,
        };
        Ok(AggregatePlan {
            engine: AggregateEngine::Continuation(engine),
            minimum_match_bytes,
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

fn tagged_grapheme_ranges(
    role: GraphemeScalarDfaRole,
    class: &ClassUnicode,
) -> impl ExactSizeIterator<Item = (GraphemeScalarDfaRole, char, char)> + '_ {
    class
        .ranges()
        .iter()
        .map(move |range| (role, range.start(), range.end()))
}

#[derive(Debug)]
enum AggregateEngine {
    ExactLiteral(LiteralAggregatePlan),
    UnicodeScalar(UnicodeScalarAggregatePlan),
    FixedClassSandwich(FixedClassSandwichPlan),
    GraphemeScalarDfa(GraphemeScalarDfaPlan),
    BoundedClassSequence(BoundedClassSequencePlan),
    BoundedSeparatedFields(BoundedSeparatedFieldsPlan),
    PrefixClassAlternation(PrefixClassAlternationPlan),
    BoundedContext(BoundedContextPlan),
    FiniteCount(OrderedLiteralCountPlan),
    FiniteSpanSum(OrderedLiteralSpanSumPlan),
    SparseFiniteCount(SparseOrderedLiteralCountPlan),
    SparseFiniteSpanSum(SparseOrderedLiteralSpanSumPlan),
    Continuation(CompiledRegex),
}

#[derive(Debug)]
struct AggregatePlan {
    engine: AggregateEngine,
    minimum_match_bytes: Option<usize>,
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

    const fn minimum_match_bytes(&self) -> Option<usize> {
        self.minimum_match_bytes
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

    #[allow(
        clippy::too_many_lines,
        reason = "the exhaustive engine dispatch keeps every typed count error mapping adjacent"
    )]
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
            AggregateEngine::GraphemeScalarDfa(engine) => engine
                .count(haystack, limits.grapheme_scalar_dfa)
                .map(AggregateCountExecution::GraphemeScalarDfa)
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::GraphemeScalarDfa(source),
                    )
                }),
            AggregateEngine::BoundedClassSequence(engine) => engine
                .count(haystack, limits.bounded_class_sequence)
                .map(AggregateCountExecution::BoundedClassSequence)
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::BoundedClassSequence(source),
                    )
                }),
            AggregateEngine::BoundedSeparatedFields(engine) => engine
                .count(haystack, limits.bounded_separated_fields)
                .map(AggregateCountExecution::BoundedSeparatedFields)
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::BoundedSeparatedFields(source),
                    )
                }),
            AggregateEngine::PrefixClassAlternation(engine) => engine
                .count(haystack, limits.prefix_class_alternation)
                .map(AggregateCountExecution::PrefixClassAlternation)
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::PrefixClassAlternation(source),
                    )
                }),
            AggregateEngine::BoundedContext(engine) => engine
                .count(haystack, limits.bounded_context)
                .map(AggregateCountExecution::BoundedContext)
                .map_err(|source| {
                    self.execution_error(limits, AggregateExecutionSource::BoundedContext(source))
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
            AggregateEngine::SparseFiniteCount(engine) => engine
                .count(haystack, sparse_finite_reduce_limits(limits.finite_literal))
                .map(|result| AggregateCountExecution::SparseFiniteLiteral {
                    value: result.count,
                    upper_bounds: result.accounting.upper_bounds,
                    actual: result.accounting.actual,
                })
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::SparseFiniteLiteral(source),
                    )
                }),
            AggregateEngine::SparseFiniteSpanSum(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "count operation retained a sparse finite span-sum plan",
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
            AggregateEngine::GraphemeScalarDfa(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span-sum operation retained a count-only ordered scalar-grammar plan",
                ),
            )),
            AggregateEngine::BoundedClassSequence(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span-sum operation retained a bounded class-sequence count plan",
                ),
            )),
            AggregateEngine::BoundedSeparatedFields(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span-sum operation retained a bounded separated-field count plan",
                ),
            )),
            AggregateEngine::PrefixClassAlternation(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span-sum operation retained a count-only prefix/class plan",
                ),
            )),
            AggregateEngine::BoundedContext(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span-sum operation retained a bounded-context count plan",
                ),
            )),
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
            AggregateEngine::SparseFiniteSpanSum(engine) => engine
                .span_sum(haystack, sparse_finite_reduce_limits(limits.finite_literal))
                .map(|result| AggregateSpanSumExecution::SparseFiniteLiteral {
                    value: result.span_sum,
                    upper_bounds: result.accounting.upper_bounds,
                    actual: result.accounting.actual,
                })
                .map_err(|source| {
                    self.execution_error(
                        limits,
                        AggregateExecutionSource::SparseFiniteLiteral(source),
                    )
                }),
            AggregateEngine::SparseFiniteCount(_) => Err(self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "span-sum operation retained a sparse finite count plan",
                ),
            )),
            AggregateEngine::Continuation(engine) => {
                self.execute_continuation_span_sum(engine, haystack, limits)
            }
        }
    }

    fn execute_continuation_span_sum(
        &self,
        engine: &CompiledRegex,
        haystack: &[u8],
        limits: &AggregateRunLimits,
    ) -> Result<AggregateSpanSumExecution, AggregateExecutionError> {
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

    fn execute_count_value(
        &self,
        haystack: &[u8],
        limits: &AggregateRunLimits,
    ) -> Result<u64, AggregateExecutionError> {
        let AggregateEngine::Continuation(engine) = &self.engine else {
            return self
                .execute_count(haystack, limits)
                .map(|execution| execution.value());
        };
        let strategy = self.report.continuation_strategy.ok_or_else(|| {
            self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "continuation count plan lacks storage strategy",
                ),
            )
        })?;
        let value = engine
            .count_value(
                haystack,
                Self::full_range(haystack),
                strategy,
                limits.continuation,
            )
            .map_err(|source| {
                self.execution_error(limits, AggregateExecutionSource::Continuation(source))
            })?;
        u64::try_from(value).map_err(|_| {
            self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant("continuation count does not fit u64"),
            )
        })
    }

    fn execute_span_sum_value(
        &self,
        haystack: &[u8],
        limits: &AggregateRunLimits,
    ) -> Result<u64, AggregateExecutionError> {
        let AggregateEngine::Continuation(engine) = &self.engine else {
            return self
                .execute_span_sum(haystack, limits)
                .map(|execution| execution.value());
        };
        let strategy = self.report.continuation_strategy.ok_or_else(|| {
            self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "continuation span-sum plan lacks storage strategy",
                ),
            )
        })?;
        let value = engine
            .span_sum_value(
                haystack,
                Self::full_range(haystack),
                strategy,
                limits.continuation,
            )
            .map_err(|source| {
                self.execution_error(limits, AggregateExecutionSource::Continuation(source))
            })?;
        u64::try_from(value).map_err(|_| {
            self.execution_error(
                limits,
                AggregateExecutionSource::InternalInvariant(
                    "continuation span sum does not fit u64",
                ),
            )
        })
    }
}

enum AggregateCountExecution {
    ExactLiteral(LiteralAggregateCountResult),
    UnicodeScalar(UnicodeScalarAggregateCountResult),
    FixedClassSandwich(FixedClassSandwichCountResult),
    GraphemeScalarDfa(GraphemeScalarDfaCountResult),
    BoundedClassSequence(BoundedClassSequenceCountResult),
    BoundedSeparatedFields(BoundedSeparatedFieldsCountResult),
    PrefixClassAlternation(PrefixClassAlternationCountResult),
    BoundedContext(BoundedContextCountResult),
    FiniteLiteral {
        value: u64,
        upper_bounds: OrderedLiteralAggregateUpperBounds,
        actual: OrderedLiteralAggregateActualCounters,
    },
    SparseFiniteLiteral {
        value: u64,
        upper_bounds: SparseOrderedLiteralAggregateUpperBounds,
        actual: SparseOrderedLiteralAggregateActualCounters,
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
            Self::GraphemeScalarDfa(result) => result.count,
            Self::BoundedClassSequence(result) => result.count,
            Self::BoundedSeparatedFields(result) => result.count,
            Self::PrefixClassAlternation(result) => result.count,
            Self::BoundedContext(result) => result.count,
            Self::FiniteLiteral { value, .. }
            | Self::SparseFiniteLiteral { value, .. }
            | Self::Continuation { value, .. } => *value,
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
            Self::GraphemeScalarDfa(result) => {
                AggregateExecutionDetails::GraphemeScalarDfa(result.accounting)
            }
            Self::BoundedClassSequence(result) => {
                AggregateExecutionDetails::BoundedClassSequence(result.accounting)
            }
            Self::BoundedSeparatedFields(result) => {
                AggregateExecutionDetails::BoundedSeparatedFields(result.accounting)
            }
            Self::PrefixClassAlternation(result) => {
                AggregateExecutionDetails::PrefixClassAlternation(result.accounting)
            }
            Self::BoundedContext(result) => {
                AggregateExecutionDetails::BoundedContext(result.accounting)
            }
            Self::FiniteLiteral {
                upper_bounds,
                actual,
                ..
            } => AggregateExecutionDetails::FiniteLiteral {
                upper_bounds,
                actual,
            },
            Self::SparseFiniteLiteral {
                upper_bounds,
                actual,
                ..
            } => AggregateExecutionDetails::SparseFiniteLiteral {
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
    SparseFiniteLiteral {
        value: u64,
        upper_bounds: SparseOrderedLiteralAggregateUpperBounds,
        actual: SparseOrderedLiteralAggregateActualCounters,
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
            Self::FiniteLiteral { value, .. }
            | Self::SparseFiniteLiteral { value, .. }
            | Self::Continuation { value, .. } => *value,
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
            Self::SparseFiniteLiteral {
                upper_bounds,
                actual,
                ..
            } => AggregateExecutionDetails::SparseFiniteLiteral {
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

enum BoundedContextInspection<'a> {
    Eligible {
        prefix: &'a ClassBytes,
        separator: &'a ClassBytes,
        tail: &'a ClassBytes,
        literal: &'a [u8],
        prefix_width: u32,
        left_gap_max: u32,
        right_gap_max: u32,
        tail_width: u32,
        work: usize,
        hir_nodes: usize,
        captures: usize,
    },
    Ineligible {
        work: usize,
    },
}

enum BoundedAffixInspection<'a> {
    Eligible {
        left: &'a ClassBytes,
        middle: &'a ClassBytes,
        right: &'a ClassBytes,
        literal: &'a [u8],
        middle_max: u32,
        work: usize,
        hir_nodes: usize,
    },
    Ineligible {
        work: usize,
    },
}

enum BoundedContextInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

fn inspect_bounded_affix(
    hir: &Hir,
    limit: usize,
) -> Result<BoundedAffixInspection<'_>, BoundedContextInspectionError> {
    let mut work = 0_usize;
    let mut nodes = 0_usize;
    let mut charge = || {
        charge_bounded_context_work(&mut work, limit)?;
        nodes = nodes
            .checked_add(1)
            .ok_or(BoundedContextInspectionError::Overflow)?;
        Ok::<(), BoundedContextInspectionError>(())
    };
    charge()?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(BoundedAffixInspection::Ineligible { work });
    };
    let [left, repeated, literal, right] = parts.as_slice() else {
        return Ok(BoundedAffixInspection::Ineligible { work });
    };
    charge()?;
    let HirKind::Class(Class::Bytes(left)) = left.kind() else {
        return Ok(BoundedAffixInspection::Ineligible { work });
    };
    charge()?;
    let HirKind::Repetition(repeated) = repeated.kind() else {
        return Ok(BoundedAffixInspection::Ineligible { work });
    };
    let Some(middle_max) = repeated.max else {
        return Ok(BoundedAffixInspection::Ineligible { work });
    };
    if repeated.min != 0 || !repeated.greedy {
        return Ok(BoundedAffixInspection::Ineligible { work });
    }
    charge()?;
    let HirKind::Class(Class::Bytes(middle)) = repeated.sub.kind() else {
        return Ok(BoundedAffixInspection::Ineligible { work });
    };
    charge()?;
    let HirKind::Literal(literal) = literal.kind() else {
        return Ok(BoundedAffixInspection::Ineligible { work });
    };
    charge()?;
    let HirKind::Class(Class::Bytes(right)) = right.kind() else {
        return Ok(BoundedAffixInspection::Ineligible { work });
    };
    if left.ranges().is_empty()
        || middle.ranges().is_empty()
        || right.ranges().is_empty()
        || literal.0.is_empty()
    {
        return Ok(BoundedAffixInspection::Ineligible { work });
    }
    for _ in left
        .ranges()
        .iter()
        .chain(middle.ranges())
        .chain(right.ranges())
    {
        charge_bounded_context_work(&mut work, limit)?;
    }
    for _ in &literal.0 {
        charge_bounded_context_work(&mut work, limit)?;
    }
    if bounded_affix_classes_overlap(left, middle, &mut work, limit)?
        || bounded_affix_classes_overlap(right, middle, &mut work, limit)?
    {
        return Ok(BoundedAffixInspection::Ineligible { work });
    }
    for &byte in &literal.0 {
        if !bounded_affix_class_contains(middle, byte, &mut work, limit)? {
            return Ok(BoundedAffixInspection::Ineligible { work });
        }
    }
    Ok(BoundedAffixInspection::Eligible {
        left,
        middle,
        right,
        literal: literal.0.as_ref(),
        middle_max,
        work,
        hir_nodes: nodes,
    })
}

fn bounded_affix_classes_overlap(
    left: &ClassBytes,
    right: &ClassBytes,
    work: &mut usize,
    limit: usize,
) -> Result<bool, BoundedContextInspectionError> {
    for left_range in left.ranges() {
        for right_range in right.ranges() {
            charge_bounded_context_work(work, limit)?;
            if left_range.start() <= right_range.end() && right_range.start() <= left_range.end() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn bounded_affix_class_contains(
    class: &ClassBytes,
    byte: u8,
    work: &mut usize,
    limit: usize,
) -> Result<bool, BoundedContextInspectionError> {
    for range in class.ranges() {
        charge_bounded_context_work(work, limit)?;
        if range.start() <= byte && byte <= range.end() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[allow(
    clippy::too_many_lines,
    reason = "the eligibility proof walks the fixed seven-part HIR in semantic order and keeps all charged early refusals together"
)]
fn inspect_bounded_context(
    hir: &Hir,
    limit: usize,
) -> Result<BoundedContextInspection<'_>, BoundedContextInspectionError> {
    let mut work = 0_usize;
    let mut hir_nodes = 0_usize;
    let mut captures = 0_usize;
    let hir = peel_bounded_context_captures(hir, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let HirKind::Concat(parts) = hir.kind() else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };
    let [
        prefix,
        left_separator,
        left_gap,
        literal,
        right_gap,
        right_separator,
        tail,
    ] = parts.as_slice()
    else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };

    let Some((prefix, prefix_width)) = inspect_bounded_context_exact_class(
        prefix,
        &mut work,
        &mut hir_nodes,
        &mut captures,
        limit,
    )?
    else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };
    let Some(left_separator) = inspect_bounded_context_separator(
        left_separator,
        &mut work,
        &mut hir_nodes,
        &mut captures,
        limit,
    )?
    else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };
    let Some(left_gap_max) =
        inspect_bounded_context_gap(left_gap, &mut work, &mut hir_nodes, &mut captures, limit)?
    else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };
    let literal =
        peel_bounded_context_captures(literal, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let HirKind::Literal(literal) = literal.kind() else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };
    if literal.0.is_empty() {
        return Ok(BoundedContextInspection::Ineligible { work });
    }
    for _ in &literal.0 {
        charge_bounded_context_work(&mut work, limit)?;
    }
    let Some(right_gap_max) =
        inspect_bounded_context_gap(right_gap, &mut work, &mut hir_nodes, &mut captures, limit)?
    else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };
    let Some(right_separator) = inspect_bounded_context_separator(
        right_separator,
        &mut work,
        &mut hir_nodes,
        &mut captures,
        limit,
    )?
    else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };
    let Some((tail, tail_width)) =
        inspect_bounded_context_exact_class(tail, &mut work, &mut hir_nodes, &mut captures, limit)?
    else {
        return Ok(BoundedContextInspection::Ineligible { work });
    };
    let separator_dedup_comparisons = left_separator
        .ranges()
        .len()
        .checked_add(right_separator.ranges().len())
        .ok_or(BoundedContextInspectionError::Overflow)?;
    for _ in 0..separator_dedup_comparisons {
        charge_bounded_context_work(&mut work, limit)?;
    }
    if left_separator != right_separator {
        return Ok(BoundedContextInspection::Ineligible { work });
    }
    for class in [prefix, left_separator, tail] {
        for _ in class.ranges() {
            charge_bounded_context_work(&mut work, limit)?;
        }
    }
    Ok(BoundedContextInspection::Eligible {
        prefix,
        separator: left_separator,
        tail,
        literal: literal.0.as_ref(),
        prefix_width,
        left_gap_max,
        right_gap_max,
        tail_width,
        work,
        hir_nodes,
        captures,
    })
}

fn inspect_bounded_context_exact_class<'a>(
    hir: &'a Hir,
    work: &mut usize,
    hir_nodes: &mut usize,
    captures: &mut usize,
    limit: usize,
) -> Result<Option<(&'a ClassBytes, u32)>, BoundedContextInspectionError> {
    let hir = peel_bounded_context_captures(hir, work, hir_nodes, captures, limit)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    let Some(maximum) = repetition.max else {
        return Ok(None);
    };
    if repetition.min != maximum || repetition.min < 2 || !repetition.greedy {
        return Ok(None);
    }
    let sub =
        peel_bounded_context_captures(repetition.sub.as_ref(), work, hir_nodes, captures, limit)?;
    let HirKind::Class(Class::Bytes(class)) = sub.kind() else {
        return Ok(None);
    };
    if class.ranges().is_empty() {
        return Ok(None);
    }
    Ok(Some((class, repetition.min)))
}

fn inspect_bounded_context_separator<'a>(
    hir: &'a Hir,
    work: &mut usize,
    hir_nodes: &mut usize,
    captures: &mut usize,
    limit: usize,
) -> Result<Option<&'a ClassBytes>, BoundedContextInspectionError> {
    let hir = peel_bounded_context_captures(hir, work, hir_nodes, captures, limit)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let sub =
        peel_bounded_context_captures(repetition.sub.as_ref(), work, hir_nodes, captures, limit)?;
    let HirKind::Class(Class::Bytes(class)) = sub.kind() else {
        return Ok(None);
    };
    if class.ranges().is_empty() {
        return Ok(None);
    }
    Ok(Some(class))
}

fn inspect_bounded_context_gap(
    hir: &Hir,
    work: &mut usize,
    hir_nodes: &mut usize,
    captures: &mut usize,
    limit: usize,
) -> Result<Option<u32>, BoundedContextInspectionError> {
    let hir = peel_bounded_context_captures(hir, work, hir_nodes, captures, limit)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    let Some(maximum) = repetition.max else {
        return Ok(None);
    };
    if repetition.min != 0 || !repetition.greedy {
        return Ok(None);
    }
    let sub =
        peel_bounded_context_captures(repetition.sub.as_ref(), work, hir_nodes, captures, limit)?;
    let HirKind::Class(Class::Bytes(class)) = sub.kind() else {
        return Ok(None);
    };
    for _ in class.ranges() {
        charge_bounded_context_work(work, limit)?;
    }
    let [range] = class.ranges() else {
        return Ok(None);
    };
    if range.start() != u8::MIN || range.end() != u8::MAX {
        return Ok(None);
    }
    Ok(Some(maximum))
}

fn peel_bounded_context_captures<'a>(
    mut hir: &'a Hir,
    work: &mut usize,
    hir_nodes: &mut usize,
    captures: &mut usize,
    limit: usize,
) -> Result<&'a Hir, BoundedContextInspectionError> {
    loop {
        charge_bounded_context_work(work, limit)?;
        *hir_nodes = (*hir_nodes)
            .checked_add(1)
            .ok_or(BoundedContextInspectionError::Overflow)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        *captures = (*captures)
            .checked_add(1)
            .ok_or(BoundedContextInspectionError::Overflow)?;
        hir = capture.sub.as_ref();
    }
}

fn charge_bounded_context_work(
    work: &mut usize,
    limit: usize,
) -> Result<(), BoundedContextInspectionError> {
    let needed = work
        .checked_add(1)
        .ok_or(BoundedContextInspectionError::Overflow)?;
    if needed > limit {
        return Err(BoundedContextInspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
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

#[derive(Clone, Copy)]
enum BoundedByteClassAtom<'a> {
    Bytes(&'a ClassBytes),
    Singleton(u8),
}

impl<'a> BoundedByteClassAtom<'a> {
    fn range_count(self) -> usize {
        match self {
            Self::Bytes(class) => class.ranges().len(),
            Self::Singleton(_) => 1,
        }
    }

    fn ranges(self) -> BoundedByteClassRanges<'a> {
        match self {
            Self::Bytes(class) => BoundedByteClassRanges::Bytes(class.ranges().iter()),
            Self::Singleton(byte) => BoundedByteClassRanges::Singleton(Some(byte)),
        }
    }
}

#[derive(Clone)]
enum BoundedByteClassRanges<'a> {
    Bytes(core::slice::Iter<'a, ClassBytesRange>),
    Singleton(Option<u8>),
}

impl Iterator for BoundedByteClassRanges<'_> {
    type Item = (u8, u8);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Bytes(ranges) => ranges.next().map(|range| (range.start(), range.end())),
            Self::Singleton(byte) => byte.take().map(|value| (value, value)),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let length = self.len();
        (length, Some(length))
    }
}

impl ExactSizeIterator for BoundedByteClassRanges<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Bytes(ranges) => ranges.len(),
            Self::Singleton(byte) => usize::from(byte.is_some()),
        }
    }
}

#[derive(Clone, Copy)]
struct BoundedSeparatedAlternativeInspection<'a> {
    atoms: [Option<BoundedByteClassAtom<'a>>; BOUNDED_SEPARATED_FIELDS_MAX_ATOMS],
    atom_count: u8,
    optional_index: Option<u8>,
}

impl BoundedSeparatedAlternativeInspection<'_> {
    const EMPTY: Self = Self {
        atoms: [None; BOUNDED_SEPARATED_FIELDS_MAX_ATOMS],
        atom_count: 0,
        optional_index: None,
    };

    fn kernel_source(self) -> Option<BoundedSeparatedFieldsAlternativeSource<'static>> {
        let mut source = BoundedSeparatedFieldsAlternativeSource::empty();
        for index in 0..usize::from(self.atom_count) {
            source.atoms[index] = Some(match self.atoms[index]? {
                BoundedByteClassAtom::Singleton(byte) => {
                    BoundedSeparatedFieldsAtomSource::Singleton(byte)
                }
                BoundedByteClassAtom::Bytes(class) => {
                    let [range] = class.ranges() else {
                        return None;
                    };
                    BoundedSeparatedFieldsAtomSource::Range(range.start(), range.end())
                }
            });
        }
        source.atom_count = self.atom_count;
        source.optional_index = self.optional_index;
        Some(source)
    }
}

#[derive(Clone, Copy)]
struct BoundedSeparatedFieldInspection<'a> {
    alternatives: [Option<BoundedSeparatedAlternativeInspection<'a>>;
        BOUNDED_SEPARATED_FIELDS_MAX_ALTERNATIVES],
    alternative_count: u8,
}

impl BoundedSeparatedFieldInspection<'_> {
    const EMPTY: Self = Self {
        alternatives: [None; BOUNDED_SEPARATED_FIELDS_MAX_ALTERNATIVES],
        alternative_count: 0,
    };

    fn kernel_source(self) -> Option<BoundedSeparatedFieldsFieldSource<'static>> {
        let mut source = BoundedSeparatedFieldsFieldSource::empty();
        for index in 0..usize::from(self.alternative_count) {
            source.alternatives[index] = Some(self.alternatives[index]?.kernel_source()?);
        }
        source.alternative_count = self.alternative_count;
        Some(source)
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "the fixed-array eligible receipt keeps HIR inspection allocation-free"
)]
enum BoundedSeparatedFieldsInspection<'a> {
    Eligible {
        field: BoundedSeparatedFieldInspection<'a>,
        separator: u8,
        fields: u32,
        work: usize,
        hir_nodes: usize,
        captures: usize,
    },
    Ineligible {
        work: usize,
    },
}

enum BoundedSeparatedFieldsInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

struct BoundedSeparatedFieldsInspector {
    limit: usize,
    work: usize,
    hir_nodes: usize,
    captures: usize,
}

impl BoundedSeparatedFieldsInspector {
    const fn new(limit: usize) -> Self {
        Self {
            limit,
            work: 0,
            hir_nodes: 0,
            captures: 0,
        }
    }

    fn inspect(
        mut self,
        hir: &Hir,
    ) -> Result<BoundedSeparatedFieldsInspection<'_>, BoundedSeparatedFieldsInspectionError> {
        let Some(root) = self.peel(hir)? else {
            return Ok(self.ineligible());
        };
        let HirKind::Concat(root_parts) = root.kind() else {
            return Ok(self.ineligible());
        };
        let [repeated_hir, final_field_hir] = root_parts.as_slice() else {
            return Ok(self.ineligible());
        };
        let Some(repeated_hir) = self.peel(repeated_hir)? else {
            return Ok(self.ineligible());
        };
        let HirKind::Repetition(repeated) = repeated_hir.kind() else {
            return Ok(self.ineligible());
        };
        let Some(maximum) = repeated.max else {
            return Ok(self.ineligible());
        };
        if repeated.min == 0 || repeated.min != maximum || !repeated.greedy {
            return Ok(self.ineligible());
        }
        let fields = repeated
            .min
            .checked_add(1)
            .ok_or(BoundedSeparatedFieldsInspectionError::Overflow)?;
        if fields > BOUNDED_SEPARATED_FIELDS_MAX_FIELDS {
            return Ok(self.ineligible());
        }
        let Some(repeated_unit) = self.peel(repeated.sub.as_ref())? else {
            return Ok(self.ineligible());
        };
        let HirKind::Concat(unit_parts) = repeated_unit.kind() else {
            return Ok(self.ineligible());
        };
        let [repeated_field_hir, separator_hir] = unit_parts.as_slice() else {
            return Ok(self.ineligible());
        };
        let Some(repeated_field) = self.field(repeated_field_hir)? else {
            return Ok(self.ineligible());
        };
        let Some(separator_hir) = self.peel(separator_hir)? else {
            return Ok(self.ineligible());
        };
        let HirKind::Literal(separator_literal) = separator_hir.kind() else {
            return Ok(self.ineligible());
        };
        let [separator] = separator_literal.0.as_ref() else {
            return Ok(self.ineligible());
        };
        self.charge(1)?;
        let Some(final_field) = self.field(final_field_hir)? else {
            return Ok(self.ineligible());
        };
        if !self.fields_equal(&repeated_field, &final_field)? {
            return Ok(self.ineligible());
        }
        Ok(BoundedSeparatedFieldsInspection::Eligible {
            field: repeated_field,
            separator: *separator,
            fields,
            work: self.work,
            hir_nodes: self.hir_nodes,
            captures: self.captures,
        })
    }

    fn field<'a>(
        &mut self,
        hir: &'a Hir,
    ) -> Result<Option<BoundedSeparatedFieldInspection<'a>>, BoundedSeparatedFieldsInspectionError>
    {
        let Some(hir) = self.peel(hir)? else {
            return Ok(None);
        };
        let HirKind::Alternation(branches) = hir.kind() else {
            return Ok(None);
        };
        if branches.is_empty() || branches.len() > BOUNDED_SEPARATED_FIELDS_MAX_ALTERNATIVES {
            return Ok(None);
        }
        let mut field = BoundedSeparatedFieldInspection::EMPTY;
        for (index, branch) in branches.iter().enumerate() {
            let Some(alternative) = self.alternative(branch)? else {
                return Ok(None);
            };
            field.alternatives[index] = Some(alternative);
        }
        field.alternative_count = u8::try_from(branches.len())
            .map_err(|_| BoundedSeparatedFieldsInspectionError::Overflow)?;
        Ok(Some(field))
    }

    fn alternative<'a>(
        &mut self,
        hir: &'a Hir,
    ) -> Result<
        Option<BoundedSeparatedAlternativeInspection<'a>>,
        BoundedSeparatedFieldsInspectionError,
    > {
        let Some(hir) = self.peel(hir)? else {
            return Ok(None);
        };
        let HirKind::Concat(parts) = hir.kind() else {
            return Ok(None);
        };
        let mut alternative = BoundedSeparatedAlternativeInspection::EMPTY;
        for part in parts {
            let Some(part) = self.peel(part)? else {
                return Ok(None);
            };
            match part.kind() {
                HirKind::Literal(literal) if !literal.0.is_empty() => {
                    self.charge(literal.0.len())?;
                    for &byte in literal.0.as_ref() {
                        if !push_bounded_separated_atom(
                            &mut alternative,
                            BoundedByteClassAtom::Singleton(byte),
                            false,
                        )? {
                            return Ok(None);
                        }
                    }
                }
                HirKind::Class(Class::Bytes(class)) if class.ranges().len() == 1 => {
                    self.charge(class.ranges().len())?;
                    if !push_bounded_separated_atom(
                        &mut alternative,
                        BoundedByteClassAtom::Bytes(class),
                        false,
                    )? {
                        return Ok(None);
                    }
                }
                HirKind::Repetition(optional)
                    if optional.min == 0 && optional.max == Some(1) && optional.greedy =>
                {
                    if alternative.optional_index.is_some() {
                        return Ok(None);
                    }
                    let Some(optional_atom) = self.peel(optional.sub.as_ref())? else {
                        return Ok(None);
                    };
                    let atom = match optional_atom.kind() {
                        HirKind::Literal(literal) => {
                            let [byte] = literal.0.as_ref() else {
                                return Ok(None);
                            };
                            self.charge(1)?;
                            BoundedByteClassAtom::Singleton(*byte)
                        }
                        HirKind::Class(Class::Bytes(class)) if class.ranges().len() == 1 => {
                            self.charge(1)?;
                            BoundedByteClassAtom::Bytes(class)
                        }
                        _ => return Ok(None),
                    };
                    if !push_bounded_separated_atom(&mut alternative, atom, true)? {
                        return Ok(None);
                    }
                }
                _ => return Ok(None),
            }
        }
        if alternative.atom_count == 0 {
            return Ok(None);
        }
        Ok(Some(alternative))
    }

    fn fields_equal(
        &mut self,
        left: &BoundedSeparatedFieldInspection<'_>,
        right: &BoundedSeparatedFieldInspection<'_>,
    ) -> Result<bool, BoundedSeparatedFieldsInspectionError> {
        self.charge(1)?;
        if left.alternative_count != right.alternative_count {
            return Ok(false);
        }
        for index in 0..usize::from(left.alternative_count) {
            let (Some(left), Some(right)) = (left.alternatives[index], right.alternatives[index])
            else {
                return Err(BoundedSeparatedFieldsInspectionError::Overflow);
            };
            self.charge(1)?;
            if left.atom_count != right.atom_count || left.optional_index != right.optional_index {
                return Ok(false);
            }
            for atom_index in 0..usize::from(left.atom_count) {
                let (Some(left), Some(right)) = (left.atoms[atom_index], right.atoms[atom_index])
                else {
                    return Err(BoundedSeparatedFieldsInspectionError::Overflow);
                };
                let comparisons = left
                    .range_count()
                    .checked_add(right.range_count())
                    .ok_or(BoundedSeparatedFieldsInspectionError::Overflow)?;
                self.charge(comparisons)?;
                if !left.ranges().eq(right.ranges()) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn peel<'a>(
        &mut self,
        mut hir: &'a Hir,
    ) -> Result<Option<&'a Hir>, BoundedSeparatedFieldsInspectionError> {
        loop {
            self.charge(1)?;
            self.hir_nodes = self
                .hir_nodes
                .checked_add(1)
                .ok_or(BoundedSeparatedFieldsInspectionError::Overflow)?;
            let HirKind::Capture(capture) = hir.kind() else {
                return Ok(Some(hir));
            };
            self.captures = self
                .captures
                .checked_add(1)
                .ok_or(BoundedSeparatedFieldsInspectionError::Overflow)?;
            hir = capture.sub.as_ref();
        }
    }

    fn charge(&mut self, amount: usize) -> Result<(), BoundedSeparatedFieldsInspectionError> {
        let needed = self
            .work
            .checked_add(amount)
            .ok_or(BoundedSeparatedFieldsInspectionError::Overflow)?;
        if needed > self.limit {
            return Err(BoundedSeparatedFieldsInspectionError::WorkLimit {
                needed,
                limit: self.limit,
            });
        }
        self.work = needed;
        Ok(())
    }

    const fn ineligible(&self) -> BoundedSeparatedFieldsInspection<'static> {
        BoundedSeparatedFieldsInspection::Ineligible { work: self.work }
    }
}

fn push_bounded_separated_atom<'a>(
    alternative: &mut BoundedSeparatedAlternativeInspection<'a>,
    atom: BoundedByteClassAtom<'a>,
    optional: bool,
) -> Result<bool, BoundedSeparatedFieldsInspectionError> {
    let index = usize::from(alternative.atom_count);
    if index >= BOUNDED_SEPARATED_FIELDS_MAX_ATOMS {
        return Ok(false);
    }
    alternative.atoms[index] = Some(atom);
    if optional {
        alternative.optional_index =
            Some(u8::try_from(index).map_err(|_| BoundedSeparatedFieldsInspectionError::Overflow)?);
    }
    alternative.atom_count = alternative
        .atom_count
        .checked_add(1)
        .ok_or(BoundedSeparatedFieldsInspectionError::Overflow)?;
    Ok(true)
}

fn inspect_bounded_separated_fields(
    hir: &Hir,
    limit: usize,
) -> Result<BoundedSeparatedFieldsInspection<'_>, BoundedSeparatedFieldsInspectionError> {
    BoundedSeparatedFieldsInspector::new(limit).inspect(hir)
}

enum BoundedClassSequenceInspection<'a> {
    Eligible {
        head: BoundedByteClassAtom<'a>,
        body: BoundedByteClassAtom<'a>,
        trail: BoundedByteClassAtom<'a>,
        minimum: u32,
        maximum: u32,
        work: usize,
        hir_nodes: usize,
        captures: usize,
    },
    Ineligible {
        work: usize,
    },
}

enum BoundedClassSequenceInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

#[allow(
    clippy::too_many_lines,
    reason = "one allocation-free traversal records the complete admitted compound-class HIR proof"
)]
fn inspect_bounded_class_sequence(
    hir: &Hir,
    limit: usize,
) -> Result<BoundedClassSequenceInspection<'_>, BoundedClassSequenceInspectionError> {
    let mut work = 0_usize;
    let mut hir_nodes = 0_usize;
    let mut captures = 0_usize;
    let hir = peel_bounded_sequence_captures(hir, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let HirKind::Repetition(outer) = hir.kind() else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    let Some(maximum) = outer.max else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    if outer.min == 0 || maximum < outer.min || !outer.greedy {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    }
    let unit = peel_bounded_sequence_captures(
        outer.sub.as_ref(),
        &mut work,
        &mut hir_nodes,
        &mut captures,
        limit,
    )?;
    let HirKind::Concat(parts) = unit.kind() else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    let [head, body, trail] = parts.as_slice() else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    let head =
        peel_bounded_sequence_captures(head, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let Some(head) = inspect_bounded_byte_class(head) else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    let body =
        peel_bounded_sequence_captures(body, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let HirKind::Repetition(body_repeat) = body.kind() else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    if body_repeat.min != 1 || body_repeat.max.is_some() || !body_repeat.greedy {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    }
    let body = peel_bounded_sequence_captures(
        body_repeat.sub.as_ref(),
        &mut work,
        &mut hir_nodes,
        &mut captures,
        limit,
    )?;
    let Some(body) = inspect_bounded_byte_class(body) else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    let trail =
        peel_bounded_sequence_captures(trail, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let HirKind::Repetition(trail_repeat) = trail.kind() else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    if trail_repeat.min != 0 || trail_repeat.max.is_some() || !trail_repeat.greedy {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    }
    let trail = peel_bounded_sequence_captures(
        trail_repeat.sub.as_ref(),
        &mut work,
        &mut hir_nodes,
        &mut captures,
        limit,
    )?;
    let Some(trail) = inspect_bounded_byte_class(trail) else {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    };
    for atom in [head, body, trail] {
        for _ in 0..atom.range_count() {
            charge_bounded_sequence_inspection_work(&mut work, limit)?;
        }
    }
    // Canonical ranges are sorted and non-overlapping, so each pairwise merge
    // needs at most left.len() + right.len() - 1 comparisons. Precharge all
    // three bounds before reading ranges; their sum is 2Q-3, keeping selection
    // linear in the retained source structure.
    let head_body_comparisons = bounded_disjoint_comparison_bound(head, body)?;
    let head_trail_comparisons = bounded_disjoint_comparison_bound(head, trail)?;
    let body_trail_comparisons = bounded_disjoint_comparison_bound(body, trail)?;
    let disjoint_comparisons = head_body_comparisons
        .checked_add(head_trail_comparisons)
        .and_then(|count| count.checked_add(body_trail_comparisons))
        .ok_or(BoundedClassSequenceInspectionError::Overflow)?;
    for _ in 0..disjoint_comparisons {
        charge_bounded_sequence_inspection_work(&mut work, limit)?;
    }
    if bounded_byte_classes_overlap(head, body)
        || bounded_byte_classes_overlap(head, trail)
        || bounded_byte_classes_overlap(body, trail)
    {
        return Ok(BoundedClassSequenceInspection::Ineligible { work });
    }
    Ok(BoundedClassSequenceInspection::Eligible {
        head,
        body,
        trail,
        minimum: outer.min,
        maximum,
        work,
        hir_nodes,
        captures,
    })
}

fn peel_bounded_sequence_captures<'a>(
    mut hir: &'a Hir,
    work: &mut usize,
    hir_nodes: &mut usize,
    captures: &mut usize,
    limit: usize,
) -> Result<&'a Hir, BoundedClassSequenceInspectionError> {
    loop {
        charge_bounded_sequence_inspection_work(work, limit)?;
        *hir_nodes = (*hir_nodes)
            .checked_add(1)
            .ok_or(BoundedClassSequenceInspectionError::Overflow)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        *captures = (*captures)
            .checked_add(1)
            .ok_or(BoundedClassSequenceInspectionError::Overflow)?;
        hir = capture.sub.as_ref();
    }
}

fn inspect_bounded_byte_class(hir: &Hir) -> Option<BoundedByteClassAtom<'_>> {
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) if !class.ranges().is_empty() => {
            Some(BoundedByteClassAtom::Bytes(class))
        }
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            Some(BoundedByteClassAtom::Singleton(literal.0[0]))
        }
        _ => None,
    }
}

fn bounded_byte_classes_overlap(
    left: BoundedByteClassAtom<'_>,
    right: BoundedByteClassAtom<'_>,
) -> bool {
    let mut left = left.ranges().peekable();
    let mut right = right.ranges().peekable();
    while let (Some(&(left_start, left_end)), Some(&(right_start, right_end))) =
        (left.peek(), right.peek())
    {
        if left_end < right_start {
            left.next();
        } else if right_end < left_start {
            right.next();
        } else {
            return true;
        }
    }
    false
}

fn bounded_disjoint_comparison_bound(
    left: BoundedByteClassAtom<'_>,
    right: BoundedByteClassAtom<'_>,
) -> Result<usize, BoundedClassSequenceInspectionError> {
    left.range_count()
        .checked_add(right.range_count())
        .and_then(|count| count.checked_sub(1))
        .ok_or(BoundedClassSequenceInspectionError::Overflow)
}

fn charge_bounded_sequence_inspection_work(
    work: &mut usize,
    limit: usize,
) -> Result<(), BoundedClassSequenceInspectionError> {
    let needed = work
        .checked_add(1)
        .ok_or(BoundedClassSequenceInspectionError::Overflow)?;
    if needed > limit {
        return Err(BoundedClassSequenceInspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
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

enum PrefixClassInspection<'a> {
    Eligible {
        prefixes: [&'a [u8]; 2],
        classes: [&'a ClassBytes; 2],
        work: usize,
        hir_nodes: usize,
        captures: usize,
    },
    Ineligible {
        work: usize,
    },
}

enum PrefixClassInspectionError {
    WorkLimit { needed: usize, limit: usize },
    Overflow,
}

struct PrefixClassBranch<'a> {
    prefix: &'a [u8],
    class: &'a ClassBytes,
}

fn inspect_prefix_class_alternation(
    hir: &Hir,
    limit: usize,
) -> Result<PrefixClassInspection<'_>, PrefixClassInspectionError> {
    let mut work = 0_usize;
    let mut hir_nodes = 0_usize;
    let mut captures = 0_usize;
    let (_, root_kind) =
        peel_prefix_class_captures(hir, &mut work, &mut hir_nodes, &mut captures, limit)?;
    let HirKind::Alternation(branches) = root_kind else {
        return Ok(PrefixClassInspection::Ineligible { work });
    };
    charge_prefix_class_work(&mut work, 2, limit)?;
    let [first, second] = branches.as_slice() else {
        return Ok(PrefixClassInspection::Ineligible { work });
    };
    let Some(first) =
        inspect_prefix_class_branch(first, &mut work, &mut hir_nodes, &mut captures, limit)?
    else {
        return Ok(PrefixClassInspection::Ineligible { work });
    };
    let Some(second) =
        inspect_prefix_class_branch(second, &mut work, &mut hir_nodes, &mut captures, limit)?
    else {
        return Ok(PrefixClassInspection::Ineligible { work });
    };
    Ok(PrefixClassInspection::Eligible {
        prefixes: [first.prefix, second.prefix],
        classes: [first.class, second.class],
        work,
        hir_nodes,
        captures,
    })
}

fn inspect_prefix_class_branch<'a>(
    hir: &'a Hir,
    work: &mut usize,
    hir_nodes: &mut usize,
    captures: &mut usize,
    limit: usize,
) -> Result<Option<PrefixClassBranch<'a>>, PrefixClassInspectionError> {
    let (_, branch_kind) = peel_prefix_class_captures(hir, work, hir_nodes, captures, limit)?;
    let HirKind::Concat(parts) = branch_kind else {
        return Ok(None);
    };
    let [prefix_hir, repeated_hir] = parts.as_slice() else {
        return Ok(None);
    };
    let (_, prefix_kind) =
        peel_prefix_class_captures(prefix_hir, work, hir_nodes, captures, limit)?;
    let HirKind::Literal(literal) = prefix_kind else {
        return Ok(None);
    };
    let prefix = literal.0.as_ref();
    let prefix_work = prefix
        .len()
        .checked_mul(2)
        .ok_or(PrefixClassInspectionError::Overflow)?;
    charge_prefix_class_work(work, prefix_work, limit)?;
    if prefix.is_empty() {
        return Ok(None);
    }
    if prefix[1..].contains(&prefix[0]) {
        return Ok(None);
    }

    let (_, repeated_kind) =
        peel_prefix_class_captures(repeated_hir, work, hir_nodes, captures, limit)?;
    let HirKind::Repetition(repetition) = repeated_kind else {
        return Ok(None);
    };
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let (_, class_kind) =
        peel_prefix_class_captures(repetition.sub.as_ref(), work, hir_nodes, captures, limit)?;
    let HirKind::Class(Class::Bytes(class)) = class_kind else {
        return Ok(None);
    };
    charge_prefix_class_work(work, class.ranges().len(), limit)?;
    if class.ranges().is_empty() {
        return Ok(None);
    }
    Ok(Some(PrefixClassBranch { prefix, class }))
}

fn peel_prefix_class_captures<'a>(
    mut hir: &'a Hir,
    work: &mut usize,
    hir_nodes: &mut usize,
    captures: &mut usize,
    limit: usize,
) -> Result<(&'a Hir, &'a HirKind), PrefixClassInspectionError> {
    loop {
        charge_prefix_class_work(work, 1, limit)?;
        *hir_nodes = hir_nodes
            .checked_add(1)
            .ok_or(PrefixClassInspectionError::Overflow)?;
        let kind = hir.kind();
        let HirKind::Capture(capture) = kind else {
            return Ok((hir, kind));
        };
        *captures = captures
            .checked_add(1)
            .ok_or(PrefixClassInspectionError::Overflow)?;
        hir = capture.sub.as_ref();
    }
}

fn charge_prefix_class_work(
    work: &mut usize,
    amount: usize,
    limit: usize,
) -> Result<(), PrefixClassInspectionError> {
    let needed = work
        .checked_add(amount)
        .ok_or(PrefixClassInspectionError::Overflow)?;
    if needed > limit {
        return Err(PrefixClassInspectionError::WorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

fn class_bytes_range_tuple(range: ClassBytesRange) -> (u8, u8) {
    (range.start(), range.end())
}

fn prefix_class_selection_work(summary: &ParseSummary) -> Option<usize> {
    let hir_nodes = usize::try_from(summary.hir_nodes).ok()?;
    let literal_bytes = usize::try_from(summary.literal_bytes).ok()?;
    let class_ranges = usize::try_from(summary.class_ranges).ok()?;
    hir_nodes
        .checked_add(literal_bytes.checked_mul(2)?)?
        .checked_add(class_ranges)?
        .checked_add(2)
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

    /// Minimum whole-match width derived from the authenticated construction HIR.
    #[must_use]
    pub const fn minimum_match_bytes(&self) -> Option<usize> {
        self.0.minimum_match_bytes()
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

    /// Minimum whole-match width derived from the authenticated construction HIR.
    #[must_use]
    pub const fn minimum_match_bytes(&self) -> Option<usize> {
        self.0.minimum_match_bytes()
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

    /// Count through the same selected plan as [`Self::count`], but return only
    /// the reducer value. Continuation programs enforce execution work against
    /// the exact work observed by the complete reduction instead of requiring
    /// the diagnostic result's conservative replay bound. All other resource
    /// preflights are unchanged. A successful call does not construct an
    /// [`AggregateExecutionReport`], cache identity, or clone the source-key
    /// `Arc`. Failures retain the complete typed identity.
    pub fn count_value(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<u64, AggregateExecutionError> {
        let limits = limits.borrow();
        self.0.execute_count_value(haystack, limits)
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

    /// Sum spans through the same selected plan as [`Self::span_sum`], but
    /// return only the reducer value. Continuation programs enforce execution
    /// work against the exact work observed by the complete reduction instead
    /// of requiring the diagnostic result's conservative replay bound. All
    /// other resource preflights are unchanged. A successful call does not
    /// construct an [`AggregateExecutionReport`], cache identity, or clone the
    /// source-key `Arc`. Failures retain the complete typed identity.
    pub fn span_sum_value(
        &self,
        haystack: &[u8],
        limits: impl core::borrow::Borrow<AggregateRunLimits>,
    ) -> Result<u64, AggregateExecutionError> {
        let limits = limits.borrow();
        self.0.execute_span_sum_value(haystack, limits)
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
