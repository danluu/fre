use core::{fmt, ops::Range};
use std::sync::Arc;

use fre_aggregate::{
    AdmittedCountAttempt, AdmittedSpanSumAttempt, AdmittedSpans, CompiledRegex,
    OperationAttemptError, OperationAttemptReceipt, OperationProspective, RustByteProfile,
    SpanIter,
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
    FixedAbsoluteDomainActual, FixedAbsoluteDomainBuildAccounting, FixedAbsoluteDomainBuildActual,
    FixedAbsoluteDomainBuildError, FixedAbsoluteDomainBuildErrorKind,
    FixedAbsoluteDomainBuildLimits, FixedAbsoluteDomainBuildProspective,
    FixedAbsoluteDomainBuildResource, FixedAbsoluteDomainCountOutcome,
    FixedAbsoluteDomainDescriptorKind, FixedAbsoluteDomainDisposition,
    FixedAbsoluteDomainOperation, FixedAbsoluteDomainOperationIdentity, FixedAbsoluteDomainPlan,
    FixedAbsoluteDomainProspective, FixedAbsoluteDomainReduceAccounting,
    FixedAbsoluteDomainReduceError, FixedAbsoluteDomainReduceLimits, FixedAbsoluteDomainResidual,
    FixedAbsoluteDomainSpanSumResult, FixedClassSandwichBuildAccounting,
    FixedClassSandwichBuildError, FixedClassSandwichBuildLimits, FixedClassSandwichCountResult,
    FixedClassSandwichOperationIdentity, FixedClassSandwichPlan,
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
    UnicodeScalarAggregateSpanSumResult, Window,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{
    Class, ClassBytes, ClassBytesRange, ClassUnicode, ClassUnicodeRange, Hir, HirKind,
};

use crate::{
    AggregateCompileAccounting, AggregateCompileAttemptError, AggregateCompileLimits,
    AggregateEngineError, AggregateExecutionAccounting, AggregateOperationCertificate,
    AggregateOperationLimits, AggregatePlanId, AggregateResource, BuildError, Match, finite,
    finite_root, fixed_absolute, grapheme_scalar,
};

pub use fre_aggregate::Strategy as AggregateStrategy;

/// Stable schema for aggregate facade reports and cache identities.
pub const AGGREGATE_EXPLAIN_SCHEMA_VERSION: u32 = 24;

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
    /// Fixed candidate derived from absolute StartText/EndText over the
    /// original haystack, with an eager residual only for scalar envelopes.
    FixedAbsoluteDomain,
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
    /// Closed fixed absolute-domain descriptor and declared residual identity.
    FixedAbsoluteDomain(AggregateFixedAbsoluteDomainIdentity),
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

/// Facade closure for one fixed absolute-domain operation. The continuation
/// identity is present only for the rejection-only scalar envelope and is
/// eagerly constructed before this identity is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainIdentity {
    pub kernel: FixedAbsoluteDomainOperationIdentity,
    pub residual: Option<AggregateContinuationIdentity>,
    pub residual_strategy: Option<AggregateStrategy>,
}

/// Owner-local construction receipt. Direct descriptors have no residual;
/// the scalar envelope reports both co-live immutable artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainBuildAccounting {
    /// Kernel-local construction receipt before the facade owner exists.
    pub kernel: FixedAbsoluteDomainBuildAccounting,
    /// The same guard construction with the construction-owner allocation
    /// included in every applicable fixed-domain build dimension.
    pub guard_with_owner: FixedAbsoluteDomainBuildAccounting,
    pub residual: Option<AggregateCompileAccounting>,
    pub prospective: AggregateFixedAbsoluteDomainResidualBuildProspective,
    pub actual: AggregateFixedAbsoluteDomainResidualBuildActual,
}

/// Compact inline projection for the fixed-domain owner. The complete kernel
/// and residual receipts live once in the construction-owned seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainBuildSummary {
    pub prospective: AggregateFixedAbsoluteDomainResidualBuildProspective,
    pub actual: AggregateFixedAbsoluteDomainResidualBuildActual,
    pub has_residual: bool,
}

impl AggregateFixedAbsoluteDomainBuildAccounting {
    const fn summary(self) -> AggregateFixedAbsoluteDomainBuildSummary {
        AggregateFixedAbsoluteDomainBuildSummary {
            prospective: self.prospective,
            actual: self.actual,
            has_residual: self.residual.is_some(),
        }
    }
}

/// Input-only construction envelope for a fixed guard and optional eager
/// scalar continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualBuildProspective {
    pub work: u64,
    pub allocations: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact cumulative construction ledger for the fixed composite.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualBuildActual {
    pub work: u64,
    pub allocations: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub published: bool,
}

/// Outer receipt retained when eager scalar construction fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt {
    pub prospective: AggregateFixedAbsoluteDomainResidualBuildProspective,
    pub actual: AggregateFixedAbsoluteDomainResidualBuildActual,
}

impl AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt {
    #[must_use]
    pub const fn contains_actual(self) -> bool {
        self.actual.work <= self.prospective.work
            && self.actual.allocations <= self.prospective.allocations
            && self.actual.persistent_bytes <= self.prospective.persistent_bytes
            && self.actual.peak_bytes <= self.prospective.peak_bytes
            && !self.actual.published
    }
}

/// Separately enforced U1 composite construction dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateFixedAbsoluteDomainResidualBuildResource {
    Work,
    Allocations,
    PersistentBytes,
    PeakBytes,
}

fn compose_fixed_residual_build_prospective(
    guard: fre_kernels::FixedAbsoluteDomainBuildProspective,
    continuation: AggregateCompileLimits,
    residual_allocations: usize,
) -> Result<AggregateFixedAbsoluteDomainResidualBuildProspective, &'static str> {
    let continuation_work =
        u64::try_from(continuation.max_work).map_err(|_| "residual work does not fit u64")?;
    let work = guard
        .build_work
        .checked_add(continuation_work)
        .ok_or("fixed residual prospective work overflow")?;
    let allocations = guard
        .allocations
        .checked_add(residual_allocations)
        .ok_or("fixed residual prospective allocations overflow")?;
    let persistent_bytes = guard
        .persistent_bytes
        .checked_add(continuation.max_program_bytes)
        .ok_or("fixed residual prospective persistent bytes overflow")?;
    let peak_bytes = guard
        .persistent_bytes
        .checked_add(continuation.max_program_bytes)
        .map(|co_live| co_live.max(guard.peak_bytes))
        .ok_or("fixed residual prospective peak bytes overflow")?;
    Ok(AggregateFixedAbsoluteDomainResidualBuildProspective {
        work,
        allocations,
        persistent_bytes,
        peak_bytes,
    })
}

fn fixed_absolute_owner_bytes() -> Result<usize, &'static str> {
    let pointer_metadata_bytes = core::mem::size_of::<usize>()
        .checked_mul(2)
        .ok_or("fixed absolute owner metadata bytes overflow")?;
    core::mem::size_of::<AggregateExecutionIdentityInner>()
        .checked_add(pointer_metadata_bytes)
        .ok_or("fixed absolute owner allocation bytes overflow")
}

fn include_fixed_absolute_owner_guard_prospective(
    prospective: FixedAbsoluteDomainBuildProspective,
) -> Result<FixedAbsoluteDomainBuildProspective, &'static str> {
    let owner_bytes = fixed_absolute_owner_bytes()?;
    let owner_work = u64::try_from(owner_bytes)
        .map_err(|_| "fixed absolute owner initialization work does not fit u64")?;
    let persistent_bytes = prospective
        .persistent_bytes
        .checked_add(owner_bytes)
        .ok_or("fixed absolute owner persistent bytes overflow")?;
    Ok(FixedAbsoluteDomainBuildProspective {
        descriptor: prospective.descriptor,
        items: prospective
            .items
            .checked_add(1)
            .ok_or("fixed absolute owner items overflow")?,
        payload_bytes: prospective
            .payload_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner payload bytes overflow")?,
        identity_bytes: prospective
            .identity_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner identity bytes overflow")?,
        retained_heap_bytes: prospective
            .retained_heap_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner retained bytes overflow")?,
        copied_bytes: prospective
            .copied_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner copied bytes overflow")?,
        allocations: prospective
            .allocations
            .checked_add(1)
            .ok_or("fixed absolute owner allocations overflow")?,
        initialized_bytes: prospective
            .initialized_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner initialized bytes overflow")?,
        build_work: prospective
            .build_work
            .checked_add(owner_work)
            .ok_or("fixed absolute owner build work overflow")?,
        scratch_bytes: prospective.scratch_bytes,
        persistent_bytes,
        peak_bytes: prospective.peak_bytes.max(persistent_bytes),
    })
}

fn include_fixed_absolute_owner_guard_actual(
    actual: FixedAbsoluteDomainBuildActual,
) -> Result<FixedAbsoluteDomainBuildActual, &'static str> {
    let owner_bytes = fixed_absolute_owner_bytes()?;
    let owner_work = u64::try_from(owner_bytes)
        .map_err(|_| "fixed absolute owner initialization work does not fit u64")?;
    let persistent_bytes = actual
        .persistent_bytes
        .checked_add(owner_bytes)
        .ok_or("fixed absolute owner actual persistent bytes overflow")?;
    Ok(FixedAbsoluteDomainBuildActual {
        items: actual
            .items
            .checked_add(1)
            .ok_or("fixed absolute owner actual items overflow")?,
        payload_bytes: actual
            .payload_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner actual payload bytes overflow")?,
        identity_bytes: actual
            .identity_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner actual identity bytes overflow")?,
        retained_heap_bytes: actual
            .retained_heap_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner actual retained bytes overflow")?,
        copied_bytes: actual
            .copied_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner actual copied bytes overflow")?,
        allocations: actual
            .allocations
            .checked_add(1)
            .ok_or("fixed absolute owner actual allocations overflow")?,
        initialized_bytes: actual
            .initialized_bytes
            .checked_add(owner_bytes)
            .ok_or("fixed absolute owner actual initialized bytes overflow")?,
        build_work: actual
            .build_work
            .checked_add(owner_work)
            .ok_or("fixed absolute owner actual build work overflow")?,
        scratch_bytes: actual.scratch_bytes,
        persistent_bytes,
        peak_bytes: actual.peak_bytes.max(persistent_bytes),
        published: actual.published,
    })
}

fn fixed_guard_build_limit_refusal(
    prospective: FixedAbsoluteDomainBuildProspective,
    limits: FixedAbsoluteDomainBuildLimits,
) -> Option<(FixedAbsoluteDomainBuildResource, u64, u64)> {
    let checks = [
        (
            FixedAbsoluteDomainBuildResource::Items,
            u64::try_from(prospective.items).ok()?,
            u64::try_from(limits.max_items).ok()?,
        ),
        (
            FixedAbsoluteDomainBuildResource::PayloadBytes,
            u64::try_from(prospective.payload_bytes).ok()?,
            u64::try_from(limits.max_payload_bytes).ok()?,
        ),
        (
            FixedAbsoluteDomainBuildResource::IdentityBytes,
            u64::try_from(prospective.identity_bytes).ok()?,
            u64::try_from(limits.max_identity_bytes).ok()?,
        ),
        (
            FixedAbsoluteDomainBuildResource::CopiedBytes,
            u64::try_from(prospective.copied_bytes).ok()?,
            u64::try_from(limits.max_copied_bytes).ok()?,
        ),
        (
            FixedAbsoluteDomainBuildResource::Allocations,
            u64::try_from(prospective.allocations).ok()?,
            u64::try_from(limits.max_allocations).ok()?,
        ),
        (
            FixedAbsoluteDomainBuildResource::InitializedBytes,
            u64::try_from(prospective.initialized_bytes).ok()?,
            u64::try_from(limits.max_initialized_bytes).ok()?,
        ),
        (
            FixedAbsoluteDomainBuildResource::Work,
            prospective.build_work,
            limits.max_build_work,
        ),
        (
            FixedAbsoluteDomainBuildResource::PersistentBytes,
            u64::try_from(prospective.persistent_bytes).ok()?,
            u64::try_from(limits.max_persistent_bytes).ok()?,
        ),
        (
            FixedAbsoluteDomainBuildResource::PeakBytes,
            u64::try_from(prospective.peak_bytes).ok()?,
            u64::try_from(limits.max_peak_bytes).ok()?,
        ),
    ];
    checks
        .into_iter()
        .find(|(_, required, limit)| required > limit)
}

fn fixed_guard_build_preflight_error(
    prospective: FixedAbsoluteDomainBuildProspective,
    resource: FixedAbsoluteDomainBuildResource,
    needed: u64,
    limit: u64,
) -> FixedAbsoluteDomainBuildError {
    FixedAbsoluteDomainBuildError {
        kind: FixedAbsoluteDomainBuildErrorKind::ResourceLimit {
            resource,
            needed,
            limit,
        },
        prospective: Some(prospective),
        actual: FixedAbsoluteDomainBuildActual::default(),
    }
}

fn bind_fixed_owner_to_guard_build_error(
    mut source: FixedAbsoluteDomainBuildError,
    prospective: FixedAbsoluteDomainBuildProspective,
) -> FixedAbsoluteDomainBuildError {
    if source.prospective.is_some() {
        source.prospective = Some(prospective);
    }
    source
}

fn include_fixed_absolute_owner_prospective(
    prospective: AggregateFixedAbsoluteDomainResidualBuildProspective,
) -> Result<AggregateFixedAbsoluteDomainResidualBuildProspective, &'static str> {
    let owner_bytes = fixed_absolute_owner_bytes()?;
    let owner_work = u64::try_from(owner_bytes)
        .map_err(|_| "fixed absolute owner initialization work does not fit u64")?;
    let work = prospective
        .work
        .checked_add(owner_work)
        .ok_or("fixed absolute owner prospective work overflow")?;
    let allocations = prospective
        .allocations
        .checked_add(1)
        .ok_or("fixed absolute owner prospective allocations overflow")?;
    let persistent_bytes = prospective
        .persistent_bytes
        .checked_add(owner_bytes)
        .ok_or("fixed absolute owner prospective persistent bytes overflow")?;
    let peak_bytes = prospective.peak_bytes.max(persistent_bytes);
    Ok(AggregateFixedAbsoluteDomainResidualBuildProspective {
        work,
        allocations,
        persistent_bytes,
        peak_bytes,
    })
}

fn fixed_residual_build_limit_refusal(
    prospective: AggregateFixedAbsoluteDomainResidualBuildProspective,
    limits: AggregateFixedAbsoluteDomainResidualBuildLimits,
) -> Option<(AggregateFixedAbsoluteDomainResidualBuildResource, u64, u64)> {
    let checks = [
        (
            AggregateFixedAbsoluteDomainResidualBuildResource::Work,
            prospective.work,
            limits.max_work,
        ),
        (
            AggregateFixedAbsoluteDomainResidualBuildResource::Allocations,
            u64::try_from(prospective.allocations).ok()?,
            u64::try_from(limits.max_allocations).ok()?,
        ),
        (
            AggregateFixedAbsoluteDomainResidualBuildResource::PersistentBytes,
            u64::try_from(prospective.persistent_bytes).ok()?,
            u64::try_from(limits.max_persistent_bytes).ok()?,
        ),
        (
            AggregateFixedAbsoluteDomainResidualBuildResource::PeakBytes,
            u64::try_from(prospective.peak_bytes).ok()?,
            u64::try_from(limits.max_peak_bytes).ok()?,
        ),
    ];
    checks
        .into_iter()
        .find(|(_, required, limit)| required > limit)
}

fn compose_fixed_residual_build_failure_actual(
    guard: FixedAbsoluteDomainBuildAccounting,
    residual: &crate::AggregateCompileAttemptReceipt,
) -> Option<AggregateFixedAbsoluteDomainResidualBuildActual> {
    let residual_work = u64::try_from(residual.actual.work).ok()?;
    let work = guard.actual.build_work.checked_add(residual_work)?;
    let allocations = guard
        .actual
        .allocations
        .checked_add(residual.actual_allocations?)?;
    let persistent_bytes = guard
        .actual
        .persistent_bytes
        .checked_add(residual.live_construction_bytes)?;
    let peak_bytes = guard
        .actual
        .persistent_bytes
        .checked_add(residual.actual.construction_peak_bytes)?
        .max(guard.actual.peak_bytes);
    Some(AggregateFixedAbsoluteDomainResidualBuildActual {
        work,
        allocations,
        persistent_bytes,
        peak_bytes,
        published: false,
    })
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
    /// Fixed absolute-domain guard and optional eager residual certificate.
    FixedAbsoluteDomain(AggregateFixedAbsoluteDomainBuildSummary),
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
    /// Maximum canonical-HIR work for closed fixed absolute-domain proofs.
    /// This quota is independent of every incumbent selector.
    pub max_fixed_absolute_planner_work: usize,
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
    /// Complete fixed absolute-domain guard construction limits.
    pub fixed_absolute: FixedAbsoluteDomainBuildLimits,
    /// U1-only composite construction caps for the scalar guard plus eager
    /// continuation residual.
    pub fixed_absolute_residual: AggregateFixedAbsoluteDomainResidualBuildLimits,
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
            max_fixed_absolute_planner_work: 4_096,
            max_finite_planner_work: 8_000_000,
            exact_literal: LiteralAggregateBuildLimits::default(),
            unicode_scalar: UnicodeScalarAggregateBuildLimits::default(),
            fixed_class_sandwich: FixedClassSandwichBuildLimits::default(),
            grapheme_scalar_dfa: GraphemeScalarDfaBuildLimits::default(),
            bounded_class_sequence: BoundedClassSequenceBuildLimits::default(),
            bounded_separated_fields: BoundedSeparatedFieldsBuildLimits::default(),
            prefix_class_alternation: PrefixClassAlternationBuildLimits::default(),
            bounded_context: BoundedContextBuildLimits::default(),
            fixed_absolute: FixedAbsoluteDomainBuildLimits::default(),
            fixed_absolute_residual: AggregateFixedAbsoluteDomainResidualBuildLimits::default(),
            finite_literal: OrderedLiteralAggregateBuildLimits::default(),
            continuation: AggregateCompileLimits::default(),
        }
    }
}

/// Composite construction ceilings for the scalar fixed-domain route. These
/// do not alter the guard's independent kernel limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualBuildLimits {
    pub max_work: u64,
    pub max_allocations: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for AggregateFixedAbsoluteDomainResidualBuildLimits {
    fn default() -> Self {
        let guard = FixedAbsoluteDomainBuildLimits::default();
        let continuation = AggregateCompileLimits::default();
        let continuation_work =
            u64::try_from(continuation.max_work).expect("default continuation work fits u64");
        let max_work = guard
            .max_build_work
            .checked_add(continuation_work)
            .expect("default fixed residual construction work fits u64");
        let max_persistent_bytes = guard
            .max_persistent_bytes
            .checked_add(continuation.max_program_bytes)
            .expect("default fixed residual construction bytes fit usize");
        let max_peak_bytes = guard.max_peak_bytes.max(max_persistent_bytes);
        Self {
            max_work,
            max_allocations: 4_096,
            max_persistent_bytes,
            max_peak_bytes,
        }
    }
}

/// U1-only composite ceilings for the fixed-scalar guard plus its eager
/// continuation. Other aggregate plan families do not consult these limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualLimits {
    pub max_work: usize,
    pub max_allocations: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Default for AggregateFixedAbsoluteDomainResidualLimits {
    fn default() -> Self {
        let guard_run = FixedAbsoluteDomainReduceLimits::default();
        let continuation_run = AggregateOperationLimits::default();
        let guard_build = FixedAbsoluteDomainBuildLimits::default();
        let continuation_build = AggregateCompileLimits::default();
        let max_work = guard_run
            .max_total_work
            .checked_add(continuation_run.max_work)
            .expect("default fixed residual work caps fit usize");
        let max_persistent_bytes = guard_build
            .max_persistent_bytes
            .checked_add(continuation_build.max_program_bytes)
            .expect("default fixed residual persistent caps fit usize");
        let max_peak_bytes = max_persistent_bytes
            .checked_add(continuation_run.max_peak_bytes)
            .expect("default fixed residual peak caps fit usize");
        Self {
            max_work,
            max_allocations: 16,
            max_persistent_bytes,
            max_peak_bytes,
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
    /// Fixed absolute-domain guard limits. Scalar residuals additionally use
    /// the unchanged continuation limits below.
    pub fixed_absolute: FixedAbsoluteDomainReduceLimits,
    /// Composite-only caps for a scalar fixed-domain residual.
    pub fixed_absolute_residual: AggregateFixedAbsoluteDomainResidualLimits,
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
    /// Continuation storage strategy, present for continuation plans and the
    /// scalar fixed-domain composite's eager residual; absent for direct-only
    /// plans.
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
    /// Fixed absolute-domain canonical-HIR inspection work.
    pub fixed_absolute_planner_work: u32,
    /// Checked finite-language root inspection and, for the dense route,
    /// analysis/expansion work; zero when finite inspection is skipped.
    /// This remains nonzero when `Auto` proves a finite language but a typed
    /// caller limit rejects the optional dense/sparse automaton preflight and
    /// continuation is selected. A rejected automaton publishes neither build
    /// accounting nor plan identity; its caller-bounded preflight is not
    /// double-counted as work of the selected continuation artifact.
    pub finite_planner_work: u64,
    /// Transparent capture-node visits charged by the selected plan builder.
    /// A scalar fixed-domain composite includes both guard inspection and its
    /// eagerly compiled residual's capture-erasure work.
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
    sealed_required_internal_anchor_identity: Option<AggregateRequiredInternalAnchorSeal>,
    sealed_url_aggregate_identity: Option<AggregateUrlOrFixedSeal>,
    /// Selected plan's retained capacity/persistent bytes.
    pub retained_capacity_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AggregateRequiredInternalAnchorSeal {
    program: AggregatePlanId,
    compile: AggregateCompileAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AggregateUrlAggregateSeal {
    program: AggregatePlanId,
    compile: AggregateCompileAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the fixed owner seal remains allocation-free and pointer-exact; boxing would add an unbudgeted allocation"
)]
enum AggregateUrlOrFixedSeal {
    Url(AggregateUrlAggregateSeal),
    Fixed(AggregateExecutionIdentity),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AggregateFixedAbsoluteDomainSeal {
    schema_version: u32,
    syntax_key: Arc<CacheKey>,
    admission: AdmissionStatus,
    syntax: ParseSummary,
    operation: AggregateOperation,
    selection: AggregatePlanSelection,
    plan: AggregatePlanKind,
    continuation_strategy: Option<AggregateStrategy>,
    capture_semantics: AggregateCaptureSemantics,
    planner_work: usize,
    unicode_scalar_planner_work: usize,
    fixed_class_sandwich_planner_work: usize,
    bounded_affix_planner_work: usize,
    grapheme_scalar_dfa_planner_work: usize,
    bounded_class_sequence_planner_work: usize,
    bounded_separated_fields_planner_work: usize,
    prefix_class_alternation_planner_work: usize,
    bounded_context_planner_work: usize,
    fixed_absolute_planner_work: usize,
    max_fixed_absolute_planner_work: usize,
    finite_planner_work: u64,
    capture_erasure_work: usize,
    captures_erased: usize,
    identity: AggregateFixedAbsoluteDomainIdentity,
    build: AggregateFixedAbsoluteDomainBuildAccounting,
    admission_policy: AdmissionPolicy,
    syntax_safety: SafetyEnvelope,
    guard_build_limits: FixedAbsoluteDomainBuildLimits,
    residual_build_limits: AggregateFixedAbsoluteDomainResidualBuildLimits,
    continuation_build_limits: AggregateCompileLimits,
    residual_allocation_census: Option<usize>,
    retained_capacity_bytes: usize,
}

impl AggregateFixedAbsoluteDomainSeal {
    fn matches_build_inputs(&self, limits: &AggregateBuildLimits) -> bool {
        let scalar = self.identity.kernel.descriptor.kind()
            == FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope;
        self.admission_policy == limits.admission
            && self.syntax_safety == limits.syntax_safety
            && self.max_fixed_absolute_planner_work == limits.max_fixed_absolute_planner_work
            && self.guard_build_limits == limits.fixed_absolute
            && (!scalar
                || self.residual_build_limits == limits.fixed_absolute_residual
                    && self.continuation_build_limits == limits.continuation)
    }

    fn matches_public_report(&self, report: &AggregateBuildReport) -> bool {
        self.schema_version == report.schema_version
            && self.syntax_key == report.syntax_key
            && self.admission == report.admission
            && self.syntax == report.syntax
            && self.operation == report.operation
            && self.selection == report.selection
            && self.plan == report.plan
            && self.continuation_strategy == report.continuation_strategy
            && self.capture_semantics == report.capture_semantics
            && self.planner_work == report.planner_work
            && self.unicode_scalar_planner_work == report.unicode_scalar_planner_work
            && self.fixed_class_sandwich_planner_work == report.fixed_class_sandwich_planner_work
            && self.bounded_affix_planner_work == report.bounded_affix_planner_work
            && self.grapheme_scalar_dfa_planner_work == report.grapheme_scalar_dfa_planner_work
            && self.bounded_class_sequence_planner_work
                == report.bounded_class_sequence_planner_work
            && self.bounded_separated_fields_planner_work
                == report.bounded_separated_fields_planner_work
            && self.prefix_class_alternation_planner_work
                == report.prefix_class_alternation_planner_work
            && self.bounded_context_planner_work == report.bounded_context_planner_work
            && u32::try_from(self.fixed_absolute_planner_work).ok()
                == Some(report.fixed_absolute_planner_work)
            && self.finite_planner_work == report.finite_planner_work
            && self.capture_erasure_work == report.capture_erasure_work
            && self.captures_erased == report.captures_erased
            && matches!(
                report.plan_identity,
                AggregatePlanIdentity::FixedAbsoluteDomain(identity)
                    if identity == self.identity
            )
            && matches!(
                report.build,
                AggregateBuildAccounting::FixedAbsoluteDomain(summary)
                    if summary == self.build.summary()
            )
            && self.retained_capacity_bytes == report.retained_capacity_bytes
    }
}

impl AggregateBuildReport {
    fn fixed_absolute_domain_owner(&self) -> Option<&AggregateExecutionIdentity> {
        match self.sealed_url_aggregate_identity.as_ref() {
            Some(AggregateUrlOrFixedSeal::Fixed(owner)) => Some(owner),
            _ => None,
        }
    }

    /// Check that all public fixed-route discriminators and resource receipts
    /// are the exact owner-local values sealed with the immutable artifacts.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the closure proof intentionally keeps every route, owner and accounting invariant in one audit boundary"
    )]
    pub fn has_closed_fixed_absolute_domain_identity(&self) -> bool {
        match (
            self.plan,
            self.build,
            self.plan_identity,
            self.fixed_absolute_domain_owner(),
        ) {
            (
                AggregatePlanKind::FixedAbsoluteDomain,
                AggregateBuildAccounting::FixedAbsoluteDomain(summary),
                AggregatePlanIdentity::FixedAbsoluteDomain(identity),
                Some(owner),
            ) => {
                let sealed = owner.fixed_absolute_domain_seal();
                if summary != sealed.build.summary() {
                    return false;
                }
                let build = sealed.build;
                let scalar = identity.kernel.descriptor.kind()
                    == FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope;
                let operation_closed = matches!(
                    (
                        self.operation,
                        identity.kernel.operation,
                        identity.kernel.descriptor.kind(),
                    ),
                    (
                        AggregateOperation::Count,
                        fre_kernels::FixedAbsoluteDomainOperation::Count,
                        FixedAbsoluteDomainDescriptorKind::WholeByteRepeat
                            | FixedAbsoluteDomainDescriptorKind::WholeOrderedWords
                            | FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope,
                    ) | (
                        AggregateOperation::SpanSum,
                        fre_kernels::FixedAbsoluteDomainOperation::SpanSum,
                        FixedAbsoluteDomainDescriptorKind::EndMaskSequence
                            | FixedAbsoluteDomainDescriptorKind::EndOneByteMask
                            | FixedAbsoluteDomainDescriptorKind::EndGreedyClassLiteral
                            | FixedAbsoluteDomainDescriptorKind::StartOrderedPrefix,
                    )
                );
                let residual_closed = match (
                    scalar,
                    identity.residual,
                    identity.residual_strategy,
                    build.residual,
                    identity.kernel.residual,
                    self.continuation_strategy,
                ) {
                    (false, None, None, None, FixedAbsoluteDomainResidual::None, None) => true,
                    (
                        true,
                        Some(AggregateContinuationIdentity {
                            semantics: AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir,
                            ..
                        }),
                        Some(identity_strategy),
                        Some(_),
                        FixedAbsoluteDomainResidual::PrepublishedContinuation,
                        Some(report_strategy),
                    ) => identity_strategy == report_strategy,
                    _ => false,
                };
                let Some(owner_bytes) = fixed_absolute_owner_bytes().ok() else {
                    return false;
                };
                let Some(owner_work) = u64::try_from(owner_bytes).ok() else {
                    return false;
                };
                let expected_guard_with_owner =
                    include_fixed_absolute_owner_guard_prospective(build.kernel.prospective)
                        .ok()
                        .zip(include_fixed_absolute_owner_guard_actual(build.kernel.actual).ok());
                let guard_with_owner_closed =
                    expected_guard_with_owner.is_some_and(|(prospective, actual)| {
                        build.guard_with_owner
                            == FixedAbsoluteDomainBuildAccounting {
                                prospective,
                                actual,
                            }
                            && fixed_guard_build_actual_fits(actual, prospective)
                            && fixed_guard_build_limit_refusal(
                                prospective,
                                sealed.guard_build_limits,
                            )
                            .is_none()
                    });
                let artifact_persistent = build.residual.map_or_else(
                    || Some(build.kernel.actual.persistent_bytes),
                    |residual| {
                        build
                            .kernel
                            .actual
                            .persistent_bytes
                            .checked_add(residual.program_bytes)
                    },
                );
                let artifact_peak = build.residual.map_or_else(
                    || Some(build.kernel.actual.peak_bytes),
                    |residual| {
                        build
                            .kernel
                            .actual
                            .persistent_bytes
                            .checked_add(residual.construction_peak_bytes)
                            .map(|co_live| co_live.max(build.kernel.actual.peak_bytes))
                    },
                );
                let expected_persistent =
                    artifact_persistent.and_then(|bytes| bytes.checked_add(owner_bytes));
                let expected_peak = artifact_peak
                    .zip(expected_persistent)
                    .map(|(peak, persistent)| peak.max(persistent));
                let expected_prospective = if scalar {
                    sealed.residual_allocation_census.and_then(|allocations| {
                        compose_fixed_residual_build_prospective(
                            build.kernel.prospective,
                            sealed.continuation_build_limits,
                            allocations,
                        )
                        .and_then(include_fixed_absolute_owner_prospective)
                        .ok()
                    })
                } else {
                    include_fixed_absolute_owner_prospective(
                        AggregateFixedAbsoluteDomainResidualBuildProspective {
                            work: build.kernel.prospective.build_work,
                            allocations: build.kernel.prospective.allocations,
                            persistent_bytes: build.kernel.prospective.persistent_bytes,
                            peak_bytes: build.kernel.prospective.peak_bytes,
                        },
                    )
                    .ok()
                };
                let expected_actual_work = build
                    .residual
                    .and_then(|residual| {
                        u64::try_from(residual.work)
                            .ok()
                            .and_then(|work| build.kernel.actual.build_work.checked_add(work))
                    })
                    .or_else(|| (!scalar).then_some(build.kernel.actual.build_work))
                    .and_then(|work| work.checked_add(owner_work));
                let expected_actual_allocations = sealed
                    .residual_allocation_census
                    .map_or_else(
                        || Some(build.kernel.actual.allocations),
                        |allocations| build.kernel.actual.allocations.checked_add(allocations),
                    )
                    .and_then(|allocations| allocations.checked_add(1));
                let prospective_admitted = fixed_residual_build_limit_refusal(
                    build.prospective,
                    sealed.residual_build_limits,
                )
                .is_none();
                operation_closed
                    && residual_closed
                    && self.schema_version == AGGREGATE_EXPLAIN_SCHEMA_VERSION
                    && self.selection == AggregatePlanSelection::Auto
                    && self.capture_semantics == AggregateCaptureSemantics::ErasedForWholeMatchOnly
                    && self.finite_planner_work == 0
                    && usize::try_from(self.fixed_absolute_planner_work)
                        .is_ok_and(|work| work <= sealed.max_fixed_absolute_planner_work)
                    && matches!(
                        &self.syntax_key.profile,
                        CompatibilityProfile::RustBytes(profile) if {
                            let mut expected = RustProfile::rebar_1_12_4();
                            expected.options.unicode = profile.options.unicode;
                            profile == &expected
                        }
                    )
                    && sealed.matches_public_report(self)
                    && identity == sealed.identity
                    && build == sealed.build
                    && fixed_guard_build_actual_fits(build.kernel.actual, build.kernel.prospective)
                    && guard_with_owner_closed
                    && build.kernel.prospective.descriptor == identity.kernel.descriptor
                    && expected_prospective == Some(build.prospective)
                    && expected_actual_work == Some(build.actual.work)
                    && expected_actual_allocations == Some(build.actual.allocations)
                    && expected_persistent == Some(build.actual.persistent_bytes)
                    && expected_peak == Some(build.actual.peak_bytes)
                    && prospective_admitted
                    && build.actual.published
                    && build.actual.work <= build.prospective.work
                    && build.actual.allocations <= build.prospective.allocations
                    && build.actual.persistent_bytes <= build.prospective.persistent_bytes
                    && build.actual.peak_bytes <= build.prospective.peak_bytes
                    && self.retained_capacity_bytes == build.actual.persistent_bytes
            }
            (plan, build, identity, None) => {
                plan != AggregatePlanKind::FixedAbsoluteDomain
                    && !matches!(build, AggregateBuildAccounting::FixedAbsoluteDomain(_))
                    && !matches!(identity, AggregatePlanIdentity::FixedAbsoluteDomain(_))
            }
            _ => false,
        }
    }

    /// Authenticate one fixed absolute-domain facade identity against the
    /// construction-owned seal.
    #[must_use]
    pub fn authenticates_fixed_absolute_domain_identity(
        &self,
        identity: AggregateFixedAbsoluteDomainIdentity,
    ) -> bool {
        self.has_closed_fixed_absolute_domain_identity()
            && matches!(
                self.fixed_absolute_domain_owner(),
                Some(owner)
                    if owner.fixed_absolute_domain_seal().identity == identity
            )
    }

    /// Complete fixed-domain construction receipt retained once behind the
    /// authenticated construction owner.
    #[must_use]
    pub fn fixed_absolute_domain_build_accounting(
        &self,
    ) -> Option<&AggregateFixedAbsoluteDomainBuildAccounting> {
        let AggregateBuildAccounting::FixedAbsoluteDomain(summary) = self.build else {
            return None;
        };
        let sealed = self
            .fixed_absolute_domain_owner()?
            .fixed_absolute_domain_seal();
        (summary == sealed.build.summary()).then_some(&sealed.build)
    }

    /// Require the public URL-aggregate accounting and the private compiled
    /// artifact to be either coherently active or coherently absent.
    #[must_use]
    pub fn has_closed_url_aggregate_identity(&self) -> bool {
        let AggregateBuildAccounting::Continuation(compile) = self.build else {
            return !matches!(
                self.sealed_url_aggregate_identity,
                Some(AggregateUrlOrFixedSeal::Url(_))
            );
        };
        let absent = compile.url_aggregate_plans == 0
            && compile.url_aggregate_tlds == 0
            && compile.url_aggregate_tld_bytes == 0
            && compile.url_aggregate_build_work == 0
            && compile.url_aggregate_persistent_bytes == 0;
        match self.sealed_url_aggregate_identity.as_ref() {
            Some(AggregateUrlOrFixedSeal::Url(sealed)) => {
                compile.url_aggregate_plans == 1
                    && compile.url_aggregate_tlds > 0
                    && compile.url_aggregate_tld_bytes > 0
                    && compile.url_aggregate_build_work > 0
                    && compile.url_aggregate_persistent_bytes > 0
                    && sealed.compile == compile
                    && matches!(
                        self.plan_identity,
                        AggregatePlanIdentity::Continuation(identity)
                            if identity.program == sealed.program
                                && identity.semantics
                                    == AggregateContinuationSemantics::UnicodeOffByteBoundaries
                    )
                    && self.plan == AggregatePlanKind::ContinuationProgram
                    && self.retained_capacity_bytes == compile.program_bytes
            }
            Some(AggregateUrlOrFixedSeal::Fixed(_)) => false,
            None => absent,
        }
    }

    #[must_use]
    pub fn authenticates_url_aggregate_identity(&self) -> bool {
        self.has_closed_url_aggregate_identity()
            && matches!(
                self.sealed_url_aggregate_identity,
                Some(AggregateUrlOrFixedSeal::Url(_))
            )
    }

    /// Require the public required-anchor discriminators and private compiled
    /// artifact to be either coherently active or coherently absent.
    #[must_use]
    pub fn has_closed_required_internal_anchor_identity(&self) -> bool {
        let AggregateBuildAccounting::Continuation(compile) = self.build else {
            return self.sealed_required_internal_anchor_identity.is_none();
        };
        let absent = compile.required_internal_anchors == 0
            && compile.required_internal_anchor_bytes == 0
            && compile.required_internal_anchor_optional_stages == 0
            && compile.required_internal_anchor_build_work == 0
            && compile.required_internal_anchor_build_work_upper_bound == 0
            && compile.required_internal_anchor_persistent_bytes == 0;
        match self.sealed_required_internal_anchor_identity {
            Some(sealed) => {
                matches!(
                    self.plan_identity,
                    AggregatePlanIdentity::Continuation(identity)
                        if identity.semantics == AggregateContinuationSemantics::UnicodeOffByteBoundaries
                            && identity.program == sealed.program
                ) && self.plan == AggregatePlanKind::ContinuationProgram
                    && compile.required_internal_anchors == 1
                    && compile.required_internal_anchor_bytes > 0
                    && compile.required_internal_anchor_build_work > 0
                    && compile.required_internal_anchor_build_work
                        <= compile.required_internal_anchor_build_work_upper_bound
                    && compile.required_internal_anchor_persistent_bytes > 0
                    && compile == sealed.compile
                    && self.retained_capacity_bytes == compile.program_bytes
            }
            None => absent,
        }
    }

    #[must_use]
    pub fn authenticates_required_internal_anchor_identity(&self) -> bool {
        self.has_closed_required_internal_anchor_identity()
            && self.sealed_required_internal_anchor_identity.is_some()
    }

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

/// Allocation-free error identity for the U1 fixed-domain route. Only the
/// limits that authenticate its nested guard/continuation receipts are kept;
/// construction accounting lives once in the colocated owner seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainErrorIdentity {
    pub schema_version: u32,
    pub syntax_key: Arc<CacheKey>,
    pub operation: AggregateOperation,
    pub selection: AggregatePlanSelection,
    pub continuation_strategy: Option<AggregateStrategy>,
    pub capture_semantics: AggregateCaptureSemantics,
    pub admission: AdmissionPolicy,
    pub syntax_safety: SafetyEnvelope,
    pub max_fixed_absolute_planner_work: usize,
    pub fixed_absolute_planner_work: usize,
    pub plan_identity: AggregateFixedAbsoluteDomainIdentity,
    pub guard_build_limits: FixedAbsoluteDomainBuildLimits,
    pub residual_build_limits: AggregateFixedAbsoluteDomainResidualBuildLimits,
    pub continuation_build_limits: AggregateCompileLimits,
    pub residual_allocation_census: Option<usize>,
}

fn fixed_guard_build_actual_fits(
    actual: FixedAbsoluteDomainBuildActual,
    prospective: FixedAbsoluteDomainBuildProspective,
) -> bool {
    actual.items <= prospective.items
        && actual.payload_bytes <= prospective.payload_bytes
        && actual.identity_bytes <= prospective.identity_bytes
        && actual.retained_heap_bytes <= prospective.retained_heap_bytes
        && actual.copied_bytes <= prospective.copied_bytes
        && actual.allocations <= prospective.allocations
        && actual.initialized_bytes <= prospective.initialized_bytes
        && actual.build_work <= prospective.build_work
        && actual.scratch_bytes <= prospective.scratch_bytes
        && actual.persistent_bytes <= prospective.persistent_bytes
        && actual.peak_bytes <= prospective.peak_bytes
        && actual.published
}

/// One-pointer construction owner for a successfully published fixed-domain
/// artifact. Equality is exact owner provenance, not structural Arc contents.
#[derive(Clone, Debug)]
pub struct AggregateExecutionIdentity(Arc<AggregateExecutionIdentityInner>);

#[derive(Debug)]
struct AggregateExecutionIdentityInner {
    seal: AggregateFixedAbsoluteDomainSeal,
    identity: AggregateFixedAbsoluteDomainErrorIdentity,
}

impl PartialEq for AggregateExecutionIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for AggregateExecutionIdentity {}

impl AggregateExecutionIdentity {
    fn fixed_absolute_domain(
        seal: AggregateFixedAbsoluteDomainSeal,
        identity: AggregateFixedAbsoluteDomainErrorIdentity,
    ) -> Self {
        Self(Arc::new(AggregateExecutionIdentityInner { seal, identity }))
    }

    #[must_use]
    pub fn as_fixed_absolute_domain(&self) -> &AggregateFixedAbsoluteDomainErrorIdentity {
        &self.0.identity
    }

    fn fixed_absolute_domain_seal(&self) -> &AggregateFixedAbsoluteDomainSeal {
        &self.0.seal
    }
}

/// Opaque fixed-domain attempt identity. Construction provenance and its one
/// lossless terminal receipt cannot be separated or reassembled by callers.
#[derive(Clone, Debug)]
pub struct AggregateFixedAbsoluteDomainAttemptIdentity {
    owner: AggregateExecutionIdentity,
    receipt: AggregateFixedAbsoluteDomainAttemptReceipt,
}

impl PartialEq for AggregateFixedAbsoluteDomainAttemptIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.receipt == other.receipt
    }
}

impl Eq for AggregateFixedAbsoluteDomainAttemptIdentity {}

impl AggregateFixedAbsoluteDomainAttemptIdentity {
    fn new(
        owner: AggregateExecutionIdentity,
        receipt: AggregateFixedAbsoluteDomainAttemptReceipt,
    ) -> Self {
        Self { owner, receipt }
    }

    /// Exact construction-owned fixed-route identity for this attempt.
    #[must_use]
    pub fn owner_identity(&self) -> &AggregateFixedAbsoluteDomainErrorIdentity {
        self.owner.as_fixed_absolute_domain()
    }

    /// Construction accounting retained once by this attempt's exact owner.
    #[must_use]
    pub fn owner_build_accounting(&self) -> &AggregateFixedAbsoluteDomainBuildAccounting {
        &self.owner.fixed_absolute_domain_seal().build
    }

    /// The one complete terminal receipt paired with this construction owner.
    #[must_use]
    pub const fn receipt(&self) -> &AggregateFixedAbsoluteDomainAttemptReceipt {
        &self.receipt
    }
}

/// Exact attempted execution identity. Incumbent failures preserve their
/// pre-U1 boxed cache identity. Fixed failures retain one opaque owner/receipt
/// pair, with no duplicate P/A payload.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "fixed failures retain one allocation-free lossless owner/receipt identity; boxing would change that contract"
)]
pub enum AggregateExecutionAttemptIdentity {
    Incumbent(Box<AggregateCacheIdentity>),
    /// Continuation construction identity plus the one complete selected-route
    /// execution receipt.
    Continuation {
        cache: Box<AggregateCacheIdentity>,
        receipt: OperationAttemptReceipt,
    },
    FixedAbsoluteDomain(AggregateFixedAbsoluteDomainAttemptIdentity),
}

impl AggregateExecutionAttemptIdentity {
    fn incumbent(identity: Box<AggregateCacheIdentity>) -> Self {
        Self::Incumbent(identity)
    }

    fn fixed_absolute_domain(
        owner: AggregateExecutionIdentity,
        receipt: AggregateFixedAbsoluteDomainAttemptReceipt,
    ) -> Self {
        Self::FixedAbsoluteDomain(AggregateFixedAbsoluteDomainAttemptIdentity::new(
            owner, receipt,
        ))
    }

    fn continuation(cache: Box<AggregateCacheIdentity>, receipt: OperationAttemptReceipt) -> Self {
        Self::Continuation { cache, receipt }
    }

    #[must_use]
    pub fn as_cache_identity(&self) -> Option<&AggregateCacheIdentity> {
        match self {
            Self::Incumbent(identity) => Some(identity),
            Self::Continuation { cache, .. } => Some(cache),
            Self::FixedAbsoluteDomain(_) => None,
        }
    }

    /// The opaque fixed-domain owner/receipt pair for this attempt.
    #[must_use]
    pub const fn as_fixed_absolute_domain_attempt(
        &self,
    ) -> Option<&AggregateFixedAbsoluteDomainAttemptIdentity> {
        match self {
            Self::Incumbent(_) | Self::Continuation { .. } => None,
            Self::FixedAbsoluteDomain(attempt) => Some(attempt),
        }
    }

    #[must_use]
    pub fn as_fixed_absolute_domain(&self) -> Option<&AggregateFixedAbsoluteDomainErrorIdentity> {
        match self {
            Self::Incumbent(_) | Self::Continuation { .. } => None,
            Self::FixedAbsoluteDomain(attempt) => Some(attempt.owner_identity()),
        }
    }

    /// The one complete fixed-domain attempt receipt retained by this failure.
    #[must_use]
    pub const fn fixed_absolute_domain_receipt(
        &self,
    ) -> Option<&AggregateFixedAbsoluteDomainAttemptReceipt> {
        match self {
            Self::Incumbent(_) | Self::Continuation { .. } => None,
            Self::FixedAbsoluteDomain(attempt) => Some(attempt.receipt()),
        }
    }

    /// Complete selected-route continuation receipt retained by this attempt.
    #[must_use]
    pub const fn continuation_receipt(&self) -> Option<&OperationAttemptReceipt> {
        match self {
            Self::Continuation { receipt, .. } => Some(receipt),
            Self::Incumbent(_) | Self::FixedAbsoluteDomain(_) => None,
        }
    }

    fn closes_fixed_source_kind(&self, source: &AggregateExecutionSource) -> bool {
        match (self, source) {
            (Self::FixedAbsoluteDomain(attempt), AggregateExecutionSource::FixedAbsoluteDomain) => {
                attempt.receipt().guard_error().is_some()
            }
            (
                Self::FixedAbsoluteDomain(attempt),
                AggregateExecutionSource::FixedAbsoluteDomainResidual,
            ) => attempt
                .receipt()
                .residual_error()
                .is_some_and(|(continuation, composite)| {
                    composite.contains_actual_with(&continuation.receipt)
                }),
            (Self::Continuation { receipt, .. }, AggregateExecutionSource::Continuation(_)) => {
                receipt.prospective.is_some_and(|upper| {
                    upper.contains(receipt.actual)
                        && receipt.actual_allocations <= upper.allocations
                        && receipt.actual_allocations <= receipt.allocation_limit
                })
            }
            _ => false,
        }
    }
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
#[allow(
    clippy::large_enum_variant,
    reason = "typed build refusals retain complete lossless accounting without post-failure allocation"
)]
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
    /// Fixed absolute-domain canonical-HIR inspection crossed its independent
    /// work cap.
    FixedAbsoluteDomainPlannerWorkLimit {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        needed: usize,
        limit: usize,
        consumed: usize,
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
    /// Fixed absolute-domain guard construction failed after route selection.
    FixedAbsoluteDomainBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        /// Classifier, structural inspection, and scalar census work already
        /// consumed before the selected guard construction failed.
        planner_work: usize,
        source: FixedAbsoluteDomainBuildError,
    },
    /// Scalar guard construction failed after the outer composite P was
    /// published but before either artifact became publishable.
    FixedAbsoluteDomainResidualGuardBuild {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        /// Classifier, structural inspection, and allocation-census work
        /// already consumed before guard construction failed.
        planner_work: usize,
        source: FixedAbsoluteDomainBuildError,
        composite: AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt,
    },
    /// The complete scalar guard-plus-residual envelope exceeded its U1-only
    /// cap before either artifact was constructed.
    FixedAbsoluteDomainResidualPreflight {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        /// Classifier, structural inspection, and allocation-census work
        /// already consumed before this outer preflight refusal.
        planner_work: usize,
        resource: AggregateFixedAbsoluteDomainResidualBuildResource,
        needed: u64,
        limit: u64,
        receipt: AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt,
    },
    /// The scalar guard was selected, but its required eager continuation
    /// residual failed before composite publication.
    FixedAbsoluteDomainResidualCompile {
        operation: AggregateOperation,
        selection: AggregatePlanSelection,
        /// Classifier, structural inspection, and allocation-census work
        /// already consumed before eager residual compilation began.
        planner_work: usize,
        strategy: AggregateStrategy,
        /// Completed, still-owner-local guard construction receipt.
        guard: FixedAbsoluteDomainBuildAccounting,
        /// Partial residual compiler ledger. Its receipt is unpublished and
        /// binds the exact continuation limits/profile used by this attempt.
        source: AggregateCompileAttemptError,
        /// Cumulative outer P/A; `published` remains false on this terminal
        /// construction failure.
        composite: AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt,
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
            Self::FixedAbsoluteDomainPlannerWorkLimit {
                operation,
                selection,
                needed,
                limit,
                consumed,
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} fixed absolute-domain inspection needs {needed} structural work units, limit is {limit}, consumed {consumed}"
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
            Self::FixedAbsoluteDomainBuild {
                operation,
                selection,
                source,
                ..
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} fixed absolute-domain construction failed: {source}"
            ),
            Self::FixedAbsoluteDomainResidualGuardBuild {
                operation,
                selection,
                source,
                ..
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} scalar fixed guard construction failed: {source}"
            ),
            Self::FixedAbsoluteDomainResidualPreflight {
                operation,
                selection,
                resource,
                needed,
                limit,
                ..
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?} fixed residual {resource:?} needs {needed}, limit is {limit}"
            ),
            Self::FixedAbsoluteDomainResidualCompile {
                operation,
                selection,
                strategy,
                source,
                ..
            } => write!(
                f,
                "aggregate {operation:?}/{selection:?}/{strategy:?} fixed absolute-domain residual compilation failed: {source}"
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
            Self::FixedAbsoluteDomainBuild { source, .. }
            | Self::FixedAbsoluteDomainResidualGuardBuild { source, .. } => Some(source),
            Self::FixedAbsoluteDomainResidualCompile { source, .. } => Some(source),
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
            | Self::FixedAbsoluteDomainPlannerWorkLimit { .. }
            | Self::FinitePlannerWorkLimit { .. }
            | Self::FinitePlannerAllocationFailed { .. }
            | Self::ExactLiteralIneligible { .. }
            | Self::FixedAbsoluteDomainResidualPreflight { .. }
            | Self::InternalInvariant { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AggregateFixedAbsoluteDomainAttemptKind {
    Guard,
    Residual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the terminal is a complete allocation-free P/A receipt and must not lose or separately allocate either branch"
)]
enum AggregateFixedAbsoluteDomainAttemptTerminal {
    Guard(FixedAbsoluteDomainReduceError),
    Residual {
        continuation: OperationAttemptError,
        composite: AggregateFixedAbsoluteDomainResidualReceipt,
    },
}

/// Lossless, allocation-free fixed-domain terminal receipt. The three limit
/// envelopes and typed terminal retain every invocation input and
/// prospective/actual counter without probabilistic hashing or a post-terminal
/// diagnostic traversal. Its enclosing attempt identity separately retains the
/// exact construction owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainAttemptReceipt {
    fixed_absolute: FixedAbsoluteDomainReduceLimits,
    fixed_absolute_residual: AggregateFixedAbsoluteDomainResidualLimits,
    continuation: AggregateOperationLimits,
    terminal: AggregateFixedAbsoluteDomainAttemptTerminal,
}

impl AggregateFixedAbsoluteDomainAttemptReceipt {
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the Copy limit envelope is captured by value as an immutable terminal snapshot"
    )]
    fn new(
        limits: AggregateRunLimits,
        failure: AggregateFixedAbsoluteDomainAttemptFailure,
    ) -> Self {
        let terminal = match failure {
            AggregateFixedAbsoluteDomainAttemptFailure::Guard(source) => {
                AggregateFixedAbsoluteDomainAttemptTerminal::Guard(source)
            }
            AggregateFixedAbsoluteDomainAttemptFailure::Residual {
                continuation,
                composite,
            } => AggregateFixedAbsoluteDomainAttemptTerminal::Residual {
                continuation,
                composite,
            },
        };
        Self {
            fixed_absolute: limits.fixed_absolute,
            fixed_absolute_residual: limits.fixed_absolute_residual,
            continuation: limits.continuation,
            terminal,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> AggregateFixedAbsoluteDomainAttemptKind {
        match self.terminal {
            AggregateFixedAbsoluteDomainAttemptTerminal::Guard(_) => {
                AggregateFixedAbsoluteDomainAttemptKind::Guard
            }
            AggregateFixedAbsoluteDomainAttemptTerminal::Residual { .. } => {
                AggregateFixedAbsoluteDomainAttemptKind::Residual
            }
        }
    }

    #[must_use]
    pub const fn fixed_absolute_limits(&self) -> FixedAbsoluteDomainReduceLimits {
        self.fixed_absolute
    }

    #[must_use]
    pub const fn fixed_absolute_residual_limits(
        &self,
    ) -> AggregateFixedAbsoluteDomainResidualLimits {
        self.fixed_absolute_residual
    }

    #[must_use]
    pub const fn continuation_limits(&self) -> AggregateOperationLimits {
        self.continuation
    }

    #[must_use]
    pub const fn guard_error(&self) -> Option<&FixedAbsoluteDomainReduceError> {
        match &self.terminal {
            AggregateFixedAbsoluteDomainAttemptTerminal::Guard(source) => Some(source),
            AggregateFixedAbsoluteDomainAttemptTerminal::Residual { .. } => None,
        }
    }

    #[must_use]
    pub const fn residual_error(
        &self,
    ) -> Option<(
        &OperationAttemptError,
        &AggregateFixedAbsoluteDomainResidualReceipt,
    )> {
        match &self.terminal {
            AggregateFixedAbsoluteDomainAttemptTerminal::Guard(_) => None,
            AggregateFixedAbsoluteDomainAttemptTerminal::Residual {
                continuation,
                composite,
            } => Some((continuation, composite)),
        }
    }

    fn terminal_error(&self) -> &(dyn std::error::Error + 'static) {
        match &self.terminal {
            AggregateFixedAbsoluteDomainAttemptTerminal::Guard(source) => source,
            AggregateFixedAbsoluteDomainAttemptTerminal::Residual { continuation, .. } => {
                continuation
            }
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
    /// Unit tag for a fixed absolute-domain guard refusal. The enclosing
    /// execution identity owns its one complete receipt.
    FixedAbsoluteDomain,
    /// Unit tag for a scalar residual refusal. The enclosing execution
    /// identity owns its construction provenance and complete receipt.
    FixedAbsoluteDomainResidual,
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
            Self::FixedAbsoluteDomain => f.write_str("fixed absolute-domain guard attempt failed"),
            Self::FixedAbsoluteDomainResidual => {
                f.write_str("fixed absolute-domain residual attempt failed")
            }
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
            Self::FixedAbsoluteDomain
            | Self::FixedAbsoluteDomainResidual
            | Self::InternalInvariant(_) => None,
            Self::FiniteLiteral(source) => Some(source),
            Self::SparseFiniteLiteral(source) => Some(source),
            Self::Continuation(source) => Some(source),
        }
    }
}

/// Whole-operation failure. No alternate plan or strategy is attempted after
/// this error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateExecutionError {
    /// Complete route-relevant attempted identity. Incumbents retain the full
    /// cache key; U1 retains one construction owner and one lossless receipt.
    pub identity: AggregateExecutionAttemptIdentity,
    /// Typed bounded selected-plan failure.
    pub source: AggregateExecutionSource,
}

impl AggregateExecutionError {
    /// Complete selected-route continuation receipt retained on a
    /// continuation terminal outcome.
    #[must_use]
    pub const fn continuation_receipt(&self) -> Option<&OperationAttemptReceipt> {
        self.identity.continuation_receipt()
    }

    /// The one complete receipt for a fixed-domain terminal attempt.
    #[must_use]
    pub const fn fixed_absolute_domain_receipt(
        &self,
    ) -> Option<&AggregateFixedAbsoluteDomainAttemptReceipt> {
        self.identity.fixed_absolute_domain_receipt()
    }

    /// Check that a fixed attempt identity and its compact source tag agree on
    /// the terminal kind. The identity itself is the sole receipt authority.
    #[must_use]
    pub fn has_closed_fixed_attempt(&self) -> bool {
        matches!(
            self.source,
            AggregateExecutionSource::FixedAbsoluteDomain
                | AggregateExecutionSource::FixedAbsoluteDomainResidual
        ) && self.identity.closes_fixed_source_kind(&self.source)
    }

    /// Check that a continuation source error retains a published route whose
    /// cumulative actual counters fit its prospective.
    #[must_use]
    pub fn has_closed_continuation_attempt(&self) -> bool {
        matches!(self.source, AggregateExecutionSource::Continuation(_))
            && self.identity.closes_fixed_source_kind(&self.source)
    }
}

impl fmt::Display for AggregateExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.identity {
            AggregateExecutionAttemptIdentity::Incumbent(identity) => write!(
                f,
                "aggregate {:?}/{:?}/{:?} execution failed: {}",
                identity.operation, identity.plan, identity.plan_identity, self.source
            ),
            AggregateExecutionAttemptIdentity::Continuation { cache, .. } => write!(
                f,
                "aggregate {:?}/{:?}/{:?} execution failed: {}",
                cache.operation, cache.plan, cache.plan_identity, self.source
            ),
            AggregateExecutionAttemptIdentity::FixedAbsoluteDomain(attempt) => {
                let identity = attempt.owner_identity();
                write!(
                    f,
                    "aggregate {:?}/{:?}/{:?} execution failed: {}",
                    identity.operation,
                    AggregatePlanKind::FixedAbsoluteDomain,
                    AggregatePlanIdentity::FixedAbsoluteDomain(identity.plan_identity),
                    attempt.receipt().terminal_error()
                )
            }
        }
    }
}

impl std::error::Error for AggregateExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.identity {
            AggregateExecutionAttemptIdentity::Incumbent(_)
            | AggregateExecutionAttemptIdentity::Continuation { .. } => Some(&self.source),
            AggregateExecutionAttemptIdentity::FixedAbsoluteDomain(attempt) => {
                Some(attempt.receipt().terminal_error())
            }
        }
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
    /// Fixed absolute-domain guard proof and, when the scalar envelope admits
    /// its residual, the nested continuation certificate/accounting.
    FixedAbsoluteDomain(AggregateFixedAbsoluteDomainExecutionDetails),
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
        receipt: OperationAttemptReceipt,
    },
}

/// Branch-explicit execution evidence for the fixed absolute-domain route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateFixedAbsoluteDomainExecutionDetails {
    /// The guard completed the operation without invoking a residual.
    Direct {
        guard: FixedAbsoluteDomainReduceAccounting,
    },
    /// The scalar envelope selected its prepublished continuation before any
    /// source access; both branch and residual receipts are retained.
    Residual {
        composite: AggregateFixedAbsoluteDomainResidualExecutionSummary,
    },
}

/// Nonduplicated public projection of a successful scalar residual. The
/// guard and continuation identities/prospectives are derivable from the
/// authenticated build owner and invocation; exact continuation counters and
/// the checked outer envelope are retained once here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualExecutionSummary {
    pub prospective: AggregateFixedAbsoluteDomainResidualProspective,
    pub actual: AggregateFixedAbsoluteDomainResidualActual,
    pub continuation_actual: AggregateExecutionAccounting,
    pub continuation_actual_allocations: usize,
}

impl AggregateFixedAbsoluteDomainResidualExecutionSummary {
    #[must_use]
    pub const fn contains_actual(&self) -> bool {
        self.actual.total_work <= self.prospective.total_work
            && self.actual.allocations <= self.prospective.allocations
            && self.actual.persistent_bytes <= self.prospective.persistent_bytes
            && self.actual.peak_bytes <= self.prospective.peak_bytes
            && self.continuation_actual_allocations <= self.prospective.allocations
            && self.continuation_actual.work <= self.prospective.total_work
            && self.continuation_actual.peak_bytes <= self.prospective.peak_bytes
    }
}

/// Complete pre-source envelope for the scalar fixed-domain guard and its
/// prepublished continuation, including co-live retained state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualProspective {
    pub total_work: usize,
    pub allocations: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact cumulative scalar-composite counters through a terminal outcome.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualActual {
    pub total_work: usize,
    pub allocations: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Guard evidence plus the checked cumulative envelope. The enclosing success
/// or failure owns the one continuation attempt receipt used to validate it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateFixedAbsoluteDomainResidualReceipt {
    pub guard: FixedAbsoluteDomainReduceAccounting,
    pub prospective: AggregateFixedAbsoluteDomainResidualProspective,
    pub actual: AggregateFixedAbsoluteDomainResidualActual,
}

impl AggregateFixedAbsoluteDomainResidualReceipt {
    /// Check both nested receipts, their exact composition, and cumulative A≤P
    /// against the enclosing attempt's sole continuation receipt.
    #[must_use]
    pub fn contains_actual_with(
        &self,
        continuation: &crate::AggregateOperationAttemptReceipt,
    ) -> bool {
        let Some(continuation_upper) = continuation.prospective else {
            return false;
        };
        if !self.guard.actual.fits(self.guard.prospective)
            || !continuation_upper.contains(continuation.actual)
            || continuation.actual_allocations > continuation_upper.allocations
            || continuation.actual_allocations > continuation.allocation_limit
        {
            return false;
        }
        let prospective = compose_fixed_residual_prospective(
            self.guard.prospective,
            continuation_upper,
            self.prospective.persistent_bytes,
        );
        let actual = compose_fixed_residual_actual(
            self.guard.actual,
            continuation.actual,
            continuation.actual_allocations,
            self.actual.persistent_bytes,
        );
        prospective.is_ok_and(|prospective| prospective == self.prospective)
            && actual.is_ok_and(|actual| actual == self.actual)
            && self.actual.total_work <= self.prospective.total_work
            && self.actual.allocations <= self.prospective.allocations
            && self.actual.persistent_bytes <= self.prospective.persistent_bytes
            && self.actual.peak_bytes <= self.prospective.peak_bytes
    }
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the Copy continuation prospective is folded into one exact composite snapshot"
)]
fn compose_fixed_residual_prospective(
    guard: FixedAbsoluteDomainProspective,
    continuation: OperationProspective,
    persistent_bytes: usize,
) -> Result<AggregateFixedAbsoluteDomainResidualProspective, AggregateEngineError> {
    let total_work = guard
        .total_work
        .checked_add(continuation.work_bound)
        .ok_or(AggregateEngineError::ArithmeticOverflow {
            resource: AggregateResource::ExecutionWork,
        })?;
    let allocations = guard
        .allocations
        .checked_add(continuation.allocations)
        .ok_or(AggregateEngineError::ArithmeticOverflow {
            resource: AggregateResource::Allocations,
        })?;
    let peak_bytes = persistent_bytes
        .checked_add(continuation.peak_bytes)
        .ok_or(AggregateEngineError::ArithmeticOverflow {
            resource: AggregateResource::PeakBytes,
        })?;
    Ok(AggregateFixedAbsoluteDomainResidualProspective {
        total_work,
        allocations,
        persistent_bytes,
        peak_bytes,
    })
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the Copy continuation accounting is folded into one exact composite snapshot"
)]
fn compose_fixed_residual_actual(
    guard: FixedAbsoluteDomainActual,
    continuation: AggregateExecutionAccounting,
    continuation_allocations: usize,
    persistent_bytes: usize,
) -> Result<AggregateFixedAbsoluteDomainResidualActual, AggregateEngineError> {
    let total_work = guard.total_work.checked_add(continuation.work).ok_or(
        AggregateEngineError::ArithmeticOverflow {
            resource: AggregateResource::ExecutionWork,
        },
    )?;
    let allocations = guard
        .allocations
        .checked_add(continuation_allocations)
        .ok_or(AggregateEngineError::ArithmeticOverflow {
            resource: AggregateResource::Allocations,
        })?;
    let peak_bytes = persistent_bytes
        .checked_add(continuation.peak_bytes)
        .ok_or(AggregateEngineError::ArithmeticOverflow {
            resource: AggregateResource::PeakBytes,
        })?;
    Ok(AggregateFixedAbsoluteDomainResidualActual {
        total_work,
        allocations,
        persistent_bytes,
        peak_bytes,
    })
}

fn enforce_fixed_residual_prospective(
    prospective: AggregateFixedAbsoluteDomainResidualProspective,
    limits: &AggregateRunLimits,
) -> Result<(), AggregateEngineError> {
    for (resource, required, limit) in [
        (
            AggregateResource::ExecutionWork,
            prospective.total_work,
            limits.fixed_absolute_residual.max_work,
        ),
        (
            AggregateResource::Allocations,
            prospective.allocations,
            limits.fixed_absolute_residual.max_allocations,
        ),
        (
            AggregateResource::ProgramBytes,
            prospective.persistent_bytes,
            limits.fixed_absolute_residual.max_persistent_bytes,
        ),
        (
            AggregateResource::PeakBytes,
            prospective.peak_bytes,
            limits.fixed_absolute_residual.max_peak_bytes,
        ),
    ] {
        if required > limit {
            return Err(AggregateEngineError::ResourceLimit {
                resource,
                required,
                limit,
            });
        }
    }
    Ok(())
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the Copy guard accounting is consumed into the lossless terminal receipt"
)]
fn fixed_residual_composite(
    guard: FixedAbsoluteDomainReduceAccounting,
    continuation: &crate::AggregateOperationAttemptReceipt,
    prospective: AggregateFixedAbsoluteDomainResidualProspective,
    persistent_bytes: usize,
) -> Result<AggregateFixedAbsoluteDomainResidualReceipt, AggregateEngineError> {
    let actual = compose_fixed_residual_actual(
        guard.actual,
        continuation.actual,
        continuation.actual_allocations,
        persistent_bytes,
    )?;
    Ok(AggregateFixedAbsoluteDomainResidualReceipt {
        guard,
        prospective,
        actual,
    })
}

/// Exact execution facts and the complete cache identity used for the call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateExecutionReport {
    pub identity: AggregateCacheIdentity,
    pub details: AggregateExecutionDetails,
}

impl AggregateExecutionReport {
    /// Clone the complete public cache certificate without allocation.
    #[must_use]
    pub fn cache_identity(&self) -> AggregateCacheIdentity {
        self.identity.clone()
    }
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

fn fixed_absolute_build_limit_allows_continuation(source: &FixedAbsoluteDomainBuildError) -> bool {
    matches!(
        source.kind,
        FixedAbsoluteDomainBuildErrorKind::ResourceLimit { .. }
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

#[allow(
    clippy::result_large_err,
    reason = "builder errors preserve complete typed P/A evidence without boxing or a post-failure allocation"
)]
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
        let mut expected_fixed_absolute_profile = RustProfile::rebar_1_12_4();
        expected_fixed_absolute_profile.options.unicode = unicode;
        let fixed_absolute_profile = self.profile == expected_fixed_absolute_profile;
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
                fixed_absolute_planner_work: 0,
                finite_planner_work: 0,
                capture_erasure_work: captures,
                captures_erased: captures,
                build: AggregateBuildAccounting::ExactLiteral(build),
                plan_identity,
                sealed_bounded_separated_fields_identity: None,
                sealed_required_internal_anchor_identity: None,
                sealed_url_aggregate_identity: None,
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
                    fixed_absolute_planner_work: 0,
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
                    sealed_required_internal_anchor_identity: None,
                    sealed_url_aggregate_identity: None,
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
                    fixed_absolute_planner_work: 0,
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
                    sealed_required_internal_anchor_identity: None,
                    sealed_url_aggregate_identity: None,
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
                fixed_absolute_planner_work: 0,
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
                sealed_required_internal_anchor_identity: None,
                sealed_url_aggregate_identity: None,
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
                    fixed_absolute_planner_work: 0,
                    finite_planner_work: 0,
                    capture_erasure_work: captures,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::BoundedClassSequence(build),
                    plan_identity: AggregatePlanIdentity::BoundedClassSequence(
                        engine.count_identity(),
                    ),
                    sealed_bounded_separated_fields_identity: None,
                    sealed_required_internal_anchor_identity: None,
                    sealed_url_aggregate_identity: None,
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
                    fixed_absolute_planner_work: 0,
                    finite_planner_work: 0,
                    capture_erasure_work: captures,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::BoundedSeparatedFields(build),
                    plan_identity: AggregatePlanIdentity::BoundedSeparatedFields(plan_identity),
                    sealed_bounded_separated_fields_identity: Some(plan_identity),
                    sealed_required_internal_anchor_identity: None,
                    sealed_url_aggregate_identity: None,
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
                    fixed_absolute_planner_work: 0,
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
                    sealed_required_internal_anchor_identity: None,
                    sealed_url_aggregate_identity: None,
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
                        fixed_absolute_planner_work: 0,
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
                        sealed_required_internal_anchor_identity: None,
                        sealed_url_aggregate_identity: None,
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
                    fixed_absolute_planner_work: 0,
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
                    sealed_required_internal_anchor_identity: None,
                    sealed_url_aggregate_identity: None,
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
        let fixed_absolute_candidate = if fixed_absolute_profile
            && selection == AggregatePlanSelection::Auto
            && matches!(
                operation,
                AggregateOperation::Count | AggregateOperation::SpanSum
            ) {
            Some(fixed_absolute::classify_candidate_with_limit(
                &rust.hir,
                unicode,
                operation,
                limits.max_fixed_absolute_planner_work,
            ))
        } else {
            None
        };
        let fixed_absolute_optional = fixed_absolute_candidate
            .is_some_and(|candidate| candidate.candidate == fixed_absolute::Candidate::Possible);
        let fixed_absolute_inspection = if let Some(candidate) = fixed_absolute_candidate {
            if candidate.exhausted || candidate.candidate == fixed_absolute::Candidate::Ineligible {
                Some(fixed_absolute::Inspection::Ineligible {
                    work: candidate.work,
                })
            } else {
                let remaining = limits
                    .max_fixed_absolute_planner_work
                    .checked_sub(candidate.work)
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed absolute classifier exceeded its planner cap",
                    })?;
                match fixed_absolute::inspect(&rust.hir, unicode, operation, remaining) {
                    Ok(fixed_absolute::Inspection::Eligible {
                        shape,
                        work,
                        hir_nodes,
                        captures,
                    }) => Some(fixed_absolute::Inspection::Eligible {
                        shape,
                        work: candidate.work.checked_add(work).ok_or(
                            AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "fixed absolute planner work overflow",
                            },
                        )?,
                        hir_nodes,
                        captures,
                    }),
                    Ok(fixed_absolute::Inspection::Ineligible { work }) => {
                        Some(fixed_absolute::Inspection::Ineligible {
                            work: candidate.work.checked_add(work).ok_or(
                                AggregateBuildError::InternalInvariant {
                                    operation,
                                    selection,
                                    detail: "fixed absolute planner work overflow",
                                },
                            )?,
                        })
                    }
                    Err(fixed_absolute::InspectionError::WorkLimit { consumed, .. })
                        if candidate.candidate == fixed_absolute::Candidate::Possible =>
                    {
                        Some(fixed_absolute::Inspection::Ineligible {
                            work: candidate.work.checked_add(consumed).ok_or(
                                AggregateBuildError::InternalInvariant {
                                    operation,
                                    selection,
                                    detail: "fixed absolute planner work overflow",
                                },
                            )?,
                        })
                    }
                    Err(fixed_absolute::InspectionError::WorkLimit { needed, consumed }) => {
                        let needed = candidate.work.checked_add(needed).ok_or(
                            AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "fixed absolute planner refusal overflow",
                            },
                        )?;
                        let consumed = candidate.work.checked_add(consumed).ok_or(
                            AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "fixed absolute planner consumed work overflow",
                            },
                        )?;
                        return Err(AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit {
                            operation,
                            selection,
                            needed,
                            limit: limits.max_fixed_absolute_planner_work,
                            consumed,
                        });
                    }
                    Err(fixed_absolute::InspectionError::Overflow) => {
                        return Err(AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "fixed absolute-domain inspection accounting overflow",
                        });
                    }
                }
            }
        } else {
            None
        };
        let fixed_absolute_planner_work = u32::try_from('fixed_absolute: {
            match fixed_absolute_inspection {
            Some(fixed_absolute::Inspection::Eligible {
                shape,
                work,
                hir_nodes,
                captures,
            }) => {
                if hir_nodes != expected_nodes || captures != expected_captures {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "syntax summary differs from fixed absolute-domain inspection",
                    });
                }
                let census_limit = limits
                    .max_fixed_absolute_planner_work
                    .checked_sub(work)
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed scalar census began outside its planner cap",
                    })?;
                let (residual_prospective_allocations, census_work) =
                    match shape.scalar_residual_compile_allocations(&rust.hir, census_limit) {
                        Ok(Some((allocations, census_work))) => (Some(allocations), census_work),
                        Ok(None) => (None, 0),
                        Err(fixed_absolute::InspectionError::WorkLimit { consumed, .. })
                            if fixed_absolute_optional =>
                        {
                            break 'fixed_absolute work.checked_add(consumed).ok_or(
                                AggregateBuildError::InternalInvariant {
                                    operation,
                                    selection,
                                    detail: "optional fixed scalar census work overflow",
                                },
                            )?;
                        }
                        Err(fixed_absolute::InspectionError::WorkLimit { needed, consumed }) => {
                            let needed = work.checked_add(needed).ok_or(
                                AggregateBuildError::InternalInvariant {
                                    operation,
                                    selection,
                                    detail: "fixed scalar census refusal overflow",
                                },
                            )?;
                            let consumed = work.checked_add(consumed).ok_or(
                                AggregateBuildError::InternalInvariant {
                                    operation,
                                    selection,
                                    detail: "fixed scalar census consumed work overflow",
                                },
                            )?;
                            return Err(AggregateBuildError::FixedAbsoluteDomainPlannerWorkLimit {
                                operation,
                                selection,
                                needed,
                                limit: limits.max_fixed_absolute_planner_work,
                                consumed,
                            });
                        }
                        Err(fixed_absolute::InspectionError::Overflow) => {
                            return Err(AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "fixed scalar residual allocation census overflow",
                            });
                        }
                    };
                let work = work.checked_add(census_work).ok_or(
                    AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed scalar census work overflow",
                    },
                )?;
                let guard_prospective = shape.guard_prospective().map_err(|source| {
                    AggregateBuildError::FixedAbsoluteDomainBuild {
                        operation,
                        selection,
                        planner_work: work,
                        source,
                    }
                })?;
                let guard_with_owner_prospective =
                    include_fixed_absolute_owner_guard_prospective(guard_prospective).map_err(
                        |detail| AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail,
                        },
                    )?;
                let scalar_guard_prospective = shape.scalar_guard_prospective().map_err(|source| {
                        AggregateBuildError::FixedAbsoluteDomainBuild {
                            operation,
                            selection,
                            planner_work: work,
                            source,
                        }
                    })?;
                if scalar_guard_prospective.is_some_and(|scalar| scalar != guard_prospective) {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed scalar and general guard prospectives disagree",
                    });
                }
                let scalar_build_prospective = match (
                    scalar_guard_prospective,
                    residual_prospective_allocations,
                ) {
                    (Some(guard), Some(allocations)) => {
                        let prospective = compose_fixed_residual_build_prospective(
                            guard,
                            limits.continuation,
                            allocations,
                        )
                        .and_then(include_fixed_absolute_owner_prospective)
                        .map_err(|detail| AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail,
                        })?;
                        if let Some((resource, needed, limit)) = fixed_residual_build_limit_refusal(
                            prospective,
                            limits.fixed_absolute_residual,
                        ) {
                            if fixed_absolute_optional {
                                break 'fixed_absolute work;
                            }
                            return Err(
                                AggregateBuildError::FixedAbsoluteDomainResidualPreflight {
                                    operation,
                                    selection,
                                    planner_work: work,
                                    resource,
                                    needed,
                                    limit,
                                    receipt:
                                        AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt {
                                            prospective,
                                            actual:
                                                AggregateFixedAbsoluteDomainResidualBuildActual::default(),
                                        },
                                },
                            );
                        }
                        Some(prospective)
                    }
                    (None, None) => None,
                    _ => {
                        return Err(AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "scalar guard and residual census presence disagree",
                        });
                    }
                };
                if let Some((resource, needed, limit)) = fixed_guard_build_limit_refusal(
                    guard_with_owner_prospective,
                    limits.fixed_absolute,
                ) {
                    if fixed_absolute_optional {
                        break 'fixed_absolute work;
                    }
                    let source = fixed_guard_build_preflight_error(
                        guard_with_owner_prospective,
                        resource,
                        needed,
                        limit,
                    );
                    return Err(scalar_build_prospective.map_or(
                        AggregateBuildError::FixedAbsoluteDomainBuild {
                            operation,
                            selection,
                            planner_work: work,
                            source: source.clone(),
                        },
                        |prospective| {
                            AggregateBuildError::FixedAbsoluteDomainResidualGuardBuild {
                                operation,
                                selection,
                                planner_work: work,
                                source,
                                composite:
                                    AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt {
                                        prospective,
                                        actual:
                                            AggregateFixedAbsoluteDomainResidualBuildActual::default(),
                                    },
                            }
                        },
                    ));
                }
                let guard = match shape.build(limits.fixed_absolute) {
                    Ok(guard) => guard,
                    Err(source)
                        if fixed_absolute_optional
                            && fixed_absolute_build_limit_allows_continuation(&source) =>
                    {
                        break 'fixed_absolute work;
                    }
                    Err(source) => {
                        let source = bind_fixed_owner_to_guard_build_error(
                            source,
                            guard_with_owner_prospective,
                        );
                        return Err(scalar_build_prospective.map_or(
                            AggregateBuildError::FixedAbsoluteDomainBuild {
                                operation,
                                selection,
                                planner_work: work,
                                source: source.clone(),
                            },
                            |prospective| {
                                AggregateBuildError::FixedAbsoluteDomainResidualGuardBuild {
                                    operation,
                                    selection,
                                    planner_work: work,
                                    source,
                                    composite:
                                        AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt {
                                            prospective,
                                            actual:
                                                AggregateFixedAbsoluteDomainResidualBuildActual::default(),
                                        },
                                }
                            },
                        ));
                    }
                };
                let kernel = match operation {
                    AggregateOperation::Count => guard.count_identity(),
                    AggregateOperation::SpanSum => guard.span_sum_identity(),
                    AggregateOperation::Compile | AggregateOperation::Spans => {
                        return Err(AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "unsupported operation selected fixed absolute-domain route",
                        });
                    }
                };
                let scalar = guard.descriptor_identity().kind()
                    == FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope;
                let guard_build = guard.build_accounting();
                let guard_with_owner = FixedAbsoluteDomainBuildAccounting {
                    prospective: guard_with_owner_prospective,
                    actual: include_fixed_absolute_owner_guard_actual(guard_build.actual).map_err(
                        |detail| AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail,
                        },
                    )?,
                };
                if !fixed_guard_build_actual_fits(
                    guard_with_owner.actual,
                    guard_with_owner.prospective,
                ) {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed guard with owner actual exceeds prospective",
                    });
                }
                if scalar && operation != AggregateOperation::Count {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "scalar fixed-domain envelope selected a non-count operation",
                    });
                }
                let continuation_profile = if unicode {
                    RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE
                } else {
                    RustByteProfile::PINNED_1_12_4
                };
                let residual_allocation_limit = limits
                    .fixed_absolute_residual
                    .max_allocations
                    .checked_sub(guard_build.prospective.allocations)
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed guard allocations exceed admitted composite cap",
                    })?;
                let (residual, residual_actual_allocations) = if scalar {
                    let prospective_allocations = residual_prospective_allocations.ok_or(
                        AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "scalar fixed-domain route lacks residual allocation census",
                        },
                    )?;
                    let (residual, actual_allocations) =
                        CompiledRegex::from_hir_erasing_captures_for_whole_match_with_allocation_receipt(
                            &rust.hir,
                            continuation_profile,
                            limits.continuation,
                            residual_allocation_limit,
                            prospective_allocations,
                        )
                        .map_err(|source| {
                            let Some(prospective) = scalar_build_prospective else {
                                return AggregateBuildError::InternalInvariant {
                                    operation,
                                    selection,
                                    detail: "scalar compile failure lacks composite P",
                                };
                            };
                            let Some(actual) = compose_fixed_residual_build_failure_actual(
                                guard_build,
                                &source.receipt,
                            ) else {
                                return AggregateBuildError::InternalInvariant {
                                    operation,
                                    selection,
                                    detail: "scalar compile failure composite A overflowed",
                                };
                            };
                            let composite =
                                AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt {
                                    prospective,
                                    actual,
                                };
                            if !composite.contains_actual() {
                                return AggregateBuildError::InternalInvariant {
                                    operation,
                                    selection,
                                    detail: "scalar compile failure A exceeds composite P",
                                };
                            }
                            AggregateBuildError::FixedAbsoluteDomainResidualCompile {
                                operation,
                                selection,
                                planner_work: work,
                                strategy,
                                guard: guard_build,
                                composite,
                                source,
                            }
                        })?;
                    (Some(residual), Some(actual_allocations))
                } else {
                    (None, None)
                };
                let residual_compile = residual.as_ref().map(CompiledRegex::compile_accounting);
                if let Some(compile) = residual_compile
                    && (compile.hir_nodes != expected_nodes
                        || compile.captures_erased != expected_captures)
                {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "syntax summary differs from fixed-domain residual traversal",
                    });
                }
                let residual_identity =
                    residual
                        .as_ref()
                        .map(|engine| AggregateContinuationIdentity {
                            semantics: AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir,
                            program: engine.plan_id(),
                        });
                let artifact_persistent_bytes = residual_compile.map_or_else(
                    || Ok(guard_build.actual.persistent_bytes),
                    |compile| {
                        guard_build
                            .actual
                            .persistent_bytes
                            .checked_add(compile.program_bytes)
                            .ok_or(AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "fixed-domain composite persistent bytes overflow",
                            })
                    },
                )?;
                let artifact_construction_peak_bytes = residual_compile.map_or_else(
                    || Ok(guard_build.actual.peak_bytes),
                    |compile| {
                        guard_build
                            .actual
                            .persistent_bytes
                            .checked_add(compile.construction_peak_bytes)
                            .map(|co_live| co_live.max(guard_build.actual.peak_bytes))
                            .ok_or(AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "fixed-domain composite construction peak overflow",
                            })
                    },
                )?;
                let capture_erasure_work = residual_compile.map_or_else(
                    || Ok(captures),
                    |compile| {
                        captures.checked_add(compile.capture_erasure_work).ok_or(
                            AggregateBuildError::InternalInvariant {
                                operation,
                                selection,
                                detail: "fixed-domain composite capture-erasure work overflow",
                            },
                        )
                    },
                )?;
                let compile_work = residual_compile.map_or(0_u64, |compile| {
                    u64::try_from(compile.work).unwrap_or(u64::MAX)
                });
                if residual_compile.is_some() && compile_work == u64::MAX {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed-domain residual compile work does not fit u64",
                    });
                }
                let owner_bytes = fixed_absolute_owner_bytes().map_err(|detail| {
                    AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail,
                    }
                })?;
                let owner_work = u64::try_from(owner_bytes).map_err(|_| {
                    AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed absolute owner work does not fit u64",
                    }
                })?;
                let actual_work = guard_build
                    .actual
                    .build_work
                    .checked_add(compile_work)
                    .and_then(|work| work.checked_add(owner_work))
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed-domain composite actual work overflow",
                    })?;
                let actual_allocations = guard_build
                    .actual
                    .allocations
                    .checked_add(residual_actual_allocations.unwrap_or(0))
                    .and_then(|allocations| allocations.checked_add(1))
                    .ok_or(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed-domain composite actual allocations overflow",
                    })?;
                let prospective = match scalar_build_prospective {
                    Some(prospective) => prospective,
                    None => include_fixed_absolute_owner_prospective(
                        AggregateFixedAbsoluteDomainResidualBuildProspective {
                        work: guard_build.prospective.build_work,
                        allocations: guard_build.prospective.allocations,
                        persistent_bytes: guard_build.prospective.persistent_bytes,
                        peak_bytes: guard_build.prospective.peak_bytes,
                        },
                    )
                    .map_err(|detail| AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail,
                    })?,
                };
                let persistent_bytes = artifact_persistent_bytes.checked_add(owner_bytes).ok_or(
                    AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed absolute owner persistent bytes overflow",
                    },
                )?;
                let construction_peak_bytes =
                    artifact_construction_peak_bytes.max(persistent_bytes);
                let actual = AggregateFixedAbsoluteDomainResidualBuildActual {
                    work: actual_work,
                    allocations: actual_allocations,
                    persistent_bytes,
                    peak_bytes: construction_peak_bytes,
                    published: true,
                };
                if actual.work > prospective.work
                    || actual.allocations > prospective.allocations
                    || actual.persistent_bytes > prospective.persistent_bytes
                    || actual.peak_bytes > prospective.peak_bytes
                {
                    return Err(AggregateBuildError::InternalInvariant {
                        operation,
                        selection,
                        detail: "fixed-domain composite actual exceeds prospective",
                    });
                }
                let build = AggregateFixedAbsoluteDomainBuildAccounting {
                    kernel: guard_build,
                    guard_with_owner,
                    residual: residual_compile,
                    prospective,
                    actual,
                };
                let identity = AggregateFixedAbsoluteDomainIdentity {
                    kernel,
                    residual: residual_identity,
                    residual_strategy: scalar.then_some(strategy),
                };
                let seal = AggregateFixedAbsoluteDomainSeal {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key: Arc::clone(&syntax_key),
                    admission,
                    syntax: syntax.clone(),
                    operation,
                    selection,
                    plan: AggregatePlanKind::FixedAbsoluteDomain,
                    continuation_strategy: scalar.then_some(strategy),
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
                    fixed_absolute_planner_work: work,
                    max_fixed_absolute_planner_work: limits.max_fixed_absolute_planner_work,
                    finite_planner_work: 0,
                    capture_erasure_work,
                    captures_erased: captures,
                    identity,
                    build,
                    admission_policy: limits.admission,
                    syntax_safety: limits.syntax_safety,
                    guard_build_limits: limits.fixed_absolute,
                    residual_build_limits: if scalar {
                        limits.fixed_absolute_residual
                    } else {
                        AggregateFixedAbsoluteDomainResidualBuildLimits::default()
                    },
                    continuation_build_limits: if scalar {
                        limits.continuation
                    } else {
                        AggregateCompileLimits::default()
                    },
                    residual_allocation_census: residual_prospective_allocations,
                    retained_capacity_bytes: persistent_bytes,
                };
                let error_identity = AggregateFixedAbsoluteDomainErrorIdentity {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key: Arc::clone(&syntax_key),
                    operation,
                    selection,
                    continuation_strategy: scalar.then_some(strategy),
                    capture_semantics: AggregateCaptureSemantics::ErasedForWholeMatchOnly,
                    admission: limits.admission,
                    syntax_safety: limits.syntax_safety,
                    max_fixed_absolute_planner_work: limits.max_fixed_absolute_planner_work,
                    fixed_absolute_planner_work: work,
                    plan_identity: identity,
                    guard_build_limits: limits.fixed_absolute,
                    residual_build_limits: if scalar {
                        limits.fixed_absolute_residual
                    } else {
                        AggregateFixedAbsoluteDomainResidualBuildLimits::default()
                    },
                    continuation_build_limits: if scalar {
                        limits.continuation
                    } else {
                        AggregateCompileLimits::default()
                    },
                    residual_allocation_census: residual_prospective_allocations,
                };
                let owner =
                    AggregateExecutionIdentity::fixed_absolute_domain(seal, error_identity);
                let report = AggregateBuildReport {
                    schema_version: AGGREGATE_EXPLAIN_SCHEMA_VERSION,
                    syntax_key,
                    admission,
                    syntax,
                    operation,
                    selection,
                    plan: AggregatePlanKind::FixedAbsoluteDomain,
                    continuation_strategy: scalar.then_some(strategy),
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
                    fixed_absolute_planner_work: u32::try_from(work).map_err(|_| {
                        AggregateBuildError::InternalInvariant {
                            operation,
                            selection,
                            detail: "fixed absolute planner work does not fit report field",
                        }
                    })?,
                    finite_planner_work: 0,
                    capture_erasure_work,
                    captures_erased: captures,
                    build: AggregateBuildAccounting::FixedAbsoluteDomain(build.summary()),
                    plan_identity: AggregatePlanIdentity::FixedAbsoluteDomain(identity),
                    sealed_bounded_separated_fields_identity: None,
                    sealed_required_internal_anchor_identity: None,
                    sealed_url_aggregate_identity: Some(AggregateUrlOrFixedSeal::Fixed(owner)),
                    retained_capacity_bytes: persistent_bytes,
                };
                return Ok(AggregatePlan {
                    engine: AggregateEngine::FixedAbsoluteDomain(
                        AggregateFixedAbsoluteDomainEngine { guard, residual },
                    ),
                    minimum_match_bytes,
                    limits,
                    report,
                });
            }
            Some(fixed_absolute::Inspection::Ineligible { work }) => work,
            None => 0,
            }
        })
        .map_err(|_| AggregateBuildError::InternalInvariant {
            operation,
            selection,
            detail: "fixed absolute planner work does not fit report field",
        })?;
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
                        fixed_absolute_planner_work,
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
                        sealed_required_internal_anchor_identity: None,
                        sealed_url_aggregate_identity: None,
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
                        fixed_absolute_planner_work,
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
                        sealed_required_internal_anchor_identity: None,
                        sealed_url_aggregate_identity: None,
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
        let program = engine.plan_id();
        let sealed_required_internal_anchor_identity = (compile.required_internal_anchors == 1)
            .then_some(AggregateRequiredInternalAnchorSeal { program, compile });
        let sealed_url_aggregate_identity = (compile.url_aggregate_plans == 1).then_some(
            AggregateUrlOrFixedSeal::Url(AggregateUrlAggregateSeal { program, compile }),
        );
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
            fixed_absolute_planner_work,
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
                program,
            }),
            sealed_bounded_separated_fields_identity: None,
            sealed_required_internal_anchor_identity,
            sealed_url_aggregate_identity,
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
#[allow(
    clippy::large_enum_variant,
    reason = "selected engines retain their already-budgeted artifacts inline; boxing would add an unaccounted allocation"
)]
enum AggregateEngine {
    ExactLiteral(LiteralAggregatePlan),
    UnicodeScalar(UnicodeScalarAggregatePlan),
    FixedClassSandwich(FixedClassSandwichPlan),
    GraphemeScalarDfa(GraphemeScalarDfaPlan),
    BoundedClassSequence(BoundedClassSequencePlan),
    BoundedSeparatedFields(BoundedSeparatedFieldsPlan),
    PrefixClassAlternation(PrefixClassAlternationPlan),
    BoundedContext(BoundedContextPlan),
    FixedAbsoluteDomain(AggregateFixedAbsoluteDomainEngine),
    FiniteCount(OrderedLiteralCountPlan),
    FiniteSpanSum(OrderedLiteralSpanSumPlan),
    SparseFiniteCount(SparseOrderedLiteralCountPlan),
    SparseFiniteSpanSum(SparseOrderedLiteralSpanSumPlan),
    Continuation(CompiledRegex),
}

#[derive(Debug)]
struct AggregateFixedAbsoluteDomainEngine {
    guard: FixedAbsoluteDomainPlan,
    residual: Option<CompiledRegex>,
}

#[derive(Debug)]
struct AggregatePlan {
    engine: AggregateEngine,
    minimum_match_bytes: Option<usize>,
    limits: AggregateBuildLimits,
    report: AggregateBuildReport,
}

#[allow(
    clippy::large_enum_variant,
    reason = "fixed terminal failures retain one lossless allocation-free continuation/composite receipt"
)]
enum AggregateFixedAbsoluteDomainAttemptFailure {
    Guard(FixedAbsoluteDomainReduceError),
    Residual {
        continuation: OperationAttemptError,
        composite: AggregateFixedAbsoluteDomainResidualReceipt,
    },
}

impl fmt::Debug for AggregateFixedAbsoluteDomainAttemptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Guard(error) => formatter.debug_tuple("Guard").field(error).finish(),
            Self::Residual {
                continuation,
                composite,
            } => formatter
                .debug_struct("Residual")
                .field("continuation", continuation)
                .field("composite", composite)
                .finish(),
        }
    }
}

#[allow(
    clippy::result_large_err,
    reason = "execution errors preserve one complete allocation-free fixed-domain owner/receipt identity"
)]
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

    fn fixed_absolute_domain_seal(&self) -> Option<&AggregateFixedAbsoluteDomainSeal> {
        let owner = self.report.fixed_absolute_domain_owner()?;
        let sealed = owner.fixed_absolute_domain_seal();
        (self.report.has_closed_fixed_absolute_domain_identity()
            && sealed.matches_build_inputs(&self.limits))
        .then_some(sealed)
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

    /// Return the exact fixed-domain guard envelope for a complete original
    /// haystack without borrowing or inspecting that haystack.
    ///
    /// `None` proves that the retained artifact and its private construction
    /// seal do not jointly authenticate a fixed absolute-domain route. The
    /// scalar-envelope route returns only its fixed guard envelope; its eager
    /// continuation remains governed by `AggregateRunLimits::continuation`.
    fn fixed_absolute_domain_full_window_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<FixedAbsoluteDomainProspective>, FixedAbsoluteDomainReduceError> {
        let AggregateEngine::FixedAbsoluteDomain(engine) = &self.engine else {
            return Ok(None);
        };
        if self.fixed_absolute_domain_seal().is_none() {
            return Ok(None);
        }
        let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = self.report.plan_identity else {
            return Ok(None);
        };
        let Some(build) = self.report.fixed_absolute_domain_build_accounting() else {
            return Ok(None);
        };
        let operation = match self.operation() {
            AggregateOperation::Count => FixedAbsoluteDomainOperation::Count,
            AggregateOperation::SpanSum => FixedAbsoluteDomainOperation::SpanSum,
            AggregateOperation::Compile | AggregateOperation::Spans => return Ok(None),
        };
        let guard_identity = match operation {
            FixedAbsoluteDomainOperation::Count => engine.guard.count_identity(),
            FixedAbsoluteDomainOperation::SpanSum => engine.guard.span_sum_identity(),
        };
        if identity.kernel != guard_identity || build.kernel != engine.guard.build_accounting() {
            return Ok(None);
        }
        let limits = FixedAbsoluteDomainReduceLimits {
            max_byte_probes: usize::MAX,
            max_branch_checks: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_total_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        };
        engine
            .guard
            .preflight(
                haystack_len,
                Window::new(0, haystack_len),
                operation,
                limits,
            )
            .map(|admission| Some(admission.prospective()))
    }

    fn fixed_absolute_domain_full_window_composite_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<AggregateFixedAbsoluteDomainResidualProspective>, AggregateExecutionSource>
    {
        let AggregateEngine::FixedAbsoluteDomain(engine) = &self.engine else {
            return Ok(None);
        };
        if self.fixed_absolute_domain_seal().is_none() {
            return Ok(None);
        }
        let AggregatePlanIdentity::FixedAbsoluteDomain(identity) = self.report.plan_identity else {
            return Ok(None);
        };
        if identity.kernel.descriptor.kind()
            != FixedAbsoluteDomainDescriptorKind::WholeScalarEnvelope
        {
            return Ok(None);
        }
        let residual =
            engine
                .residual
                .as_ref()
                .ok_or(AggregateExecutionSource::InternalInvariant(
                    "scalar fixed-domain query lacks its eager residual",
                ))?;
        let strategy = self.report.continuation_strategy.ok_or(
            AggregateExecutionSource::InternalInvariant(
                "scalar fixed-domain query lacks its continuation strategy",
            ),
        )?;
        let guard = self
            .fixed_absolute_domain_full_window_prospective(haystack_len)
            .map_err(|_| {
                AggregateExecutionSource::InternalInvariant(
                    "authenticated fixed guard prospective derivation failed",
                )
            })?
            .ok_or(AggregateExecutionSource::InternalInvariant(
                "scalar fixed-domain query lost its authenticated guard",
            ))?;
        if guard.disposition != FixedAbsoluteDomainDisposition::PrepublishedContinuation {
            return Ok(None);
        }
        let continuation = residual
            .fixed_scalar_dense_count_prospective(haystack_len, strategy)
            .map_err(AggregateExecutionSource::Continuation)?;
        let persistent_bytes = self
            .report
            .fixed_absolute_domain_build_accounting()
            .ok_or(AggregateExecutionSource::InternalInvariant(
                "scalar fixed-domain query lacks composite build accounting",
            ))?
            .actual
            .persistent_bytes;
        compose_fixed_residual_prospective(guard, continuation, persistent_bytes)
            .map(Some)
            .map_err(AggregateExecutionSource::Continuation)
    }

    fn execution_error(
        &self,
        execution_limits: &AggregateRunLimits,
        source: AggregateExecutionSource,
    ) -> AggregateExecutionError {
        AggregateExecutionError {
            identity: AggregateExecutionAttemptIdentity::incumbent(Box::new(
                self.cache_identity(execution_limits),
            )),
            source,
        }
    }

    fn continuation_execution_error(
        &self,
        execution_limits: &AggregateRunLimits,
        attempt: OperationAttemptError,
    ) -> AggregateExecutionError {
        let OperationAttemptError { source, receipt } = attempt;
        self.continuation_error_from_receipt(
            execution_limits,
            receipt,
            AggregateExecutionSource::Continuation(source),
        )
    }

    fn continuation_error_from_receipt(
        &self,
        execution_limits: &AggregateRunLimits,
        receipt: OperationAttemptReceipt,
        source: AggregateExecutionSource,
    ) -> AggregateExecutionError {
        AggregateExecutionError {
            identity: AggregateExecutionAttemptIdentity::continuation(
                Box::new(self.cache_identity(execution_limits)),
                receipt,
            ),
            source,
        }
    }

    fn fixed_execution_error(
        &self,
        execution_limits: &AggregateRunLimits,
        failure: AggregateFixedAbsoluteDomainAttemptFailure,
    ) -> AggregateExecutionError {
        let Some(owner) = self
            .report
            .fixed_absolute_domain_owner()
            .filter(|_| self.fixed_absolute_domain_seal().is_some())
            .cloned()
        else {
            return self.execution_error(
                execution_limits,
                AggregateExecutionSource::InternalInvariant(
                    "fixed terminal failure lacks its authenticated construction owner",
                ),
            );
        };
        let receipt = AggregateFixedAbsoluteDomainAttemptReceipt::new(*execution_limits, failure);
        let kind = receipt.kind();
        let identity = AggregateExecutionAttemptIdentity::fixed_absolute_domain(owner, receipt);
        let source = match kind {
            AggregateFixedAbsoluteDomainAttemptKind::Guard => {
                AggregateExecutionSource::FixedAbsoluteDomain
            }
            AggregateFixedAbsoluteDomainAttemptKind::Residual => {
                AggregateExecutionSource::FixedAbsoluteDomainResidual
            }
        };
        AggregateExecutionError { identity, source }
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

    fn fixed_residual_persistent_bytes(
        &self,
        execution_limits: &AggregateRunLimits,
    ) -> Result<usize, AggregateExecutionError> {
        match self.report.fixed_absolute_domain_build_accounting() {
            Some(build) if build.residual.is_some() => Ok(build.actual.persistent_bytes),
            _ => Err(self.execution_error(
                execution_limits,
                AggregateExecutionSource::InternalInvariant(
                    "fixed-domain residual lacks sealed composite build accounting",
                ),
            )),
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
            AggregateEngine::FixedAbsoluteDomain(engine) => {
                let guard = engine
                    .guard
                    .count(haystack, limits.fixed_absolute)
                    .map_err(|source| {
                        self.fixed_execution_error(
                            limits,
                            AggregateFixedAbsoluteDomainAttemptFailure::Guard(source),
                        )
                    })?;
                match guard.outcome {
                    FixedAbsoluteDomainCountOutcome::Complete { count } => {
                        Ok(AggregateCountExecution::FixedAbsoluteDirect {
                            value: count,
                            guard: guard.accounting,
                        })
                    }
                    FixedAbsoluteDomainCountOutcome::PrepublishedContinuation => {
                        let residual = engine.residual.as_ref().ok_or_else(|| {
                            self.execution_error(
                                limits,
                                AggregateExecutionSource::InternalInvariant(
                                    "fixed-domain continuation branch lacks its eager residual",
                                ),
                            )
                        })?;
                        let strategy = self.report.continuation_strategy.ok_or_else(|| {
                            self.execution_error(
                                limits,
                                AggregateExecutionSource::InternalInvariant(
                                    "fixed-domain continuation branch lacks its strategy",
                                ),
                            )
                        })?;
                        let persistent_bytes = self.fixed_residual_persistent_bytes(limits)?;
                        let residual_allocation_limit = limits
                            .fixed_absolute_residual
                            .max_allocations
                            .saturating_sub(guard.accounting.prospective.allocations);
                        let mut published_prospective = None;
                        let attempt = residual.admit_count_with_receipt_observer(
                            haystack,
                            Self::full_range(haystack),
                            strategy,
                            limits.continuation,
                            residual_allocation_limit,
                            |continuation| {
                                let prospective = compose_fixed_residual_prospective(
                                    guard.accounting.prospective,
                                    continuation,
                                    persistent_bytes,
                                )?;
                                published_prospective = Some(prospective);
                                enforce_fixed_residual_prospective(prospective, limits)
                            },
                        );
                        let admitted = match attempt {
                            Ok(admitted) => admitted,
                            Err(continuation) => {
                                let Some(prospective) = published_prospective else {
                                    return Err(self.execution_error(
                                        limits,
                                        AggregateExecutionSource::InternalInvariant(
                                            "fixed residual failed before publishing composite P",
                                        ),
                                    ));
                                };
                                let composite = fixed_residual_composite(
                                    guard.accounting,
                                    &continuation.receipt,
                                    prospective,
                                    persistent_bytes,
                                )
                                .map_err(|_| {
                                    self.execution_error(
                                        limits,
                                        AggregateExecutionSource::InternalInvariant(
                                            "fixed residual failure composite overflowed",
                                        ),
                                    )
                                })?;
                                return Err(self.fixed_execution_error(
                                    limits,
                                    AggregateFixedAbsoluteDomainAttemptFailure::Residual {
                                        continuation,
                                        composite,
                                    },
                                ));
                            }
                        };
                        let prospective = published_prospective.ok_or_else(|| {
                            self.execution_error(
                                limits,
                                AggregateExecutionSource::InternalInvariant(
                                    "fixed residual succeeded without publishing composite P",
                                ),
                            )
                        })?;
                        let composite = fixed_residual_composite(
                            guard.accounting,
                            &admitted.receipt,
                            prospective,
                            persistent_bytes,
                        )
                        .map_err(|_| {
                            self.execution_error(
                                limits,
                                AggregateExecutionSource::InternalInvariant(
                                    "fixed residual success composite overflowed",
                                ),
                            )
                        })?;
                        if !composite.contains_actual_with(&admitted.receipt) {
                            return Err(self.execution_error(
                                limits,
                                AggregateExecutionSource::InternalInvariant(
                                    "fixed residual success escaped its composite P",
                                ),
                            ));
                        }
                        let value = u64::try_from(admitted.admitted.value()).map_err(|_| {
                            self.execution_error(
                                limits,
                                AggregateExecutionSource::InternalInvariant(
                                    "fixed-domain residual count does not fit u64",
                                ),
                            )
                        })?;
                        Ok(AggregateCountExecution::FixedAbsoluteResidual {
                            value,
                            admitted,
                            composite,
                        })
                    }
                }
            }
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
                    .admit_count_attempt(
                        haystack,
                        Self::full_range(haystack),
                        strategy,
                        limits.continuation,
                    )
                    .map_err(|attempt| self.continuation_execution_error(limits, attempt))?;
                let value = match u64::try_from(admitted.admitted.value()) {
                    Ok(value) => value,
                    Err(_) => {
                        return Err(self.continuation_error_from_receipt(
                            limits,
                            admitted.receipt,
                            AggregateExecutionSource::InternalInvariant(
                                "continuation count does not fit u64",
                            ),
                        ));
                    }
                };
                Ok(AggregateCountExecution::Continuation { admitted, value })
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the exhaustive engine dispatch keeps every typed span-sum error mapping adjacent"
    )]
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
            AggregateEngine::FixedAbsoluteDomain(engine) => {
                if engine.residual.is_some() {
                    return Err(self.execution_error(
                        limits,
                        AggregateExecutionSource::InternalInvariant(
                            "span-sum fixed-domain route retained a residual",
                        ),
                    ));
                }
                engine
                    .guard
                    .span_sum(haystack, limits.fixed_absolute)
                    .map(AggregateSpanSumExecution::FixedAbsoluteDomain)
                    .map_err(|source| {
                        self.fixed_execution_error(
                            limits,
                            AggregateFixedAbsoluteDomainAttemptFailure::Guard(source),
                        )
                    })
            }
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
            .admit_span_sum_with_receipt(
                haystack,
                Self::full_range(haystack),
                strategy,
                limits.continuation,
            )
            .map_err(|attempt| self.continuation_execution_error(limits, attempt))?;
        let value = match u64::try_from(admitted.admitted.value()) {
            Ok(value) => value,
            Err(_) => {
                return Err(self.continuation_error_from_receipt(
                    limits,
                    admitted.receipt,
                    AggregateExecutionSource::InternalInvariant(
                        "continuation span sum does not fit u64",
                    ),
                ));
            }
        };
        Ok(AggregateSpanSumExecution::Continuation { admitted, value })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the value-only fixed/residual path keeps publication and terminal P/A checks in one audit boundary"
    )]
    fn execute_count_value(
        &self,
        haystack: &[u8],
        limits: &AggregateRunLimits,
    ) -> Result<u64, AggregateExecutionError> {
        if let AggregateEngine::FixedAbsoluteDomain(engine) = &self.engine {
            let guard = engine
                .guard
                .count(haystack, limits.fixed_absolute)
                .map_err(|source| {
                    self.fixed_execution_error(
                        limits,
                        AggregateFixedAbsoluteDomainAttemptFailure::Guard(source),
                    )
                })?;
            return match guard.outcome {
                FixedAbsoluteDomainCountOutcome::Complete { count } => Ok(count),
                FixedAbsoluteDomainCountOutcome::PrepublishedContinuation => {
                    let residual = engine.residual.as_ref().ok_or_else(|| {
                        self.execution_error(
                            limits,
                            AggregateExecutionSource::InternalInvariant(
                                "fixed-domain value branch lacks its eager residual",
                            ),
                        )
                    })?;
                    let strategy = self.report.continuation_strategy.ok_or_else(|| {
                        self.execution_error(
                            limits,
                            AggregateExecutionSource::InternalInvariant(
                                "fixed-domain value branch lacks its strategy",
                            ),
                        )
                    })?;
                    let persistent_bytes = self.fixed_residual_persistent_bytes(limits)?;
                    let residual_allocation_limit = limits
                        .fixed_absolute_residual
                        .max_allocations
                        .saturating_sub(guard.accounting.prospective.allocations);
                    let mut published_prospective = None;
                    let result = residual.count_value_with_receipt_observer(
                        haystack,
                        Self::full_range(haystack),
                        strategy,
                        limits.continuation,
                        residual_allocation_limit,
                        |continuation| {
                            let prospective = compose_fixed_residual_prospective(
                                guard.accounting.prospective,
                                continuation,
                                persistent_bytes,
                            )?;
                            published_prospective = Some(prospective);
                            enforce_fixed_residual_prospective(prospective, limits)
                        },
                    );
                    let attempt = match result {
                        Ok(attempt) => attempt,
                        Err(continuation) => {
                            let Some(prospective) = published_prospective else {
                                return Err(self.execution_error(
                                    limits,
                                    AggregateExecutionSource::InternalInvariant(
                                        "fixed residual value failed before publishing composite P",
                                    ),
                                ));
                            };
                            let composite = fixed_residual_composite(
                                guard.accounting,
                                &continuation.receipt,
                                prospective,
                                persistent_bytes,
                            )
                            .map_err(|_| {
                                self.execution_error(
                                    limits,
                                    AggregateExecutionSource::InternalInvariant(
                                        "fixed residual value failure composite overflowed",
                                    ),
                                )
                            })?;
                            return Err(self.fixed_execution_error(
                                limits,
                                AggregateFixedAbsoluteDomainAttemptFailure::Residual {
                                    continuation,
                                    composite,
                                },
                            ));
                        }
                    };
                    let prospective = published_prospective.ok_or_else(|| {
                        self.execution_error(
                            limits,
                            AggregateExecutionSource::InternalInvariant(
                                "fixed residual value succeeded without publishing composite P",
                            ),
                        )
                    })?;
                    let composite = fixed_residual_composite(
                        guard.accounting,
                        &attempt.receipt,
                        prospective,
                        persistent_bytes,
                    )
                    .map_err(|_| {
                        self.execution_error(
                            limits,
                            AggregateExecutionSource::InternalInvariant(
                                "fixed residual value success composite overflowed",
                            ),
                        )
                    })?;
                    if !composite.contains_actual_with(&attempt.receipt) {
                        return Err(self.execution_error(
                            limits,
                            AggregateExecutionSource::InternalInvariant(
                                "fixed residual value success escaped its composite P",
                            ),
                        ));
                    }
                    u64::try_from(attempt.value).map_err(|_| {
                        self.execution_error(
                            limits,
                            AggregateExecutionSource::InternalInvariant(
                                "fixed-domain residual count does not fit u64",
                            ),
                        )
                    })
                }
            };
        }
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
        let attempt = engine
            .count_value_attempt(
                haystack,
                Self::full_range(haystack),
                strategy,
                limits.continuation,
            )
            .map_err(|attempt| self.continuation_execution_error(limits, attempt))?;
        match u64::try_from(attempt.value) {
            Ok(value) => Ok(value),
            Err(_) => Err(self.continuation_error_from_receipt(
                limits,
                attempt.receipt,
                AggregateExecutionSource::InternalInvariant("continuation count does not fit u64"),
            )),
        }
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
        let attempt = engine
            .span_sum_value_with_receipt(
                haystack,
                Self::full_range(haystack),
                strategy,
                limits.continuation,
            )
            .map_err(|attempt| self.continuation_execution_error(limits, attempt))?;
        match u64::try_from(attempt.value) {
            Ok(value) => Ok(value),
            Err(_) => Err(self.continuation_error_from_receipt(
                limits,
                attempt.receipt,
                AggregateExecutionSource::InternalInvariant(
                    "continuation span sum does not fit u64",
                ),
            )),
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "execution variants retain already-budgeted result receipts inline without a new allocation"
)]
enum AggregateCountExecution {
    ExactLiteral(LiteralAggregateCountResult),
    UnicodeScalar(UnicodeScalarAggregateCountResult),
    FixedClassSandwich(FixedClassSandwichCountResult),
    GraphemeScalarDfa(GraphemeScalarDfaCountResult),
    BoundedClassSequence(BoundedClassSequenceCountResult),
    BoundedSeparatedFields(BoundedSeparatedFieldsCountResult),
    PrefixClassAlternation(PrefixClassAlternationCountResult),
    BoundedContext(BoundedContextCountResult),
    FixedAbsoluteDirect {
        value: u64,
        guard: FixedAbsoluteDomainReduceAccounting,
    },
    FixedAbsoluteResidual {
        value: u64,
        admitted: AdmittedCountAttempt,
        composite: AggregateFixedAbsoluteDomainResidualReceipt,
    },
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
        admitted: AdmittedCountAttempt,
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
            Self::FixedAbsoluteDirect { value, .. } | Self::FixedAbsoluteResidual { value, .. } => {
                *value
            }
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
            Self::FixedAbsoluteDirect { guard, .. } => {
                AggregateExecutionDetails::FixedAbsoluteDomain(
                    AggregateFixedAbsoluteDomainExecutionDetails::Direct { guard },
                )
            }
            Self::FixedAbsoluteResidual {
                admitted,
                composite,
                ..
            } => AggregateExecutionDetails::FixedAbsoluteDomain(
                AggregateFixedAbsoluteDomainExecutionDetails::Residual {
                    composite: AggregateFixedAbsoluteDomainResidualExecutionSummary {
                        prospective: composite.prospective,
                        actual: composite.actual,
                        continuation_actual: admitted.admitted.accounting(),
                        continuation_actual_allocations: admitted.receipt.actual_allocations,
                    },
                },
            ),
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
            Self::Continuation { admitted, .. } => {
                let certificate = admitted.admitted.certificate().clone();
                let accounting = admitted.admitted.accounting();
                AggregateExecutionDetails::Continuation {
                    certificate,
                    accounting,
                    receipt: admitted.receipt,
                }
            }
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "boxing would add an allocation to the operation whose complete accounting is retained inline"
)]
enum AggregateSpanSumExecution {
    ExactLiteral(LiteralAggregateSpanSumResult),
    UnicodeScalar(UnicodeScalarAggregateSpanSumResult),
    FixedClassSandwich(FixedClassSandwichSpanSumResult),
    FixedAbsoluteDomain(FixedAbsoluteDomainSpanSumResult),
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
        admitted: AdmittedSpanSumAttempt,
        value: u64,
    },
}

impl AggregateSpanSumExecution {
    const fn value(&self) -> u64 {
        match self {
            Self::ExactLiteral(result) => result.span_sum,
            Self::UnicodeScalar(result) => result.span_sum,
            Self::FixedClassSandwich(result) => result.span_sum,
            Self::FixedAbsoluteDomain(result) => result.span_sum,
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
            Self::FixedAbsoluteDomain(result) => AggregateExecutionDetails::FixedAbsoluteDomain(
                AggregateFixedAbsoluteDomainExecutionDetails::Direct {
                    guard: result.accounting,
                },
            ),
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
            Self::Continuation { admitted, .. } => {
                let certificate = admitted.admitted.certificate().clone();
                let accounting = admitted.admitted.accounting();
                AggregateExecutionDetails::Continuation {
                    certificate,
                    accounting,
                    receipt: admitted.receipt,
                }
            }
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

#[allow(
    clippy::result_large_err,
    reason = "public verification returns the exact lossless aggregate execution error by contract"
)]
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

    /// Exact intrinsic fixed-domain guard envelope for complete-haystack
    /// verification, computed without source access or allocation.
    ///
    /// Returns `None` unless this artifact authenticates a fixed absolute-
    /// domain count guard. This common query lets verification code avoid
    /// reconstructing descriptor details from public summary identities.
    pub fn fixed_absolute_domain_full_window_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<FixedAbsoluteDomainProspective>, FixedAbsoluteDomainReduceError> {
        self.0
            .fixed_absolute_domain_full_window_prospective(haystack_len)
    }

    /// Full scalar guard-plus-intrinsic-dense continuation prospective.
    pub fn fixed_absolute_domain_full_window_composite_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<AggregateFixedAbsoluteDomainResidualProspective>, AggregateExecutionSource>
    {
        self.0
            .fixed_absolute_domain_full_window_composite_prospective(haystack_len)
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

#[allow(
    clippy::result_large_err,
    reason = "public execution returns the exact lossless aggregate execution error by contract"
)]
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
        let attempt = engine
            .admit_spans_with_receipt(
                haystack,
                AggregatePlan::full_range(haystack),
                strategy,
                limits.continuation,
            )
            .map_err(|attempt| self.0.continuation_execution_error(limits, attempt))?;
        let certificate = attempt.admitted.certificate().clone();
        let accounting = attempt.admitted.accounting();
        let admitted = attempt.admitted;
        let details = AggregateExecutionDetails::Continuation {
            certificate,
            accounting,
            receipt: attempt.receipt,
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

#[allow(
    clippy::result_large_err,
    reason = "public execution returns the exact lossless aggregate execution error by contract"
)]
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

    /// Exact intrinsic fixed-domain guard envelope for a complete haystack of
    /// `haystack_len` bytes, computed without source access or allocation.
    ///
    /// Returns `None` unless the private construction seal, retained guard,
    /// build receipt, and count-operation identity all authenticate the same
    /// fixed absolute-domain artifact. This does not apply caller run limits.
    /// For the scalar-envelope route it describes the guard only; the eager
    /// residual uses the independently published continuation envelope.
    pub fn fixed_absolute_domain_full_window_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<FixedAbsoluteDomainProspective>, FixedAbsoluteDomainReduceError> {
        self.0
            .fixed_absolute_domain_full_window_prospective(haystack_len)
    }

    /// Full scalar guard-plus-intrinsic-dense continuation prospective.
    pub fn fixed_absolute_domain_full_window_composite_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<AggregateFixedAbsoluteDomainResidualProspective>, AggregateExecutionSource>
    {
        self.0
            .fixed_absolute_domain_full_window_composite_prospective(haystack_len)
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

#[allow(
    clippy::result_large_err,
    reason = "public execution returns the exact lossless aggregate execution error by contract"
)]
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

    /// Exact intrinsic fixed-domain guard envelope for a complete haystack of
    /// `haystack_len` bytes, computed without source access or allocation.
    ///
    /// Returns `None` unless the private construction seal, retained guard,
    /// build receipt, and span-sum identity all authenticate the same fixed
    /// absolute-domain artifact. This does not apply caller run limits.
    pub fn fixed_absolute_domain_full_window_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<FixedAbsoluteDomainProspective>, FixedAbsoluteDomainReduceError> {
        self.0
            .fixed_absolute_domain_full_window_prospective(haystack_len)
    }

    /// Full scalar guard-plus-intrinsic-dense continuation prospective.
    pub fn fixed_absolute_domain_full_window_composite_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<AggregateFixedAbsoluteDomainResidualProspective>, AggregateExecutionSource>
    {
        self.0
            .fixed_absolute_domain_full_window_composite_prospective(haystack_len)
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
