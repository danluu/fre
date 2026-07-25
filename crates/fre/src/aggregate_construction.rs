//! Construction-wide transaction and receipt model for aggregate selection.
//!
//! The model is deliberately generic over the facade's existing request and
//! selected-plan identity types. This module owns transaction ordering,
//! accounting, fallback, publication, and exact owner provenance without
//! defining parallel operation, profile, strategy, or limit enums.

#![forbid(unsafe_code)]

use std::fmt;

fn allocations_fit_charged_work(work: u64, allocations: usize, slack: usize) -> bool {
    usize::try_from(work).map_or(true, |work| {
        work.checked_add(slack)
            .is_some_and(|bound| allocations <= bound)
    })
}

/// Allocation-free terminal wrapper for a planner inspection.
///
/// The source error preserves the established public/internal error
/// precedence, while `work` records the exact logical units successfully
/// charged before the refusing or overflowing next charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AggregateInspectionAttemptError<E> {
    source: E,
    work: usize,
}

impl<E> AggregateInspectionAttemptError<E> {
    pub(crate) const fn new(source: E, work: usize) -> Self {
        Self { source, work }
    }

    pub(crate) const fn work(&self) -> usize {
        self.work
    }

    pub(crate) const fn source(&self) -> &E {
        &self.source
    }

    pub(crate) fn into_source(self) -> E {
        self.source
    }
}

/// Version of the aggregate construction transaction algorithm.
pub const AGGREGATE_CONSTRUCTION_ALGORITHM_VERSION: u32 = 1;

/// Version of the aggregate construction prospective/actual accounting.
pub const AGGREGATE_CONSTRUCTION_ACCOUNTING_VERSION: u32 = 1;

/// Exact maximum number of selector stages in the construction transaction.
pub const AGGREGATE_CONSTRUCTION_LEDGER_CAPACITY: usize = 23;

/// Exact request inputs bound by one construction owner.
///
/// The type parameters are the facade's existing exact identity types. In
/// particular, `SyntaxRequest` must own or share the complete pattern/request;
/// a length or probabilistic digest is not an adequate substitute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateConstructionRequestInputs<
    SyntaxRequest,
    Operation,
    Selection,
    Strategy,
    Profile,
    BuildLimits,
> {
    /// Exact owned syntax request, including the complete pattern.
    pub syntax_request: SyntaxRequest,
    /// Whole-match operation selected before construction.
    pub operation: Operation,
    /// Caller-selected aggregate plan policy.
    pub selection: Selection,
    /// Caller-selected continuation strategy.
    pub strategy: Strategy,
    /// Complete compatibility profile.
    pub profile: Profile,
    /// Complete caller-supplied build limits.
    pub build_limits: BuildLimits,
}

/// Exact inline owner of one complete construction request.
///
/// The facade request includes the syntax layer's allocation-bound source
/// origin. Keeping the remaining immutable fields inline avoids fabricating a
/// second heap owner while still rejecting equal-length cross-source splices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateConstructionRequestOwnerSeal<Request>(Request);

impl<Request> AggregateConstructionRequestOwnerSeal<Request> {
    /// Bind an exact request without allocating.
    #[must_use]
    pub const fn from_owned(request: Request) -> Self {
        Self(request)
    }

    /// Exact immutable request inputs.
    #[must_use]
    pub fn request(&self) -> &Request {
        &self.0
    }

    fn request_mut(&mut self) -> &mut Request {
        &mut self.0
    }
}

/// Exact inline owner of the one selected plan published by a transaction.
///
/// The facade's selected-plan identity is immutable and copyable. Retaining it
/// inline makes publication allocation-free and avoids an owner cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateConstructionSelectedPlanOwnerSeal<Plan> {
    stage: AggregateConstructionStage,
    plan: Plan,
}

impl<Plan> AggregateConstructionSelectedPlanOwnerSeal<Plan> {
    /// Bind an exact selected-plan identity without allocating.
    #[must_use]
    pub const fn from_owned(stage: AggregateConstructionStage, plan: Plan) -> Self {
        Self { stage, plan }
    }

    /// Stage that published this plan.
    #[must_use]
    pub const fn stage(&self) -> AggregateConstructionStage {
        self.stage
    }

    /// Exact immutable selected-plan identity.
    #[must_use]
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
}

/// Declared construction-time fallback policy bound into every attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateConstructionDeclaredFallbackPolicy {
    /// The exact selector order and typed whitelist represented by this
    /// algorithm version.
    CurrentSelectorOrder,
}

/// Immutable identity of one aggregate construction transaction.
#[derive(Clone, Debug)]
pub struct AggregateConstructionAttemptIdentity<Request> {
    /// Pointer-exact owner of the complete request.
    pub request_owner: AggregateConstructionRequestOwnerSeal<Request>,
    /// Aggregate explanation schema consumed by this transaction.
    pub explain_schema_version: u32,
    /// Construction transaction algorithm version.
    pub algorithm_version: u32,
    /// Prospective/actual accounting version.
    pub accounting_version: u32,
    /// Exact declared prepublication fallback policy.
    pub declared_fallback_policy: AggregateConstructionDeclaredFallbackPolicy,
}

impl<Request: PartialEq> PartialEq for AggregateConstructionAttemptIdentity<Request> {
    fn eq(&self, other: &Self) -> bool {
        self.request_owner == other.request_owner
            && self.explain_schema_version == other.explain_schema_version
            && self.algorithm_version == other.algorithm_version
            && self.accounting_version == other.accounting_version
            && self.declared_fallback_policy == other.declared_fallback_policy
    }
}

impl<Request: Eq> Eq for AggregateConstructionAttemptIdentity<Request> {}

impl<Request> AggregateConstructionAttemptIdentity<Request> {
    /// Construct the canonical identity for this implementation.
    #[must_use]
    pub const fn new(
        request_owner: AggregateConstructionRequestOwnerSeal<Request>,
        explain_schema_version: u32,
    ) -> Self {
        Self {
            request_owner,
            explain_schema_version,
            algorithm_version: AGGREGATE_CONSTRUCTION_ALGORITHM_VERSION,
            accounting_version: AGGREGATE_CONSTRUCTION_ACCOUNTING_VERSION,
            declared_fallback_policy:
                AggregateConstructionDeclaredFallbackPolicy::CurrentSelectorOrder,
        }
    }

    fn has_current_protocol(&self) -> bool {
        self.explain_schema_version != 0
            && self.algorithm_version == AGGREGATE_CONSTRUCTION_ALGORITHM_VERSION
            && self.accounting_version == AGGREGATE_CONSTRUCTION_ACCOUNTING_VERSION
            && self.declared_fallback_policy
                == AggregateConstructionDeclaredFallbackPolicy::CurrentSelectorOrder
    }
}

/// Exact aggregate selector order.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AggregateConstructionStage {
    /// Pre-syntax `ForceExactLiteral` plus `Spans` terminal check.
    PreSyntaxForceExactLiteralSpans = 0,
    /// Syntax parse/admission and exact request/cache-key construction.
    SyntaxParseAdmission = 1,
    /// Exact literal specialization.
    ExactLiteral = 2,
    /// Direct Unicode scalar specialization.
    UnicodeScalar = 3,
    /// Direct word-run specialization.
    WordRun = 4,
    /// Ordered literal/assertion specialization.
    LiteralAssertions = 5,
    /// Blocking-delimiter specialization.
    BlockingDelimiter = 6,
    /// ASCII token-phrase specialization.
    TokenPhrase = 7,
    /// Fixed-class sandwich specialization.
    FixedClassSandwich = 8,
    /// Ordered grapheme/scalar DFA specialization.
    GraphemeScalarDfa = 9,
    /// Bounded class-sequence specialization.
    BoundedClassSequence = 10,
    /// Bounded separated-fields specialization.
    BoundedSeparatedFields = 11,
    /// Prefix/class alternation specialization.
    PrefixClassAlternation = 12,
    /// Bounded literal-pair specialization.
    BoundedLiteralPair = 13,
    /// Literal/class-run/literal specialization.
    LiteralClassRunLiteral = 14,
    /// Bounded-affix inspection implemented by the bounded-context engine.
    BoundedAffix = 15,
    /// General bounded-context specialization.
    BoundedContext = 16,
    /// Fixed absolute-domain classifier, guard, and optional residual.
    FixedAbsolute = 17,
    /// Finite-root sparse inspection, materialization, and construction.
    SparseFiniteRoot = 18,
    /// General finite extraction, including guarded finite construction.
    GeneralFiniteExtraction = 19,
    /// Dense finite-language construction.
    DenseFinite = 20,
    /// Fixed-predicate Word64 construction after an admitted finite refusal.
    FixedPredicateWord64 = 21,
    /// Final continuation compilation.
    Continuation = 22,
}

impl AggregateConstructionStage {
    /// Canonical selector order.
    pub const ORDER: [Self; AGGREGATE_CONSTRUCTION_LEDGER_CAPACITY] = [
        Self::PreSyntaxForceExactLiteralSpans,
        Self::SyntaxParseAdmission,
        Self::ExactLiteral,
        Self::UnicodeScalar,
        Self::WordRun,
        Self::LiteralAssertions,
        Self::BlockingDelimiter,
        Self::TokenPhrase,
        Self::FixedClassSandwich,
        Self::GraphemeScalarDfa,
        Self::BoundedClassSequence,
        Self::BoundedSeparatedFields,
        Self::PrefixClassAlternation,
        Self::BoundedLiteralPair,
        Self::LiteralClassRunLiteral,
        Self::BoundedAffix,
        Self::BoundedContext,
        Self::FixedAbsolute,
        Self::SparseFiniteRoot,
        Self::GeneralFiniteExtraction,
        Self::DenseFinite,
        Self::FixedPredicateWord64,
        Self::Continuation,
    ];

    /// Zero-based canonical stage ordinal.
    #[must_use]
    #[allow(
        clippy::as_conversions,
        reason = "repr discriminants are pinned to usize ordinals"
    )]
    pub const fn ordinal(self) -> usize {
        self as usize
    }

    /// Next stage in the ordinary selector order.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        let Some(next) = self.ordinal().checked_add(1) else {
            return None;
        };
        if next < AGGREGATE_CONSTRUCTION_LEDGER_CAPACITY {
            Some(Self::ORDER[next])
        } else {
            None
        }
    }
}

/// Final or transient disposition of one visited selector stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateConstructionStageDisposition {
    /// Caller policy/profile made the route unattempted.
    PolicySkipped,
    /// Inspection ran and proved the route semantically ineligible.
    SemanticIneligible,
    /// A required intermediate stage completed successfully and advances
    /// without selecting or publishing an executable plan.
    Completed,
    /// Semantics selected the route; build/publication has not resolved yet.
    Selected,
    /// A specifically whitelisted prepublication resource edge was taken.
    SoftResourceRefused,
    /// Construction terminated without publishing a plan.
    HardTerminal,
    /// The selected immutable plan owner was published exactly once.
    Published,
}

/// Exact typed prepublication fallback/transition reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateConstructionPrepublicationFallback {
    /// No fallback or special semantic transition.
    None,
    /// Optional `FixedAbsolute` candidate/inspection/census resource refusal.
    FixedAbsoluteOptionalInspectionResource,
    /// Optional `FixedAbsolute` scalar-residual composite resource refusal.
    FixedAbsoluteOptionalResidualResource,
    /// Optional `FixedAbsolute` guard preflight or guard resource refusal.
    FixedAbsoluteOptionalGuardResource,
    /// Optional `FixedAbsolute` admitted shape-build resource refusal.
    FixedAbsoluteOptionalBuildResource,
    /// Sparse finite materialization scratch refusal.
    SparseFiniteMaterializationScratch,
    /// Sparse finite materialization peak refusal.
    SparseFiniteMaterializationPeak,
    /// Sparse finite builder resource refusal.
    SparseFiniteBuildResource,
    /// Guarded dictionary resource/work refusal.
    GuardedFiniteDictionaryResource,
    /// Guarded outer construction scratch/peak refusal.
    GuardedFiniteConstructionResource,
    /// Dense finite resource refusal followed by `FixedPredicateWord64`.
    DenseFiniteBuildResourceToFixedPredicateWord64,
    /// Dense finite resource refusal followed by continuation.
    DenseFiniteBuildResourceToContinuation,
    /// Finite extraction's separately declared too-large fixed sequence edge.
    TooLargeFixedSequenceToFixedPredicateWord64,
    /// `FixedPredicateWord64` resource refusal followed by continuation.
    FixedPredicateWord64BuildResource,
}

impl AggregateConstructionPrepublicationFallback {
    const fn transition(self) -> Option<AggregateConstructionTransition> {
        match self {
            Self::None => None,
            Self::FixedAbsoluteOptionalInspectionResource
            | Self::FixedAbsoluteOptionalResidualResource
            | Self::FixedAbsoluteOptionalGuardResource
            | Self::FixedAbsoluteOptionalBuildResource => {
                Some(AggregateConstructionTransition::FixedAbsoluteToSparseFiniteRoot)
            }
            Self::SparseFiniteMaterializationScratch
            | Self::SparseFiniteMaterializationPeak
            | Self::SparseFiniteBuildResource => {
                Some(AggregateConstructionTransition::SparseFiniteToContinuation)
            }
            Self::GuardedFiniteDictionaryResource | Self::GuardedFiniteConstructionResource => {
                Some(AggregateConstructionTransition::GuardedFiniteToContinuation)
            }
            Self::DenseFiniteBuildResourceToFixedPredicateWord64 => {
                Some(AggregateConstructionTransition::DenseFiniteToFixedPredicateWord64)
            }
            Self::DenseFiniteBuildResourceToContinuation => {
                Some(AggregateConstructionTransition::DenseFiniteToContinuation)
            }
            Self::TooLargeFixedSequenceToFixedPredicateWord64 => {
                Some(AggregateConstructionTransition::TooLargeFixedSequenceToFixedPredicateWord64)
            }
            Self::FixedPredicateWord64BuildResource => {
                Some(AggregateConstructionTransition::FixedPredicateWord64ToContinuation)
            }
        }
    }

    const fn source_stage(self) -> Option<AggregateConstructionStage> {
        match self {
            Self::None => None,
            Self::FixedAbsoluteOptionalInspectionResource
            | Self::FixedAbsoluteOptionalResidualResource
            | Self::FixedAbsoluteOptionalGuardResource
            | Self::FixedAbsoluteOptionalBuildResource => {
                Some(AggregateConstructionStage::FixedAbsolute)
            }
            Self::SparseFiniteMaterializationScratch
            | Self::SparseFiniteMaterializationPeak
            | Self::SparseFiniteBuildResource => Some(AggregateConstructionStage::SparseFiniteRoot),
            Self::GuardedFiniteDictionaryResource
            | Self::GuardedFiniteConstructionResource
            | Self::TooLargeFixedSequenceToFixedPredicateWord64 => {
                Some(AggregateConstructionStage::GeneralFiniteExtraction)
            }
            Self::DenseFiniteBuildResourceToFixedPredicateWord64
            | Self::DenseFiniteBuildResourceToContinuation => {
                Some(AggregateConstructionStage::DenseFinite)
            }
            Self::FixedPredicateWord64BuildResource => {
                Some(AggregateConstructionStage::FixedPredicateWord64)
            }
        }
    }
}

/// Exact selector edge recorded after a stage disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateConstructionTransition {
    /// Ordinary advance to the named next stage.
    Advance(AggregateConstructionStage),
    /// Transient selection before build/publication resolution.
    Selected,
    /// Optional fixed-domain refusal to sparse finite inspection.
    FixedAbsoluteToSparseFiniteRoot,
    /// Sparse finite resource refusal directly to continuation.
    SparseFiniteToContinuation,
    /// Guarded finite resource refusal directly to continuation.
    GuardedFiniteToContinuation,
    /// Dense finite resource refusal to `FixedPredicateWord64`.
    DenseFiniteToFixedPredicateWord64,
    /// Dense finite resource refusal directly to continuation.
    DenseFiniteToContinuation,
    /// Too-large fixed sequence to `FixedPredicateWord64`.
    TooLargeFixedSequenceToFixedPredicateWord64,
    /// `FixedPredicateWord64` resource refusal to continuation.
    FixedPredicateWord64ToContinuation,
    /// Hard construction terminal.
    HardTerminal,
    /// Irreversible publication.
    Published,
}

impl AggregateConstructionTransition {
    const fn target(self) -> Option<AggregateConstructionStage> {
        match self {
            Self::Advance(stage) => Some(stage),
            Self::FixedAbsoluteToSparseFiniteRoot => {
                Some(AggregateConstructionStage::SparseFiniteRoot)
            }
            Self::SparseFiniteToContinuation
            | Self::GuardedFiniteToContinuation
            | Self::DenseFiniteToContinuation
            | Self::FixedPredicateWord64ToContinuation => {
                Some(AggregateConstructionStage::Continuation)
            }
            Self::DenseFiniteToFixedPredicateWord64
            | Self::TooLargeFixedSequenceToFixedPredicateWord64 => {
                Some(AggregateConstructionStage::FixedPredicateWord64)
            }
            Self::Selected | Self::HardTerminal | Self::Published => None,
        }
    }
}

/// Complete construction upper bounds published before controlled effects.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateConstructionProspective {
    /// Charged construction and inspection work.
    pub work: u64,
    /// Exact controlled allocation count.
    pub allocations: usize,
    /// Total bytes successfully allocated over the transaction.
    pub allocated_bytes: usize,
    /// Total bytes copied by observed controlled effects.
    pub copied_bytes: usize,
    /// Total bytes initialized by observed controlled effects, including
    /// inline returned-plan storage that requires no heap allocation.
    pub initialized_bytes: usize,
    /// Work that may be abandoned across declared fallback edges.
    pub abandoned_work: u64,
    /// Allocations that may be abandoned across declared fallback edges.
    pub abandoned_allocations: usize,
    /// Heap-allocated or inline initialized bytes that may be abandoned across
    /// fallback edges.
    pub abandoned_bytes: usize,
    /// Persistent bytes retained by the ultimately selected construction.
    pub live_persistent_bytes: usize,
    /// Maximum co-live construction bytes. This independent peak may be
    /// exposed by a nested receipt even when that component does not expose
    /// cumulative allocated/copied/initialized byte counters.
    pub high_water_bytes: usize,
}

impl AggregateConstructionProspective {
    /// Check structural relations between cumulative and live upper bounds.
    #[must_use]
    pub fn is_well_formed(self) -> bool {
        let observable_bytes = self.allocated_bytes.checked_add(self.initialized_bytes);
        allocations_fit_charged_work(self.work, self.allocations, 2)
            && self.abandoned_work <= self.work
            && self.abandoned_allocations <= self.allocations
            && observable_bytes.is_some_and(|bytes| {
                self.abandoned_bytes <= bytes
                    && self.live_persistent_bytes <= bytes
                    && self
                        .abandoned_bytes
                        .checked_add(self.live_persistent_bytes)
                        .is_some_and(|retained| retained <= bytes)
            })
            && self.live_persistent_bytes <= self.high_water_bytes
    }

    /// Componentwise containment of one cumulative actual.
    #[must_use]
    pub fn contains(self, actual: AggregateConstructionActual) -> bool {
        self.is_well_formed()
            && actual.is_well_formed()
            && actual.work <= self.work
            && actual.allocations <= self.allocations
            && actual.allocated_bytes <= self.allocated_bytes
            && actual.copied_bytes <= self.copied_bytes
            && actual.initialized_bytes <= self.initialized_bytes
            && actual.abandoned_work <= self.abandoned_work
            && actual.abandoned_allocations <= self.abandoned_allocations
            && actual.abandoned_bytes <= self.abandoned_bytes
            && actual.live_persistent_bytes <= self.live_persistent_bytes
            && actual.high_water_bytes <= self.high_water_bytes
    }
}

/// Exact controlled effect completed by one selector stage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateConstructionEffect {
    /// Newly charged construction/inspection work.
    pub work: u64,
    /// Newly successful controlled allocations.
    pub allocations: usize,
    /// Bytes from those successful allocations.
    pub allocated_bytes: usize,
    /// Newly copied bytes.
    pub copied_bytes: usize,
    /// Newly initialized heap or inline bytes.
    pub initialized_bytes: usize,
    /// Newly retained persistent bytes still live after the effect.
    pub retained_persistent_bytes: usize,
    /// Persistent bytes from earlier completed stages released normally by
    /// this effect. This is distinct from fallback abandonment: a staging
    /// owner may be consumed by the selected successor on the success path.
    pub released_persistent_bytes: usize,
    /// Maximum additional bytes co-live with the prior persistent state.
    ///
    /// This includes `retained_persistent_bytes` plus any temporary bytes live
    /// at the effect's peak. It is independent of cumulative byte counters so
    /// a nested exact peak never requires fabricated allocation accounting.
    pub co_live_bytes: usize,
}

impl AggregateConstructionEffect {
    fn is_zero(self) -> bool {
        self == Self::default()
    }

    fn is_well_formed(self) -> bool {
        // Every lower-layer controlled allocation is preceded by at least
        // one charged work unit. The single per-effect slack admits only the
        // allocation-backed source owner or cache-key owner, whose creation
        // is itself the stage boundary being recorded.
        allocations_fit_charged_work(self.work, self.allocations, 1)
            && self
                .allocated_bytes
                .checked_add(self.initialized_bytes)
                .is_some_and(|bytes| self.retained_persistent_bytes <= bytes)
            && self
                .retained_persistent_bytes
                .saturating_sub(self.released_persistent_bytes)
                <= self.co_live_bytes
    }
}

/// Exact cumulative effects abandoned by one declared fallback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateConstructionAbandonment {
    /// Previously charged work that will not contribute to the selected plan.
    pub work: u64,
    /// Previously successful allocations being abandoned.
    pub allocations: usize,
    /// Previously allocated or inline initialized bytes being abandoned.
    pub bytes: usize,
    /// Live persistent bytes released by this fallback.
    pub released_persistent_bytes: usize,
}

impl AggregateConstructionAbandonment {
    fn is_zero(self) -> bool {
        self == Self::default()
    }
}

/// Exact cumulative construction effects through a terminal point.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AggregateConstructionActual {
    /// Charged construction and inspection work.
    pub work: u64,
    /// Successful controlled allocation count.
    pub allocations: usize,
    /// Total successfully allocated bytes.
    pub allocated_bytes: usize,
    /// Total observed copied bytes.
    pub copied_bytes: usize,
    /// Total observed initialized heap or inline bytes.
    pub initialized_bytes: usize,
    /// Cumulative work abandoned across fallbacks.
    pub abandoned_work: u64,
    /// Cumulative allocations abandoned across fallbacks.
    pub abandoned_allocations: usize,
    /// Cumulative heap-allocated or inline initialized bytes abandoned across
    /// fallbacks.
    pub abandoned_bytes: usize,
    /// Persistent bytes currently live.
    pub live_persistent_bytes: usize,
    /// Maximum co-live construction bytes reached so far. This is an
    /// independently observed dimension, not a reconstruction from the
    /// cumulative byte counters above.
    pub high_water_bytes: usize,
}

impl AggregateConstructionActual {
    /// Check structural relations between cumulative, abandoned, live, and
    /// co-live actual counters.
    #[must_use]
    pub fn is_well_formed(self) -> bool {
        let observable_bytes = self.allocated_bytes.checked_add(self.initialized_bytes);
        // Exactly two allocation-only owners may exist in a complete
        // construction: the stable source owner and the cache-key Arc.
        // Every kernel/compiler allocation is charged by lower-layer work.
        allocations_fit_charged_work(self.work, self.allocations, 2)
            && self.abandoned_work <= self.work
            && self.abandoned_allocations <= self.allocations
            && observable_bytes.is_some_and(|bytes| {
                self.abandoned_bytes <= bytes
                    && self.live_persistent_bytes <= bytes
                    && self
                        .abandoned_bytes
                        .checked_add(self.live_persistent_bytes)
                        .is_some_and(|retained| retained <= bytes)
            })
            && self.live_persistent_bytes <= self.high_water_bytes
    }

    /// Checked application of one stage effect.
    pub fn checked_apply(
        self,
        effect: AggregateConstructionEffect,
    ) -> Result<Self, AggregateConstructionStateError> {
        if !self.is_well_formed() || !effect.is_well_formed() {
            return Err(AggregateConstructionStateError::InvalidAccounting);
        }
        let work = self
            .work
            .checked_add(effect.work)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let allocations = self
            .allocations
            .checked_add(effect.allocations)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let allocated_bytes = self
            .allocated_bytes
            .checked_add(effect.allocated_bytes)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let copied_bytes = self
            .copied_bytes
            .checked_add(effect.copied_bytes)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let initialized_bytes = self
            .initialized_bytes
            .checked_add(effect.initialized_bytes)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        if effect.released_persistent_bytes > self.live_persistent_bytes {
            return Err(AggregateConstructionStateError::InvalidAccounting);
        }
        let live_persistent_bytes = self
            .live_persistent_bytes
            .checked_sub(effect.released_persistent_bytes)
            .and_then(|bytes| bytes.checked_add(effect.retained_persistent_bytes))
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let co_live = self
            .live_persistent_bytes
            .checked_add(effect.co_live_bytes)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let next = Self {
            work,
            allocations,
            allocated_bytes,
            copied_bytes,
            initialized_bytes,
            live_persistent_bytes,
            high_water_bytes: self.high_water_bytes.max(co_live),
            ..self
        };
        if next.is_well_formed() {
            Ok(next)
        } else {
            Err(AggregateConstructionStateError::InvalidAccounting)
        }
    }

    /// Checked abandonment and release of already charged effects.
    pub fn checked_abandon(
        self,
        abandonment: AggregateConstructionAbandonment,
    ) -> Result<Self, AggregateConstructionStateError> {
        if !self.is_well_formed()
            || abandonment.work > self.work
            || abandonment.allocations > self.allocations
            || self
                .allocated_bytes
                .checked_add(self.initialized_bytes)
                .is_none_or(|bytes| abandonment.bytes > bytes)
            || abandonment.released_persistent_bytes > abandonment.bytes
            || abandonment.released_persistent_bytes > self.live_persistent_bytes
        {
            return Err(AggregateConstructionStateError::InvalidAccounting);
        }
        let abandoned_work = self
            .abandoned_work
            .checked_add(abandonment.work)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let abandoned_allocations = self
            .abandoned_allocations
            .checked_add(abandonment.allocations)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let abandoned_bytes = self
            .abandoned_bytes
            .checked_add(abandonment.bytes)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let live_persistent_bytes = self
            .live_persistent_bytes
            .checked_sub(abandonment.released_persistent_bytes)
            .ok_or(AggregateConstructionStateError::ArithmeticOverflow)?;
        let next = Self {
            abandoned_work,
            abandoned_allocations,
            abandoned_bytes,
            live_persistent_bytes,
            ..self
        };
        if next.is_well_formed() {
            Ok(next)
        } else {
            Err(AggregateConstructionStateError::InvalidAccounting)
        }
    }

    fn is_monotone_successor_of(self, earlier: Self) -> bool {
        self.work >= earlier.work
            && self.allocations >= earlier.allocations
            && self.allocated_bytes >= earlier.allocated_bytes
            && self.copied_bytes >= earlier.copied_bytes
            && self.initialized_bytes >= earlier.initialized_bytes
            && self.abandoned_work >= earlier.abandoned_work
            && self.abandoned_allocations >= earlier.abandoned_allocations
            && self.abandoned_bytes >= earlier.abandoned_bytes
            && self.high_water_bytes >= earlier.high_water_bytes
    }
}

/// One resolved or transient stage record in the fixed-capacity ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateConstructionLedgerEntry {
    /// Visited selector stage.
    pub stage: AggregateConstructionStage,
    /// Stage disposition.
    pub disposition: AggregateConstructionStageDisposition,
    /// Typed fallback or declared semantic-transition reason.
    pub fallback: AggregateConstructionPrepublicationFallback,
    /// Exact outgoing selector edge.
    pub transition: AggregateConstructionTransition,
    /// Effects charged by this stage.
    pub effect: AggregateConstructionEffect,
    /// Effects abandoned by this stage's fallback.
    pub abandonment: AggregateConstructionAbandonment,
    /// Exact cumulative actual after this stage.
    pub actual: AggregateConstructionActual,
}

/// Inline, allocation-free construction-stage ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateConstructionLedger {
    entries: [Option<AggregateConstructionLedgerEntry>; AGGREGATE_CONSTRUCTION_LEDGER_CAPACITY],
    len: u8,
}

impl Default for AggregateConstructionLedger {
    fn default() -> Self {
        Self {
            entries: [None; AGGREGATE_CONSTRUCTION_LEDGER_CAPACITY],
            len: 0,
        }
    }
}

impl AggregateConstructionLedger {
    /// Number of retained stage records.
    #[must_use]
    #[allow(clippy::as_conversions, reason = "u8 ledger length always fits usize")]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the ledger is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// One retained entry by chronological index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&AggregateConstructionLedgerEntry> {
        (index < self.len())
            .then(|| self.entries[index].as_ref())
            .flatten()
    }

    /// Retained entries in chronological order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &AggregateConstructionLedgerEntry> {
        self.entries[..self.len()]
            .iter()
            .map(|entry| entry.as_ref().expect("retained ledger prefix is populated"))
    }

    fn push(
        &mut self,
        entry: AggregateConstructionLedgerEntry,
    ) -> Result<(), AggregateConstructionStateError> {
        let index = self.len();
        let slot = self
            .entries
            .get_mut(index)
            .ok_or(AggregateConstructionStateError::LedgerFull)?;
        *slot = Some(entry);
        self.len = self
            .len
            .checked_add(1)
            .ok_or(AggregateConstructionStateError::LedgerFull)?;
        Ok(())
    }

    fn last_mut(&mut self) -> Option<&mut AggregateConstructionLedgerEntry> {
        self.len()
            .checked_sub(1)
            .and_then(|index| self.entries[index].as_mut())
    }

    fn validates(
        &self,
        final_actual: AggregateConstructionActual,
        terminal: AggregateConstructionTerminal,
    ) -> bool {
        let len = self.len();
        if len > AGGREGATE_CONSTRUCTION_LEDGER_CAPACITY
            || self.entries[..len].iter().any(Option::is_none)
            || self.entries[len..].iter().any(Option::is_some)
        {
            return false;
        }
        let mut expected = Some(AggregateConstructionStage::ORDER[0]);
        let mut actual = AggregateConstructionActual::default();
        for (index, entry) in self.iter().enumerate() {
            if Some(entry.stage) != expected
                || !entry.actual.is_monotone_successor_of(actual)
                || entry.disposition == AggregateConstructionStageDisposition::Selected
            {
                return false;
            }
            let Ok(after_effect) = actual.checked_apply(entry.effect) else {
                return false;
            };
            let Ok(after_abandonment) = after_effect.checked_abandon(entry.abandonment) else {
                return false;
            };
            if after_abandonment != entry.actual
                || !entry_shape_is_valid(entry)
                || matches!(
                    entry.transition,
                    AggregateConstructionTransition::HardTerminal
                        | AggregateConstructionTransition::Published
                ) && index.checked_add(1) != Some(self.len())
            {
                return false;
            }
            actual = entry.actual;
            expected = entry.transition.target();
        }
        let last = self.get(self.len().saturating_sub(1));
        actual == final_actual
            && match terminal {
                AggregateConstructionTerminal::Success => last.is_some_and(|entry| {
                    entry.disposition == AggregateConstructionStageDisposition::Published
                        && entry.transition == AggregateConstructionTransition::Published
                }),
                AggregateConstructionTerminal::Failure => last.is_some_and(|entry| {
                    entry.disposition == AggregateConstructionStageDisposition::HardTerminal
                        && entry.transition == AggregateConstructionTransition::HardTerminal
                }),
            }
    }
}

fn entry_shape_is_valid(entry: &AggregateConstructionLedgerEntry) -> bool {
    let no_fallback = entry.fallback == AggregateConstructionPrepublicationFallback::None;
    match entry.disposition {
        AggregateConstructionStageDisposition::PolicySkipped => {
            no_fallback
                && entry.effect.is_zero()
                && entry.abandonment.is_zero()
                && entry.transition
                    == entry
                        .stage
                        .next()
                        .map_or(AggregateConstructionTransition::HardTerminal, |next| {
                            AggregateConstructionTransition::Advance(next)
                        })
        }
        AggregateConstructionStageDisposition::SemanticIneligible => {
            entry.effect.work > 0
                && entry.abandonment.is_zero()
                && if entry.fallback
                    == AggregateConstructionPrepublicationFallback::TooLargeFixedSequenceToFixedPredicateWord64
                {
                    entry.stage == AggregateConstructionStage::GeneralFiniteExtraction
                        && entry.transition
                            == AggregateConstructionTransition::TooLargeFixedSequenceToFixedPredicateWord64
                } else {
                    no_fallback
                        && entry.stage.next().is_some_and(|next| {
                            entry.transition == AggregateConstructionTransition::Advance(next)
                        })
                }
        }
        AggregateConstructionStageDisposition::Completed => {
            no_fallback
                && entry.abandonment.is_zero()
                && entry.stage.next().is_some_and(|next| {
                    entry.transition == AggregateConstructionTransition::Advance(next)
                })
        }
        AggregateConstructionStageDisposition::Selected => {
            no_fallback
                && entry.transition == AggregateConstructionTransition::Selected
                && entry.effect.is_zero()
                && entry.abandonment.is_zero()
        }
        AggregateConstructionStageDisposition::SoftResourceRefused => {
            !no_fallback
                && entry.fallback
                    != AggregateConstructionPrepublicationFallback::TooLargeFixedSequenceToFixedPredicateWord64
                && entry.fallback.source_stage() == Some(entry.stage)
                && entry.fallback.transition() == Some(entry.transition)
        }
        AggregateConstructionStageDisposition::HardTerminal => {
            no_fallback
                && entry.transition == AggregateConstructionTransition::HardTerminal
                && entry.abandonment.is_zero()
        }
        AggregateConstructionStageDisposition::Published => {
            no_fallback
                && entry.transition == AggregateConstructionTransition::Published
                && entry.abandonment.is_zero()
        }
    }
}

/// Terminal disposition authenticated by a construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateConstructionTerminal {
    /// Exactly one selected plan was published.
    Success,
    /// Construction terminated without publishing a plan.
    Failure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AggregateConstructionPublicationState {
    Unpublished,
    Published(AggregateConstructionStage),
}

/// Allocation-free transaction state error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateConstructionStateError {
    /// Prospective accounting was already published.
    ProspectiveAlreadyPublished,
    /// A nonzero controlled effect was attempted before prospective
    /// publication.
    EffectBeforeProspective,
    /// A prospective or actual accounting relation is invalid.
    InvalidAccounting,
    /// A checked accounting operation overflowed.
    ArithmeticOverflow,
    /// Cumulative actual accounting exceeded the published prospective.
    ActualExceedsProspective,
    /// The fixed inline ledger is full.
    LedgerFull,
    /// A stage was visited outside the authenticated selector order.
    UnexpectedStage {
        /// Required next stage.
        expected: AggregateConstructionStage,
        /// Supplied stage.
        actual: AggregateConstructionStage,
    },
    /// A selected stage must be resolved before another transition.
    SelectedStagePending,
    /// No selected stage exists for this resolution.
    StageNotSelected,
    /// A disposition/fallback combination is not admitted.
    InvalidTransition,
    /// The selected plan owner belongs to another stage.
    PlanStageMismatch,
    /// The transaction is already published or terminal.
    AttemptTerminal,
    /// Success was requested without publication, or failure without a hard
    /// terminal.
    InvalidTerminal,
}

/// Mutable construction transaction used only before receipt publication.
pub struct AggregateConstructionAttempt<Request, Plan> {
    identity: AggregateConstructionAttemptIdentity<Request>,
    prospective: Option<AggregateConstructionProspective>,
    request_provenance_bound: bool,
    actual: AggregateConstructionActual,
    ledger: AggregateConstructionLedger,
    expected_stage: Option<AggregateConstructionStage>,
    selected_stage: Option<AggregateConstructionStage>,
    publication_state: AggregateConstructionPublicationState,
    published_plan: Option<AggregateConstructionSelectedPlanOwnerSeal<Plan>>,
    hard_terminal: bool,
}

impl<Request, Plan> fmt::Debug for AggregateConstructionAttempt<Request, Plan> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AggregateConstructionAttempt")
            .field(
                "explain_schema_version",
                &self.identity.explain_schema_version,
            )
            .field("algorithm_version", &self.identity.algorithm_version)
            .field("accounting_version", &self.identity.accounting_version)
            .field("prospective", &self.prospective)
            .field("request_provenance_bound", &self.request_provenance_bound)
            .field("actual", &self.actual)
            .field("ledger_len", &self.ledger.len())
            .field("expected_stage", &self.expected_stage)
            .field("selected_stage", &self.selected_stage)
            .field("publication_state", &self.publication_state)
            .field("has_published_plan", &self.published_plan.is_some())
            .field("hard_terminal", &self.hard_terminal)
            .finish_non_exhaustive()
    }
}

impl<Request, Plan> AggregateConstructionAttempt<Request, Plan> {
    /// Start one unpublished transaction with no prospective or actual.
    #[must_use]
    pub fn new(identity: AggregateConstructionAttemptIdentity<Request>) -> Self {
        Self {
            identity,
            prospective: None,
            request_provenance_bound: false,
            actual: AggregateConstructionActual::default(),
            ledger: AggregateConstructionLedger::default(),
            expected_stage: Some(AggregateConstructionStage::ORDER[0]),
            selected_stage: None,
            publication_state: AggregateConstructionPublicationState::Unpublished,
            published_plan: None,
            hard_terminal: false,
        }
    }

    /// Current cumulative actual accounting.
    #[must_use]
    pub const fn actual(&self) -> AggregateConstructionActual {
        self.actual
    }

    /// Published prospective, if publication has occurred.
    #[must_use]
    pub const fn prospective(&self) -> Option<AggregateConstructionProspective> {
        self.prospective
    }

    /// Current fixed-capacity stage ledger.
    #[must_use]
    pub const fn ledger(&self) -> &AggregateConstructionLedger {
        &self.ledger
    }

    /// Next stage required by the authenticated selector order.
    #[must_use]
    pub const fn expected_stage(&self) -> Option<AggregateConstructionStage> {
        self.expected_stage
    }

    /// Stage selected and awaiting publication or terminal resolution.
    #[must_use]
    pub const fn selected_stage(&self) -> Option<AggregateConstructionStage> {
        self.selected_stage
    }

    /// Publish the complete prospective exactly once.
    pub fn publish_prospective(
        &mut self,
        prospective: AggregateConstructionProspective,
    ) -> Result<(), AggregateConstructionStateError> {
        self.ensure_unpublished()?;
        if self.prospective.is_some() {
            return Err(AggregateConstructionStateError::ProspectiveAlreadyPublished);
        }
        if !prospective.is_well_formed() || !prospective.contains(self.actual) {
            return Err(AggregateConstructionStateError::InvalidAccounting);
        }
        self.prospective = Some(prospective);
        Ok(())
    }

    /// Bind construction-owned request provenance after P publication and
    /// before the first ledger effect. This narrow seam exists so the facade
    /// can charge a stable source-owner allocation instead of allocating it
    /// before P.
    pub(crate) fn request_mut_after_prospective(
        &mut self,
    ) -> Result<&mut Request, AggregateConstructionStateError> {
        self.ensure_unpublished()?;
        if self.prospective.is_none()
            || !self.ledger.is_empty()
            || self.actual != AggregateConstructionActual::default()
            || self.selected_stage.is_some()
            || self.hard_terminal
            || self.request_provenance_bound
        {
            return Err(AggregateConstructionStateError::InvalidTransition);
        }
        self.request_provenance_bound = true;
        Ok(self.identity.request_owner.request_mut())
    }

    /// Record a policy skip with no semantic inspection or controlled effect.
    pub fn record_policy_skip(
        &mut self,
        stage: AggregateConstructionStage,
    ) -> Result<(), AggregateConstructionStateError> {
        self.record_unselected(
            stage,
            AggregateConstructionStageDisposition::PolicySkipped,
            AggregateConstructionEffect::default(),
            AggregateConstructionPrepublicationFallback::None,
        )
    }

    /// Record an inspected but semantically ineligible route.
    pub fn record_semantic_ineligible(
        &mut self,
        stage: AggregateConstructionStage,
        effect: AggregateConstructionEffect,
    ) -> Result<(), AggregateConstructionStateError> {
        self.record_unselected(
            stage,
            AggregateConstructionStageDisposition::SemanticIneligible,
            effect,
            AggregateConstructionPrepublicationFallback::None,
        )
    }

    /// Record a successful intermediate stage and its exact effects.
    pub fn record_completed(
        &mut self,
        stage: AggregateConstructionStage,
        effect: AggregateConstructionEffect,
    ) -> Result<(), AggregateConstructionStateError> {
        self.record_unselected(
            stage,
            AggregateConstructionStageDisposition::Completed,
            effect,
            AggregateConstructionPrepublicationFallback::None,
        )
    }

    /// Record `TooLargeFixedSequence` as its separately typed semantic edge.
    pub fn record_too_large_fixed_sequence(
        &mut self,
        effect: AggregateConstructionEffect,
    ) -> Result<(), AggregateConstructionStateError> {
        self.record_unselected(
            AggregateConstructionStage::GeneralFiniteExtraction,
            AggregateConstructionStageDisposition::SemanticIneligible,
            effect,
            AggregateConstructionPrepublicationFallback::TooLargeFixedSequenceToFixedPredicateWord64,
        )
    }

    /// Record an unselected hard terminal, including pre-syntax failure.
    pub fn record_hard_terminal(
        &mut self,
        stage: AggregateConstructionStage,
        effect: AggregateConstructionEffect,
    ) -> Result<(), AggregateConstructionStateError> {
        self.record_unselected(
            stage,
            AggregateConstructionStageDisposition::HardTerminal,
            effect,
            AggregateConstructionPrepublicationFallback::None,
        )
    }

    /// Mark the expected stage as semantically selected before build.
    pub fn select_stage(
        &mut self,
        stage: AggregateConstructionStage,
    ) -> Result<(), AggregateConstructionStateError> {
        self.ensure_unpublished()?;
        self.require_expected(stage)?;
        if self.selected_stage.is_some() {
            return Err(AggregateConstructionStateError::SelectedStagePending);
        }
        self.ledger.push(AggregateConstructionLedgerEntry {
            stage,
            disposition: AggregateConstructionStageDisposition::Selected,
            fallback: AggregateConstructionPrepublicationFallback::None,
            transition: AggregateConstructionTransition::Selected,
            effect: AggregateConstructionEffect::default(),
            abandonment: AggregateConstructionAbandonment::default(),
            actual: self.actual,
        })?;
        self.selected_stage = Some(stage);
        Ok(())
    }

    /// Resolve the selected stage as a typed soft resource refusal.
    pub fn resolve_selected_soft_refusal(
        &mut self,
        effect: AggregateConstructionEffect,
        abandonment: AggregateConstructionAbandonment,
        fallback: AggregateConstructionPrepublicationFallback,
    ) -> Result<(), AggregateConstructionStateError> {
        self.ensure_unpublished()?;
        let stage = self
            .selected_stage
            .ok_or(AggregateConstructionStateError::StageNotSelected)?;
        let Some(transition) = fallback.transition() else {
            return Err(AggregateConstructionStateError::InvalidTransition);
        };
        if fallback.source_stage() != Some(stage)
            || fallback
                == AggregateConstructionPrepublicationFallback::TooLargeFixedSequenceToFixedPredicateWord64
        {
            return Err(AggregateConstructionStateError::InvalidTransition);
        }
        let actual = self.apply(effect, abandonment)?;
        self.resolve_selected_entry(
            AggregateConstructionStageDisposition::SoftResourceRefused,
            fallback,
            transition,
            effect,
            abandonment,
            actual,
        )?;
        self.actual = actual;
        self.selected_stage = None;
        self.expected_stage = transition.target();
        Ok(())
    }

    /// Resolve the selected stage as a hard terminal.
    pub fn resolve_selected_hard_terminal(
        &mut self,
        effect: AggregateConstructionEffect,
    ) -> Result<(), AggregateConstructionStateError> {
        self.ensure_unpublished()?;
        if self.selected_stage.is_none() {
            return Err(AggregateConstructionStateError::StageNotSelected);
        }
        let abandonment = AggregateConstructionAbandonment::default();
        let actual = self.apply(effect, abandonment)?;
        self.resolve_selected_entry(
            AggregateConstructionStageDisposition::HardTerminal,
            AggregateConstructionPrepublicationFallback::None,
            AggregateConstructionTransition::HardTerminal,
            effect,
            abandonment,
            actual,
        )?;
        self.actual = actual;
        self.selected_stage = None;
        self.expected_stage = None;
        self.hard_terminal = true;
        Ok(())
    }

    /// Terminate whichever stage currently owns construction control.
    ///
    /// A pending selected stage is resolved in place so the ledger retains
    /// its selection provenance. Otherwise the exact expected unselected
    /// stage receives the hard terminal. Published and already-terminal
    /// attempts reject this operation.
    pub fn terminate_current(
        &mut self,
        effect: AggregateConstructionEffect,
    ) -> Result<(), AggregateConstructionStateError> {
        self.ensure_unpublished()?;
        if self.selected_stage.is_some() {
            self.resolve_selected_hard_terminal(effect)
        } else {
            let stage = self
                .expected_stage
                .ok_or(AggregateConstructionStateError::AttemptTerminal)?;
            self.record_hard_terminal(stage, effect)
        }
    }

    /// Irreversibly publish the selected plan exactly once.
    pub fn publish_selected(
        &mut self,
        effect: AggregateConstructionEffect,
        plan: AggregateConstructionSelectedPlanOwnerSeal<Plan>,
    ) -> Result<(), AggregateConstructionStateError> {
        self.ensure_unpublished()?;
        let stage = self
            .selected_stage
            .ok_or(AggregateConstructionStateError::StageNotSelected)?;
        if plan.stage() != stage {
            return Err(AggregateConstructionStateError::PlanStageMismatch);
        }
        let abandonment = AggregateConstructionAbandonment::default();
        let actual = self.apply(effect, abandonment)?;
        self.resolve_selected_entry(
            AggregateConstructionStageDisposition::Published,
            AggregateConstructionPrepublicationFallback::None,
            AggregateConstructionTransition::Published,
            effect,
            abandonment,
            actual,
        )?;
        self.actual = actual;
        self.selected_stage = None;
        self.expected_stage = None;
        self.publication_state = AggregateConstructionPublicationState::Published(stage);
        self.published_plan = Some(plan);
        Ok(())
    }

    /// Validate and materialize the exact receipt that the next successful
    /// publication would produce without changing this transaction.
    ///
    /// This narrow prepublication seam lets a construction-owned artifact
    /// initialize circular closure storage before the one-way publication
    /// transition. The caller must publish the same effect and plan next and
    /// authenticate equality with the returned receipt.
    pub(crate) fn preview_success(
        &self,
        effect: AggregateConstructionEffect,
        plan: AggregateConstructionSelectedPlanOwnerSeal<Plan>,
    ) -> Result<AggregateConstructionAttemptReceipt<Request, Plan>, AggregateConstructionStateError>
    where
        Request: Clone,
        Plan: Clone,
    {
        self.ensure_unpublished()?;
        let mut preview = Self {
            identity: self.identity.clone(),
            prospective: self.prospective,
            request_provenance_bound: self.request_provenance_bound,
            actual: self.actual,
            ledger: self.ledger.clone(),
            expected_stage: self.expected_stage,
            selected_stage: self.selected_stage,
            publication_state: self.publication_state,
            published_plan: self.published_plan.clone(),
            hard_terminal: self.hard_terminal,
        };
        preview.publish_selected(effect, plan)?;
        preview.finish_success()
    }

    /// Finish a successfully published transaction.
    pub fn finish_success(
        self,
    ) -> Result<AggregateConstructionAttemptReceipt<Request, Plan>, AggregateConstructionStateError>
    {
        let AggregateConstructionPublicationState::Published(_) = self.publication_state else {
            return Err(AggregateConstructionStateError::InvalidTerminal);
        };
        self.finish(AggregateConstructionTerminal::Success)
    }

    /// Finish a hard-terminal unpublished transaction.
    pub fn finish_failure(
        self,
    ) -> Result<AggregateConstructionAttemptReceipt<Request, Plan>, AggregateConstructionStateError>
    {
        if !self.hard_terminal
            || self.publication_state != AggregateConstructionPublicationState::Unpublished
        {
            return Err(AggregateConstructionStateError::InvalidTerminal);
        }
        self.finish(AggregateConstructionTerminal::Failure)
    }

    fn ensure_unpublished(&self) -> Result<(), AggregateConstructionStateError> {
        if self.publication_state != AggregateConstructionPublicationState::Unpublished
            || self.hard_terminal
        {
            Err(AggregateConstructionStateError::AttemptTerminal)
        } else {
            Ok(())
        }
    }

    fn require_expected(
        &self,
        stage: AggregateConstructionStage,
    ) -> Result<(), AggregateConstructionStateError> {
        if self.selected_stage.is_some() {
            return Err(AggregateConstructionStateError::SelectedStagePending);
        }
        let Some(expected) = self.expected_stage else {
            return Err(AggregateConstructionStateError::AttemptTerminal);
        };
        if expected == stage {
            Ok(())
        } else {
            Err(AggregateConstructionStateError::UnexpectedStage {
                expected,
                actual: stage,
            })
        }
    }

    fn record_unselected(
        &mut self,
        stage: AggregateConstructionStage,
        disposition: AggregateConstructionStageDisposition,
        effect: AggregateConstructionEffect,
        fallback: AggregateConstructionPrepublicationFallback,
    ) -> Result<(), AggregateConstructionStateError> {
        self.ensure_unpublished()?;
        self.require_expected(stage)?;
        let transition = match (disposition, fallback) {
            (
                AggregateConstructionStageDisposition::PolicySkipped
                | AggregateConstructionStageDisposition::SemanticIneligible
                | AggregateConstructionStageDisposition::Completed,
                AggregateConstructionPrepublicationFallback::None,
            ) => stage
                .next()
                .map(AggregateConstructionTransition::Advance)
                .ok_or(AggregateConstructionStateError::InvalidTransition)?,
            (
                AggregateConstructionStageDisposition::SemanticIneligible,
                AggregateConstructionPrepublicationFallback::TooLargeFixedSequenceToFixedPredicateWord64,
            ) if stage == AggregateConstructionStage::GeneralFiniteExtraction => {
                AggregateConstructionTransition::TooLargeFixedSequenceToFixedPredicateWord64
            }
            (
                AggregateConstructionStageDisposition::HardTerminal,
                AggregateConstructionPrepublicationFallback::None,
            ) => AggregateConstructionTransition::HardTerminal,
            _ => return Err(AggregateConstructionStateError::InvalidTransition),
        };
        if disposition == AggregateConstructionStageDisposition::PolicySkipped && !effect.is_zero()
        {
            return Err(AggregateConstructionStateError::InvalidTransition);
        }
        let abandonment = AggregateConstructionAbandonment::default();
        let actual = self.apply(effect, abandonment)?;
        let entry = AggregateConstructionLedgerEntry {
            stage,
            disposition,
            fallback,
            transition,
            effect,
            abandonment,
            actual,
        };
        if !entry_shape_is_valid(&entry) {
            return Err(AggregateConstructionStateError::InvalidTransition);
        }
        self.ledger.push(entry)?;
        self.actual = actual;
        self.expected_stage = transition.target();
        if disposition == AggregateConstructionStageDisposition::HardTerminal {
            self.hard_terminal = true;
        }
        Ok(())
    }

    fn apply(
        &self,
        effect: AggregateConstructionEffect,
        abandonment: AggregateConstructionAbandonment,
    ) -> Result<AggregateConstructionActual, AggregateConstructionStateError> {
        if self.prospective.is_none() && (!effect.is_zero() || !abandonment.is_zero()) {
            return Err(AggregateConstructionStateError::EffectBeforeProspective);
        }
        let actual = self
            .actual
            .checked_apply(effect)?
            .checked_abandon(abandonment)?;
        if self
            .prospective
            .is_some_and(|prospective| !prospective.contains(actual))
        {
            return Err(AggregateConstructionStateError::ActualExceedsProspective);
        }
        Ok(actual)
    }

    fn resolve_selected_entry(
        &mut self,
        disposition: AggregateConstructionStageDisposition,
        fallback: AggregateConstructionPrepublicationFallback,
        transition: AggregateConstructionTransition,
        effect: AggregateConstructionEffect,
        abandonment: AggregateConstructionAbandonment,
        actual: AggregateConstructionActual,
    ) -> Result<(), AggregateConstructionStateError> {
        let stage = self
            .selected_stage
            .ok_or(AggregateConstructionStateError::StageNotSelected)?;
        let entry = self
            .ledger
            .last_mut()
            .ok_or(AggregateConstructionStateError::StageNotSelected)?;
        if entry.stage != stage
            || entry.disposition != AggregateConstructionStageDisposition::Selected
            || entry.transition != AggregateConstructionTransition::Selected
            || entry.actual != self.actual
        {
            return Err(AggregateConstructionStateError::InvalidTransition);
        }
        *entry = AggregateConstructionLedgerEntry {
            stage,
            disposition,
            fallback,
            transition,
            effect,
            abandonment,
            actual,
        };
        if entry_shape_is_valid(entry) {
            Ok(())
        } else {
            Err(AggregateConstructionStateError::InvalidTransition)
        }
    }

    fn finish(
        self,
        terminal: AggregateConstructionTerminal,
    ) -> Result<AggregateConstructionAttemptReceipt<Request, Plan>, AggregateConstructionStateError>
    {
        if self.selected_stage.is_some()
            || !self.ledger.validates(self.actual, terminal)
            || self.prospective.is_none() && self.actual != AggregateConstructionActual::default()
        {
            return Err(AggregateConstructionStateError::InvalidTerminal);
        }
        Ok(AggregateConstructionAttemptReceipt {
            identity: self.identity,
            prospective: self.prospective,
            actual: self.actual,
            ledger: self.ledger,
            published_stage: match self.publication_state {
                AggregateConstructionPublicationState::Unpublished => None,
                AggregateConstructionPublicationState::Published(stage) => Some(stage),
            },
            published_plan: self.published_plan,
            authenticated_prospective: self.prospective,
            publication_state: self.publication_state,
            authenticated_terminal: terminal,
            terminal,
        })
    }
}

/// Closed receipt shared by aggregate construction success and terminal error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateConstructionAttemptReceipt<Request, Plan> {
    /// Exact request owner and protocol identity.
    pub identity: AggregateConstructionAttemptIdentity<Request>,
    /// Complete prospective, absent only for a pre-prospective terminal.
    pub prospective: Option<AggregateConstructionProspective>,
    /// Cumulative actual through success or terminal failure.
    pub actual: AggregateConstructionActual,
    /// Fixed-capacity typed selector ledger.
    pub ledger: AggregateConstructionLedger,
    /// Exactly one published stage on success.
    pub published_stage: Option<AggregateConstructionStage>,
    /// Pointer-exact selected plan owner on success.
    pub published_plan: Option<AggregateConstructionSelectedPlanOwnerSeal<Plan>>,
    authenticated_prospective: Option<AggregateConstructionProspective>,
    publication_state: AggregateConstructionPublicationState,
    authenticated_terminal: AggregateConstructionTerminal,
    /// Public terminal projection.
    pub terminal: AggregateConstructionTerminal,
}

impl<Request, Plan> AggregateConstructionAttemptReceipt<Request, Plan> {
    /// Authenticate exact request provenance, versions, P/A, typed ledger,
    /// one-shot publication, selected-plan provenance, and terminal state.
    #[must_use]
    pub fn closes(
        &self,
        expected_identity: &AggregateConstructionAttemptIdentity<Request>,
        expected_plan: Option<&AggregateConstructionSelectedPlanOwnerSeal<Plan>>,
    ) -> bool
    where
        Request: PartialEq,
        Plan: PartialEq,
    {
        if self.identity != *expected_identity
            || !self.identity.has_current_protocol()
            || self.authenticated_terminal != self.terminal
            || self.authenticated_prospective != self.prospective
            || !self.ledger.validates(self.actual, self.terminal)
            || match self.prospective {
                Some(prospective) => !prospective.contains(self.actual),
                None => self.actual != AggregateConstructionActual::default(),
            }
        {
            return false;
        }
        match (
            self.terminal,
            self.publication_state,
            self.published_stage,
            self.published_plan.as_ref(),
            expected_plan,
        ) {
            (
                AggregateConstructionTerminal::Success,
                AggregateConstructionPublicationState::Published(state_stage),
                Some(public_stage),
                Some(actual_plan),
                Some(expected_plan),
            ) => {
                state_stage == public_stage
                    && actual_plan.stage() == public_stage
                    && actual_plan == expected_plan
                    && self
                        .ledger
                        .get(self.ledger.len().saturating_sub(1))
                        .is_some_and(|entry| {
                            entry.stage == public_stage
                                && entry.disposition
                                    == AggregateConstructionStageDisposition::Published
                        })
            }
            (
                AggregateConstructionTerminal::Failure,
                AggregateConstructionPublicationState::Unpublished,
                None,
                None,
                None,
            ) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type RequestInputs =
        AggregateConstructionRequestInputs<String, u8, u8, u8, &'static str, [usize; 3]>;
    type Attempt = AggregateConstructionAttempt<RequestInputs, &'static str>;
    type Identity = AggregateConstructionAttemptIdentity<RequestInputs>;
    type PlanSeal = AggregateConstructionSelectedPlanOwnerSeal<&'static str>;

    fn identity(pattern: &str) -> Identity {
        let request = RequestInputs {
            syntax_request: pattern.to_string(),
            operation: 1,
            selection: 2,
            strategy: 3,
            profile: "rust-bytes",
            build_limits: [11, 13, 17],
        };
        AggregateConstructionAttemptIdentity::new(
            AggregateConstructionRequestOwnerSeal::from_owned(request),
            35,
        )
    }

    fn prospective() -> AggregateConstructionProspective {
        AggregateConstructionProspective {
            work: 1_000,
            allocations: 20,
            allocated_bytes: 1_000,
            copied_bytes: 1_000,
            initialized_bytes: 1_000,
            abandoned_work: 900,
            abandoned_allocations: 18,
            abandoned_bytes: 900,
            live_persistent_bytes: 100,
            high_water_bytes: 500,
        }
    }

    fn effect(
        work: u64,
        allocations: usize,
        bytes: usize,
        persistent: usize,
        co_live: usize,
    ) -> AggregateConstructionEffect {
        AggregateConstructionEffect {
            work,
            allocations,
            allocated_bytes: bytes,
            copied_bytes: bytes,
            initialized_bytes: bytes,
            retained_persistent_bytes: persistent,
            released_persistent_bytes: 0,
            co_live_bytes: co_live,
        }
    }

    fn advance_to(attempt: &mut Attempt, target: AggregateConstructionStage) {
        for stage in AggregateConstructionStage::ORDER {
            if stage == target {
                return;
            }
            if attempt.expected_stage == Some(stage) {
                attempt.record_policy_skip(stage).unwrap();
            }
        }
        panic!("target stage was not reached");
    }

    fn published_receipt(
        pattern: &str,
    ) -> (
        Identity,
        PlanSeal,
        AggregateConstructionAttemptReceipt<RequestInputs, &'static str>,
    ) {
        let identity = identity(pattern);
        let mut attempt = Attempt::new(identity.clone());
        attempt.publish_prospective(prospective()).unwrap();
        advance_to(&mut attempt, AggregateConstructionStage::ExactLiteral);
        attempt
            .select_stage(AggregateConstructionStage::ExactLiteral)
            .unwrap();
        let plan = PlanSeal::from_owned(AggregateConstructionStage::ExactLiteral, "exact-plan");
        attempt
            .publish_selected(effect(7, 1, 40, 30, 40), plan.clone())
            .unwrap();
        let receipt = attempt.finish_success().unwrap();
        (identity, plan, receipt)
    }

    #[test]
    fn exact_stage_order_is_pinned_and_enforced() {
        assert_eq!(
            AggregateConstructionStage::ORDER.len(),
            AGGREGATE_CONSTRUCTION_LEDGER_CAPACITY
        );
        for (ordinal, stage) in AggregateConstructionStage::ORDER.into_iter().enumerate() {
            assert_eq!(stage.ordinal(), ordinal);
            assert_eq!(
                stage.next(),
                AggregateConstructionStage::ORDER.get(ordinal + 1).copied()
            );
        }

        let mut attempt: Attempt = AggregateConstructionAttempt::new(identity("a"));
        assert_eq!(
            attempt.record_policy_skip(AggregateConstructionStage::ExactLiteral),
            Err(AggregateConstructionStateError::UnexpectedStage {
                expected: AggregateConstructionStage::PreSyntaxForceExactLiteralSpans,
                actual: AggregateConstructionStage::ExactLiteral,
            })
        );
        attempt
            .record_policy_skip(AggregateConstructionStage::PreSyntaxForceExactLiteralSpans)
            .unwrap();
        assert_eq!(
            attempt.ledger().get(0).unwrap().transition,
            AggregateConstructionTransition::Advance(
                AggregateConstructionStage::SyntaxParseAdmission
            )
        );
    }

    #[test]
    fn successful_intermediate_stages_advance_without_ineligibility() {
        let mut attempt: Attempt = AggregateConstructionAttempt::new(identity("intermediate"));
        attempt.publish_prospective(prospective()).unwrap();
        attempt
            .record_policy_skip(AggregateConstructionStage::PreSyntaxForceExactLiteralSpans)
            .unwrap();
        attempt
            .record_completed(
                AggregateConstructionStage::SyntaxParseAdmission,
                effect(3, 0, 0, 0, 0),
            )
            .unwrap();
        let syntax = attempt.ledger().get(1).unwrap();
        assert_eq!(
            syntax.disposition,
            AggregateConstructionStageDisposition::Completed
        );
        assert_eq!(syntax.actual.work, 3);
        assert_eq!(
            syntax.transition,
            AggregateConstructionTransition::Advance(AggregateConstructionStage::ExactLiteral)
        );

        advance_to(
            &mut attempt,
            AggregateConstructionStage::GeneralFiniteExtraction,
        );
        attempt
            .record_completed(
                AggregateConstructionStage::GeneralFiniteExtraction,
                effect(5, 0, 0, 0, 0),
            )
            .unwrap();
        let finite = attempt.ledger().get(attempt.ledger().len() - 1).unwrap();
        assert_eq!(
            finite.disposition,
            AggregateConstructionStageDisposition::Completed
        );
        assert_eq!(
            finite.transition,
            AggregateConstructionTransition::Advance(AggregateConstructionStage::DenseFinite)
        );
        assert_eq!(
            attempt.expected_stage,
            Some(AggregateConstructionStage::DenseFinite)
        );
    }

    #[test]
    fn zero_work_semantic_ineligibility_cannot_impersonate_a_policy_skip() {
        let mut attempt: Attempt = AggregateConstructionAttempt::new(identity("zero-refusal"));
        attempt.publish_prospective(prospective()).unwrap();
        advance_to(&mut attempt, AggregateConstructionStage::ExactLiteral);
        assert_eq!(
            attempt.record_semantic_ineligible(
                AggregateConstructionStage::ExactLiteral,
                AggregateConstructionEffect::default(),
            ),
            Err(AggregateConstructionStateError::InvalidTransition)
        );
        assert_eq!(
            attempt.expected_stage(),
            Some(AggregateConstructionStage::ExactLiteral)
        );
        attempt
            .record_policy_skip(AggregateConstructionStage::ExactLiteral)
            .unwrap();
        let entry = attempt.ledger().get(attempt.ledger().len() - 1).unwrap();
        assert_eq!(
            entry.disposition,
            AggregateConstructionStageDisposition::PolicySkipped
        );
        assert_eq!(entry.effect, AggregateConstructionEffect::default());
        assert_eq!(
            attempt.expected_stage(),
            Some(AggregateConstructionStage::UnicodeScalar)
        );
    }

    #[test]
    fn prospective_one_below_rejects_each_positive_actual_and_partial_actual_is_retained() {
        let actual = AggregateConstructionActual {
            work: 10,
            allocations: 4,
            allocated_bytes: 100,
            copied_bytes: 80,
            initialized_bytes: 90,
            abandoned_work: 3,
            abandoned_allocations: 1,
            abandoned_bytes: 20,
            live_persistent_bytes: 40,
            high_water_bytes: 70,
        };
        let exact = AggregateConstructionProspective {
            work: actual.work,
            allocations: actual.allocations,
            allocated_bytes: actual.allocated_bytes,
            copied_bytes: actual.copied_bytes,
            initialized_bytes: actual.initialized_bytes,
            abandoned_work: actual.abandoned_work,
            abandoned_allocations: actual.abandoned_allocations,
            abandoned_bytes: actual.abandoned_bytes,
            live_persistent_bytes: actual.live_persistent_bytes,
            high_water_bytes: actual.high_water_bytes,
        };
        assert!(exact.contains(actual));

        let one_below = [
            AggregateConstructionProspective {
                work: exact.work - 1,
                ..exact
            },
            AggregateConstructionProspective {
                allocations: exact.allocations - 1,
                ..exact
            },
            AggregateConstructionProspective {
                allocated_bytes: exact.allocated_bytes - 1,
                ..exact
            },
            AggregateConstructionProspective {
                copied_bytes: exact.copied_bytes - 1,
                ..exact
            },
            AggregateConstructionProspective {
                initialized_bytes: exact.initialized_bytes - 1,
                ..exact
            },
            AggregateConstructionProspective {
                abandoned_work: exact.abandoned_work - 1,
                ..exact
            },
            AggregateConstructionProspective {
                abandoned_allocations: exact.abandoned_allocations - 1,
                ..exact
            },
            AggregateConstructionProspective {
                abandoned_bytes: exact.abandoned_bytes - 1,
                ..exact
            },
            AggregateConstructionProspective {
                live_persistent_bytes: exact.live_persistent_bytes - 1,
                ..exact
            },
            AggregateConstructionProspective {
                high_water_bytes: exact.high_water_bytes - 1,
                ..exact
            },
        ];
        assert!(one_below.into_iter().all(|upper| !upper.contains(actual)));

        let partial = AggregateConstructionActual::default()
            .checked_apply(effect(4, 1, 50, 20, 35))
            .unwrap();
        assert_eq!(partial.work, 4);
        assert_eq!(partial.live_persistent_bytes, 20);
        assert_eq!(partial.high_water_bytes, 35);
        assert!(prospective().contains(partial));
    }

    #[test]
    fn independently_observed_peak_never_fabricates_cumulative_byte_counters() {
        let actual = AggregateConstructionActual::default()
            .checked_apply(AggregateConstructionEffect {
                work: 1,
                allocations: 0,
                allocated_bytes: 0,
                copied_bytes: 0,
                initialized_bytes: 32,
                retained_persistent_bytes: 32,
                released_persistent_bytes: 0,
                co_live_bytes: 96,
            })
            .unwrap();
        assert_eq!(actual.allocated_bytes, 0);
        assert_eq!(actual.initialized_bytes, 32);
        assert_eq!(actual.live_persistent_bytes, 32);
        assert_eq!(actual.high_water_bytes, 96);
        assert!(
            AggregateConstructionProspective {
                work: 1,
                allocations: 0,
                allocated_bytes: 0,
                copied_bytes: 0,
                initialized_bytes: 32,
                abandoned_work: 0,
                abandoned_allocations: 0,
                abandoned_bytes: 0,
                live_persistent_bytes: 32,
                high_water_bytes: 96,
            }
            .contains(actual)
        );
    }

    #[test]
    fn fallback_accumulates_abandoned_effects_and_co_live_high_water() {
        let mut attempt: Attempt = AggregateConstructionAttempt::new(identity("fallback"));
        attempt.publish_prospective(prospective()).unwrap();
        advance_to(&mut attempt, AggregateConstructionStage::FixedAbsolute);
        attempt
            .select_stage(AggregateConstructionStage::FixedAbsolute)
            .unwrap();
        attempt
            .resolve_selected_soft_refusal(
                effect(5, 1, 40, 10, 30),
                AggregateConstructionAbandonment {
                    work: 5,
                    allocations: 1,
                    bytes: 40,
                    released_persistent_bytes: 10,
                },
                AggregateConstructionPrepublicationFallback::FixedAbsoluteOptionalGuardResource,
            )
            .unwrap();
        assert_eq!(
            attempt.expected_stage,
            Some(AggregateConstructionStage::SparseFiniteRoot)
        );

        attempt
            .select_stage(AggregateConstructionStage::SparseFiniteRoot)
            .unwrap();
        attempt
            .resolve_selected_soft_refusal(
                effect(7, 2, 60, 15, 45),
                AggregateConstructionAbandonment {
                    work: 7,
                    allocations: 2,
                    bytes: 60,
                    released_persistent_bytes: 15,
                },
                AggregateConstructionPrepublicationFallback::SparseFiniteBuildResource,
            )
            .unwrap();
        let actual = attempt.actual();
        assert_eq!(actual.work, 12);
        assert_eq!(actual.abandoned_work, 12);
        assert_eq!(actual.allocations, 3);
        assert_eq!(actual.abandoned_allocations, 3);
        assert_eq!(actual.allocated_bytes, 100);
        assert_eq!(actual.abandoned_bytes, 100);
        assert_eq!(actual.live_persistent_bytes, 0);
        assert_eq!(actual.high_water_bytes, 45);
        assert_eq!(
            attempt.expected_stage,
            Some(AggregateConstructionStage::Continuation)
        );
    }

    #[test]
    fn publication_is_one_shot_and_rejects_every_later_transition() {
        let identity = identity("published");
        let mut attempt: Attempt = AggregateConstructionAttempt::new(identity);
        attempt.publish_prospective(prospective()).unwrap();
        advance_to(&mut attempt, AggregateConstructionStage::ExactLiteral);
        attempt
            .select_stage(AggregateConstructionStage::ExactLiteral)
            .unwrap();
        let plan = PlanSeal::from_owned(AggregateConstructionStage::ExactLiteral, "exact-plan");
        attempt
            .publish_selected(effect(1, 1, 10, 10, 10), plan)
            .unwrap();
        assert_eq!(
            attempt.record_policy_skip(AggregateConstructionStage::UnicodeScalar),
            Err(AggregateConstructionStateError::AttemptTerminal)
        );
        assert_eq!(
            attempt.publish_prospective(prospective()),
            Err(AggregateConstructionStateError::AttemptTerminal)
        );
        assert_eq!(
            attempt.select_stage(AggregateConstructionStage::UnicodeScalar),
            Err(AggregateConstructionStateError::AttemptTerminal)
        );
    }

    #[test]
    fn inline_plan_publication_requires_no_fabricated_heap_allocation() {
        let attempt_identity = identity("inline");
        let mut attempt: Attempt = AggregateConstructionAttempt::new(attempt_identity.clone());
        let upper = AggregateConstructionProspective {
            work: 2,
            allocations: 0,
            allocated_bytes: 0,
            copied_bytes: 0,
            initialized_bytes: 32,
            abandoned_work: 0,
            abandoned_allocations: 0,
            abandoned_bytes: 0,
            live_persistent_bytes: 32,
            high_water_bytes: 32,
        };
        assert!(upper.is_well_formed());
        attempt.publish_prospective(upper).unwrap();
        attempt
            .record_policy_skip(AggregateConstructionStage::PreSyntaxForceExactLiteralSpans)
            .unwrap();
        attempt
            .record_completed(
                AggregateConstructionStage::SyntaxParseAdmission,
                effect(1, 0, 0, 0, 0),
            )
            .unwrap();
        attempt
            .select_stage(AggregateConstructionStage::ExactLiteral)
            .unwrap();
        let plan = PlanSeal::from_owned(AggregateConstructionStage::ExactLiteral, "inline-plan");
        attempt
            .publish_selected(
                AggregateConstructionEffect {
                    work: 1,
                    allocations: 0,
                    allocated_bytes: 0,
                    copied_bytes: 0,
                    initialized_bytes: 32,
                    retained_persistent_bytes: 32,
                    released_persistent_bytes: 0,
                    co_live_bytes: 32,
                },
                plan.clone(),
            )
            .unwrap();
        let receipt = attempt.finish_success().unwrap();
        assert_eq!(receipt.actual.allocations, 0);
        assert_eq!(receipt.actual.allocated_bytes, 0);
        assert_eq!(receipt.actual.initialized_bytes, 32);
        assert_eq!(receipt.actual.live_persistent_bytes, 32);
        assert_eq!(receipt.actual.high_water_bytes, 32);
        assert!(receipt.closes(&attempt_identity, Some(&plan)));
    }

    #[test]
    fn receipt_rejects_accounting_order_request_plan_and_terminal_splices() {
        let (attempt_identity, plan, receipt) = published_receipt("needle");
        assert!(receipt.closes(&attempt_identity, Some(&plan)));

        let mut accounting = receipt.clone();
        accounting.actual.work += 1;
        assert!(!accounting.closes(&attempt_identity, Some(&plan)));

        let mut order = receipt.clone();
        order.ledger.entries[0].as_mut().unwrap().stage =
            AggregateConstructionStage::SyntaxParseAdmission;
        assert!(!order.closes(&attempt_identity, Some(&plan)));

        let mut transition = receipt.clone();
        transition.ledger.entries[0].as_mut().unwrap().transition =
            AggregateConstructionTransition::Published;
        assert!(!transition.closes(&attempt_identity, Some(&plan)));

        let mut deletion = receipt.clone();
        deletion.ledger.entries[0] = None;
        assert!(!deletion.closes(&attempt_identity, Some(&plan)));

        let mut insertion = receipt.clone();
        let insertion_index = insertion.ledger.len();
        let inserted = *insertion.ledger.get(insertion_index - 1).unwrap();
        insertion.ledger.entries[insertion_index] = Some(inserted);
        assert!(!insertion.closes(&attempt_identity, Some(&plan)));

        let mut disposition = receipt.clone();
        disposition.ledger.entries[0].as_mut().unwrap().disposition =
            AggregateConstructionStageDisposition::SemanticIneligible;
        assert!(!disposition.closes(&attempt_identity, Some(&plan)));

        let mut fallback = receipt.clone();
        fallback.ledger.entries[0].as_mut().unwrap().fallback =
            AggregateConstructionPrepublicationFallback::SparseFiniteBuildResource;
        assert!(!fallback.closes(&attempt_identity, Some(&plan)));

        let mut prospective = receipt.clone();
        prospective.prospective.as_mut().unwrap().work = receipt.actual.work - 1;
        assert!(!prospective.closes(&attempt_identity, Some(&plan)));

        let other_identity = identity("banana");
        assert!(!receipt.closes(&other_identity, Some(&plan)));

        let mut different_request = attempt_identity.request_owner.request().clone();
        different_request.operation = different_request.operation.wrapping_add(1);
        let structurally_equal_request = AggregateConstructionAttemptIdentity::new(
            AggregateConstructionRequestOwnerSeal::from_owned(different_request),
            attempt_identity.explain_schema_version,
        );
        assert!(!receipt.closes(&structurally_equal_request, Some(&plan)));

        let other_plan =
            PlanSeal::from_owned(AggregateConstructionStage::ExactLiteral, "other-plan");
        assert!(!receipt.closes(&attempt_identity, Some(&other_plan)));

        let mut terminal = receipt.clone();
        terminal.terminal = AggregateConstructionTerminal::Failure;
        assert!(!terminal.closes(&attempt_identity, Some(&plan)));

        let mut publication = receipt.clone();
        publication.publication_state = AggregateConstructionPublicationState::Unpublished;
        assert!(!publication.closes(&attempt_identity, Some(&plan)));

        let mut published_stage = receipt.clone();
        published_stage.published_stage = Some(AggregateConstructionStage::UnicodeScalar);
        assert!(!published_stage.closes(&attempt_identity, Some(&plan)));

        let mut version = receipt.clone();
        version.identity.accounting_version += 1;
        assert!(!version.closes(&attempt_identity, Some(&plan)));
    }

    #[test]
    fn preprospective_failure_has_none_and_zero_actual() {
        let identity = identity("bad");
        let mut attempt: Attempt = AggregateConstructionAttempt::new(identity.clone());
        attempt
            .record_hard_terminal(
                AggregateConstructionStage::PreSyntaxForceExactLiteralSpans,
                AggregateConstructionEffect::default(),
            )
            .unwrap();
        let receipt = attempt.finish_failure().unwrap();
        assert_eq!(receipt.prospective, None);
        assert_eq!(receipt.actual, AggregateConstructionActual::default());
        assert!(receipt.closes(&identity, None));
    }

    #[test]
    fn terminate_current_closes_expected_unselected_stage() {
        let attempt_identity = identity("unselected-terminal");
        let mut attempt: Attempt = AggregateConstructionAttempt::new(attempt_identity.clone());
        attempt.publish_prospective(prospective()).unwrap();
        assert_eq!(
            attempt.expected_stage(),
            Some(AggregateConstructionStage::PreSyntaxForceExactLiteralSpans)
        );
        assert_eq!(attempt.selected_stage(), None);
        attempt.terminate_current(effect(3, 0, 0, 0, 0)).unwrap();
        let terminal = attempt.ledger().get(0).unwrap();
        assert_eq!(
            terminal.disposition,
            AggregateConstructionStageDisposition::HardTerminal
        );
        assert_eq!(
            terminal.transition,
            AggregateConstructionTransition::HardTerminal
        );
        assert_eq!(attempt.expected_stage(), None);
        assert_eq!(
            attempt.record_policy_skip(AggregateConstructionStage::PreSyntaxForceExactLiteralSpans),
            Err(AggregateConstructionStateError::AttemptTerminal)
        );
        let receipt = attempt.finish_failure().unwrap();
        assert!(receipt.closes(&attempt_identity, None));
    }

    #[test]
    fn terminate_current_resolves_pending_selected_stage_in_place() {
        let attempt_identity = identity("selected-terminal");
        let mut attempt: Attempt = AggregateConstructionAttempt::new(attempt_identity.clone());
        attempt.publish_prospective(prospective()).unwrap();
        advance_to(&mut attempt, AggregateConstructionStage::ExactLiteral);
        attempt
            .select_stage(AggregateConstructionStage::ExactLiteral)
            .unwrap();
        assert_eq!(
            attempt.selected_stage(),
            Some(AggregateConstructionStage::ExactLiteral)
        );
        let entries_before = attempt.ledger().len();
        attempt.terminate_current(effect(4, 1, 20, 10, 20)).unwrap();
        assert_eq!(attempt.ledger().len(), entries_before);
        let terminal = attempt.ledger().get(entries_before - 1).unwrap();
        assert_eq!(terminal.stage, AggregateConstructionStage::ExactLiteral);
        assert_eq!(
            terminal.disposition,
            AggregateConstructionStageDisposition::HardTerminal
        );
        assert_eq!(attempt.selected_stage(), None);
        assert_eq!(
            attempt.terminate_current(AggregateConstructionEffect::default()),
            Err(AggregateConstructionStateError::AttemptTerminal)
        );
        let receipt = attempt.finish_failure().unwrap();
        assert!(receipt.closes(&attempt_identity, None));
    }

    #[test]
    fn allocation_envelope_is_derived_from_charged_work() {
        let mut valid = prospective();
        valid.work = 3;
        valid.allocations = 5;
        valid.abandoned_work = 3;
        valid.abandoned_allocations = 5;
        assert!(valid.is_well_formed());
        valid.allocations = 6;
        assert!(!valid.is_well_formed());

        assert!(effect(0, 1, 16, 16, 16).is_well_formed());
        assert!(!effect(0, 2, 32, 32, 32).is_well_formed());
    }

    #[test]
    fn cumulative_accounting_admits_only_two_allocation_only_owners() {
        let actual = AggregateConstructionActual {
            work: 0,
            allocations: 2,
            allocated_bytes: 32,
            initialized_bytes: 32,
            live_persistent_bytes: 32,
            high_water_bytes: 32,
            ..AggregateConstructionActual::default()
        };
        assert!(actual.is_well_formed());
        assert!(
            !AggregateConstructionActual {
                allocations: 3,
                ..actual
            }
            .is_well_formed()
        );
    }
}
