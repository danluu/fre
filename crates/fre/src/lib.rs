//! Honest operation-specific facade for the currently certified FRE subsets.
//!
//! [`PortableRegex`] provides bounded single-search operations for the HIR
//! subset that `fre-lower` can prove exact. With the default
//! `qualified-exact-search-jit` feature, [`QualifiedExactSearch`] exposes an
//! experimental, explicit opt-in 16-byte exact-literal JIT leaf with portable
//! fallback outside its evidence-gated large-window envelope. No default
//! facade selects that native route.
//! The default-off `explicit-search-span-aot` feature adds safe binders from
//! an already-adopted static Search Span handle to the authenticated portable
//! exact-literal owner. Exact legacy rows remain explicit AOT-only calls. A
//! separately typed automatic wrapper is available only when the adopted
//! broad production family carries a source-qualified window/prefix/evidence
//! policy; no default [`PortableRegex`] call selects AOT code.
//! The still-default-off `compiled-search-v25-aot` feature only prepares an
//! owning bind-once facade and forwards the tag38 static-link boundary. A
//! missing or mismatched source-authority row is cached as a portable route;
//! the feature, facade, and linked objects cannot create tag38 authority.
//! The separate default-off `compiled-search-v26-aot` facade does the same for
//! tag39, but prequalifies only decoded exact literals of width 9..=32 before
//! calling glue. Its private authorization atom is fixed to absent, so even an
//! all-features build remains portable. It does not change JIT `CURRENT`,
//! ordinary [`PortableRegex`] behavior, or any default feature.
//! The default-off `compiled-search-v27-aot` facade extends this fail-closed
//! bind-once surface to topology-total tag40 exact literals. Its
//! evidence-qualified production envelope is width 17..=32; shorter literals
//! remain portable. A linked object and Cargo feature still cannot create
//! production authority; absent or mismatched source authority is cached as a
//! portable route.
//! The separate default-off `explicit-count-v3-aot` feature binds an
//! already-adopted optimizing Count-v3 handle only to the live fixed-policy
//! exact-literal Count owner whose literal, semantic identity, and planning
//! receipt all match. A bind refusal leaves that owner as the construction-time
//! portable fallback; successful calls contain no artifact lookup or target
//! dispatch.
//! [`PortableRegexSetBuilder`] and
//! [`PortableTextRegexSetBuilder`] compose independently admitted matchers
//! with exact ascending pattern-ID semantics. [`AggregateBuilder`] constructs
//! separate complete-span, count, or matched-byte-sum plans for the bounded
//! `fre-aggregate` Rust-byte subset. [`AggregateManyBuilder`] retains each
//! pattern's syntax identity and composes ordered whole-match compile/count/
//! span-sum/complete-span plans without source concatenation. It also admits
//! capture count when every pattern proves the same nonempty root-capture
//! participation. Whole-match aggregate plans may erase capture annotations.
//! Their complete spans also
//! provide bounded byte `split`/`splitn` and literal/no-expansion replacement/
//! `replacen`.
//! [`CaptureBuilder`] separately preserves capture histories for the
//! participating-group reducer on its certified Rust-byte subset; it is not a
//! general capture-record facade. None of these types is named `Regex`:
//! unsupported syntax/profile/operation combinations are typed build errors,
//! and there is no full Rust-regex/RE2 or JIT claim.

#![forbid(unsafe_code)]

use core::fmt;

use fre_kernels::FixedPredicateWord64SearchCursor;
use memchr::{memchr, memchr2, memchr3};
use regex_syntax::hir::{Hir, HirKind, Look};

mod aggregate;
mod aggregate_construction;
#[cfg(feature = "explicit-count-v3-aot")]
mod aggregate_count_aot_v3;
mod aggregate_many;
mod anchored_line_capture;
mod anchored_word_capture;
mod blocking_delimiter;
mod bounded_byte_class_sequence;
mod bounded_byte_class_repeat;
mod bounded_literal_pair;
mod bounded_word_class;
mod capture_absolute_full;
mod capture_count_seal;
mod capture_iteration_seal;
mod capture_noqa;
mod capture_required_literal;
mod capture_run_alternation;
mod capture_word_run;
mod captures;
mod finite;
mod finite_root;
mod fixed_absolute;
mod forward_anchored;
mod grapheme_scalar;
pub mod guarded_ascii_word;
mod guarded_literal_set;
pub mod guarded_unicode_word;
mod line_capture;
mod line_total_grep;
mod literal_assertions;
mod literal_class_run_literal;
pub mod operation_session;
mod pure_byte_class_repeat;
#[cfg(feature = "qualified-exact-search-jit")]
mod qualified_exact_search;
mod replacement;
mod required_literal;
mod reverse_inner;
mod search_aot;
#[cfg(feature = "explicit-search-span-aot")]
mod search_aot_facade;
mod set;
mod split;
#[cfg(all(
    feature = "qualified-exact-search-jit",
    test,
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
mod sve_class_suffix_benchmark;
mod text;
mod text_match;
mod text_set;
mod token_phrase;
mod unicode_folded_literal;
mod unicode_word_run;

pub use pure_byte_class_repeat::{
    Accounting as PureByteClassRepeatAccounting, Error as PureByteClassRepeatSearchError,
    Operation as PureByteClassRepeatOperation, PLAN_ID as PURE_BYTE_CLASS_REPEAT_PLAN_ID,
};
pub use bounded_byte_class_sequence::{
    Accounting as BoundedByteClassSequenceAccounting,
    Error as BoundedByteClassSequenceSearchError,
    Operation as BoundedByteClassSequenceOperation,
    PLAN_ID as BOUNDED_BYTE_CLASS_SEQUENCE_PLAN_ID,
};
pub use unicode_folded_literal::{
    UNICODE_FOLDED_LITERAL_ALGORITHM_ID, UNICODE_FOLDED_LITERAL_COUNT_OPERATION_ID,
    UNICODE_FOLDED_LITERAL_SEARCH_ALGORITHM_ID, UNICODE_FOLDED_LITERAL_SPAN_SUM_OPERATION_ID,
    UnicodeFoldedLiteralBuildAttempt, UnicodeFoldedLiteralBuildError,
    UnicodeFoldedLiteralBuildLimits, UnicodeFoldedLiteralBuildReport, UnicodeFoldedLiteralBuilder,
    UnicodeFoldedLiteralCountRegex, UnicodeFoldedLiteralIneligibility,
    UnicodeFoldedLiteralOperation, UnicodeFoldedLiteralPlannerAccounting,
    UnicodeFoldedLiteralRunError, UnicodeFoldedLiteralRunLimits, UnicodeFoldedLiteralRunReceipt,
    UnicodeFoldedLiteralRunResult, UnicodeFoldedLiteralRunUpperBounds,
    UnicodeFoldedLiteralSearchBuildAccounting, UnicodeFoldedLiteralSpanSumRegex,
};

pub use aggregate::PortableGrepLineTotalError;
pub use aggregate::{
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_LITERAL_BYTES_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_SOURCE_BYTES_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_POLICY_VERSION,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_RECEIPT_SCHEMA_VERSION,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_SEMANTIC_BINDING_SCHEMA_VERSION,
    AGGREGATE_DIRECT_OWNER_ACCOUNTING_VERSION, AGGREGATE_DIRECT_OWNER_ALGORITHM_VERSION,
    AGGREGATE_EXPLAIN_SCHEMA_VERSION, AggregateBlockingDelimiterIdentity,
    AggregateBlockingDelimiterSemantics, AggregateBoundedContextIdentity,
    AggregateBoundedLiteralPairIdentity, AggregateBoundedSeparatedFieldsIdentity,
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuildReport,
    AggregateBuilder, AggregateCacheIdentity, AggregateCaptureSemantics, AggregateCompileRegex,
    AggregateConstructionAttemptError, AggregateConstructionReceipt, AggregateConstructionRequest,
    AggregateContinuationIdentity, AggregateContinuationSemantics,
    AggregateCountExactLiteralAotCandidate,
    AggregateCountExactLiteralAotIdentityProjectionAccounting,
    AggregateCountExactLiteralAotPlannedCandidate, AggregateCountExactLiteralAotPlanningAccounting,
    AggregateCountExactLiteralAotPlanningReceiptIdentity,
    AggregateCountExactLiteralAotSemanticBindingIdentity, AggregateCountRegex,
    AggregateCountResult, AggregateCountWorkspace, AggregateDirectAttemptIdentity,
    AggregateDirectAttemptReceipt, AggregateDirectAttemptTerminal, AggregateDirectDeclaredFallback,
    AggregateDirectInvocation, AggregateDirectOwnerSeal, AggregateDirectRoute,
    AggregateDirectRouteIdentity, AggregateExactLiteralExecutionDetails,
    AggregateExactLiteralIdentity, AggregateExactLiteralSemantics,
    AggregateExecutionAttemptIdentity, AggregateExecutionDetails, AggregateExecutionError,
    AggregateExecutionIdentity, AggregateExecutionReport, AggregateExecutionSource,
    AggregateFiniteLiteralIdentity, AggregateFiniteLiteralSemantics,
    AggregateFixedAbsoluteDomainAttemptIdentity, AggregateFixedAbsoluteDomainAttemptKind,
    AggregateFixedAbsoluteDomainAttemptReceipt, AggregateFixedAbsoluteDomainBuildAccounting,
    AggregateFixedAbsoluteDomainBuildSummary, AggregateFixedAbsoluteDomainErrorIdentity,
    AggregateFixedAbsoluteDomainExecutionDetails, AggregateFixedAbsoluteDomainIdentity,
    AggregateFixedAbsoluteDomainResidualActual, AggregateFixedAbsoluteDomainResidualBuildActual,
    AggregateFixedAbsoluteDomainResidualBuildAttemptReceipt,
    AggregateFixedAbsoluteDomainResidualBuildLimits,
    AggregateFixedAbsoluteDomainResidualBuildProspective,
    AggregateFixedAbsoluteDomainResidualBuildResource,
    AggregateFixedAbsoluteDomainResidualExecutionSummary,
    AggregateFixedAbsoluteDomainResidualLimits, AggregateFixedAbsoluteDomainResidualProspective,
    AggregateFixedAbsoluteDomainResidualReceipt, AggregateFixedClassSandwichIdentity,
    AggregateFixedClassSandwichSemantics, AggregateGraphemeScalarDfaIdentity,
    AggregateGraphemeScalarDfaSemantics, AggregateGuardedAsciiWordBuildAccounting,
    AggregateGuardedAsciiWordIdentity, AggregateGuardedAsciiWordSemantics,
    AggregateGuardedUnicodeWordBuildAccounting, AggregateGuardedUnicodeWordIdentity,
    AggregateGuardedUnicodeWordSemantics, AggregateImpossibleMatchReason,
    AggregateLiteralAssertionsIdentity, AggregateLiteralAssertionsSemantics,
    AggregateLiteralClassRunLiteralIdentity, AggregateLiteralIneligibility,
    AggregateMatchDomainExecutionReceipt, AggregateOperation, AggregatePlanIdentity,
    AggregatePlanKind, AggregatePlanSelection, AggregatePrefixClassAlternationIdentity,
    AggregateRetainedFullWindowUpperBounds, AggregateReverseInnerIdentity, AggregateRunLimits,
    AggregateSearchStep, AggregateSearchStepIter, AggregateSpanIter, AggregateSpanSumRegex,
    AggregateSpanSumResult, AggregateSpanSumWorkspace, AggregateSpans, AggregateSpansRegex,
    AggregateStrategy, AggregateTokenPhraseIdentity, AggregateTokenPhraseSemantics,
    AggregateUnicodeScalarIdentity, AggregateUnicodeScalarSemantics, AggregateValueCounterResult,
    AggregateWordRunIdentity, AggregateWordRunSemantics, LITERAL_ANCHOR_AGGREGATE_ACCOUNTING_ID,
    LITERAL_ANCHOR_AGGREGATE_SCHEMA_VERSION, LiteralAnchorAggregateBuildError,
    LiteralAnchorAggregateBuildLimits, LiteralAnchorAggregateBuildReport,
    LiteralAnchorAggregateBuilder, LiteralAnchorAggregateCountRegex,
    LiteralAnchorAggregateExecutionReceipt, LiteralAnchorAggregateRoute,
    LiteralAnchorAggregateRunError, LiteralAnchorAggregateRunLimits,
    LiteralAnchorAggregateSpanSumRegex, LiteralAnchorCandidateBuildReport,
    LiteralAnchorCandidateExecutionReceipt, LiteralAnchorFallbackReason,
    PORTABLE_GREP_ACCOUNTING_ID, PORTABLE_GREP_ACCOUNTING_VERSION, PORTABLE_GREP_ALGORITHM_VERSION,
    PRIORITY_AGGREGATE_ACCOUNTING_ID, PRIORITY_AGGREGATE_MANY_ACCOUNTING_ID,
    PRIORITY_AGGREGATE_MANY_SCHEMA_VERSION, PRIORITY_AGGREGATE_SCHEMA_VERSION,
    PortableGrepBuildError, PortableGrepError, PortableGrepExecutionError,
    PortableGrepLiteralError, PortableGrepMatch, PortableGrepProspective, PortableGrepResult,
    PortableGrepSession, PortableGrepWordError, PriorityAggregateAssertionProof,
    PriorityAggregateBridgeAccounting, PriorityAggregateBridgeLimits,
    PriorityAggregateBridgeProspective, PriorityAggregateBridgeResource,
    PriorityAggregateBuildError, PriorityAggregateBuildLimits, PriorityAggregateBuildReport,
    PriorityAggregateBuilder, PriorityAggregateCountRegex, PriorityAggregateDeterminismProof,
    PriorityAggregateExecutionReceipt, PriorityAggregateFactReceipt,
    PriorityAggregateManyBuildError, PriorityAggregateManyBuildLimits,
    PriorityAggregateManyBuildReport, PriorityAggregateManyBuilder,
    PriorityAggregateManyCaptureBuildLimits, PriorityAggregateManyCaptureBuildReport,
    PriorityAggregateManyCaptureBuildResource, PriorityAggregateManyCaptureConstructionAccounting,
    PriorityAggregateManyCaptureCountRegex, PriorityAggregateManyCaptureCountResult,
    PriorityAggregateManyCaptureProjectionLimits, PriorityAggregateManyCaptureProjectionReceipt,
    PriorityAggregateManyCaptureRunError, PriorityAggregateManyCaptureRunFailure,
    PriorityAggregateManyCaptureRunLimits, PriorityAggregateManyCaptureSelectorReceipt,
    PriorityAggregateManyCaptureSession, PriorityAggregateManyCaptureSessionAccounting,
    PriorityAggregateManyCaptureSessionLimits, PriorityAggregateManyCaptureSessionResource,
    PriorityAggregateManyCompositionAccounting, PriorityAggregateManyCountRegex,
    PriorityAggregateManyExecutionReceipt, PriorityAggregateManyOperation,
    PriorityAggregateManyPatternReport, PriorityAggregateManyRunError,
    PriorityAggregateManyRunFailure, PriorityAggregateManyRunLimits,
    PriorityAggregateManySourceOwnerAccounting, PriorityAggregateManySourceOwnerLimits,
    PriorityAggregateManySourceOwnerResource, PriorityAggregateManySpanSumRegex,
    PriorityAggregateManyTraceReceipt, PriorityAggregateManyWholeRequiredLiteralBuildReceipt,
    PriorityAggregateOperation, PriorityAggregateProofRefusal, PriorityAggregateRouteProof,
    PriorityAggregateRunError, PriorityAggregateRunFailure, PriorityAggregateRunLimits,
    PriorityAggregateSourceOwnerAccounting, PriorityAggregateSourceOwnerLimits,
    PriorityAggregateSourceOwnerResource, PriorityAggregateSpanSumRegex,
    PriorityAggregateSyntaxEvidence, PriorityAggregateUsizeProof,
};
pub use aggregate_construction::{
    AGGREGATE_CONSTRUCTION_ACCOUNTING_VERSION, AGGREGATE_CONSTRUCTION_ALGORITHM_VERSION,
    AGGREGATE_CONSTRUCTION_LEDGER_CAPACITY, AggregateConstructionAbandonment,
    AggregateConstructionActual, AggregateConstructionAttempt,
    AggregateConstructionAttemptIdentity, AggregateConstructionAttemptReceipt,
    AggregateConstructionDeclaredFallbackPolicy, AggregateConstructionEffect,
    AggregateConstructionLedger, AggregateConstructionLedgerEntry,
    AggregateConstructionPrepublicationFallback, AggregateConstructionProspective,
    AggregateConstructionRequestInputs, AggregateConstructionRequestOwnerSeal,
    AggregateConstructionSelectedPlanOwnerSeal, AggregateConstructionStage,
    AggregateConstructionStageDisposition, AggregateConstructionStateError,
    AggregateConstructionTerminal, AggregateConstructionTransition,
};
#[cfg(feature = "explicit-count-v3-aot")]
pub use aggregate_count_aot_v3::{
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MIN_HAYSTACK_BYTES_V3,
    AggregateCountExactLiteralAotBindErrorV3, AggregateCountExactLiteralAotExecutionErrorV3,
    AggregateCountExactLiteralAotOutcomeV3, AggregateCountExactLiteralAotRouteV3,
    AggregateCountExactLiteralAotSveSessionV3, AggregateCountExactLiteralAotSveV3,
    AggregateCountExactLiteralAotV3,
};
#[cfg(feature = "count-v3-aot-qualification-private")]
#[doc(hidden)]
pub use aggregate_count_aot_v3::{
    AggregateCountExactLiteralAotQualificationV3,
    AggregateCountExactLiteralAotSveQualificationSessionV3,
    AggregateCountExactLiteralAotSveQualificationV3,
};
pub use aggregate_many::{
    AGGREGATE_MANY_BYTE_UNIT_COVER_PROOF_ALGORITHM_ID, AGGREGATE_MANY_EXPLAIN_SCHEMA_VERSION,
    AGGREGATE_MANY_TOTAL_BYTE_COVER_SPAN_SUM_ALGORITHM_ID, AggregateManyBuildAccounting,
    AggregateManyBuildError, AggregateManyBuildLimits, AggregateManyBuildReport,
    AggregateManyBuilder, AggregateManyByteUnitCoverProof, AggregateManyCaptureCountRegex,
    AggregateManyCaptureCountResult, AggregateManyCaptureCountSession,
    AggregateManyCaptureCountSessionFootprint, AggregateManyCaptureIneligibility,
    AggregateManyCaptureRunLimits, AggregateManyCaptureSemantics, AggregateManyCompileRegex,
    AggregateManyCompositionAccounting, AggregateManyCountRegex, AggregateManyCountResult,
    AggregateManyExecutionDetails, AggregateManyExecutionError, AggregateManyExecutionSource,
    AggregateManyLiteralSemantics, AggregateManyOperation, AggregateManyOutput,
    AggregateManyPatternReport, AggregateManyPlanIdentity, AggregateManyPlanKind,
    AggregateManyRegex, AggregateManyRunLimits, AggregateManySpanIter, AggregateManySpanSumRegex,
    AggregateManySpanSumResult, AggregateManySpans, AggregateManySpansRegex,
    AggregateManyTotalByteCoverActual, AggregateManyTotalByteCoverBuildAccounting,
    AggregateManyTotalByteCoverIdentity, AggregateManyTotalByteCoverUpperBounds,
};
pub use anchored_line_capture::{
    ANCHORED_LINE_CAPTURE_ACCOUNTING_VERSION, ANCHORED_LINE_CAPTURE_ALGORITHM_VERSION,
    AnchoredLineCaptureBuildError, AnchoredLineCaptureBuildLimits, AnchoredLineCaptureBuildReport,
    AnchoredLineCaptureBuilder, AnchoredLineCaptureHirAccounting, AnchoredLineCapturePlan,
    AnchoredLineCapturePlanIdentity,
};
pub use anchored_word_capture::{
    ANCHORED_WORD_CAPTURE_ACCOUNTING_VERSION, ANCHORED_WORD_CAPTURE_ALGORITHM_VERSION,
    ANCHORED_WORD_CAPTURE_COUNT_OPERATION_ID, ANCHORED_WORD_CAPTURE_PLAN_ID,
    AnchoredWordCaptureBuildError, AnchoredWordCaptureBuildLimits, AnchoredWordCaptureBuildReport,
    AnchoredWordCaptureBuilder, AnchoredWordCaptureCountResult, AnchoredWordCaptureHirAccounting,
    AnchoredWordCaptureKind, AnchoredWordCaptureMode, AnchoredWordCaptureOperationIdentity,
    AnchoredWordCapturePlan, AnchoredWordCapturePlanIdentity, AnchoredWordCaptureRunActual,
    AnchoredWordCaptureRunError, AnchoredWordCaptureRunLimits, AnchoredWordCaptureRunResource,
    AnchoredWordCaptureRunUpperBounds,
};
pub use capture_absolute_full::{
    ABSOLUTE_FULL_CAPTURE_ACCOUNTING_VERSION, ABSOLUTE_FULL_CAPTURE_ALGORITHM_VERSION,
    ABSOLUTE_FULL_CAPTURE_COUNT_OPERATION_ID, ABSOLUTE_FULL_CAPTURE_PLAN_ID,
    AbsoluteFullCaptureBuildError, AbsoluteFullCaptureBuildLimits, AbsoluteFullCaptureBuildReport,
    AbsoluteFullCaptureBuilder, AbsoluteFullCaptureCountResult, AbsoluteFullCaptureHirAccounting,
    AbsoluteFullCaptureOperationIdentity, AbsoluteFullCapturePlan, AbsoluteFullCapturePlanIdentity,
    AbsoluteFullCaptureRunActual, AbsoluteFullCaptureRunError, AbsoluteFullCaptureRunLimits,
    AbsoluteFullCaptureRunResource, AbsoluteFullCaptureRunUpperBounds,
};
pub use capture_count_seal::{
    CAPTURE_COUNT_ACCOUNTING_VERSION, CAPTURE_COUNT_ALGORITHM_VERSION, CaptureCountActual,
    CaptureCountAttemptReceipt, CaptureCountBranch, CaptureCountDeclaredFallback,
    CaptureCountOwnerSeal, CaptureCountPrepublicationFallback, CaptureCountProspective,
    CaptureCountRouteIdentity, CaptureCountSeal, CaptureCountSelectorRoute, CaptureCountTerminal,
};
pub use capture_iteration_seal::{
    CAPTURE_ITERATION_ACCOUNTING_VERSION, CAPTURE_ITERATION_ALGORITHM_VERSION,
    CaptureIterationActual, CaptureIterationAttemptReceipt, CaptureIterationBackend,
    CaptureIterationDeclaredFallback, CaptureIterationOperation, CaptureIterationOwnerSeal,
    CaptureIterationProspective, CaptureIterationRouteIdentity, CaptureIterationSeal,
    CaptureIterationTerminal,
};
pub use capture_noqa::{
    NOQA_ASCII_LEADING_PLAN_ID, NOQA_ASCII_NO_LEADING_PLAN_ID, NOQA_UNICODE_LEADING_PLAN_ID,
    NoqaActualCounters, NoqaBuildAccounting, NoqaBuildAllocationAccounting, NoqaBuildError,
    NoqaBuildLimits, NoqaBuildReport, NoqaGrepCaptureBuilder, NoqaGrepCaptureRegex,
    NoqaPlanIdentity, NoqaResource, NoqaRunError, NoqaRunLimits, NoqaRunOutcome, NoqaRunReport,
    NoqaUpperBounds, NoqaVariant,
};
pub use capture_required_literal::{
    CAPTURE_REQUIRED_LITERAL_PLAN_ID, CaptureRequiredLiteralBuildAccounting,
    CaptureRequiredLiteralBuildError, CaptureRequiredLiteralBuildLimits,
    CaptureRequiredLiteralBuildReport, CaptureRequiredLiteralCacheIdentity,
    CaptureRequiredLiteralIdentity, CaptureRequiredLiteralLinePartitionMatches,
    CaptureRequiredLiteralPlan, CaptureRequiredLiteralRunLimits, CaptureRequiredLiteralSearchError,
    CaptureRequiredLiteralSearchOperation, CaptureRequiredLiteralSearchReport,
};
pub use capture_run_alternation::{
    CAPTURE_RUN_ALTERNATION_ACCOUNTING_VERSION, CAPTURE_RUN_ALTERNATION_ALGORITHM_VERSION,
    CAPTURE_RUN_ALTERNATION_COUNT_OPERATION_ID, CAPTURE_RUN_ALTERNATION_PLAN_ID,
    CaptureRunAlternationBuildError, CaptureRunAlternationBuildLimits,
    CaptureRunAlternationBuildReport, CaptureRunAlternationBuilder,
    CaptureRunAlternationCountResult, CaptureRunAlternationHirAccounting,
    CaptureRunAlternationKind, CaptureRunAlternationOperationIdentity, CaptureRunAlternationPlan,
    CaptureRunAlternationPlanIdentity, CaptureRunAlternationRunActual,
    CaptureRunAlternationRunError, CaptureRunAlternationRunLimits,
    CaptureRunAlternationRunResource, CaptureRunAlternationRunUpperBounds,
};
pub use capture_word_run::{
    CAPTURE_WORD_RUN_ACCOUNTING_VERSION, CAPTURE_WORD_RUN_ALGORITHM_VERSION,
    CAPTURE_WORD_RUN_COUNT_OPERATION_ID, CAPTURE_WORD_RUN_PLAN_ID, CaptureWordRunBuildError,
    CaptureWordRunBuildLimits, CaptureWordRunBuildReport, CaptureWordRunBuilder,
    CaptureWordRunCountResult, CaptureWordRunHirAccounting, CaptureWordRunMode,
    CaptureWordRunOperationIdentity, CaptureWordRunPlan, CaptureWordRunPlanIdentity,
    CaptureWordRunRunActual, CaptureWordRunRunError, CaptureWordRunRunLimits,
    CaptureWordRunRunResource, CaptureWordRunRunUpperBounds,
};
pub use captures::{
    CaptureBuildError, CaptureBuildLimits, CaptureBuildReport, CaptureBuilder,
    CaptureCacheIdentity, CaptureExecutionError, CaptureExecutionReport, CaptureExecutionSource,
    CaptureHirAccounting, CaptureIterationError, CaptureIterationIdentity,
    CaptureIterationPlanKind, CaptureIterationReport, CaptureLineBatchProof, CaptureOperation,
    CaptureParticipationQuotientFallback, CaptureParticipationQuotientProof, CapturePlanIdentity,
    CapturePlanKind, CapturePrefixClassParticipationIdentity, CaptureRegex, CaptureRunLimits,
    CaptureStreamSession, CaptureUnsupported, OrderedRootCaptureManyProof, OrderedRootUnitCover,
    PortableTextCaptureBuildError, PortableTextCaptureBuildReport, PortableTextCaptureBuilder,
    PortableTextCaptureIterationError, PortableTextCaptureMatch, PortableTextCaptureRegex,
    PortableTextCaptureSearchError, PortableTextCaptures,
};
pub use fre_aggregate::{
    CONTINUATION_OPERATION_ACCOUNTING_VERSION as AGGREGATE_CONTINUATION_ACCOUNTING_VERSION,
    CONTINUATION_OPERATION_ALGORITHM_VERSION as AGGREGATE_CONTINUATION_ALGORITHM_VERSION,
    CONTINUATION_OPERATION_MAX_ALLOCATIONS as AGGREGATE_CONTINUATION_MAX_ALLOCATIONS,
    CompileAccounting as AggregateCompileAccounting,
    CompileAttemptError as AggregateCompileAttemptError,
    CompileAttemptIdentity as AggregateCompileAttemptIdentity,
    CompileAttemptKind as AggregateCompileAttemptKind,
    CompileAttemptReceipt as AggregateCompileAttemptReceipt,
    CompileLimits as AggregateCompileLimits, ContinuationSweepRunUpperBounds,
    ContinuationSweepUpperBounds, Error as AggregateEngineError,
    ExecutionAccounting as AggregateExecutionAccounting,
    OPERATION_COUNTER_RECEIPT_SCHEMA_VERSION as AGGREGATE_OPERATION_COUNTER_RECEIPT_SCHEMA_VERSION,
    OperationAttemptError as AggregateOperationAttemptError,
    OperationAttemptIdentity as AggregateOperationAttemptIdentity,
    OperationAttemptKind as AggregateOperationAttemptKind,
    OperationAttemptReceipt as AggregateOperationAttemptReceipt,
    OperationCertificate as AggregateOperationCertificate,
    OperationCounterReceipt as AggregateOperationCounterReceipt,
    OperationCounterValue as AggregateOperationCounterValue,
    OperationHotCounterReceipt as AggregateOperationHotCounterReceipt,
    OperationId as AggregateOperationId, OperationInvocation as AggregateOperationInvocation,
    OperationLimits as AggregateOperationLimits, OperationLimitsId as AggregateOperationLimitsId,
    OperationPhysicalRoute as AggregateOperationPhysicalRoute,
    OperationPrepublicationFallback as AggregateOperationPrepublicationFallback,
    OperationProspective as AggregateOperationProspective,
    OperationStructuralCounters as AggregateOperationStructuralCounters,
    OperationWorkMode as AggregateOperationWorkMode, PlanId as AggregatePlanId,
    Resource as AggregateResource, RowStorage as AggregateRowStorage, Span as AggregateSpan,
    Unsupported as AggregateUnsupported, continuation_sweep_run_upper_bounds,
    continuation_sweep_upper_bounds,
};
#[cfg(feature = "explicit-search-span-aot")]
pub use fre_aot_static_runtime::{
    StaticSearchSpanCallErrorV1, StaticSearchSpanFamilyExecutionPolicyV1,
    StaticSearchSpanThreadContractErrorV1, VerifiedStaticSearchSpanV1,
};
pub use fre_capture_lab::{
    AggregateLimits as CaptureAggregateLimits, BuildError as CaptureEngineBuildError,
    BuildLimits as CaptureEngineBuildLimits, BuildReport as CaptureEngineBuildReport,
    CaptureCountOutcome, CaptureRecord, GroupRecord as CaptureGroupRecord,
    MatchKind as CaptureMatchKind, PARTICIPATION_QUOTIENT_ACCOUNTING_VERSION,
    PARTICIPATION_QUOTIENT_ALGORITHM_VERSION, PARTICIPATION_QUOTIENT_CAPTURE_BITS,
    PARTICIPATION_QUOTIENT_MASK_BITS,
    ParticipationSearchProspective as CaptureParticipationSearchProspective,
    ResourceKind as CaptureResource, RunReport as CaptureSearchAccounting,
    SearchConfig as CaptureSearchConfig, SearchError as CaptureSearchError,
    SearchKind as CaptureSearchKind, SearchLimits as CaptureSearchLimits,
    SearchOutcome as CaptureSearchOutcome, Span as CaptureSpan, Window as CaptureWindow,
};
pub use fre_capture_lab::{
    CAPTURE_STREAM_ACCOUNTING_VERSION, CAPTURE_STREAM_ALGORITHM_VERSION, CaptureStreamAccounting,
    CaptureStreamDomains, CaptureStreamError, CaptureStreamLimits,
    CaptureStreamOperationProspective, CaptureStreamProjection, CaptureStreamProspective,
    CaptureStreamReport, CaptureStreamResource,
};
pub use fre_kernels::{
    ANCHORED_LINE_CAPTURE_COUNT_OPERATION_ID, ANCHORED_LINE_CAPTURE_MAX_ATOMS,
    ANCHORED_LINE_CAPTURE_PLAN_ID, AnchoredLineCaptureCountResult, AnchoredLineCaptureRunActual,
    AnchoredLineCaptureRunError, AnchoredLineCaptureRunLimits, AnchoredLineCaptureRunUpperBounds,
    FoldedLiteralTrieBuildError, FoldedLiteralTrieBuildLimits, FoldedLiteralTrieScanAttemptError,
    FoldedLiteralTrieScanError, FoldedLiteralTrieScanLimits,
    PACKED_ORDERED_LITERAL_CERTIFIED_MAX_PATTERNS, RequiredLiteralClassRepeat,
};
pub use fre_kernels::{
    AsciiSelection as SimdAsciiSelection, DispatchPolicy as SimdDispatchPolicy,
    DispatchProfile as SimdDispatchProfile, Feature as SimdFeature, FeatureSet as SimdFeatureSet,
    SimdDispatchContext, dispatch_profile as simd_dispatch_profile,
};
pub use fre_kernels::{
    BLOCKING_DELIMITER_COUNT_OPERATION_ID, BLOCKING_DELIMITER_PLAN_ID,
    BLOCKING_DELIMITER_SPAN_SUM_OPERATION_ID, BOUNDED_AFFIX_PLAN_ID,
    BOUNDED_CLASS_SEQUENCE_COUNT_OPERATION_ID, BOUNDED_CLASS_SEQUENCE_PLAN_ID,
    BOUNDED_CONTEXT_COUNT_OPERATION_ID, BOUNDED_CONTEXT_PLAN_ID,
    BOUNDED_CONTEXT_SPAN_SUM_OPERATION_ID, BOUNDED_LITERAL_PAIR_COUNT_OPERATION_ID,
    BOUNDED_LITERAL_PAIR_PLAN_ID, BOUNDED_LITERAL_PAIR_SPAN_SUM_OPERATION_ID,
    BOUNDED_SEPARATED_FIELDS_COUNT_OPERATION_ID, BOUNDED_SEPARATED_FIELDS_MAX_ALTERNATIVES,
    BOUNDED_SEPARATED_FIELDS_MAX_ATOMS, BOUNDED_SEPARATED_FIELDS_MAX_FIELDS,
    BOUNDED_SEPARATED_FIELDS_PLAN_ID, BlockingDelimiterActualCounters,
    BlockingDelimiterBuildAccounting, BlockingDelimiterBuildError, BlockingDelimiterBuildLimits,
    BlockingDelimiterOperationIdentity, BlockingDelimiterReduceAccounting,
    BlockingDelimiterReduceError, BlockingDelimiterReduceLimits, BlockingDelimiterTopology,
    BlockingDelimiterUpperBounds, BoundedClassSequenceActualCounters,
    BoundedClassSequenceBuildAccounting, BoundedClassSequenceBuildError,
    BoundedClassSequenceBuildLimits, BoundedClassSequenceOperationIdentity,
    BoundedClassSequenceReduceAccounting, BoundedClassSequenceReduceError,
    BoundedClassSequenceReduceLimits, BoundedClassSequenceUpperBounds,
    BoundedContextActualCounters, BoundedContextBuildAccounting, BoundedContextBuildError,
    BoundedContextBuildLimits, BoundedContextOperationIdentity, BoundedContextReduceAccounting,
    BoundedContextReduceError, BoundedContextReduceLimits, BoundedContextSpanSumAccounting,
    BoundedContextSpanSumActualCounters, BoundedContextSpanSumLimits,
    BoundedContextSpanSumUpperBounds, BoundedContextUpperBounds, BoundedLiteralPairActualCounters,
    BoundedLiteralPairBuildAccounting, BoundedLiteralPairBuildError, BoundedLiteralPairBuildLimits,
    BoundedLiteralPairOperationIdentity, BoundedLiteralPairReduceAccounting,
    BoundedLiteralPairReduceError, BoundedLiteralPairReduceLimits, BoundedLiteralPairTopology,
    BoundedLiteralPairUpperBounds, BoundedSeparatedFieldsActualCounters,
    BoundedSeparatedFieldsBuildAccounting, BoundedSeparatedFieldsBuildError,
    BoundedSeparatedFieldsBuildLimits, BoundedSeparatedFieldsOperationIdentity,
    BoundedSeparatedFieldsReduceAccounting, BoundedSeparatedFieldsReduceError,
    BoundedSeparatedFieldsReduceLimits, BoundedSeparatedFieldsUpperBounds,
    DISPATCHED_PREFIX_CLASS_ALTERNATION_PLAN_ID,
    DISPATCHED_PREFIX_CLASS_UNIFORM_PARTICIPATION_PLAN_ID,
    DISPATCHED_UNICODE_SCALAR_AGGREGATE_PLAN_ID, FIXED_ABSOLUTE_DOMAIN_ACCOUNTING_VERSION,
    FIXED_ABSOLUTE_DOMAIN_ALGORITHM_VERSION, FIXED_ABSOLUTE_DOMAIN_COUNT_OPERATION_ID,
    FIXED_ABSOLUTE_DOMAIN_PLAN_ID, FIXED_ABSOLUTE_DOMAIN_SPAN_SUM_OPERATION_ID,
    FIXED_CLASS_SANDWICH_COUNT_OPERATION_ID, FIXED_CLASS_SANDWICH_PLAN_ID,
    FIXED_CLASS_SANDWICH_SPAN_SUM_OPERATION_ID, FIXED_PREDICATE_WORD64_COUNT_OPERATION_ID,
    FIXED_PREDICATE_WORD64_MASK_SLOTS, FIXED_PREDICATE_WORD64_MAX_WIDTH,
    FIXED_PREDICATE_WORD64_MIN_WIDTH, FIXED_PREDICATE_WORD64_PLAN_ID,
    FIXED_PREDICATE_WORD64_SEARCH_PLAN_ID, FIXED_PREDICATE_WORD64_SPAN_SUM_OPERATION_ID,
    FixedAbsoluteDomainActual, FixedAbsoluteDomainBuildAccounting, FixedAbsoluteDomainBuildActual,
    FixedAbsoluteDomainBuildError, FixedAbsoluteDomainBuildErrorKind,
    FixedAbsoluteDomainBuildLimits, FixedAbsoluteDomainBuildProspective,
    FixedAbsoluteDomainBuildResource, FixedAbsoluteDomainContentDigest,
    FixedAbsoluteDomainCountOutcome, FixedAbsoluteDomainDescriptorIdentity,
    FixedAbsoluteDomainDescriptorKind, FixedAbsoluteDomainDisposition,
    FixedAbsoluteDomainOperation, FixedAbsoluteDomainOperationIdentity,
    FixedAbsoluteDomainProspective, FixedAbsoluteDomainReduceAccounting,
    FixedAbsoluteDomainReduceError, FixedAbsoluteDomainReduceErrorKind,
    FixedAbsoluteDomainReduceFailureReceipt, FixedAbsoluteDomainReduceLimits,
    FixedAbsoluteDomainReduceResource, FixedAbsoluteDomainResidual,
    FixedClassSandwichActualCounters, FixedClassSandwichBuildAccounting,
    FixedClassSandwichBuildError, FixedClassSandwichBuildLimits, FixedClassSandwichOperation,
    FixedClassSandwichOperationIdentity, FixedClassSandwichReduceAccounting,
    FixedClassSandwichReduceError, FixedClassSandwichReduceLimits, FixedClassSandwichSemantics,
    FixedClassSandwichUpperBounds, FixedPredicateWord64ActualCounters,
    FixedPredicateWord64AdaptiveFinderIdentity, FixedPredicateWord64AdaptiveFinderKind,
    FixedPredicateWord64AdaptiveHandoffIdentity, FixedPredicateWord64BuildAccounting,
    FixedPredicateWord64BuildError, FixedPredicateWord64BuildLimits,
    FixedPredicateWord64CountResult, FixedPredicateWord64ExactAnchorIdentity,
    FixedPredicateWord64MatchSelection, FixedPredicateWord64MatchSemantics,
    FixedPredicateWord64Operation, FixedPredicateWord64OperationIdentity, FixedPredicateWord64Plan,
    FixedPredicateWord64ReduceAccounting, FixedPredicateWord64ReduceError,
    FixedPredicateWord64ReduceLimits, FixedPredicateWord64Reducer,
    FixedPredicateWord64SearchAccounting, FixedPredicateWord64SearchActualCounters,
    FixedPredicateWord64SearchError, FixedPredicateWord64SearchLimits,
    FixedPredicateWord64SearchOperation, FixedPredicateWord64SearchOperationIdentity,
    FixedPredicateWord64SearchUpperBounds, FixedPredicateWord64SpanSumResult,
    FixedPredicateWord64UpperBounds, GraphemeScalarDfaActualCounters,
    GraphemeScalarDfaBuildAccounting, GraphemeScalarDfaBuildError, GraphemeScalarDfaBuildLimits,
    GraphemeScalarDfaOperation, GraphemeScalarDfaOperationIdentity,
    GraphemeScalarDfaReduceAccounting, GraphemeScalarDfaReduceError, GraphemeScalarDfaReduceLimits,
    GraphemeScalarDfaRole, GraphemeScalarDfaSemantics, GraphemeScalarDfaUpperBounds,
    LITERAL_AGGREGATE_ACCOUNTING_VERSION, LITERAL_AGGREGATE_ALGORITHM_VERSION,
    LITERAL_ASSERTIONS_COUNT_OPERATION_ID, LITERAL_ASSERTIONS_PLAN_ID,
    LITERAL_ASSERTIONS_SPAN_SUM_OPERATION_ID, LITERAL_CLASS_RUN_GENERAL_SEARCH_OPERATION_ID,
    LITERAL_CLASS_RUN_GENERAL_SEARCH_PLAN_ID,
    LITERAL_CLASS_RUN_GENERAL_SHORTEST_SEARCH_OPERATION_ID,
    LITERAL_CLASS_RUN_LITERAL_COUNT_OPERATION_ID, LITERAL_CLASS_RUN_LITERAL_PLAN_ID,
    LITERAL_CLASS_RUN_LITERAL_SPAN_SUM_OPERATION_ID, LiteralAggregateActualCounters,
    LiteralAggregateBuildAccounting, LiteralAggregateBuildError, LiteralAggregateBuildLimits,
    LiteralAggregateCountAttempt, LiteralAggregateDeclaredFallback, LiteralAggregateOperation,
    LiteralAggregateOperationIdentity, LiteralAggregatePlanOrigin,
    LiteralAggregateReduceAccounting, LiteralAggregateReduceAttemptError,
    LiteralAggregateReduceAttemptReceipt, LiteralAggregateReduceError,
    LiteralAggregateReduceInvocation, LiteralAggregateReduceLimits, LiteralAggregateSpanSumAttempt,
    LiteralAggregateUpperBounds, LiteralAssertionsActualCounters, LiteralAssertionsBuildAccounting,
    LiteralAssertionsBuildError, LiteralAssertionsBuildLimits, LiteralAssertionsOperationIdentity,
    LiteralAssertionsReduceAccounting, LiteralAssertionsReduceError, LiteralAssertionsReduceLimits,
    LiteralAssertionsTopology, LiteralAssertionsUpperBounds, LiteralClassRunLiteralActualCounters,
    LiteralClassRunLiteralBoundarySemantics, LiteralClassRunLiteralBuildAccounting,
    LiteralClassRunLiteralBuildError, LiteralClassRunLiteralBuildLimits,
    LiteralClassRunLiteralOperationIdentity, LiteralClassRunLiteralReduceAccounting,
    LiteralClassRunLiteralReduceError, LiteralClassRunLiteralReduceLimits,
    LiteralClassRunLiteralSearchAccounting, LiteralClassRunLiteralSearchError,
    LiteralClassRunLiteralSearchLimits, LiteralClassRunLiteralUpperBounds,
    LiteralClassRunSearchMinimum, ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    ORDERED_LITERAL_COUNT_PLAN_ID, ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    OrderedLiteralAggregateActualCounters, OrderedLiteralAggregateBuildAccounting,
    OrderedLiteralAggregateBuildError, OrderedLiteralAggregateBuildLimits,
    OrderedLiteralAggregateReduceError, OrderedLiteralAggregateReduceLimits,
    OrderedLiteralAggregateUpperBounds, PACKED_BOUNDED_PREFIX_LITERAL_COUNT_PLAN_ID,
    PACKED_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID, PACKED_ORDERED_LITERAL_COUNT_PLAN_ID,
    PACKED_ORDERED_LITERAL_SPAN_SUM_PLAN_ID, PREFIX_CLASS_ALTERNATION_COUNT_OPERATION_ID,
    PREFIX_CLASS_ALTERNATION_PLAN_ID, PREFIX_CLASS_ALTERNATION_SPAN_SUM_OPERATION_ID,
    PREFIX_CLASS_UNIFORM_PARTICIPATION_ACCOUNTING_VERSION,
    PREFIX_CLASS_UNIFORM_PARTICIPATION_ALGORITHM_VERSION,
    PREFIX_CLASS_UNIFORM_PARTICIPATION_OPERATION_ID, PREFIX_CLASS_UNIFORM_PARTICIPATION_PLAN_ID,
    PackedBoundedPrefixLiteralBounds, PackedOrderedLiteralAggregateActualCounters,
    PackedOrderedLiteralAggregateBuildAccounting, PackedOrderedLiteralAggregateBuildError,
    PackedOrderedLiteralAggregateBuildLimits, PackedOrderedLiteralAggregateOperationIdentity,
    PackedOrderedLiteralAggregateReduceError, PackedOrderedLiteralAggregateReduceLimits,
    PackedOrderedLiteralAggregateUpperBounds, PrefixClassAlternationActualCounters,
    PrefixClassAlternationBuildAccounting, PrefixClassAlternationBuildError,
    PrefixClassAlternationBuildLimits, PrefixClassAlternationOperationIdentity,
    PrefixClassAlternationReduceAccounting, PrefixClassAlternationReduceError,
    PrefixClassAlternationReduceLimits, PrefixClassAlternationRunScannerBuildAccounting,
    PrefixClassAlternationSpanSumResult, PrefixClassAlternationUpperBounds,
    PrefixClassUniformParticipationAccounting, PrefixClassUniformParticipationActual,
    PrefixClassUniformParticipationAttempt, PrefixClassUniformParticipationAttemptError,
    PrefixClassUniformParticipationAttemptReceipt, PrefixClassUniformParticipationBuildAccounting,
    PrefixClassUniformParticipationBuildError, PrefixClassUniformParticipationBuildLimits,
    PrefixClassUniformParticipationError, PrefixClassUniformParticipationIdentity,
    PrefixClassUniformParticipationInvocation, PrefixClassUniformParticipationLimits,
    PrefixClassUniformParticipationProspective, PrefixClassUniformParticipationResult,
    PrefixClassUniformParticipationSchema, REVERSE_INNER_COUNT_OPERATION_ID,
    REVERSE_INNER_MAX_LITERALS, REVERSE_INNER_PLAN_ID, REVERSE_INNER_SPAN_SUM_OPERATION_ID,
    ReverseInnerActualCounters, ReverseInnerBuildAccounting, ReverseInnerBuildError,
    ReverseInnerBuildLimits, ReverseInnerOperation, ReverseInnerOperationIdentity,
    ReverseInnerReduceAccounting, ReverseInnerReduceError, ReverseInnerReduceLimits,
    ReverseInnerSemantics, ReverseInnerUpperBounds, SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID, SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    SparseOrderedLiteralAggregateActualCounters, SparseOrderedLiteralAggregateBuildAccounting,
    SparseOrderedLiteralAggregateBuildError, SparseOrderedLiteralAggregateBuildLimits,
    SparseOrderedLiteralAggregateReduceError, SparseOrderedLiteralAggregateReduceLimits,
    SparseOrderedLiteralAggregateUpperBounds, SparseOrderedLiteralCountPlan,
    TOKEN_PHRASE_COUNT_OPERATION_ID, TOKEN_PHRASE_PLAN_ID, TOKEN_PHRASE_SPAN_SUM_OPERATION_ID,
    TokenPhraseActualCounters, TokenPhraseBuildAccounting, TokenPhraseBuildError,
    TokenPhraseBuildLimits, TokenPhraseOperationIdentity, TokenPhraseReduceAccounting,
    TokenPhraseReduceError, TokenPhraseReduceLimits, TokenPhraseRoute, TokenPhraseTopology,
    TokenPhraseUpperBounds, UnicodeScalarAggregateBuildAccounting,
    UnicodeScalarAggregateBuildError, UnicodeScalarAggregateBuildLimits,
    UnicodeScalarAggregateOperation, UnicodeScalarAggregateOperationIdentity,
    UnicodeScalarAggregateReduceAccounting, UnicodeScalarAggregateReduceError,
    UnicodeScalarAggregateReduceLimits, UnicodeScalarAggregateRepetition,
    UnicodeScalarAggregateSemantics, UnicodeScalarAggregateUpperBounds, UrlAggregateReduceError,
    UrlAggregateReduceUpperBounds, url_aggregate_reduce_upper_bounds,
};
pub use operation_session::hot::{
    HOT_BYTE_PROGRAM_ACCOUNTING_ID, HOT_BYTE_PROGRAM_ACCOUNTING_VERSION,
    HOT_BYTE_PROGRAM_ALGORITHM_VERSION, HotByteBuildAccounting, HotByteBuildError,
    HotByteBuildLimits, HotByteBuildReceipt, HotByteBuildResource, HotByteDispatch,
    HotByteIneligibility, HotByteProgramArtifact, HotByteProgramBuilder, HotByteRunError,
    HotByteRunLimits, HotKernelPreparationError,
};
pub use operation_session::{
    OperationSession, OperationSessionAdmission, OperationSessionAttemptReceipt,
    OperationSessionConstructionLimits, OperationSessionConstructionReceipt, OperationSessionLeaf,
    OperationSessionReducer, OperationSessionResetLimits, OperationSessionRunLimits,
    OperationSessionValue,
};
#[cfg(feature = "qualified-exact-search-jit")]
pub use qualified_exact_search::{
    QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION, QUALIFIED_EXACT_SEARCH_LARGE_MIN_SEARCHES,
    QUALIFIED_EXACT_SEARCH_LARGE_WINDOW_BYTES, QUALIFIED_EXACT_SEARCH_LITERAL_BYTES,
    QUALIFIED_EXACT_SEARCH_MIN_SEARCHES, QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
    QUALIFIED_EXACT_SEARCH_QUALIFICATION, QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION,
    QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
    QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION, QualifiedExactSearch,
    QualifiedExactSearchBackendPolicy, QualifiedExactSearchBuildError,
    QualifiedExactSearchBuildReport, QualifiedExactSearchCacheUnavailable,
    QualifiedExactSearchError, QualifiedExactSearchExecution, QualifiedExactSearchFacade,
    QualifiedExactSearchFacadeBuildError, QualifiedExactSearchFacadeError,
    QualifiedExactSearchFacadeExecution, QualifiedExactSearchFacadeRoute,
    QualifiedExactSearchFacadeSelection, QualifiedExactSearchFacadeThreadSession,
    QualifiedExactSearchNativeAbi, QualifiedExactSearchNativeIdentity,
    QualifiedExactSearchNativeStatus, QualifiedExactSearchQualification, QualifiedExactSearchRoute,
    QualifiedExactSearchThreadContractError, QualifiedExactSearchThreadSession,
    QualifiedExactSearchWorkload,
};
pub use replacement::{
    CaptureExpansionAccounting, CaptureExpansionError, CaptureExpansionLimits,
    CaptureExpansionReport, CaptureExpansionResult, FunctionalReplacementAccounting,
    FunctionalReplacementError, FunctionalReplacementErrorSource, FunctionalReplacementIdentity,
    FunctionalReplacementLimits, FunctionalReplacementReport, FunctionalReplacementResult,
    LiteralReplacementAccounting, LiteralReplacementError, LiteralReplacementErrorSource,
    LiteralReplacementIdentity, LiteralReplacementLimits, LiteralReplacementReport,
    LiteralReplacementResult, LiteralReplacer, NoExpand,
};
pub use search_aot::{
    SEARCH_EXACT_LITERAL_AOT_FIXED_BUILD_POLICY_VERSION,
    SEARCH_EXACT_LITERAL_AOT_SEMANTIC_BINDING_SCHEMA_VERSION, SearchExactLiteralAotCandidate,
    SearchExactLiteralAotSemanticBindingIdentity,
};
#[cfg(feature = "explicit-search-span-aot")]
pub use search_aot_facade::{
    SearchExactLiteralAotBindErrorV1, SearchExactLiteralAotThreadSessionV1,
    SearchExactLiteralAotV1, SearchExactLiteralAutoAotV1,
};
#[cfg(feature = "compiled-search-v25-aot")]
pub use search_aot_facade::{
    SearchExactLiteralCompiledAotV25, SearchExactLiteralCompiledAotV25Error,
    SearchExactLiteralCompiledAotV25Fallback, SearchExactLiteralCompiledAotV25Route,
};
#[cfg(feature = "compiled-search-v26-aot")]
pub use search_aot_facade::{
    SearchExactLiteralCompiledAotV26, SearchExactLiteralCompiledAotV26Error,
    SearchExactLiteralCompiledAotV26Fallback, SearchExactLiteralCompiledAotV26Route,
};
#[cfg(feature = "compiled-search-v27-aot")]
pub use search_aot_facade::{
    SearchExactLiteralCompiledAotV27, SearchExactLiteralCompiledAotV27Error,
    SearchExactLiteralCompiledAotV27Fallback, SearchExactLiteralCompiledAotV27Route,
};
pub use set::{
    PORTABLE_REGEX_SET_EXPLAIN_SCHEMA_VERSION, PortableRegexSet, PortableRegexSetBuildError,
    PortableRegexSetBuildLimits, PortableRegexSetBuildReport, PortableRegexSetBuilder,
    PortableRegexSetExecutionError, PortableRegexSetExecutionReport, PortableRegexSetRunLimits,
    PortableSetMatches, PortableSetMatchesIntoIter, PortableSetMatchesIter,
};
pub use split::{AggregateSplit, PortableSplit};
pub use text::{
    PortableTextBuildError, PortableTextBuildReport, PortableTextBuilder, PortableTextMatches,
    PortableTextProof, PortableTextRegex, PortableTextSearchError, PortableTextSearchSession,
    PortableTextSessionMatches,
};
pub use text_match::{PortableTextBorrowedMatches, PortableTextMatch};
pub use text_set::{
    PORTABLE_TEXT_REGEX_SET_EXPLAIN_SCHEMA_VERSION, PortableTextRegexSet,
    PortableTextRegexSetBuildError, PortableTextRegexSetBuildReport, PortableTextRegexSetBuilder,
};

use fre_automata::{
    Automaton, EarliestEnd, Exists, K0PositiveEndLimits, K0PositiveEndOutcome, K0SearchSession,
    K0SpanSourceCursor, MandatoryCutAnalysis, MandatoryCutAnalysisLimits, MandatoryCutCandidate,
    MandatoryCutDeclineReason, MandatoryCutResource, MandatorySuffixAnalysis,
    MandatorySuffixAnalysisLimits, MandatorySuffixDeclineReason, MandatorySuffixResource,
    MaximumConsumedDistance, SelectedEnd, Span,
};
use fre_kernels::{
    ASCII_RUN_SCANNER_BUILD_WORK, AbsoluteEndFixedPlan, AsciiByteSet, AsciiByteSetRunScanner,
    BoundedRequiredLiteralPlan, DispatchedBoundedRequiredLiteralPlan, DispatchedForwardAnchoredPlan,
    DispatchedRequiredLiteralPlan, ForwardAnchoredBuildAccounting,
    ForwardAnchoredBuildError, ForwardAnchoredBuildLimits, ForwardAnchoredPlan,
    ForwardAnchoredSearchAccounting, ForwardAnchoredSearchError, ForwardAnchoredSearchLimits,
    LiteralAccounting, LiteralBuildLimits, LiteralClassRunLiteralPlan, LiteralClassRunSearchPlan,
    LiteralError, LiteralPlan, LiteralSearchLimits, LiteralSetAccounting, LiteralSetBuildLimits,
    LiteralSetError, LiteralSetPlan, LiteralSetSearchLimits,
    PACKED_LITERAL_SET_CERTIFIED_MAX_PATTERNS, PackedLiteralSetAccounting,
    PackedLiteralSetBuildLimits, PackedLiteralSetError, PackedLiteralSetPlan,
    PackedLiteralSetSearchLimits, RequiredLiteralBuildAccounting, RequiredLiteralBuildError,
    RequiredLiteralBuildLimits, RequiredLiteralPlan, RequiredLiteralSearchAccounting,
    RequiredLiteralSearchError, RequiredLiteralSearchLimits, Window as LiteralWindow,
};
use fre_lower::{LowerLimits, LowerStats, OperationSemantics};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CanonicalPattern, ParseSummary, SafetyEnvelope,
};

pub use fre_syntax::{CompatibilityProfile, RustProfile};
pub use guarded_literal_set::{
    SearchAccounting as GuardedLiteralSetSearchAccounting,
    SearchActual as GuardedLiteralSetSearchActual, SearchError as GuardedLiteralSetSearchError,
    SearchUpperBounds as GuardedLiteralSetSearchUpperBounds,
};
pub use line_capture::{
    ANCHORED_ASCII_SEPARATED_FIELDS_CAPTURE_PATTERN,
    ANCHORED_ASCII_SEPARATED_FIELDS_INSPECTION_WORK, ANCHORED_ASCII_SEPARATED_FIELDS_OPERATION_ID,
    LineCaptureBuildError, LineCaptureBuildLimits, LineCaptureBuildReport,
    LineCaptureBuildResource, LineCaptureBuilder, LineCaptureConfiguration,
    LineCaptureOperationIdentity, LineCapturePlan, LineCapturePlanIdentity, LineCapturePlanKind,
    LineCaptureResource, LineCaptureRunError, LineCaptureRunLimits, LineCaptureRunReport,
    SHEBANG_CAPTURE_PATTERN, SHEBANG_INSPECTION_WORK, SHEBANG_OPERATION_ID,
    SPACE_AROUND_OPERATOR_CAPTURE_PATTERN, SPACE_AROUND_OPERATOR_INSPECTION_WORK,
    SPACE_AROUND_OPERATOR_OPERATION_ID, STRING_QUOTE_PREFIX_CAPTURE_PATTERN,
    STRING_QUOTE_PREFIX_INSPECTION_WORK, STRING_QUOTE_PREFIX_OPERATION_ID,
    WHITESPACE_AROUND_KEYWORDS_CAPTURE_PATTERN, WHITESPACE_AROUND_KEYWORDS_INSPECTION_WORK,
    WHITESPACE_AROUND_KEYWORDS_OPERATION_ID,
};

pub use fre_automata::{
    DirectReduceLimits, ForcedExecution, PreparationAccounting, PriorityExecutionKernel,
    PriorityTarget, ReduceError, SearchError as K0SearchError, SearchLimits, SearchWindow,
    SetupAccounting as SearchSessionSetupAccounting, WorkspaceLimits as SearchSessionLimits,
};
pub use unicode_word_run::{
    AGGREGATE_COUNT_OPERATION_ID as WORD_RUN_COUNT_OPERATION_ID,
    AGGREGATE_SPAN_SUM_OPERATION_ID as WORD_RUN_SPAN_SUM_OPERATION_ID,
    ASCII_PLAN_ID as ASCII_WORD_RUN_PLAN_ID, Accounting as UnicodeWordRunAccounting,
    AggregateBuildAccounting as WordRunBuildAccounting, AggregateBuildError as WordRunBuildError,
    AggregateBuildLimits as WordRunBuildLimits, AggregateCountResult as WordRunCountResult,
    AggregateOperationIdentity as WordRunOperationIdentity,
    AggregateReduceAccounting as WordRunReduceAccounting,
    AggregateReduceActual as WordRunReduceActual, AggregateReduceError as WordRunReduceError,
    AggregateReduceLimits as WordRunReduceLimits, AggregateReduceResource as WordRunReduceResource,
    AggregateReduceUpperBounds as WordRunReduceUpperBounds,
    AggregateSpanSumResult as WordRunSpanSumResult, Error as UnicodeWordRunError,
    FIXED_CLASS_CHUNKS_COUNT_OPERATION_ID, FIXED_CLASS_CHUNKS_PLAN_ID,
    FIXED_CLASS_CHUNKS_SPAN_SUM_OPERATION_ID, UNICODE_PLAN_ID as UNICODE_WORD_RUN_PLAN_ID,
    WordRunTopology, aggregate_build_accounting_matches as word_run_build_accounting_matches,
};

/// Stable schema for facade-level explanation records.
pub const EXPLAIN_SCHEMA_VERSION: u32 = 12;

// Automatic ordinary search admits every fixed-width plan with an exact
// one- or two-byte anchor. Construction already proves a word width of at
// most 64, so one primary anchor leaves at most 63 non-universal verification
// predicates. The retained adaptive finder and final Shift-And handoff keep
// dense rejection streams inside the kernel's closed linear bound.
const FIXED_PREDICATE_SEARCH_AUTO_MAX_VERIFICATION_PREDICATES: usize =
    FIXED_PREDICATE_WORD64_MAX_WIDTH - 1;

/// Escapes all regular-expression meta characters in `pattern`.
///
/// The returned string is safe to use as a literal in a Rust-compatible
/// regular expression. Its behavior is pinned by FRE's exact
/// `regex-syntax` 0.8.11 dependency, which is also part of
/// [`RustProfile::regex_1_12_4`].
#[must_use]
pub fn escape(pattern: &str) -> String {
    regex_syntax::escape(pattern)
}

/// Construction limits whose identities affect admission or lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    /// Exact-upstream-pending strict mode or an explicitly FRE-quota mode.
    pub admission: AdmissionPolicy,
    /// Non-configurable-in-production hard syntax safety envelope.
    pub syntax_safety: SafetyEnvelope,
    /// Checked graph construction limits.
    pub lowering: LowerLimits,
    /// Persistent exact-literal kernel limit.
    pub literal: LiteralBuildLimits,
    /// Bounded DFA fallback for an exactly enumerated finite language.
    pub literal_set: LiteralSetBuildLimits,
    /// SIMD packed plan limits for an exactly enumerated finite language.
    pub packed_literal_set: PackedLiteralSetBuildLimits,
    /// Proof-restricted positive greedy `CLASS{min,max} SUFFIX` construction limits.
    pub required_literal: RequiredLiteralBuildLimits,
    /// Canonical `LITERAL? BYTE_CLASS+ LITERAL?` construction limits.
    pub literal_class_run_literal: LiteralClassRunLiteralBuildLimits,
    /// Unique-boundary `\A CLASS+ SUFFIX (?:\z)?` construction limits.
    pub forward_anchored: ForwardAnchoredBuildLimits,
    /// Maximum checked planner traversal/copy work.
    pub max_planner_work: u64,
    /// Maximum logical bytes retained by the published source, capture-name
    /// metadata and selected execution plan.
    pub max_persistent_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            lowering: LowerLimits::default(),
            literal: LiteralBuildLimits::default(),
            literal_set: LiteralSetBuildLimits::default(),
            packed_literal_set: PackedLiteralSetBuildLimits::default(),
            required_literal: RequiredLiteralBuildLimits::default(),
            literal_class_run_literal: LiteralClassRunLiteralBuildLimits::default(),
            forward_anchored: ForwardAnchoredBuildLimits::default(),
            max_planner_work: 8_000_000,
            max_persistent_bytes: 268_435_456,
        }
    }
}

/// A half-open byte match in the original haystack.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Match {
    start: usize,
    end: usize,
}

impl Match {
    /// Inclusive byte start.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive byte end.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Whether the selected match consumed no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Number of matched bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Half-open byte range in the original haystack.
    #[must_use]
    pub const fn range(self) -> core::ops::Range<usize> {
        self.start..self.end
    }
}

/// A byte match that retains the exact original haystack it was selected from.
///
/// [`Match`] remains the small offset-only value used by accounting-oriented
/// APIs. This companion preserves the pinned Rust bytes API's borrowed-match
/// contract, including direct access to the matched bytes and lossless
/// conversion to either the bytes or their original range.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ByteMatch<'h> {
    haystack: &'h [u8],
    span: Match,
}

impl<'h> ByteMatch<'h> {
    /// Inclusive byte start in the original haystack.
    #[must_use]
    pub const fn start(self) -> usize {
        self.span.start()
    }

    /// Exclusive byte end in the original haystack.
    #[must_use]
    pub const fn end(self) -> usize {
        self.span.end()
    }

    /// Whether the selected match consumed no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.span.is_empty()
    }

    /// Number of matched bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.span.len()
    }

    /// Half-open byte range in the original haystack.
    #[must_use]
    pub const fn range(self) -> core::ops::Range<usize> {
        self.span.range()
    }

    /// The exact bytes selected from the original haystack.
    #[must_use]
    pub fn as_bytes(&self) -> &'h [u8] {
        &self.haystack[self.span.range()]
    }
}

impl fmt::Debug for ByteMatch<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ByteMatch")
            .field("start", &self.start())
            .field("end", &self.end())
            .field("bytes", &DebugMatchBytes(self.as_bytes()))
            .finish()
    }
}

/// Pinned Rust-regex debug escaping for a byte match's selected haystack.
///
/// Valid UTF-8 is formatted like a Rust string while each byte that cannot be
/// decoded is emitted as a lower-case hexadecimal escape. Keeping this helper
/// private avoids adding a formatting type to the public compatibility
/// surface.
struct DebugMatchBytes<'a>(&'a [u8]);

impl fmt::Debug for DebugMatchBytes<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"")?;
        let mut bytes = self.0;
        while !bytes.is_empty() {
            match core::str::from_utf8(bytes) {
                Ok(valid) => {
                    write_debug_match_str(formatter, valid)?;
                    bytes = &[];
                }
                Err(error) => {
                    let valid_up_to = error.valid_up_to();
                    let valid = core::str::from_utf8(&bytes[..valid_up_to])
                        .expect("UTF-8 error's valid prefix must decode");
                    write_debug_match_str(formatter, valid)?;
                    write!(formatter, r"\x{:02x}", bytes[valid_up_to])?;
                    bytes = &bytes[valid_up_to.saturating_add(1)..];
                }
            }
        }
        formatter.write_str("\"")
    }
}

fn write_debug_match_str(formatter: &mut fmt::Formatter<'_>, valid: &str) -> fmt::Result {
    for character in valid.chars() {
        match character {
            '\0' => formatter.write_str("\\0")?,
            '\u{1}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{19}' | '\u{7f}' => {
                write!(formatter, "\\x{:02x}", u32::from(character))?;
            }
            _ => write!(formatter, "{}", character.escape_debug())?,
        }
    }
    Ok(())
}

impl<'h> From<ByteMatch<'h>> for &'h [u8] {
    fn from(matched: ByteMatch<'h>) -> Self {
        matched.as_bytes()
    }
}

impl From<ByteMatch<'_>> for core::ops::Range<usize> {
    fn from(matched: ByteMatch<'_>) -> Self {
        matched.range()
    }
}

/// Auditable construction facts for one portable plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildReport {
    /// Complete compatibility profile selected before parsing.
    pub profile: CompatibilityProfile,
    /// What has and has not established constructor admission.
    pub admission: AdmissionStatus,
    /// Bounded syntax traversal facts.
    pub syntax: ParseSummary,
    /// Selected execution-plan family.
    pub plan: PlanKind,
    /// Checked planner traversal/copy work.
    pub planner_work: u64,
    /// Checked K0 lowering facts, absent for direct native finite-language plans.
    pub lowering: Option<LowerStats>,
    /// Immutable state count after independent automata validation.
    pub states: usize,
    /// Immutable edge count after independent automata validation.
    pub edges: usize,
    /// Immutable logical table payload bytes.
    pub plan_storage_bytes: usize,
    /// Exact retained bytes for the original pattern source.
    pub source_storage_bytes: usize,
    /// Exact logical heap bytes retained for indexed capture-name metadata.
    pub capture_name_storage_bytes: usize,
    /// Checked sum of source, capture-name and selected-plan logical bytes.
    pub charged_persistent_bytes: usize,
    /// Total persistent-byte ceiling enforced before publication.
    pub persistent_byte_limit: usize,
    /// Total capture slots, including the implicit whole-match slot.
    pub captures_len: usize,
    /// Capture slots present in every possible match, including the implicit
    /// whole-match slot, or `None` when participation cardinality can vary.
    pub static_captures_len: Option<usize>,
    /// Exact minimum bytes consumed by any match, or `None` if the HIR's
    /// language is empty. This is preserved for future aggregate routing.
    pub minimum_match_bytes: Option<usize>,
    /// Complete construction certificate for the proof-restricted plan.
    pub required_literal: Option<RequiredLiteralBuildAccounting>,
    /// Complete construction certificate for the literal/class-run plan.
    pub literal_class_run_literal: Option<LiteralClassRunLiteralBuildAccounting>,
    /// Complete construction certificate for the forward-boundary plan.
    pub forward_anchored: Option<ForwardAnchoredBuildAccounting>,
}

/// An honestly labelled selected plan family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanKind {
    /// SIMD-aware shared native exact-substring primitive. This is not JIT.
    ExactLiteral,
    /// Shared native finite-literal primitive, including the fixed-column
    /// exact complete-word composition. This is not JIT.
    PackedLiteralSet,
    /// Bounded ordered finite-literal DFA used when packed search is ineligible.
    LiteralSetDfa,
    /// Proof-restricted SIMD-aware `CLASS{min,max} SUFFIX` kernel. This is not JIT.
    RequiredLiteral,
    /// Canonical literal/class-run search backed by one native literal anchor.
    LiteralClassRunLiteral,
    /// Operation-specialized root byte class repeated one or more times.
    PureByteClassRepeat,
    /// Finite positive greedy byte-class sequence with deterministic boundaries.
    BoundedByteClassSequence,
    /// Absolute-start unique-boundary forward scan. This is not JIT.
    ForwardAnchored,
    /// Generic bounded portable prioritized automaton.
    K0,
    /// Ordered Unicode simple-fold scalar sequences backed by a sparse trie.
    UnicodeFoldedLiteral,
    /// Linear ASCII or Unicode word-boundary class-run scan.
    UnicodeWordRun,
    /// Fixed-width Cartesian byte predicates backed by one 64-bit Shift-And state.
    FixedPredicateWord64,
}

/// Construction failure without semantic fallback.
#[derive(Debug)]
#[non_exhaustive]
pub enum BuildError {
    /// Syntax/profile/admission failure.
    Syntax(fre_syntax::ParseError),
    /// The syntax was valid but is outside the certified portable lowering.
    Lower(fre_lower::LowerError),
    /// Operation-specific kernel construction failure.
    Literal(LiteralError),
    /// Ordered finite-literal DFA construction failure.
    LiteralSet(LiteralSetError),
    /// Required-literal proof or construction failure.
    RequiredLiteral(RequiredLiteralBuildError),
    /// Literal/class-run proof revalidation or construction failure.
    LiteralClassRunLiteral(LiteralClassRunLiteralBuildError),
    /// A forced required-literal request did not have the exact HIR shape.
    RequiredLiteralShape,
    /// Forward-anchored proof or construction failure.
    ForwardAnchored(ForwardAnchoredBuildError),
    /// A forced forward-anchored request did not have the exact HIR shape.
    ForwardAnchoredShape,
    /// Checked planner work was exhausted before plan selection.
    PlannerWorkLimit { needed: u64, limit: u64 },
    /// Persistent-byte accounting overflowed `usize`.
    PersistentBytesOverflow,
    /// The completed matcher exceeded the total persistent-byte ceiling.
    PersistentBytesLimit { needed: usize, limit: usize },
    /// A planner buffer could not be reserved.
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
    /// Internal facade/profile mismatch.
    InternalInvariant(&'static str),
}

/// Stable top-level classification for a failed portable construction.
///
/// This is deliberately coarser than [`BuildError`]. It lets conformance
/// adapters distinguish an upstream-invalid pattern from an FRE capability
/// gap, an explicitly configured resource refusal, invalid profile state, or
/// an internal construction failure without parsing diagnostic text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildFailureClass {
    /// The pinned syntax front-end rejected the pattern or its encoding.
    ExpectedInvalid,
    /// The pattern is valid but outside the currently certified executor.
    Unsupported,
    /// A checked caller-configured construction bound was exceeded.
    ResourceLimit,
    /// The requested compatibility profile or builder configuration is invalid.
    InvalidConfiguration,
    /// Allocation, arithmetic, emitted-plan, or facade invariants failed.
    InternalFailure,
}

impl BuildError {
    /// Classify this failure without inspecting its human-readable message.
    #[must_use]
    pub fn failure_class(&self) -> BuildFailureClass {
        match self {
            Self::Syntax(error) => match &error.category {
                fre_syntax::ErrorCategory::InvalidPatternEncoding
                | fre_syntax::ErrorCategory::UpstreamRustSyntax
                | fre_syntax::ErrorCategory::UpstreamRustCompiledTooBig { .. }
                | fre_syntax::ErrorCategory::Re2Syntax { .. } => BuildFailureClass::ExpectedInvalid,
                fre_syntax::ErrorCategory::FreResourceLimit { .. }
                | fre_syntax::ErrorCategory::StrictQualificationFailure { .. } => {
                    BuildFailureClass::ResourceLimit
                }
                fre_syntax::ErrorCategory::UnsupportedNotYetImplemented { .. } => {
                    BuildFailureClass::Unsupported
                }
                fre_syntax::ErrorCategory::InvalidConfiguration => {
                    BuildFailureClass::InvalidConfiguration
                }
            },
            Self::Lower(error) => lower_failure_class(error),
            Self::Literal(error) => match error {
                LiteralError::NeedleLimit { .. } | LiteralError::LinearTermLimit { .. } => {
                    BuildFailureClass::ResourceLimit
                }
                _ => BuildFailureClass::InternalFailure,
            },
            Self::LiteralSet(error) => match error {
                LiteralSetError::PatternLimit { .. }
                | LiteralSetError::PatternBytesLimit { .. }
                | LiteralSetError::BuildWorkLimit { .. }
                | LiteralSetError::BuildBytesLimit { .. }
                | LiteralSetError::PersistentBytesLimit { .. }
                | LiteralSetError::TransitionLimit { .. } => BuildFailureClass::ResourceLimit,
                _ => BuildFailureClass::InternalFailure,
            },
            Self::RequiredLiteral(error) => required_literal_failure_class(error),
            Self::LiteralClassRunLiteral(error) => literal_class_run_literal_failure_class(error),
            Self::RequiredLiteralShape | Self::ForwardAnchoredShape => {
                BuildFailureClass::Unsupported
            }
            Self::ForwardAnchored(error) => forward_anchored_failure_class(error),
            Self::PlannerWorkLimit { .. } | Self::PersistentBytesLimit { .. } => {
                BuildFailureClass::ResourceLimit
            }
            Self::PersistentBytesOverflow
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => BuildFailureClass::InternalFailure,
        }
    }
}

fn lower_failure_class(error: &fre_lower::LowerError) -> BuildFailureClass {
    match error {
        fre_lower::LowerError::Unsupported(_) => BuildFailureClass::Unsupported,
        fre_lower::LowerError::ResourceLimit { .. }
        | fre_lower::LowerError::Automata(fre_automata::CompileError::ResourceLimit { .. }) => {
            BuildFailureClass::ResourceLimit
        }
        _ => BuildFailureClass::InternalFailure,
    }
}

fn required_literal_failure_class(error: &RequiredLiteralBuildError) -> BuildFailureClass {
    if error.is_semantic_refusal() {
        return BuildFailureClass::Unsupported;
    }
    match error {
        RequiredLiteralBuildError::SuffixLimit { .. }
        | RequiredLiteralBuildError::WorkLimit { .. }
        | RequiredLiteralBuildError::ScratchLimit { .. }
        | RequiredLiteralBuildError::PersistentLimit { .. }
        | RequiredLiteralBuildError::PeakLimit { .. } => BuildFailureClass::ResourceLimit,
        _ => BuildFailureClass::InternalFailure,
    }
}

fn literal_class_run_literal_failure_class(
    error: &LiteralClassRunLiteralBuildError,
) -> BuildFailureClass {
    match error {
        LiteralClassRunLiteralBuildError::LiteralBytesLimit { .. }
        | LiteralClassRunLiteralBuildError::ClassRangesLimit { .. }
        | LiteralClassRunLiteralBuildError::ClassMembersLimit { .. }
        | LiteralClassRunLiteralBuildError::WorkLimit { .. }
        | LiteralClassRunLiteralBuildError::ScratchLimit { .. }
        | LiteralClassRunLiteralBuildError::PersistentLimit { .. }
        | LiteralClassRunLiteralBuildError::PeakLimit { .. } => BuildFailureClass::ResourceLimit,
        LiteralClassRunLiteralBuildError::MissingLiteralAnchor
        | LiteralClassRunLiteralBuildError::EmptyPrefix
        | LiteralClassRunLiteralBuildError::NonEmptyPrefixForCompleteAsciiWordRun
        | LiteralClassRunLiteralBuildError::EmptySuffix
        | LiteralClassRunLiteralBuildError::EmptyClass
        | LiteralClassRunLiteralBuildError::NonCanonicalClass
        | LiteralClassRunLiteralBuildError::UnsupportedUnicodeClass
        | LiteralClassRunLiteralBuildError::NonAsciiUnicodeLiteral
        | LiteralClassRunLiteralBuildError::PrefixBoundaryInClass
        | LiteralClassRunLiteralBuildError::SuffixBoundaryInClass
        | LiteralClassRunLiteralBuildError::InexactAsciiWordClass
        | LiteralClassRunLiteralBuildError::SuffixByteOutsideAsciiWordClass
        | LiteralClassRunLiteralBuildError::UnsupportedSearchMinimum
        | LiteralClassRunLiteralBuildError::ClassOutsideAsciiWord
        | LiteralClassRunLiteralBuildError::SuffixByteOutsideAsciiWord => {
            BuildFailureClass::Unsupported
        }
        LiteralClassRunLiteralBuildError::AllocationFailed { .. }
        | LiteralClassRunLiteralBuildError::ArithmeticOverflow { .. } => {
            BuildFailureClass::InternalFailure
        }
        _ => BuildFailureClass::InternalFailure,
    }
}

fn forward_anchored_failure_class(error: &ForwardAnchoredBuildError) -> BuildFailureClass {
    if error.is_semantic_refusal() {
        return BuildFailureClass::Unsupported;
    }
    match error {
        ForwardAnchoredBuildError::SuffixLimit { .. }
        | ForwardAnchoredBuildError::WorkLimit { .. }
        | ForwardAnchoredBuildError::ScratchLimit { .. }
        | ForwardAnchoredBuildError::PersistentLimit { .. }
        | ForwardAnchoredBuildError::PeakLimit { .. } => BuildFailureClass::ResourceLimit,
        _ => BuildFailureClass::InternalFailure,
    }
}

fn unicode_folded_literal_resource_refusal(error: &UnicodeFoldedLiteralBuildError) -> bool {
    matches!(
        error,
        UnicodeFoldedLiteralBuildError::Resource { .. }
            | UnicodeFoldedLiteralBuildError::Trie(
                fre_kernels::FoldedLiteralTrieBuildError::Resource { .. }
            )
    )
}

fn map_unicode_folded_literal_build_error(error: UnicodeFoldedLiteralBuildError) -> BuildError {
    match error {
        UnicodeFoldedLiteralBuildError::Syntax(error) => BuildError::Syntax(error.into_source()),
        UnicodeFoldedLiteralBuildError::AllocationFailed { structure, items } => {
            BuildError::AllocationFailed {
                structure,
                additional: items,
            }
        }
        UnicodeFoldedLiteralBuildError::Trie(
            fre_kernels::FoldedLiteralTrieBuildError::AllocationFailed { structure, items },
        ) => BuildError::AllocationFailed {
            structure,
            additional: items,
        },
        UnicodeFoldedLiteralBuildError::Invariant { detail }
        | UnicodeFoldedLiteralBuildError::Trie(
            fre_kernels::FoldedLiteralTrieBuildError::Invariant { detail },
        ) => BuildError::InternalInvariant(detail),
        UnicodeFoldedLiteralBuildError::ArithmeticOverflow { computation }
        | UnicodeFoldedLiteralBuildError::Trie(
            fre_kernels::FoldedLiteralTrieBuildError::ArithmeticOverflow { computation },
        ) => BuildError::InternalInvariant(computation),
        UnicodeFoldedLiteralBuildError::Resource { .. }
        | UnicodeFoldedLiteralBuildError::Trie(
            fre_kernels::FoldedLiteralTrieBuildError::Resource { .. },
        ) => BuildError::InternalInvariant(
            "folded-literal resource refusal escaped optional Auto routing",
        ),
        UnicodeFoldedLiteralBuildError::Trie(_) => {
            BuildError::InternalInvariant("folded-literal trie returned an unknown failure")
        }
    }
}

fn charge_unicode_folded_planner_work(
    incumbent: u64,
    completed: usize,
    limit: u64,
) -> Result<u64, BuildError> {
    let folded = u64::try_from(completed).map_err(|_| {
        BuildError::InternalInvariant("folded-literal planner work does not fit u64")
    })?;
    let needed = incumbent
        .checked_add(folded)
        .ok_or(BuildError::InternalInvariant(
            "cumulative folded-literal planner work overflowed u64",
        ))?;
    if needed > limit {
        return Err(BuildError::PlannerWorkLimit { needed, limit });
    }
    Ok(needed)
}

const K0_NEGATIVE_PREFILTER_MIN_NEEDLE_BYTES: usize = 1;
const K0_MANDATORY_SUFFIX_MIN_NEEDLE_BYTES: usize = 3;
const K0_NEGATIVE_PREFILTER_MAX_NEEDLE_BYTES: usize = 1_024;
// Mandatory-cut materialization charges one operation per bitmap word read,
// byte-domain membership test, retained byte write and final inline plan.
const K0_MANDATORY_CUT_CARDINALITY_WORK: u64 = 4;
const K0_MANDATORY_CUT_BYTE_ENUMERATION_WORK: u64 = 256;
const K0_MANDATORY_CUT_PLAN_CONSTRUCTION_WORK: u64 = 1;

#[derive(Clone, Copy, Debug)]
struct K0MandatoryCutPlan {
    candidate: MandatoryCutCandidate,
    bytes: [u8; 3],
    count: u8,
}

impl K0MandatoryCutPlan {
    fn try_from_candidate(
        candidate: MandatoryCutCandidate,
        planner_work: &mut u64,
        max_planner_work: u64,
    ) -> Result<Option<Self>, BuildError> {
        if !try_charge_k0_mandatory_cut_work(
            planner_work,
            K0_MANDATORY_CUT_CARDINALITY_WORK,
            max_planner_work,
        )? {
            return Ok(None);
        }
        let cardinality = usize::from(candidate.byte_class().cardinality());
        if !(1..=3).contains(&cardinality) {
            return Ok(None);
        }
        let retained_byte_work = u64::try_from(cardinality).map_err(|_| {
            BuildError::InternalInvariant("K0 mandatory-cut cardinality does not fit planner work")
        })?;
        let construction_work = K0_MANDATORY_CUT_BYTE_ENUMERATION_WORK
            .checked_add(retained_byte_work)
            .and_then(|work| work.checked_add(K0_MANDATORY_CUT_PLAN_CONSTRUCTION_WORK))
            .ok_or(BuildError::InternalInvariant(
                "K0 mandatory-cut construction work overflowed",
            ))?;
        // Precharge the complete fixed-domain scan, retained-byte writes and
        // final inline plan construction. A refusal therefore publishes no
        // partially enumerated sidecar and leaves only completed work charged.
        if !try_charge_k0_mandatory_cut_work(
            planner_work,
            construction_work,
            max_planner_work,
        )? {
            return Ok(None);
        }
        let mut bytes = [0_u8; 3];
        let mut count = 0usize;
        for byte in u8::MIN..=u8::MAX {
            if candidate.byte_class().contains(byte) {
                *bytes.get_mut(count).ok_or(BuildError::InternalInvariant(
                    "eligible K0 mandatory-cut class exceeded inline storage",
                ))? = byte;
                count = count.checked_add(1).ok_or(BuildError::InternalInvariant(
                    "K0 mandatory-cut cardinality overflowed",
                ))?;
            }
        }
        if count != cardinality {
            return Err(BuildError::InternalInvariant(
                "K0 mandatory-cut enumeration disagreed with its cardinality",
            ));
        }
        Ok(Some(Self {
            candidate,
            bytes,
            count: u8::try_from(count).map_err(|_| {
                BuildError::InternalInvariant("K0 mandatory-cut cardinality does not fit u8")
            })?,
        }))
    }

    fn first_member(self, haystack: &[u8]) -> Option<usize> {
        debug_assert_eq!(
            usize::from(self.candidate.byte_class().cardinality()),
            usize::from(self.count)
        );
        match self.count {
            1 => memchr(self.bytes[0], haystack),
            2 => memchr2(self.bytes[0], self.bytes[1], haystack),
            3 => memchr3(self.bytes[0], self.bytes[1], self.bytes[2], haystack),
            _ => None,
        }
    }

    fn candidate_floor(self, window_start: usize, first_member: usize) -> Option<usize> {
        let MaximumConsumedDistance::Finite(maximum_before_root) =
            self.candidate.maximum_before_root()
        else {
            return None;
        };
        let first_member = window_start.checked_add(first_member)?;
        let maximum_before_root =
            usize::try_from(maximum_before_root).unwrap_or(usize::MAX);
        // If a selected match starts at s and consumes its mandatory-cut
        // byte at c, then c - s <= M. The first class member p is no later
        // than c, so p - M <= s; saturation only weakens that lower bound.
        Some(
            first_member
                .saturating_sub(maximum_before_root)
                .max(window_start),
        )
    }

    #[cfg(test)]
    const fn maximum_before_root(self) -> MaximumConsumedDistance {
        self.candidate.maximum_before_root()
    }

    #[cfg(test)]
    const fn bytes(self) -> ([u8; 3], u8) {
        (self.bytes, self.count)
    }
}

fn try_charge_k0_mandatory_cut_work(
    work: &mut u64,
    amount: u64,
    limit: u64,
) -> Result<bool, BuildError> {
    let needed = work.checked_add(amount).ok_or(BuildError::InternalInvariant(
        "K0 mandatory-cut planner work overflowed",
    ))?;
    if needed > limit {
        return Ok(false);
    }
    *work = needed;
    Ok(true)
}

struct K0MandatoryCutBuild {
    plan: Option<K0MandatoryCutPlan>,
    planner_work: u64,
    storage_bytes: usize,
}

fn try_build_k0_mandatory_cut(
    raw: &fre_automata::RawPlan,
    limits: BuildLimits,
    incumbent_planner_work: u64,
) -> Result<K0MandatoryCutBuild, BuildError> {
    let remaining_work = limits
        .max_planner_work
        .checked_sub(incumbent_planner_work)
        .ok_or(BuildError::InternalInvariant(
            "incumbent planner work exceeded its enforced limit",
        ))?;
    if remaining_work == 0 {
        return Ok(K0MandatoryCutBuild {
            plan: None,
            planner_work: incumbent_planner_work,
            storage_bytes: 0,
        });
    }
    let mut analysis_limits = MandatoryCutAnalysisLimits::default();
    analysis_limits.max_work = analysis_limits.max_work.min(remaining_work);
    analysis_limits.max_allocation_items = analysis_limits
        .max_allocation_items
        .min(limits.lowering.max_stack_items);
    let analysis = fre_automata::analyze_mandatory_cut(raw, analysis_limits);
    let stats = analysis.stats();
    if !stats.closes(analysis_limits) {
        return Err(BuildError::InternalInvariant(
            "K0 mandatory-cut analysis receipt did not close",
        ));
    }
    let mut planner_work = incumbent_planner_work
        .checked_add(stats.work())
        .ok_or(BuildError::InternalInvariant(
            "cumulative K0 mandatory-cut planner work overflowed u64",
        ))?;
    if planner_work > limits.max_planner_work {
        return Err(BuildError::InternalInvariant(
            "K0 mandatory-cut analysis exceeded its admitted planner work",
        ));
    }
    let candidate = match analysis {
        MandatoryCutAnalysis::Complete(report) => report.candidate(),
        MandatoryCutAnalysis::Declined(decline) => match decline.reason() {
            MandatoryCutDeclineReason::Resource {
                resource:
                    MandatoryCutResource::Work
                    | MandatoryCutResource::AllocationItems
                    | MandatoryCutResource::AllocationAttempts,
                ..
            }
            | MandatoryCutDeclineReason::Allocation { .. } => None,
            MandatoryCutDeclineReason::MalformedGraph(_)
            | MandatoryCutDeclineReason::ArithmeticOverflow { .. }
            | MandatoryCutDeclineReason::InternalInvariant { .. } => {
                return Err(BuildError::InternalInvariant(
                    "lowered K0 graph failed mandatory-cut analysis",
                ));
            }
            _ => {
                return Err(BuildError::InternalInvariant(
                    "K0 mandatory-cut analysis returned an unknown decline",
                ));
            }
        },
    };
    let plan = match candidate {
        Some(candidate) => K0MandatoryCutPlan::try_from_candidate(
            candidate,
            &mut planner_work,
            limits.max_planner_work,
        )?,
        None => None,
    };
    Ok(K0MandatoryCutBuild {
        storage_bytes: plan.map_or(0, |_| core::mem::size_of::<K0MandatoryCutPlan>()),
        plan,
        planner_work,
    })
}

#[derive(Debug)]
struct K0ConsumptionRunPlan {
    members: [u64; 4],
    ascii_members: AsciiByteSetRunScanner,
}

impl K0ConsumptionRunPlan {
    fn contains(&self, byte: u8) -> bool {
        let word = usize::from(byte / 64);
        let bit = u32::from(byte % 64);
        self.members[word] & (1_u64 << bit) != 0
    }

    fn narrowed_start_before(&self, haystack: &[u8], window_start: usize, end: usize) -> usize {
        let mut cursor = end;
        let mut high_members = 0_usize;
        while cursor > window_start {
            let run = self
                .ascii_members
                .scan_backward(&haystack[window_start..cursor]);
            cursor = cursor.saturating_sub(run.member_run_len());
            if cursor == window_start {
                return window_start;
            }

            let byte_position = cursor.saturating_sub(1);
            let byte = haystack[byte_position];
            if !self.contains(byte) {
                // The byte at cursor - 1 cannot occur on any consuming edge,
                // so no match can cross it and the next byte is a sound lower
                // bound for every match containing the selected suffix.
                return cursor;
            }

            // Every admitted ASCII member is consumed by the run scanner. A
            // remaining exact member is therefore high. Bound scalar recovery
            // independently of the source; exhausting the bound fails open
            // all the way to the original window start.
            debug_assert!(byte > 0x7f);
            if high_members >= K0_SUFFIX_HIGH_BYTE_BACKWARD_MAX {
                return window_start;
            }
            high_members = high_members.saturating_add(1);
            cursor = byte_position;
        }
        window_start
    }
}

#[derive(Debug)]
struct K0MandatorySuffixPlan {
    literal: LiteralPlan,
    consumption_run: Option<K0ConsumptionRunPlan>,
}

impl K0MandatorySuffixPlan {
    fn needle(&self) -> &[u8] {
        self.literal.needle()
    }

    fn find_window(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Result<Option<(usize, usize)>, LiteralError> {
        self.literal
            .find_window(
                haystack,
                LiteralWindow::new(start, end),
                LiteralSearchLimits::unlimited(),
            )
            .map(|(matched, _)| matched)
    }

    fn narrowed_start_before(&self, haystack: &[u8], window_start: usize, end: usize) -> usize {
        let Some(scanner) = self.consumption_run.as_ref() else {
            return window_start;
        };
        scanner.narrowed_start_before(haystack, window_start, end)
    }
}

struct K0MandatorySuffixBuild {
    plan: Option<K0MandatorySuffixPlan>,
    planner_work: u64,
    storage_bytes: usize,
}

fn try_build_k0_mandatory_suffix(
    raw: &fre_automata::RawPlan,
    limits: BuildLimits,
    incumbent_planner_work: u64,
) -> Result<K0MandatorySuffixBuild, BuildError> {
    let declined = |planner_work| K0MandatorySuffixBuild {
        plan: None,
        planner_work,
        storage_bytes: 0,
    };
    let remaining_work = limits
        .max_planner_work
        .checked_sub(incumbent_planner_work)
        .ok_or(BuildError::InternalInvariant(
            "incumbent planner work exceeded its enforced limit",
        ))?;
    if remaining_work == 0 {
        return Ok(declined(incumbent_planner_work));
    }
    let mut analysis_limits = MandatorySuffixAnalysisLimits::default();
    analysis_limits.max_work = analysis_limits.max_work.min(remaining_work);
    analysis_limits.max_allocation_items = analysis_limits
        .max_allocation_items
        .min(limits.lowering.max_stack_items);
    let analysis = fre_automata::analyze_mandatory_suffix(raw, analysis_limits);
    let stats = analysis.stats();
    if !stats.closes(analysis_limits) {
        return Err(BuildError::InternalInvariant(
            "K0 mandatory-suffix analysis receipt did not close",
        ));
    }
    let mut planner_work = incumbent_planner_work
        .checked_add(stats.work())
        .ok_or(BuildError::InternalInvariant(
            "cumulative K0 mandatory-suffix planner work overflowed u64",
        ))?;
    if planner_work > limits.max_planner_work {
        return Err(BuildError::InternalInvariant(
            "K0 mandatory-suffix analysis exceeded its admitted planner work",
        ));
    }
    let candidate = match analysis {
        MandatorySuffixAnalysis::Complete(report) => report.candidate(),
        MandatorySuffixAnalysis::Declined(decline) => match decline.reason() {
            MandatorySuffixDeclineReason::Resource {
                resource:
                    MandatorySuffixResource::SuffixBytes
                    | MandatorySuffixResource::Work
                    | MandatorySuffixResource::AllocationItems
                    | MandatorySuffixResource::AllocationAttempts,
                ..
            }
            | MandatorySuffixDeclineReason::Allocation { .. }
            | MandatorySuffixDeclineReason::AssertionsPresent
            | MandatorySuffixDeclineReason::EmptyLanguage
            | MandatorySuffixDeclineReason::NullableLanguage
            | MandatorySuffixDeclineReason::AmbiguousSuffixLayer => {
                return Ok(declined(planner_work));
            }
            MandatorySuffixDeclineReason::MalformedGraph(_)
            | MandatorySuffixDeclineReason::ArithmeticOverflow { .. }
            | MandatorySuffixDeclineReason::InternalInvariant { .. } => {
                return Err(BuildError::InternalInvariant(
                    "lowered K0 graph failed mandatory-suffix analysis",
                ));
            }
            _ => {
                return Err(BuildError::InternalInvariant(
                    "K0 mandatory-suffix analysis returned an unknown decline",
                ));
            }
        },
    };
    if candidate.len() < K0_MANDATORY_SUFFIX_MIN_NEEDLE_BYTES {
        return Ok(declined(planner_work));
    }
    let copy_work = u64::try_from(candidate.len()).map_err(|_| {
        BuildError::InternalInvariant("K0 mandatory suffix length does not fit u64")
    })?;
    if !try_charge_k0_negative_prefilter_work(
        &mut planner_work,
        copy_work,
        limits.max_planner_work,
    )? {
        return Ok(declined(planner_work));
    }
    let literal = match LiteralPlan::new(candidate.as_bytes(), limits.literal) {
        Ok(literal) => literal,
        Err(LiteralError::NeedleLimit { .. } | LiteralError::AllocationFailed { .. }) => {
            return Ok(declined(planner_work));
        }
        Err(_) => {
            return Err(BuildError::InternalInvariant(
                "admitted K0 mandatory suffix failed literal construction",
            ));
        }
    };
    if !try_charge_k0_negative_prefilter_work(&mut planner_work, 1, limits.max_planner_work)? {
        return Ok(declined(planner_work));
    }
    let consumption_run = try_build_k0_consumption_run(
        raw,
        &mut planner_work,
        limits.max_planner_work,
    )?;
    let storage_bytes = core::mem::size_of::<K0MandatorySuffixPlan>()
        .checked_add(literal.storage_bytes())
        .ok_or(BuildError::PersistentBytesOverflow)?;
    Ok(K0MandatorySuffixBuild {
        plan: Some(K0MandatorySuffixPlan {
            literal,
            consumption_run,
        }),
        planner_work,
        storage_bytes,
    })
}

fn try_build_k0_consumption_run(
    raw: &fre_automata::RawPlan,
    planner_work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<K0ConsumptionRunPlan>, BuildError> {
    let edge_work = u64::try_from(raw.edge_kinds.len()).map_err(|_| {
        BuildError::InternalInvariant("K0 consuming-edge count does not fit planner work")
    })?;
    if !try_charge_k0_negative_prefilter_work(planner_work, edge_work, max_planner_work)? {
        return Ok(None);
    }

    let mut members = [0_u64; 4];
    for (edge, &kind) in raw.edge_kinds.iter().enumerate() {
        if kind != fre_automata::EdgeKind::ByteRange {
            continue;
        }
        let start = raw.byte_starts[edge];
        let end = raw.byte_ends[edge];
        insert_k0_consumption_range(&mut members, start, end)?;
    }
    if members == [0; 4] || members == [u64::MAX; 4] {
        return Ok(None);
    }
    if !try_charge_k0_negative_prefilter_work(
        planner_work,
        u64::try_from(ASCII_RUN_SCANNER_BUILD_WORK)
            .expect("ASCII run-scanner construction work fits u64"),
        max_planner_work,
    )? {
        return Ok(None);
    }
    Ok(Some(K0ConsumptionRunPlan {
        members,
        ascii_members: AsciiByteSetRunScanner::new(AsciiByteSet::from_words([
            members[0],
            members[1],
        ])),
    }))
}

fn insert_k0_consumption_range(
    members: &mut [u64; 4],
    start: u8,
    end: u8,
) -> Result<(), BuildError> {
    if start > end {
        return Err(BuildError::InternalInvariant(
            "lowered K0 consuming range is reversed",
        ));
    }
    let first_word = usize::from(start / 64);
    let last_word = usize::from(end / 64);
    for word_index in first_word..=last_word {
        let first_bit = if word_index == first_word {
            u32::from(start % 64)
        } else {
            0
        };
        let last_bit = if word_index == last_word {
            u32::from(end % 64)
        } else {
            u64::BITS - 1
        };
        let through_last = if last_bit == u64::BITS - 1 {
            u64::MAX
        } else {
            1_u64
                .checked_shl(last_bit.saturating_add(1))
                .and_then(|mask| mask.checked_sub(1))
                .ok_or(BuildError::InternalInvariant(
                    "lowered K0 consuming range upper mask overflowed",
                ))?
        };
        let below_first = if first_bit == 0 {
            0
        } else {
            1_u64
                .checked_shl(first_bit)
                .and_then(|mask| mask.checked_sub(1))
                .ok_or(BuildError::InternalInvariant(
                    "lowered K0 consuming range lower mask overflowed",
                ))?
        };
        members[word_index] |= through_last & !below_first;
    }
    Ok(())
}

#[derive(Debug)]
struct K0NegativePrefilterPlan {
    literals: fre_exact_alloc::ExactVec<LiteralPlan>,
    maximum_needle_bytes: usize,
}

impl K0NegativePrefilterPlan {
    fn primary_needle_bytes(&self) -> Option<usize> {
        self.literals
            .iter()
            .map(|literal| literal.needle().len())
            .max()
    }
}

struct K0NegativePrefilterBuild {
    plan: Option<Box<K0NegativePrefilterPlan>>,
    planner_work: u64,
    storage_bytes: usize,
}

fn try_charge_k0_negative_prefilter_work(
    work: &mut u64,
    amount: u64,
    limit: u64,
) -> Result<bool, BuildError> {
    let needed = work.checked_add(amount).ok_or(BuildError::InternalInvariant(
        "K0 negative-prefilter planner work overflowed",
    ))?;
    if needed > limit {
        return Ok(false);
    }
    *work = needed;
    Ok(true)
}

fn try_build_k0_negative_prefilter(
    hir: &Hir,
    minimum_match_bytes: Option<usize>,
    limits: BuildLimits,
    incumbent_planner_work: u64,
    source_storage_bytes: usize,
    capture_name_storage_bytes: usize,
    automaton_storage_bytes: usize,
) -> Result<K0NegativePrefilterBuild, BuildError> {
    let declined = |planner_work| K0NegativePrefilterBuild {
        plan: None,
        planner_work,
        storage_bytes: 0,
    };
    if !matches!(minimum_match_bytes, Some(minimum) if minimum > 0) {
        return Ok(declined(incumbent_planner_work));
    }
    // K0 can reject a fully absolute-start-anchored pattern without injecting
    // candidate starts across the window. A whole-window literal pass would
    // turn that constant-prefix rejection into a linear scan.
    if hir.properties().look_set_prefix().contains(Look::Start) {
        return Ok(declined(incumbent_planner_work));
    }
    let base_persistent_bytes = source_storage_bytes
        .checked_add(capture_name_storage_bytes)
        .and_then(|bytes| bytes.checked_add(automaton_storage_bytes))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let minimum_sidecar_bytes = core::mem::size_of::<K0NegativePrefilterPlan>()
        .checked_add(core::mem::size_of::<LiteralPlan>())
        .and_then(|bytes| bytes.checked_add(K0_NEGATIVE_PREFILTER_MIN_NEEDLE_BYTES))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    if limits
        .max_persistent_bytes
        .saturating_sub(base_persistent_bytes)
        < minimum_sidecar_bytes
    {
        return Ok(declined(incumbent_planner_work));
    }

    let remaining_planner_work = limits
        .max_planner_work
        .checked_sub(incumbent_planner_work)
        .ok_or(BuildError::InternalInvariant(
            "incumbent planner work exceeded its enforced limit",
        ))?;
    if remaining_planner_work == 0 {
        return Ok(declined(incumbent_planner_work));
    }
    let mut inspection_limits = CaptureRequiredLiteralBuildLimits::default();
    inspection_limits.max_planner_work = inspection_limits.max_planner_work.min(
        usize::try_from(remaining_planner_work).unwrap_or(usize::MAX),
    );
    inspection_limits.max_needle_bytes = inspection_limits
        .max_needle_bytes
        .min(K0_NEGATIVE_PREFILTER_MAX_NEEDLE_BYTES);

    let inspection =
        match capture_required_literal::inspect_conjunctive_required_literals(hir, inspection_limits)
        {
            Ok(inspection) => inspection,
            Err(failure) => {
                let actual_work = u64::try_from(failure.actual_work).map_err(|_| {
                    BuildError::InternalInvariant(
                        "K0 negative-prefilter planner work does not fit u64",
                    )
                })?;
                let planner_work = incumbent_planner_work.checked_add(actual_work).ok_or(
                    BuildError::InternalInvariant(
                        "cumulative K0 negative-prefilter planner work overflowed u64",
                    ),
                )?;
                if planner_work > limits.max_planner_work {
                    return Err(BuildError::InternalInvariant(
                        "K0 negative-prefilter attempt exceeded its planner-work admission",
                    ));
                }
                return match failure.source {
                    CaptureRequiredLiteralBuildError::Resource { .. }
                    | CaptureRequiredLiteralBuildError::Allocation { .. } => {
                        Ok(declined(planner_work))
                    }
                    CaptureRequiredLiteralBuildError::Overflow(computation)
                    | CaptureRequiredLiteralBuildError::InternalInvariant(computation) => {
                        Err(BuildError::InternalInvariant(computation))
                    }
                    CaptureRequiredLiteralBuildError::LiteralSet(_) => {
                        Err(BuildError::InternalInvariant(
                            "proof-only K0 negative-prefilter inspection constructed a literal set",
                        ))
                    }
                };
            }
        };
    let actual_work = u64::try_from(inspection.actual_work).map_err(|_| {
        BuildError::InternalInvariant("K0 negative-prefilter planner work does not fit u64")
    })?;
    let mut planner_work = incumbent_planner_work.checked_add(actual_work).ok_or(
        BuildError::InternalInvariant(
            "cumulative K0 negative-prefilter planner work overflowed u64",
        ),
    )?;
    if planner_work > limits.max_planner_work {
        return Err(BuildError::InternalInvariant(
            "K0 negative-prefilter inspection exceeded its planner-work admission",
        ));
    }
    let inspected = inspection
        .literals
        .get(..inspection.count)
        .ok_or(BuildError::InternalInvariant(
            "K0 negative-prefilter inspection count exceeded inline literals",
        ))?;
    let inspected_work = u64::try_from(inspected.len()).map_err(|_| {
        BuildError::InternalInvariant("K0 negative-prefilter inspected count does not fit u64")
    })?;
    if !try_charge_k0_negative_prefilter_work(
        &mut planner_work,
        inspected_work,
        limits.max_planner_work,
    )? {
        return Ok(declined(planner_work));
    }
    let mut eligible = [None; capture_required_literal::MAX_CONJUNCTIVE_REQUIRED_LITERALS];
    let mut literal_count = 0usize;
    let mut literal_bytes = 0usize;
    let mut maximum_needle_bytes = 0usize;
    for &literal in inspected {
        if literal.len() > K0_NEGATIVE_PREFILTER_MAX_NEEDLE_BYTES
            || literal.len() > limits.literal.max_needle_bytes
        {
            continue;
        }
        *eligible
            .get_mut(literal_count)
            .ok_or(BuildError::InternalInvariant(
                "K0 negative-prefilter eligible literals exceeded inline storage",
            ))? = Some(literal);
        literal_count = literal_count
            .checked_add(1)
            .ok_or(BuildError::PersistentBytesOverflow)?;
        literal_bytes = literal_bytes
            .checked_add(literal.len())
            .ok_or(BuildError::PersistentBytesOverflow)?;
        maximum_needle_bytes = maximum_needle_bytes.max(literal.len());
    }
    // Every retained literal is independently mandatory. Short predicates are
    // absence-only filters in the runtime below: a present byte never proposes
    // an endpoint and adaptive backoff returns repeatedly positive inputs to
    // K0. Keeping them in this last-priority sidecar avoids displacing the
    // graph cut or the more capable exact-suffix verifier.
    if literal_count == 0 {
        return Ok(declined(planner_work));
    }
    let storage_bytes = core::mem::size_of::<K0NegativePrefilterPlan>()
        .checked_add(
            literal_count
                .checked_mul(core::mem::size_of::<LiteralPlan>())
                .ok_or(BuildError::PersistentBytesOverflow)?,
        )
        .and_then(|bytes| bytes.checked_add(literal_bytes))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let charged_with_sidecar = base_persistent_bytes
        .checked_add(storage_bytes)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    if charged_with_sidecar > limits.max_persistent_bytes {
        return Ok(declined(planner_work));
    }
    if !try_charge_k0_negative_prefilter_work(
        &mut planner_work,
        1,
        limits.max_planner_work,
    )? {
        return Ok(declined(planner_work));
    }
    let mut literals = match fre_exact_alloc::ExactVec::try_with_capacity(literal_count) {
        Ok(literals) => literals,
        Err(fre_exact_alloc::CopyError::AllocationFailed) => {
            return Ok(declined(planner_work));
        }
        Err(fre_exact_alloc::CopyError::LayoutOverflow) => {
            return Err(BuildError::InternalInvariant(
                "K0 negative-prefilter literal vector layout overflowed",
            ));
        }
    };
    for literal in eligible[..literal_count].iter().copied() {
        let literal = literal.ok_or(BuildError::InternalInvariant(
            "K0 negative-prefilter eligible literal was not initialized",
        ))?;
        let copy_work = u64::try_from(literal.len()).map_err(|_| {
            BuildError::InternalInvariant("K0 negative-prefilter literal size does not fit u64")
        })?;
        if !try_charge_k0_negative_prefilter_work(
            &mut planner_work,
            copy_work,
            limits.max_planner_work,
        )? {
            return Ok(declined(planner_work));
        }
        let plan = match LiteralPlan::new(literal, limits.literal) {
            Ok(plan) => plan,
            Err(LiteralError::NeedleLimit { .. } | LiteralError::AllocationFailed { .. }) => {
                return Ok(declined(planner_work));
            }
            Err(_) => {
                return Err(BuildError::InternalInvariant(
                    "admitted K0 negative-prefilter literal failed infallible construction",
                ));
            }
        };
        if !try_charge_k0_negative_prefilter_work(
            &mut planner_work,
            1,
            limits.max_planner_work,
        )? {
            return Ok(declined(planner_work));
        }
        literals.try_push(plan).map_err(|_| {
            BuildError::InternalInvariant(
                "admitted K0 negative-prefilter vector rejected a literal",
            )
        })?;
    }
    let plan = K0NegativePrefilterPlan {
        literals,
        maximum_needle_bytes,
    };
    if !try_charge_k0_negative_prefilter_work(
        &mut planner_work,
        1,
        limits.max_planner_work,
    )? {
        return Ok(declined(planner_work));
    }
    let plan = match fre_exact_alloc::try_box_preserve(plan) {
        Ok(plan) => plan,
        Err((fre_exact_alloc::CopyError::AllocationFailed, _)) => {
            return Ok(declined(planner_work));
        }
        Err((fre_exact_alloc::CopyError::LayoutOverflow, _)) => {
            return Err(BuildError::InternalInvariant(
                "K0 negative-prefilter owner layout overflowed",
            ));
        }
    };
    Ok(K0NegativePrefilterBuild {
        plan: Some(plan),
        planner_work,
        storage_bytes,
    })
}

fn folded_tail_planner_work_upper_bound(
    hir_nodes: u64,
    literal_set: &LiteralSetPlan,
) -> Option<u64> {
    let finite = literal_set.build_accounting();
    let pattern_bytes = u64::try_from(finite.pattern_bytes).ok()?;
    let patterns = u64::try_from(finite.patterns).ok()?;
    // Exhaustive finite extraction preserves every expansion and duplicate.
    // Its aggregate bytes bound both folded scalar positions and equivalent
    // scalar memberships, while its word count bounds source alternatives.
    // Folded inspection plus materialization costs at most 2H + S + 2E + 2P.
    hir_nodes
        .checked_mul(2)?
        .checked_add(pattern_bytes.checked_mul(3)?)?
        .checked_add(patterns.checked_mul(2)?)
}

struct FixedPredicateAutoAttempt {
    plan: Option<Box<FixedPredicateWord64Plan>>,
    planner_work: u64,
    plan_storage_bytes: usize,
    charged_persistent_bytes: usize,
    declined: bool,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn try_fixed_predicate_word64_before_finite(
    hir: &Hir,
    expected_hir_nodes: u64,
    explicit_captures: usize,
    initial_work: u64,
    planner_work_limit: u64,
    source_storage_bytes: usize,
    capture_name_storage_bytes: usize,
    persistent_byte_limit: usize,
) -> Result<FixedPredicateAutoAttempt, BuildError> {
    let inspection = finite::inspect_fixed_predicate_word64_attempt(
        hir,
        initial_work,
        planner_work_limit,
    );
    if !inspection.has_closed_receipt() {
        return Err(BuildError::InternalInvariant(
            "fixed-predicate search inspection lost its attempt closure",
        ));
    }
    let receipt = inspection.receipt();
    if receipt.initial_work() != initial_work || receipt.work_limit() != planner_work_limit {
        return Err(BuildError::InternalInvariant(
            "fixed-predicate search inspection lost its cumulative planner envelope",
        ));
    }
    let planner_work = receipt.actual().work;
    let fixed = match inspection {
        finite::FixedPredicateInspectionAttempt::Succeeded { source, .. } => source,
        finite::FixedPredicateInspectionAttempt::Refused { .. } => {
            return Ok(FixedPredicateAutoAttempt {
                plan: None,
                planner_work,
                plan_storage_bytes: 0,
                charged_persistent_bytes: 0,
                declined: false,
            });
        }
        finite::FixedPredicateInspectionAttempt::ResourceFailure { error, .. } => {
            return Err(error);
        }
    };
    let expected_hir_nodes = usize::try_from(expected_hir_nodes)
        .map_err(|_| BuildError::InternalInvariant("syntax HIR-node count does not fit usize"))?;
    if fixed.hir_nodes() != expected_hir_nodes || fixed.captures() != explicit_captures {
        return Err(BuildError::InternalInvariant(
            "syntax summary differs from fixed-predicate search inspection",
        ));
    }
    if fixed.variable_predicates() == 0 {
        return Err(BuildError::InternalInvariant(
            "fixed-predicate search source lost its variable predicate proof",
        ));
    }
    let mut normalized =
        [finite::FixedPredicateRanges::EMPTY; FIXED_PREDICATE_WORD64_MAX_WIDTH];
    for (index, ranges) in fixed.positions().enumerate() {
        let Some(slot) = normalized.get_mut(index) else {
            return Err(BuildError::InternalInvariant(
                "fixed-predicate search source exceeded its inline width",
            ));
        };
        *slot = ranges;
    }
    let Some(normalized) = normalized.get(..fixed.width()) else {
        return Err(BuildError::InternalInvariant(
            "fixed-predicate search source width exceeded its inline storage",
        ));
    };
    let mut positions: [&[(u8, u8)]; FIXED_PREDICATE_WORD64_MAX_WIDTH] =
        [&[]; FIXED_PREDICATE_WORD64_MAX_WIDTH];
    for (slot, predicate) in positions.iter_mut().zip(normalized) {
        *slot = predicate.ranges();
    }
    let attempt = match FixedPredicateWord64Plan::build_attempt(
        &positions[..normalized.len()],
        FixedPredicateWord64BuildLimits::unlimited(),
    ) {
        Ok(attempt) => attempt,
        Err(error) => {
            if !error.closes() {
                return Err(BuildError::InternalInvariant(
                    "fixed-predicate search construction failure lost its attempt closure",
                ));
            }
            return Err(BuildError::InternalInvariant(
                "inspected fixed-predicate search source failed kernel construction",
            ));
        }
    };
    if !attempt.closes() {
        return Err(BuildError::InternalInvariant(
            "fixed-predicate search construction lost its attempt closure",
        ));
    }
    let (plan, _) = attempt.into_parts();
    let reducer = plan
        .search_operation_identity(FixedPredicateWord64SearchOperation::Exists)
        .reducer;
    let anchored = matches!(
        reducer,
        FixedPredicateWord64Reducer::OneByteAnchor | FixedPredicateWord64Reducer::TwoByteAnchor
    );
    let auto_admitted = anchored
        && plan.max_verification_predicates()
            <= FIXED_PREDICATE_SEARCH_AUTO_MAX_VERIFICATION_PREDICATES;
    if !auto_admitted {
        return Ok(FixedPredicateAutoAttempt {
            plan: None,
            planner_work,
            plan_storage_bytes: 0,
            charged_persistent_bytes: 0,
            declined: true,
        });
    }
    let plan_storage_bytes = plan.build_accounting().persistent_bytes;
    let charged_persistent_bytes = source_storage_bytes
        .checked_add(capture_name_storage_bytes)
        .and_then(|bytes| bytes.checked_add(plan_storage_bytes))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    if charged_persistent_bytes > persistent_byte_limit {
        return Err(BuildError::PersistentBytesLimit {
            needed: charged_persistent_bytes,
            limit: persistent_byte_limit,
        });
    }
    let plan = fre_exact_alloc::try_box_preserve(plan).map_err(|(error, _)| match error {
        fre_exact_alloc::CopyError::LayoutOverflow => {
            BuildError::InternalInvariant("fixed-predicate search owner layout overflowed")
        }
        fre_exact_alloc::CopyError::AllocationFailed => BuildError::AllocationFailed {
            structure: "fixed-predicate search owner",
            additional: 1,
        },
    })?;
    Ok(FixedPredicateAutoAttempt {
        plan: Some(plan),
        planner_work,
        plan_storage_bytes,
        charged_persistent_bytes,
        declined: false,
    })
}

#[cold]
#[inline(never)]
fn try_attach_unicode_folded_long_tail(
    literal_set: &mut LiteralSetPlan,
    words: &[Vec<u8>],
    parsed_hir: (&Hir, u64),
    profile: &RustProfile,
    limits: &BuildLimits,
    retained_facade_bytes: usize,
    incumbent_planner_work: u64,
) -> Result<u64, BuildError> {
    let (hir, hir_nodes) = parsed_hir;
    let available_plan_bytes = limits
        .max_persistent_bytes
        .saturating_sub(retained_facade_bytes);
    let dfa_bytes = literal_set.build_accounting().persistent_bytes;
    let Some(available_trie_bytes) =
        available_plan_bytes
            .checked_sub(dfa_bytes)
            .and_then(|bytes| {
                bytes.checked_sub(LiteralSetPlan::folded_long_tail_additional_owner_bytes())
            })
    else {
        return Ok(incumbent_planner_work);
    };
    let remaining_planner_work = limits
        .max_planner_work
        .checked_sub(incumbent_planner_work)
        .ok_or(BuildError::InternalInvariant(
            "incumbent planner work exceeded its enforced limit",
        ))?;
    let Some(folded_planner_work_upper_bound) =
        folded_tail_planner_work_upper_bound(hir_nodes, literal_set)
    else {
        return Ok(incumbent_planner_work);
    };
    if folded_planner_work_upper_bound > remaining_planner_work {
        return Ok(incumbent_planner_work);
    }
    let planner_limit = usize::try_from(remaining_planner_work).unwrap_or(usize::MAX);
    let mut folded_limits = UnicodeFoldedLiteralBuildLimits::default();
    folded_limits.max_planner_work = folded_limits.max_planner_work.min(planner_limit);
    folded_limits.trie.max_work = folded_limits.trie.max_work.min(planner_limit);
    folded_limits.trie.max_persistent_bytes = folded_limits
        .trie
        .max_persistent_bytes
        .min(available_trie_bytes);
    folded_limits.trie.max_peak_bytes = folded_limits.trie.max_peak_bytes.min(available_trie_bytes);

    let attempt = unicode_folded_literal::build_search_plan(
        SimdDispatchContext::capture(),
        hir,
        profile,
        folded_limits,
    );
    let (plan, folded_planner) = match attempt {
        Ok(UnicodeFoldedLiteralBuildAttempt::Admitted(plan)) => {
            let work = plan.build_accounting().planner.work;
            (Some(plan), work)
        }
        Ok(UnicodeFoldedLiteralBuildAttempt::Ineligible { planner, .. }) => (None, planner.work),
        Err(attempt_error) => {
            let (error, completed_planner) = attempt_error.into_parts();
            if !unicode_folded_literal_resource_refusal(&error) {
                return Err(map_unicode_folded_literal_build_error(error));
            }
            (None, completed_planner)
        }
    };
    let planner_work = charge_unicode_folded_planner_work(
        incumbent_planner_work,
        folded_planner,
        limits.max_planner_work,
    )?;
    if let Some(plan) = plan {
        let max_pattern_bytes =
            words
                .iter()
                .map(Vec::len)
                .max()
                .ok_or(BuildError::InternalInvariant(
                    "nonempty folded finite language lost every pattern",
                ))?;
        let _attached = literal_set.try_attach_folded_long_tail(
            plan.into_trie(),
            max_pattern_bytes,
            available_plan_bytes,
        )?;
    }
    Ok(planner_work)
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(f, "syntax construction failed: {error}"),
            Self::Lower(error) => write!(f, "portable lowering failed: {error}"),
            Self::Literal(error) => write!(f, "literal-plan construction failed: {error}"),
            Self::LiteralSet(error) => {
                write!(f, "literal-set DFA construction failed: {error}")
            }
            Self::RequiredLiteral(error) => {
                write!(f, "required-literal construction failed: {error}")
            }
            Self::LiteralClassRunLiteral(error) => {
                write!(f, "literal/class-run construction failed: {error}")
            }
            Self::RequiredLiteralShape => {
                f.write_str("pattern is outside the forced required-literal HIR shape")
            }
            Self::ForwardAnchored(error) => {
                write!(f, "forward-anchored construction failed: {error}")
            }
            Self::ForwardAnchoredShape => {
                f.write_str("pattern is outside the forced forward-anchored HIR shape")
            }
            Self::PlannerWorkLimit { needed, limit } => {
                write!(f, "planner needs {needed} work units, exceeding {limit}")
            }
            Self::PersistentBytesOverflow => {
                f.write_str("portable matcher persistent-byte accounting overflowed usize")
            }
            Self::PersistentBytesLimit { needed, limit } => write!(
                f,
                "portable matcher needs {needed} persistent bytes, exceeding {limit}"
            ),
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(
                f,
                "failed to reserve {additional} additional items for planner {structure}"
            ),
            Self::InternalInvariant(detail) => {
                write!(f, "facade internal invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Lower(error) => Some(error),
            Self::Literal(error) => Some(error),
            Self::LiteralSet(error) => Some(error),
            Self::RequiredLiteral(error) => Some(error),
            Self::LiteralClassRunLiteral(error) => Some(error),
            Self::ForwardAnchored(error) => Some(error),
            Self::RequiredLiteralShape
            | Self::ForwardAnchoredShape
            | Self::PlannerWorkLimit { .. }
            | Self::PersistentBytesOverflow
            | Self::PersistentBytesLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl BuildReport {
    fn enforce_persistent_limit(mut self, limit: usize) -> Result<Self, BuildError> {
        let needed = self
            .source_storage_bytes
            .checked_add(self.capture_name_storage_bytes)
            .and_then(|bytes| bytes.checked_add(self.plan_storage_bytes))
            .ok_or(BuildError::PersistentBytesOverflow)?;
        if needed > limit {
            return Err(BuildError::PersistentBytesLimit { needed, limit });
        }
        self.charged_persistent_bytes = needed;
        self.persistent_byte_limit = limit;
        Ok(self)
    }
}

impl From<fre_syntax::ParseError> for BuildError {
    fn from(value: fre_syntax::ParseError) -> Self {
        Self::Syntax(value)
    }
}

impl From<fre_lower::LowerError> for BuildError {
    fn from(value: fre_lower::LowerError) -> Self {
        Self::Lower(value)
    }
}

impl From<LiteralError> for BuildError {
    fn from(value: LiteralError) -> Self {
        Self::Literal(value)
    }
}

impl From<LiteralSetError> for BuildError {
    fn from(value: LiteralSetError) -> Self {
        Self::LiteralSet(value)
    }
}

impl From<RequiredLiteralBuildError> for BuildError {
    fn from(value: RequiredLiteralBuildError) -> Self {
        Self::RequiredLiteral(value)
    }
}

impl From<LiteralClassRunLiteralBuildError> for BuildError {
    fn from(value: LiteralClassRunLiteralBuildError) -> Self {
        Self::LiteralClassRunLiteral(value)
    }
}

impl From<ForwardAnchoredBuildError> for BuildError {
    fn from(value: ForwardAnchoredBuildError) -> Self {
        Self::ForwardAnchored(value)
    }
}

#[derive(Debug)]
struct CaptureNameMetadata {
    names: Box<[Option<Box<str>>]>,
    captures_len: usize,
    storage_bytes: usize,
}

fn capture_slot_len(
    hir: &Hir,
    explicit_captures: usize,
    hir_nodes: usize,
) -> Result<usize, BuildError> {
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(hir_nodes)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "capture-slot HIR traversal",
            additional: hir_nodes,
        })?;
    stack.push(hir);
    let mut visited = 0_usize;
    let mut capture_nodes = 0_usize;
    let mut maximum_index = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.checked_add(1).ok_or(BuildError::InternalInvariant(
            "capture-slot HIR traversal count overflowed",
        ))?;
        if visited > hir_nodes {
            return Err(BuildError::InternalInvariant(
                "capture-slot traversal exceeded parsed HIR accounting",
            ));
        }
        if let HirKind::Capture(capture) = node.kind() {
            let index = usize::try_from(capture.index).map_err(|_| {
                BuildError::InternalInvariant("capture-slot index does not fit usize")
            })?;
            if index == 0 {
                return Err(BuildError::InternalInvariant(
                    "canonical HIR used the implicit whole-match capture index",
                ));
            }
            capture_nodes = capture_nodes
                .checked_add(1)
                .ok_or(BuildError::InternalInvariant(
                    "capture-slot count overflowed",
                ))?;
            maximum_index = maximum_index.max(index);
        }
        for child in node.kind().subs() {
            if stack.len() >= hir_nodes {
                return Err(BuildError::InternalInvariant(
                    "capture-slot traversal stack exceeded parsed HIR accounting",
                ));
            }
            stack.push(child);
        }
    }
    if visited != hir_nodes || capture_nodes != explicit_captures {
        return Err(BuildError::InternalInvariant(
            "capture-slot metadata differs from parsed HIR accounting",
        ));
    }
    maximum_index
        .checked_add(1)
        .ok_or(BuildError::InternalInvariant(
            "capture count including group zero overflowed usize",
        ))
}

fn capture_name_metadata(
    hir: &Hir,
    explicit_captures: usize,
    hir_nodes: u64,
) -> Result<CaptureNameMetadata, BuildError> {
    let hir_nodes = usize::try_from(hir_nodes)
        .map_err(|_| BuildError::InternalInvariant("HIR node count does not fit usize"))?;
    if hir_nodes == 0 {
        return Err(BuildError::InternalInvariant(
            "capture metadata received an empty HIR inventory",
        ));
    }

    let captures_len = capture_slot_len(hir, explicit_captures, hir_nodes)?;

    let mut names = Vec::new();
    names
        .try_reserve_exact(captures_len)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "capture-name slots",
            additional: captures_len,
        })?;
    names.resize_with(captures_len, || None);

    let mut seen = Vec::new();
    seen.try_reserve_exact(captures_len)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "capture-name validation bitmap",
            additional: captures_len,
        })?;
    seen.resize(captures_len, false);
    seen[0] = true;

    let mut stack = Vec::new();
    stack
        .try_reserve_exact(hir_nodes)
        .map_err(|_| BuildError::AllocationFailed {
            structure: "capture-name HIR traversal",
            additional: hir_nodes,
        })?;
    stack.push(hir);
    let mut visited = 0_usize;
    while let Some(node) = stack.pop() {
        visited = visited.checked_add(1).ok_or(BuildError::InternalInvariant(
            "capture-name HIR traversal count overflowed",
        ))?;
        if visited > hir_nodes {
            return Err(BuildError::InternalInvariant(
                "capture-name traversal exceeded parsed HIR accounting",
            ));
        }
        if let HirKind::Capture(capture) = node.kind() {
            let index = usize::try_from(capture.index).map_err(|_| {
                BuildError::InternalInvariant("capture-name index does not fit usize")
            })?;
            if index == 0 || index >= captures_len {
                return Err(BuildError::InternalInvariant(
                    "capture-name index is outside parsed capture cardinality",
                ));
            }
            if seen[index] {
                return Err(BuildError::InternalInvariant(
                    "capture-name index appeared more than once in canonical HIR",
                ));
            }
            seen[index] = true;
            names[index].clone_from(&capture.name);
        }
        for child in node.kind().subs() {
            if stack.len() >= hir_nodes {
                return Err(BuildError::InternalInvariant(
                    "capture-name traversal stack exceeded parsed HIR accounting",
                ));
            }
            stack.push(child);
        }
    }
    if visited != hir_nodes
        || seen.iter().skip(1).filter(|was_seen| **was_seen).count() != explicit_captures
    {
        return Err(BuildError::InternalInvariant(
            "capture-name metadata differs from parsed HIR accounting",
        ));
    }

    let slot_bytes = core::mem::size_of::<Option<Box<str>>>()
        .checked_mul(names.len())
        .ok_or(BuildError::InternalInvariant(
            "capture-name slot byte accounting overflowed",
        ))?;
    let storage_bytes = names.iter().try_fold(slot_bytes, |total, name| {
        total
            .checked_add(name.as_deref().map_or(0, str::len))
            .ok_or(BuildError::InternalInvariant(
                "capture-name string byte accounting overflowed",
            ))
    })?;
    Ok(CaptureNameMetadata {
        names: names.into_boxed_slice(),
        captures_len,
        storage_bytes,
    })
}

/// Per-search accounting with the selected plan kept explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SearchAccounting {
    /// Exact K0 counters.
    K0(fre_automata::SearchAccounting),
    /// Inputs to the native literal plan's documented linear bound.
    ExactLiteral(LiteralAccounting),
    /// Conservative SIMD packed filter-plus-verification bound.
    PackedLiteralSet(PackedLiteralSetAccounting),
    /// Ordered finite-literal DFA or combined adaptive work accounting.
    LiteralSetDfa(LiteralSetAccounting),
    /// Complete required-literal proof-bound and actual counters.
    RequiredLiteral(RequiredLiteralSearchAccounting),
    /// Complete literal/class-run source-independent envelope and counters.
    LiteralClassRunLiteral(LiteralClassRunLiteralSearchAccounting),
    /// Exact operation-specialized root byte-class repetition counters.
    PureByteClassRepeat(PureByteClassRepeatAccounting),
    /// Exact bounded byte-class sequence counters.
    BoundedByteClassSequence(BoundedByteClassSequenceAccounting),
    /// Complete forward-boundary proof-bound and structural counters.
    ForwardAnchored(ForwardAnchoredSearchAccounting),
    /// Exact folded-scalar trie early-stop counters.
    ///
    /// The source-independent envelope is available separately from
    /// [`PortableRegex::unicode_folded_literal_search_upper_bounds`] so this
    /// admitted-only route does not enlarge unrelated accounting owners.
    UnicodeFoldedLiteral(fre_kernels::FoldedLiteralTrieScanActual),
    /// Exact linear Unicode word-run counters.
    UnicodeWordRun(UnicodeWordRunAccounting),
    /// Exact fixed-predicate first-match counters.
    FixedPredicateWord64(FixedPredicateWord64SearchAccounting),
    /// Fixed-column candidate and exact maximal-word dictionary accounting.
    GuardedLiteralSet(GuardedLiteralSetSearchAccounting),
}

impl SearchAccounting {
    /// Selected plan family.
    #[must_use]
    pub const fn plan(&self) -> PlanKind {
        match self {
            Self::K0(_) => PlanKind::K0,
            Self::ExactLiteral(_) => PlanKind::ExactLiteral,
            Self::PackedLiteralSet(_) | Self::GuardedLiteralSet(_) => PlanKind::PackedLiteralSet,
            Self::LiteralSetDfa(_) => PlanKind::LiteralSetDfa,
            Self::RequiredLiteral(_) => PlanKind::RequiredLiteral,
            Self::LiteralClassRunLiteral(_) => PlanKind::LiteralClassRunLiteral,
            Self::PureByteClassRepeat(_) => PlanKind::PureByteClassRepeat,
            Self::BoundedByteClassSequence(_) => PlanKind::BoundedByteClassSequence,
            Self::ForwardAnchored(_) => PlanKind::ForwardAnchored,
            Self::UnicodeFoldedLiteral(_) => PlanKind::UnicodeFoldedLiteral,
            Self::UnicodeWordRun(_) => PlanKind::UnicodeWordRun,
            Self::FixedPredicateWord64(_) => PlanKind::FixedPredicateWord64,
        }
    }

    /// Actual charged K0 work or checked literal linear-bound terms.
    #[must_use]
    pub fn work_or_linear_terms(&self) -> u64 {
        match self {
            Self::K0(accounting) => accounting.work(),
            Self::ExactLiteral(accounting) => {
                u64::try_from(accounting.linear_terms).unwrap_or(u64::MAX)
            }
            Self::PackedLiteralSet(accounting) => {
                u64::try_from(accounting.work_upper_bound).unwrap_or(u64::MAX)
            }
            Self::GuardedLiteralSet(accounting) => {
                u64::try_from(accounting.upper_bounds.total_work).unwrap_or(u64::MAX)
            }
            Self::LiteralSetDfa(accounting) => {
                u64::try_from(accounting.transitions_upper_bound).unwrap_or(u64::MAX)
            }
            Self::RequiredLiteral(accounting) => accounting.work_upper_bound,
            Self::LiteralClassRunLiteral(accounting) => accounting.work_upper_bound,
            Self::PureByteClassRepeat(accounting) => accounting.actual_work,
            Self::BoundedByteClassSequence(accounting) => accounting.actual_work,
            Self::ForwardAnchored(accounting) => accounting.work_upper_bound,
            Self::UnicodeFoldedLiteral(accounting) => {
                u64::try_from(accounting.work).unwrap_or(u64::MAX)
            }
            Self::UnicodeWordRun(accounting) => accounting.work(),
            Self::FixedPredicateWord64(accounting) => accounting.actual.work,
        }
    }
}

/// Compact folded-plan failure projection that preserves charged work and
/// source reads without enlarging unrelated search-error owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnicodeFoldedLiteralSearchError {
    pub source: fre_kernels::FoldedLiteralTrieScanError,
    pub actual_work: usize,
    pub actual_source_byte_reads: usize,
}

impl fmt::Display for UnicodeFoldedLiteralSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for UnicodeFoldedLiteralSearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Search failure from the selected forced plan; no fallback is attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchError {
    K0(K0SearchError),
    ExactLiteral(LiteralError),
    PackedLiteralSet(PackedLiteralSetError),
    LiteralSetDfa(LiteralSetError),
    RequiredLiteral(RequiredLiteralSearchError),
    LiteralClassRunLiteral(LiteralClassRunLiteralSearchError),
    PureByteClassRepeat(PureByteClassRepeatSearchError),
    BoundedByteClassSequence(BoundedByteClassSequenceSearchError),
    ForwardAnchored(ForwardAnchoredSearchError),
    UnicodeFoldedLiteral(UnicodeFoldedLiteralSearchError),
    UnicodeWordRun(UnicodeWordRunError),
    FixedPredicateWord64(FixedPredicateWord64SearchError),
    GuardedLiteralSet(GuardedLiteralSetSearchError),
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::K0(error) => write!(f, "K0 search failed: {error}"),
            Self::ExactLiteral(error) => write!(f, "literal search failed: {error}"),
            Self::PackedLiteralSet(error) => {
                write!(f, "packed literal-set search failed: {error}")
            }
            Self::GuardedLiteralSet(error) => {
                write!(f, "guarded literal-set search failed: {error}")
            }
            Self::LiteralSetDfa(error) => write!(f, "literal-set DFA search failed: {error}"),
            Self::RequiredLiteral(error) => write!(f, "required-literal search failed: {error}"),
            Self::LiteralClassRunLiteral(error) => {
                write!(f, "literal/class-run search failed: {error}")
            }
            Self::PureByteClassRepeat(error) => {
                write!(f, "pure byte-class repeat search failed: {error}")
            }
            Self::BoundedByteClassSequence(error) => {
                write!(f, "bounded byte-class sequence search failed: {error}")
            }
            Self::ForwardAnchored(error) => {
                write!(f, "forward-anchored search failed: {error}")
            }
            Self::UnicodeFoldedLiteral(error) => {
                write!(f, "Unicode folded-literal search failed: {error}")
            }
            Self::UnicodeWordRun(error) => write!(f, "Unicode word-run search failed: {error}"),
            Self::FixedPredicateWord64(error) => {
                write!(f, "fixed-predicate search failed: {error}")
            }
        }
    }
}

impl std::error::Error for SearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::K0(error) => Some(error),
            Self::ExactLiteral(error) => Some(error),
            Self::PackedLiteralSet(error) => Some(error),
            Self::GuardedLiteralSet(error) => Some(error),
            Self::LiteralSetDfa(error) => Some(error),
            Self::RequiredLiteral(error) => Some(error),
            Self::LiteralClassRunLiteral(error) => Some(error),
            Self::PureByteClassRepeat(error) => Some(error),
            Self::BoundedByteClassSequence(error) => Some(error),
            Self::ForwardAnchored(error) => Some(error),
            Self::UnicodeFoldedLiteral(error) => Some(error),
            Self::UnicodeWordRun(error) => Some(error),
            Self::FixedPredicateWord64(error) => Some(error),
        }
    }
}

impl From<K0SearchError> for SearchError {
    fn from(value: K0SearchError) -> Self {
        Self::K0(value)
    }
}

impl From<LiteralError> for SearchError {
    fn from(value: LiteralError) -> Self {
        Self::ExactLiteral(value)
    }
}

impl From<PackedLiteralSetError> for SearchError {
    fn from(value: PackedLiteralSetError) -> Self {
        Self::PackedLiteralSet(value)
    }
}

impl From<GuardedLiteralSetSearchError> for SearchError {
    fn from(value: GuardedLiteralSetSearchError) -> Self {
        Self::GuardedLiteralSet(value)
    }
}

impl From<LiteralSetError> for SearchError {
    fn from(value: LiteralSetError) -> Self {
        Self::LiteralSetDfa(value)
    }
}

impl From<RequiredLiteralSearchError> for SearchError {
    fn from(value: RequiredLiteralSearchError) -> Self {
        Self::RequiredLiteral(value)
    }
}

impl From<LiteralClassRunLiteralSearchError> for SearchError {
    fn from(value: LiteralClassRunLiteralSearchError) -> Self {
        Self::LiteralClassRunLiteral(value)
    }
}

impl From<PureByteClassRepeatSearchError> for SearchError {
    fn from(value: PureByteClassRepeatSearchError) -> Self {
        Self::PureByteClassRepeat(value)
    }
}

impl From<BoundedByteClassSequenceSearchError> for SearchError {
    fn from(value: BoundedByteClassSequenceSearchError) -> Self {
        Self::BoundedByteClassSequence(value)
    }
}

impl From<ForwardAnchoredSearchError> for SearchError {
    fn from(value: ForwardAnchoredSearchError) -> Self {
        Self::ForwardAnchored(value)
    }
}

impl From<fre_kernels::FoldedLiteralTrieScanAttemptError> for SearchError {
    fn from(value: fre_kernels::FoldedLiteralTrieScanAttemptError) -> Self {
        Self::UnicodeFoldedLiteral(UnicodeFoldedLiteralSearchError {
            source: value.source,
            actual_work: value.actual.work,
            actual_source_byte_reads: value.actual.source_byte_reads,
        })
    }
}

impl From<UnicodeWordRunError> for SearchError {
    fn from(value: UnicodeWordRunError) -> Self {
        Self::UnicodeWordRun(value)
    }
}

impl From<FixedPredicateWord64SearchError> for SearchError {
    fn from(value: FixedPredicateWord64SearchError) -> Self {
        Self::FixedPredicateWord64(value)
    }
}

/// Hard limits for complete non-overlapping match iteration.
///
/// `max_search_calls` bounds the contextual searches actually executed across
/// the whole iterator. A deterministic replay of an already emitted empty
/// match is suppressed without executing another search; its byte- or
/// scalar-wise progress remains accounted separately. The session and
/// per-search limits retain their existing operation-specific meanings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableFindIterLimits {
    /// One-time reusable K0 workspace construction limits.
    pub session: SearchSessionLimits,
    /// Limits applied independently to each contextual search.
    pub search: SearchLimits,
    /// Maximum contextual searches across the entire iterator.
    pub max_search_calls: usize,
}

impl PortableFindIterLimits {
    /// Limits that accept every representable iterator execution.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            session: SearchSessionLimits::unlimited(),
            search: SearchLimits::unlimited(),
            max_search_calls: usize::MAX,
        }
    }

    /// Retain only the limits applied after session construction.
    ///
    /// This is useful when moving from [`PortableRegex::find_iter`], which
    /// constructs a fresh session, to [`PortableSearchSession::find_iter`],
    /// which reuses an already constructed session.
    #[must_use]
    pub const fn run(self) -> PortableFindIterRunLimits {
        PortableFindIterRunLimits {
            search: self.search,
            max_search_calls: self.max_search_calls,
        }
    }
}

impl Default for PortableFindIterLimits {
    fn default() -> Self {
        Self {
            session: SearchSessionLimits::default(),
            search: SearchLimits::default(),
            max_search_calls: 1_000_000,
        }
    }
}

/// Hard limits for one complete iteration on an existing search session.
///
/// Unlike [`PortableFindIterLimits`], this has no session-construction
/// allowance: [`PortableSearchSession::find_iter`] reuses the session's
/// already allocated K0 workspace. Each new iterator starts fresh
/// whole-iterator accounting while the one-time setup facts remain available
/// from [`PortableSearchSession::workspace_setup_accounting`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableFindIterRunLimits {
    /// Limits applied independently to each contextual search.
    pub search: SearchLimits,
    /// Maximum contextual searches across the entire iterator.
    pub max_search_calls: usize,
}

impl PortableFindIterRunLimits {
    /// Limits that accept every representable iterator execution.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            search: SearchLimits::unlimited(),
            max_search_calls: usize::MAX,
        }
    }
}

impl Default for PortableFindIterRunLimits {
    fn default() -> Self {
        Self {
            search: SearchLimits::default(),
            max_search_calls: 1_000_000,
        }
    }
}

/// Exact no-clock accounting accumulated by the portable byte or text match
/// iterators.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PortableFindIterAccounting {
    /// Contextual searches actually executed, including a final miss or an
    /// observed repeated-empty probe. Proven same-cursor empty replays do not
    /// execute or count another search.
    pub search_calls: usize,
    /// Non-overlapping matches returned to the caller.
    pub matches: usize,
    /// Repeated empty matches suppressed to guarantee byte- or scalar-wise
    /// progress, including deterministic same-cursor replays proven without
    /// another search.
    pub suppressed_empty: usize,
    /// Sum of charged work or conservative linear terms from successful
    /// contextual searches and UTF-8 empty-match progress.
    pub work_or_linear_terms: u64,
    /// Exact byte classifications performed while advancing a text iterator
    /// to the next UTF-8 scalar boundary after a repeated empty match.
    pub utf8_progress_byte_probes: u64,
    /// Exact charged work for UTF-8 empty-match progress: one initial offset
    /// increment, one term per byte classification, and one term per
    /// continuation-byte increment.
    pub utf8_progress_work: u64,
}

/// Checked terminal failure from complete portable match iteration.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableFindIterError {
    /// One contextual search failed under its operation-specific limits.
    Search(SearchError),
    /// The next contextual search would exceed the whole-iterator call cap.
    SearchCallLimit { needed: usize, limit: usize },
    /// An exact whole-iterator counter could not be incremented.
    AccountingOverflow { counter: &'static str },
}

impl fmt::Display for PortableFindIterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Search(error) => write!(formatter, "portable iteration search failed: {error}"),
            Self::SearchCallLimit { needed, limit } => write!(
                formatter,
                "portable iteration needs {needed} search calls, exceeding {limit}",
            ),
            Self::AccountingOverflow { counter } => {
                write!(
                    formatter,
                    "portable iteration {counter} accounting overflowed"
                )
            }
        }
    }
}

impl std::error::Error for PortableFindIterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Search(error) => Some(error),
            Self::SearchCallLimit { .. } | Self::AccountingOverflow { .. } => None,
        }
    }
}

impl From<SearchError> for PortableFindIterError {
    fn from(value: SearchError) -> Self {
        Self::Search(value)
    }
}

/// Planner selection control used by forced-plan differential tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PlanSelection {
    /// Use evidence-backed production routing.
    #[default]
    Auto,
    /// Require the v1 required-literal plan and propagate every refusal.
    ForceRequiredLiteral,
    /// Require the distinct forward-boundary plan and propagate every refusal.
    ForceForwardAnchored,
    /// Require the generic bounded K0 plan for qualification comparisons.
    ForceK0,
}

/// Capture-free operation stamped into a required-literal cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureFreeOperation {
    Exists,
    SelectedEnd,
    Span,
}

/// Complete equality key for one required-literal compiled/search contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequiredLiteralCacheIdentity {
    pub schema_version: u32,
    pub plan_id: &'static str,
    pub profile: CompatibilityProfile,
    pub operation: CaptureFreeOperation,
    pub anchors: fre_kernels::RequiredLiteralAnchors,
    pub class_words: [u64; 4],
    pub repeat: RequiredLiteralClassRepeat,
    pub suffix: Vec<u8>,
    pub build_limits: BuildLimits,
    pub search_limits: SearchLimits,
}

/// Complete equality key for one forward-anchored compiled/search contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardAnchoredCacheIdentity {
    pub schema_version: u32,
    pub plan_id: &'static str,
    pub profile: CompatibilityProfile,
    pub operation: CaptureFreeOperation,
    pub anchors: fre_kernels::ForwardAnchoredAnchors,
    pub class_words: [u64; 4],
    pub suffix: Vec<u8>,
    pub implementation: fre_kernels::ForwardClassImplementation,
    pub build_limits: BuildLimits,
    pub search_limits: SearchLimits,
}

/// Builder for the exact currently certified Rust-bytes subset.
#[derive(Clone, Debug)]
pub struct PortableBuilder {
    pattern: String,
    profile: RustProfile,
    limits: BuildLimits,
    selection: PlanSelection,
    set_admitted: bool,
    utf8_start_guarded: bool,
    pure_byte_class_repeat_allowed: bool,
}

impl PortableBuilder {
    /// Start from pinned Rust-regex defaults. Because the current lowerer has
    /// no Unicode-class compiler, callers commonly select [`Self::unicode`]
    /// `false` for byte classes; unsupported HIR is rejected either way.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: BuildLimits::default(),
            selection: PlanSelection::Auto,
            set_admitted: false,
            utf8_start_guarded: false,
            pure_byte_class_repeat_allowed: true,
        }
    }

    /// Select the complete Rust release-stack and constructor identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile.into_regex_builder();
        self
    }

    /// Retain a set-constructor stamp while building one already-associated
    /// constituent. Only the set builder may use this path; public single-
    /// pattern construction always normalizes to `RegexBuilder` identity.
    #[must_use]
    fn set_constituent_profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set the Rust bytes facade's Unicode mode before parsing.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Set case-insensitive mode for the complete pattern before parsing.
    ///
    /// Inline `i` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust bytes builder.
    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    /// Set multiline mode for `^` and `$` before parsing.
    #[must_use]
    pub fn multi_line(mut self, enabled: bool) -> Self {
        self.profile.options.multi_line = enabled;
        self
    }

    /// Set whether `.` matches the configured line terminator.
    #[must_use]
    pub fn dot_matches_new_line(mut self, enabled: bool) -> Self {
        self.profile.options.dot_matches_new_line = enabled;
        self
    }

    /// Set CRLF mode for the complete pattern before parsing.
    ///
    /// This makes both carriage return and line feed line terminators for
    /// dot and multiline assertions. Inline `R` flag groups may still
    /// override this setting locally, just as they do in the pinned Rust
    /// bytes builder.
    #[must_use]
    pub fn crlf(mut self, enabled: bool) -> Self {
        self.profile.options.crlf = enabled;
        self
    }

    /// Swap greedy and lazy repetition semantics before parsing.
    ///
    /// Inline `U` flag groups may still override this setting locally, just as
    /// they do in the pinned Rust bytes builder.
    #[must_use]
    pub fn swap_greed(mut self, enabled: bool) -> Self {
        self.profile.options.swap_greed = enabled;
        self
    }

    /// Set verbose mode before parsing, ignoring unescaped pattern whitespace
    /// and treating `#` as the start of a line comment.
    #[must_use]
    pub fn ignore_whitespace(mut self, enabled: bool) -> Self {
        self.profile.options.ignore_whitespace = enabled;
        self
    }

    /// Enable or disable octal escape syntax before parsing.
    #[must_use]
    pub fn octal(mut self, enabled: bool) -> Self {
        self.profile.options.octal = enabled;
        self
    }

    /// Set the parser's abstract-syntax-tree nesting limit.
    #[must_use]
    pub fn nest_limit(mut self, limit: u32) -> Self {
        self.profile.options.nest_limit = limit;
        self
    }

    /// Set the byte recognized by multiline `^` and `$` assertions.
    #[must_use]
    pub fn line_terminator(mut self, line_terminator: u8) -> Self {
        self.profile.options.line_terminator = line_terminator;
        self
    }

    /// Set the pinned high-level builder's approximate compiled-regex limit.
    ///
    /// FRE applies this limit with the same pinned meta-construction path and
    /// configuration used by `regex` 1.12.4 before selecting an FRE executor.
    /// A pattern that exceeds the limit is therefore an upstream constructor
    /// rejection, not an FRE capability or plan-resource refusal. The
    /// distinct direct-Rebar constructor profile has no corresponding high-
    /// level option and is left unchanged.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { size_limit, .. } =
            &mut self.profile.constructor
        {
            *size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Set the pinned high-level builder's lazy-DFA cache capacity identity.
    ///
    /// FRE's portable plans do not use the upstream lazy-DFA cache, so this
    /// option cannot weaken their independently checked construction and
    /// execution limits. It is nevertheless retained in the compatibility
    /// profile exactly because it is part of the public Rust bytes builder
    /// configuration. The distinct direct-Rebar constructor profile has no
    /// corresponding high-level option and is left unchanged.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let fre_syntax::RustConstructor::RegexBuilder { dfa_size_limit, .. } =
            &mut self.profile.constructor
        {
            *dfa_size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }

    /// Replace every checked construction limit.
    #[must_use]
    pub const fn limits(mut self, limits: BuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the total logical persistent-byte ceiling for the published
    /// matcher without changing any plan-specific construction limits.
    #[must_use]
    pub const fn max_persistent_bytes(mut self, limit: usize) -> Self {
        self.limits.max_persistent_bytes = limit;
        self
    }

    /// Force one plan so tests and qualification cannot accidentally exercise
    /// an alternative implementation.
    #[must_use]
    pub const fn plan_selection(mut self, selection: PlanSelection) -> Self {
        self.selection = selection;
        self
    }

    /// Use the already-completed aggregate Rust-set constructor admission.
    pub(crate) const fn after_set_admission(mut self) -> Self {
        self.set_admitted = true;
        self
    }

    pub(crate) const fn after_set_admission_if(mut self, admitted: bool) -> Self {
        self.set_admitted = admitted;
        self
    }

    /// Restrict every candidate match start to a UTF-8 scalar boundary. The
    /// text facade is the sole caller and proves valid UTF-8 input plus HIR
    /// equivalence before enabling this synthesized K0 guard.
    pub(crate) const fn with_utf8_start_guard(mut self) -> Self {
        self.utf8_start_guarded = true;
        self
    }

    /// Preserve text-facade routing while keeping byte-only native plans out
    /// of an otherwise equivalent unguarded text HIR.
    pub(crate) const fn for_text_facade(mut self) -> Self {
        self.pure_byte_class_repeat_allowed = false;
        self
    }

    /// Parse, plan, and independently validate an immutable portable plan.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] for syntax/admission failure, a resource cap, or
    /// any feature outside the certified subset. No alternate engine silently
    /// accepts an unsupported pattern.
    #[allow(
        clippy::too_many_lines,
        reason = "plan selection keeps each no-fallback construction branch and report explicit"
    )]
    pub fn build(self) -> Result<PortableRegex, BuildError> {
        let profile = CompatibilityProfile::RustBytes(self.profile.clone());
        let request = fre_syntax::ParseRequest::rust(self.pattern, profile.clone())
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety);
        let parsed = if self.set_admitted {
            fre_syntax::parse_rust_regex_set_constituent(request)?
        } else {
            fre_syntax::parse(request)?
        };
        let source = String::from_utf8(parsed.key.pattern.into_bytes())
            .map_err(|_| {
                BuildError::InternalInvariant("Rust parse retained a non-UTF-8 source pattern")
            })?
            .into_boxed_str();
        let source_storage_bytes = source.len();
        let admission = parsed.admission_status;
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(BuildError::InternalInvariant(
                "Rust bytes request produced a non-Rust canonical pattern",
            ));
        };
        let explicit_captures = usize::try_from(syntax.captures).map_err(|_| {
            BuildError::InternalInvariant("syntax capture count does not fit usize")
        })?;
        if explicit_captures != rust.hir.properties().explicit_captures_len() {
            return Err(BuildError::InternalInvariant(
                "syntax capture count differs from HIR properties",
            ));
        }
        let static_captures_len = rust
            .hir
            .properties()
            .static_explicit_captures_len()
            .map(|len| {
                len.checked_add(1).ok_or(BuildError::InternalInvariant(
                    "static capture count including group zero overflowed usize",
                ))
            })
            .transpose()?;
        let CaptureNameMetadata {
            names: capture_names,
            captures_len,
            storage_bytes: capture_name_storage_bytes,
        } = capture_name_metadata(&rust.hir, explicit_captures, syntax.hir_nodes)?;
        let minimum_match_bytes = rust.hir.properties().minimum_len();
        let line_total_grep_plan = line_total_grep::prove(&rust.hir);
        if self.utf8_start_guarded
            && !matches!(self.selection, PlanSelection::Auto | PlanSelection::ForceK0)
        {
            return Err(BuildError::InternalInvariant(
                "UTF-8 start guard requires automatic or forced K0 selection",
            ));
        }
        if self.selection == PlanSelection::ForceK0 || self.utf8_start_guarded {
            let lowered = if self.utf8_start_guarded {
                fre_lower::lower_utf8_start_guarded(
                    &rust,
                    OperationSemantics::CaptureFree,
                    self.limits.lowering,
                )?
            } else {
                fre_lower::lower(&rust, OperationSemantics::CaptureFree, self.limits.lowering)?
            };
            let lowering = lowered.stats();
            let automaton = lowered
                .into_automaton()
                .with_line_terminator(self.profile.options.line_terminator);
            let plan = automaton.stats();
            return Ok(PortableRegex {
                source,
                capture_names,
                line_total_grep_plan,
                plan: PortablePlan::K0(PortableK0Plan {
                    automaton,
                    mandatory_suffix: None,
                    mandatory_cut: None,
                    negative_prefilter: None,
                }),
                profile: profile.clone(),
                limits: self.limits,
                selection: self.selection,
                report: BuildReport {
                    profile: profile.clone(),
                    admission,
                    syntax,
                    plan: PlanKind::K0,
                    planner_work: 0,
                    lowering: Some(lowering),
                    states: plan.states(),
                    edges: plan.edges(),
                    plan_storage_bytes: plan.storage_bytes(),
                    source_storage_bytes,
                    capture_name_storage_bytes,
                    charged_persistent_bytes: 0,
                    persistent_byte_limit: 0,
                    captures_len,
                    static_captures_len,
                    minimum_match_bytes,
                    required_literal: None,
                    literal_class_run_literal: None,
                    forward_anchored: None,
                }
                .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
            });
        }
        if self.selection == PlanSelection::Auto
            && let Some(plan) = unicode_word_run::extract(&rust.hir)
        {
            let planner_work = u64::try_from(plan.portable_build_work()).map_err(|_| {
                BuildError::InternalInvariant("word-run build work does not fit u64")
            })?;
            if planner_work > self.limits.max_planner_work {
                return Err(BuildError::PlannerWorkLimit {
                    needed: planner_work,
                    limit: self.limits.max_planner_work,
                });
            }
            let plan_storage_bytes = plan.portable_storage_bytes();
            return Ok(PortableRegex {
                source,
                capture_names,
                line_total_grep_plan,
                plan: if plan.is_ascii_word() {
                    PortablePlan::AsciiWordRun(
                        unicode_word_run::AsciiPlan::build_auto(plan).map_err(
                            |error| match error {
                                fre_exact_alloc::CopyError::LayoutOverflow => {
                                    BuildError::InternalInvariant(
                                        "exact ASCII word-run owner layout overflowed",
                                    )
                                }
                                fre_exact_alloc::CopyError::AllocationFailed => {
                                    BuildError::AllocationFailed {
                                        structure: "ASCII word-run owner",
                                        additional: 1,
                                    }
                                }
                            },
                        )?,
                    )
                } else {
                    PortablePlan::UnicodeWordRun(plan)
                },
                profile: profile.clone(),
                limits: self.limits,
                selection: self.selection,
                report: BuildReport {
                    profile: profile.clone(),
                    admission,
                    syntax,
                    plan: PlanKind::UnicodeWordRun,
                    planner_work,
                    lowering: None,
                    states: 0,
                    edges: 0,
                    plan_storage_bytes,
                    source_storage_bytes,
                    capture_name_storage_bytes,
                    charged_persistent_bytes: 0,
                    persistent_byte_limit: 0,
                    captures_len,
                    static_captures_len,
                    minimum_match_bytes,
                    required_literal: None,
                    literal_class_run_literal: None,
                    forward_anchored: None,
                }
                .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
            });
        }
        let mut planner_work = 0_u64;
        if self.selection == PlanSelection::Auto {
            let inspection = bounded_word_class::inspect(
                &rust.hir,
                SimdDispatchContext::capture(),
                planner_work,
                self.limits.max_planner_work,
            )
            .map_err(|error| match error {
                bounded_word_class::InspectionError::WorkLimit { needed, limit } => {
                    BuildError::PlannerWorkLimit { needed, limit }
                }
                bounded_word_class::InspectionError::ArithmeticOverflow(detail) => {
                    BuildError::InternalInvariant(detail)
                }
            })?;
            planner_work = inspection.planner_work();
            if let bounded_word_class::InspectionOutcome::Eligible(inspection) = inspection {
                let plan_storage_bytes = inspection.storage_bytes();
                let charged_persistent_bytes = source_storage_bytes
                    .checked_add(capture_name_storage_bytes)
                    .and_then(|bytes| bytes.checked_add(plan_storage_bytes))
                    .ok_or(BuildError::PersistentBytesOverflow)?;
                if charged_persistent_bytes > self.limits.max_persistent_bytes {
                    return Err(BuildError::PersistentBytesLimit {
                        needed: charged_persistent_bytes,
                        limit: self.limits.max_persistent_bytes,
                    });
                }
                let plan = inspection.build()?;
                if plan.storage_bytes() != plan_storage_bytes {
                    return Err(BuildError::InternalInvariant(
                        "bounded word-class retained storage differs from inspection",
                    ));
                }
                return Ok(PortableRegex {
                    source,
                    capture_names,
                    line_total_grep_plan,
                    plan: PortablePlan::BoundedWordClass(plan),
                    profile: profile.clone(),
                    limits: self.limits,
                    selection: self.selection,
                    report: BuildReport {
                        profile: profile.clone(),
                        admission,
                        syntax,
                        plan: PlanKind::UnicodeWordRun,
                        planner_work,
                        lowering: None,
                        states: 0,
                        edges: 0,
                        plan_storage_bytes,
                        source_storage_bytes,
                        capture_name_storage_bytes,
                        charged_persistent_bytes: 0,
                        persistent_byte_limit: 0,
                        captures_len,
                        static_captures_len,
                        minimum_match_bytes,
                        required_literal: None,
                        literal_class_run_literal: None,
                        forward_anchored: None,
                    }
                    .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                });
            }
        }
        if matches!(
            self.selection,
            PlanSelection::Auto | PlanSelection::ForceForwardAnchored
        ) {
            let forward =
                forward_anchored::extract(&rust.hir, planner_work, self.limits.max_planner_work)?;
            planner_work = forward.work;
            if let Some(shape) = forward.shape {
                if self.selection == PlanSelection::ForceForwardAnchored && shape.anchors.end {
                    let plan = AbsoluteEndFixedPlan::build(
                        shape.class,
                        shape.suffix,
                        shape.anchors,
                        self.limits.forward_anchored,
                    )
                    .map_err(BuildError::ForwardAnchored)?;
                    let build = plan.build_accounting();
                    return Ok(PortableRegex {
                        source,
                        capture_names,
                        line_total_grep_plan,
                        plan: PortablePlan::ForwardEndFixed(plan),
                        profile: profile.clone(),
                        limits: self.limits,
                        selection: self.selection,
                        report: BuildReport {
                            profile: profile.clone(),
                            admission,
                            syntax,
                            plan: PlanKind::ForwardAnchored,
                            planner_work,
                            lowering: None,
                            states: 0,
                            edges: 0,
                            plan_storage_bytes: build.persistent_bytes,
                            source_storage_bytes,
                            capture_name_storage_bytes,
                            charged_persistent_bytes: 0,
                            persistent_byte_limit: 0,
                            captures_len,
                            static_captures_len,
                            minimum_match_bytes,
                            required_literal: None,
                            literal_class_run_literal: None,
                            forward_anchored: Some(build),
                        }
                        .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                    });
                }
                let dispatch = SimdDispatchContext::capture();
                let forward = if ForwardAnchoredPlan::run_scanner_eligible(dispatch, shape.class) {
                    ForwardAnchoredPlan::build_with_dispatch(
                        dispatch,
                        shape.class,
                        shape.suffix,
                        shape.anchors,
                        self.limits.forward_anchored,
                    )
                    .map(PortablePlan::DispatchedForwardAnchored)
                } else {
                    ForwardAnchoredPlan::build(
                        shape.class,
                        shape.suffix,
                        shape.anchors,
                        self.limits.forward_anchored,
                    )
                    .map(PortablePlan::ForwardAnchored)
                };
                match forward {
                    Ok(plan) => {
                        let build = match &plan {
                            PortablePlan::ForwardAnchored(plan) => plan.build_accounting(),
                            PortablePlan::DispatchedForwardAnchored(plan) => {
                                plan.build_accounting()
                            }
                            _ => unreachable!("the forward constructor returned another family"),
                        };
                        return Ok(PortableRegex {
                            source,
                            capture_names,
                            line_total_grep_plan,
                            plan,
                            profile: profile.clone(),
                            limits: self.limits,
                            selection: self.selection,
                            report: BuildReport {
                                profile: profile.clone(),
                                admission,
                                syntax,
                                plan: PlanKind::ForwardAnchored,
                                planner_work,
                                lowering: None,
                                states: 0,
                                edges: 0,
                                plan_storage_bytes: build.persistent_bytes,
                                source_storage_bytes,
                                capture_name_storage_bytes,
                                charged_persistent_bytes: 0,
                                persistent_byte_limit: 0,
                                captures_len,
                                static_captures_len,
                                minimum_match_bytes,
                                required_literal: None,
                                literal_class_run_literal: None,
                                forward_anchored: Some(build),
                            }
                            .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                        });
                    }
                    Err(error)
                        if self.selection == PlanSelection::Auto && error.is_semantic_refusal() => {
                    }
                    Err(error) => return Err(BuildError::ForwardAnchored(error)),
                }
            } else if self.selection == PlanSelection::ForceForwardAnchored {
                return Err(BuildError::ForwardAnchoredShape);
            }
        }
        let required =
            required_literal::extract(&rust.hir, planner_work, self.limits.max_planner_work)?;
        let required_work = required.work;
        if let Some(shape) = required.shape {
            let default_allowed = !(shape.anchors.start && shape.anchors.end);
            if self.selection == PlanSelection::ForceRequiredLiteral || default_allowed {
                let dispatch = SimdDispatchContext::capture();
                let scanner_eligible =
                    RequiredLiteralPlan::run_scanner_eligible(dispatch, shape.class);
                let required_plan = if shape.repeat == RequiredLiteralClassRepeat::one_or_more() {
                    if scanner_eligible {
                        RequiredLiteralPlan::build_with_dispatch(
                            dispatch,
                            shape.class,
                            &shape.suffix,
                            shape.anchors,
                            self.limits.required_literal,
                        )
                        .map(PortablePlan::DispatchedRequiredLiteral)
                    } else {
                        RequiredLiteralPlan::build(
                            shape.class,
                            &shape.suffix,
                            shape.anchors,
                            self.limits.required_literal,
                        )
                        .map(PortablePlan::RequiredLiteral)
                    }
                } else if scanner_eligible {
                    BoundedRequiredLiteralPlan::build_with_dispatch(
                        dispatch,
                        shape.class,
                        shape.repeat,
                        &shape.suffix,
                        shape.anchors,
                        self.limits.required_literal,
                    )
                    .map(PortablePlan::DispatchedBoundedRequiredLiteral)
                } else {
                    BoundedRequiredLiteralPlan::build(
                        shape.class,
                        shape.repeat,
                        &shape.suffix,
                        shape.anchors,
                        self.limits.required_literal,
                    )
                    .map(PortablePlan::BoundedRequiredLiteral)
                };
                match required_plan {
                    Ok(plan) => {
                        let build = match &plan {
                            PortablePlan::RequiredLiteral(plan) => plan.build_accounting(),
                            PortablePlan::DispatchedRequiredLiteral(plan) => {
                                plan.build_accounting()
                            }
                            PortablePlan::BoundedRequiredLiteral(plan) => plan.build_accounting(),
                            PortablePlan::DispatchedBoundedRequiredLiteral(plan) => {
                                plan.build_accounting()
                            }
                            _ => unreachable!(
                                "the required-literal constructor returned another family"
                            ),
                        };
                        return Ok(PortableRegex {
                            source,
                            capture_names,
                            line_total_grep_plan,
                            plan,
                            profile: profile.clone(),
                            limits: self.limits,
                            selection: self.selection,
                            report: BuildReport {
                                profile: profile.clone(),
                                admission,
                                syntax,
                                plan: PlanKind::RequiredLiteral,
                                planner_work: required_work,
                                lowering: None,
                                states: 0,
                                edges: 0,
                                plan_storage_bytes: build.persistent_bytes,
                                source_storage_bytes,
                                capture_name_storage_bytes,
                                charged_persistent_bytes: 0,
                                persistent_byte_limit: 0,
                                captures_len,
                                static_captures_len,
                                minimum_match_bytes,
                                required_literal: Some(build),
                                literal_class_run_literal: None,
                                forward_anchored: None,
                            }
                            .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                        });
                    }
                    Err(error)
                        if self.selection == PlanSelection::Auto && error.is_semantic_refusal() => {
                    }
                    Err(error) => return Err(BuildError::RequiredLiteral(error)),
                }
            }
        } else if self.selection == PlanSelection::ForceRequiredLiteral {
            return Err(BuildError::RequiredLiteralShape);
        }
        let mut literal_class_run_work = required_work;
        if self.selection == PlanSelection::Auto {
            let remaining = self
                .limits
                .max_planner_work
                .checked_sub(required_work)
                .ok_or(BuildError::InternalInvariant(
                    "required-literal planner work exceeded its enforced limit",
                ))?;
            let inspection_limit = usize::try_from(remaining).unwrap_or(usize::MAX);
            let inspection = literal_class_run_literal::inspect(&rust.hir, inspection_limit)
                .map_err(|error| match error {
                    literal_class_run_literal::InspectionError::WorkLimit { needed, .. } => {
                        let needed =
                            required_work.saturating_add(u64::try_from(needed).unwrap_or(u64::MAX));
                        BuildError::PlannerWorkLimit {
                            needed,
                            limit: self.limits.max_planner_work,
                        }
                    }
                    literal_class_run_literal::InspectionError::Overflow => {
                        BuildError::InternalInvariant(
                            "literal/class-run inspection accounting overflowed",
                        )
                    }
                })?;
            let inspection_work = match inspection {
                literal_class_run_literal::InspectionOutcome::Eligible(inspection) => {
                    inspection.work
                }
                literal_class_run_literal::InspectionOutcome::Ineligible { work } => work,
            };
            literal_class_run_work = required_work
                .checked_add(u64::try_from(inspection_work).map_err(|_| {
                    BuildError::InternalInvariant("literal/class-run planner work does not fit u64")
                })?)
                .ok_or(BuildError::InternalInvariant(
                    "cumulative literal/class-run planner work overflowed u64",
                ))?;
            if literal_class_run_work > self.limits.max_planner_work {
                return Err(BuildError::PlannerWorkLimit {
                    needed: literal_class_run_work,
                    limit: self.limits.max_planner_work,
                });
            }
            if let literal_class_run_literal::InspectionOutcome::Eligible(inspection) = inspection {
                let dispatch = SimdDispatchContext::capture();
                let built = if inspection.generalized_search {
                    if let Some(ranges) = inspection.class.unicode_ranges() {
                        LiteralClassRunSearchPlan::build_unicode_all_non_ascii_with_dispatch(
                            dispatch,
                            inspection.prefix,
                            ranges.iter().map(|range| (range.start(), range.end())),
                            inspection.suffix,
                            inspection.minimum,
                            self.limits.literal_class_run_literal,
                        )
                    } else {
                        LiteralClassRunSearchPlan::build_with_dispatch(
                            dispatch,
                            inspection.prefix,
                            inspection.class.ranges(),
                            inspection.suffix,
                            inspection.minimum,
                            inspection.boundary_semantics,
                            self.limits.literal_class_run_literal,
                        )
                    }
                    .map(PortablePlan::LiteralClassRunSearch)
                } else {
                    match inspection.boundary_semantics {
                        LiteralClassRunLiteralBoundarySemantics::Unguarded => {
                            LiteralClassRunLiteralPlan::build_with_dispatch(
                                dispatch,
                                inspection.prefix,
                                inspection.class.ranges(),
                                inspection.suffix,
                                self.limits.literal_class_run_literal,
                            )
                        }
                        LiteralClassRunLiteralBoundarySemantics::CompleteAsciiWordRun => {
                            LiteralClassRunLiteralPlan::build_complete_ascii_word_run_with_dispatch(
                                dispatch,
                                inspection.prefix,
                                inspection.class.ranges(),
                                inspection.suffix,
                                self.limits.literal_class_run_literal,
                            )
                        }
                    }
                    .map(PortablePlan::LiteralClassRunLiteral)
                };
                let plan = match built {
                    Ok(plan) => Some(plan),
                    Err(error)
                        if literal_class_run_literal_failure_class(&error)
                            == BuildFailureClass::Unsupported =>
                    {
                        None
                    }
                    Err(error) => return Err(BuildError::LiteralClassRunLiteral(error)),
                };
                if let Some(plan) = plan {
                    let build = match &plan {
                        PortablePlan::LiteralClassRunLiteral(plan) => plan.build_accounting(),
                        PortablePlan::LiteralClassRunSearch(plan) => plan.build_accounting(),
                        _ => {
                            return Err(BuildError::InternalInvariant(
                                "literal/class-run admission built another plan family",
                            ));
                        }
                    };
                    return Ok(PortableRegex {
                        source,
                        capture_names,
                        line_total_grep_plan,
                        plan,
                        profile: profile.clone(),
                        limits: self.limits,
                        selection: self.selection,
                        report: BuildReport {
                            profile: profile.clone(),
                            admission,
                            syntax,
                            plan: PlanKind::LiteralClassRunLiteral,
                            planner_work: literal_class_run_work,
                            lowering: None,
                            states: 0,
                            edges: 0,
                            plan_storage_bytes: build.persistent_bytes,
                            source_storage_bytes,
                            capture_name_storage_bytes,
                            charged_persistent_bytes: 0,
                            persistent_byte_limit: 0,
                            captures_len,
                            static_captures_len,
                            minimum_match_bytes,
                            required_literal: None,
                            literal_class_run_literal: Some(build),
                            forward_anchored: None,
                        }
                        .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                    });
                }
            }
        }
        let mut pure_byte_class_repeat_work = literal_class_run_work;
        if self.selection == PlanSelection::Auto && self.pure_byte_class_repeat_allowed {
            let inspection = pure_byte_class_repeat::inspect(
                &rust.hir,
                literal_class_run_work,
                self.limits.max_planner_work,
            )
            .map_err(|error| match error {
                pure_byte_class_repeat::InspectionError::WorkLimit { needed, limit } => {
                    BuildError::PlannerWorkLimit { needed, limit }
                }
                pure_byte_class_repeat::InspectionError::ArithmeticOverflow => {
                    BuildError::InternalInvariant(
                        "pure byte-class repeat planner arithmetic overflow",
                    )
                }
            })?;
            pure_byte_class_repeat_work = inspection.planner_work();
            if let pure_byte_class_repeat::InspectionOutcome::Eligible(inspection) = inspection {
                let plan_storage_bytes = pure_byte_class_repeat::Plan::storage_bytes();
                let charged_persistent_bytes = source_storage_bytes
                    .checked_add(capture_name_storage_bytes)
                    .and_then(|bytes| bytes.checked_add(plan_storage_bytes))
                    .ok_or(BuildError::PersistentBytesOverflow)?;
                if charged_persistent_bytes > self.limits.max_persistent_bytes {
                    return Err(BuildError::PersistentBytesLimit {
                        needed: charged_persistent_bytes,
                        limit: self.limits.max_persistent_bytes,
                    });
                }
                let plan = inspection
                    .build(SimdDispatchContext::capture())
                    .map_err(|error| match error {
                        fre_exact_alloc::CopyError::LayoutOverflow => {
                            BuildError::InternalInvariant(
                                "pure byte-class repeat owner layout overflowed",
                            )
                        }
                        fre_exact_alloc::CopyError::AllocationFailed => {
                            BuildError::AllocationFailed {
                                structure: "pure byte-class repeat owner",
                                additional: 1,
                            }
                        }
                    })?;
                return Ok(PortableRegex {
                    source,
                    capture_names,
                    line_total_grep_plan,
                    plan: PortablePlan::PureByteClassRepeat(plan),
                    profile: profile.clone(),
                    limits: self.limits,
                    selection: self.selection,
                    report: BuildReport {
                        profile: profile.clone(),
                        admission,
                        syntax,
                        plan: PlanKind::PureByteClassRepeat,
                        planner_work: pure_byte_class_repeat_work,
                        lowering: None,
                        states: 0,
                        edges: 0,
                        plan_storage_bytes,
                        source_storage_bytes,
                        capture_name_storage_bytes,
                        charged_persistent_bytes,
                        persistent_byte_limit: self.limits.max_persistent_bytes,
                        captures_len,
                        static_captures_len,
                        minimum_match_bytes,
                        required_literal: None,
                        literal_class_run_literal: None,
                        forward_anchored: None,
                    },
                });
            }
        }
        let mut bounded_byte_class_repeat_work = pure_byte_class_repeat_work;
        if self.selection == PlanSelection::Auto && self.pure_byte_class_repeat_allowed {
            let inspection = bounded_byte_class_repeat::inspect(
                &rust.hir,
                pure_byte_class_repeat_work,
                self.limits.max_planner_work,
            )
            .map_err(|error| match error {
                bounded_byte_class_repeat::InspectionError::WorkLimit { needed, limit } => {
                    BuildError::PlannerWorkLimit { needed, limit }
                }
                bounded_byte_class_repeat::InspectionError::ArithmeticOverflow => {
                    BuildError::InternalInvariant(
                        "bounded byte-class repeat planner arithmetic overflow",
                    )
                }
            })?;
            bounded_byte_class_repeat_work = inspection.planner_work();
            if let bounded_byte_class_repeat::InspectionOutcome::Eligible(inspection) = inspection {
                let plan_storage_bytes = bounded_byte_class_repeat::Plan::storage_bytes();
                let charged_persistent_bytes = source_storage_bytes
                    .checked_add(capture_name_storage_bytes)
                    .and_then(|bytes| bytes.checked_add(plan_storage_bytes))
                    .ok_or(BuildError::PersistentBytesOverflow)?;
                if charged_persistent_bytes > self.limits.max_persistent_bytes {
                    return Err(BuildError::PersistentBytesLimit {
                        needed: charged_persistent_bytes,
                        limit: self.limits.max_persistent_bytes,
                    });
                }
                let plan = inspection
                    .build(SimdDispatchContext::capture())
                    .map_err(|error| match error {
                        fre_exact_alloc::CopyError::LayoutOverflow => {
                            BuildError::InternalInvariant(
                                "bounded byte-class repeat owner layout overflowed",
                            )
                        }
                        fre_exact_alloc::CopyError::AllocationFailed => {
                            BuildError::AllocationFailed {
                                structure: "bounded byte-class repeat owner",
                                additional: 1,
                            }
                        }
                    })?;
                return Ok(PortableRegex {
                    source,
                    capture_names,
                    line_total_grep_plan,
                    plan: PortablePlan::BoundedByteClassRepeat(plan),
                    profile: profile.clone(),
                    limits: self.limits,
                    selection: self.selection,
                    report: BuildReport {
                        profile: profile.clone(),
                        admission,
                        syntax,
                        plan: PlanKind::PureByteClassRepeat,
                        planner_work: bounded_byte_class_repeat_work,
                        lowering: None,
                        states: 0,
                        edges: 0,
                        plan_storage_bytes,
                        source_storage_bytes,
                        capture_name_storage_bytes,
                        charged_persistent_bytes,
                        persistent_byte_limit: self.limits.max_persistent_bytes,
                        captures_len,
                        static_captures_len,
                        minimum_match_bytes,
                        required_literal: None,
                        literal_class_run_literal: None,
                        forward_anchored: None,
                    },
                });
            }
        }
        let FixedPredicateAutoAttempt {
            plan: fixed_predicate_plan,
            planner_work: fixed_predicate_work,
            plan_storage_bytes: fixed_predicate_storage_bytes,
            charged_persistent_bytes: fixed_predicate_charged_bytes,
            declined: fixed_predicate_declined,
        } = try_fixed_predicate_word64_before_finite(
            &rust.hir,
            syntax.hir_nodes,
            explicit_captures,
            bounded_byte_class_repeat_work,
            self.limits.max_planner_work,
            source_storage_bytes,
            capture_name_storage_bytes,
            self.limits.max_persistent_bytes,
        )?;
        if let Some(plan) = fixed_predicate_plan {
            return Ok(PortableRegex {
                source,
                capture_names,
                line_total_grep_plan,
                plan: PortablePlan::FixedPredicateWord64(plan),
                profile: profile.clone(),
                limits: self.limits,
                selection: self.selection,
                report: BuildReport {
                    profile: profile.clone(),
                    admission,
                    syntax,
                    plan: PlanKind::FixedPredicateWord64,
                    planner_work: fixed_predicate_work,
                    lowering: None,
                    states: 0,
                    edges: 0,
                    plan_storage_bytes: fixed_predicate_storage_bytes,
                    source_storage_bytes,
                    capture_name_storage_bytes,
                    charged_persistent_bytes: fixed_predicate_charged_bytes,
                    persistent_byte_limit: self.limits.max_persistent_bytes,
                    captures_len,
                    static_captures_len,
                    minimum_match_bytes,
                    required_literal: None,
                    literal_class_run_literal: None,
                    forward_anchored: None,
                },
            });
        }
        let retained_facade_bytes = source_storage_bytes
            .checked_add(capture_name_storage_bytes)
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let guarded_plan_persistent_bytes = self
            .limits
            .max_persistent_bytes
            .saturating_sub(retained_facade_bytes);
        let look_set = rust.hir.properties().look_set();
        let has_guarded_ascii_left = look_set.contains(Look::WordAscii)
            || look_set.contains(Look::WordStartAscii)
            || look_set.contains(Look::WordStartHalfAscii);
        let has_guarded_ascii_right = look_set.contains(Look::WordAscii)
            || look_set.contains(Look::WordEndAscii)
            || look_set.contains(Look::WordEndHalfAscii);
        let derive_guarded_ascii_dictionary = self.selection == PlanSelection::Auto
            && has_guarded_ascii_left
            && has_guarded_ascii_right;
        let finite_outcome = finite::extract(
            &rust.hir,
            self.limits.literal_set.max_patterns,
            self.limits.literal_set.max_pattern_bytes,
            fixed_predicate_work,
            self.limits.max_planner_work,
            derive_guarded_ascii_dictionary,
            guarded_literal_set::extraction_limits(
                self.limits.packed_literal_set,
                guarded_plan_persistent_bytes,
            ),
        );
        if !finite_outcome.has_closed_receipt() {
            return Err(BuildError::InternalInvariant(
                "finite outcome lost its extraction-attempt closure",
            ));
        }
        let mut finite_work = finite_outcome.work();
        let (finite_words, guarded_dictionary) = match finite_outcome {
            finite::FiniteOutcome::Fits { words, .. } => (Some(words), None),
            finite::FiniteOutcome::GuardedFiniteBody { dictionary, .. } => {
                (None, Some(dictionary))
            }
            finite::FiniteOutcome::TooLargeFixedSequence { .. }
            | finite::FiniteOutcome::Unsupported { .. }
            | finite::FiniteOutcome::GuardedResourceFailure {
                error: finite::GuardedFiniteBuildError::ConstructionLimit { .. },
                ..
            } => (None, None),
            finite::FiniteOutcome::ResourceFailure { error, .. } => return Err(error),
            finite::FiniteOutcome::GuardedResourceFailure {
                error: finite::GuardedFiniteBuildError::Dictionary(error),
                ..
            } => match error.kind {
                guarded_ascii_word::BuildErrorKind::ResourceLimit { .. }
                | guarded_ascii_word::BuildErrorKind::WorkLimit { .. }
                | guarded_ascii_word::BuildErrorKind::RepresentationLimit { .. } => (None, None),
                guarded_ascii_word::BuildErrorKind::AllocationFailed {
                    structure,
                    additional,
                } => {
                    return Err(BuildError::AllocationFailed {
                        structure,
                        additional,
                    });
                }
                guarded_ascii_word::BuildErrorKind::ArithmeticOverflow { computation } => {
                    return Err(BuildError::InternalInvariant(computation));
                }
                guarded_ascii_word::BuildErrorKind::InternalInvariant { detail } => {
                    return Err(BuildError::InternalInvariant(detail));
                }
                guarded_ascii_word::BuildErrorKind::EmptyDictionary
                | guarded_ascii_word::BuildErrorKind::ImpossibleDimensions { .. }
                | guarded_ascii_word::BuildErrorKind::SourceLengthMismatch { .. }
                | guarded_ascii_word::BuildErrorKind::PackedBytesMismatch { .. }
                | guarded_ascii_word::BuildErrorKind::EmptyWord { .. }
                | guarded_ascii_word::BuildErrorKind::InvalidLeftGuard { .. }
                | guarded_ascii_word::BuildErrorKind::InvalidRightGuard { .. }
                | guarded_ascii_word::BuildErrorKind::NonAsciiWordByte { .. } => {
                    return Err(BuildError::InternalInvariant(
                        "guarded finite extraction produced an invalid ASCII-word dictionary",
                    ));
                }
            },
        };
        if let Some(dictionary) = guarded_dictionary
            && let Ok(plan) = guarded_literal_set::Plan::build(
                dictionary,
                self.limits.packed_literal_set,
                guarded_plan_persistent_bytes,
            )
        {
            let storage = plan.storage_bytes();
            return Ok(PortableRegex {
                source,
                capture_names,
                line_total_grep_plan,
                plan: PortablePlan::GuardedLiteralSet(plan),
                profile: profile.clone(),
                limits: self.limits,
                selection: self.selection,
                report: BuildReport {
                    profile: profile.clone(),
                    admission,
                    syntax,
                    plan: PlanKind::PackedLiteralSet,
                    planner_work: finite_work,
                    lowering: None,
                    states: 0,
                    edges: 0,
                    plan_storage_bytes: storage,
                    source_storage_bytes,
                    capture_name_storage_bytes,
                    charged_persistent_bytes: 0,
                    persistent_byte_limit: 0,
                    captures_len,
                    static_captures_len,
                    minimum_match_bytes,
                    required_literal: None,
                    literal_class_run_literal: None,
                    forward_anchored: None,
                }
                .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
            });
        }
        if let Some(words) = finite_words {
            if words.len() == 1 {
                let literal = LiteralPlan::new(&words[0], self.limits.literal)?;
                let storage = literal.storage_bytes();
                return Ok(PortableRegex {
                    source,
                    capture_names,
                    line_total_grep_plan,
                    plan: PortablePlan::ExactLiteral(literal),
                    profile: profile.clone(),
                    limits: self.limits,
                    selection: self.selection,
                    report: BuildReport {
                        profile: profile.clone(),
                        admission,
                        syntax,
                        plan: PlanKind::ExactLiteral,
                        planner_work: finite_work,
                        lowering: None,
                        states: 0,
                        edges: 0,
                        plan_storage_bytes: storage,
                        source_storage_bytes,
                        capture_name_storage_bytes,
                        charged_persistent_bytes: 0,
                        persistent_byte_limit: 0,
                        captures_len,
                        static_captures_len,
                        minimum_match_bytes,
                        required_literal: None,
                        literal_class_run_literal: None,
                        forward_anchored: None,
                    }
                    .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                });
            }
            if words.len() > 1 {
                if let Ok(packed) =
                    PackedLiteralSetPlan::new(&words, self.limits.packed_literal_set)
                {
                    let storage = packed.build_accounting().persistent_bytes;
                    return Ok(PortableRegex {
                        source,
                        capture_names,
                        line_total_grep_plan,
                        plan: PortablePlan::PackedLiteralSet(packed),
                        profile: profile.clone(),
                        limits: self.limits,
                        selection: self.selection,
                        report: BuildReport {
                            profile: profile.clone(),
                            admission,
                            syntax,
                            plan: PlanKind::PackedLiteralSet,
                            planner_work: finite_work,
                            lowering: None,
                            states: 0,
                            edges: 0,
                            plan_storage_bytes: storage,
                            source_storage_bytes,
                            capture_name_storage_bytes,
                            charged_persistent_bytes: 0,
                            persistent_byte_limit: 0,
                            captures_len,
                            static_captures_len,
                            minimum_match_bytes,
                            required_literal: None,
                            literal_class_run_literal: None,
                            forward_anchored: None,
                        }
                        .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                    });
                }
                let mut literal_set = LiteralSetPlan::new(&words, self.limits.literal_set)?;
                if self.selection == PlanSelection::Auto
                    && words.len() > PACKED_LITERAL_SET_CERTIFIED_MAX_PATTERNS
                {
                    let retained_facade_bytes = source_storage_bytes
                        .checked_add(capture_name_storage_bytes)
                        .ok_or(BuildError::PersistentBytesOverflow)?;
                    finite_work = try_attach_unicode_folded_long_tail(
                        &mut literal_set,
                        &words,
                        (&rust.hir, syntax.hir_nodes),
                        &self.profile,
                        &self.limits,
                        retained_facade_bytes,
                        finite_work,
                    )?;
                }
                let storage = literal_set.build_accounting().persistent_bytes;
                return Ok(PortableRegex {
                    source,
                    capture_names,
                    line_total_grep_plan,
                    plan: PortablePlan::LiteralSetDfa(literal_set),
                    profile: profile.clone(),
                    limits: self.limits,
                    selection: self.selection,
                    report: BuildReport {
                        profile: profile.clone(),
                        admission,
                        syntax,
                        plan: PlanKind::LiteralSetDfa,
                        planner_work: finite_work,
                        lowering: None,
                        states: 0,
                        edges: 0,
                        plan_storage_bytes: storage,
                        source_storage_bytes,
                        capture_name_storage_bytes,
                        charged_persistent_bytes: 0,
                        persistent_byte_limit: 0,
                        captures_len,
                        static_captures_len,
                        minimum_match_bytes,
                        required_literal: None,
                        literal_class_run_literal: None,
                        forward_anchored: None,
                    }
                    .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                });
            }
        }
        let mut bounded_byte_class_sequence_work = finite_work;
        if self.selection == PlanSelection::Auto && self.pure_byte_class_repeat_allowed {
            let inspection = bounded_byte_class_sequence::inspect(
                &rust.hir,
                finite_work,
                self.limits.max_planner_work,
            )
            .map_err(|error| match error {
                bounded_byte_class_sequence::InspectionError::WorkLimit { needed, limit } => {
                    BuildError::PlannerWorkLimit { needed, limit }
                }
                bounded_byte_class_sequence::InspectionError::ArithmeticOverflow => {
                    BuildError::InternalInvariant(
                        "bounded byte-class sequence planner arithmetic overflow",
                    )
                }
            })?;
            bounded_byte_class_sequence_work = inspection.planner_work();
            if let bounded_byte_class_sequence::InspectionOutcome::Eligible(inspection) =
                inspection
            {
                let plan_storage_bytes = bounded_byte_class_sequence::Plan::storage_bytes();
                let charged_persistent_bytes = source_storage_bytes
                    .checked_add(capture_name_storage_bytes)
                    .and_then(|bytes| bytes.checked_add(plan_storage_bytes))
                    .ok_or(BuildError::PersistentBytesOverflow)?;
                if charged_persistent_bytes > self.limits.max_persistent_bytes {
                    return Err(BuildError::PersistentBytesLimit {
                        needed: charged_persistent_bytes,
                        limit: self.limits.max_persistent_bytes,
                    });
                }
                let plan = inspection
                    .build(SimdDispatchContext::capture())
                    .map_err(|error| match error {
                        fre_exact_alloc::CopyError::LayoutOverflow => {
                            BuildError::InternalInvariant(
                                "bounded byte-class sequence owner layout overflowed",
                            )
                        }
                        fre_exact_alloc::CopyError::AllocationFailed => {
                            BuildError::AllocationFailed {
                                structure: "bounded byte-class sequence owner",
                                additional: 1,
                            }
                        }
                    })?;
                return Ok(PortableRegex {
                    source,
                    capture_names,
                    line_total_grep_plan,
                    plan: PortablePlan::BoundedByteClassSequence(plan),
                    profile: profile.clone(),
                    limits: self.limits,
                    selection: self.selection,
                    report: BuildReport {
                        profile: profile.clone(),
                        admission,
                        syntax,
                        plan: PlanKind::BoundedByteClassSequence,
                        planner_work: bounded_byte_class_sequence_work,
                        lowering: None,
                        states: 0,
                        edges: 0,
                        plan_storage_bytes,
                        source_storage_bytes,
                        capture_name_storage_bytes,
                        charged_persistent_bytes,
                        persistent_byte_limit: self.limits.max_persistent_bytes,
                        captures_len,
                        static_captures_len,
                        minimum_match_bytes,
                        required_literal: None,
                        literal_class_run_literal: None,
                        forward_anchored: None,
                    },
                });
            }
        }
        finite_work = bounded_byte_class_sequence_work;
        let mut fallback_planner_work = finite_work;
        if self.selection == PlanSelection::Auto && !fixed_predicate_declined {
            let retained_facade_bytes = source_storage_bytes
                .checked_add(capture_name_storage_bytes)
                .ok_or(BuildError::PersistentBytesOverflow)?;
            let available_plan_bytes = self
                .limits
                .max_persistent_bytes
                .saturating_sub(retained_facade_bytes);
            let folded_owner_bytes = unicode_folded_literal::search_plan_owner_bytes();
            if let Some(available_trie_bytes) = available_plan_bytes.checked_sub(folded_owner_bytes)
            {
                let remaining_planner_work = self
                    .limits
                    .max_planner_work
                    .checked_sub(finite_work)
                    .ok_or(BuildError::InternalInvariant(
                        "incumbent planner work exceeded its enforced limit",
                    ))?;
                let planner_limit = usize::try_from(remaining_planner_work).unwrap_or(usize::MAX);
                let mut folded_limits = UnicodeFoldedLiteralBuildLimits::default();
                folded_limits.max_planner_work = folded_limits.max_planner_work.min(planner_limit);
                folded_limits.trie.max_work = folded_limits.trie.max_work.min(planner_limit);
                folded_limits.trie.max_persistent_bytes = folded_limits
                    .trie
                    .max_persistent_bytes
                    .min(available_trie_bytes);
                folded_limits.trie.max_peak_bytes =
                    folded_limits.trie.max_peak_bytes.min(available_trie_bytes);

                match unicode_folded_literal::build_search_plan(
                    SimdDispatchContext::capture(),
                    &rust.hir,
                    &self.profile,
                    folded_limits,
                ) {
                    Ok(UnicodeFoldedLiteralBuildAttempt::Admitted(plan)) => {
                        let build = plan.build_accounting();
                        let planner_work = charge_unicode_folded_planner_work(
                            finite_work,
                            build.planner.work,
                            self.limits.max_planner_work,
                        )?;
                        fallback_planner_work = planner_work;
                        if let Ok(plan) = fre_exact_alloc::try_box_preserve(plan) {
                            return Ok(PortableRegex {
                                source,
                                capture_names,
                                line_total_grep_plan,
                                plan: PortablePlan::UnicodeFoldedLiteral(plan),
                                profile: profile.clone(),
                                limits: self.limits,
                                selection: self.selection,
                                report: BuildReport {
                                    profile: profile.clone(),
                                    admission,
                                    syntax,
                                    plan: PlanKind::UnicodeFoldedLiteral,
                                    planner_work,
                                    lowering: None,
                                    states: build.trie.states,
                                    edges: build.trie.transitions,
                                    plan_storage_bytes: build.persistent_bytes,
                                    source_storage_bytes,
                                    capture_name_storage_bytes,
                                    charged_persistent_bytes: 0,
                                    persistent_byte_limit: 0,
                                    captures_len,
                                    static_captures_len,
                                    minimum_match_bytes,
                                    required_literal: None,
                                    literal_class_run_literal: None,
                                    forward_anchored: None,
                                }
                                .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
                            });
                        }
                    }
                    Ok(UnicodeFoldedLiteralBuildAttempt::Ineligible { planner, .. }) => {
                        fallback_planner_work = charge_unicode_folded_planner_work(
                            finite_work,
                            planner.work,
                            self.limits.max_planner_work,
                        )?;
                    }
                    Err(attempt_error) => {
                        let (error, completed_planner) = attempt_error.into_parts();
                        if !unicode_folded_literal_resource_refusal(&error) {
                            return Err(map_unicode_folded_literal_build_error(error));
                        }
                        fallback_planner_work = charge_unicode_folded_planner_work(
                            finite_work,
                            completed_planner,
                            self.limits.max_planner_work,
                        )?;
                    }
                }
            }
        }
        let lowered = fre_lower::lower_raw(
            &rust,
            OperationSemantics::CaptureFree,
            self.limits.lowering,
        )?;
        let lowering = lowered.stats();
        let raw = lowered.into_plan();
        let mandatory_cut = if matches!(minimum_match_bytes, Some(minimum) if minimum > 0)
            && !rust.hir.properties().look_set_prefix().contains(Look::Start)
        {
            try_build_k0_mandatory_cut(&raw, self.limits, fallback_planner_work)?
        } else {
            K0MandatoryCutBuild {
                plan: None,
                planner_work: fallback_planner_work,
                storage_bytes: 0,
            }
        };
        fallback_planner_work = mandatory_cut.planner_work;
        let mandatory_suffix = if matches!(minimum_match_bytes, Some(minimum) if minimum > 0)
            && !rust.hir.properties().look_set_prefix().contains(Look::Start)
        {
            try_build_k0_mandatory_suffix(&raw, self.limits, fallback_planner_work)?
        } else {
            K0MandatorySuffixBuild {
                plan: None,
                planner_work: fallback_planner_work,
                storage_bytes: 0,
            }
        };
        fallback_planner_work = mandatory_suffix.planner_work;
        let automaton = Automaton::from_raw(raw, self.limits.lowering.automata)
            .map_err(fre_lower::LowerError::from)?
            .with_line_terminator(self.profile.options.line_terminator);
        let automaton_stats = automaton.stats();
        let base_persistent_bytes = source_storage_bytes
            .checked_add(capture_name_storage_bytes)
            .and_then(|bytes| bytes.checked_add(automaton_stats.storage_bytes()))
            .ok_or(BuildError::PersistentBytesOverflow)?;
        let available_optional_bytes = self
            .limits
            .max_persistent_bytes
            .saturating_sub(base_persistent_bytes);
        let mut mandatory_suffix_plan = mandatory_suffix.plan;
        let mut mandatory_suffix_storage_bytes = mandatory_suffix_plan
            .as_ref()
            .map_or(0, |_| mandatory_suffix.storage_bytes);
        if mandatory_suffix_storage_bytes > available_optional_bytes {
            mandatory_suffix_plan = None;
            mandatory_suffix_storage_bytes = 0;
        }
        let mut mandatory_cut_plan = mandatory_cut.plan;
        let mut mandatory_cut_storage_bytes = mandatory_cut_plan
            .map_or(0, |_| mandatory_cut.storage_bytes);
        let cut_fits = mandatory_cut_storage_bytes
            <= available_optional_bytes.saturating_sub(mandatory_suffix_storage_bytes);
        if !cut_fits {
            mandatory_cut_plan = None;
            mandatory_cut_storage_bytes = 0;
        }
        let negative_prefilter = try_build_k0_negative_prefilter(
            &rust.hir,
            minimum_match_bytes,
            self.limits,
            fallback_planner_work,
            source_storage_bytes,
            capture_name_storage_bytes,
            automaton_stats
                .storage_bytes()
                .checked_add(mandatory_suffix_storage_bytes)
                .and_then(|bytes| bytes.checked_add(mandatory_cut_storage_bytes))
                .ok_or(BuildError::PersistentBytesOverflow)?,
        )?;
        fallback_planner_work = negative_prefilter.planner_work;
        let plan_storage_bytes = automaton_stats
            .storage_bytes()
            .checked_add(mandatory_suffix_storage_bytes)
            .and_then(|bytes| bytes.checked_add(mandatory_cut_storage_bytes))
            .and_then(|bytes| bytes.checked_add(negative_prefilter.storage_bytes))
            .ok_or(BuildError::PersistentBytesOverflow)?;
        Ok(PortableRegex {
            source,
            capture_names,
            line_total_grep_plan,
            plan: PortablePlan::K0(PortableK0Plan {
                automaton,
                mandatory_suffix: mandatory_suffix_plan,
                mandatory_cut: mandatory_cut_plan,
                negative_prefilter: negative_prefilter.plan,
            }),
            profile: profile.clone(),
            limits: self.limits,
            selection: self.selection,
            report: BuildReport {
                profile: profile.clone(),
                admission,
                syntax,
                plan: PlanKind::K0,
                planner_work: fallback_planner_work,
                lowering: Some(lowering),
                states: automaton_stats.states(),
                edges: automaton_stats.edges(),
                plan_storage_bytes,
                source_storage_bytes,
                capture_name_storage_bytes,
                charged_persistent_bytes: 0,
                persistent_byte_limit: 0,
                captures_len,
                static_captures_len,
                minimum_match_bytes,
                required_literal: None,
                literal_class_run_literal: None,
                forward_anchored: None,
            }
            .enforce_persistent_limit(self.limits.max_persistent_bytes)?,
        })
    }
}

/// Immutable, shareable matcher for the certified capture-free byte subset.
pub struct PortableRegex {
    source: Box<str>,
    capture_names: Box<[Option<Box<str>>]>,
    line_total_grep_plan: Option<line_total_grep::Plan>,
    plan: PortablePlan,
    profile: CompatibilityProfile,
    limits: BuildLimits,
    selection: PlanSelection,
    report: BuildReport,
}

/// An iterator over capture names in opening-parenthesis index order.
///
/// The first item is always `None` for the implicit whole-match slot. Unnamed
/// explicit groups also yield `None`.
#[derive(Clone, Debug)]
pub struct PortableCaptureNames<'r> {
    names: core::slice::Iter<'r, Option<Box<str>>>,
}

impl<'r> Iterator for PortableCaptureNames<'r> {
    type Item = Option<&'r str>;

    fn next(&mut self) -> Option<Self::Item> {
        self.names.next().map(Option::as_deref)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.names.size_hint()
    }

    fn count(self) -> usize {
        self.names.len()
    }
}

impl ExactSizeIterator for PortableCaptureNames<'_> {}
impl core::iter::FusedIterator for PortableCaptureNames<'_> {}

/// Reusable byte offsets for every capture slot in a portable regex.
///
/// A newly allocated buffer contains no matched locations. Its cardinality is
/// nevertheless fixed by the regex and includes the implicit whole-match slot
/// at index zero. This is the reusable-buffer half of the pinned Rust bytes
/// `CaptureLocations` contract; [`PortableRegex::captures_read`] populates its
/// admitted capture-free group-zero slice.
#[derive(Clone, Debug)]
pub struct PortableCaptureLocations {
    slots: Box<[Option<(usize, usize)>]>,
}

/// Compatibility alias mirroring the pinned bytes API's legacy `Locations`.
#[doc(hidden)]
pub type PortableLocations = PortableCaptureLocations;

#[allow(
    clippy::len_without_is_empty,
    reason = "the pinned buffer always has the implicit whole-match slot and exposes len without is_empty"
)]
impl PortableCaptureLocations {
    /// Return the matched byte offsets for capture slot `index`.
    ///
    /// A fresh buffer and an unmatched slot both return `None`. An index that
    /// is not a capture slot also returns `None`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<(usize, usize)> {
        self.slots.get(index).copied().flatten()
    }

    /// Return the fixed number of capture slots represented by this buffer.
    ///
    /// This is always at least one because slot zero is the whole match.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.slots.len()
    }

    /// Compatibility alias mirroring the pinned bytes API's legacy `pos`.
    #[doc(hidden)]
    #[must_use]
    pub fn pos(&self, index: usize) -> Option<(usize, usize)> {
        self.get(index)
    }
}

/// Failure while populating reusable portable capture locations.
///
/// The portable whole-match executors can populate group zero exactly for a
/// capture-free pattern. Explicit subgroup preservation remains a separate
/// capability and is refused instead of publishing incomplete locations.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortableCapturesReadError {
    /// The caller supplied a location buffer created for another regex.
    LocationCount {
        /// Capture slots required by this regex.
        expected: usize,
        /// Capture slots present in the supplied buffer.
        actual: usize,
    },
    /// The regex contains explicit groups whose offsets are not preserved by
    /// the selected portable whole-match executor.
    ExplicitCapturesUnsupported {
        /// Number of explicit groups, excluding the whole-match slot.
        captures: usize,
    },
    /// The selected whole-match executor refused the bounded search.
    Search(SearchError),
}

impl fmt::Display for PortableCapturesReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocationCount { expected, actual } => write!(
                formatter,
                "capture location count mismatch: expected {expected}, got {actual}"
            ),
            Self::ExplicitCapturesUnsupported { captures } => write!(
                formatter,
                "portable capture reading does not yet preserve {captures} explicit capture groups"
            ),
            Self::Search(error) => write!(formatter, "portable capture search failed: {error}"),
        }
    }
}

impl std::error::Error for PortableCapturesReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Search(error) => Some(error),
            Self::LocationCount { .. } | Self::ExplicitCapturesUnsupported { .. } => None,
        }
    }
}

impl From<SearchError> for PortableCapturesReadError {
    fn from(value: SearchError) -> Self {
        Self::Search(value)
    }
}

impl Clone for PortableRegex {
    /// Rebuild an equivalent immutable matcher under its original profile,
    /// limits, and planner-selection contract.
    ///
    /// Some certified native plans deliberately do not expose `Clone`, so the
    /// facade replays its already-admitted deterministic construction instead
    /// of weakening those plan-level ownership contracts.
    fn clone(&self) -> Self {
        let profile = match &self.profile {
            CompatibilityProfile::RustBytes(profile) => profile.clone(),
            CompatibilityProfile::RustText(_) | CompatibilityProfile::Re2(_) => {
                panic!("portable byte regex retained a non-byte profile")
            }
        };
        PortableBuilder::new(self.as_str())
            .set_constituent_profile(profile)
            .limits(self.limits)
            .plan_selection(self.selection)
            .build()
            .unwrap_or_else(|error| {
                panic!("previously admitted portable regex could not be cloned: {error}")
            })
    }
}

impl fmt::Display for PortableRegex {
    /// Show the original regular expression source.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for PortableRegex {
    /// Show the original source under the facade's honest public type name.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PortableRegex")
            .field(&self.as_str())
            .finish()
    }
}

impl core::str::FromStr for PortableRegex {
    type Err = BuildError;

    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        Self::new(pattern)
    }
}

impl TryFrom<&str> for PortableRegex {
    type Error = BuildError;

    fn try_from(pattern: &str) -> Result<Self, Self::Error> {
        Self::new(pattern)
    }
}

impl TryFrom<String> for PortableRegex {
    type Error = BuildError;

    fn try_from(pattern: String) -> Result<Self, Self::Error> {
        Self::new(pattern)
    }
}

struct PortableK0Plan {
    automaton: Automaton,
    mandatory_suffix: Option<K0MandatorySuffixPlan>,
    mandatory_cut: Option<K0MandatoryCutPlan>,
    negative_prefilter: Option<Box<K0NegativePrefilterPlan>>,
}

enum PortablePlan {
    ExactLiteral(LiteralPlan),
    PackedLiteralSet(PackedLiteralSetPlan),
    LiteralSetDfa(LiteralSetPlan),
    RequiredLiteral(RequiredLiteralPlan),
    DispatchedRequiredLiteral(DispatchedRequiredLiteralPlan),
    BoundedRequiredLiteral(BoundedRequiredLiteralPlan),
    DispatchedBoundedRequiredLiteral(DispatchedBoundedRequiredLiteralPlan),
    LiteralClassRunLiteral(LiteralClassRunLiteralPlan),
    LiteralClassRunSearch(LiteralClassRunSearchPlan),
    PureByteClassRepeat(pure_byte_class_repeat::Plan),
    ForwardAnchored(ForwardAnchoredPlan),
    DispatchedForwardAnchored(DispatchedForwardAnchoredPlan),
    ForwardEndFixed(AbsoluteEndFixedPlan),
    K0(PortableK0Plan),
    UnicodeFoldedLiteral(Box<unicode_folded_literal::UnicodeFoldedLiteralSearchPlan>),
    UnicodeWordRun(unicode_word_run::Plan),
    AsciiWordRun(unicode_word_run::AsciiPlan),
    BoundedWordClass(bounded_word_class::Plan),
    // Append new runtime classes so existing implicit discriminants, including
    // K0's, remain unchanged for code-layout containment.
    BoundedByteClassRepeat(bounded_byte_class_repeat::Plan),
    FixedPredicateWord64(Box<FixedPredicateWord64Plan>),
    BoundedByteClassSequence(bounded_byte_class_sequence::Plan),
    GuardedLiteralSet(guarded_literal_set::Plan),
}

impl PortablePlan {
    const fn runtime_implementation_id(&self) -> &'static str {
        match self {
            Self::ExactLiteral(_) => "exact-literal",
            Self::PackedLiteralSet(_) => "packed-literal-set",
            Self::LiteralSetDfa(_) => "literal-set-dfa",
            Self::RequiredLiteral(required) => required.plan_id(),
            Self::DispatchedRequiredLiteral(required) => required.plan_id(),
            Self::BoundedRequiredLiteral(required) => required.plan_id(),
            Self::DispatchedBoundedRequiredLiteral(required) => required.plan_id(),
            Self::LiteralClassRunLiteral(_) => fre_kernels::LITERAL_CLASS_RUN_LITERAL_PLAN_ID,
            Self::LiteralClassRunSearch(plan) => plan.plan_id(),
            Self::PureByteClassRepeat(_) => pure_byte_class_repeat::PLAN_ID,
            Self::BoundedByteClassRepeat(_) => bounded_byte_class_repeat::PLAN_ID,
            Self::ForwardAnchored(forward) => forward.plan_id(),
            Self::DispatchedForwardAnchored(forward) => forward.plan_id(),
            Self::ForwardEndFixed(fixed) => fixed.plan_id(),
            Self::K0(_) => "k0",
            Self::UnicodeFoldedLiteral(plan) => plan.plan_id(),
            Self::UnicodeWordRun(plan) => plan.plan_id(),
            Self::AsciiWordRun(_) => unicode_word_run::ASCII_PLAN_ID,
            Self::BoundedWordClass(plan) => plan.plan_id(),
            Self::FixedPredicateWord64(_) => FIXED_PREDICATE_WORD64_SEARCH_PLAN_ID,
            Self::BoundedByteClassSequence(_) => bounded_byte_class_sequence::PLAN_ID,
            Self::GuardedLiteralSet(_) => guarded_literal_set::PLAN_ID,
        }
    }
}

impl PortableRegex {
    /// Construct with pinned Rust-bytes defaults and default resource limits.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] under the same conditions as
    /// [`PortableBuilder::build`].
    pub fn new(pattern: impl Into<String>) -> Result<Self, BuildError> {
        PortableBuilder::new(pattern).build()
    }

    /// Return the original pattern source exactly as supplied at construction.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Iterate over every capture slot's optional name in capture-index order.
    ///
    /// This metadata is retained before capture-erasing execution planning,
    /// so it remains identical across every portable plan family.
    #[must_use]
    pub fn capture_names(&self) -> PortableCaptureNames<'_> {
        PortableCaptureNames {
            names: self.capture_names.iter(),
        }
    }

    /// Return the number of capture slots, including the implicit unnamed
    /// slot for the overall match.
    ///
    /// This metadata is preserved before capture-erasing execution planning,
    /// so it is identical for every selected portable plan family.
    #[must_use]
    pub const fn captures_len(&self) -> usize {
        self.report.captures_len
    }

    /// Return the number of capture slots that participate in every possible
    /// match, including the implicit whole-match slot.
    ///
    /// `None` means that capture participation cardinality can vary across
    /// alternatives or repetitions. This is construction metadata and does
    /// not execute a search.
    #[must_use]
    pub const fn static_captures_len(&self) -> Option<usize> {
        self.report.static_captures_len
    }

    /// Allocate fresh reusable locations for every capture slot.
    ///
    /// The returned buffer has the same fixed cardinality as
    /// [`Self::captures_len`] and initially contains no matched offsets.
    #[must_use]
    pub fn capture_locations(&self) -> PortableCaptureLocations {
        PortableCaptureLocations {
            slots: vec![None; self.captures_len()].into_boxed_slice(),
        }
    }

    /// Compatibility alias mirroring the pinned bytes API's legacy method.
    #[doc(hidden)]
    #[must_use]
    pub fn locations(&self) -> PortableCaptureLocations {
        self.capture_locations()
    }

    /// Search and populate reusable locations for a capture-free regex.
    ///
    /// This is the admitted group-zero slice of the pinned Rust bytes
    /// `captures_read` contract. The buffer is cleared before every attempt,
    /// including typed refusals, and a successful match stores its offsets in
    /// slot zero. Patterns with explicit capture groups are refused until the
    /// portable facade has a capture-preserving executor for their offsets.
    ///
    /// # Errors
    ///
    /// Returns [`PortableCapturesReadError`] if `locations` belongs to a regex
    /// with different capture cardinality, explicit subgroups require an
    /// unavailable capability, or the selected search exceeds its limits.
    pub fn captures_read<'h>(
        &self,
        locations: &mut PortableCaptureLocations,
        haystack: &'h [u8],
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), PortableCapturesReadError> {
        locations.slots.fill(None);
        if locations.len() != self.captures_len() {
            return Err(PortableCapturesReadError::LocationCount {
                expected: self.captures_len(),
                actual: locations.len(),
            });
        }
        let explicit_captures = self.captures_len().saturating_sub(1);
        if explicit_captures != 0 {
            return Err(PortableCapturesReadError::ExplicitCapturesUnsupported {
                captures: explicit_captures,
            });
        }
        let (matched, accounting) = self.find_borrowed(haystack, limits)?;
        if let Some(matched) = matched {
            locations.slots[0] = Some((matched.start(), matched.end()));
        }
        Ok((matched, accounting))
    }

    /// The immutable compatibility profile used during parsing.
    #[must_use]
    pub const fn profile(&self) -> &CompatibilityProfile {
        &self.profile
    }

    /// Construction accounting and admission status.
    #[must_use]
    pub const fn build_report(&self) -> &BuildReport {
        &self.report
    }

    /// Maximum length among the construction-proved mandatory literals
    /// retained for reusable unlimited K0 value searches.
    ///
    /// `None` means either another runtime family was selected or the
    /// optional proof, resource, and regret gates declined the sidecar.
    /// Literals prove negative results directly. An exact graph-proved suffix
    /// may additionally propose endpoints, but every positive result is still
    /// authenticated by the original K0 reverse machine.
    #[must_use]
    pub fn k0_negative_prefilter_needle_bytes(&self) -> Option<usize> {
        match &self.plan {
            PortablePlan::K0(k0) => {
                let suffix = k0
                    .mandatory_suffix
                    .as_ref()
                    .map(|suffix| suffix.needle().len());
                let conjunctive = k0
                    .negative_prefilter
                    .as_deref()
                    .and_then(K0NegativePrefilterPlan::primary_needle_bytes);
                match (suffix, conjunctive) {
                    (Some(left), Some(right)) => Some(left.max(right)),
                    (Some(length), None) | (None, Some(length)) => Some(length),
                    (None, None) => None,
                }
            }
            _ => None,
        }
    }

    /// Number of independent mandatory literal sidecars retained for K0.
    ///
    /// This includes the exact graph-proved suffix, when present, plus every
    /// conjunctive negative-prefilter literal.
    #[must_use]
    pub fn k0_negative_prefilter_needle_count(&self) -> usize {
        match &self.plan {
            PortablePlan::K0(k0) => {
                usize::from(k0.mandatory_suffix.is_some())
                    + k0.negative_prefilter
                        .as_deref()
                        .map_or(0, |plan| plan.literals.len())
            }
            _ => 0,
        }
    }

    /// Complete admitted-only construction census for the Unicode
    /// folded-literal plan.
    ///
    /// The census is retained with that optional plan instead of enlarging
    /// every portable matcher and aggregate owner. Other plan families return
    /// `None`.
    #[must_use]
    pub fn unicode_folded_literal_build_accounting(
        &self,
    ) -> Option<UnicodeFoldedLiteralSearchBuildAccounting> {
        match &self.plan {
            PortablePlan::UnicodeFoldedLiteral(plan) => Some(plan.build_accounting()),
            _ => None,
        }
    }

    /// Derive the folded plan's complete source-independent search envelope
    /// without touching a haystack.
    ///
    /// Other plan families return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns a checked arithmetic failure if `input_bytes` cannot be
    /// represented by the retained folded plan's envelope.
    pub fn unicode_folded_literal_search_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<
        Option<fre_kernels::FoldedLiteralTrieScanUpperBounds>,
        fre_kernels::FoldedLiteralTrieScanError,
    > {
        match &self.plan {
            PortablePlan::UnicodeFoldedLiteral(plan) => {
                plan.scan_upper_bounds(input_bytes).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Stable identity of the selected runtime implementation.
    ///
    /// This is intentionally obtained from the stored plan rather than
    /// reconstructed from [`PlanKind`]. For the required-literal and
    /// forward-anchored plans, it is the same strategy identity stored in
    /// their operation cache keys.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        self.plan.runtime_implementation_id()
    }

    /// Prepare allocation-free repeated searches over this immutable matcher.
    ///
    /// K0 allocates and fully initializes one fixed-capacity workspace here.
    /// Eligible byte graphs with a statically known positive minimum length
    /// retain a bounded forward endpoint cache plus a separate reverse cache
    /// for exact full-span recovery. Assertion-free nullable graphs retain a
    /// forward cache whose initial pending match proves every selected span
    /// starts at the requested window; they need no reverse cache.
    /// Assertion-free graphs use direct byte rows; assertion-bearing graphs key
    /// transitions by the exact enabled-assertion mask at each boundary.
    /// Contextual nullable, statically empty, or resource-refused graphs keep
    /// the ordinary Pike workspace. Cache selection is source-free and occurs
    /// before allocation; every subsequent call reuses the selected storage
    /// without growing. Native plans retain their existing operation-specific
    /// dispatch and need no session storage.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if K0 workspace construction exceeds the
    /// supplied setup-work or scratch limit, or if allocation fails. Native
    /// specialized plans ignore these limits because they construct no K0
    /// workspace.
    pub fn search_session(
        &self,
        limits: SearchSessionLimits,
    ) -> Result<PortableSearchSession<'_>, SearchError> {
        self.search_session_mode(limits, true)
    }

    /// Prepare a smaller reusable session for existence and endpoint
    /// projections.
    ///
    /// Eligible K0 graphs retain only the ordered forward cache.
    /// Assertion-free nullable full-span methods can reuse that cache because
    /// their selected start is known; other full-span calls remain correct but
    /// use Pike. Callers that need nonnullable `find`/iteration acceleration
    /// should use [`Self::search_session`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same conditions as
    /// [`Self::search_session`].
    pub fn endpoint_search_session(
        &self,
        limits: SearchSessionLimits,
    ) -> Result<PortableSearchSession<'_>, SearchError> {
        self.search_session_mode(limits, false)
    }

    fn search_session_mode(
        &self,
        limits: SearchSessionLimits,
        bidirectional: bool,
    ) -> Result<PortableSearchSession<'_>, SearchError> {
        let plan = match &self.plan {
            PortablePlan::K0(k0) => {
                let workspace_limits = SearchSessionLimits {
                    max_setup_work: limits.max_setup_work,
                    max_scratch_bytes: limits.max_scratch_bytes,
                };
                let positive =
                    matches!(self.report.minimum_match_bytes, Some(minimum) if minimum > 0);
                let assertion_free_nullable = self.report.minimum_match_bytes == Some(0)
                    && !k0.automaton.stats().has_assertions();
                let endpoint_eligible = positive || assertion_free_nullable;
                // Select the optional cache from its source-free layout before
                // allocating. Once accelerated construction begins, propagate
                // every failure so a partial attempt cannot disappear from
                // successful setup accounting.
                let session = K0SearchSession::new_selected(
                    &k0.automaton,
                    workspace_limits,
                    endpoint_eligible,
                    bidirectional && positive,
                )?;
                PortableSearchSessionPlan::K0 {
                    session,
                    mandatory_suffix: k0.mandatory_suffix.as_ref(),
                    mandatory_cut: k0.mandatory_cut.as_ref(),
                    negative_prefilter: k0.negative_prefilter.as_deref(),
                    mandatory_suffix_exists_state: K0NegativePrefilterState::default(),
                    mandatory_suffix_span_state: K0NegativePrefilterState::default(),
                    negative_prefilter_exists_state: K0NegativePrefilterState::default(),
                    negative_prefilter_span_state: K0NegativePrefilterState::default(),
                }
            }
            _ => PortableSearchSessionPlan::Native(self),
        };
        Ok(PortableSearchSession { plan })
    }

    /// Whether a selected match exists.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Whether a selected match exists without constructing facade diagnostic
    /// accounting on the success path.
    ///
    /// This is the value-only counterpart to [`Self::is_match`]. It preserves
    /// the same selected plan, checked execution limits and typed failures,
    /// while keeping callers that only consume the boolean outside the
    /// [`SearchAccounting`] projection boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn is_match_value(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_window_value(haystack, SearchWindow::full(haystack), limits)
    }

    /// Whether a selected match exists at or after `start`.
    ///
    /// Assertions inspect the complete original haystack. Unlike the pinned
    /// Rust API, an out-of-bounds `start` is returned as a typed error instead
    /// of panicking.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn is_match_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Whether a selected match exists at or after `start` without
    /// constructing facade diagnostic accounting on the success path.
    ///
    /// Assertions inspect the complete original haystack. Range validation,
    /// execution limits and typed failures are identical to
    /// [`Self::is_match_at`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn is_match_value_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_window_value(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Whether a selected match exists wholly inside a search range.
    ///
    /// Assertions retain original-haystack context. K0 executes its typed
    /// existence contract directly instead of materializing a match span.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window or a resource refusal.
    #[allow(
        clippy::too_many_lines,
        reason = "each authenticated native owner projects the same operation-specific accounting without erasing its concrete type"
    )]
    pub fn is_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    literal.find_window(haystack, literal_window, literal_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::ExactLiteral(accounting),
                ))
            }
            PortablePlan::PackedLiteralSet(literal_set) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = literal_set.find_window(
                    haystack,
                    literal_window,
                    packed_literal_set_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::PackedLiteralSet(accounting),
                ))
            }
            PortablePlan::GuardedLiteralSet(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::GuardedLiteralSet(accounting),
                ))
            }
            PortablePlan::LiteralSetDfa(literal_set) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = literal_set.find_window(
                    haystack,
                    literal_window,
                    literal_set_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::LiteralSetDfa(accounting),
                ))
            }
            PortablePlan::RequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::DispatchedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::BoundedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::DispatchedBoundedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::LiteralClassRunLiteral(plan) => {
                let (matched, accounting) = plan.shortest_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::LiteralClassRunLiteral(accounting),
                ))
            }
            PortablePlan::LiteralClassRunSearch(plan) => {
                let (matched, accounting) = plan.shortest_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::LiteralClassRunLiteral(accounting),
                ))
            }
            PortablePlan::PureByteClassRepeat(plan) => {
                let (matched, accounting) = plan.is_match_window(haystack, window, limits)?;
                Ok((matched, SearchAccounting::PureByteClassRepeat(accounting)))
            }
            PortablePlan::BoundedByteClassRepeat(plan) => {
                let (matched, accounting) = plan.is_match_window(haystack, window, limits)?;
                Ok((matched, SearchAccounting::PureByteClassRepeat(accounting)))
            }
            PortablePlan::BoundedByteClassSequence(plan) => {
                let (matched, accounting) = plan
                    .is_match_window(haystack, window, limits)
                    .map_err(SearchError::BoundedByteClassSequence)?;
                Ok((
                    matched,
                    SearchAccounting::BoundedByteClassSequence(accounting),
                ))
            }
            PortablePlan::ForwardAnchored(forward) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = forward.find_window(
                    haystack,
                    literal_window,
                    forward_anchored_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::DispatchedForwardAnchored(forward) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = forward.find_window(
                    haystack,
                    literal_window,
                    forward_anchored_limits(limits),
                )?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    fixed.find_window(haystack, literal_window, forward_anchored_limits(limits))?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::UnicodeFoldedLiteral(plan) => {
                let (matched, accounting) = plan.is_match_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    unicode_folded_literal_limits(limits),
                )?;
                Ok((
                    matched,
                    SearchAccounting::UnicodeFoldedLiteral(accounting.actual),
                ))
            }
            PortablePlan::K0(k0) => {
                let report = k0
                    .automaton
                    .prepare::<Exists>()
                    .search_window(haystack, window, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
            PortablePlan::AsciiWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
            PortablePlan::BoundedWordClass(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched.is_some(),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
            PortablePlan::FixedPredicateWord64(plan) => {
                let (matched, accounting) = plan.is_match_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    fixed_predicate_word64_search_limits(limits),
                )?;
                Ok((matched, SearchAccounting::FixedPredicateWord64(accounting)))
            }
        }
    }

    /// Whether a selected match exists wholly inside a search range without
    /// constructing facade diagnostic accounting on the success path.
    ///
    /// Assertions retain original-haystack context and every plan executes
    /// the same existence operation as [`Self::is_match_window`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window or a resource refusal.
    #[allow(
        clippy::too_many_lines,
        reason = "each native owner retains its direct value-only existence projection"
    )]
    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => literal
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::PackedLiteralSet(literal_set) => literal_set
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    packed_literal_set_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::GuardedLiteralSet(plan) => plan
                .find_window_value(haystack, window, limits)
                .map(|matched| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::LiteralSetDfa(literal_set) => literal_set
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_set_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::RequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::DispatchedRequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::BoundedRequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::DispatchedBoundedRequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::LiteralClassRunLiteral(plan) => plan
                .shortest_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::LiteralClassRunSearch(plan) => plan
                .is_match_window_value(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )
                .map_err(SearchError::from),
            PortablePlan::PureByteClassRepeat(plan) => plan
                .is_match_window_value(haystack, window, limits)
                .map_err(SearchError::from),
            PortablePlan::BoundedByteClassRepeat(plan) => plan
                .is_match_window(haystack, window, limits)
                .map(|(matched, _)| matched)
                .map_err(SearchError::from),
            PortablePlan::BoundedByteClassSequence(plan) => plan
                .is_match_window_value(haystack, window, limits)
                .map_err(SearchError::BoundedByteClassSequence),
            PortablePlan::ForwardAnchored(forward) => forward
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    forward_anchored_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::DispatchedForwardAnchored(forward) => forward
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    forward_anchored_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::ForwardEndFixed(fixed) => fixed
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    forward_anchored_limits(limits),
                )
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::UnicodeFoldedLiteral(plan) => plan
                .is_match_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    unicode_folded_literal_limits(limits),
                )
                .map(|(matched, _)| matched)
                .map_err(SearchError::from),
            PortablePlan::K0(k0) => k0
                .automaton
                .prepare::<Exists>()
                .search_window(haystack, window, limits)
                .map(fre_automata::SearchReport::into_output)
                .map_err(SearchError::from),
            PortablePlan::UnicodeWordRun(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::AsciiWordRun(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::BoundedWordClass(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched.is_some())
                .map_err(SearchError::from),
            PortablePlan::FixedPredicateWord64(plan) => plan
                .is_match_window_value(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    fixed_predicate_word64_search_limits(limits),
                )
                .map_err(SearchError::from),
        }
    }

    /// Return the end offset at the first boundary where a match is detected.
    ///
    /// Like the pinned Rust bytes API, this may be shorter than the end of the
    /// leftmost-first match returned by [`Self::find`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn shortest_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_match_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return the first detected match end at or after `start`.
    ///
    /// Assertions inspect the complete original haystack and the returned
    /// offset remains relative to it. Unlike the pinned Rust API, an
    /// out-of-bounds `start` is returned as a typed error instead of panicking.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn shortest_match_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_match_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each authenticated native owner projects the same operation-specific accounting without erasing its concrete type"
    )]
    fn shortest_match_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    literal.find_window(haystack, literal_window, literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ExactLiteral(accounting),
                ))
            }
            PortablePlan::PackedLiteralSet(literal_set) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = literal_set.find_window(
                    haystack,
                    literal_window,
                    packed_literal_set_limits(limits),
                )?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::PackedLiteralSet(accounting),
                ))
            }
            PortablePlan::GuardedLiteralSet(plan) => {
                let (end, accounting) = plan.shortest_window(haystack, window, limits)?;
                Ok((end, SearchAccounting::GuardedLiteralSet(accounting)))
            }
            PortablePlan::LiteralSetDfa(literal_set) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = literal_set.find_window(
                    haystack,
                    literal_window,
                    literal_set_limits(limits),
                )?;
                let end = if self.report.minimum_match_bytes == Some(0) {
                    Some(window.start())
                } else {
                    matched.map(|(_, end)| end)
                };
                Ok((end, SearchAccounting::LiteralSetDfa(accounting)))
            }
            PortablePlan::RequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::DispatchedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::BoundedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::DispatchedBoundedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::LiteralClassRunLiteral(plan) => {
                let (end, accounting) = plan.shortest_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )?;
                Ok((end, SearchAccounting::LiteralClassRunLiteral(accounting)))
            }
            PortablePlan::LiteralClassRunSearch(plan) => {
                let (end, accounting) = plan.shortest_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )?;
                Ok((end, SearchAccounting::LiteralClassRunLiteral(accounting)))
            }
            PortablePlan::PureByteClassRepeat(plan) => {
                let (end, accounting) = plan.earliest_end_window(haystack, window, limits)?;
                Ok((end, SearchAccounting::PureByteClassRepeat(accounting)))
            }
            PortablePlan::BoundedByteClassRepeat(plan) => {
                let (end, accounting) = plan.earliest_end_window(haystack, window, limits)?;
                Ok((end, SearchAccounting::PureByteClassRepeat(accounting)))
            }
            PortablePlan::BoundedByteClassSequence(plan) => {
                let (end, accounting) = plan
                    .earliest_end_window(haystack, window, limits)
                    .map_err(SearchError::BoundedByteClassSequence)?;
                Ok((
                    end,
                    SearchAccounting::BoundedByteClassSequence(accounting),
                ))
            }
            PortablePlan::ForwardAnchored(forward) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = forward.find_window(
                    haystack,
                    literal_window,
                    forward_anchored_limits(limits),
                )?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::DispatchedForwardAnchored(forward) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = forward.find_window(
                    haystack,
                    literal_window,
                    forward_anchored_limits(limits),
                )?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    fixed.find_window(haystack, literal_window, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::UnicodeFoldedLiteral(plan) => {
                let (end, accounting) = plan.shortest_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    unicode_folded_literal_limits(limits),
                )?;
                Ok((
                    end,
                    SearchAccounting::UnicodeFoldedLiteral(accounting.actual),
                ))
            }
            PortablePlan::K0(k0) => {
                let report = k0
                    .automaton
                    .prepare::<EarliestEnd>()
                    .search_window(haystack, window, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched.map(Match::end),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
            PortablePlan::AsciiWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched.map(Match::end),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
            PortablePlan::BoundedWordClass(plan) => {
                let (end, accounting) = plan.shortest_window(haystack, window, limits)?;
                Ok((end, SearchAccounting::UnicodeWordRun(accounting)))
            }
            PortablePlan::FixedPredicateWord64(plan) => {
                let (end, accounting) = plan.earliest_end_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    fixed_predicate_word64_search_limits(limits),
                )?;
                Ok((end, SearchAccounting::FixedPredicateWord64(accounting)))
            }
        }
    }

    /// Return the selected match end without materializing its start.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    #[allow(
        clippy::too_many_lines,
        reason = "each native owner projects its selected endpoint and concrete accounting explicitly"
    )]
    pub fn selected_end(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let (matched, accounting) = literal.find(haystack, literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ExactLiteral(accounting),
                ))
            }
            PortablePlan::PackedLiteralSet(literal_set) => {
                let (matched, accounting) =
                    literal_set.find(haystack, packed_literal_set_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::PackedLiteralSet(accounting),
                ))
            }
            PortablePlan::GuardedLiteralSet(plan) => {
                let (end, accounting) = plan.shortest_window(
                    haystack,
                    SearchWindow::full(haystack),
                    limits,
                )?;
                Ok((end, SearchAccounting::GuardedLiteralSet(accounting)))
            }
            PortablePlan::LiteralSetDfa(literal_set) => {
                let (matched, accounting) =
                    literal_set.find(haystack, literal_set_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::LiteralSetDfa(accounting),
                ))
            }
            PortablePlan::RequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find(haystack, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::DispatchedRequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find(haystack, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::BoundedRequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find(haystack, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::DispatchedBoundedRequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find(haystack, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::LiteralClassRunLiteral(plan) => {
                let (matched, accounting) =
                    plan.find(haystack, literal_class_run_literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::LiteralClassRunLiteral(accounting),
                ))
            }
            PortablePlan::LiteralClassRunSearch(plan) => {
                let (matched, accounting) =
                    plan.find(haystack, literal_class_run_literal_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::LiteralClassRunLiteral(accounting),
                ))
            }
            PortablePlan::PureByteClassRepeat(plan) => {
                let (end, accounting) =
                    plan.selected_end_window(haystack, SearchWindow::full(haystack), limits)?;
                Ok((end, SearchAccounting::PureByteClassRepeat(accounting)))
            }
            PortablePlan::BoundedByteClassRepeat(plan) => {
                let (end, accounting) =
                    plan.selected_end_window(haystack, SearchWindow::full(haystack), limits)?;
                Ok((end, SearchAccounting::PureByteClassRepeat(accounting)))
            }
            PortablePlan::BoundedByteClassSequence(plan) => {
                let (end, accounting) = plan
                    .selected_end_window(haystack, SearchWindow::full(haystack), limits)
                    .map_err(SearchError::BoundedByteClassSequence)?;
                Ok((
                    end,
                    SearchAccounting::BoundedByteClassSequence(accounting),
                ))
            }
            PortablePlan::ForwardAnchored(forward) => {
                let (matched, accounting) =
                    forward.find(haystack, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::DispatchedForwardAnchored(forward) => {
                let (matched, accounting) =
                    forward.find(haystack, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let (matched, accounting) =
                    fixed.find(haystack, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(_, end)| end),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::UnicodeFoldedLiteral(plan) => {
                let (matched, accounting) = plan.find_window(
                    haystack,
                    LiteralWindow::full(haystack),
                    unicode_folded_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|candidate| candidate.end()),
                    SearchAccounting::UnicodeFoldedLiteral(accounting.actual),
                ))
            }
            PortablePlan::K0(k0) => {
                let report = k0
                    .automaton
                    .prepare::<SelectedEnd>()
                    .search(haystack, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::full(haystack), limits)?;
                Ok((
                    matched.map(Match::end),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
            PortablePlan::AsciiWordRun(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::full(haystack), limits)?;
                Ok((
                    matched.map(Match::end),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
            PortablePlan::BoundedWordClass(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::full(haystack), limits)?;
                Ok((
                    matched.map(Match::end),
                    SearchAccounting::UnicodeWordRun(accounting),
                ))
            }
            PortablePlan::FixedPredicateWord64(plan) => {
                let (end, accounting) =
                    plan.selected_end(haystack, fixed_predicate_word64_search_limits(limits))?;
                Ok((end, SearchAccounting::FixedPredicateWord64(accounting)))
            }
        }
    }

    /// Return the profile-selected leftmost-first match.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return only the profile-selected leftmost-first match.
    ///
    /// This is the value-only counterpart to [`Self::find`]. It preserves the
    /// same selected plan, checked execution limits and typed failures. K0
    /// stays outside the facade [`SearchAccounting`] projection boundary;
    /// native owners retain their existing concrete search implementations.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn find_value(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.find_window_value(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return the profile-selected leftmost-first match while retaining the
    /// exact original haystack.
    ///
    /// This is the borrowed-byte companion to [`Self::find`]. It preserves the
    /// same selected span and execution accounting, while [`ByteMatch`]
    /// supplies the pinned Rust bytes match accessors and conversions.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if scratch/work limits refuse the operation.
    pub fn find_borrowed<'h>(
        &self,
        haystack: &'h [u8],
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find(haystack, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), accounting))
    }

    /// Iterate over every non-overlapping match with Rust bytes empty-match
    /// progress and original-haystack assertion context.
    ///
    /// K0 prepares one reusable workspace before iteration. Every subsequent
    /// search is allocation-free for K0, while native plans retain their
    /// selected dispatch. Iterator items are errors so a resource refusal is
    /// never silently treated as exhaustion.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] if reusable K0 workspace construction exceeds
    /// `limits.session`. Per-search and whole-iterator failures are yielded as
    /// [`PortableFindIterError`] items.
    pub fn find_iter<'r, 'h>(
        &'r self,
        haystack: &'h [u8],
        limits: PortableFindIterLimits,
    ) -> Result<PortableMatches<'r, 'h>, SearchError> {
        self.find_iter_with_progress(haystack, limits, EmptyMatchProgress::Byte)
    }

    pub(crate) fn find_iter_utf8<'r, 'h>(
        &'r self,
        haystack: &'h str,
        limits: PortableFindIterLimits,
    ) -> Result<PortableMatches<'r, 'h>, SearchError> {
        self.find_iter_with_progress(haystack.as_bytes(), limits, EmptyMatchProgress::Utf8Scalar)
    }

    fn find_iter_with_progress<'r, 'h>(
        &'r self,
        haystack: &'h [u8],
        limits: PortableFindIterLimits,
        empty_match_progress: EmptyMatchProgress,
    ) -> Result<PortableMatches<'r, 'h>, SearchError> {
        let fixed_predicate_cursor = self.fixed_predicate_search_cursor(haystack);
        let session = self.search_session(limits.session)?;
        Ok(PortableMatches {
            session,
            state: PortableMatchIterState::new(
                haystack,
                limits.run(),
                empty_match_progress,
                fixed_predicate_cursor,
            ),
        })
    }

    /// Iterate over every non-overlapping match while retaining the exact
    /// original haystack in each emitted [`ByteMatch`].
    ///
    /// Selection, empty-match progress, workspace reuse, resource limits and
    /// accounting are identical to [`Self::find_iter`]. The companion
    /// [`PortableByteMatches`] iterator only projects each selected span into
    /// the pinned Rust bytes match-value contract.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same construction contract as
    /// [`Self::find_iter`]. Per-search and whole-iterator failures are yielded
    /// as [`PortableFindIterError`] items.
    pub fn find_iter_borrowed<'r, 'h>(
        &'r self,
        haystack: &'h [u8],
        limits: PortableFindIterLimits,
    ) -> Result<PortableByteMatches<'r, 'h>, SearchError> {
        Ok(PortableByteMatches {
            inner: self.find_iter(haystack, limits)?,
        })
    }

    /// Return the selected match at or after `start`.
    ///
    /// Assertions inspect the complete original haystack and returned offsets
    /// remain relative to it. Unlike the pinned Rust API, an out-of-bounds
    /// `start` is returned as a typed error instead of panicking.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn find_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Return only the selected match at or after `start`.
    ///
    /// Assertions inspect the complete original haystack. Range validation,
    /// execution limits and typed failures are identical to [`Self::find_at`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid start or a resource refusal.
    pub fn find_at_value(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.find_window_value(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Return the selected match at or after `start` while retaining the
    /// complete original haystack.
    ///
    /// This is the ranged companion to [`Self::find_borrowed`]. Assertions
    /// still inspect bytes before `start`, and [`ByteMatch`] offsets and bytes
    /// are both relative to the unsliced original haystack.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`Self::find_at`].
    pub fn find_at_borrowed<'h>(
        &self,
        haystack: &'h [u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find_at(haystack, start, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), accounting))
    }

    /// Search a range while assertions retain original-haystack context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window or a resource refusal.
    #[allow(
        clippy::too_many_lines,
        reason = "each authenticated native owner projects the same operation-specific accounting without erasing its concrete type"
    )]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    literal.find_window(haystack, literal_window, literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::ExactLiteral(accounting),
                ))
            }
            PortablePlan::PackedLiteralSet(literal_set) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = literal_set.find_window(
                    haystack,
                    literal_window,
                    packed_literal_set_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::PackedLiteralSet(accounting),
                ))
            }
            PortablePlan::GuardedLiteralSet(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((
                    matched,
                    SearchAccounting::GuardedLiteralSet(accounting),
                ))
            }
            PortablePlan::LiteralSetDfa(literal_set) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = literal_set.find_window(
                    haystack,
                    literal_window,
                    literal_set_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::LiteralSetDfa(accounting),
                ))
            }
            PortablePlan::RequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::DispatchedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::BoundedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::DispatchedBoundedRequiredLiteral(required) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = required.find_window(
                    haystack,
                    literal_window,
                    required_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::RequiredLiteral(accounting),
                ))
            }
            PortablePlan::LiteralClassRunLiteral(plan) => {
                let (matched, accounting) = plan.find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::LiteralClassRunLiteral(accounting),
                ))
            }
            PortablePlan::LiteralClassRunSearch(plan) => {
                let (matched, accounting) = plan.find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::LiteralClassRunLiteral(accounting),
                ))
            }
            PortablePlan::PureByteClassRepeat(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((matched, SearchAccounting::PureByteClassRepeat(accounting)))
            }
            PortablePlan::BoundedByteClassRepeat(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((matched, SearchAccounting::PureByteClassRepeat(accounting)))
            }
            PortablePlan::BoundedByteClassSequence(plan) => {
                let (matched, accounting) = plan
                    .find_window(haystack, window, limits)
                    .map_err(SearchError::BoundedByteClassSequence)?;
                Ok((
                    matched,
                    SearchAccounting::BoundedByteClassSequence(accounting),
                ))
            }
            PortablePlan::ForwardAnchored(forward) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = forward.find_window(
                    haystack,
                    literal_window,
                    forward_anchored_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::DispatchedForwardAnchored(forward) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) = forward.find_window(
                    haystack,
                    literal_window,
                    forward_anchored_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let literal_window = LiteralWindow::new(window.start(), window.end());
                let (matched, accounting) =
                    fixed.find_window(haystack, literal_window, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::ForwardAnchored(accounting),
                ))
            }
            PortablePlan::UnicodeFoldedLiteral(plan) => {
                let (matched, accounting) = plan.find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    unicode_folded_literal_limits(limits),
                )?;
                Ok((
                    matched.map(|candidate| Match {
                        start: candidate.start(),
                        end: candidate.end(),
                    }),
                    SearchAccounting::UnicodeFoldedLiteral(accounting.actual),
                ))
            }
            PortablePlan::K0(k0) => {
                let report = k0
                    .automaton
                    .prepare::<Span>()
                    .search_window(haystack, window, limits)?;
                let accounting = report.accounting();
                let matched = report.into_output().map(|span| Match {
                    start: span.start(),
                    end: span.end(),
                });
                Ok((matched, SearchAccounting::K0(accounting)))
            }
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((matched, SearchAccounting::UnicodeWordRun(accounting)))
            }
            PortablePlan::AsciiWordRun(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((matched, SearchAccounting::UnicodeWordRun(accounting)))
            }
            PortablePlan::BoundedWordClass(plan) => {
                let (matched, accounting) = plan.find_window(haystack, window, limits)?;
                Ok((matched, SearchAccounting::UnicodeWordRun(accounting)))
            }
            PortablePlan::FixedPredicateWord64(plan) => {
                let (matched, accounting) = plan.find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    fixed_predicate_word64_search_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    SearchAccounting::FixedPredicateWord64(accounting),
                ))
            }
        }
    }

    /// Return only the selected match wholly inside a search range.
    ///
    /// Assertions retain original-haystack context. K0 executes its typed span
    /// contract directly; native plans retain their existing concrete search
    /// implementations.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an invalid window or a resource refusal.
    #[allow(
        clippy::too_many_lines,
        reason = "each native owner retains its direct value-only span projection"
    )]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => literal
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::PackedLiteralSet(literal_set) => literal_set
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    packed_literal_set_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::GuardedLiteralSet(plan) => plan
                .find_window_value(haystack, window, limits)
                .map_err(SearchError::from),
            PortablePlan::LiteralSetDfa(literal_set) => literal_set
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_set_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::RequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::DispatchedRequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::BoundedRequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::DispatchedBoundedRequiredLiteral(required) => required
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    required_literal_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::LiteralClassRunLiteral(plan) => plan
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::LiteralClassRunSearch(plan) => plan
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    literal_class_run_literal_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::PureByteClassRepeat(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched)
                .map_err(SearchError::from),
            PortablePlan::ForwardAnchored(forward) => forward
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    forward_anchored_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::DispatchedForwardAnchored(forward) => forward
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    forward_anchored_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::ForwardEndFixed(fixed) => fixed
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    forward_anchored_limits(limits),
                )
                .map(|(matched, _)| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
            PortablePlan::K0(k0) => k0
                .automaton
                .prepare::<Span>()
                .search_window(haystack, window, limits)
                .map(|report| {
                    report.into_output().map(|span| Match {
                        start: span.start(),
                        end: span.end(),
                    })
                })
                .map_err(SearchError::from),
            PortablePlan::UnicodeFoldedLiteral(plan) => plan
                .find_window(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    unicode_folded_literal_limits(limits),
                )
                .map(|(matched, _)| {
                    matched.map(|candidate| Match {
                        start: candidate.start(),
                        end: candidate.end(),
                    })
                })
                .map_err(SearchError::from),
            PortablePlan::UnicodeWordRun(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched)
                .map_err(SearchError::from),
            PortablePlan::AsciiWordRun(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched)
                .map_err(SearchError::from),
            PortablePlan::BoundedWordClass(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched)
                .map_err(SearchError::from),
            PortablePlan::BoundedByteClassRepeat(plan) => plan
                .find_window(haystack, window, limits)
                .map(|(matched, _)| matched)
                .map_err(SearchError::from),
            PortablePlan::BoundedByteClassSequence(plan) => plan
                .find_window_value(haystack, window, limits)
                .map_err(SearchError::BoundedByteClassSequence),
            PortablePlan::FixedPredicateWord64(plan) => plan
                .find_window_value(
                    haystack,
                    LiteralWindow::new(window.start(), window.end()),
                    fixed_predicate_word64_search_limits(limits),
                )
                .map(|matched| matched.map(|(start, end)| Match { start, end }))
                .map_err(SearchError::from),
        }
    }

    fn fixed_predicate_search_cursor<'r, 'h>(
        &'r self,
        haystack: &'h [u8],
    ) -> Option<FixedPredicateWord64SearchCursor<'r, 'h>> {
        match &self.plan {
            PortablePlan::FixedPredicateWord64(plan) => Some(plan.search_cursor(haystack)),
            _ => None,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "each native owner projects its span and exact iterator work without facade accounting"
    )]
    fn find_iter_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, u64), SearchError> {
        let window = LiteralWindow::new(start, haystack.len());
        match &self.plan {
            PortablePlan::ExactLiteral(literal) => {
                let (matched, accounting) =
                    literal.find_window(haystack, window, literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    u64::try_from(accounting.linear_terms).unwrap_or(u64::MAX),
                ))
            }
            PortablePlan::PackedLiteralSet(literal_set) => {
                let (matched, accounting) =
                    literal_set.find_window(haystack, window, packed_literal_set_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    u64::try_from(accounting.work_upper_bound).unwrap_or(u64::MAX),
                ))
            }
            PortablePlan::GuardedLiteralSet(plan) => {
                let (matched, accounting) = plan.find_window(
                    haystack,
                    SearchWindow::new(start, haystack.len()),
                    limits,
                )?;
                Ok((
                    matched,
                    u64::try_from(accounting.upper_bounds.total_work).unwrap_or(u64::MAX),
                ))
            }
            PortablePlan::LiteralSetDfa(literal_set) => {
                let (matched, accounting) =
                    literal_set.find_window(haystack, window, literal_set_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    u64::try_from(accounting.transitions_upper_bound).unwrap_or(u64::MAX),
                ))
            }
            PortablePlan::RequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find_window(haystack, window, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::DispatchedRequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find_window(haystack, window, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::BoundedRequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find_window(haystack, window, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::DispatchedBoundedRequiredLiteral(required) => {
                let (matched, accounting) =
                    required.find_window(haystack, window, required_literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::LiteralClassRunLiteral(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, window, literal_class_run_literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::LiteralClassRunSearch(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, window, literal_class_run_literal_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::PureByteClassRepeat(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)?;
                Ok((matched, accounting.actual_work))
            }
            PortablePlan::BoundedByteClassRepeat(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)?;
                Ok((matched, accounting.actual_work))
            }
            PortablePlan::BoundedByteClassSequence(plan) => {
                let (matched, accounting) = plan
                    .find_window(haystack, SearchWindow::new(start, haystack.len()), limits)
                    .map_err(SearchError::BoundedByteClassSequence)?;
                Ok((matched, accounting.actual_work))
            }
            PortablePlan::ForwardAnchored(forward) => {
                let (matched, accounting) =
                    forward.find_window(haystack, window, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::DispatchedForwardAnchored(forward) => {
                let (matched, accounting) =
                    forward.find_window(haystack, window, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::ForwardEndFixed(fixed) => {
                let (matched, accounting) =
                    fixed.find_window(haystack, window, forward_anchored_limits(limits))?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.work_upper_bound,
                ))
            }
            PortablePlan::UnicodeFoldedLiteral(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, window, unicode_folded_literal_limits(limits))?;
                Ok((
                    matched.map(|candidate| Match {
                        start: candidate.start(),
                        end: candidate.end(),
                    }),
                    u64::try_from(accounting.actual.work).unwrap_or(u64::MAX),
                ))
            }
            PortablePlan::UnicodeWordRun(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)?;
                Ok((matched, accounting.work()))
            }
            PortablePlan::AsciiWordRun(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)?;
                Ok((matched, accounting.work()))
            }
            PortablePlan::BoundedWordClass(plan) => {
                let (matched, accounting) =
                    plan.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)?;
                Ok((matched, accounting.work()))
            }
            PortablePlan::FixedPredicateWord64(plan) => {
                let (matched, accounting) = plan.find_window(
                    haystack,
                    LiteralWindow::new(start, haystack.len()),
                    fixed_predicate_word64_search_limits(limits),
                )?;
                Ok((
                    matched.map(|(start, end)| Match { start, end }),
                    accounting.actual.work,
                ))
            }
            PortablePlan::K0(_) => {
                let (matched, accounting) =
                    self.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)?;
                Ok((matched, accounting.work_or_linear_terms()))
            }
        }
    }

    /// Produce the complete equality key for a required-literal operation.
    ///
    /// `None` means this matcher selected another plan family. Search limits
    /// are included deliberately so cached qualification records cannot mix
    /// distinct refusal contracts.
    #[must_use]
    pub fn required_literal_cache_identity(
        &self,
        operation: CaptureFreeOperation,
        search_limits: SearchLimits,
    ) -> Option<RequiredLiteralCacheIdentity> {
        match &self.plan {
            PortablePlan::RequiredLiteral(required) => Some(RequiredLiteralCacheIdentity {
                schema_version: EXPLAIN_SCHEMA_VERSION,
                plan_id: required.plan_id(),
                profile: self.profile.clone(),
                operation,
                anchors: required.anchors(),
                class_words: required.class().words(),
                repeat: RequiredLiteralClassRepeat::one_or_more(),
                suffix: required.suffix().to_vec(),
                build_limits: self.limits,
                search_limits,
            }),
            PortablePlan::DispatchedRequiredLiteral(required) => {
                Some(RequiredLiteralCacheIdentity {
                    schema_version: EXPLAIN_SCHEMA_VERSION,
                    plan_id: required.plan_id(),
                    profile: self.profile.clone(),
                    operation,
                    anchors: required.anchors(),
                    class_words: required.class().words(),
                    repeat: RequiredLiteralClassRepeat::one_or_more(),
                    suffix: required.suffix().to_vec(),
                    build_limits: self.limits,
                    search_limits,
                })
            }
            PortablePlan::BoundedRequiredLiteral(required) => Some(RequiredLiteralCacheIdentity {
                schema_version: EXPLAIN_SCHEMA_VERSION,
                plan_id: required.plan_id(),
                profile: self.profile.clone(),
                operation,
                anchors: required.anchors(),
                class_words: required.class().words(),
                repeat: required.repeat(),
                suffix: required.suffix().to_vec(),
                build_limits: self.limits,
                search_limits,
            }),
            PortablePlan::DispatchedBoundedRequiredLiteral(required) => {
                Some(RequiredLiteralCacheIdentity {
                    schema_version: EXPLAIN_SCHEMA_VERSION,
                    plan_id: required.plan_id(),
                    profile: self.profile.clone(),
                    operation,
                    anchors: required.anchors(),
                    class_words: required.class().words(),
                    repeat: required.repeat(),
                    suffix: required.suffix().to_vec(),
                    build_limits: self.limits,
                    search_limits,
                })
            }
            _ => None,
        }
    }

    /// Produce the complete equality key for a forward-anchored operation.
    ///
    /// `None` means this matcher selected another plan family. The key is
    /// deliberately distinct from the required-literal candidate.
    #[must_use]
    pub fn forward_anchored_cache_identity(
        &self,
        operation: CaptureFreeOperation,
        search_limits: SearchLimits,
    ) -> Option<ForwardAnchoredCacheIdentity> {
        match &self.plan {
            PortablePlan::ForwardAnchored(forward) => Some(ForwardAnchoredCacheIdentity {
                schema_version: EXPLAIN_SCHEMA_VERSION,
                plan_id: forward.plan_id(),
                profile: self.profile.clone(),
                operation,
                anchors: forward.anchors(),
                class_words: forward.class().words(),
                suffix: forward.suffix().to_vec(),
                implementation: forward.implementation(),
                build_limits: self.limits,
                search_limits,
            }),
            PortablePlan::DispatchedForwardAnchored(forward) => {
                Some(ForwardAnchoredCacheIdentity {
                    schema_version: EXPLAIN_SCHEMA_VERSION,
                    plan_id: forward.plan_id(),
                    profile: self.profile.clone(),
                    operation,
                    anchors: forward.anchors(),
                    class_words: forward.class().words(),
                    suffix: forward.suffix().to_vec(),
                    implementation: forward.implementation(),
                    build_limits: self.limits,
                    search_limits,
                })
            }
            PortablePlan::ForwardEndFixed(fixed) => Some(ForwardAnchoredCacheIdentity {
                schema_version: EXPLAIN_SCHEMA_VERSION,
                plan_id: fixed.plan_id(),
                profile: self.profile.clone(),
                operation,
                anchors: fixed.anchors(),
                class_words: fixed.class().words(),
                suffix: fixed.suffix().to_vec(),
                implementation: fixed.implementation(),
                build_limits: self.limits,
                search_limits,
            }),
            _ => None,
        }
    }
}

/// Operation-local reusable search state for one immutable portable matcher.
///
/// This keeps construction-selected specialized plans unchanged. Only K0 owns
/// mutable state, consisting of one fixed-capacity workspace plus bounded
/// performance-only prefilter histories whose sizes are determined entirely
/// by the validated plan.
#[derive(Debug)]
pub struct PortableSearchSession<'a> {
    plan: PortableSearchSessionPlan<'a>,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing K0 would add a second allocation and falsify workspace setup accounting"
)]
enum PortableSearchSessionPlan<'a> {
    Native(&'a PortableRegex),
    K0 {
        session: K0SearchSession<'a>,
        mandatory_suffix: Option<&'a K0MandatorySuffixPlan>,
        mandatory_cut: Option<&'a K0MandatoryCutPlan>,
        negative_prefilter: Option<&'a K0NegativePrefilterPlan>,
        mandatory_suffix_exists_state: K0NegativePrefilterState,
        mandatory_suffix_span_state: K0NegativePrefilterState,
        negative_prefilter_exists_state: K0NegativePrefilterState,
        negative_prefilter_span_state: K0NegativePrefilterState,
    },
}

// A negative literal pass pays for itself only on a reusable, sufficiently
// large window. Requiring four windows of needle width limits exposure for
// long needles whose first occurrence is early while retaining the broad
// absent-input case this sidecar is meant to accelerate.
const K0_NEGATIVE_PREFILTER_MIN_WINDOW_BYTES: usize = 1_024;
const K0_NEGATIVE_PREFILTER_WINDOW_NEEDLE_FACTOR: usize = 4;
const K0_NEGATIVE_PREFILTER_PRESENT_STREAK_LIMIT: u8 = 8;
const K0_NEGATIVE_PREFILTER_MAX_DISABLED_CALLS: u8 = 64;
const K0_NEGATIVE_PREFILTER_SIZE_CLASS_STATES: usize = 4;
const K0_SUFFIX_FORWARD_FALLBACK_BYTES: usize = 1_024;
// Scalar recovery is needed only for high bytes because the exact ASCII
// subset is scanned in bulk. High-heavy inputs fail open instead of turning
// this optional separator proof into an unbounded reverse byte walk.
const K0_SUFFIX_HIGH_BYTE_BACKWARD_MAX: usize = 256;
const K0_SUFFIX_MAX_CANDIDATES: usize = 8;
const K0_SUFFIX_REVERSE_CREDIT_BYTES: usize = 1_024;
const K0_SUFFIX_REVERSE_PROGRESS_FACTOR: usize = 2;

#[derive(Clone, Copy, Debug, Default)]
struct K0NegativePrefilterClassState {
    present_streak: u8,
    disabled_calls: u8,
    present_backoff: u8,
    next_predicate: u8,
    window_size_class: Option<u32>,
}

impl K0NegativePrefilterClassState {
    const fn observe_absent(&mut self) {
        self.present_streak = 0;
        self.disabled_calls = 0;
        self.present_backoff = 0;
    }

    fn observe_present(&mut self) {
        self.present_streak = self.present_streak.saturating_add(1);
        if self.present_streak >= K0_NEGATIVE_PREFILTER_PRESENT_STREAK_LIMIT {
            self.present_streak = K0_NEGATIVE_PREFILTER_PRESENT_STREAK_LIMIT - 1;
            self.present_backoff = if self.present_backoff == 0 {
                1
            } else {
                self.present_backoff
                    .saturating_mul(2)
                    .min(K0_NEGATIVE_PREFILTER_MAX_DISABLED_CALLS)
            };
            self.disabled_calls = self.present_backoff;
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct K0NegativePrefilterState {
    classes: [K0NegativePrefilterClassState; K0_NEGATIVE_PREFILTER_SIZE_CLASS_STATES],
    next_replacement: u8,
}

impl K0NegativePrefilterState {
    fn class_for(&mut self, window_size_class: u32) -> usize {
        if let Some(index) = self
            .classes
            .iter()
            .position(|state| state.window_size_class == Some(window_size_class))
        {
            return index;
        }
        if let Some(index) = self
            .classes
            .iter()
            .position(|state| state.window_size_class.is_none())
        {
            self.classes[index].window_size_class = Some(window_size_class);
            return index;
        }
        let index = usize::from(self.next_replacement) % self.classes.len();
        self.next_replacement = self
            .next_replacement
            .wrapping_add(1)
            % u8::try_from(self.classes.len()).expect("size-class state count fits u8");
        self.classes[index] = K0NegativePrefilterClassState {
            window_size_class: Some(window_size_class),
            ..K0NegativePrefilterClassState::default()
        };
        index
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum K0NegativePrefilterOutcome {
    Bypass,
    Absent,
    Present,
}

#[derive(Clone, Copy, Debug)]
struct K0NegativePrefilterAttempt {
    outcome: K0NegativePrefilterOutcome,
    candidate_floor: Option<usize>,
    state_after_success: K0NegativePrefilterState,
}

fn run_k0_negative_prefilter(
    mandatory_cut: Option<&K0MandatoryCutPlan>,
    plan: Option<&K0NegativePrefilterPlan>,
    state: K0NegativePrefilterState,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
) -> K0NegativePrefilterAttempt {
    let unchanged = |outcome| K0NegativePrefilterAttempt {
        outcome,
        candidate_floor: None,
        state_after_success: state,
    };
    if mandatory_cut.is_none() && plan.is_none() {
        return unchanged(K0NegativePrefilterOutcome::Bypass);
    }
    if limits != SearchLimits::unlimited()
        || window.start() > window.end()
        || window.end() > haystack.len()
    {
        return unchanged(K0NegativePrefilterOutcome::Bypass);
    }
    let window_bytes = window.end() - window.start();
    let maximum_needle_bytes = plan.map_or(1, |plan| plan.maximum_needle_bytes);
    let minimum_window_bytes = K0_NEGATIVE_PREFILTER_MIN_WINDOW_BYTES.max(
        maximum_needle_bytes
            .saturating_mul(K0_NEGATIVE_PREFILTER_WINDOW_NEEDLE_FACTOR),
    );
    if window_bytes < minimum_window_bytes {
        return unchanged(K0NegativePrefilterOutcome::Bypass);
    }
    let window_size_class = usize::BITS - window_bytes.leading_zeros();
    let mut next_state = state;
    let class_index = next_state.class_for(window_size_class);
    let class_state = &mut next_state.classes[class_index];
    if class_state.disabled_calls != 0 {
        class_state.disabled_calls -= 1;
        return K0NegativePrefilterAttempt {
            outcome: K0NegativePrefilterOutcome::Bypass,
            candidate_floor: None,
            state_after_success: next_state,
        };
    }
    let literal_count = plan.map_or(0, |plan| plan.literals.len());
    let cut_count = usize::from(mandatory_cut.is_some());
    let predicate_count = cut_count
        .checked_add(literal_count)
        .expect("bounded negative-predicate count cannot overflow");
    if predicate_count == 0 {
        return unchanged(K0NegativePrefilterOutcome::Bypass);
    }
    // K0 already derives its own graph-proved forward start filter. Start at
    // the cheap graph cut when available, then the longest structural literal;
    // conjunctive inspection publishes literals in descending length order.
    // The exact suffix is a mutually exclusive positive-verification route.
    // Keeping an equal literal here is intentional fallback coverage for calls
    // where suffix verification bypasses before scanning. One probe owns
    // exactly one whole-window pass; retaining an absent predicate's ordinal
    // makes subsequent calls reuse the useful proof instead of paying for
    // other conjuncts first.
    let predicate_ordinal = usize::from(class_state.next_predicate) % predicate_count;
    let mut candidate_floor = None;
    let present = if predicate_ordinal < cut_count {
        let cut = mandatory_cut
            .copied()
            .expect("cut ordinal requires a mandatory-cut plan");
        match cut.first_member(&haystack[window.start()..window.end()]) {
            Some(first_member) => {
                candidate_floor = cut.candidate_floor(window.start(), first_member);
                true
            }
            None => false,
        }
    } else {
        let plan = plan.expect("literal ordinal requires a literal plan");
        let literal_index = predicate_ordinal
            .checked_sub(cut_count)
            .expect("literal predicate ordinal follows the cut");
        let literal = &plan.literals[literal_index];
        match literal.find_window(
            haystack,
            LiteralWindow::new(window.start(), window.end()),
            LiteralSearchLimits::unlimited(),
        ) {
            Ok((found, _)) => found.is_some(),
            Err(_) => return unchanged(K0NegativePrefilterOutcome::Bypass),
        }
    };
    if !present {
        class_state.observe_absent();
        K0NegativePrefilterAttempt {
            outcome: K0NegativePrefilterOutcome::Absent,
            candidate_floor: None,
            state_after_success: next_state,
        }
    } else {
        class_state.next_predicate = u8::try_from(
            predicate_ordinal
                .checked_add(1)
                .expect("bounded predicate ordinal cannot overflow")
                % predicate_count,
        )
        .expect("bounded predicate count fits u8");
        class_state.observe_present();
        K0NegativePrefilterAttempt {
            outcome: K0NegativePrefilterOutcome::Present,
            candidate_floor,
            state_after_success: next_state,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum K0MandatorySuffixOutcome {
    Bypass,
    Fallback,
    Found(bool),
}

#[derive(Clone, Copy, Debug)]
struct K0MandatorySuffixAttempt {
    outcome: K0MandatorySuffixOutcome,
    state_after_success: K0NegativePrefilterState,
}

fn k0_mandatory_suffix_completed_negative_is_useful(
    window_bytes: usize,
    candidates: usize,
    verifier_work: u64,
) -> bool {
    // Finding no suffix candidate is the sidecar's intended fast negative
    // proof, so keep it as an immediate reset independently of numeric
    // conversions. Once endpoint verification begins, learn from two
    // disjoint costs outside the base suffix pass: one additional literal
    // dispatch per candidate and the verifier's complete work receipt. The
    // receipt already charges each reverse source byte, so do not count its
    // physical traffic again. Equality pays for one extra window-equivalent
    // pass; anything larger should let ordinary K0 run directly after the
    // existing streak threshold.
    candidates == 0
        || u64::try_from(window_bytes).is_ok_and(|window_work| {
            u64::try_from(candidates)
                .ok()
                .and_then(|candidate_work| candidate_work.checked_add(verifier_work))
                .is_some_and(|extra_work| extra_work <= window_work)
        })
}

fn observe_k0_mandatory_suffix_completed_negative(
    state: &mut K0NegativePrefilterClassState,
    window_bytes: usize,
    candidates: usize,
    verifier_work: u64,
) {
    if k0_mandatory_suffix_completed_negative_is_useful(
        window_bytes,
        candidates,
        verifier_work,
    ) {
        state.observe_absent();
    } else {
        state.observe_present();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum K0MandatorySuffixSpanOutcome {
    Bypass,
    Fallback,
    Absent,
    Narrowed(usize),
}

#[derive(Clone, Copy, Debug)]
struct K0MandatorySuffixSpanAttempt {
    outcome: K0MandatorySuffixSpanOutcome,
    state_after_success: K0NegativePrefilterState,
}

fn try_k0_mandatory_suffix_span_start(
    suffix: &K0MandatorySuffixPlan,
    state: K0NegativePrefilterState,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
) -> K0MandatorySuffixSpanAttempt {
    let unchanged = |outcome| K0MandatorySuffixSpanAttempt {
        outcome,
        state_after_success: state,
    };
    if limits != SearchLimits::unlimited()
        || suffix.consumption_run.is_none()
        || window.start() > window.end()
        || window.end() > haystack.len()
    {
        return unchanged(K0MandatorySuffixSpanOutcome::Bypass);
    }
    let window_bytes = window.end().saturating_sub(window.start());
    if window_bytes < K0_NEGATIVE_PREFILTER_MIN_WINDOW_BYTES {
        return unchanged(K0MandatorySuffixSpanOutcome::Bypass);
    }

    let window_size_class = usize::BITS - window_bytes.leading_zeros();
    let mut next_state = state;
    let class_index = next_state.class_for(window_size_class);
    if next_state.classes[class_index].disabled_calls != 0 {
        next_state.classes[class_index].disabled_calls -= 1;
        return K0MandatorySuffixSpanAttempt {
            outcome: K0MandatorySuffixSpanOutcome::Fallback,
            state_after_success: next_state,
        };
    }

    let occurrence = match suffix.find_window(haystack, window.start(), window.end()) {
        Ok(occurrence) => occurrence,
        Err(_) => {
            next_state.classes[class_index].observe_present();
            return K0MandatorySuffixSpanAttempt {
                outcome: K0MandatorySuffixSpanOutcome::Fallback,
                state_after_success: next_state,
            };
        }
    };
    let Some((occurrence_start, _)) = occurrence else {
        next_state.classes[class_index].observe_absent();
        return K0MandatorySuffixSpanAttempt {
            outcome: K0MandatorySuffixSpanOutcome::Absent,
            state_after_success: next_state,
        };
    };
    let narrowed = suffix.narrowed_start_before(haystack, window.start(), occurrence_start);
    let useful = narrowed
        .checked_sub(window.start())
        .is_some_and(|saved| saved >= K0_SUFFIX_FORWARD_FALLBACK_BYTES);
    if !useful {
        next_state.classes[class_index].observe_present();
        return K0MandatorySuffixSpanAttempt {
            outcome: K0MandatorySuffixSpanOutcome::Fallback,
            state_after_success: next_state,
        };
    }
    next_state.classes[class_index].observe_absent();
    K0MandatorySuffixSpanAttempt {
        outcome: K0MandatorySuffixSpanOutcome::Narrowed(narrowed),
        state_after_success: next_state,
    }
}

#[inline(never)]
fn try_k0_mandatory_suffix_exists(
    session: &mut K0SearchSession<'_>,
    suffix: &K0MandatorySuffixPlan,
    state: K0NegativePrefilterState,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
) -> Result<K0MandatorySuffixAttempt, SearchError> {
    let unchanged = |outcome| K0MandatorySuffixAttempt {
        outcome,
        state_after_success: state,
    };
    if limits != SearchLimits::unlimited()
        || window.start() > window.end()
        || window.end() > haystack.len()
    {
        return Ok(unchanged(K0MandatorySuffixOutcome::Bypass));
    }
    let Some(window_bytes) = window.end().checked_sub(window.start()) else {
        return Ok(unchanged(K0MandatorySuffixOutcome::Bypass));
    };
    if window_bytes < K0_NEGATIVE_PREFILTER_MIN_WINDOW_BYTES
        || !session.positive_end_verifier_available()
    {
        return Ok(unchanged(K0MandatorySuffixOutcome::Bypass));
    }

    let window_size_class = usize::BITS - window_bytes.leading_zeros();
    let mut next_state = state;
    let class_index = next_state.class_for(window_size_class);
    if next_state.classes[class_index].disabled_calls != 0 {
        next_state.classes[class_index].disabled_calls -= 1;
        return Ok(K0MandatorySuffixAttempt {
            // This size class already learned that suffix speculation loses.
            // Run ordinary K0 directly instead of phase-locking a second
            // adaptive predicate while the suffix retry clock counts down.
            outcome: K0MandatorySuffixOutcome::Fallback,
            state_after_success: next_state,
        });
    }
    if !session.negative_terminal_has_reused_work_certificate(window_bytes) {
        return Ok(unchanged(K0MandatorySuffixOutcome::Bypass));
    }

    let mut search_start = window.start();
    let mut candidates = 0usize;
    let mut cumulative_work = 0u64;
    let mut cumulative_reverse_bytes = 0usize;
    loop {
        let occurrence = match suffix.find_window(haystack, search_start, window.end()) {
            Ok(occurrence) => occurrence,
            Err(_) => {
                next_state.classes[class_index].observe_present();
                return Ok(K0MandatorySuffixAttempt {
                    outcome: K0MandatorySuffixOutcome::Fallback,
                    state_after_success: next_state,
                });
            }
        };
        let Some((occurrence_start, endpoint)) = occurrence else {
            observe_k0_mandatory_suffix_completed_negative(
                &mut next_state.classes[class_index],
                window_bytes,
                candidates,
                cumulative_work,
            );
            return Ok(K0MandatorySuffixAttempt {
                outcome: K0MandatorySuffixOutcome::Found(false),
                state_after_success: next_state,
            });
        };
        let Some(progress) = endpoint.checked_sub(window.start()) else {
            next_state.classes[class_index].observe_present();
            return Ok(K0MandatorySuffixAttempt {
                outcome: K0MandatorySuffixOutcome::Fallback,
                state_after_success: next_state,
            });
        };
        candidates = candidates.saturating_add(1);
        if candidates > K0_SUFFIX_MAX_CANDIDATES
            || progress <= K0_SUFFIX_FORWARD_FALLBACK_BYTES
        {
            next_state.classes[class_index].observe_present();
            return Ok(K0MandatorySuffixAttempt {
                outcome: K0MandatorySuffixOutcome::Fallback,
                state_after_success: next_state,
            });
        }
        let Some(allowed_reverse_bytes) = progress
            .checked_mul(K0_SUFFIX_REVERSE_PROGRESS_FACTOR)
            .and_then(|bytes| bytes.checked_add(K0_SUFFIX_REVERSE_CREDIT_BYTES))
        else {
            next_state.classes[class_index].observe_present();
            return Ok(K0MandatorySuffixAttempt {
                outcome: K0MandatorySuffixOutcome::Fallback,
                state_after_success: next_state,
            });
        };
        let Some(remaining_reverse_bytes) =
            allowed_reverse_bytes.checked_sub(cumulative_reverse_bytes)
        else {
            next_state.classes[class_index].observe_present();
            return Ok(K0MandatorySuffixAttempt {
                outcome: K0MandatorySuffixOutcome::Fallback,
                state_after_success: next_state,
            });
        };
        let Some(work_budget_bytes) = progress.checked_add(K0_SUFFIX_REVERSE_CREDIT_BYTES) else {
            next_state.classes[class_index].observe_present();
            return Ok(K0MandatorySuffixAttempt {
                outcome: K0MandatorySuffixOutcome::Fallback,
                state_after_success: next_state,
            });
        };
        let Some(allowed_work) =
            session.positive_end_verifier_work_certificate(work_budget_bytes)
        else {
            next_state.classes[class_index].observe_present();
            return Ok(K0MandatorySuffixAttempt {
                outcome: K0MandatorySuffixOutcome::Fallback,
                state_after_success: next_state,
            });
        };
        let Some(remaining_work) = allowed_work.checked_sub(cumulative_work) else {
            next_state.classes[class_index].observe_present();
            return Ok(K0MandatorySuffixAttempt {
                outcome: K0MandatorySuffixOutcome::Fallback,
                state_after_success: next_state,
            });
        };
        let verification = session
            .try_positive_match_ending_at(
                haystack,
                window,
                endpoint,
                K0PositiveEndLimits::new(remaining_work, remaining_reverse_bytes),
            )
            .map_err(SearchError::from)?;
        cumulative_work = cumulative_work
            .checked_add(verification.receipt().work())
            .ok_or(SearchError::K0(K0SearchError::ArithmeticOverflow {
                computation: "cumulative mandatory-suffix verifier work",
            }))?;
        cumulative_reverse_bytes = cumulative_reverse_bytes
            .checked_add(verification.receipt().reverse_source_bytes())
            .ok_or(SearchError::K0(
                K0SearchError::ArithmeticOverflow {
                    computation: "cumulative mandatory-suffix reverse bytes",
                },
            ))?;
        match verification.outcome() {
            K0PositiveEndOutcome::Matched => {
                let useful_work = u64::try_from(progress)
                    .is_ok_and(|progress| cumulative_work <= progress);
                if useful_work {
                    next_state.classes[class_index].observe_absent();
                } else {
                    next_state.classes[class_index].observe_present();
                }
                return Ok(K0MandatorySuffixAttempt {
                    outcome: K0MandatorySuffixOutcome::Found(true),
                    state_after_success: next_state,
                });
            }
            K0PositiveEndOutcome::Declined => {
                next_state.classes[class_index].observe_present();
                return Ok(K0MandatorySuffixAttempt {
                    outcome: K0MandatorySuffixOutcome::Fallback,
                    state_after_success: next_state,
                });
            }
            K0PositiveEndOutcome::Rejected => {}
        }
        search_start = occurrence_start.checked_add(1).ok_or(SearchError::K0(
            K0SearchError::ArithmeticOverflow {
                computation: "next overlapping mandatory-suffix occurrence",
            },
        ))?;
    }
}

impl<'r> PortableSearchSession<'r> {
    /// Stable runtime identity of the borrowed matcher.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        match &self.plan {
            PortableSearchSessionPlan::Native(regex) => regex.runtime_implementation_id(),
            PortableSearchSessionPlan::K0 { .. } => "k0",
        }
    }

    /// One-time K0 workspace allocation and initialization facts.
    ///
    /// Native specialized plans return `None` because the session allocates no
    /// storage for them.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        match &self.plan {
            PortableSearchSessionPlan::Native(_) => None,
            PortableSearchSessionPlan::K0 { session, .. } => {
                Some(session.construction_accounting())
            }
        }
    }

    /// Whether a selected match exists, reusing K0 state when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::is_match`].
    pub fn is_match(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Whether a selected match exists without constructing facade diagnostic
    /// accounting on the success path, reusing K0 state when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::is_match_value`].
    pub fn is_match_value(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_window_value(haystack, SearchWindow::full(haystack), limits)
    }

    /// Whether a selected match exists at or after `start`, reusing K0 state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::is_match_at`].
    pub fn is_match_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        self.is_match_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Whether a selected match exists at or after `start` without
    /// constructing facade diagnostic accounting, reusing K0 state when
    /// applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::is_match_value_at`].
    pub fn is_match_value_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        self.is_match_window_value(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Whether a selected match exists wholly inside a range, reusing K0
    /// state and retaining original-haystack assertion context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::is_match_window`].
    pub fn is_match_window(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(bool, SearchAccounting), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.is_match_window(haystack, window, limits)
            }
            PortableSearchSessionPlan::K0 { session, .. } => {
                let report = session.search_window::<Exists>(haystack, window, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Whether a selected match exists wholly inside a range without
    /// constructing facade diagnostic accounting, reusing K0 state when
    /// applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::is_match_window_value`].
    pub fn is_match_window_value(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.is_match_window_value(haystack, window, limits)
            }
            PortableSearchSessionPlan::K0 {
                session,
                mandatory_suffix,
                mandatory_cut,
                negative_prefilter,
                mandatory_suffix_exists_state,
                negative_prefilter_exists_state,
                ..
            } => {
                let mut suffix_state_after_success = *mandatory_suffix_exists_state;
                if let Some(suffix) = *mandatory_suffix {
                    let suffix_attempt = try_k0_mandatory_suffix_exists(
                        session,
                        suffix,
                        *mandatory_suffix_exists_state,
                        haystack,
                        window,
                        limits,
                    )?;
                    suffix_state_after_success = suffix_attempt.state_after_success;
                    match suffix_attempt.outcome {
                        K0MandatorySuffixOutcome::Found(found) => {
                            *mandatory_suffix_exists_state = suffix_state_after_success;
                            return Ok(found);
                        }
                        K0MandatorySuffixOutcome::Fallback => {
                            let result = session
                                .search_exists_value(haystack, window, limits)
                                .map_err(SearchError::from);
                            if result.is_ok() {
                                *mandatory_suffix_exists_state = suffix_state_after_success;
                            }
                            return result;
                        }
                        K0MandatorySuffixOutcome::Bypass => {}
                    }
                }
                let attempt = run_k0_negative_prefilter(
                    *mandatory_cut,
                    *negative_prefilter,
                    *negative_prefilter_exists_state,
                    haystack,
                    window,
                    limits,
                );
                if attempt.outcome == K0NegativePrefilterOutcome::Absent {
                    let certified = window
                        .end()
                        .checked_sub(window.start())
                        .is_some_and(|input_bytes| {
                            session.negative_terminal_has_reused_work_certificate(input_bytes)
                        });
                    if certified {
                        *mandatory_suffix_exists_state = suffix_state_after_success;
                        *negative_prefilter_exists_state = attempt.state_after_success;
                        return Ok(false);
                    }
                }
                let search_window = attempt
                    .candidate_floor
                    .map_or(window, |start| SearchWindow::new(start, window.end()));
                let result = session
                    .search_exists_value(haystack, search_window, limits)
                    .map_err(SearchError::from);
                if result.is_ok() {
                    *mandatory_suffix_exists_state = suffix_state_after_success;
                    *negative_prefilter_exists_state = attempt.state_after_success;
                }
                result
            }
        }
    }

    /// Return the first detected match end, reusing K0 state when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::shortest_match`].
    pub fn shortest_match(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_match_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return the first detected match end at or after `start`, reusing K0
    /// state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::shortest_match_at`].
    pub fn shortest_match_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        self.shortest_match_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    fn shortest_match_window(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.shortest_match_window(haystack, window, limits)
            }
            PortableSearchSessionPlan::K0 { session, .. } => {
                let report = session.search_window::<EarliestEnd>(haystack, window, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Return the selected match end, reusing K0 state when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::selected_end`].
    pub fn selected_end(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<usize>, SearchAccounting), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => regex.selected_end(haystack, limits),
            PortableSearchSessionPlan::K0 { session, .. } => {
                let report = session.search::<SelectedEnd>(haystack, limits)?;
                let accounting = report.accounting();
                Ok((report.into_output(), SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Return the profile-selected leftmost-first match.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::find`].
    pub fn find(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return only the profile-selected leftmost-first match, reusing K0 state
    /// when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::find_value`].
    pub fn find_value(
        &mut self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.find_window_value(haystack, SearchWindow::full(haystack), limits)
    }

    /// Return the selected match while retaining the complete original
    /// haystack and reusing K0 state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`Self::find`].
    pub fn find_borrowed<'h>(
        &mut self,
        haystack: &'h [u8],
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find(haystack, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), accounting))
    }

    /// Return the selected match at or after `start`, reusing K0 state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::find_at`].
    pub fn find_at(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        self.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Return only the selected match at or after `start`, reusing K0 state
    /// when applicable.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::find_at_value`].
    pub fn find_at_value(
        &mut self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        self.find_window_value(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Return the selected match at or after `start` while retaining the
    /// complete original haystack and reusing K0 state.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`Self::find_at`].
    pub fn find_at_borrowed<'h>(
        &mut self,
        haystack: &'h [u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<ByteMatch<'h>>, SearchAccounting), SearchError> {
        let (matched, accounting) = self.find_at(haystack, start, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), accounting))
    }

    /// Search a range while assertions retain original-haystack context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same per-invocation limits as
    /// [`PortableRegex::find_window`].
    pub fn find_window(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, SearchAccounting), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => regex.find_window(haystack, window, limits),
            PortableSearchSessionPlan::K0 { session, .. } => {
                let report = if window.end() == haystack.len() {
                    session.search_span_at_cursor(haystack, window.start(), limits)?
                } else {
                    session.search_window::<Span>(haystack, window, limits)?
                };
                let accounting = report.accounting();
                let matched = report.into_output().map(|span| Match {
                    start: span.start(),
                    end: span.end(),
                });
                Ok((matched, SearchAccounting::K0(accounting)))
            }
        }
    }

    /// Return only the selected match wholly inside a search range, reusing K0
    /// state and retaining original-haystack assertion context.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] under the same range and resource contract as
    /// [`PortableRegex::find_window_value`].
    pub fn find_window_value(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.find_window_value(haystack, window, limits)
            }
            PortableSearchSessionPlan::K0 {
                session,
                mandatory_suffix,
                mandatory_cut,
                negative_prefilter,
                mandatory_suffix_span_state,
                negative_prefilter_span_state,
                ..
            } => {
                let mut suffix_state_after_success = *mandatory_suffix_span_state;
                if let Some(suffix) = *mandatory_suffix {
                    let suffix_attempt = try_k0_mandatory_suffix_span_start(
                        suffix,
                        *mandatory_suffix_span_state,
                        haystack,
                        window,
                        limits,
                    );
                    suffix_state_after_success = suffix_attempt.state_after_success;
                    let run_k0_directly = match suffix_attempt.outcome {
                        K0MandatorySuffixSpanOutcome::Absent => {
                            let certified = window
                                .end()
                                .checked_sub(window.start())
                                .is_some_and(|input_bytes| {
                                    session
                                        .negative_terminal_has_reused_work_certificate(input_bytes)
                                });
                            if certified {
                                *mandatory_suffix_span_state = suffix_state_after_success;
                                return Ok(None);
                            }
                            true
                        }
                        K0MandatorySuffixSpanOutcome::Narrowed(start) => {
                            let narrowed = SearchWindow::new(start, window.end());
                            let result = session
                                .search_span_value(haystack, narrowed, limits)
                                .map(|found| {
                                    found.map(|span| Match {
                                        start: span.start(),
                                        end: span.end(),
                                    })
                                })
                                .map_err(SearchError::from);
                            if result.is_ok() {
                                *mandatory_suffix_span_state = suffix_state_after_success;
                            }
                            return result;
                        }
                        K0MandatorySuffixSpanOutcome::Fallback => true,
                        K0MandatorySuffixSpanOutcome::Bypass => false,
                    };
                    if run_k0_directly {
                        // A completed or failed suffix attempt may already
                        // have scanned the source. Do not phase-lock a second
                        // sidecar predicate behind it.
                        let result = session
                            .search_span_value(haystack, window, limits)
                            .map(|found| {
                                found.map(|span| Match {
                                    start: span.start(),
                                    end: span.end(),
                                })
                            })
                            .map_err(SearchError::from);
                        if result.is_ok() {
                            *mandatory_suffix_span_state = suffix_state_after_success;
                        }
                        return result;
                    }
                }
                let attempt = run_k0_negative_prefilter(
                    *mandatory_cut,
                    *negative_prefilter,
                    *negative_prefilter_span_state,
                    haystack,
                    window,
                    limits,
                );
                if attempt.outcome == K0NegativePrefilterOutcome::Absent {
                    let certified = window
                        .end()
                        .checked_sub(window.start())
                        .is_some_and(|input_bytes| {
                            session.negative_terminal_has_reused_work_certificate(input_bytes)
                        });
                    if certified {
                        *mandatory_suffix_span_state = suffix_state_after_success;
                        *negative_prefilter_span_state = attempt.state_after_success;
                        return Ok(None);
                    }
                }
                let search_window = attempt
                    .candidate_floor
                    .map_or(window, |start| SearchWindow::new(start, window.end()));
                let result = session
                    .search_span_value(haystack, search_window, limits)
                    .map(|found| {
                        found.map(|span| Match {
                            start: span.start(),
                            end: span.end(),
                        })
                    })
                    .map_err(SearchError::from);
                if result.is_ok() {
                    *mandatory_suffix_span_state = suffix_state_after_success;
                    *negative_prefilter_span_state = attempt.state_after_success;
                }
                result
            }
        }
    }

    /// Iterate over every non-overlapping byte match while reusing this
    /// session's existing workspace.
    ///
    /// Session construction and its one-time accounting happened before this
    /// call. Constructing this iterator allocates nothing, and its
    /// [`PortableFindIterAccounting`] starts at zero for this haystack.
    /// Dropping the iterator early, or dropping it after a yielded error,
    /// releases the mutable borrow so the session can be used again.
    ///
    /// [`PortableRegex::find_iter`] remains the cold/fresh convenience API:
    /// it constructs and owns a new session for each iterator. This method is
    /// the explicit steady-state API for callers that choose to retain one
    /// session across haystacks.
    #[must_use]
    pub fn find_iter<'s, 'h>(
        &'s mut self,
        haystack: &'h [u8],
        limits: PortableFindIterRunLimits,
    ) -> PortableSessionMatches<'s, 'r, 'h> {
        self.find_iter_with_progress(haystack, limits, EmptyMatchProgress::Byte)
    }

    pub(crate) fn find_iter_utf8<'s, 'h>(
        &'s mut self,
        haystack: &'h str,
        limits: PortableFindIterRunLimits,
    ) -> PortableSessionMatches<'s, 'r, 'h> {
        self.find_iter_with_progress(haystack.as_bytes(), limits, EmptyMatchProgress::Utf8Scalar)
    }

    fn find_iter_with_progress<'s, 'h>(
        &'s mut self,
        haystack: &'h [u8],
        limits: PortableFindIterRunLimits,
        empty_match_progress: EmptyMatchProgress,
    ) -> PortableSessionMatches<'s, 'r, 'h> {
        let fixed_predicate_cursor = self.fixed_predicate_search_cursor(haystack);
        PortableSessionMatches {
            session: self,
            state: PortableMatchIterState::new(
                haystack,
                limits,
                empty_match_progress,
                fixed_predicate_cursor,
            ),
        }
    }

    fn fixed_predicate_search_cursor<'h>(
        &self,
        haystack: &'h [u8],
    ) -> Option<FixedPredicateWord64SearchCursor<'r, 'h>> {
        match &self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.fixed_predicate_search_cursor(haystack)
            }
            PortableSearchSessionPlan::K0 { .. } => None,
        }
    }

    fn find_iter_at(
        &mut self,
        source: &mut K0SpanSourceCursor<'_>,
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, u64), SearchError> {
        match &mut self.plan {
            PortableSearchSessionPlan::Native(regex) => {
                regex.find_iter_at(source.haystack(), start, limits)
            }
            PortableSearchSessionPlan::K0 { session, .. } => {
                let report = session.search_span_at_source_cursor(source, start, limits)?;
                let work = report.accounting().work();
                let matched = report.into_output().map(|span| Match {
                    start: span.start(),
                    end: span.end(),
                });
                Ok((matched, work))
            }
        }
    }
}

/// Fallible iterator over every non-overlapping byte match.
///
/// Repeated empty matches at the previous match end are suppressed before the
/// next byte position is searched. This preserves the pinned Rust bytes
/// iterator's adjacent-empty behavior without reinterpreting anchors against
/// sliced suffixes.
#[derive(Debug)]
pub struct PortableMatches<'r, 'h> {
    session: PortableSearchSession<'r>,
    state: PortableMatchIterState<'r, 'h>,
}

/// Fallible byte-match iterator borrowing an existing search session.
///
/// The mutable borrow is held for the iterator's lifetime, preventing
/// overlapping use of the same workspace. Dropping this iterator releases the
/// session for another haystack. Unlike [`PortableMatches`], this type performs
/// no session construction and owns no workspace.
#[derive(Debug)]
pub struct PortableSessionMatches<'s, 'r, 'h> {
    session: &'s mut PortableSearchSession<'r>,
    state: PortableMatchIterState<'r, 'h>,
}

#[derive(Debug)]
enum PortableMatchIterState<'r, 'h> {
    General(PortableMatchIterCore<'h>),
    FixedPredicate {
        core: PortableMatchIterCore<'h>,
        cursor: FixedPredicateWord64SearchCursor<'r, 'h>,
    },
}

#[derive(Debug)]
struct PortableMatchIterCore<'h> {
    k0_source: K0SpanSourceCursor<'h>,
    limits: PortableFindIterRunLimits,
    empty_match_progress: EmptyMatchProgress,
    start: usize,
    last_match_end: Option<usize>,
    pending_empty_progress: bool,
    accounting: PortableFindIterAccounting,
    finished: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmptyMatchProgress {
    Byte,
    Utf8Scalar,
}

impl<'h> PortableMatchIterCore<'h> {
    const fn new(
        haystack: &'h [u8],
        limits: PortableFindIterRunLimits,
        empty_match_progress: EmptyMatchProgress,
    ) -> Self {
        Self {
            k0_source: K0SpanSourceCursor::new(haystack),
            limits,
            empty_match_progress,
            start: 0,
            last_match_end: None,
            pending_empty_progress: false,
            accounting: PortableFindIterAccounting {
                search_calls: 0,
                matches: 0,
                suppressed_empty: 0,
                work_or_linear_terms: 0,
                utf8_progress_byte_probes: 0,
                utf8_progress_work: 0,
            },
            finished: false,
        }
    }

    const fn haystack(&self) -> &'h [u8] {
        self.k0_source.haystack()
    }

    fn fail(&mut self, error: PortableFindIterError) -> Result<Match, PortableFindIterError> {
        self.finished = true;
        Err(error)
    }

    fn begin_search(&mut self) -> Result<(), PortableFindIterError> {
        let needed = self.accounting.search_calls.checked_add(1).ok_or(
            PortableFindIterError::AccountingOverflow {
                counter: "search-call",
            },
        )?;
        if needed > self.limits.max_search_calls {
            return Err(PortableFindIterError::SearchCallLimit {
                needed,
                limit: self.limits.max_search_calls,
            });
        }
        self.accounting.search_calls = needed;
        Ok(())
    }

    fn record_search_work(&mut self, work: u64) -> Result<(), PortableFindIterError> {
        self.accounting.work_or_linear_terms = self
            .accounting
            .work_or_linear_terms
            .checked_add(work)
            .ok_or(PortableFindIterError::AccountingOverflow { counter: "work" })?;
        Ok(())
    }

    fn record_utf8_progress(
        &mut self,
        byte_probes: u64,
        work: u64,
    ) -> Result<(), PortableFindIterError> {
        let next_byte_probes = self
            .accounting
            .utf8_progress_byte_probes
            .checked_add(byte_probes)
            .ok_or(PortableFindIterError::AccountingOverflow {
                counter: "utf8-progress-byte-probe",
            })?;
        let next_work = self
            .accounting
            .work_or_linear_terms
            .checked_add(work)
            .ok_or(PortableFindIterError::AccountingOverflow {
                counter: "utf8-progress-work",
            })?;
        let next_progress_work = self.accounting.utf8_progress_work.checked_add(work).ok_or(
            PortableFindIterError::AccountingOverflow {
                counter: "utf8-progress-work",
            },
        )?;
        self.accounting.utf8_progress_byte_probes = next_byte_probes;
        self.accounting.work_or_linear_terms = next_work;
        self.accounting.utf8_progress_work = next_progress_work;
        Ok(())
    }

    fn advance_past_repeated_empty(&mut self) -> Result<bool, PortableFindIterError> {
        self.accounting.suppressed_empty = self.accounting.suppressed_empty.checked_add(1).ok_or(
            PortableFindIterError::AccountingOverflow {
                counter: "suppressed-empty",
            },
        )?;
        if self.start == self.haystack().len() {
            self.finished = true;
            return Ok(true);
        }
        self.start = match self.empty_match_progress {
            EmptyMatchProgress::Byte => self.start.saturating_add(1),
            EmptyMatchProgress::Utf8Scalar => {
                // This mode is constructed only from `&str`. Starting at a
                // scalar boundary, skip its UTF-8 continuation bytes to reach
                // the next scalar boundary. Charge the initial increment,
                // every byte classification, and every continuation-byte
                // increment.
                let mut next = self.start.saturating_add(1);
                let mut byte_probes = 0_u64;
                let mut progress_work = 1_u64;
                while next < self.haystack().len() {
                    byte_probes = byte_probes.checked_add(1).ok_or(
                        PortableFindIterError::AccountingOverflow {
                            counter: "utf8-progress-byte-probe",
                        },
                    )?;
                    progress_work = progress_work.checked_add(1).ok_or(
                        PortableFindIterError::AccountingOverflow {
                            counter: "utf8-progress-work",
                        },
                    )?;
                    if (self.haystack()[next] & 0b1100_0000) != 0b1000_0000 {
                        break;
                    }
                    progress_work = progress_work.checked_add(1).ok_or(
                        PortableFindIterError::AccountingOverflow {
                            counter: "utf8-progress-work",
                        },
                    )?;
                    next = next.saturating_add(1);
                }
                self.record_utf8_progress(byte_probes, progress_work)?;
                next
            }
        };
        Ok(false)
    }

    fn advance_pending_empty(&mut self) -> Result<bool, PortableFindIterError> {
        if !self.pending_empty_progress {
            return Ok(false);
        }
        self.pending_empty_progress = false;
        // The immutable matcher, original haystack, assertion context, and
        // cursor are unchanged since the emitted empty match. Repeating the
        // same search can only select that same empty span, so suppress it
        // without another invocation and perform the standard progress step.
        self.advance_past_repeated_empty()
    }

    fn next_match_with(
        &mut self,
        mut search: impl FnMut(
            &mut K0SpanSourceCursor<'h>,
            usize,
            SearchLimits,
        ) -> Result<(Option<Match>, u64), SearchError>,
    ) -> Option<Result<Match, PortableFindIterError>> {
        while !self.finished {
            match self.advance_pending_empty() {
                Ok(false) => {}
                Ok(true) => return None,
                Err(error) => return Some(self.fail(error)),
            }
            if let Err(error) = self.begin_search() {
                return Some(self.fail(error));
            }
            let searched = search(&mut self.k0_source, self.start, self.limits.search);
            let (matched, search_work) = match searched {
                Ok(result) => result,
                Err(error) => return Some(self.fail(PortableFindIterError::Search(error))),
            };
            if let Err(error) = self.record_search_work(search_work) {
                return Some(self.fail(error));
            }
            let Some(matched) = matched else {
                self.finished = true;
                return None;
            };

            if matched.is_empty() && self.last_match_end == Some(matched.end()) {
                match self.advance_past_repeated_empty() {
                    Ok(false) => continue,
                    Ok(true) => return None,
                    Err(error) => return Some(self.fail(error)),
                }
            }

            self.start = matched.end();
            self.last_match_end = Some(matched.end());
            self.pending_empty_progress = matched.is_empty();
            let Some(emitted_count) = self.accounting.matches.checked_add(1) else {
                return Some(
                    self.fail(PortableFindIterError::AccountingOverflow { counter: "match" }),
                );
            };
            self.accounting.matches = emitted_count;
            return Some(Ok(matched));
        }
        None
    }
}

impl<'r, 'h> PortableMatchIterState<'r, 'h> {
    const fn new(
        haystack: &'h [u8],
        limits: PortableFindIterRunLimits,
        empty_match_progress: EmptyMatchProgress,
        fixed_predicate_cursor: Option<FixedPredicateWord64SearchCursor<'r, 'h>>,
    ) -> Self {
        let core = PortableMatchIterCore::new(haystack, limits, empty_match_progress);
        match fixed_predicate_cursor {
            Some(cursor) => Self::FixedPredicate { core, cursor },
            None => Self::General(core),
        }
    }

    const fn core(&self) -> &PortableMatchIterCore<'h> {
        match self {
            Self::General(core) | Self::FixedPredicate { core, .. } => core,
        }
    }

    #[cfg(test)]
    fn core_mut(&mut self) -> &mut PortableMatchIterCore<'h> {
        match self {
            Self::General(core) | Self::FixedPredicate { core, .. } => core,
        }
    }

    const fn haystack(&self) -> &'h [u8] {
        self.core().haystack()
    }

    const fn accounting(&self) -> PortableFindIterAccounting {
        self.core().accounting
    }

    #[cfg(test)]
    const fn is_fixed_predicate(&self) -> bool {
        matches!(self, Self::FixedPredicate { .. })
    }

    fn next_match(
        &mut self,
        session: &mut PortableSearchSession<'r>,
    ) -> Option<Result<Match, PortableFindIterError>> {
        match self {
            Self::General(core) => core.next_match_with(|source, start, limits| {
                session.find_iter_at(source, start, limits)
            }),
            Self::FixedPredicate { core, cursor } => {
                core.next_match_with(|_source, start, limits| {
                    let (matched, accounting) = cursor
                        .find_at(start, fixed_predicate_word64_search_limits(limits))
                        .map_err(SearchError::from)?;
                    Ok((
                        matched.map(|(start, end)| Match { start, end }),
                        accounting.actual.work,
                    ))
                })
            }
        }
    }
}

impl PortableMatches<'_, '_> {
    /// Exact counters accumulated through the most recent iterator action.
    #[must_use]
    pub const fn accounting(&self) -> PortableFindIterAccounting {
        self.state.accounting()
    }

    /// One-time K0 workspace setup facts, or `None` for native plans.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.session.workspace_setup_accounting()
    }
}

impl Iterator for PortableMatches<'_, '_> {
    type Item = Result<Match, PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.state.next_match(&mut self.session)
    }
}

impl core::iter::FusedIterator for PortableMatches<'_, '_> {}

impl PortableSessionMatches<'_, '_, '_> {
    /// Exact counters accumulated by this iterator.
    ///
    /// Every new iterator starts from zero even when the same session has
    /// already searched other haystacks.
    #[must_use]
    pub const fn accounting(&self) -> PortableFindIterAccounting {
        self.state.accounting()
    }

    /// The reused session's one-time K0 setup facts.
    ///
    /// These facts predate this iterator and are not included in
    /// [`Self::accounting`]. Native plans return `None`.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.session.workspace_setup_accounting()
    }
}

impl Iterator for PortableSessionMatches<'_, '_, '_> {
    type Item = Result<Match, PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.state.next_match(self.session)
    }
}

impl core::iter::FusedIterator for PortableSessionMatches<'_, '_, '_> {}

/// Fallible iterator over borrowed, non-overlapping byte matches.
///
/// This is the match-value projection of [`PortableMatches`]. It retains the
/// complete original haystack for [`ByteMatch::as_bytes`] while delegating all
/// search and progress state to the offset iterator.
#[derive(Debug)]
pub struct PortableByteMatches<'r, 'h> {
    inner: PortableMatches<'r, 'h>,
}

impl PortableByteMatches<'_, '_> {
    /// Exact counters accumulated through the most recent iterator action.
    #[must_use]
    pub const fn accounting(&self) -> PortableFindIterAccounting {
        self.inner.accounting()
    }

    /// One-time K0 workspace setup facts, or `None` for native plans.
    #[must_use]
    pub const fn workspace_setup_accounting(&self) -> Option<SearchSessionSetupAccounting> {
        self.inner.workspace_setup_accounting()
    }
}

impl<'h> Iterator for PortableByteMatches<'_, 'h> {
    type Item = Result<ByteMatch<'h>, PortableFindIterError>;

    fn next(&mut self) -> Option<Self::Item> {
        let haystack = self.inner.state.haystack();
        self.inner
            .next()
            .map(|result| result.map(|span| ByteMatch { haystack, span }))
    }
}

impl core::iter::FusedIterator for PortableByteMatches<'_, '_> {}

pub(crate) fn reserve_planner<T>(
    values: &mut Vec<T>,
    additional: usize,
    work: &mut u64,
    limit: u64,
    structure: &'static str,
) -> Result<(), BuildError> {
    let needed = values
        .len()
        .checked_add(additional)
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit,
        })?;
    if needed > values.capacity() {
        charge_planner(work, u64::try_from(values.len()).unwrap_or(u64::MAX), limit)?;
    }
    charge_planner(work, u64::try_from(additional).unwrap_or(u64::MAX), limit)?;
    values
        .try_reserve(additional)
        .map_err(|_| BuildError::AllocationFailed {
            structure,
            additional,
        })
}

pub(crate) fn charge_planner(work: &mut u64, amount: u64, limit: u64) -> Result<(), BuildError> {
    let needed = work
        .checked_add(amount)
        .ok_or(BuildError::PlannerWorkLimit {
            needed: u64::MAX,
            limit,
        })?;
    if needed > limit {
        return Err(BuildError::PlannerWorkLimit { needed, limit });
    }
    *work = needed;
    Ok(())
}

fn literal_limits(limits: SearchLimits) -> LiteralSearchLimits {
    LiteralSearchLimits {
        max_linear_terms: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
    }
}

fn packed_literal_set_limits(limits: SearchLimits) -> PackedLiteralSetSearchLimits {
    PackedLiteralSetSearchLimits {
        max_work: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
    }
}

fn literal_set_limits(limits: SearchLimits) -> LiteralSetSearchLimits {
    LiteralSetSearchLimits {
        max_transitions: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
    }
}

fn required_literal_limits(limits: SearchLimits) -> RequiredLiteralSearchLimits {
    RequiredLiteralSearchLimits {
        max_work_upper_bound: limits.max_work,
        max_candidate_visits: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
        max_scratch_bytes: limits.max_scratch_bytes,
    }
}

fn literal_class_run_literal_limits(limits: SearchLimits) -> LiteralClassRunLiteralSearchLimits {
    LiteralClassRunLiteralSearchLimits {
        max_work_upper_bound: limits.max_work,
        // The public facade exposes work and scratch limits only. Candidate
        // visits remain a separately metered kernel unit and must not inherit
        // a numerically unrelated work budget.
        max_candidate_visits: usize::MAX,
        max_scratch_bytes: limits.max_scratch_bytes,
    }
}

fn forward_anchored_limits(limits: SearchLimits) -> ForwardAnchoredSearchLimits {
    ForwardAnchoredSearchLimits {
        max_work_upper_bound: limits.max_work,
        max_examined_bytes_upper_bound: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
        max_scratch_bytes: limits.max_scratch_bytes,
    }
}

fn unicode_folded_literal_limits(limits: SearchLimits) -> FoldedLiteralTrieScanLimits {
    FoldedLiteralTrieScanLimits {
        max_work: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
        max_scratch_bytes: limits.max_scratch_bytes,
        ..FoldedLiteralTrieScanLimits::unlimited()
    }
}

fn fixed_predicate_word64_search_limits(limits: SearchLimits) -> FixedPredicateWord64SearchLimits {
    FixedPredicateWord64SearchLimits {
        max_work: limits.max_work,
        max_scratch_bytes: limits.max_scratch_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Automaton, BuildError, BuildLimits, CanonicalPattern, CaptureFreeOperation,
        CompatibilityProfile, GuardedLiteralSetSearchError, K0MandatoryCutPlan,
        K0MandatorySuffixPlan,
        K0NegativePrefilterOutcome, Match, OperationSemantics, PlanKind, PlanSelection,
        PortableBuilder, PortableFindIterAccounting, PortableFindIterError, PortableFindIterLimits,
        PortableFindIterRunLimits, PortablePlan, PortableRegex, SearchAccounting, SearchError,
        SearchLimits, SearchSessionLimits, SearchWindow, K0NegativePrefilterClassState,
        K0NegativePrefilterState,
        K0_NEGATIVE_PREFILTER_MAX_DISABLED_CALLS,
        K0_MANDATORY_CUT_BYTE_ENUMERATION_WORK, K0_MANDATORY_CUT_CARDINALITY_WORK,
        K0_MANDATORY_CUT_PLAN_CONSTRUCTION_WORK,
        K0_NEGATIVE_PREFILTER_PRESENT_STREAK_LIMIT, K0_NEGATIVE_PREFILTER_SIZE_CLASS_STATES,
        k0_mandatory_suffix_completed_negative_is_useful,
        observe_k0_mandatory_suffix_completed_negative, run_k0_negative_prefilter,
        try_build_k0_mandatory_cut,
    };
    use fre_automata::{MandatoryCutAnalysisLimits, MaximumConsumedDistance};
    use fre_kernels::FixedPredicateWord64SearchCursor;
    use fre_lower::UnsupportedFeature;
    use std::fmt::Write as _;

    fn lowered_k0_mandatory_cut(
        pattern: &str,
    ) -> (fre_automata::RawPlan, BuildLimits, u8) {
        let builder = PortableBuilder::new(pattern).unicode(false);
        let profile = CompatibilityProfile::RustBytes(builder.profile.clone());
        let request = fre_syntax::ParseRequest::rust(pattern, profile)
            .with_admission(builder.limits.admission)
            .with_safety_envelope(builder.limits.syntax_safety);
        let parsed = fre_syntax::parse(request)
            .expect("focused mandatory-cut pattern parses under the builder profile");
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            panic!("Rust bytes request produced a non-Rust canonical pattern");
        };
        let raw = fre_lower::lower_raw(
            &rust,
            OperationSemantics::CaptureFree,
            builder.limits.lowering,
        )
        .expect("focused mandatory-cut pattern lowers through K0")
        .into_plan();
        (
            raw,
            builder.limits,
            builder.profile.options.line_terminator,
        )
    }

    fn analyzed_k0_mandatory_cut(pattern: &str) -> (K0MandatoryCutPlan, Automaton) {
        let (raw, limits, line_terminator) = lowered_k0_mandatory_cut(pattern);
        let cut = try_build_k0_mandatory_cut(&raw, limits, 0)
            .expect("focused mandatory-cut analysis completes")
            .plan
            .expect("focused pattern retains a mandatory-cut proof");
        let automaton = Automaton::from_raw(raw, limits.lowering.automata)
            .expect("focused mandatory-cut graph validates")
            .with_line_terminator(line_terminator);
        (cut, automaton)
    }

    fn forced_k0_mandatory_cut(pattern: &str) -> K0MandatoryCutPlan {
        analyzed_k0_mandatory_cut(pattern).0
    }

    fn forced_k0_with_only_mandatory_cut(pattern: &str) -> PortableRegex {
        let (cut, automaton) = analyzed_k0_mandatory_cut(pattern);
        let mut regex = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .expect("focused mandatory-cut pattern builds through K0");
        let PortablePlan::K0(plan) = &mut regex.plan else {
            panic!("forced mandatory-cut pattern did not retain K0");
        };
        plan.automaton = automaton;
        plan.mandatory_cut = Some(cut);
        plan.mandatory_suffix = None;
        plan.negative_prefilter = None;
        regex
    }

    #[test]
    fn k0_mandatory_cut_construction_work_is_exact_and_transactional() {
        for (pattern, expected_retained_bytes) in
            [("Z", 1_u64), ("[XZ]", 2), ("[XYZ]", 3)]
        {
            let (raw, limits, _) = lowered_k0_mandatory_cut(pattern);
            let mut analysis_limits = MandatoryCutAnalysisLimits::default();
            analysis_limits.max_work = analysis_limits.max_work.min(limits.max_planner_work);
            analysis_limits.max_allocation_items = analysis_limits
                .max_allocation_items
                .min(limits.lowering.max_stack_items);
            let analysis = fre_automata::analyze_mandatory_cut(&raw, analysis_limits);
            assert!(analysis.stats().closes(analysis_limits));

            let complete = try_build_k0_mandatory_cut(&raw, limits, 0).unwrap();
            let retained_bytes = u64::from(
                complete
                    .plan
                    .expect("default work retains the mandatory-cut sidecar")
                    .bytes()
                    .1,
            );
            assert_eq!(retained_bytes, expected_retained_bytes, "pattern={pattern:?}");
            let required = analysis
                .stats()
                .work()
                .checked_add(K0_MANDATORY_CUT_CARDINALITY_WORK)
                .and_then(|work| work.checked_add(K0_MANDATORY_CUT_BYTE_ENUMERATION_WORK))
                .and_then(|work| work.checked_add(retained_bytes))
                .and_then(|work| work.checked_add(K0_MANDATORY_CUT_PLAN_CONSTRUCTION_WORK))
                .unwrap();
            assert_eq!(complete.planner_work, required, "pattern={pattern:?}");
            assert_eq!(
                complete.storage_bytes,
                core::mem::size_of::<K0MandatoryCutPlan>(),
                "pattern={pattern:?}"
            );

            let exact = try_build_k0_mandatory_cut(
                &raw,
                BuildLimits {
                    max_planner_work: required,
                    ..limits
                },
                0,
            )
            .unwrap();
            assert!(exact.plan.is_some(), "pattern={pattern:?}");
            assert_eq!(exact.planner_work, required, "pattern={pattern:?}");
            assert_eq!(
                exact.storage_bytes, complete.storage_bytes,
                "pattern={pattern:?}"
            );

            let one_below = try_build_k0_mandatory_cut(
                &raw,
                BuildLimits {
                    max_planner_work: required.checked_sub(1).unwrap(),
                    ..limits
                },
                0,
            )
            .unwrap();
            assert!(one_below.plan.is_none(), "pattern={pattern:?}");
            assert_eq!(one_below.storage_bytes, 0, "pattern={pattern:?}");
            assert_eq!(
                one_below.planner_work,
                analysis
                    .stats()
                    .work()
                    .checked_add(K0_MANDATORY_CUT_CARDINALITY_WORK)
                    .unwrap(),
                "pattern={pattern:?}"
            );
        }
    }

    #[test]
    fn k0_mandatory_cut_scan_returns_exact_sound_candidate_floors() {
        let zero = forced_k0_mandatory_cut("Z[ab]{2}");
        let small = forced_k0_mandatory_cut("[ab]{2}Z");
        let unbounded = forced_k0_mandatory_cut("[ab]+Z");
        assert_eq!(zero.maximum_before_root(), MaximumConsumedDistance::Finite(0));
        assert_eq!(small.maximum_before_root(), MaximumConsumedDistance::Finite(2));
        assert_eq!(unbounded.maximum_before_root(), MaximumConsumedDistance::Unbounded);
        for cut in [zero, small, unbounded] {
            let (bytes, count) = cut.bytes();
            assert_eq!(count, 1);
            assert_eq!(bytes[0], b'Z');
        }

        let window = SearchWindow::new(100, 1_500);
        let mut haystack = vec![b'x'; 2_048];
        haystack[99] = b'Z';
        haystack[100] = b'Z';
        haystack[1_200] = b'Z';
        let early = run_k0_negative_prefilter(
            Some(&zero),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            window,
            SearchLimits::unlimited(),
        );
        assert_eq!(early.outcome, K0NegativePrefilterOutcome::Present);
        assert_eq!(early.candidate_floor, Some(100));

        haystack[100] = b'x';
        let late = run_k0_negative_prefilter(
            Some(&zero),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            window,
            SearchLimits::unlimited(),
        );
        assert_eq!(late.candidate_floor, Some(1_200));

        haystack[101] = b'Z';
        let boundary = run_k0_negative_prefilter(
            Some(&small),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            window,
            SearchLimits::unlimited(),
        );
        assert_eq!(boundary.candidate_floor, Some(100));
        haystack[101] = b'x';
        haystack[900] = b'Z';
        let multiple = run_k0_negative_prefilter(
            Some(&small),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            window,
            SearchLimits::unlimited(),
        );
        assert_eq!(multiple.candidate_floor, Some(898));

        let unlimited_distance = run_k0_negative_prefilter(
            Some(&unbounded),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            window,
            SearchLimits::unlimited(),
        );
        assert_eq!(unlimited_distance.outcome, K0NegativePrefilterOutcome::Present);
        assert_eq!(unlimited_distance.candidate_floor, None);

        haystack[900] = b'x';
        haystack[1_200] = b'x';
        let absent = run_k0_negative_prefilter(
            Some(&small),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            window,
            SearchLimits::unlimited(),
        );
        assert_eq!(absent.outcome, K0NegativePrefilterOutcome::Absent);
        assert_eq!(absent.candidate_floor, None);
    }

    #[test]
    fn k0_mandatory_cut_floor_rescans_mutated_storage_and_preserves_outputs() {
        let cut = forced_k0_mandatory_cut("[ab]{2}Z");
        let mut haystack = vec![b'x'; 4_096];
        let address = haystack.as_ptr();
        haystack[1_500] = b'Z';
        let first = run_k0_negative_prefilter(
            Some(&cut),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            SearchWindow::full(&haystack),
            SearchLimits::unlimited(),
        );
        assert_eq!(first.candidate_floor, Some(1_498));
        haystack[1_500] = b'x';
        haystack[400] = b'Z';
        assert_eq!(haystack.as_ptr(), address);
        let second = run_k0_negative_prefilter(
            Some(&cut),
            None,
            first.state_after_success,
            &haystack,
            SearchWindow::full(&haystack),
            SearchLimits::unlimited(),
        );
        assert_eq!(second.candidate_floor, Some(398));

        let regex = forced_k0_with_only_mandatory_cut("[ab]{2}Z");
        haystack[400] = b'x';
        haystack[30..33].copy_from_slice(b"abZ");
        haystack[1_200] = b'Z';
        haystack[3_000..3_003].copy_from_slice(b"abZ");
        let window = SearchWindow::new(128, 4_000);
        let expected = regex
            .find_window(&haystack, window, SearchLimits::unlimited())
            .unwrap()
            .0;
        assert_eq!(expected, Some(Match { start: 3_000, end: 3_003 }));
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        assert_eq!(
            session
                .find_window_value(&haystack, window, SearchLimits::unlimited())
                .unwrap(),
            expected
        );
        assert!(session
            .is_match_window_value(&haystack, window, SearchLimits::unlimited())
            .unwrap());
    }

    #[test]
    fn k0_mandatory_cut_floor_bypasses_every_finite_search_limit() {
        let cut = forced_k0_mandatory_cut("[ab]{2}Z");
        let haystack = vec![b'x'; 2_048];
        let finite = SearchLimits {
            max_work: 0,
            max_scratch_bytes: usize::MAX,
        };
        let attempt = run_k0_negative_prefilter(
            Some(&cut),
            None,
            K0NegativePrefilterState::default(),
            &haystack,
            SearchWindow::full(&haystack),
            finite,
        );
        assert_eq!(attempt.outcome, K0NegativePrefilterOutcome::Bypass);
        assert_eq!(attempt.candidate_floor, None);
        assert!(attempt
            .state_after_success
            .classes
            .iter()
            .all(|class| class.window_size_class.is_none()));

        let regex = forced_k0_with_only_mandatory_cut("[ab]{2}Z");
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        assert!(matches!(
            session.find_window_value(
                &haystack,
                SearchWindow::full(&haystack),
                finite,
            ),
            Err(SearchError::K0(_))
        ));
    }

    #[test]
    fn k0_negative_prefilter_backoff_grows_and_absence_resets_it() {
        let mut state = K0NegativePrefilterClassState {
            window_size_class: Some(17),
            ..K0NegativePrefilterClassState::default()
        };
        for _ in 0..K0_NEGATIVE_PREFILTER_PRESENT_STREAK_LIMIT {
            state.observe_present();
        }
        assert_eq!(state.disabled_calls, 1);
        assert_eq!(state.present_backoff, 1);

        let mut expected = 2;
        while expected <= K0_NEGATIVE_PREFILTER_MAX_DISABLED_CALLS {
            state.disabled_calls = 0;
            state.observe_present();
            assert_eq!(state.disabled_calls, expected);
            assert_eq!(state.present_backoff, expected);
            if expected == K0_NEGATIVE_PREFILTER_MAX_DISABLED_CALLS {
                break;
            }
            expected *= 2;
        }

        state.observe_absent();
        assert_eq!(state.present_streak, 0);
        assert_eq!(state.disabled_calls, 0);
        assert_eq!(state.present_backoff, 0);
        assert_eq!(state.window_size_class, Some(17));
    }

    #[test]
    fn k0_mandatory_suffix_negative_cost_thresholds_are_exact() {
        assert!(k0_mandatory_suffix_completed_negative_is_useful(
            1_024, 7, 1_017,
        ));
        assert!(!k0_mandatory_suffix_completed_negative_is_useful(
            1_023, 7, 1_017,
        ));
        assert!(!k0_mandatory_suffix_completed_negative_is_useful(
            1_024, 8, 1_017,
        ));
        assert!(!k0_mandatory_suffix_completed_negative_is_useful(
            1_024, 7, 1_018,
        ));
        assert!(!k0_mandatory_suffix_completed_negative_is_useful(
            usize::MAX, 1, u64::MAX,
        ));
    }

    #[test]
    fn k0_mandatory_suffix_negative_learning_distinguishes_zero_cheap_and_costly() {
        let primed = K0NegativePrefilterClassState {
            present_streak: K0_NEGATIVE_PREFILTER_PRESENT_STREAK_LIMIT - 1,
            present_backoff: 8,
            next_predicate: 3,
            window_size_class: Some(14),
            ..K0NegativePrefilterClassState::default()
        };

        let mut zero_candidates = primed;
        observe_k0_mandatory_suffix_completed_negative(
            &mut zero_candidates,
            1_024,
            0,
            u64::MAX,
        );
        assert_eq!(zero_candidates.present_streak, 0);
        assert_eq!(zero_candidates.disabled_calls, 0);
        assert_eq!(zero_candidates.present_backoff, 0);
        assert_eq!(zero_candidates.next_predicate, 3);
        assert_eq!(zero_candidates.window_size_class, Some(14));

        let mut cheap_candidates = primed;
        observe_k0_mandatory_suffix_completed_negative(
            &mut cheap_candidates,
            1_024,
            7,
            1_017,
        );
        assert_eq!(cheap_candidates.present_streak, 0);
        assert_eq!(cheap_candidates.disabled_calls, 0);
        assert_eq!(cheap_candidates.present_backoff, 0);

        let mut costly_candidates = primed;
        observe_k0_mandatory_suffix_completed_negative(
            &mut costly_candidates,
            1_024,
            7,
            1_018,
        );
        assert_eq!(
            costly_candidates.present_streak,
            K0_NEGATIVE_PREFILTER_PRESENT_STREAK_LIMIT - 1,
        );
        assert_eq!(costly_candidates.disabled_calls, 16);
        assert_eq!(costly_candidates.present_backoff, 16);
        assert_eq!(costly_candidates.next_predicate, 3);
        assert_eq!(costly_candidates.window_size_class, Some(14));
    }

    #[test]
    fn k0_mandatory_suffix_rescans_same_address_after_candidate_mutation() {
        let regex = PortableBuilder::new("a.*XYZ")
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .expect("focused suffix pattern builds through K0");
        let PortablePlan::K0(plan) = &regex.plan else {
            panic!("forced suffix pattern did not retain K0");
        };
        assert_eq!(
            plan.mandatory_suffix
                .as_ref()
                .map(K0MandatorySuffixPlan::needle),
            Some(b"XYZ".as_slice()),
        );

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .expect("focused suffix session constructs");
        let mut haystack = vec![b'x'; 8_192];
        let address = haystack.as_ptr();
        let write = |source: &mut [u8], start: usize, bytes: &[u8; 3]| {
            let end = start.checked_add(bytes.len()).unwrap();
            source.get_mut(start..end).unwrap().copy_from_slice(bytes);
        };
        let mut check = |source: &[u8], expected: bool| {
            assert_eq!(
                regex
                    .is_match_value(source, SearchLimits::unlimited())
                    .unwrap(),
                expected,
            );
            assert_eq!(
                session
                    .is_match_window_value(
                        source,
                        SearchWindow::full(source),
                        SearchLimits::unlimited(),
                    )
                    .unwrap(),
                expected,
            );
        };

        check(&haystack, false);
        write(&mut haystack, 1_200, b"XYZ");
        assert_eq!(haystack.as_ptr(), address);
        check(&haystack, false);
        for position in [2_500, 5_000, 8_000] {
            write(&mut haystack, position, b"XYZ");
        }
        assert_eq!(haystack.as_ptr(), address);
        check(&haystack, false);
        for _ in 1..K0_NEGATIVE_PREFILTER_PRESENT_STREAK_LIMIT {
            check(&haystack, false);
        }

        haystack[0] = b'a';
        assert_eq!(haystack.as_ptr(), address);
        check(&haystack, true);
        for position in [1_200, 2_500, 5_000, 8_000] {
            write(&mut haystack, position, b"xxx");
        }
        assert_eq!(haystack.as_ptr(), address);
        check(&haystack, false);
        write(&mut haystack, 8_000, b"XYZ");
        assert_eq!(haystack.as_ptr(), address);
        check(&haystack, true);
    }

    #[test]
    fn k0_negative_prefilter_probes_the_longest_conjunctive_literal_first() {
        let regex = PortableBuilder::new("LONGNEEDLE.*abc")
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .expect("focused conjunctive pattern builds through K0");
        let PortablePlan::K0(plan) = &regex.plan else {
            panic!("forced conjunctive pattern did not retain K0");
        };
        let prefilter = plan
            .negative_prefilter
            .as_deref()
            .expect("focused conjunctive pattern retains a negative prefilter");
        assert_eq!(prefilter.literals.len(), 2);
        assert_eq!(prefilter.literals[0].needle(), b"LONGNEEDLE");
        assert_eq!(prefilter.literals[1].needle(), b"abc");

        let mut haystack = vec![b'x'; 4_096];
        haystack[2_000..2_003].copy_from_slice(b"abc");
        let attempt = run_k0_negative_prefilter(
            None,
            Some(prefilter),
            K0NegativePrefilterState::default(),
            &haystack,
            SearchWindow::full(&haystack),
            SearchLimits::unlimited(),
        );
        assert_eq!(attempt.outcome, K0NegativePrefilterOutcome::Absent);
    }

    #[test]
    fn k0_negative_prefilter_retains_bounded_size_class_histories() {
        let mut state = K0NegativePrefilterState::default();
        let state_count = u32::try_from(K0_NEGATIVE_PREFILTER_SIZE_CLASS_STATES).unwrap();
        for size_class in 10..10 + state_count {
            let index = state.class_for(size_class);
            state.classes[index].present_backoff = u8::try_from(size_class).unwrap();
        }
        for size_class in 10..10 + state_count {
            let index = state.class_for(size_class);
            assert_eq!(
                state.classes[index].present_backoff,
                u8::try_from(size_class).unwrap()
            );
        }

        let replacement = state.class_for(99);
        assert_eq!(replacement, 0);
        assert_eq!(state.classes[replacement].window_size_class, Some(99));
        assert_eq!(state.classes[replacement].present_backoff, 0);
        for size_class in 11..10 + state_count {
            assert!(state
                .classes
                .iter()
                .any(|entry| entry.window_size_class == Some(size_class)));
        }
    }

    #[test]
    fn utf8_progress_accounting_overflow_is_atomic() {
        let regex = PortableBuilder::new("").build().unwrap();
        let mut iterator = regex
            .find_iter_utf8("é", PortableFindIterLimits::unlimited())
            .unwrap();

        iterator.state.core_mut().accounting = PortableFindIterAccounting {
            work_or_linear_terms: u64::MAX,
            ..PortableFindIterAccounting::default()
        };
        let before = iterator.state.accounting();
        assert_eq!(
            iterator.state.core_mut().record_utf8_progress(1, 1),
            Err(PortableFindIterError::AccountingOverflow {
                counter: "utf8-progress-work",
            })
        );
        assert_eq!(iterator.state.accounting(), before);

        iterator.state.core_mut().accounting = PortableFindIterAccounting {
            utf8_progress_work: u64::MAX,
            ..PortableFindIterAccounting::default()
        };
        let before = iterator.state.accounting();
        assert_eq!(
            iterator.state.core_mut().record_utf8_progress(1, 1),
            Err(PortableFindIterError::AccountingOverflow {
                counter: "utf8-progress-work",
            })
        );
        assert_eq!(iterator.state.accounting(), before);

        iterator.state.core_mut().accounting = PortableFindIterAccounting {
            utf8_progress_byte_probes: u64::MAX,
            ..PortableFindIterAccounting::default()
        };
        let before = iterator.state.accounting();
        assert_eq!(
            iterator.state.core_mut().record_utf8_progress(1, 1),
            Err(PortableFindIterError::AccountingOverflow {
                counter: "utf8-progress-byte-probe",
            })
        );
        assert_eq!(iterator.state.accounting(), before);
    }

    #[test]
    fn facade_selects_the_certified_literal_class_run_path() {
        let regex = PortableBuilder::new("ab[0-3]+")
            .unicode(false)
            .build()
            .unwrap();
        let (matched, accounting) = regex.find(b"zzab123x", SearchLimits::unlimited()).unwrap();
        let matched = matched.unwrap();
        assert_eq!((matched.start(), matched.end()), (2, 7));
        assert!(accounting.work_or_linear_terms() > 0);
        assert_eq!(regex.build_report().plan, PlanKind::LiteralClassRunLiteral);
        assert_eq!(regex.build_report().states, 0);
        assert!(matches!(
            accounting,
            SearchAccounting::LiteralClassRunLiteral(_)
        ));
    }

    #[test]
    fn facade_selects_unicode_all_non_ascii_class_run_and_matches_upstream() {
        let pattern = r"a[^z\r\n]*z";
        let regex = PortableBuilder::new(pattern).build().unwrap();
        let upstream = regex::bytes::RegexBuilder::new(pattern).build().unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::LiteralClassRunLiteral);
        assert_eq!(regex.build_report().lowering, None);
        assert_eq!(regex.build_report().states, 0);

        for haystack in [
            b"".as_slice(),
            b"--abz--aaaz--",
            "--aé文z--aβz--".as_bytes(),
            b"a\x80z--abz--a\xC0\xAFz--aokz",
            b"a\xED\xA0\x80z--aokz--a\xF0\x9F\x92z--abz",
        ] {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let actual = regex
                .find(haystack, SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(actual, expected, "haystack={haystack:?}");
            assert_eq!(
                regex
                    .is_match(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected.is_some(),
                "haystack={haystack:?}"
            );
            assert_eq!(
                regex
                    .is_match_value(haystack, SearchLimits::unlimited())
                    .unwrap(),
                expected.is_some(),
                "value-only haystack={haystack:?}"
            );
            let mut session = regex
                .search_session(SearchSessionLimits::unlimited())
                .unwrap();
            assert_eq!(
                session
                    .is_match_value(haystack, SearchLimits::unlimited())
                    .unwrap(),
                expected.is_some(),
                "session value-only haystack={haystack:?}"
            );
            assert_eq!(
                regex
                    .shortest_match(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                upstream.shortest_match(haystack),
                "haystack={haystack:?}"
            );
            let expected_iter: Vec<_> = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            let actual_iter: Vec<_> = regex
                .find_iter(haystack, PortableFindIterLimits::unlimited())
                .unwrap()
                .map(|matched| {
                    let matched = matched.unwrap();
                    (matched.start(), matched.end())
                })
                .collect();
            assert_eq!(actual_iter, expected_iter, "haystack={haystack:?}");
            for start in 0..=haystack.len() {
                let expected_at = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let actual_at = regex
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap()
                    .0
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(
                    actual_at, expected_at,
                    "haystack={haystack:?} start={start}"
                );
                assert_eq!(
                    regex
                        .is_match_value_at(haystack, start, SearchLimits::unlimited())
                        .unwrap(),
                    expected_at.is_some(),
                    "exists haystack={haystack:?} start={start}"
                );
                assert_eq!(
                    regex
                        .shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    upstream.shortest_match_at(haystack, start),
                    "shortest haystack={haystack:?} start={start}"
                );
            }
        }
    }

    #[test]
    fn unicode_all_non_ascii_unique_exit_admits_lazy_and_plus_repeats() {
        let haystack = "--aéaaaz--a文z--a\nzzz--abz".as_bytes();
        for pattern in [
            r"a[^z\r\n]*z",
            r"a[^z\r\n]*?z",
            r"a[^z\r\n]+z",
            r"a[^z\r\n]+?z",
        ] {
            let regex = PortableBuilder::new(pattern).build().unwrap();
            let upstream = regex::bytes::RegexBuilder::new(pattern).build().unwrap();
            assert_eq!(regex.build_report().plan, PlanKind::LiteralClassRunLiteral);
            let expected: Vec<_> = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            let actual: Vec<_> = regex
                .find_iter(haystack, PortableFindIterLimits::unlimited())
                .unwrap()
                .map(|matched| {
                    let matched = matched.unwrap();
                    (matched.start(), matched.end())
                })
                .collect();
            assert_eq!(actual, expected, "pattern={pattern:?}");
            assert_eq!(
                regex
                    .is_match_value(haystack, SearchLimits::unlimited())
                    .unwrap(),
                !expected.is_empty(),
                "value-only pattern={pattern:?}"
            );
        }
    }

    #[test]
    fn exact_literals_select_the_labelled_native_kernel() {
        let regex = PortableRegex::new("Sherlock").unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::ExactLiteral);
        assert_eq!(regex.build_report().lowering, None);
        let (matched, accounting) = regex
            .find(b"zzSherlock", SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 10))
        );
        assert!(matches!(accounting, SearchAccounting::ExactLiteral(_)));

        let captured = PortableRegex::new("(Sherlock)").unwrap();
        assert_eq!(captured.build_report().plan, PlanKind::ExactLiteral);
    }

    #[test]
    fn exact_literal_plan_exhaustively_matches_the_rebar_baseline() {
        let patterns = words(3);
        let haystacks = words(5);
        for pattern in &patterns {
            let pattern = core::str::from_utf8(pattern).unwrap();
            let fre = PortableBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            assert_eq!(fre.build_report().plan, PlanKind::ExactLiteral);
            let upstream = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for haystack in &haystacks {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, _) = fre.find(haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
                let (exists, _) = fre.is_match(haystack, SearchLimits::unlimited()).unwrap();
                let (end, _) = fre
                    .selected_end(haystack, SearchLimits::unlimited())
                    .unwrap();
                assert_eq!(exists, expected.is_some());
                assert_eq!(end, expected.map(|(_, end)| end));
            }
        }
    }

    #[test]
    fn finite_languages_select_a_forced_literal_set_and_match_upstream() {
        let patterns = [
            "a|ab",
            "ab|a",
            "(?:a|b)(?:c|)",
            "[ab]c|d",
            "foobar|foobaz|fooquux",
            "(?:|a)",
        ];
        let mut haystacks = words(4);
        haystacks.push(b"foo-no-match/foobaz".to_vec());
        for pattern in patterns {
            let fre = PortableBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
            assert!(matches!(
                fre.build_report().plan,
                PlanKind::PackedLiteralSet | PlanKind::LiteralSetDfa
            ));
            let upstream = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            for haystack in &haystacks {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, accounting) = fre.find(haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}"
                );
                assert_eq!(accounting.plan(), fre.build_report().plan);
            }
        }
    }

    #[test]
    fn boundary_wrapped_finite_ascii_words_select_guarded_candidates() {
        let pattern = r"(?-u:\b(?:a|ab|cat|dog)\b)";
        let fre = PortableBuilder::new(pattern).unicode(false).build().unwrap();
        assert_eq!(fre.build_report().plan, PlanKind::PackedLiteralSet);
        assert_eq!(
            fre.runtime_implementation_id(),
            "guarded-ascii-word-literal-set.fixed-column-dictionary.v3",
        );
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let haystacks: &[&[u8]] = &[
            b"",
            b"ab",
            b"a",
            b"alphabet cat dogmatic dog",
            b"xcat catz cat",
            b"\xffcat\xff",
        ];
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, accounting) = fre
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap();
                assert_eq!(
                    actual.map(|matched| (matched.start(), matched.end())),
                    expected,
                    "haystack={haystack:?}, start={start}",
                );
                assert!(matches!(
                    accounting,
                    SearchAccounting::GuardedLiteralSet(_)
                ));
            }
        }

        let (_, SearchAccounting::GuardedLiteralSet(accounting)) = fre
            .find(b"zz dog", SearchLimits::unlimited())
            .unwrap()
        else {
            panic!("guarded route returned another accounting family");
        };
        let exact = u64::try_from(accounting.upper_bounds.total_work).unwrap();
        assert!(fre
            .find(
                b"zz dog",
                SearchLimits {
                    max_work: exact,
                    max_scratch_bytes: 0,
                },
            )
            .is_ok());
        assert!(matches!(
            fre.find(
                b"zz dog",
                SearchLimits {
                    max_work: exact - 1,
                    max_scratch_bytes: 0,
                },
            ),
            Err(SearchError::GuardedLiteralSet(
                GuardedLiteralSetSearchError::WorkLimit { .. }
            )),
        ));
    }

    #[test]
    fn directional_ascii_word_boundaries_select_the_same_guarded_plan() {
        for pattern in [
            r"(?-u:\b{start}(?:a|ab)\b{end})",
            r"(?-u:\b{start-half}(?:a|ab)\b{end-half})",
        ] {
            let fre = PortableBuilder::new(pattern).unicode(false).build().unwrap();
            assert_eq!(fre.build_report().plan, PlanKind::PackedLiteralSet);
            assert_eq!(
                fre.runtime_implementation_id(),
                "guarded-ascii-word-literal-set.fixed-column-dictionary.v3",
            );
            assert_eq!(
                fre.find_value(b"x ab y", SearchLimits::unlimited())
                    .unwrap(),
                Some(Match { start: 2, end: 4 }),
            );
        }
    }

    #[test]
    fn native_iterator_projection_matches_facade_spans_and_work() {
        let exact = PortableBuilder::new("aba").unicode(false).build().unwrap();
        let packed = PortableBuilder::new("alpha|beta|gamma")
            .unicode(false)
            .build()
            .unwrap();
        let dfa = PortableBuilder::new("alpha|beta|gamma")
            .unicode(false)
            .limits(BuildLimits {
                packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
                    max_patterns: 0,
                    ..fre_kernels::PackedLiteralSetBuildLimits::default()
                },
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert_eq!(exact.build_report().plan, PlanKind::ExactLiteral);
        assert_eq!(packed.build_report().plan, PlanKind::PackedLiteralSet);
        assert_eq!(dfa.build_report().plan, PlanKind::LiteralSetDfa);

        let haystack = b"zzalpha-beta-gamma";
        for regex in [&exact, &packed, &dfa] {
            for start in 0..=haystack.len() {
                let (expected, accounting) = regex
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap();
                let actual = regex
                    .find_iter_at(haystack, start, SearchLimits::unlimited())
                    .unwrap();
                assert_eq!(actual.0, expected);
                assert_eq!(actual.1, accounting.work_or_linear_terms());
            }
        }
    }

    #[test]
    fn fixed_predicate_iterator_cursor_has_a_bounded_inline_layout() {
        let word = core::mem::size_of::<usize>();
        let cursor = core::mem::size_of::<FixedPredicateWord64SearchCursor<'static, 'static>>();
        let state = core::mem::size_of::<super::PortableMatchIterState<'static, 'static>>();
        let general = core::mem::size_of::<super::PortableMatchIterCore<'static>>();
        let source_cursor = core::mem::size_of::<fre_automata::K0SpanSourceCursor<'static>>();

        assert_eq!(
            core::mem::align_of::<FixedPredicateWord64SearchCursor<'static, 'static>>(),
            core::mem::align_of::<usize>()
        );
        assert!(cursor <= 10 * word, "cursor grew to {cursor} bytes");
        assert!(
            state >= cursor + source_cursor,
            "fixed iterator variant lost one of its two independent source cursors"
        );
        assert!(
            general < state,
            "general iterator payload retained the fixed cursor"
        );
        assert!(
            state <= 32 * word,
            "iterator state grew beyond its inline 32-word envelope: {state} bytes"
        );
    }

    #[test]
    fn packed_ineligibility_is_resolved_before_selecting_the_dfa() {
        let limits = BuildLimits {
            packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
                max_patterns: 0,
                ..fre_kernels::PackedLiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        };
        let fre = PortableBuilder::new("foobar|foobaz|fooquux")
            .unicode(false)
            .limits(limits)
            .build()
            .unwrap();
        assert_eq!(fre.build_report().plan, PlanKind::LiteralSetDfa);
        let (matched, accounting) = fre.find(b"xxfoobaz", SearchLimits::unlimited()).unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 8))
        );
        assert!(matches!(accounting, SearchAccounting::LiteralSetDfa(_)));
    }

    #[test]
    fn finite_enumeration_cap_routes_fixed_product_before_k0_growth() {
        let limits = BuildLimits {
            literal_set: fre_kernels::LiteralSetBuildLimits {
                max_patterns: 4,
                ..fre_kernels::LiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        };
        let fre = PortableBuilder::new("[ab][cd][ef]")
            .unicode(false)
            .limits(limits)
            .build()
            .unwrap();
        assert_eq!(fre.build_report().plan, PlanKind::FixedPredicateWord64);
        let (matched, accounting) = fre.find(b"xxbcf", SearchLimits::unlimited()).unwrap();
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((2, 5))
        );
        assert!(matches!(
            accounting,
            SearchAccounting::FixedPredicateWord64(_)
        ));
    }

    #[test]
    fn fixed_predicate_iterators_retain_candidates_and_reset_after_early_drop() {
        let limits = BuildLimits {
            literal_set: fre_kernels::LiteralSetBuildLimits {
                max_patterns: 4,
                ..fre_kernels::LiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        };
        let regex = PortableBuilder::new(r"[A-D][\x00-\x7F]Q")
            .unicode(false)
            .limits(limits)
            .build()
            .unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::FixedPredicateWord64);

        let mut haystack = Vec::new();
        for _ in 0..8 {
            haystack.extend_from_slice(&[b'A', 0xff, b'Q']);
        }
        for _ in 0..64 {
            haystack.extend_from_slice(b"A!Q");
        }
        let expected_first = Match { start: 24, end: 27 };

        let mut early = regex
            .find_iter(&haystack, PortableFindIterLimits::unlimited())
            .unwrap();
        assert!(early.state.is_fixed_predicate());
        assert_eq!(early.next().unwrap().unwrap(), expected_first);
        drop(early);
        let mut restarted = regex
            .find_iter(&haystack, PortableFindIterLimits::unlimited())
            .unwrap();
        assert!(restarted.state.is_fixed_predicate());
        assert_eq!(restarted.next().unwrap().unwrap(), expected_first);
        assert_eq!(restarted.count(), 63);

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let mut session_matches =
            session.find_iter(&haystack, PortableFindIterRunLimits::unlimited());
        assert!(session_matches.state.is_fixed_predicate());
        let matches = session_matches
            .by_ref()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        drop(session_matches);
        assert_eq!(matches.len(), 64);
        assert_eq!(matches[0], expected_first);
        assert!(
            matches
                .windows(2)
                .all(|pair| pair[0].end() == pair[1].start())
        );

        let exact = PortableBuilder::new("literal")
            .unicode(false)
            .build()
            .unwrap();
        let exact_iter = exact
            .find_iter(b"literal", PortableFindIterLimits::unlimited())
            .unwrap();
        assert!(!exact_iter.state.is_fixed_predicate());
    }

    #[test]
    fn fixed_predicate_construction_failure_checks_receipt_closure_before_divergence() {
        let source = include_str!("lib.rs");
        let start = source
            .find("let attempt = match FixedPredicateWord64Plan::build_attempt(")
            .expect("fixed-predicate construction match remains explicit");
        let end = source[start..]
            .find("if !attempt.closes()")
            .expect("successful construction closure check remains explicit");
        let construction_match = &source[start..start + end];
        assert!(construction_match.contains("Err(error) =>"));
        assert!(construction_match.contains("if !error.closes()"));
        assert!(
            construction_match
                .contains("fixed-predicate search construction failure lost its attempt closure")
        );
        assert!(
            construction_match
                .contains("inspected fixed-predicate search source failed kernel construction")
        );
    }

    #[test]
    fn k0_session_retains_a_general_ascii_root_classifier() {
        let pattern = r"([0-9][0-9]?)/([0-9][0-9]?)/([0-9][0-9]([0-9][0-9])?)";
        let fre = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("bounded date shape belongs to portable K0");
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut session = fre
            .search_session(super::SearchSessionLimits::unlimited())
            .unwrap();

        let mut haystack = vec![b'x'; 4_096];
        haystack.extend_from_slice(b" 1/2/2024 tail");
        let expected = upstream
            .find(&haystack)
            .map(|matched| (matched.start(), matched.end()));
        let (actual, accounting) = session.find(&haystack, SearchLimits::unlimited()).unwrap();
        assert_eq!(
            actual.map(|matched| (matched.start(), matched.end())),
            expected
        );
        let SearchAccounting::K0(accounting) = accounting else {
            panic!("date shape should report K0 accounting");
        };
        assert!(accounting.boundaries() < 32);
    }

    #[test]
    fn forced_k0_root_run_scanner_mismatches_fall_back_to_ordinary_iteration() {
        let cases: [(&str, &[u8]); 5] = [
            ("a+", b"aa--a--aaaa"),
            ("[ab]{2,4}", b"abba--aa--bbbb"),
            ("[abc]{2}", b"ab--ca--bc"),
            ("[a-z]{2}", b"ab--cd--ef"),
            ("[0-9]+?", b"12--3--456"),
        ];

        for (pattern, haystack) in cases {
            let fre = PortableBuilder::new(pattern)
                .unicode(false)
                .plan_selection(PlanSelection::ForceK0)
                .build()
                .unwrap();
            assert_eq!(fre.build_report().plan, PlanKind::K0);
            let upstream = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            let expected: Vec<_> = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            let mut session = fre
                .search_session(super::SearchSessionLimits::unlimited())
                .unwrap();
            let actual: Result<Vec<_>, _> = session
                .find_iter(haystack, PortableFindIterRunLimits::unlimited())
                .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                .collect();
            assert_eq!(actual.unwrap(), expected, "pattern={pattern}");
        }
    }

    #[test]
    fn forced_k0_root_run_iterator_reuses_source_bound_masks_and_releases_them_on_drop() {
        let fre = PortableBuilder::new("[aceg]{2}")
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        let mut session = fre
            .search_session(super::SearchSessionLimits::unlimited())
            .unwrap();
        let dense = b"acegacegacegacegacegacegacegacegacegacegacegacegacegacegacegaceg";
        let expected: Vec<_> = (0..dense.len())
            .step_by(2)
            .map(|start| (start, start.checked_add(2).unwrap()))
            .collect();

        let fresh: Result<Vec<_>, _> = fre
            .find_iter(dense, PortableFindIterLimits::unlimited())
            .unwrap()
            .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
            .collect();
        assert_eq!(fresh.unwrap(), expected);

        {
            let mut matches = session.find_iter(dense, PortableFindIterRunLimits::unlimited());
            let first = matches.next().unwrap().unwrap();
            assert_eq!((first.start(), first.end()), (0, 2));
            let second = matches.next().unwrap().unwrap();
            assert_eq!((second.start(), second.end()), (2, 4));
            let third = matches.next().unwrap().unwrap();
            assert_eq!((third.start(), third.end()), (4, 6));
            let activated_work = matches.accounting().work_or_linear_terms;
            let fourth = matches.next().unwrap().unwrap();
            assert_eq!((fourth.start(), fourth.end()), (6, 8));
            assert_eq!(
                matches
                    .accounting()
                    .work_or_linear_terms
                    .checked_sub(activated_work)
                    .unwrap(),
                3,
                "a retained qualified-start mask needs only the K0 invocation reset"
            );
            // End the iterator borrow early; the next block must start with
            // fresh source-bound cursors while retaining the session itself.
        }

        let restarted: Result<Vec<_>, _> = session
            .find_iter(dense, PortableFindIterRunLimits::unlimited())
            .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
            .collect();
        assert_eq!(
            restarted.unwrap(),
            expected,
            "a new non-fixed K0 iterator must start with fresh source cursors after early drop"
        );

        assert_eq!(
            session
                .find(b"zzaceg", SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 4))
        );
    }

    #[test]
    fn finite_planner_work_limit_is_an_exact_preselection_boundary() {
        let pattern = "(?:ab|cd)(?:e|f)";
        let baseline = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let required = baseline.build_report().planner_work;
        assert!(required > 0);
        let exact = BuildLimits {
            max_planner_work: required,
            ..BuildLimits::default()
        };
        assert!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(exact)
                .build()
                .is_ok()
        );
        let refused = BuildLimits {
            max_planner_work: required - 1,
            ..BuildLimits::default()
        };
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(refused)
                .build(),
            Err(BuildError::PlannerWorkLimit { .. })
        ));
    }

    #[test]
    fn certified_ordered_empty_loops_build_through_k0() {
        let certified = PortableBuilder::new("(?:|a)*")
            .unicode(false)
            .build()
            .expect("empty-first nullable loop is normalized");
        assert_eq!(certified.build_report().plan, PlanKind::K0);
        assert_eq!(
            certified
                .build_report()
                .lowering
                .expect("K0 lowering report")
                .normalized_nullable_repetitions(),
            1
        );

        let consuming_first = PortableBuilder::new("(?:a|)*b")
            .unicode(false)
            .build()
            .expect("one-byte consuming-first nullable loop is normalized");
        assert_eq!(consuming_first.build_report().plan, PlanKind::K0);
        let (matched, _) = consuming_first
            .find(b"aaab", SearchLimits::unlimited())
            .expect("normalized K0 search succeeds");
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((0, 4))
        );
    }

    #[test]
    fn uncertified_nullable_loop_is_a_build_error() {
        let error = PortableBuilder::new("(?:ab|)*b")
            .unicode(false)
            .build()
            .unwrap_err();
        assert!(matches!(
            error,
            BuildError::Lower(fre_lower::LowerError::Unsupported(
                UnsupportedFeature::UncertifiedUnboundedRepetition
            ))
        ));
    }

    #[test]
    fn ranged_search_keeps_original_anchor_context() {
        let regex = PortableRegex::new("^a").unwrap();
        let (matched, _) = regex
            .find_window(b"za", SearchWindow::new(1, 2), SearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None);
    }

    #[test]
    fn guarded_suffix_inside_class_bounded_shortest_matches_earliest_oracle() {
        for (pattern, haystack) in [
            (r"\b[AB]+B\b", b"\xff!AABB!CBB!\x80".as_slice()),
            (r"\b[A-T]+T\b", b"\x80!AMTT!UT!\xff".as_slice()),
        ] {
            let regex = PortableBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            assert_eq!(
                regex.build_report().plan,
                PlanKind::LiteralClassRunLiteral,
                "{pattern:?}"
            );
            let oracle = regex::bytes::RegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            let mut bounded_windows = 0_usize;
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = oracle
                        .shortest_match_at(haystack, start)
                        .filter(|&matched_end| matched_end <= end);
                    let actual = regex
                        .shortest_match_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0;
                    assert_eq!(
                        actual, expected,
                        "pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                    );
                    bounded_windows += usize::from(end < haystack.len());
                }
            }
            assert!(bounded_windows > 0);
        }
    }

    #[test]
    fn production_routing_selects_only_the_evidence_backed_anchor_slice() {
        let selected = PortableBuilder::new("[a-z]+Z")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(selected.build_report().plan, PlanKind::RequiredLiteral);
        assert_eq!(selected.build_report().minimum_match_bytes, Some(2));
        assert!(selected.build_report().required_literal.is_some());

        for (pattern, minimum_match_bytes) in [
            ("[a-z]{3,6}TRAILER", Some(10)),
            ("[a-z]{3,}TRAILER", Some(10)),
        ] {
            let bounded = PortableBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap();
            assert_eq!(
                bounded.build_report().plan,
                PlanKind::RequiredLiteral,
                "pattern={pattern:?}"
            );
            assert_eq!(
                bounded.build_report().minimum_match_bytes,
                minimum_match_bytes,
                "pattern={pattern:?}"
            );
            assert!(bounded.build_report().required_literal.is_some());
        }

        let anchored_start = PortableBuilder::new(r"\A[a-z]+Z")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            anchored_start.build_report().plan,
            PlanKind::ForwardAnchored
        );

        let both_anchors = PortableBuilder::new(r"\A[a-z]+Z\z")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(both_anchors.build_report().plan, PlanKind::ForwardAnchored);

        let forced = PortableBuilder::new(r"\A[a-z]+Z\z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        assert_eq!(forced.build_report().plan, PlanKind::RequiredLiteral);

        let captured = PortableBuilder::new("([a-z]+Z)")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(captured.build_report().plan, PlanKind::RequiredLiteral);
    }

    #[test]
    fn forced_shape_and_theorem_refusals_are_typed() {
        assert!(matches!(
            PortableBuilder::new("[ab]*Z")
                .unicode(false)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(BuildError::RequiredLiteralShape)
        ));
        assert!(matches!(
            PortableBuilder::new("a+a")
                .unicode(false)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(BuildError::RequiredLiteral(
                fre_kernels::RequiredLiteralBuildError::FirstSuffixByteInClass { .. }
            ))
        ));
        assert!(matches!(
            PortableBuilder::new("b+aba")
                .unicode(false)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(BuildError::RequiredLiteral(
                fre_kernels::RequiredLiteralBuildError::OverlappingSuffix { .. }
            ))
        ));

        // Canonical singleton repetitions are represented as one-byte
        // classes by the structural search admission.
        let singleton_run = PortableBuilder::new("b+aba")
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            singleton_run.build_report().plan,
            PlanKind::LiteralClassRunLiteral
        );
        assert_eq!(
            singleton_run
                .find(b"ababa", SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 5))
        );
    }

    #[test]
    fn facade_propagates_exact_required_literal_resource_boundaries() {
        let baseline = PortableBuilder::new("a+Z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        let accounting = baseline.build_report().required_literal.unwrap();
        let exact_kernel = fre_kernels::RequiredLiteralBuildLimits {
            max_suffix_bytes: accounting.suffix_bytes,
            max_build_work: accounting.work_upper_bound,
            max_scratch_bytes: accounting.scratch_bytes,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
        };
        let exact = BuildLimits {
            required_literal: exact_kernel,
            ..BuildLimits::default()
        };
        assert!(
            PortableBuilder::new("a+Z")
                .unicode(false)
                .limits(exact)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build()
                .is_ok()
        );

        for limited in [
            fre_kernels::RequiredLiteralBuildLimits {
                max_suffix_bytes: accounting.suffix_bytes - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
            fre_kernels::RequiredLiteralBuildLimits {
                max_build_work: accounting.work_upper_bound - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
            fre_kernels::RequiredLiteralBuildLimits {
                max_scratch_bytes: accounting.scratch_bytes - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
            fre_kernels::RequiredLiteralBuildLimits {
                max_persistent_bytes: accounting.persistent_bytes - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
            fre_kernels::RequiredLiteralBuildLimits {
                max_peak_bytes: accounting.peak_bytes - 1,
                ..fre_kernels::RequiredLiteralBuildLimits::default()
            },
        ] {
            let limits = BuildLimits {
                required_literal: limited,
                ..BuildLimits::default()
            };
            assert!(matches!(
                PortableBuilder::new("a+Z")
                    .unicode(false)
                    .limits(limits)
                    .plan_selection(PlanSelection::ForceRequiredLiteral)
                    .build(),
                Err(BuildError::RequiredLiteral(_))
            ));
        }

        let (_, search) = baseline.find(b"aaaaZ", SearchLimits::unlimited()).unwrap();
        let SearchAccounting::RequiredLiteral(search) = search else {
            panic!("forced required-literal search changed plans")
        };
        assert!(
            baseline
                .find(
                    b"aaaaZ",
                    SearchLimits {
                        max_work: search.work_upper_bound,
                        max_scratch_bytes: search.scratch_bytes,
                    }
                )
                .is_ok()
        );
        assert!(matches!(
            baseline.find(
                b"aaaaZ",
                SearchLimits {
                    max_work: search.work_upper_bound - 1,
                    max_scratch_bytes: search.scratch_bytes,
                }
            ),
            Err(SearchError::RequiredLiteral(
                fre_kernels::RequiredLiteralSearchError::WorkLimit { .. }
            ))
        ));
        assert_eq!(baseline.build_report().plan, PlanKind::RequiredLiteral);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the routing test keeps eligibility, identity, cache identity, and exact owner accounting together"
    )]
    fn required_literal_facade_dispatch_is_confined_to_sve_ascii_classes() {
        use fre_kernels::{
            REQUIRED_LITERAL_ASCII_BACKWARD_RUN_PLAN_ID, REQUIRED_LITERAL_PLAN_ID,
            RequiredLiteralAnchors, RequiredLiteralByteClass, RequiredLiteralPlan,
            SimdDispatchContext,
        };

        let dispatch = SimdDispatchContext::capture();
        let anchors = RequiredLiteralAnchors::default();
        let ascii_class = RequiredLiteralByteClass::from_bytes(b"0_aceg");
        let ascii = PortableBuilder::new("[0_aceg]+Z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        let ascii_build = ascii
            .build_report()
            .required_literal
            .expect("forced required-literal plan retains its construction receipt");
        let eligible = RequiredLiteralPlan::run_scanner_eligible(dispatch, ascii_class);
        assert_eq!(
            matches!(&ascii.plan, PortablePlan::DispatchedRequiredLiteral(_)),
            eligible
        );
        assert_eq!(
            ascii.runtime_implementation_id(),
            if eligible {
                REQUIRED_LITERAL_ASCII_BACKWARD_RUN_PLAN_ID
            } else {
                REQUIRED_LITERAL_PLAN_ID
            }
        );
        assert_eq!(
            ascii
                .required_literal_cache_identity(
                    CaptureFreeOperation::Span,
                    SearchLimits::default(),
                )
                .unwrap()
                .plan_id,
            ascii.runtime_implementation_id()
        );
        let expected = if eligible {
            RequiredLiteralPlan::build_with_dispatch(
                dispatch,
                ascii_class,
                b"Z",
                anchors,
                fre_kernels::RequiredLiteralBuildLimits::default(),
            )
            .unwrap()
            .build_accounting()
        } else {
            RequiredLiteralPlan::build(
                ascii_class,
                b"Z",
                anchors,
                fre_kernels::RequiredLiteralBuildLimits::default(),
            )
            .unwrap()
            .build_accounting()
        };
        assert_eq!(ascii_build, expected);
        assert_eq!(
            ascii.build_report().plan_storage_bytes,
            ascii_build.persistent_bytes
        );

        let non_ascii_class = RequiredLiteralByteClass::from_bytes(&[0, 2, 4, 0x80, 0xff]);
        assert!(!RequiredLiteralPlan::run_scanner_eligible(
            dispatch,
            non_ascii_class
        ));
        let non_ascii = PortableBuilder::new(r"(?-u:[\x00\x02\x04\x80\xFF]+Z)")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        assert!(matches!(&non_ascii.plan, PortablePlan::RequiredLiteral(_)));
        assert_eq!(
            non_ascii.runtime_implementation_id(),
            REQUIRED_LITERAL_PLAN_ID
        );
        let expected = RequiredLiteralPlan::build(
            non_ascii_class,
            b"Z",
            anchors,
            fre_kernels::RequiredLiteralBuildLimits::default(),
        )
        .unwrap()
        .build_accounting();
        assert_eq!(non_ascii.build_report().required_literal, Some(expected));
        assert_eq!(
            non_ascii.build_report().plan_storage_bytes,
            expected.persistent_bytes
        );
    }

    #[test]
    fn cache_identity_stamps_profile_operation_anchors_and_every_limit() {
        let regex = PortableBuilder::new("[ab]+Z")
            .unicode(false)
            .build()
            .unwrap();
        let limits = SearchLimits::default();
        let span = regex
            .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
            .unwrap();
        assert_eq!(span.plan_id, regex.runtime_implementation_id());
        assert_eq!(
            span.repeat,
            fre_kernels::RequiredLiteralClassRepeat::one_or_more()
        );
        assert_eq!(span.build_limits, BuildLimits::default());
        assert_eq!(span.search_limits, limits);
        assert_eq!(
            span,
            regex
                .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
                .unwrap()
        );
        assert_ne!(
            span,
            regex
                .required_literal_cache_identity(CaptureFreeOperation::Exists, limits)
                .unwrap()
        );
        assert_ne!(
            span,
            regex
                .required_literal_cache_identity(
                    CaptureFreeOperation::Span,
                    SearchLimits::unlimited()
                )
                .unwrap()
        );
        let bounded = PortableBuilder::new("[ab]{2,3}Z")
            .unicode(false)
            .build()
            .unwrap()
            .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
            .unwrap();
        let other_bound = PortableBuilder::new("[ab]{2,4}Z")
            .unicode(false)
            .build()
            .unwrap()
            .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
            .unwrap();
        assert_eq!(
            bounded.repeat,
            fre_kernels::RequiredLiteralClassRepeat {
                min: 2,
                max: Some(3)
            }
        );
        assert_ne!(bounded, other_bound);
    }

    #[test]
    fn arbitrary_bytes_and_absolute_windows_reach_the_forced_facade_plan() {
        let regex = PortableBuilder::new(r"(?-u:[\x00\x80\xFF]+\x7F\xFE)")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        assert_eq!(
            regex
                .find(&[9, 0x80, 0xFF, 0x7F, 0xFE], SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 5))
        );

        let anchored = PortableBuilder::new(r"\Aa+Z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        assert_eq!(
            anchored
                .find_window(b"aaaZ", SearchWindow::new(1, 4), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
    }

    #[test]
    fn forced_facade_plan_matches_regex_1_12_4_exhaustively() {
        let alphabet = [b'a', b'b', b'Z'];
        let haystacks = byte_words(&alphabet, 6);
        let suffixes = non_empty_byte_words(&alphabet, 3);
        let mut span_comparisons = 0_usize;
        let mut operation_comparisons = 0_usize;
        for mask in 1_u8..4 {
            let class_bytes: Vec<u8> = [b'a', b'b']
                .into_iter()
                .enumerate()
                .filter_map(|(bit, byte)| (mask & (1_u8 << bit) != 0).then_some(byte))
                .collect();
            for suffix in &suffixes {
                for start in [false, true] {
                    for end in [false, true] {
                        let pattern = required_pattern(&class_bytes, suffix, start, end);
                        let fre = match PortableBuilder::new(&pattern)
                            .unicode(false)
                            .plan_selection(PlanSelection::ForceRequiredLiteral)
                            .build()
                        {
                            Ok(fre) => fre,
                            Err(BuildError::RequiredLiteral(error))
                                if error.is_semantic_refusal() =>
                            {
                                continue;
                            }
                            Err(error) => panic!("pattern={pattern:?}: {error:?}"),
                        };
                        let upstream = regex::bytes::RegexBuilder::new(&pattern)
                            .unicode(false)
                            .build()
                            .unwrap();
                        for haystack in &haystacks {
                            let expected = upstream
                                .find(haystack)
                                .map(|matched| (matched.start(), matched.end()));
                            let (actual, accounting) =
                                fre.find(haystack, SearchLimits::unlimited()).unwrap();
                            assert_eq!(accounting.plan(), PlanKind::RequiredLiteral);
                            assert_eq!(
                                actual.map(|matched| (matched.start(), matched.end())),
                                expected,
                                "pattern={pattern:?}, haystack={haystack:?}"
                            );
                            assert_eq!(
                                fre.is_match(haystack, SearchLimits::unlimited()).unwrap().0,
                                expected.is_some()
                            );
                            assert_eq!(
                                fre.selected_end(haystack, SearchLimits::unlimited())
                                    .unwrap()
                                    .0,
                                expected.map(|(_, end)| end)
                            );
                            span_comparisons = span_comparisons.saturating_add(1);
                            operation_comparisons = operation_comparisons.saturating_add(3);
                        }
                    }
                }
            }
        }
        assert_eq!(span_comparisons, 196_740);
        assert_eq!(operation_comparisons, 590_220);
    }

    #[test]
    fn bounded_required_literal_matches_upstream_across_steady_operations() {
        let haystacks = byte_words(&[b'a', b'b', b'Z', b'!'], 6);
        let mut comparisons = 0_usize;
        for quantifier in ["{1,2}", "{2}", "{2,4}", "{3,}"] {
            for start_anchor in [false, true] {
                for end_anchor in [false, true] {
                    let pattern = required_repeated_pattern(
                        b"ab",
                        quantifier,
                        b"Z",
                        start_anchor,
                        end_anchor,
                    );
                    let fre = PortableBuilder::new(&pattern)
                        .unicode(false)
                        .plan_selection(PlanSelection::ForceRequiredLiteral)
                        .build()
                        .unwrap();
                    assert_eq!(
                        fre.build_report().plan,
                        PlanKind::RequiredLiteral,
                        "pattern={pattern:?}"
                    );
                    let upstream = regex::bytes::RegexBuilder::new(&pattern)
                        .unicode(false)
                        .build()
                        .unwrap();
                    for haystack in &haystacks {
                        let expected = upstream
                            .find(haystack)
                            .map(|matched| (matched.start(), matched.end()));
                        let actual = fre
                            .find(haystack, SearchLimits::unlimited())
                            .unwrap()
                            .0
                            .map(|matched| (matched.start(), matched.end()));
                        assert_eq!(
                            actual, expected,
                            "pattern={pattern:?} haystack={haystack:?}"
                        );
                        assert_eq!(
                            fre.is_match(haystack, SearchLimits::unlimited()).unwrap().0,
                            expected.is_some(),
                            "pattern={pattern:?} haystack={haystack:?}"
                        );
                        assert_eq!(
                            fre.selected_end(haystack, SearchLimits::unlimited())
                                .unwrap()
                                .0,
                            expected.map(|(_, end)| end),
                            "pattern={pattern:?} haystack={haystack:?}"
                        );
                        assert_eq!(
                            fre.shortest_match(haystack, SearchLimits::unlimited())
                                .unwrap()
                                .0,
                            upstream.shortest_match(haystack),
                            "pattern={pattern:?} haystack={haystack:?}"
                        );
                        let expected_iter: Vec<_> = upstream
                            .find_iter(haystack)
                            .map(|matched| (matched.start(), matched.end()))
                            .collect();
                        let actual_iter: Vec<_> = fre
                            .find_iter(haystack, PortableFindIterLimits::unlimited())
                            .unwrap()
                            .map(|matched| {
                                let matched = matched.unwrap();
                                (matched.start(), matched.end())
                            })
                            .collect();
                        assert_eq!(
                            actual_iter, expected_iter,
                            "pattern={pattern:?} haystack={haystack:?}"
                        );
                        for offset in 0..=haystack.len() {
                            let expected_at = upstream
                                .find_at(haystack, offset)
                                .map(|matched| (matched.start(), matched.end()));
                            let actual_at = fre
                                .find_at(haystack, offset, SearchLimits::unlimited())
                                .unwrap()
                                .0
                                .map(|matched| (matched.start(), matched.end()));
                            assert_eq!(
                                actual_at, expected_at,
                                "pattern={pattern:?} haystack={haystack:?} offset={offset}"
                            );
                            assert_eq!(
                                fre.shortest_match_at(haystack, offset, SearchLimits::unlimited(),)
                                    .unwrap()
                                    .0,
                                upstream.shortest_match_at(haystack, offset),
                                "pattern={pattern:?} haystack={haystack:?} offset={offset}"
                            );
                            comparisons = comparisons.saturating_add(1);
                        }
                    }
                }
            }
        }
        assert!(comparisons > 500_000);
    }

    #[test]
    fn bounded_required_literal_accepts_unbordered_suffix_ending_in_class_bytes() {
        let pattern = r"(?-u:[ab]{2,4}Zab)";
        let haystack = b"__ababaZab__abZab";
        let fre = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();

        assert_eq!(fre.build_report().plan, PlanKind::RequiredLiteral);
        assert_eq!(
            fre.find(haystack, SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()))
        );
        assert_eq!(
            fre.shortest_match(haystack, SearchLimits::unlimited())
                .unwrap()
                .0,
            upstream.shortest_match(haystack)
        );
        for start in 0..=haystack.len() {
            assert_eq!(
                fre.find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap()
                    .0
                    .map(|matched| (matched.start(), matched.end())),
                upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end())),
                "start={start}"
            );
            assert_eq!(
                fre.shortest_match_at(haystack, start, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                upstream.shortest_match_at(haystack, start),
                "start={start}"
            );
        }
    }

    #[test]
    fn forced_facade_windows_match_find_at_exhaustively() {
        let alphabet = [b'a', b'Z'];
        let haystacks = byte_words(&alphabet, 4);
        let suffixes = non_empty_byte_words(&alphabet, 2);
        let mut comparisons = 0_usize;
        for suffix in &suffixes {
            for start in [false, true] {
                for end in [false, true] {
                    let pattern = required_pattern(b"a", suffix, start, end);
                    let fre = match PortableBuilder::new(&pattern)
                        .unicode(false)
                        .plan_selection(PlanSelection::ForceRequiredLiteral)
                        .build()
                    {
                        Ok(fre) => fre,
                        Err(BuildError::RequiredLiteral(error)) if error.is_semantic_refusal() => {
                            continue;
                        }
                        Err(error) => panic!("pattern={pattern:?}: {error:?}"),
                    };
                    let upstream = regex::bytes::RegexBuilder::new(&pattern)
                        .unicode(false)
                        .build()
                        .unwrap();
                    for haystack in &haystacks {
                        for window_start in 0..=haystack.len() {
                            for window_end in window_start..=haystack.len() {
                                let actual = fre
                                    .find_window(
                                        haystack,
                                        SearchWindow::new(window_start, window_end),
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .0
                                    .map(|matched| (matched.start(), matched.end()));
                                let expected = upstream
                                    .find_at(haystack, window_start)
                                    .filter(|matched| matched.end() <= window_end)
                                    .map(|matched| (matched.start(), matched.end()));
                                assert_eq!(
                                    actual, expected,
                                    "pattern={pattern:?} haystack={haystack:?} window={window_start}..{window_end}"
                                );
                                comparisons = comparisons.saturating_add(1);
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(comparisons, 2_808);
    }

    #[test]
    fn forward_candidate_keeps_distinct_identity_after_evidence_backed_promotion() {
        let pattern = r"\Ab+aba";
        let forced = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        assert_eq!(forced.build_report().plan, PlanKind::ForwardAnchored);
        assert!(forced.build_report().forward_anchored.is_some());
        assert!(forced.build_report().required_literal.is_none());
        assert_eq!(
            forced
                .find(b"bbbaba", SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 6))
        );
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .plan_selection(PlanSelection::ForceRequiredLiteral)
                .build(),
            Err(BuildError::RequiredLiteral(
                fre_kernels::RequiredLiteralBuildError::OverlappingSuffix { .. }
            ))
        ));

        assert_eq!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .build()
                .unwrap()
                .build_report()
                .plan,
            PlanKind::ForwardAnchored
        );
        assert_eq!(
            PortableBuilder::new(r"\A[ab]+?Z")
                .unicode(false)
                .build()
                .unwrap()
                .build_report()
                .plan,
            PlanKind::ForwardAnchored
        );
    }

    #[test]
    fn forward_forced_shape_theorem_and_absolute_windows_are_typed() {
        for pattern in [r"[ab]+Z", r"\A[ab]*Z", r"\A[ab]+[ZQ]"] {
            assert!(matches!(
                PortableBuilder::new(pattern)
                    .unicode(false)
                    .plan_selection(PlanSelection::ForceForwardAnchored)
                    .build(),
                Err(BuildError::ForwardAnchoredShape)
            ));
        }
        assert!(matches!(
            PortableBuilder::new(r"\Aa+a")
                .unicode(false)
                .plan_selection(PlanSelection::ForceForwardAnchored)
                .build(),
            Err(BuildError::ForwardAnchored(
                fre_kernels::ForwardAnchoredBuildError::FirstSuffixByteInClass { .. }
            ))
        ));

        let forced = PortableBuilder::new(r"\A([ab]+Z)\z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        assert_eq!(
            forced
                .find_window(b"abZ", SearchWindow::new(1, 3), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
        assert_eq!(
            forced
                .find_window(b"abZx", SearchWindow::new(0, 3), SearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
        assert!(matches!(
            forced.find_window(b"abZ", SearchWindow::new(2, 1), SearchLimits::unlimited()),
            Err(SearchError::ForwardAnchored(
                fre_kernels::ForwardAnchoredSearchError::InvalidWindow { .. }
            ))
        ));
    }

    #[test]
    fn forward_facade_propagates_exact_resource_boundaries() {
        let baseline = PortableBuilder::new(r"\A[a-z]+Zborderedaba")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let accounting = baseline.build_report().forward_anchored.unwrap();
        let exact_kernel = fre_kernels::ForwardAnchoredBuildLimits {
            max_suffix_bytes: accounting.suffix_bytes,
            max_build_work: accounting.work_upper_bound,
            max_scratch_bytes: accounting.scratch_bytes,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
        };
        let exact = BuildLimits {
            forward_anchored: exact_kernel,
            ..BuildLimits::default()
        };
        assert!(
            PortableBuilder::new(r"\A[a-z]+Zborderedaba")
                .unicode(false)
                .limits(exact)
                .plan_selection(PlanSelection::ForceForwardAnchored)
                .build()
                .is_ok()
        );
        for limited in [
            fre_kernels::ForwardAnchoredBuildLimits {
                max_suffix_bytes: accounting.suffix_bytes - 1,
                ..exact_kernel
            },
            fre_kernels::ForwardAnchoredBuildLimits {
                max_build_work: accounting.work_upper_bound - 1,
                ..exact_kernel
            },
            fre_kernels::ForwardAnchoredBuildLimits {
                max_persistent_bytes: accounting.persistent_bytes - 1,
                ..exact_kernel
            },
            fre_kernels::ForwardAnchoredBuildLimits {
                max_peak_bytes: accounting.peak_bytes - 1,
                ..exact_kernel
            },
        ] {
            let limits = BuildLimits {
                forward_anchored: limited,
                ..BuildLimits::default()
            };
            assert!(matches!(
                PortableBuilder::new(r"\A[a-z]+Zborderedaba")
                    .unicode(false)
                    .limits(limits)
                    .plan_selection(PlanSelection::ForceForwardAnchored)
                    .build(),
                Err(BuildError::ForwardAnchored(_))
            ));
        }
        assert_eq!(accounting.scratch_bytes, 0);

        let (_, search) = baseline
            .find(b"alphabetZborderedaba", SearchLimits::unlimited())
            .unwrap();
        let SearchAccounting::ForwardAnchored(search) = search else {
            panic!("forced forward plan changed identities")
        };
        assert!(
            baseline
                .find(
                    b"alphabetZborderedaba",
                    SearchLimits {
                        max_work: search.work_upper_bound,
                        max_scratch_bytes: search.scratch_bytes,
                    }
                )
                .is_ok()
        );
        assert!(matches!(
            baseline.find(
                b"alphabetZborderedaba",
                SearchLimits {
                    max_work: search.work_upper_bound - 1,
                    max_scratch_bytes: search.scratch_bytes,
                }
            ),
            Err(SearchError::ForwardAnchored(
                fre_kernels::ForwardAnchoredSearchError::ExaminedBytesLimit { .. }
                    | fre_kernels::ForwardAnchoredSearchError::WorkLimit { .. }
            ))
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the routing test keeps eligibility, identity, and exact owner accounting together"
    )]
    fn forward_facade_dispatch_is_confined_to_sve_ascii_bitsets() {
        use fre_kernels::{
            FORWARD_ANCHORED_ASCII_BITSET_RUN_PLAN_ID, FORWARD_ANCHORED_PLAN_ID,
            ForwardAnchoredAnchors, ForwardAnchoredByteClass, ForwardAnchoredPlan,
            ForwardClassImplementation, SimdDispatchContext,
        };

        let dispatch = SimdDispatchContext::capture();
        let anchors = ForwardAnchoredAnchors {
            start: true,
            end: false,
        };
        let bitset_class = ForwardAnchoredByteClass::from_bytes(b"0_aceg");
        let bitset = PortableBuilder::new(r"\A[0_aceg]+Z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let bitset_build = bitset
            .build_report()
            .forward_anchored
            .expect("forced forward plan retains its construction receipt");
        assert_eq!(
            bitset_build.implementation,
            ForwardClassImplementation::Bitset
        );
        let eligible = ForwardAnchoredPlan::run_scanner_eligible(dispatch, bitset_class);
        assert_eq!(
            matches!(&bitset.plan, PortablePlan::DispatchedForwardAnchored(_)),
            eligible
        );
        assert_eq!(
            bitset.runtime_implementation_id(),
            if eligible {
                FORWARD_ANCHORED_ASCII_BITSET_RUN_PLAN_ID
            } else {
                FORWARD_ANCHORED_PLAN_ID
            }
        );
        assert_eq!(
            bitset
                .forward_anchored_cache_identity(
                    CaptureFreeOperation::Span,
                    SearchLimits::default(),
                )
                .unwrap()
                .plan_id,
            bitset.runtime_implementation_id()
        );
        if eligible {
            let expected = ForwardAnchoredPlan::build_with_dispatch(
                dispatch,
                bitset_class,
                b"Z",
                anchors,
                fre_kernels::ForwardAnchoredBuildLimits::default(),
            )
            .unwrap();
            assert_eq!(bitset_build, expected.build_accounting());
        } else {
            let expected = ForwardAnchoredPlan::build(
                bitset_class,
                b"Z",
                anchors,
                fre_kernels::ForwardAnchoredBuildLimits::default(),
            )
            .unwrap();
            assert_eq!(bitset_build, expected.build_accounting());
        }
        assert_eq!(
            bitset.build_report().plan_storage_bytes,
            bitset_build.persistent_bytes
        );

        let established = [
            (
                r"\A[a-z]+Z",
                ForwardAnchoredByteClass::inclusive(b'a', b'z'),
                ForwardClassImplementation::InclusiveRange {
                    start: b'a',
                    end: b'z',
                },
            ),
            (
                r"\A[acegi]+Z",
                ForwardAnchoredByteClass::from_bytes(b"acegi"),
                ForwardClassImplementation::Quint {
                    first: b'a',
                    second: b'c',
                    third: b'e',
                    fourth: b'g',
                    fifth: b'i',
                },
            ),
            (
                r"(?-u:\A[\x00\x02\x04\x06\x80\xFF]+Z)",
                ForwardAnchoredByteClass::from_bytes(&[0, 2, 4, 6, 0x80, 0xff]),
                ForwardClassImplementation::Bitset,
            ),
        ];
        for (pattern, class, implementation) in established {
            assert!(!ForwardAnchoredPlan::run_scanner_eligible(dispatch, class));
            let regex = PortableBuilder::new(pattern)
                .unicode(false)
                .plan_selection(PlanSelection::ForceForwardAnchored)
                .build()
                .unwrap();
            assert!(matches!(&regex.plan, PortablePlan::ForwardAnchored(_)));
            assert_eq!(regex.runtime_implementation_id(), FORWARD_ANCHORED_PLAN_ID);
            let expected = ForwardAnchoredPlan::build(
                class,
                b"Z",
                anchors,
                fre_kernels::ForwardAnchoredBuildLimits::default(),
            )
            .unwrap()
            .build_accounting();
            assert_eq!(
                regex.build_report().forward_anchored,
                Some(expected),
                "pattern={pattern:?}"
            );
            assert_eq!(expected.implementation, implementation);
            assert_eq!(
                regex.build_report().plan_storage_bytes,
                expected.persistent_bytes
            );
        }
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "bounded fixtures exercise scanner and window boundaries"
    )]
    fn forward_ascii_bitset_facade_matches_pinned_bytes_at_run_boundaries() {
        const MEMBERS: &[u8] = b"0_aceg";
        let pattern = r"\A[0_aceg]+Z";
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::ForwardAnchored);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();

        let mut cases = Vec::new();
        for run_len in [0_usize, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 257] {
            let prefix: Vec<u8> = (0..run_len)
                .map(|index| MEMBERS[index % MEMBERS.len()])
                .collect();

            let mut success = prefix.clone();
            success.extend_from_slice(b"Ztail");
            cases.push(success);

            cases.push(prefix.clone());
            if !prefix.is_empty() {
                let mut outsider = prefix;
                outsider[run_len / 2] = b'Q';
                outsider.push(b'Z');
                cases.push(outsider);
            }
        }

        for haystack in cases {
            let expected = upstream
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end()));
            let (actual, accounting) = regex.find(&haystack, SearchLimits::unlimited()).unwrap();
            assert_eq!(
                actual.map(|matched| (matched.start(), matched.end())),
                expected,
                "haystack_len={}",
                haystack.len()
            );
            let SearchAccounting::ForwardAnchored(accounting) = accounting else {
                panic!("eligible production pattern changed plans")
            };
            assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
            assert_eq!(
                regex
                    .is_match_value(&haystack, SearchLimits::unlimited())
                    .unwrap(),
                expected.is_some()
            );
            assert_eq!(
                regex
                    .selected_end(&haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                expected.map(|(_, end)| end)
            );

            for (start, end) in [
                (0, haystack.len()),
                (usize::from(!haystack.is_empty()), haystack.len()),
                (0, haystack.len().saturating_sub(1)),
            ] {
                let actual = regex
                    .find_window(
                        &haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0
                    .map(|matched| (matched.start(), matched.end()));
                let expected = upstream
                    .find_at(&haystack, start)
                    .filter(|matched| matched.end() <= end)
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(
                    actual,
                    expected,
                    "haystack_len={} window={start}..{end}",
                    haystack.len()
                );
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
    #[test]
    #[ignore = "native release benchmark; requires OS-usable SVE"]
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "the ignored benchmark uses bounded iterations and checksum arithmetic"
    )]
    fn benchmark_forward_ascii_bitset_facade_dispatch_against_established_path() {
        use fre_kernels::{
            FORWARD_ANCHORED_ASCII_BITSET_RUN_PLAN_ID, FORWARD_ANCHORED_PLAN_ID, Feature,
            ForwardAnchoredAnchors, ForwardAnchoredByteClass, ForwardAnchoredPlan,
            SimdDispatchContext,
        };
        use std::{hint::black_box, time::Instant};

        fn measure(regex: &PortableRegex, haystack: &[u8], iterations: usize) -> f64 {
            let started = Instant::now();
            let mut checksum = 0_usize;
            for iteration in 0..iterations {
                let (matched, accounting) = black_box(regex)
                    .find(black_box(haystack), SearchLimits::unlimited())
                    .unwrap();
                checksum ^= matched.map_or(0, |matched| matched.end().rotate_left(7))
                    ^ usize::try_from(accounting.work_or_linear_terms()).unwrap_or(usize::MAX)
                    ^ iteration;
            }
            black_box(checksum);
            started.elapsed().as_secs_f64() * 1_000_000_000.0
                / f64::from(u32::try_from(iterations).unwrap())
        }

        let dispatch = SimdDispatchContext::capture();
        assert!(
            dispatch.capabilities().usable().contains(Feature::ArmSve),
            "benchmark requires OS-usable SVE"
        );
        let pattern = r"\A[0_aceg]+Z";
        let dispatched = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        assert_eq!(
            dispatched.runtime_implementation_id(),
            FORWARD_ANCHORED_ASCII_BITSET_RUN_PLAN_ID
        );

        let class = ForwardAnchoredByteClass::from_bytes(b"0_aceg");
        let legacy_plan = ForwardAnchoredPlan::build(
            class,
            b"Z",
            ForwardAnchoredAnchors {
                start: true,
                end: false,
            },
            fre_kernels::ForwardAnchoredBuildLimits::default(),
        )
        .unwrap();
        let legacy_build = legacy_plan.build_accounting();
        let mut established = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        established.plan = PortablePlan::ForwardAnchored(legacy_plan);
        established.report.forward_anchored = Some(legacy_build);
        established.report.plan_storage_bytes = legacy_build.persistent_bytes;
        established.report.charged_persistent_bytes = established
            .report
            .source_storage_bytes
            .checked_add(established.report.capture_name_storage_bytes)
            .and_then(|bytes| bytes.checked_add(legacy_build.persistent_bytes))
            .unwrap();
        assert_eq!(
            established.runtime_implementation_id(),
            FORWARD_ANCHORED_PLAN_ID
        );

        let mut haystack: Vec<u8> = b"0_aceg".iter().copied().cycle().take(65_536).collect();
        haystack.push(b'Z');
        assert_eq!(
            dispatched
                .find(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0,
            established
                .find(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0
        );
        let iterations = std::env::var("FRE_FORWARD_FACADE_BENCH_ITERS").map_or(2_000, |raw| {
            raw.parse::<usize>()
                .unwrap_or_else(|error| panic!("FRE_FORWARD_FACADE_BENCH_ITERS: {error}"))
        });
        assert!(iterations > 0 && u32::try_from(iterations).is_ok());
        let _ = measure(&dispatched, &haystack, iterations / 10 + 1);
        let _ = measure(&established, &haystack, iterations / 10 + 1);

        let mut dispatched_samples = Vec::with_capacity(8);
        let mut established_samples = Vec::with_capacity(8);
        for sample in 0..8 {
            if sample % 2 == 0 {
                dispatched_samples.push(measure(&dispatched, &haystack, iterations));
                established_samples.push(measure(&established, &haystack, iterations));
            } else {
                established_samples.push(measure(&established, &haystack, iterations));
                dispatched_samples.push(measure(&dispatched, &haystack, iterations));
            }
        }
        dispatched_samples.sort_by(f64::total_cmp);
        established_samples.sort_by(f64::total_cmp);
        let dispatched_ns = dispatched_samples[dispatched_samples.len() / 2];
        let established_ns = established_samples[established_samples.len() / 2];
        eprintln!(
            "forward-ascii-bitset-facade: dispatched={dispatched_ns:.3}ns established={established_ns:.3}ns speedup={:.3}x",
            established_ns / dispatched_ns
        );
    }

    #[test]
    fn forward_cache_identity_is_complete_and_not_required_literal_identity() {
        let regex = PortableBuilder::new(r"\A[a-z]+Z\z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let limits = SearchLimits::default();
        let span = regex
            .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
            .unwrap();
        assert_eq!(span.plan_id, fre_kernels::ABSOLUTE_END_FIXED_PLAN_ID);
        assert_eq!(span.build_limits, BuildLimits::default());
        assert_eq!(span.search_limits, limits);
        assert_eq!(
            span,
            regex
                .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
                .unwrap()
        );
        assert_ne!(
            span,
            regex
                .forward_anchored_cache_identity(CaptureFreeOperation::Exists, limits)
                .unwrap()
        );
        assert!(
            regex
                .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
                .is_none()
        );
    }

    #[test]
    fn runtime_implementation_identity_tracks_cache_bound_strategy_variants() {
        let pattern = r"\A[a-z]+Z";
        let limits = SearchLimits::default();
        let forward = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let required = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();

        let forward_id = forward.runtime_implementation_id();
        let required_id = required.runtime_implementation_id();
        assert_eq!(forward.build_report().plan, PlanKind::ForwardAnchored);
        assert_eq!(required.build_report().plan, PlanKind::RequiredLiteral);
        assert_eq!(
            forward_id,
            forward
                .forward_anchored_cache_identity(CaptureFreeOperation::Span, limits)
                .unwrap()
                .plan_id
        );
        assert_eq!(
            required_id,
            required
                .required_literal_cache_identity(CaptureFreeOperation::Span, limits)
                .unwrap()
                .plan_id
        );
        assert_ne!(forward_id, required_id);
    }

    #[test]
    fn equality5_short_middle_runtime_identity_rejects_stale_forward_family_labels() {
        const EQUALITY5_ID: &str = "anchored-class-suffix.single-candidate32-65536-equality32-pair-candidate16-4096-neon16-swar8-tail-extension4097-65536-cold-entry-triple-candidate-swar8x4-cold-recovery32-range-swar1-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-bitset-prefix31-inline.v23";
        const STALE_ES8I_ID: &str = "anchored-class-suffix.asymmetric-scalar8-reverse32-inline.v1";
        const STALE_FORWARD_ID: &str = "anchored-class-suffix.forward.v1";

        assert_eq!(fre_kernels::FORWARD_ANCHORED_PLAN_ID, EQUALITY5_ID);
        let forward = PortableBuilder::new(r"\A[a-z]+Z")
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        assert_eq!(forward.runtime_implementation_id(), EQUALITY5_ID);
        assert_ne!(forward.runtime_implementation_id(), STALE_ES8I_ID);
        assert_ne!(forward.runtime_implementation_id(), STALE_FORWARD_ID);
    }

    #[test]
    fn forward_forced_facade_matches_regex_1_12_4_exhaustively() {
        let alphabet = [0_u8, 1, 2];
        let haystacks = byte_words(&alphabet, 6);
        let suffixes = non_empty_byte_words(&alphabet, 3);
        let mut span_comparisons = 0_usize;
        let mut operation_comparisons = 0_usize;
        for mask in 1_u8..8 {
            let class_bytes: Vec<u8> = alphabet
                .into_iter()
                .enumerate()
                .filter_map(|(bit, byte)| (mask & (1_u8 << bit) != 0).then_some(byte))
                .collect();
            for suffix in &suffixes {
                if class_bytes.contains(&suffix[0]) {
                    continue;
                }
                for lazy in [false, true] {
                    for end in [false, true] {
                        let pattern = forward_pattern(&class_bytes, suffix, lazy, end);
                        let fre = PortableBuilder::new(&pattern)
                            .unicode(false)
                            .plan_selection(PlanSelection::ForceForwardAnchored)
                            .build()
                            .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error:?}"));
                        let upstream = regex::bytes::RegexBuilder::new(&pattern)
                            .unicode(false)
                            .build()
                            .unwrap();
                        for haystack in &haystacks {
                            let expected = upstream
                                .find(haystack)
                                .map(|matched| (matched.start(), matched.end()));
                            let (actual, accounting) =
                                fre.find(haystack, SearchLimits::unlimited()).unwrap();
                            assert_eq!(accounting.plan(), PlanKind::ForwardAnchored);
                            assert_eq!(
                                actual.map(|matched| (matched.start(), matched.end())),
                                expected,
                                "pattern={pattern:?}, haystack={haystack:?}"
                            );
                            assert_eq!(
                                fre.is_match(haystack, SearchLimits::unlimited()).unwrap().0,
                                expected.is_some()
                            );
                            assert_eq!(
                                fre.selected_end(haystack, SearchLimits::unlimited())
                                    .unwrap()
                                    .0,
                                expected.map(|(_, end)| end)
                            );
                            span_comparisons += 1;
                            operation_comparisons += 3;
                        }
                    }
                }
            }
        }
        assert_eq!(span_comparisons, 511_524);
        assert_eq!(operation_comparisons, 1_534_572);
    }

    #[test]
    fn forward_forced_windows_match_find_at_exhaustively() {
        let alphabet = [b'a', b'b', b'Z'];
        let haystacks = byte_words(&alphabet, 4);
        let suffixes = non_empty_byte_words(&alphabet, 2);
        let mut comparisons = 0_usize;
        for suffix in &suffixes {
            if suffix[0] == b'a' {
                continue;
            }
            for lazy in [false, true] {
                for end in [false, true] {
                    let pattern = forward_pattern(b"a", suffix, lazy, end);
                    let fre = PortableBuilder::new(&pattern)
                        .unicode(false)
                        .plan_selection(PlanSelection::ForceForwardAnchored)
                        .build()
                        .unwrap();
                    let upstream = regex::bytes::RegexBuilder::new(&pattern)
                        .unicode(false)
                        .build()
                        .unwrap();
                    for haystack in &haystacks {
                        for window_start in 0..=haystack.len() {
                            for window_end in window_start..=haystack.len() {
                                let actual = fre
                                    .find_window(
                                        haystack,
                                        SearchWindow::new(window_start, window_end),
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .0
                                    .map(|matched| (matched.start(), matched.end()));
                                let expected = upstream
                                    .find_at(haystack, window_start)
                                    .filter(|matched| matched.end() <= window_end)
                                    .map(|matched| (matched.start(), matched.end()));
                                assert_eq!(
                                    actual, expected,
                                    "pattern={pattern:?} haystack={haystack:?} window={window_start}..{window_end}"
                                );
                                comparisons += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(comparisons, 49_568);
    }

    #[test]
    fn forward_arbitrary_bytes_captures_and_existing_plan_overlap_are_exact() {
        let pattern = r"(?-u:\A([\x00\x80\xFF]+)\x7F\xFE\z)";
        let forward = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let haystack = [0, 0x80, 0xFF, 0x7F, 0xFE];
        assert_eq!(
            forward
                .find(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 5))
        );

        let unbordered = r"\A[a-z]+Z";
        let forward = PortableBuilder::new(unbordered)
            .unicode(false)
            .plan_selection(PlanSelection::ForceForwardAnchored)
            .build()
            .unwrap();
        let required = PortableBuilder::new(unbordered)
            .unicode(false)
            .plan_selection(PlanSelection::ForceRequiredLiteral)
            .build()
            .unwrap();
        for haystack in [
            b"".as_slice(),
            b"a".as_slice(),
            b"Z".as_slice(),
            b"abcZ".as_slice(),
            b"abcQ".as_slice(),
            b"abcZZ".as_slice(),
        ] {
            let forward_match = forward.find(haystack, SearchLimits::unlimited()).unwrap().0;
            let required_match = required
                .find(haystack, SearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(forward_match, required_match, "haystack={haystack:?}");
        }
    }

    fn forward_pattern(class: &[u8], suffix: &[u8], lazy: bool, end: bool) -> String {
        let mut pattern = String::from(r"(?-u:\A[");
        for &byte in class {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        pattern.push_str("]+");
        if lazy {
            pattern.push('?');
        }
        for &byte in suffix {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        if end {
            pattern.push_str(r"\z");
        }
        pattern.push(')');
        pattern
    }

    fn required_pattern(class: &[u8], suffix: &[u8], start: bool, end: bool) -> String {
        let mut pattern = String::from("(?-u:");
        if start {
            pattern.push_str(r"\A");
        }
        pattern.push('[');
        for &byte in class {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        pattern.push_str("]+");
        for &byte in suffix {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        if end {
            pattern.push_str(r"\z");
        }
        pattern.push(')');
        pattern
    }

    fn required_repeated_pattern(
        class: &[u8],
        quantifier: &str,
        suffix: &[u8],
        start: bool,
        end: bool,
    ) -> String {
        let mut pattern = String::from("(?-u:");
        if start {
            pattern.push_str(r"\A");
        }
        pattern.push('[');
        for &byte in class {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        pattern.push(']');
        pattern.push_str(quantifier);
        for &byte in suffix {
            write!(pattern, r"\x{byte:02X}").unwrap();
        }
        if end {
            pattern.push_str(r"\z");
        }
        pattern.push(')');
        pattern
    }

    fn byte_words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        all
    }

    fn non_empty_byte_words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        byte_words(alphabet, max_len)
            .into_iter()
            .filter(|word| !word.is_empty())
            .collect()
    }

    fn words(max_len: usize) -> Vec<Vec<u8>> {
        let mut words = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in frontier {
                for byte in [b'a', b'b', b'c'] {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            words.extend(next.iter().cloned());
            frontier = next;
        }
        words
    }
}
