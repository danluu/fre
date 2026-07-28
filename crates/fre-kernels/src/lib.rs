//! Bounded operation-specific native kernels below the FRE planner.
//!
//! The first plan is an exact-literal substring search backed by `memchr`'s
//! native/SIMD-aware `memmem::Finder`. It is a shared native primitive, not a
//! pattern-specialized JIT. The dependency documents worst-case
//! `O(needle.len() + haystack.len())` time and constant search space.

#![forbid(unsafe_code)]

use core::fmt;

use fre_exact_alloc::CopyError;
use fre_kernel_ir::CheckedSearchWindow;
use memchr::memmem::{Finder, FinderBuilder};

pub use fre_simd_kernels::{
    ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier,
    AsciiByteSetRunScanner, AsciiSelection, AsciiWordSpaceClassifier, AsciiWordSpaceMasks16,
    AsciiWordSpaceMasks32, DispatchPolicy, DispatchProfile, Feature, FeatureSet, SelectionReceipt,
    SimdDispatchContext, TuningClass, UnsupportedRequiredFeatures, dispatch_profile,
};

mod anchored_line_capture;
mod blocking_delimiter;
mod bounded_class_sequence;
mod bounded_context;
mod bounded_literal_pair;
mod bounded_separated_fields;
mod byte_candidate_stream;
mod byte_start_map;
mod determinize_state_codec;
mod direct_build_attempt;
mod fixed_absolute_domain;
mod fixed_class_sandwich;
mod fixed_predicate_word64;
mod folded_literal_trie;
mod forward_anchored;
mod grapheme_scalar_dfa;
mod literal_aggregate;
mod literal_anchor;
mod literal_assertions;
mod literal_class_run_literal;
mod literal_set;
mod ordered_literal_aggregate;
mod packed_literal_set;
mod packed_ordered_literal_aggregate;
mod prefix_class_alternation;
mod required_internal_anchor;
mod required_literal;
mod sparse_ordered_literal_aggregate;
mod token_phrase;
mod unicode_scalar_aggregate;
mod url_aggregate;

pub use direct_build_attempt::{
    DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError,
};

pub use anchored_line_capture::{
    AnchoredLineCapturePlan, Atom as AnchoredLineCaptureAtom,
    BuildAccounting as AnchoredLineCaptureBuildAccounting,
    BuildError as AnchoredLineCaptureBuildError, BuildLimits as AnchoredLineCaptureBuildLimits,
    ByteMask as AnchoredLineCaptureByteMask,
    COUNT_OPERATION_ID as ANCHORED_LINE_CAPTURE_COUNT_OPERATION_ID,
    CountResult as AnchoredLineCaptureCountResult, MAX_ATOMS as ANCHORED_LINE_CAPTURE_MAX_ATOMS,
    OperationIdentity as AnchoredLineCaptureOperationIdentity,
    PLAN_ID as ANCHORED_LINE_CAPTURE_PLAN_ID, RunActual as AnchoredLineCaptureRunActual,
    RunError as AnchoredLineCaptureRunError, RunLimits as AnchoredLineCaptureRunLimits,
    RunUpperBounds as AnchoredLineCaptureRunUpperBounds,
};

pub use bounded_class_sequence::{
    BoundedClassSequencePlan, BuildAccounting as BoundedClassSequenceBuildAccounting,
    BuildError as BoundedClassSequenceBuildError, BuildLimits as BoundedClassSequenceBuildLimits,
    COUNT_OPERATION_ID as BOUNDED_CLASS_SEQUENCE_COUNT_OPERATION_ID,
    CountResult as BoundedClassSequenceCountResult,
    OperationIdentity as BoundedClassSequenceOperationIdentity,
    PLAN_ID as BOUNDED_CLASS_SEQUENCE_PLAN_ID,
    ReduceAccounting as BoundedClassSequenceReduceAccounting,
    ReduceActualCounters as BoundedClassSequenceActualCounters,
    ReduceError as BoundedClassSequenceReduceError,
    ReduceLimits as BoundedClassSequenceReduceLimits,
    ReduceUpperBounds as BoundedClassSequenceUpperBounds,
};

pub use bounded_context::{
    BOUNDED_AFFIX_PLAN_ID, BoundedContextPlan, BuildAccounting as BoundedContextBuildAccounting,
    BuildError as BoundedContextBuildError, BuildLimits as BoundedContextBuildLimits,
    COUNT_OPERATION_ID as BOUNDED_CONTEXT_COUNT_OPERATION_ID,
    CountResult as BoundedContextCountResult, OperationIdentity as BoundedContextOperationIdentity,
    PLAN_ID as BOUNDED_CONTEXT_PLAN_ID, ReduceAccounting as BoundedContextReduceAccounting,
    ReduceActualCounters as BoundedContextActualCounters, ReduceError as BoundedContextReduceError,
    ReduceLimits as BoundedContextReduceLimits, ReduceUpperBounds as BoundedContextUpperBounds,
    SPAN_SUM_OPERATION_ID as BOUNDED_CONTEXT_SPAN_SUM_OPERATION_ID,
    SpanSumAccounting as BoundedContextSpanSumAccounting,
    SpanSumActualCounters as BoundedContextSpanSumActualCounters,
    SpanSumLimits as BoundedContextSpanSumLimits, SpanSumResult as BoundedContextSpanSumResult,
    SpanSumUpperBounds as BoundedContextSpanSumUpperBounds,
};
pub use bounded_literal_pair::{
    BoundedLiteralPairPlan, BuildAccounting as BoundedLiteralPairBuildAccounting,
    BuildError as BoundedLiteralPairBuildError, BuildLimits as BoundedLiteralPairBuildLimits,
    COUNT_OPERATION_ID as BOUNDED_LITERAL_PAIR_COUNT_OPERATION_ID,
    CountResult as BoundedLiteralPairCountResult,
    OperationIdentity as BoundedLiteralPairOperationIdentity,
    PLAN_ID as BOUNDED_LITERAL_PAIR_PLAN_ID,
    ReduceAccounting as BoundedLiteralPairReduceAccounting,
    ReduceActualCounters as BoundedLiteralPairActualCounters,
    ReduceError as BoundedLiteralPairReduceError, ReduceLimits as BoundedLiteralPairReduceLimits,
    ReduceUpperBounds as BoundedLiteralPairUpperBounds,
    SPAN_SUM_OPERATION_ID as BOUNDED_LITERAL_PAIR_SPAN_SUM_OPERATION_ID,
    SpanSumResult as BoundedLiteralPairSpanSumResult, Topology as BoundedLiteralPairTopology,
};
pub use bounded_separated_fields::{
    AlternativeSource as BoundedSeparatedFieldsAlternativeSource,
    AtomSource as BoundedSeparatedFieldsAtomSource, BoundedSeparatedFieldsPlan,
    BuildAccounting as BoundedSeparatedFieldsBuildAccounting,
    BuildError as BoundedSeparatedFieldsBuildError,
    BuildLimits as BoundedSeparatedFieldsBuildLimits,
    COUNT_OPERATION_ID as BOUNDED_SEPARATED_FIELDS_COUNT_OPERATION_ID,
    CountResult as BoundedSeparatedFieldsCountResult,
    FieldSource as BoundedSeparatedFieldsFieldSource,
    MAX_ALTERNATIVES as BOUNDED_SEPARATED_FIELDS_MAX_ALTERNATIVES,
    MAX_ATOMS as BOUNDED_SEPARATED_FIELDS_MAX_ATOMS,
    MAX_FIELDS as BOUNDED_SEPARATED_FIELDS_MAX_FIELDS,
    OperationIdentity as BoundedSeparatedFieldsOperationIdentity,
    PLAN_ID as BOUNDED_SEPARATED_FIELDS_PLAN_ID,
    ReduceAccounting as BoundedSeparatedFieldsReduceAccounting,
    ReduceActualCounters as BoundedSeparatedFieldsActualCounters,
    ReduceError as BoundedSeparatedFieldsReduceError,
    ReduceLimits as BoundedSeparatedFieldsReduceLimits,
    ReduceUpperBounds as BoundedSeparatedFieldsUpperBounds,
};

pub use blocking_delimiter::{
    BlockingDelimiterPlan, BuildAccounting as BlockingDelimiterBuildAccounting,
    BuildError as BlockingDelimiterBuildError, BuildLimits as BlockingDelimiterBuildLimits,
    COUNT_OPERATION_ID as BLOCKING_DELIMITER_COUNT_OPERATION_ID,
    CountResult as BlockingDelimiterCountResult,
    OperationIdentity as BlockingDelimiterOperationIdentity, PLAN_ID as BLOCKING_DELIMITER_PLAN_ID,
    ReduceAccounting as BlockingDelimiterReduceAccounting,
    ReduceActualCounters as BlockingDelimiterActualCounters,
    ReduceError as BlockingDelimiterReduceError, ReduceLimits as BlockingDelimiterReduceLimits,
    ReduceUpperBounds as BlockingDelimiterUpperBounds,
    SPAN_SUM_OPERATION_ID as BLOCKING_DELIMITER_SPAN_SUM_OPERATION_ID,
    SpanSumResult as BlockingDelimiterSpanSumResult, Topology as BlockingDelimiterTopology,
};
pub use byte_candidate_stream::{
    Algorithm as ByteCandidateAlgorithm, BuildAccounting as ByteCandidateBuildAccounting,
    BuildAttempt as ByteCandidateBuildAttempt, BuildError as ByteCandidateBuildError,
    BuildLimits as ByteCandidateBuildLimits, BuildResource as ByteCandidateBuildResource,
    ByteCandidatePlan, DenseFallback as ByteCandidateDenseFallback,
    DenseFallbackReason as ByteCandidateDenseFallbackReason, PLAN_ID as BYTE_CANDIDATE_PLAN_ID,
    ScanActual as ByteCandidateScanActual, ScanAttemptError as ByteCandidateScanAttemptError,
    ScanError as ByteCandidateScanError, ScanLimits as ByteCandidateScanLimits,
    ScanReceipt as ByteCandidateScanReceipt, ScanResource as ByteCandidateScanResource,
    ScanUpperBounds as ByteCandidateScanUpperBounds,
};
pub use byte_start_map::{
    BuildAccounting as ByteStartMapBuildAccounting, BuildError as ByteStartMapBuildError,
    BuildLimits as ByteStartMapBuildLimits, ByteStartMap, Direction as ByteStartDirection,
    LookupAccounting as ByteStartMapLookupAccounting, LookupError as ByteStartMapLookupError,
    LookupLimits as ByteStartMapLookupLimits, LookupResult as ByteStartMapLookupResult,
    PLAN_ID as BYTE_START_MAP_PLAN_ID, Resource as ByteStartMapResource,
    StartClass as ByteStartClass,
};
pub use determinize_state_codec::{
    Accounting as DeterminizeStateCodecAccounting, Decoded as DeterminizeStateDecoded,
    Error as DeterminizeStateCodecError, Limits as DeterminizeStateCodecLimits,
    MAX_ENCODED_BYTES as DETERMINIZE_STATE_MAX_ENCODED_BYTES,
    PLAN_ID as DETERMINIZE_STATE_CODEC_PLAN_ID, Resource as DeterminizeStateCodecResource,
    decode_i32 as decode_determinize_state_i32,
    decode_requirements as determinize_state_decode_requirements,
    decode_u32 as decode_determinize_state_u32, encode_i32 as encode_determinize_state_i32,
    encode_requirements as determinize_state_encode_requirements,
    encode_u32 as encode_determinize_state_u32, encoded_len as determinize_state_encoded_len,
};
pub use fixed_absolute_domain::{
    ACCOUNTING_VERSION as FIXED_ABSOLUTE_DOMAIN_ACCOUNTING_VERSION,
    ALGORITHM_VERSION as FIXED_ABSOLUTE_DOMAIN_ALGORITHM_VERSION,
    Admission as FixedAbsoluteDomainAdmission,
    BuildAccounting as FixedAbsoluteDomainBuildAccounting,
    BuildActual as FixedAbsoluteDomainBuildActual, BuildError as FixedAbsoluteDomainBuildError,
    BuildErrorKind as FixedAbsoluteDomainBuildErrorKind,
    BuildLimits as FixedAbsoluteDomainBuildLimits,
    BuildProspective as FixedAbsoluteDomainBuildProspective,
    BuildResource as FixedAbsoluteDomainBuildResource, ByteMask as FixedAbsoluteDomainByteMask,
    COUNT_OPERATION_ID as FIXED_ABSOLUTE_DOMAIN_COUNT_OPERATION_ID,
    ContentDigest as FixedAbsoluteDomainContentDigest,
    CountOutcome as FixedAbsoluteDomainCountOutcome, CountResult as FixedAbsoluteDomainCountResult,
    DeclaredResidual as FixedAbsoluteDomainResidual,
    DescriptorIdentity as FixedAbsoluteDomainDescriptorIdentity,
    DescriptorKind as FixedAbsoluteDomainDescriptorKind,
    Disposition as FixedAbsoluteDomainDisposition, FixedAbsoluteDomainPlan,
    Operation as FixedAbsoluteDomainOperation,
    OperationIdentity as FixedAbsoluteDomainOperationIdentity,
    PLAN_ID as FIXED_ABSOLUTE_DOMAIN_PLAN_ID,
    ReduceAccounting as FixedAbsoluteDomainReduceAccounting,
    ReduceActual as FixedAbsoluteDomainActual, ReduceError as FixedAbsoluteDomainReduceError,
    ReduceErrorKind as FixedAbsoluteDomainReduceErrorKind,
    ReduceFailureReceipt as FixedAbsoluteDomainReduceFailureReceipt,
    ReduceLimits as FixedAbsoluteDomainReduceLimits,
    ReduceProspective as FixedAbsoluteDomainProspective,
    ReduceResource as FixedAbsoluteDomainReduceResource,
    SPAN_SUM_OPERATION_ID as FIXED_ABSOLUTE_DOMAIN_SPAN_SUM_OPERATION_ID,
    SpanSumResult as FixedAbsoluteDomainSpanSumResult,
};
pub use fixed_class_sandwich::{
    BuildAccounting as FixedClassSandwichBuildAccounting,
    BuildError as FixedClassSandwichBuildError, BuildLimits as FixedClassSandwichBuildLimits,
    COUNT_OPERATION_ID as FIXED_CLASS_SANDWICH_COUNT_OPERATION_ID,
    CountResult as FixedClassSandwichCountResult, FixedClassSandwichPlan,
    Operation as FixedClassSandwichOperation,
    OperationIdentity as FixedClassSandwichOperationIdentity,
    PLAN_ID as FIXED_CLASS_SANDWICH_PLAN_ID,
    ReduceAccounting as FixedClassSandwichReduceAccounting,
    ReduceActualCounters as FixedClassSandwichActualCounters,
    ReduceError as FixedClassSandwichReduceError, ReduceLimits as FixedClassSandwichReduceLimits,
    ReduceUpperBounds as FixedClassSandwichUpperBounds,
    SPAN_SUM_OPERATION_ID as FIXED_CLASS_SANDWICH_SPAN_SUM_OPERATION_ID,
    Semantics as FixedClassSandwichSemantics, SpanSumResult as FixedClassSandwichSpanSumResult,
};
pub use fixed_predicate_word64::{
    BUILD_ATTEMPT_ACCOUNTING_VERSION as FIXED_PREDICATE_WORD64_BUILD_ATTEMPT_ACCOUNTING_VERSION,
    BUILD_ATTEMPT_ALGORITHM_VERSION as FIXED_PREDICATE_WORD64_BUILD_ATTEMPT_ALGORITHM_VERSION,
    BuildAccounting as FixedPredicateWord64BuildAccounting,
    BuildAttempt as FixedPredicateWord64BuildAttempt,
    BuildAttemptActual as FixedPredicateWord64BuildAttemptActual,
    BuildAttemptError as FixedPredicateWord64BuildAttemptError,
    BuildAttemptIdentity as FixedPredicateWord64BuildAttemptIdentity,
    BuildAttemptReceipt as FixedPredicateWord64BuildAttemptReceipt,
    BuildError as FixedPredicateWord64BuildError, BuildLimits as FixedPredicateWord64BuildLimits,
    COUNT_OPERATION_ID as FIXED_PREDICATE_WORD64_COUNT_OPERATION_ID,
    CountResult as FixedPredicateWord64CountResult, FixedPredicateWord64Plan,
    MASK_SLOTS as FIXED_PREDICATE_WORD64_MASK_SLOTS, MAX_WIDTH as FIXED_PREDICATE_WORD64_MAX_WIDTH,
    MIN_WIDTH as FIXED_PREDICATE_WORD64_MIN_WIDTH,
    MatchSelection as FixedPredicateWord64MatchSelection,
    MatchSemantics as FixedPredicateWord64MatchSemantics,
    Operation as FixedPredicateWord64Operation,
    OperationIdentity as FixedPredicateWord64OperationIdentity,
    PLAN_ID as FIXED_PREDICATE_WORD64_PLAN_ID,
    ReduceAccounting as FixedPredicateWord64ReduceAccounting,
    ReduceActualCounters as FixedPredicateWord64ActualCounters,
    ReduceError as FixedPredicateWord64ReduceError,
    ReduceLimits as FixedPredicateWord64ReduceLimits,
    ReduceUpperBounds as FixedPredicateWord64UpperBounds,
    SPAN_SUM_OPERATION_ID as FIXED_PREDICATE_WORD64_SPAN_SUM_OPERATION_ID,
    SpanSumResult as FixedPredicateWord64SpanSumResult,
};
pub use folded_literal_trie::{
    BuildAccounting as FoldedLiteralTrieBuildAccounting,
    BuildAttempt as FoldedLiteralTrieBuildAttempt, BuildError as FoldedLiteralTrieBuildError,
    BuildLimits as FoldedLiteralTrieBuildLimits, BuildResource as FoldedLiteralTrieBuildResource,
    DenseFallback as FoldedLiteralTrieDenseFallback,
    DenseFallbackReason as FoldedLiteralTrieDenseFallbackReason, FoldedLiteral,
    FoldedLiteralTriePlan, FoldedScalarClass, PLAN_ID as FOLDED_LITERAL_TRIE_PLAN_ID,
    ScanActual as FoldedLiteralTrieScanActual,
    ScanAttemptError as FoldedLiteralTrieScanAttemptError, ScanError as FoldedLiteralTrieScanError,
    ScanLimits as FoldedLiteralTrieScanLimits, ScanReceipt as FoldedLiteralTrieScanReceipt,
    ScanResource as FoldedLiteralTrieScanResource,
    ScanUpperBounds as FoldedLiteralTrieScanUpperBounds,
};
pub use forward_anchored::{
    ABSOLUTE_END_FIXED_PLAN_ID,
    ASCII_BITSET_RUN_PLAN_ID as FORWARD_ANCHORED_ASCII_BITSET_RUN_PLAN_ID, AbsoluteEndFixedPlan,
    Anchors as ForwardAnchoredAnchors, BuildAccounting as ForwardAnchoredBuildAccounting,
    BuildError as ForwardAnchoredBuildError, BuildLimits as ForwardAnchoredBuildLimits,
    ByteClass as ForwardAnchoredByteClass, ClassImplementation as ForwardClassImplementation,
    DispatchedForwardAnchoredPlan, ForwardAnchoredPlan, PLAN_ID as FORWARD_ANCHORED_PLAN_ID,
    SearchAccounting as ForwardAnchoredSearchAccounting, SearchError as ForwardAnchoredSearchError,
    SearchLimits as ForwardAnchoredSearchLimits,
};

pub use grapheme_scalar_dfa::{
    BuildAccounting as GraphemeScalarDfaBuildAccounting, BuildError as GraphemeScalarDfaBuildError,
    BuildLimits as GraphemeScalarDfaBuildLimits,
    COUNT_OPERATION_ID as GRAPHEME_SCALAR_DFA_COUNT_OPERATION_ID,
    CountResult as GraphemeScalarDfaCountResult, GraphemeScalarClassRole,
    GraphemeScalarClassRole as GraphemeScalarDfaRole, GraphemeScalarDfaPlan,
    Operation as GraphemeScalarDfaOperation,
    OperationIdentity as GraphemeScalarDfaOperationIdentity,
    PLAN_ID as GRAPHEME_SCALAR_DFA_PLAN_ID, ReduceAccounting as GraphemeScalarDfaReduceAccounting,
    ReduceActualCounters as GraphemeScalarDfaActualCounters,
    ReduceError as GraphemeScalarDfaReduceError, ReduceLimits as GraphemeScalarDfaReduceLimits,
    ReduceUpperBounds as GraphemeScalarDfaUpperBounds,
    SPAN_SUM_OPERATION_ID as GRAPHEME_SCALAR_DFA_SPAN_SUM_OPERATION_ID,
    Semantics as GraphemeScalarDfaSemantics, SpanSumResult as GraphemeScalarDfaSpanSumResult,
};

pub use literal_aggregate::{
    ACCOUNTING_VERSION as LITERAL_AGGREGATE_ACCOUNTING_VERSION,
    ALGORITHM_VERSION as LITERAL_AGGREGATE_ALGORITHM_VERSION,
    BoundarySemantics as LiteralAggregateBoundarySemantics,
    BuildAccounting as LiteralAggregateBuildAccounting, BuildError as LiteralAggregateBuildError,
    BuildLimits as LiteralAggregateBuildLimits,
    COUNT_OPERATION_ID as LITERAL_AGGREGATE_COUNT_OPERATION_ID,
    CountAttempt as LiteralAggregateCountAttempt, CountResult as LiteralAggregateCountResult,
    DISPATCHED_PLAN_ID as DISPATCHED_LITERAL_AGGREGATE_PLAN_ID,
    DeclaredFallback as LiteralAggregateDeclaredFallback, DispatchedLiteralAggregatePlan,
    LiteralAggregatePlan, Operation as LiteralAggregateOperation,
    OperationIdentity as LiteralAggregateOperationIdentity, PLAN_ID as LITERAL_AGGREGATE_PLAN_ID,
    PlanOrigin as LiteralAggregatePlanOrigin, ReduceAccounting as LiteralAggregateReduceAccounting,
    ReduceActualCounters as LiteralAggregateActualCounters,
    ReduceAttemptError as LiteralAggregateReduceAttemptError,
    ReduceAttemptReceipt as LiteralAggregateReduceAttemptReceipt,
    ReduceError as LiteralAggregateReduceError,
    ReduceInvocation as LiteralAggregateReduceInvocation,
    ReduceLimits as LiteralAggregateReduceLimits, ReduceUpperBounds as LiteralAggregateUpperBounds,
    SPAN_SUM_OPERATION_ID as LITERAL_AGGREGATE_SPAN_SUM_OPERATION_ID,
    SpanSumAttempt as LiteralAggregateSpanSumAttempt,
    SpanSumResult as LiteralAggregateSpanSumResult,
};
pub use literal_anchor::{
    AnchorError as LiteralAnchorError, AnchorRecovery as LiteralAnchorRecovery,
    CandidateEmissionOrder as LiteralCandidateEmissionOrder, LiteralAnchor, LiteralCandidate,
    OffsetBounds as LiteralAnchorOffsetBounds,
};

pub use literal_assertions::{
    BuildAccounting as LiteralAssertionsBuildAccounting, BuildError as LiteralAssertionsBuildError,
    BuildLimits as LiteralAssertionsBuildLimits,
    COUNT_OPERATION_ID as LITERAL_ASSERTIONS_COUNT_OPERATION_ID,
    CountResult as LiteralAssertionsCountResult, LiteralAssertionsPlan,
    OperationIdentity as LiteralAssertionsOperationIdentity, PLAN_ID as LITERAL_ASSERTIONS_PLAN_ID,
    ReduceAccounting as LiteralAssertionsReduceAccounting,
    ReduceActualCounters as LiteralAssertionsActualCounters,
    ReduceError as LiteralAssertionsReduceError, ReduceLimits as LiteralAssertionsReduceLimits,
    ReduceUpperBounds as LiteralAssertionsUpperBounds,
    SPAN_SUM_OPERATION_ID as LITERAL_ASSERTIONS_SPAN_SUM_OPERATION_ID,
    SpanSumResult as LiteralAssertionsSpanSumResult, Topology as LiteralAssertionsTopology,
};

pub use literal_class_run_literal::{
    BuildAccounting as LiteralClassRunLiteralBuildAccounting,
    BuildError as LiteralClassRunLiteralBuildError,
    BuildLimits as LiteralClassRunLiteralBuildLimits,
    COUNT_OPERATION_ID as LITERAL_CLASS_RUN_LITERAL_COUNT_OPERATION_ID,
    ClassScanIdentity as LiteralClassRunLiteralClassScanIdentity,
    CountResult as LiteralClassRunLiteralCountResult, LiteralClassRunLiteralPlan,
    OperationIdentity as LiteralClassRunLiteralOperationIdentity,
    PLAN_ID as LITERAL_CLASS_RUN_LITERAL_PLAN_ID,
    ReduceAccounting as LiteralClassRunLiteralReduceAccounting,
    ReduceActualCounters as LiteralClassRunLiteralActualCounters,
    ReduceError as LiteralClassRunLiteralReduceError,
    ReduceLimits as LiteralClassRunLiteralReduceLimits,
    ReduceUpperBounds as LiteralClassRunLiteralUpperBounds,
    SPAN_SUM_OPERATION_ID as LITERAL_CLASS_RUN_LITERAL_SPAN_SUM_OPERATION_ID,
    SpanSumResult as LiteralClassRunLiteralSpanSumResult,
};

pub use literal_set::{
    LiteralSetAccounting, LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError,
    LiteralSetIterationAccounting, LiteralSetMatchSemantics, LiteralSetMatches, LiteralSetPlan,
    LiteralSetSearchLimits,
};
pub use ordered_literal_aggregate::{
    ALGORITHM_ID as ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    BUILD_ATTEMPT_ACCOUNTING_VERSION as ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ACCOUNTING_VERSION,
    BUILD_ATTEMPT_ALGORITHM_VERSION as ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ALGORITHM_VERSION,
    BoundarySemantics as OrderedLiteralAggregateBoundarySemantics,
    BuildAccounting as OrderedLiteralAggregateBuildAccounting,
    BuildAttemptActual as OrderedLiteralAggregateBuildAttemptActual,
    BuildAttemptError as OrderedLiteralAggregateBuildAttemptError,
    BuildAttemptIdentity as OrderedLiteralAggregateBuildAttemptIdentity,
    BuildAttemptReceipt as OrderedLiteralAggregateBuildAttemptReceipt,
    BuildError as OrderedLiteralAggregateBuildError,
    BuildLimits as OrderedLiteralAggregateBuildLimits,
    COUNT_PLAN_ID as ORDERED_LITERAL_COUNT_PLAN_ID,
    CacheIdentity as OrderedLiteralAggregateCacheIdentity,
    CountBuildAttempt as OrderedLiteralCountBuildAttempt, CountResult as OrderedLiteralCountResult,
    IterationSemantics as OrderedLiteralAggregateIterationSemantics,
    MatchSemantics as OrderedLiteralAggregateMatchSemantics,
    Operation as OrderedLiteralAggregateOperation, OrderedLiteralCountPlan,
    OrderedLiteralSpanSumPlan, ReduceAccounting as OrderedLiteralAggregateReduceAccounting,
    ReduceActualCounters as OrderedLiteralAggregateActualCounters,
    ReduceError as OrderedLiteralAggregateReduceError,
    ReduceLimits as OrderedLiteralAggregateReduceLimits,
    ReduceUpperBounds as OrderedLiteralAggregateUpperBounds,
    SPAN_SUM_PLAN_ID as ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    Semantics as OrderedLiteralAggregateSemantics,
    SpanSumBuildAttempt as OrderedLiteralSpanSumBuildAttempt,
    SpanSumResult as OrderedLiteralSpanSumResult,
};
pub use packed_literal_set::{
    PackedLiteralSetAccounting, PackedLiteralSetBuildAccounting, PackedLiteralSetBuildLimits,
    PackedLiteralSetError, PackedLiteralSetPlan, PackedLiteralSetSearchLimits,
};
pub use packed_ordered_literal_aggregate::{
    ALGORITHM_ID as PACKED_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    BUILD_ATTEMPT_ACCOUNTING_VERSION as PACKED_ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ACCOUNTING_VERSION,
    BUILD_ATTEMPT_ALGORITHM_VERSION as PACKED_ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ALGORITHM_VERSION,
    BoundarySemantics as PackedOrderedLiteralAggregateBoundarySemantics,
    BuildAccounting as PackedOrderedLiteralAggregateBuildAccounting,
    BuildAttemptActual as PackedOrderedLiteralAggregateBuildAttemptActual,
    BuildAttemptError as PackedOrderedLiteralAggregateBuildAttemptError,
    BuildAttemptIdentity as PackedOrderedLiteralAggregateBuildAttemptIdentity,
    BuildAttemptReceipt as PackedOrderedLiteralAggregateBuildAttemptReceipt,
    BuildError as PackedOrderedLiteralAggregateBuildError,
    BuildLimits as PackedOrderedLiteralAggregateBuildLimits,
    CERTIFIED_MAX_PATTERN_BYTES as PACKED_ORDERED_LITERAL_CERTIFIED_MAX_PATTERN_BYTES,
    CERTIFIED_MAX_PATTERNS as PACKED_ORDERED_LITERAL_CERTIFIED_MAX_PATTERNS,
    CERTIFIED_MAX_TOTAL_PATTERN_BYTES as PACKED_ORDERED_LITERAL_CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
    CERTIFIED_MIN_PATTERN_BYTES as PACKED_ORDERED_LITERAL_CERTIFIED_MIN_PATTERN_BYTES,
    CERTIFIED_MIN_PATTERNS as PACKED_ORDERED_LITERAL_CERTIFIED_MIN_PATTERNS,
    COUNT_PLAN_ID as PACKED_ORDERED_LITERAL_COUNT_PLAN_ID,
    CacheIdentity as PackedOrderedLiteralAggregateCacheIdentity,
    CountBuildAttempt as PackedOrderedLiteralCountBuildAttempt,
    CountResult as PackedOrderedLiteralCountResult,
    OperationIdentity as PackedOrderedLiteralAggregateOperationIdentity,
    PackedOrderedLiteralCountPlan, PackedOrderedLiteralSpanSumPlan,
    ReduceAccounting as PackedOrderedLiteralAggregateReduceAccounting,
    ReduceActualCounters as PackedOrderedLiteralAggregateActualCounters,
    ReduceError as PackedOrderedLiteralAggregateReduceError,
    ReduceLimits as PackedOrderedLiteralAggregateReduceLimits,
    ReduceUpperBounds as PackedOrderedLiteralAggregateUpperBounds,
    SPAN_SUM_PLAN_ID as PACKED_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    Semantics as PackedOrderedLiteralAggregateSemantics,
    SpanSumBuildAttempt as PackedOrderedLiteralSpanSumBuildAttempt,
    SpanSumResult as PackedOrderedLiteralSpanSumResult,
};
pub use prefix_class_alternation::{
    BuildAccounting as PrefixClassAlternationBuildAccounting,
    BuildError as PrefixClassAlternationBuildError,
    BuildLimits as PrefixClassAlternationBuildLimits,
    COUNT_OPERATION_ID as PREFIX_CLASS_ALTERNATION_COUNT_OPERATION_ID,
    CountResult as PrefixClassAlternationCountResult,
    DISPATCHED_PLAN_ID as DISPATCHED_PREFIX_CLASS_ALTERNATION_PLAN_ID,
    DISPATCHED_UNIFORM_PARTICIPATION_PLAN_ID as DISPATCHED_PREFIX_CLASS_UNIFORM_PARTICIPATION_PLAN_ID,
    DispatchedPrefixClassAlternationPlan,
    OperationIdentity as PrefixClassAlternationOperationIdentity,
    PLAN_ID as PREFIX_CLASS_ALTERNATION_PLAN_ID, PrefixClassAlternationPlan,
    ReduceAccounting as PrefixClassAlternationReduceAccounting,
    ReduceActualCounters as PrefixClassAlternationActualCounters,
    ReduceError as PrefixClassAlternationReduceError,
    ReduceLimits as PrefixClassAlternationReduceLimits,
    ReduceUpperBounds as PrefixClassAlternationUpperBounds,
    RunScannerBuildAccounting as PrefixClassAlternationRunScannerBuildAccounting,
    UNIFORM_PARTICIPATION_ACCOUNTING_VERSION as PREFIX_CLASS_UNIFORM_PARTICIPATION_ACCOUNTING_VERSION,
    UNIFORM_PARTICIPATION_ALGORITHM_VERSION as PREFIX_CLASS_UNIFORM_PARTICIPATION_ALGORITHM_VERSION,
    UNIFORM_PARTICIPATION_OPERATION_ID as PREFIX_CLASS_UNIFORM_PARTICIPATION_OPERATION_ID,
    UNIFORM_PARTICIPATION_PLAN_ID as PREFIX_CLASS_UNIFORM_PARTICIPATION_PLAN_ID,
    UniformParticipationAccounting as PrefixClassUniformParticipationAccounting,
    UniformParticipationActual as PrefixClassUniformParticipationActual,
    UniformParticipationAttempt as PrefixClassUniformParticipationAttempt,
    UniformParticipationAttemptError as PrefixClassUniformParticipationAttemptError,
    UniformParticipationAttemptReceipt as PrefixClassUniformParticipationAttemptReceipt,
    UniformParticipationBuildAccounting as PrefixClassUniformParticipationBuildAccounting,
    UniformParticipationBuildError as PrefixClassUniformParticipationBuildError,
    UniformParticipationBuildLimits as PrefixClassUniformParticipationBuildLimits,
    UniformParticipationError as PrefixClassUniformParticipationError,
    UniformParticipationIdentity as PrefixClassUniformParticipationIdentity,
    UniformParticipationInvocation as PrefixClassUniformParticipationInvocation,
    UniformParticipationLimits as PrefixClassUniformParticipationLimits,
    UniformParticipationProspective as PrefixClassUniformParticipationProspective,
    UniformParticipationResult as PrefixClassUniformParticipationResult,
    UniformParticipationSchema as PrefixClassUniformParticipationSchema,
};
pub use required_internal_anchor::{
    BuildAccounting as RequiredInternalAnchorBuildAccounting,
    BuildError as RequiredInternalAnchorBuildError,
    BuildLimits as RequiredInternalAnchorBuildLimits,
    COUNT_OPERATION_ID as REQUIRED_INTERNAL_ANCHOR_COUNT_OPERATION_ID,
    ContinuationSource as RequiredInternalAnchorContinuationSource,
    CountAccounting as RequiredInternalAnchorCountAccounting,
    CountActual as RequiredInternalAnchorCountActual,
    CountAttemptError as RequiredInternalAnchorCountAttemptError,
    CountError as RequiredInternalAnchorCountError,
    CountLimits as RequiredInternalAnchorCountLimits,
    CountResource as RequiredInternalAnchorCountResource,
    CountResult as RequiredInternalAnchorCountResult,
    CountUpperBounds as RequiredInternalAnchorCountUpperBounds,
    MAX_OPTIONAL_STAGES as REQUIRED_INTERNAL_ANCHOR_MAX_OPTIONAL_STAGES,
    OptionalStageSource as RequiredInternalAnchorOptionalStageSource,
    PLAN_ID as REQUIRED_INTERNAL_ANCHOR_PLAN_ID, RequiredInternalAnchorPlan,
};
pub use required_literal::ByteClass as RequiredInternalAnchorByteClass;
pub use required_literal::{
    ASCII_BACKWARD_RUN_PLAN_ID as REQUIRED_LITERAL_ASCII_BACKWARD_RUN_PLAN_ID,
    Anchors as RequiredLiteralAnchors, BuildAccounting as RequiredLiteralBuildAccounting,
    BuildError as RequiredLiteralBuildError, BuildLimits as RequiredLiteralBuildLimits,
    ByteClass as RequiredLiteralByteClass, DispatchedRequiredLiteralPlan,
    PLAN_ID as REQUIRED_LITERAL_PLAN_ID, RequiredLiteralPlan,
    SearchAccounting as RequiredLiteralSearchAccounting, SearchError as RequiredLiteralSearchError,
    SearchLimits as RequiredLiteralSearchLimits,
};
pub use sparse_ordered_literal_aggregate::{
    ALGORITHM_ID as SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID,
    BUILD_ATTEMPT_ACCOUNTING_VERSION as SPARSE_ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ACCOUNTING_VERSION,
    BUILD_ATTEMPT_ALGORITHM_VERSION as SPARSE_ORDERED_LITERAL_AGGREGATE_BUILD_ATTEMPT_ALGORITHM_VERSION,
    BoundarySemantics as SparseOrderedLiteralAggregateBoundarySemantics,
    BuildAccounting as SparseOrderedLiteralAggregateBuildAccounting,
    BuildAttemptActual as SparseOrderedLiteralAggregateBuildAttemptActual,
    BuildAttemptError as SparseOrderedLiteralAggregateBuildAttemptError,
    BuildAttemptIdentity as SparseOrderedLiteralAggregateBuildAttemptIdentity,
    BuildAttemptReceipt as SparseOrderedLiteralAggregateBuildAttemptReceipt,
    BuildError as SparseOrderedLiteralAggregateBuildError,
    BuildLimits as SparseOrderedLiteralAggregateBuildLimits,
    COUNT_PLAN_ID as SPARSE_ORDERED_LITERAL_COUNT_PLAN_ID,
    CacheIdentity as SparseOrderedLiteralAggregateCacheIdentity,
    CountBuildAttempt as SparseOrderedLiteralCountBuildAttempt,
    CountResult as SparseOrderedLiteralCountResult,
    IterationSemantics as SparseOrderedLiteralAggregateIterationSemantics,
    MatchSemantics as SparseOrderedLiteralAggregateMatchSemantics,
    Operation as SparseOrderedLiteralAggregateOperation,
    ReduceAccounting as SparseOrderedLiteralAggregateReduceAccounting,
    ReduceActualCounters as SparseOrderedLiteralAggregateActualCounters,
    ReduceError as SparseOrderedLiteralAggregateReduceError,
    ReduceLimits as SparseOrderedLiteralAggregateReduceLimits,
    ReduceUpperBounds as SparseOrderedLiteralAggregateUpperBounds,
    SPAN_SUM_PLAN_ID as SPARSE_ORDERED_LITERAL_SPAN_SUM_PLAN_ID,
    Semantics as SparseOrderedLiteralAggregateSemantics,
    SpanSumBuildAttempt as SparseOrderedLiteralSpanSumBuildAttempt,
    SpanSumResult as SparseOrderedLiteralSpanSumResult, SparseOrderedLiteralCountPlan,
    SparseOrderedLiteralSpanSumPlan,
};
pub use token_phrase::{
    BuildAccounting as TokenPhraseBuildAccounting, BuildError as TokenPhraseBuildError,
    BuildLimits as TokenPhraseBuildLimits, COUNT_OPERATION_ID as TOKEN_PHRASE_COUNT_OPERATION_ID,
    CountResult as TokenPhraseCountResult, OperationIdentity as TokenPhraseOperationIdentity,
    PLAN_ID as TOKEN_PHRASE_PLAN_ID, ReduceAccounting as TokenPhraseReduceAccounting,
    ReduceActualCounters as TokenPhraseActualCounters, ReduceError as TokenPhraseReduceError,
    ReduceLimits as TokenPhraseReduceLimits, ReduceUpperBounds as TokenPhraseUpperBounds,
    SPAN_SUM_OPERATION_ID as TOKEN_PHRASE_SPAN_SUM_OPERATION_ID,
    SpanSumResult as TokenPhraseSpanSumResult, TokenPhrasePlan, Topology as TokenPhraseTopology,
};
pub use unicode_scalar_aggregate::{
    BuildAccounting as UnicodeScalarAggregateBuildAccounting,
    BuildError as UnicodeScalarAggregateBuildError,
    BuildLimits as UnicodeScalarAggregateBuildLimits,
    COUNT_OPERATION_ID as UNICODE_SCALAR_AGGREGATE_COUNT_OPERATION_ID,
    CountResult as UnicodeScalarAggregateCountResult,
    DISPATCHED_PLAN_ID as DISPATCHED_UNICODE_SCALAR_AGGREGATE_PLAN_ID,
    DispatchedUnicodeScalarAggregatePlan, Operation as UnicodeScalarAggregateOperation,
    OperationIdentity as UnicodeScalarAggregateOperationIdentity,
    PLAN_ID as UNICODE_SCALAR_AGGREGATE_PLAN_ID,
    RUN_COUNT_OPERATION_ID as UNICODE_SCALAR_RUN_AGGREGATE_COUNT_OPERATION_ID,
    RUN_PLAN_ID as UNICODE_SCALAR_RUN_AGGREGATE_PLAN_ID,
    RUN_SPAN_SUM_OPERATION_ID as UNICODE_SCALAR_RUN_AGGREGATE_SPAN_SUM_OPERATION_ID,
    ReduceAccounting as UnicodeScalarAggregateReduceAccounting,
    ReduceActualCounters as UnicodeScalarAggregateActualCounters,
    ReduceError as UnicodeScalarAggregateReduceError,
    ReduceLimits as UnicodeScalarAggregateReduceLimits,
    ReduceUpperBounds as UnicodeScalarAggregateUpperBounds,
    Repetition as UnicodeScalarAggregateRepetition,
    SPAN_SUM_OPERATION_ID as UNICODE_SCALAR_AGGREGATE_SPAN_SUM_OPERATION_ID,
    ScalarSemantics as UnicodeScalarAggregateSemantics,
    SpanSumResult as UnicodeScalarAggregateSpanSumResult, UnicodeScalarAggregatePlan,
};
pub use url_aggregate::{
    BuildAccounting as UrlAggregateBuildAccounting, BuildError as UrlAggregateBuildError,
    BuildLimits as UrlAggregateBuildLimits, PLAN_ID as URL_AGGREGATE_PLAN_ID,
    ReduceAccounting as UrlAggregateReduceAccounting,
    ReduceAttemptError as UrlAggregateReduceAttemptError, ReduceError as UrlAggregateReduceError,
    ReduceLimits as UrlAggregateReduceLimits, ReduceUpperBounds as UrlAggregateReduceUpperBounds,
    SPAN_SUM_OPERATION_ID as URL_AGGREGATE_SPAN_SUM_OPERATION_ID,
    SpanSumResult as UrlAggregateSpanSumResult, UrlAggregateBuildAuthority, UrlAggregatePlan,
    reduce_upper_bounds as url_aggregate_reduce_upper_bounds,
};

/// Hard limits for building one exact-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralBuildLimits {
    /// Maximum copied needle bytes.
    pub max_needle_bytes: usize,
}

impl Default for LiteralBuildLimits {
    fn default() -> Self {
        Self {
            max_needle_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Per-search limits for a linear exact-literal invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSearchLimits {
    /// Maximum `needle bytes + searched haystack bytes` linear terms.
    pub max_linear_terms: usize,
}

impl LiteralSearchLimits {
    /// No caller-selected limit. Address-space arithmetic remains checked.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_linear_terms: usize::MAX,
        }
    }
}

impl Default for LiteralSearchLimits {
    fn default() -> Self {
        Self {
            max_linear_terms: 128 * 1024 * 1024,
        }
    }
}

/// Half-open byte range searched within the original haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window {
    start: usize,
    end: usize,
}

impl Window {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn full(haystack: &[u8]) -> Self {
        Self {
            start: 0,
            end: haystack.len(),
        }
    }

    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// Exact accounting/certificate inputs for one literal search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralAccounting {
    /// Needle length used by the linear bound.
    pub needle_bytes: usize,
    /// Searched haystack range length used by the linear bound.
    pub searched_bytes: usize,
    /// Checked sum of the two linear terms.
    pub linear_terms: usize,
    /// Search scratch bytes required by the plan contract.
    pub scratch_bytes: usize,
}

/// Exact literal build or search failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LiteralError {
    NeedleLimit {
        needed: usize,
        limit: usize,
    },
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    LinearTermLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    /// The exact owned-needle allocation failed.
    AllocationFailed {
        structure: &'static str,
        additional: usize,
    },
}

impl fmt::Display for LiteralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedleLimit { needed, limit } => {
                write!(f, "literal needs {needed} needle bytes, exceeding {limit}")
            }
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "literal window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::LinearTermLimit { needed, limit } => write!(
                f,
                "literal search needs {needed} linear terms, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
            Self::AllocationFailed {
                structure,
                additional,
            } => write!(f, "failed to allocate {additional} bytes for {structure}"),
        }
    }
}

impl std::error::Error for LiteralError {}

/// Validate an exact-literal search from scalar lengths only.
///
/// This is the shared refusal boundary for executors that already have an
/// authenticated literal width but do not own a [`LiteralPlan`], such as a
/// statically linked AOT handle. It performs no allocation and does not read
/// the haystack.
///
/// # Errors
///
/// Returns [`LiteralError::InvalidWindow`] or a checked limit/arithmetic
/// failure before an executor may inspect or call through any haystack
/// pointer.
#[inline]
pub fn preflight_literal_window(
    needle_bytes: usize,
    haystack_len: usize,
    window: Window,
    limits: LiteralSearchLimits,
) -> Result<LiteralAccounting, LiteralError> {
    if window.start > window.end || window.end > haystack_len {
        return Err(LiteralError::InvalidWindow {
            start: window.start,
            end: window.end,
            haystack_len,
        });
    }
    let searched_bytes =
        window
            .end
            .checked_sub(window.start)
            .ok_or(LiteralError::ArithmeticOverflow {
                computation: "literal window length",
            })?;
    preflight_literal_terms(needle_bytes, searched_bytes, limits)
}

/// Validate exact-literal resource limits for an already checked window.
///
/// The private-field [`CheckedSearchWindow`] proves the window bounds against
/// its borrowed haystack. This boundary therefore performs only the shared
/// literal work/accounting preflight and lets a native executor consume the
/// same checked token without repeating the bounds check.
///
/// # Errors
///
/// Returns a checked limit or arithmetic failure before an executor may call
/// through the checked haystack pointer.
#[doc(hidden)]
#[inline]
pub fn preflight_checked_literal_window(
    needle_bytes: usize,
    window: CheckedSearchWindow<'_>,
    limits: LiteralSearchLimits,
) -> Result<LiteralAccounting, LiteralError> {
    preflight_literal_terms(needle_bytes, window.searched_bytes(), limits)
}

#[inline]
fn preflight_literal_terms(
    needle_bytes: usize,
    searched_bytes: usize,
    limits: LiteralSearchLimits,
) -> Result<LiteralAccounting, LiteralError> {
    let linear_terms =
        searched_bytes
            .checked_add(needle_bytes)
            .ok_or(LiteralError::ArithmeticOverflow {
                computation: "literal linear terms",
            })?;
    if linear_terms > limits.max_linear_terms {
        return Err(LiteralError::LinearTermLimit {
            needed: linear_terms,
            limit: limits.max_linear_terms,
        });
    }
    Ok(LiteralAccounting {
        needle_bytes,
        searched_bytes,
        linear_terms,
        scratch_bytes: 0,
    })
}

/// Immutable exact-literal plan with an owned preprocessed finder.
#[derive(Debug)]
pub struct LiteralPlan {
    finder: Finder<'static>,
    needle_bytes: usize,
}

/// Private-field certificate for one checked, resource-admitted literal call.
///
/// This token binds the exact plan, haystack borrow, window, accounting, and
/// caller limit result. It is exposed only so FRE's sibling facade can hand
/// the same checked window to an independently typed native executor.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct LiteralSearchPreflight<'plan, 'haystack> {
    plan: &'plan LiteralPlan,
    window: CheckedSearchWindow<'haystack>,
    accounting: LiteralAccounting,
}

impl<'plan, 'haystack> LiteralSearchPreflight<'plan, 'haystack> {
    /// Exact accounting produced by the authoritative literal preflight.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub const fn accounting(self) -> LiteralAccounting {
        self.accounting
    }

    /// Checked byte count used for workload routing and resource accounting.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub const fn searched_bytes(self) -> usize {
        self.accounting.searched_bytes
    }

    /// Authenticated literal width owned by the plan that issued this token.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub const fn literal_bytes(self) -> usize {
        self.accounting.needle_bytes
    }

    /// Exact immutable needle owned by the plan that issued this token.
    ///
    /// Native sibling executors use this to bind scalar preflight to one exact
    /// embedded artifact instead of accepting any plan with the same width.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn literal(self) -> &'plan [u8] {
        self.plan.needle()
    }

    /// Whether this token was issued by one exact plan instance.
    ///
    /// A native session may first compare that plan's immutable needle with
    /// its sealed artifact and then use this allocation-free identity check on
    /// repeated calls. Equal bytes in a different plan remain a distinct
    /// instance and therefore take the general byte-identity path.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn was_issued_by(self, plan: &LiteralPlan) -> bool {
        core::ptr::eq(self.plan, plan)
    }

    /// The non-forgeable window bound to this preflight's haystack.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub const fn checked_window(self) -> CheckedSearchWindow<'haystack> {
        self.window
    }

    /// Execute the portable owner without repeating window or limit preflight.
    #[doc(hidden)]
    #[inline]
    pub fn find(self) -> Result<Option<(usize, usize)>, LiteralError> {
        let window = self.window.window();
        self.plan.find_after_preflight(
            self.window.haystack(),
            Window::new(window.start(), window.end()),
        )
    }
}

impl LiteralPlan {
    /// Copy and preprocess one byte needle.
    ///
    /// # Errors
    ///
    /// Returns [`LiteralError::NeedleLimit`] before construction if the
    /// declared payload cap is too small. Allocation failure is returned as a
    /// typed error; this plan deliberately does not implement `Clone` because
    /// cloning its owned finder would introduce an unmetered allocation.
    pub fn new(needle: &[u8], limits: LiteralBuildLimits) -> Result<Self, LiteralError> {
        if needle.len() > limits.max_needle_bytes {
            return Err(LiteralError::NeedleLimit {
                needed: needle.len(),
                limit: limits.max_needle_bytes,
            });
        }
        let owned = copy_literal_exact(needle)?;
        Ok(Self {
            finder: FinderBuilder::new().build_forward_owned(owned),
            needle_bytes: needle.len(),
        })
    }

    /// Logical persistent pattern payload bytes.
    #[must_use]
    pub const fn storage_bytes(&self) -> usize {
        self.needle_bytes
    }

    /// The preprocessed needle.
    #[must_use]
    pub fn needle(&self) -> &[u8] {
        self.finder.needle()
    }

    /// Find the first occurrence in a full haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked resource/arithmetic error before invoking the native
    /// primitive.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: LiteralSearchLimits,
    ) -> Result<(Option<(usize, usize)>, LiteralAccounting), LiteralError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the first occurrence wholly inside a range.
    ///
    /// # Errors
    ///
    /// Returns [`LiteralError::InvalidWindow`] or a checked limit/arithmetic
    /// error before invoking the native primitive.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSearchLimits,
    ) -> Result<(Option<(usize, usize)>, LiteralAccounting), LiteralError> {
        let accounting = self.preflight_window(haystack.len(), window, limits)?;
        let matched = self.find_after_preflight(haystack, window)?;
        Ok((matched, accounting))
    }

    fn find_after_preflight(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralError> {
        let relative = self.finder.find(&haystack[window.start..window.end]);
        relative
            .map(|relative| {
                let start =
                    window
                        .start
                        .checked_add(relative)
                        .ok_or(LiteralError::ArithmeticOverflow {
                            computation: "literal match start",
                        })?;
                let end = start.checked_add(self.needle_bytes).ok_or(
                    LiteralError::ArithmeticOverflow {
                        computation: "literal match end",
                    },
                )?;
                Ok((start, end))
            })
            .transpose()
    }

    /// Validate a literal search and return its exact resource certificate
    /// without reading the haystack.
    ///
    /// This lets a higher-level semantic router preserve the portable plan's
    /// refusal contract before selecting an independently authenticated
    /// executor for the same exact-literal operation.
    pub fn preflight_window(
        &self,
        haystack_len: usize,
        window: Window,
        limits: LiteralSearchLimits,
    ) -> Result<LiteralAccounting, LiteralError> {
        preflight_literal_window(self.needle_bytes, haystack_len, window, limits)
    }

    /// Seal one checked window and exact resource admission into a proof token.
    #[doc(hidden)]
    #[inline]
    pub fn preflight_checked_window<'plan, 'haystack>(
        &'plan self,
        window: CheckedSearchWindow<'haystack>,
        limits: LiteralSearchLimits,
    ) -> Result<LiteralSearchPreflight<'plan, 'haystack>, LiteralError> {
        let accounting = preflight_checked_literal_window(self.needle_bytes, window, limits)?;
        Ok(LiteralSearchPreflight {
            plan: self,
            window,
            accounting,
        })
    }
}

fn copy_literal_exact(needle: &[u8]) -> Result<Vec<u8>, LiteralError> {
    #[cfg(test)]
    exact_literal_copy_probe::record();
    #[cfg(test)]
    if let Some(error) = exact_literal_copy_probe::take_failure() {
        return Err(map_literal_copy_error(error, needle.len()));
    }
    fre_exact_alloc::copy_exact(needle).map_err(|error| map_literal_copy_error(error, needle.len()))
}

const fn map_literal_copy_error(error: CopyError, needle_len: usize) -> LiteralError {
    match error {
        CopyError::LayoutOverflow => LiteralError::ArithmeticOverflow {
            computation: "exact literal allocation layout",
        },
        CopyError::AllocationFailed => LiteralError::AllocationFailed {
            structure: "exact literal needle",
            additional: needle_len,
        },
    }
}

#[cfg(test)]
mod exact_literal_copy_probe {
    use std::cell::Cell;

    use fre_exact_alloc::CopyError;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static FAILURE: Cell<Option<CopyError>> = const { Cell::new(None) };
    }

    pub(super) fn record() {
        CALLS.set(CALLS.get().checked_add(1).expect("test probe overflow"));
    }

    pub(super) fn reset() {
        CALLS.set(0);
        FAILURE.set(None);
    }

    pub(super) fn calls() -> usize {
        CALLS.get()
    }

    pub(super) fn fail_next(error: CopyError) {
        FAILURE.set(Some(error));
    }

    pub(super) fn take_failure() -> Option<CopyError> {
        let failure = FAILURE.get();
        FAILURE.set(None);
        failure
    }
}

#[cfg(test)]
mod tests {
    use fre_exact_alloc::CopyError;
    use fre_kernel_ir::{CheckedSearchWindow, SearchWindow as KernelSearchWindow};

    use super::{
        LiteralAccounting, LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits,
        Window, copy_literal_exact, exact_literal_copy_probe, preflight_checked_literal_window,
        preflight_literal_window,
    };

    #[test]
    fn literals_and_empty_needles_keep_exact_offsets() {
        let plan = LiteralPlan::new(b"aba", LiteralBuildLimits::default()).unwrap();
        let (matched, accounting) = plan
            .find(b"zzababa", LiteralSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((2, 5)));
        assert_eq!(accounting.needle_bytes, 3);
        assert_eq!(accounting.searched_bytes, 7);

        let empty = LiteralPlan::new(b"", LiteralBuildLimits::default()).unwrap();
        assert_eq!(
            empty
                .find_window(b"abc", Window::new(2, 3), LiteralSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((2, 2))
        );
    }

    #[test]
    fn checked_literal_preflight_seals_accounting_limit_and_portable_execution() {
        let plan = LiteralPlan::new(b"needle", LiteralBuildLimits::default()).unwrap();
        let haystack = b"xxneedlexx";
        let checked =
            CheckedSearchWindow::new(haystack, KernelSearchWindow::new(1, haystack.len()))
                .expect("valid checked window");
        let expected = plan
            .preflight_checked_window(checked, LiteralSearchLimits::unlimited())
            .expect("unlimited preflight");
        assert_eq!(
            expected.accounting(),
            plan.preflight_window(
                haystack.len(),
                Window::new(1, haystack.len()),
                LiteralSearchLimits::unlimited(),
            )
            .expect("legacy preflight parity")
        );
        let exact_limit = LiteralSearchLimits {
            max_linear_terms: expected.accounting().linear_terms,
        };
        let exact = plan
            .preflight_checked_window(checked, exact_limit)
            .expect("exact linear-term cap");
        assert_eq!(exact.accounting(), expected.accounting());
        assert_eq!(
            exact.searched_bytes(),
            haystack.len().checked_sub(1).expect("nonempty haystack")
        );
        assert_eq!(exact.literal(), b"needle");
        assert!(exact.was_issued_by(&plan));
        let equal_but_distinct =
            LiteralPlan::new(b"needle", LiteralBuildLimits::default()).unwrap();
        assert!(!exact.was_issued_by(&equal_but_distinct));
        assert_eq!(
            exact.checked_window().haystack().as_ptr(),
            haystack.as_ptr()
        );
        assert_eq!(exact.checked_window().haystack().len(), haystack.len());
        assert_eq!(
            exact.find().expect("preflighted portable search"),
            Some((2, 8))
        );

        let one_below_terms = exact_limit
            .max_linear_terms
            .checked_sub(1)
            .expect("positive exact linear terms");
        let one_below = LiteralSearchLimits {
            max_linear_terms: one_below_terms,
        };
        assert!(matches!(
            plan.preflight_checked_window(checked, one_below),
            Err(LiteralError::LinearTermLimit { needed, limit })
                if needed == exact_limit.max_linear_terms && limit == one_below.max_linear_terms
        ));
    }

    #[test]
    fn exact_literal_plan_owns_the_fallibly_copied_needle() {
        let plan = {
            let source = b"temporary needle".to_vec();
            LiteralPlan::new(&source, LiteralBuildLimits::default()).unwrap()
        };
        assert_eq!(plan.needle(), b"temporary needle");
        assert_eq!(
            plan.find(
                b"a temporary needle survives",
                LiteralSearchLimits::unlimited()
            )
            .unwrap()
            .0,
            Some((2, 18))
        );
    }

    #[test]
    fn ranges_do_not_match_across_their_end() {
        let plan = LiteralPlan::new(b"bc", LiteralBuildLimits::default()).unwrap();
        assert_eq!(
            plan.find_window(b"abcd", Window::new(0, 2), LiteralSearchLimits::unlimited())
                .unwrap()
                .0,
            None
        );
    }

    #[test]
    fn every_declared_limit_fails_before_search() {
        exact_literal_copy_probe::reset();
        assert!(matches!(
            LiteralPlan::new(
                b"ab",
                LiteralBuildLimits {
                    max_needle_bytes: 1
                }
            ),
            Err(LiteralError::NeedleLimit { .. })
        ));
        assert_eq!(exact_literal_copy_probe::calls(), 0);
        let plan = LiteralPlan::new(b"ab", LiteralBuildLimits::default()).unwrap();
        assert!(matches!(
            plan.find(
                b"haystack",
                LiteralSearchLimits {
                    max_linear_terms: 1
                }
            ),
            Err(LiteralError::LinearTermLimit { .. })
        ));
    }

    #[test]
    fn scalar_literal_preflight_is_the_plan_independent_refusal_contract() {
        let plan = LiteralPlan::new(b"needle", LiteralBuildLimits::default()).unwrap();
        let limits = LiteralSearchLimits {
            max_linear_terms: 12,
        };
        for window in [
            Window::new(0, 0),
            Window::new(2, 6),
            Window::new(6, 2),
            Window::new(0, 9),
        ] {
            assert_eq!(
                preflight_literal_window(6, 8, window, limits),
                plan.preflight_window(8, window, limits)
            );
        }
        assert_eq!(
            preflight_literal_window(6, 8, Window::new(2, 6), limits),
            Ok(LiteralAccounting {
                needle_bytes: 6,
                searched_bytes: 4,
                linear_terms: 10,
                scratch_bytes: 0,
            })
        );

        let haystack = b"12345678";
        let checked = CheckedSearchWindow::new(haystack, KernelSearchWindow::new(2, 6))
            .expect("valid checked window");
        assert_eq!(
            preflight_checked_literal_window(6, checked, limits),
            preflight_literal_window(6, haystack.len(), Window::new(2, 6), limits),
        );
        let one_below = LiteralSearchLimits {
            max_linear_terms: 9,
        };
        assert!(matches!(
            preflight_checked_literal_window(6, checked, one_below),
            Err(LiteralError::LinearTermLimit {
                needed: 10,
                limit: 9
            })
        ));
    }

    #[test]
    fn exact_literal_copy_has_exact_capacity() {
        for len in [0_usize, 1, 2, 3, 7, 8, 15, 16, 31, 32, 255, 256, 4096] {
            let source: Vec<u8> = (0_u8..=u8::MAX).cycle().take(len).collect();
            exact_literal_copy_probe::reset();
            let owned = copy_literal_exact(&source).unwrap();
            assert_eq!(exact_literal_copy_probe::calls(), 1);
            assert_eq!(owned, source);
            assert_eq!(owned.capacity(), len);
        }
    }

    #[test]
    fn exact_literal_copy_failures_are_typed_without_retry() {
        for (injected, expected) in [
            (
                CopyError::LayoutOverflow,
                LiteralError::ArithmeticOverflow {
                    computation: "exact literal allocation layout",
                },
            ),
            (
                CopyError::AllocationFailed,
                LiteralError::AllocationFailed {
                    structure: "exact literal needle",
                    additional: 6,
                },
            ),
        ] {
            exact_literal_copy_probe::reset();
            exact_literal_copy_probe::fail_next(injected);
            assert_eq!(
                LiteralPlan::new(b"needle", LiteralBuildLimits::default()).unwrap_err(),
                expected
            );
            assert_eq!(exact_literal_copy_probe::calls(), 1);
        }
    }
}
