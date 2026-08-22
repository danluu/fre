//! General, self-contained AOT compilation for FRE's capture-free automata.
//!
//! Unlike the legacy template compiler, this crate admits a pattern because
//! [`fre_lower`] can lower it to a validated prioritized Thompson automaton,
//! not because its source or graph matches a small recipe list. The fast mode
//! freezes the universal ordered-TNFA representation. The optimizing mode
//! additionally performs complete byte-local or contextual ordered
//! determinization, reverse-machine construction for exact span recovery,
//! alphabet reduction, and target lowering under explicit resource limits.
//!
//! Object production is deterministic and does not invoke LLVM, a C compiler,
//! an assembler, a linker, or any subprocess.

#![forbid(unsafe_code)]

mod absolute_anchored_cut;
mod bit_parallel_exists;
mod bounded_suffix_retry;
mod byte_frequency;
mod capture_aot;
mod captures;
mod context_dfa;
mod context_native;
mod dfa;
mod dfa_loop_skip;
mod error;
mod finite_language;
mod grep_count;
mod mandatory_teddy;
mod module;
mod object;
mod operation_set;
mod operation_set_v2;
mod ordered_literal_artifact;
mod ordered_many;
mod ordered_nfa_native;
mod participation_aot;
mod prefix_block;
mod prefix_fast_forward;
mod prefix_predicate;
mod prefix_relation;
mod program;
mod regex_set;
mod rebar_single_capture;
mod required_literals;
mod seeded_reverse;
mod uniform_capture;

use fre_automata::{Automaton, RawPlan};
use fre_lower::{LowerError, LowerLimits, LowerResource, OperationSemantics};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustConstructor, RustProfile,
};
use sha2::{Digest, Sha256};

pub use bit_parallel_exists::{
    BitParallelExistsStats, MAX_BIT_PARALLEL_EXISTS_MEMORY_BYTES, MAX_BIT_PARALLEL_EXISTS_STATES,
    MAX_BIT_PARALLEL_EXISTS_WORDS, MAX_BIT_PARALLEL_EXISTS_WORK,
};
pub use capture_aot::{
    NATIVE_CAPTURE_AOT_V1_ABI_VERSION, NATIVE_CAPTURE_AOT_V1_BUNDLE_DIGEST_OFFSET,
    NATIVE_CAPTURE_AOT_V1_CAPTURE_LEVEL_ALL, NATIVE_CAPTURE_AOT_V1_FLAG_BYTE_SEMANTICS,
    NATIVE_CAPTURE_AOT_V1_FLAG_NATIVE_ONEPASS, NATIVE_CAPTURE_AOT_V1_FLAG_NEGATIVE_ENTRY,
    NATIVE_CAPTURE_AOT_V1_FLAG_SPAN_SELECTOR, NATIVE_CAPTURE_AOT_V1_HEADER_BYTES,
    NATIVE_CAPTURE_AOT_V1_IDENTITY_DOMAIN, NATIVE_CAPTURE_AOT_V1_ITER_STATE_ALIGN,
    NATIVE_CAPTURE_AOT_V1_ITER_STATE_BYTES, NATIVE_CAPTURE_AOT_V1_MAGIC,
    NATIVE_CAPTURE_AOT_V1_OFFSET_BYTES, NATIVE_CAPTURE_AOT_V1_PLAN_OFFSET,
    NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_ALIGN, NATIVE_CAPTURE_AOT_V1_RESULT_SLOT_BYTES,
    NATIVE_CAPTURE_AOT_V1_STATUS_UNAVAILABLE, NATIVE_CAPTURE_AOT_V1_UNSET,
    NativeCaptureAotArtifactV1, NativeCaptureAotDeclineV1, NativeCaptureAotError,
    NativeCaptureAotLimitsV1, NativeCaptureAotReceiptV1, NativeCaptureAotStrategyV1,
    NativeCaptureBundleV1Error, NativeCaptureBundleV1View, NativeCaptureDescriptorV1,
};
pub use captures::{
    CaptureArtifactIdentity, CaptureAuthenticationError, CaptureCompileError, CaptureCompileLimits,
    CaptureCompileReceipt, CaptureCompileRequest, CaptureGroupSlot, CaptureLevel,
    CaptureOnePassDisposition, CapturePrepareError, CaptureProgramV1, CaptureProgramV1Error,
    CaptureProgramV1Limits, CaptureProgramV1Usage, CaptureReplayStrategy, CaptureRunError,
    CaptureRunReport, CaptureSearchError, CaptureSearchLimits, CaptureSession,
    CaptureSessionLimits, CaptureSessionResource, CompiledCaptureRegex, HirProgramBuildError,
    HirProgramBuildLimits, HirProgramBuildReport, HistoryExactWorkspaceUsage,
    OnePassCaptureBuildError, OnePassCaptureBuildFailure, OnePassCaptureBuildLimits,
    OnePassCaptureBuildReport, OnePassCaptureWorkspaceUsage, RunReport as CaptureReplayRunReport,
    compile_captures,
};
pub use context_dfa::{ContextDfaDecline, ContextDfaResource, ContextDfaStats};
pub use dfa::{
    CompleteDfaFinalizationDisposition, CompleteDfaFinalizationLimits,
    CompleteDfaFinalizationReceipt, CompleteDfaGeometry, DeterminizationDecline,
    DeterminizationReport, DeterminizationResource, DeterminizationStage, DeterminizeLimits,
    DfaStats, NativeSlowPartialQuotientDisposition, NativeSlowPartialQuotientReceipt,
    MAX_STABLE_DFA_BUILD_WORK, MAX_STABLE_DFA_STATES, MAX_STABLE_DFA_TRANSITIONS,
};
pub use error::{CompileError, CompileResource, ObjectError};
pub use grep_count::{
    DEFAULT_GREP_COUNT_MAX_WORKSPACE_BYTES, GREP_COUNT_ACCOUNTING_ID,
    GREP_COUNT_ACCOUNTING_VERSION, GREP_COUNT_ALGORITHM_VERSION, GrepCountConstructionReceipt,
    GrepCountError, GrepCountPrepareError, GrepCountReceipt, GrepCountWorkspace,
    GrepCountWorkspaceLimits,
};
pub use module::{
    Architecture, CallAbi, CompiledModule, CompilerK0AotReport, CpuFeature,
    ExactFiniteExistsByteSetAotReport, ExactFiniteSelectedEndDfaBaselineReport,
    ExactFiniteSelectedEndTeddyAotIsa, ExactFiniteSelectedEndTeddyAotReport,
    ExactFiniteSelectedEndTeddyAotReportV2, ExactFiniteSelectedEndTeddyAotTargetTier,
    ExactFiniteSelectedEndTeddyIncumbentSourceV2, ExactFiniteSelectedEndTeddySelectionBasisV2,
    ExactSingleLiteralAotIsa, ExactSingleLiteralAotReport, ExactSingleLiteralPairPrefilterReport,
    ExactSingleLiteralTwoWayShift, FeatureSet, ModuleRelocation, ModuleSection, ModuleSymbol,
    OperatingSystem, OrderedFiniteLanguageAotReport, PreparedAggregateExports,
    PreparedAggregateStrategy, PreparedBulkStrategy, RelocationKind, SectionKind, SlowAotLimits,
    SlowAotReport, SlowContextAotReport, StartAccelerator, SymbolBinding, SymbolKind, Target,
    PREPARED_CAPABILITY_ORDERED_NFA_V15,
};
pub use object::{ObjectFormat, emit_object};
pub use operation_set::{
    AOT_OPERATION_SET_V1_HEADER_BYTES, AOT_OPERATION_SET_V1_IDENTITY_DOMAIN,
    AOT_OPERATION_SET_V1_MAGIC, AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V1_NONE_INDEX, AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES, AOT_OPERATION_SET_V1_SHARED_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES, AOT_OPERATION_SET_V1_VERSION,
    MAX_AOT_OPERATION_SET_V1_BYTES, AotDomainV1, AotOperationAxesV1, AotOperationOutputV1,
    AotOperationOutputRecordV1, AotOperationRootV1, AotOperationSetMemberV1,
    AotOperationSetMemberV1View, AotOperationSetV1, AotOperationSetV1Error,
    AotOperationSetV1Parts, AotOperationSetV1View, AotOperationStageV1, AotProjectionV1,
    AotReducerV1,
};
pub use operation_set_v2::{
    AOT_OPERATION_SET_V2_HEADER_BYTES, AOT_OPERATION_SET_V2_IDENTITY_DOMAIN,
    AOT_OPERATION_SET_V2_MAGIC, AOT_OPERATION_SET_V2_MEMBER_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V2_NONE_INDEX, AOT_OPERATION_SET_V2_OUTPUT_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V2_ROOT_DESCRIPTOR_BYTES, AOT_OPERATION_SET_V2_SHARED_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V2_STAGE_DESCRIPTOR_BYTES, AOT_OPERATION_SET_V2_VERSION,
    MAX_AOT_OPERATION_SET_V2_BYTES, AotDomainV2, AotOperationAxesV2, AotOperationOutputRecordV2,
    AotOperationOutputV2, AotOperationRootV2, AotOperationSetMemberInputV2,
    AotOperationSetMemberKindV2, AotOperationSetMemberV2,
    AotOperationSetMemberV2StructuralView, AotOperationSetMemberV2View, AotOperationSetV2,
    AotOperationSetV2Error, AotOperationSetV2StructuralView, AotOperationSetV2View,
    AotOperationStageV2, AotProjectionV2, AotReducerV2,
};
pub use ordered_literal_artifact::{
    MAX_ORDERED_LITERAL_ARTIFACT_V1_BYTES, MAX_ORDERED_LITERAL_ARTIFACT_V1_PATTERNS,
    ORDERED_LITERAL_ARTIFACT_V1_FORMAT_ID, ORDERED_LITERAL_ARTIFACT_V1_HEADER_BYTES,
    ORDERED_LITERAL_ARTIFACT_V1_IDENTITY_DOMAIN, ORDERED_LITERAL_ARTIFACT_V1_MAGIC,
    ORDERED_LITERAL_ARTIFACT_V1_OFFSET_BYTES,
    ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_ID,
    ORDERED_LITERAL_ARTIFACT_V1_OWNED_ACCOUNTING_VERSION,
    ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_ID,
    ORDERED_LITERAL_ARTIFACT_V1_RECONSTRUCTION_ACCOUNTING_VERSION,
    ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_ID,
    ORDERED_LITERAL_ARTIFACT_V1_VALIDATION_ACCOUNTING_VERSION, ORDERED_LITERAL_ARTIFACT_V1_VERSION,
    OrderedLiteralArtifactBoundarySemantics, OrderedLiteralArtifactCensus,
    OrderedLiteralArtifactError, OrderedLiteralArtifactLimits,
    OrderedLiteralArtifactMatchSemantics, OrderedLiteralArtifactOwnedAccounting,
    OrderedLiteralArtifactOwnedOperation, OrderedLiteralArtifactResource,
    OrderedLiteralArtifactSemantics, OrderedLiteralArtifactV1, OrderedLiteralArtifactV1View,
    OrderedLiteralArtifactValidationAccounting, OrderedLiteralCountPlanBuild,
    OrderedLiteralCountPlanReconstructionError, OrderedLiteralCountPlanReconstructionLimits,
    OrderedLiteralCountPlanReconstructionReceipt, OrderedLiteralIterationSemantics,
};
pub use ordered_many::{
    ORDERED_MANY_TAGGED_MAX_ROWS, OrderedManyCompileError, OrderedManyCompileLimits,
    OrderedManyCompileRequest, OrderedManyFallbackReason, OrderedManyFillReport,
    OrderedManyMatch, OrderedManyPatternId, OrderedManyPrepareError, OrderedManyProgram,
    OrderedManyProgramStats, OrderedManyRow, OrderedManyRunError, OrderedManySession,
    OrderedManySessionLimits, OrderedManyStrategy, compile_ordered_many,
};
#[doc(hidden)]
pub use ordered_nfa_native::{
    DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES,
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION,
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_BYTES, FROZEN_ORDERED_NFA_DESCRIPTOR_V1_MAGIC,
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_READY_SEAL, FROZEN_ORDERED_NFA_V1_MAX_DESCRIPTOR_BYTES,
    FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES, FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
    FrozenOrderedNfaAccountingV1,
    FrozenOrderedNfaLimitsV1, FrozenOrderedNfaPreparedScratchV1,
    FrozenOrderedNfaStorageV1,
};
pub use participation_aot::{
    NATIVE_PARTICIPATION_AOT_V1_ABI_VERSION, NATIVE_PARTICIPATION_AOT_V1_HEADER_BYTES,
    NATIVE_PARTICIPATION_AOT_V1_IDENTITY_DOMAIN, NATIVE_PARTICIPATION_AOT_V1_MAGIC,
    NATIVE_PARTICIPATION_AOT_V1_READY_SEAL, NATIVE_PARTICIPATION_AOT_V1_SCRATCH_ALIGN,
    NATIVE_PARTICIPATION_AOT_V1_SCRATCH_BYTES, NATIVE_PARTICIPATION_AOT_V1_STATUS_UNAVAILABLE,
    NATIVE_PARTICIPATION_DFA_V1_ALGORITHM_ID, NativeParticipationAotArtifactV1,
    NativeParticipationAotDeclineV1, NativeParticipationAotErrorV1, NativeParticipationAotLimitsV1,
    NativeParticipationAotReceiptV1, NativeParticipationAotResourceV1,
    NativeParticipationAotStrategyV1,
};
pub use program::{
    AnchoredPrefixStats, CompiledProgram, ContextDeterminizationReport,
    DYNAMIC_NATIVE_ROWS_V1_ACCEPT_MASK, DYNAMIC_NATIVE_ROWS_V1_NEXT_ROW_TOKEN_MASK,
    DYNAMIC_NATIVE_ROWS_V1_UNFILLED_CELL, DYNAMIC_NATIVE_ROWS_V3_ACCEPT_MASK,
    DYNAMIC_NATIVE_ROWS_V3_DEAD_CELL, DYNAMIC_NATIVE_ROWS_V3_NEXT_STATE_TOKEN_MASK,
    DYNAMIC_NATIVE_ROWS_V10_ACCEPT_MASK, DYNAMIC_NATIVE_ROWS_V10_DEAD_CELL,
    DYNAMIC_NATIVE_ROWS_V10_NEXT_STATE_TOKEN_MASK,
    DYNAMIC_NATIVE_ROWS_V11_ACCEPT_BACK_ONE_MASK, DYNAMIC_NATIVE_ROWS_V11_ANY_ACCEPT_MASK,
    DYNAMIC_NATIVE_ROWS_V11_FIRST_DEAD_MASK, DYNAMIC_NATIVE_ROWS_V11_NEXT_BLOCK_TOKEN_MASK,
    DYNAMIC_NATIVE_ROWS_V12_ACCEPT_MASK, DYNAMIC_NATIVE_ROWS_V12_DEAD_CELL,
    DYNAMIC_NATIVE_ROWS_V12_NEXT_STATE_TOKEN_MASK,
    DYNAMIC_NATIVE_ROWS_V13_ACCEPT_BACK_ONE_MASK, DYNAMIC_NATIVE_ROWS_V13_ANY_ACCEPT_MASK,
    DYNAMIC_NATIVE_ROWS_V13_NEXT_BLOCK_TOKEN_MASK,
    DYNAMIC_NATIVE_ROWS_V14_ACCEPT_DISTANCE_MASK, DYNAMIC_NATIVE_ROWS_V14_ANY_ACCEPT_MASK,
    DYNAMIC_NATIVE_ROWS_V14_NEXT_BLOCK_TOKEN_MASK, DynamicNativeRowsHoleResolution,
    DynamicNativeRowsV1, EngineKind,
    EngineSelectionReason,
    FROZEN_COMPACT_LOOP_PLAN_V1_BYTES, FROZEN_COMPACT_LOOP_PLAN_V1_CANONICAL_STATE_OFFSET,
    FROZEN_COMPACT_LOOP_PLAN_V1_MEMBERS_OFFSET, FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
    FROZEN_COMPACT_LOOP_PLAN_V1_START_ACTION_OFFSET, FROZEN_COMPACT_LOOP_SCAN_MIN_BYTES,
    FROZEN_DYNAMIC_ROWS_V3_CACHE_IDENTITY_OFFSET, FROZEN_DYNAMIC_ROWS_V3_CLASS_COUNT_OFFSET,
    FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION_OFFSET,
    FROZEN_DYNAMIC_ROWS_V3_INITIAL_STATE_OFFSET, FROZEN_DYNAMIC_ROWS_V3_LOOP_COUNT_OFFSET,
    FROZEN_DYNAMIC_ROWS_V3_LOOP_STATES_OFFSET, FROZEN_DYNAMIC_ROWS_V3_READY_SEAL_OFFSET,
    FROZEN_DYNAMIC_ROWS_V3_ROWS_ADDRESS_OFFSET, FROZEN_DYNAMIC_ROWS_V3_ROW_SHIFT_OFFSET,
    FROZEN_DYNAMIC_ROWS_V3_STATE_COUNT_OFFSET, FROZEN_DYNAMIC_ROWS_V4_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V5_CACHE_IDENTITY_OFFSET, FROZEN_DYNAMIC_ROWS_V5_CLASS_COUNT_OFFSET,
    FROZEN_DYNAMIC_ROWS_V5_FIRST_ACCEPT_STEP_COMPLEMENT_OFFSET,
    FROZEN_DYNAMIC_ROWS_V5_FIRST_ACCEPT_STEP_OFFSET, FROZEN_DYNAMIC_ROWS_V5_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V5_FORMAT_VERSION_OFFSET, FROZEN_DYNAMIC_ROWS_V5_INITIAL_STATE_OFFSET,
    FROZEN_DYNAMIC_ROWS_V5_LOOP_COUNT_OFFSET, FROZEN_DYNAMIC_ROWS_V5_LOOP_STATES_OFFSET,
    FROZEN_DYNAMIC_ROWS_V5_READY_SEAL_OFFSET, FROZEN_DYNAMIC_ROWS_V5_ROWS_ADDRESS_OFFSET,
    FROZEN_DYNAMIC_ROWS_V5_ROW_SHIFT_OFFSET, FROZEN_DYNAMIC_ROWS_V5_STATE_COUNT_OFFSET,
    FROZEN_DYNAMIC_ROWS_V6_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V6_LOOP_INDEX_ADDRESS_OFFSET,
    FROZEN_DYNAMIC_ROWS_V6_LOOP_INDEX_LENGTH_OFFSET,
    FROZEN_DYNAMIC_ROWS_V6_LOOP_PLAN_COUNT_OFFSET, FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET,
    FROZEN_DYNAMIC_ROWS_V6_RESERVED_OFFSET, FROZEN_DYNAMIC_ROWS_V7_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V8_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V9_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V10_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V11_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V12_FORMAT_VERSION, FROZEN_DYNAMIC_ROWS_V13_FORMAT_VERSION,
    FROZEN_DYNAMIC_ROWS_V14_FORMAT_VERSION,
    FROZEN_DYNAMIC_SIDECAR_MAX_K0_BYTES, FROZEN_DYNAMIC_SIDECAR_MAX_PACKED_BYTES,
    FROZEN_PREPARED_HEADER_V1_ABI_VERSION, FROZEN_PREPARED_HEADER_V1_ABI_VERSION_OFFSET,
    FROZEN_PREPARED_HEADER_V1_ACCEPT_MASK_OFFSET, FROZEN_PREPARED_HEADER_V1_ACTIVE_SEAL,
    FROZEN_PREPARED_HEADER_V1_ACTIVE_SEAL_OFFSET,
    FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET, FROZEN_PREPARED_HEADER_V1_BYTES,
    FROZEN_PREPARED_HEADER_V1_CACHE_IDENTITY_OFFSET, FROZEN_PREPARED_HEADER_V1_CLASS_MAP_OFFSET,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS, FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V3,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V4, FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V5,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V6, FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V7,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V8, FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V9,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V10,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V11,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V12,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V13,
    FROZEN_PREPARED_HEADER_V1_FLAG_DYNAMIC_ROWS_V14,
    FROZEN_PREPARED_HEADER_V1_FLAG_ORDERED_NFA_V15,
    FROZEN_PREPARED_HEADER_V1_FLAG_INITIAL_PENDING,
    FROZEN_PREPARED_HEADER_V1_FLAG_INITIAL_TERMINAL, FROZEN_PREPARED_HEADER_V1_FLAG_REVERSE,
    FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET, FROZEN_PREPARED_HEADER_V1_FORWARD_INITIAL_ROW_OFFSET,
    FROZEN_PREPARED_HEADER_V1_FORWARD_LIVE_CELLS_OFFSET,
    FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET,
    FROZEN_PREPARED_HEADER_V1_HEADER_BYTES_OFFSET, FROZEN_PREPARED_HEADER_V1_MAGIC,
    FROZEN_PREPARED_HEADER_V1_MAGIC_OFFSET, FROZEN_PREPARED_HEADER_V1_NEXT_ROW_TOKEN_MASK_OFFSET,
    FROZEN_PREPARED_HEADER_V1_NO_REVERSE_ROW,
    FROZEN_PREPARED_HEADER_V1_REVERSE_INITIAL_ROW_OFFSET,
    FROZEN_PREPARED_HEADER_V1_REVERSE_LIVE_CELLS_OFFSET,
    FROZEN_PREPARED_HEADER_V1_REVERSE_ROWS_ADDRESS_OFFSET,
    FROZEN_PREPARED_HEADER_V1_ROW_STRIDE_OFFSET, FROZEN_PREPARED_HEADER_V1_UNFILLED_CELL_OFFSET,
    FROZEN_PREPARED_HEADER_V2_BYTES, FROZEN_PREPARED_HEADER_V2_DYNAMIC_ROWS_OFFSET,
    FROZEN_PREPARED_HEADER_V3_BYTES, FROZEN_PREPARED_HEADER_V3_DYNAMIC_ROWS_OFFSET,
    FROZEN_PREPARED_HEADER_V3_READY_SEAL, FROZEN_PREPARED_HEADER_V4_BYTES,
    FROZEN_PREPARED_HEADER_V4_DYNAMIC_ROWS_OFFSET, FROZEN_PREPARED_HEADER_V4_READY_SEAL,
    FROZEN_PREPARED_HEADER_V5_BYTES, FROZEN_PREPARED_HEADER_V5_DYNAMIC_ROWS_OFFSET,
    FROZEN_PREPARED_HEADER_V5_READY_SEAL, FROZEN_PREPARED_HEADER_V6_BYTES,
    FROZEN_PREPARED_HEADER_V6_DYNAMIC_ROWS_OFFSET, FROZEN_PREPARED_HEADER_V6_READY_SEAL,
    FROZEN_PREPARED_HEADER_V7_BYTES, FROZEN_PREPARED_HEADER_V7_DYNAMIC_ROWS_OFFSET,
    FROZEN_PREPARED_HEADER_V7_READY_SEAL,
    FROZEN_PREPARED_HEADER_V8_BYTES, FROZEN_PREPARED_HEADER_V8_DYNAMIC_ROWS_OFFSET,
    FROZEN_PREPARED_HEADER_V8_READY_SEAL, FROZEN_PREPARED_HEADER_V9_BYTES,
    FROZEN_PREPARED_HEADER_V9_DYNAMIC_ROWS_OFFSET, FROZEN_PREPARED_HEADER_V9_READY_SEAL,
    FROZEN_PREPARED_HEADER_V10_BYTES, FROZEN_PREPARED_HEADER_V10_DYNAMIC_ROWS_OFFSET,
    FROZEN_PREPARED_HEADER_V10_READY_SEAL,
    FROZEN_PREPARED_HEADER_V11_BYTES, FROZEN_PREPARED_HEADER_V11_DYNAMIC_ROWS_OFFSET,
    FROZEN_PREPARED_HEADER_V11_READY_SEAL, FROZEN_PREPARED_HEADER_V12_BYTES,
    FROZEN_PREPARED_HEADER_V12_DYNAMIC_ROWS_OFFSET, FROZEN_PREPARED_HEADER_V12_READY_SEAL,
    FROZEN_PREPARED_HEADER_V13_BYTES,
    FROZEN_PREPARED_HEADER_V13_DYNAMIC_ROWS_OFFSET, FROZEN_PREPARED_HEADER_V13_READY_SEAL,
    FROZEN_PREPARED_HEADER_V14_BYTES, FROZEN_PREPARED_HEADER_V14_DYNAMIC_ROWS_OFFSET,
    FROZEN_PREPARED_HEADER_V14_READY_SEAL, FROZEN_PREPARED_HEADER_V15_BYTES,
    FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET, FROZEN_PREPARED_HEADER_V15_READY_SEAL,
    FROZEN_ORDERED_NFA_V15_FORMAT_VERSION, FrozenCompactLoopPlanV1, FrozenCompactLoopScanner,
    FrozenStaticContinuationRowsStorageV1, FrozenDynamicRowsStorage,
    FrozenDynamicRowsStorageV3, FrozenDynamicRowsV3, FrozenDynamicRowsV5,
    FrozenDynamicRowsV6, FrozenRetainedPartialResumeProjection,
    FrozenStaticPrefixResumeProjection, FrozenStaticPrefixResumeSelection,
    FrozenPreparedHeaderOwnerGenerationKey, FrozenPreparedHeaderV1, FrozenPreparedHeaderV2,
    FrozenPreparedHeaderV3,
    FrozenPreparedHeaderV5, FrozenPreparedHeaderV6,
    FullyPrefilledFallbackReceipt, GENERIC_NFA_PROGRAM_FORMAT_VERSION,
    GenericNfaProgramCensus, GenericNfaProgramCensusError, MAX_ANCHORED_PREFIX_BYTES,
    MAX_SERIALIZED_PROGRAM_BYTES, MatchResult, OutputContract, PROGRAM_HEADER_LEN,
    PartialDfaStats, ProgramFormatError, ProgramStats, ProgramWorkspace,
    RetainedPartialPreflight, SearchWindow,
    ColdStaticPrefixResumeObject, StaticPrefixResumeAdmission,
    StaticPrefixResumeAdmissionPlan, StaticPrefixResumeDescriptorKey,
    StaticPrefixResumeSearchOutcome, StaticPrefixSpanRecoveryAdmission,
    STATIC_PREFIX_INVOCATION_EPOCH_OFFSET,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V1_HEADER_BYTES,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAGIC, STATIC_PREFIX_RESUME_DESCRIPTOR_V1_MAX_BYTES,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V1_STATE_BYTES, STATIC_PREFIX_RESUME_DESCRIPTOR_V1_VERSION,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V2_HEADER_BYTES,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V2_MAGIC, STATIC_PREFIX_RESUME_DESCRIPTOR_V2_STATE_BYTES,
    STATIC_PREFIX_RESUME_DESCRIPTOR_V2_VERSION,
};
pub use regex_set::{
    RegexSetArtifactIdentity, RegexSetCompileError, RegexSetCompileLimits,
    RegexSetCompileRequest, RegexSetFillReport, RegexSetOutputError, RegexSetPatternIds,
    RegexSetPrepareError, RegexSetProgram, RegexSetProgramShapeError, RegexSetProgramStats,
    RegexSetRunError, RegexSetSession, RegexSetSessionLimits, compile_regex_set,
};
pub use rebar_single_capture::{
    REBAR_SINGLE_CAPTURE_AOT_V1_IDENTITY_DOMAIN, REBAR_SINGLE_CAPTURE_AOT_V1_SOURCE_CARDINALITY,
    REBAR_SINGLE_CAPTURE_PARTICIPATION_AOT_V1_IDENTITY_DOMAIN,
    RebarSingleCaptureAotArtifactV1, RebarSingleCaptureAotError, RebarSingleCaptureAotReceiptV1,
    RebarSingleCaptureAotRequestV1, RebarSingleCaptureCardinalityError,
    RebarSingleCaptureEmptyProgressV1, RebarSingleCaptureParticipationAotArtifactV1,
    RebarSingleCaptureParticipationAotErrorV1, RebarSingleCaptureParticipationAotReceiptV1,
    compile_rebar_single_capture_aot_v1, compile_rebar_single_capture_participation_aot_v1,
};
pub use uniform_capture::{
    CompiledUniformCapturePreparedSpanFillSelector, CompiledUniformCaptureSelector,
    UniformCaptureAuthenticationError,
    UniformCaptureCompileDisposition, UniformCaptureCompileError, UniformCaptureCompileReceipt,
    UniformCaptureCompileRequest, UniformCapturePreparedSpanFillAuthenticationError,
    UniformCapturePreparedSpanFillCompileDisposition,
    UniformCapturePreparedSpanFillCompileError, UniformCapturePreparedSpanFillCompileReceipt,
    compile_uniform_capture_prepared_span_fill_selector, compile_uniform_capture_selector,
};

/// Stable compiler pipeline identity.
pub const COMPILER_VERSION: u32 = 1;
/// Stable optimizer/cost-model identity.
pub const OPTIMIZER_VERSION: u32 = 25;
/// Schema identity for the opt-in experimental compile request and receipt.
pub const COMPILE_REQUEST_V2_SCHEMA_VERSION: u32 = 2;
/// Optimizer identity for the opt-in accelerated-incumbent Teddy experiment.
///
/// The stable V1 receipt deliberately retains [`OPTIMIZER_VERSION`], including
/// when a V2 request uses `Automatic`, so existing evidence is not relabeled.
pub const EXPERIMENTAL_OPTIMIZER_VERSION_V2: u32 = 26;

/// Deterministic pass identity retained in every compiler receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OptimizationPass {
    ValidateAutomaton,
    CanonicalDigest,
    AnchoredPrefixAnalysis,
    UniversalOrderedTnfa,
    OrderedDeterminization,
    CompilerK0Closure,
    OrderedFiniteLanguageLowering,
    ExactFiniteSelectedEndTeddyLowering,
    ExactFiniteExistsByteSetLowering,
    ExactFiniteExistsSingleLiteralLowering,
    ContextOrderedDeterminization,
    ContextNativeLowering,
    DfaStateMinimization,
    ReverseStartRecovery,
    ExactWidthStartRecovery,
    AlphabetPartition,
    AlphabetColumnCoalescing,
    RemoveUnusedReverseMachine,
    OutputContractSpecialization,
    ConstantFold,
    StrengthReduceRowAddressing,
    StartStateScanAcceleration,
    AnchoredPrefixCandidateFilter,
    TargetInstructionSelection,
    FixedRegisterAssignment,
    CheckedBranchFixup,
    BitParallelEndpointOracleLowering,
    NativeOrderedTnfaLowering,
    PreparedAggregateLowering,
    RuntimeAdapterLowering,
    PositionIndependentDataLayout,
    RelocatableObjectSerialization,
}

/// User-selected compilation strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileMode {
    /// Freeze the general ordered-TNFA plan with minimal analysis.
    Fast,
    /// Run complete ordered determinization and target optimization.
    Optimizing,
}

/// Opt-in policy for the V2 exact-finite `SelectedEnd` Teddy experiment.
///
/// `ForceStructurallyEligible` bypasses only result-blind performance
/// admission. It does not bypass finite-language proof, output/ABI, target,
/// plan geometry, resource, or receipt-authentication checks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExactFiniteSelectedEndTeddyPolicyV2 {
    /// Do not consider the Teddy wrapper.
    Disabled,
    /// Preserve the stable V1 selector exactly.
    #[default]
    Automatic,
    /// Admit every otherwise-valid structural candidate for measurement.
    ForceStructurallyEligible,
}

/// Exact C entry-point ABI emitted for one capture-free output contract.
///
/// Consumers that turn a symbol address into a typed function pointer must
/// check this receipt field in addition to the semantic output contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryAbi {
    ExistsSearchV1,
    SelectedEndSearchV1,
    SpanSearchV1,
}

impl EntryAbi {
    const fn for_output(output: OutputContract) -> Self {
        match output {
            OutputContract::Exists => Self::ExistsSearchV1,
            OutputContract::SelectedEnd => Self::SelectedEndSearchV1,
            OutputContract::Span => Self::SpanSearchV1,
        }
    }
}

/// Checked limits for one complete compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimitsV1 {
    pub lower: LowerLimits,
    pub determinize: DeterminizeLimits,
    pub max_program_bytes: usize,
    pub max_object_bytes: usize,
}

impl Default for CompileLimitsV1 {
    fn default() -> Self {
        Self {
            lower: LowerLimits::default(),
            determinize: DeterminizeLimits::default(),
            max_program_bytes: 256 * 1024 * 1024,
            max_object_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Complete explicit compiler request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileRequest {
    pub pattern: String,
    pub profile: RustProfile,
    pub output: OutputContract,
    pub target: Target,
    pub mode: CompileMode,
    pub limits: CompileLimitsV1,
}

impl CompileRequest {
    #[must_use]
    pub fn new(pattern: impl Into<String>, target: Target) -> Self {
        let profile = RustProfile::default();
        let mut limits = CompileLimitsV1::default();
        if let Some(limit) = rust_profile_compiled_size_limit(&profile) {
            limits.max_program_bytes = limit;
        }
        Self {
            pattern: pattern.into(),
            profile,
            output: OutputContract::Span,
            target,
            mode: CompileMode::Optimizing,
            limits,
        }
    }

    #[must_use]
    pub const fn output(mut self, output: OutputContract) -> Self {
        self.output = output;
        self
    }

    #[must_use]
    pub const fn mode(mut self, mode: CompileMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub const fn limits(mut self, limits: CompileLimitsV1) -> Self {
        self.limits = limits;
        set_rust_profile_compiled_size_limit(&mut self.profile, limits.max_program_bytes);
        self
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self.limits.max_program_bytes = rust_profile_compiled_size_limit(&self.profile)
            .unwrap_or(CompileLimitsV1::default().max_program_bytes);
        self
    }

    /// Set the maximum bytes in FRE's stable serialized semantic program.
    #[must_use]
    pub fn size_limit(mut self, bytes: usize) -> Self {
        set_rust_profile_compiled_size_limit(&mut self.profile, bytes);
        self.limits.max_program_bytes = bytes;
        self
    }

    /// Retain the Rust-like lazy-DFA cache option. FRE's AOT compiler does not
    /// use that cache, so this does not change compilation or execution.
    #[must_use]
    pub fn dfa_size_limit(mut self, bytes: usize) -> Self {
        if let RustConstructor::RegexBuilder { dfa_size_limit, .. } = &mut self.profile.constructor
        {
            *dfa_size_limit = u64::try_from(bytes).unwrap_or(u64::MAX);
        }
        self
    }
}

/// Versioned opt-in request for experimental compiler policies.
///
/// Keeping this wrapper separate leaves [`CompileRequest`] and [`compile`]
/// source-compatible and preserves their stable V1 receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileRequestV2 {
    pub request: CompileRequest,
    pub exact_finite_selected_end_teddy: ExactFiniteSelectedEndTeddyPolicyV2,
}

impl CompileRequestV2 {
    #[must_use]
    pub const fn new(request: CompileRequest) -> Self {
        Self {
            request,
            exact_finite_selected_end_teddy: ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
        }
    }

    #[must_use]
    pub const fn exact_finite_selected_end_teddy(
        mut self,
        policy: ExactFiniteSelectedEndTeddyPolicyV2,
    ) -> Self {
        self.exact_finite_selected_end_teddy = policy;
        self
    }
}

pub(crate) fn rust_profile_compiled_size_limit(profile: &RustProfile) -> Option<usize> {
    match &profile.constructor {
        RustConstructor::RegexBuilder { size_limit, .. }
        | RustConstructor::RegexSetBuilder { size_limit, .. } => {
            Some(usize::try_from(*size_limit).unwrap_or(usize::MAX))
        }
        RustConstructor::RebarMeta { .. } => None,
    }
}

pub(crate) const fn set_rust_profile_compiled_size_limit(
    profile: &mut RustProfile,
    bytes: usize,
) {
    match &mut profile.constructor {
        RustConstructor::RegexBuilder { size_limit, .. }
        | RustConstructor::RegexSetBuilder { size_limit, .. } => {
            // Every Rust 1.93 target pointer width fits in `u64`, so this is
            // equivalent to the former saturating conversion and is const.
            *size_limit = bytes as u64;
        }
        RustConstructor::RebarMeta { .. } => {}
    }
}

/// Structural, source-independent record of the selected compiler route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileReceipt {
    pub compiler_version: u32,
    pub optimizer_version: u32,
    pub mode: CompileMode,
    pub output: OutputContract,
    /// Versioned callable contract for the exported ordinary entry symbol.
    pub entry_abi: EntryAbi,
    pub target: Target,
    /// Byte configured as the line terminator for this semantic program.
    pub line_terminator: u8,
    pub automaton_sha256: [u8; 32],
    /// SHA-256 of [`CompiledProgram::serialize`] for this compilation.
    pub program_sha256: [u8; 32],
    /// SHA-256 of the complete emitted relocatable object.
    pub object_sha256: [u8; 32],
    pub engine: EngineKind,
    pub engine_selection_reason: EngineSelectionReason,
    /// Requested/effective limits, completed stages, and any exact resource
    /// decline from target-neutral determinization.
    pub determinization: DeterminizationReport,
    /// A separately bounded second determinization actually selected by the
    /// slow optimizing AOT compiler. The semantic-program report above is
    /// never overwritten, including when its first attempt declined.
    pub slow_aot: Option<SlowAotReport>,
    /// A complete compiler-owned K0 closure selected into the native module.
    /// This is distinct from ordered determinization provenance.
    pub compiler_k0_aot: Option<CompilerK0AotReport>,
    /// Authenticated direct exact one-byte `Exists` lowering, when selected.
    pub exact_finite_exists_byte_set_aot: Option<ExactFiniteExistsByteSetAotReport>,
    /// Authenticated direct exact wide single-literal `Exists` lowering, when
    /// selected.
    pub exact_single_literal_aot: Option<ExactSingleLiteralAotReport>,
    /// Direct exact finite-language Teddy `SelectedEnd` leaf, when selected.
    pub exact_finite_selected_end_teddy_aot: Option<ExactFiniteSelectedEndTeddyAotReport>,
    /// Authenticated target-neutral and native-data geometry for a selected
    /// ordered finite-language leaf. This is never stable program data.
    pub ordered_finite_language_aot: Option<OrderedFiniteLanguageAotReport>,
    /// A separately bounded contextual machine rebuilt from the retained
    /// graph and actually selected into the native module. This never
    /// overwrites `context_determinization` and is absent after a later
    /// native-data or object-size fallback.
    pub slow_context_aot: Option<SlowContextAotReport>,
    pub source_bytes: usize,
    pub thompson_states: usize,
    pub thompson_edges: usize,
    pub dfa: Option<DfaStats>,
    /// Fresh contextual-determinization outcome. This is absent when no
    /// contextual attempt occurred and after stable program deserialization.
    pub context_determinization: Option<ContextDeterminizationReport>,
    /// Bounded, graph-only required-prefix facts derived for this program.
    pub anchored_prefix: AnchoredPrefixStats,
    /// Consumed byte width shared by every accepting path, when proved from
    /// the complete lowered graph under a fixed work ceiling.
    pub exact_match_width: Option<usize>,
    pub passes: Box<[OptimizationPass]>,
    pub runtime_helper_required: bool,
    /// Additive prepared scalar and matching-line reducers exported by the
    /// object.
    pub prepared_aggregate_exports: PreparedAggregateExports,
    /// Backend selected for the additive prepared scalar reducers.
    pub prepared_aggregate_strategy: Option<PreparedAggregateStrategy>,
    /// Exact capability mask that runtime prepare V3 must require before this
    /// object's capability-bound prepared bulk or aggregate routes are used.
    /// The public scalar prepared-search entry retains its authenticated
    /// whole-search compatibility edge for V1/V2 handles.
    pub required_prepare_capabilities: u64,
    /// Start or candidate scanner actually present in the native module.
    pub start_accelerator: StartAccelerator,
    /// Required prefix depth checked before a native start candidate enters
    /// the DFA, or zero when no multi-byte filter was emitted.
    pub anchored_prefix_filter_bytes: u8,
    pub program_bytes: usize,
    pub code_bytes: usize,
    pub data_bytes: usize,
    pub object_bytes: usize,
}

/// One complete compiler result.
#[derive(Clone, Debug)]
pub struct CompiledRegex {
    program: CompiledProgram,
    module: CompiledModule,
    object: Box<[u8]>,
    receipt: CompileReceipt,
}

/// Supplemental receipt for one V2 experimental request.
///
/// The stable V1 receipt remains available from [`CompiledRegex::receipt`]
/// and is not rewritten. In particular, a forced V2 route never appears in
/// the V1 Teddy field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileReceiptV2 {
    pub schema_version: u32,
    pub optimizer_version: u32,
    pub exact_finite_selected_end_teddy_policy: ExactFiniteSelectedEndTeddyPolicyV2,
    pub exact_finite_selected_end_teddy_aot: Option<ExactFiniteSelectedEndTeddyAotReportV2>,
}

/// Compiler result carrying both the unchanged stable receipt and the V2
/// experimental supplement.
#[derive(Clone, Debug)]
pub struct CompiledRegexV2 {
    compiled: CompiledRegex,
    receipt_v2: CompileReceiptV2,
}

impl CompiledRegexV2 {
    #[must_use]
    pub const fn compiled(&self) -> &CompiledRegex {
        &self.compiled
    }

    #[must_use]
    pub const fn receipt_v2(&self) -> &CompileReceiptV2 {
        &self.receipt_v2
    }

    #[must_use]
    pub fn into_compiled(self) -> CompiledRegex {
        self.compiled
    }
}

impl core::ops::Deref for CompiledRegexV2 {
    type Target = CompiledRegex;

    fn deref(&self) -> &Self::Target {
        &self.compiled
    }
}

/// Reusable execution storage prepared by an AOT compiler result.
///
/// This wrapper is intentionally distinct from [`ProgramWorkspace`]. It lets
/// the AOT facade select a retained partial-DFA entry without adding a field
/// load or branch to [`CompiledProgram::search_with_workspace`].
#[derive(Debug)]
pub struct CompiledRegexWorkspace {
    program: ProgramWorkspace,
}

impl CompiledRegex {
    #[cfg(test)]
    pub(crate) fn inject_test_only_runtime_program_dependency(&mut self) {
        self.module.inject_test_only_runtime_program_dependency();
    }

    #[must_use]
    pub const fn program(&self) -> &CompiledProgram {
        &self.program
    }

    #[must_use]
    pub const fn module(&self) -> &CompiledModule {
        &self.module
    }

    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &CompileReceipt {
        &self.receipt
    }

    /// Allocate reusable execution storage for this compiler result.
    ///
    /// # Errors
    ///
    /// Returns a portable executor error if the universal NFA workspace
    /// cannot be prepared.
    pub fn prepare_workspace(&self) -> Result<CompiledRegexWorkspace, CompileError> {
        Ok(CompiledRegexWorkspace {
            program: self.program.prepare_workspace()?,
        })
    }

    /// Execute with storage prepared by this AOT compiler result.
    ///
    /// Retained rows are selected through the program's separate optimizing
    /// entry, outside the ordinary semantic dispatch. Short windows use the
    /// exact ordinary prepared entry because retained-row setup has a fixed
    /// cost that they cannot amortize.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-window error before reading the haystack, a
    /// portable executor error, or an invariant error if `workspace` belongs
    /// to a different semantic program.
    #[inline(never)]
    pub fn search_with_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut CompiledRegexWorkspace,
    ) -> Result<MatchResult, CompileError> {
        self.program
            .search_optimized_with_workspace(haystack, window, &mut workspace.program)
    }

    /// Execute the compiler's target-neutral semantic program.
    ///
    /// This is the differential-testing and portable-adoption boundary. Native
    /// consumers link the emitted object and the versioned runtime entry
    /// declared by [`CompiledModule::required_runtime_symbol`].
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid search window.
    pub fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        let mut workspace = self.prepare_workspace()?;
        self.search_with_workspace(haystack, window, &mut workspace)
    }
}

impl CompiledModule {
    /// Return the unresolved runtime helper required when linking this module.
    ///
    /// Direct native byte-local and contextual DFA modules return `None`. The existing
    /// [`Self::runtime_symbol`] method remains a compatibility accessor for the
    /// stable helper name, even when no helper is required.
    #[must_use]
    pub fn required_runtime_symbol(&self) -> Option<&str> {
        let compatibility_name = self.runtime_symbol();
        self.symbols()
            .iter()
            .find(|symbol| symbol.section.is_none() && symbol.name == compatibility_name)
            .map(|symbol| symbol.name.as_str())
    }
}

/// Compile a Rust byte regex through the general AOT pipeline.
///
/// Every pattern that reaches lowering enters the same automaton pipeline.
/// Selection depends only on the validated graph, output contract, explicit
/// target, mode, and limits. The returned [`CompileReceipt`] records the exact
/// structural engine-selection reason and SHA-256 identities for both the
/// semantic program and emitted object.
///
/// # Errors
///
/// Returns a typed syntax, lowering, resource, determinization, target, or
/// object-production failure.
pub fn compile(request: CompileRequest) -> Result<CompiledRegex, CompileError> {
    compile_with_slow_aot_limits(request, SlowAotLimits::default())
}

/// Compile with an explicit V2 experimental-selection policy.
///
/// The returned result retains the stable [`CompileReceipt`] unchanged and
/// carries policy/selection provenance in [`CompileReceiptV2`].
///
/// # Errors
///
/// Returns the same typed failures as [`compile`].
pub fn compile_v2(request: CompileRequestV2) -> Result<CompiledRegexV2, CompileError> {
    compile_v2_with_slow_aot_limits(request, SlowAotLimits::default())
}

/// Compile a V2 request with an explicit optional-native resource envelope.
///
/// # Errors
///
/// Returns the same typed failures as [`compile_with_slow_aot_limits`].
pub fn compile_v2_with_slow_aot_limits(
    request: CompileRequestV2,
    slow_aot_limits: SlowAotLimits,
) -> Result<CompiledRegexV2, CompileError> {
    let policy = request.exact_finite_selected_end_teddy;
    let compiled =
        compile_with_slow_aot_limits_and_teddy_policy_v2(request.request, slow_aot_limits, policy)?;
    let exact_finite_selected_end_teddy_aot = match policy {
        ExactFiniteSelectedEndTeddyPolicyV2::Disabled => None,
        ExactFiniteSelectedEndTeddyPolicyV2::Automatic => compiled
            .module()
            .exact_finite_selected_end_teddy_aot_report()
            .copied()
            .map(|report| {
                let incumbent_prefix =
                    module::exact_finite_selected_end_teddy_incumbent_prefix_bytes(
                        compiled.program(),
                        compiled.receipt().target,
                        &report,
                    )?;
                module::exact_finite_selected_end_teddy_report_v2(
                    report,
                    policy,
                    ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
                    incumbent_prefix,
                )
            })
            .transpose()?,
        ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible => compiled
            .module()
            .exact_finite_selected_end_teddy_aot_report_v2()
            .copied(),
    };
    if policy == ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible
        && compiled
            .module()
            .exact_finite_selected_end_teddy_aot_report()
            .is_some()
    {
        return Err(CompileError::InternalInvariant(
            "forced Teddy V2 route leaked into the stable V1 receipt",
        ));
    }
    Ok(CompiledRegexV2 {
        compiled,
        receipt_v2: CompileReceiptV2 {
            schema_version: COMPILE_REQUEST_V2_SCHEMA_VERSION,
            optimizer_version: EXPERIMENTAL_OPTIMIZER_VERSION_V2,
            exact_finite_selected_end_teddy_policy: policy,
            exact_finite_selected_end_teddy_aot,
        },
    })
}

/// Compile a program and append explicitly requested prepared reducer
/// exports.
///
/// The ordinary search, prepared search, and stable semantic-program bytes are
/// identical to [`compile`]. The additive identity-suffixed Count and
/// `SpanSum` entries use complete Rust-byte iterator semantics without
/// materializing a caller-visible span buffer. `GREP_COUNT` instead counts
/// matching LF/CRLF line domains in one ordered source pass. Every entry uses
/// the same exclusive prepared handle. Requesting no exports is exactly
/// equivalent to [`compile`].
///
/// # Errors
///
/// Returns [`CompileError::PreparedAggregateRequiresSpan`] when Count or
/// `SpanSum` is requested on another output contract. A grep-only export is
/// valid for all output contracts. Otherwise returns the same compiler/object
/// errors as [`compile`], including the final object-size check after appending
/// the reducer entries.
pub fn compile_with_prepared_aggregate_exports(
    request: CompileRequest,
    exports: PreparedAggregateExports,
) -> Result<CompiledRegex, CompileError> {
    compile_with_prepared_aggregate_exports_and_slow_aot_limits(
        request,
        exports,
        SlowAotLimits::default(),
    )
}

/// Compile with prepared reducers and an explicit resource envelope for the
/// separately selected slow AOT completion pass.
///
/// This is the prepared-export counterpart to [`compile_with_slow_aot_limits`].
/// It leaves the semantic-program limits in [`CompileRequest`] independent of
/// the later optional native completion work.
///
/// # Errors
///
/// Returns the same typed failures as
/// [`compile_with_prepared_aggregate_exports`]. Exhausting a slow-AOT numeric
/// resource declines that optional candidate and preserves bounded fallbacks.
pub fn compile_with_prepared_aggregate_exports_and_slow_aot_limits(
    request: CompileRequest,
    exports: PreparedAggregateExports,
    slow_aot_limits: SlowAotLimits,
) -> Result<CompiledRegex, CompileError> {
    if exports.is_empty() {
        return compile_with_slow_aot_limits(request, slow_aot_limits);
    }
    let span_reducers_requested = exports.contains(PreparedAggregateExports::COUNT)
        || exports.contains(PreparedAggregateExports::SPAN_SUM);
    if span_reducers_requested && request.output != OutputContract::Span {
        return Err(CompileError::PreparedAggregateRequiresSpan {
            actual: request.output,
        });
    }
    let target = request.target;
    let max_object_bytes = request.limits.max_object_bytes;
    let effective_native_data_limit_bytes = match request.mode {
        CompileMode::Fast => usize::MAX,
        CompileMode::Optimizing => slow_aot_limits
            .max_native_data_bytes
            .min(max_object_bytes),
    };
    let CompiledRegex {
        program,
        module,
        object,
        mut receipt,
    } = compile_with_slow_aot_limits(request, slow_aot_limits)?;
    drop(object);
    let artifact_identity = program.artifact_identity();
    let serialized_program = program.serialize()?;
    let exact_teddy_incumbent = module
        .exact_finite_selected_end_teddy_aot_report()
        .copied();
    let module =
        module.append_prepared_aggregate_exports(exports, artifact_identity, &serialized_program)?;
    let ordered_nfa_selected = module.required_prepare_capabilities()
        & PREPARED_CAPABILITY_ORDERED_NFA_V15
        != 0;
    let format = ObjectFormat::for_target(target);
    let (module, object) = match emit_with_ordered_nfa_accelerator_retries(
        module,
        format,
        max_object_bytes,
        || {
            let without_exact_set = CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                &program, target, false, true, true, true, true, true, true, false,
                effective_native_data_limit_bytes,
            )?;
            Ok(without_exact_set.append_prepared_aggregate_exports(
                exports,
                artifact_identity,
                &serialized_program,
            )?)
        },
        || {
            let without_width = CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                &program, target, false, true, true, true, true, true, false, false,
                effective_native_data_limit_bytes,
            )?;
            Ok(without_width.append_prepared_aggregate_exports(
                exports,
                artifact_identity,
                &serialized_program,
            )?)
        },
        || {
            let without_prefix = CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                &program, target, false, true, true, true, true, false, false, false,
                effective_native_data_limit_bytes,
            )?;
            Ok(without_prefix.append_prepared_aggregate_exports(
                exports,
                artifact_identity,
                &serialized_program,
            )?)
        },
        || {
            let without_start = CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                &program, target, false, true, true, true, false, false, false, false,
                effective_native_data_limit_bytes,
            )?;
            Ok(without_start.append_prepared_aggregate_exports(
                exports,
                artifact_identity,
                &serialized_program,
            )?)
        },
        || {
            let without_terminal = CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                &program, target, false, true, true, false, false, false, false, false,
                effective_native_data_limit_bytes,
            )?;
            Ok(without_terminal.append_prepared_aggregate_exports(
                exports,
                artifact_identity,
                &serialized_program,
            )?)
        },
        || {
            let scalar_base = CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                &program, target, false, true, false, false, false, false, false, false,
                effective_native_data_limit_bytes,
            )?;
            Ok(scalar_base.append_prepared_aggregate_exports(
                exports,
                artifact_identity,
                &serialized_program,
            )?)
        },
    )? {
        FinalObjectAttempt::Fit { module, object } => (module, object),
        FinalObjectAttempt::ObjectBytes {
            first_error: first,
            ..
        } if ordered_nfa_selected || exact_teddy_incumbent.is_some() => {
            // The aggregate additions are part of the same object-size
            // transaction as the base module. If the additive Ordered-TNFA
            // V3 object fit by itself but the complete object does not, the
            // shared retry above preserves V2 dispatch and then scalar V1.
            // Only after V1 also exceeds the ceiling do we rebuild the
            // incumbent adapter and its whole-operation helpers exactly once.
            //
            // The direct exact-finite Teddy wrapper has the same transaction:
            // its report authenticates the byte-identical complete-DFA
            // incumbent and its exact data extent. The ordinary (non-slow)
            // fallback scheduler excludes the Teddy wrapper and publishes the
            // established semantic DFA. Reusing the authenticated incumbent
            // extent as its ceiling prevents a larger optional route from
            // replacing that fallback. The postcondition below authenticates
            // the exact incumbent before aggregation.
            let fallback_native_data_limit_bytes = exact_teddy_incumbent
                .map_or(effective_native_data_limit_bytes, |report| {
                    effective_native_data_limit_bytes.min(report.incumbent_data_bytes)
                });
            let fallback = CompiledModule::lower_with_native_data_limit_and_optional_routes(
                &program,
                target,
                false,
                false,
                fallback_native_data_limit_bytes,
            )?;
            if let Some(report) = exact_teddy_incumbent {
                let code = fallback
                    .sections()
                    .iter()
                    .find(|section| section.kind == SectionKind::Text)
                    .ok_or(CompileError::InternalInvariant(
                        "exact finite SelectedEnd Teddy aggregate fallback has no text",
                    ))?;
                let data = fallback
                    .sections()
                    .iter()
                    .find(|section| section.kind == SectionKind::ReadOnlyData)
                    .ok_or(CompileError::InternalInvariant(
                        "exact finite SelectedEnd Teddy aggregate fallback has no data",
                    ))?;
                let code_sha256: [u8; 32] = Sha256::digest(code.bytes()).into();
                let data_sha256: [u8; 32] = Sha256::digest(data.bytes()).into();
                if fallback
                    .exact_finite_selected_end_teddy_aot_report()
                    .is_some()
                    || fallback.exact_finite_exists_byte_set_aot_report().is_some()
                    || fallback.exact_single_literal_aot_report().is_some()
                    || fallback.ordered_finite_language_aot_report().is_some()
                    || fallback.slow_aot_report().is_some()
                    || fallback.slow_context_aot_report().is_some()
                    || fallback.compiler_k0_aot_report().is_some()
                    || fallback.required_runtime_symbols().next().is_some()
                    || fallback.start_accelerator()
                        != report.incumbent_complete_dfa.scanner
                    || code.bytes().len() != report.incumbent_code_bytes
                    || data.bytes().len() != report.incumbent_data_bytes
                    || code_sha256 != report.incumbent_code_sha256
                    || data_sha256 != report.incumbent_data_sha256
                    || fallback.relocations().len()
                        != report.incumbent_relocation_count
                    || crate::module::exact_finite_selected_end_relocation_digest(
                        fallback.relocations(),
                    ) != Some(report.incumbent_relocations_sha256)
                {
                    return Err(CompileError::InternalInvariant(
                        "exact finite SelectedEnd Teddy aggregate fallback did not restore the authenticated semantic DFA incumbent",
                    ));
                }
            }
            let fallback = fallback.append_prepared_aggregate_exports(
                exports,
                artifact_identity,
                &serialized_program,
            )?;
            match emit_object(&fallback, format, max_object_bytes) {
                Ok(object) => (fallback, object),
                Err(ObjectError::Resource {
                    resource: CompileResource::ObjectBytes,
                    ..
                }) => return Err(first.into()),
                Err(error) => return Err(error.into()),
            }
        }
        FinalObjectAttempt::ObjectBytes { first_error, .. } => {
            return Err(first_error.into());
        }
    };
    drop(serialized_program);
    let mut passes = selected_passes(&program, &module);
    passes
        .try_reserve_exact(1)
        .map_err(|_| ObjectError::Allocation("prepared aggregate pass receipt"))?;
    let aggregate_index = passes
        .iter()
        .position(|pass| *pass == OptimizationPass::PositionIndependentDataLayout)
        .unwrap_or(passes.len());
    passes.insert(
        aggregate_index,
        OptimizationPass::PreparedAggregateLowering,
    );
    receipt.passes = passes.into_boxed_slice();
    receipt.object_sha256 = Sha256::digest(&object).into();
    receipt.slow_aot = module.slow_aot_report().cloned();
    receipt.compiler_k0_aot = module.compiler_k0_aot_report().cloned();
    receipt.exact_finite_exists_byte_set_aot = module
        .exact_finite_exists_byte_set_aot_report()
        .copied();
    receipt.exact_single_literal_aot = module.exact_single_literal_aot_report().copied();
    receipt.ordered_finite_language_aot = module
        .ordered_finite_language_aot_report()
        .copied();
    receipt.exact_finite_selected_end_teddy_aot = module
        .exact_finite_selected_end_teddy_aot_report()
        .copied();
    receipt.slow_context_aot = module.slow_context_aot_report().cloned();
    receipt.runtime_helper_required = module.required_runtime_symbols().next().is_some();
    receipt.prepared_aggregate_exports = module.prepared_aggregate_exports();
    receipt.prepared_aggregate_strategy = module.prepared_aggregate_strategy();
    receipt.required_prepare_capabilities = module.required_prepare_capabilities();
    receipt.start_accelerator = module.start_accelerator();
    receipt.anchored_prefix_filter_bytes = module.anchored_prefix_filter_bytes();
    receipt.code_bytes = module.code_bytes();
    receipt.data_bytes = module
        .sections()
        .iter()
        .filter(|section| section.kind == SectionKind::ReadOnlyData)
        .map(|section| section.data.len())
        .sum();
    receipt.object_bytes = object.len();
    Ok(CompiledRegex {
        program,
        module,
        object: object.into_boxed_slice(),
        receipt,
    })
}

/// Compile one regex through only the prepared Ordered-NFA V15 backend,
/// optionally appending prepared reducer exports.
///
/// This explicit route does not alter or consult the ordinary optimizer's
/// DFA, partial-row, dynamic-row, or endpoint-oracle backend ordering. Once
/// parsing and lowering succeed, unsupported Ordered-NFA structure, native
/// data limits, allocation failures, code-generation failures, and final
/// object limits are terminal. The returned module is authenticated to publish
/// [`PreparedBulkStrategy::NativeOrderedNfaLoop`], SpanFill, and exactly
/// [`PREPARED_CAPABILITY_ORDERED_NFA_V15`].
///
/// # Errors
///
/// This route requires [`OutputContract::Span`]. It returns the same typed
/// parse/lower/program/object failures as [`compile`], without falling back to
/// another backend after the explicit route has been selected.
pub fn compile_with_prepared_ordered_nfa_v15(
    request: CompileRequest,
    exports: PreparedAggregateExports,
) -> Result<CompiledRegex, CompileError> {
    compile_with_prepared_ordered_nfa_v15_and_native_data_limit(
        request,
        exports,
        SlowAotLimits::default().max_native_data_bytes,
    )
}

/// As [`compile_with_prepared_ordered_nfa_v15`], with an exact ceiling for the
/// additional immutable Ordered-NFA object data. Sizing precedes image
/// allocation; a miss is returned as a terminal `ProgramBytes` resource error.
pub fn compile_with_prepared_ordered_nfa_v15_and_native_data_limit(
    request: CompileRequest,
    exports: PreparedAggregateExports,
    max_native_data_bytes: usize,
) -> Result<CompiledRegex, CompileError> {
    if request.output != OutputContract::Span {
        return Err(CompileError::PreparedAggregateRequiresSpan {
            actual: request.output,
        });
    }
    let CompileRequest {
        pattern,
        profile,
        output,
        target,
        mode,
        mut limits,
    } = request;
    if let Some(profile_limit) = rust_profile_compiled_size_limit(&profile) {
        limits.max_program_bytes = limits.max_program_bytes.min(profile_limit);
    }
    let source_bytes = pattern.len();
    let line_terminator = profile.options.line_terminator;
    let parsed = fre_syntax::parse(ParseRequest::rust(
        pattern,
        CompatibilityProfile::RustBytes(profile),
    ))?;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return Err(CompileError::InternalInvariant(
            "Rust byte request produced a non-Rust syntax tree",
        ));
    };
    let lowered =
        fre_lower::lower_raw_general(&parsed, OperationSemantics::CaptureFree, limits.lower)?;
    compile_raw_prepared_ordered_nfa_v15(
        source_bytes,
        lowered.into_plan(),
        line_terminator,
        output,
        target,
        mode,
        limits,
        exports,
        max_native_data_bytes,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the explicit route keeps one plan, its six additive text retries, and its authenticated receipt in one transaction"
)]
fn compile_raw_prepared_ordered_nfa_v15(
    source_bytes: usize,
    raw: RawPlan,
    line_terminator: u8,
    output: OutputContract,
    target: Target,
    mode: CompileMode,
    limits: CompileLimitsV1,
    exports: PreparedAggregateExports,
    max_native_data_bytes: usize,
) -> Result<CompiledRegex, CompileError> {
    let digest = program::automaton_digest(&raw, line_terminator);
    let automaton = Automaton::from_raw(raw.clone(), limits.lower.automata)?
        .with_line_terminator(line_terminator);
    let stats = automaton.stats();
    let program = CompiledProgram::build(
        raw,
        automaton,
        output,
        mode,
        limits.determinize,
        limits.max_program_bytes,
    )?;
    let program_bytes = program.serialized_len()?;
    let program_sha256 = program.artifact_identity();
    let artifact_identity = program.artifact_identity();
    let serialized_program = program.serialize()?;
    let max_native_data_bytes = max_native_data_bytes.min(limits.max_object_bytes);
    let append_exports = |module: CompiledModule| -> Result<CompiledModule, CompileError> {
        if exports.is_empty() {
            Ok(module)
        } else {
            module
                .append_prepared_aggregate_exports(
                    exports,
                    artifact_identity,
                    &serialized_program,
                )
                .map_err(CompileError::from)
        }
    };
    let initial = append_exports(
        CompiledModule::lower_prepared_ordered_nfa_v15_with_native_data_limit(
            &program,
            target,
            true,
            true,
            true,
            true,
            true,
            true,
            max_native_data_bytes,
        )?,
    )?;
    let format = ObjectFormat::for_target(target);
    let (module, object) = match emit_with_ordered_nfa_accelerator_retries(
        initial,
        format,
        limits.max_object_bytes,
        || {
            append_exports(
                CompiledModule::lower_prepared_ordered_nfa_v15_with_native_data_limit(
                    &program,
                    target,
                    true,
                    true,
                    true,
                    true,
                    true,
                    false,
                    max_native_data_bytes,
                )?,
            )
        },
        || {
            append_exports(
                CompiledModule::lower_prepared_ordered_nfa_v15_with_native_data_limit(
                    &program,
                    target,
                    true,
                    true,
                    true,
                    true,
                    false,
                    false,
                    max_native_data_bytes,
                )?,
            )
        },
        || {
            append_exports(
                CompiledModule::lower_prepared_ordered_nfa_v15_with_native_data_limit(
                    &program,
                    target,
                    true,
                    true,
                    true,
                    false,
                    false,
                    false,
                    max_native_data_bytes,
                )?,
            )
        },
        || {
            append_exports(
                CompiledModule::lower_prepared_ordered_nfa_v15_with_native_data_limit(
                    &program,
                    target,
                    true,
                    true,
                    false,
                    false,
                    false,
                    false,
                    max_native_data_bytes,
                )?,
            )
        },
        || {
            append_exports(
                CompiledModule::lower_prepared_ordered_nfa_v15_with_native_data_limit(
                    &program,
                    target,
                    true,
                    false,
                    false,
                    false,
                    false,
                    false,
                    max_native_data_bytes,
                )?,
            )
        },
        || {
            append_exports(
                CompiledModule::lower_prepared_ordered_nfa_v15_with_native_data_limit(
                    &program,
                    target,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    max_native_data_bytes,
                )?,
            )
        },
    )? {
        FinalObjectAttempt::Fit { module, object } => (module, object),
        FinalObjectAttempt::ObjectBytes { first_error, .. } => {
            return Err(first_error.into());
        }
    };
    if module.prepared_bulk_strategy() != Some(PreparedBulkStrategy::NativeOrderedNfaLoop)
        || module.required_prepare_capabilities() != PREPARED_CAPABILITY_ORDERED_NFA_V15
        || module.prepared_entry_symbol().is_none()
        || module.prepared_span_fill_symbol().is_none()
        || module.prepared_aggregate_exports() != exports
    {
        return Err(CompileError::InternalInvariant(
            "explicit prepared Ordered-NFA compiler lost its V15 route",
        ));
    }

    let object_sha256 = Sha256::digest(&object).into();
    let engine_selection_reason =
        program
            .engine_selection_reason()
            .ok_or(CompileError::InternalInvariant(
                "newly compiled program lost engine-selection provenance",
            ))?;
    let determinization =
        program
            .determinization_report()
            .cloned()
            .ok_or(CompileError::InternalInvariant(
                "newly compiled program lost determinization provenance",
            ))?;
    let mut passes = selected_passes(&program, &module);
    if !exports.is_empty() {
        passes
            .try_reserve_exact(1)
            .map_err(|_| ObjectError::Allocation("prepared aggregate pass receipt"))?;
        let aggregate_index = passes
            .iter()
            .position(|pass| *pass == OptimizationPass::PositionIndependentDataLayout)
            .unwrap_or(passes.len());
        passes.insert(
            aggregate_index,
            OptimizationPass::PreparedAggregateLowering,
        );
    }
    let receipt = CompileReceipt {
        compiler_version: COMPILER_VERSION,
        optimizer_version: OPTIMIZER_VERSION,
        mode,
        output,
        target,
        line_terminator,
        automaton_sha256: digest,
        program_sha256,
        object_sha256,
        engine: program.engine_kind(),
        engine_selection_reason,
        determinization,
        slow_aot: None,
        compiler_k0_aot: None,
        exact_finite_exists_byte_set_aot: None,
        exact_single_literal_aot: None,
        ordered_finite_language_aot: None,
        slow_context_aot: None,
        source_bytes,
        thompson_states: stats.states(),
        thompson_edges: stats.edges(),
        dfa: program.dfa_stats(),
        context_determinization: program.context_determinization_report().cloned(),
        anchored_prefix: program.anchored_prefix_stats(),
        exact_match_width: program.exact_match_width(),
        passes: passes.into_boxed_slice(),
        runtime_helper_required: module.required_runtime_symbols().next().is_some(),
        prepared_aggregate_exports: module.prepared_aggregate_exports(),
        prepared_aggregate_strategy: module.prepared_aggregate_strategy(),
        required_prepare_capabilities: module.required_prepare_capabilities(),
        start_accelerator: module.start_accelerator(),
        anchored_prefix_filter_bytes: module.anchored_prefix_filter_bytes(),
        program_bytes,
        code_bytes: module.code_bytes(),
        data_bytes: module
            .sections()
            .iter()
            .filter(|section| section.kind == SectionKind::ReadOnlyData)
            .map(|section| section.data.len())
            .sum(),
        object_bytes: object.len(),
    };
    Ok(CompiledRegex {
        program,
        module,
        object: object.into_boxed_slice(),
        receipt,
    })
}

/// Compile with an explicit resource envelope for the separately selected
/// slow contextual and assertion-free DFA completion passes.
///
/// This leaves [`CompileLimitsV1`] source-compatible and keeps its semantic
/// program limits distinct from later AOT work. `CompileMode::Fast` never
/// invokes the slow pass. In optimizing mode only, an ordinary automaton-state
/// ceiling may use a separately authenticated exact, assertion-free finite
/// language when its priority trie fits the same [`LowerLimits`]. Hard
/// allocation, arithmetic, and invariant failures remain terminal, and an
/// ordinary lowering success keeps the established optimizer portfolio.
///
/// # Errors
///
/// Returns the same typed failures as [`compile`]. Exhausting a slow-AOT
/// resource declines that optional candidate and preserves bounded fallbacks.
pub fn compile_with_slow_aot_limits(
    request: CompileRequest,
    slow_aot_limits: SlowAotLimits,
) -> Result<CompiledRegex, CompileError> {
    compile_with_slow_aot_limits_and_teddy_policy_v2(
        request,
        slow_aot_limits,
        ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
    )
}

fn compile_with_slow_aot_limits_and_teddy_policy_v2(
    request: CompileRequest,
    slow_aot_limits: SlowAotLimits,
    teddy_policy: ExactFiniteSelectedEndTeddyPolicyV2,
) -> Result<CompiledRegex, CompileError> {
    let CompileRequest {
        pattern,
        profile,
        output,
        target,
        mode,
        mut limits,
    } = request;
    if let Some(profile_limit) = rust_profile_compiled_size_limit(&profile) {
        limits.max_program_bytes = limits.max_program_bytes.min(profile_limit);
    }
    let source_bytes = pattern.len();
    let line_terminator = profile.options.line_terminator;
    let profile = CompatibilityProfile::RustBytes(profile);
    let parsed = fre_syntax::parse(ParseRequest::rust(pattern, profile))?;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return Err(CompileError::InternalInvariant(
            "Rust byte request produced a non-Rust syntax tree",
        ));
    };
    let (raw, native_finite_language_candidate, finite_lower_state_rescue) =
        match fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            limits.lower,
        ) {
            Ok(lowered) => {
                let candidate = (mode == CompileMode::Optimizing)
                    .then(|| {
                        finite_language::NativeFiniteLanguageCandidate::analyze(&parsed, output)
                    })
                    .flatten();
                (lowered.into_plan(), candidate, None)
            }
            Err(
                original @ LowerError::ResourceLimit {
                    resource: LowerResource::States,
                    ..
                },
            )
                if mode == CompileMode::Optimizing =>
            {
                let Some(candidate) = finite_language::NativeFiniteLanguageCandidate::
                    analyze_for_lower_state_rescue(&parsed, output)?
                else {
                    return Err(original.into());
                };
                let Some(raw) = candidate.priority_trie_raw_plan(limits.lower)? else {
                    return Err(original.into());
                };
                (raw, Some(candidate), Some(original))
            }
            Err(error) => return Err(error.into()),
        };
    compile_raw_with_line_terminator_and_slow_aot_limits(
        source_bytes,
        raw,
        line_terminator,
        output,
        native_finite_language_candidate,
        finite_lower_state_rescue,
        target,
        mode,
        limits,
        slow_aot_limits,
        teddy_policy,
    )
}

/// Compile an already-lowered canonical automaton.
///
/// This entry is primarily useful for exhaustive and generated semantic tests;
/// production source compilation should use [`compile`].
///
/// # Errors
///
/// Returns a typed validation, resource, determinization, target, or object
/// failure.
pub fn compile_raw(
    source_bytes: usize,
    raw: RawPlan,
    output: OutputContract,
    target: Target,
    mode: CompileMode,
    limits: CompileLimitsV1,
) -> Result<CompiledRegex, CompileError> {
    compile_raw_with_line_terminator_and_slow_aot_limits(
        source_bytes,
        raw,
        b'\n',
        output,
        None,
        None,
        target,
        mode,
        limits,
        SlowAotLimits::default(),
        ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
    )
}

/// Compile an already-lowered canonical automaton with explicit line
/// semantics.
///
/// The lowered graph must have been produced with the same line terminator
/// when syntax such as `.` depends on that byte. Contextual multiline
/// assertions use `line_terminator` directly at execution time.
///
/// # Errors
///
/// Returns a typed validation, resource, determinization, target, or object
/// failure.
pub fn compile_raw_with_line_terminator(
    source_bytes: usize,
    raw: RawPlan,
    line_terminator: u8,
    output: OutputContract,
    target: Target,
    mode: CompileMode,
    limits: CompileLimitsV1,
) -> Result<CompiledRegex, CompileError> {
    compile_raw_with_line_terminator_and_slow_aot_limits(
        source_bytes,
        raw,
        line_terminator,
        output,
        None,
        None,
        target,
        mode,
        limits,
        SlowAotLimits::default(),
        ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
    )
}

/// One exact final-object attempt, retaining the first byte-ceiling failure
/// so a later, smaller fallback cannot replace the caller-visible resource
/// receipt when every candidate is still oversized.
enum FinalObjectAttempt {
    Fit {
        module: CompiledModule,
        object: Vec<u8>,
    },
    ObjectBytes {
        module: CompiledModule,
        first_error: ObjectError,
    },
}

/// Emit one selected module and retry its compositional Ordered-NFA
/// accelerators in exact additive order. Compiler-only fragmented terminal-set
/// aggregate text is removed first, followed by the whole-window width gate,
/// prefix, and independent start-closure text, preserving the exact
/// pre-feature V1/V2/V3 object. A selected V3 then
/// omits only the terminal-range prefilter, yielding V2 when dispatch is
/// present and V1 when it is not; a selected V2 becomes scalar V1 by omitting
/// canonical edge dispatch. Established route fallbacks run only after that
/// smallest native candidate also exceeds the final object ceiling.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the four compiler-text, V3, V2, and V1 object retries form one ordered resource transaction"
)]
fn emit_with_ordered_nfa_accelerator_retries(
    mut module: CompiledModule,
    format: ObjectFormat,
    max_object_bytes: usize,
    rebuild_without_terminal_exact_set: impl FnOnce() -> Result<CompiledModule, CompileError>,
    rebuild_without_whole_window_width_gate: impl FnOnce() -> Result<CompiledModule, CompileError>,
    rebuild_without_width_gate_or_start_prefix: impl FnOnce() -> Result<CompiledModule, CompileError>,
    rebuild_without_width_gate_start_prefix_or_start_closure_dispatch: impl FnOnce() -> Result<
        CompiledModule,
        CompileError,
    >,
    rebuild_without_compiler_text_or_terminal_range: impl FnOnce()
        -> Result<CompiledModule, CompileError>,
    rebuild_scalar_ordered_nfa: impl FnOnce() -> Result<CompiledModule, CompileError>,
) -> Result<FinalObjectAttempt, CompileError> {
    let optimizing_fallbacks_may_continue = module.optimizing_fallbacks_may_continue();
    let selected_terminal_exact_set = module.has_ordered_nfa_terminal_exact_set();
    let selected_width_gate = module.has_ordered_nfa_whole_window_width_gate();
    let selected_start_prefix = module.has_ordered_nfa_start_prefix();
    let selected_start_closure = module.has_ordered_nfa_start_closure_dispatch();
    let selected_terminal_range = module.has_ordered_nfa_terminal_range_object();
    let selected_edge_dispatch = module.has_ordered_edge_dispatch_object();
    let first_error = match emit_object(&module, format, max_object_bytes) {
        Ok(object) => return Ok(FinalObjectAttempt::Fit { module, object }),
        Err(error @ ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            ..
        }) => error,
        Err(error) => return Err(error.into()),
    };

    if selected_terminal_exact_set {
        let without_exact_set = rebuild_without_terminal_exact_set()?
            .with_optimizing_fallbacks_may_continue(optimizing_fallbacks_may_continue);
        if without_exact_set.has_ordered_nfa_terminal_exact_set()
            || without_exact_set.has_ordered_nfa_whole_window_width_gate() != selected_width_gate
            || without_exact_set.has_ordered_nfa_start_prefix() != selected_start_prefix
            || without_exact_set.has_ordered_nfa_start_closure_dispatch() != selected_start_closure
            || without_exact_set.has_ordered_nfa_terminal_range_object() != selected_terminal_range
            || without_exact_set.has_ordered_edge_dispatch_object() != selected_edge_dispatch
            || without_exact_set.required_prepare_capabilities()
                & PREPARED_CAPABILITY_ORDERED_NFA_V15
                == 0
        {
            return Err(CompileError::InternalInvariant(
                "Ordered-NFA terminal exact-set final-object retry changed its retained route",
            ));
        }
        match emit_object(&without_exact_set, format, max_object_bytes) {
            Ok(object) => {
                return Ok(FinalObjectAttempt::Fit {
                    module: without_exact_set,
                    object,
                });
            }
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                ..
            }) => module = without_exact_set,
            Err(error) => return Err(error.into()),
        }
    }

    if selected_width_gate {
        let without_width = rebuild_without_whole_window_width_gate()?
            .with_optimizing_fallbacks_may_continue(optimizing_fallbacks_may_continue);
        if without_width.has_ordered_nfa_terminal_exact_set()
            || without_width.has_ordered_nfa_whole_window_width_gate()
            || without_width.has_ordered_nfa_start_prefix() != selected_start_prefix
            || without_width.has_ordered_nfa_start_closure_dispatch() != selected_start_closure
            || without_width.has_ordered_nfa_terminal_range_object() != selected_terminal_range
            || without_width.has_ordered_edge_dispatch_object() != selected_edge_dispatch
            || without_width.required_prepare_capabilities() & PREPARED_CAPABILITY_ORDERED_NFA_V15
                == 0
        {
            return Err(CompileError::InternalInvariant(
                "Ordered-NFA whole-window width final-object retry changed its retained route",
            ));
        }
        match emit_object(&without_width, format, max_object_bytes) {
            Ok(object) => {
                return Ok(FinalObjectAttempt::Fit {
                    module: without_width,
                    object,
                });
            }
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                ..
            }) => module = without_width,
            Err(error) => return Err(error.into()),
        }
    }

    if selected_start_prefix {
        let without_prefix = rebuild_without_width_gate_or_start_prefix()?
            .with_optimizing_fallbacks_may_continue(optimizing_fallbacks_may_continue);
        if without_prefix.has_ordered_nfa_terminal_exact_set()
            || without_prefix.has_ordered_nfa_whole_window_width_gate()
            || without_prefix.has_ordered_nfa_start_prefix()
            || without_prefix.has_ordered_nfa_start_closure_dispatch() != selected_start_closure
            || without_prefix.has_ordered_nfa_terminal_range_object() != selected_terminal_range
            || without_prefix.has_ordered_edge_dispatch_object() != selected_edge_dispatch
            || without_prefix.required_prepare_capabilities()
                & PREPARED_CAPABILITY_ORDERED_NFA_V15
                == 0
        {
            return Err(CompileError::InternalInvariant(
                "Ordered-NFA start-prefix final-object retry changed its retained route",
            ));
        }
        match emit_object(&without_prefix, format, max_object_bytes) {
            Ok(object) => {
                return Ok(FinalObjectAttempt::Fit {
                    module: without_prefix,
                    object,
                });
            }
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                ..
            }) => module = without_prefix,
            Err(error) => return Err(error.into()),
        }
    }

    if selected_start_closure {
        let without_start = rebuild_without_width_gate_start_prefix_or_start_closure_dispatch()?
            .with_optimizing_fallbacks_may_continue(optimizing_fallbacks_may_continue);
        if without_start.has_ordered_nfa_terminal_exact_set()
            || without_start.has_ordered_nfa_whole_window_width_gate()
            || without_start.has_ordered_nfa_start_prefix()
            || without_start.has_ordered_nfa_start_closure_dispatch()
            || without_start.has_ordered_nfa_terminal_range_object() != selected_terminal_range
            || without_start.has_ordered_edge_dispatch_object() != selected_edge_dispatch
            || without_start.required_prepare_capabilities()
                & PREPARED_CAPABILITY_ORDERED_NFA_V15
                == 0
        {
            return Err(CompileError::InternalInvariant(
                "Ordered-NFA start-closure final-object retry changed its retained route",
            ));
        }
        match emit_object(&without_start, format, max_object_bytes) {
            Ok(object) => {
                return Ok(FinalObjectAttempt::Fit {
                    module: without_start,
                    object,
                });
            }
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                ..
            }) => module = without_start,
            Err(error) => return Err(error.into()),
        }
    }

    if selected_terminal_range {
        let without_terminal = rebuild_without_compiler_text_or_terminal_range()?
            .with_optimizing_fallbacks_may_continue(optimizing_fallbacks_may_continue);
        if without_terminal.has_ordered_nfa_terminal_exact_set()
            || without_terminal.has_ordered_nfa_whole_window_width_gate()
            || without_terminal.has_ordered_nfa_start_prefix()
            || without_terminal.has_ordered_nfa_start_closure_dispatch()
            || without_terminal.has_ordered_nfa_terminal_range_object()
            || without_terminal.has_ordered_edge_dispatch_object() != selected_edge_dispatch
            || without_terminal.required_prepare_capabilities()
                & PREPARED_CAPABILITY_ORDERED_NFA_V15
                == 0
        {
            return Err(CompileError::InternalInvariant(
                "Ordered-NFA terminal-range final-object retry changed its retained route",
            ));
        }
        match emit_object(&without_terminal, format, max_object_bytes) {
            Ok(object) => {
                return Ok(FinalObjectAttempt::Fit {
                    module: without_terminal,
                    object,
                });
            }
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                ..
            }) => module = without_terminal,
            Err(error) => return Err(error.into()),
        }
    }

    if selected_edge_dispatch {
        let scalar = rebuild_scalar_ordered_nfa()?
            .with_optimizing_fallbacks_may_continue(optimizing_fallbacks_may_continue);
        if scalar.has_ordered_nfa_terminal_exact_set()
            || scalar.has_ordered_nfa_whole_window_width_gate()
            || scalar.has_ordered_nfa_start_prefix()
            || scalar.has_ordered_nfa_start_closure_dispatch()
            || scalar.has_ordered_nfa_terminal_range_object()
            || scalar.has_ordered_edge_dispatch_object()
            || scalar.required_prepare_capabilities() & PREPARED_CAPABILITY_ORDERED_NFA_V15 == 0
        {
            return Err(CompileError::InternalInvariant(
                "Ordered-edge final-object retry did not preserve scalar native V1",
            ));
        }
        match emit_object(&scalar, format, max_object_bytes) {
            Ok(object) => return Ok(FinalObjectAttempt::Fit { module: scalar, object }),
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                ..
            }) => module = scalar,
            Err(error) => return Err(error.into()),
        }
    }

    Ok(FinalObjectAttempt::ObjectBytes {
        module,
        first_error,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the public request decomposition, lowering fallback order, and one final receipt stay one transaction"
)]
fn lower_ordinary_with_endpoint_oracle_object_retry(
    program: &CompiledProgram,
    target: Target,
    format: ObjectFormat,
    max_object_bytes: usize,
    max_native_data_bytes: usize,
    allow_ordered_nfa: bool,
) -> Result<(CompiledModule, Vec<u8>), CompileError> {
    let enabled = CompiledModule::lower_with_native_data_limit_and_optional_routes(
        program,
        target,
        true,
        allow_ordered_nfa,
        max_native_data_bytes,
    )?;
    match emit_with_ordered_nfa_accelerator_retries(
        enabled,
        format,
        max_object_bytes,
        || {
            CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                program, target, false, allow_ordered_nfa, true, true, true, true, true, false,
                max_native_data_bytes,
            )
        },
        || {
            CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                program, target, false, allow_ordered_nfa, true, true, true, true, false, false,
                max_native_data_bytes,
            )
        },
        || {
            CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                program, target, false, allow_ordered_nfa, true, true, true, false, false, false,
                max_native_data_bytes,
            )
        },
        || {
            CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                program, target, false, allow_ordered_nfa, true, true, false, false, false, false,
                max_native_data_bytes,
            )
        },
        || {
            CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                program, target, false, allow_ordered_nfa, true, false, false, false, false, false,
                max_native_data_bytes,
            )
        },
        || {
            CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                program, target, false, allow_ordered_nfa, false, false, false, false, false, false,
                max_native_data_bytes,
            )
        },
    )? {
        FinalObjectAttempt::Fit { module, object } => Ok((module, object)),
        FinalObjectAttempt::ObjectBytes {
            module: enabled,
            first_error: first,
        } => {
            let enabled_ordered = enabled.required_prepare_capabilities()
                & PREPARED_CAPABILITY_ORDERED_NFA_V15
                != 0;
            let (second_endpoint, second_ordered_route) = if enabled_ordered {
                (true, false)
            } else if allow_ordered_nfa {
                (false, true)
            } else {
                (false, false)
            };
            let second = CompiledModule::lower_with_native_data_limit_and_optional_routes(
                program,
                target,
                second_endpoint,
                second_ordered_route,
                max_native_data_bytes,
            )?;
            match emit_with_ordered_nfa_accelerator_retries(
                second,
                format,
                max_object_bytes,
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        program, target, second_endpoint, second_ordered_route, true, true, true, true, true, false,
                        max_native_data_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        program, target, second_endpoint, second_ordered_route, true, true, true, true, false, false,
                        max_native_data_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        program, target, second_endpoint, second_ordered_route, true, true, true, false, false, false,
                        max_native_data_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        program, target, second_endpoint, second_ordered_route, true, true, false, false, false, false,
                        max_native_data_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        program, target, second_endpoint, second_ordered_route, true, false, false, false, false, false,
                        max_native_data_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        program, target, second_endpoint, second_ordered_route, false, false, false, false, false, false,
                        max_native_data_bytes,
                    )
                },
            )? {
                FinalObjectAttempt::Fit { module, object } => Ok((module, object)),
                FinalObjectAttempt::ObjectBytes { module: second, .. } => {
                    let second_ordered = second.required_prepare_capabilities()
                        & PREPARED_CAPABILITY_ORDERED_NFA_V15
                        != 0;
                    if !enabled_ordered && !second_ordered && !allow_ordered_nfa {
                        return Err(first.into());
                    }
                    // The terminal candidate disables both additive routes,
                    // so neither oversized object can be selected again.
                    let terminal = CompiledModule::lower_with_native_data_limit_and_optional_routes(
                        program,
                        target,
                        false,
                        false,
                        max_native_data_bytes,
                    )?;
                    match emit_object(&terminal, format, max_object_bytes) {
                        Ok(object) => Ok((terminal, object)),
                        Err(ObjectError::Resource {
                            resource: CompileResource::ObjectBytes,
                            ..
                        }) => Err(first.into()),
                        Err(error) => Err(error.into()),
                    }
                }
            }
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the public request decomposition, lowering fallback order, and one final receipt stay one transaction"
)]
fn compile_raw_with_line_terminator_and_slow_aot_limits(
    source_bytes: usize,
    raw: RawPlan,
    line_terminator: u8,
    output: OutputContract,
    native_finite_language_candidate: Option<finite_language::NativeFiniteLanguageCandidate>,
    mut finite_lower_state_rescue: Option<LowerError>,
    target: Target,
    mode: CompileMode,
    limits: CompileLimitsV1,
    slow_aot_limits: SlowAotLimits,
    teddy_policy: ExactFiniteSelectedEndTeddyPolicyV2,
) -> Result<CompiledRegex, CompileError> {
    let digest = program::automaton_digest(&raw, line_terminator);
    let automaton = Automaton::from_raw(raw.clone(), limits.lower.automata)?
        .with_line_terminator(line_terminator);
    let stats = automaton.stats();
    let is_lower_state_rescue = finite_lower_state_rescue.is_some();
    let build_determinize_limits = if is_lower_state_rescue {
        DeterminizeLimits {
            max_states: 0,
            max_transitions: 0,
            max_work: 0,
        }
    } else {
        limits.determinize
    };
    let mut program = CompiledProgram::build(
        raw,
        automaton,
        output,
        mode,
        build_determinize_limits,
        limits.max_program_bytes,
    )?;
    if let Some(candidate) = native_finite_language_candidate {
        if is_lower_state_rescue {
            if !program.attach_native_finite_language_for_lower_state_rescue(candidate)? {
                return Err(finite_lower_state_rescue
                    .take()
                    .expect("authenticated lower-state rescue retained its original error")
                    .into());
            }
        } else {
            program.attach_native_finite_language(candidate);
        }
    }
    let program_bytes = program.serialized_len()?;
    let program_sha256 = program.artifact_identity();
    let format = ObjectFormat::for_target(target);
    let (module, object) = match mode {
        CompileMode::Fast => lower_ordinary_with_endpoint_oracle_object_retry(
            &program,
            target,
            format,
            limits.max_object_bytes,
            usize::MAX,
            true,
        )?,
        CompileMode::Optimizing => {
            let optimizing_limits = if is_lower_state_rescue {
                SlowAotLimits {
                    determinize: DeterminizeLimits {
                        max_states: 0,
                        max_transitions: 0,
                        max_work: 0,
                    },
                    ..slow_aot_limits
                }
            } else {
                slow_aot_limits
            };
            let effective_native_data_limit_bytes = slow_aot_limits
                .max_native_data_bytes
                .min(limits.max_object_bytes);
            let optimized = CompiledModule::lower_optimizing_with_limits_and_native_data_limit_and_ordered_nfa_and_teddy_policy_v2(
                &program,
                target,
                optimizing_limits,
                effective_native_data_limit_bytes,
                true,
                teddy_policy,
            )?;
            match emit_with_ordered_nfa_accelerator_retries(
                optimized,
                format,
                limits.max_object_bytes,
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        &program, target, false, true, true, true, true, true, true, false,
                        effective_native_data_limit_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        &program, target, false, true, true, true, true, true, false, false,
                        effective_native_data_limit_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        &program, target, false, true, true, true, true, false, false, false,
                        effective_native_data_limit_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        &program, target, false, true, true, true, false, false, false, false,
                        effective_native_data_limit_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        &program, target, false, true, true, false, false, false, false, false,
                        effective_native_data_limit_bytes,
                    )
                },
                || {
                    CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                        &program, target, false, true, false, false, false, false, false, false,
                        effective_native_data_limit_bytes,
                    )
                },
            )? {
                FinalObjectAttempt::Fit { module, object } => (module, object),
                FinalObjectAttempt::ObjectBytes {
                    module: optimized,
                    first_error: error,
                } => {
                    let optimized_ordered = optimized.required_prepare_capabilities()
                        & PREPARED_CAPABILITY_ORDERED_NFA_V15
                        != 0;
                    if optimized.optimizing_fallbacks_may_continue() {
                        let k0_fallback =
                            CompiledModule::lower_k0_optimizing_with_data_limit_and_ordered_nfa(
                            &program,
                            target,
                            effective_native_data_limit_bytes,
                            !optimized_ordered,
                        )?;
                        match emit_with_ordered_nfa_accelerator_retries(
                            k0_fallback,
                            format,
                            limits.max_object_bytes,
                            || {
                                CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                                    &program, target, false, true, true, true, true, true, true, false,
                                    effective_native_data_limit_bytes,
                                )
                            },
                            || {
                                CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                                    &program, target, false, true, true, true, true, true, false, false,
                                    effective_native_data_limit_bytes,
                                )
                            },
                            || {
                                CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                                    &program, target, false, true, true, true, true, false, false, false,
                                    effective_native_data_limit_bytes,
                                )
                            },
                            || {
                                CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                                    &program, target, false, true, true, true, false, false, false, false,
                                    effective_native_data_limit_bytes,
                                )
                            },
                            || {
                                CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                                    &program, target, false, true, true, false, false, false, false, false,
                                    effective_native_data_limit_bytes,
                                )
                            },
                            || {
                                CompiledModule::lower_with_native_data_limit_and_optional_routes_and_ordered_nfa_accelerators_and_start_closure_and_prefix_and_width_and_terminal_exact_set(
                                    &program, target, false, true, false, false, false, false, false, false,
                                    effective_native_data_limit_bytes,
                                )
                            },
                        )? {
                            FinalObjectAttempt::Fit { module, object } => (module, object),
                            FinalObjectAttempt::ObjectBytes {
                                module: k0_fallback,
                                ..
                            } => {
                                let k0_ordered = k0_fallback.required_prepare_capabilities()
                                    & PREPARED_CAPABILITY_ORDERED_NFA_V15
                                    != 0;
                                match lower_ordinary_with_endpoint_oracle_object_retry(
                                    &program,
                                    target,
                                    format,
                                    limits.max_object_bytes,
                                    effective_native_data_limit_bytes,
                                    !optimized_ordered && !k0_ordered,
                                ) {
                                    Ok(fallback) => fallback,
                                    Err(CompileError::Object(ObjectError::Resource {
                                        resource: CompileResource::ObjectBytes,
                                        ..
                                    })) => return Err(error.into()),
                                    Err(fallback_error) => return Err(fallback_error),
                                }
                            }
                        }
                    } else {
                        match lower_ordinary_with_endpoint_oracle_object_retry(
                            &program,
                            target,
                            format,
                            limits.max_object_bytes,
                            effective_native_data_limit_bytes,
                            !optimized_ordered,
                        ) {
                            Ok(fallback) => fallback,
                            Err(CompileError::Object(ObjectError::Resource {
                                resource: CompileResource::ObjectBytes,
                                ..
                            })) => return Err(error.into()),
                            Err(fallback_error) => return Err(fallback_error),
                        }
                    }
                }
            }
        }
    };
    let object_sha256 = Sha256::digest(&object).into();
    let engine_selection_reason =
        program
            .engine_selection_reason()
            .ok_or(CompileError::InternalInvariant(
                "newly compiled program lost engine-selection provenance",
            ))?;
    let determinization =
        program
            .determinization_report()
            .cloned()
            .ok_or(CompileError::InternalInvariant(
                "newly compiled program lost determinization provenance",
            ))?;
    let receipt = CompileReceipt {
        compiler_version: COMPILER_VERSION,
        optimizer_version: OPTIMIZER_VERSION,
        mode,
        output,
        entry_abi: EntryAbi::for_output(output),
        target,
        line_terminator,
        automaton_sha256: digest,
        program_sha256,
        object_sha256,
        engine: program.engine_kind(),
        engine_selection_reason,
        determinization,
        slow_aot: module.slow_aot_report().cloned(),
        compiler_k0_aot: module.compiler_k0_aot_report().cloned(),
        exact_finite_exists_byte_set_aot: module
            .exact_finite_exists_byte_set_aot_report()
            .copied(),
        exact_single_literal_aot: module.exact_single_literal_aot_report().copied(),
        exact_finite_selected_end_teddy_aot: module
            .exact_finite_selected_end_teddy_aot_report()
            .copied(),
        ordered_finite_language_aot: module
            .ordered_finite_language_aot_report()
            .copied(),
        slow_context_aot: module.slow_context_aot_report().cloned(),
        source_bytes,
        thompson_states: stats.states(),
        thompson_edges: stats.edges(),
        dfa: program.dfa_stats(),
        context_determinization: program.context_determinization_report().cloned(),
        anchored_prefix: program.anchored_prefix_stats(),
        exact_match_width: program.exact_match_width(),
        passes: selected_passes(&program, &module).into_boxed_slice(),
        runtime_helper_required: module.required_runtime_symbols().next().is_some(),
        prepared_aggregate_exports: module.prepared_aggregate_exports(),
        prepared_aggregate_strategy: module.prepared_aggregate_strategy(),
        required_prepare_capabilities: module.required_prepare_capabilities(),
        start_accelerator: module.start_accelerator(),
        anchored_prefix_filter_bytes: module.anchored_prefix_filter_bytes(),
        program_bytes,
        code_bytes: module.code_bytes(),
        data_bytes: module
            .sections()
            .iter()
            .filter(|section| section.kind == SectionKind::ReadOnlyData)
            .map(|section| section.data.len())
            .sum(),
        object_bytes: object.len(),
    };
    Ok(CompiledRegex {
        program,
        module,
        object: object.into_boxed_slice(),
        receipt,
    })
}

fn selected_passes(program: &CompiledProgram, module: &CompiledModule) -> Vec<OptimizationPass> {
    let mut passes = vec![
        OptimizationPass::ValidateAutomaton,
        OptimizationPass::CanonicalDigest,
        OptimizationPass::AnchoredPrefixAnalysis,
    ];
    if let Some(report) = program.determinization_report() {
        for &stage in report.completed_stages.as_ref() {
            passes.push(match stage {
                DeterminizationStage::AlphabetPartition => OptimizationPass::AlphabetPartition,
                DeterminizationStage::ForwardSubsetConstruction => {
                    OptimizationPass::OrderedDeterminization
                }
                DeterminizationStage::ReverseSubsetConstruction => {
                    OptimizationPass::ReverseStartRecovery
                }
                DeterminizationStage::DfaStateMinimization => {
                    OptimizationPass::DfaStateMinimization
                }
                DeterminizationStage::AlphabetColumnCoalescing => {
                    OptimizationPass::AlphabetColumnCoalescing
                }
            });
        }
    }
    if let Some(report) = module.slow_aot_report() {
        for &stage in report.determinization.completed_stages.as_ref() {
            passes.push(match stage {
                DeterminizationStage::AlphabetPartition => OptimizationPass::AlphabetPartition,
                DeterminizationStage::ForwardSubsetConstruction => {
                    OptimizationPass::OrderedDeterminization
                }
                DeterminizationStage::ReverseSubsetConstruction => {
                    OptimizationPass::ReverseStartRecovery
                }
                DeterminizationStage::DfaStateMinimization => {
                    OptimizationPass::DfaStateMinimization
                }
                DeterminizationStage::AlphabetColumnCoalescing => {
                    OptimizationPass::AlphabetColumnCoalescing
                }
            });
        }
        // Forward minimization can commit before reverse minimization reaches
        // a numeric refusal. The combined determinization stage correctly
        // remains incomplete, while this private selected-artifact bit keeps
        // the receipt faithful to the useful forward quotient in the object.
        if module.slow_retained_forward_minimized()
            && !passes.contains(&OptimizationPass::DfaStateMinimization)
        {
            passes.push(OptimizationPass::DfaStateMinimization);
        }
    }
    match program.engine_kind() {
        EngineKind::OrderedNfa if module.slow_context_aot_report().is_some() => {
            // The stable semantic program remains the universal ordered TNFA;
            // the separately receipted contextual machine is transient native
            // IR rebuilt from that same retained graph.
            passes.push(OptimizationPass::UniversalOrderedTnfa);
            if let Some(report) = module.slow_context_aot_report() {
                append_native_context_passes(&mut passes, program, module, report.dfa);
            }
        }
        EngineKind::OrderedNfa if module.compiler_k0_aot_report().is_some() => {
            passes.push(OptimizationPass::UniversalOrderedTnfa);
            passes.push(OptimizationPass::CompilerK0Closure);
            let finalization = module
                .compiler_k0_aot_report()
                .map(|report| report.finalization)
                .expect("guarded compiler K0 report");
            if finalization.forward_minimization_completed
                || finalization.reverse_minimization_completed
            {
                passes.push(OptimizationPass::DfaStateMinimization);
            }
            if finalization.column_coalescing_completed {
                passes.push(OptimizationPass::AlphabetColumnCoalescing);
            }
            let reverse_unused = finalization.output.reverse_states == 0;
            if !reverse_unused
                && program.output_contract() == OutputContract::Span
                && program.exact_match_width().is_none()
            {
                passes.push(OptimizationPass::ReverseStartRecovery);
            }
            append_native_dfa_passes(&mut passes, program, module, reverse_unused);
        }
        EngineKind::OrderedNfa if module.slow_aot_report().is_some() => {
            // A selected slow candidate leaves the stable semantic engine as
            // the universal ordered TNFA. Report both the native DFA passes
            // physically present in the object and, only for a genuinely
            // incomplete transient prefix, its whole-search runtime adapter.
            passes.push(OptimizationPass::UniversalOrderedTnfa);
            let reverse_unused = module
                .slow_aot_report()
                .is_some_and(|report| report.dfa.reverse_states == 0);
            append_native_dfa_passes(&mut passes, program, module, reverse_unused);
            if module.required_runtime_symbol().is_some() {
                passes.push(OptimizationPass::RuntimeAdapterLowering);
            }
        }
        engine if module.exact_finite_exists_byte_set_aot_report().is_some() => {
            if engine == EngineKind::OrderedNfa {
                passes.push(OptimizationPass::UniversalOrderedTnfa);
            }
            passes.extend_from_slice(&[
                OptimizationPass::ExactFiniteExistsByteSetLowering,
                OptimizationPass::OutputContractSpecialization,
                OptimizationPass::ConstantFold,
            ]);
            if module.start_accelerator() != StartAccelerator::Scalar {
                passes.push(OptimizationPass::StartStateScanAcceleration);
            }
            passes.extend_from_slice(&[
                OptimizationPass::TargetInstructionSelection,
                OptimizationPass::FixedRegisterAssignment,
                OptimizationPass::CheckedBranchFixup,
            ]);
        }
        engine if module.exact_single_literal_aot_report().is_some() => {
            if engine == EngineKind::OrderedNfa {
                passes.push(OptimizationPass::UniversalOrderedTnfa);
            }
            passes.extend_from_slice(&[
                OptimizationPass::ExactFiniteExistsSingleLiteralLowering,
                OptimizationPass::OutputContractSpecialization,
                OptimizationPass::ConstantFold,
            ]);
            if module.start_accelerator() != StartAccelerator::Scalar {
                passes.push(OptimizationPass::StartStateScanAcceleration);
            }
            passes.extend_from_slice(&[
                OptimizationPass::TargetInstructionSelection,
                OptimizationPass::FixedRegisterAssignment,
                OptimizationPass::CheckedBranchFixup,
            ]);
        }
        engine if module.ordered_finite_language_aot_report().is_some() => {
            if engine == EngineKind::OrderedNfa {
                passes.push(OptimizationPass::UniversalOrderedTnfa);
            }
            passes.extend_from_slice(&[
                OptimizationPass::OrderedFiniteLanguageLowering,
                OptimizationPass::OutputContractSpecialization,
                OptimizationPass::ConstantFold,
                OptimizationPass::StrengthReduceRowAddressing,
            ]);
            if module
                .exact_finite_selected_end_teddy_aot_report()
                .is_some()
                || module
                    .exact_finite_selected_end_teddy_aot_report_v2()
                    .is_some()
            {
                passes.push(OptimizationPass::ExactFiniteSelectedEndTeddyLowering);
            }
            passes.extend_from_slice(&[
                OptimizationPass::TargetInstructionSelection,
                OptimizationPass::FixedRegisterAssignment,
                OptimizationPass::CheckedBranchFixup,
            ]);
        }
        EngineKind::OrderedNfa
            if module.required_prepare_capabilities()
                & PREPARED_CAPABILITY_ORDERED_NFA_V15
                != 0 =>
        {
            passes.extend_from_slice(&[
                OptimizationPass::UniversalOrderedTnfa,
                OptimizationPass::OutputContractSpecialization,
            ]);
            if module.has_ordered_nfa_start_prefix() {
                passes.push(OptimizationPass::AnchoredPrefixCandidateFilter);
            }
            passes.extend_from_slice(&[
                OptimizationPass::NativeOrderedTnfaLowering,
                OptimizationPass::TargetInstructionSelection,
                OptimizationPass::FixedRegisterAssignment,
                OptimizationPass::CheckedBranchFixup,
                // The public ordinary search remains an honest compatibility
                // adapter even when required-V15 bulk/aggregate entries are
                // native and cannot invoke their whole-operation helpers.
                OptimizationPass::RuntimeAdapterLowering,
            ]);
        }
        EngineKind::OrderedNfa if module.required_runtime_symbol().is_some() => {
            passes.push(OptimizationPass::UniversalOrderedTnfa);
            if module.has_bit_parallel_endpoint_oracle() {
                passes.push(OptimizationPass::BitParallelEndpointOracleLowering);
                if module.start_accelerator() != StartAccelerator::None {
                    passes.push(OptimizationPass::StartStateScanAcceleration);
                }
                passes.extend_from_slice(&[
                    OptimizationPass::TargetInstructionSelection,
                    OptimizationPass::FixedRegisterAssignment,
                    OptimizationPass::CheckedBranchFixup,
                ]);
            }
            passes.push(OptimizationPass::RuntimeAdapterLowering);
        }
        EngineKind::OrderedNfa => {
            // A resource decline can leave a complete retained forward
            // transducer even though the stable semantic engine remains the
            // universal ordered TNFA. When that table is lowered directly,
            // report the native passes actually present in the object rather
            // than claiming that a runtime adapter was emitted.
            passes.push(OptimizationPass::UniversalOrderedTnfa);
            let reverse_unused = module
                .slow_aot_report()
                .is_none_or(|report| report.dfa.reverse_states == 0);
            append_native_dfa_passes(&mut passes, program, module, reverse_unused);
        }
        EngineKind::OrderedDfa => {
            let reverse_unused = program
                .dfa_stats()
                .is_some_and(|stats| stats.reverse_states == 0);
            append_native_dfa_passes(&mut passes, program, module, reverse_unused);
        }
        EngineKind::OrderedContextDfa => {
            if let Some(stats) = program.context_dfa_stats() {
                append_native_context_passes(&mut passes, program, module, stats);
            }
        }
    }
    passes.extend_from_slice(&[
        OptimizationPass::PositionIndependentDataLayout,
        OptimizationPass::RelocatableObjectSerialization,
    ]);
    passes
}

fn append_native_context_passes(
    passes: &mut Vec<OptimizationPass>,
    program: &CompiledProgram,
    module: &CompiledModule,
    stats: ContextDfaStats,
) {
    passes.extend_from_slice(&[
        OptimizationPass::AlphabetPartition,
        OptimizationPass::ContextOrderedDeterminization,
    ]);
    if program.output_contract() == OutputContract::Span {
        if program.exact_match_width().is_some() {
            passes.push(OptimizationPass::ExactWidthStartRecovery);
        } else if stats.reverse_states != 0 {
            passes.push(OptimizationPass::ReverseStartRecovery);
        }
    }
    passes.extend_from_slice(&[
        OptimizationPass::OutputContractSpecialization,
        OptimizationPass::ConstantFold,
        OptimizationPass::StrengthReduceRowAddressing,
    ]);
    if module.start_accelerator() != StartAccelerator::None {
        passes.push(OptimizationPass::StartStateScanAcceleration);
    }
    if module.anchored_prefix_filter_bytes() != 0 {
        passes.push(OptimizationPass::AnchoredPrefixCandidateFilter);
    }
    passes.extend_from_slice(&[
        OptimizationPass::ContextNativeLowering,
        OptimizationPass::TargetInstructionSelection,
        OptimizationPass::FixedRegisterAssignment,
        OptimizationPass::CheckedBranchFixup,
    ]);
}

fn append_native_dfa_passes(
    passes: &mut Vec<OptimizationPass>,
    program: &CompiledProgram,
    module: &CompiledModule,
    reverse_unused: bool,
) {
    if reverse_unused {
        passes.push(OptimizationPass::RemoveUnusedReverseMachine);
    }
    if program.output_contract() == OutputContract::Span && program.exact_match_width().is_some() {
        passes.push(OptimizationPass::ExactWidthStartRecovery);
    }
    passes.extend_from_slice(&[
        OptimizationPass::OutputContractSpecialization,
        OptimizationPass::ConstantFold,
        OptimizationPass::StrengthReduceRowAddressing,
    ]);
    if module
        .exact_finite_selected_end_teddy_aot_report()
        .is_some()
        || module
            .exact_finite_selected_end_teddy_aot_report_v2()
            .is_some()
    {
        passes.push(OptimizationPass::ExactFiniteSelectedEndTeddyLowering);
    }
    if module.start_accelerator() != StartAccelerator::None {
        passes.push(OptimizationPass::StartStateScanAcceleration);
    }
    if module.anchored_prefix_filter_bytes() != 0 {
        passes.push(OptimizationPass::AnchoredPrefixCandidateFilter);
    }
    passes.extend_from_slice(&[
        OptimizationPass::TargetInstructionSelection,
        OptimizationPass::FixedRegisterAssignment,
        OptimizationPass::CheckedBranchFixup,
    ]);
}

#[cfg(test)]
mod tests;
