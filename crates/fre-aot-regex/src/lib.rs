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
mod ordered_many;
mod prefix_block;
mod prefix_fast_forward;
mod prefix_predicate;
mod prefix_relation;
mod program;
mod regex_set;
mod required_literals;
mod seeded_reverse;

use fre_automata::{Automaton, RawPlan};
use fre_lower::{LowerLimits, OperationSemantics};
use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};
use sha2::{Digest, Sha256};

pub use bit_parallel_exists::{
    BitParallelExistsStats, MAX_BIT_PARALLEL_EXISTS_MEMORY_BYTES, MAX_BIT_PARALLEL_EXISTS_STATES,
    MAX_BIT_PARALLEL_EXISTS_WORDS, MAX_BIT_PARALLEL_EXISTS_WORK,
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
    ExactFiniteExistsByteSetAotReport, ExactSingleLiteralAotIsa, ExactSingleLiteralAotReport,
    ExactSingleLiteralPairPrefilterReport, ExactSingleLiteralTwoWayShift, FeatureSet,
    ModuleRelocation, ModuleSection, ModuleSymbol, OperatingSystem,
    OrderedFiniteLanguageAotReport, PreparedAggregateExports,
    PreparedAggregateStrategy, PreparedBulkStrategy, RelocationKind, SectionKind, SlowAotLimits,
    SlowAotReport, SlowContextAotReport, StartAccelerator, SymbolBinding, SymbolKind, Target,
};
pub use object::{ObjectFormat, emit_object};
pub use operation_set::{
    AOT_OPERATION_SET_V1_HEADER_BYTES, AOT_OPERATION_SET_V1_IDENTITY_DOMAIN,
    AOT_OPERATION_SET_V1_MAGIC, AOT_OPERATION_SET_V1_MEMBER_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V1_NONE_INDEX, AOT_OPERATION_SET_V1_OUTPUT_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V1_ROOT_DESCRIPTOR_BYTES, AOT_OPERATION_SET_V1_SHARED_DESCRIPTOR_BYTES,
    AOT_OPERATION_SET_V1_STAGE_DESCRIPTOR_BYTES, AOT_OPERATION_SET_V1_VERSION,
    MAX_AOT_OPERATION_SET_V1_BYTES, AotDomainV1, AotOperationAxesV1, AotOperationOutputV1,
    AotOperationRootV1, AotOperationSetMemberV1, AotOperationSetV1, AotOperationSetV1Error,
    AotOperationSetV1Parts, AotProjectionV1, AotReducerV1,
};
pub use ordered_many::{
    ORDERED_MANY_TAGGED_MAX_ROWS, OrderedManyCompileError, OrderedManyCompileLimits,
    OrderedManyCompileRequest, OrderedManyFallbackReason, OrderedManyFillReport,
    OrderedManyMatch, OrderedManyPatternId, OrderedManyPrepareError, OrderedManyProgram,
    OrderedManyProgramStats, OrderedManyRow, OrderedManyRunError, OrderedManySession,
    OrderedManySessionLimits, OrderedManyStrategy, compile_ordered_many,
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
    FROZEN_PREPARED_HEADER_V14_READY_SEAL, FrozenCompactLoopPlanV1, FrozenCompactLoopScanner,
    FrozenStaticContinuationRowsStorageV1, FrozenDynamicRowsStorage,
    FrozenDynamicRowsStorageV3, FrozenDynamicRowsV3, FrozenDynamicRowsV5,
    FrozenDynamicRowsV6, FrozenRetainedPartialResumeProjection,
    FrozenStaticPrefixResumeProjection, FrozenStaticPrefixResumeSelection,
    FrozenPreparedHeaderOwnerGenerationKey, FrozenPreparedHeaderV1, FrozenPreparedHeaderV2,
    FrozenPreparedHeaderV3,
    FrozenPreparedHeaderV5, FrozenPreparedHeaderV6,
    FullyPrefilledFallbackReceipt, MAX_ANCHORED_PREFIX_BYTES, MAX_SERIALIZED_PROGRAM_BYTES,
    MatchResult, OutputContract, PROGRAM_HEADER_LEN, PartialDfaStats, ProgramFormatError,
    ProgramStats, ProgramWorkspace, RetainedPartialPreflight, SearchWindow,
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

/// Stable compiler pipeline identity.
pub const COMPILER_VERSION: u32 = 1;
/// Stable optimizer/cost-model identity.
pub const OPTIMIZER_VERSION: u32 = 13;

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
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            output: OutputContract::Span,
            target,
            mode: CompileMode::Optimizing,
            limits: CompileLimitsV1::default(),
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
        self
    }

    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }
}

/// Structural, source-independent record of the selected compiler route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompileReceipt {
    pub compiler_version: u32,
    pub optimizer_version: u32,
    pub mode: CompileMode,
    pub output: OutputContract,
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
    if exports.is_empty() {
        return compile(request);
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
    let CompiledRegex {
        program,
        module,
        object,
        mut receipt,
    } = compile(request)?;
    drop(object);
    let artifact_identity = program.artifact_identity();
    let serialized_program = program.serialize()?;
    let module =
        module.append_prepared_aggregate_exports(exports, artifact_identity, &serialized_program)?;
    drop(serialized_program);
    let object = emit_object(&module, ObjectFormat::for_target(target), max_object_bytes)?;
    let mut passes = std::mem::take(&mut receipt.passes).into_vec();
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
    receipt.runtime_helper_required = module.required_runtime_symbols().next().is_some();
    receipt.prepared_aggregate_exports = module.prepared_aggregate_exports();
    receipt.prepared_aggregate_strategy = module.prepared_aggregate_strategy();
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

/// Compile with an explicit resource envelope for the separately selected
/// slow contextual and assertion-free DFA completion passes.
///
/// This leaves [`CompileLimitsV1`] source-compatible and keeps its semantic
/// program limits distinct from later AOT work. `CompileMode::Fast` never
/// invokes the slow pass.
///
/// # Errors
///
/// Returns the same typed failures as [`compile`]. Exhausting a slow-AOT
/// resource declines that optional candidate and preserves bounded fallbacks.
pub fn compile_with_slow_aot_limits(
    request: CompileRequest,
    slow_aot_limits: SlowAotLimits,
) -> Result<CompiledRegex, CompileError> {
    let CompileRequest {
        pattern,
        profile,
        output,
        target,
        mode,
        limits,
    } = request;
    let source_bytes = pattern.len();
    let line_terminator = profile.options.line_terminator;
    let profile = CompatibilityProfile::RustBytes(profile);
    let parsed = fre_syntax::parse(ParseRequest::rust(pattern, profile))?;
    let CanonicalPattern::Rust(parsed) = parsed.pattern else {
        return Err(CompileError::InternalInvariant(
            "Rust byte request produced a non-Rust syntax tree",
        ));
    };
    let lowered =
        fre_lower::lower_raw_general(&parsed, OperationSemantics::CaptureFree, limits.lower)?;
    let native_finite_language_candidate = (mode == CompileMode::Optimizing)
        .then(|| finite_language::NativeFiniteLanguageCandidate::analyze(&parsed, output))
        .flatten();
    compile_raw_with_line_terminator_and_slow_aot_limits(
        source_bytes,
        lowered.into_plan(),
        line_terminator,
        output,
        native_finite_language_candidate,
        target,
        mode,
        limits,
        slow_aot_limits,
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
        target,
        mode,
        limits,
        SlowAotLimits::default(),
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
        target,
        mode,
        limits,
        SlowAotLimits::default(),
    )
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
) -> Result<(CompiledModule, Vec<u8>), CompileError> {
    let enabled = CompiledModule::lower(program, target)?;
    match emit_object(&enabled, format, max_object_bytes) {
        Ok(object) => Ok((enabled, object)),
        Err(first @ ObjectError::Resource {
            resource: CompileResource::ObjectBytes,
            ..
        }) => {
            // This is the terminal ordinary fallback transaction. The first
            // retry preserves a useful bounded endpoint oracle after some
            // other oversized optimizing candidate; if that composed object
            // itself is too large, the second lowering explicitly disables
            // only the oracle so it cannot be selected again.
            let disabled = CompiledModule::lower_without_endpoint_oracle(program, target)?;
            match emit_object(&disabled, format, max_object_bytes) {
                Ok(object) => Ok((disabled, object)),
                Err(ObjectError::Resource {
                    resource: CompileResource::ObjectBytes,
                    ..
                }) => Err(first.into()),
                Err(error) => Err(error.into()),
            }
        }
        Err(error) => Err(error.into()),
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
    target: Target,
    mode: CompileMode,
    limits: CompileLimitsV1,
    slow_aot_limits: SlowAotLimits,
) -> Result<CompiledRegex, CompileError> {
    let digest = program::automaton_digest(&raw, line_terminator);
    let automaton = Automaton::from_raw(raw.clone(), limits.lower.automata)?
        .with_line_terminator(line_terminator);
    let stats = automaton.stats();
    let mut program = CompiledProgram::build(
        raw,
        automaton,
        output,
        mode,
        limits.determinize,
        limits.max_program_bytes,
    )?;
    if let Some(candidate) = native_finite_language_candidate {
        program.attach_native_finite_language(candidate);
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
        )?,
        CompileMode::Optimizing => {
            let effective_native_data_limit_bytes = slow_aot_limits
                .max_native_data_bytes
                .min(limits.max_object_bytes);
            let optimized = CompiledModule::lower_optimizing_with_limits_and_native_data_limit(
                &program,
                target,
                slow_aot_limits,
                effective_native_data_limit_bytes,
            )?;
            match emit_object(&optimized, format, limits.max_object_bytes) {
                Ok(object) => (optimized, object),
                Err(error @ ObjectError::Resource {
                    resource: CompileResource::ObjectBytes,
                    ..
                }) => {
                    if optimized.optimizing_fallbacks_may_continue() {
                        let k0_fallback = CompiledModule::lower_k0_optimizing_with_data_limit(
                            &program,
                            target,
                            effective_native_data_limit_bytes,
                        )?;
                        match emit_object(&k0_fallback, format, limits.max_object_bytes) {
                            Ok(object) => (k0_fallback, object),
                            Err(ObjectError::Resource {
                                resource: CompileResource::ObjectBytes,
                                ..
                            }) => {
                                match lower_ordinary_with_endpoint_oracle_object_retry(
                                    &program,
                                    target,
                                    format,
                                    limits.max_object_bytes,
                                ) {
                                    Ok(fallback) => fallback,
                                    Err(CompileError::Object(ObjectError::Resource {
                                        resource: CompileResource::ObjectBytes,
                                        ..
                                    })) => return Err(error.into()),
                                    Err(fallback_error) => return Err(fallback_error),
                                }
                            }
                            Err(k0_error) => return Err(k0_error.into()),
                        }
                    } else {
                        match lower_ordinary_with_endpoint_oracle_object_retry(
                            &program,
                            target,
                            format,
                            limits.max_object_bytes,
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
                Err(error) => return Err(error.into()),
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
                OptimizationPass::TargetInstructionSelection,
                OptimizationPass::FixedRegisterAssignment,
                OptimizationPass::CheckedBranchFixup,
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
