//! Capture-preserving facade for the certified Rust-byte subset.
//!
//! Persistent tagged history remains the complete semantic fallback. Eligible
//! exact-span capture replay uses a construction-complete one-pass sidecar.

use core::fmt;
use std::sync::Arc;

use fre_aggregate::{
    CompileAccounting as SelectorCompileAccounting, CompileLimits as SelectorCompileLimits,
    CompiledRegex as SelectorRegex, Error as SelectorError,
    ExecutionAccounting as SelectorExecutionAccounting,
    OperationAttemptError as SelectorOperationAttemptError,
    OperationAttemptReceipt as SelectorOperationAttemptReceipt,
    OperationCertificate as SelectorOperationCertificate,
    OperationLimits as SelectorOperationLimits,
    OperationProspective as SelectorOperationProspective, PlanId as SelectorPlanId,
    Resource as SelectorResource, RustByteProfile as SelectorProfile, Strategy as SelectorStrategy,
};
use fre_capture_lab::{
    AggregateLimits, BuildError as EngineBuildError, BuildLimits as EngineBuildLimits,
    BuildReport as EngineBuildReport, CandidateKind as EngineCandidateKind, CaptureCountOutcome,
    CaptureGroupSlot, CaptureProfile, CaptureRecord, CaptureStream, CaptureStreamAccounting,
    CaptureStreamDomains,
    CaptureStreamError, CaptureStreamLimits, CaptureStreamOperationProspective,
    CaptureStreamProjection, CaptureStreamProspective, CaptureStreamReport, FirstByteProof,
    HirProgramBuildError, HirProgramBuildLimits, HistoryExactWorkspace, HistoryRegex,
    HistorySearchProspective,
    ONEPASS_CAPTURE_ACCOUNTING_VERSION, ONEPASS_CAPTURE_ALGORITHM_VERSION,
    OnePassCaptureBuildError, OnePassCaptureBuildLimits, OnePassCaptureBuildReport,
    OnePassCapturePlan, OnePassCaptureWorkspace, PARTICIPATION_QUOTIENT_ACCOUNTING_VERSION,
    PARTICIPATION_QUOTIENT_ALGORITHM_VERSION, PARTICIPATION_QUOTIENT_CAPTURE_BITS,
    PARTICIPATION_QUOTIENT_MASK_BITS, ParticipationSearchProspective, Program,
    ResourceKind as EngineResource, RunReport as EngineSearchAccounting,
    SearchConfig as CaptureSearchConfig, SearchError as EngineSearchError,
    SearchLimits as EngineSearchLimits, SearchOutcome as EngineSearchOutcome, Span as EngineSpan,
    Window, build_program_from_hir_with_accounting,
};
use fre_kernels::{
    DispatchedPrefixClassAlternationPlan, LiteralSetError, PrefixClassAlternationBuildError,
    PrefixClassAlternationPlan, PrefixClassUniformParticipationAccounting,
    PrefixClassUniformParticipationAttempt, PrefixClassUniformParticipationAttemptError,
    PrefixClassUniformParticipationAttemptReceipt, PrefixClassUniformParticipationBuildAccounting,
    PrefixClassUniformParticipationBuildError, PrefixClassUniformParticipationBuildLimits,
    PrefixClassUniformParticipationError, PrefixClassUniformParticipationIdentity,
    PrefixClassUniformParticipationInvocation, PrefixClassUniformParticipationLimits,
    PrefixClassUniformParticipationProspective, PrefixClassUniformParticipationSchema,
    SimdDispatchContext,
};
use fre_syntax::{
    AdmissionPolicy, AdmissionStatus, CacheKey, CanonicalPattern, CompatibilityProfile, ParseError,
    ParseSummary, RustProfile, SafetyEnvelope,
};
use regex_syntax::hir::{Class, ClassBytesRange, Hir, HirKind, Look};

use crate::aggregate::{
    PrefixClassInspection, PrefixClassInspectionError, inspect_prefix_class_alternation,
    prefix_class_selection_work,
};
use crate::capture_count_seal::{
    CAPTURE_COUNT_ACCOUNTING_VERSION, CAPTURE_COUNT_ALGORITHM_VERSION, CaptureCountActual,
    CaptureCountAttemptReceipt, CaptureCountBranch, CaptureCountDeclaredFallback,
    CaptureCountOwnerSeal, CaptureCountPrepublicationFallback, CaptureCountProspective,
    CaptureCountPublicationPhase, CaptureCountRouteIdentity, CaptureCountSeal,
    CaptureCountSelectorRoute, CaptureCountTerminal,
};
use crate::capture_iteration_seal::{
    CAPTURE_ITERATION_ACCOUNTING_VERSION, CAPTURE_ITERATION_ALGORITHM_VERSION,
    CAPTURE_ITERATION_ASCII_FOLD_RANGE, CAPTURE_ITERATION_START_CLASSIFIER_WORK,
    CaptureIterationActual, CaptureIterationAttemptReceipt, CaptureIterationBackend,
    CaptureIterationDeclaredFallback, CaptureIterationOperation, CaptureIterationOwnerSeal,
    CaptureIterationProspective, CaptureIterationRouteIdentity, CaptureIterationSeal,
    CaptureIterationStartClassifierOutcome, CaptureIterationStartClassifierReceipt,
};
use crate::capture_required_literal::{
    self, CaptureRequiredLiteralBuildAccounting, CaptureRequiredLiteralBuildError,
    CaptureRequiredLiteralBuildLimits, CaptureRequiredLiteralIdentity, CaptureRequiredLiteralPlan,
};

pub use fre_capture_lab::HirBuildAccounting as CaptureHirAccounting;

/// Version of capture-valued exact-span replay route selection.
pub const CAPTURE_EXACT_REPLAY_ALGORITHM_VERSION: u32 = 1;
/// Version of exact-replay facade identity and fallback accounting.
pub const CAPTURE_EXACT_REPLAY_ACCOUNTING_VERSION: u32 = 1;

const FIXED_BYTE_CAPTURE_RECORD_MAX_WIDTH: usize = 64;
const FIXED_BYTE_CAPTURE_RECORD_MAX_GROUPS: usize = 64;
const FIXED_BYTE_CAPTURE_RECORD_MAX_INSPECTION_WORK: usize = 1_024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FixedByteCaptureMask([u64; 4]);

impl FixedByteCaptureMask {
    fn insert(&mut self, byte: u8) {
        let byte = usize::from(byte);
        self.0[byte / 64] |= 1_u64 << (byte % 64);
    }

    fn contains(self, byte: u8) -> bool {
        let byte = usize::from(byte);
        self.0[byte / 64] & (1_u64 << (byte % 64)) != 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FixedByteCaptureRange {
    start: usize,
    end: usize,
    optional: bool,
}

/// Direct exact-record plan for an unanchored, fixed byte sequence whose
/// captures are direct root children. The only variable-width form admitted
/// is one greedy optional capture at the end of the root concatenation.
#[derive(Clone, Debug)]
struct FixedByteCaptureRecordPlan {
    masks: [FixedByteCaptureMask; FIXED_BYTE_CAPTURE_RECORD_MAX_WIDTH],
    captures: [Option<FixedByteCaptureRange>; FIXED_BYTE_CAPTURE_RECORD_MAX_GROUPS],
    mandatory_width: usize,
    optional_width: usize,
    group_count: usize,
}

#[derive(Clone, Debug)]
struct FixedByteCaptureRecordBuild {
    plan: Option<Arc<FixedByteCaptureRecordPlan>>,
    inspection_work: usize,
}

/// Capture-aware operation included in construction and execution identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureOperation {
    /// Sum participating groups over a non-overlapping sequence of non-empty matches.
    CountParticipatingNonempty,
}

/// Production plan selected for the admitted capture operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturePlanKind {
    /// A proved ordered root alternation whose direct arms each contain one
    /// distinct capture; the selector batches root choice once per row.
    OrderedRootCaptureManyCount,
    /// Direct capture Count for two ordered `LITERAL BYTE_CLASS+` arms, with
    /// one canonical-HIR-proved participating group per selected match.
    UniformPrefixClassParticipation,
    /// One operation-wide span selector plus a construction-time proof of a
    /// fixed participating-capture cardinality for every selected match.
    LinearSelectorUniformParticipation,
    /// One operation-wide span selector plus exact-span persistent-history replay.
    LinearSelectorPersistentHistory,
    /// One operation-wide span selector plus exact-span paired-side
    /// participation masks. Tagged offsets are erased because the aggregate
    /// observes only whether each group participated.
    LinearSelectorParticipationQuotientV1,
    /// One reusable ordered frontier carries only aggregate-observable
    /// participation masks and applies capture tags before first-arrival
    /// program-counter deduplication. Source-free construction refusal retains
    /// the selector/quotient route as its declared generic fallback.
    FusedCaptureStreamParticipationV1,
    /// The same reusable ordered frontier with construction-selected bounded
    /// persistent histories for schemas wider than one participation word.
    /// Source-free construction refusal retains selector/history replay.
    FusedCaptureStreamPersistentHistoryV1,
}

/// Aggregate-only projection selected for one already-verified whole-match
/// span. This is crate-visible because the forced multi-pattern bridge owns
/// ordinal selection while this facade owns capture semantics.
///
/// The variants deliberately retain only the information observable by a
/// capture-count reducer. In particular, neither the mask nor the fixed
/// cardinality route materializes capture offsets. Full persistent history is
/// reserved for schemas whose participation cannot be represented by the
/// fixed quotient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExactCaptureParticipation {
    /// A canonical-HIR proof fixes the complete participating-group count.
    Cardinality(u64),
    /// Count projected from a fixed-width reusable participation mask. The
    /// reusable workspace deliberately retains no externally observable tag
    /// offsets; only this count is needed by the aggregate reducer.
    MaskCount(u64),
    /// Exact persistent-history materialization counted participating groups.
    PersistentHistory(u64),
}

impl ExactCaptureParticipation {
    /// Number of participating groups, including the overall group.
    pub(crate) const fn entries(self) -> u64 {
        match self {
            Self::Cardinality(entries)
            | Self::MaskCount(entries)
            | Self::PersistentHistory(entries) => entries,
        }
    }
}

/// Typed compatibility receipt for HIR forms outside the certified capture compiler.
///
/// The pinned `regex-syntax` look set is currently implemented. This type is
/// retained so future upstream look variants can remain explicit refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureUnsupported {
    /// A look assertion has not been implemented by the tagged program.
    Look(Look),
}

/// Construction proof for the ordered-root capture-many Count route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderedRootUnitCover {
    /// The terminal class plus earlier unconditional witnesses cover every
    /// possible byte.
    Bytes,
    /// The terminal class plus earlier unconditional witnesses cover every
    /// Unicode scalar. Invalid UTF-8 remains outside the scalar language and
    /// is handled by the ordinary byte-haystack search semantics.
    UnicodeScalars,
}

/// Construction proof for the ordered-root capture-many Count route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedRootCaptureManyProof {
    /// Source-ordered root alternatives and explicit capture slots.
    pub root_arms: usize,
    /// Participating user captures per selected match.
    pub participating_captures: usize,
    /// Participating groups including group zero.
    pub groups_per_match: usize,
    /// Optional source-independent proof that every byte/scalar boundary has
    /// a nonempty ordered arm. This permits an anchored token representation
    /// without changing the selected leftmost-first language.
    pub unit_cover: Option<OrderedRootUnitCover>,
    /// Exact work charged while classifying the canonical capture HIR.
    pub proof_work: usize,
}

/// Construction proof that independent line domains may be concatenated for
/// capture-participation Count by inserting one non-consuming ASCII scalar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLineBatchProof {
    /// ASCII byte rejected by every consuming HIR atom.
    pub separator: u8,
    /// Positive whole-match minimum from the same canonical HIR.
    pub minimum_match_bytes: usize,
    /// Metered canonical-HIR work used to establish delimiter exclusion and
    /// the absence of context-sensitive look assertions.
    pub planner_work: usize,
}

/// Only permitted construction-time action when the fixed participation
/// quotient cannot represent the complete capture schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureParticipationQuotientFallback {
    /// Retain exact-span full tagged-history replay.
    PersistentHistory,
}

/// Construction proof for aggregate-only tagged-history quotienting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureParticipationQuotientProof {
    /// User capture groups represented by the state masks.
    pub user_captures: u8,
    /// Fixed bit width of each state mask, including group zero.
    pub mask_bits: u8,
    /// Bits reserved for authenticating overall-match participation.
    pub reserved_overall_bits: u8,
    /// Number of inline masks: open groups and completed participation.
    pub state_masks: u8,
    /// Tagged byte offsets retained by this aggregate-only route.
    pub retained_offsets: u8,
    /// Version of the quotient transition and winner projection.
    pub algorithm_version: u32,
    /// Version of its state-visit, scratch, and zero-history ledger.
    pub accounting_version: u32,
    /// Generic construction-time fallback for larger schemas.
    pub declared_prepublication_fallback: CaptureParticipationQuotientFallback,
}

/// Construction limits whose exact values participate in cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureBuildLimits {
    /// Syntax admission policy.
    pub admission: AdmissionPolicy,
    /// Hard syntax safety envelope.
    pub syntax_safety: SafetyEnvelope,
    /// Maximum HIR-to-AST conversion work.
    pub max_hir_work: usize,
    /// Maximum HIR conversion depth.
    pub max_hir_depth: usize,
    /// Persistent-history compiler limits.
    pub engine: EngineBuildLimits,
    /// Capture-erased operation-wide span-selector compiler limits.
    pub selector: SelectorCompileLimits,
    /// Optional required-literal proof and DFA limits. `None` performs no
    /// additional HIR traversal and preserves the legacy capture artifact.
    pub required_literal: Option<CaptureRequiredLiteralBuildLimits>,
    /// Independent canonical-HIR inspection ceiling for the optional direct
    /// two-arm prefix/class capture route.
    pub max_prefix_class_participation_planner_work: usize,
    /// Construction limits for the optional direct prefix/class kernel.
    pub prefix_class_participation: PrefixClassUniformParticipationBuildLimits,
}

impl Default for CaptureBuildLimits {
    fn default() -> Self {
        // These checked ceilings admit the pinned 2,500-scalar dot repeat and
        // 50-scalar Unicode-letter repeat. They do not preallocate their
        // maximum state or patch capacities.
        let engine = EngineBuildLimits {
            max_ast_nodes: 65_536,
            // The authenticated Rebar lexer surface contains 65 user
            // captures. This remains a checked construction ceiling, not a
            // preallocation: the compiler charges every capture and all
            // resulting states before publishing a program.
            max_captures: 1_024,
            max_repeat_expansion: 2_500,
            max_states: 524_288,
            max_patch_entries: 524_288,
            ..EngineBuildLimits::default()
        };
        let selector = SelectorCompileLimits {
            max_repeat_bound: 2_500,
            // The authenticated Rebar overlapping-word capture pair expands
            // ten ordered Unicode-letter repetitions into more than 2^18
            // capture-erased selector states. Construction remains metered
            // and bounded; these ceilings do not preallocate either buffer.
            max_program_states: 524_288,
            max_temporary_states: 524_288,
            max_program_bytes: 32 * 1_048_576,
            ..SelectorCompileLimits::default()
        };
        Self {
            admission: AdmissionPolicy::default(),
            syntax_safety: SafetyEnvelope::default(),
            max_hir_work: 1_000_000,
            max_hir_depth: 250,
            engine,
            selector,
            required_literal: None,
            max_prefix_class_participation_planner_work: 4_096,
            prefix_class_participation: PrefixClassUniformParticipationBuildLimits::default(),
        }
    }
}

/// Execution limits included verbatim in the execution cache identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureRunLimits {
    /// Limits for exact-span tagged replay and capture reduction.
    pub aggregate: AggregateLimits,
    /// Limits for the complete operation-wide span selection.
    pub selector: SelectorOperationLimits,
    /// Maximum logical dynamic bytes across selector execution or retained
    /// selector output plus one exact-span replay.
    pub max_combined_peak_bytes: usize,
    /// Independent direct-operation limits. These are inactive for selector
    /// and persistent-history plans but remain part of invocation identity.
    pub prefix_class_participation: PrefixClassUniformParticipationLimits,
}

impl Default for CaptureRunLimits {
    fn default() -> Self {
        Self {
            aggregate: AggregateLimits::default(),
            selector: SelectorOperationLimits::default(),
            max_combined_peak_bytes: 512 * 1_048_576,
            prefix_class_participation: PrefixClassUniformParticipationLimits::default(),
        }
    }
}

/// Exact direct-route identity proved from canonical HIR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturePrefixClassParticipationIdentity {
    /// Distinct capture-aware physical operation identity.
    pub kernel: PrefixClassUniformParticipationIdentity,
    /// Numeric capture index around each ordered branch's greedy class.
    pub participating_capture_indices: [u32; 2],
    /// The only route allowed when direct construction refuses before plan
    /// publication.
    pub declared_prepublication_fallback: CapturePlanKind,
}

/// Stable physical plan selected for exact-span capture replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureExactReplayPlan {
    /// Construction-complete deterministic replay.
    OnePass,
    /// Complete tagged-history semantic authority.
    PersistentHistory,
}

/// Only permitted source-free fallback from an optional exact-replay route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureExactReplayFallback {
    /// Use complete tagged-history exact replay before source access.
    PersistentHistory,
}

/// Versioned identity for the capture-valued exact-replay operation.
///
/// This is deliberately separate from [`CapturePlanIdentity`], whose operation
/// is capture participation Count and is unaffected by an auxiliary exact
/// replay route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureExactReplayIdentity {
    /// Complete syntax/profile/admission key.
    pub syntax: Arc<CacheKey>,
    /// Versioned capture semantics.
    pub capture_profile: CaptureProfile,
    /// Selected exact-capture physical route.
    pub plan: CaptureExactReplayPlan,
    /// Exact capture construction limits.
    pub build_limits: CaptureBuildLimits,
    /// Stable one-pass shape/version identity, present only for that route.
    pub onepass: Option<CaptureOnePassPlanIdentity>,
    /// Facade route-selection algorithm version, including the
    /// persistent-history-only route.
    pub algorithm_version: u32,
    /// Facade admission and fallback accounting version.
    pub accounting_version: u32,
    /// Only permitted fallback before source access. A one-pass route may use
    /// it when invocation bounds or workspace construction refuse; the
    /// persistent-history route is already at this authority.
    pub declared_pre_source_fallback: CaptureExactReplayFallback,
}

/// Stable identity for one admitted one-pass exact-replay sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureOnePassPlanIdentity {
    /// Deterministic state count.
    pub states: usize,
    /// Complete dense transition count.
    pub transitions: usize,
    /// Interned action count.
    pub actions: usize,
    /// Exact immutable sidecar bytes.
    pub program_bytes: usize,
    /// Semantic one-pass exact-replay version.
    pub algorithm_version: u32,
    /// Construction/execution accounting version.
    pub accounting_version: u32,
}

impl CaptureOnePassPlanIdentity {
    fn from_engine(report: &OnePassCaptureBuildReport) -> Self {
        Self {
            states: report.states,
            transitions: report.transitions,
            actions: report.actions,
            program_bytes: report.program_bytes,
            algorithm_version: ONEPASS_CAPTURE_ALGORITHM_VERSION,
            accounting_version: ONEPASS_CAPTURE_ACCOUNTING_VERSION,
        }
    }
}

/// Immutable plan identity. Source syntax remains distinct even when HIRs agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturePlanIdentity {
    /// Complete syntax/profile/admission key.
    pub syntax: Arc<CacheKey>,
    /// Capture-aware operation.
    pub operation: CaptureOperation,
    /// Selected engine family.
    pub plan: CapturePlanKind,
    /// Versioned capture semantic profile.
    pub capture_profile: CaptureProfile,
    /// Exact capture-erased selector program identity.
    pub selector_plan_id: SelectorPlanId,
    /// Ordered-root theorem dimensions for the dedicated capture-many route.
    pub ordered_root_capture_many: Option<OrderedRootCaptureManyProof>,
    /// Optional generic required-any-literal proof sharing this exact syntax.
    pub required_literal: Option<CaptureRequiredLiteralIdentity>,
    /// Optional separator theorem for exact independent-domain batching.
    pub line_batch: Option<CaptureLineBatchProof>,
    /// Direct physical route and its declared U3 fallback, when selected.
    pub prefix_class_participation: Option<CapturePrefixClassParticipationIdentity>,
}

/// Stable construction accounting for an optional one-pass exact-capture
/// sidecar.
///
/// The engine's process-local workspace-authentication identity is
/// intentionally omitted so independently constructed equivalent plans retain
/// equal facade build reports and cache identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureOnePassBuildReport {
    /// Deterministic DFA states.
    pub states: usize,
    /// Equivalence classes over input bytes.
    pub byte_classes: usize,
    /// Dense state/class transitions.
    pub transitions: usize,
    /// Interned transition and terminal actions.
    pub actions: usize,
    /// Capture-tag writes across all interned actions.
    pub tag_actions: usize,
    /// Assertion checks across all interned actions.
    pub assertions: usize,
    /// Greatest number of capture-tag writes in one action.
    pub max_action_tag_actions: usize,
    /// Greatest number of assertion predicates evaluated by one action.
    pub max_action_assertions: usize,
    /// Whether assertion-free actions use direct transition-local tag masks.
    pub direct_tag_masks: bool,
    /// Metered construction work.
    pub compile_work: usize,
    /// Immutable bytes retained by the sidecar.
    pub program_bytes: usize,
}

impl CaptureOnePassBuildReport {
    fn from_engine(report: &OnePassCaptureBuildReport) -> Self {
        Self {
            states: report.states,
            byte_classes: report.byte_classes,
            transitions: report.transitions,
            actions: report.actions,
            tag_actions: report.tag_actions,
            assertions: report.assertions,
            max_action_tag_actions: report.max_action_tag_actions,
            max_action_assertions: report.max_action_assertions,
            direct_tag_masks: report.direct_tag_masks,
            compile_work: report.compile_work,
            program_bytes: report.program_bytes,
        }
    }
}

/// Construction report for one immutable capture plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureBuildReport {
    /// What constructor admission has established.
    pub admission: AdmissionStatus,
    /// Bounded syntax facts.
    pub syntax: ParseSummary,
    /// Checked HIR conversion accounting.
    pub hir: CaptureHirAccounting,
    /// Tagged-program construction and allocation accounting.
    pub engine: EngineBuildReport,
    /// Stable optional one-pass exact-capture sidecar accounting. Construction
    /// spends only the tagged engine's remaining state, work and
    /// immutable-byte ceilings; `None` is the source-independent
    /// persistent-history fallback.
    /// This auxiliary capture-valued route does not alter the Count operation
    /// sealed by [`CapturePlanIdentity`].
    pub onepass_capture: Option<CaptureOnePassBuildReport>,
    /// Exact metered compile work completed by the optional sidecar attempt,
    /// including attempts that declined before publication.
    pub onepass_capture_compile_work: usize,
    /// Complete operation identity for capture-valued exact-span replay.
    pub exact_replay_identity: CaptureExactReplayIdentity,
    /// Capture-erased selector construction accounting.
    pub selector: SelectorCompileAccounting,
    /// Exact explicit-capture participation per selected match when the HIR
    /// proves that cardinality independent of input and branch choice.
    pub uniform_participating_captures: Option<usize>,
    /// Proof attached only to the ordered-root capture-many route.
    pub ordered_root_capture_many: Option<OrderedRootCaptureManyProof>,
    /// Optional bounded required-literal construction receipt.
    pub required_literal: Option<CaptureRequiredLiteralBuildAccounting>,
    /// Optional exact separator theorem for independent line batching.
    pub line_batch: Option<CaptureLineBatchProof>,
    /// Additional canonical-HIR work used to accept or refuse the optional
    /// direct prefix/class route.
    pub prefix_class_participation_planner_work: usize,
    /// Successful direct-kernel construction accounting.
    pub prefix_class_participation: Option<PrefixClassUniformParticipationBuildAccounting>,
    /// Complete immutable plan identity.
    pub plan_identity: CapturePlanIdentity,
}

impl CaptureBuildReport {
    /// Reconstruct the fixed quotient theorem from the immutable selected plan
    /// and compiled capture schema. No proof bytes are duplicated in the
    /// artifact or execution identity.
    #[must_use]
    pub fn participation_quotient_proof(&self) -> Option<CaptureParticipationQuotientProof> {
        if !matches!(
            self.plan_identity.plan,
            CapturePlanKind::LinearSelectorParticipationQuotientV1
                | CapturePlanKind::FusedCaptureStreamParticipationV1
        ) || self.engine.captures > PARTICIPATION_QUOTIENT_CAPTURE_BITS
        {
            return None;
        }
        let user_captures = u8::try_from(self.engine.captures).ok()?;
        Some(CaptureParticipationQuotientProof {
            user_captures,
            mask_bits: PARTICIPATION_QUOTIENT_MASK_BITS,
            reserved_overall_bits: 1,
            state_masks: 2,
            retained_offsets: 0,
            algorithm_version: PARTICIPATION_QUOTIENT_ALGORITHM_VERSION,
            accounting_version: PARTICIPATION_QUOTIENT_ACCOUNTING_VERSION,
            declared_prepublication_fallback:
                CaptureParticipationQuotientFallback::PersistentHistory,
        })
    }
}

/// Execution/cache identity for a capture reducer invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureCacheIdentity {
    /// Immutable plan identity.
    pub plan: CapturePlanIdentity,
    /// Construction limits used to publish the plan.
    pub build_limits: CaptureBuildLimits,
    /// Execution limits used for this invocation.
    pub run_limits: CaptureRunLimits,
    /// Construction-owned Count route plus these exact execution limits.
    /// Positive-width uniform selector and direct plans retain `Some`.
    pub count_seal: Option<CaptureCountSeal>,
}

impl CaptureCacheIdentity {
    fn has_coherent_count_seal(&self) -> bool {
        self.count_seal.as_ref().is_some_and(|seal| {
            let route = seal.route_identity();
            self.plan == route.plan
                && self.build_limits == route.build_limits
                && self.run_limits == seal.run_limits()
        })
    }
}

/// Typed capture construction failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureBuildError {
    /// Syntax/profile/admission failure.
    Syntax(fre_syntax::ParseError),
    /// Syntax is valid but outside the certified capture subset.
    Unsupported(CaptureUnsupported),
    /// HIR conversion work or depth exceeded its explicit limit.
    HirResource {
        /// Resource dimension.
        resource: &'static str,
        /// Required amount.
        required: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// A checked HIR conversion allocation failed.
    Allocation {
        /// Structure being allocated.
        structure: &'static str,
        /// Requested items.
        items: usize,
    },
    /// Tagged-program construction refused or faulted.
    Engine(EngineBuildError),
    /// Operation-wide capture-erased span selector refused or faulted.
    Selector(SelectorError),
    /// Direct prefix/class construction reached a non-optional terminal.
    PrefixClassParticipation(PrefixClassUniformParticipationBuildError),
    /// Optional required-literal proof or DFA construction refused.
    RequiredLiteral(CaptureRequiredLiteralBuildError),
    /// Facade invariant failure.
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(error) => write!(formatter, "capture syntax failed: {error}"),
            Self::Unsupported(feature) => {
                write!(formatter, "unsupported capture HIR feature: {feature:?}")
            }
            Self::HirResource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "capture HIR {resource} needs {required}, exceeding {limit}"
            ),
            Self::Allocation { structure, items } => {
                write!(
                    formatter,
                    "capture HIR failed to reserve {items} {structure} items"
                )
            }
            Self::Engine(error) => write!(formatter, "capture engine build failed: {error}"),
            Self::Selector(error) => write!(formatter, "capture selector build failed: {error}"),
            Self::PrefixClassParticipation(error) => {
                write!(formatter, "capture prefix/class build failed: {error}")
            }
            Self::RequiredLiteral(error) => {
                write!(formatter, "capture required-literal build failed: {error}")
            }
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture facade invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Syntax(error) => Some(error),
            Self::Engine(error) => Some(error),
            Self::Selector(error) => Some(error),
            Self::PrefixClassParticipation(error) => Some(error),
            Self::RequiredLiteral(error) => Some(error),
            _ => None,
        }
    }
}

fn capture_hir_program_build_error(error: HirProgramBuildError) -> CaptureBuildError {
    match error {
        HirProgramBuildError::Resource {
            resource,
            required,
            limit,
        } => CaptureBuildError::HirResource {
            resource: resource.as_str(),
            required,
            limit,
        },
        HirProgramBuildError::Allocation { structure, items } => CaptureBuildError::Allocation {
            structure: structure.as_str(),
            items,
        },
        HirProgramBuildError::Program(error) => CaptureBuildError::Engine(error),
        HirProgramBuildError::InternalInvariant(detail) => {
            CaptureBuildError::InternalInvariant(detail)
        }
    }
}

/// Typed source of a capture operation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureExecutionSource {
    /// Direct prefix/class participation route refused or faulted. Once its
    /// prospective is published this is terminal and never selects U3.
    PrefixClassParticipation(PrefixClassUniformParticipationError),
    /// Immutable selector/history/direct plans plus direct operation state, or
    /// the mandatory U3 control envelope, exceed the caller's peak before
    /// source access.
    CombinedPeak {
        /// Required co-live bytes.
        needed: usize,
        /// Caller limit.
        limit: usize,
    },
    /// Complete capture-erased span selection failed before tagged replay.
    Selector(SelectorError),
    /// Exact-span persistent-history replay or reduction failed.
    History(EngineSearchError),
    /// Fused ordered-frontier construction or execution failed.
    Stream(CaptureStreamError),
    /// Selector and tagged replay disagreed despite sharing one canonical HIR.
    InternalInvariant(&'static str),
}

impl fmt::Display for CaptureExecutionSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixClassParticipation(error) => error.fmt(formatter),
            Self::CombinedPeak { needed, limit } => write!(
                formatter,
                "capture co-live peak needs {needed} bytes, exceeding {limit}"
            ),
            Self::Selector(error) => error.fmt(formatter),
            Self::History(error) => error.fmt(formatter),
            Self::Stream(error) => error.fmt(formatter),
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture operation invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureExecutionSource {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrefixClassParticipation(error) => Some(error),
            Self::CombinedPeak { .. } | Self::InternalInvariant(_) => None,
            Self::Selector(error) => Some(error),
            Self::History(error) => Some(error),
            Self::Stream(error) => Some(error),
        }
    }
}

/// Capture execution failure retaining the exact plan and limit identity.
#[derive(Debug)]
pub struct CaptureExecutionError {
    /// Complete invocation identity.
    pub identity: CaptureCacheIdentity,
    /// Typed selector/history/reducer failure.
    pub source: CaptureExecutionSource,
    /// Complete Count-attempt receipt when the uniform-participation route
    /// reached its prospective selector boundary.
    pub selector_receipt: Option<SelectorOperationAttemptReceipt>,
    /// Complete direct attempt receipt, including optional P, cumulative A and
    /// successful allocation count.
    pub prefix_class_participation_receipt: Option<PrefixClassUniformParticipationAttemptReceipt>,
    /// Whole-operation owner receipt for a sealed positive-width Count route.
    pub count_receipt: Option<CaptureCountAttemptReceipt>,
}

impl fmt::Display for CaptureExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture execution failed: {}", self.source)
    }
}

impl std::error::Error for CaptureExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl CaptureExecutionError {
    /// Whether this terminal failure retains one authenticated construction
    /// owner and a complete whole-operation Count receipt.
    #[must_use]
    pub fn has_closed_count_attempt(&self) -> bool {
        if !self.identity.has_coherent_count_seal() {
            return false;
        }
        let (Some(seal), Some(receipt)) = (
            self.identity.count_seal.as_ref(),
            self.count_receipt.as_ref(),
        ) else {
            return false;
        };
        if receipt.terminal != CaptureCountTerminal::Failure || !receipt.closes(seal) {
            return false;
        }
        if !count_failure_source_closes(seal, receipt, &self.source) {
            return false;
        }
        match seal.route_identity().branch {
            CaptureCountBranch::SelectorUniformParticipation => {
                self.prefix_class_participation_receipt.is_none()
                    && matches!(
                        (self.selector_receipt.as_ref(), receipt.selector.as_ref()),
                        (Some(selector), Some(nested)) if selector == nested
                    )
            }
            CaptureCountBranch::DirectPrefixClassParticipation => {
                self.selector_receipt.is_none()
                    && matches!(
                        (
                            self.prefix_class_participation_receipt.as_ref(),
                            receipt.direct.as_ref(),
                        ),
                        (Some(direct), Some(nested)) if direct == nested
                    )
            }
        }
    }
}

/// Successful reducer value and exact allocation/work counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureExecutionReport {
    /// Complete invocation identity.
    pub identity: CaptureCacheIdentity,
    /// Persistent-history and reducer accounting.
    pub accounting: CaptureCountOutcome,
    /// Whole-operation selector certificate.
    pub selector_certificate: Option<SelectorOperationCertificate>,
    /// Exact selector work and storage accounting.
    pub selector_accounting: Option<SelectorExecutionAccounting>,
    /// Complete selector Count receipt for the positive-width uniform route.
    /// Span-bearing selector/replay routes retain `None`.
    pub selector_receipt: Option<SelectorOperationAttemptReceipt>,
    /// Complete direct prefix/class P/A accounting. Selector-backed routes
    /// retain `None`.
    pub prefix_class_participation: Option<PrefixClassUniformParticipationAccounting>,
    /// Complete direct identity/invocation/P/A receipt. Selector-backed routes
    /// retain `None`.
    pub prefix_class_participation_receipt: Option<PrefixClassUniformParticipationAttemptReceipt>,
    /// Whole-operation owner receipt for a sealed positive-width Count route.
    pub count_receipt: Option<CaptureCountAttemptReceipt>,
    /// Complete fused ordered-frontier construction and execution report.
    /// Selector/direct routes retain `None`.
    pub capture_stream: Option<CaptureStreamReport>,
    /// Complete capture-schema entries logically inspected by the reducer.
    pub capture_events: usize,
    /// Conservative retained/operation peak for the selected route, never
    /// below the mandatory U3 control envelope. Selector routes retain their
    /// existing dynamic interpretation.
    pub combined_peak_bytes: usize,
}

impl CaptureExecutionReport {
    /// Whether this success retains one authenticated construction owner and a
    /// complete whole-operation Count receipt.
    #[must_use]
    pub fn has_closed_count_attempt(&self) -> bool {
        if !self.identity.has_coherent_count_seal() {
            return false;
        }
        let (Some(seal), Some(receipt)) = (
            self.identity.count_seal.as_ref(),
            self.count_receipt.as_ref(),
        ) else {
            return false;
        };
        if receipt.terminal != CaptureCountTerminal::Success || !receipt.closes(seal) {
            return false;
        }
        if self.accounting.matches != receipt.actual.matches
            || self.accounting.count != receipt.actual.capture_count
            || self.accounting.searches != 0
            || self.accounting.total_state_visits != 0
            || self.accounting.total_history_nodes != 0
            || self.accounting.total_history_walk != 0
            || self.accounting.peak_threads != 0
            || self.capture_events != receipt.actual.capture_events
        {
            return false;
        }
        match seal.route_identity().branch {
            CaptureCountBranch::SelectorUniformParticipation => matches!(
                (
                    self.selector_receipt.as_ref(),
                    receipt.selector.as_ref(),
                    self.selector_certificate.as_ref(),
                ),
                (Some(selector), Some(nested), Some(certificate))
                    if selector == nested
                        && selector_certificate_closes(certificate, selector)
                        && self.selector_accounting.as_ref() == Some(&selector.actual)
                        && self.combined_peak_bytes == receipt.actual.combined_peak_bytes
                        && self.prefix_class_participation.is_none()
                        && self.prefix_class_participation_receipt.is_none()
            ),
            CaptureCountBranch::DirectPrefixClassParticipation => matches!(
                (
                    self.prefix_class_participation.as_ref(),
                    self.prefix_class_participation_receipt.as_ref(),
                    receipt.direct.as_ref(),
                ),
                (Some(accounting), Some(direct), Some(nested))
                    if direct == nested
                        && accounting.closes_receipt(direct)
                        && receipt.prospective.is_some_and(|prospective| {
                            self.combined_peak_bytes == prospective.combined_peak_bytes
                        })
                        && self.selector_certificate.is_none()
                        && self.selector_accounting.is_none()
                        && self.selector_receipt.is_none()
            ),
        }
    }
}

fn count_failure_source_closes(
    seal: &CaptureCountSeal,
    receipt: &CaptureCountAttemptReceipt,
    source: &CaptureExecutionSource,
) -> bool {
    let branch = seal.route_identity().branch;
    let publication_phase = receipt.publication_phase();
    let direct_zero_effects = receipt.actual
        == CaptureCountActual {
            direct: Some(fre_kernels::PrefixClassUniformParticipationActual::default()),
            combined_peak_bytes: seal.route_identity().retained_fallback_bytes,
            ..CaptureCountActual::default()
        };
    matches!(
        (branch, publication_phase, source),
        (
            CaptureCountBranch::SelectorUniformParticipation,
            CaptureCountPublicationPhase::BeforeNested,
            CaptureExecutionSource::Selector(_),
        ) | (
            CaptureCountBranch::SelectorUniformParticipation,
            CaptureCountPublicationPhase::Nested,
            CaptureExecutionSource::History(_),
        ) | (
            CaptureCountBranch::SelectorUniformParticipation,
            CaptureCountPublicationPhase::Whole,
            CaptureExecutionSource::Selector(_)
                | CaptureExecutionSource::History(_)
                | CaptureExecutionSource::InternalInvariant(_),
        ) | (
            CaptureCountBranch::DirectPrefixClassParticipation,
            CaptureCountPublicationPhase::BeforeNested,
            CaptureExecutionSource::PrefixClassParticipation(_),
        ) | (
            CaptureCountBranch::DirectPrefixClassParticipation,
            CaptureCountPublicationPhase::Nested,
            CaptureExecutionSource::Selector(_)
                | CaptureExecutionSource::History(_)
                | CaptureExecutionSource::InternalInvariant(_),
        ) | (
            CaptureCountBranch::DirectPrefixClassParticipation,
            CaptureCountPublicationPhase::Whole,
            CaptureExecutionSource::PrefixClassParticipation(_)
                | CaptureExecutionSource::InternalInvariant(_),
        )
    ) || (direct_zero_effects
        && matches!(
            (branch, publication_phase, source),
            (
                CaptureCountBranch::DirectPrefixClassParticipation,
                CaptureCountPublicationPhase::Whole,
                CaptureExecutionSource::Selector(_)
                    | CaptureExecutionSource::History(_)
                    | CaptureExecutionSource::CombinedPeak { .. },
            )
        ))
}

#[allow(
    clippy::too_many_lines,
    reason = "the public compact certificate duplicates every published selector identity and prospective field, so closure names each field explicitly"
)]
fn selector_certificate_closes(
    certificate: &SelectorOperationCertificate,
    selector: &SelectorOperationAttemptReceipt,
) -> bool {
    let Some(prospective) = selector.prospective else {
        return false;
    };
    let Some(boundaries) = certificate
        .range
        .end
        .checked_sub(certificate.range.start)
        .and_then(|bytes| bytes.checked_add(1))
    else {
        return false;
    };
    certificate.regex_plan_id == selector.identity.regex_plan_id
        && certificate.operation_limits_id == selector.identity.operation_limits_id
        && certificate.strategy == selector.identity.strategy
        && certificate.operation == selector.identity.operation
        && selector.identity.operation_id() == Some(certificate.operation_id())
        && selector.identity.physical_route == Some(certificate.physical_route)
        && certificate.algorithm_version == selector.identity.algorithm_version
        && certificate.accounting_version == selector.identity.accounting_version
        && certificate.prepublication_fallback == selector.identity.prepublication_fallback
        && certificate.range == selector.invocation.range
        && boundaries == prospective.boundaries
        && certificate.states == prospective.states
        && certificate.table_cells == prospective.table_cells
        && certificate.row_storage == prospective.row_storage
        && certificate.row_record_bytes == prospective.row_record_bytes
        && certificate.terminal_frontier == prospective.terminal_frontier
        && certificate.work_bound == prospective.work_bound
        && certificate.random_access_bytes == prospective.random_access_bytes
        && certificate.scratch_bytes == prospective.scratch_bytes
        && certificate.log_bytes == prospective.log_bytes
        && certificate.sequential_bytes_bound == prospective.sequential_bytes
        && certificate.match_events == prospective.match_events
        && certificate.output_matches == prospective.output_matches
        && certificate.output_bytes == prospective.output_bytes
        && certificate.span_sum == prospective.span_sum
        && usize::from(certificate.prospective_allocations) == prospective.allocations
        && usize::from(certificate.actual_allocations) == selector.actual_allocations
        && certificate.peak_bytes == prospective.peak_bytes
}

/// Plan selected for bounded materialized capture iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureIterationPlanKind {
    /// Independently bounded leftmost searches with persistent tagged history
    /// and Rust byte-regex empty-match progression.
    RestartedPersistentHistory,
}

/// Production identity for the bounded persistent-history capture iterator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIterationIdentity {
    /// Complete syntax/profile/admission key.
    pub syntax: Arc<CacheKey>,
    /// Versioned capture semantic profile.
    pub capture_profile: CaptureProfile,
    /// Exact materializing iterator formulation.
    pub plan: CaptureIterationPlanKind,
    /// Match-end selection and start-injection policy.
    pub search: CaptureSearchConfig,
    /// Construction limits used to publish the immutable tagged program.
    pub build_limits: CaptureBuildLimits,
    /// Aggregate limits used for this repeated-search invocation.
    pub run_limits: AggregateLimits,
    /// Construction provenance, physical backend, search policy, versions,
    /// limits, and declared terminal behavior for this exact invocation.
    pub session_seal: CaptureIterationSeal,
}

/// Successful complete capture sequence and bounded execution accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIterationReport {
    /// Complete operation identity.
    pub identity: CaptureIterationIdentity,
    /// Every match, with one stable numeric/name/span entry for every group.
    /// Unmatched groups remain explicit `None` entries and empty participating
    /// groups retain their zero-width spans.
    pub captures: Vec<CaptureRecord>,
    /// Number of independently bounded searches, including the final miss
    /// unless iteration ended at a terminal empty match or construction proved
    /// that a published record consumed the sole original-haystack
    /// absolute-start opportunity.
    pub searches: usize,
    /// Total Thompson state visits.
    pub total_state_visits: usize,
    /// Total inline capture-slot copies (zero for persistent history).
    pub total_slot_copies: usize,
    /// Total persistent-history nodes.
    pub total_history_nodes: usize,
    /// Total winning-history reconstruction steps.
    pub total_history_walk: usize,
    /// Complete capture-schema entries materialized.
    pub capture_events: usize,
    /// Maximum live persistent-history threads in any search.
    pub peak_threads: usize,
    /// Maximum admitted dynamic scratch bytes in any search.
    pub peak_scratch_bytes: usize,
    /// Exact versioned logical bytes retained by returned capture records.
    pub retained_output_bytes: usize,
    /// Maximum logical retained/current capture bytes plus charged current
    /// search scratch.
    pub combined_peak_bytes: usize,
    /// Complete owner-local terminal success receipt.
    pub session_receipt: CaptureIterationAttemptReceipt,
}

/// Checked capture-iteration failure retaining exact source and limit identity.
#[derive(Debug)]
pub struct CaptureIterationError {
    /// Complete attempted operation identity.
    pub identity: Box<CaptureIterationIdentity>,
    /// Persistent-history search or aggregate resource failure.
    pub source: EngineSearchError,
    /// Complete owner-local terminal failure receipt. The receipt is boxed so
    /// ordinary text-wrapper error paths do not inherit its inline size.
    pub session_receipt: Box<CaptureIterationAttemptReceipt>,
}

impl CaptureIterationIdentity {
    fn closes_session_seal(&self) -> bool {
        let route = self.session_seal.route_identity();
        self.syntax == route.syntax
            && self.capture_profile == route.capture_profile
            && self.plan == route.plan
            && self.search == self.session_seal.search()
            && self.build_limits == route.build_limits
            && self.run_limits == self.session_seal.run_limits()
    }
}

impl CaptureIterationReport {
    /// Whether this success retains one immutable construction owner and a
    /// complete capture-array session receipt with cumulative A≤P.
    #[must_use]
    pub fn has_closed_session_attempt(&self) -> bool {
        let actual = self.session_receipt.actual;
        self.identity.closes_session_seal()
            && self.session_receipt.terminal == crate::CaptureIterationTerminal::Success
            && self.session_receipt.closes(&self.identity.session_seal)
            && self.captures.len() == actual.results
            && self.searches == actual.searches
            && self.total_slot_copies == actual.total_slot_copies
            && self.capture_events == actual.capture_events
            && self.peak_scratch_bytes == actual.scratch_bytes
            && self.retained_output_bytes == actual.retained_output_bytes
            && self.combined_peak_bytes == actual.combined_peak_bytes
    }
}

impl CaptureIterationError {
    /// Whether this failure retains one immutable construction owner and a
    /// complete capture-array session receipt with cumulative A≤P.
    #[must_use]
    pub fn has_closed_session_attempt(&self) -> bool {
        self.identity.closes_session_seal()
            && self.session_receipt.terminal == crate::CaptureIterationTerminal::Failure
            && self.session_receipt.closes(&self.identity.session_seal)
    }
}

/// Construction evidence for the exact-HIR Rust text capture slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableTextCaptureBuildReport {
    /// Public Rust text profile proved before capture construction.
    pub profile: CompatibilityProfile,
    /// Bounded public `RustText` parse.
    pub text_syntax: ParseSummary,
    /// Independently parsed same-option `RustBytes` proof HIR.
    pub bytes_syntax: ParseSummary,
    /// Construction report for the byte-stable tagged executor.
    pub capture: CaptureBuildReport,
}

/// Failure to prove or construct the Rust text capture slice.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextCaptureBuildError {
    /// Public `RustText` parsing rejected the pattern.
    TextSyntax(ParseError),
    /// Independent same-option `RustBytes` proof parsing rejected the pattern.
    BytesProofSyntax(ParseError),
    /// The two capture-preserving HIRs are not exactly equal.
    ProfileHirMismatch,
    /// The common HIR does not guarantee valid UTF-8 for every non-empty
    /// whole match.
    InvalidUtf8Hir,
    /// The exact-HIR tagged executor refused construction.
    Capture(CaptureBuildError),
    /// An impossible profile state was observed.
    InternalInvariant(&'static str),
}

impl fmt::Display for PortableTextCaptureBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextSyntax(error) => {
                write!(formatter, "Rust text capture syntax failed: {error}")
            }
            Self::BytesProofSyntax(error) => {
                write!(formatter, "Rust bytes capture proof syntax failed: {error}")
            }
            Self::ProfileHirMismatch => {
                formatter.write_str("Rust text and byte capture HIRs differ")
            }
            Self::InvalidUtf8Hir => {
                formatter.write_str("capture HIR does not guarantee valid UTF-8 matches")
            }
            Self::Capture(error) => write!(formatter, "capture construction failed: {error}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "text capture invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for PortableTextCaptureBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TextSyntax(error) | Self::BytesProofSyntax(error) => Some(error),
            Self::Capture(error) => Some(error),
            Self::ProfileHirMismatch | Self::InvalidUtf8Hir | Self::InternalInvariant(_) => None,
        }
    }
}

/// Text-specific capture iteration failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextCaptureIterationError {
    /// The bounded tagged executor refused execution.
    Capture(CaptureIterationError),
    /// The tagged executor published a record without participating group
    /// zero.
    MissingOverall { match_index: usize },
    /// A retained match or group span violated the proved UTF-8 boundary
    /// contract.
    InvalidUtf8Capture {
        match_index: usize,
        group_index: usize,
        start: usize,
        end: usize,
    },
    /// The requested search window is not a valid UTF-8 substring boundary.
    InvalidUtf8Window {
        /// Inclusive search start.
        start: usize,
        /// Exclusive search end.
        end: usize,
    },
}

/// Failure from one bounded Rust text capture search.
#[derive(Debug)]
#[non_exhaustive]
pub enum PortableTextCaptureSearchError {
    /// The selected bounded capture executor refused the search.
    Capture(EngineSearchError),
    /// A selected capture record did not contain its whole-match slot.
    MissingOverall,
    /// A selected record's vector position and declared group index differed.
    InvalidCaptureIndex {
        /// Position in the selected record.
        expected: usize,
        /// Index declared by the capture engine.
        actual: u32,
    },
    /// A selected group span was not a valid slice of the UTF-8 haystack.
    InvalidUtf8Capture {
        /// Numeric capture slot.
        group_index: usize,
        /// Inclusive byte offset.
        start: usize,
        /// Exclusive byte offset.
        end: usize,
    },
}

impl fmt::Display for PortableTextCaptureSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(error) => error.fmt(formatter),
            Self::MissingOverall => formatter.write_str("text capture match lacks group zero"),
            Self::InvalidCaptureIndex { expected, actual } => write!(
                formatter,
                "text capture slot {expected} declared group index {actual}",
            ),
            Self::InvalidUtf8Capture {
                group_index,
                start,
                end,
            } => write!(
                formatter,
                "text capture group {group_index} has non-boundary span [{start}, {end})",
            ),
        }
    }
}

impl std::error::Error for PortableTextCaptureSearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capture(error) => Some(error),
            Self::MissingOverall
            | Self::InvalidCaptureIndex { .. }
            | Self::InvalidUtf8Capture { .. } => None,
        }
    }
}

/// One borrowed UTF-8 capture match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableTextCaptureMatch<'h> {
    haystack: &'h str,
    span: EngineSpan,
}

impl<'h> PortableTextCaptureMatch<'h> {
    /// Inclusive byte offset in the original haystack.
    #[must_use]
    pub const fn start(self) -> usize {
        self.span.start
    }

    /// Exclusive byte offset in the original haystack.
    #[must_use]
    pub const fn end(self) -> usize {
        self.span.end
    }

    /// Borrow the matched text with the haystack's lifetime.
    #[must_use]
    pub fn as_str(self) -> &'h str {
        &self.haystack[self.span.start..self.span.end]
    }
}

/// Borrowed capture groups from one selected Rust text match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableTextCaptures<'h> {
    haystack: &'h str,
    record: CaptureRecord,
}

impl<'h> PortableTextCaptures<'h> {
    /// Number of capture slots, including group zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.record.groups.len()
    }

    /// Capture records always include group zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.record.groups.is_empty()
    }

    /// Return one participating capture by numeric index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<PortableTextCaptureMatch<'h>> {
        let group = self.record.groups.get(index)?;
        let span = group.span?;
        Some(PortableTextCaptureMatch {
            haystack: self.haystack,
            span,
        })
    }

    /// Return one participating capture by name.
    #[must_use]
    pub fn name(&self, name: &str) -> Option<PortableTextCaptureMatch<'h>> {
        let group = self
            .record
            .groups
            .iter()
            .find(|group| group.name.as_deref() == Some(name))?;
        let span = group.span?;
        Some(PortableTextCaptureMatch {
            haystack: self.haystack,
            span,
        })
    }
}

impl core::ops::Index<usize> for PortableTextCaptures<'_> {
    type Output = str;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index)
            .unwrap_or_else(|| panic!("capture group {index} did not participate"))
            .as_str()
    }
}

impl core::ops::Index<&str> for PortableTextCaptures<'_> {
    type Output = str;

    fn index(&self, name: &str) -> &Self::Output {
        self.name(name)
            .unwrap_or_else(|| {
                panic!("capture group {name:?} does not exist or did not participate")
            })
            .as_str()
    }
}

impl fmt::Display for PortableTextCaptureIterationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(error) => error.fmt(formatter),
            Self::MissingOverall { match_index } => {
                write!(
                    formatter,
                    "text capture match {match_index} lacks group zero"
                )
            }
            Self::InvalidUtf8Capture {
                match_index,
                group_index,
                start,
                end,
            } => write!(
                formatter,
                "text capture match {match_index} group {group_index} has non-boundary span [{start}, {end})",
            ),
            Self::InvalidUtf8Window { start, end } => write!(
                formatter,
                "text capture window [{start}, {end}) is not a valid UTF-8 substring",
            ),
        }
    }
}

impl std::error::Error for PortableTextCaptureIterationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capture(error) => Some(error),
            Self::MissingOverall { .. }
            | Self::InvalidUtf8Capture { .. }
            | Self::InvalidUtf8Window { .. } => None,
        }
    }
}

/// Builder for the exact-HIR Rust text capture subset.
#[derive(Clone, Debug)]
pub struct PortableTextCaptureBuilder {
    pattern: String,
    profile: RustProfile,
    limits: CaptureBuildLimits,
}

impl PortableTextCaptureBuilder {
    /// Start from pinned Rust text defaults.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: CaptureBuildLimits::default(),
        }
    }

    /// Replace the complete public Rust text profile.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Replace every checked capture construction limit.
    #[must_use]
    pub const fn limits(mut self, limits: CaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Prove exact capture-preserving HIR equivalence and build the tagged
    /// byte-stable executor.
    pub fn build(self) -> Result<PortableTextCaptureRegex, PortableTextCaptureBuildError> {
        let text_profile = CompatibilityProfile::RustText(self.profile.clone());
        let text = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(self.pattern.clone(), text_profile.clone())
                .with_admission(self.limits.admission)
                .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(PortableTextCaptureBuildError::TextSyntax)?;
        let text_syntax = text.summary.clone();
        let CanonicalPattern::Rust(text_pattern) = text.pattern else {
            return Err(PortableTextCaptureBuildError::InternalInvariant(
                "RustText parse produced non-Rust syntax",
            ));
        };

        let bytes_profile = self.profile.clone();
        let bytes = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(
                self.pattern.clone(),
                CompatibilityProfile::RustBytes(bytes_profile.clone()),
            )
            .with_admission(self.limits.admission)
            .with_safety_envelope(self.limits.syntax_safety),
        )
        .map_err(PortableTextCaptureBuildError::BytesProofSyntax)?;
        let bytes_syntax = bytes.summary.clone();
        let CanonicalPattern::Rust(bytes_pattern) = bytes.pattern else {
            return Err(PortableTextCaptureBuildError::InternalInvariant(
                "RustBytes proof parse produced non-Rust syntax",
            ));
        };
        if text_pattern.hir != bytes_pattern.hir {
            return Err(PortableTextCaptureBuildError::ProfileHirMismatch);
        }
        if !text_pattern.hir.properties().is_utf8() {
            return Err(PortableTextCaptureBuildError::InvalidUtf8Hir);
        }
        let inner = CaptureBuilder::new(self.pattern)
            .profile(bytes_profile)
            .limits(self.limits)
            .build()
            .map_err(PortableTextCaptureBuildError::Capture)?;
        let report = PortableTextCaptureBuildReport {
            profile: text_profile,
            text_syntax,
            bytes_syntax,
            capture: inner.build_report().clone(),
        };
        Ok(PortableTextCaptureRegex { inner, report })
    }
}

/// Immutable exact-HIR Rust text capture matcher.
#[derive(Clone, Debug)]
pub struct PortableTextCaptureRegex {
    inner: CaptureRegex,
    report: PortableTextCaptureBuildReport,
}

impl PortableTextCaptureRegex {
    /// Text/bytes equivalence and tagged construction evidence.
    #[must_use]
    pub const fn build_report(&self) -> &PortableTextCaptureBuildReport {
        &self.report
    }

    /// Return the selected leftmost-first capture record while borrowing every
    /// participating group from the original UTF-8 haystack.
    ///
    /// # Errors
    ///
    /// Returns [`PortableTextCaptureSearchError::Capture`] when the bounded
    /// capture search is refused. Any violation of the construction-time
    /// UTF-8 proof is reported as a typed invariant error.
    pub fn captures<'h>(
        &self,
        haystack: &'h str,
        limits: EngineSearchLimits,
    ) -> Result<
        (Option<PortableTextCaptures<'h>>, EngineSearchAccounting),
        PortableTextCaptureSearchError,
    > {
        self.captures_with_config(haystack, CaptureSearchConfig::LEFTMOST, limits)
    }

    /// Return one capture record under explicit match-end, match-priority and
    /// start-injection policies.
    pub fn captures_with_config<'h>(
        &self,
        haystack: &'h str,
        config: CaptureSearchConfig,
        limits: EngineSearchLimits,
    ) -> Result<
        (Option<PortableTextCaptures<'h>>, EngineSearchAccounting),
        PortableTextCaptureSearchError,
    > {
        self.captures_window_with_config(haystack, Window::all(haystack.as_bytes()), config, limits)
    }

    /// Return the first text capture record inside `window` under an explicit
    /// match-end selection and start-injection policy.
    pub fn captures_window_with_config<'h>(
        &self,
        haystack: &'h str,
        window: Window,
        config: CaptureSearchConfig,
        limits: EngineSearchLimits,
    ) -> Result<
        (Option<PortableTextCaptures<'h>>, EngineSearchAccounting),
        PortableTextCaptureSearchError,
    > {
        if !text_capture_window_is_valid(haystack, window) {
            return Err(PortableTextCaptureSearchError::Capture(
                EngineSearchError::InvalidWindow,
            ));
        }
        let outcome = self
            .inner
            .captures_window_with_config(haystack.as_bytes(), window, config, limits)
            .map_err(PortableTextCaptureSearchError::Capture)?;
        portable_text_capture_outcome(haystack, outcome)
    }

    /// Query whether `span` is an exact UTF-8 match inside `window`, returning
    /// its prioritized captures when it is. An ordinary non-match is a
    /// successful outcome with no capture record.
    pub fn captures_exact_window<'h>(
        &self,
        haystack: &'h str,
        window: Window,
        span: EngineSpan,
        limits: EngineSearchLimits,
    ) -> Result<
        (Option<PortableTextCaptures<'h>>, EngineSearchAccounting),
        PortableTextCaptureSearchError,
    > {
        if !text_capture_window_is_valid(haystack, window)
            || span.start > span.end
            || span.start < window.start
            || span.end > window.end
            || !haystack.is_char_boundary(span.start)
            || !haystack.is_char_boundary(span.end)
        {
            return Err(PortableTextCaptureSearchError::Capture(
                EngineSearchError::InvalidWindow,
            ));
        }
        let outcome = self
            .inner
            .captures_exact_window(haystack.as_bytes(), window, span, limits)
            .map_err(PortableTextCaptureSearchError::Capture)?;
        portable_text_capture_outcome(haystack, outcome)
    }

    /// Materialize complete text captures while removing only empty records
    /// that fall inside a UTF-8 scalar. Non-empty matches and every retained
    /// group span must satisfy the independently proved boundary contract.
    pub fn captures_iter(
        &self,
        haystack: &str,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, PortableTextCaptureIterationError> {
        self.captures_iter_window_with_config(
            haystack,
            Window::all(haystack.as_bytes()),
            CaptureSearchConfig::LEFTMOST,
            limits,
        )
    }

    /// Materialize complete text captures whose whole-match spans are
    /// constrained to `window`, while assertions retain original-haystack
    /// context.
    pub fn captures_iter_window(
        &self,
        haystack: &str,
        window: Window,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, PortableTextCaptureIterationError> {
        self.captures_iter_window_with_config(
            haystack,
            window,
            CaptureSearchConfig::LEFTMOST,
            limits,
        )
    }

    /// Materialize complete text captures under explicit match-end,
    /// match-priority and start-injection policies.
    pub fn captures_iter_window_with_config(
        &self,
        haystack: &str,
        window: Window,
        config: CaptureSearchConfig,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, PortableTextCaptureIterationError> {
        if window.start > window.end
            || window.end > haystack.len()
            || !haystack.is_char_boundary(window.start)
            || !haystack.is_char_boundary(window.end)
        {
            return Err(PortableTextCaptureIterationError::InvalidUtf8Window {
                start: window.start,
                end: window.end,
            });
        }
        let mut report = self
            .inner
            .captures_iter_window_with_config(haystack.as_bytes(), window, config, limits)
            .map_err(PortableTextCaptureIterationError::Capture)?;
        for (match_index, record) in report.captures.iter().enumerate() {
            if record.overall().is_none() {
                return Err(PortableTextCaptureIterationError::MissingOverall { match_index });
            }
        }
        report.captures.retain(|record| {
            record
                .overall()
                .is_some_and(|span| span.start != span.end || haystack.is_char_boundary(span.start))
        });
        for (match_index, record) in report.captures.iter().enumerate() {
            for (group_index, group) in record.groups.iter().enumerate() {
                let Some(span) = group.span else {
                    continue;
                };
                if !haystack.is_char_boundary(span.start) || !haystack.is_char_boundary(span.end) {
                    return Err(PortableTextCaptureIterationError::InvalidUtf8Capture {
                        match_index,
                        group_index,
                        start: span.start,
                        end: span.end,
                    });
                }
            }
        }
        Ok(report)
    }
}

fn text_capture_window_is_valid(haystack: &str, window: Window) -> bool {
    window.start <= window.end
        && window.end <= haystack.len()
        && haystack.is_char_boundary(window.start)
        && haystack.is_char_boundary(window.end)
}

fn portable_text_capture_outcome(
    haystack: &str,
    outcome: EngineSearchOutcome,
) -> Result<
    (Option<PortableTextCaptures<'_>>, EngineSearchAccounting),
    PortableTextCaptureSearchError,
> {
    let accounting = outcome.report;
    let Some(record) = outcome.captures else {
        return Ok((None, accounting));
    };
    if record.overall().is_none() {
        return Err(PortableTextCaptureSearchError::MissingOverall);
    }
    for (group_index, group) in record.groups.iter().enumerate() {
        if usize::try_from(group.index) != Ok(group_index) {
            return Err(PortableTextCaptureSearchError::InvalidCaptureIndex {
                expected: group_index,
                actual: group.index,
            });
        }
        let Some(span) = group.span else {
            continue;
        };
        if span.start > span.end
            || span.end > haystack.len()
            || !haystack.is_char_boundary(span.start)
            || !haystack.is_char_boundary(span.end)
        {
            return Err(PortableTextCaptureSearchError::InvalidUtf8Capture {
                group_index,
                start: span.start,
                end: span.end,
            });
        }
    }
    Ok((Some(PortableTextCaptures { haystack, record }), accounting))
}

impl fmt::Display for CaptureIterationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "capture iteration failed: {}", self.source)
    }
}

impl std::error::Error for CaptureIterationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn capture_iteration_failure(
    identity: &CaptureIterationIdentity,
    source: EngineSearchError,
    prospective: Option<CaptureIterationProspective>,
    actual: CaptureIterationActual,
) -> CaptureIterationError {
    CaptureIterationError {
        identity: Box::new(identity.clone()),
        source,
        session_receipt: Box::new(CaptureIterationAttemptReceipt::failure(prospective, actual)),
    }
}

fn capture_iteration_exact_add(
    current: usize,
    increment: usize,
    resource: EngineResource,
    limit: usize,
) -> Result<usize, EngineSearchError> {
    let required = current
        .checked_add(increment)
        .ok_or(EngineSearchError::BoundOverflow(resource))?;
    if required > limit {
        return Err(EngineSearchError::Resource {
            kind: resource,
            required,
            limit,
        });
    }
    Ok(required)
}

fn capture_iteration_search_fits(
    prospective: HistorySearchProspective,
    actual: &EngineSearchAccounting,
) -> bool {
    actual.candidate == EngineCandidateKind::PersistentHistory
        && actual.state_visits <= prospective.state_visits
        && actual.slot_copies == 0
        && actual.history_nodes <= prospective.history_nodes
        && actual.history_walk <= prospective.history_walk
        && actual.bytes_examined <= prospective.bytes_examined
        && actual.starts_injected <= prospective.starts_injected
        && actual.peak_threads <= prospective.peak_threads
        && actual.admitted_scratch_bytes <= prospective.scratch_bytes
}

fn optional_required_literal_refusal(error: &CaptureRequiredLiteralBuildError) -> bool {
    match error {
        CaptureRequiredLiteralBuildError::Resource { .. }
        | CaptureRequiredLiteralBuildError::Allocation { .. } => true,
        CaptureRequiredLiteralBuildError::LiteralSet(source) => matches!(
            source,
            LiteralSetError::PatternLimit { .. }
                | LiteralSetError::PatternBytesLimit { .. }
                | LiteralSetError::BuildWorkLimit { .. }
                | LiteralSetError::BuildBytesLimit { .. }
                | LiteralSetError::PersistentBytesLimit { .. }
        ),
        CaptureRequiredLiteralBuildError::Overflow(_)
        | CaptureRequiredLiteralBuildError::InternalInvariant(_) => false,
    }
}

#[derive(Debug)]
struct OptionalOnePassCaptureBuild {
    plan: Option<OnePassCapturePlan>,
    compile_work: usize,
}

const CAPTURE_ITERATION_ASCII_FOLD_WORDS: [u64; 4] = [
    0,
    (((1_u64 << 26) - 1) << 1) | (((1_u64 << 26) - 1) << 33),
    0,
    0,
];

fn project_capture_iteration_start_classifier(
    proof: FirstByteProof,
    accounting: &mut CaptureHirAccounting,
    max_hir_work: usize,
) -> CaptureIterationStartClassifierReceipt {
    let work_before = accounting.work;
    let Some(work_after) = work_before
        .checked_add(CAPTURE_ITERATION_START_CLASSIFIER_WORK)
        .filter(|&work| work <= max_hir_work)
    else {
        return CaptureIterationStartClassifierReceipt::new(
            work_before,
            0,
            work_before,
            CaptureIterationStartClassifierOutcome::NotAttempted,
        );
    };

    // This is the last HIR-budget transaction. The candidate and its exact
    // four-word image are predetermined, so the fixed ledger is one attempt
    // plus four comparisons with no scan, inference or allocation.
    accounting.work = work_after;
    let outcome = if proof.equals_nonnullable_words(CAPTURE_ITERATION_ASCII_FOLD_WORDS) {
        CaptureIterationStartClassifierOutcome::Selected(CAPTURE_ITERATION_ASCII_FOLD_RANGE)
    } else {
        CaptureIterationStartClassifierOutcome::AttemptedIneligible
    };
    CaptureIterationStartClassifierReceipt::new(
        work_before,
        CAPTURE_ITERATION_START_CLASSIFIER_WORK,
        work_after,
        outcome,
    )
}

fn build_optional_onepass_capture(
    program: Arc<Program>,
    engine_report: &EngineBuildReport,
    engine_limits: EngineBuildLimits,
) -> Result<OptionalOnePassCaptureBuild, CaptureBuildError> {
    // The sidecar is optional and co-live with the complete tagged program.
    // Spend only the unused portions of the incumbent engine ceilings so
    // enabling it cannot silently double the state, work, or immutable-byte
    // envelope associated with `CaptureBuildLimits::engine`.
    let Some(max_states) = engine_limits.max_states.checked_sub(engine_report.states) else {
        return Ok(OptionalOnePassCaptureBuild {
            plan: None,
            compile_work: 0,
        });
    };
    let Some(max_compile_work) = engine_limits
        .max_compile_work
        .checked_sub(engine_report.compile_work)
    else {
        return Ok(OptionalOnePassCaptureBuild {
            plan: None,
            compile_work: 0,
        });
    };
    let Some(max_program_bytes) = engine_limits
        .max_program_bytes
        .checked_sub(engine_report.program_bytes)
    else {
        return Ok(OptionalOnePassCaptureBuild {
            plan: None,
            compile_work: 0,
        });
    };
    let limits = OnePassCaptureBuildLimits {
        max_states,
        max_compile_work,
        max_program_bytes,
    };
    match OnePassCapturePlan::try_from_program_accounted(program, limits) {
        Ok(plan) => Ok(OptionalOnePassCaptureBuild {
            compile_work: plan.build_report().compile_work,
            plan: Some(plan),
        }),
        Err(failure)
            if matches!(
                failure.source,
                OnePassCaptureBuildError::Resource { .. }
                    | OnePassCaptureBuildError::Allocation(_)
                    | OnePassCaptureBuildError::NotOnePass(_)
            ) =>
        {
            Ok(OptionalOnePassCaptureBuild {
                plan: None,
                compile_work: failure.compile_work,
            })
        }
        Err(failure) if matches!(failure.source, OnePassCaptureBuildError::Overflow(_)) => {
            Err(CaptureBuildError::InternalInvariant(
                "one-pass capture construction accounting overflowed",
            ))
        }
        Err(failure) => {
            let OnePassCaptureBuildError::InvalidProgram(detail) = failure.source else {
                return Err(CaptureBuildError::InternalInvariant(
                    "one-pass capture construction returned an unknown terminal",
                ));
            };
            Err(CaptureBuildError::InternalInvariant(detail))
        }
    }
}

fn onepass_capture_admits_exact(
    plan: &OnePassCapturePlan,
    span: EngineSpan,
    limits: EngineSearchLimits,
) -> bool {
    plan.exact_replay_work_is_admitted(span, limits)
}

#[derive(Debug)]
struct CapturePrefixClassParticipationPlan {
    engine: CapturePrefixClassParticipationEngine,
    schema: PrefixClassUniformParticipationSchema,
    participating_capture_indices: [u32; 2],
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "both direct owners remain allocation-free and retain their separately accounted inline kernel artifacts"
)]
enum CapturePrefixClassParticipationEngine {
    Established(PrefixClassAlternationPlan),
    Dispatched(DispatchedPrefixClassAlternationPlan),
}

impl CapturePrefixClassParticipationEngine {
    fn uniform_participation_build_accounting(
        &self,
    ) -> PrefixClassUniformParticipationBuildAccounting {
        match self {
            Self::Established(engine) => engine.uniform_participation_build_accounting(),
            Self::Dispatched(engine) => engine.uniform_participation_build_accounting(),
        }
    }

    const fn uniform_participation_identity(
        &self,
        schema: PrefixClassUniformParticipationSchema,
    ) -> PrefixClassUniformParticipationIdentity {
        match self {
            Self::Established(engine) => engine.uniform_participation_identity(schema),
            Self::Dispatched(engine) => engine.uniform_participation_identity(schema),
        }
    }

    fn uniform_participation_attempt_receipt(
        &self,
        haystack_bytes: usize,
        schema: PrefixClassUniformParticipationSchema,
        limits: PrefixClassUniformParticipationLimits,
    ) -> PrefixClassUniformParticipationAttemptReceipt {
        match self {
            Self::Established(engine) => {
                engine.uniform_participation_attempt_receipt(haystack_bytes, schema, limits)
            }
            Self::Dispatched(engine) => {
                engine.uniform_participation_attempt_receipt(haystack_bytes, schema, limits)
            }
        }
    }

    fn uniform_participation_prospective(
        &self,
        haystack_len: usize,
        schema: PrefixClassUniformParticipationSchema,
    ) -> Result<PrefixClassUniformParticipationProspective, PrefixClassUniformParticipationError>
    {
        match self {
            Self::Established(engine) => {
                engine.uniform_participation_prospective(haystack_len, schema)
            }
            Self::Dispatched(engine) => {
                engine.uniform_participation_prospective(haystack_len, schema)
            }
        }
    }

    fn enforce_uniform_participation(
        &self,
        prospective: PrefixClassUniformParticipationProspective,
        limits: PrefixClassUniformParticipationLimits,
    ) -> Result<(), PrefixClassUniformParticipationError> {
        match self {
            Self::Established(engine) => engine.enforce_uniform_participation(prospective, limits),
            Self::Dispatched(engine) => engine.enforce_uniform_participation(prospective, limits),
        }
    }

    #[allow(
        clippy::result_large_err,
        reason = "the fixed-layout terminal receipt deliberately preserves complete direct P/A without allocating"
    )]
    fn count_uniform_participation_attempt(
        &self,
        haystack: &[u8],
        schema: PrefixClassUniformParticipationSchema,
        limits: PrefixClassUniformParticipationLimits,
    ) -> Result<PrefixClassUniformParticipationAttempt, PrefixClassUniformParticipationAttemptError>
    {
        match self {
            Self::Established(engine) => {
                engine.count_uniform_participation_attempt(haystack, schema, limits)
            }
            Self::Dispatched(engine) => {
                engine.count_uniform_participation_attempt(haystack, schema, limits)
            }
        }
    }
}

impl CapturePrefixClassParticipationPlan {
    fn identity(&self) -> CapturePrefixClassParticipationIdentity {
        CapturePrefixClassParticipationIdentity {
            kernel: self.engine.uniform_participation_identity(self.schema),
            participating_capture_indices: self.participating_capture_indices,
            declared_prepublication_fallback: CapturePlanKind::LinearSelectorUniformParticipation,
        }
    }
}

struct CapturePrefixClassParticipationBuild {
    plan: Option<Arc<CapturePrefixClassParticipationPlan>>,
    planner_work: usize,
}

fn optional_prefix_class_build_refusal(error: &PrefixClassUniformParticipationBuildError) -> bool {
    match error {
        PrefixClassUniformParticipationBuildError::Kernel(error) => matches!(
            error,
            PrefixClassAlternationBuildError::EmptyPrefix { .. }
                | PrefixClassAlternationBuildError::SelfOverlappingPrefix { .. }
                | PrefixClassAlternationBuildError::EmptyClass { .. }
                | PrefixClassAlternationBuildError::NonCanonicalClass { .. }
                | PrefixClassAlternationBuildError::RunScannerDispatchUnavailable
                | PrefixClassAlternationBuildError::NonAsciiRunScannerClass { .. }
                | PrefixClassAlternationBuildError::RunScannerAllocationFailed { .. }
                | PrefixClassAlternationBuildError::ShapeLimit { .. }
                | PrefixClassAlternationBuildError::WorkLimit { .. }
                | PrefixClassAlternationBuildError::ScratchLimit { .. }
                | PrefixClassAlternationBuildError::PersistentLimit { .. }
                | PrefixClassAlternationBuildError::PeakLimit { .. }
        ),
        PrefixClassUniformParticipationBuildError::AllocationsLimit { .. }
        | PrefixClassUniformParticipationBuildError::CopiedPrefixBytesLimit { .. }
        | PrefixClassUniformParticipationBuildError::FinderPreprocessInputBytesLimit { .. }
        | PrefixClassUniformParticipationBuildError::InitializedBitmapBytesLimit { .. }
        | PrefixClassUniformParticipationBuildError::InitializedRunScannerBytesLimit { .. }
        | PrefixClassUniformParticipationBuildError::RetainedCapacityBytesLimit { .. } => true,
        _ => false,
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "direct eligibility and fallible construction retain all canonical-HIR inputs and accounting in one transactional helper"
)]
fn build_prefix_class_participation(
    simd_dispatch: SimdDispatchContext,
    hir: &Hir,
    syntax: &ParseSummary,
    unicode: bool,
    case_insensitive: bool,
    selector_has_terminal_frontier: bool,
    uniform_participating_captures: Option<usize>,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<CapturePrefixClassParticipationBuild, CaptureBuildError> {
    let ineligible = || CapturePrefixClassParticipationBuild {
        plan: None,
        planner_work: 0,
    };
    if unicode
        || case_insensitive
        || selector_has_terminal_frontier
        || limits.required_literal.is_some()
        || uniform_participating_captures != Some(1)
        || syntax.captures != 2
    {
        return Ok(ineligible());
    }
    let Some(selection_work) = prefix_class_selection_work(syntax) else {
        return Ok(ineligible());
    };
    let remaining_hir_work =
        limits
            .max_hir_work
            .checked_sub(accounting.work)
            .ok_or(CaptureBuildError::HirResource {
                resource: "work",
                required: accounting.work,
                limit: limits.max_hir_work,
            })?;
    if selection_work > limits.max_prefix_class_participation_planner_work
        || selection_work > remaining_hir_work
    {
        return Ok(ineligible());
    }
    let inspection =
        inspect_prefix_class_alternation(hir, selection_work).map_err(|error| match error {
            PrefixClassInspectionError::WorkLimit { needed, limit, .. } => {
                CaptureBuildError::HirResource {
                    resource: "prefix/class participation work",
                    required: needed,
                    limit,
                }
            }
            PrefixClassInspectionError::Overflow { .. } => CaptureBuildError::InternalInvariant(
                "prefix/class participation inspection overflowed",
            ),
        })?;
    match inspection {
        PrefixClassInspection::PackedBoundedPrefixLiterals { .. } => unreachable!(
            "capture prefix/class inspection does not request bounded-prefix alternatives"
        ),
        PrefixClassInspection::Ineligible { work } => {
            charge_hir(accounting, work, limits.max_hir_work)?;
            Ok(CapturePrefixClassParticipationBuild {
                plan: None,
                planner_work: work,
            })
        }
        PrefixClassInspection::Eligible {
            prefixes,
            classes,
            work,
            hir_nodes,
            captures,
            uniform_participating_capture_indices,
        } => {
            charge_hir(accounting, work, limits.max_hir_work)?;
            let expected_nodes = usize::try_from(syntax.hir_nodes).map_err(|_| {
                CaptureBuildError::InternalInvariant("syntax HIR nodes do not fit usize")
            })?;
            let expected_captures = usize::try_from(syntax.captures).map_err(|_| {
                CaptureBuildError::InternalInvariant("syntax captures do not fit usize")
            })?;
            if hir_nodes != expected_nodes || captures != expected_captures {
                return Err(CaptureBuildError::InternalInvariant(
                    "syntax summary differs from shared prefix/class inspection",
                ));
            }
            let Some(participating_capture_indices) = uniform_participating_capture_indices else {
                return Ok(CapturePrefixClassParticipationBuild {
                    plan: None,
                    planner_work: work,
                });
            };
            let use_run_scanners = PrefixClassAlternationPlan::run_scanners_usable(simd_dispatch)
                && classes
                    .iter()
                    .all(|class| class.ranges().iter().all(|range| range.end() <= 0x7f));
            let engine = if use_run_scanners {
                match DispatchedPrefixClassAlternationPlan::build_uniform_participation_with_dispatch(
                    simd_dispatch,
                    prefixes,
                    [
                        classes[0]
                            .ranges()
                            .iter()
                            .copied()
                            .map(capture_class_bytes_range_tuple),
                        classes[1]
                            .ranges()
                            .iter()
                            .copied()
                            .map(capture_class_bytes_range_tuple),
                    ],
                    limits.prefix_class_participation,
                ) {
                    Ok(engine) => CapturePrefixClassParticipationEngine::Dispatched(engine),
                    Err(error) if optional_prefix_class_build_refusal(&error) => {
                        return Ok(CapturePrefixClassParticipationBuild {
                            plan: None,
                            planner_work: work,
                        });
                    }
                    Err(error) => {
                        return Err(CaptureBuildError::PrefixClassParticipation(error));
                    }
                }
            } else {
                match PrefixClassAlternationPlan::build_uniform_participation(
                    prefixes,
                    [
                        classes[0]
                            .ranges()
                            .iter()
                            .copied()
                            .map(capture_class_bytes_range_tuple),
                        classes[1]
                            .ranges()
                            .iter()
                            .copied()
                            .map(capture_class_bytes_range_tuple),
                    ],
                    limits.prefix_class_participation,
                ) {
                    Ok(engine) => CapturePrefixClassParticipationEngine::Established(engine),
                    Err(error) if optional_prefix_class_build_refusal(&error) => {
                        return Ok(CapturePrefixClassParticipationBuild {
                            plan: None,
                            planner_work: work,
                        });
                    }
                    Err(error) => {
                        return Err(CaptureBuildError::PrefixClassParticipation(error));
                    }
                }
            };
            Ok(CapturePrefixClassParticipationBuild {
                plan: Some(Arc::new(CapturePrefixClassParticipationPlan {
                    engine,
                    schema: PrefixClassUniformParticipationSchema {
                        participating_with_overall: 2,
                        capture_schema_slots: 3,
                    },
                    participating_capture_indices,
                })),
                planner_work: work,
            })
        }
    }
}

fn capture_class_bytes_range_tuple(range: ClassBytesRange) -> (u8, u8) {
    (range.start(), range.end())
}

/// Builder for a capture-preserving plan with persistent-history authority and
/// an optional construction-complete one-pass exact-replay sidecar.
#[derive(Clone, Debug)]
pub struct CaptureBuilder {
    pattern: String,
    profile: RustProfile,
    limits: CaptureBuildLimits,
    build_onepass_capture: bool,
}

impl CaptureBuilder {
    /// Start from the pinned Rust byte profile. Unicode defaults to enabled;
    /// scalar classes lower to compact canonical-scalar transitions with
    /// checked bounded UTF-8 decoding.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            profile: RustProfile::default(),
            limits: CaptureBuildLimits::default(),
            build_onepass_capture: true,
        }
    }

    /// Select the complete Rust constructor/profile identity.
    #[must_use]
    pub fn profile(mut self, profile: RustProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Select Unicode syntax mode.
    #[must_use]
    pub fn unicode(mut self, enabled: bool) -> Self {
        self.profile.options.unicode = enabled;
        self
    }

    /// Select case-insensitive syntax lowering.
    #[must_use]
    pub fn case_insensitive(mut self, enabled: bool) -> Self {
        self.profile.options.case_insensitive = enabled;
        self
    }

    /// Replace all checked construction limits.
    #[must_use]
    pub const fn limits(mut self, limits: CaptureBuildLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Omit the exact-replay sidecar for an enclosing constructor that never
    /// invokes capture-valued exact replay.
    #[must_use]
    pub(crate) const fn without_onepass_capture(mut self) -> Self {
        self.build_onepass_capture = false;
        self
    }

    /// Build only the conservative required-literal sidecar.
    ///
    /// This performs the same pinned parse and bounded any-required-literal
    /// proof used by [`Self::build`], but it does not lower or allocate the
    /// capture selector, tagged-history program, or capture-operation seals.
    /// `Ok(None)` means either that no sound effective literal antichain
    /// exists or that the optional sidecar refused a caller resource limit;
    /// the caller may select its already-built semantic authority before
    /// source access. Arithmetic and invariant failures remain terminal.
    ///
    /// # Errors
    ///
    /// Returns a syntax error for an invalid pattern, or a terminal
    /// required-literal/invariant failure. Optional construction-resource
    /// refusals are reported as `Ok(None)`.
    pub fn build_required_literal_plan(
        self,
    ) -> Result<Option<CaptureRequiredLiteralPlan>, CaptureBuildError> {
        let limits = self.limits;
        let Some(mut required_limits) = limits.required_literal else {
            return Ok(None);
        };
        let profile = CompatibilityProfile::RustBytes(self.profile);
        let parsed = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(self.pattern, profile)
                .with_admission(limits.admission)
                .with_safety_envelope(limits.syntax_safety),
        )
        .map_err(CaptureBuildError::Syntax)?;
        let syntax_key = Arc::new(parsed.key);
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(CaptureBuildError::InternalInvariant(
                "Rust byte request produced non-Rust syntax",
            ));
        };
        let explicit_captures = usize::try_from(syntax.captures).map_err(|_| {
            CaptureBuildError::InternalInvariant("syntax capture count does not fit usize")
        })?;
        if explicit_captures != rust.hir.properties().explicit_captures_len() {
            return Err(CaptureBuildError::InternalInvariant(
                "syntax capture count differs from HIR properties",
            ));
        }
        required_limits.max_planner_work =
            required_limits.max_planner_work.min(limits.max_hir_work);
        required_limits.max_hir_depth = required_limits.max_hir_depth.min(limits.max_hir_depth);
        match capture_required_literal::build_from_hir(&rust.hir, syntax_key, required_limits) {
            Ok(outcome) => Ok(outcome.plan),
            Err(failure) if optional_required_literal_refusal(&failure.source) => Ok(None),
            Err(failure) => Err(CaptureBuildError::RequiredLiteral(failure.source)),
        }
    }

    /// Compile a capture-participation reducer for non-empty matches.
    #[allow(
        clippy::too_many_lines,
        reason = "the single-parse proof, selector, one-pass sidecar, replay, identity, and accounting publication remain locally auditable"
    )]
    pub fn build(self) -> Result<CaptureRegex, CaptureBuildError> {
        let simd_dispatch = SimdDispatchContext::capture();
        let limits = self.limits;
        let unicode = self.profile.options.unicode;
        let case_insensitive = self.profile.options.case_insensitive;
        let line_terminator = self.profile.options.line_terminator;
        let build_onepass_capture = self.build_onepass_capture;
        let profile = CompatibilityProfile::RustBytes(self.profile);
        let parsed = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(self.pattern, profile)
                .with_admission(limits.admission)
                .with_safety_envelope(limits.syntax_safety),
        )
        .map_err(CaptureBuildError::Syntax)?;
        let syntax_key = Arc::new(parsed.key);
        let admission = parsed.admission_status;
        let syntax = parsed.summary;
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            return Err(CaptureBuildError::InternalInvariant(
                "Rust byte request produced non-Rust syntax",
            ));
        };
        let explicit_captures = usize::try_from(syntax.captures).map_err(|_| {
            CaptureBuildError::InternalInvariant("syntax capture count does not fit usize")
        })?;
        if explicit_captures != rust.hir.properties().explicit_captures_len() {
            return Err(CaptureBuildError::InternalInvariant(
                "syntax capture count differs from HIR properties",
            ));
        }
        let mut accounting = CaptureHirAccounting::default();
        let required_literal = if let Some(mut required_limits) = limits.required_literal {
            let remaining_hir_work = limits.max_hir_work.checked_sub(accounting.work).ok_or(
                CaptureBuildError::HirResource {
                    resource: "work",
                    required: accounting.work,
                    limit: limits.max_hir_work,
                },
            )?;
            required_limits.max_planner_work =
                required_limits.max_planner_work.min(remaining_hir_work);
            required_limits.max_hir_depth = required_limits.max_hir_depth.min(limits.max_hir_depth);
            match capture_required_literal::build_from_hir(
                &rust.hir,
                Arc::clone(&syntax_key),
                required_limits,
            ) {
                Ok(outcome) => {
                    charge_hir(&mut accounting, outcome.planner_work, limits.max_hir_work)?;
                    outcome.plan
                }
                Err(failure) => {
                    charge_hir(&mut accounting, failure.planner_work, limits.max_hir_work)?;
                    if optional_required_literal_refusal(&failure.source) {
                        None
                    } else {
                        return Err(CaptureBuildError::RequiredLiteral(failure.source));
                    }
                }
            }
        } else {
            None
        };
        let selector_profile = if unicode {
            SelectorProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE
        } else {
            SelectorProfile::PINNED_1_12_4
        };
        let ordered_root_capture_many = ordered_root_capture_many_proof(
            &rust.hir,
            explicit_captures,
            unicode,
            &limits,
            &mut accounting,
        )?;
        let selector = if ordered_root_capture_many.is_some_and(|proof| proof.unit_cover.is_none())
        {
            SelectorRegex::from_hir_erasing_captures_for_ordered_root_count(
                &rust.hir,
                selector_profile,
                limits.selector,
            )
        } else {
            SelectorRegex::from_hir_erasing_captures_for_whole_match(
                &rust.hir,
                selector_profile,
                limits.selector,
            )
        }
        .map_err(CaptureBuildError::Selector)?;
        let selector_accounting = selector.compile_accounting();
        let uniform_participating_captures =
            capture_participation(&rust.hir, 1, &limits, &mut accounting)?.uniform;
        let line_batch = if required_literal.is_some() {
            capture_line_batch_proof(&rust.hir, &limits, &mut accounting)?
        } else {
            None
        };
        if ordered_root_capture_many.is_some() && uniform_participating_captures != Some(1) {
            return Err(CaptureBuildError::InternalInvariant(
                "ordered-root proof disagrees with participation analysis",
            ));
        }
        let prefix_class_participation = build_prefix_class_participation(
            simd_dispatch,
            &rust.hir,
            &syntax,
            unicode,
            case_insensitive,
            selector.has_terminal_frontier(),
            uniform_participating_captures,
            &limits,
            &mut accounting,
        )?;
        let fixed_byte_capture_records = {
            let remaining_work = limits.max_hir_work.saturating_sub(accounting.work);
            let build = build_fixed_byte_capture_record_plan(
                &rust.hir,
                explicit_captures,
                unicode,
                remaining_work.min(FIXED_BYTE_CAPTURE_RECORD_MAX_INSPECTION_WORK),
            );
            charge_hir(&mut accounting, build.inspection_work, limits.max_hir_work)?;
            build.plan
        };
        let hir_program = build_program_from_hir_with_accounting(
            &rust.hir,
            line_terminator,
            HirProgramBuildLimits {
                max_hir_work: limits.max_hir_work,
                max_hir_depth: limits.max_hir_depth,
                program: limits.engine,
            },
            accounting,
        )
        .map_err(capture_hir_program_build_error)?;
        let (program, hir_program_report, first_byte_proof) =
            hir_program.into_parts_with_first_byte_proof();
        accounting = hir_program_report.hir;
        let engine_report = hir_program_report.program;
        let program = Arc::new(program);
        let onepass_capture_build = if build_onepass_capture {
            build_optional_onepass_capture(Arc::clone(&program), &engine_report, limits.engine)?
        } else {
            OptionalOnePassCaptureBuild {
                plan: None,
                compile_work: 0,
            }
        };
        let onepass_capture = onepass_capture_build.plan;
        let onepass_capture_compile_work = onepass_capture_build.compile_work;
        let iteration_start_classifier = project_capture_iteration_start_classifier(
            first_byte_proof,
            &mut accounting,
            limits.max_hir_work,
        );
        let participation_quotient = if ordered_root_capture_many.is_none()
            && prefix_class_participation.plan.is_none()
            && uniform_participating_captures.is_none()
            && engine_report.captures <= PARTICIPATION_QUOTIENT_CAPTURE_BITS
        {
            Some(CaptureParticipationQuotientProof {
                user_captures: u8::try_from(engine_report.captures).map_err(|_| {
                    CaptureBuildError::InternalInvariant(
                        "quotient capture schema did not fit its published identity",
                    )
                })?,
                mask_bits: PARTICIPATION_QUOTIENT_MASK_BITS,
                reserved_overall_bits: 1,
                state_masks: 2,
                retained_offsets: 0,
                algorithm_version: PARTICIPATION_QUOTIENT_ALGORITHM_VERSION,
                accounting_version: PARTICIPATION_QUOTIENT_ACCOUNTING_VERSION,
                declared_prepublication_fallback:
                    CaptureParticipationQuotientFallback::PersistentHistory,
            })
        } else {
            None
        };
        let stream_minimum_match_bytes = rust
            .hir
            .properties()
            .minimum_len()
            .filter(|minimum| *minimum > 0);
        let record_search_absolute_start = rust
            .hir
            .properties()
            .look_set_prefix()
            .contains(Look::Start);
        let record_search_absolute_end = rust
            .hir
            .properties()
            .look_set_suffix()
            .contains(Look::End);
        let record_search_absolute_fixed_width = if record_search_absolute_start {
            let properties = rust.hir.properties();
            properties
                .minimum_len()
                .filter(|minimum| Some(*minimum) == properties.maximum_len())
        } else {
            None
        };
        let plan_identity = CapturePlanIdentity {
            syntax: syntax_key,
            operation: CaptureOperation::CountParticipatingNonempty,
            plan: if ordered_root_capture_many.is_some() {
                CapturePlanKind::OrderedRootCaptureManyCount
            } else if prefix_class_participation.plan.is_some() {
                CapturePlanKind::UniformPrefixClassParticipation
            } else if uniform_participating_captures.is_some() {
                CapturePlanKind::LinearSelectorUniformParticipation
            } else if participation_quotient.is_some() && stream_minimum_match_bytes.is_some() {
                CapturePlanKind::FusedCaptureStreamParticipationV1
            } else if participation_quotient.is_some() {
                CapturePlanKind::LinearSelectorParticipationQuotientV1
            } else if stream_minimum_match_bytes.is_some() {
                CapturePlanKind::FusedCaptureStreamPersistentHistoryV1
            } else {
                CapturePlanKind::LinearSelectorPersistentHistory
            },
            capture_profile: CaptureProfile::RustRegexBytes1_12_4,
            selector_plan_id: selector.plan_id(),
            ordered_root_capture_many,
            required_literal: required_literal
                .as_ref()
                .map(|plan| plan.build_report().identity.clone()),
            line_batch,
            prefix_class_participation: prefix_class_participation
                .plan
                .as_ref()
                .map(|plan| plan.identity()),
        };
        let prefix_class_participation_build = prefix_class_participation
            .plan
            .as_ref()
            .map(|plan| plan.engine.uniform_participation_build_accounting());
        let uniform_count_minimum_match_bytes =
            uniform_participating_captures.and(stream_minimum_match_bytes);
        let count_owner = match (
            uniform_participating_captures,
            uniform_count_minimum_match_bytes,
        ) {
            (Some(participating), Some(minimum_match_bytes)) => {
                let participating_captures_per_match =
                    participating
                        .checked_add(1)
                        .ok_or(CaptureBuildError::InternalInvariant(
                            "uniform capture participation overflowed usize",
                        ))?;
                let capture_schema_entries_per_match =
                    engine_report.captures.checked_add(1).ok_or(
                        CaptureBuildError::InternalInvariant("capture schema overflowed usize"),
                    )?;
                let (branch, retained_fallback_bytes, declared_prepublication_fallback) =
                    match plan_identity.plan {
                        CapturePlanKind::OrderedRootCaptureManyCount
                        | CapturePlanKind::LinearSelectorUniformParticipation => (
                            CaptureCountBranch::SelectorUniformParticipation,
                            0,
                            CaptureCountPrepublicationFallback::None,
                        ),
                        CapturePlanKind::UniformPrefixClassParticipation => {
                            if plan_identity.prefix_class_participation.is_none() {
                                return Err(CaptureBuildError::InternalInvariant(
                                    "direct capture plan lost its route identity",
                                ));
                            }
                            let retained_fallback_bytes = engine_report
                                .program_bytes
                                .checked_add(selector_accounting.program_bytes)
                                .ok_or(CaptureBuildError::InternalInvariant(
                                    "capture retained fallback bytes overflowed usize",
                                ))?;
                            (
                                CaptureCountBranch::DirectPrefixClassParticipation,
                                retained_fallback_bytes,
                                CaptureCountPrepublicationFallback::SelectorUniformParticipation,
                            )
                        }
                        CapturePlanKind::LinearSelectorPersistentHistory
                        | CapturePlanKind::LinearSelectorParticipationQuotientV1
                        | CapturePlanKind::FusedCaptureStreamParticipationV1
                        | CapturePlanKind::FusedCaptureStreamPersistentHistoryV1 => {
                            return Err(CaptureBuildError::InternalInvariant(
                                "uniform positive-width plan selected a nonuniform replay",
                            ));
                        }
                    };
                Some(CaptureCountOwnerSeal::new(CaptureCountRouteIdentity {
                    plan: plan_identity.clone(),
                    build_limits: limits,
                    branch,
                    selector_route: CaptureCountSelectorRoute {
                        physical_route: match plan_identity.plan {
                            CapturePlanKind::OrderedRootCaptureManyCount => {
                                if ordered_root_capture_many
                                    .is_some_and(|proof| proof.unit_cover.is_some())
                                {
                                    fre_aggregate::OperationPhysicalRoute::CachedFrontier
                                } else {
                                    fre_aggregate::OperationPhysicalRoute::OrderedRootRows
                                }
                            }
                            CapturePlanKind::LinearSelectorUniformParticipation => {
                                selector.uniform_capture_count_route()
                            }
                            CapturePlanKind::UniformPrefixClassParticipation
                            | CapturePlanKind::LinearSelectorPersistentHistory
                            | CapturePlanKind::LinearSelectorParticipationQuotientV1
                            | CapturePlanKind::FusedCaptureStreamParticipationV1
                            | CapturePlanKind::FusedCaptureStreamPersistentHistoryV1 => {
                                fre_aggregate::OperationPhysicalRoute::DenseRows
                            }
                        },
                        algorithm_version: fre_aggregate::CONTINUATION_OPERATION_ALGORITHM_VERSION,
                        accounting_version:
                            fre_aggregate::CONTINUATION_OPERATION_ACCOUNTING_VERSION,
                        prepublication_fallback:
                            fre_aggregate::OperationPrepublicationFallback::None,
                    },
                    selector_strategy: SelectorStrategy::ReverseSequentialRows,
                    selector_operation: fre_aggregate::OperationAttemptKind::Count,
                    selector_work_mode: match branch {
                        CaptureCountBranch::SelectorUniformParticipation => {
                            fre_aggregate::OperationWorkMode::Observed
                        }
                        CaptureCountBranch::DirectPrefixClassParticipation => {
                            fre_aggregate::OperationWorkMode::ConservativeAdmission
                        }
                    },
                    minimum_match_bytes,
                    participating_captures_per_match,
                    capture_schema_entries_per_match,
                    retained_fallback_bytes,
                    algorithm_version: CAPTURE_COUNT_ALGORITHM_VERSION,
                    accounting_version: CAPTURE_COUNT_ACCOUNTING_VERSION,
                    declared_prepublication_fallback,
                    declared_fallback: CaptureCountDeclaredFallback::None,
                }))
            }
            _ => None,
        };
        let iteration_owner = CaptureIterationOwnerSeal::new(
            CaptureIterationRouteIdentity {
                syntax: Arc::clone(&plan_identity.syntax),
                capture_profile: plan_identity.capture_profile,
                operation: CaptureIterationOperation::MaterializeCaptureArray,
                plan: CaptureIterationPlanKind::RestartedPersistentHistory,
                backend: CaptureIterationBackend::PersistentHistory,
                engine_shape: program.history_program_shape(),
                minimum_match_bytes: rust.hir.properties().minimum_len().unwrap_or(0),
                build_limits: limits,
                algorithm_version: CAPTURE_ITERATION_ALGORITHM_VERSION,
                accounting_version: CAPTURE_ITERATION_ACCOUNTING_VERSION,
                declared_fallback: CaptureIterationDeclaredFallback::None,
            },
            iteration_start_classifier,
        );
        let report = CaptureBuildReport {
            admission,
            syntax,
            hir: accounting,
            engine: engine_report,
            onepass_capture: onepass_capture
                .as_ref()
                .map(|plan| CaptureOnePassBuildReport::from_engine(plan.build_report())),
            onepass_capture_compile_work,
            exact_replay_identity: CaptureExactReplayIdentity {
                syntax: Arc::clone(&plan_identity.syntax),
                capture_profile: plan_identity.capture_profile,
                plan: if onepass_capture.is_some() {
                    CaptureExactReplayPlan::OnePass
                } else {
                    CaptureExactReplayPlan::PersistentHistory
                },
                build_limits: limits,
                onepass: onepass_capture
                    .as_ref()
                    .map(|plan| CaptureOnePassPlanIdentity::from_engine(plan.build_report())),
                algorithm_version: CAPTURE_EXACT_REPLAY_ALGORITHM_VERSION,
                accounting_version: CAPTURE_EXACT_REPLAY_ACCOUNTING_VERSION,
                declared_pre_source_fallback: CaptureExactReplayFallback::PersistentHistory,
            },
            selector: selector_accounting,
            uniform_participating_captures,
            ordered_root_capture_many,
            required_literal: required_literal
                .as_ref()
                .map(|plan| plan.build_report().accounting),
            line_batch,
            prefix_class_participation_planner_work: prefix_class_participation.planner_work,
            prefix_class_participation: prefix_class_participation_build,
            plan_identity,
        };
        Ok(CaptureRegex {
            engine: HistoryRegex::from_program(program),
            onepass_capture,
            fixed_byte_capture_records,
            selector: Arc::new(selector),
            record_search_absolute_start,
            record_search_absolute_end,
            record_search_absolute_fixed_width,
            required_literal,
            prefix_class_participation: prefix_class_participation.plan,
            uniform_count_minimum_match_bytes,
            count_owner,
            iteration_owner,
            build_limits: limits,
            report,
        })
    }
}

/// Immutable capture-preserving reducer plan with persistent-history semantic
/// authority and an optional one-pass exact-replay sidecar.
#[derive(Clone, Debug)]
pub struct CaptureRegex {
    engine: HistoryRegex,
    onepass_capture: Option<OnePassCapturePlan>,
    fixed_byte_capture_records: Option<Arc<FixedByteCaptureRecordPlan>>,
    selector: Arc<SelectorRegex>,
    /// The canonical HIR proves that every match requires the absolute start
    /// of the original haystack, independent of the requested search window.
    record_search_absolute_start: bool,
    /// The canonical HIR proves that every match requires the absolute end of
    /// the current search domain.
    record_search_absolute_end: bool,
    /// Exact byte width when the same canonical absolute-start HIR proves one.
    record_search_absolute_fixed_width: Option<usize>,
    required_literal: Option<CaptureRequiredLiteralPlan>,
    prefix_class_participation: Option<Arc<CapturePrefixClassParticipationPlan>>,
    /// Positive whole-match minimum from the same canonical HIR that proved
    /// uniform capture participation. `None` retains the span validator for
    /// nullable or empty-language plans.
    uniform_count_minimum_match_bytes: Option<usize>,
    /// Construction-owned seal for each positive-width uniform Count route.
    count_owner: Option<CaptureCountOwnerSeal>,
    /// Construction-owned materialized capture-array route.
    iteration_owner: CaptureIterationOwnerSeal,
    build_limits: CaptureBuildLimits,
    report: CaptureBuildReport,
}

/// Caller-owned capture-record storage reused across independent input
/// domains. The exact semantic matcher retains all engine and group-slot
/// buffers across searches and public operations.
#[derive(Debug)]
pub struct CaptureRecordVisitorSession {
    backend: CaptureRecordVisitorBackend,
    groups: Vec<CaptureGroupSlot>,
    absolute_start: bool,
    max_span_bytes: usize,
    persistent_bytes: usize,
}

#[derive(Debug)]
enum CaptureRecordVisitorBackend {
    FixedByteSequence {
        plan: Arc<FixedByteCaptureRecordPlan>,
    },
    History {
        engine: HistoryRegex,
        workspace: HistoryExactWorkspace,
    },
    AbsoluteExactOnePass {
        plan: OnePassCapturePlan,
        workspace: OnePassCaptureWorkspace,
        span: AbsoluteOnePassSpan,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AbsoluteOnePassSpan {
    FixedWidth(usize),
    FullDomain,
}

/// Complete accounting from one exact capture-record visit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureRecordVisitReport {
    /// Complete non-overlapping records delivered to the visitor.
    pub matches: usize,
    /// Repeated semantic searches, including the terminal miss unless a
    /// terminal empty match ended iteration or a published record consumed a
    /// construction-proved original-haystack absolute-start opportunity.
    pub searches: usize,
    /// Numeric schema entries delivered across all records.
    pub capture_events: usize,
    /// Participating numeric groups across all records.
    pub capture_count: usize,
    /// Total retained semantic-search state visits.
    pub total_state_visits: usize,
    /// Total inline tag copies (zero for persistent history).
    pub total_slot_copies: usize,
    /// Total persistent-history nodes.
    pub total_history_nodes: usize,
    /// Total winning-history reconstruction steps.
    pub total_history_walk: usize,
    /// Peak live tagged threads in any search.
    pub peak_threads: usize,
    /// Peak admitted tagged-search scratch.
    pub peak_scratch_bytes: usize,
}

/// Failure from a retained exact capture-record visit.
#[derive(Debug)]
#[non_exhaustive]
pub enum CaptureRecordVisitError {
    /// Tagged search, materialization or fixed workspace construction refused.
    Replay(EngineSearchError),
    /// The retained matcher or its group schema violated an invariant.
    InternalInvariant(&'static str),
}

impl CaptureRecordVisitorSession {
    /// Whether every retained record search is pinned to the absolute start
    /// of its independent input domain.
    #[must_use]
    pub const fn is_absolute_start_anchored(&self) -> bool {
        self.absolute_start
    }

    /// Whether a canonical absolute-start and exact-width proof selected
    /// direct retained one-pass replay for the sole possible record.
    #[doc(hidden)]
    #[must_use]
    pub const fn uses_absolute_fixed_onepass(&self) -> bool {
        matches!(
            &self.backend,
            CaptureRecordVisitorBackend::AbsoluteExactOnePass {
                span: AbsoluteOnePassSpan::FixedWidth(_),
                ..
            }
        )
    }

    /// Whether construction proved a direct unanchored fixed-byte capture
    /// sequence whose complete numeric records can be emitted without tagged
    /// history.
    #[doc(hidden)]
    #[must_use]
    pub const fn uses_fixed_byte_sequence(&self) -> bool {
        matches!(
            &self.backend,
            CaptureRecordVisitorBackend::FixedByteSequence { .. }
        )
    }

    /// Whether canonical absolute-start and absolute-end proofs selected
    /// direct retained one-pass replay over the complete input domain.
    #[doc(hidden)]
    #[must_use]
    pub const fn uses_absolute_full_onepass(&self) -> bool {
        matches!(
            &self.backend,
            CaptureRecordVisitorBackend::AbsoluteExactOnePass {
                span: AbsoluteOnePassSpan::FullDomain,
                ..
            }
        )
    }

    /// Largest exact span admitted by this retained session.
    #[must_use]
    pub const fn max_span_bytes(&self) -> usize {
        self.max_span_bytes
    }

    /// Exact retained workspace and group-buffer bytes.
    #[must_use]
    pub const fn persistent_bytes(&self) -> usize {
        self.persistent_bytes
    }

    /// Visit every non-overlapping leftmost-first capture record in `haystack`
    /// using the retained semantic search workspace. The visitor is invoked
    /// only after group zero and every matched/unmatched endpoint pair have
    /// been validated.
    pub fn visit_records<F>(
        &mut self,
        haystack: &[u8],
        limits: CaptureRunLimits,
        mut visitor: F,
    ) -> Result<CaptureRecordVisitReport, CaptureRecordVisitError>
    where
        F: FnMut(&[CaptureGroupSlot]),
    {
        if haystack.len() > self.max_span_bytes {
            return Err(CaptureRecordVisitError::Replay(
                EngineSearchError::InvalidWindow,
            ));
        }
        if self.groups.is_empty() {
            return Err(CaptureRecordVisitError::InternalInvariant(
                "capture record session retained an empty schema",
            ));
        }
        if let CaptureRecordVisitorBackend::FixedByteSequence { plan } = &self.backend {
            return visit_fixed_byte_capture_records(
                plan,
                &mut self.groups,
                haystack,
                limits,
                visitor,
            );
        }
        if let CaptureRecordVisitorBackend::AbsoluteExactOnePass {
            plan,
            workspace,
            span,
        } = &mut self.backend
        {
            return visit_absolute_onepass_record(
                plan,
                workspace,
                *span,
                &mut self.groups,
                haystack,
                limits,
                visitor,
            );
        }
        let CaptureRecordVisitorBackend::History { engine, workspace } = &mut self.backend else {
            return Err(CaptureRecordVisitError::InternalInvariant(
                "capture record backend changed after publication",
            ));
        };
        let window = Window::all(haystack);
        let mut report = CaptureRecordVisitReport::default();
        let mut cursor = window.start;
        let mut last_match_end = None;
        loop {
            report.searches = record_add(
                report.searches,
                1,
                limits.aggregate.max_searches,
                EngineResource::Searches,
            )?;
            let mut per_search = limits.aggregate.per_search;
            per_search.max_state_visits = per_search.max_state_visits.min(record_remaining(
                limits.aggregate.max_total_state_visits,
                report.total_state_visits,
                EngineResource::AggregateStateVisits,
            )?);
            per_search.max_slot_copies = per_search.max_slot_copies.min(record_remaining(
                limits.aggregate.max_total_slot_copies,
                report.total_slot_copies,
                EngineResource::AggregateSlotCopies,
            )?);
            per_search.max_history_nodes = per_search.max_history_nodes.min(record_remaining(
                limits.aggregate.max_total_history_nodes,
                report.total_history_nodes,
                EngineResource::AggregateHistoryNodes,
            )?);
            per_search.max_history_walk = per_search.max_history_walk.min(record_remaining(
                limits.aggregate.max_total_history_walk,
                report.total_history_walk,
                EngineResource::AggregateHistoryWalk,
            )?);
            let search = CaptureSearchConfig::LEFTMOST.anchored(self.absolute_start);
            let outcome = engine
                .captures_from_slots_with_workspace(
                    workspace,
                    haystack,
                    window,
                    cursor,
                    search,
                    &mut self.groups,
                    per_search,
                )
                .map_err(CaptureRecordVisitError::Replay)?;
            report.total_state_visits = record_add(
                report.total_state_visits,
                outcome.report.state_visits,
                limits.aggregate.max_total_state_visits,
                EngineResource::AggregateStateVisits,
            )?;
            report.total_slot_copies = record_add(
                report.total_slot_copies,
                outcome.report.slot_copies,
                limits.aggregate.max_total_slot_copies,
                EngineResource::AggregateSlotCopies,
            )?;
            report.total_history_nodes = record_add(
                report.total_history_nodes,
                outcome.report.history_nodes,
                limits.aggregate.max_total_history_nodes,
                EngineResource::AggregateHistoryNodes,
            )?;
            report.total_history_walk = record_add(
                report.total_history_walk,
                outcome.report.history_walk,
                limits.aggregate.max_total_history_walk,
                EngineResource::AggregateHistoryWalk,
            )?;
            report.peak_threads = report.peak_threads.max(outcome.report.peak_threads);
            report.peak_scratch_bytes = report
                .peak_scratch_bytes
                .max(outcome.report.admitted_scratch_bytes);
            if !outcome.matched {
                break;
            }
            let overall = self
                .groups
                .first()
                .and_then(|slot| slot.span())
                .ok_or(CaptureRecordVisitError::InternalInvariant(
                    "retained capture search omitted group zero",
                ))?;
            if overall.start == overall.end && last_match_end == Some(overall.start) {
                if overall.end == window.end {
                    break;
                }
                cursor = overall.end.checked_add(1).ok_or(
                    CaptureRecordVisitError::Replay(EngineSearchError::BoundOverflow(
                        EngineResource::Searches,
                    )),
                )?;
                continue;
            }
            report.matches = record_add(
                report.matches,
                1,
                limits.aggregate.max_results,
                EngineResource::Results,
            )?;
            report.capture_events = record_add(
                report.capture_events,
                self.groups.len(),
                limits.aggregate.max_capture_events,
                EngineResource::CaptureEvents,
            )?;
            for group in &self.groups {
                if *group == CaptureGroupSlot::UNMATCHED {
                    continue;
                }
                let group_span = group.span().ok_or(
                    CaptureRecordVisitError::InternalInvariant(
                        "retained search published a noncanonical capture slot",
                    ),
                )?;
                if group_span.start > group_span.end || group_span.end > haystack.len() {
                    return Err(CaptureRecordVisitError::InternalInvariant(
                        "retained search published a capture outside its domain",
                    ));
                }
                report.capture_count = record_add(
                    report.capture_count,
                    1,
                    limits.aggregate.max_capture_count,
                    EngineResource::CaptureCount,
                )?;
            }
            visitor(&self.groups);
            // The canonical HIR proved that every accepting path requires the
            // absolute start of this invocation's original haystack. After
            // publishing its sole possible leftmost record, no later
            // non-overlapping record can exist, so do not open a redundant
            // terminal search.
            if self.absolute_start {
                break;
            }
            last_match_end = Some(overall.end);
            if overall.start == overall.end {
                if overall.end == window.end {
                    break;
                }
                cursor = overall.end.checked_add(1).ok_or(
                    CaptureRecordVisitError::Replay(EngineSearchError::BoundOverflow(
                        EngineResource::Searches,
                    )),
                )?;
            } else {
                cursor = overall.end;
            }
        }
        Ok(report)
    }
}

fn visit_absolute_onepass_record<F>(
    plan: &OnePassCapturePlan,
    workspace: &mut OnePassCaptureWorkspace,
    span: AbsoluteOnePassSpan,
    groups: &mut [CaptureGroupSlot],
    haystack: &[u8],
    limits: CaptureRunLimits,
    mut visitor: F,
) -> Result<CaptureRecordVisitReport, CaptureRecordVisitError>
where
    F: FnMut(&[CaptureGroupSlot]),
{
    let mut report = CaptureRecordVisitReport::default();
    report.searches = record_add(
        report.searches,
        1,
        limits.aggregate.max_searches,
        EngineResource::Searches,
    )?;
    let scratch_bytes = workspace.scratch_bytes();
    if scratch_bytes > limits.aggregate.per_search.max_scratch_bytes {
        return Err(CaptureRecordVisitError::Replay(
            EngineSearchError::Resource {
                kind: EngineResource::ScratchBytes,
                required: scratch_bytes,
                limit: limits.aggregate.per_search.max_scratch_bytes,
            },
        ));
    }
    report.peak_scratch_bytes = scratch_bytes;
    let width = match span {
        AbsoluteOnePassSpan::FixedWidth(width) if haystack.len() < width => return Ok(report),
        AbsoluteOnePassSpan::FixedWidth(width) => width,
        AbsoluteOnePassSpan::FullDomain => haystack.len(),
    };

    let mut per_search = limits.aggregate.per_search;
    per_search.max_state_visits = per_search
        .max_state_visits
        .min(limits.aggregate.max_total_state_visits);
    per_search.max_slot_copies = per_search
        .max_slot_copies
        .min(limits.aggregate.max_total_slot_copies);
    let exact = plan
        .captures_exact_slots(
            workspace,
            haystack,
            Window::all(haystack),
            EngineSpan {
                start: 0,
                end: width,
            },
            groups,
            per_search,
        )
        .map_err(CaptureRecordVisitError::Replay)?;
    report.total_state_visits = record_add(
        report.total_state_visits,
        exact.report.state_visits,
        limits.aggregate.max_total_state_visits,
        EngineResource::AggregateStateVisits,
    )?;
    report.total_slot_copies = record_add(
        report.total_slot_copies,
        exact.report.slot_copies,
        limits.aggregate.max_total_slot_copies,
        EngineResource::AggregateSlotCopies,
    )?;
    report.peak_threads = exact.report.peak_threads;
    report.peak_scratch_bytes = exact.report.admitted_scratch_bytes;
    if !exact.matched {
        return Ok(report);
    }
    report.matches = record_add(
        report.matches,
        1,
        limits.aggregate.max_results,
        EngineResource::Results,
    )?;
    if groups.len() > limits.aggregate.max_capture_events {
        return Err(CaptureRecordVisitError::Replay(
            EngineSearchError::Resource {
                kind: EngineResource::CaptureEvents,
                required: groups.len(),
                limit: limits.aggregate.max_capture_events,
            },
        ));
    }
    report.capture_events = groups.len();
    for group in &*groups {
        if *group == CaptureGroupSlot::UNMATCHED {
            continue;
        }
        let Some(group_span) = group.span() else {
            return Err(CaptureRecordVisitError::InternalInvariant(
                "one-pass replay published a noncanonical capture slot",
            ));
        };
        if group_span.start > group_span.end || group_span.end > haystack.len() {
            return Err(CaptureRecordVisitError::InternalInvariant(
                "one-pass replay published a capture outside its domain",
            ));
        }
        report.capture_count = record_add(
            report.capture_count,
            1,
            limits.aggregate.max_capture_count,
            EngineResource::CaptureCount,
        )?;
    }
    visitor(groups);
    Ok(report)
}

struct FixedByteCaptureInspector {
    masks: [FixedByteCaptureMask; FIXED_BYTE_CAPTURE_RECORD_MAX_WIDTH],
    captures: [Option<FixedByteCaptureRange>; FIXED_BYTE_CAPTURE_RECORD_MAX_GROUPS],
    width: usize,
    work: usize,
    max_work: usize,
}

impl FixedByteCaptureInspector {
    fn charge(&mut self, additional: usize) -> bool {
        let Some(next) = self.work.checked_add(additional) else {
            self.work = self.max_work;
            return false;
        };
        if next > self.max_work {
            self.work = self.max_work;
            return false;
        }
        self.work = next;
        true
    }

    fn push_mask(&mut self, mask: FixedByteCaptureMask) -> bool {
        if self.width >= FIXED_BYTE_CAPTURE_RECORD_MAX_WIDTH {
            return false;
        }
        self.masks[self.width] = mask;
        self.width += 1;
        true
    }

    fn emit_capture(&mut self, hir: &Hir, optional: bool) -> bool {
        let HirKind::Capture(capture) = hir.kind() else {
            return false;
        };
        if !self.charge(1) {
            return false;
        }
        let Ok(index) = usize::try_from(capture.index) else {
            return false;
        };
        let Some(slot) = index.checked_sub(1) else {
            return false;
        };
        if slot >= self.captures.len() || self.captures[slot].is_some() {
            return false;
        }
        let start = self.width;
        if !self.emit_atoms(capture.sub.as_ref(), 1) {
            return false;
        }
        self.captures[slot] = Some(FixedByteCaptureRange {
            start,
            end: self.width,
            optional,
        });
        true
    }

    fn emit_atoms(&mut self, hir: &Hir, depth: usize) -> bool {
        if depth > 64 || !self.charge(1) {
            return false;
        }
        match hir.kind() {
            HirKind::Empty => true,
            HirKind::Literal(literal) => {
                for &byte in literal.0.iter() {
                    if !self.charge(1) {
                        return false;
                    }
                    let mut mask = FixedByteCaptureMask::default();
                    mask.insert(byte);
                    if !self.push_mask(mask) {
                        return false;
                    }
                }
                true
            }
            HirKind::Class(Class::Bytes(class)) => {
                let mut mask = FixedByteCaptureMask::default();
                for range in class.ranges() {
                    for byte in u16::from(range.start())..=u16::from(range.end()) {
                        if !self.charge(1) {
                            return false;
                        }
                        mask.insert(byte as u8);
                    }
                }
                self.push_mask(mask)
            }
            HirKind::Repetition(repetition)
                if repetition.max == Some(repetition.min)
                    && usize::try_from(repetition.min).is_ok() =>
            {
                let repeats = usize::try_from(repetition.min).unwrap_or(usize::MAX);
                for _ in 0..repeats {
                    if !self.emit_atoms(repetition.sub.as_ref(), depth + 1) {
                        return false;
                    }
                }
                true
            }
            HirKind::Concat(parts) => parts.iter().all(|part| self.emit_atoms(part, depth + 1)),
            HirKind::Class(Class::Unicode(_))
            | HirKind::Look(_)
            | HirKind::Capture(_)
            | HirKind::Alternation(_)
            | HirKind::Repetition(_) => false,
        }
    }

    fn inspect_root_item(&mut self, hir: &Hir, terminal: bool) -> Option<bool> {
        if matches!(hir.kind(), HirKind::Capture(_)) {
            return self.emit_capture(hir, false).then_some(false);
        }
        if let HirKind::Repetition(repetition) = hir.kind()
            && terminal
            && repetition.min == 0
            && repetition.max == Some(1)
            && repetition.greedy
            && matches!(repetition.sub.kind(), HirKind::Capture(_))
        {
            if !self.charge(1) {
                return None;
            }
            return self
                .emit_capture(repetition.sub.as_ref(), true)
                .then_some(true);
        }
        self.emit_atoms(hir, 1).then_some(false)
    }
}

fn build_fixed_byte_capture_record_plan(
    hir: &Hir,
    explicit_captures: usize,
    unicode: bool,
    max_work: usize,
) -> FixedByteCaptureRecordBuild {
    let ineligible = |inspection_work| FixedByteCaptureRecordBuild {
        plan: None,
        inspection_work,
    };
    let Some(group_count) = explicit_captures.checked_add(1) else {
        return ineligible(0);
    };
    if unicode
        || explicit_captures == 0
        || group_count > FIXED_BYTE_CAPTURE_RECORD_MAX_GROUPS
        || max_work == 0
    {
        return ineligible(0);
    }
    let mut inspector = FixedByteCaptureInspector {
        masks: [FixedByteCaptureMask::default(); FIXED_BYTE_CAPTURE_RECORD_MAX_WIDTH],
        captures: [None; FIXED_BYTE_CAPTURE_RECORD_MAX_GROUPS],
        width: 0,
        work: 0,
        max_work,
    };
    let mut optional_start = None;
    let eligible = match hir.kind() {
        HirKind::Concat(parts) => {
            if !inspector.charge(1) {
                false
            } else {
                let part_count = parts.len();
                parts.iter().enumerate().all(|(index, part)| {
                    let terminal = index.checked_add(1) == Some(part_count);
                    let Some(optional) = inspector.inspect_root_item(part, terminal) else {
                        return false;
                    };
                    if optional {
                        optional_start = inspector
                            .captures
                            .iter()
                            .flatten()
                            .find(|range| range.optional)
                            .map(|range| range.start);
                    }
                    true
                })
            }
        }
        _ => {
            let Some(optional) = inspector.inspect_root_item(hir, true) else {
                return ineligible(inspector.work);
            };
            if optional {
                optional_start = inspector
                    .captures
                    .iter()
                    .flatten()
                    .find(|range| range.optional)
                    .map(|range| range.start);
            }
            true
        }
    };
    if !eligible
        || inspector.captures[..explicit_captures]
            .iter()
            .any(Option::is_none)
        || inspector.captures[explicit_captures..]
            .iter()
            .any(Option::is_some)
    {
        return ineligible(inspector.work);
    }
    let mandatory_width = optional_start.unwrap_or(inspector.width);
    if mandatory_width == 0 {
        return ineligible(inspector.work);
    }
    let optional_width = inspector.width.saturating_sub(mandatory_width);
    if optional_start.is_some() && optional_width == 0 {
        // A greedy optional empty capture is semantically deterministic, but
        // retaining it here would make the direct route nullable when the
        // mandatory prefix is later generalized. Keep this first route
        // strictly positive and byte-consuming at both boundaries.
        return ineligible(inspector.work);
    }
    FixedByteCaptureRecordBuild {
        plan: Some(Arc::new(FixedByteCaptureRecordPlan {
            masks: inspector.masks,
            captures: inspector.captures,
            mandatory_width,
            optional_width,
            group_count,
        })),
        inspection_work: inspector.work,
    }
}

fn fixed_byte_sequence_matches(
    masks: &[FixedByteCaptureMask],
    haystack: &[u8],
    start: usize,
    probes: &mut usize,
) -> bool {
    for (offset, mask) in masks.iter().enumerate() {
        *probes = probes.saturating_add(1);
        if !mask.contains(haystack[start + offset]) {
            return false;
        }
    }
    true
}

fn visit_fixed_byte_capture_records<F>(
    plan: &FixedByteCaptureRecordPlan,
    groups: &mut [CaptureGroupSlot],
    haystack: &[u8],
    limits: CaptureRunLimits,
    mut visitor: F,
) -> Result<CaptureRecordVisitReport, CaptureRecordVisitError>
where
    F: FnMut(&[CaptureGroupSlot]),
{
    if groups.len() != plan.group_count || plan.mandatory_width == 0 {
        return Err(CaptureRecordVisitError::InternalInvariant(
            "fixed-byte capture record schema is inconsistent",
        ));
    }
    let maximum_width = plan
        .mandatory_width
        .checked_add(plan.optional_width)
        .ok_or(CaptureRecordVisitError::Replay(
            EngineSearchError::BoundOverflow(EngineResource::StateVisits),
        ))?;
    let candidate_starts = haystack
        .len()
        .checked_sub(plan.mandatory_width)
        .map_or(0, |remaining| remaining.saturating_add(1));
    let state_visit_bound =
        candidate_starts
            .checked_mul(maximum_width)
            .ok_or(CaptureRecordVisitError::Replay(
                EngineSearchError::BoundOverflow(EngineResource::AggregateStateVisits),
            ))?;
    let match_bound = haystack.len() / plan.mandatory_width;
    let search_bound = match_bound
        .checked_add(1)
        .ok_or(CaptureRecordVisitError::Replay(
            EngineSearchError::BoundOverflow(EngineResource::Searches),
        ))?;
    let event_bound =
        match_bound
            .checked_mul(groups.len())
            .ok_or(CaptureRecordVisitError::Replay(
                EngineSearchError::BoundOverflow(EngineResource::CaptureEvents),
            ))?;
    for (required, limit, resource) in [
        (
            state_visit_bound,
            limits.aggregate.per_search.max_state_visits,
            EngineResource::StateVisits,
        ),
        (
            state_visit_bound,
            limits.aggregate.max_total_state_visits,
            EngineResource::AggregateStateVisits,
        ),
        (
            search_bound,
            limits.aggregate.max_searches,
            EngineResource::Searches,
        ),
        (
            match_bound,
            limits.aggregate.max_results,
            EngineResource::Results,
        ),
        (
            event_bound,
            limits.aggregate.max_capture_events,
            EngineResource::CaptureEvents,
        ),
        (
            event_bound,
            limits.aggregate.max_capture_count,
            EngineResource::CaptureCount,
        ),
    ] {
        if required > limit {
            return Err(CaptureRecordVisitError::Replay(
                EngineSearchError::Resource {
                    kind: resource,
                    required,
                    limit,
                },
            ));
        }
    }

    let mandatory_masks = &plan.masks[..plan.mandatory_width];
    let optional_masks = &plan.masks[plan.mandatory_width..maximum_width];
    let mut report = CaptureRecordVisitReport {
        peak_threads: 1,
        ..CaptureRecordVisitReport::default()
    };
    let mut cursor = 0_usize;
    loop {
        report.searches += 1;
        if haystack.len() < plan.mandatory_width || cursor > haystack.len() - plan.mandatory_width {
            break;
        }
        let mut start = cursor;
        let mut found = None;
        while start <= haystack.len() - plan.mandatory_width {
            if fixed_byte_sequence_matches(
                mandatory_masks,
                haystack,
                start,
                &mut report.total_state_visits,
            ) {
                found = Some(start);
                break;
            }
            start += 1;
        }
        let Some(start) = found else {
            break;
        };
        let optional = plan.optional_width > 0
            && start
                .checked_add(maximum_width)
                .is_some_and(|end| end <= haystack.len())
            && fixed_byte_sequence_matches(
                optional_masks,
                haystack,
                start + plan.mandatory_width,
                &mut report.total_state_visits,
            );
        let end = start + plan.mandatory_width + usize::from(optional) * plan.optional_width;
        groups.fill(CaptureGroupSlot::UNMATCHED);
        groups[0] = CaptureGroupSlot::matched(EngineSpan { start, end });
        report.capture_count += 1;
        for (slot, range) in plan.captures[..plan.group_count - 1].iter().enumerate() {
            let range = range.ok_or(CaptureRecordVisitError::InternalInvariant(
                "fixed-byte capture record lost a numeric group",
            ))?;
            if range.optional && !optional {
                continue;
            }
            groups[slot + 1] = CaptureGroupSlot::matched(EngineSpan {
                start: start + range.start,
                end: start + range.end,
            });
            report.capture_count += 1;
        }
        report.matches += 1;
        report.capture_events += groups.len();
        visitor(groups);
        cursor = end;
    }
    Ok(report)
}

fn record_remaining(
    limit: usize,
    used: usize,
    resource: EngineResource,
) -> Result<usize, CaptureRecordVisitError> {
    limit.checked_sub(used).ok_or(CaptureRecordVisitError::Replay(
        EngineSearchError::BoundOverflow(resource),
    ))
}

fn allocate_capture_record_groups(
    group_count: usize,
) -> Result<Vec<CaptureGroupSlot>, CaptureRecordVisitError> {
    let mut groups = Vec::new();
    groups
        .try_reserve_exact(group_count)
        .map_err(|_| CaptureRecordVisitError::Replay(EngineSearchError::Allocation(
            EngineResource::Captures,
        )))?;
    if groups.capacity() != group_count {
        return Err(CaptureRecordVisitError::Replay(
            EngineSearchError::Allocation(EngineResource::Captures),
        ));
    }
    groups.resize(group_count, CaptureGroupSlot::UNMATCHED);
    Ok(groups)
}

fn record_add(
    current: usize,
    additional: usize,
    limit: usize,
    resource: EngineResource,
) -> Result<usize, CaptureRecordVisitError> {
    let required = current
        .checked_add(additional)
        .ok_or(CaptureRecordVisitError::Replay(
            EngineSearchError::BoundOverflow(resource),
        ))?;
    if required > limit {
        return Err(CaptureRecordVisitError::Replay(
            EngineSearchError::Resource {
                kind: resource,
                required,
                limit,
            },
        ));
    }
    Ok(required)
}

impl fmt::Display for CaptureRecordVisitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replay(error) => write!(formatter, "capture record search failed: {error}"),
            Self::InternalInvariant(detail) => {
                write!(formatter, "capture record visit invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for CaptureRecordVisitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Replay(error) => Some(error),
            Self::InternalInvariant(_) => None,
        }
    }
}

/// Caller-owned reusable execution shell for one source-length/domain/limit
/// bound fused capture operation.
///
/// A [`CaptureRegex`] remains immutable and can be shared freely. Each thread
/// or public-operation lifecycle that elects the fused route owns one of these
/// sessions, so steady calls reuse the admitted frontier and tag workspace
/// plus its bounded source-independent transition cache, without locks or
/// operation-time allocation.
#[derive(Debug)]
pub struct CaptureStreamSession {
    stream: CaptureStream,
    program: Arc<Program>,
    identity: CaptureCacheIdentity,
    domains: CaptureStreamDomains,
    expected_projection: CaptureStreamProjection,
    stream_limits: CaptureStreamLimits,
    /// Immutable selector artifact co-live with this session's workspace.
    selector_retained_bytes: usize,
    /// Exact outer peak admitted before source access.
    combined_peak_bytes: usize,
}

impl CaptureStreamSession {
    /// Immutable source-free restart envelope bound during preparation.
    ///
    /// For a cached-value-only session this authenticates the fixed program
    /// but is intentionally not claimed to fit the session limits. Use
    /// [`Self::is_cached_value_only`] to distinguish that mode.
    #[must_use]
    pub const fn operation_prospective(&self) -> CaptureStreamOperationProspective {
        self.stream.operation_report()
    }

    /// Whether this session supports only bounded cached Count values.
    #[must_use]
    pub const fn is_cached_value_only(&self) -> bool {
        self.stream.is_cached_value_only()
    }

    /// Execute the prepared operation and return only the capture count.
    ///
    /// Regular sessions use the construction-admitted operation envelope and
    /// replay a receipt-bearing terminal if the compact path refuses.
    /// Cache-only sessions meter their own bounded work and return that typed
    /// terminal directly; they never switch to restarted execution after
    /// observing source bytes.
    #[allow(
        clippy::result_large_err,
        reason = "cold replay preserves the established complete capture execution error"
    )]
    pub fn count_value(&mut self, haystack: &[u8]) -> Result<usize, CaptureExecutionError> {
        match self.stream.count_value(haystack) {
            Ok(value) => Ok(value),
            Err(source) if self.stream.is_cached_value_only() => {
                Err(self.stream_execution_error(source))
            }
            Err(_) => self.replay_count_value(haystack),
        }
    }

    fn stream_execution_error(&self, source: CaptureStreamError) -> CaptureExecutionError {
        CaptureExecutionError {
            identity: self.identity.clone(),
            source: CaptureExecutionSource::Stream(source),
            selector_receipt: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
        }
    }

    #[cold]
    #[inline(never)]
    #[allow(
        clippy::result_large_err,
        reason = "cold replay preserves the established complete capture execution error"
    )]
    fn replay_count_value(&mut self, haystack: &[u8]) -> Result<usize, CaptureExecutionError> {
        self.execute(haystack).map(|report| report.accounting.count)
    }

    /// Execute one complete operation using the already admitted workspace.
    ///
    /// This path never reconstructs a stream and never takes a fallback after
    /// source access begins.
    #[allow(
        clippy::result_large_err,
        reason = "the established public execution error preserves complete source receipts without an API-breaking box"
    )]
    pub fn execute(
        &mut self,
        haystack: &[u8],
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        let stream_report =
            self.stream
                .execute(haystack)
                .map_err(|source| CaptureExecutionError {
                    identity: self.identity.clone(),
                    source: CaptureExecutionSource::Stream(source),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
        if !stream_report.authenticates_program(&self.program) {
            return Err(CaptureExecutionError {
                identity: self.identity.clone(),
                source: CaptureExecutionSource::InternalInvariant(
                    "capture stream session success failed program/P/A authentication",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            });
        }
        let result = CaptureExecutionReport {
            identity: self.identity.clone(),
            accounting: stream_report.captures.clone(),
            selector_certificate: None,
            selector_accounting: None,
            selector_receipt: None,
            prefix_class_participation: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
            capture_events: stream_report.capture_events,
            capture_stream: Some(stream_report),
            combined_peak_bytes: self.combined_peak_bytes,
        };
        if self.authenticates_success(&result) {
            Ok(result)
        } else {
            Err(CaptureExecutionError {
                identity: self.identity.clone(),
                source: CaptureExecutionSource::InternalInvariant(
                    "capture stream session outer receipt failed identity/peak closure",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            })
        }
    }

    fn authenticates_success(&self, result: &CaptureExecutionReport) -> bool {
        let Some(stream) = result.capture_stream.as_ref() else {
            return false;
        };
        let expected_peak = stream
            .combined_peak_bytes
            .checked_add(self.selector_retained_bytes);
        result.identity == self.identity
            && stream.domains == self.domains
            && stream.limits == self.stream_limits
            && stream.prospective.projection == self.expected_projection
            && stream.prospective.source_bytes
                == self.operation_prospective().construction.source_bytes
            && stream.operation == self.operation_prospective()
            && stream.authenticates_program(&self.program)
            && stream.captures == result.accounting
            && stream.capture_events == result.capture_events
            && expected_peak == Some(self.combined_peak_bytes)
            && result.combined_peak_bytes == self.combined_peak_bytes
            && result.selector_certificate.is_none()
            && result.selector_accounting.is_none()
            && result.selector_receipt.is_none()
            && result.prefix_class_participation.is_none()
            && result.prefix_class_participation_receipt.is_none()
            && result.count_receipt.is_none()
    }
}

/// One caller-owned reusable projection table for a capture sidecar selected
/// by an outer shared multi-pattern automaton. It never searches for a start:
/// each invocation receives the ordinal/span already fixed by that selector.
#[derive(Debug)]
pub(crate) struct CaptureExactProjectionSession {
    route: CaptureExactProjectionRoute,
}

#[derive(Debug)]
enum CaptureExactProjectionRoute {
    /// A positive-width uniform proof needs no tag workspace at all: every
    /// span emitted by the shared selector has the already-proved count.
    Uniform {
        entries: u64,
    },
    /// A nullable uniform proof still reduces non-empty spans directly, but
    /// retains one exact workspace to authenticate the selector's empty-span
    /// progress semantics.
    UniformWithEmpty {
        entries: u64,
        empty_span_stream: CaptureStream,
        empty_projection: CaptureStreamProjection,
    },
    Mask {
        stream: CaptureStream,
    },
    PersistentHistory {
        stream: CaptureStream,
    },
}

impl CaptureExactProjectionSession {
    /// Immutable exact workspace envelope retained by this route. A fixed
    /// positive-width cardinality proof deliberately retains no stream.
    pub(crate) const fn stream_prospective(&self) -> Option<CaptureStreamProspective> {
        match &self.route {
            CaptureExactProjectionRoute::Uniform { .. } => None,
            CaptureExactProjectionRoute::UniformWithEmpty {
                empty_span_stream, ..
            }
            | CaptureExactProjectionRoute::Mask {
                stream: empty_span_stream,
            }
            | CaptureExactProjectionRoute::PersistentHistory {
                stream: empty_span_stream,
            } => Some(empty_span_stream.build_report()),
        }
    }

    pub(crate) fn project(
        &mut self,
        haystack: &[u8],
        span: EngineSpan,
    ) -> Result<(ExactCaptureParticipation, CaptureStreamAccounting), CaptureStreamError> {
        match &mut self.route {
            CaptureExactProjectionRoute::Uniform { entries } => {
                if span.start == span.end {
                    return Err(CaptureStreamError::InvalidProgram);
                }
                Ok((
                    ExactCaptureParticipation::Cardinality(*entries),
                    CaptureStreamAccounting::default(),
                ))
            }
            CaptureExactProjectionRoute::UniformWithEmpty { entries, .. }
                if span.start != span.end =>
            {
                Ok((
                    ExactCaptureParticipation::Cardinality(*entries),
                    CaptureStreamAccounting::default(),
                ))
            }
            CaptureExactProjectionRoute::UniformWithEmpty {
                empty_span_stream,
                empty_projection,
                ..
            } => {
                let (entries, accounting) = empty_span_stream.execute_exact_span(haystack, span)?;
                let entries =
                    u64::try_from(entries).map_err(|_| CaptureStreamError::InvalidProgram)?;
                let projection = match empty_projection {
                    CaptureStreamProjection::ParticipationMask => {
                        ExactCaptureParticipation::MaskCount(entries)
                    }
                    CaptureStreamProjection::PersistentHistory => {
                        ExactCaptureParticipation::PersistentHistory(entries)
                    }
                };
                Ok((projection, accounting))
            }
            CaptureExactProjectionRoute::Mask { stream } => {
                let (entries, accounting) = stream.execute_exact_span(haystack, span)?;
                let entries =
                    u64::try_from(entries).map_err(|_| CaptureStreamError::InvalidProgram)?;
                Ok((ExactCaptureParticipation::MaskCount(entries), accounting))
            }
            CaptureExactProjectionRoute::PersistentHistory { stream } => {
                let (entries, accounting) = stream.execute_exact_span(haystack, span)?;
                let entries =
                    u64::try_from(entries).map_err(|_| CaptureStreamError::InvalidProgram)?;
                Ok((
                    ExactCaptureParticipation::PersistentHistory(entries),
                    accounting,
                ))
            }
        }
    }
}

fn capture_exact_stream_limits(
    states: usize,
    user_captures: usize,
    source_bytes: usize,
    limits: EngineSearchLimits,
    requested: CaptureStreamLimits,
) -> CaptureStreamLimits {
    let groups = user_captures.saturating_add(1);
    let history_reads = limits
        .max_history_nodes
        .saturating_add(limits.max_history_walk.saturating_mul(2));
    let baseline = CaptureStreamLimits {
        max_source_bytes: source_bytes,
        max_states: states,
        max_build_work: usize::MAX,
        max_persistent_bytes: limits.max_scratch_bytes,
        max_combined_peak_bytes: limits.max_scratch_bytes,
        max_allocations: 16,
        max_line_domains: 1,
        max_searches: 1,
        max_matches: 1,
        max_bytes_examined: source_bytes,
        max_starts_injected: 1,
        max_state_visits: limits.max_state_visits,
        max_tag_actions: limits.max_slot_copies,
        max_history_nodes: limits.max_history_nodes,
        max_history_walk: limits.max_history_walk,
        max_history_reads: history_reads,
        max_materialization_reads: limits.max_history_walk,
        max_materialization_writes: limits.max_history_walk,
        max_materialization_preview_writes: 0,
        max_mask_states: 0,
        max_mask_word_copies: 0,
        max_mask_word_reads: limits.max_state_visits,
        max_reset_cells: usize::MAX,
        max_capture_events: groups,
        max_capture_count: groups,
        max_line_source_reads: 0,
        max_work: usize::MAX,
    };
    intersect_capture_stream_limits(baseline, requested)
}

fn intersect_capture_stream_limits(
    baseline: CaptureStreamLimits,
    requested: CaptureStreamLimits,
) -> CaptureStreamLimits {
    macro_rules! bounded {
        ($field:ident) => {
            baseline.$field.min(requested.$field)
        };
    }
    CaptureStreamLimits {
        max_source_bytes: bounded!(max_source_bytes),
        max_states: bounded!(max_states),
        max_build_work: bounded!(max_build_work),
        max_persistent_bytes: bounded!(max_persistent_bytes),
        max_combined_peak_bytes: bounded!(max_combined_peak_bytes),
        max_allocations: bounded!(max_allocations),
        max_line_domains: bounded!(max_line_domains),
        max_searches: bounded!(max_searches),
        max_matches: bounded!(max_matches),
        max_bytes_examined: bounded!(max_bytes_examined),
        max_starts_injected: bounded!(max_starts_injected),
        max_state_visits: bounded!(max_state_visits),
        max_tag_actions: bounded!(max_tag_actions),
        max_history_nodes: bounded!(max_history_nodes),
        max_history_walk: bounded!(max_history_walk),
        max_history_reads: bounded!(max_history_reads),
        max_materialization_reads: bounded!(max_materialization_reads),
        max_materialization_writes: bounded!(max_materialization_writes),
        max_materialization_preview_writes: bounded!(max_materialization_preview_writes),
        max_mask_states: bounded!(max_mask_states),
        max_mask_word_copies: bounded!(max_mask_word_copies),
        max_mask_word_reads: bounded!(max_mask_word_reads),
        max_reset_cells: bounded!(max_reset_cells),
        max_capture_events: bounded!(max_capture_events),
        max_capture_count: bounded!(max_capture_count),
        max_line_source_reads: bounded!(max_line_source_reads),
        max_work: bounded!(max_work),
    }
}

impl CaptureRegex {
    /// Prepare caller-owned capture-record storage for independent domains no
    /// longer than `max_span_bytes`.
    ///
    /// Every engine workspace and numeric group slot is allocated before a
    /// visitor can be invoked. Repeated searches then use one retained exact
    /// semantic authority without allocating a record or group vector.
    pub fn prepare_capture_record_visitor(
        &self,
        max_span_bytes: usize,
        limits: EngineSearchLimits,
        max_persistent_bytes: usize,
    ) -> Result<CaptureRecordVisitorSession, CaptureRecordVisitError> {
        let group_count = self
            .report
            .engine
            .captures
            .checked_add(1)
            .ok_or(CaptureRecordVisitError::InternalInvariant(
                "capture record schema overflowed usize",
            ))?;
        let group_bytes = group_count
            .checked_mul(core::mem::size_of::<CaptureGroupSlot>())
            .ok_or(CaptureRecordVisitError::Replay(
                EngineSearchError::BoundOverflow(EngineResource::ScratchBytes),
            ))?;
        if let Some(plan) = &self.fixed_byte_capture_records {
            if plan.group_count != group_count {
                return Err(CaptureRecordVisitError::InternalInvariant(
                    "fixed-byte capture record schema changed after construction",
                ));
            }
            if group_bytes > max_persistent_bytes {
                return Err(CaptureRecordVisitError::Replay(
                    EngineSearchError::Resource {
                        kind: EngineResource::ScratchBytes,
                        required: group_bytes,
                        limit: max_persistent_bytes,
                    },
                ));
            }
            let groups = allocate_capture_record_groups(group_count)?;
            return Ok(CaptureRecordVisitorSession {
                backend: CaptureRecordVisitorBackend::FixedByteSequence {
                    plan: Arc::clone(plan),
                },
                groups,
                absolute_start: false,
                max_span_bytes,
                persistent_bytes: group_bytes,
            });
        }
        let exact_span = self
            .record_search_absolute_fixed_width
            .map(AbsoluteOnePassSpan::FixedWidth)
            .or_else(|| {
                (self.record_search_absolute_start && self.record_search_absolute_end)
                    .then_some(AbsoluteOnePassSpan::FullDomain)
            });
        let exact_span = exact_span.map(|span| {
            let width = match span {
                AbsoluteOnePassSpan::FixedWidth(width) => width,
                AbsoluteOnePassSpan::FullDomain => max_span_bytes,
            };
            (span, width)
        });
        if let Some((exact_span, width)) = exact_span
            && let Some(plan) = &self.onepass_capture
            && plan.exact_replay_work_is_admitted(
                EngineSpan {
                    start: 0,
                    end: width,
                },
                limits,
            )
            && let Ok(workspace_usage) = plan.workspace_usage(limits)
            && let Some(persistent_bytes) = workspace_usage.persistent_bytes.checked_add(group_bytes)
            && persistent_bytes <= max_persistent_bytes
            && let Ok(workspace) = plan.create_workspace(limits)
            && workspace.usage() == workspace_usage
        {
            let groups = allocate_capture_record_groups(group_count)?;
            return Ok(CaptureRecordVisitorSession {
                backend: CaptureRecordVisitorBackend::AbsoluteExactOnePass {
                    plan: plan.clone(),
                    workspace,
                    span: exact_span,
                },
                groups,
                absolute_start: true,
                max_span_bytes,
                persistent_bytes,
            });
        }
        let workspace_usage = self
            .engine
            .exact_workspace_usage(max_span_bytes, limits)
            .map_err(CaptureRecordVisitError::Replay)?;
        let persistent_bytes = workspace_usage
            .persistent_bytes
            .checked_add(group_bytes)
            .ok_or(CaptureRecordVisitError::Replay(
                EngineSearchError::BoundOverflow(EngineResource::ScratchBytes),
            ))?;
        if persistent_bytes > max_persistent_bytes {
            return Err(CaptureRecordVisitError::Replay(
                EngineSearchError::Resource {
                    kind: EngineResource::ScratchBytes,
                    required: persistent_bytes,
                    limit: max_persistent_bytes,
                },
            ));
        }
        let groups = allocate_capture_record_groups(group_count)?;
        let workspace = self
            .engine
            .prepare_exact_workspace(max_span_bytes, limits)
            .map_err(CaptureRecordVisitError::Replay)?;
        if workspace.usage() != workspace_usage {
            return Err(CaptureRecordVisitError::Replay(
                EngineSearchError::InvalidProgram,
            ));
        }
        Ok(CaptureRecordVisitorSession {
            backend: CaptureRecordVisitorBackend::History {
                engine: self.engine.clone(),
                workspace,
            },
            groups,
            absolute_start: self.record_search_absolute_start,
            max_span_bytes,
            persistent_bytes,
        })
    }

    /// Construction and plan identity.
    #[must_use]
    pub const fn build_report(&self) -> &CaptureBuildReport {
        &self.report
    }

    /// Exact construction limits retained by this immutable sidecar.
    ///
    /// Forced multi-pattern capture composition uses this accessor to
    /// authenticate that every ordinal inherited its enclosing policy and
    /// resource envelope rather than silently using a default constructor.
    #[must_use]
    pub const fn build_limits(&self) -> CaptureBuildLimits {
        self.build_limits
    }

    /// Recompute the exact source-free direct-operation P for adapter/cache
    /// authentication. Non-direct plans return `Ok(None)`.
    pub fn prefix_class_participation_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<
        Option<PrefixClassUniformParticipationProspective>,
        PrefixClassUniformParticipationError,
    > {
        self.prefix_class_participation
            .as_ref()
            .map(|plan| {
                plan.engine
                    .uniform_participation_prospective(haystack_len, plan.schema)
            })
            .transpose()
    }

    /// Return the exact source-free direct-operation envelope only after the
    /// retained kernel, published report, and construction-owned Count route
    /// authenticate one another.
    pub fn retained_prefix_class_participation_prospective(
        &self,
        haystack_len: usize,
    ) -> Result<Option<PrefixClassUniformParticipationProspective>, CaptureExecutionSource> {
        let report_selects_direct =
            self.report.plan_identity.plan == CapturePlanKind::UniformPrefixClassParticipation;
        let report_identity = self.report.plan_identity.prefix_class_participation;
        let report_build = self.report.prefix_class_participation;
        let Some(plan) = self.prefix_class_participation.as_ref() else {
            if report_selects_direct || report_identity.is_some() || report_build.is_some() {
                return Err(CaptureExecutionSource::InternalInvariant(
                    "direct capture report retained no direct owner",
                ));
            }
            return Ok(None);
        };
        let Some(owner) = self.count_owner.as_ref() else {
            return Err(CaptureExecutionSource::InternalInvariant(
                "direct capture kernel retained no Count owner",
            ));
        };
        let route = owner.identity();
        if !report_selects_direct
            || report_identity != Some(plan.identity())
            || report_build != Some(plan.engine.uniform_participation_build_accounting())
            || route.branch != CaptureCountBranch::DirectPrefixClassParticipation
            || route.plan != self.report.plan_identity
            || route.build_limits != self.build_limits
        {
            return Err(CaptureExecutionSource::InternalInvariant(
                "direct capture kernel, report, and Count owner do not authenticate",
            ));
        }
        plan.engine
            .uniform_participation_prospective(haystack_len, plan.schema)
            .map(Some)
            .map_err(CaptureExecutionSource::PrefixClassParticipation)
    }

    /// Recompute the exact source-independent envelope for one quotient
    /// replay. Plans that retained full persistent history return `Ok(None)`.
    pub fn participation_quotient_prospective(
        &self,
        span: EngineSpan,
    ) -> Result<Option<ParticipationSearchProspective>, EngineSearchError> {
        if self.report.plan_identity.plan == CapturePlanKind::LinearSelectorParticipationQuotientV1
        {
            self.engine.participation_exact_prospective(span).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Return the immutable stream envelope needed by one reusable exact
    /// projector, if this sidecar actually needs tagged replay. Positive-width
    /// uniform cardinality proofs return `None`: their selected spans can be
    /// reduced without retaining a frontier or history workspace.
    pub(crate) fn exact_projection_stream_prospective(
        &self,
        source_bytes: usize,
        limits: EngineSearchLimits,
        projection_limits: CaptureStreamLimits,
    ) -> Result<Option<CaptureStreamProspective>, CaptureStreamError> {
        if self.report.uniform_participating_captures.is_some()
            && self.uniform_count_minimum_match_bytes.is_some()
        {
            return Ok(None);
        }
        let prospective = CaptureStream::prospective(self.engine.program(), source_bytes)?;
        let stream_limits = capture_exact_stream_limits(
            self.report.engine.states,
            self.report.engine.captures,
            source_bytes,
            limits,
            projection_limits,
        );
        prospective.admits_construction(stream_limits)?;
        Ok(Some(prospective))
    }

    /// Prepare one reusable exact-span participation projector for a fixed
    /// complete haystack length. The caller owns this session for an entire
    /// shared multi-pattern operation, so every selected replay reuses the
    /// same bounded frontiers and tag workspace.
    #[allow(
        clippy::result_large_err,
        reason = "the pinned capture-lab error retains the exact refused resource dimension"
    )]
    pub(crate) fn prepare_exact_projection_session(
        &self,
        source_bytes: usize,
        limits: EngineSearchLimits,
        projection_limits: CaptureStreamLimits,
    ) -> Result<CaptureExactProjectionSession, CaptureStreamError> {
        let stream_limits = capture_exact_stream_limits(
            self.report.engine.states,
            self.report.engine.captures,
            source_bytes,
            limits,
            projection_limits,
        );
        if let Some(participating) = self.report.uniform_participating_captures {
            let entries = participating
                .checked_add(1)
                .and_then(|entries| u64::try_from(entries).ok())
                .ok_or(CaptureStreamError::InvalidProgram)?;
            if self.uniform_count_minimum_match_bytes.is_some() {
                return Ok(CaptureExactProjectionSession {
                    route: CaptureExactProjectionRoute::Uniform { entries },
                });
            }
            let stream = CaptureStream::new_exact(
                Arc::clone(self.engine.program()),
                source_bytes,
                stream_limits,
            )?;
            let empty_projection = stream.build_report().projection;
            return Ok(CaptureExactProjectionSession {
                route: CaptureExactProjectionRoute::UniformWithEmpty {
                    entries,
                    empty_span_stream: stream,
                    empty_projection,
                },
            });
        }
        let stream = CaptureStream::new_exact(
            Arc::clone(self.engine.program()),
            source_bytes,
            stream_limits,
        )?;
        let projection = stream.build_report().projection;
        match projection {
            CaptureStreamProjection::ParticipationMask
                if self.report.participation_quotient_proof().is_some() =>
            {
                Ok(CaptureExactProjectionSession {
                    route: CaptureExactProjectionRoute::Mask { stream },
                })
            }
            CaptureStreamProjection::PersistentHistory
                if self.report.participation_quotient_proof().is_none() =>
            {
                Ok(CaptureExactProjectionSession {
                    route: CaptureExactProjectionRoute::PersistentHistory { stream },
                })
            }
            _ => Err(CaptureStreamError::InvalidProgram),
        }
    }

    /// Optional generic line-candidate proof built from this exact capture HIR.
    #[must_use]
    pub const fn required_literal_plan(&self) -> Option<&CaptureRequiredLiteralPlan> {
        self.required_literal.as_ref()
    }

    /// Optional construction proof for concatenating independent positive-width
    /// domains with a non-consuming ASCII separator.
    #[must_use]
    pub const fn line_batch_proof(&self) -> Option<CaptureLineBatchProof> {
        self.report.plan_identity.line_batch
    }

    /// Exact cache identity for these execution limits.
    #[must_use]
    pub fn cache_identity(&self, run_limits: CaptureRunLimits) -> CaptureCacheIdentity {
        CaptureCacheIdentity {
            plan: self.report.plan_identity.clone(),
            build_limits: self.build_limits,
            run_limits,
            count_seal: self
                .count_owner
                .as_ref()
                .map(|owner| owner.for_limits(&run_limits)),
        }
    }

    /// Construction-selected fused projection for one LF/CRLF line operation.
    ///
    /// The ordinary positive-width uniform Count artifact keeps its existing
    /// sealed selector route. A line operation may additionally select the
    /// reusable stream because its fixed participation theorem makes tag
    /// projection source-independent; this does not relabel the ordinary
    /// Count route or its owner receipt.
    #[must_use]
    pub fn line_stream_projection(&self) -> Option<CaptureStreamProjection> {
        match self.report.plan_identity.plan {
            CapturePlanKind::FusedCaptureStreamParticipationV1 => {
                Some(CaptureStreamProjection::ParticipationMask)
            }
            CapturePlanKind::FusedCaptureStreamPersistentHistoryV1 => {
                Some(CaptureStreamProjection::PersistentHistory)
            }
            CapturePlanKind::LinearSelectorUniformParticipation
                if self.uniform_count_minimum_match_bytes.is_some() =>
            {
                CaptureStream::prospective(self.engine.program(), 0)
                    .ok()
                    .map(|prospective| prospective.projection)
            }
            CapturePlanKind::OrderedRootCaptureManyCount
            | CapturePlanKind::UniformPrefixClassParticipation
            | CapturePlanKind::LinearSelectorUniformParticipation
            | CapturePlanKind::LinearSelectorParticipationQuotientV1
            | CapturePlanKind::LinearSelectorPersistentHistory => None,
        }
    }

    /// Source-free line-stream operation envelope when every fixed-program
    /// construction and restart dimension fits this exact invocation.
    /// `Ok(None)` is the declared prepublication fallback edge to the retained
    /// per-line selector route.
    pub fn line_stream_operation_prospective(
        &self,
        source_bytes: usize,
        limits: CaptureRunLimits,
    ) -> Result<Option<CaptureStreamOperationProspective>, CaptureStreamError> {
        let Some(expected_projection) = self.line_stream_projection() else {
            return Ok(None);
        };
        let Some((stream_limits, _)) = self.capture_stream_limits(source_bytes, &limits) else {
            return Ok(None);
        };
        let prospective = CaptureStream::operation_prospective(
            self.engine.program(),
            source_bytes,
            CaptureStreamDomains::RebarLines,
        )?;
        if prospective.construction.projection != expected_projection
            || !prospective.authenticates_program(self.engine.program())
        {
            return Err(CaptureStreamError::InvalidProgram);
        }
        Ok(prospective
            .admits(stream_limits)
            .is_ok()
            .then_some(prospective))
    }

    /// Backwards-compatible construction receipt for an admitted line stream.
    ///
    /// New callers that need the complete restart/resource receipt should use
    /// [`Self::line_stream_operation_prospective`].
    pub fn line_stream_prospective(
        &self,
        source_bytes: usize,
        limits: CaptureRunLimits,
    ) -> Result<Option<CaptureStreamProspective>, CaptureStreamError> {
        self.line_stream_operation_prospective(source_bytes, limits)
            .map(|operation| operation.map(|operation| operation.construction))
    }

    /// Prepare a reusable caller-owned fused stream before any source byte is
    /// observed. A `None` result is the declared source-free fallback edge;
    /// a returned session never allocates or switches routes while executing.
    #[allow(
        clippy::result_large_err,
        reason = "the established public preparation error preserves complete source receipts without an API-breaking box"
    )]
    pub fn prepare_capture_stream_session(
        &self,
        source_bytes: usize,
        limits: CaptureRunLimits,
        domains: CaptureStreamDomains,
    ) -> Result<Option<CaptureStreamSession>, CaptureExecutionError> {
        self.prepare_capture_stream_session_mode(source_bytes, limits, domains, false)
    }

    /// Prepare a whole-haystack Count session, admitting the bounded
    /// participation cache when the restarted receipt is too pessimistic.
    ///
    /// A cache-only session supports [`CaptureStreamSession::count_value`].
    /// It returns a typed terminal on resource exhaustion or fixed-cache
    /// saturation and never replays the restarted executor after observing
    /// source bytes.
    #[allow(
        clippy::result_large_err,
        reason = "the established public preparation error preserves complete source receipts without an API-breaking box"
    )]
    pub fn prepare_capture_count_stream_session(
        &self,
        source_bytes: usize,
        limits: CaptureRunLimits,
    ) -> Result<Option<CaptureStreamSession>, CaptureExecutionError> {
        self.prepare_capture_stream_session_mode(
            source_bytes,
            limits,
            CaptureStreamDomains::Whole,
            true,
        )
    }

    #[allow(
        clippy::large_types_passed_by_value,
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "the private mode-neutral preparation transaction preserves the public by-value limits and complete error receipt"
    )]
    fn prepare_capture_stream_session_mode(
        &self,
        source_bytes: usize,
        limits: CaptureRunLimits,
        domains: CaptureStreamDomains,
        allow_cached_value_only: bool,
    ) -> Result<Option<CaptureStreamSession>, CaptureExecutionError> {
        let identity = self.cache_identity(limits);
        let expected_projection = self.capture_stream_session_projection(&identity, domains);
        let Some(expected_projection) = expected_projection else {
            return Ok(None);
        };
        let Some((stream_limits, selector_retained_bytes)) =
            self.capture_stream_limits(source_bytes, &limits)
        else {
            return Ok(None);
        };
        let operation =
            CaptureStream::operation_prospective(self.engine.program(), source_bytes, domains)
                .map_err(|source| CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::Stream(source),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
        if operation.construction.projection != expected_projection
            || !operation.authenticates_program(self.engine.program())
        {
            return Err(CaptureExecutionError {
                identity,
                source: CaptureExecutionSource::InternalInvariant(
                    "capture stream operation prospective diverged from its program/route identity",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            });
        }
        let restarted_admitted = operation.admits(stream_limits).is_ok();
        let cached_value_only = !restarted_admitted
            && allow_cached_value_only
            && domains == CaptureStreamDomains::Whole
            && expected_projection == CaptureStreamProjection::ParticipationMask
            && operation
                .construction
                .admits_construction(stream_limits)
                .is_ok();
        if !restarted_admitted && !cached_value_only {
            return Ok(None);
        }
        let Some(combined_peak_bytes) = operation
            .construction
            .combined_peak_bytes
            .checked_add(selector_retained_bytes)
        else {
            return Ok(None);
        };
        if combined_peak_bytes > limits.max_combined_peak_bytes {
            return Ok(None);
        }
        let constructed = if cached_value_only {
            CaptureStream::new_cached_value(
                Arc::clone(self.engine.program()),
                source_bytes,
                stream_limits,
            )
        } else {
            CaptureStream::new(
                Arc::clone(self.engine.program()),
                source_bytes,
                domains,
                stream_limits,
            )
        };
        let stream = match constructed {
            Ok(stream) => stream,
            Err(CaptureStreamError::Resource { .. } | CaptureStreamError::Allocation(_)) => {
                return Ok(None);
            }
            Err(source) => {
                return Err(CaptureExecutionError {
                    identity,
                    source: CaptureExecutionSource::Stream(source),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                });
            }
        };
        if stream.build_report() != operation.construction
            || stream.operation_report() != operation
            || stream.is_cached_value_only() != cached_value_only
            || !stream
                .build_report()
                .authenticates_program(self.engine.program())
        {
            return Err(CaptureExecutionError {
                identity,
                source: CaptureExecutionSource::InternalInvariant(
                    "capture stream session construction diverged from its prospective",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            });
        }
        Ok(Some(CaptureStreamSession {
            stream,
            program: Arc::clone(self.engine.program()),
            identity,
            domains,
            expected_projection,
            stream_limits,
            selector_retained_bytes,
            combined_peak_bytes,
        }))
    }

    fn capture_stream_session_projection(
        &self,
        identity: &CaptureCacheIdentity,
        domains: CaptureStreamDomains,
    ) -> Option<CaptureStreamProjection> {
        match domains {
            CaptureStreamDomains::Whole
                if matches!(
                    identity.plan.plan,
                    CapturePlanKind::FusedCaptureStreamParticipationV1
                        | CapturePlanKind::FusedCaptureStreamPersistentHistoryV1
                ) =>
            {
                self.line_stream_projection()
            }
            CaptureStreamDomains::Whole => None,
            CaptureStreamDomains::RebarLines => self.line_stream_projection(),
        }
    }

    /// Authenticate the complete fused success, including exact program,
    /// invocation limits, domain, retained selector bytes and outer peak.
    #[must_use]
    pub fn authenticates_capture_stream_success(
        &self,
        source_bytes: usize,
        limits: CaptureRunLimits,
        domains: CaptureStreamDomains,
        result: &CaptureExecutionReport,
    ) -> bool {
        let Some(expected_projection) = self.line_stream_projection() else {
            return false;
        };
        let Some((expected_limits, selector_fallback_bytes)) =
            self.capture_stream_limits(source_bytes, &limits)
        else {
            return false;
        };
        let Some(stream) = result.capture_stream.as_ref() else {
            return false;
        };
        let expected_peak = stream
            .combined_peak_bytes
            .checked_add(selector_fallback_bytes);
        result.identity == self.cache_identity(limits)
            && stream.domains == domains
            && stream.limits == expected_limits
            && stream.prospective.projection == expected_projection
            && stream.prospective.source_bytes == source_bytes
            && CaptureStream::operation_prospective(self.engine.program(), source_bytes, domains)
                .is_ok_and(|expected| stream.operation == expected)
            && stream.authenticates_program(self.engine.program())
            && stream.captures == result.accounting
            && stream.capture_events == result.capture_events
            && expected_peak == Some(result.combined_peak_bytes)
            && result.selector_certificate.is_none()
            && result.selector_accounting.is_none()
            && result.selector_receipt.is_none()
            && result.prefix_class_participation.is_none()
            && result.prefix_class_participation_receipt.is_none()
            && result.count_receipt.is_none()
    }

    fn capture_stream_limits(
        &self,
        source_bytes: usize,
        limits: &CaptureRunLimits,
    ) -> Option<(CaptureStreamLimits, usize)> {
        let selector_fallback_bytes = self.report.selector.program_bytes;
        let workspace_peak_limit = limits
            .max_combined_peak_bytes
            .checked_sub(selector_fallback_bytes)?;
        Some((
            CaptureStreamLimits {
                max_source_bytes: source_bytes,
                max_states: self.report.engine.states,
                max_build_work: limits.aggregate.max_total_state_visits,
                max_persistent_bytes: workspace_peak_limit,
                max_combined_peak_bytes: workspace_peak_limit,
                max_allocations: 16,
                max_line_domains: limits.aggregate.max_searches,
                max_searches: limits.aggregate.max_searches,
                max_matches: limits.aggregate.max_results,
                max_bytes_examined: limits.selector.max_sequential_bytes,
                max_starts_injected: limits.selector.max_work,
                max_state_visits: limits.aggregate.max_total_state_visits,
                max_tag_actions: limits.aggregate.max_total_state_visits,
                max_history_nodes: limits.aggregate.max_total_history_nodes,
                max_history_walk: limits.aggregate.max_total_history_walk,
                max_history_reads: limits.selector.max_work,
                max_materialization_reads: limits.selector.max_work,
                max_materialization_writes: limits.selector.max_work,
                max_materialization_preview_writes: limits.selector.max_work,
                max_mask_states: limits.selector.max_work,
                max_mask_word_copies: limits.selector.max_work,
                max_mask_word_reads: limits.selector.max_work,
                max_reset_cells: limits.selector.max_work,
                max_capture_events: limits.aggregate.max_capture_events,
                max_capture_count: limits.aggregate.max_capture_count,
                max_line_source_reads: limits.selector.max_sequential_bytes,
                max_work: limits.selector.max_work,
            },
            selector_fallback_bytes,
        ))
    }

    /// Complete identity for one bounded capture-iteration invocation.
    #[must_use]
    pub fn iteration_identity(&self, run_limits: AggregateLimits) -> CaptureIterationIdentity {
        self.iteration_identity_with_config(run_limits, CaptureSearchConfig::LEFTMOST)
    }

    /// Complete identity for one bounded capture-iteration invocation under
    /// an explicit search policy.
    #[must_use]
    pub fn iteration_identity_with_config(
        &self,
        run_limits: AggregateLimits,
        search: CaptureSearchConfig,
    ) -> CaptureIterationIdentity {
        CaptureIterationIdentity {
            syntax: Arc::clone(&self.report.plan_identity.syntax),
            capture_profile: self.report.plan_identity.capture_profile,
            plan: CaptureIterationPlanKind::RestartedPersistentHistory,
            search,
            build_limits: self.build_limits,
            run_limits,
            session_seal: self.iteration_owner.for_invocation(search, run_limits),
        }
    }

    /// Return the first leftmost-first capture record under explicit
    /// per-search limits, together with exact execution accounting.
    pub fn captures(
        &self,
        haystack: &[u8],
        limits: EngineSearchLimits,
    ) -> Result<EngineSearchOutcome, EngineSearchError> {
        self.captures_with_config(haystack, CaptureSearchConfig::LEFTMOST, limits)
    }

    /// Return the first capture record under explicit match-end,
    /// match-priority and start-injection policies.
    pub fn captures_with_config(
        &self,
        haystack: &[u8],
        config: CaptureSearchConfig,
        limits: EngineSearchLimits,
    ) -> Result<EngineSearchOutcome, EngineSearchError> {
        self.captures_window_with_config(haystack, Window::all(haystack), config, limits)
    }

    /// Return the first capture record inside `window` under an explicit
    /// match-end selection and start-injection policy. Consuming transitions
    /// stay inside the window while assertions retain original-haystack
    /// context.
    pub fn captures_window_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        config: CaptureSearchConfig,
        limits: EngineSearchLimits,
    ) -> Result<EngineSearchOutcome, EngineSearchError> {
        self.engine
            .captures_with_config(haystack, window, config, limits)
    }

    /// Query whether `span` is an exact match inside `window`, returning its
    /// prioritized captures when it is. Construction-eligible plans use the
    /// complete one-pass capture DFA; construction, exact-bound, or workspace
    /// refusal stays on exact persistent history before source access. An
    /// ordinary non-match is a successful outcome with no capture record.
    pub fn captures_exact_window(
        &self,
        haystack: &[u8],
        window: Window,
        span: EngineSpan,
        limits: EngineSearchLimits,
    ) -> Result<EngineSearchOutcome, EngineSearchError> {
        if let Some(plan) = &self.onepass_capture {
            debug_assert_eq!(
                self.report.onepass_capture.as_ref(),
                Some(&CaptureOnePassBuildReport::from_engine(plan.build_report()))
            );
            if onepass_capture_admits_exact(plan, span, limits) {
                if let Some(outcome) =
                    plan.try_captures_exact_inline(haystack, window, span, limits)?
                {
                    return Ok(outcome);
                }
                if let Ok(mut workspace) = plan.create_workspace(limits) {
                    return plan.captures_exact(&mut workspace, haystack, window, span, limits);
                }
            }
        }
        self.engine.captures_exact(haystack, window, span, limits)
    }

    /// Collect every non-overlapping leftmost-first match and every capture
    /// slot, including empty participating spans and explicit unmatched slots.
    ///
    /// This bounded persistent-history formulation can restart at successive
    /// match boundaries. It is the correctness path for materialized capture
    /// records; the existing selector/replay reducer remains the linear path
    /// for participation counts.
    pub fn captures_iter(
        &self,
        haystack: &[u8],
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, CaptureIterationError> {
        self.captures_iter_window_with_config(
            haystack,
            Window::all(haystack),
            CaptureSearchConfig::LEFTMOST,
            limits,
        )
    }

    /// Collect every match wholly inside `window` while retaining assertion
    /// context from the original haystack.
    pub fn captures_iter_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, CaptureIterationError> {
        self.captures_iter_window_with_config(
            haystack,
            window,
            CaptureSearchConfig::LEFTMOST,
            limits,
        )
    }

    /// Collect every match under explicit match-end, match-priority and
    /// start-injection policies.
    #[allow(
        clippy::too_many_lines,
        reason = "pre-source publication, charged terminal accounting, retained-output accounting, and Rust empty-progress semantics stay in one auditable owner-local session"
    )]
    pub fn captures_iter_window_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        config: CaptureSearchConfig,
        limits: AggregateLimits,
    ) -> Result<CaptureIterationReport, CaptureIterationError> {
        let identity = self.iteration_identity_with_config(limits, config);
        let mut actual = CaptureIterationActual::default();
        let prospective = identity
            .session_seal
            .prospective(haystack.len(), window)
            .map_err(|source| capture_iteration_failure(&identity, source, None, actual))?;
        if let Some(source) = prospective.first_limit_error(limits) {
            return Err(capture_iteration_failure(
                &identity,
                source,
                Some(prospective),
                actual,
            ));
        }
        let shape = self.iteration_owner.identity().engine_shape;
        let materialized_record_bytes = shape.materialized_record_bytes().map_err(|source| {
            capture_iteration_failure(&identity, source, Some(prospective), actual)
        })?;
        let retained_record_bytes = shape.retained_record_bytes().map_err(|source| {
            capture_iteration_failure(&identity, source, Some(prospective), actual)
        })?;
        let minimum_match_bytes = self.iteration_owner.identity().minimum_match_bytes;
        let maximum_start = (config == CaptureSearchConfig::LEFTMOST && minimum_match_bytes > 0)
            .then(|| window.end.checked_sub(minimum_match_bytes));
        let start_classifier = (config == CaptureSearchConfig::LEFTMOST && minimum_match_bytes > 0)
            .then(|| self.iteration_owner.start_classifier_receipt().classifier())
            .flatten();

        let mut captures = Vec::new();
        let mut total_state_visits = 0_usize;
        let total_slot_copies = 0_usize;
        let mut total_history_nodes = 0_usize;
        let mut total_history_walk = 0_usize;
        let mut peak_threads = 0_usize;
        let mut peak_scratch_bytes = 0_usize;
        let mut cursor = window.start;
        let mut last_match_end = None;
        loop {
            let search_prospective =
                self.engine
                    .search_prospective(window, cursor)
                    .map_err(|source| {
                        capture_iteration_failure(&identity, source, Some(prospective), actual)
                    })?;
            let mut charged = actual;
            charged
                .charge_search(search_prospective)
                .map_err(|source| {
                    capture_iteration_failure(&identity, source, Some(prospective), actual)
                })?;
            if !prospective.contains(charged) {
                return Err(capture_iteration_failure(
                    &identity,
                    EngineSearchError::InvalidProgram,
                    Some(prospective),
                    actual,
                ));
            }
            actual = charged;

            let mut per_search = limits.per_search;
            per_search.max_state_visits = per_search.max_state_visits.min(
                limits
                    .max_total_state_visits
                    .checked_sub(total_state_visits)
                    .ok_or_else(|| {
                        capture_iteration_failure(
                            &identity,
                            EngineSearchError::BoundOverflow(EngineResource::AggregateStateVisits),
                            Some(prospective),
                            actual,
                        )
                    })?,
            );
            per_search.max_history_nodes = per_search.max_history_nodes.min(
                limits
                    .max_total_history_nodes
                    .checked_sub(total_history_nodes)
                    .ok_or_else(|| {
                        capture_iteration_failure(
                            &identity,
                            EngineSearchError::BoundOverflow(EngineResource::AggregateHistoryNodes),
                            Some(prospective),
                            actual,
                        )
                    })?,
            );
            per_search.max_history_walk = per_search.max_history_walk.min(
                limits
                    .max_total_history_walk
                    .checked_sub(total_history_walk)
                    .ok_or_else(|| {
                        capture_iteration_failure(
                            &identity,
                            EngineSearchError::BoundOverflow(EngineResource::AggregateHistoryWalk),
                            Some(prospective),
                            actual,
                        )
                    })?,
            );

            let outcome = if let (Some(maximum_start), Some(start_classifier)) =
                (maximum_start, start_classifier)
            {
                // The opaque first-byte proof was returned atomically with the
                // same program, then selected only after incumbent one-pass
                // construction. Exact set equality makes this restricted root
                // domain equivalent for an ordinary positive-width LEFTMOST
                // search; already-live threads remain unrestricted.
                self.engine
                    .captures_from_with_config_start_ceiling_filtered(
                        haystack,
                        window,
                        cursor,
                        config,
                        maximum_start,
                        start_classifier,
                        per_search,
                    )
            } else if let Some(maximum_start) = maximum_start {
                // The immutable iteration owner binds this byte minimum to the
                // same canonical HIR and engine program. Therefore no complete
                // match can begin after this inclusive ceiling. The low-level
                // engine operation itself promises only restricted-start
                // semantics; this owner supplies the full-search equivalence.
                self.engine.captures_from_with_config_start_ceiling(
                    haystack,
                    window,
                    cursor,
                    config,
                    maximum_start,
                    per_search,
                )
            } else {
                self.engine
                    .captures_from_with_config(haystack, window, cursor, config, per_search)
            }
            .map_err(|source| {
                capture_iteration_failure(&identity, source, Some(prospective), actual)
            })?;
            if !capture_iteration_search_fits(search_prospective, &outcome.report) {
                return Err(capture_iteration_failure(
                    &identity,
                    EngineSearchError::InvalidProgram,
                    Some(prospective),
                    actual,
                ));
            }
            total_state_visits = capture_iteration_exact_add(
                total_state_visits,
                outcome.report.state_visits,
                EngineResource::AggregateStateVisits,
                limits.max_total_state_visits,
            )
            .map_err(|source| {
                capture_iteration_failure(&identity, source, Some(prospective), actual)
            })?;
            total_history_nodes = capture_iteration_exact_add(
                total_history_nodes,
                outcome.report.history_nodes,
                EngineResource::AggregateHistoryNodes,
                limits.max_total_history_nodes,
            )
            .map_err(|source| {
                capture_iteration_failure(&identity, source, Some(prospective), actual)
            })?;
            total_history_walk = capture_iteration_exact_add(
                total_history_walk,
                outcome.report.history_walk,
                EngineResource::AggregateHistoryWalk,
                limits.max_total_history_walk,
            )
            .map_err(|source| {
                capture_iteration_failure(&identity, source, Some(prospective), actual)
            })?;
            peak_threads = peak_threads.max(outcome.report.peak_threads);
            peak_scratch_bytes = peak_scratch_bytes.max(outcome.report.admitted_scratch_bytes);

            let Some(record) = outcome.captures else {
                break;
            };
            let mut materialized = actual;
            materialized
                .record_materialized(
                    shape.groups,
                    materialized_record_bytes,
                    search_prospective.scratch_bytes,
                )
                .map_err(|source| {
                    capture_iteration_failure(&identity, source, Some(prospective), actual)
                })?;
            if !prospective.contains(materialized) {
                return Err(capture_iteration_failure(
                    &identity,
                    EngineSearchError::InvalidProgram,
                    Some(prospective),
                    actual,
                ));
            }
            actual = materialized;
            let overall = record.overall().ok_or_else(|| {
                capture_iteration_failure(
                    &identity,
                    EngineSearchError::InvalidProgram,
                    Some(prospective),
                    actual,
                )
            })?;
            if overall.start == overall.end && last_match_end == Some(overall.start) {
                if overall.end == window.end {
                    break;
                }
                cursor = overall.end.checked_add(1).ok_or_else(|| {
                    capture_iteration_failure(
                        &identity,
                        EngineSearchError::BoundOverflow(EngineResource::Searches),
                        Some(prospective),
                        actual,
                    )
                })?;
                continue;
            }
            let mut retained = actual;
            retained
                .record_result(retained_record_bytes)
                .map_err(|source| {
                    capture_iteration_failure(&identity, source, Some(prospective), actual)
                })?;
            if !prospective.contains(retained) {
                return Err(capture_iteration_failure(
                    &identity,
                    EngineSearchError::InvalidProgram,
                    Some(prospective),
                    actual,
                ));
            }
            captures.try_reserve_exact(1).map_err(|_| {
                capture_iteration_failure(
                    &identity,
                    EngineSearchError::Allocation(EngineResource::RetainedOutputBytes),
                    Some(prospective),
                    actual,
                )
            })?;
            actual = retained;
            captures.push(record);
            // Every accepting path requires the absolute start of the original
            // haystack, so no later non-overlapping record can exist after this one.
            if self.record_search_absolute_start {
                break;
            }
            last_match_end = Some(overall.end);
            if overall.start == overall.end {
                if overall.end == window.end {
                    break;
                }
                cursor = overall.end.checked_add(1).ok_or_else(|| {
                    capture_iteration_failure(
                        &identity,
                        EngineSearchError::BoundOverflow(EngineResource::Searches),
                        Some(prospective),
                        actual,
                    )
                })?;
            } else {
                cursor = overall.end;
            }
        }
        let session_receipt = CaptureIterationAttemptReceipt::success(prospective, actual);
        if !session_receipt.closes(&identity.session_seal) {
            return Err(capture_iteration_failure(
                &identity,
                EngineSearchError::InvalidProgram,
                Some(prospective),
                actual,
            ));
        }
        Ok(CaptureIterationReport {
            identity,
            captures,
            searches: actual.searches,
            total_state_visits,
            total_slot_copies,
            total_history_nodes,
            total_history_walk,
            capture_events: actual.capture_events,
            peak_threads,
            peak_scratch_bytes,
            retained_output_bytes: actual.retained_output_bytes,
            combined_peak_bytes: actual.combined_peak_bytes,
            session_receipt,
        })
    }

    /// Reduce all non-overlapping non-empty matches over the complete byte haystack.
    #[allow(
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "selector, replay, and complete checked reducer accounting stay locally auditable; terminal errors retain the allocation-free Count P/A receipt inline"
    )]
    pub fn count_captures(
        &self,
        haystack: &[u8],
        limits: CaptureRunLimits,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        self.count_captures_with_selector_work(haystack, limits, false)
    }

    /// Execute Count with exact observed selector-work admission. This is used
    /// by a construction-certified independent-domain batch whose selector
    /// economics can prefer the bounded frontier cache without changing the
    /// ordinary Count route.
    #[doc(hidden)]
    pub fn count_captures_observed_selector(
        &self,
        haystack: &[u8],
        limits: CaptureRunLimits,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        self.count_captures_with_selector_work(haystack, limits, true)
    }

    fn count_captures_with_selector_work(
        &self,
        haystack: &[u8],
        limits: CaptureRunLimits,
        observed_selector: bool,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        let identity = self.cache_identity(limits);
        let mut selector_limits = limits.selector;
        selector_limits.max_peak_bytes = selector_limits
            .max_peak_bytes
            .min(limits.max_combined_peak_bytes);
        if let Some(plan) = &self.prefix_class_participation {
            return self.count_prefix_class_participation(
                plan,
                haystack,
                limits,
                selector_limits,
                identity,
            );
        }
        if let Some(participating) = self.report.uniform_participating_captures {
            if let Some(minimum_match_bytes) = self.uniform_count_minimum_match_bytes {
                return self.count_uniform_captures(
                    haystack,
                    limits,
                    selector_limits,
                    identity,
                    participating,
                    minimum_match_bytes,
                );
            }
            let selected = self
                .selector
                .admit_spans_observed(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                )
                .map_err(|source| CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::Selector(source),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
            let selector_accounting = selected.accounting();
            let mut matches = 0_usize;
            for span in selected.as_slice() {
                if span.start == span.end {
                    return Err(Self::history_error(
                        &identity,
                        EngineSearchError::EmptyMatch,
                    ));
                }
                matches = checked_capture_add(
                    &identity,
                    matches,
                    1,
                    EngineResource::Results,
                    limits.aggregate.max_results,
                )?;
            }
            let participating_with_overall =
                participating
                    .checked_add(1)
                    .ok_or_else(|| CaptureExecutionError {
                        identity: identity.clone(),
                        source: CaptureExecutionSource::InternalInvariant(
                            "uniform capture participation overflowed usize",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    })?;
            let count = checked_capture_mul(
                &identity,
                matches,
                participating_with_overall,
                EngineResource::CaptureCount,
                limits.aggregate.max_capture_count,
            )?;
            let all_groups = self.report.engine.captures.checked_add(1).ok_or_else(|| {
                CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::InternalInvariant(
                        "capture schema overflowed usize",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                }
            })?;
            let capture_events = checked_capture_mul(
                &identity,
                matches,
                all_groups,
                EngineResource::CaptureEvents,
                limits.aggregate.max_capture_events,
            )?;
            return Ok(CaptureExecutionReport {
                identity,
                accounting: CaptureCountOutcome {
                    count,
                    matches,
                    searches: 0,
                    total_state_visits: 0,
                    total_history_nodes: 0,
                    total_history_walk: 0,
                    peak_threads: 0,
                },
                selector_certificate: Some(selected.certificate().clone()),
                selector_accounting: Some(selector_accounting),
                selector_receipt: None,
                prefix_class_participation: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
                capture_stream: None,
                capture_events,
                combined_peak_bytes: selector_accounting.peak_bytes,
            });
        }
        self.count_nonuniform_captures(
            haystack,
            &limits,
            selector_limits,
            identity,
            observed_selector,
        )
    }

    #[allow(
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "the nonuniform selector and exact-span replay retain one contiguous checked accounting transaction"
    )]
    fn count_nonuniform_captures(
        &self,
        haystack: &[u8],
        limits: &CaptureRunLimits,
        selector_limits: SelectorOperationLimits,
        identity: CaptureCacheIdentity,
        observed_selector: bool,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        let use_participation_quotient = match identity.plan.plan {
            CapturePlanKind::LinearSelectorParticipationQuotientV1
            | CapturePlanKind::FusedCaptureStreamParticipationV1 => {
                let Some(proof) = self.report.participation_quotient_proof() else {
                    return Err(CaptureExecutionError {
                        identity,
                        source: CaptureExecutionSource::InternalInvariant(
                            "participation quotient lost its construction proof",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    });
                };
                if usize::from(proof.user_captures) != self.report.engine.captures
                    || usize::from(proof.user_captures) > PARTICIPATION_QUOTIENT_CAPTURE_BITS
                    || proof.mask_bits != PARTICIPATION_QUOTIENT_MASK_BITS
                    || proof.reserved_overall_bits != 1
                    || proof.state_masks != 2
                    || proof.retained_offsets != 0
                    || proof.algorithm_version != PARTICIPATION_QUOTIENT_ALGORITHM_VERSION
                    || proof.accounting_version != PARTICIPATION_QUOTIENT_ACCOUNTING_VERSION
                    || proof.declared_prepublication_fallback
                        != CaptureParticipationQuotientFallback::PersistentHistory
                {
                    return Err(CaptureExecutionError {
                        identity,
                        source: CaptureExecutionSource::InternalInvariant(
                            "participation quotient proof diverged from its compiled schema",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    });
                }
                true
            }
            CapturePlanKind::LinearSelectorPersistentHistory
            | CapturePlanKind::FusedCaptureStreamPersistentHistoryV1 => {
                if self.report.participation_quotient_proof().is_some()
                    || self.report.engine.captures <= PARTICIPATION_QUOTIENT_CAPTURE_BITS
                {
                    return Err(CaptureExecutionError {
                        identity,
                        source: CaptureExecutionSource::InternalInvariant(
                            "persistent-history fallback diverged from quotient eligibility",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    });
                }
                false
            }
            CapturePlanKind::OrderedRootCaptureManyCount
            | CapturePlanKind::UniformPrefixClassParticipation
            | CapturePlanKind::LinearSelectorUniformParticipation => {
                return Err(CaptureExecutionError {
                    identity,
                    source: CaptureExecutionSource::InternalInvariant(
                        "nonuniform Count reached an incompatible compiled plan",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                });
            }
        };
        let selected = if observed_selector {
            self.selector.admit_spans_observed_cached_when_amortized(
                haystack,
                0..haystack.len(),
                SelectorStrategy::ReverseSequentialRows,
                selector_limits,
            )
        } else {
            self.selector.admit_spans(
                haystack,
                0..haystack.len(),
                SelectorStrategy::ReverseSequentialRows,
                selector_limits,
            )
        }
        .map_err(|source| CaptureExecutionError {
            identity: identity.clone(),
            source: CaptureExecutionSource::Selector(source),
            selector_receipt: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
        })?;
        let selector_accounting = selected.accounting();
        let replay_scratch_limit = limits
            .max_combined_peak_bytes
            .checked_sub(selector_accounting.output_bytes)
            .ok_or_else(|| CaptureExecutionError {
                identity: identity.clone(),
                source: CaptureExecutionSource::InternalInvariant(
                    "selector output exceeded the admitted combined peak",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            })?;
        let mut combined_peak_bytes = selector_accounting.peak_bytes;
        let mut accounting = CaptureCountOutcome {
            count: 0,
            matches: 0,
            searches: 0,
            total_state_visits: 0,
            total_history_nodes: 0,
            total_history_walk: 0,
            peak_threads: 0,
        };
        let mut capture_events = 0_usize;
        let all_groups =
            self.report
                .engine
                .captures
                .checked_add(1)
                .ok_or_else(|| CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::InternalInvariant(
                        "capture schema overflowed usize",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
        let window = Window::all(haystack);
        let mut participation_workspace = None;
        for selected_span in selected.as_slice() {
            if selected_span.start == selected_span.end {
                return Err(Self::history_error(
                    &identity,
                    EngineSearchError::EmptyMatch,
                ));
            }
            accounting.searches = checked_capture_add(
                &identity,
                accounting.searches,
                1,
                EngineResource::Searches,
                limits.aggregate.max_searches,
            )?;
            accounting.matches = checked_capture_add(
                &identity,
                accounting.matches,
                1,
                EngineResource::Results,
                limits.aggregate.max_results,
            )?;
            let mut per_search = limits.aggregate.per_search;
            per_search.max_scratch_bytes = per_search.max_scratch_bytes.min(replay_scratch_limit);
            per_search.max_state_visits = per_search.max_state_visits.min(capture_remaining(
                &identity,
                limits.aggregate.max_total_state_visits,
                accounting.total_state_visits,
                EngineResource::AggregateStateVisits,
            )?);
            per_search.max_history_nodes = per_search.max_history_nodes.min(capture_remaining(
                &identity,
                limits.aggregate.max_total_history_nodes,
                accounting.total_history_nodes,
                EngineResource::AggregateHistoryNodes,
            )?);
            per_search.max_history_walk = per_search.max_history_walk.min(capture_remaining(
                &identity,
                limits.aggregate.max_total_history_walk,
                accounting.total_history_walk,
                EngineResource::AggregateHistoryWalk,
            )?);
            let span = EngineSpan {
                start: selected_span.start,
                end: selected_span.end,
            };
            let (participation_mask, capture_groups, replay_report) = if use_participation_quotient
            {
                let workspace = match &mut participation_workspace {
                    Some(workspace) => workspace,
                    slot => slot.insert(
                        self.engine
                            .prepare_participation_exact_workspace(span, per_search)
                            .map_err(|source| Self::history_error(&identity, source))?,
                    ),
                };
                let replay = self
                    .engine
                    .captures_participation_exact_with_workspace(
                        workspace, haystack, window, span, per_search,
                    )
                    .map_err(|source| Self::history_error(&identity, source))?;
                if !replay.prospective.closes_report(&replay.report) {
                    return Err(CaptureExecutionError {
                        identity,
                        source: CaptureExecutionSource::InternalInvariant(
                            "participation quotient report did not close its prospective",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    });
                }
                let participating =
                    replay
                        .participating_captures
                        .ok_or_else(|| CaptureExecutionError {
                            identity: identity.clone(),
                            source: CaptureExecutionSource::InternalInvariant(
                                "selector-certified span produced no quotient winner",
                            ),
                            selector_receipt: None,
                            prefix_class_participation_receipt: None,
                            count_receipt: None,
                        })?;
                if participating > self.report.engine.captures {
                    return Err(CaptureExecutionError {
                        identity,
                        source: CaptureExecutionSource::InternalInvariant(
                            "participation quotient exceeded the compiled capture schema",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    });
                }
                let participation_mask =
                    replay
                        .participation_mask
                        .ok_or_else(|| CaptureExecutionError {
                            identity: identity.clone(),
                            source: CaptureExecutionSource::InternalInvariant(
                                "selector-certified span produced no quotient mask",
                            ),
                            selector_receipt: None,
                            prefix_class_participation_receipt: None,
                            count_receipt: None,
                        })?;
                if all_groups > usize::from(PARTICIPATION_QUOTIENT_MASK_BITS) {
                    return Err(CaptureExecutionError {
                        identity,
                        source: CaptureExecutionSource::InternalInvariant(
                            "participation quotient exceeded its fixed mask width",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    });
                }
                let allowed_mask = if all_groups == usize::from(PARTICIPATION_QUOTIENT_MASK_BITS) {
                    u64::MAX
                } else {
                    let shift = u32::try_from(all_groups).map_err(|_| CaptureExecutionError {
                        identity: identity.clone(),
                        source: CaptureExecutionSource::InternalInvariant(
                            "participation quotient mask shift exceeded u32",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    })?;
                    1_u64
                        .checked_shl(shift)
                        .and_then(|value| value.checked_sub(1))
                        .ok_or_else(|| CaptureExecutionError {
                            identity: identity.clone(),
                            source: CaptureExecutionSource::InternalInvariant(
                                "participation quotient mask construction overflowed",
                            ),
                            selector_receipt: None,
                            prefix_class_participation_receipt: None,
                            count_receipt: None,
                        })?
                };
                let mask_participating =
                    usize::try_from((participation_mask & !1_u64).count_ones()).map_err(|_| {
                        CaptureExecutionError {
                            identity: identity.clone(),
                            source: CaptureExecutionSource::InternalInvariant(
                                "participation quotient mask count exceeded usize",
                            ),
                            selector_receipt: None,
                            prefix_class_participation_receipt: None,
                            count_receipt: None,
                        }
                    })?;
                if participation_mask & 1 == 0
                    || participation_mask & !allowed_mask != 0
                    || mask_participating != participating
                {
                    return Err(CaptureExecutionError {
                        identity,
                        source: CaptureExecutionSource::InternalInvariant(
                            "participation quotient mask diverged from the compiled schema",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    });
                }
                (Some(participation_mask), None, replay.report)
            } else {
                let replay = self
                    .engine
                    .captures_exact(haystack, window, span, per_search)
                    .map_err(|source| Self::history_error(&identity, source))?;
                let captures = replay.captures.ok_or_else(|| CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::InternalInvariant(
                        "selector-certified span produced no tagged winner",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
                if captures.groups.len() != all_groups {
                    return Err(CaptureExecutionError {
                        identity,
                        source: CaptureExecutionSource::InternalInvariant(
                            "persistent-history replay diverged from the capture schema",
                        ),
                        selector_receipt: None,
                        prefix_class_participation_receipt: None,
                        count_receipt: None,
                    });
                }
                (None, Some(captures.groups), replay.report)
            };
            let replay_combined_peak = selector_accounting
                .output_bytes
                .checked_add(replay_report.admitted_scratch_bytes)
                .ok_or_else(|| CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::InternalInvariant(
                        "combined selector/replay peak overflowed usize",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
            combined_peak_bytes = combined_peak_bytes.max(replay_combined_peak);
            accounting.total_state_visits = checked_capture_add(
                &identity,
                accounting.total_state_visits,
                replay_report.state_visits,
                EngineResource::AggregateStateVisits,
                limits.aggregate.max_total_state_visits,
            )?;
            accounting.total_history_nodes = checked_capture_add(
                &identity,
                accounting.total_history_nodes,
                replay_report.history_nodes,
                EngineResource::AggregateHistoryNodes,
                limits.aggregate.max_total_history_nodes,
            )?;
            accounting.total_history_walk = checked_capture_add(
                &identity,
                accounting.total_history_walk,
                replay_report.history_walk,
                EngineResource::AggregateHistoryWalk,
                limits.aggregate.max_total_history_walk,
            )?;
            accounting.peak_threads = accounting.peak_threads.max(replay_report.peak_threads);
            if let Some(mask) = participation_mask {
                for group_index in 0..all_groups {
                    capture_events = checked_capture_add(
                        &identity,
                        capture_events,
                        1,
                        EngineResource::CaptureEvents,
                        limits.aggregate.max_capture_events,
                    )?;
                    if mask & (1_u64 << group_index) != 0 {
                        accounting.count = checked_capture_add(
                            &identity,
                            accounting.count,
                            1,
                            EngineResource::CaptureCount,
                            limits.aggregate.max_capture_count,
                        )?;
                    }
                }
            } else {
                let groups = capture_groups.ok_or_else(|| CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::InternalInvariant(
                        "persistent-history replay lost its group participation",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
                for group in groups {
                    capture_events = checked_capture_add(
                        &identity,
                        capture_events,
                        1,
                        EngineResource::CaptureEvents,
                        limits.aggregate.max_capture_events,
                    )?;
                    if group.span.is_some() {
                        accounting.count = checked_capture_add(
                            &identity,
                            accounting.count,
                            1,
                            EngineResource::CaptureCount,
                            limits.aggregate.max_capture_count,
                        )?;
                    }
                }
            }
        }
        Ok(CaptureExecutionReport {
            identity,
            accounting,
            selector_certificate: Some(selected.certificate().clone()),
            selector_accounting: Some(selector_accounting),
            selector_receipt: None,
            prefix_class_participation: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
            capture_stream: None,
            capture_events,
            combined_peak_bytes,
        })
    }

    #[allow(
        clippy::large_types_passed_by_value,
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "the Copy run-limit snapshot and direct terminals retain the complete fixed-layout invocation and prospective inline beside source-free U3-control admission"
    )]
    fn count_prefix_class_participation(
        &self,
        plan: &CapturePrefixClassParticipationPlan,
        haystack: &[u8],
        limits: CaptureRunLimits,
        selector_limits: SelectorOperationLimits,
        identity: CaptureCacheIdentity,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        let sealed_route = identity.count_seal.as_ref().map(|seal| {
            let route = seal.route_identity();
            (
                route.branch,
                route.plan.selector_plan_id,
                route.selector_route.physical_route,
                route.selector_strategy,
                route.minimum_match_bytes,
                route.participating_captures_per_match,
                route.capture_schema_entries_per_match,
                route.retained_fallback_bytes,
                route.declared_prepublication_fallback,
                route.declared_fallback,
            )
        });
        let Some((
            CaptureCountBranch::DirectPrefixClassParticipation,
            sealed_selector_plan_id,
            fre_aggregate::OperationPhysicalRoute::DenseRows,
            SelectorStrategy::ReverseSequentialRows,
            minimum_match_bytes,
            sealed_participating,
            sealed_schema,
            retained_fallback_bytes,
            CaptureCountPrepublicationFallback::SelectorUniformParticipation,
            CaptureCountDeclaredFallback::None,
        )) = sealed_route
        else {
            return Err(CaptureExecutionError {
                identity,
                source: CaptureExecutionSource::InternalInvariant(
                    "direct prefix/class Count lost its construction owner",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            });
        };
        if sealed_participating != plan.schema.participating_with_overall
            || sealed_schema != plan.schema.capture_schema_slots
            || sealed_selector_plan_id != self.selector.plan_id()
            || self.uniform_count_minimum_match_bytes != Some(minimum_match_bytes)
        {
            return Err(CaptureExecutionError {
                identity,
                source: CaptureExecutionSource::InternalInvariant(
                    "direct Count construction owner diverged from its capture schema",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            });
        }
        let mut receipt = plan.engine.uniform_participation_attempt_receipt(
            haystack.len(),
            plan.schema,
            limits.prefix_class_participation,
        );
        let prospective = plan
            .engine
            .uniform_participation_prospective(haystack.len(), plan.schema)
            .map_err(|source| {
                Self::direct_count_error(
                    &identity,
                    CaptureExecutionSource::PrefixClassParticipation(source),
                    receipt,
                    None,
                )
            })?;
        receipt.prospective = Some(prospective);
        let selector_control = self
            .selector
            .fixed_scalar_dense_count_prospective(
                haystack.len(),
                SelectorStrategy::ReverseSequentialRows,
            )
            .map_err(|source| {
                Self::direct_count_error(
                    &identity,
                    CaptureExecutionSource::Selector(source),
                    receipt,
                    None,
                )
            })?;
        let mut owner_prospective = uniform_capture_prospective(
            &selector_control,
            haystack.len(),
            minimum_match_bytes,
            plan.schema.participating_with_overall,
            plan.schema.capture_schema_slots,
        )
        .map_err(|source| {
            Self::direct_count_error(
                &identity,
                CaptureExecutionSource::History(source),
                receipt,
                None,
            )
        })?;
        if owner_prospective.selector.terminal_frontier
            || owner_prospective.matches != prospective.results
            || owner_prospective.capture_count != prospective.capture_count
            || owner_prospective.capture_events != prospective.capture_events
        {
            return Err(Self::direct_count_error(
                &identity,
                CaptureExecutionSource::InternalInvariant(
                    "direct prefix/class envelope diverged from its retained U3 control",
                ),
                receipt,
                None,
            ));
        }
        let observed_retained_fallback_bytes = self
            .report
            .engine
            .program_bytes
            .checked_add(self.report.selector.program_bytes)
            .ok_or_else(|| {
                Self::direct_count_error(
                    &identity,
                    CaptureExecutionSource::InternalInvariant(
                        "capture retained fallback bytes overflowed usize",
                    ),
                    receipt,
                    None,
                )
            })?;
        if observed_retained_fallback_bytes != retained_fallback_bytes {
            return Err(Self::direct_count_error(
                &identity,
                CaptureExecutionSource::InternalInvariant(
                    "direct Count owner diverged from retained fallback storage",
                ),
                receipt,
                None,
            ));
        }
        let direct_peak_bytes = retained_fallback_bytes
            .checked_add(prospective.peak_bytes)
            .ok_or_else(|| {
                Self::direct_count_error(
                    &identity,
                    CaptureExecutionSource::InternalInvariant(
                        "capture direct co-live peak overflowed usize",
                    ),
                    receipt,
                    None,
                )
            })?;
        let combined_peak_bytes = direct_peak_bytes.max(owner_prospective.selector.peak_bytes);
        owner_prospective.direct = Some(prospective);
        owner_prospective.allocations = prospective.operation_allocations;
        owner_prospective.combined_peak_bytes = combined_peak_bytes;
        plan.engine
            .enforce_uniform_participation(prospective, limits.prefix_class_participation)
            .map_err(|source| {
                Self::direct_count_error(
                    &identity,
                    CaptureExecutionSource::PrefixClassParticipation(source),
                    receipt,
                    Some(&owner_prospective),
                )
            })?;
        enforce_uniform_capture_prospective(&owner_prospective, limits.aggregate).map_err(
            |source| {
                Self::direct_count_error(
                    &identity,
                    CaptureExecutionSource::History(source),
                    receipt,
                    Some(&owner_prospective),
                )
            },
        )?;
        if combined_peak_bytes > limits.max_combined_peak_bytes {
            return Err(Self::direct_count_error(
                &identity,
                CaptureExecutionSource::CombinedPeak {
                    needed: combined_peak_bytes,
                    limit: limits.max_combined_peak_bytes,
                },
                receipt,
                Some(&owner_prospective),
            ));
        }
        enforce_retained_selector_control(owner_prospective.selector, selector_limits).map_err(
            |source| {
                Self::direct_count_error(
                    &identity,
                    CaptureExecutionSource::Selector(source),
                    receipt,
                    Some(&owner_prospective),
                )
            },
        )?;
        let attempt = plan
            .engine
            .count_uniform_participation_attempt(
                haystack,
                plan.schema,
                limits.prefix_class_participation,
            )
            .map_err(
                |PrefixClassUniformParticipationAttemptError { source, receipt }| {
                    Self::direct_count_error(
                        &identity,
                        CaptureExecutionSource::PrefixClassParticipation(source),
                        receipt,
                        Some(&owner_prospective),
                    )
                },
            )?;
        let expected_kernel_identity = plan.engine.uniform_participation_identity(plan.schema);
        let expected_invocation = PrefixClassUniformParticipationInvocation {
            haystack_bytes: haystack.len(),
            schema: plan.schema,
            limits: limits.prefix_class_participation,
        };
        if attempt.receipt.prospective != Some(prospective)
            || !attempt.authenticates(expected_kernel_identity, expected_invocation)
            || identity.plan.prefix_class_participation != Some(plan.identity())
            || identity.plan.plan != CapturePlanKind::UniformPrefixClassParticipation
        {
            return Err(Self::direct_count_error(
                &identity,
                CaptureExecutionSource::InternalInvariant(
                    "direct prefix/class execution diverged from its published plan",
                ),
                attempt.receipt,
                Some(&owner_prospective),
            ));
        }
        let result = attempt.result;
        if !result.accounting.closes_receipt(&attempt.receipt)
            || result.accounting.prospective != prospective
        {
            return Err(Self::direct_count_error(
                &identity,
                CaptureExecutionSource::InternalInvariant(
                    "direct prefix/class result did not close its P/A receipt",
                ),
                attempt.receipt,
                Some(&owner_prospective),
            ));
        }
        receipt = attempt.receipt;
        let actual = CaptureCountActual::from_direct(&receipt, retained_fallback_bytes)
            .ok_or_else(|| {
                Self::direct_count_error(
                    &identity,
                    CaptureExecutionSource::InternalInvariant(
                        "direct Count actual co-live peak overflowed usize",
                    ),
                    receipt,
                    Some(&owner_prospective),
                )
            })?;
        if receipt.actual_allocations != 0
            || receipt.actual.operation_allocations != 0
            || prospective.operation_allocations != 0
        {
            return Err(Self::direct_count_error(
                &identity,
                CaptureExecutionSource::InternalInvariant(
                    "allocation-free direct route reported an allocation",
                ),
                receipt,
                Some(&owner_prospective),
            ));
        }
        let Some(count_receipt) = identity.count_seal.as_ref().map(|seal| {
            CaptureCountAttemptReceipt::direct_success(seal, &receipt, &owner_prospective, &actual)
        }) else {
            return Err(Self::direct_count_error(
                &identity,
                CaptureExecutionSource::InternalInvariant(
                    "direct Count success lost its invocation seal",
                ),
                receipt,
                Some(&owner_prospective),
            ));
        };
        if !identity
            .count_seal
            .as_ref()
            .is_some_and(|seal| count_receipt.closes(seal))
        {
            return Err(Self::direct_count_error(
                &identity,
                CaptureExecutionSource::InternalInvariant(
                    "direct Count terminal receipt failed owner authentication",
                ),
                receipt,
                Some(&owner_prospective),
            ));
        }
        let report = CaptureExecutionReport {
            identity,
            accounting: CaptureCountOutcome {
                count: result.capture_count,
                matches: result.matches,
                searches: 0,
                total_state_visits: 0,
                total_history_nodes: 0,
                total_history_walk: 0,
                peak_threads: 0,
            },
            selector_certificate: None,
            selector_accounting: None,
            selector_receipt: None,
            prefix_class_participation: Some(result.accounting),
            prefix_class_participation_receipt: Some(receipt),
            count_receipt: Some(count_receipt),
            capture_stream: None,
            capture_events: result.accounting.actual.capture_events,
            combined_peak_bytes,
        };
        if !report.has_closed_count_attempt() {
            return Err(Self::direct_count_error(
                &report.identity,
                CaptureExecutionSource::InternalInvariant(
                    "direct Count success diverged from its owner receipt",
                ),
                receipt,
                Some(&owner_prospective),
            ));
        }
        Ok(report)
    }

    #[allow(
        clippy::large_types_passed_by_value,
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "the Copy run-limit snapshot and sealed uniform route preserve complete selector and owner P/A on every terminal"
    )]
    fn count_uniform_captures(
        &self,
        haystack: &[u8],
        limits: CaptureRunLimits,
        selector_limits: SelectorOperationLimits,
        identity: CaptureCacheIdentity,
        participating: usize,
        minimum_match_bytes: usize,
    ) -> Result<CaptureExecutionReport, CaptureExecutionError> {
        let participating_with_overall =
            participating
                .checked_add(1)
                .ok_or_else(|| CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::InternalInvariant(
                        "uniform capture participation overflowed usize",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
        let all_groups =
            self.report
                .engine
                .captures
                .checked_add(1)
                .ok_or_else(|| CaptureExecutionError {
                    identity: identity.clone(),
                    source: CaptureExecutionSource::InternalInvariant(
                        "capture schema overflowed usize",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                })?;
        let ordered_root = identity.plan.plan == CapturePlanKind::OrderedRootCaptureManyCount;
        let mut ordered_root_unit_cover = false;
        if ordered_root {
            let Some(proof) = identity.plan.ordered_root_capture_many else {
                return Err(CaptureExecutionError {
                    identity,
                    source: CaptureExecutionSource::InternalInvariant(
                        "ordered-root Count lost its construction proof",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                });
            };
            if proof.participating_captures != participating
                || proof.groups_per_match != participating_with_overall
                || proof.root_arms != self.report.engine.captures
                || self.report.ordered_root_capture_many != Some(proof)
            {
                return Err(CaptureExecutionError {
                    identity,
                    source: CaptureExecutionSource::InternalInvariant(
                        "ordered-root Count proof diverged from capture schema",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                });
            }
            ordered_root_unit_cover = proof.unit_cover.is_some();
        }
        let sealed_route = identity.count_seal.as_ref().map(|seal| {
            let route = seal.route_identity();
            (
                route.branch,
                route.selector_route.physical_route,
                route.minimum_match_bytes,
                route.participating_captures_per_match,
                route.capture_schema_entries_per_match,
            )
        });
        let Some((
            CaptureCountBranch::SelectorUniformParticipation,
            selector_route,
            sealed_minimum_match_bytes,
            sealed_participating,
            sealed_schema,
        )) = sealed_route
        else {
            return Err(CaptureExecutionError {
                identity,
                source: CaptureExecutionSource::InternalInvariant(
                    "positive-width selector Count lost its construction owner",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            });
        };
        if sealed_minimum_match_bytes != minimum_match_bytes
            || sealed_participating != participating_with_overall
            || sealed_schema != all_groups
        {
            return Err(CaptureExecutionError {
                identity,
                source: CaptureExecutionSource::InternalInvariant(
                    "selector Count construction owner diverged from its capture schema",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            });
        }
        let terminal_frontier =
            selector_route == fre_aggregate::OperationPhysicalRoute::TerminalFrontierRows;
        let route_is_coherent = if ordered_root_unit_cover {
            selector_route == fre_aggregate::OperationPhysicalRoute::CachedFrontier
        } else if ordered_root {
            selector_route == fre_aggregate::OperationPhysicalRoute::OrderedRootRows
        } else {
            matches!(
                selector_route,
                fre_aggregate::OperationPhysicalRoute::DenseRows
                    | fre_aggregate::OperationPhysicalRoute::TerminalFrontierRows
                    | fre_aggregate::OperationPhysicalRoute::RequiredSuffixRows
                    | fre_aggregate::OperationPhysicalRoute::Candidate
                    | fre_aggregate::OperationPhysicalRoute::StartDomain
            ) && selector_route == self.selector.uniform_capture_count_route()
        };
        if !route_is_coherent {
            return Err(CaptureExecutionError {
                identity,
                source: CaptureExecutionSource::InternalInvariant(
                    "selector Count owner diverged from its retained physical route",
                ),
                selector_receipt: None,
                prefix_class_participation_receipt: None,
                count_receipt: None,
            });
        }
        let mut published = None;
        let mut owner_refusal = None;
        let mut observer =
            |selector: SelectorOperationProspective| match uniform_capture_prospective(
                &selector,
                haystack.len(),
                minimum_match_bytes,
                participating_with_overall,
                all_groups,
            ) {
                Ok(prospective) => {
                    published = Some(prospective);
                    match enforce_uniform_capture_prospective(&prospective, limits.aggregate) {
                        Ok(()) => Ok(()),
                        Err(source) => {
                            owner_refusal = Some(source);
                            Err(SelectorError::InternalInvariant(
                                "capture uniform Count prospective refused",
                            ))
                        }
                    }
                }
                Err(source) => {
                    owner_refusal = Some(source);
                    Err(SelectorError::InternalInvariant(
                        "capture uniform Count prospective refused",
                    ))
                }
            };
        let attempt = match selector_route {
            fre_aggregate::OperationPhysicalRoute::CachedFrontier if ordered_root_unit_cover => {
                self.selector
                    .admit_count_observed_with_cached_frontier_receipt_observer(
                        haystack,
                        0..haystack.len(),
                        SelectorStrategy::ReverseSequentialRows,
                        selector_limits,
                        usize::MAX,
                        &mut observer,
                    )
            }
            fre_aggregate::OperationPhysicalRoute::OrderedRootRows if ordered_root => self
                .selector
                .admit_ordered_root_count_observed_with_receipt_observer(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                    usize::MAX,
                    &mut observer,
                ),
            fre_aggregate::OperationPhysicalRoute::TerminalFrontierRows if !ordered_root => self
                .selector
                .admit_count_observed_with_terminal_frontier_receipt_observer(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                    usize::MAX,
                    &mut observer,
                ),
            fre_aggregate::OperationPhysicalRoute::RequiredSuffixRows if !ordered_root => self
                .selector
                .admit_count_observed_with_required_suffix_receipt_observer(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                    usize::MAX,
                    &mut observer,
                ),
            fre_aggregate::OperationPhysicalRoute::Candidate if !ordered_root => self
                .selector
                .admit_count_observed_with_candidate_receipt_observer(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                    usize::MAX,
                    &mut observer,
                ),
            fre_aggregate::OperationPhysicalRoute::StartDomain if !ordered_root => self
                .selector
                .admit_count_observed_with_start_domain_receipt_observer(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                    usize::MAX,
                    &mut observer,
                ),
            fre_aggregate::OperationPhysicalRoute::DenseRows if !ordered_root => {
                self.selector.admit_count_observed_with_receipt_observer(
                    haystack,
                    0..haystack.len(),
                    SelectorStrategy::ReverseSequentialRows,
                    selector_limits,
                    usize::MAX,
                    &mut observer,
                )
            }
            _ => {
                return Err(CaptureExecutionError {
                    identity,
                    source: CaptureExecutionSource::InternalInvariant(
                        "selector Count owner selected an uncallable physical route",
                    ),
                    selector_receipt: None,
                    prefix_class_participation_receipt: None,
                    count_receipt: None,
                });
            }
        };
        let attempt = match attempt {
            Ok(attempt) => attempt,
            Err(SelectorOperationAttemptError { source, receipt }) => {
                let source = owner_refusal.map_or(
                    CaptureExecutionSource::Selector(source),
                    CaptureExecutionSource::History,
                );
                let actual = CaptureCountActual::from_selector(&receipt);
                return Err(Self::uniform_count_error(
                    identity,
                    source,
                    receipt,
                    published.as_ref(),
                    &actual,
                ));
            }
        };
        if owner_refusal.is_some() {
            let actual = CaptureCountActual::from_selector(&attempt.receipt);
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::InternalInvariant(
                    "selector succeeded after capture owner refused its prospective",
                ),
                attempt.receipt,
                published.as_ref(),
                &actual,
            ));
        }
        let Some(prospective) = published else {
            let actual = CaptureCountActual::from_selector(&attempt.receipt);
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::InternalInvariant(
                    "uniform Count succeeded without publishing its prospective",
                ),
                attempt.receipt,
                None,
                &actual,
            ));
        };
        if prospective.selector.terminal_frontier != terminal_frontier
            || attempt.receipt.prospective != Some(prospective.selector)
        {
            let actual = CaptureCountActual::from_selector(&attempt.receipt);
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::InternalInvariant(
                    "uniform Count route diverged from its published prospective",
                ),
                attempt.receipt,
                Some(&prospective),
                &actual,
            ));
        }
        let selected = attempt.admitted;
        let selector_receipt = attempt.receipt;
        let selector_certificate = selected.certificate();
        let selector_accounting = selected.accounting();
        let matches = selected.value();
        let mut actual = CaptureCountActual::from_selector(&selector_receipt);
        actual.matches = matches;
        if matches > prospective.matches
            || selector_accounting.emitted_matches != matches
            || selector_accounting.output_bytes != 0
            || selector_receipt.prospective.is_none_or(|published| {
                usize::from(selector_certificate.prospective_allocations) != published.allocations
                    || usize::from(selector_certificate.actual_allocations)
                        != selector_receipt.actual_allocations
            })
        {
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::InternalInvariant(
                    "uniform Count actual escaped its positive-width prospective",
                ),
                selector_receipt,
                Some(&prospective),
                &actual,
            ));
        }
        let Some(count) = matches.checked_mul(participating_with_overall) else {
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::History(EngineSearchError::BoundOverflow(
                    EngineResource::CaptureCount,
                )),
                selector_receipt,
                Some(&prospective),
                &actual,
            ));
        };
        actual.capture_count = count;
        let Some(capture_events) = matches.checked_mul(all_groups) else {
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::History(EngineSearchError::BoundOverflow(
                    EngineResource::CaptureEvents,
                )),
                selector_receipt,
                Some(&prospective),
                &actual,
            ));
        };
        actual.capture_events = capture_events;
        if count > prospective.capture_count || capture_events > prospective.capture_events {
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::InternalInvariant(
                    "uniform capture arithmetic escaped its prospective",
                ),
                selector_receipt,
                Some(&prospective),
                &actual,
            ));
        }
        let Some(count_receipt) = identity.count_seal.as_ref().map(|seal| {
            CaptureCountAttemptReceipt::selector_success(
                seal,
                selector_receipt.clone(),
                &prospective,
                &actual,
            )
        }) else {
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::InternalInvariant(
                    "selector Count success lost its invocation seal",
                ),
                selector_receipt,
                Some(&prospective),
                &actual,
            ));
        };
        if !identity
            .count_seal
            .as_ref()
            .is_some_and(|seal| count_receipt.closes(seal))
        {
            return Err(Self::uniform_count_error(
                identity,
                CaptureExecutionSource::InternalInvariant(
                    "selector Count terminal receipt failed owner authentication",
                ),
                selector_receipt,
                Some(&prospective),
                &actual,
            ));
        }
        let report = CaptureExecutionReport {
            identity,
            accounting: CaptureCountOutcome {
                count,
                matches,
                searches: 0,
                total_state_visits: 0,
                total_history_nodes: 0,
                total_history_walk: 0,
                peak_threads: 0,
            },
            selector_certificate: Some(selector_certificate.clone()),
            selector_accounting: Some(selector_accounting),
            selector_receipt: Some(selector_receipt),
            prefix_class_participation: None,
            prefix_class_participation_receipt: None,
            count_receipt: Some(count_receipt),
            capture_stream: None,
            capture_events,
            combined_peak_bytes: selector_accounting.peak_bytes,
        };
        if !report.has_closed_count_attempt() {
            let selector_receipt = report
                .selector_receipt
                .expect("sealed selector success must retain its nested receipt");
            return Err(Self::uniform_count_error(
                report.identity,
                CaptureExecutionSource::InternalInvariant(
                    "selector Count success certificate diverged from its owner receipt",
                ),
                selector_receipt,
                Some(&prospective),
                &actual,
            ));
        }
        Ok(report)
    }

    fn uniform_count_error(
        identity: CaptureCacheIdentity,
        source: CaptureExecutionSource,
        selector_receipt: SelectorOperationAttemptReceipt,
        prospective: Option<&CaptureCountProspective>,
        actual: &CaptureCountActual,
    ) -> CaptureExecutionError {
        let count_receipt = identity.count_seal.as_ref().map(|seal| {
            CaptureCountAttemptReceipt::selector_failure(
                seal,
                selector_receipt.clone(),
                prospective,
                actual,
            )
        });
        CaptureExecutionError {
            identity,
            source,
            selector_receipt: Some(selector_receipt),
            prefix_class_participation_receipt: None,
            count_receipt,
        }
    }

    fn history_error(
        identity: &CaptureCacheIdentity,
        source: EngineSearchError,
    ) -> CaptureExecutionError {
        CaptureExecutionError {
            identity: identity.clone(),
            source: CaptureExecutionSource::History(source),
            selector_receipt: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
        }
    }

    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the Copy receipt is moved into the terminal error as one immutable fixed-layout snapshot"
    )]
    fn direct_count_error(
        identity: &CaptureCacheIdentity,
        source: CaptureExecutionSource,
        receipt: PrefixClassUniformParticipationAttemptReceipt,
        prospective: Option<&CaptureCountProspective>,
    ) -> CaptureExecutionError {
        let count_receipt = identity.count_seal.as_ref().and_then(|seal| {
            let retained_fallback_bytes = seal.route_identity().retained_fallback_bytes;
            CaptureCountActual::from_direct(&receipt, retained_fallback_bytes).map(|actual| {
                CaptureCountAttemptReceipt::direct_failure(seal, &receipt, prospective, &actual)
            })
        });
        CaptureExecutionError {
            identity: identity.clone(),
            source,
            selector_receipt: None,
            prefix_class_participation_receipt: Some(receipt),
            count_receipt,
        }
    }
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the Copy prospective is admitted as one immutable source-free selector-control snapshot"
)]
fn enforce_retained_selector_control(
    prospective: SelectorOperationProspective,
    limits: SelectorOperationLimits,
) -> Result<(), SelectorError> {
    for (required, limit, resource) in [
        (
            prospective.boundaries,
            limits.max_boundaries,
            SelectorResource::Boundaries,
        ),
        (
            prospective.table_cells,
            limits.max_table_cells,
            SelectorResource::TableCells,
        ),
        (
            prospective.random_access_bytes,
            limits.max_random_access_bytes,
            SelectorResource::RandomAccessBytes,
        ),
        (
            prospective.scratch_bytes,
            limits.max_scratch_bytes,
            SelectorResource::ScratchBytes,
        ),
        (
            prospective.log_bytes,
            limits.max_log_bytes,
            SelectorResource::LogBytes,
        ),
        (
            prospective.sequential_bytes,
            limits.max_sequential_bytes,
            SelectorResource::SequentialBytes,
        ),
        (
            prospective.match_events,
            limits.max_match_events,
            SelectorResource::MatchEvents,
        ),
        (
            prospective.output_matches,
            limits.max_output_matches,
            SelectorResource::OutputMatches,
        ),
        (
            prospective.output_bytes,
            limits.max_output_bytes,
            SelectorResource::OutputBytes,
        ),
        (
            prospective.span_sum,
            limits.max_span_sum,
            SelectorResource::SpanSum,
        ),
        (
            prospective.peak_bytes,
            limits.max_peak_bytes,
            SelectorResource::PeakBytes,
        ),
    ] {
        if required > limit {
            return Err(SelectorError::ResourceLimit {
                resource,
                required,
                limit,
            });
        }
    }
    Ok(())
}

fn uniform_capture_prospective(
    selector: &SelectorOperationProspective,
    haystack_len: usize,
    minimum_match_bytes: usize,
    participating_with_overall: usize,
    all_groups: usize,
) -> Result<CaptureCountProspective, EngineSearchError> {
    if minimum_match_bytes == 0 || selector.output_bytes != 0 {
        return Err(EngineSearchError::InvalidProgram);
    }
    let matches = haystack_len
        .checked_div(minimum_match_bytes)
        .ok_or(EngineSearchError::InvalidProgram)?;
    if matches > selector.output_matches {
        return Err(EngineSearchError::InvalidProgram);
    }
    let capture_count =
        matches
            .checked_mul(participating_with_overall)
            .ok_or(EngineSearchError::BoundOverflow(
                EngineResource::CaptureCount,
            ))?;
    let capture_events =
        matches
            .checked_mul(all_groups)
            .ok_or(EngineSearchError::BoundOverflow(
                EngineResource::CaptureEvents,
            ))?;
    Ok(CaptureCountProspective {
        selector: *selector,
        direct: None,
        matches,
        capture_count,
        capture_events,
        allocations: selector.allocations,
        combined_peak_bytes: selector.peak_bytes,
    })
}

fn enforce_uniform_capture_prospective(
    prospective: &CaptureCountProspective,
    limits: AggregateLimits,
) -> Result<(), EngineSearchError> {
    enforce_capture_prospective(
        prospective.matches,
        limits.max_results,
        EngineResource::Results,
    )?;
    enforce_capture_prospective(
        prospective.capture_count,
        limits.max_capture_count,
        EngineResource::CaptureCount,
    )?;
    enforce_capture_prospective(
        prospective.capture_events,
        limits.max_capture_events,
        EngineResource::CaptureEvents,
    )
}

fn enforce_capture_prospective(
    required: usize,
    limit: usize,
    resource: EngineResource,
) -> Result<(), EngineSearchError> {
    if required > limit {
        return Err(EngineSearchError::Resource {
            kind: resource,
            required,
            limit,
        });
    }
    Ok(())
}

#[allow(
    clippy::result_large_err,
    reason = "capture terminals retain the complete allocation-free selector P/A receipt inline"
)]
fn capture_remaining(
    identity: &CaptureCacheIdentity,
    limit: usize,
    used: usize,
    resource: EngineResource,
) -> Result<usize, CaptureExecutionError> {
    limit
        .checked_sub(used)
        .ok_or_else(|| CaptureExecutionError {
            identity: identity.clone(),
            source: CaptureExecutionSource::History(EngineSearchError::BoundOverflow(resource)),
            selector_receipt: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
        })
}

#[allow(
    clippy::result_large_err,
    reason = "capture terminals retain the complete allocation-free selector P/A receipt inline"
)]
fn checked_capture_add(
    identity: &CaptureCacheIdentity,
    current: usize,
    amount: usize,
    resource: EngineResource,
    limit: usize,
) -> Result<usize, CaptureExecutionError> {
    let required = current
        .checked_add(amount)
        .ok_or_else(|| CaptureExecutionError {
            identity: identity.clone(),
            source: CaptureExecutionSource::History(EngineSearchError::BoundOverflow(resource)),
            selector_receipt: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
        })?;
    if required > limit {
        return Err(CaptureExecutionError {
            identity: identity.clone(),
            source: CaptureExecutionSource::History(EngineSearchError::Resource {
                kind: resource,
                required,
                limit,
            }),
            selector_receipt: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
        });
    }
    Ok(required)
}

#[allow(
    clippy::result_large_err,
    reason = "capture terminals retain the complete allocation-free selector P/A receipt inline"
)]
fn checked_capture_mul(
    identity: &CaptureCacheIdentity,
    left: usize,
    right: usize,
    resource: EngineResource,
    limit: usize,
) -> Result<usize, CaptureExecutionError> {
    let required = left
        .checked_mul(right)
        .ok_or_else(|| CaptureExecutionError {
            identity: identity.clone(),
            source: CaptureExecutionSource::History(EngineSearchError::BoundOverflow(resource)),
            selector_receipt: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
        })?;
    if required > limit {
        return Err(CaptureExecutionError {
            identity: identity.clone(),
            source: CaptureExecutionSource::History(EngineSearchError::Resource {
                kind: resource,
                required,
                limit,
            }),
            selector_receipt: None,
            prefix_class_participation_receipt: None,
            count_receipt: None,
        });
    }
    Ok(required)
}

#[derive(Clone, Copy)]
struct CaptureParticipation {
    uniform: Option<usize>,
    stable_set: bool,
    can_participate: bool,
}

impl CaptureParticipation {
    const CAPTURE_FREE: Self = Self {
        uniform: Some(0),
        stable_set: true,
        can_participate: false,
    };
}

fn ordered_root_capture_many_proof(
    hir: &Hir,
    explicit_captures: usize,
    unicode: bool,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<Option<OrderedRootCaptureManyProof>, CaptureBuildError> {
    let work_before = accounting.work;
    charge_hir(accounting, 1, limits.max_hir_work)?;
    let HirKind::Alternation(children) = hir.kind() else {
        return Ok(None);
    };
    charge_hir(accounting, 3, limits.max_hir_work)?;
    if children.len() < 2
        || children.len() != explicit_captures
        || hir.properties().explicit_captures_len() != explicit_captures
    {
        return Ok(None);
    }
    for (index, child) in children.iter().enumerate() {
        charge_hir(accounting, 4, limits.max_hir_work)?;
        let HirKind::Capture(capture) = child.kind() else {
            return Ok(None);
        };
        let expected_index = index
            .checked_add(1)
            .ok_or(CaptureBuildError::InternalInvariant(
                "ordered-root capture index overflowed usize",
            ))?;
        let expected_index = u32::try_from(expected_index).map_err(|_| {
            CaptureBuildError::InternalInvariant("ordered-root capture index exceeded u32")
        })?;
        if capture.index != expected_index
            || capture.sub.properties().explicit_captures_len() != 0
            || !matches!(capture.sub.properties().minimum_len(), Some(minimum) if minimum > 0)
        {
            return Ok(None);
        }
    }
    let unit_cover = ordered_root_unit_cover(children, unicode, limits, accounting)?;
    let proof_work =
        accounting
            .work
            .checked_sub(work_before)
            .ok_or(CaptureBuildError::InternalInvariant(
                "ordered-root proof work moved backward",
            ))?;
    Ok(Some(OrderedRootCaptureManyProof {
        root_arms: children.len(),
        participating_captures: 1,
        groups_per_match: 2,
        unit_cover,
        proof_work,
    }))
}

const MAX_ORDERED_ROOT_UNIT_COVER_GAPS: usize = 32;

#[derive(Clone, Copy)]
struct ZeroOneUnitLanguage {
    empty: bool,
    target: bool,
}

fn ordered_root_unit_cover(
    children: &[Hir],
    unicode: bool,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<Option<OrderedRootUnitCover>, CaptureBuildError> {
    let Some(HirKind::Capture(terminal)) = children.last().map(Hir::kind) else {
        return Ok(None);
    };
    let mut gaps = [0_u32; MAX_ORDERED_ROOT_UNIT_COVER_GAPS];
    let Some(gap_count) = terminal_class_gaps(
        terminal.sub.as_ref(),
        unicode,
        &mut gaps,
        limits,
        accounting,
    )?
    else {
        return Ok(None);
    };
    for &unit in &gaps[..gap_count] {
        let mut witnessed = false;
        for child in &children[..children.len().saturating_sub(1)] {
            let HirKind::Capture(capture) = child.kind() else {
                return Ok(None);
            };
            let Some(language) =
                zero_one_unit_language(capture.sub.as_ref(), unit, unicode, limits, accounting)?
            else {
                continue;
            };
            if language.target {
                witnessed = true;
                break;
            }
        }
        if !witnessed {
            return Ok(None);
        }
    }
    Ok(Some(if unicode {
        OrderedRootUnitCover::UnicodeScalars
    } else {
        OrderedRootUnitCover::Bytes
    }))
}

fn terminal_class_gaps(
    hir: &Hir,
    unicode: bool,
    gaps: &mut [u32; MAX_ORDERED_ROOT_UNIT_COVER_GAPS],
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<Option<usize>, CaptureBuildError> {
    charge_hir(accounting, 1, limits.max_hir_work)?;
    match (unicode, hir.kind()) {
        (false, HirKind::Class(Class::Bytes(class))) => {
            let mut gap_count = 0_usize;
            for byte in u8::MIN..=u8::MAX {
                charge_hir(accounting, 1, limits.max_hir_work)?;
                if class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= byte && byte <= range.end())
                {
                    continue;
                }
                let Some(slot) = gaps.get_mut(gap_count) else {
                    return Ok(None);
                };
                *slot = u32::from(byte);
                gap_count =
                    gap_count
                        .checked_add(1)
                        .ok_or(CaptureBuildError::InternalInvariant(
                            "ordered-root byte-cover gap count overflowed usize",
                        ))?;
            }
            Ok(Some(gap_count))
        }
        (true, HirKind::Class(Class::Unicode(class))) => {
            let mut gap_count = 0_usize;
            for (domain_start, domain_end) in [(0_u32, 0xD7FF_u32), (0xE000, 0x0010_FFFF)] {
                let mut cursor = domain_start;
                for range in class.ranges() {
                    charge_hir(accounting, 1, limits.max_hir_work)?;
                    let start = u32::from(range.start()).max(domain_start);
                    let end = u32::from(range.end()).min(domain_end);
                    if start > end || end < cursor {
                        continue;
                    }
                    if start > cursor {
                        let gap_end =
                            start
                                .checked_sub(1)
                                .ok_or(CaptureBuildError::InternalInvariant(
                                    "ordered-root scalar gap underflowed",
                                ))?;
                        if !append_ordered_root_gaps(cursor, gap_end, gaps, &mut gap_count) {
                            return Ok(None);
                        }
                    }
                    cursor = cursor.max(end.saturating_add(1));
                    if cursor > domain_end {
                        break;
                    }
                }
                if cursor <= domain_end
                    && !append_ordered_root_gaps(cursor, domain_end, gaps, &mut gap_count)
                {
                    return Ok(None);
                }
            }
            charge_hir(accounting, gap_count, limits.max_hir_work)?;
            Ok(Some(gap_count))
        }
        _ => Ok(None),
    }
}

fn append_ordered_root_gaps(
    start: u32,
    end: u32,
    gaps: &mut [u32; MAX_ORDERED_ROOT_UNIT_COVER_GAPS],
    gap_count: &mut usize,
) -> bool {
    let Some(width) = end
        .checked_sub(start)
        .and_then(|value| value.checked_add(1))
    else {
        return false;
    };
    let Ok(width) = usize::try_from(width) else {
        return false;
    };
    let Some(required) = gap_count.checked_add(width) else {
        return false;
    };
    if required > gaps.len() {
        return false;
    }
    for unit in start..=end {
        gaps[*gap_count] = unit;
        let Some(next) = gap_count.checked_add(1) else {
            return false;
        };
        *gap_count = next;
    }
    true
}

fn zero_one_unit_language(
    hir: &Hir,
    target: u32,
    unicode: bool,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<Option<ZeroOneUnitLanguage>, CaptureBuildError> {
    charge_hir(accounting, 1, limits.max_hir_work)?;
    match hir.kind() {
        HirKind::Empty => Ok(Some(ZeroOneUnitLanguage {
            empty: true,
            target: false,
        })),
        HirKind::Literal(literal) => {
            let target_matches = if unicode {
                char::from_u32(target).is_some_and(|scalar| {
                    let mut bytes = [0_u8; 4];
                    literal.0.as_ref() == scalar.encode_utf8(&mut bytes).as_bytes()
                })
            } else {
                u8::try_from(target)
                    .ok()
                    .is_some_and(|byte| literal.0.as_ref() == [byte])
            };
            Ok(Some(ZeroOneUnitLanguage {
                empty: literal.0.is_empty(),
                target: target_matches,
            }))
        }
        HirKind::Class(Class::Bytes(class)) if !unicode => {
            let Some(target) = u8::try_from(target).ok() else {
                return Ok(Some(ZeroOneUnitLanguage {
                    empty: false,
                    target: false,
                }));
            };
            charge_hir(accounting, class.ranges().len(), limits.max_hir_work)?;
            Ok(Some(ZeroOneUnitLanguage {
                empty: false,
                target: class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= target && target <= range.end()),
            }))
        }
        HirKind::Class(Class::Unicode(class)) if unicode => {
            let Some(target) = char::from_u32(target) else {
                return Ok(Some(ZeroOneUnitLanguage {
                    empty: false,
                    target: false,
                }));
            };
            charge_hir(accounting, class.ranges().len(), limits.max_hir_work)?;
            Ok(Some(ZeroOneUnitLanguage {
                empty: false,
                target: class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= target && target <= range.end()),
            }))
        }
        HirKind::Class(_) | HirKind::Look(_) => Ok(None),
        HirKind::Capture(capture) => {
            zero_one_unit_language(capture.sub.as_ref(), target, unicode, limits, accounting)
        }
        HirKind::Repetition(repetition) => {
            let Some(child) = zero_one_unit_language(
                repetition.sub.as_ref(),
                target,
                unicode,
                limits,
                accounting,
            )?
            else {
                return Ok(None);
            };
            let can_repeat = repetition.max != Some(0);
            Ok(Some(ZeroOneUnitLanguage {
                empty: repetition.min == 0 || child.empty,
                target: can_repeat && child.target && (repetition.min <= 1 || child.empty),
            }))
        }
        HirKind::Concat(children) => {
            let mut combined = ZeroOneUnitLanguage {
                empty: true,
                target: false,
            };
            for child in children {
                let Some(right) =
                    zero_one_unit_language(child, target, unicode, limits, accounting)?
                else {
                    return Ok(None);
                };
                combined = ZeroOneUnitLanguage {
                    empty: combined.empty && right.empty,
                    target: (combined.target && right.empty) || (combined.empty && right.target),
                };
            }
            Ok(Some(combined))
        }
        HirKind::Alternation(children) => {
            let mut combined = ZeroOneUnitLanguage {
                empty: false,
                target: false,
            };
            for child in children {
                if let Some(branch) =
                    zero_one_unit_language(child, target, unicode, limits, accounting)?
                {
                    combined.empty |= branch.empty;
                    combined.target |= branch.target;
                }
            }
            Ok(Some(combined))
        }
    }
}

fn capture_line_batch_proof(
    hir: &Hir,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<Option<CaptureLineBatchProof>, CaptureBuildError> {
    let Some(minimum_match_bytes) = hir
        .properties()
        .minimum_len()
        .filter(|minimum| *minimum > 0)
    else {
        return Ok(None);
    };
    let work_before = accounting.work;
    let mut allowed = [u64::MAX; 2];
    if !capture_line_batch_exclusions(hir, 1, limits, accounting, &mut allowed)? {
        return Ok(None);
    }
    let separator = (u8::MIN..=0x7f).find(|byte| {
        let index = usize::from(*byte) / 64;
        let bit = usize::from(*byte) % 64;
        allowed[index] & (1_u64 << bit) != 0
    });
    let Some(separator) = separator else {
        return Ok(None);
    };
    let planner_work =
        accounting
            .work
            .checked_sub(work_before)
            .ok_or(CaptureBuildError::InternalInvariant(
                "line-batch proof work moved backward",
            ))?;
    Ok(Some(CaptureLineBatchProof {
        separator,
        minimum_match_bytes,
        planner_work,
    }))
}

fn capture_line_batch_exclusions(
    hir: &Hir,
    depth: usize,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
    allowed: &mut [u64; 2],
) -> Result<bool, CaptureBuildError> {
    if depth > limits.max_hir_depth {
        return Ok(false);
    }
    charge_hir(accounting, 1, limits.max_hir_work)?;
    match hir.kind() {
        HirKind::Empty => Ok(true),
        HirKind::Look(_) => Ok(false),
        HirKind::Literal(literal) => {
            charge_hir(accounting, literal.0.len(), limits.max_hir_work)?;
            for &byte in literal.0.iter().filter(|byte| **byte < 0x80) {
                clear_line_batch_separator(allowed, byte);
            }
            Ok(true)
        }
        HirKind::Class(Class::Bytes(class)) => {
            charge_hir(accounting, class.ranges().len(), limits.max_hir_work)?;
            for range in class.ranges() {
                let start = range.start();
                let end = range.end().min(0x7f);
                if start <= end {
                    for byte in start..=end {
                        clear_line_batch_separator(allowed, byte);
                    }
                }
            }
            Ok(true)
        }
        HirKind::Class(Class::Unicode(class)) => {
            charge_hir(accounting, class.ranges().len(), limits.max_hir_work)?;
            for range in class.ranges() {
                let start = u32::from(range.start());
                let end = u32::from(range.end()).min(0x7f);
                if start <= end {
                    for scalar in start..=end {
                        let byte = u8::try_from(scalar).map_err(|_| {
                            CaptureBuildError::InternalInvariant(
                                "ASCII line-batch scalar did not fit u8",
                            )
                        })?;
                        clear_line_batch_separator(allowed, byte);
                    }
                }
            }
            Ok(true)
        }
        HirKind::Capture(capture) => capture_line_batch_exclusions(
            capture.sub.as_ref(),
            next_depth(depth)?,
            limits,
            accounting,
            allowed,
        ),
        HirKind::Repetition(repetition) => capture_line_batch_exclusions(
            repetition.sub.as_ref(),
            next_depth(depth)?,
            limits,
            accounting,
            allowed,
        ),
        HirKind::Concat(children) | HirKind::Alternation(children) => {
            for child in children {
                if !capture_line_batch_exclusions(
                    child,
                    next_depth(depth)?,
                    limits,
                    accounting,
                    allowed,
                )? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

fn clear_line_batch_separator(allowed: &mut [u64; 2], byte: u8) {
    let index = usize::from(byte) / 64;
    let bit = usize::from(byte) % 64;
    allowed[index] &= !(1_u64 << bit);
}

/// Prove only the cardinality needed by the reducer while charging this
/// auxiliary traversal to the same construction-work ledger as lowering.
fn capture_participation(
    hir: &Hir,
    depth: usize,
    limits: &CaptureBuildLimits,
    accounting: &mut CaptureHirAccounting,
) -> Result<CaptureParticipation, CaptureBuildError> {
    if depth > limits.max_hir_depth {
        return Err(CaptureBuildError::HirResource {
            resource: "depth",
            required: depth,
            limit: limits.max_hir_depth,
        });
    }
    charge_hir(accounting, 1, limits.max_hir_work)?;
    match hir.kind() {
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => {
            Ok(CaptureParticipation::CAPTURE_FREE)
        }
        HirKind::Capture(capture) => {
            let child = capture_participation(
                capture.sub.as_ref(),
                next_depth(depth)?,
                limits,
                accounting,
            )?;
            let uniform = child
                .uniform
                .map(|count| {
                    checked_dimension_add(count, 1, "capture participation", limits.max_hir_work)
                })
                .transpose()?;
            Ok(CaptureParticipation {
                uniform,
                stable_set: child.stable_set,
                can_participate: true,
            })
        }
        HirKind::Repetition(repetition) => {
            let child = capture_participation(
                repetition.sub.as_ref(),
                next_depth(depth)?,
                limits,
                accounting,
            )?;
            if repetition.max == Some(0) || !child.can_participate {
                return Ok(CaptureParticipation::CAPTURE_FREE);
            }
            let can_repeat = match repetition.max {
                Some(maximum) => maximum > 1,
                None => true,
            };
            if repetition.min == 0 || (can_repeat && !child.stable_set) {
                return Ok(CaptureParticipation {
                    uniform: None,
                    stable_set: false,
                    can_participate: true,
                });
            }
            Ok(child)
        }
        HirKind::Concat(children) => {
            let mut combined = CaptureParticipation::CAPTURE_FREE;
            for child in children {
                let child = capture_participation(child, next_depth(depth)?, limits, accounting)?;
                charge_hir(accounting, 1, limits.max_hir_work)?;
                combined = CaptureParticipation {
                    uniform: match (combined.uniform, child.uniform) {
                        (Some(left), Some(right)) => Some(checked_dimension_add(
                            left,
                            right,
                            "capture participation",
                            limits.max_hir_work,
                        )?),
                        _ => None,
                    },
                    stable_set: combined.stable_set && child.stable_set,
                    can_participate: combined.can_participate || child.can_participate,
                };
            }
            Ok(combined)
        }
        HirKind::Alternation(children) => {
            let mut uniform = None;
            let mut can_participate = false;
            for (index, child) in children.iter().enumerate() {
                let child = capture_participation(child, next_depth(depth)?, limits, accounting)?;
                charge_hir(accounting, 1, limits.max_hir_work)?;
                uniform = if index == 0 || uniform == child.uniform {
                    child.uniform
                } else {
                    None
                };
                can_participate |= child.can_participate;
            }
            Ok(CaptureParticipation {
                uniform,
                // Capture IDs are unique HIR nodes, so distinct alternatives
                // have one stable set only when all of them are capture-free.
                stable_set: !can_participate,
                can_participate,
            })
        }
    }
}
fn next_depth(depth: usize) -> Result<usize, CaptureBuildError> {
    depth.checked_add(1).ok_or(CaptureBuildError::HirResource {
        resource: "depth",
        required: usize::MAX,
        limit: usize::MAX,
    })
}

fn charge_hir(
    accounting: &mut CaptureHirAccounting,
    amount: usize,
    limit: usize,
) -> Result<(), CaptureBuildError> {
    let required = accounting
        .work
        .checked_add(amount)
        .ok_or(CaptureBuildError::HirResource {
            resource: "work",
            required: usize::MAX,
            limit,
        })?;
    if required > limit {
        return Err(CaptureBuildError::HirResource {
            resource: "work",
            required,
            limit,
        });
    }
    accounting.work = required;
    Ok(())
}

fn checked_dimension_add(
    current: usize,
    amount: usize,
    resource: &'static str,
    limit: usize,
) -> Result<usize, CaptureBuildError> {
    let required = current
        .checked_add(amount)
        .ok_or(CaptureBuildError::HirResource {
            resource,
            required: usize::MAX,
            limit,
        })?;
    if required > limit {
        return Err(CaptureBuildError::HirResource {
            resource,
            required,
            limit,
        });
    }
    Ok(required)
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::RegexBuilder as BytesRegexBuilder;

    fn canonical_capture_hir(
        pattern: &str,
        profile: &RustProfile,
        limits: CaptureBuildLimits,
    ) -> Hir {
        let parsed = fre_syntax::parse(
            fre_syntax::ParseRequest::rust(
                pattern.to_owned(),
                CompatibilityProfile::RustBytes(profile.clone()),
            )
            .with_admission(limits.admission)
            .with_safety_envelope(limits.syntax_safety),
        )
        .expect("facade differential parse");
        let CanonicalPattern::Rust(rust) = parsed.pattern else {
            panic!("Rust byte request produced non-Rust syntax");
        };
        rust.hir
    }

    #[test]
    fn facade_and_direct_hir_programs_are_identical_across_capture_semantics() {
        let mut unicode_lines = RustProfile::default();
        unicode_lines.options.multi_line = true;

        let mut invalid_byte_lines = RustProfile::default();
        invalid_byte_lines.options.unicode = false;
        invalid_byte_lines.options.multi_line = true;
        invalid_byte_lines.options.line_terminator = b';';

        let mut ascii_crlf = RustProfile::default();
        ascii_crlf.options.unicode = false;
        ascii_crlf.options.multi_line = true;
        ascii_crlf.options.crlf = true;

        let fixtures = [
            (
                r"^(?P<outer>(?P<item>a|[β-δ])+)(?P<optional>z)?$",
                unicode_lines,
                "junk\naβδ\n".as_bytes(),
            ),
            (
                r"^(?P<raw>[\x80-\xFF]+)(?P<optional>x)?$",
                invalid_byte_lines,
                b"ascii;\x80\xff;tail".as_slice(),
            ),
            (
                r"^(?P<word>\b[a-z]+\b)$",
                ascii_crlf,
                b"9\r\nabc\r\n!".as_slice(),
            ),
        ];

        for (pattern, profile, haystack) in fixtures {
            let limits = CaptureBuildLimits::default();
            let facade = CaptureBuilder::new(pattern)
                .profile(profile.clone())
                .limits(limits)
                .build()
                .expect("facade capture build");
            let hir = canonical_capture_hir(pattern, &profile, limits);
            let direct_limits = HirProgramBuildLimits {
                max_hir_work: limits.max_hir_work,
                max_hir_depth: limits.max_hir_depth,
                program: limits.engine,
            };
            let isolated = fre_capture_lab::build_program_from_hir(
                &hir,
                profile.options.line_terminator,
                direct_limits,
            )
            .expect("isolated direct HIR build");
            let outer_work = facade
                .build_report()
                .hir
                .work
                .checked_sub(isolated.report().hir.work)
                .expect("facade planner work contains direct lowering work");
            let direct = build_program_from_hir_with_accounting(
                &hir,
                profile.options.line_terminator,
                direct_limits,
                CaptureHirAccounting {
                    work: outer_work,
                    ..CaptureHirAccounting::default()
                },
            )
            .expect("facade-ledger direct HIR build");

            assert_eq!(direct.report().hir, facade.build_report().hir);
            assert_eq!(direct.report().program, facade.build_report().engine);
            assert_eq!(direct.program(), facade.engine.program().as_ref());

            let direct_engine = HistoryRegex::from_program(Arc::new(direct.into_program()));
            let direct_outcome = direct_engine
                .captures(
                    haystack,
                    Window::all(haystack),
                    EngineSearchLimits::default(),
                )
                .expect("direct capture execution");
            let facade_outcome = facade
                .captures(haystack, EngineSearchLimits::default())
                .expect("facade capture execution");
            assert_eq!(facade_outcome, direct_outcome, "pattern {pattern:?}");
        }
    }

    #[test]
    fn exact_replay_sidecar_does_not_change_fused_count_identity_or_peak() {
        let pattern = r"(?:(a())|(b))";
        let source_bytes = 16;
        let with_onepass = CaptureBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("default capture build");
        assert!(with_onepass.build_report().onepass_capture.is_some());
        let without_onepass = CaptureBuilder::new(pattern)
            .unicode(false)
            .without_onepass_capture()
            .build()
            .expect("history-only capture build");
        assert!(without_onepass.build_report().onepass_capture.is_none());

        let limits = CaptureRunLimits::default();
        assert_eq!(
            with_onepass.cache_identity(limits),
            without_onepass.cache_identity(limits)
        );
        let with_session = with_onepass
            .prepare_capture_stream_session(source_bytes, limits, CaptureStreamDomains::Whole)
            .expect("default fused preparation")
            .expect("default fused session");
        let without_session = without_onepass
            .prepare_capture_stream_session(source_bytes, limits, CaptureStreamDomains::Whole)
            .expect("history-only fused preparation")
            .expect("history-only fused session");
        assert_eq!(
            with_session.operation_prospective(),
            without_session.operation_prospective()
        );
        assert_eq!(
            with_session.combined_peak_bytes,
            without_session.combined_peak_bytes
        );
        assert_eq!(
            with_session.selector_retained_bytes,
            without_session.selector_retained_bytes
        );
    }

    fn reference_records(
        regex: &regex::bytes::Regex,
        haystack: &[u8],
    ) -> Vec<Vec<Option<(usize, usize)>>> {
        regex
            .captures_iter(haystack)
            .map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|span| (span.start(), span.end())))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn fixed_byte_capture_records_match_rust_over_exhaustive_short_haystacks() {
        let patterns = [
            r"([ab])([ab])([ab])?",
            r"x([ab]{2})y([0-2])?",
            r"()([ab]{2})",
            r"q([ab])r",
        ];
        let alphabet = [b'a', b'b', b'x', b'y', b'0', b'q', b'r', 0xff];
        for pattern in patterns {
            let reference = BytesRegexBuilder::new(pattern)
                .unicode(false)
                .build()
                .expect("fixed-byte reference build");
            let regex = CaptureBuilder::new(pattern)
                .unicode(false)
                .build()
                .expect("fixed-byte facade build");
            let mut visitor = regex
                .prepare_capture_record_visitor(8, EngineSearchLimits::default(), usize::MAX)
                .expect("fixed-byte visitor preparation");
            assert!(visitor.uses_fixed_byte_sequence(), "{pattern:?}");
            let mut haystack = Vec::new();
            for length in 0..=5 {
                let cases = alphabet.len().pow(length);
                for mut ordinal in 0..cases {
                    haystack.clear();
                    for _ in 0..length {
                        haystack.push(alphabet[ordinal % alphabet.len()]);
                        ordinal /= alphabet.len();
                    }
                    let mut actual = Vec::new();
                    visitor
                        .visit_records(&haystack, CaptureRunLimits::default(), |groups| {
                            actual.push(
                                groups
                                    .iter()
                                    .map(|group| group.span().map(|span| (span.start, span.end)))
                                    .collect::<Vec<_>>(),
                            );
                        })
                        .expect("fixed-byte record visit");
                    assert_eq!(
                        actual,
                        reference_records(&reference, &haystack),
                        "pattern={pattern:?} haystack={haystack:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn fixed_byte_capture_record_route_refuses_ambiguous_or_scalar_shapes() {
        for (pattern, unicode) in [
            (r"(a(b))", false),
            (r"([ab]|x)", false),
            (r"([ab])?([ab])", false),
            (r"([ab])??", false),
            (r"([ab]+)", false),
            (r"([ab])", true),
            (r"([ab])([ab])(?:(x))?y", false),
        ] {
            let regex = CaptureBuilder::new(pattern)
                .unicode(unicode)
                .build()
                .expect("fallback capture build");
            let visitor = regex
                .prepare_capture_record_visitor(8, EngineSearchLimits::default(), usize::MAX)
                .expect("fallback capture visitor");
            assert!(!visitor.uses_fixed_byte_sequence(), "{pattern:?}");
        }
    }

    #[test]
    fn fixed_byte_capture_record_route_refuses_before_callbacks() {
        let regex = CaptureBuilder::new(r"([ab])([ab])([ab])?")
            .unicode(false)
            .build()
            .expect("direct capture build");
        let mut visitor = regex
            .prepare_capture_record_visitor(3, EngineSearchLimits::default(), usize::MAX)
            .expect("direct capture visitor");
        assert!(visitor.uses_fixed_byte_sequence());
        let mut limits = CaptureRunLimits::default();
        limits.aggregate.max_capture_events = 3;
        let mut callbacks = 0_usize;
        let error = visitor
            .visit_records(b"aba", limits, |_| callbacks += 1)
            .expect_err("one-below event envelope must refuse");
        assert!(matches!(
            error,
            CaptureRecordVisitError::Replay(EngineSearchError::Resource {
                kind: EngineResource::CaptureEvents,
                ..
            })
        ));
        assert_eq!(callbacks, 0);
    }
}
