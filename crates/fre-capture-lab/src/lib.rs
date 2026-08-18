//! Bounded engines for exact regular-expression capture semantics.
//!
//! This crate implements the small capture-aware AST and tagged execution core
//! for the pinned Rust byte-regex leftmost-first and `All` match-priority
//! profiles. The production `fre` facade owns syntax/profile admission and
//! exposes only its qualified HIR subset. [`InlineRegex`] remains a comparative formulation, while
//! [`HistoryRegex`] supplies the persistent-history production plan and a
//! source-independently admitted resource-bounded backtracking route. No
//! executor uses call-stack recursion or falls back after inspecting source.
//!
//! Single-match search and aggregate iteration have different resource
//! contracts. A single search visits at most one copy of each instruction at
//! each byte boundary. The laboratory iterator intentionally repeats that
//! bounded search and therefore carries a separate, potentially quadratic
//! aggregate certificate; it is a correctness oracle, not a production
//! iterator design.

#![forbid(unsafe_code)]

mod ast;
mod backtrack;
mod compile;
mod error;
mod hir;
mod history;
mod inline;
mod limits;
mod line;
mod model;
mod onepass;
mod participation_cache;
mod profile;
mod program_v1;
mod runtime;
mod stream;
mod tagged;

pub use ast::{Assertion, Ast, Greed};
pub use compile::{BuildReport, FirstByteProof, MaskedInclusiveRange, Program, ProgramBuildOrigin};
pub use error::{BuildError, ResourceKind, SearchError};
pub use hir::{
    HirBuildAccounting, HirBuildAllocation, HirBuildResource, HirProgramBuild,
    HirProgramBuildError, HirProgramBuildLimits, HirProgramBuildReport, build_program_from_hir,
    build_program_from_hir_with_accounting,
};
pub use history::{
    HISTORY_EXACT_WORKSPACE_ACCOUNTING_VERSION, HISTORY_EXACT_WORKSPACE_ALGORITHM_VERSION,
    HistoryExactWorkspace, HistoryExactWorkspaceUsage, HistoryRegex,
    PARTICIPATION_QUOTIENT_ACCOUNTING_VERSION, PARTICIPATION_QUOTIENT_ALGORITHM_VERSION,
    ParticipationExactWorkspace,
};
pub use inline::InlineRegex;
pub use limits::{AggregateLimits, BuildLimits, SearchLimits};
pub use line::{
    LineMode, LinePartition, LineScanError, LineScanLimits, LineScanProspective, LineScanReport,
    LineScanResource, LineScanner, SemanticBoundary,
};
pub use model::{
    AggregateOutcome, BoundedBacktrackProspective, CandidateKind, CaptureCountOutcome,
    CaptureGroupSlot, CaptureRecord, ExactCaptureSlotsOutcome, GroupRecord, HistoryProgramShape,
    HistorySearchProspective, MatchKind, PARTICIPATION_QUOTIENT_CAPTURE_BITS,
    PARTICIPATION_QUOTIENT_MASK_BITS, ParticipationSearchOutcome, ParticipationSearchProspective,
    RestartedHistoryProspective, RunReport, SearchConfig, SearchKind, SearchOutcome, Span, Window,
};
pub use onepass::{
    ONEPASS_CAPTURE_ACCOUNTING_VERSION, ONEPASS_CAPTURE_ALGORITHM_VERSION,
    OnePassCaptureBuildError, OnePassCaptureBuildFailure, OnePassCaptureBuildLimits,
    OnePassCaptureBuildReport, OnePassCaptureBuildResource, OnePassCapturePlan,
    OnePassCaptureRefusal, OnePassCaptureWorkspace, OnePassCaptureWorkspaceUsage,
};
pub use profile::CaptureProfile;
pub use program_v1::{
    CAPTURE_PROGRAM_V1_CENSUS_ACCOUNTING_ID, CAPTURE_PROGRAM_V1_HEADER_BYTES,
    CAPTURE_PROGRAM_V1_RETAINED_OWNER_ACCOUNTING_ID, CAPTURE_PROGRAM_V1_VALIDATION_ACCOUNTING_ID,
    CaptureGroupSchema, CaptureProgramV1, CaptureProgramV1Allocation, CaptureProgramV1Census,
    CaptureProgramV1Error, CaptureProgramV1FormatError, CaptureProgramV1Limits,
    CaptureProgramV1Resource, CaptureProgramV1RetainedOwnerReceipt, CaptureProgramV1Usage,
    CaptureSchema,
};
pub use stream::{
    CAPTURE_STREAM_ACCOUNTING_VERSION, CAPTURE_STREAM_ALGORITHM_VERSION, CaptureStream,
    CaptureStreamAccounting, CaptureStreamDomains, CaptureStreamError, CaptureStreamLimits,
    CaptureStreamOperationProspective, CaptureStreamProjection, CaptureStreamProspective,
    CaptureStreamReport, CaptureStreamResource,
};
pub use tagged::{
    HistoryId, ParticipationMask, ParticipationState, ParticipationStorage, ProgramTagAction,
    ProgramTagActions, TAG_WORKSPACE_ACCOUNTING_VERSION, TAG_WORKSPACE_ALGORITHM_VERSION,
    TagAction, TagKind, TagRunAccounting, TagRunLimits, TagSnapshot, TagWorkspace,
    TagWorkspaceError, TagWorkspaceLimits, TagWorkspaceProspective, TagWorkspaceResource,
};
