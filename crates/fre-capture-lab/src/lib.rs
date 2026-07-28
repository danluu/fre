//! Bounded engines for exact regular-expression capture semantics.
//!
//! This crate implements the small capture-aware AST and tagged execution core
//! for the pinned Rust byte-regex leftmost-first and `All` match-priority
//! profiles. The production `fre` facade owns syntax/profile admission and
//! exposes only its qualified HIR subset. [`InlineRegex`] remains a comparative formulation, while
//! [`HistoryRegex`] supplies the persistent-history production plan. Neither
//! executor uses recursive backtracking or silently falls back to another
//! engine.
//!
//! Single-match search and aggregate iteration have different resource
//! contracts. A single search visits at most one copy of each instruction at
//! each byte boundary. The laboratory iterator intentionally repeats that
//! bounded search and therefore carries a separate, potentially quadratic
//! aggregate certificate; it is a correctness oracle, not a production
//! iterator design.

#![forbid(unsafe_code)]

mod ast;
mod compile;
mod error;
mod history;
mod inline;
mod limits;
mod line;
mod model;
mod profile;
mod runtime;
mod stream;
mod tagged;

pub use ast::{Assertion, Ast, Greed};
pub use compile::{BuildReport, Program};
pub use error::{BuildError, ResourceKind, SearchError};
pub use history::{
    HistoryRegex, PARTICIPATION_QUOTIENT_ACCOUNTING_VERSION,
    PARTICIPATION_QUOTIENT_ALGORITHM_VERSION,
};
pub use inline::InlineRegex;
pub use limits::{AggregateLimits, BuildLimits, SearchLimits};
pub use line::{
    LineMode, LinePartition, LineScanError, LineScanLimits, LineScanProspective, LineScanReport,
    LineScanResource, LineScanner, SemanticBoundary,
};
pub use model::{
    AggregateOutcome, CandidateKind, CaptureCountOutcome, CaptureRecord, GroupRecord,
    HistoryProgramShape, HistorySearchProspective, MatchKind, PARTICIPATION_QUOTIENT_CAPTURE_BITS,
    PARTICIPATION_QUOTIENT_MASK_BITS, ParticipationSearchOutcome, ParticipationSearchProspective,
    RestartedHistoryProspective, RunReport, SearchConfig, SearchKind, SearchOutcome, Span, Window,
};
pub use profile::CaptureProfile;
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
