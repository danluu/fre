//! Canonical bounded automata and the portable capture-free K0 search floor.
//!
//! This crate intentionally starts below syntax lowering. It accepts a manually
//! constructed prioritized Thompson graph, validates and freezes it into
//! structure-of-arrays storage, and executes it with a non-recursive ordered
//! Pike scan. It is not a parser and does not claim Rust `regex` or RE2 syntax
//! compatibility.
//!
//! The graph is automaton data, not executable regex bytecode: execution keeps
//! sets of active consuming states and computes ordered zero-width closure over
//! graph edges. There is no instruction pointer, call stack, or backtracking
//! stack. Unicode word assertions use the pinned directional decoder for at
//! most one scalar on each side and the workspace-pinned UTS#18 word table;
//! malformed leading bytes are non-word context and cannot be consumed by
//! scalar paths.

#![forbid(unsafe_code)]

mod contract;
mod error;
mod k0;
mod k0_root_corridor;
mod mandatory_cut;
mod mandatory_suffix;
pub mod p16_grep_stream;
mod plan;
mod priority;
mod tagged_many;
mod unicode_look;

pub use contract::{
    EarliestEnd, Exists, MatchSpan, Operation, OutputContract, SearchAccounting, SearchReport,
    SelectedEnd, SetupAccounting, Span, TypedPlan,
};
pub use error::{CompileError, MalformedPlan, ResourceKind, SearchError};
pub use k0::{
    K0PositiveEndLimits, K0PositiveEndOutcome, K0PositiveEndReceipt,
    K0PositiveEndStartOutcome, K0PositiveEndStartVerification, K0PositiveEndVerification,
    K0ResumeSet, K0SearchSession, K0SpanSourceCursor, K0Workspace, WorkspaceLayout, WorkspaceLimits,
};
pub use mandatory_cut::{
    DEFAULT_MANDATORY_CUT_MAX_ALLOCATION_ATTEMPTS, DEFAULT_MANDATORY_CUT_MAX_ALLOCATION_ITEMS,
    DEFAULT_MANDATORY_CUT_MAX_WORK, MANDATORY_CUT_ACCOUNTING_ID, MandatoryCutAnalysis,
    MandatoryCutAnalysisDecline, MandatoryCutAnalysisLimits, MandatoryCutAnalysisReport,
    MandatoryCutAnalysisStats, MandatoryCutByteClass, MandatoryCutCandidate,
    MandatoryCutDeclineReason, MandatoryCutGraphIssue, MandatoryCutResource,
    MaximumConsumedDistance, analyze_mandatory_cut,
};
pub use mandatory_suffix::{
    DEFAULT_MANDATORY_SUFFIX_MAX_ALLOCATION_ATTEMPTS,
    DEFAULT_MANDATORY_SUFFIX_MAX_ALLOCATION_ITEMS, DEFAULT_MANDATORY_SUFFIX_MAX_BYTES,
    DEFAULT_MANDATORY_SUFFIX_MAX_WORK, MANDATORY_SUFFIX_ACCOUNTING_ID,
    MAX_MANDATORY_SUFFIX_BYTES, MandatorySuffixAnalysis, MandatorySuffixAnalysisDecline,
    MandatorySuffixAnalysisLimits, MandatorySuffixAnalysisReport, MandatorySuffixAnalysisStats,
    MandatorySuffixCandidate, MandatorySuffixDeclineReason, MandatorySuffixGraphIssue,
    MandatorySuffixResource, MandatorySuffixStopReason, analyze_mandatory_suffix,
};
pub use plan::{
    Automaton, CompileLimits, EdgeKind, PlanStats, RawPlan, SearchLimits, SearchWindow, StateRole,
};
pub use priority::{
    ActionCapabilities, DirectCount, DirectReduceLimits, DirectReduceReport,
    DirectReduceTraceReport, DirectReduceValue, DirectSpanSum, EmptyMatchProgress, ExecutionActual,
    ExecutionProspective, ForcedExecution, MatchLengthProof, PatternAction, PatternOrdinal,
    PreparationAccounting, PreparationError, PreparationLimits, PreparationProspective,
    PreparationResource, PreparedPriorityAutomaton, PriorityAutomataFacts, PriorityExecutionKernel,
    PriorityMatch, PriorityTarget, ReduceError, PRIORITY_ACCOUNTING_ID,
};
pub use tagged_many::{
    TaggedManyBuildAccounting, TaggedManyBuildError, TaggedManyBuildLimits,
    TaggedManyExecutionClass, TaggedManyPlan, TaggedManyStats, TaggedManyTraceSession,
    TaggedManyTraceSessionReport, TaggedManyTraceSessionSetupProspective,
    TAGGED_MANY_ACCOUNTING_ID, TAGGED_MANY_BUILD_ALLOCATION_ATTEMPTS,
};
pub use unicode_look::{UnicodeLookError, UnicodeLookMatcher};
