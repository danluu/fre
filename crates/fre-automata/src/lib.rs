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
mod epsilon_closure_dispatch;
mod error;
mod k0;
mod k0_root_corridor;
mod mandatory_cut;
mod mandatory_literal_frontier;
mod mandatory_suffix;
mod ordered_edge_dispatch;
pub mod p16_grep_stream;
mod plan;
mod priority;
mod tagged_many;
mod unicode_look;

pub use contract::{
    EarliestEnd, Exists, K0OrderedResumeCompletion, K0OrderedResumeValue, MatchSpan, Operation,
    OutputContract, SearchAccounting, SearchReport, SelectedEnd, SetupAccounting, Span, TypedPlan,
};
pub use epsilon_closure_dispatch::EpsilonClosureDispatchAllocationError;
pub use error::{CompileError, MalformedPlan, ResourceKind, SearchError};
pub use k0::{
    K0DynamicLoopPlan, K0DynamicLoopStartAction, K0DynamicRootProjection,
    K0FullyPrefilledResumeCacheReceipt,
    K0FullyPrefilledResumeMapProjection, K0FullyPrefilledRootProjection, K0PositiveEndLimits,
    K0PositiveEndOutcome, K0PositiveEndReceipt, K0PositiveEndStartOutcome,
    K0PositiveEndStartVerification, K0PositiveEndVerification, K0ResumeSet, K0SearchSession,
    K0SpanSourceCursor, K0Workspace, WorkspaceLayout, WorkspaceLimits,
};
pub use mandatory_cut::{
    DEFAULT_MANDATORY_CUT_MAX_ALLOCATION_ATTEMPTS, DEFAULT_MANDATORY_CUT_MAX_ALLOCATION_ITEMS,
    DEFAULT_MANDATORY_CUT_MAX_WORK, MANDATORY_CUT_ACCOUNTING_ID, MandatoryCutAnalysis,
    MandatoryCutAnalysisDecline, MandatoryCutAnalysisLimits, MandatoryCutAnalysisReport,
    MandatoryCutAnalysisStats, MandatoryCutByteClass, MandatoryCutCandidate,
    MandatoryCutContinuation, MandatoryCutContinuationAnalysis, MandatoryCutDeclineReason,
    MandatoryCutGraphIssue, MandatoryCutResource, MaximumConsumedDistance,
    analyze_mandatory_cut, analyze_mandatory_cut_continuation,
};
pub use mandatory_literal_frontier::{
    DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_ALLOCATION_ATTEMPTS,
    DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_ALLOCATION_ITEMS,
    DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_CONFIGURATIONS,
    DEFAULT_MANDATORY_LITERAL_FRONTIER_MAX_WORK, MANDATORY_LITERAL_FRONTIER_ACCOUNTING_ID,
    MAX_MANDATORY_LITERAL_FRONTIER_BYTES, MAX_MANDATORY_LITERAL_FRONTIER_LITERALS,
    MAX_MANDATORY_LITERAL_FRONTIER_ROOT_BYTES, MAX_MANDATORY_LITERAL_FRONTIER_TOTAL_BYTES,
    MIN_MANDATORY_LITERAL_FRONTIER_BYTES, MandatoryLiteralFrontierAnalysis,
    MandatoryLiteralFrontierAnalysisDecline, MandatoryLiteralFrontierAnalysisLimits,
    MandatoryLiteralFrontierAnalysisReport, MandatoryLiteralFrontierAnalysisStats,
    MandatoryLiteralFrontierCandidate, MandatoryLiteralFrontierDeclineReason,
    MandatoryLiteralFrontierIter, MandatoryLiteralFrontierResource,
    MandatoryLiteralFrontierStopReason, analyze_mandatory_literal_frontier,
    continue_mandatory_literal_frontier,
};
pub use mandatory_suffix::{
    DEFAULT_MANDATORY_SUFFIX_MAX_ALLOCATION_ATTEMPTS,
    DEFAULT_MANDATORY_SUFFIX_MAX_ALLOCATION_ITEMS, DEFAULT_MANDATORY_SUFFIX_MAX_BYTES,
    DEFAULT_MANDATORY_SUFFIX_MAX_WORK, MANDATORY_SUFFIX_ACCOUNTING_ID,
    MANDATORY_SUFFIX_UNIVERSAL_FINITE_CORRIDOR_ACCOUNTING_ID,
    MAX_MANDATORY_SUFFIX_BYTES, MAX_MANDATORY_SUFFIX_UNIVERSAL_CORRIDOR_PREFIX_BYTES,
    MandatorySuffixAnalysis, MandatorySuffixAnalysisDecline,
    MandatorySuffixAnalysisLimits, MandatorySuffixAnalysisReport, MandatorySuffixAnalysisStats,
    MandatorySuffixCandidate, MandatorySuffixDeclineReason, MandatorySuffixGraphIssue,
    MandatorySuffixResource, MandatorySuffixStopReason,
    MandatorySuffixUniversalFiniteCorridor, MandatorySuffixUniversalFiniteCorridorAnalysis,
    MandatorySuffixUniversalFiniteCorridorDecline,
    MandatorySuffixUniversalFiniteCorridorDeclineReason,
    MandatorySuffixUniversalFiniteCorridorReport, MandatorySuffixUniversalFiniteCorridorStats,
    analyze_mandatory_suffix, analyze_mandatory_suffix_universal_finite_corridor,
};
pub use ordered_edge_dispatch::OrderedEdgeDispatchAllocationError;
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
