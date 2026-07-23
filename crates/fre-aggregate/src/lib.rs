//! Bounded whole-operation regex iteration for FRE.
//!
//! This crate accepts canonical [`regex_syntax::hir::Hir`] for pinned Rust
//! regex byte profiles. Unicode-off admits the complete byte program below;
//! Unicode-on additionally retains scalar classes as bounded scalar-consuming
//! transitions at canonical UTF-8 boundaries and admits positive Unicode word
//! boundaries, while refusing the remaining Unicode word assertion forms. The
//! semantic program is capture-free and consists of empty
//! expressions, byte literals, byte classes, ordered alternation,
//! concatenation, whole-operation absolute and LF-aware line assertions,
//! ASCII word assertions, positive Unicode word boundaries, and arbitrary
//! nested greedy or lazy repetition.
//! Positive Unicode word-boundary operations make a typed admission refusal
//! for malformed UTF-8 instead of approximating range-dependent byte-regex
//! iteration behavior.
//! Assertions always inspect their absolute
//! boundary in the original haystack, even for an interior operation range;
//! byte-consuming transitions remain confined to that range.
//! The default compiler rejects capture HIR. A separate whole-match-only entry
//! point transparently traverses capture children inside the same bounded
//! compiler and accounts every erased annotation; it cannot return captures.
//!
//! Nullable unbounded repetitions are compiled with a zero/progress product.
//! Consequently, every cycle in the resulting continuation graph consumes a
//! byte; same-boundary dependencies are certified acyclic. Execution computes
//! one complete operation over the requested input range. It never implements
//! global iteration by repeatedly searching overlapping suffixes.
//!
//! Two independently selectable storage strategies are provided:
//! [`Strategy::FullTable`] and [`Strategy::ReverseSequentialRows`]. Reverse
//! rows construction-selects the narrower of split/root decisions and a
//! minimally encoded reachable endpoint per input boundary. Both strategies
//! have checked whole-operation work and storage certificates. A public pull
//! iterator is only created after the entire match sequence has been admitted
//! and evaluated, so repeated calls cannot evade a resource limit.

#![forbid(unsafe_code)]

mod accounting;
#[allow(
    dead_code,
    reason = "the finite-anchor certifier is landed independently before its reviewed executor"
)]
mod anchored_island;
mod candidate;
mod compile;
mod error;
mod limits;
mod operation;
mod program;
mod required_internal_anchor;

pub use accounting::{CompileAccounting, ExecutionAccounting};
pub use compile::{
    CompileAttemptError, CompileAttemptIdentity, CompileAttemptKind, CompileAttemptReceipt,
    CompiledRegex, PlanId, RustByteProfile,
};
pub use error::{Error, Resource, Unsupported};
pub use limits::{CompileLimits, OperationLimits};
pub use operation::{
    AdmittedCount, AdmittedCountAttempt, AdmittedSpanSum, AdmittedSpanSumAttempt, AdmittedSpans,
    AdmittedSpansAttempt, CONTINUATION_OPERATION_ACCOUNTING_VERSION,
    CONTINUATION_OPERATION_ALGORITHM_VERSION, CountValueAttempt, MatchCount, OperationAttemptError,
    OperationAttemptIdentity, OperationAttemptKind, OperationAttemptReceipt, OperationCertificate,
    OperationId, OperationInvocation, OperationPhysicalRoute, OperationPrepublicationFallback,
    OperationProspective, OperationWorkMode, RowStorage, Span, SpanIter, SpanIteration, SpanSum,
    SpanSumValueAttempt, Strategy,
};
