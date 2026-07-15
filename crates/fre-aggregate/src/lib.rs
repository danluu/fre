//! Bounded whole-operation regex iteration for FRE.
//!
//! This crate accepts canonical [`regex_syntax::hir::Hir`] for pinned Rust
//! regex byte profiles. Unicode-off admits the complete byte program below;
//! Unicode-on admits the same byte-stable subset after parsing has expanded
//! literals, including positive Unicode word boundaries, but refuses
//! variable-width Unicode classes and the remaining Unicode word assertion
//! forms. The semantic program is capture-free and consists of empty
//! expressions, byte literals, byte classes, ordered alternation,
//! concatenation, whole-operation absolute and LF-aware line assertions,
//! ASCII word assertions, positive Unicode word boundaries, and arbitrary
//! nested greedy or lazy repetition.
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
//! [`Strategy::FullTable`] and [`Strategy::ReverseSequentialRows`]. Both have
//! checked whole-operation work and storage certificates. A public pull
//! iterator is only created after the entire match sequence has been admitted
//! and evaluated, so repeated calls cannot evade a resource limit.

#![forbid(unsafe_code)]

mod accounting;
mod compile;
mod error;
mod limits;
mod operation;
mod program;

pub use accounting::{CompileAccounting, ExecutionAccounting};
pub use compile::{CompiledRegex, PlanId, RustByteProfile};
pub use error::{Error, Resource, Unsupported};
pub use limits::{CompileLimits, OperationLimits};
pub use operation::{
    AdmittedCount, AdmittedSpanSum, AdmittedSpans, MatchCount, OperationCertificate, OperationId,
    Span, SpanIter, SpanIteration, SpanSum, Strategy,
};
