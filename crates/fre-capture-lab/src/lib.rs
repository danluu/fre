//! Bounded research prototypes for exact regular-expression capture semantics.
//!
//! This crate is an isolated laboratory for the pinned Rust byte-regex
//! leftmost-first profile. It deliberately exposes a small AST instead of
//! claiming to parse the complete Rust or RE2 syntaxes. A checked compiler
//! lowers that AST to one immutable prioritized tagged Thompson program.
//! [`InlineRegex`] executes it with inline capture vectors, while
//! [`HistoryRegex`] uses persistent capture histories. Neither executor uses
//! recursive backtracking, and neither can silently fall back to another
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
mod model;
mod profile;
mod runtime;

pub use ast::{Ast, Greed};
pub use compile::{BuildReport, Program};
pub use error::{BuildError, ResourceKind, SearchError};
pub use history::HistoryRegex;
pub use inline::InlineRegex;
pub use limits::{AggregateLimits, BuildLimits, SearchLimits};
pub use model::{
    AggregateOutcome, CandidateKind, CaptureRecord, GroupRecord, RunReport, SearchOutcome, Span,
    Window,
};
pub use profile::CaptureProfile;
