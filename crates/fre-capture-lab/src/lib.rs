//! Bounded engines for exact regular-expression capture semantics.
//!
//! This crate implements the small capture-aware AST and tagged execution core
//! for the pinned Rust byte-regex leftmost-first profile. The production `fre`
//! facade owns syntax/profile admission and exposes only its qualified HIR
//! subset. [`InlineRegex`] remains a comparative formulation, while
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
mod model;
mod profile;
mod runtime;

pub use ast::{AsciiWordLook, Ast, Greed};
pub use compile::{BuildReport, Program};
pub use error::{BuildError, ResourceKind, SearchError};
pub use history::HistoryRegex;
pub use inline::InlineRegex;
pub use limits::{AggregateLimits, BuildLimits, SearchLimits};
pub use model::{
    AggregateOutcome, CandidateKind, CaptureCountOutcome, CaptureRecord, GroupRecord, RunReport,
    SearchOutcome, Span, Window,
};
pub use profile::CaptureProfile;
