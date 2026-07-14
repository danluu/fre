//! Bounded research prototypes for exact aggregate regex iteration.
//!
//! This crate investigates capture-free, byte-oriented, Rust-style
//! non-overlapping leftmost-first iteration. It deliberately supports a small
//! syntax subset whose boundary is represented by [`Ast`] itself. The legacy
//! [`Ast::Repeat`] keeps an ordered list of [`RepeatAtom`] values. The
//! generalized [`Ast::Repetition`] accepts an arbitrary nested capture-free
//! child with `*`, `+`, `?`, finite or open ranges and greedy/lazy priority.
//! Its progress-product lowering makes every generated loop backedge consume
//! without erasing nullable alternatives. Captures, Unicode, look-around,
//! word/line assertions and subrange searches remain unsupported.
//!
//! The full-table, packed-log and reverse-sequential-row-log executors share
//! the progress-product compiler. [`GuardedRegex`] separately keys recurrence
//! cells by explicit saved iteration starts. [`CompiledRegex::find_all_oracle`]
//! intentionally repeats a bounded suffix-table search and is only a test
//! oracle. Candidate executors never call it as a fallback.

#![forbid(unsafe_code)]

mod accounting;
mod ast;
mod compile;
mod decision_log;
mod error;
mod full_dp;
mod guarded;
mod iterate;
mod oracle;
mod sequential_log;

pub use accounting::{Accounting, RunReport};
pub use ast::{Ast, Greed, RepeatAtom};
pub use compile::{CompileLimits, CompiledRegex};
pub use error::{Error, ResourceKind};
pub use guarded::GuardedRegex;
pub use iterate::Span;
