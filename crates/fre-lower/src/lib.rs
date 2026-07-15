//! Checked lowering from Rust-regex HIR to FRE's prioritized byte automata.
//!
//! This crate is intentionally a narrow integration layer. It supports only
//! expressions whose HIR already has an exact one-byte transition model:
//! empty expressions, byte literals and byte classes, concatenation, ordered
//! alternation, greedy or lazy repetition, whole-haystack start/end assertions,
//! LF line assertions, and ASCII word assertions. Unicode scalar classes,
//! CRLF/Unicode-word assertions, and capture-sensitive operations are rejected
//! explicitly.
//!
//! `RustParsed` does not retain a high-level regex builder's separately
//! configured runtime line byte. This layer therefore implements the literal
//! LF semantics named by `StartLF`/`EndLF`; profile-aware callers must refuse
//! or carry any non-LF runtime configuration before lowering.
//!
//! Construction is iterative. HIR traversal, repetition expansion, graph
//! patching, and final table construction use explicit, quota-checked work
//! storage and checked arithmetic. The resulting graph is still validated by
//! [`fre_automata::Automaton`] before it can execute.

#![forbid(unsafe_code)]

mod compiler;
mod error;

use fre_automata::{Automaton, CompileLimits, RawPlan};
use fre_syntax::RustParsed;
use regex_syntax::hir::Hir;

pub use error::{LowerError, LowerResource, UnsupportedFeature};

/// Whether lowering may erase capture annotations.
///
/// K0 currently exposes capture-free output contracts only. A caller must
/// select [`Self::CaptureFree`] before capture nodes may be erased. Selecting
/// [`Self::CaptureSensitive`] always returns an explicit unsupported error;
/// this prevents an operation planner from silently losing capture semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationSemantics {
    CaptureFree,
    CaptureSensitive,
}

/// Hard limits for one lowering invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LowerLimits {
    /// Charged traversal, explicit-storage movement, graph construction, and
    /// final table writes. Linear work is charged before it executes.
    pub max_work: u64,
    /// Maximum combined explicit task and fragment stack occupancy.
    pub max_stack_items: usize,
    /// Limits used both during emission and by final automaton validation.
    pub automata: CompileLimits,
}

impl Default for LowerLimits {
    fn default() -> Self {
        Self {
            max_work: 8_000_000,
            max_stack_items: 1_000_000,
            automata: CompileLimits::default(),
        }
    }
}

/// Exact lowering charges and emitted graph dimensions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LowerStats {
    work: u64,
    peak_stack_items: usize,
    states: usize,
    edges: usize,
    erased_captures: usize,
}

impl LowerStats {
    #[must_use]
    /// Total charged compilation work, including conservative charges for
    /// vector relocation and every item written to final CSR tables.
    pub const fn work(self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn peak_stack_items(self) -> usize {
        self.peak_stack_items
    }

    #[must_use]
    pub const fn states(self) -> usize {
        self.states
    }

    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }

    #[must_use]
    /// Number of distinct explicit capture annotations erased from the source
    /// HIR. Repeat expansion does not multiply this syntax-level count.
    pub const fn erased_captures(self) -> usize {
        self.erased_captures
    }
}

/// A lowered but not yet independently validated automaton table.
#[derive(Debug)]
pub struct LoweredRaw {
    plan: RawPlan,
    stats: LowerStats,
}

impl LoweredRaw {
    #[must_use]
    pub const fn plan(&self) -> &RawPlan {
        &self.plan
    }

    #[must_use]
    pub const fn stats(&self) -> LowerStats {
        self.stats
    }

    #[must_use]
    pub fn into_plan(self) -> RawPlan {
        self.plan
    }
}

/// A lowered graph that passed the independent `fre-automata` validator.
#[derive(Debug)]
pub struct LoweredAutomaton {
    automaton: Automaton,
    stats: LowerStats,
}

impl LoweredAutomaton {
    #[must_use]
    pub const fn automaton(&self) -> &Automaton {
        &self.automaton
    }

    #[must_use]
    pub const fn stats(&self) -> LowerStats {
        self.stats
    }

    #[must_use]
    pub fn into_automaton(self) -> Automaton {
        self.automaton
    }
}

/// Lower a parsed Rust pattern into mutable interchange tables.
///
/// # Errors
///
/// Returns [`LowerError`] for an unsupported semantic feature, a hard limit,
/// checked arithmetic failure, allocation failure, or internal invariant.
pub fn lower_raw(
    parsed: &RustParsed,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredRaw, LowerError> {
    lower_hir_raw(&parsed.hir, operation, limits)
}

/// Lower HIR directly into mutable interchange tables.
///
/// This is useful for isolated lowering tests. Production integration should
/// normally use [`lower_raw`] so that syntax parsing remains a distinct stage.
///
/// # Errors
///
/// Returns [`LowerError`] under the same conditions as [`lower_raw`].
pub fn lower_hir_raw(
    hir: &Hir,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredRaw, LowerError> {
    let (plan, stats) = compiler::compile(hir, operation, limits)?;
    Ok(LoweredRaw { plan, stats })
}

/// Lower and independently validate a parsed Rust pattern.
///
/// # Errors
///
/// Returns [`LowerError`] when lowering fails or `fre-automata` rejects the
/// emitted graph or its declared construction limits.
pub fn lower(
    parsed: &RustParsed,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredAutomaton, LowerError> {
    lower_hir(&parsed.hir, operation, limits)
}

/// Lower and independently validate HIR directly.
///
/// # Errors
///
/// Returns [`LowerError`] under the same conditions as [`lower`].
pub fn lower_hir(
    hir: &Hir,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredAutomaton, LowerError> {
    let lowered = lower_hir_raw(hir, operation, limits)?;
    let stats = lowered.stats;
    let automaton = Automaton::from_raw(lowered.plan, limits.automata)?;
    Ok(LoweredAutomaton { automaton, stats })
}
