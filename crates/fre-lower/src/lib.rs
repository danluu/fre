//! Checked lowering from Rust-regex HIR to FRE's prioritized byte automata.
//!
//! This crate is intentionally a narrow integration layer. It supports only
//! expressions whose HIR has an exact byte-automaton representation: empty
//! expressions, byte literals and byte classes, Unicode scalar classes lowered
//! to canonical valid-UTF-8 byte paths, concatenation, ordered alternation,
//! greedy or lazy repetition, whole-haystack start/end assertions, configured
//! single-byte and CRLF-aware line assertions, and every pinned ASCII or
//! Unicode word assertion. Capture-sensitive operations are rejected
//! explicitly.
//!
//! `RustParsed` does not retain a high-level regex builder's separately
//! configured runtime line byte. Standalone lowered automata therefore use LF
//! by default. Profile-aware callers bind their line byte on the validated
//! automaton before publication; `StartLF`/`EndLF` are regex-syntax's
//! historical variant names, not a requirement to hard-code LF.
//!
//! Construction is iterative. HIR traversal, repetition expansion, graph
//! patching, and final table construction use explicit, quota-checked work
//! storage and checked arithmetic. The resulting graph is still validated by
//! [`fre_automata::Automaton`] before it can execute.

#![forbid(unsafe_code)]

mod compiler;
mod error;
pub mod facts;

use fre_automata::{Automaton, CompileLimits, RawPlan};
use fre_syntax::RustParsed;
use regex_syntax::hir::Hir;

pub use error::{LowerError, LowerResource, UnsupportedFeature};
pub use facts::{
    AffixCertificate, AssertionFacts, BoundedContext, CaptureFacts, CaptureParticipation,
    CertificatePreconditions, CheckedWidth, DeterminismFacts, DeterministicCertificate,
    FactCaptureSemantics, FactError, FactIdentity, FactLimits, FactOperation, FactOptionalProofs,
    FactOutput, FactProof, FactProspective, FactRefusal, FactResource, FactStats, FiniteLanguage,
    HIR_FACT_ACCOUNTING_VERSION, HIR_FACT_ALGORITHM_VERSION, HirFacts, OnePassCertificate,
    PositionedAssertion, PositionedCapture, ReductionFacts, RequiredAlternatives, RequiredString,
    StringEncoding, UnicodeFacts, WidthRange, analyze_facts, analyze_hir_facts,
};

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
    normalized_nullable_repetitions: usize,
    utf8_start_guarded: bool,
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

    #[must_use]
    /// Number of capture-free nullable nested repetitions replaced by their
    /// certified equivalent positive-width repetition before graph emission.
    pub const fn normalized_nullable_repetitions(self) -> usize {
        self.normalized_nullable_repetitions
    }

    #[must_use]
    /// Whether lowering synthesized a Unicode scalar-boundary assertion before
    /// every candidate start. This is used only after the text facade proves a
    /// valid UTF-8 haystack and byte-equivalent HIR.
    pub const fn utf8_start_guarded(self) -> bool {
        self.utf8_start_guarded
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

/// Lower a parsed Rust pattern with the general leftmost-first Thompson
/// construction.
///
/// Unlike [`lower_raw`], this route does not require a source-shape
/// normalization certificate for an unbounded nullable repetition. It
/// structurally compiles nullable `x*` as `(x+)?`, which is the general
/// leftmost-first construction. This route may therefore contain finite
/// epsilon cycles; executors must use a per-position visited set.
///
/// This is the lowering entry used by the general AOT compiler. The legacy
/// route remains separate so existing facade plan identities do not change.
///
/// # Errors
///
/// Returns [`LowerError`] for an unsupported semantic feature, a hard limit,
/// checked arithmetic failure, allocation failure, or internal invariant.
pub fn lower_raw_general(
    parsed: &RustParsed,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredRaw, LowerError> {
    lower_hir_raw_general(&parsed.hir, operation, limits)
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
    let (plan, stats) = compiler::compile(hir, operation, limits, false)?;
    Ok(LoweredRaw { plan, stats })
}

/// Lower HIR directly through the general nullable-repetition construction.
///
/// This is the HIR-level counterpart of [`lower_raw_general`].
///
/// # Errors
///
/// Returns [`LowerError`] under the same checked limits as
/// [`lower_raw_general`].
pub fn lower_hir_raw_general(
    hir: &Hir,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredRaw, LowerError> {
    let (plan, stats) = compiler::compile_general(hir, operation, limits, false)?;
    Ok(LoweredRaw { plan, stats })
}

/// Lower a parsed Rust pattern with a synthesized UTF-8 scalar-boundary guard
/// on every candidate match start, then independently validate it.
///
/// This is an integration primitive for the Rust text facade. Callers must
/// separately prove that the haystack is valid UTF-8 and that the parsed HIR
/// is byte-equivalent to the text expression. Bytes-facing APIs must use
/// [`lower`] so that arbitrary byte offsets remain observable.
///
/// # Errors
///
/// Returns [`LowerError`] under the same checked limits and invariants as
/// [`lower`].
pub fn lower_utf8_start_guarded(
    parsed: &RustParsed,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredAutomaton, LowerError> {
    if operation == OperationSemantics::CaptureSensitive {
        return Err(LowerError::Unsupported(
            UnsupportedFeature::CaptureSensitiveOperation,
        ));
    }
    let (plan, stats) = compiler::compile(&parsed.hir, operation, limits, true)?;
    let automaton = Automaton::from_raw(plan, limits.automata)?;
    Ok(LoweredAutomaton { automaton, stats })
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

/// Lower and independently validate a parsed Rust pattern through the general
/// nullable-repetition construction.
///
/// This is the validated counterpart of [`lower_raw_general`].
///
/// # Errors
///
/// Returns [`LowerError`] under the same checked limits as [`lower`].
pub fn lower_general(
    parsed: &RustParsed,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredAutomaton, LowerError> {
    lower_hir_general(&parsed.hir, operation, limits)
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

/// Lower a borrowed sequence of HIR nodes as one concatenation and
/// independently validate the result.
///
/// This avoids constructing or cloning an owned [`Hir`] when a caller already
/// has a checked slice of a larger concatenation. The capture census, borrowed
/// traversal, explicit compiler stacks and emitted graph all remain subject to
/// this invocation's [`LowerLimits`].
///
/// # Errors
///
/// Returns [`LowerError`] under the same conditions as [`lower_hir`].
pub fn lower_hir_concat_slice(
    parts: &[Hir],
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredAutomaton, LowerError> {
    let (plan, stats) = compiler::compile_concat_slice(parts, operation, limits)?;
    let automaton = Automaton::from_raw(plan, limits.automata)?;
    Ok(LoweredAutomaton { automaton, stats })
}

/// Lower and independently validate HIR through the general
/// nullable-repetition construction.
///
/// # Errors
///
/// Returns [`LowerError`] under the same checked limits as [`lower_general`].
pub fn lower_hir_general(
    hir: &Hir,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<LoweredAutomaton, LowerError> {
    let lowered = lower_hir_raw_general(hir, operation, limits)?;
    let stats = lowered.stats;
    let automaton = Automaton::from_raw(lowered.plan, limits.automata)?;
    Ok(LoweredAutomaton { automaton, stats })
}
