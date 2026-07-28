//! Persistent lazy-DFA workspace for byte-only continuation reductions.
//!
//! Eligible value calls carry their ordered frontier through one forward
//! direct-index transition cache. Count consumes selected endpoints directly;
//! SpanSum uses a second reverse cache to recover each selected start. Cache
//! state belongs to the caller workspace and is independent of haystack
//! identity and length.

use core::ops::Range;

use crate::compile::PlanId;
use crate::error::{add, enforce};
use crate::program::Program;
use crate::{Error, OperationLimits, Resource};

mod lazy;

/// Source-independent fixed-arena bounds for the continuation sweep route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuationSweepUpperBounds {
    /// Direct transition cells across the forward and reverse caches.
    pub table_cells: usize,
    /// Exact fixed-arena bytes under the conservative graph-edge census.
    pub workspace_bytes: usize,
    /// Conservative charged work for allocation initialization and graph setup.
    pub preparation_work: usize,
    /// Bounded speculative work used only to retain new direct transitions.
    ///
    /// Exhausting this allowance switches the current frontier to inline
    /// execution and cannot make the operation terminal.
    pub learning_work: usize,
    /// Maximum non-accepting bytes after an ordered acceptance. `None` means
    /// no finite compiler certificate was supplied, including an unbounded
    /// non-accepting consume cycle.
    pub max_nonaccepting_run: Option<usize>,
    /// Authenticated positive whole-match minimum for match-count bounds.
    ///
    /// State-count-only prospective envelopes publish `None` and retain the
    /// conservative one-byte minimum.
    pub minimum_match_bytes: Option<usize>,
}

/// Source-free mandatory bounds for one continuation sweep operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuationSweepRunUpperBounds {
    /// Mandatory Count execution work, excluding cold preparation and
    /// optional transition learning.
    pub count_work: usize,
    /// Mandatory SpanSum execution work, excluding cold preparation and
    /// optional transition learning.
    pub span_sum_work: usize,
    /// Maximum Count source-byte visits.
    pub count_sequential_bytes: usize,
    /// Maximum SpanSum source-byte visits, including disjoint reverse walks.
    pub span_sum_sequential_bytes: usize,
}

/// Derive fixed continuation-sweep bounds from authenticated program states.
///
/// # Errors
///
/// Returns an arithmetic error when the prospective dimensions do not fit.
pub fn continuation_sweep_upper_bounds(
    program_states: usize,
) -> Result<ContinuationSweepUpperBounds, Error> {
    lazy::upper_bounds(program_states, None, None)
}

pub(crate) fn continuation_sweep_upper_bounds_with_run(
    program_states: usize,
    max_nonaccepting_run: Option<usize>,
    minimum_match_bytes: Option<usize>,
) -> Result<ContinuationSweepUpperBounds, Error> {
    lazy::upper_bounds(program_states, max_nonaccepting_run, minimum_match_bytes)
}

/// Derive mandatory per-operation bounds for a published continuation sweep.
///
/// The program's authenticated execution-state work is supplied separately
/// because it is tighter than the state-count-only public fixed envelope.
pub fn continuation_sweep_run_upper_bounds(
    fixed: ContinuationSweepUpperBounds,
    input_bytes: usize,
    execution_state_work: usize,
) -> Result<ContinuationSweepRunUpperBounds, Error> {
    lazy::run_upper_bounds(
        input_bytes,
        execution_state_work,
        fixed.max_nonaccepting_run,
        fixed.minimum_match_bytes.unwrap_or(1),
    )
}

/// Caller-owned persistent transition cache for ordinary continuation values.
///
/// Preparation is fallible on the first eligible call. Calls with the same
/// compiled plan retain observed transitions and do not allocate in steady
/// state. Resource refusal or saturation can replace the arena with a compact
/// plan-bound disabled marker. Rebinding releases the old cache before
/// constructing the new plan's fixed-capacity workspace.
#[derive(Debug, Default)]
pub struct ContinuationSweepWorkspace {
    lazy: lazy::Workspace,
}

impl ContinuationSweepWorkspace {
    /// Create an empty workspace.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lazy: lazy::Workspace::new(),
        }
    }

    /// Allocator-reported bytes retained by a prepared cache or disabled
    /// marker. `Some(0)` denotes a plan-bound refusal after the arena was
    /// released.
    #[must_use]
    pub const fn retained_bytes(&self) -> Option<usize> {
        self.lazy.retained_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SweepKind {
    Count,
    SpanSum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SweepValue {
    pub(crate) count: usize,
    pub(crate) span_sum: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SweepOutcome {
    Complete(SweepValue),
}

/// Execute an assertion-free, non-nullable byte program through its
/// persistent ordered lazy DFA.
///
/// `Ok(None)` is a source-free structural or resource refusal. Cold
/// preparation and mandatory execution are admitted together. Optional
/// transition learning uses only remaining speculative work; if it or the
/// fixed cache fills, execution carries the ordered frontier forward inline
/// from the current source position. It never rereads a prefix or restarts
/// through the incumbent. The saturated cache is dropped after the operation,
/// so the next call selects its incumbent source-free.
pub(crate) fn reduce_lazy(
    plan_id: PlanId,
    program: &Program,
    haystack: &[u8],
    range: Range<usize>,
    kind: SweepKind,
    minimum_match_bytes: Option<usize>,
    limits: OperationLimits,
    workspace: &mut ContinuationSweepWorkspace,
) -> Result<Option<SweepOutcome>, Error> {
    lazy::reduce(
        plan_id,
        program,
        haystack,
        range,
        kind,
        minimum_match_bytes,
        limits,
        &mut workspace.lazy,
    )
}

struct SweepMeter {
    limits: OperationLimits,
    work: usize,
    cache_work_remaining: usize,
    sequential: usize,
    events: usize,
}

impl SweepMeter {
    const fn new(limits: OperationLimits) -> Self {
        Self {
            limits,
            work: 0,
            cache_work_remaining: 0,
            sequential: 0,
            events: 0,
        }
    }

    const fn with_cache_budget(limits: OperationLimits, cache_work: usize) -> Self {
        Self {
            limits,
            work: 0,
            cache_work_remaining: cache_work,
            sequential: 0,
            events: 0,
        }
    }

    #[inline]
    fn charge_work(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.work, amount, Resource::ExecutionWork)?;
        enforce(required, self.limits.max_work, Resource::ExecutionWork)?;
        #[cfg(test)]
        lazy::test_fault::record_work(amount);
        self.work = required;
        Ok(())
    }

    #[inline]
    fn charge_cache_work(&mut self, amount: usize) -> Result<bool, Error> {
        if amount > self.cache_work_remaining {
            return Ok(false);
        }
        self.charge_work(amount)?;
        self.cache_work_remaining -= amount;
        Ok(true)
    }

    #[inline]
    fn charge_sequential(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.sequential, amount, Resource::SequentialBytes)?;
        enforce(
            required,
            self.limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
        #[cfg(test)]
        lazy::test_fault::record_source_bytes(amount);
        self.sequential = required;
        Ok(())
    }

    fn charge_event(&mut self) -> Result<(), Error> {
        self.charge_work(1)?;
        let required = add(self.events, 1, Resource::MatchEvents)?;
        enforce(
            required,
            self.limits.max_match_events,
            Resource::MatchEvents,
        )?;
        self.events = required;
        Ok(())
    }

    fn enforce_terminal_limits(&self) -> Result<(), Error> {
        enforce(self.work, self.limits.max_work, Resource::ExecutionWork)
    }
}
