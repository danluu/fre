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
}

/// Derive fixed continuation-sweep bounds from authenticated program states.
///
/// # Errors
///
/// Returns an arithmetic error when the prospective dimensions do not fit.
pub fn continuation_sweep_upper_bounds(
    program_states: usize,
) -> Result<ContinuationSweepUpperBounds, Error> {
    lazy::upper_bounds(program_states)
}

/// Caller-owned persistent transition cache for ordinary continuation values.
///
/// Preparation is fallible on the first eligible call. Calls with the same
/// compiled plan retain every learned transition and do not allocate in
/// steady state. Rebinding to another plan releases the old cache before
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

    /// Allocator-reported bytes retained by a prepared continuation cache.
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
/// `Ok(None)` is a source-free structural refusal. Preparation resource use
/// and execution share one operation budget. If a transition cannot fit the
/// fixed cache, execution carries the ordered frontier forward inline from the
/// current source position; it never rereads a prefix or restarts through the
/// incumbent. The saturated cache is dropped after the operation, so the next
/// call selects its incumbent source-free.
pub(crate) fn reduce_lazy(
    plan_id: PlanId,
    program: &Program,
    haystack: &[u8],
    range: Range<usize>,
    kind: SweepKind,
    limits: OperationLimits,
    workspace: &mut ContinuationSweepWorkspace,
) -> Result<Option<SweepOutcome>, Error> {
    lazy::reduce(
        plan_id,
        program,
        haystack,
        range,
        kind,
        limits,
        &mut workspace.lazy,
    )
}

struct SweepMeter {
    limits: OperationLimits,
    work: usize,
    sequential: usize,
    events: usize,
}

impl SweepMeter {
    const fn new(limits: OperationLimits) -> Self {
        Self {
            limits,
            work: 0,
            sequential: 0,
            events: 0,
        }
    }

    #[inline]
    fn charge_work(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.work, amount, Resource::ExecutionWork)?;
        enforce(required, self.limits.max_work, Resource::ExecutionWork)?;
        self.work = required;
        Ok(())
    }

    #[inline]
    fn charge_sequential(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.sequential, amount, Resource::SequentialBytes)?;
        enforce(
            required,
            self.limits.max_sequential_bytes,
            Resource::SequentialBytes,
        )?;
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
