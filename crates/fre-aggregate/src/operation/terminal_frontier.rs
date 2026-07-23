use super::{
    Requirements, RowStorage, RowStore, add, encode, enforce, mul, set_bit, try_charge_amount,
    try_charge_assertion, try_charge_transition, write_encoded,
};
use crate::accounting::ExecutionAccounting;
use crate::compile::TerminalFrontierSeed;
use crate::program::{AssertionContext, Inst, NO_SPLIT_RANK, Program};
use crate::{Error, OperationLimits, Resource};
use fre_exact_alloc::{ExactVec, zeroed_exact};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrontierRequirements {
    pub(super) bytes: usize,
    pub(super) source_bytes_bound: usize,
    active_limit: usize,
    sweep_work_limit: usize,
    prefix_work_bound: usize,
    post_build_work: usize,
    minimum_work: usize,
}

#[derive(Clone, Copy)]
struct Layout {
    states: usize,
    edges: usize,
    candidate_words: usize,
    summary_words: usize,
    total_words: usize,
    bytes: usize,
}

impl Layout {
    fn new(program: &Program) -> Result<Self, Error> {
        let states = program.insts.len();
        if states == 0 || program.contains_scalar_transition() {
            return Err(Error::InternalInvariant(
                "terminal frontier requires a nonempty byte program",
            ));
        }
        let edges = program.predecessor_edges();
        let candidate_words = bit_words(states)?;
        let summary_words = bit_words(candidate_words)?;
        let index_words = add(
            add(states, 1, Resource::ScratchBytes)?,
            edges,
            Resource::ScratchBytes,
        )?;
        let state_words = mul(states, 3, Resource::ScratchBytes)?;
        let ordered_words = add(candidate_words, summary_words, Resource::ScratchBytes)?;
        let total_words = add(
            add(index_words, state_words, Resource::ScratchBytes)?,
            ordered_words,
            Resource::ScratchBytes,
        )?;
        let bytes = mul(
            total_words,
            core::mem::size_of::<usize>(),
            Resource::ScratchBytes,
        )?;
        Ok(Self {
            states,
            edges,
            candidate_words,
            summary_words,
            total_words,
            bytes,
        })
    }

    fn fixed_work(self) -> Result<usize, Error> {
        let instruction_passes = mul(self.states, 2, Resource::ExecutionWork)?;
        let edge_passes = mul(self.edges, 2, Resource::ExecutionWork)?;
        let prefix_and_copy = mul(self.states, 2, Resource::ExecutionWork)?;
        add(
            self.total_words,
            add(
                instruction_passes,
                add(edge_passes, prefix_and_copy, Resource::ExecutionWork)?,
                Resource::ExecutionWork,
            )?,
            Resource::ExecutionWork,
        )
    }
}

pub(super) fn requirements(
    program: &Program,
    seed: &TerminalFrontierSeed,
    boundaries: usize,
    log_bytes: usize,
    post_build_work: usize,
    limits: OperationLimits,
) -> Result<FrontierRequirements, Error> {
    let layout = Layout::new(program)?;
    let haystack_len = boundaries.checked_sub(1).ok_or(Error::InternalInvariant(
        "terminal frontier has no boundary",
    ))?;
    let prefix_starts = match haystack_len.checked_sub(seed.prefix_len()) {
        Some(remaining) => add(remaining, 1, Resource::Boundaries)?,
        None => 0,
    };
    let prefix_work_bound = mul(prefix_starts, seed.prefix_len(), Resource::ExecutionWork)?;
    let sweep_source = mul(haystack_len, 4, Resource::SequentialBytes)?;
    let source_bytes_bound = add(prefix_work_bound, sweep_source, Resource::SequentialBytes)?;

    // One prefix census, fixed index construction, two identical frontier
    // sweeps, one between-sweep reset, two complete log writes (zeroing plus
    // production), and the already-derived selector/replay bound must all fit
    // the caller's existing work quota. `active_limit` is deliberately below
    // the program-state count, so an all-live row is a typed refusal rather
    // than an accidental O(NQ) fallback.
    let fixed = layout.fixed_work()?;
    let log_work = mul(log_bytes, 2, Resource::ExecutionWork)?;
    let non_sweep = add(
        add(fixed, prefix_work_bound, Resource::ExecutionWork)?,
        add(log_work, post_build_work, Resource::ExecutionWork)?,
        Resource::ExecutionWork,
    )?;
    // A live slot is useful only if the existing budget can pay at least one
    // visit at every boundary in both sweeps plus the between-sweep reset.
    // This makes L monotone in the caller's existing whole-operation work and
    // input-boundary quotas instead of silently degenerating to Q.
    let live_slot_work = add(
        mul(boundaries, 2, Resource::ExecutionWork)?,
        1,
        Resource::ExecutionWork,
    )?;
    let minimum = add(non_sweep, live_slot_work, Resource::ExecutionWork)?;
    enforce(minimum, limits.max_work, Resource::ExecutionWork)?;
    let available = limits
        .max_work
        .checked_sub(non_sweep)
        .ok_or(Error::InternalInvariant(
            "terminal frontier admission subtraction underflow",
        ))?;
    let all_live_refusal = layout
        .states
        .checked_sub(1)
        .ok_or(Error::InternalInvariant("terminal frontier has no state"))?;
    let work_slots = available
        .checked_div(live_slot_work)
        .ok_or(Error::InternalInvariant(
            "terminal frontier live-slot cost is zero",
        ))?;
    let active_limit = all_live_refusal.min(work_slots);
    if active_limit == 0 {
        return Err(Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            required: minimum,
            limit: limits.max_work,
        });
    }
    let sweep_work_limit = available
        .checked_sub(active_limit)
        .ok_or(Error::InternalInvariant(
            "terminal frontier reset reservation underflow",
        ))?
        / 2;
    if sweep_work_limit < active_limit {
        return Err(Error::InternalInvariant(
            "terminal frontier sweep cannot cover its active-state limit",
        ));
    }
    Ok(FrontierRequirements {
        bytes: layout.bytes,
        source_bytes_bound,
        active_limit,
        sweep_work_limit,
        prefix_work_bound,
        post_build_work,
        minimum_work: minimum,
    })
}

/// Derive the fixed typed frontier envelope used by an explicit
/// receipt-bearing route. Unlike [`requirements`], this construction does not
/// use the invocation's caller limits to choose its physical shape. The
/// established default whole-operation work ceiling is the owner-local route
/// cap, so default callers preserve the incumbent terminal-frontier shape and
/// lower callers compare against one immutable prospective before source.
pub(super) fn receipt_requirements(
    program: &Program,
    seed: &TerminalFrontierSeed,
    boundaries: usize,
    log_bytes: usize,
    post_build_work: usize,
) -> Result<(FrontierRequirements, usize), Error> {
    if seed.is_empty() {
        return Err(Error::InternalInvariant(
            "terminal frontier requirements have no compiled HIR proof",
        ));
    }
    let limits = OperationLimits::default();
    let frontier = requirements(
        program,
        seed,
        boundaries,
        log_bytes,
        post_build_work,
        limits,
    )?;
    Ok((frontier, limits.max_work))
}

pub(super) fn allocation_count(program: &Program, log_bytes: usize) -> Result<usize, Error> {
    let layout = Layout::new(program)?;
    let offsets = add(layout.states, 1, Resource::Allocations)?;
    Ok([
        offsets,
        layout.edges,
        layout.states,
        layout.states,
        layout.states,
        layout.candidate_words,
        layout.summary_words,
        log_bytes,
    ]
    .into_iter()
    .filter(|length| *length != 0)
    .count())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "terminal-frontier construction keeps its two-pass P/A ordering and allocation ledger in one audit unit"
)]
pub(super) fn build(
    program: &Program,
    haystack: &[u8],
    assertions: AssertionContext<'_>,
    requirements: Requirements,
    seed: &TerminalFrontierSeed,
    limits: OperationLimits,
    accounting: &mut ExecutionAccounting,
    actual_allocations: &mut usize,
) -> Result<RowStore, Error> {
    let (storage, frontier, layout) = validate_build_inputs(program, requirements, seed, limits)?;
    let Some(first_prefix_end) = admitted_prefix(
        haystack,
        seed,
        requirements.work_bound,
        frontier.prefix_work_bound,
        accounting,
    )?
    else {
        return build_zero_log(
            program,
            requirements,
            storage,
            limits,
            accounting,
            actual_allocations,
            frontier,
        );
    };
    let mut allocated = Allocated::new(
        layout,
        limits,
        accounting,
        actual_allocations,
        requirements.work_bound,
    )?;
    accounting.random_access_peak_bytes = allocated.bytes;
    accounting.scratch_peak_bytes = allocated.bytes;
    accounting.frontier_bytes = allocated.bytes;
    accounting.peak_bytes = allocated.bytes;
    let index = ReverseIndex::build(
        program,
        &mut allocated.offsets,
        &mut allocated.predecessors,
        &mut allocated.active,
        accounting,
        requirements.work_bound,
    )?;
    let mut machine = Machine {
        program,
        haystack,
        assertions,
        seed,
        index,
        storage,
        record_bytes: requirements.record_bytes,
        first_prefix_end,
        active_limit: frontier.active_limit,
        work_bound: add(
            accounting.work,
            frontier.sweep_work_limit,
            Resource::ExecutionWork,
        )?,
    };
    enforce(
        machine.work_bound,
        requirements.work_bound,
        Resource::ExecutionWork,
    )?;
    let before_census = Snapshot::new(*accounting);
    machine.sweep(&mut allocated, None, accounting)?;
    let census = before_census.delta(*accounting)?;
    if census.work > frontier.sweep_work_limit {
        return Err(Error::InternalInvariant(
            "terminal frontier census crossed its private work ceiling",
        ));
    }
    machine.work_bound = requirements.work_bound;
    preflight_completion(
        *accounting,
        census,
        allocated.active.len(),
        requirements,
        limits,
        frontier.post_build_work,
    )?;
    machine.reset(&mut allocated, accounting)?;
    let mut store = allocate_log(requirements.requested_log_bytes, allocated.bytes, limits)?;
    super::record_allocation(actual_allocations, store.capacity())?;
    accounting.log_bytes = requirements.requested_log_bytes;
    accounting.peak_bytes = add(
        requirements.requested_log_bytes,
        allocated.bytes,
        Resource::PeakBytes,
    )?;
    charge_bookkeeping(
        accounting,
        requirements.work_bound,
        requirements.requested_log_bytes,
    )?;
    machine.work_bound = add(
        accounting.work,
        add(
            census.work,
            requirements.requested_log_bytes,
            Resource::ExecutionWork,
        )?,
        Resource::ExecutionWork,
    )?;
    enforce(
        machine.work_bound,
        requirements.work_bound,
        Resource::ExecutionWork,
    )?;
    let before_production = Snapshot::new(*accounting);
    machine.sweep(&mut allocated, Some(&mut store), accounting)?;
    let production = before_production.delta(*accounting)?;
    census.verify_production(production, requirements.requested_log_bytes)?;

    let allocated_store = requirements.requested_log_bytes;
    accounting.random_access_peak_bytes = allocated.bytes;
    accounting.scratch_peak_bytes = allocated.bytes;
    accounting.log_bytes = allocated_store;
    accounting.frontier_bytes = allocated.bytes;
    Ok(RowStore {
        bytes: store,
        storage,
        record_bytes: requirements.record_bytes,
        allocated_store_bytes: allocated_store,
        build_scratch_bytes: allocated.bytes,
        root_rank: program.split_count,
    })
}

fn validate_build_inputs(
    program: &Program,
    requirements: Requirements,
    seed: &TerminalFrontierSeed,
    limits: OperationLimits,
) -> Result<(RowStorage, FrontierRequirements, Layout), Error> {
    if seed.is_empty() || !requirements.terminal_frontier {
        return Err(Error::InternalInvariant(
            "terminal frontier was selected without its HIR certificate",
        ));
    }
    let storage = requirements.row_storage.ok_or(Error::InternalInvariant(
        "terminal frontier has no row-record storage",
    ))?;
    let frontier = requirements.frontier.ok_or(Error::InternalInvariant(
        "terminal frontier has no private admission certificate",
    ))?;
    let layout = Layout::new(program)?;
    if layout.bytes != frontier.bytes {
        return Err(Error::InternalInvariant(
            "terminal frontier layout changed after admission",
        ));
    }
    enforce(
        layout.fixed_work()?,
        requirements.work_bound,
        Resource::ExecutionWork,
    )?;
    preflight_frontier_bytes(layout.bytes, requirements.requested_log_bytes, limits)?;
    Ok((storage, frontier, layout))
}

fn admitted_prefix(
    haystack: &[u8],
    seed: &TerminalFrontierSeed,
    work_bound: usize,
    prefix_work_bound: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<Option<usize>, Error> {
    let work_start = accounting.work;
    let prefix_end = earliest_required_prefix(haystack, seed, work_bound, accounting)?;
    if delta(accounting.work, work_start)? > prefix_work_bound {
        return Err(Error::InternalInvariant(
            "terminal frontier prefix census exceeded its admission bound",
        ));
    }
    Ok(prefix_end)
}

fn earliest_required_prefix(
    haystack: &[u8],
    seed: &TerminalFrontierSeed,
    work_bound: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<Option<usize>, Error> {
    let prefix = seed.prefix_bytes();
    let Some(last_start) = haystack.len().checked_sub(prefix.len()) else {
        return Ok(None);
    };
    for start in 0..=last_start {
        let mut matched = true;
        for (offset, &expected) in prefix.iter().enumerate() {
            charge_source(accounting, work_bound, 1)?;
            let position = add(start, offset, Resource::Boundaries)?;
            let actual = *haystack.get(position).ok_or(Error::InternalInvariant(
                "terminal frontier prefix comparison outside source",
            ))?;
            if actual != expected {
                matched = false;
                break;
            }
        }
        if matched {
            return add(start, prefix.len(), Resource::Boundaries).map(Some);
        }
    }
    Ok(None)
}

fn build_zero_log(
    program: &Program,
    requirements: Requirements,
    storage: RowStorage,
    limits: OperationLimits,
    accounting: &mut ExecutionAccounting,
    actual_allocations: &mut usize,
    frontier: FrontierRequirements,
) -> Result<RowStore, Error> {
    let future = add(
        requirements.requested_log_bytes,
        frontier.post_build_work,
        Resource::ExecutionWork,
    )?;
    enforce(
        add(accounting.work, future, Resource::ExecutionWork)?,
        limits.max_work,
        Resource::ExecutionWork,
    )?;
    let store = allocate_log(requirements.requested_log_bytes, 0, limits)?;
    super::record_allocation(actual_allocations, store.capacity())?;
    accounting.log_bytes = requirements.requested_log_bytes;
    accounting.peak_bytes = requirements.requested_log_bytes;
    charge_bookkeeping(
        accounting,
        requirements.work_bound,
        requirements.requested_log_bytes,
    )?;
    accounting.sequential_bytes_written = add(
        accounting.sequential_bytes_written,
        requirements.requested_log_bytes,
        Resource::SequentialBytes,
    )?;
    Ok(RowStore {
        bytes: store,
        storage,
        record_bytes: requirements.record_bytes,
        allocated_store_bytes: requirements.requested_log_bytes,
        build_scratch_bytes: 0,
        root_rank: program.split_count,
    })
}

fn preflight_frontier_bytes(
    frontier: usize,
    log: usize,
    limits: OperationLimits,
) -> Result<(), Error> {
    enforce(
        frontier,
        limits.max_random_access_bytes,
        Resource::RandomAccessBytes,
    )?;
    enforce(frontier, limits.max_scratch_bytes, Resource::ScratchBytes)?;
    enforce(log, limits.max_log_bytes, Resource::LogBytes)?;
    enforce(
        add(frontier, log, Resource::PeakBytes)?,
        limits.max_peak_bytes,
        Resource::PeakBytes,
    )
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the fixed accounting snapshot is copied deliberately before admission publication"
)]
fn preflight_completion(
    accounting: ExecutionAccounting,
    census: Delta,
    reset_states: usize,
    requirements: Requirements,
    limits: OperationLimits,
    post_build_work: usize,
) -> Result<(), Error> {
    let log_work = mul(requirements.requested_log_bytes, 2, Resource::ExecutionWork)?;
    let future = add(
        add(census.work, reset_states, Resource::ExecutionWork)?,
        add(log_work, post_build_work, Resource::ExecutionWork)?,
        Resource::ExecutionWork,
    )?;
    enforce(
        add(accounting.work, future, Resource::ExecutionWork)?,
        limits.max_work,
        Resource::ExecutionWork,
    )
}

fn allocate_log(length: usize, frontier: usize, limits: OperationLimits) -> Result<Vec<u8>, Error> {
    enforce(length, limits.max_log_bytes, Resource::LogBytes)?;
    enforce(
        add(length, frontier, Resource::PeakBytes)?,
        limits.max_peak_bytes,
        Resource::PeakBytes,
    )?;
    #[cfg(test)]
    if length != 0 && super::allocation_fault::should_fail() {
        return Err(Error::AllocationFailed {
            resource: Resource::LogBytes,
            items: length,
        });
    }
    zeroed_exact(length).map_err(|_| Error::AllocationFailed {
        resource: Resource::LogBytes,
        items: length,
    })
}

struct Allocated {
    offsets: ExactVec<usize>,
    predecessors: ExactVec<usize>,
    active: ExactVec<usize>,
    row: ExactVec<usize>,
    next_row: ExactVec<usize>,
    candidates: OrderedSet,
    bytes: usize,
}

impl Allocated {
    fn new(
        layout: Layout,
        limits: OperationLimits,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        work_bound: usize,
    ) -> Result<Self, Error> {
        preflight_frontier_bytes(layout.bytes, 0, limits)?;
        let mut live_words = 0_usize;
        let offsets = zeroed_words_tracked(
            add(layout.states, 1, Resource::ScratchBytes)?,
            accounting,
            actual_allocations,
            work_bound,
            &mut live_words,
        )?;
        let predecessors = zeroed_words_tracked(
            layout.edges,
            accounting,
            actual_allocations,
            work_bound,
            &mut live_words,
        )?;
        let active = zeroed_words_tracked(
            layout.states,
            accounting,
            actual_allocations,
            work_bound,
            &mut live_words,
        )?;
        let row = zeroed_words_tracked(
            layout.states,
            accounting,
            actual_allocations,
            work_bound,
            &mut live_words,
        )?;
        let next_row = zeroed_words_tracked(
            layout.states,
            accounting,
            actual_allocations,
            work_bound,
            &mut live_words,
        )?;
        let mut candidates =
            OrderedSet::reserved_tracked(layout, accounting, actual_allocations, &mut live_words)?;
        let bytes = layout.bytes;
        candidates.initialize(layout, accounting, work_bound)?;
        if live_words != layout.total_words {
            return Err(Error::InternalInvariant(
                "terminal frontier live allocation census changed",
            ));
        }
        Ok(Self {
            offsets,
            predecessors,
            active,
            row,
            next_row,
            candidates,
            bytes,
        })
    }
}

#[cfg(test)]
pub(super) fn test_allocation_shape(program: &Program) -> Result<(usize, usize), Error> {
    let layout = Layout::new(program)?;
    Ok((layout.total_words, layout.bytes))
}

#[cfg(test)]
pub(super) fn test_allocated_composite(
    program: &Program,
    limits: OperationLimits,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    let layout = Layout::new(program)?;
    let mut actual_allocations = 0;
    Allocated::new(
        layout,
        limits,
        accounting,
        &mut actual_allocations,
        usize::MAX,
    )
    .map(drop)
}

#[cfg(test)]
pub(super) fn test_allocated_then_log(
    program: &Program,
    log_bytes: usize,
    limits: OperationLimits,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    let layout = Layout::new(program)?;
    let mut actual_allocations = 0;
    let allocated = Allocated::new(
        layout,
        limits,
        accounting,
        &mut actual_allocations,
        usize::MAX,
    )?;
    allocate_log(log_bytes, allocated.bytes, limits).map(drop)
}

fn reserved_words_tracked(
    length: usize,
    accounting: &mut ExecutionAccounting,
    actual_allocations: &mut usize,
    live_words: &mut usize,
) -> Result<ExactVec<usize>, Error> {
    #[cfg(test)]
    if length != 0 && super::allocation_fault::should_fail() {
        return Err(Error::AllocationFailed {
            resource: Resource::ScratchBytes,
            items: length,
        });
    }
    let values = ExactVec::try_with_capacity(length).map_err(|_| Error::AllocationFailed {
        resource: Resource::ScratchBytes,
        items: length,
    })?;
    super::record_allocation(actual_allocations, values.capacity())?;
    *live_words = add(*live_words, length, Resource::ScratchBytes)?;
    let live_bytes = mul(
        *live_words,
        core::mem::size_of::<usize>(),
        Resource::ScratchBytes,
    )?;
    accounting.random_access_peak_bytes = accounting.random_access_peak_bytes.max(live_bytes);
    accounting.scratch_peak_bytes = accounting.scratch_peak_bytes.max(live_bytes);
    accounting.frontier_bytes = accounting.frontier_bytes.max(live_bytes);
    accounting.peak_bytes = accounting.peak_bytes.max(live_bytes);
    Ok(values)
}

fn zeroed_words_tracked(
    length: usize,
    accounting: &mut ExecutionAccounting,
    actual_allocations: &mut usize,
    work_bound: usize,
    live_words: &mut usize,
) -> Result<ExactVec<usize>, Error> {
    let mut values = reserved_words_tracked(length, accounting, actual_allocations, live_words)?;
    for _ in 0..length {
        charge_bookkeeping(accounting, work_bound, 1)?;
        values.try_push(0).map_err(|_| {
            Error::InternalInvariant(
                "terminal frontier exact allocation filled before initialization",
            )
        })?;
    }
    Ok(values)
}

struct ReverseIndex {
    offsets: ExactVec<usize>,
    predecessors: ExactVec<usize>,
    match_rank: usize,
}

impl ReverseIndex {
    fn build(
        program: &Program,
        offsets: &mut ExactVec<usize>,
        predecessors: &mut ExactVec<usize>,
        cursor: &mut ExactVec<usize>,
        accounting: &mut ExecutionAccounting,
        work_bound: usize,
    ) -> Result<Self, Error> {
        let mut match_rank = None;
        for (rank, &pc) in program.epsilon_order.iter().enumerate() {
            charge_bookkeeping(accounting, work_bound, 1)?;
            let inst = program.instruction(pc)?;
            if matches!(inst, Inst::Match) && match_rank.replace(rank).is_some() {
                return Err(Error::InternalInvariant(
                    "terminal frontier has multiple match states",
                ));
            }
            for target in targets(inst)? {
                charge_bookkeeping(accounting, work_bound, 1)?;
                increment(offsets, target)?;
            }
        }
        prefix_offsets(offsets, accounting, work_bound)?;
        if *offsets.last().ok_or(Error::InternalInvariant(
            "terminal frontier has no offset sentinel",
        ))? != predecessors.len()
        {
            return Err(Error::InternalInvariant(
                "terminal frontier edge census changed",
            ));
        }
        let states = cursor.len();
        charge_bookkeeping(accounting, work_bound, states)?;
        cursor.copy_from_slice(&offsets[..states]);
        for (rank, &pc) in program.epsilon_order.iter().enumerate() {
            charge_bookkeeping(accounting, work_bound, 1)?;
            for target in targets(program.instruction(pc)?)? {
                charge_bookkeeping(accounting, work_bound, 1)?;
                put(predecessors, cursor, target, rank)?;
            }
        }
        cursor.clear();
        Ok(Self {
            offsets: core::mem::take(offsets),
            predecessors: core::mem::take(predecessors),
            match_rank: match_rank.ok_or(Error::InternalInvariant(
                "terminal frontier has no match state",
            ))?,
        })
    }

    fn predecessors(&self, state: usize) -> Result<&[usize], Error> {
        let start = *self.offsets.get(state).ok_or(Error::InternalInvariant(
            "terminal frontier predecessor state outside index",
        ))?;
        let end = *self
            .offsets
            .get(add(state, 1, Resource::ScratchBytes)?)
            .ok_or(Error::InternalInvariant(
                "terminal frontier predecessor sentinel outside index",
            ))?;
        self.predecessors
            .get(start..end)
            .ok_or(Error::InternalInvariant(
                "terminal frontier predecessor range outside index",
            ))
    }
}

fn targets(inst: &Inst) -> Result<impl Iterator<Item = usize>, Error> {
    let targets = match inst {
        Inst::Consume { next, .. } | Inst::Assert { next, .. } => [Some(*next), None, None, None],
        Inst::Split {
            preferred,
            fallback,
        } => [Some(*preferred), Some(*fallback), None, None],
        Inst::Unfilled => {
            return Err(Error::InternalInvariant(
                "terminal frontier reached an unfilled state",
            ));
        }
        Inst::ConsumeScalar { .. } => {
            return Err(Error::InternalInvariant(
                "terminal frontier reached a scalar state",
            ));
        }
        Inst::Fail | Inst::Match => [None, None, None, None],
    };
    Ok(targets.into_iter().flatten())
}

fn increment(offsets: &mut [usize], state: usize) -> Result<(), Error> {
    let slot = add(state, 1, Resource::ScratchBytes)?;
    let count = offsets.get_mut(slot).ok_or(Error::InternalInvariant(
        "terminal frontier target outside offsets",
    ))?;
    *count = add(*count, 1, Resource::ScratchBytes)?;
    Ok(())
}

fn prefix_offsets(
    offsets: &mut [usize],
    accounting: &mut ExecutionAccounting,
    work_bound: usize,
) -> Result<(), Error> {
    let mut total = 0_usize;
    for count in offsets.iter_mut().skip(1) {
        charge_bookkeeping(accounting, work_bound, 1)?;
        total = add(total, *count, Resource::ScratchBytes)?;
        *count = total;
    }
    Ok(())
}

fn put(
    predecessors: &mut [usize],
    cursor: &mut [usize],
    state: usize,
    rank: usize,
) -> Result<(), Error> {
    let slot = cursor.get_mut(state).ok_or(Error::InternalInvariant(
        "terminal frontier target outside cursor",
    ))?;
    *predecessors.get_mut(*slot).ok_or(Error::InternalInvariant(
        "terminal frontier predecessor slot outside index",
    ))? = rank;
    *slot = add(*slot, 1, Resource::ScratchBytes)?;
    Ok(())
}

struct OrderedSet {
    bits: ExactVec<usize>,
    summary: ExactVec<usize>,
    states: usize,
}

// Fixed conservative charges are paid before touching either bitset level.
// They cover the rank bound/probe, quotient/remainder operations, both shifts,
// duplicate test, candidate write, summary quotient/remainder, summary probe,
// and summary write. A duplicate intentionally pays the same upper bound.
const ORDERED_INSERT_WORK: usize = 24;
// Covers both trailing-zero selections, index arithmetic, two probes, two
// shifts, both empty tests, both clears, and the padding-rank check.
const ORDERED_POP_WORK: usize = 24;
// Covers the cursor bound, summary probe, empty-word comparison, and possible
// cursor advance before the next probe.
const ORDERED_SUMMARY_PROBE_WORK: usize = 4;

impl OrderedSet {
    fn reserved_tracked(
        layout: Layout,
        accounting: &mut ExecutionAccounting,
        actual_allocations: &mut usize,
        live_words: &mut usize,
    ) -> Result<Self, Error> {
        Ok(Self {
            bits: reserved_words_tracked(
                layout.candidate_words,
                accounting,
                actual_allocations,
                live_words,
            )?,
            summary: reserved_words_tracked(
                layout.summary_words,
                accounting,
                actual_allocations,
                live_words,
            )?,
            states: layout.states,
        })
    }

    fn initialize(
        &mut self,
        layout: Layout,
        accounting: &mut ExecutionAccounting,
        work_bound: usize,
    ) -> Result<(), Error> {
        if self.states != layout.states {
            return Err(Error::InternalInvariant(
                "terminal frontier ordered-set shape changed",
            ));
        }
        for _ in 0..layout.candidate_words {
            charge_bookkeeping(accounting, work_bound, 1)?;
            self.bits.try_push(0).map_err(|_| {
                Error::InternalInvariant(
                    "terminal frontier candidate words exceeded exact allocation",
                )
            })?;
        }
        for _ in 0..layout.summary_words {
            charge_bookkeeping(accounting, work_bound, 1)?;
            self.summary.try_push(0).map_err(|_| {
                Error::InternalInvariant(
                    "terminal frontier summary words exceeded exact allocation",
                )
            })?;
        }
        Ok(())
    }

    fn insert(
        &mut self,
        rank: usize,
        accounting: &mut ExecutionAccounting,
        work_bound: usize,
    ) -> Result<(), Error> {
        charge_insertion(accounting, work_bound, ORDERED_INSERT_WORK)?;
        if rank >= self.states {
            return Err(Error::InternalInvariant(
                "terminal frontier insertion rank outside program",
            ));
        }
        let word_bits = word_bits()?;
        let word_index = rank
            .checked_div(word_bits)
            .ok_or(Error::InternalInvariant("zero frontier word width"))?;
        let bit_index = rank
            .checked_rem(word_bits)
            .ok_or(Error::InternalInvariant("zero frontier word width"))?;
        let bit = 1_usize
            .checked_shl(
                u32::try_from(bit_index)
                    .map_err(|_| Error::InternalInvariant("frontier bit index does not fit u32"))?,
            )
            .ok_or(Error::InternalInvariant("frontier bit shift overflow"))?;
        let word = self
            .bits
            .get_mut(word_index)
            .ok_or(Error::InternalInvariant(
                "terminal frontier insertion word outside set",
            ))?;
        if *word & bit != 0 {
            return Ok(());
        }
        *word |= bit;
        let summary_index = word_index
            .checked_div(word_bits)
            .ok_or(Error::InternalInvariant("zero frontier word width"))?;
        let summary_bit_index = word_index
            .checked_rem(word_bits)
            .ok_or(Error::InternalInvariant("zero frontier word width"))?;
        let summary_bit =
            1_usize
                .checked_shl(u32::try_from(summary_bit_index).map_err(|_| {
                    Error::InternalInvariant("frontier summary index does not fit u32")
                })?)
                .ok_or(Error::InternalInvariant("frontier summary shift overflow"))?;
        *self
            .summary
            .get_mut(summary_index)
            .ok_or(Error::InternalInvariant(
                "terminal frontier summary word outside set",
            ))? |= summary_bit;
        Ok(())
    }

    fn pop_first(
        &mut self,
        cursor: &mut usize,
        accounting: &mut ExecutionAccounting,
        work_bound: usize,
    ) -> Result<Option<usize>, Error> {
        loop {
            charge_bookkeeping(accounting, work_bound, ORDERED_SUMMARY_PROBE_WORK)?;
            if *cursor >= self.summary.len() {
                return Ok(None);
            }
            let summary_word = self.summary[*cursor];
            if summary_word == 0 {
                *cursor = add(*cursor, 1, Resource::ScratchBytes)?;
                continue;
            }
            return self.pop_from_summary(*cursor, summary_word, accounting, work_bound);
        }
    }

    fn pop_from_summary(
        &mut self,
        summary_index: usize,
        summary_word: usize,
        accounting: &mut ExecutionAccounting,
        work_bound: usize,
    ) -> Result<Option<usize>, Error> {
        charge_bookkeeping(accounting, work_bound, ORDERED_POP_WORK)?;
        let word_bits = word_bits()?;
        let summary_bit = usize::try_from(summary_word.trailing_zeros())
            .map_err(|_| Error::InternalInvariant("frontier summary rank conversion failed"))?;
        let word_index = add(
            mul(summary_index, word_bits, Resource::ScratchBytes)?,
            summary_bit,
            Resource::ScratchBytes,
        )?;
        let word = self
            .bits
            .get_mut(word_index)
            .ok_or(Error::InternalInvariant(
                "terminal frontier selected word outside set",
            ))?;
        if *word == 0 {
            return Err(Error::InternalInvariant(
                "terminal frontier summary selected an empty word",
            ));
        }
        let candidate_bit = usize::try_from(word.trailing_zeros())
            .map_err(|_| Error::InternalInvariant("frontier candidate rank conversion failed"))?;
        let bit = 1_usize
            .checked_shl(u32::try_from(candidate_bit).map_err(|_| {
                Error::InternalInvariant("frontier candidate index does not fit u32")
            })?)
            .ok_or(Error::InternalInvariant(
                "frontier candidate bit shift overflow",
            ))?;
        *word &= !bit;
        if *word == 0 {
            let summary_mask = 1_usize
                .checked_shl(u32::try_from(summary_bit).map_err(|_| {
                    Error::InternalInvariant("frontier summary bit does not fit u32")
                })?)
                .ok_or(Error::InternalInvariant(
                    "frontier summary bit shift overflow",
                ))?;
            self.summary[summary_index] &= !summary_mask;
        }
        let rank = add(
            mul(word_index, word_bits, Resource::ScratchBytes)?,
            candidate_bit,
            Resource::ScratchBytes,
        )?;
        if rank >= self.states {
            return Err(Error::InternalInvariant(
                "terminal frontier selected a padding bit",
            ));
        }
        Ok(Some(rank))
    }
}

fn word_bits() -> Result<usize, Error> {
    usize::try_from(usize::BITS)
        .map_err(|_| Error::InternalInvariant("platform word width does not fit usize"))
}

fn bit_words(bits: usize) -> Result<usize, Error> {
    let width = word_bits()?;
    let adjustment = width
        .checked_sub(1)
        .ok_or(Error::InternalInvariant("zero frontier word width"))?;
    add(bits, adjustment, Resource::ScratchBytes)?
        .checked_div(width)
        .ok_or(Error::InternalInvariant("zero frontier word width"))
}

struct Machine<'a> {
    program: &'a Program,
    haystack: &'a [u8],
    assertions: AssertionContext<'a>,
    seed: &'a TerminalFrontierSeed,
    index: ReverseIndex,
    storage: RowStorage,
    record_bytes: usize,
    first_prefix_end: usize,
    active_limit: usize,
    work_bound: usize,
}

impl Machine<'_> {
    fn sweep(
        &self,
        buffers: &mut Allocated,
        mut store: Option<&mut [u8]>,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        let boundaries = add(self.haystack.len(), 1, Resource::Boundaries)?;
        for position in (0..boundaries).rev() {
            let mut record = None;
            if let Some(bytes) = store.as_deref_mut() {
                let ordinal =
                    self.haystack
                        .len()
                        .checked_sub(position)
                        .ok_or(Error::InternalInvariant(
                            "terminal frontier record ordinal underflow",
                        ))?;
                let start = mul(ordinal, self.record_bytes, Resource::LogBytes)?;
                let end = add(start, self.record_bytes, Resource::LogBytes)?;
                charge_bookkeeping(accounting, self.work_bound, self.record_bytes)?;
                accounting.sequential_bytes_written = add(
                    accounting.sequential_bytes_written,
                    self.record_bytes,
                    Resource::SequentialBytes,
                )?;
                record = Some(bytes.get_mut(start..end).ok_or(Error::InternalInvariant(
                    "terminal frontier record outside log",
                ))?);
            }
            self.build_row(position, buffers, record, accounting)?;
            core::mem::swap(&mut buffers.row, &mut buffers.next_row);
        }
        Ok(())
    }

    fn reset(
        &self,
        buffers: &mut Allocated,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        while let Some(rank) = buffers.active.pop() {
            charge_bookkeeping(accounting, self.work_bound, 1)?;
            let pc = *self
                .program
                .epsilon_order
                .get(rank)
                .ok_or(Error::InternalInvariant(
                    "terminal frontier reset rank outside program",
                ))?;
            *buffers
                .next_row
                .get_mut(pc)
                .ok_or(Error::InternalInvariant(
                    "terminal frontier reset state outside row",
                ))? = 0;
        }
        Ok(())
    }

    fn build_row(
        &self,
        position: usize,
        buffers: &mut Allocated,
        record: Option<&mut [u8]>,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        self.seed_match(position, &mut buffers.candidates, accounting)?;
        self.cross_consuming(position, buffers, accounting)?;
        self.clear_next(buffers, accounting)?;
        self.evaluate(position, buffers, record, accounting)
    }

    fn seed_match(
        &self,
        position: usize,
        candidates: &mut OrderedSet,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        if position < self.first_prefix_end {
            return Ok(());
        }
        let Some(previous) = position.checked_sub(1) else {
            return Ok(());
        };
        charge_source(accounting, self.work_bound, 1)?;
        let byte = *self.haystack.get(previous).ok_or(Error::InternalInvariant(
            "terminal frontier terminal byte outside source",
        ))?;
        for terminal in self.seed.terminal_bytes() {
            charge_bookkeeping(accounting, self.work_bound, 1)?;
            if byte == terminal {
                candidates.insert(self.index.match_rank, accounting, self.work_bound)?;
                break;
            }
        }
        Ok(())
    }

    fn cross_consuming(
        &self,
        position: usize,
        buffers: &mut Allocated,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        let Some(&input) = self.haystack.get(position) else {
            return Ok(());
        };
        charge_source(accounting, self.work_bound, 1)?;
        let mut active_index = 0_usize;
        while active_index < buffers.active.len() {
            charge_bookkeeping(accounting, self.work_bound, 1)?;
            let child_rank = buffers.active[active_index];
            active_index = add(active_index, 1, Resource::ExecutionWork)?;
            let child = self.pc(child_rank)?;
            let child_value = *buffers.next_row.get(child).ok_or(Error::InternalInvariant(
                "terminal frontier child outside successor row",
            ))?;
            if child_value == 0 {
                return Err(Error::InternalInvariant(
                    "terminal frontier active child has no endpoint",
                ));
            }
            for &parent_rank in self.index.predecessors(child)? {
                try_charge_transition(accounting, self.work_bound)?;
                let parent = self.pc(parent_rank)?;
                if let Inst::Consume { bytes, next } = self.program.instruction(parent)? {
                    if *next != child {
                        return Err(Error::InternalInvariant(
                            "terminal frontier consuming edge changed",
                        ));
                    }
                    if bytes.contains(input) {
                        buffers.row[parent] = child_value;
                        buffers
                            .candidates
                            .insert(parent_rank, accounting, self.work_bound)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn clear_next(
        &self,
        buffers: &mut Allocated,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        while let Some(rank) = buffers.active.pop() {
            charge_bookkeeping(accounting, self.work_bound, 1)?;
            let pc = self.pc(rank)?;
            *buffers
                .next_row
                .get_mut(pc)
                .ok_or(Error::InternalInvariant(
                    "terminal frontier clear state outside successor row",
                ))? = 0;
        }
        Ok(())
    }

    fn evaluate(
        &self,
        position: usize,
        buffers: &mut Allocated,
        mut record: Option<&mut [u8]>,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        let mut cursor = 0_usize;
        while let Some(rank) =
            buffers
                .candidates
                .pop_first(&mut cursor, accounting, self.work_bound)?
        {
            charge_evaluation(accounting, self.work_bound)?;
            let pc = self.pc(rank)?;
            let value = self.evaluate_state(
                pc,
                position,
                &buffers.row,
                record.as_deref_mut(),
                accounting,
            )?;
            buffers.row[pc] = value;
            if value == 0 {
                continue;
            }
            self.push_live(rank, buffers, accounting)?;
            self.raise_parents(rank, pc, &mut buffers.candidates, accounting)?;
        }
        self.write_root(&buffers.row, record)
    }

    fn evaluate_state(
        &self,
        pc: usize,
        position: usize,
        row: &[usize],
        record: Option<&mut [u8]>,
        accounting: &mut ExecutionAccounting,
    ) -> Result<usize, Error> {
        match self.program.instruction(pc)? {
            Inst::Unfilled | Inst::ConsumeScalar { .. } => Err(Error::InternalInvariant(
                "terminal frontier reached an unsupported state",
            )),
            Inst::Fail => Ok(0),
            Inst::Match => encode(position),
            Inst::Consume { .. } => {
                let value = row[pc];
                if value == 0 {
                    return Err(Error::InternalInvariant(
                        "terminal frontier consuming candidate has no endpoint",
                    ));
                }
                Ok(value)
            }
            Inst::Assert { assertion, next } => {
                try_charge_assertion(accounting, self.work_bound)?;
                Ok(if self.assertions.is_match(*assertion, position)? {
                    row[*next]
                } else {
                    0
                })
            }
            Inst::Split {
                preferred,
                fallback,
            } => self.evaluate_split(pc, *preferred, *fallback, row, record, accounting),
        }
    }

    fn evaluate_split(
        &self,
        pc: usize,
        preferred: usize,
        fallback: usize,
        row: &[usize],
        record: Option<&mut [u8]>,
        accounting: &mut ExecutionAccounting,
    ) -> Result<usize, Error> {
        try_charge_transition(accounting, self.work_bound)?;
        let selected = row[preferred];
        if selected != 0 {
            if self.storage == RowStorage::SplitDecisions {
                let rank = self.program.split_rank[pc];
                if rank == NO_SPLIT_RANK {
                    return Err(Error::InternalInvariant(
                        "terminal frontier split has no decision rank",
                    ));
                }
                if let Some(record) = record {
                    set_bit(record, rank)?;
                }
            }
            return Ok(selected);
        }
        try_charge_transition(accounting, self.work_bound)?;
        Ok(row[fallback])
    }

    fn push_live(
        &self,
        rank: usize,
        buffers: &mut Allocated,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        charge_bookkeeping(accounting, self.work_bound, 1)?;
        enforce_active_capacity(
            buffers.active.len(),
            self.active_limit.min(buffers.active.capacity()),
            self.work_bound,
        )?;
        buffers.active.try_push(rank).map_err(|_| {
            Error::InternalInvariant("terminal frontier active set exceeded exact allocation")
        })?;
        accounting.frontier_peak_states = accounting.frontier_peak_states.max(buffers.active.len());
        Ok(())
    }

    fn raise_parents(
        &self,
        rank: usize,
        pc: usize,
        candidates: &mut OrderedSet,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        for &parent_rank in self.index.predecessors(pc)? {
            try_charge_transition(accounting, self.work_bound)?;
            let parent = self.pc(parent_rank)?;
            match self.program.instruction(parent)? {
                Inst::Assert { next, .. } if *next == pc => {
                    Self::check_parent_order(rank, parent_rank)?;
                    candidates.insert(parent_rank, accounting, self.work_bound)?;
                }
                Inst::Split {
                    preferred,
                    fallback,
                } if *preferred == pc || *fallback == pc => {
                    Self::check_parent_order(rank, parent_rank)?;
                    candidates.insert(parent_rank, accounting, self.work_bound)?;
                }
                Inst::Consume { next, .. } if *next == pc => {}
                _ => {
                    return Err(Error::InternalInvariant(
                        "terminal frontier predecessor edge changed",
                    ));
                }
            }
        }
        Ok(())
    }

    fn write_root(&self, row: &[usize], record: Option<&mut [u8]>) -> Result<(), Error> {
        let Some(record) = record else {
            return Ok(());
        };
        match self.storage {
            RowStorage::SplitDecisions => {
                if row[self.program.entry] != 0 {
                    set_bit(record, self.program.split_count)?;
                }
                Ok(())
            }
            RowStorage::ReachableEndpoints => write_encoded(record, row[self.program.entry]),
        }
    }

    fn pc(&self, rank: usize) -> Result<usize, Error> {
        self.program
            .epsilon_order
            .get(rank)
            .copied()
            .ok_or(Error::InternalInvariant(
                "terminal frontier rank outside program",
            ))
    }

    fn check_parent_order(child: usize, parent: usize) -> Result<(), Error> {
        if parent <= child {
            return Err(Error::InternalInvariant(
                "terminal frontier violates certified epsilon order",
            ));
        }
        Ok(())
    }
}

fn enforce_active_capacity(live: usize, limit: usize, work_bound: usize) -> Result<(), Error> {
    if live >= limit {
        return Err(Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            required: add(work_bound, 1, Resource::ExecutionWork)?,
            limit: work_bound,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Snapshot {
    work: usize,
    state_evaluations: usize,
    transition_checks: usize,
    frontier_bookkeeping: usize,
    frontier_insertions: usize,
    frontier_evaluations: usize,
    frontier_source_bytes: usize,
}

impl Snapshot {
    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the fixed accounting snapshot is copied deliberately for exact delta accounting"
    )]
    const fn new(accounting: ExecutionAccounting) -> Self {
        Self {
            work: accounting.work,
            state_evaluations: accounting.state_evaluations,
            transition_checks: accounting.transition_checks,
            frontier_bookkeeping: accounting.frontier_bookkeeping,
            frontier_insertions: accounting.frontier_insertions,
            frontier_evaluations: accounting.frontier_evaluations,
            frontier_source_bytes: accounting.frontier_source_bytes,
        }
    }

    #[allow(
        clippy::large_types_passed_by_value,
        reason = "the fixed accounting snapshot is copied deliberately for exact delta accounting"
    )]
    fn delta(self, accounting: ExecutionAccounting) -> Result<Delta, Error> {
        Ok(Delta {
            work: delta(accounting.work, self.work)?,
            state_evaluations: delta(accounting.state_evaluations, self.state_evaluations)?,
            transition_checks: delta(accounting.transition_checks, self.transition_checks)?,
            frontier_bookkeeping: delta(
                accounting.frontier_bookkeeping,
                self.frontier_bookkeeping,
            )?,
            frontier_insertions: delta(accounting.frontier_insertions, self.frontier_insertions)?,
            frontier_evaluations: delta(
                accounting.frontier_evaluations,
                self.frontier_evaluations,
            )?,
            frontier_source_bytes: delta(
                accounting.frontier_source_bytes,
                self.frontier_source_bytes,
            )?,
        })
    }
}

#[derive(Clone, Copy)]
struct Delta {
    work: usize,
    state_evaluations: usize,
    transition_checks: usize,
    frontier_bookkeeping: usize,
    frontier_insertions: usize,
    frontier_evaluations: usize,
    frontier_source_bytes: usize,
}

impl Delta {
    fn verify_production(self, production: Self, record_work: usize) -> Result<(), Error> {
        if production.work != add(self.work, record_work, Resource::ExecutionWork)?
            || production.frontier_bookkeeping
                != add(
                    self.frontier_bookkeeping,
                    record_work,
                    Resource::ExecutionWork,
                )?
            || production.state_evaluations != self.state_evaluations
            || production.transition_checks != self.transition_checks
            || production.frontier_insertions != self.frontier_insertions
            || production.frontier_evaluations != self.frontier_evaluations
            || production.frontier_source_bytes != self.frontier_source_bytes
        {
            return Err(Error::InternalInvariant(
                "terminal frontier production sweep changed its census",
            ));
        }
        Ok(())
    }
}

fn delta(later: usize, earlier: usize) -> Result<usize, Error> {
    later.checked_sub(earlier).ok_or(Error::InternalInvariant(
        "terminal frontier accounting moved backward",
    ))
}

fn charge_bookkeeping(
    accounting: &mut ExecutionAccounting,
    work_bound: usize,
    amount: usize,
) -> Result<(), Error> {
    let next = add(
        accounting.frontier_bookkeeping,
        amount,
        Resource::ExecutionWork,
    )?;
    try_charge_amount(accounting, work_bound, amount)?;
    accounting.frontier_bookkeeping = next;
    Ok(())
}

fn charge_insertion(
    accounting: &mut ExecutionAccounting,
    work_bound: usize,
    work: usize,
) -> Result<(), Error> {
    charge_bookkeeping(accounting, work_bound, work)?;
    accounting.frontier_insertions =
        add(accounting.frontier_insertions, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_evaluation(accounting: &mut ExecutionAccounting, work_bound: usize) -> Result<(), Error> {
    let next_state = add(accounting.state_evaluations, 1, Resource::ExecutionWork)?;
    let next_frontier = add(accounting.frontier_evaluations, 1, Resource::ExecutionWork)?;
    try_charge_amount(accounting, work_bound, 1)?;
    accounting.state_evaluations = next_state;
    accounting.frontier_evaluations = next_frontier;
    Ok(())
}

fn charge_source(
    accounting: &mut ExecutionAccounting,
    work_bound: usize,
    bytes: usize,
) -> Result<(), Error> {
    charge_bookkeeping(accounting, work_bound, bytes)?;
    accounting.frontier_source_bytes = add(
        accounting.frontier_source_bytes,
        bytes,
        Resource::SequentialBytes,
    )?;
    accounting.sequential_bytes_read = add(
        accounting.sequential_bytes_read,
        bytes,
        Resource::SequentialBytes,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::*;
    use crate::{CompileLimits, RustByteProfile};

    type LimitMutation = fn(&mut OperationLimits);

    fn compiled(pattern: &str) -> crate::CompiledRegex {
        let hir = ParserBuilder::new()
            .utf8(false)
            .unicode(false)
            .build()
            .parse(pattern)
            .unwrap();
        crate::CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn terminal_frontier_private_work_and_all_live_ceilings_are_exact_and_one_below_refuses() {
        let regex = compiled(r"cargo[\\/].*[\\/]");
        let boundaries = 65;
        let rows =
            super::super::ReverseRowRequirements::new(&regex.program, boundaries, 1).unwrap();
        let post_build_work = add(
            mul(boundaries, 4, Resource::ExecutionWork).unwrap(),
            rows.replay_bound,
            Resource::ExecutionWork,
        )
        .unwrap();
        let baseline = requirements(
            &regex.program,
            &regex.terminal_frontier,
            boundaries,
            rows.log_bytes,
            post_build_work,
            OperationLimits::default(),
        )
        .unwrap();
        let exact_limit = baseline.minimum_work;
        let exact = requirements(
            &regex.program,
            &regex.terminal_frontier,
            boundaries,
            rows.log_bytes,
            post_build_work,
            OperationLimits {
                max_work: exact_limit,
                ..OperationLimits::default()
            },
        )
        .unwrap();
        assert_eq!(exact.active_limit, 1);
        assert_eq!(exact.sweep_work_limit, boundaries);
        assert!(exact.active_limit < regex.program.insts.len());
        assert_eq!(
            enforce_active_capacity(exact.active_limit, exact.active_limit, exact_limit),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: exact_limit + 1,
                limit: exact_limit,
            })
        );
        assert_eq!(
            requirements(
                &regex.program,
                &regex.terminal_frontier,
                boundaries,
                rows.log_bytes,
                post_build_work,
                OperationLimits {
                    max_work: exact_limit - 1,
                    ..OperationLimits::default()
                },
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: exact_limit,
                limit: exact_limit - 1,
            })
        );
    }

    #[test]
    fn terminal_frontier_private_component_ceilings_are_exact_and_one_below_refuses() {
        let regex = compiled(r"cargo[\\/].*[\\/]");
        let boundaries = 65;
        let baseline = super::super::Requirements::new_terminal_frontier(
            &regex.program,
            boundaries,
            super::super::Strategy::ReverseSequentialRows,
            1,
            &regex.terminal_frontier,
            OperationLimits::default(),
        )
        .unwrap();
        let frontier = baseline.frontier.unwrap();
        let exact = OperationLimits {
            max_random_access_bytes: frontier.bytes,
            max_scratch_bytes: frontier.bytes,
            max_log_bytes: baseline.requested_log_bytes,
            max_sequential_bytes: baseline.sequential_bound,
            max_peak_bytes: add(
                frontier.bytes,
                baseline.requested_log_bytes,
                Resource::PeakBytes,
            )
            .unwrap(),
            ..OperationLimits::default()
        };
        super::super::Requirements::new_terminal_frontier(
            &regex.program,
            boundaries,
            super::super::Strategy::ReverseSequentialRows,
            1,
            &regex.terminal_frontier,
            exact,
        )
        .unwrap();

        let cases: [(Resource, LimitMutation); 5] = [
            (Resource::RandomAccessBytes, |limits| {
                limits.max_random_access_bytes -= 1;
            }),
            (Resource::ScratchBytes, |limits| {
                limits.max_scratch_bytes -= 1;
            }),
            (Resource::LogBytes, |limits| {
                limits.max_log_bytes -= 1;
            }),
            (Resource::SequentialBytes, |limits| {
                limits.max_sequential_bytes -= 1;
            }),
            (Resource::PeakBytes, |limits| {
                limits.max_peak_bytes -= 1;
            }),
        ];
        for (resource, lower) in cases {
            let mut one_below = exact;
            lower(&mut one_below);
            assert!(matches!(
                super::super::Requirements::new_terminal_frontier(
                    &regex.program,
                    boundaries,
                    super::super::Strategy::ReverseSequentialRows,
                    1,
                    &regex.terminal_frontier,
                    one_below,
                ),
                Err(Error::ResourceLimit {
                    resource: actual,
                    ..
                }) if actual == resource
            ));
        }
    }
}
