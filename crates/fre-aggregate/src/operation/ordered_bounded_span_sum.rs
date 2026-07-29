use core::ops::Range;

use fre_exact_alloc::{CopyError, ExactVec};

use crate::compile::ordered_bounded_span_sum::{
    MAX_ORDERED_BOUNDED_ANCHOR_BYTES, MAX_ORDERED_BOUNDED_CHUNKS,
};
use crate::compile::{CompiledRegex, OrderedBoundedSpanSumPlan};
use crate::error::{add, enforce, mul};
use crate::program::Program;
use crate::{Error, OperationLimits, Resource};

use super::{
    AttemptPublication, CONTINUATION_OPERATION_ACCOUNTING_VERSION,
    CONTINUATION_OPERATION_ALGORITHM_VERSION, ExecutionAccounting, ExecutionResult,
    OperationAttemptKind, OperationCertificate, OperationPhysicalRoute,
    OperationPrepublicationFallback, OperationProspective, ScanSummary, Strategy,
    compact_operation_allocation_count, operation_limits_identity,
};

const MAX_MIDDLE_STATES: usize = 3 * MAX_ORDERED_BOUNDED_CHUNKS + 1;
const MAX_FRONTIER_SLOTS: usize = 4 * MAX_MIDDLE_STATES;
const NONE: usize = usize::MAX;

// The middle Thompson frontier has one empty state plus leading/data/trailing
// states for each finite chunk. Direction and "has seen a terminal" are the
// only other semantic axes, so `4 * (3K + 1)` slots are complete. A later
// start entering an occupied slot has identical future language; the earlier
// start dominates it until non-overlap commits, while the separate candidate
// axis preserves a later already-successful start if the earlier one has not
// yet reached a terminal.
#[derive(Clone, Copy)]
struct Lane {
    start: usize,
    last_end: usize,
}

impl Lane {
    const EMPTY: Self = Self {
        start: NONE,
        last_end: NONE,
    };

    const fn has_candidate(self) -> bool {
        self.last_end != NONE
    }
}

struct SparseFrontier {
    slots: [Lane; MAX_FRONTIER_SLOTS],
    keys: [u16; MAX_FRONTIER_SLOTS],
    len: usize,
}

impl SparseFrontier {
    const fn new() -> Self {
        Self {
            slots: [Lane::EMPTY; MAX_FRONTIER_SLOTS],
            keys: [0; MAX_FRONTIER_SLOTS],
            len: 0,
        }
    }

    fn clear(&mut self) {
        for index in 0..self.len {
            let key = usize::from(self.keys[index]);
            self.slots[key] = Lane::EMPTY;
        }
        self.len = 0;
    }

    fn insert(
        &mut self,
        direction: usize,
        state: usize,
        lane: Lane,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        charge_frontier_insert(accounting)?;
        let key = frontier_key(direction, state, lane.has_candidate())?;
        let incumbent = self.slots[key];
        if incumbent.start == NONE {
            if self.len == self.keys.len() {
                return Err(Error::InternalInvariant(
                    "ordered bounded-span frontier exceeded its proved slot count",
                ));
            }
            self.slots[key] = lane;
            self.keys[self.len] = u16::try_from(key).map_err(|_| {
                Error::InternalInvariant("ordered bounded-span frontier key does not fit u16")
            })?;
            self.len = add(self.len, 1, Resource::ExecutionWork)?;
        } else if lane.start < incumbent.start
            || (lane.start == incumbent.start
                && lane.has_candidate()
                && lane.last_end > incumbent.last_end)
        {
            self.slots[key] = lane;
        }
        update_frontier_peak(accounting, self.len);
        Ok(())
    }

    fn compact(&mut self) -> Result<(), Error> {
        let mut retained = 0_usize;
        for index in 0..self.len {
            let key = self.keys[index];
            if self.slots[usize::from(key)].start != NONE {
                self.keys[retained] = key;
                retained = add(retained, 1, Resource::ExecutionWork)?;
            }
        }
        self.len = retained;
        Ok(())
    }

    fn discard_before(
        &mut self,
        minimum_start: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        for index in 0..self.len {
            charge_frontier_bookkeeping(accounting, 1)?;
            let key = usize::from(self.keys[index]);
            if self.slots[key].start < minimum_start {
                self.slots[key] = Lane::EMPTY;
            }
        }
        self.compact()?;
        Ok(())
    }

    fn earliest_key(
        &self,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Option<(usize, usize)>, Error> {
        let mut earliest = None;
        for index in 0..self.len {
            charge_frontier_bookkeeping(accounting, 1)?;
            let key = usize::from(self.keys[index]);
            let lane = self.slots[key];
            if lane.start == NONE {
                continue;
            }
            let (direction, _, _) = decode_frontier_key(key);
            let candidate = (lane.start, direction);
            if earliest.is_none_or(|current| candidate < current) {
                earliest = Some(candidate);
            }
        }
        Ok(earliest)
    }
}

#[derive(Clone, Copy)]
struct Completed {
    start: usize,
    end: usize,
    direction: usize,
}

impl Completed {
    const EMPTY: Self = Self {
        start: NONE,
        end: NONE,
        direction: 0,
    };
}

struct CompletedSet {
    entries: [Completed; MAX_FRONTIER_SLOTS],
    len: usize,
}

impl CompletedSet {
    const fn new() -> Self {
        Self {
            entries: [Completed::EMPTY; MAX_FRONTIER_SLOTS],
            len: 0,
        }
    }

    fn insert(
        &mut self,
        completed: Completed,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        // A completion is created only when one of the finite frontier slots
        // dies. Settlement runs at the same boundary. If an earlier lane
        // delays settlement, later deaths advance monotonically through its
        // remaining chunk/phase frontier; they cannot exceed the slot census
        // before that lane also dies or succeeds and filters them.
        charge_frontier_insert(accounting)?;
        for index in 0..self.len {
            charge_frontier_bookkeeping(accounting, 1)?;
            let incumbent = &mut self.entries[index];
            if incumbent.start == completed.start && incumbent.direction == completed.direction {
                if completed.end > incumbent.end {
                    incumbent.end = completed.end;
                }
                return Ok(());
            }
        }
        if self.len == self.entries.len() {
            return Err(Error::InternalInvariant(
                "ordered bounded-span completions exceeded their proved finite frontier",
            ));
        }
        self.entries[self.len] = completed;
        self.len = add(self.len, 1, Resource::ExecutionWork)?;
        Ok(())
    }

    fn earliest(
        &self,
        accounting: &mut ExecutionAccounting,
    ) -> Result<Option<(usize, Completed)>, Error> {
        let mut earliest: Option<(usize, Completed)> = None;
        for index in 0..self.len {
            charge_frontier_bookkeeping(accounting, 1)?;
            let candidate = self.entries[index];
            if candidate.start == NONE {
                continue;
            }
            let key = (candidate.start, candidate.direction);
            if earliest.is_none_or(|(_, current)| key < (current.start, current.direction)) {
                earliest = Some((index, candidate));
            }
        }
        Ok(earliest)
    }

    fn discard_before(
        &mut self,
        minimum_start: usize,
        accounting: &mut ExecutionAccounting,
    ) -> Result<(), Error> {
        let mut retained = 0_usize;
        for index in 0..self.len {
            charge_frontier_bookkeeping(accounting, 1)?;
            let candidate = self.entries[index];
            if candidate.start >= minimum_start {
                self.entries[retained] = candidate;
                retained = add(retained, 1, Resource::ExecutionWork)?;
            }
        }
        self.len = retained;
        Ok(())
    }
}

struct ExecutorScratch {
    active: SparseFrontier,
    next: SparseFrontier,
    completed: CompletedSet,
}

impl ExecutorScratch {
    const fn new() -> Self {
        Self {
            active: SparseFrontier::new(),
            next: SparseFrontier::new(),
            completed: CompletedSet::new(),
        }
    }
}

#[derive(Clone, Copy)]
struct MiddleSymbol {
    separator: bool,
    data: bool,
}

/// One exact occurrence of either retained anchor.
///
/// The forward pass fills the three facts needed when this occurrence is a
/// terminal and the two prefix facts needed when it is a start. The reverse
/// pass fills the remaining start fact. Keeping only those six facts makes the
/// source-independent scratch ceiling materially smaller than retaining a
/// complete prefix record at every input boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AnchorOccurrence {
    start: usize,
    end: usize,
    start_invalid: usize,
    start_data: usize,
    start_first_run: usize,
    end_invalid: usize,
    end_data: usize,
    end_last_run: usize,
}

struct AnchorEvents {
    first: ExactVec<AnchorOccurrence>,
    second: ExactVec<AnchorOccurrence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedExecutor {
    Events,
    Frontier,
}

#[derive(Clone, Copy)]
struct Selection {
    executor: SelectedExecutor,
    prospective: OperationProspective,
    physical_route: OperationPhysicalRoute,
    prepublication_fallback: OperationPrepublicationFallback,
}

pub(super) struct RouteInvocation {
    pub(super) range: Range<usize>,
    pub(super) strategy: Strategy,
    pub(super) limits: OperationLimits,
    pub(super) allocation_limit: usize,
}

pub(super) struct RouteEffects<'attempt, 'publication, 'accounting, 'allocation, 'observer> {
    pub(super) attempt: Option<&'attempt mut AttemptPublication<'publication>>,
    pub(super) accounting: &'accounting mut ExecutionAccounting,
    pub(super) actual_allocations: &'allocation mut usize,
    pub(super) prospective_observer:
        Option<&'observer mut dyn FnMut(OperationProspective) -> Result<(), Error>>,
}

impl CompiledRegex {
    pub(super) fn execute_ordered_bounded_span_sum(
        &self,
        plan: &OrderedBoundedSpanSumPlan,
        local: &[u8],
        invocation: RouteInvocation,
        effects: RouteEffects<'_, '_, '_, '_, '_>,
    ) -> Result<ExecutionResult, Error> {
        let selection = select_executor(
            &self.program,
            plan,
            local.len(),
            invocation.limits,
            invocation.allocation_limit,
        )?;
        let prospective = selection.prospective;
        if let Some(publication) = effects.attempt {
            publication.identity.physical_route = Some(selection.physical_route);
            publication.identity.prepublication_fallback = selection.prepublication_fallback;
            *publication.prospective = Some(prospective);
            if let Some(observer) = effects.prospective_observer {
                observer(prospective)?;
            }
        }
        enforce(
            prospective.allocations,
            invocation.allocation_limit,
            Resource::Allocations,
        )?;
        prospective.enforce_limits(invocation.limits)?;

        *effects.actual_allocations = 0;
        let (matches, span_sum) = match selection.executor {
            SelectedExecutor::Events => {
                reduce_events(plan, local, effects.accounting, effects.actual_allocations)?
            }
            SelectedExecutor::Frontier => {
                effects.accounting.scratch_peak_bytes = core::mem::size_of::<ExecutorScratch>();
                effects.accounting.peak_bytes = effects.accounting.scratch_peak_bytes;
                reduce_frontier(plan, local, effects.accounting)?
            }
        };
        if !prospective.contains(*effects.accounting) {
            return Err(Error::InternalInvariant(
                "ordered bounded-span actual accounting exceeds its prospective",
            ));
        }
        let certificate = OperationCertificate {
            regex_plan_id: self.plan_id(),
            operation_limits_id: operation_limits_identity(invocation.limits),
            strategy: invocation.strategy,
            operation: OperationAttemptKind::SpanSum,
            physical_route: selection.physical_route,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: selection.prepublication_fallback,
            prospective_allocations: compact_operation_allocation_count(prospective.allocations)?,
            actual_allocations: compact_operation_allocation_count(*effects.actual_allocations)?,
            range: invocation.range,
            states: prospective.states,
            table_cells: prospective.table_cells,
            row_storage: prospective.row_storage,
            row_record_bytes: prospective.row_record_bytes,
            terminal_frontier: prospective.terminal_frontier,
            work_bound: prospective.work_bound,
            random_access_bytes: prospective.random_access_bytes,
            scratch_bytes: prospective.scratch_bytes,
            log_bytes: prospective.log_bytes,
            sequential_bytes_bound: prospective.sequential_bytes,
            match_events: prospective.match_events,
            output_matches: prospective.output_matches,
            output_bytes: prospective.output_bytes,
            span_sum: prospective.span_sum,
            peak_bytes: prospective.peak_bytes,
        };
        Ok(ExecutionResult {
            certificate,
            accounting: *effects.accounting,
            summary: ScanSummary {
                matches,
                events: matches,
                suppressed: 0,
                span_sum,
            },
            spans: Vec::new(),
        })
    }
}

fn select_executor(
    program: &Program,
    plan: &OrderedBoundedSpanSumPlan,
    input_bytes: usize,
    limits: OperationLimits,
    allocation_limit: usize,
) -> Result<Selection, Error> {
    let events = match event_prospective(program, plan, input_bytes) {
        Ok(prospective) => Some(prospective),
        Err(Error::ArithmeticOverflow { .. }) => None,
        Err(error) => return Err(error),
    };
    let frontier = match frontier_prospective(program, plan, input_bytes) {
        Ok(prospective) => prospective,
        Err(error @ Error::ArithmeticOverflow { .. }) => {
            if let Some(prospective) = events
                && prospective.allocations <= allocation_limit
                && prospective.enforce_limits(limits).is_ok()
            {
                return Ok(Selection {
                    executor: SelectedExecutor::Events,
                    prospective,
                    physical_route: OperationPhysicalRoute::OrderedBoundedSpanSumEvents,
                    prepublication_fallback: OperationPrepublicationFallback::None,
                });
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    if let Some(prospective) = events
        && prospective.work_bound < frontier.work_bound
        && prospective.allocations <= allocation_limit
        && prospective.enforce_limits(limits).is_ok()
    {
        Ok(Selection {
            executor: SelectedExecutor::Events,
            prospective,
            physical_route: OperationPhysicalRoute::OrderedBoundedSpanSumEvents,
            prepublication_fallback: OperationPrepublicationFallback::None,
        })
    } else {
        Ok(Selection {
            executor: SelectedExecutor::Frontier,
            prospective: frontier,
            physical_route: OperationPhysicalRoute::OrderedBoundedSpanSum,
            prepublication_fallback:
                OperationPrepublicationFallback::OrderedBoundedEventsThenFrontier,
        })
    }
}

fn event_prospective(
    program: &Program,
    plan: &OrderedBoundedSpanSumPlan,
    input_bytes: usize,
) -> Result<OperationProspective, Error> {
    let boundaries = add(input_bytes, 1, Resource::Boundaries)?;
    let first_events = anchor_occurrence_upper(input_bytes, plan.first_anchor().len())?;
    let second_events = anchor_occurrence_upper(input_bytes, plan.second_anchor().len())?;
    let event_upper = add(first_events, second_events, Resource::MatchEvents)?;
    let allocation_upper = usize::from(first_events != 0)
        .checked_add(usize::from(second_events != 0))
        .ok_or(Error::ArithmeticOverflow {
            resource: Resource::Allocations,
        })?;
    let event_bytes = mul(
        event_upper,
        core::mem::size_of::<AnchorOccurrence>(),
        Resource::ScratchBytes,
    )?;
    let scratch = add(
        core::mem::size_of::<AnchorEvents>(),
        event_bytes,
        Resource::ScratchBytes,
    )?;
    let anchor_bytes = add(
        plan.first_anchor().len(),
        plan.second_anchor().len(),
        Resource::ExecutionWork,
    )?;
    // Both complete anchor scans verify both retained literals at every
    // first-byte candidate. `memchr2` emits at most one candidate per source
    // position even when the two first bytes are equal.
    let root_probes = mul(
        mul(2, input_bytes, Resource::ExecutionWork)?,
        anchor_bytes,
        Resource::ExecutionWork,
    )?;
    let search_steps = mul(
        mul(2, event_upper, Resource::ExecutionWork)?,
        binary_search_step_upper(event_upper)?,
        Resource::ExecutionWork,
    )?;
    let transition_checks = add(
        mul(4, input_bytes, Resource::ExecutionWork)?,
        search_steps,
        Resource::ExecutionWork,
    )?;
    let frontier_bookkeeping = mul(5, event_upper, Resource::ExecutionWork)?;
    let work_bound = add(
        add(
            add(
                mul(11, input_bytes, Resource::ExecutionWork)?,
                root_probes,
                Resource::ExecutionWork,
            )?,
            mul(6, event_upper, Resource::ExecutionWork)?,
            Resource::ExecutionWork,
        )?,
        search_steps,
        Resource::ExecutionWork,
    )?;
    let sequential_bytes = mul(4, input_bytes, Resource::SequentialBytes)?;
    let accounting = ExecutionAccounting {
        state_evaluations: event_upper,
        transition_checks,
        root_probes,
        emitted_matches: input_bytes,
        frontier_insertions: mul(2, event_upper, Resource::ExecutionWork)?,
        frontier_evaluations: mul(2, input_bytes, Resource::ExecutionWork)?,
        frontier_bookkeeping,
        sequential_bytes_read: sequential_bytes,
        random_access_bytes_read: root_probes,
        scratch_peak_bytes: scratch,
        peak_bytes: scratch,
        work: work_bound,
        ..ExecutionAccounting::default()
    };
    Ok(OperationProspective {
        states: program.insts.len(),
        boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: 0,
        terminal_frontier: false,
        work_bound,
        random_access_bytes: root_probes,
        scratch_bytes: scratch,
        log_bytes: 0,
        sequential_bytes,
        match_events: event_upper,
        output_matches: input_bytes,
        output_bytes: 0,
        span_sum: input_bytes,
        allocations: allocation_upper,
        peak_bytes: scratch,
        accounting,
    })
}

fn anchor_occurrence_upper(input_bytes: usize, anchor_bytes: usize) -> Result<usize, Error> {
    let Some(remaining) = input_bytes.checked_sub(anchor_bytes) else {
        return Ok(0);
    };
    add(remaining, 1, Resource::MatchEvents)
}

fn binary_search_step_upper(items: usize) -> Result<usize, Error> {
    if items == 0 {
        Ok(0)
    } else {
        let significant =
            usize::BITS
                .checked_sub(items.leading_zeros())
                .ok_or(Error::InternalInvariant(
                    "ordered bounded-span search width exceeded the target word",
                ))?;
        usize::try_from(significant).map_err(|_| {
            Error::InternalInvariant(
                "ordered bounded-span search width does not fit the target word",
            )
        })
    }
}

fn frontier_prospective(
    program: &Program,
    plan: &OrderedBoundedSpanSumPlan,
    input_bytes: usize,
) -> Result<OperationProspective, Error> {
    let boundaries = add(input_bytes, 1, Resource::Boundaries)?;
    let anchor_bytes = add(
        plan.first_anchor().len(),
        plan.second_anchor().len(),
        Resource::ExecutionWork,
    )?;
    let root_probes = mul(
        mul(2, anchor_bytes, Resource::ExecutionWork)?,
        boundaries,
        Resource::ExecutionWork,
    )?;
    let states = middle_state_count(plan.max_chunks())?;
    let slots = mul(4, states, Resource::ExecutionWork)?;
    let lane_bound = mul(slots, boundaries, Resource::ExecutionWork)?;
    // A work unit is one bounded service, not the sum of its correlated
    // public subcounters. Each slot can participate in at most six services
    // per boundary: epsilon closure, two direction-presence passes, terminal
    // update, symbol transition, and settlement/filtering. Literal source
    // probes and the two class predicates are charged separately.
    let work_bound = add(
        add(
            mul(6, lane_bound, Resource::ExecutionWork)?,
            mul(2, root_probes, Resource::ExecutionWork)?,
            Resource::ExecutionWork,
        )?,
        mul(3, input_bytes, Resource::ExecutionWork)?,
        Resource::ExecutionWork,
    )?;
    let scratch = core::mem::size_of::<ExecutorScratch>();
    let accounting = ExecutionAccounting {
        state_evaluations: mul(4, lane_bound, Resource::ExecutionWork)?,
        transition_checks: add(
            mul(2, input_bytes, Resource::ExecutionWork)?,
            lane_bound,
            Resource::ExecutionWork,
        )?,
        root_probes,
        successful_paths: mul(2, lane_bound, Resource::ExecutionWork)?,
        emitted_matches: input_bytes,
        frontier_peak_states: slots,
        frontier_insertions: mul(8, lane_bound, Resource::ExecutionWork)?,
        frontier_evaluations: mul(6, lane_bound, Resource::ExecutionWork)?,
        frontier_bookkeeping: mul(slots, lane_bound, Resource::ExecutionWork)?,
        sequential_bytes_read: input_bytes,
        random_access_bytes_read: root_probes,
        scratch_peak_bytes: scratch,
        peak_bytes: scratch,
        work: work_bound,
        ..ExecutionAccounting::default()
    };
    Ok(OperationProspective {
        states: program.insts.len(),
        boundaries,
        table_cells: 0,
        row_storage: None,
        row_record_bytes: 0,
        terminal_frontier: false,
        work_bound,
        random_access_bytes: 0,
        scratch_bytes: scratch,
        log_bytes: 0,
        sequential_bytes: input_bytes,
        match_events: input_bytes,
        output_matches: input_bytes,
        output_bytes: 0,
        span_sum: input_bytes,
        allocations: 0,
        peak_bytes: scratch,
        accounting,
    })
}

fn reduce_events(
    plan: &OrderedBoundedSpanSumPlan,
    haystack: &[u8],
    accounting: &mut ExecutionAccounting,
    actual_allocations: &mut usize,
) -> Result<(usize, usize), Error> {
    accounting.scratch_peak_bytes = core::mem::size_of::<AnchorEvents>();
    accounting.peak_bytes = accounting.scratch_peak_bytes;

    let mut first_count = 0_usize;
    let mut second_count = 0_usize;
    scan_anchor_candidates(plan, haystack, accounting, |direction, _, _| {
        if direction == 0 {
            first_count = add(first_count, 1, Resource::MatchEvents)?;
        } else {
            second_count = add(second_count, 1, Resource::MatchEvents)?;
        }
        Ok(())
    })?;

    let first_bytes = mul(
        first_count,
        core::mem::size_of::<AnchorOccurrence>(),
        Resource::ScratchBytes,
    )?;
    let first = exact_occurrences(first_count, first_bytes)?;
    record_event_allocation(actual_allocations, first_count)?;
    update_event_scratch_peak(accounting, first_bytes)?;

    let second_bytes = mul(
        second_count,
        core::mem::size_of::<AnchorOccurrence>(),
        Resource::ScratchBytes,
    )?;
    let second = exact_occurrences(second_count, second_bytes)?;
    record_event_allocation(actual_allocations, second_count)?;
    update_event_scratch_peak(accounting, second_bytes)?;

    let mut events = AnchorEvents { first, second };
    scan_anchor_candidates(plan, haystack, accounting, |direction, start, end| {
        let occurrence = AnchorOccurrence {
            start,
            end,
            ..AnchorOccurrence::default()
        };
        let target = if direction == 0 {
            &mut events.first
        } else {
            &mut events.second
        };
        target.try_push(occurrence).map_err(|_| {
            Error::InternalInvariant("ordered bounded-span anchor census changed during collection")
        })
    })?;
    if events.first.len() != first_count || events.second.len() != second_count {
        return Err(Error::InternalInvariant(
            "ordered bounded-span collected anchor count diverged from its census",
        ));
    }

    let total_runs = annotate_forward(plan, haystack, &mut events, accounting)?;
    annotate_reverse(plan, haystack, &mut events, total_runs, accounting)?;
    reduce_annotated_events(plan, &events, total_runs, accounting)
}

fn exact_occurrences(
    length: usize,
    allocation_bytes: usize,
) -> Result<ExactVec<AnchorOccurrence>, Error> {
    #[cfg(test)]
    if length != 0 && super::allocation_fault::should_fail() {
        return Err(Error::AllocationFailed {
            resource: Resource::ScratchBytes,
            items: allocation_bytes,
        });
    }
    ExactVec::try_with_capacity(length).map_err(|error| match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow {
            resource: Resource::ScratchBytes,
        },
        CopyError::AllocationFailed => Error::AllocationFailed {
            resource: Resource::ScratchBytes,
            items: allocation_bytes,
        },
    })
}

fn record_event_allocation(actual_allocations: &mut usize, items: usize) -> Result<(), Error> {
    if items != 0 {
        *actual_allocations = add(*actual_allocations, 1, Resource::Allocations)?;
    }
    Ok(())
}

fn update_event_scratch_peak(
    accounting: &mut ExecutionAccounting,
    added_bytes: usize,
) -> Result<(), Error> {
    accounting.scratch_peak_bytes = add(
        accounting.scratch_peak_bytes,
        added_bytes,
        Resource::ScratchBytes,
    )?;
    accounting.peak_bytes = accounting.scratch_peak_bytes;
    Ok(())
}

fn scan_anchor_candidates(
    plan: &OrderedBoundedSpanSumPlan,
    haystack: &[u8],
    accounting: &mut ExecutionAccounting,
    mut observe: impl FnMut(usize, usize, usize) -> Result<(), Error>,
) -> Result<(), Error> {
    charge_complete_source_pass(accounting, haystack.len())?;
    let first = plan.first_anchor();
    let second = plan.second_anchor();
    for start in memchr::memchr2_iter(first[0], second[0], haystack) {
        charge_anchor_candidate(accounting)?;
        if literal_matches(haystack, start, first, accounting)? {
            charge_anchor_occurrence(accounting)?;
            let end = add(start, first.len(), Resource::Boundaries)?;
            observe(0, start, end)?;
        }
        if literal_matches(haystack, start, second, accounting)? {
            charge_anchor_occurrence(accounting)?;
            let end = add(start, second.len(), Resource::Boundaries)?;
            observe(1, start, end)?;
        }
    }
    Ok(())
}

// For M = (S* D+ S*){0,K}, classify every byte as S\D, D\S, S∩D or
// outside S∪D. A nonempty interval is in M exactly when it has no outside
// byte, contains a D-capable byte, and needs at most K D+ factors. Every D\S
// byte must belong to a D+ factor, while an S\D byte separates such factors;
// conversely, one factor per D-run containing D\S is constructive, assigning
// all remaining bytes to S. If there is no D\S byte, any one S∩D byte supplies
// the single required factor.
//
// The passes below rank global D-runs containing D\S by their first and last
// such byte. For an interval [l,r), F(r) + L(l) - G counts intersecting ranked
// runs. The only possible rank intersection without an actual D\S byte in the
// interval lies wholly inside one D-run between two ranked bytes; its value is
// one, exactly the required factor count for that S∩D-only interval. Thus the
// rank predicate is exact even when S and D overlap.
fn annotate_forward(
    plan: &OrderedBoundedSpanSumPlan,
    haystack: &[u8],
    events: &mut AnchorEvents,
    accounting: &mut ExecutionAccounting,
) -> Result<usize, Error> {
    charge_complete_source_pass(accounting, haystack.len())?;
    let mut first_start = 0_usize;
    let mut first_end = 0_usize;
    let mut second_start = 0_usize;
    let mut second_end = 0_usize;
    let mut invalid_prefix = 0_usize;
    let mut data_prefix = 0_usize;
    let mut first_run_prefix = 0_usize;
    let mut in_data_run = false;
    let mut run_has_data_only = false;
    let mut next_annotation = forward_annotation_boundary(
        &events.first,
        first_start,
        first_end,
        &events.second,
        second_start,
        second_end,
    );

    for boundary in 0..=haystack.len() {
        if next_annotation == Some(boundary) {
            annotate_forward_boundary(
                events.first.as_mut_slice(),
                &mut first_start,
                &mut first_end,
                boundary,
                invalid_prefix,
                data_prefix,
                first_run_prefix,
                accounting,
            )?;
            annotate_forward_boundary(
                events.second.as_mut_slice(),
                &mut second_start,
                &mut second_end,
                boundary,
                invalid_prefix,
                data_prefix,
                first_run_prefix,
                accounting,
            )?;
            next_annotation = forward_annotation_boundary(
                &events.first,
                first_start,
                first_end,
                &events.second,
                second_start,
                second_end,
            );
        }
        if boundary == haystack.len() {
            break;
        }

        let byte = haystack[boundary];
        charge_class_check(accounting)?;
        let data = plan.data().contains(byte);
        charge_class_check(accounting)?;
        let separator = plan.separators().contains(byte);
        if data {
            data_prefix = add(data_prefix, 1, Resource::Boundaries)?;
            if !in_data_run {
                in_data_run = true;
                run_has_data_only = false;
            }
            if !separator && !run_has_data_only {
                first_run_prefix = add(first_run_prefix, 1, Resource::Boundaries)?;
                run_has_data_only = true;
            }
        } else {
            in_data_run = false;
            run_has_data_only = false;
        }
        if !data && !separator {
            invalid_prefix = add(invalid_prefix, 1, Resource::Boundaries)?;
        }
    }
    if first_start != events.first.len()
        || first_end != events.first.len()
        || second_start != events.second.len()
        || second_end != events.second.len()
    {
        return Err(Error::InternalInvariant(
            "ordered bounded-span forward annotation missed an anchor boundary",
        ));
    }
    Ok(first_run_prefix)
}

fn forward_annotation_boundary(
    first: &[AnchorOccurrence],
    first_start: usize,
    first_end: usize,
    second: &[AnchorOccurrence],
    second_start: usize,
    second_end: usize,
) -> Option<usize> {
    [
        first.get(first_start).map(|event| event.start),
        first.get(first_end).map(|event| event.end),
        second.get(second_start).map(|event| event.start),
        second.get(second_end).map(|event| event.end),
    ]
    .into_iter()
    .flatten()
    .min()
}

#[allow(
    clippy::too_many_arguments,
    reason = "the two monotone occurrence cursors receive one shared boundary fact tuple"
)]
fn annotate_forward_boundary(
    events: &mut [AnchorOccurrence],
    start_index: &mut usize,
    end_index: &mut usize,
    boundary: usize,
    invalid_prefix: usize,
    data_prefix: usize,
    first_run_prefix: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    while events
        .get(*start_index)
        .is_some_and(|event| event.start == boundary)
    {
        let event = events
            .get_mut(*start_index)
            .ok_or(Error::InternalInvariant(
                "ordered bounded-span start annotation escaped its event slice",
            ))?;
        event.start_invalid = invalid_prefix;
        event.start_data = data_prefix;
        event.start_first_run = first_run_prefix;
        *start_index = add(*start_index, 1, Resource::MatchEvents)?;
        charge_event_annotation(accounting)?;
    }
    while events
        .get(*end_index)
        .is_some_and(|event| event.end == boundary)
    {
        let event = events.get_mut(*end_index).ok_or(Error::InternalInvariant(
            "ordered bounded-span end annotation escaped its event slice",
        ))?;
        event.end_invalid = invalid_prefix;
        event.end_data = data_prefix;
        *end_index = add(*end_index, 1, Resource::MatchEvents)?;
        charge_event_annotation(accounting)?;
    }
    Ok(())
}

fn annotate_reverse(
    plan: &OrderedBoundedSpanSumPlan,
    haystack: &[u8],
    events: &mut AnchorEvents,
    total_runs: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    charge_complete_source_pass(accounting, haystack.len())?;
    let mut first_end = events.first.len();
    let mut second_end = events.second.len();
    let mut last_run_suffix = 0_usize;
    let mut in_data_run = false;
    let mut run_has_data_only = false;
    let mut boundary = haystack.len();
    let mut next_annotation =
        reverse_annotation_boundary(&events.first, first_end, &events.second, second_end);

    loop {
        if next_annotation == Some(boundary) {
            annotate_reverse_boundary(
                events.first.as_mut_slice(),
                &mut first_end,
                boundary,
                last_run_suffix,
                accounting,
            )?;
            annotate_reverse_boundary(
                events.second.as_mut_slice(),
                &mut second_end,
                boundary,
                last_run_suffix,
                accounting,
            )?;
            next_annotation =
                reverse_annotation_boundary(&events.first, first_end, &events.second, second_end);
        }
        if boundary == 0 {
            break;
        }
        boundary = boundary.checked_sub(1).ok_or(Error::InternalInvariant(
            "ordered bounded-span reverse boundary underflow",
        ))?;
        let byte = haystack[boundary];
        charge_class_check(accounting)?;
        let data = plan.data().contains(byte);
        charge_class_check(accounting)?;
        let separator = plan.separators().contains(byte);
        if data {
            if !in_data_run {
                in_data_run = true;
                run_has_data_only = false;
            }
            if !separator && !run_has_data_only {
                last_run_suffix = add(last_run_suffix, 1, Resource::Boundaries)?;
                run_has_data_only = true;
            }
        } else {
            in_data_run = false;
            run_has_data_only = false;
        }
    }
    if first_end != 0 || second_end != 0 || last_run_suffix != total_runs {
        return Err(Error::InternalInvariant(
            "ordered bounded-span reverse rank diverged from its forward census",
        ));
    }
    Ok(())
}

fn reverse_annotation_boundary(
    first: &[AnchorOccurrence],
    first_end: usize,
    second: &[AnchorOccurrence],
    second_end: usize,
) -> Option<usize> {
    [
        first_end
            .checked_sub(1)
            .and_then(|index| first.get(index))
            .map(|event| event.end),
        second_end
            .checked_sub(1)
            .and_then(|index| second.get(index))
            .map(|event| event.end),
    ]
    .into_iter()
    .flatten()
    .max()
}

fn annotate_reverse_boundary(
    events: &mut [AnchorOccurrence],
    end_index: &mut usize,
    boundary: usize,
    last_run_suffix: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    while end_index
        .checked_sub(1)
        .and_then(|index| events.get(index))
        .is_some_and(|event| event.end == boundary)
    {
        *end_index = end_index.checked_sub(1).ok_or(Error::InternalInvariant(
            "ordered bounded-span reverse event index underflow",
        ))?;
        let event = events.get_mut(*end_index).ok_or(Error::InternalInvariant(
            "ordered bounded-span reverse annotation escaped its event slice",
        ))?;
        event.end_last_run = last_run_suffix;
        charge_event_annotation(accounting)?;
    }
    Ok(())
}

fn reduce_annotated_events(
    plan: &OrderedBoundedSpanSumPlan,
    events: &AnchorEvents,
    total_runs: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<(usize, usize), Error> {
    let mut first_index = 0_usize;
    let mut second_index = 0_usize;
    let mut minimum_start = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;

    while first_index < events.first.len() || second_index < events.second.len() {
        let use_first = match (
            events.first.get(first_index),
            events.second.get(second_index),
        ) {
            (Some(first), Some(second)) => (first.start, 0_usize) <= (second.start, 1_usize),
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => break,
        };
        let (starter, terminals) = if use_first {
            let starter = *events
                .first
                .get(first_index)
                .ok_or(Error::InternalInvariant(
                    "ordered bounded-span first starter escaped its event slice",
                ))?;
            first_index = add(first_index, 1, Resource::MatchEvents)?;
            (starter, events.second.as_slice())
        } else {
            let starter = *events
                .second
                .get(second_index)
                .ok_or(Error::InternalInvariant(
                    "ordered bounded-span second starter escaped its event slice",
                ))?;
            second_index = add(second_index, 1, Resource::MatchEvents)?;
            (starter, events.first.as_slice())
        };
        charge_event_starter(accounting)?;
        if starter.start < minimum_start {
            continue;
        }
        let Some(terminal_index) = latest_terminal_index(
            &starter,
            terminals,
            total_runs,
            plan.max_chunks(),
            accounting,
        )?
        else {
            continue;
        };
        let terminal = terminals
            .get(terminal_index)
            .ok_or(Error::InternalInvariant(
                "ordered bounded-span terminal selection escaped its event slice",
            ))?;
        accounting.emitted_matches = add(accounting.emitted_matches, 1, Resource::MatchEvents)?;
        accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
        matches = add(matches, 1, Resource::OutputMatches)?;
        span_sum = add(
            span_sum,
            terminal
                .end
                .checked_sub(starter.start)
                .ok_or(Error::InternalInvariant(
                    "ordered bounded-span event route selected a reversed match",
                ))?,
            Resource::SpanSum,
        )?;
        minimum_start = terminal.end;
    }
    Ok((matches, span_sum))
}

fn latest_terminal_index(
    starter: &AnchorOccurrence,
    terminals: &[AnchorOccurrence],
    total_runs: usize,
    max_chunks: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<Option<usize>, Error> {
    let lower = lower_bound_terminal(terminals, starter.end, accounting)?;
    if lower == terminals.len() {
        return Ok(None);
    }
    let run_limit = add(total_runs, max_chunks, Resource::ExecutionWork)?;
    let mut left = lower;
    let mut right = terminals.len();
    while left < right {
        charge_event_search(accounting)?;
        let width = right.checked_sub(left).ok_or(Error::InternalInvariant(
            "ordered bounded-span terminal search interval reversed",
        ))?;
        let middle = add(left, width / 2, Resource::MatchEvents)?;
        let terminal = terminals.get(middle).ok_or(Error::InternalInvariant(
            "ordered bounded-span terminal search escaped its event slice",
        ))?;
        let run_sum = add(
            terminal.start_first_run,
            starter.end_last_run,
            Resource::ExecutionWork,
        )?;
        let admissible = terminal.start_invalid == starter.end_invalid && run_sum <= run_limit;
        if admissible {
            left = add(middle, 1, Resource::MatchEvents)?;
        } else {
            right = middle;
        }
    }
    if left == lower {
        return Ok(None);
    }
    let latest_index = left.checked_sub(1).ok_or(Error::InternalInvariant(
        "ordered bounded-span terminal predecessor underflow",
    ))?;
    let latest = terminals.get(latest_index).ok_or(Error::InternalInvariant(
        "ordered bounded-span latest terminal escaped its event slice",
    ))?;
    if latest.start == starter.end || latest.start_data > starter.end_data {
        return Ok(Some(latest_index));
    }
    // A nonempty separator-only middle is not in the language. All earlier
    // nonempty terminals also precede the first D-capable byte, but an exact
    // adjacent terminal still accepts through the zero-repetition branch.
    if terminals
        .get(lower)
        .is_some_and(|terminal| terminal.start == starter.end)
    {
        return Ok(Some(lower));
    }
    Ok(None)
}

fn lower_bound_terminal(
    terminals: &[AnchorOccurrence],
    target: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<usize, Error> {
    let mut left = 0_usize;
    let mut right = terminals.len();
    while left < right {
        charge_event_search(accounting)?;
        let width = right.checked_sub(left).ok_or(Error::InternalInvariant(
            "ordered bounded-span lower-bound interval reversed",
        ))?;
        let middle = add(left, width / 2, Resource::MatchEvents)?;
        let terminal = terminals.get(middle).ok_or(Error::InternalInvariant(
            "ordered bounded-span lower bound escaped its event slice",
        ))?;
        if terminal.start < target {
            left = add(middle, 1, Resource::MatchEvents)?;
        } else {
            right = middle;
        }
    }
    Ok(left)
}

fn charge_complete_source_pass(
    accounting: &mut ExecutionAccounting,
    source_bytes: usize,
) -> Result<(), Error> {
    accounting.sequential_bytes_read = add(
        accounting.sequential_bytes_read,
        source_bytes,
        Resource::SequentialBytes,
    )?;
    accounting.work = add(accounting.work, source_bytes, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_anchor_candidate(accounting: &mut ExecutionAccounting) -> Result<(), Error> {
    accounting.frontier_evaluations =
        add(accounting.frontier_evaluations, 1, Resource::ExecutionWork)?;
    accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_anchor_occurrence(accounting: &mut ExecutionAccounting) -> Result<(), Error> {
    accounting.frontier_insertions =
        add(accounting.frontier_insertions, 1, Resource::ExecutionWork)?;
    accounting.frontier_bookkeeping =
        add(accounting.frontier_bookkeeping, 1, Resource::ExecutionWork)?;
    accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_event_annotation(accounting: &mut ExecutionAccounting) -> Result<(), Error> {
    accounting.frontier_bookkeeping =
        add(accounting.frontier_bookkeeping, 1, Resource::ExecutionWork)?;
    accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_event_starter(accounting: &mut ExecutionAccounting) -> Result<(), Error> {
    accounting.state_evaluations = add(accounting.state_evaluations, 1, Resource::ExecutionWork)?;
    accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_event_search(accounting: &mut ExecutionAccounting) -> Result<(), Error> {
    accounting.transition_checks = add(accounting.transition_checks, 1, Resource::ExecutionWork)?;
    accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn reduce_frontier(
    plan: &OrderedBoundedSpanSumPlan,
    haystack: &[u8],
    accounting: &mut ExecutionAccounting,
) -> Result<(usize, usize), Error> {
    let mut scratch = ExecutorScratch::new();
    let mut boundary = 0_usize;
    let mut minimum_start = 0_usize;
    let mut matches = 0_usize;
    let mut span_sum = 0_usize;
    while boundary <= haystack.len() {
        activate_anchors(
            plan,
            haystack,
            boundary,
            minimum_start,
            &mut scratch.active,
            accounting,
        )?;
        epsilon_close(plan.max_chunks(), &mut scratch.active, accounting)?;
        update_terminals(plan, haystack, boundary, &mut scratch.active, accounting)?;
        if boundary == haystack.len() {
            drain_active(&mut scratch.active, &mut scratch.completed, accounting)?;
        } else {
            let symbol = classify_at(plan, haystack, boundary, accounting)?;
            transition(
                plan.max_chunks(),
                symbol,
                &mut scratch.active,
                &mut scratch.next,
                &mut scratch.completed,
                accounting,
            )?;
            core::mem::swap(&mut scratch.active, &mut scratch.next);
        }
        if scratch.completed.len != 0 {
            settle(
                &mut scratch,
                &mut minimum_start,
                &mut matches,
                &mut span_sum,
                accounting,
            )?;
        }
        if boundary == haystack.len() {
            break;
        }
        let next = add(boundary, 1, Resource::Boundaries)?;
        boundary = next.max(minimum_start);
    }
    Ok((matches, span_sum))
}

fn activate_anchors(
    plan: &OrderedBoundedSpanSumPlan,
    haystack: &[u8],
    boundary: usize,
    minimum_start: usize,
    active: &mut SparseFrontier,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    for (direction, anchor) in [
        (0_usize, plan.first_anchor()),
        (1_usize, plan.second_anchor()),
    ] {
        let Some(start) = boundary.checked_sub(anchor.len()) else {
            continue;
        };
        if start < minimum_start {
            continue;
        }
        if literal_matches(haystack, start, anchor, accounting)? {
            active.insert(
                direction,
                0,
                Lane {
                    start,
                    last_end: NONE,
                },
                accounting,
            )?;
        }
    }
    Ok(())
}

fn update_terminals(
    plan: &OrderedBoundedSpanSumPlan,
    haystack: &[u8],
    boundary: usize,
    active: &mut SparseFrontier,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    for direction in 0..2 {
        if !has_accepting_direction(active, direction, accounting)? {
            continue;
        }
        let terminal = if direction == 0 {
            plan.second_anchor()
        } else {
            plan.first_anchor()
        };
        if !literal_matches(haystack, boundary, terminal, accounting)? {
            continue;
        }
        let end = add(boundary, terminal.len(), Resource::Boundaries)?;
        update_direction_candidates(active, direction, end, accounting)?;
    }
    Ok(())
}

fn has_accepting_direction(
    active: &SparseFrontier,
    direction: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<bool, Error> {
    for index in 0..active.len {
        charge_frontier_evaluation(accounting)?;
        let key = usize::from(active.keys[index]);
        let (lane_direction, state, _) = decode_frontier_key(key);
        if lane_direction == direction && middle_accepts(state) && active.slots[key].start != NONE {
            return Ok(true);
        }
    }
    Ok(false)
}

fn update_direction_candidates(
    active: &mut SparseFrontier,
    direction: usize,
    end: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    let original_len = active.len;
    for index in 0..original_len {
        charge_frontier_evaluation(accounting)?;
        let key = usize::from(active.keys[index]);
        let (lane_direction, state, has_candidate) = decode_frontier_key(key);
        if lane_direction != direction || !middle_accepts(state) {
            continue;
        }
        let mut lane = active.slots[key];
        if lane.start == NONE {
            continue;
        }
        accounting.state_evaluations =
            add(accounting.state_evaluations, 1, Resource::ExecutionWork)?;
        accounting.successful_paths = add(accounting.successful_paths, 1, Resource::ExecutionWork)?;
        lane.last_end = end;
        if has_candidate {
            active.slots[key] = lane;
        } else {
            active.slots[key] = Lane::EMPTY;
            active.insert(direction, state, lane, accounting)?;
        }
    }
    active.compact()?;
    Ok(())
}

fn transition(
    max_chunks: usize,
    symbol: MiddleSymbol,
    active: &mut SparseFrontier,
    next: &mut SparseFrontier,
    completed: &mut CompletedSet,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    next.clear();
    for index in 0..active.len {
        charge_frontier_evaluation(accounting)?;
        let key = usize::from(active.keys[index]);
        let lane = active.slots[key];
        if lane.start == NONE {
            continue;
        }
        let (direction, state, _) = decode_frontier_key(key);
        accounting.state_evaluations =
            add(accounting.state_evaluations, 1, Resource::ExecutionWork)?;
        accounting.transition_checks =
            add(accounting.transition_checks, 1, Resource::ExecutionWork)?;
        let destinations = transition_destinations(state, symbol, max_chunks)?;
        for next_state in destinations.iter().copied() {
            next.insert(direction, next_state, lane, accounting)?;
        }
        if destinations.is_empty() && lane.has_candidate() {
            completed.insert(
                Completed {
                    start: lane.start,
                    end: lane.last_end,
                    direction,
                },
                accounting,
            )?;
        }
    }
    active.clear();
    Ok(())
}

fn epsilon_close(
    max_chunks: usize,
    active: &mut SparseFrontier,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    let original_len = active.len;
    for index in 0..original_len {
        charge_frontier_evaluation(accounting)?;
        let key = usize::from(active.keys[index]);
        let lane = active.slots[key];
        if lane.start == NONE {
            continue;
        }
        let (direction, state, _) = decode_frontier_key(key);
        let Some(chunk) = completed_chunk(state) else {
            continue;
        };
        let next_chunk = chunk.checked_add(1).ok_or(Error::ArithmeticOverflow {
            resource: Resource::ExecutionWork,
        })?;
        if next_chunk < max_chunks {
            active.insert(direction, leading_state(next_chunk)?, lane, accounting)?;
        }
    }
    Ok(())
}

fn drain_active(
    active: &mut SparseFrontier,
    completed: &mut CompletedSet,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    for index in 0..active.len {
        charge_frontier_evaluation(accounting)?;
        let key = usize::from(active.keys[index]);
        let lane = active.slots[key];
        if lane.has_candidate() {
            let (direction, _, _) = decode_frontier_key(key);
            completed.insert(
                Completed {
                    start: lane.start,
                    end: lane.last_end,
                    direction,
                },
                accounting,
            )?;
        }
    }
    active.clear();
    Ok(())
}

fn settle(
    scratch: &mut ExecutorScratch,
    minimum_start: &mut usize,
    matches: &mut usize,
    span_sum: &mut usize,
    accounting: &mut ExecutionAccounting,
) -> Result<(), Error> {
    loop {
        let Some((_, completed)) = scratch.completed.earliest(accounting)? else {
            return Ok(());
        };
        let completed_key = (completed.start, completed.direction);
        if scratch
            .active
            .earliest_key(accounting)?
            .is_some_and(|active_key| active_key <= completed_key)
        {
            return Ok(());
        }
        accounting.emitted_matches = add(accounting.emitted_matches, 1, Resource::MatchEvents)?;
        accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
        *matches = add(*matches, 1, Resource::OutputMatches)?;
        *span_sum = add(
            *span_sum,
            completed
                .end
                .checked_sub(completed.start)
                .ok_or(Error::InternalInvariant(
                    "ordered bounded-span selected a reversed match",
                ))?,
            Resource::SpanSum,
        )?;
        *minimum_start = completed.end;
        scratch.active.discard_before(*minimum_start, accounting)?;
        scratch
            .completed
            .discard_before(*minimum_start, accounting)?;
    }
}

fn classify_at(
    plan: &OrderedBoundedSpanSumPlan,
    haystack: &[u8],
    index: usize,
    accounting: &mut ExecutionAccounting,
) -> Result<MiddleSymbol, Error> {
    accounting.sequential_bytes_read = add(
        accounting.sequential_bytes_read,
        1,
        Resource::SequentialBytes,
    )?;
    accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
    let byte = haystack[index];
    charge_class_check(accounting)?;
    let data = plan.data().contains(byte);
    charge_class_check(accounting)?;
    let separator = plan.separators().contains(byte);
    Ok(MiddleSymbol { separator, data })
}

fn literal_matches(
    haystack: &[u8],
    start: usize,
    literal: &[u8],
    accounting: &mut ExecutionAccounting,
) -> Result<bool, Error> {
    let Some(end) = start.checked_add(literal.len()) else {
        return Ok(false);
    };
    if end > haystack.len() {
        return Ok(false);
    }
    for (offset, &expected) in literal.iter().enumerate() {
        accounting.root_probes = add(accounting.root_probes, 1, Resource::ExecutionWork)?;
        accounting.random_access_bytes_read = add(
            accounting.random_access_bytes_read,
            1,
            Resource::RandomAccessBytes,
        )?;
        accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
        let index = add(start, offset, Resource::Boundaries)?;
        if haystack[index] != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

struct Destinations {
    states: [usize; 2],
    len: usize,
}

impl Destinations {
    const fn new() -> Self {
        Self {
            states: [0; 2],
            len: 0,
        }
    }

    fn push(&mut self, state: usize) -> Result<(), Error> {
        if self.states[..self.len].contains(&state) {
            return Ok(());
        }
        if self.len == self.states.len() {
            return Err(Error::InternalInvariant(
                "ordered bounded-span transition exceeded two destinations",
            ));
        }
        self.states[self.len] = state;
        self.len = add(self.len, 1, Resource::ExecutionWork)?;
        Ok(())
    }

    fn iter(&self) -> impl Iterator<Item = &usize> {
        self.states[..self.len].iter()
    }

    const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

fn transition_destinations(
    state: usize,
    symbol: MiddleSymbol,
    max_chunks: usize,
) -> Result<Destinations, Error> {
    let mut destinations = Destinations::new();
    if state == 0 {
        if symbol.separator {
            destinations.push(leading_state(0)?)?;
        }
        if symbol.data {
            destinations.push(data_state(0)?)?;
        }
        return Ok(destinations);
    }
    let (chunk, phase) = decode_middle_state(state).ok_or(Error::InternalInvariant(
        "ordered bounded-span encountered an invalid middle state",
    ))?;
    if chunk >= max_chunks {
        return Err(Error::InternalInvariant(
            "ordered bounded-span middle state exceeds its chunk theorem",
        ));
    }
    match phase {
        MiddlePhase::Leading => {
            if symbol.separator {
                destinations.push(state)?;
            }
            if symbol.data {
                destinations.push(data_state(chunk)?)?;
            }
        }
        MiddlePhase::Data => {
            if symbol.data {
                destinations.push(state)?;
            }
            if symbol.separator {
                destinations.push(trailing_state(chunk)?)?;
            }
        }
        MiddlePhase::Trailing => {
            if symbol.separator {
                destinations.push(state)?;
            }
        }
    }
    Ok(destinations)
}

const fn middle_accepts(state: usize) -> bool {
    state == 0
        || matches!(
            decode_middle_state(state),
            Some((_, MiddlePhase::Data | MiddlePhase::Trailing))
        )
}

#[derive(Clone, Copy)]
enum MiddlePhase {
    Leading,
    Data,
    Trailing,
}

fn leading_state(chunk: usize) -> Result<usize, Error> {
    add(
        mul(3, chunk, Resource::ExecutionWork)?,
        1,
        Resource::ExecutionWork,
    )
}

fn data_state(chunk: usize) -> Result<usize, Error> {
    add(leading_state(chunk)?, 1, Resource::ExecutionWork)
}

fn trailing_state(chunk: usize) -> Result<usize, Error> {
    add(leading_state(chunk)?, 2, Resource::ExecutionWork)
}

const fn decode_middle_state(state: usize) -> Option<(usize, MiddlePhase)> {
    if state == 0 {
        return None;
    }
    let Some(offset) = state.checked_sub(1) else {
        return None;
    };
    let chunk = offset / 3;
    let phase = match offset % 3 {
        0 => MiddlePhase::Leading,
        1 => MiddlePhase::Data,
        _ => MiddlePhase::Trailing,
    };
    Some((chunk, phase))
}

const fn completed_chunk(state: usize) -> Option<usize> {
    match decode_middle_state(state) {
        Some((chunk, MiddlePhase::Data | MiddlePhase::Trailing)) => Some(chunk),
        _ => None,
    }
}

fn middle_state_count(max_chunks: usize) -> Result<usize, Error> {
    add(
        mul(3, max_chunks, Resource::ExecutionWork)?,
        1,
        Resource::ExecutionWork,
    )
}

fn frontier_key(direction: usize, state: usize, has_candidate: bool) -> Result<usize, Error> {
    let direction_base = mul(direction, MAX_MIDDLE_STATES, Resource::ExecutionWork)?;
    let state_key = add(direction_base, state, Resource::ExecutionWork)?;
    add(
        mul(2, state_key, Resource::ExecutionWork)?,
        usize::from(has_candidate),
        Resource::ExecutionWork,
    )
}

const fn decode_frontier_key(key: usize) -> (usize, usize, bool) {
    let has_candidate = !key.is_multiple_of(2);
    let state_key = key / 2;
    (
        state_key / MAX_MIDDLE_STATES,
        state_key % MAX_MIDDLE_STATES,
        has_candidate,
    )
}

fn charge_class_check(accounting: &mut ExecutionAccounting) -> Result<(), Error> {
    accounting.transition_checks = add(accounting.transition_checks, 1, Resource::ExecutionWork)?;
    accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_frontier_insert(accounting: &mut ExecutionAccounting) -> Result<(), Error> {
    accounting.frontier_insertions =
        add(accounting.frontier_insertions, 1, Resource::ExecutionWork)?;
    accounting.frontier_bookkeeping =
        add(accounting.frontier_bookkeeping, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_frontier_evaluation(accounting: &mut ExecutionAccounting) -> Result<(), Error> {
    accounting.frontier_evaluations =
        add(accounting.frontier_evaluations, 1, Resource::ExecutionWork)?;
    accounting.work = add(accounting.work, 1, Resource::ExecutionWork)?;
    Ok(())
}

fn charge_frontier_bookkeeping(
    accounting: &mut ExecutionAccounting,
    amount: usize,
) -> Result<(), Error> {
    accounting.frontier_bookkeeping = add(
        accounting.frontier_bookkeeping,
        amount,
        Resource::ExecutionWork,
    )?;
    Ok(())
}

fn update_frontier_peak(accounting: &mut ExecutionAccounting, states: usize) {
    if states > accounting.frontier_peak_states {
        accounting.frontier_peak_states = states;
    }
}

const _: () = {
    assert!(MAX_ORDERED_BOUNDED_ANCHOR_BYTES <= 255);
    assert!(MAX_FRONTIER_SLOTS <= 65_535);
};

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::*;
    use crate::{CompileLimits, RustByteProfile};

    const PATTERN: &str =
        r"(?:red(?:[ _]*[a-z]+[ _]*){0,10}blue)|(?:blue(?:[ _]*[a-z]+[ _]*){0,10}red)";
    const OVERLAP_PATTERN: &str = r"first(?:\s*.+\s*){0,10}second|second(?:\s*.+\s*){0,10}first";

    fn compiled(pattern: &str) -> CompiledRegex {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn oracle(pattern: &str, haystack: &[u8]) -> usize {
        RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| matched.end().checked_sub(matched.start()).unwrap())
            .sum()
    }

    fn direct_event_and_frontier(
        compiled: &CompiledRegex,
        haystack: &[u8],
    ) -> ((usize, usize), (usize, usize), ExecutionAccounting, usize) {
        let plan = compiled
            .ordered_bounded_span_sum
            .as_ref()
            .expect("ordered bounded-span plan");
        let mut event_accounting = ExecutionAccounting::default();
        let mut event_allocations = 0_usize;
        let event = reduce_events(
            plan,
            haystack,
            &mut event_accounting,
            &mut event_allocations,
        )
        .unwrap();
        assert!(
            event_prospective(&compiled.program, plan, haystack.len())
                .unwrap()
                .contains(event_accounting)
        );

        let mut frontier_accounting = ExecutionAccounting::default();
        frontier_accounting.scratch_peak_bytes = core::mem::size_of::<ExecutorScratch>();
        frontier_accounting.peak_bytes = frontier_accounting.scratch_peak_bytes;
        let frontier = reduce_frontier(plan, haystack, &mut frontier_accounting).unwrap();
        assert!(
            frontier_prospective(&compiled.program, plan, haystack.len())
                .unwrap()
                .contains(frontier_accounting)
        );
        (event, frontier, event_accounting, event_allocations)
    }

    fn exact_limits(prospective: &OperationProspective) -> OperationLimits {
        OperationLimits {
            max_boundaries: prospective.boundaries,
            max_table_cells: prospective.table_cells,
            max_random_access_bytes: prospective.random_access_bytes,
            max_scratch_bytes: prospective.scratch_bytes,
            max_log_bytes: prospective.log_bytes,
            max_sequential_bytes: prospective.sequential_bytes,
            max_match_events: prospective.match_events,
            max_output_matches: prospective.output_matches,
            max_output_bytes: prospective.output_bytes,
            max_span_sum: prospective.span_sum,
            max_peak_bytes: prospective.peak_bytes,
            max_work: prospective.work_bound,
        }
    }

    fn assert_pre_source_refusal(
        compiled: &CompiledRegex,
        haystack: &[u8],
        limits: OperationLimits,
        resource: Resource,
    ) {
        let failure = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap_err();
        assert!(matches!(
            failure.source,
            Error::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
        assert_eq!(failure.receipt.actual_allocations, 0);
        assert_eq!(
            failure.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedBoundedSpanSum)
        );
        assert_eq!(
            failure.receipt.identity.prepublication_fallback,
            OperationPrepublicationFallback::OrderedBoundedEventsThenFrontier
        );
        assert!(failure.receipt.prospective.is_some());
        assert!(failure.closes());
    }

    #[test]
    fn ordered_bounded_span_sum_selects_last_reachable_terminal() {
        let compiled = compiled(PATTERN);
        let compile_accounting = compiled.compile_accounting();
        assert_eq!(
            (
                compile_accounting.ordered_bounded_span_sum_plans,
                compile_accounting.ordered_bounded_span_sum_anchor_bytes,
                compile_accounting.ordered_bounded_span_sum_max_chunks,
                compile_accounting.ordered_bounded_span_sum_persistent_bytes,
            ),
            (1, 7, 10, OrderedBoundedSpanSumPlan::retained_slot_bytes(),)
        );
        assert!(compile_accounting.ordered_bounded_span_sum_build_work > 0);
        let greedy_witness = b"red blue red blue";
        assert_eq!(
            compiled
                .span_sum_value(
                    greedy_witness,
                    0..greedy_witness.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
            greedy_witness.len()
        );
        let haystack = b"!red blue red blue! blue one red? red   a_b blue";
        let expected = oracle(PATTERN, haystack);
        let attempt = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(attempt.value, expected);
        assert_eq!(
            attempt.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedBoundedSpanSumEvents)
        );
        assert_eq!(
            attempt.receipt.identity.prepublication_fallback,
            OperationPrepublicationFallback::None
        );
        assert!(attempt.receipt.authenticates_success());
        assert_eq!(
            compiled
                .span_sum_value(
                    haystack,
                    0..haystack.len(),
                    Strategy::FullTable,
                    OperationLimits::default(),
                )
                .unwrap(),
            expected
        );
    }

    #[test]
    fn ordered_bounded_span_sum_preserves_overlapping_class_assignments() {
        let compiled = compiled(OVERLAP_PATTERN);
        assert_eq!(
            compiled.compile_accounting().ordered_bounded_span_sum_plans,
            1
        );
        let haystack = b"first second first\n\nsecond! second\nx\nfirst";
        assert_eq!(
            compiled
                .span_sum_value(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
            oracle(OVERLAP_PATTERN, haystack)
        );
    }

    #[test]
    fn ordered_bounded_span_sum_exhaustive_small_alphabet_matches_upstream() {
        let pattern = r"(?:a(?:_*[ab]+_*){0,2}b)|(?:b(?:_*[ab]+_*){0,2}a)";
        let compiled = compiled(pattern);
        assert_eq!(
            compiled.compile_accounting().ordered_bounded_span_sum_plans,
            1
        );
        let alphabet = [b'a', b'b', b'_', b'#'];
        let mut haystack = [0_u8; 7];
        for encoded in 0_u32..16_384 {
            let mut value = encoded;
            for byte in &mut haystack {
                *byte = alphabet[usize::try_from(value & 3).unwrap()];
                value >>= 2;
            }
            let expected = oracle(pattern, &haystack);
            let actual = compiled
                .span_sum_value(
                    &haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(actual, expected, "haystack={haystack:?}");
            let ranged_expected = oracle(pattern, &haystack[1..6]);
            let ranged_actual = compiled
                .span_sum_value(
                    &haystack,
                    1..6,
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(
                ranged_actual, ranged_expected,
                "ranged haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn ordered_bounded_span_sum_exhaustive_overlapping_classes_matches_upstream() {
        let pattern = r"(?:a(?:\s*.+\s*){0,2}b)|(?:b(?:\s*.+\s*){0,2}a)";
        let compiled = compiled(pattern);
        let alphabet = [b'a', b'b', b' ', b'\n'];
        let mut haystack = [0_u8; 7];
        for encoded in 0_u32..16_384 {
            let mut value = encoded;
            for byte in &mut haystack {
                *byte = alphabet[usize::try_from(value & 3).unwrap()];
                value >>= 2;
            }
            assert_eq!(
                compiled
                    .span_sum_value(
                        &haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                oracle(pattern, &haystack),
                "haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn ordered_bounded_span_sum_event_ranks_exhaust_all_byte_memberships() {
        // `_` is S-only, `a`/`b` are D-only, space is S∩D and `#` is outside
        // both classes. This independently exercises every algebraic category
        // used by the event rank theorem, including complete inputs containing
        // both retained anchors.
        let pattern = r"(?:a(?:[ _]*[ ab]+[ _]*){0,2}b)|(?:b(?:[ _]*[ ab]+[ _]*){0,2}a)";
        let compiled = compiled(pattern);
        assert_eq!(
            compiled.compile_accounting().ordered_bounded_span_sum_plans,
            1
        );
        let alphabet = [b'_', b'a', b'b', b' ', b'#'];
        let mut haystack = [0_u8; 6];
        for encoded in 0_u32..15_625 {
            let mut value = encoded;
            for byte in &mut haystack {
                *byte = alphabet[usize::try_from(value % 5).unwrap()];
                value /= 5;
            }
            let (event, frontier, _, _) = direct_event_and_frontier(&compiled, &haystack);
            assert_eq!(event, frontier, "haystack={haystack:?}");
            assert_eq!(event.1, oracle(pattern, &haystack), "haystack={haystack:?}");
        }
    }

    #[test]
    fn ordered_bounded_span_sum_economics_choose_zero_allocation_dense_frontier() {
        let pattern = r"(?:a(?:_*[ab]+_*){0,1}b)|(?:b(?:_*[ab]+_*){0,1}a)";
        let compiled = compiled(pattern);
        let plan = compiled
            .ordered_bounded_span_sum
            .as_ref()
            .expect("ordered bounded-span plan");
        let input_bytes = 1_048_576;
        let events = event_prospective(&compiled.program, plan, input_bytes).unwrap();
        let frontier = frontier_prospective(&compiled.program, plan, input_bytes).unwrap();
        assert!(events.work_bound > frontier.work_bound);
        assert_eq!(events.allocations, 2);
        assert_eq!(frontier.allocations, 0);

        let selection = select_executor(
            &compiled.program,
            plan,
            input_bytes,
            OperationLimits::default(),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(selection.executor, SelectedExecutor::Frontier);
        assert_eq!(selection.prospective, frontier);
        assert_eq!(
            selection.physical_route,
            OperationPhysicalRoute::OrderedBoundedSpanSum
        );
        assert_eq!(
            selection.prepublication_fallback,
            OperationPrepublicationFallback::OrderedBoundedEventsThenFrontier
        );
    }

    #[test]
    fn ordered_bounded_span_sum_economics_threshold_covers_overlap_and_intersection() {
        // The retained anchors `a` and `ab` overlap by prefix, while space is
        // in both S and D. At this exact source-independent boundary the event
        // upper changes from 2^20-1 to 2^20+1, adding one binary-search rank
        // step and making the fixed frontier the strict work winner.
        let pattern = r"(?:a(?:[ _]*[ ab]+[ _]*){0,1}ab)|(?:ab(?:[ _]*[ ab]+[ _]*){0,1}a)";
        let compiled = compiled(pattern);
        let plan = compiled
            .ordered_bounded_span_sum
            .as_ref()
            .expect("ordered bounded-span plan");
        let below = 524_288;
        let threshold = below + 1;
        let below_events = event_prospective(&compiled.program, plan, below).unwrap();
        let below_frontier = frontier_prospective(&compiled.program, plan, below).unwrap();
        let threshold_events = event_prospective(&compiled.program, plan, threshold).unwrap();
        let threshold_frontier = frontier_prospective(&compiled.program, plan, threshold).unwrap();
        assert_eq!(below_events.match_events, (1 << 20) - 1);
        assert_eq!(threshold_events.match_events, (1 << 20) + 1);
        assert!(below_events.work_bound < below_frontier.work_bound);
        assert!(threshold_events.work_bound > threshold_frontier.work_bound);
        assert_eq!(
            select_executor(
                &compiled.program,
                plan,
                below,
                OperationLimits::default(),
                usize::MAX,
            )
            .unwrap()
            .executor,
            SelectedExecutor::Events
        );
        let threshold_selection = select_executor(
            &compiled.program,
            plan,
            threshold,
            OperationLimits::default(),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(threshold_selection.executor, SelectedExecutor::Frontier);
        assert_eq!(threshold_selection.prospective.allocations, 0);

        let mut haystack = vec![b'#'; threshold];
        haystack[..4].copy_from_slice(b"a ab");
        let expected = oracle(pattern, &haystack);
        let fault = super::super::allocation_fault::arm(0);
        let attempt = compiled
            .span_sum_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(attempt.value, expected);
        assert_eq!(
            attempt.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedBoundedSpanSum)
        );
        assert_eq!(
            attempt.receipt.identity.prepublication_fallback,
            OperationPrepublicationFallback::OrderedBoundedEventsThenFrontier
        );
        assert_eq!(attempt.receipt.actual_allocations, 0);
        assert_eq!(super::super::allocation_fault::calls(), 0);
        assert!(attempt.receipt.authenticates_success());
        drop(fault);
    }

    #[test]
    fn ordered_bounded_span_sum_events_survive_frontier_prospective_overflow() {
        let compiled = compiled(PATTERN);
        let plan = compiled
            .ordered_bounded_span_sum
            .as_ref()
            .expect("ordered bounded-span plan");
        let input_bytes = usize::MAX / 512;
        let events = event_prospective(&compiled.program, plan, input_bytes).unwrap();
        assert!(matches!(
            frontier_prospective(&compiled.program, plan, input_bytes),
            Err(Error::ArithmeticOverflow { .. })
        ));
        let selection = select_executor(
            &compiled.program,
            plan,
            input_bytes,
            super::super::intrinsic_attempt_limits(),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(selection.executor, SelectedExecutor::Events);
        assert_eq!(selection.prospective, events);
        assert_eq!(
            selection.physical_route,
            OperationPhysicalRoute::OrderedBoundedSpanSumEvents
        );
        assert_eq!(
            selection.prepublication_fallback,
            OperationPrepublicationFallback::None
        );
    }

    #[test]
    fn ordered_bounded_span_sum_allocation_faults_close_exact_partial_ledgers() {
        let compiled = compiled(PATTERN);
        let haystack = b"red one blue; blue two red";
        let plan = compiled
            .ordered_bounded_span_sum
            .as_ref()
            .expect("ordered bounded-span plan");
        let prospective = event_prospective(&compiled.program, plan, haystack.len()).unwrap();
        assert_eq!(
            select_executor(
                &compiled.program,
                plan,
                haystack.len(),
                OperationLimits::default(),
                usize::MAX,
            )
            .unwrap()
            .executor,
            SelectedExecutor::Events
        );

        let mut census = ExecutionAccounting {
            scratch_peak_bytes: core::mem::size_of::<AnchorEvents>(),
            peak_bytes: core::mem::size_of::<AnchorEvents>(),
            ..ExecutionAccounting::default()
        };
        let mut first_count = 0_usize;
        let mut second_count = 0_usize;
        scan_anchor_candidates(plan, haystack, &mut census, |direction, _, _| {
            if direction == 0 {
                first_count += 1;
            } else {
                second_count += 1;
            }
            Ok(())
        })
        .unwrap();
        assert_ne!(first_count, 0);
        assert_ne!(second_count, 0);
        let first_bytes = first_count * core::mem::size_of::<AnchorOccurrence>();
        let second_bytes = second_count * core::mem::size_of::<AnchorOccurrence>();

        for (ordinal, failed_items, committed_bytes) in
            [(0, first_bytes, 0), (1, second_bytes, first_bytes)]
        {
            let fault = super::super::allocation_fault::arm(ordinal);
            let failure = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap_err();
            assert_eq!(
                failure.source,
                Error::AllocationFailed {
                    resource: Resource::ScratchBytes,
                    items: failed_items,
                }
            );
            assert_eq!(failure.receipt.prospective, Some(prospective));
            assert_eq!(
                failure.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::OrderedBoundedSpanSumEvents)
            );
            assert_eq!(
                failure.receipt.identity.prepublication_fallback,
                OperationPrepublicationFallback::None
            );
            let mut expected = census;
            expected.scratch_peak_bytes += committed_bytes;
            expected.peak_bytes = expected.scratch_peak_bytes;
            assert_eq!(failure.receipt.actual, expected);
            assert_eq!(failure.receipt.actual_allocations, ordinal);
            assert!(prospective.contains(failure.receipt.actual));
            assert_eq!(super::super::allocation_fault::calls(), ordinal + 1);
            assert!(failure.closes());
            drop(fault);
        }
    }

    #[test]
    fn ordered_bounded_span_sum_chunk_boundary_and_priority_cases() {
        let pattern = r"(?:a(?:_*[ab]+_*){0,1}ab)|(?:ab(?:_*[ab]+_*){0,1}a)";
        let compiled = compiled(pattern);
        for haystack in [
            b"aab".as_slice(),
            b"ababa",
            b"!a_ba_ab?",
            b"ab_b_a a_ab",
            b"a__a__ab",
            b"abababab",
        ] {
            assert_eq!(
                compiled
                    .span_sum_value(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                oracle(pattern, haystack),
                "haystack={haystack:?}"
            );
        }
    }

    #[test]
    fn ordered_bounded_span_sum_long_priority_adversaries_match_upstream() {
        let patterns = [
            r"(?:a(?:\s*.+\s*){0,3}ab)|(?:ab(?:\s*.+\s*){0,3}a)",
            r"(?:left(?:\s*.+\s*){0,10}right)|(?:right(?:\s*.+\s*){0,10}left)",
        ];
        let alphabet = b"a b\nleftrighx";
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        let mut haystack = Vec::with_capacity(4_096);
        for _ in 0..4_096 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let index = usize::try_from(state % u64::try_from(alphabet.len()).unwrap()).unwrap();
            haystack.push(alphabet[index]);
        }
        for pattern in patterns {
            let compiled = compiled(pattern);
            assert_eq!(
                compiled
                    .span_sum_value(
                        &haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                oracle(pattern, &haystack),
                "pattern={pattern:?}"
            );
        }
    }

    #[test]
    fn ordered_bounded_span_sum_accepts_exact_shape_ceilings() {
        let first = "a".repeat(MAX_ORDERED_BOUNDED_ANCHOR_BYTES);
        let second = "b".repeat(MAX_ORDERED_BOUNDED_ANCHOR_BYTES);
        let pattern = format!(
            r"(?:{first}(?:[ab]*[ab]+[ab]*){{0,{MAX_ORDERED_BOUNDED_CHUNKS}}}{second})|(?:{second}(?:[ab]*[ab]+[ab]*){{0,{MAX_ORDERED_BOUNDED_CHUNKS}}}{first})"
        );
        let accepted = compiled(&pattern);
        let compile_accounting = accepted.compile_accounting();
        assert_eq!(compile_accounting.ordered_bounded_span_sum_plans, 1);
        assert_eq!(
            compile_accounting.ordered_bounded_span_sum_anchor_bytes,
            MAX_ORDERED_BOUNDED_ANCHOR_BYTES.checked_mul(2).unwrap()
        );
        assert_eq!(
            compile_accounting.ordered_bounded_span_sum_max_chunks,
            MAX_ORDERED_BOUNDED_CHUNKS
        );

        let mut haystack = first.as_bytes().to_vec();
        haystack.extend_from_slice(
            "ab".repeat(MAX_ORDERED_BOUNDED_CHUNKS.checked_mul(4).unwrap())
                .as_bytes(),
        );
        haystack.extend_from_slice(second.as_bytes());
        let attempt = accepted
            .span_sum_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(attempt.value, oracle(&pattern, &haystack));
        assert_eq!(
            attempt.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedBoundedSpanSumEvents)
        );
        assert_eq!(attempt.receipt.actual.frontier_peak_states, 0);
        assert!(attempt.receipt.actual_allocations <= 2);
        assert!(attempt.receipt.authenticates_success());

        let overlong = "a".repeat(MAX_ORDERED_BOUNDED_ANCHOR_BYTES.checked_add(1).unwrap());
        let rejected =
            format!(r"(?:{overlong}(?:_*[ab]+_*){{0,2}}b)|(?:b(?:_*[ab]+_*){{0,2}}{overlong})");
        let rejected_compiled = compiled(&rejected);
        assert_eq!(
            rejected_compiled
                .compile_accounting()
                .ordered_bounded_span_sum_plans,
            0
        );
        let rejected_haystack = format!("{overlong}_b b_{overlong}");
        let fallback = rejected_compiled
            .span_sum_value_with_receipt(
                rejected_haystack.as_bytes(),
                0..rejected_haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(
            fallback.value,
            oracle(&rejected, rejected_haystack.as_bytes())
        );
        assert_ne!(
            fallback.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedBoundedSpanSum)
        );
        assert_ne!(
            fallback.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedBoundedSpanSumEvents)
        );
        assert!(fallback.receipt.authenticates_success());
    }

    #[test]
    fn ordered_bounded_span_sum_refuses_unproved_shapes_into_continuation() {
        let haystack = b"x a_b b_a aab bab abc x";
        for pattern in [
            r"(?:(?:a(?:_*[ab]+_*){0,2}b)|(?:b(?:_*[ab]+_*){0,2}a))x",
            r"(?:a(?:_*[ab]+-*){0,2}b)|(?:b(?:_*[ab]+-*){0,2}a)",
            r"(?:a(?:_*[ab]+_*){0,2}?b)|(?:b(?:_*[ab]+_*){0,2}?a)",
            r"(?:a(?:_*[ab]+_*){1,2}b)|(?:b(?:_*[ab]+_*){1,2}a)",
            r"(?:a(?:_*[ab]+_*)*b)|(?:b(?:_*[ab]+_*)*a)",
            r"(?:a(?:_*[ab]+_*){0,33}b)|(?:b(?:_*[ab]+_*){0,33}a)",
            r"(?:x(?:_*[ab]+_*){0,2}b)|(?:b(?:_*[ab]+_*){0,2}x)",
            r"(?:a(?:_*[ab]+_*){0,2}b)|(?:b(?:_*[ab]+_*){0,3}a)",
            r"(?:a(?:_*[ab]+_*){0,2}b)|(?:b(?:_*[ac]+_*){0,2}a)",
            r"(?:a(?:_*[ab]+_*){0,2}b)|(?:b(?:_*[ab]+_*){0,2}c)",
        ] {
            let compiled = compiled(pattern);
            assert_eq!(
                compiled.compile_accounting().ordered_bounded_span_sum_plans,
                0,
                "pattern={pattern:?}"
            );
            let attempt = compiled
                .span_sum_value_with_receipt(
                    haystack,
                    0..haystack.len(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(attempt.value, oracle(pattern, haystack));
            assert_ne!(
                attempt.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::OrderedBoundedSpanSum),
                "pattern={pattern:?}"
            );
            assert_ne!(
                attempt.receipt.identity.physical_route,
                Some(OperationPhysicalRoute::OrderedBoundedSpanSumEvents),
                "pattern={pattern:?}"
            );
            assert!(attempt.receipt.authenticates_success());
        }
    }

    #[test]
    fn ordered_bounded_span_sum_exact_and_one_below_operation_limits() {
        let compiled = compiled(PATTERN);
        let haystack = b"red one blue; blue two red; red blue".repeat(32);
        let plan = compiled
            .ordered_bounded_span_sum
            .as_ref()
            .expect("ordered bounded-span plan");
        assert_eq!(
            event_prospective(&compiled.program, plan, 0)
                .unwrap()
                .allocations,
            0
        );
        assert_eq!(
            event_prospective(&compiled.program, plan, 3)
                .unwrap()
                .allocations,
            1
        );
        assert_eq!(
            event_prospective(&compiled.program, plan, 4)
                .unwrap()
                .allocations,
            2
        );
        let event_upper = event_prospective(&compiled.program, plan, haystack.len()).unwrap();
        let frontier_upper = frontier_prospective(&compiled.program, plan, haystack.len()).unwrap();
        let baseline = compiled
            .span_sum_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let prospective = baseline.receipt.prospective.unwrap();
        assert_eq!(prospective, event_upper);
        assert_eq!(
            baseline.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedBoundedSpanSumEvents)
        );
        let event_count = haystack
            .windows(3)
            .filter(|window| *window == b"red")
            .count()
            + haystack
                .windows(4)
                .filter(|window| *window == b"blue")
                .count();
        let actual_event_bytes = event_count
            .checked_mul(core::mem::size_of::<AnchorOccurrence>())
            .unwrap();
        assert_eq!(baseline.receipt.actual_allocations, 2);
        assert_eq!(
            baseline.receipt.actual.scratch_peak_bytes,
            core::mem::size_of::<AnchorEvents>() + actual_event_bytes
        );
        assert_eq!(
            baseline.receipt.actual.sequential_bytes_read,
            haystack.len() * 4
        );
        assert_eq!(baseline.receipt.actual.state_evaluations, event_count);
        assert_eq!(baseline.receipt.actual.frontier_insertions, event_count * 2);
        assert_eq!(
            baseline.receipt.actual.frontier_bookkeeping,
            event_count * 5
        );
        let exact = exact_limits(&prospective);
        let exact_attempt = compiled
            .span_sum_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
            )
            .unwrap();
        assert_eq!(exact_attempt.value, oracle(PATTERN, &haystack));
        assert!(exact_attempt.receipt.authenticates_success());

        let fallback_limits = OperationLimits {
            max_sequential_bytes: event_upper.sequential_bytes - 1,
            ..OperationLimits::default()
        };
        let fallback = compiled
            .span_sum_value_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                fallback_limits,
            )
            .unwrap();
        assert_eq!(fallback.value, oracle(PATTERN, &haystack));
        assert_eq!(
            fallback.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::OrderedBoundedSpanSum)
        );
        assert_eq!(
            fallback.receipt.identity.prepublication_fallback,
            OperationPrepublicationFallback::OrderedBoundedEventsThenFrontier
        );
        assert_eq!(fallback.receipt.prospective, Some(frontier_upper));
        assert_eq!(fallback.receipt.actual_allocations, 0);
        assert!(fallback.receipt.authenticates_success());

        let allocation_fallback = select_executor(
            &compiled.program,
            plan,
            haystack.len(),
            OperationLimits::default(),
            1,
        )
        .unwrap();
        assert_eq!(allocation_fallback.executor, SelectedExecutor::Frontier);
        assert_eq!(allocation_fallback.prospective, frontier_upper);

        let cases = [
            (
                Resource::Boundaries,
                OperationLimits {
                    max_boundaries: event_upper.boundaries.min(frontier_upper.boundaries) - 1,
                    ..OperationLimits::default()
                },
            ),
            (
                Resource::ScratchBytes,
                OperationLimits {
                    max_scratch_bytes: event_upper.scratch_bytes.min(frontier_upper.scratch_bytes)
                        - 1,
                    ..OperationLimits::default()
                },
            ),
            (
                Resource::SequentialBytes,
                OperationLimits {
                    max_sequential_bytes: event_upper
                        .sequential_bytes
                        .min(frontier_upper.sequential_bytes)
                        - 1,
                    ..OperationLimits::default()
                },
            ),
            (
                Resource::MatchEvents,
                OperationLimits {
                    max_match_events: event_upper.match_events.min(frontier_upper.match_events) - 1,
                    ..OperationLimits::default()
                },
            ),
            (
                Resource::OutputMatches,
                OperationLimits {
                    max_output_matches: event_upper
                        .output_matches
                        .min(frontier_upper.output_matches)
                        - 1,
                    ..OperationLimits::default()
                },
            ),
            (
                Resource::SpanSum,
                OperationLimits {
                    max_span_sum: event_upper.span_sum.min(frontier_upper.span_sum) - 1,
                    ..OperationLimits::default()
                },
            ),
            (
                Resource::PeakBytes,
                OperationLimits {
                    max_peak_bytes: event_upper.peak_bytes.min(frontier_upper.peak_bytes) - 1,
                    ..OperationLimits::default()
                },
            ),
            (
                Resource::ExecutionWork,
                OperationLimits {
                    max_work: event_upper.work_bound.min(frontier_upper.work_bound) - 1,
                    ..OperationLimits::default()
                },
            ),
        ];
        for (resource, limits) in cases {
            assert_pre_source_refusal(&compiled, &haystack, limits, resource);
        }
    }

    #[test]
    fn ordered_bounded_span_sum_exact_and_one_below_compile_limits() {
        let baseline = compiled(PATTERN).compile_accounting();
        let exact = CompileLimits {
            max_program_bytes: baseline.program_bytes,
            max_work: baseline.work,
            ..CompileLimits::default()
        };
        let compile_with = |limits| {
            let hir = ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(PATTERN)
                .unwrap();
            CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                limits,
            )
        };
        compile_with(exact).unwrap();
        assert!(matches!(
            compile_with(CompileLimits {
                max_program_bytes: baseline.program_bytes - 1,
                ..exact
            }),
            Err(Error::ResourceLimit {
                resource: Resource::ProgramBytes,
                ..
            })
        ));
        assert!(matches!(
            compile_with(CompileLimits {
                max_work: baseline.work - 1,
                ..exact
            }),
            Err(Error::ResourceLimit {
                resource: Resource::CompileWork,
                ..
            })
        ));
    }
}
