use core::ops::Range;

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
    operation_limits_identity,
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
        let prospective = prospective(&self.program, plan, local.len())?;
        if let Some(publication) = effects.attempt {
            let physical_route = OperationPhysicalRoute::OrderedBoundedSpanSum;
            publication.identity.physical_route = Some(physical_route);
            publication.identity.prepublication_fallback = OperationPrepublicationFallback::None;
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
        effects.accounting.scratch_peak_bytes = core::mem::size_of::<ExecutorScratch>();
        effects.accounting.peak_bytes = effects.accounting.scratch_peak_bytes;
        let (matches, span_sum) = reduce(plan, local, effects.accounting)?;
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
            physical_route: OperationPhysicalRoute::OrderedBoundedSpanSum,
            algorithm_version: CONTINUATION_OPERATION_ALGORITHM_VERSION,
            accounting_version: CONTINUATION_OPERATION_ACCOUNTING_VERSION,
            prepublication_fallback: OperationPrepublicationFallback::None,
            prospective_allocations: 0,
            actual_allocations: 0,
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

fn prospective(
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

fn reduce(
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
            Some(OperationPhysicalRoute::OrderedBoundedSpanSum)
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
            Some(OperationPhysicalRoute::OrderedBoundedSpanSum)
        );
        assert!(
            attempt.receipt.actual.frontier_peak_states
                >= middle_state_count(MAX_ORDERED_BOUNDED_CHUNKS).unwrap()
        );
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
            assert!(attempt.receipt.authenticates_success());
        }
    }

    #[test]
    fn ordered_bounded_span_sum_exact_and_one_below_operation_limits() {
        let compiled = compiled(PATTERN);
        let haystack = b"red one blue; blue two red; red blue";
        let baseline = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let prospective = baseline.receipt.prospective.unwrap();
        let exact = exact_limits(&prospective);
        let exact_attempt = compiled
            .span_sum_value_with_receipt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                exact,
            )
            .unwrap();
        assert_eq!(exact_attempt.value, oracle(PATTERN, haystack));
        assert!(exact_attempt.receipt.authenticates_success());

        let cases = [
            (
                Resource::Boundaries,
                OperationLimits {
                    max_boundaries: prospective.boundaries - 1,
                    ..exact
                },
            ),
            (
                Resource::ScratchBytes,
                OperationLimits {
                    max_scratch_bytes: prospective.scratch_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::SequentialBytes,
                OperationLimits {
                    max_sequential_bytes: prospective.sequential_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::MatchEvents,
                OperationLimits {
                    max_match_events: prospective.match_events - 1,
                    ..exact
                },
            ),
            (
                Resource::OutputMatches,
                OperationLimits {
                    max_output_matches: prospective.output_matches - 1,
                    ..exact
                },
            ),
            (
                Resource::SpanSum,
                OperationLimits {
                    max_span_sum: prospective.span_sum - 1,
                    ..exact
                },
            ),
            (
                Resource::PeakBytes,
                OperationLimits {
                    max_peak_bytes: prospective.peak_bytes - 1,
                    ..exact
                },
            ),
            (
                Resource::ExecutionWork,
                OperationLimits {
                    max_work: prospective.work_bound - 1,
                    ..exact
                },
            ),
        ];
        for (resource, limits) in cases {
            assert_pre_source_refusal(&compiled, haystack, limits, resource);
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
