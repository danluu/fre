//! Inline capture-vector candidate executor.

use std::sync::Arc;

use crate::ast::Ast;
use crate::compile::{Program, State};
use crate::error::{BuildError, ResourceKind, SearchError};
use crate::limits::{AggregateLimits, BuildLimits, SearchLimits};
use crate::model::{
    AggregateOutcome, CandidateKind, RunReport, SearchConfig, SearchKind, SearchOutcome, Window,
};
use crate::runtime::{
    admit_inline, assertion_matches, canonicalize, check, checked_add, validate_window,
};

#[derive(Clone, Debug)]
struct Thread {
    pc: usize,
    slots: Vec<Option<usize>>,
}

#[derive(Debug)]
struct Counters {
    state_visits: usize,
    slot_copies: usize,
    starts_injected: usize,
    bytes_examined: usize,
    peak_threads: usize,
}

/// Exact Pike-style executor with capture slots copied inline with threads.
#[derive(Clone, Debug)]
pub struct InlineRegex {
    program: Arc<Program>,
}

impl InlineRegex {
    /// Compile and wrap a laboratory AST.
    pub fn compile(ast: &Ast, limits: BuildLimits) -> Result<Self, BuildError> {
        Ok(Self {
            program: Arc::new(Program::compile(ast, limits)?),
        })
    }

    /// Wrap an already compiled immutable program.
    #[must_use]
    pub fn from_program(program: Arc<Program>) -> Self {
        Self { program }
    }

    /// Access the shared immutable program.
    #[must_use]
    pub fn program(&self) -> &Arc<Program> {
        &self.program
    }

    /// Find the first leftmost-first match and its captures in `window`.
    pub fn captures(
        &self,
        haystack: &[u8],
        window: Window,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        self.captures_with_config(haystack, window, SearchConfig::LEFTMOST, limits)
    }

    /// Find the first capture record under an explicit selection and
    /// anchoring policy.
    pub fn captures_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        config: SearchConfig,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        self.search_from(haystack, window, window.start, config, limits)
    }

    /// Bounded repeated-search iterator with Rust byte-regex empty suppression.
    ///
    /// This is deliberately a quadratic-capable correctness formulation. Its
    /// limits and accounting are separate from one-search limits.
    pub fn captures_iter(
        &self,
        haystack: &[u8],
        window: Window,
        limits: AggregateLimits,
    ) -> Result<AggregateOutcome, SearchError> {
        self.captures_iter_with_config(haystack, window, SearchConfig::LEFTMOST, limits)
    }

    /// Bounded repeated search under an explicit selection and anchoring
    /// policy, with Rust byte-regex empty-match progression.
    pub fn captures_iter_with_config(
        &self,
        haystack: &[u8],
        window: Window,
        config: SearchConfig,
        limits: AggregateLimits,
    ) -> Result<AggregateOutcome, SearchError> {
        validate_window(haystack, window, window.start)?;
        let mut records = Vec::new();
        let mut searches = 0_usize;
        let mut total_state_visits = 0_usize;
        let mut total_slot_copies = 0_usize;
        let mut cursor = window.start;
        let mut last_match_end = None;
        loop {
            let next_searches = checked_add(searches, 1, ResourceKind::Searches)?;
            check(ResourceKind::Searches, next_searches, limits.max_searches)?;
            searches = next_searches;

            let mut per_search = limits.per_search;
            let state_remaining = limits
                .max_total_state_visits
                .checked_sub(total_state_visits)
                .ok_or(SearchError::BoundOverflow(
                    ResourceKind::AggregateStateVisits,
                ))?;
            per_search.max_state_visits = per_search.max_state_visits.min(state_remaining);
            let copy_remaining = limits
                .max_total_slot_copies
                .checked_sub(total_slot_copies)
                .ok_or(SearchError::BoundOverflow(
                    ResourceKind::AggregateSlotCopies,
                ))?;
            per_search.max_slot_copies = per_search.max_slot_copies.min(copy_remaining);

            let outcome = self.search_from(haystack, window, cursor, config, per_search)?;
            total_state_visits = checked_add(
                total_state_visits,
                outcome.report.state_visits,
                ResourceKind::AggregateStateVisits,
            )?;
            total_slot_copies = checked_add(
                total_slot_copies,
                outcome.report.slot_copies,
                ResourceKind::AggregateSlotCopies,
            )?;
            let Some(record) = outcome.captures else {
                break;
            };
            let overall = record.overall().ok_or(SearchError::InvalidProgram)?;
            if overall.start == overall.end && last_match_end == Some(overall.start) {
                if overall.end == window.end {
                    break;
                }
                cursor = overall
                    .end
                    .checked_add(1)
                    .ok_or(SearchError::BoundOverflow(ResourceKind::Searches))?;
                continue;
            }
            let next_results = checked_add(records.len(), 1, ResourceKind::Results)?;
            check(ResourceKind::Results, next_results, limits.max_results)?;
            records
                .try_reserve(1)
                .map_err(|_| SearchError::Allocation(ResourceKind::Results))?;
            records.push(record);
            last_match_end = Some(overall.end);
            if overall.start == overall.end {
                if overall.end == window.end {
                    break;
                }
                cursor = overall
                    .end
                    .checked_add(1)
                    .ok_or(SearchError::BoundOverflow(ResourceKind::Searches))?;
            } else {
                cursor = overall.end;
            }
        }
        Ok(AggregateOutcome {
            captures: records,
            searches,
            total_state_visits,
            total_slot_copies,
            total_history_nodes: 0,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the complete generation transition is kept locally auditable"
    )]
    fn search_from(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        config: SearchConfig,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        validate_window(haystack, window, from)?;
        let admission = admit_inline(&self.program, window, from, limits)?;
        let state_count = self.program.states.len();
        let mut current = reserve_threads(state_count)?;
        let mut next = reserve_threads(state_count)?;
        let mut stack = reserve_threads(state_count)?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(state_count)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        seen.resize(state_count, 0_usize);
        let mut generation = 1_usize;
        let mut counters = Counters {
            state_visits: 0,
            slot_copies: 0,
            starts_injected: 0,
            bytes_examined: 0,
            peak_threads: 0,
        };
        let mut winner: Option<Vec<Option<usize>>> = None;
        let mut pos = from;

        loop {
            if winner.is_none() && (!config.anchored || pos == from) {
                let slots = blank_slots(self.program.slot_count, &mut counters, limits)?;
                counters.starts_injected =
                    checked_add(counters.starts_injected, 1, ResourceKind::StateVisits)?;
                add_thread(
                    &self.program,
                    &mut current,
                    &mut stack,
                    &mut seen,
                    generation,
                    Thread {
                        pc: self.program.start,
                        slots,
                    },
                    pos,
                    haystack,
                    window,
                    &mut counters,
                    limits,
                )?;
            }

            if let Some(index) = current
                .iter()
                .position(|thread| matches!(self.program.states[thread.pc], State::Match))
            {
                winner = Some(copy_slots(&current[index].slots, &mut counters, limits)?);
                if config.kind == SearchKind::Earliest {
                    current.clear();
                } else {
                    current.truncate(index);
                }
            }
            counters.peak_threads = counters.peak_threads.max(current.len());
            if winner.is_some() && current.is_empty() {
                break;
            }
            if pos == window.end {
                break;
            }

            next.clear();
            generation = generation
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
            let next_pos = pos
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
            let byte = *haystack.get(pos).ok_or(SearchError::InvalidWindow)?;
            for thread in current.drain(..) {
                let State::Byte {
                    ranges,
                    next: target,
                } = self
                    .program
                    .states
                    .get(thread.pc)
                    .ok_or(SearchError::InvalidProgram)?
                else {
                    return Err(SearchError::InvalidProgram);
                };
                if ranges
                    .iter()
                    .any(|&(start, end)| start <= byte && byte <= end)
                {
                    add_thread(
                        &self.program,
                        &mut next,
                        &mut stack,
                        &mut seen,
                        generation,
                        Thread {
                            pc: *target,
                            slots: thread.slots,
                        },
                        next_pos,
                        haystack,
                        window,
                        &mut counters,
                        limits,
                    )?;
                }
            }
            counters.bytes_examined =
                checked_add(counters.bytes_examined, 1, ResourceKind::StateVisits)?;
            std::mem::swap(&mut current, &mut next);
            pos = next_pos;
        }

        let captures = winner
            .as_deref()
            .map(|slots| canonicalize(&self.program, slots))
            .transpose()?;
        Ok(SearchOutcome {
            captures,
            report: RunReport {
                candidate: CandidateKind::InlineSlots,
                state_visits: counters.state_visits,
                slot_copies: counters.slot_copies,
                history_nodes: 0,
                history_walk: 0,
                starts_injected: counters.starts_injected,
                bytes_examined: counters.bytes_examined,
                peak_threads: counters.peak_threads,
                admitted_scratch_bytes: admission.scratch_bytes,
            },
        })
    }
}

fn reserve_threads(capacity: usize) -> Result<Vec<Thread>, SearchError> {
    let mut threads = Vec::new();
    threads
        .try_reserve_exact(capacity)
        .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
    Ok(threads)
}

fn blank_slots(
    count: usize,
    counters: &mut Counters,
    limits: SearchLimits,
) -> Result<Vec<Option<usize>>, SearchError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(count)
        .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
    slots.resize(count, None);
    add_slot_copies(counters, count, limits)?;
    Ok(slots)
}

fn copy_slots(
    source: &[Option<usize>],
    counters: &mut Counters,
    limits: SearchLimits,
) -> Result<Vec<Option<usize>>, SearchError> {
    add_slot_copies(counters, source.len(), limits)?;
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len())
        .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
    copy.extend_from_slice(source);
    Ok(copy)
}

fn add_slot_copies(
    counters: &mut Counters,
    count: usize,
    limits: SearchLimits,
) -> Result<(), SearchError> {
    counters.slot_copies = checked_add(counters.slot_copies, count, ResourceKind::SlotCopies)?;
    check(
        ResourceKind::SlotCopies,
        counters.slot_copies,
        limits.max_slot_copies,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "closure resources are explicit laboratory inputs"
)]
fn add_thread(
    program: &Program,
    output: &mut Vec<Thread>,
    stack: &mut Vec<Thread>,
    seen: &mut [usize],
    generation: usize,
    initial: Thread,
    pos: usize,
    haystack: &[u8],
    window: Window,
    counters: &mut Counters,
    limits: SearchLimits,
) -> Result<(), SearchError> {
    stack.clear();
    stack.push(initial);
    while let Some(mut thread) = stack.pop() {
        counters.state_visits = checked_add(counters.state_visits, 1, ResourceKind::StateVisits)?;
        check(
            ResourceKind::StateVisits,
            counters.state_visits,
            limits.max_state_visits,
        )?;
        let mark = seen.get_mut(thread.pc).ok_or(SearchError::InvalidProgram)?;
        if *mark == generation {
            continue;
        }
        *mark = generation;
        match program
            .states
            .get(thread.pc)
            .ok_or(SearchError::InvalidProgram)?
        {
            State::Byte { .. } | State::Match => output.push(thread),
            State::Fail => {}
            State::Epsilon { next } => {
                thread.pc = *next;
                stack.push(thread);
            }
            State::Assert { assertion, next } => {
                if assertion_matches(*assertion, haystack, window, pos)? {
                    thread.pc = *next;
                    stack.push(thread);
                }
            }
            State::Save { slot, next } => {
                let saved = thread
                    .slots
                    .get_mut(*slot)
                    .ok_or(SearchError::InvalidProgram)?;
                *saved = Some(pos);
                thread.pc = *next;
                stack.push(thread);
            }
            State::Split { first, second } => {
                let second_slots = copy_slots(&thread.slots, counters, limits)?;
                stack.push(Thread {
                    pc: *second,
                    slots: second_slots,
                });
                thread.pc = *first;
                stack.push(thread);
            }
        }
    }
    counters.peak_threads = counters.peak_threads.max(output.len());
    Ok(())
}
