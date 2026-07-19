//! Persistent capture-history candidate executor.

use std::sync::Arc;

use crate::ast::Ast;
use crate::compile::{Program, State};
use crate::error::{BuildError, ResourceKind, SearchError};
use crate::limits::{AggregateLimits, BuildLimits, SearchLimits};
use crate::model::{
    AggregateOutcome, CandidateKind, CaptureCountOutcome, MatchKind, RunReport, SearchConfig,
    SearchKind, SearchOutcome, Span, Window,
};
use crate::runtime::HISTORY_CHUNK_CAPACITY;
use crate::runtime::{
    admit_history, admit_history_exact, assertion_matches, canonicalize, check, checked_add,
    validate_window,
};

#[derive(Clone, Copy, Debug)]
struct Thread {
    pc: usize,
    history: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct HistoryNode {
    slot: usize,
    offset: usize,
    previous: Option<usize>,
}

#[derive(Debug)]
struct HistoryArena {
    chunks: Vec<Vec<HistoryNode>>,
    len: usize,
    limit: usize,
}

impl HistoryArena {
    fn new(limit: usize) -> Result<Self, SearchError> {
        let chunk_count = limit
            .checked_add(HISTORY_CHUNK_CAPACITY.saturating_sub(1))
            .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?
            .checked_div(HISTORY_CHUNK_CAPACITY)
            .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?;
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(chunk_count)
            .map_err(|_| SearchError::Allocation(ResourceKind::HistoryNodes))?;
        Ok(Self {
            chunks,
            len: 0,
            limit,
        })
    }

    fn push(&mut self, node: HistoryNode) -> Result<usize, SearchError> {
        let required = checked_add(self.len, 1, ResourceKind::HistoryNodes)?;
        check(ResourceKind::HistoryNodes, required, self.limit)?;
        if self.len.is_multiple_of(HISTORY_CHUNK_CAPACITY) {
            let remaining = self
                .limit
                .checked_sub(self.len)
                .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?;
            let capacity = remaining.min(HISTORY_CHUNK_CAPACITY);
            let mut chunk = Vec::new();
            chunk
                .try_reserve_exact(capacity)
                .map_err(|_| SearchError::Allocation(ResourceKind::HistoryNodes))?;
            self.chunks.push(chunk);
        }
        let id = self.len;
        let chunk = self.chunks.last_mut().ok_or(SearchError::InvalidProgram)?;
        chunk.push(node);
        self.len = required;
        Ok(id)
    }

    fn get(&self, id: usize) -> Option<&HistoryNode> {
        if id >= self.len {
            return None;
        }
        let chunk = id / HISTORY_CHUNK_CAPACITY;
        let offset = id % HISTORY_CHUNK_CAPACITY;
        self.chunks.get(chunk)?.get(offset)
    }

    const fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug)]
struct Counters {
    state_visits: usize,
    history_walk: usize,
    starts_injected: usize,
    bytes_examined: usize,
    peak_threads: usize,
}

/// Exact Pike-style executor with persistent tagged histories.
#[derive(Clone, Debug)]
pub struct HistoryRegex {
    program: Arc<Program>,
}

impl HistoryRegex {
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

    /// Query one exact span while preserving assertion context from the
    /// original logical window.
    ///
    /// The start thread is injected exactly once. Match states before
    /// `span.end` are ignored, and the first prioritized match at `span.end`
    /// supplies captures. A span outside the pattern's language returns a
    /// successful outcome with no captures. Callers that already certified a
    /// span can therefore use the same operation for tagged replay, while
    /// correctness-oriented callers may enumerate exact spans without
    /// confusing an ordinary non-match with an invalid program.
    #[allow(
        clippy::too_many_lines,
        reason = "the exact-span tagged replay keeps its one-pass state transition auditable"
    )]
    pub fn captures_exact(
        &self,
        haystack: &[u8],
        window: Window,
        span: Span,
        limits: SearchLimits,
    ) -> Result<SearchOutcome, SearchError> {
        validate_window(haystack, window, span.start)?;
        if span.start > span.end || span.start < window.start || span.end > window.end {
            return Err(SearchError::InvalidWindow);
        }
        let admission = admit_history_exact(&self.program, span, limits)?;
        let state_count = self.program.states.len();
        let mut current = reserve_threads(state_count)?;
        let mut next = reserve_threads(state_count)?;
        let mut stack = reserve_threads(state_count)?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(state_count)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        seen.resize(state_count, 0_usize);
        let mut histories = HistoryArena::new(admission.history_node_bound)?;
        let mut generation = 1_usize;
        let mut counters = Counters {
            state_visits: 0,
            history_walk: 0,
            starts_injected: 1,
            bytes_examined: 0,
            peak_threads: 0,
        };
        let mut pos = span.start;
        add_thread(
            &self.program,
            &mut current,
            &mut stack,
            &mut seen,
            &mut histories,
            generation,
            Thread {
                pc: self.program.start,
                history: None,
            },
            pos,
            haystack,
            window,
            &mut counters,
            limits,
        )?;

        while pos < span.end {
            current
                .retain(|thread| !matches!(self.program.states.get(thread.pc), Some(State::Match)));
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
                        &mut histories,
                        generation,
                        Thread {
                            pc: *target,
                            history: thread.history,
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

        counters.peak_threads = counters.peak_threads.max(current.len());
        let winner = current
            .iter()
            .find(|thread| matches!(self.program.states.get(thread.pc), Some(State::Match)))
            .map(|thread| thread.history.ok_or(SearchError::InvalidProgram))
            .transpose()?;
        let captures = if let Some(winner) = winner {
            let slots = materialize(&self.program, &histories, winner, &mut counters, limits)?;
            let captures = canonicalize(&self.program, &slots)?;
            if captures.overall() != Some(span) {
                return Err(SearchError::InvalidProgram);
            }
            Some(captures)
        } else {
            None
        };
        Ok(SearchOutcome {
            captures,
            report: RunReport {
                candidate: CandidateKind::PersistentHistory,
                state_visits: counters.state_visits,
                slot_copies: 0,
                history_nodes: histories.len(),
                history_walk: counters.history_walk,
                starts_injected: counters.starts_injected,
                bytes_examined: counters.bytes_examined,
                peak_threads: counters.peak_threads,
                admitted_scratch_bytes: admission.scratch_bytes,
            },
        })
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
        let mut total_history_nodes = 0_usize;
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
            let history_remaining = limits
                .max_total_history_nodes
                .checked_sub(total_history_nodes)
                .ok_or(SearchError::BoundOverflow(
                    ResourceKind::AggregateHistoryNodes,
                ))?;
            per_search.max_history_nodes = per_search.max_history_nodes.min(history_remaining);

            let outcome = self.search_from(haystack, window, cursor, config, per_search)?;
            total_state_visits = checked_add(
                total_state_visits,
                outcome.report.state_visits,
                ResourceKind::AggregateStateVisits,
            )?;
            total_history_nodes = checked_add(
                total_history_nodes,
                outcome.report.history_nodes,
                ResourceKind::AggregateHistoryNodes,
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
            total_slot_copies: 0,
            total_history_nodes,
        })
    }

    /// Sum participating groups over non-overlapping, non-empty matches.
    ///
    /// This is the capture-preserving reducer used by models whose public
    /// result is participation count rather than capture records. It never
    /// retains prior winners and never clones a slot vector for speculative
    /// threads. Empty selection is rejected because silently applying an
    /// iterator progress policy would change this operation's contract.
    pub fn count_captures_nonempty(
        &self,
        haystack: &[u8],
        window: Window,
        limits: AggregateLimits,
    ) -> Result<CaptureCountOutcome, SearchError> {
        validate_window(haystack, window, window.start)?;
        let mut count = 0_usize;
        let mut matches = 0_usize;
        let mut searches = 0_usize;
        let mut capture_events = 0_usize;
        let mut total_state_visits = 0_usize;
        let mut total_history_nodes = 0_usize;
        let mut total_history_walk = 0_usize;
        let mut peak_threads = 0_usize;
        let mut cursor = window.start;
        loop {
            searches = checked_add(searches, 1, ResourceKind::Searches)?;
            check(ResourceKind::Searches, searches, limits.max_searches)?;

            let mut per_search = limits.per_search;
            per_search.max_state_visits = per_search.max_state_visits.min(
                limits
                    .max_total_state_visits
                    .checked_sub(total_state_visits)
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateStateVisits,
                    ))?,
            );
            per_search.max_history_nodes = per_search.max_history_nodes.min(
                limits
                    .max_total_history_nodes
                    .checked_sub(total_history_nodes)
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateHistoryNodes,
                    ))?,
            );
            per_search.max_history_walk = per_search.max_history_walk.min(
                limits
                    .max_total_history_walk
                    .checked_sub(total_history_walk)
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateHistoryWalk,
                    ))?,
            );

            let outcome =
                self.search_from(haystack, window, cursor, SearchConfig::LEFTMOST, per_search)?;
            total_state_visits = checked_add(
                total_state_visits,
                outcome.report.state_visits,
                ResourceKind::AggregateStateVisits,
            )?;
            total_history_nodes = checked_add(
                total_history_nodes,
                outcome.report.history_nodes,
                ResourceKind::AggregateHistoryNodes,
            )?;
            total_history_walk = checked_add(
                total_history_walk,
                outcome.report.history_walk,
                ResourceKind::AggregateHistoryWalk,
            )?;
            peak_threads = peak_threads.max(outcome.report.peak_threads);

            let Some(record) = outcome.captures else {
                break;
            };
            let overall = record.overall().ok_or(SearchError::InvalidProgram)?;
            if overall.start == overall.end {
                return Err(SearchError::EmptyMatch);
            }
            matches = checked_add(matches, 1, ResourceKind::Results)?;
            check(ResourceKind::Results, matches, limits.max_results)?;
            for group in record.groups {
                capture_events = checked_add(capture_events, 1, ResourceKind::CaptureEvents)?;
                check(
                    ResourceKind::CaptureEvents,
                    capture_events,
                    limits.max_capture_events,
                )?;
                if group.span.is_some() {
                    count = checked_add(count, 1, ResourceKind::CaptureCount)?;
                    check(ResourceKind::CaptureCount, count, limits.max_capture_count)?;
                }
            }
            cursor = overall.end;
        }
        Ok(CaptureCountOutcome {
            count,
            matches,
            searches,
            total_state_visits,
            total_history_nodes,
            total_history_walk,
            peak_threads,
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
        let admission = admit_history(&self.program, window, from, limits)?;
        let state_count = self.program.states.len();
        let mut current = reserve_threads(state_count)?;
        let mut next = reserve_threads(state_count)?;
        let mut stack = reserve_threads(state_count)?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(state_count)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        seen.resize(state_count, 0_usize);
        let mut histories = HistoryArena::new(admission.history_node_bound)?;
        let mut generation = 1_usize;
        let mut counters = Counters {
            state_visits: 0,
            history_walk: 0,
            starts_injected: 0,
            bytes_examined: 0,
            peak_threads: 0,
        };
        let mut winner = None;
        let mut pos = from;

        let all_matches = config.match_kind == MatchKind::All;
        let continue_after_match = all_matches && config.kind == SearchKind::Leftmost;
        loop {
            if (winner.is_none() || continue_after_match) && (!config.anchored || pos == from) {
                counters.starts_injected =
                    checked_add(counters.starts_injected, 1, ResourceKind::StateVisits)?;
                add_thread(
                    &self.program,
                    &mut current,
                    &mut stack,
                    &mut seen,
                    &mut histories,
                    generation,
                    Thread {
                        pc: self.program.start,
                        history: None,
                    },
                    pos,
                    haystack,
                    window,
                    &mut counters,
                    limits,
                )?;
            }

            let accepting = if all_matches {
                current
                    .iter()
                    .rposition(|thread| matches!(self.program.states[thread.pc], State::Match))
            } else {
                current
                    .iter()
                    .position(|thread| matches!(self.program.states[thread.pc], State::Match))
            };
            if let Some(index) = accepting {
                winner = Some(current[index].history.ok_or(SearchError::InvalidProgram)?);
                if config.kind == SearchKind::Earliest {
                    current.clear();
                } else if !all_matches {
                    current.truncate(index);
                }
            }
            counters.peak_threads = counters.peak_threads.max(current.len());
            if winner.is_some() && current.is_empty() && !continue_after_match {
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
                let state = self
                    .program
                    .states
                    .get(thread.pc)
                    .ok_or(SearchError::InvalidProgram)?;
                let State::Byte {
                    ranges,
                    next: target,
                } = state
                else {
                    if all_matches && matches!(state, State::Match) {
                        continue;
                    }
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
                        &mut histories,
                        generation,
                        Thread {
                            pc: *target,
                            history: thread.history,
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

        let captures = if let Some(history) = winner {
            let slots = materialize(&self.program, &histories, history, &mut counters, limits)?;
            Some(canonicalize(&self.program, &slots)?)
        } else {
            None
        };
        Ok(SearchOutcome {
            captures,
            report: RunReport {
                candidate: CandidateKind::PersistentHistory,
                state_visits: counters.state_visits,
                slot_copies: 0,
                history_nodes: histories.len(),
                history_walk: counters.history_walk,
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

#[allow(
    clippy::too_many_arguments,
    reason = "closure resources are explicit laboratory inputs"
)]
fn add_thread(
    program: &Program,
    output: &mut Vec<Thread>,
    stack: &mut Vec<Thread>,
    seen: &mut [usize],
    histories: &mut HistoryArena,
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
                let id = histories.push(HistoryNode {
                    slot: *slot,
                    offset: pos,
                    previous: thread.history,
                })?;
                thread.history = Some(id);
                thread.pc = *next;
                stack.push(thread);
            }
            State::Split { first, second } => {
                stack.push(Thread {
                    pc: *second,
                    history: thread.history,
                });
                thread.pc = *first;
                stack.push(thread);
            }
        }
    }
    counters.peak_threads = counters.peak_threads.max(output.len());
    Ok(())
}

fn materialize(
    program: &Program,
    histories: &HistoryArena,
    winner: usize,
    counters: &mut Counters,
    limits: SearchLimits,
) -> Result<Vec<Option<usize>>, SearchError> {
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(program.slot_count)
        .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
    slots.resize(program.slot_count, None);
    let mut cursor = Some(winner);
    while let Some(id) = cursor {
        counters.history_walk = checked_add(counters.history_walk, 1, ResourceKind::HistoryWalk)?;
        check(
            ResourceKind::HistoryWalk,
            counters.history_walk,
            limits.max_history_walk,
        )?;
        let node = histories.get(id).ok_or(SearchError::InvalidProgram)?;
        let slot = slots
            .get_mut(node.slot)
            .ok_or(SearchError::InvalidProgram)?;
        if slot.is_none() {
            *slot = Some(node.offset);
        }
        cursor = node.previous;
    }
    Ok(slots)
}
