//! Shared resource admission and canonicalization helpers.

use std::mem::size_of;

use crate::ast::Assertion;
use crate::compile::Program;
use crate::error::{ResourceKind, SearchError};
use crate::limits::SearchLimits;
use crate::line::SemanticBoundary;
use crate::model::{
    BoundedBacktrackProspective, CaptureRecord, GroupRecord, HistoryProgramShape,
    HistorySearchProspective, ParticipationSearchProspective, RestartedHistoryProspective, Span,
    Window,
};

pub(crate) const HISTORY_CHUNK_CAPACITY: usize = 16_384;

impl HistoryProgramShape {
    /// Derive the complete route-independent bounded-backtracking envelope
    /// from immutable program shape and search boundaries only.
    pub fn bounded_backtrack_prospective(
        self,
        window: Window,
        from: usize,
        anchored: bool,
        frame_bytes: usize,
    ) -> Result<BoundedBacktrackProspective, SearchError> {
        self.bounded_backtrack_prospective_with_frame_states(
            window,
            from,
            anchored,
            frame_bytes,
            self.states,
        )
    }

    pub(crate) fn bounded_backtrack_prospective_with_frame_states(
        self,
        window: Window,
        from: usize,
        anchored: bool,
        frame_bytes: usize,
        frame_states: usize,
    ) -> Result<BoundedBacktrackProspective, SearchError> {
        if window.start > window.end || from < window.start || from > window.end {
            return Err(SearchError::InvalidWindow);
        }
        if frame_states > self.states {
            return Err(SearchError::InvalidProgram);
        }
        let boundaries = boundary_count(window, from)?;
        let pairs = self
            .states
            .checked_mul(boundaries)
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let roots = if anchored { 1 } else { boundaries };
        let state_visits = pairs
            .checked_mul(2)
            .and_then(|work| work.checked_add(roots))
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        // Every first visit to a pair can push at most one frame because a
        // program state is either a Split or a Save, never both. The injected
        // root frame is popped before that root can push descendants, and a
        // failed root drains the stack before the next root is injected.
        // Consequently roots do not accumulate in the peak-stack bound.
        let peak_threads = frame_states
            .checked_mul(boundaries)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?
            .max(1);
        let save_pairs = self
            .save_states
            .checked_mul(boundaries)
            .ok_or(SearchError::BoundOverflow(ResourceKind::SlotCopies))?;
        let slot_copies = save_pairs
            .checked_mul(2)
            .ok_or(SearchError::BoundOverflow(ResourceKind::SlotCopies))?;
        let word_bits = size_of::<usize>()
            .checked_mul(8)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let rounded_bits = word_bits
            .checked_sub(1)
            .and_then(|rounding| pairs.checked_add(rounding))
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let visited_bytes = rounded_bits
            .checked_div(word_bits)
            .and_then(|words| words.checked_mul(size_of::<usize>()))
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let frames = peak_threads
            .checked_mul(frame_bytes)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        // The bounded backtracker represents an unset slot with a sentinel,
        // just as a niche-optimized optional offset would. Every source
        // boundary is a valid slice offset and therefore strictly below
        // `usize::MAX`.
        let slots = self
            .slots
            .checked_mul(size_of::<usize>())
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        // `frames`, `visited`, and `slots` are the only dynamic containers.
        let container_headers = size_of::<Vec<usize>>()
            .checked_mul(3)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let scratch_bytes = visited_bytes
            .checked_add(frames)
            .and_then(|bytes| bytes.checked_add(slots))
            .and_then(|bytes| bytes.checked_add(container_headers))
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        Ok(BoundedBacktrackProspective {
            state_visits,
            slot_copies,
            // Each first-time state/boundary pair can dispatch at most one
            // byte transition, and duplicate probes read no source byte.
            // A complete candidate scan costs at most `boundaries - 1`
            // logical byte examinations. Every valid capture program has at
            // least one non-byte state, so its byte-transition comparisons
            // plus that scan remain within this unchanged state-pair bound.
            bytes_examined: pairs,
            starts_injected: roots,
            peak_threads,
            scratch_bytes,
        })
    }

    /// Logical group-vector and cloned-name bytes present while one canonical
    /// record is materialized. This versioned accounting intentionally uses
    /// element sizes and name payload lengths, not allocator capacity.
    pub fn materialized_record_bytes(self) -> Result<usize, SearchError> {
        self.groups
            .checked_mul(size_of::<GroupRecord>())
            .and_then(|bytes| bytes.checked_add(self.name_payload_bytes))
            .ok_or(SearchError::BoundOverflow(
                ResourceKind::RetainedOutputBytes,
            ))
    }

    /// Logical bytes retained per returned record: one outer vector cell plus
    /// that record's group-vector cells and cloned name payloads.
    pub fn retained_record_bytes(self) -> Result<usize, SearchError> {
        self.materialized_record_bytes()?
            .checked_add(size_of::<CaptureRecord>())
            .ok_or(SearchError::BoundOverflow(
                ResourceKind::RetainedOutputBytes,
            ))
    }

    /// Derive one search envelope from immutable program shape and byte
    /// boundaries only. No source byte is inspected.
    pub fn search_prospective(
        self,
        window: Window,
        from: usize,
    ) -> Result<HistorySearchProspective, SearchError> {
        if window.start > window.end || from < window.start || from > window.end {
            return Err(SearchError::InvalidWindow);
        }
        let boundaries = boundary_count(window, from)?;
        self.search_prospective_for_boundaries(boundaries)
    }

    /// Derive the complete worst-case restarted-session envelope. At most one
    /// capture record is retained at each byte boundary. Every nonterminal
    /// boundary can be searched twice only when Rust empty-match progression
    /// suppresses the second winner; the terminal boundary is searched once.
    pub fn restarted_prospective(
        self,
        window: Window,
    ) -> Result<RestartedHistoryProspective, SearchError> {
        self.restarted_prospective_with_minimum(window, 0)
    }

    /// Derive the complete restarted-session envelope using a
    /// construction-proved whole-match lower bound. A positive bound excludes
    /// empty progression and limits successful restarts; zero retains the
    /// general nullable envelope.
    #[allow(
        clippy::too_many_lines,
        reason = "the source-independent restarted-work and retained-output proof remains one checked arithmetic derivation"
    )]
    pub fn restarted_prospective_with_minimum(
        self,
        window: Window,
        minimum_match_bytes: usize,
    ) -> Result<RestartedHistoryProspective, SearchError> {
        if window.start > window.end {
            return Err(SearchError::InvalidWindow);
        }
        let boundaries = boundary_count(window, window.start)?;
        let length = boundaries.saturating_sub(1);
        let (searches, results, coefficient, bytes_examined, materialized_records) =
            if minimum_match_bytes == 0 {
                let searches = boundaries
                    .checked_mul(2)
                    .and_then(|value| value.checked_sub(1))
                    .ok_or(SearchError::BoundOverflow(ResourceKind::Searches))?;
                let coefficient = boundaries
                    .checked_mul(boundaries.checked_add(1).ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateStateVisits,
                    ))?)
                    .and_then(|value| value.checked_sub(1))
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateStateVisits,
                    ))?;
                let bytes_examined =
                    boundaries
                        .checked_mul(length)
                        .ok_or(SearchError::BoundOverflow(
                            ResourceKind::AggregateStateVisits,
                        ))?;
                (searches, boundaries, coefficient, bytes_examined, searches)
            } else {
                let results = length
                    .checked_div(minimum_match_bytes)
                    .ok_or(SearchError::BoundOverflow(ResourceKind::Results))?;
                let searches = results
                    .checked_add(1)
                    .ok_or(SearchError::BoundOverflow(ResourceKind::Searches))?;
                let progress = minimum_match_bytes
                    .checked_mul(triangular(results, ResourceKind::AggregateStateVisits)?)
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateStateVisits,
                    ))?;
                let coefficient = searches
                    .checked_mul(boundaries)
                    .and_then(|value| value.checked_sub(progress))
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateStateVisits,
                    ))?;
                let bytes_examined = searches
                    .checked_mul(length)
                    .and_then(|value| value.checked_sub(progress))
                    .ok_or(SearchError::BoundOverflow(
                        ResourceKind::AggregateStateVisits,
                    ))?;
                (searches, results, coefficient, bytes_examined, results)
            };
        let state_visits_per_boundary =
            self.states
                .checked_mul(4)
                .ok_or(SearchError::BoundOverflow(
                    ResourceKind::AggregateStateVisits,
                ))?;
        let total_state_visits = state_visits_per_boundary.checked_mul(coefficient).ok_or(
            SearchError::BoundOverflow(ResourceKind::AggregateStateVisits),
        )?;
        let total_history_nodes =
            self.save_states
                .checked_mul(coefficient)
                .ok_or(SearchError::BoundOverflow(
                    ResourceKind::AggregateHistoryNodes,
                ))?;
        let total_history_walk =
            self.save_states
                .checked_mul(coefficient)
                .ok_or(SearchError::BoundOverflow(
                    ResourceKind::AggregateHistoryWalk,
                ))?;
        let capture_events = materialized_records
            .checked_mul(self.groups)
            .ok_or(SearchError::BoundOverflow(ResourceKind::CaptureEvents))?;
        let starts_injected = coefficient;
        let largest = self.search_prospective(window, window.start)?;
        let retained_output_bytes = results.checked_mul(self.retained_record_bytes()?).ok_or(
            SearchError::BoundOverflow(ResourceKind::RetainedOutputBytes),
        )?;
        // The retained bound includes one complete cell/payload budget for
        // every possible boundary. It therefore also dominates the transient
        // current materialization after any prior retained prefix, including
        // a nullable winner that will be suppressed.
        let combined_peak_bytes = retained_output_bytes
            .checked_add(largest.scratch_bytes)
            .ok_or(SearchError::BoundOverflow(ResourceKind::CombinedPeakBytes))?;
        Ok(RestartedHistoryProspective {
            window,
            minimum_match_bytes,
            largest_search: largest,
            searches,
            materialized_records,
            results,
            total_state_visits,
            total_slot_copies: 0,
            total_history_nodes,
            total_history_walk,
            capture_events,
            bytes_examined,
            starts_injected,
            peak_threads: self.states,
            scratch_bytes: largest.scratch_bytes,
            retained_output_bytes,
            combined_peak_bytes,
        })
    }

    pub(crate) fn search_prospective_for_boundaries(
        self,
        boundaries: usize,
    ) -> Result<HistorySearchProspective, SearchError> {
        let state_visits = self
            .states
            .checked_mul(4)
            .and_then(|per_boundary| per_boundary.checked_mul(boundaries))
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        // `add_thread` marks a program counter before dispatch, and one mark
        // generation spans all closure roots at an input boundary.
        let history_nodes = self
            .save_states
            .checked_mul(boundaries)
            .ok_or(SearchError::BoundOverflow(ResourceKind::HistoryNodes))?;
        let thread_bytes = self
            .states
            .checked_mul(3)
            .and_then(|count| count.checked_mul(size_of::<(usize, Option<usize>)>()))
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let seen_bytes = self
            .states
            .checked_mul(size_of::<usize>())
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let history_bytes = history_nodes
            .checked_mul(size_of::<(usize, usize, Option<usize>)>())
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let history_chunks = history_nodes
            .checked_add(HISTORY_CHUNK_CAPACITY.saturating_sub(1))
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?
            .checked_div(HISTORY_CHUNK_CAPACITY)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let history_chunk_headers = history_chunks
            .checked_mul(size_of::<Vec<(usize, usize, Option<usize>)>>())
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let materialized_slots = self
            .slots
            .checked_mul(size_of::<Option<usize>>())
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let container_headers = size_of::<Vec<usize>>()
            .checked_mul(6)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let scratch_bytes = thread_bytes
            .checked_add(seen_bytes)
            .and_then(|bytes| bytes.checked_add(history_bytes))
            .and_then(|bytes| bytes.checked_add(history_chunk_headers))
            .and_then(|bytes| bytes.checked_add(materialized_slots))
            .and_then(|bytes| bytes.checked_add(container_headers))
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        Ok(HistorySearchProspective {
            state_visits,
            history_nodes,
            history_walk: history_nodes,
            bytes_examined: boundaries.saturating_sub(1),
            starts_injected: boundaries,
            peak_threads: self.states,
            scratch_bytes,
        })
    }
}

fn triangular(value: usize, resource: ResourceKind) -> Result<usize, SearchError> {
    let successor = value
        .checked_add(1)
        .ok_or(SearchError::BoundOverflow(resource))?;
    if value.is_multiple_of(2) {
        value
            .checked_div(2)
            .and_then(|half| half.checked_mul(successor))
            .ok_or(SearchError::BoundOverflow(resource))
    } else {
        successor
            .checked_div(2)
            .and_then(|half| half.checked_mul(value))
            .ok_or(SearchError::BoundOverflow(resource))
    }
}

pub(crate) fn assertion_matches(
    assertion: Assertion,
    haystack: &[u8],
    window: Window,
    position: usize,
) -> Result<bool, SearchError> {
    SemanticBoundary::new(haystack, window, position)?.matches(assertion)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Admission {
    pub(crate) history_node_bound: usize,
    pub(crate) scratch_bytes: usize,
}

pub(crate) fn validate_window(
    haystack: &[u8],
    window: Window,
    from: usize,
) -> Result<(), SearchError> {
    if window.start > window.end || window.end > haystack.len() {
        return Err(SearchError::InvalidWindow);
    }
    if from < window.start || from > window.end {
        return Err(SearchError::InvalidWindow);
    }
    Ok(())
}

pub(crate) fn admit_inline(
    program: &Program,
    window: Window,
    from: usize,
    limits: SearchLimits,
) -> Result<Admission, SearchError> {
    let boundaries = boundary_count(window, from)?;
    let state_visit_bound = state_visit_bound(program, boundaries)?;
    check(
        ResourceKind::StateVisits,
        state_visit_bound,
        limits.max_state_visits,
    )?;
    let twice_slots = program
        .slot_count
        .checked_mul(2)
        .ok_or(SearchError::BoundOverflow(ResourceKind::SlotCopies))?;
    let copies_per_visit = twice_slots.max(program.slot_count);
    let slot_copy_bound = state_visit_bound
        .checked_mul(copies_per_visit)
        .ok_or(SearchError::BoundOverflow(ResourceKind::SlotCopies))?;
    check(
        ResourceKind::SlotCopies,
        slot_copy_bound,
        limits.max_slot_copies,
    )?;

    let thread_header = size_of::<(usize, Vec<Option<usize>>)>();
    let slot_heap = program
        .slot_count
        .checked_mul(size_of::<Option<usize>>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let per_thread = thread_header
        .checked_add(slot_heap)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let thread_copies = program
        .states
        .len()
        .checked_mul(3)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let threads = thread_copies
        .checked_mul(per_thread)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let seen = program
        .states
        .len()
        .checked_mul(size_of::<usize>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let winner_slots = program
        .slot_count
        .checked_mul(size_of::<Option<usize>>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let container_headers = size_of::<Vec<usize>>()
        .checked_mul(5)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let scratch_bytes = threads
        .checked_add(seen)
        .and_then(|bytes| bytes.checked_add(winner_slots))
        .and_then(|bytes| bytes.checked_add(container_headers))
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    check(
        ResourceKind::ScratchBytes,
        scratch_bytes,
        limits.max_scratch_bytes,
    )?;
    Ok(Admission {
        history_node_bound: 0,
        scratch_bytes,
    })
}

pub(crate) fn admit_history(
    program: &Program,
    window: Window,
    from: usize,
    limits: SearchLimits,
) -> Result<Admission, SearchError> {
    let boundaries = boundary_count(window, from)?;
    admit_history_boundaries(program, boundaries, limits)
}

pub(crate) fn admit_history_exact(
    program: &Program,
    span: Span,
    limits: SearchLimits,
) -> Result<Admission, SearchError> {
    let boundaries = span
        .end
        .checked_sub(span.start)
        .and_then(|length| length.checked_add(1))
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    admit_history_boundaries(program, boundaries, limits)
}

pub(crate) fn participation_exact_prospective(
    program: &Program,
    span: Span,
    thread_bytes: usize,
) -> Result<ParticipationSearchProspective, SearchError> {
    if span.start > span.end {
        return Err(SearchError::InvalidWindow);
    }
    let boundaries = span
        .end
        .checked_sub(span.start)
        .and_then(|length| length.checked_add(1))
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let state_visits = state_visit_bound(program, boundaries)?;
    let thread_cells = program
        .states
        .len()
        .checked_mul(3)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let threads = thread_cells
        .checked_mul(thread_bytes)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let seen = program
        .states
        .len()
        .checked_mul(size_of::<usize>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    // `current`, `next`, `stack`, and `seen` are the only dynamic
    // containers. Participation masks live inline in each thread.
    let container_headers = size_of::<Vec<usize>>()
        .checked_mul(4)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let scratch_bytes = threads
        .checked_add(seen)
        .and_then(|bytes| bytes.checked_add(container_headers))
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    Ok(ParticipationSearchProspective {
        state_visits,
        starts_injected: 1,
        bytes_examined: boundaries.saturating_sub(1),
        peak_threads: program.states.len(),
        slot_copies: 0,
        history_nodes: 0,
        history_walk: 0,
        scratch_bytes,
    })
}

pub(crate) fn admit_participation_exact(
    program: &Program,
    span: Span,
    thread_bytes: usize,
    limits: SearchLimits,
) -> Result<ParticipationSearchProspective, SearchError> {
    let prospective = participation_exact_prospective(program, span, thread_bytes)?;
    check(
        ResourceKind::StateVisits,
        prospective.state_visits,
        limits.max_state_visits,
    )?;
    check(
        ResourceKind::ScratchBytes,
        prospective.scratch_bytes,
        limits.max_scratch_bytes,
    )?;
    Ok(prospective)
}

fn admit_history_boundaries(
    program: &Program,
    boundaries: usize,
    limits: SearchLimits,
) -> Result<Admission, SearchError> {
    let prospective = program
        .history_program_shape()
        .search_prospective_for_boundaries(boundaries)?;
    check(
        ResourceKind::StateVisits,
        prospective.state_visits,
        limits.max_state_visits,
    )?;
    check(
        ResourceKind::HistoryNodes,
        prospective.history_nodes,
        limits.max_history_nodes,
    )?;
    check(
        ResourceKind::HistoryWalk,
        prospective.history_walk,
        limits.max_history_walk,
    )?;
    check(
        ResourceKind::ScratchBytes,
        prospective.scratch_bytes,
        limits.max_scratch_bytes,
    )?;
    Ok(Admission {
        history_node_bound: prospective.history_nodes,
        scratch_bytes: prospective.scratch_bytes,
    })
}

fn boundary_count(window: Window, from: usize) -> Result<usize, SearchError> {
    window
        .end
        .checked_sub(from)
        .and_then(|length| length.checked_add(1))
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))
}

fn state_visit_bound(program: &Program, boundaries: usize) -> Result<usize, SearchError> {
    // Each processed instruction contributes at most two successor pushes,
    // and one injected start is added per boundary. Four state-count units
    // per generation dominate unique visits, duplicate edge targets, roots
    // from the preceding consuming generation and the newly injected start.
    let per_boundary = program
        .states
        .len()
        .checked_mul(4)
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    boundaries
        .checked_mul(per_boundary)
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))
}

pub(crate) fn canonicalize(
    program: &Program,
    slots: &[Option<usize>],
) -> Result<CaptureRecord, SearchError> {
    canonicalize_with(program, slots.len(), |slot| {
        slots.get(slot).copied().flatten()
    })
}

pub(crate) fn canonicalize_unset(
    program: &Program,
    slots: &[usize],
    unset: usize,
) -> Result<CaptureRecord, SearchError> {
    canonicalize_with(program, slots.len(), |slot| {
        slots.get(slot).copied().filter(|&value| value != unset)
    })
}

fn canonicalize_with(
    program: &Program,
    slot_count: usize,
    mut slot: impl FnMut(usize) -> Option<usize>,
) -> Result<CaptureRecord, SearchError> {
    if slot_count != program.slot_count {
        return Err(SearchError::InvalidProgram);
    }
    let mut groups = Vec::new();
    groups
        .try_reserve_exact(program.groups.len())
        .map_err(|_| SearchError::Allocation(ResourceKind::RetainedOutputBytes))?;
    for (numeric, meta) in program.groups.iter().enumerate() {
        let start_slot = numeric
            .checked_mul(2)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let end_slot = start_slot
            .checked_add(1)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let span = match (slot(start_slot), slot(end_slot)) {
            (Some(start), Some(end)) if start <= end => Some(Span { start, end }),
            (None, None) => None,
            _ => return Err(SearchError::InvalidProgram),
        };
        let name = meta
            .name
            .as_ref()
            .map(|name| {
                let mut copied = String::new();
                copied
                    .try_reserve_exact(name.len())
                    .map_err(|_| SearchError::Allocation(ResourceKind::RetainedOutputBytes))?;
                copied.push_str(name);
                Ok(copied)
            })
            .transpose()?;
        groups.push(GroupRecord {
            index: meta.index,
            name,
            span,
        });
    }
    if groups.first().is_none_or(|group| group.span.is_none()) {
        return Err(SearchError::InvalidProgram);
    }
    Ok(CaptureRecord { groups })
}

pub(crate) fn checked_add(
    left: usize,
    right: usize,
    kind: ResourceKind,
) -> Result<usize, SearchError> {
    left.checked_add(right)
        .ok_or(SearchError::BoundOverflow(kind))
}

pub(crate) fn check(kind: ResourceKind, required: usize, limit: usize) -> Result<(), SearchError> {
    if required > limit {
        return Err(SearchError::Resource {
            kind,
            required,
            limit,
        });
    }
    Ok(())
}
