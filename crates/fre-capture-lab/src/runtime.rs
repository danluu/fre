//! Shared resource admission and canonicalization helpers.

use std::mem::size_of;

use crate::compile::Program;
use crate::error::{ResourceKind, SearchError};
use crate::limits::SearchLimits;
use crate::model::{CaptureRecord, GroupRecord, Span, Window};

pub(crate) const HISTORY_CHUNK_CAPACITY: usize = 16_384;

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
    let state_visit_bound = state_visit_bound(program, boundaries)?;
    check(
        ResourceKind::StateVisits,
        state_visit_bound,
        limits.max_state_visits,
    )?;
    let history_node_bound = state_visit_bound;
    check(
        ResourceKind::HistoryNodes,
        history_node_bound,
        limits.max_history_nodes,
    )?;
    check(
        ResourceKind::HistoryWalk,
        history_node_bound,
        limits.max_history_walk,
    )?;

    let thread_bytes = program
        .states
        .len()
        .checked_mul(3)
        .and_then(|count| count.checked_mul(size_of::<(usize, Option<usize>)>()))
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let seen_bytes = program
        .states
        .len()
        .checked_mul(size_of::<usize>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let history_bytes = history_node_bound
        .checked_mul(size_of::<(usize, usize, Option<usize>)>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let history_chunks = history_node_bound
        .checked_add(HISTORY_CHUNK_CAPACITY.saturating_sub(1))
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?
        .checked_div(HISTORY_CHUNK_CAPACITY)
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let history_chunk_headers = history_chunks
        .checked_mul(size_of::<Vec<(usize, usize, Option<usize>)>>())
        .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
    let materialized_slots = program
        .slot_count
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
    check(
        ResourceKind::ScratchBytes,
        scratch_bytes,
        limits.max_scratch_bytes,
    )?;
    Ok(Admission {
        history_node_bound,
        scratch_bytes,
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
    if slots.len() != program.slot_count {
        return Err(SearchError::InvalidProgram);
    }
    let mut groups = Vec::new();
    groups
        .try_reserve(program.groups.len())
        .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
    for (numeric, meta) in program.groups.iter().enumerate() {
        let start_slot = numeric
            .checked_mul(2)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let end_slot = start_slot
            .checked_add(1)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let span = match (
            slots.get(start_slot).copied().flatten(),
            slots.get(end_slot).copied().flatten(),
        ) {
            (Some(start), Some(end)) if start <= end => Some(Span { start, end }),
            (None, None) => None,
            _ => return Err(SearchError::InvalidProgram),
        };
        groups.push(GroupRecord {
            index: meta.index,
            name: meta.name.clone(),
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
