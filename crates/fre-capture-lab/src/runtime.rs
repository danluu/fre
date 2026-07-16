//! Shared resource admission and canonicalization helpers.

use std::mem::size_of;

use crate::ast::Assertion;
use crate::compile::Program;
use crate::error::{ResourceKind, SearchError};
use crate::limits::SearchLimits;
use crate::model::{CaptureRecord, GroupRecord, Span, Window};

pub(crate) const HISTORY_CHUNK_CAPACITY: usize = 16_384;

pub(crate) fn assertion_matches(
    assertion: Assertion,
    haystack: &[u8],
    window: Window,
    position: usize,
) -> Result<bool, SearchError> {
    if position < window.start || position > window.end || window.end > haystack.len() {
        return Err(SearchError::InvalidWindow);
    }
    let left_byte = position
        .checked_sub(1)
        .filter(|&index| index >= window.start)
        .and_then(|index| haystack.get(index));
    let right_byte = (position < window.end)
        .then(|| haystack.get(position))
        .flatten();
    let left_ascii_word = left_byte.is_some_and(|&byte| is_ascii_word(byte));
    let right_ascii_word = right_byte.is_some_and(|&byte| is_ascii_word(byte));
    Ok(match assertion {
        Assertion::Start => position == window.start,
        Assertion::End => position == window.end,
        Assertion::StartLf => {
            position == window.start || left_byte.is_some_and(|&byte| byte == b'\n')
        }
        Assertion::EndLf => position == window.end || right_byte.is_some_and(|&byte| byte == b'\n'),
        Assertion::WordAscii => left_ascii_word != right_ascii_word,
        Assertion::WordAsciiNegate => left_ascii_word == right_ascii_word,
        Assertion::WordStartAscii => !left_ascii_word && right_ascii_word,
        Assertion::WordEndAscii => left_ascii_word && !right_ascii_word,
        Assertion::WordStartHalfAscii => !left_ascii_word,
        Assertion::WordEndHalfAscii => !right_ascii_word,
        Assertion::WordUnicode => {
            let before = haystack
                .get(window.start..position)
                .ok_or(SearchError::InvalidWindow)?;
            let after = haystack
                .get(position..window.end)
                .ok_or(SearchError::InvalidWindow)?;
            unicode_word(decode_last_scalar(before))? != unicode_word(decode_first_scalar(after))?
        }
    })
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn unicode_word(scalar: Option<char>) -> Result<bool, SearchError> {
    let Some(scalar) = scalar else {
        return Ok(false);
    };
    regex_syntax::try_is_word_character(scalar).map_err(|_| SearchError::InvalidProgram)
}

fn decode_first_scalar(bytes: &[u8]) -> Option<char> {
    let first = *bytes.first()?;
    let width = match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return None,
    };
    core::str::from_utf8(bytes.get(..width)?)
        .ok()?
        .chars()
        .next()
}

fn decode_last_scalar(bytes: &[u8]) -> Option<char> {
    let end = bytes.len();
    let mut start = end.checked_sub(1)?;
    let limit = end.saturating_sub(4);
    while start > limit && matches!(bytes[start], 0x80..=0xBF) {
        start = start.checked_sub(1)?;
    }
    let encoded = bytes.get(start..end)?;
    let scalar = decode_first_scalar(encoded)?;
    (scalar.len_utf8() == encoded.len()).then_some(scalar)
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

fn admit_history_boundaries(
    program: &Program,
    boundaries: usize,
    limits: SearchLimits,
) -> Result<Admission, SearchError> {
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
