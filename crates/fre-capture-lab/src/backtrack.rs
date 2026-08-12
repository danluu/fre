//! Short priority-ordered bounded backtracking over the capture program.

use std::mem::size_of;

use crate::compile::{Program, State};
use crate::error::{ResourceKind, SearchError};
use crate::limits::SearchLimits;
use crate::model::{BoundedBacktrackProspective, CandidateKind, RunReport, SearchOutcome, Window};
use crate::runtime::{assertion_matches, canonicalize_unset, check};

const UNSET_SLOT: usize = usize::MAX;
#[allow(
    clippy::as_conversions,
    reason = "the target's pointer width is representable by the same target's usize"
)]
const WORD_BITS: usize = usize::BITS as usize;
const RESTORE_TAG: u32 = 1_u32 << (u32::BITS - 1);
const FRAME_INDEX_MASK: u32 = !RESTORE_TAG;

#[derive(Clone, Copy, Debug)]
struct Frame {
    tagged_index: u32,
    value: usize,
}

impl Frame {
    #[inline]
    fn step(pc: usize, at: usize) -> Self {
        Self {
            tagged_index: compact_index(pc),
            value: at,
        }
    }

    #[inline]
    fn restore(slot: usize, offset: usize) -> Self {
        Self {
            tagged_index: RESTORE_TAG | compact_index(slot),
            value: offset,
        }
    }

    #[inline]
    const fn is_restore(self) -> bool {
        self.tagged_index & RESTORE_TAG != 0
    }

    #[inline]
    fn index(self) -> usize {
        usize::try_from(self.tagged_index & FRAME_INDEX_MASK)
            .expect("u32 index requires a usize-wide target")
    }
}

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "bounded-backtracker structural admission proves every program and slot index is below the tagged u32 ceiling before source access"
)]
#[inline]
fn compact_index(index: usize) -> u32 {
    debug_assert!(index <= usize::try_from(FRAME_INDEX_MASK).unwrap_or(usize::MAX));
    index as u32
}

#[derive(Debug)]
struct Counters {
    state_visits: usize,
    slot_copies: usize,
    starts_injected: usize,
    bytes_examined: usize,
    peak_frames: usize,
}

/// A bounded DFS view of one immutable FRE capture program.
pub(crate) struct BoundedBacktracker<'p> {
    program: &'p Program,
}

impl<'p> BoundedBacktracker<'p> {
    pub(crate) const fn new(program: &'p Program) -> Self {
        Self { program }
    }

    pub(crate) fn prospective(
        &self,
        window: Window,
        from: usize,
        anchored: bool,
    ) -> Result<BoundedBacktrackProspective, SearchError> {
        if !self.is_supported() {
            return Err(SearchError::InvalidProgram);
        }
        self.program
            .history_program_shape()
            .bounded_backtrack_prospective_with_frame_states(
                window,
                from,
                anchored,
                size_of::<Frame>(),
                self.program.backtrack_frame_state_len(),
            )
    }

    pub(crate) fn admit(
        &self,
        window: Window,
        from: usize,
        anchored: bool,
        limits: SearchLimits,
    ) -> Result<BoundedBacktrackProspective, SearchError> {
        let prospective = self.prospective(window, from, anchored)?;
        check(
            ResourceKind::StateVisits,
            prospective.state_visits,
            limits.max_state_visits,
        )?;
        check(
            ResourceKind::SlotCopies,
            prospective.slot_copies,
            limits.max_slot_copies,
        )?;
        check(
            ResourceKind::ScratchBytes,
            prospective.scratch_bytes,
            limits.max_scratch_bytes,
        )?;
        Ok(prospective)
    }

    pub(crate) fn captures(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        anchored: bool,
        prospective: BoundedBacktrackProspective,
    ) -> Result<SearchOutcome, SearchError> {
        let boundaries = window
            .end
            .checked_sub(from)
            .and_then(|length| length.checked_add(1))
            .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
        let pairs = self
            .program
            .state_len()
            .checked_mul(boundaries)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let word_bits = size_of::<usize>()
            .checked_mul(8)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let rounded_bits = word_bits
            .checked_sub(1)
            .and_then(|rounding| pairs.checked_add(rounding))
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;
        let words = rounded_bits
            .checked_div(word_bits)
            .ok_or(SearchError::BoundOverflow(ResourceKind::ScratchBytes))?;

        let mut visited = Vec::new();
        visited
            .try_reserve_exact(words)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        visited.resize(words, 0_usize);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(self.program.history_program_shape().slots)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        slots.resize(self.program.history_program_shape().slots, UNSET_SLOT);

        let mut counters = Counters {
            state_visits: 0,
            slot_copies: 0,
            starts_injected: 0,
            bytes_examined: 0,
            peak_frames: 0,
        };
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(prospective.peak_threads)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        self.captures_with_stack(
            haystack,
            window,
            from,
            anchored,
            prospective,
            boundaries,
            &mut frames,
            &mut visited,
            &mut slots,
            &mut counters,
        )
    }

    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_arguments,
        reason = "source-independent admission proves the root counter and monotone boundary increment before source access; the admitted storage and complete bounded DFS state remain explicit"
    )]
    fn captures_with_stack(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        anchored: bool,
        prospective: BoundedBacktrackProspective,
        boundaries: usize,
        frames: &mut Vec<Frame>,
        visited: &mut [usize],
        slots: &mut [usize],
        counters: &mut Counters,
    ) -> Result<SearchOutcome, SearchError> {
        let last_start = if anchored { from } else { window.end };
        let mut at = from;
        let captures = loop {
            counters.starts_injected += 1;
            frames.push(Frame::step(self.program.start, at));
            counters.peak_frames = counters.peak_frames.max(frames.len());
            if self.backtrack(
                haystack, window, from, boundaries, frames, visited, slots, counters,
            )? {
                break Some(canonicalize_unset(self.program, slots, UNSET_SLOT)?);
            }
            if at == last_start {
                break None;
            }
            at += 1;
        };
        let report = RunReport {
            candidate: CandidateKind::BoundedBacktracker,
            state_visits: counters.state_visits,
            slot_copies: counters.slot_copies,
            history_nodes: 0,
            history_walk: 0,
            starts_injected: counters.starts_injected,
            bytes_examined: counters.bytes_examined,
            peak_threads: counters.peak_frames,
            admitted_scratch_bytes: prospective.scratch_bytes,
        };
        if !prospective.closes_report(&report) {
            return Err(SearchError::InvalidProgram);
        }
        Ok(SearchOutcome { captures, report })
    }

    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_arguments,
        reason = "source-independent admission proves each hot-loop counter increment and byte advance before source access; the complete bounded DFS state and ledgers remain explicit"
    )]
    fn backtrack(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        stride: usize,
        frames: &mut Vec<Frame>,
        visited: &mut [usize],
        slots: &mut [usize],
        counters: &mut Counters,
    ) -> Result<bool, SearchError> {
        while let Some(frame) = frames.pop() {
            if frame.is_restore() {
                debug_assert!(frame.index() < slots.len());
                slots[frame.index()] = frame.value;
                counters.slot_copies += 1;
            } else {
                let mut pc = frame.index();
                let mut at = frame.value;
                loop {
                    counters.state_visits += 1;
                    if !insert_visited(visited, stride, from, pc, at) {
                        break;
                    }
                    debug_assert!(pc < self.program.states.len());
                    match &self.program.states[pc] {
                        State::Byte { ranges, next } => {
                            if at >= window.end {
                                break;
                            }
                            debug_assert!(at < haystack.len());
                            let byte = haystack[at];
                            counters.bytes_examined += 1;
                            if !ranges_match(ranges, byte) {
                                break;
                            }
                            pc = *next;
                            at += 1;
                        }
                        State::Split { first, second } => {
                            frames.push(Frame::step(*second, at));
                            counters.peak_frames = counters.peak_frames.max(frames.len());
                            pc = *first;
                        }
                        State::Save { slot, next } => {
                            debug_assert!(*slot < slots.len());
                            frames.push(Frame::restore(*slot, slots[*slot]));
                            counters.peak_frames = counters.peak_frames.max(frames.len());
                            slots[*slot] = at;
                            counters.slot_copies += 1;
                            pc = *next;
                        }
                        State::Assert { assertion, next } => {
                            if !assertion_matches(*assertion, haystack, window, at)? {
                                break;
                            }
                            pc = *next;
                        }
                        State::Epsilon { next } => pc = *next,
                        State::Match => return Ok(true),
                        State::Fail => break,
                    }
                }
            }
        }
        Ok(false)
    }

    pub(crate) fn is_supported(&self) -> bool {
        let maximum = usize::try_from(FRAME_INDEX_MASK).unwrap_or(usize::MAX);
        self.program
            .state_len()
            .checked_sub(1)
            .is_none_or(|index| index <= maximum)
            && self
                .program
                .history_program_shape()
                .slots
                .checked_sub(1)
                .is_none_or(|index| index <= maximum)
    }
}

#[inline]
fn ranges_match(ranges: &[(u8, u8)], byte: u8) -> bool {
    if let &[(start, end)] = ranges {
        return start <= byte && byte <= end;
    }
    for &(start, end) in ranges {
        if start > byte {
            return false;
        }
        if byte <= end {
            return true;
        }
    }
    false
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the caller proves the complete state-by-boundary product before allocation; validated coordinates are strictly inside that product"
)]
#[inline]
fn insert_visited(visited: &mut [usize], stride: usize, from: usize, pc: usize, at: usize) -> bool {
    debug_assert!(at >= from);
    let offset = at - from;
    debug_assert!(offset < stride);
    let index = pc * stride + offset;
    let word = index / WORD_BITS;
    let bit = index % WORD_BITS;
    let mask = 1_usize << bit;
    debug_assert!(word < visited.len());
    if visited[word] & mask != 0 {
        return false;
    }
    visited[word] |= mask;
    true
}

#[cfg(test)]
mod tests {
    use super::{FRAME_INDEX_MASK, Frame};
    use std::mem::size_of;

    #[test]
    fn admitted_frame_layout_and_index_ceiling_are_exact() {
        assert_eq!(size_of::<Frame>(), size_of::<(u32, usize)>());
        assert_eq!(FRAME_INDEX_MASK, u32::MAX >> 1);
    }
}
