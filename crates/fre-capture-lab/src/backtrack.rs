//! Short priority-ordered bounded backtracking over the capture program.

use std::mem::size_of;

use crate::compile::{Program, State};
use crate::error::{ResourceKind, SearchError};
use crate::limits::SearchLimits;
use crate::model::{BoundedBacktrackProspective, CandidateKind, RunReport, SearchOutcome, Window};
use crate::runtime::{assertion_matches, canonicalize, check, checked_add};

#[derive(Clone, Copy, Debug)]
enum Frame {
    Step { pc: usize, at: usize },
    Restore { slot: usize, offset: Option<usize> },
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
        self.program
            .history_program_shape()
            .bounded_backtrack_prospective(window, from, anchored, size_of::<Frame>())
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
        limits: SearchLimits,
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

        let mut frames = Vec::new();
        frames
            .try_reserve_exact(prospective.peak_threads)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        let mut visited = Vec::new();
        visited
            .try_reserve_exact(words)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        visited.resize(words, 0_usize);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(self.program.history_program_shape().slots)
            .map_err(|_| SearchError::Allocation(ResourceKind::ScratchBytes))?;
        slots.resize(self.program.history_program_shape().slots, None);

        let mut counters = Counters {
            state_visits: 0,
            slot_copies: 0,
            starts_injected: 0,
            bytes_examined: 0,
            peak_frames: 0,
        };
        let last_start = if anchored { from } else { window.end };
        let mut at = from;
        let captures = loop {
            counters.starts_injected =
                checked_add(counters.starts_injected, 1, ResourceKind::StateVisits)?;
            frames.push(Frame::Step {
                pc: self.program.start,
                at,
            });
            counters.peak_frames = counters.peak_frames.max(frames.len());
            if self.backtrack(
                haystack,
                window,
                from,
                boundaries,
                &mut frames,
                &mut visited,
                &mut slots,
                &mut counters,
                limits,
            )? {
                break Some(canonicalize(self.program, &slots)?);
            }
            if at == last_start {
                break None;
            }
            at = at
                .checked_add(1)
                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
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
        clippy::too_many_arguments,
        reason = "the complete bounded DFS state and ledgers remain explicit"
    )]
    fn backtrack(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        stride: usize,
        frames: &mut Vec<Frame>,
        visited: &mut [usize],
        slots: &mut [Option<usize>],
        counters: &mut Counters,
        limits: SearchLimits,
    ) -> Result<bool, SearchError> {
        while let Some(frame) = frames.pop() {
            match frame {
                Frame::Restore { slot, offset } => {
                    let target = slots.get_mut(slot).ok_or(SearchError::InvalidProgram)?;
                    *target = offset;
                    counters.slot_copies =
                        checked_add(counters.slot_copies, 1, ResourceKind::SlotCopies)?;
                    check(
                        ResourceKind::SlotCopies,
                        counters.slot_copies,
                        limits.max_slot_copies,
                    )?;
                }
                Frame::Step { mut pc, mut at } => loop {
                    counters.state_visits =
                        checked_add(counters.state_visits, 1, ResourceKind::StateVisits)?;
                    check(
                        ResourceKind::StateVisits,
                        counters.state_visits,
                        limits.max_state_visits,
                    )?;
                    if !insert_visited(visited, self.program.state_len(), stride, from, pc, at)? {
                        break;
                    }
                    match self
                        .program
                        .states
                        .get(pc)
                        .ok_or(SearchError::InvalidProgram)?
                    {
                        State::Byte { ranges, next } => {
                            if at >= window.end {
                                break;
                            }
                            let byte = *haystack.get(at).ok_or(SearchError::InvalidWindow)?;
                            counters.bytes_examined =
                                checked_add(counters.bytes_examined, 1, ResourceKind::StateVisits)?;
                            if !ranges
                                .iter()
                                .any(|&(start, end)| start <= byte && byte <= end)
                            {
                                break;
                            }
                            pc = *next;
                            at = at
                                .checked_add(1)
                                .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
                        }
                        State::Split { first, second } => {
                            frames.push(Frame::Step { pc: *second, at });
                            counters.peak_frames = counters.peak_frames.max(frames.len());
                            pc = *first;
                        }
                        State::Save { slot, next } => {
                            let target = slots.get_mut(*slot).ok_or(SearchError::InvalidProgram)?;
                            frames.push(Frame::Restore {
                                slot: *slot,
                                offset: *target,
                            });
                            counters.peak_frames = counters.peak_frames.max(frames.len());
                            *target = Some(at);
                            counters.slot_copies =
                                checked_add(counters.slot_copies, 1, ResourceKind::SlotCopies)?;
                            check(
                                ResourceKind::SlotCopies,
                                counters.slot_copies,
                                limits.max_slot_copies,
                            )?;
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
                },
            }
        }
        Ok(false)
    }
}

fn insert_visited(
    visited: &mut [usize],
    state_len: usize,
    stride: usize,
    from: usize,
    pc: usize,
    at: usize,
) -> Result<bool, SearchError> {
    if pc >= state_len {
        return Err(SearchError::InvalidProgram);
    }
    let offset = at.checked_sub(from).ok_or(SearchError::InvalidProgram)?;
    if offset >= stride {
        return Err(SearchError::InvalidProgram);
    }
    let index = pc
        .checked_mul(stride)
        .and_then(|base| base.checked_add(offset))
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let word_bits = size_of::<usize>()
        .checked_mul(8)
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let word = index
        .checked_div(word_bits)
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let bit = index
        .checked_rem(word_bits)
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let shift =
        u32::try_from(bit).map_err(|_| SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let mask = 1_usize
        .checked_shl(shift)
        .ok_or(SearchError::BoundOverflow(ResourceKind::StateVisits))?;
    let target = visited.get_mut(word).ok_or(SearchError::InvalidProgram)?;
    if *target & mask != 0 {
        return Ok(false);
    }
    *target |= mask;
    Ok(true)
}
