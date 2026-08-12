//! Short priority-ordered bounded backtracking over the capture program.

use std::mem::size_of;

use memchr::{memchr, memchr2, memchr3};

use crate::compile::{Program, State};
use crate::error::{ResourceKind, SearchError};
use crate::limits::SearchLimits;
use crate::model::{
    BoundedBacktrackProspective, CandidateKind, CaptureRecord, RunReport, SearchOutcome, Window,
};
use crate::runtime::{assertion_matches, canonicalize_unset, check};

/// Smallest source suffix on which the candidate scanner is selected.
const START_BYTE_PREFILTER_MIN_SEARCH_BYTES: usize = 64;
/// Candidate scans observed before effectiveness may disable the scanner.
pub(crate) const START_BYTE_PREFILTER_MIN_SCANS: u32 = 50;
/// Required average forward distance per candidate scan.
pub(crate) const START_BYTE_PREFILTER_MIN_SKIP_BYTES: u32 = 8;

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

#[derive(Clone, Copy, Debug)]
struct CandidatePrefilterState {
    scans: u32,
    advanced: u32,
    effective: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidatePrefilterKind {
    StartByte1,
    StartByte2,
    StartByte3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidatePrefilter {
    kind: CandidatePrefilterKind,
    bytes: [u8; 3],
}

impl CandidatePrefilterState {
    const fn new() -> Self {
        Self {
            scans: 0,
            advanced: 0,
            effective: true,
        }
    }

    #[inline]
    const fn is_effective(self) -> bool {
        self.effective
    }

    #[inline]
    fn update(&mut self, advanced: usize) {
        self.scans = self.scans.saturating_add(1);
        self.advanced = self
            .advanced
            .saturating_add(u32::try_from(advanced).unwrap_or(u32::MAX));
        let alignment_slack = START_BYTE_PREFILTER_MIN_SKIP_BYTES.saturating_sub(1);
        if self.scans >= START_BYTE_PREFILTER_MIN_SCANS
            && self.advanced.saturating_add(alignment_slack)
                < START_BYTE_PREFILTER_MIN_SKIP_BYTES.saturating_mul(self.scans)
        {
            self.effective = false;
        }
    }
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
        debug_assert!(window.end <= haystack.len());
        debug_assert_eq!(self.prospective(window, from, anchored), Ok(prospective));
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

    pub(crate) fn captures_prefiltered(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        prefilter: CandidatePrefilter,
        prospective: BoundedBacktrackProspective,
    ) -> Result<SearchOutcome, SearchError> {
        debug_assert!(window.end <= haystack.len());
        debug_assert_eq!(self.prospective(window, from, false), Ok(prospective));
        debug_assert_eq!(
            self.candidate_prefilter(window, from, false),
            Some(prefilter)
        );
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
        self.captures_with_stack_prefiltered(
            haystack,
            window,
            from,
            prefilter,
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
    #[inline]
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
        clippy::too_many_arguments,
        reason = "the prefiltered route keeps its admitted storage and complete bounded DFS state explicit without perturbing the legacy root loop"
    )]
    #[inline]
    fn captures_with_stack_prefiltered(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        prefilter: CandidatePrefilter,
        prospective: BoundedBacktrackProspective,
        boundaries: usize,
        frames: &mut Vec<Frame>,
        visited: &mut [usize],
        slots: &mut [usize],
        counters: &mut Counters,
    ) -> Result<SearchOutcome, SearchError> {
        let captures = self.captures_candidate_roots(
            haystack, window, from, prefilter, boundaries, frames, visited, slots, counters,
        )?;
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
        reason = "construction proves nonnullability and the complete candidate set; admission bounds the initial root plus every scanned or scalar-backoff root before source access"
    )]
    #[inline]
    fn captures_candidate_roots(
        &self,
        haystack: &[u8],
        window: Window,
        from: usize,
        prefilter: CandidatePrefilter,
        boundaries: usize,
        frames: &mut Vec<Frame>,
        visited: &mut [usize],
        slots: &mut [usize],
        counters: &mut Counters,
    ) -> Result<Option<CaptureRecord>, SearchError> {
        let last_start = window
            .end
            .checked_sub(1)
            .ok_or(SearchError::InvalidProgram)?;
        let mut state = CandidatePrefilterState::new();
        let mut at = from;
        loop {
            if state.is_effective() {
                let remaining = &haystack[at..window.end];
                let Some(relative) = find_candidate(prefilter.kind, prefilter.bytes, remaining)
                else {
                    counters.bytes_examined += remaining.len();
                    return Ok(None);
                };
                counters.bytes_examined += relative + 1;
                state.update(relative + 1);
                at += relative;
            }
            counters.starts_injected += 1;
            frames.push(Frame::step(self.program.start, at));
            counters.peak_frames = counters.peak_frames.max(frames.len());
            if self.backtrack(
                haystack, window, from, boundaries, frames, visited, slots, counters,
            )? {
                return canonicalize_unset(self.program, slots, UNSET_SLOT).map(Some);
            }
            if at == last_start {
                return Ok(None);
            }
            at += 1;
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        clippy::inline_always,
        clippy::too_many_arguments,
        reason = "the two construction-specialized root enumerators must each retain the former single-call-site DFS code generation; source-independent admission proves every counter increment and byte advance"
    )]
    #[inline(always)]
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
                        State::Save { slot, next, .. } => {
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

    #[inline]
    pub(crate) fn candidate_prefilter(
        &self,
        window: Window,
        from: usize,
        anchored: bool,
    ) -> Option<CandidatePrefilter> {
        if anchored {
            return None;
        }
        let search_bytes = window.end.checked_sub(from)?;
        if search_bytes < START_BYTE_PREFILTER_MIN_SEARCH_BYTES {
            return None;
        }
        let (bytes, length) = self.program.start_byte_candidates()?;
        let kind = candidate_prefilter_kind(length)?;
        Some(CandidatePrefilter { kind, bytes })
    }
}

const fn candidate_prefilter_kind(length: usize) -> Option<CandidatePrefilterKind> {
    match length {
        1 => Some(CandidatePrefilterKind::StartByte1),
        2 => Some(CandidatePrefilterKind::StartByte2),
        3 => Some(CandidatePrefilterKind::StartByte3),
        _ => None,
    }
}

#[inline]
fn find_candidate(kind: CandidatePrefilterKind, bytes: [u8; 3], haystack: &[u8]) -> Option<usize> {
    let (&first, rest) = haystack.split_first()?;
    let first_is_candidate = match kind {
        CandidatePrefilterKind::StartByte1 => first == bytes[0],
        CandidatePrefilterKind::StartByte2 => first == bytes[0] || first == bytes[1],
        CandidatePrefilterKind::StartByte3 => {
            first == bytes[0] || first == bytes[1] || first == bytes[2]
        }
    };
    if first_is_candidate {
        return Some(0);
    }
    let relative = match kind {
        CandidatePrefilterKind::StartByte1 => memchr(bytes[0], rest),
        CandidatePrefilterKind::StartByte2 => memchr2(bytes[0], bytes[1], rest),
        CandidatePrefilterKind::StartByte3 => memchr3(bytes[0], bytes[1], bytes[2], rest),
    }?;
    relative.checked_add(1)
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
    use super::{
        BoundedBacktracker, CandidatePrefilterKind, FRAME_INDEX_MASK, Frame,
        START_BYTE_PREFILTER_MIN_SEARCH_BYTES,
    };
    use crate::{Ast, BuildLimits, Program, SearchLimits, Window};
    use std::mem::size_of;

    #[test]
    fn admitted_frame_layout_and_index_ceiling_are_exact() {
        assert_eq!(size_of::<Frame>(), size_of::<(u32, usize)>());
        assert_eq!(FRAME_INDEX_MASK, u32::MAX >> 1);
    }

    #[test]
    fn candidate_route_and_scan_accounting_are_bound_before_source_access() {
        let program = Program::compile(&Ast::Byte(b'a'), BuildLimits::default()).unwrap();
        let backtracker = BoundedBacktracker::new(&program);
        let window = Window {
            start: 3,
            end: 3 + START_BYTE_PREFILTER_MIN_SEARCH_BYTES,
        };
        let prospective = backtracker
            .admit(window, window.start, false, SearchLimits::default())
            .unwrap();
        let prefilter = backtracker
            .candidate_prefilter(window, window.start, false)
            .unwrap();
        assert_eq!(prefilter.kind, CandidatePrefilterKind::StartByte1);
        assert_eq!(
            prospective,
            backtracker.prospective(window, 3, false).unwrap()
        );

        let mut absent = vec![b'x'; window.end];
        let outcome = backtracker
            .captures_prefiltered(&absent, window, window.start, prefilter, prospective)
            .unwrap();
        assert!(outcome.captures.is_none());
        assert_eq!(outcome.report.bytes_examined, window.end - window.start);
        assert!(prospective.closes_report(&outcome.report));

        absent[window.start] = b'a';
        let outcome = backtracker
            .captures_prefiltered(&absent, window, window.start, prefilter, prospective)
            .unwrap();
        assert_eq!(
            outcome.captures.unwrap().overall().unwrap().start,
            window.start
        );
        assert_eq!(outcome.report.bytes_examined, 2);
        assert!(prospective.closes_report(&outcome.report));

        let anchored_prospective = backtracker
            .admit(window, window.start, true, SearchLimits::default())
            .unwrap();
        assert_eq!(
            anchored_prospective,
            backtracker.prospective(window, window.start, true).unwrap()
        );
        assert_eq!(
            backtracker.candidate_prefilter(window, window.start, true),
            None
        );
    }
}
