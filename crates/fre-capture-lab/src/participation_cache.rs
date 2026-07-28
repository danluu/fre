//! Fixed-capacity lazy determinization for participation-count streams.
//!
//! The retained state is source independent: ordered consuming program
//! counters plus the two inline participation words. Transition cells are
//! keyed only by that state, the next byte and whether the next boundary is
//! the absolute end. A full cache hands its just-computed ordered frontier to
//! the inline executor at the already-advanced source position. The current
//! operation therefore completes without a cache-induced replay, and the
//! saturated cache is sticky-disabled for later calls.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::inline_always,
    clippy::large_types_passed_by_value,
    reason = "the admitted cache envelope proves arithmetic and packed-field representability; the frozen hot loop deliberately keeps its compiler-elided Copy receipt and forced inlining"
)]

use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactBoxOrUsize, ExactVec};

use crate::ast::Assertion;
use crate::compile::{Program, State};
use crate::stream::{
    CaptureStreamAccounting, CaptureStreamError, CaptureStreamOperationProspective,
    CaptureStreamResource,
};

const BYTE_ALPHABET: usize = 256;
const BOUNDARY_ALPHABET: usize = BYTE_ALPHABET * 2;
const MAX_CACHE_STATES: usize = 256;
const MAX_CACHE_ITEMS: usize = 1 << 16;
const CELL_UNFILLED: u32 = u32::MAX;
const INITIAL_CONTEXTS: usize = 4;
const INITIAL_CONTEXT_PAIRS: usize = INITIAL_CONTEXTS * (INITIAL_CONTEXTS - 1) / 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ParticipationCacheShape {
    pub(crate) states: usize,
    pub(crate) cells: usize,
    pub(crate) items: usize,
    pub(crate) bytes: usize,
    pub(crate) allocations: usize,
    pub(crate) build_work: usize,
}

impl ParticipationCacheShape {
    pub(crate) fn for_program(
        program: &Program,
        source_bytes: usize,
    ) -> Result<Self, CaptureStreamError> {
        let program_states = program.states.len();
        if program.groups.len() > 64
            || program_states == 0
            || program_states > u32::MAX as usize
            || program_states > MAX_CACHE_ITEMS
            || program.states.iter().any(|state| {
                matches!(
                    state,
                    State::Assert {
                        assertion: Assertion::StartLf
                            | Assertion::EndLf
                            | Assertion::StartLine(_)
                            | Assertion::EndLine(_)
                            | Assertion::StartCrlf
                            | Assertion::EndCrlf
                            | Assertion::WordAscii
                            | Assertion::WordAsciiNegate
                            | Assertion::WordStartAscii
                            | Assertion::WordEndAscii
                            | Assertion::WordStartHalfAscii
                            | Assertion::WordEndHalfAscii
                            | Assertion::WordUnicode
                            | Assertion::WordUnicodeNegate
                            | Assertion::WordStartUnicode
                            | Assertion::WordEndUnicode
                            | Assertion::WordStartHalfUnicode
                            | Assertion::WordEndHalfUnicode,
                        ..
                    }
                )
            })
        {
            return Ok(Self::default());
        }
        Self::for_dimensions(program_states, source_bytes)
    }

    pub(crate) fn for_dimensions(
        program_states: usize,
        source_bytes: usize,
    ) -> Result<Self, CaptureStreamError> {
        let states = source_bytes
            .checked_add(4)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::PersistentBytes,
            ))?
            .clamp(4, MAX_CACHE_STATES);
        let cells = states
            .checked_mul(BOUNDARY_ALPHABET)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::PersistentBytes,
            ))?;
        Self::from_cells(program_states, cells)
    }

    pub(crate) fn from_cells(
        program_states: usize,
        cells: usize,
    ) -> Result<Self, CaptureStreamError> {
        if cells == 0 {
            return Ok(Self::default());
        }
        if !cells.is_multiple_of(BOUNDARY_ALPHABET) {
            return Err(CaptureStreamError::InvalidProgram);
        }
        let states = cells / BOUNDARY_ALPHABET;
        if !(4..=MAX_CACHE_STATES).contains(&states)
            || program_states == 0
            || program_states > MAX_CACHE_ITEMS
        {
            return Err(CaptureStreamError::InvalidProgram);
        }
        let items = program_states
            .checked_mul(states)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::PersistentBytes,
            ))?
            .min(MAX_CACHE_ITEMS)
            .max(program_states);
        let bytes = cache_bytes(program_states, states, cells, items)?;
        // One exact box retains the cache metadata without inflating every
        // public receipt that embeds a prepared capture stream.
        let allocations = 8;
        let build_work = cache_build_work(program_states, states, cells, items, allocations)?;
        Ok(Self {
            states,
            cells,
            items,
            bytes,
            allocations,
            build_work,
        })
    }

    pub(crate) fn closes(self, program_states: usize) -> bool {
        if self == Self::default() {
            return true;
        }
        if self.states < 4 || self.states > MAX_CACHE_STATES || program_states > MAX_CACHE_ITEMS {
            return false;
        }
        let expected_cells = self.states.checked_mul(BOUNDARY_ALPHABET);
        let expected_items = program_states
            .checked_mul(self.states)
            .map(|items| items.min(MAX_CACHE_ITEMS).max(program_states));
        let expected_bytes = cache_bytes(program_states, self.states, self.cells, self.items).ok();
        let expected_build_work =
            cache_build_work(program_states, self.states, self.cells, self.items, 8).ok();
        expected_cells == Some(self.cells)
            && expected_items == Some(self.items)
            && expected_bytes == Some(self.bytes)
            && self.allocations == 8
            && expected_build_work == Some(self.build_work)
    }
}

fn cache_build_work(
    program_states: usize,
    cache_states: usize,
    cells: usize,
    items: usize,
    allocations: usize,
) -> Result<usize, CaptureStreamError> {
    let initialized = cells
        .checked_add(cache_states)
        .and_then(|value| value.checked_add(program_states))
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::BuildWork,
        ))?;
    // Each of the four absolute start/end contexts may visit the complete
    // program. Interning those closures additionally compares each context
    // with every preceding context (one metadata comparison plus at most one
    // complete frontier comparison) and copies at most four complete
    // frontiers into the fixed item arena. Four metadata records are then
    // published. This is deliberately a conservative source-free bound: a
    // duplicate context or an early full arena only reduces the actual work.
    let closure_visits =
        program_states
            .checked_mul(INITIAL_CONTEXTS)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::BuildWork,
            ))?;
    let interner_comparisons = program_states
        .checked_add(1)
        .and_then(|per_pair| per_pair.checked_mul(INITIAL_CONTEXT_PAIRS))
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::BuildWork,
        ))?;
    let maximum_initial_items =
        program_states
            .checked_mul(INITIAL_CONTEXTS)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::BuildWork,
            ))?;
    let retained_item_copies = items.min(maximum_initial_items);
    initialized
        .checked_add(closure_visits)
        .and_then(|value| value.checked_add(interner_comparisons))
        .and_then(|value| value.checked_add(retained_item_copies))
        .and_then(|value| value.checked_add(INITIAL_CONTEXTS))
        .and_then(|value| value.checked_add(allocations))
        .and_then(|value| value.checked_add(1))
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::BuildWork,
        ))
}

fn cache_bytes(
    program_states: usize,
    cache_states: usize,
    cells: usize,
    items: usize,
) -> Result<usize, CaptureStreamError> {
    cells
        .checked_mul(size_of::<CacheCell>())
        .and_then(|value| {
            cache_states
                .checked_mul(size_of::<CacheStateMeta>())
                .and_then(|bytes| value.checked_add(bytes))
        })
        .and_then(|value| {
            items
                .checked_mul(size_of::<CacheThread>())
                .and_then(|bytes| value.checked_add(bytes))
        })
        .and_then(|value| {
            program_states
                .checked_mul(size_of::<CacheThread>())
                .and_then(|bytes| bytes.checked_mul(3))
                .and_then(|bytes| value.checked_add(bytes))
        })
        .and_then(|value| {
            program_states
                .checked_mul(size_of::<usize>())
                .and_then(|bytes| value.checked_add(bytes))
        })
        .and_then(|value| value.checked_add(size_of::<ParticipationDfa>()))
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::PersistentBytes,
        ))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CacheThread {
    pc: u32,
    open: u64,
    participated: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CacheStateMeta {
    offset: usize,
    length: u32,
    pending: bool,
}

#[derive(Clone, Copy, Debug)]
struct CacheCell {
    packed_delta: u64,
    control: u64,
}

impl Default for CacheCell {
    fn default() -> Self {
        Self {
            packed_delta: 0,
            control: u64::from(CELL_UNFILLED),
        }
    }
}

impl CacheCell {
    fn new(
        next: u32,
        packed_delta: u64,
        peak_threads: u32,
        participating: u8,
    ) -> Result<Self, CaptureStreamError> {
        if peak_threads > 0x00ff_ffff {
            return Err(CaptureStreamError::InvalidProgram);
        }
        Ok(Self {
            packed_delta,
            control: u64::from(next)
                | (u64::from(participating) << 32)
                | (u64::from(peak_threads) << 40),
        })
    }

    #[inline]
    fn next(self) -> u32 {
        self.control as u32
    }

    #[inline]
    fn participating(self) -> u8 {
        (self.control >> 32) as u8
    }

    #[inline]
    fn peak_threads(self) -> u32 {
        (self.control >> 40) as u32
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct InitialState {
    next: u32,
    packed_delta: u64,
    peak_threads: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct CacheDelta {
    state_visits: u32,
    tag_actions: u32,
    peak_threads: u32,
    starts_injected: u8,
}

impl CacheDelta {
    fn visit(&mut self) -> Result<(), CaptureStreamError> {
        self.state_visits =
            self.state_visits
                .checked_add(1)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::StateVisits,
                ))?;
        Ok(())
    }

    fn tag(&mut self) -> Result<(), CaptureStreamError> {
        self.tag_actions = self
            .tag_actions
            .checked_add(1)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::TagActions,
            ))?;
        Ok(())
    }

    fn start(&mut self) -> Result<(), CaptureStreamError> {
        self.starts_injected =
            self.starts_injected
                .checked_add(1)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::StartsInjected,
                ))?;
        Ok(())
    }

    fn observe_peak(&mut self, peak: usize) -> Result<(), CaptureStreamError> {
        self.peak_threads = self.peak_threads.max(to_u32(peak)?);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct DeltaLayout {
    tag_shift: u32,
    starts_shift: u32,
    state_mask: u64,
    tag_mask: u64,
    starts_mask: u64,
}

impl DeltaLayout {
    fn for_operation(operation: CaptureStreamOperationProspective) -> Option<Self> {
        let state_bits = bits_needed(operation.state_visits);
        let tag_bits = bits_needed(operation.tag_actions);
        let starts_bits = bits_needed(operation.starts_injected);
        let tag_shift = state_bits;
        let starts_shift = state_bits.checked_add(tag_bits)?;
        let total = starts_shift.checked_add(starts_bits)?;
        if total > 64 {
            return None;
        }
        Some(Self {
            tag_shift,
            starts_shift,
            state_mask: low_mask(state_bits),
            tag_mask: low_mask(tag_bits),
            starts_mask: low_mask(starts_bits),
        })
    }

    fn pack(self, delta: CacheDelta) -> Result<u64, CaptureStreamError> {
        let state_visits = u64::from(delta.state_visits);
        let tag_actions = u64::from(delta.tag_actions);
        let starts_injected = u64::from(delta.starts_injected);
        if state_visits > self.state_mask
            || tag_actions > self.tag_mask
            || starts_injected > self.starts_mask
        {
            return Err(CaptureStreamError::InvalidProgram);
        }
        Ok(state_visits | (tag_actions << self.tag_shift) | (starts_injected << self.starts_shift))
    }

    fn unpack(self, packed: u64) -> (usize, usize, usize) {
        (
            (packed & self.state_mask) as usize,
            ((packed >> self.tag_shift) & self.tag_mask) as usize,
            ((packed >> self.starts_shift) & self.starts_mask) as usize,
        )
    }
}

#[derive(Debug, Default)]
struct CacheAccounting {
    packed_delta: u64,
    peak_threads: u32,
    bytes_examined: usize,
    searches: usize,
}

impl CacheAccounting {
    #[inline]
    fn add_delta(&mut self, packed_delta: u64, peak_threads: u32) {
        self.packed_delta += packed_delta;
        self.peak_threads = self.peak_threads.max(peak_threads);
    }

    #[inline]
    fn add_search(&mut self) {
        self.searches += 1;
    }

    #[inline]
    fn add_byte(&mut self) {
        self.bytes_examined += 1;
    }
}

#[derive(Debug)]
pub(crate) struct ParticipationCache {
    storage: ExactBoxOrUsize<ParticipationDfa>,
}

impl ParticipationCache {
    pub(crate) fn disabled() -> Self {
        let Ok(storage) = ExactBoxOrUsize::try_from_usize(0) else {
            unreachable!("zero is always representable by ExactBoxOrUsize");
        };
        Self { storage }
    }

    pub(crate) fn new(
        program: &Program,
        source_bytes: usize,
        operation: CaptureStreamOperationProspective,
    ) -> Result<Self, CaptureStreamError> {
        let shape = ParticipationCacheShape::for_program(program, source_bytes)?;
        if shape == ParticipationCacheShape::default() {
            return Ok(Self::disabled());
        }
        let delta_layout = DeltaLayout::for_operation(operation);
        let mut dfa = ParticipationDfa::allocate(shape, program.states.len(), delta_layout)?;
        if delta_layout.is_some() {
            dfa.initialize(program)?;
        }
        Ok(Self {
            storage: ExactBoxOrUsize::try_from_boxed(dfa).map_err(map_box_error)?,
        })
    }

    #[inline]
    pub(crate) fn count_value(
        &mut self,
        program: &Program,
        haystack: &[u8],
        groups: usize,
        operation: CaptureStreamOperationProspective,
    ) -> Option<Result<usize, CaptureStreamError>> {
        let dfa = self.storage.boxed_mut()?;
        if !dfa.admitted || dfa.saturated {
            return None;
        }
        let result = dfa.reduce(program, haystack, groups, operation);
        Some(result)
    }
}

#[derive(Debug)]
pub(crate) struct ParticipationDfa {
    rows: ExactVec<CacheCell>,
    states: ExactVec<CacheStateMeta>,
    items: ExactVec<CacheThread>,
    scratch: ExactVec<CacheThread>,
    frontier: ExactVec<CacheThread>,
    stack: ExactVec<CacheThread>,
    seen: ExactVec<usize>,
    state_len: usize,
    item_len: usize,
    scratch_len: usize,
    frontier_len: usize,
    generation: usize,
    initial: [InitialState; 4],
    delta_layout: Option<DeltaLayout>,
    admitted: bool,
    saturated: bool,
}

impl ParticipationDfa {
    fn allocate(
        shape: ParticipationCacheShape,
        program_states: usize,
        delta_layout: Option<DeltaLayout>,
    ) -> Result<Self, CaptureStreamError> {
        Ok(Self {
            rows: allocated_slots(shape.cells, CacheCell::default())?,
            states: allocated_slots(shape.states, CacheStateMeta::default())?,
            items: exact_vec(shape.items)?,
            scratch: exact_vec(program_states)?,
            frontier: exact_vec(program_states)?,
            stack: exact_vec(program_states)?,
            seen: allocated_slots(program_states, 0_usize)?,
            state_len: 0,
            item_len: 0,
            scratch_len: 0,
            frontier_len: 0,
            generation: 0,
            initial: [InitialState::default(); 4],
            delta_layout,
            admitted: false,
            saturated: false,
        })
    }

    fn initialize(&mut self, program: &Program) -> Result<(), CaptureStreamError> {
        let mut admitted = true;
        for context in 0..4 {
            self.begin_closure()?;
            let mut delta = CacheDelta::default();
            delta.start()?;
            let accepted = self.expand(
                program,
                CacheThread {
                    pc: to_u32(program.start)?,
                    open: 0,
                    participated: 0,
                },
                BoundaryContext {
                    at_start: context & 1 != 0,
                    at_end: context & 2 != 0,
                },
                &mut delta,
            )?;
            if accepted.is_some() {
                admitted = false;
            }
            let next = if self.scratch_len == 0 {
                0
            } else {
                match self.intern_scratch(false)? {
                    Interned::State(state) => encode_state(state)?,
                    Interned::Full => {
                        admitted = false;
                        0
                    }
                }
            };
            self.initial[context] = InitialState {
                next,
                packed_delta: self
                    .delta_layout
                    .ok_or(CaptureStreamError::InvalidProgram)?
                    .pack(delta)?,
                peak_threads: delta.peak_threads,
            };
        }
        self.admitted = admitted;
        Ok(())
    }

    fn begin_closure(&mut self) -> Result<(), CaptureStreamError> {
        self.scratch.clear();
        self.scratch_len = 0;
        self.stack.clear();
        if self.generation == usize::MAX {
            return Err(CaptureStreamError::Overflow(
                CaptureStreamResource::Generation,
            ));
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::Generation,
            ))?;
        Ok(())
    }

    fn state_bounds(&self, state: u32) -> Result<(usize, usize, bool), CaptureStreamError> {
        let state = usize::try_from(state).map_err(|_| CaptureStreamError::InvalidProgram)?;
        if state >= self.state_len {
            return Err(CaptureStreamError::InvalidProgram);
        }
        let meta = *self
            .states
            .get(state)
            .ok_or(CaptureStreamError::InvalidProgram)?;
        let length =
            usize::try_from(meta.length).map_err(|_| CaptureStreamError::InvalidProgram)?;
        let end = meta
            .offset
            .checked_add(length)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::PersistentBytes,
            ))?;
        if end > self.item_len || end > self.items.len() {
            return Err(CaptureStreamError::InvalidProgram);
        }
        Ok((meta.offset, length, meta.pending))
    }

    fn item(&self, state: u32, ordinal: usize) -> Result<CacheThread, CaptureStreamError> {
        let (offset, length, _) = self.state_bounds(state)?;
        if ordinal >= length {
            return Err(CaptureStreamError::InvalidProgram);
        }
        self.items
            .get(offset + ordinal)
            .copied()
            .ok_or(CaptureStreamError::InvalidProgram)
    }

    #[inline(always)]
    fn cell(&self, row: u32, byte: u8, at_end: bool) -> Result<CacheCell, CaptureStreamError> {
        let symbol = usize::from(byte) + usize::from(at_end) * BYTE_ALPHABET;
        let index = row as usize + symbol;
        self.rows
            .get(index)
            .copied()
            .ok_or(CaptureStreamError::InvalidProgram)
    }

    #[inline(always)]
    fn set_cell(
        &mut self,
        row: u32,
        byte: u8,
        at_end: bool,
        cell: CacheCell,
    ) -> Result<(), CaptureStreamError> {
        let symbol = usize::from(byte) + usize::from(at_end) * BYTE_ALPHABET;
        let index = usize::try_from(row)
            .ok()
            .and_then(|row| row.checked_add(symbol))
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::PersistentBytes,
            ))?;
        *self
            .rows
            .get_mut(index)
            .ok_or(CaptureStreamError::InvalidProgram)? = cell;
        Ok(())
    }

    fn intern_scratch(&mut self, pending: bool) -> Result<Interned, CaptureStreamError> {
        for state in 0..self.state_len {
            let meta = *self
                .states
                .get(state)
                .ok_or(CaptureStreamError::InvalidProgram)?;
            if meta.pending != pending {
                continue;
            }
            let length =
                usize::try_from(meta.length).map_err(|_| CaptureStreamError::InvalidProgram)?;
            if length != self.scratch_len {
                continue;
            }
            let end = meta
                .offset
                .checked_add(length)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::PersistentBytes,
                ))?;
            let retained = self
                .items
                .get(meta.offset..end)
                .ok_or(CaptureStreamError::InvalidProgram)?;
            if retained == self.scratch.as_slice() {
                return Ok(Interned::State(to_u32(state)?));
            }
        }
        if self.state_len == self.states.len() {
            return Ok(Interned::Full);
        }
        let end =
            self.item_len
                .checked_add(self.scratch_len)
                .ok_or(CaptureStreamError::Overflow(
                    CaptureStreamResource::PersistentBytes,
                ))?;
        if end > self.items.capacity() {
            return Ok(Interned::Full);
        }
        for thread in self.scratch.as_slice().iter().copied() {
            exact_push(&mut self.items, thread)?;
        }
        let state = self.state_len;
        *self
            .states
            .get_mut(state)
            .ok_or(CaptureStreamError::InvalidProgram)? = CacheStateMeta {
            offset: self.item_len,
            length: to_u32(self.scratch_len)?,
            pending,
        };
        self.item_len = end;
        self.state_len = self
            .state_len
            .checked_add(1)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::PersistentBytes,
            ))?;
        Ok(Interned::State(to_u32(state)?))
    }

    fn retain_scratch_as_frontier(&mut self) {
        core::mem::swap(&mut self.scratch, &mut self.frontier);
        self.frontier_len = self.scratch_len;
        self.scratch_len = 0;
    }

    #[inline]
    fn load_initial(
        &mut self,
        context: BoundaryContext,
        accounting: &mut CacheAccounting,
    ) -> Result<Option<ForwardState>, CaptureStreamError> {
        let initial = self.initial[context.index()];
        accounting.add_delta(initial.packed_delta, initial.peak_threads);
        if initial.next == 0 {
            return Ok(None);
        }
        let row = decode_state(initial.next)?;
        if !self.saturated {
            return Ok(Some(ForwardState::Cached(row)));
        }
        let state = state_from_row(row)?;
        let (offset, length, pending) = self.state_bounds(state)?;
        self.frontier.clear();
        for index in offset..offset + length {
            exact_push(
                &mut self.frontier,
                *self
                    .items
                    .get(index)
                    .ok_or(CaptureStreamError::InvalidProgram)?,
            )?;
        }
        self.frontier_len = length;
        Ok(Some(ForwardState::Inline { pending }))
    }

    #[allow(
        clippy::if_not_else,
        clippy::redundant_else,
        clippy::too_many_lines,
        reason = "the value-only reduction keeps the cached-success fast path, exact counter transaction, and current-position handoff together"
    )]
    fn reduce(
        &mut self,
        program: &Program,
        haystack: &[u8],
        groups: usize,
        operation: CaptureStreamOperationProspective,
    ) -> Result<usize, CaptureStreamError> {
        if groups == 0 || groups > 64 {
            return Err(CaptureStreamError::InvalidProgram);
        }
        let delta_layout = self
            .delta_layout
            .ok_or(CaptureStreamError::InvalidProgram)?;
        let mut accounting = CacheAccounting::default();
        let mut count = 0_usize;
        let mut matches = 0_usize;
        let mut cursor = 0_usize;
        loop {
            accounting.add_search();
            let initial_context = BoundaryContext {
                at_start: cursor == 0,
                at_end: cursor == haystack.len(),
            };
            let Some(mut state) = self.load_initial(initial_context, &mut accounting)? else {
                break;
            };
            let mut position = cursor;
            let mut pending_end = None;
            let mut pending_count = None;
            let selected = 'scan: loop {
                if position == haystack.len() {
                    break pending_count.zip(pending_end);
                }
                accounting.add_byte();
                let byte = haystack[position];
                let next_position = position + 1;
                let at_end = next_position == haystack.len();
                let transition = match state {
                    ForwardState::Cached(row) => {
                        let cached = self.cell(row, byte, at_end)?;
                        if cached.next() != CELL_UNFILLED {
                            accounting.add_delta(cached.packed_delta, cached.peak_threads());
                            position = next_position;
                            let participating = cached.participating();
                            if participating != 0 {
                                pending_count = Some(usize::from(participating));
                                pending_end = Some(position);
                            }
                            let next = cached.next();
                            if next == 0 {
                                break 'scan pending_count.zip(pending_end);
                            }
                            state = ForwardState::Cached(next - 1);
                            continue;
                        } else {
                            self.populate_transition(program, row, byte, at_end, &mut accounting)?
                        }
                    }
                    ForwardState::Inline { pending } => {
                        self.inline_transition(program, byte, at_end, pending, &mut accounting)?
                    }
                };
                position = next_position;
                if let Some(participating) = transition.participating {
                    pending_count = Some(usize::from(participating));
                    pending_end = Some(position);
                }
                let Some(next) = transition.next else {
                    break 'scan pending_count.zip(pending_end);
                };
                state = next;
            };
            let Some((participating, end)) = selected else {
                break;
            };
            if end <= cursor || end > haystack.len() || participating == 0 {
                return Err(CaptureStreamError::InvalidProgram);
            }
            let next_matches = matches
                .checked_add(1)
                .ok_or(CaptureStreamError::Overflow(CaptureStreamResource::Matches))?;
            let next_count =
                count
                    .checked_add(participating)
                    .ok_or(CaptureStreamError::Overflow(
                        CaptureStreamResource::CaptureCount,
                    ))?;
            matches = next_matches;
            count = next_count;
            cursor = end;
        }
        finish_accounting(accounting, count, matches, groups, delta_layout, operation)?;
        Ok(count)
    }

    #[cold]
    fn populate_transition(
        &mut self,
        program: &Program,
        row: u32,
        byte: u8,
        at_end: bool,
        accounting: &mut CacheAccounting,
    ) -> Result<Transition, CaptureStreamError> {
        let state = state_from_row(row)?;
        let (_, length, pending) = self.state_bounds(state)?;
        self.begin_closure()?;
        let mut delta = CacheDelta::default();
        let mut accepted = None;
        for ordinal in 0..length {
            let thread = self.item(state, ordinal)?;
            let State::Byte {
                ranges,
                next: target,
            } = program
                .states
                .get(usize::try_from(thread.pc).map_err(|_| CaptureStreamError::InvalidProgram)?)
                .ok_or(CaptureStreamError::InvalidProgram)?
            else {
                return Err(CaptureStreamError::InvalidProgram);
            };
            if ranges
                .iter()
                .any(|&(start, end)| start <= byte && byte <= end)
            {
                accepted = self.expand(
                    program,
                    CacheThread {
                        pc: to_u32(*target)?,
                        open: thread.open,
                        participated: thread.participated,
                    },
                    BoundaryContext {
                        at_start: false,
                        at_end,
                    },
                    &mut delta,
                )?;
                if accepted.is_some() {
                    break;
                }
            }
        }
        if accepted.is_none() && !pending {
            delta.start()?;
            accepted = self.expand(
                program,
                CacheThread {
                    pc: to_u32(program.start)?,
                    open: 0,
                    participated: 0,
                },
                BoundaryContext {
                    at_start: false,
                    at_end,
                },
                &mut delta,
            )?;
        }
        delta.observe_peak(
            self.scratch_len
                .saturating_add(usize::from(accepted.is_some())),
        )?;
        let packed_delta = self
            .delta_layout
            .ok_or(CaptureStreamError::InvalidProgram)?
            .pack(delta)?;
        accounting.add_delta(packed_delta, delta.peak_threads);
        let next_pending = pending || accepted.is_some();
        let next = if self.scratch_len == 0 {
            0
        } else {
            match self.intern_scratch(next_pending)? {
                Interned::State(next) => encode_state(next)?,
                Interned::Full => {
                    self.saturated = true;
                    self.retain_scratch_as_frontier();
                    return Ok(Transition {
                        participating: accepted,
                        next: Some(ForwardState::Inline {
                            pending: next_pending,
                        }),
                    });
                }
            }
        };
        let cell = CacheCell::new(
            next,
            packed_delta,
            delta.peak_threads,
            accepted.unwrap_or(0),
        )?;
        self.set_cell(row, byte, at_end, cell)?;
        decode_transition(cell)
    }

    fn inline_transition(
        &mut self,
        program: &Program,
        byte: u8,
        at_end: bool,
        pending: bool,
        accounting: &mut CacheAccounting,
    ) -> Result<Transition, CaptureStreamError> {
        let length = self.frontier_len;
        self.begin_closure()?;
        let mut delta = CacheDelta::default();
        let mut accepted = None;
        for ordinal in 0..length {
            let thread = *self
                .frontier
                .get(ordinal)
                .ok_or(CaptureStreamError::InvalidProgram)?;
            let State::Byte {
                ranges,
                next: target,
            } = program
                .states
                .get(usize::try_from(thread.pc).map_err(|_| CaptureStreamError::InvalidProgram)?)
                .ok_or(CaptureStreamError::InvalidProgram)?
            else {
                return Err(CaptureStreamError::InvalidProgram);
            };
            if ranges
                .iter()
                .any(|&(start, end)| start <= byte && byte <= end)
            {
                accepted = self.expand(
                    program,
                    CacheThread {
                        pc: to_u32(*target)?,
                        open: thread.open,
                        participated: thread.participated,
                    },
                    BoundaryContext {
                        at_start: false,
                        at_end,
                    },
                    &mut delta,
                )?;
                if accepted.is_some() {
                    break;
                }
            }
        }
        if accepted.is_none() && !pending {
            delta.start()?;
            accepted = self.expand(
                program,
                CacheThread {
                    pc: to_u32(program.start)?,
                    open: 0,
                    participated: 0,
                },
                BoundaryContext {
                    at_start: false,
                    at_end,
                },
                &mut delta,
            )?;
        }
        delta.observe_peak(
            self.scratch_len
                .saturating_add(usize::from(accepted.is_some())),
        )?;
        let packed_delta = self
            .delta_layout
            .ok_or(CaptureStreamError::InvalidProgram)?
            .pack(delta)?;
        accounting.add_delta(packed_delta, delta.peak_threads);
        let next_pending = pending || accepted.is_some();
        if self.scratch_len == 0 {
            self.frontier.clear();
            self.frontier_len = 0;
            return Ok(Transition {
                participating: accepted,
                next: None,
            });
        }
        self.retain_scratch_as_frontier();
        Ok(Transition {
            participating: accepted,
            next: Some(ForwardState::Inline {
                pending: next_pending,
            }),
        })
    }

    fn expand(
        &mut self,
        program: &Program,
        initial: CacheThread,
        boundary: BoundaryContext,
        delta: &mut CacheDelta,
    ) -> Result<Option<u8>, CaptureStreamError> {
        self.stack.clear();
        exact_push(&mut self.stack, initial)?;
        while let Some(mut thread) = self.stack.pop() {
            delta.visit()?;
            let pc = usize::try_from(thread.pc).map_err(|_| CaptureStreamError::InvalidProgram)?;
            let mark = self
                .seen
                .get_mut(pc)
                .ok_or(CaptureStreamError::InvalidProgram)?;
            if *mark == self.generation {
                continue;
            }
            *mark = self.generation;
            match program
                .states
                .get(pc)
                .ok_or(CaptureStreamError::InvalidProgram)?
            {
                State::Byte { .. } => exact_push(&mut self.scratch, thread)?,
                State::Match => {
                    self.scratch_len = self.scratch.len();
                    if thread.open != 0 || thread.participated & 1 == 0 {
                        return Err(CaptureStreamError::InvalidProgram);
                    }
                    let participating = u8::try_from(thread.participated.count_ones())
                        .map_err(|_| CaptureStreamError::InvalidProgram)?;
                    if participating == 0 {
                        return Err(CaptureStreamError::InvalidProgram);
                    }
                    delta.observe_peak(self.scratch.len().checked_add(1).ok_or(
                        CaptureStreamError::Overflow(CaptureStreamResource::StateVisits),
                    )?)?;
                    return Ok(Some(participating));
                }
                State::Fail => {}
                State::Epsilon { next } => {
                    thread.pc = to_u32(*next)?;
                    exact_push(&mut self.stack, thread)?;
                }
                State::Assert { assertion, next } => {
                    let matches = match assertion {
                        Assertion::Start => boundary.at_start,
                        Assertion::End => boundary.at_end,
                        _ => return Err(CaptureStreamError::InvalidProgram),
                    };
                    if matches {
                        thread.pc = to_u32(*next)?;
                        exact_push(&mut self.stack, thread)?;
                    }
                }
                State::Save { slot, next } => {
                    let group = slot / 2;
                    if group >= 64 || group >= program.groups.len() {
                        return Err(CaptureStreamError::InvalidProgram);
                    }
                    let bit = 1_u64
                        .checked_shl(
                            u32::try_from(group).map_err(|_| CaptureStreamError::InvalidProgram)?,
                        )
                        .ok_or(CaptureStreamError::InvalidProgram)?;
                    if slot.is_multiple_of(2) {
                        if thread.open & bit != 0 {
                            return Err(CaptureStreamError::InvalidProgram);
                        }
                        thread.open |= bit;
                    } else {
                        if thread.open & bit == 0 {
                            return Err(CaptureStreamError::InvalidProgram);
                        }
                        thread.open &= !bit;
                        thread.participated |= bit;
                    }
                    delta.tag()?;
                    thread.pc = to_u32(*next)?;
                    exact_push(&mut self.stack, thread)?;
                }
                State::Split { first, second } => {
                    exact_push(
                        &mut self.stack,
                        CacheThread {
                            pc: to_u32(*second)?,
                            ..thread
                        },
                    )?;
                    thread.pc = to_u32(*first)?;
                    exact_push(&mut self.stack, thread)?;
                }
            }
        }
        delta.observe_peak(self.scratch.len())?;
        self.scratch_len = self.scratch.len();
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug)]
enum Interned {
    State(u32),
    Full,
}

#[derive(Clone, Copy, Debug)]
enum ForwardState {
    Cached(u32),
    Inline { pending: bool },
}

#[derive(Clone, Copy, Debug)]
struct Transition {
    participating: Option<u8>,
    next: Option<ForwardState>,
}

#[inline(always)]
fn decode_transition(cell: CacheCell) -> Result<Transition, CaptureStreamError> {
    let next = cell.next();
    if next == CELL_UNFILLED {
        return Err(CaptureStreamError::InvalidProgram);
    }
    Ok(Transition {
        participating: (cell.participating() != 0).then_some(cell.participating()),
        next: if next == 0 {
            None
        } else {
            Some(ForwardState::Cached(decode_state(next)?))
        },
    })
}

#[derive(Clone, Copy, Debug)]
struct BoundaryContext {
    at_start: bool,
    at_end: bool,
}

impl BoundaryContext {
    fn index(self) -> usize {
        usize::from(self.at_start) | (usize::from(self.at_end) << 1)
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "terminal closure consumes the operation-local accounting ledger"
)]
fn finish_accounting(
    cache: CacheAccounting,
    count: usize,
    matches: usize,
    groups: usize,
    delta_layout: DeltaLayout,
    operation: CaptureStreamOperationProspective,
) -> Result<CaptureStreamAccounting, CaptureStreamError> {
    let (state_visits, tag_actions, starts_injected) = delta_layout.unpack(cache.packed_delta);
    let capture_events = groups
        .checked_mul(matches)
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::CaptureEvents,
        ))?;
    let mask_word_reads = matches.checked_mul(3).ok_or(CaptureStreamError::Overflow(
        CaptureStreamResource::MaskWordReads,
    ))?;
    let reset_per_search = groups
        .checked_mul(2)
        .and_then(|slots| slots.checked_add(slots.div_ceil(64)))
        .ok_or(CaptureStreamError::Overflow(
            CaptureStreamResource::ResetCells,
        ))?;
    let reset_cells =
        reset_per_search
            .checked_mul(cache.searches)
            .ok_or(CaptureStreamError::Overflow(
                CaptureStreamResource::ResetCells,
            ))?;
    let expected_searches = matches.checked_add(1).ok_or(CaptureStreamError::Overflow(
        CaptureStreamResource::Searches,
    ))?;
    let work = 1_usize
        .checked_add(cache.searches)
        .and_then(|value| value.checked_add(state_visits))
        .and_then(|value| value.checked_add(tag_actions))
        .and_then(|value| value.checked_add(mask_word_reads))
        .and_then(|value| value.checked_add(reset_cells))
        .and_then(|value| value.checked_add(capture_events))
        .and_then(|value| value.checked_add(cache.bytes_examined))
        .and_then(|value| value.checked_add(starts_injected))
        .ok_or(CaptureStreamError::Overflow(CaptureStreamResource::Work))?;
    if cache.searches != expected_searches
        || count > capture_events
        || operation.line_domains != 1
        || cache.searches > operation.searches
        || matches > operation.matches
        || cache.bytes_examined > operation.bytes_examined
        || starts_injected > operation.starts_injected
        || state_visits > operation.state_visits
        || tag_actions > operation.tag_actions
        || mask_word_reads > operation.mask_word_reads
        || reset_cells > operation.reset_cells
        || capture_events > operation.capture_events
        || count > operation.capture_count
        || work > operation.work
    {
        return Err(CaptureStreamError::InvalidProgram);
    }
    Ok(CaptureStreamAccounting {
        line_domains: 1,
        searches: cache.searches,
        state_visits,
        tag_actions,
        mask_word_reads,
        reset_cells,
        capture_events,
        bytes_examined: cache.bytes_examined,
        starts_injected,
        peak_threads: cache.peak_threads as usize,
        work,
        ..CaptureStreamAccounting::default()
    })
}

fn bits_needed(value: usize) -> u32 {
    (usize::BITS - value.leading_zeros()).max(1)
}

fn low_mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    }
}

fn encode_state(state: u32) -> Result<u32, CaptureStreamError> {
    state
        .checked_mul(
            u32::try_from(BOUNDARY_ALPHABET).map_err(|_| CaptureStreamError::InvalidProgram)?,
        )
        .ok_or(CaptureStreamError::InvalidProgram)?
        .checked_add(1)
        .ok_or(CaptureStreamError::InvalidProgram)
}

fn decode_state(encoded: u32) -> Result<u32, CaptureStreamError> {
    encoded
        .checked_sub(1)
        .ok_or(CaptureStreamError::InvalidProgram)
}

fn state_from_row(row: u32) -> Result<u32, CaptureStreamError> {
    let alphabet =
        u32::try_from(BOUNDARY_ALPHABET).map_err(|_| CaptureStreamError::InvalidProgram)?;
    if !row.is_multiple_of(alphabet) {
        return Err(CaptureStreamError::InvalidProgram);
    }
    Ok(row / alphabet)
}

fn to_u32(value: usize) -> Result<u32, CaptureStreamError> {
    u32::try_from(value).map_err(|_| CaptureStreamError::InvalidProgram)
}

fn map_box_error(error: CopyError) -> CaptureStreamError {
    match error {
        CopyError::LayoutOverflow => {
            CaptureStreamError::Overflow(CaptureStreamResource::PersistentBytes)
        }
        CopyError::AllocationFailed => {
            CaptureStreamError::Allocation(CaptureStreamResource::PersistentBytes)
        }
    }
}

fn exact_vec<T>(capacity: usize) -> Result<ExactVec<T>, CaptureStreamError> {
    ExactVec::try_with_capacity(capacity).map_err(|error| match error {
        CopyError::LayoutOverflow => {
            CaptureStreamError::Overflow(CaptureStreamResource::PersistentBytes)
        }
        CopyError::AllocationFailed => {
            CaptureStreamError::Allocation(CaptureStreamResource::PersistentBytes)
        }
    })
}

fn allocated_slots<T: Copy>(length: usize, value: T) -> Result<ExactVec<T>, CaptureStreamError> {
    let mut output = exact_vec(length)?;
    for _ in 0..length {
        exact_push(&mut output, value)?;
    }
    Ok(output)
}

fn exact_push<T>(storage: &mut ExactVec<T>, value: T) -> Result<(), CaptureStreamError> {
    storage
        .try_push(value)
        .map_err(|_| CaptureStreamError::Resource {
            resource: CaptureStreamResource::PersistentBytes,
            required: storage.len().saturating_add(1),
            limit: storage.capacity(),
        })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        Ast, BuildLimits, CaptureStream, CaptureStreamDomains, CaptureStreamLimits, Greed,
    };

    #[test]
    fn shape_charges_initial_closure_interning_comparisons_and_copies() {
        let program_states = 7;
        let cache_states = INITIAL_CONTEXTS;
        let cells = cache_states * BOUNDARY_ALPHABET;
        let shape =
            ParticipationCacheShape::from_cells(program_states, cells).expect("cache shape");
        let initialized = cells + cache_states + program_states;
        let closure_visits = program_states * INITIAL_CONTEXTS;
        let comparisons = (program_states + 1) * INITIAL_CONTEXT_PAIRS;
        let copies = program_states * INITIAL_CONTEXTS;
        let expected = initialized
            + closure_visits
            + comparisons
            + copies
            + INITIAL_CONTEXTS
            + shape.allocations
            + 1;
        assert_eq!(shape.build_work, expected);
        assert!(shape.closes(program_states));
    }

    fn assert_forced_saturation_preserves_result(ast: &Ast, haystack: &[u8]) {
        let program =
            Arc::new(Program::compile(ast, BuildLimits::default()).expect("forced-cap program"));
        let operation = CaptureStream::operation_prospective(
            &program,
            haystack.len(),
            CaptureStreamDomains::Whole,
        )
        .expect("operation prospective");
        let delta_layout = DeltaLayout::for_operation(operation).expect("compact counter layout");
        // One initial state consumes the entire test-only state arena. The
        // first non-dead byte transition must therefore hand its just-built
        // frontier to the inline continuation at the current source
        // position.
        let states = 1;
        let cells = states * BOUNDARY_ALPHABET;
        let items = program.states.len();
        let shape = ParticipationCacheShape {
            states,
            cells,
            items,
            bytes: cache_bytes(program.states.len(), states, cells, items)
                .expect("forced-cap bytes"),
            allocations: 8,
            build_work: 0,
        };
        let mut dfa = ParticipationDfa::allocate(shape, program.states.len(), Some(delta_layout))
            .expect("forced-cap cache");
        dfa.initialize(&program).expect("initial closures");
        assert!(dfa.admitted, "fixture must admit its initial closure");
        assert!(!dfa.saturated, "fixture must saturate after source starts");
        let mut cache = ParticipationCache {
            storage: ExactBoxOrUsize::try_from_boxed(dfa).expect("forced-cap owner"),
        };

        let mut incumbent = CaptureStream::new(
            Arc::clone(&program),
            haystack.len(),
            CaptureStreamDomains::Whole,
            CaptureStreamLimits::default(),
        )
        .expect("incumbent stream");
        let expected = incumbent
            .execute(haystack)
            .expect("incumbent result")
            .captures
            .count;
        let observed = cache
            .count_value(&program, haystack, program.groups.len(), operation)
            .expect("forced cache selected")
            .expect("forced cache result");
        assert_eq!(observed, expected);
        assert!(
            cache.storage.boxed().is_some_and(|dfa| dfa.saturated),
            "saturation must sticky-disable later cached operations"
        );
        assert!(
            cache
                .count_value(&program, haystack, program.groups.len(), operation)
                .is_none(),
            "sticky disable must select the established executor"
        );
    }

    #[test]
    fn forced_saturation_continues_mid_potential_match_without_replay() {
        let branch = Ast::alt([
            Ast::concat([Ast::Byte(b'a').capture(1), Ast::Byte(b'b')]),
            Ast::Byte(b'a').capture(2),
        ])
        .repeat(1, None, Greed::Greedy);
        let ast = Ast::concat([branch, Ast::Byte(b'z').capture(3)]);
        assert_forced_saturation_preserves_result(&ast, b"ababaz");
    }

    #[test]
    fn forced_saturation_preserves_absolute_start_and_end_context() {
        let ast = Ast::concat([
            Ast::Start,
            Ast::Class(vec![(b'a', b'b')])
                .repeat(1, None, Greed::Greedy)
                .capture(1),
            Ast::Byte(b'a').capture(2).repeat(0, Some(1), Greed::Greedy),
            Ast::End,
        ]);
        assert_forced_saturation_preserves_result(&ast, b"abba");
    }
}
