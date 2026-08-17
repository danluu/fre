//! Persistent ordered lazy DFA for ordinary byte and scalar continuations.
//!
//! A DFA state is an ordered set of consuming Thompson instructions. The
//! ordering is the VM's leftmost-first priority order. A second state bit says
//! that a lower-priority accepting path is pending; while it is set, later
//! start positions are not injected. A transition that reaches `Match` drops
//! that match and every lower-priority thread while retaining higher-priority
//! consuming threads. The pending endpoint becomes final when that retained
//! prefix dies.
//!
//! Selected endpoints are sufficient for Count. SpanSum recovers the selected
//! start with a second, unprioritized reverse lazy DFA. Selected non-overlap
//! intervals are disjoint, so successful reverse walks add at most one extra
//! source pass. Both transition tables belong to the caller workspace and use
//! direct byte indexing after each transition's first observed construction.
//! If either fixed table saturates, the just-computed frontier continues
//! inline from the current position; no source prefix is replayed.

use core::mem::size_of;
use core::ops::Range;

use fre_exact_alloc::{CopyError, ExactVec};

use crate::compile::PlanId;
use crate::error::{add, enforce, mul};
use crate::program::{ByteSet, Inst, Program, ScalarSet, decode_first_scalar};
use crate::{Error, OperationLimits, Resource};

use super::{
    ContinuationSweepRunUpperBounds, ContinuationSweepUpperBounds, SweepKind, SweepMeter,
    SweepOutcome, SweepValue,
};

const BYTE_ALPHABET: usize = 256;
const SCALAR_LEAD_BASE: u8 = 0xC2;
const SCALAR_LEAD_SLOTS: usize = 51;
const DEFERRED_ROW_INITIALIZATION_SLOTS: usize = BYTE_ALPHABET + 3 * SCALAR_LEAD_SLOTS;
const MAX_DFA_STATES: usize = 1_024;
const MAX_DFA_ITEMS: usize = 1 << 20;
const LARGE_DFA_PROGRAM_STATES: usize = 4_096;
const LARGE_DFA_STATES: usize = 8_192;
const LARGE_DFA_ITEMS: usize = 1 << 24;
const CELL_ACCEPT: u32 = 1 << 31;
const CELL_STATE_MASK: u32 = CELL_ACCEPT - 1;
const CELL_UNFILLED: u32 = u32::MAX;
const SCALAR_KEY_NONE: u32 = 0x11_0000;
const SCALAR_KEY_UNFILLED: u32 = u32::MAX;
const NO_STATE: u32 = u32::MAX;
#[cfg(test)]
const FIXED_ARENA_ALLOCATIONS: usize = 28;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheProfile {
    states: usize,
    items: usize,
}

const fn cache_profile(program_states: usize) -> CacheProfile {
    if program_states >= LARGE_DFA_PROGRAM_STATES {
        CacheProfile {
            states: LARGE_DFA_STATES,
            items: LARGE_DFA_ITEMS,
        }
    } else {
        CacheProfile {
            states: MAX_DFA_STATES,
            items: MAX_DFA_ITEMS,
        }
    }
}

#[cfg(test)]
pub(super) mod test_fault {
    use core::cell::Cell;

    std::thread_local! {
        static FAIL_FIXED_ALLOCATION_AFTER: Cell<usize> = const { Cell::new(0) };
        static SOURCE_BYTES: Cell<usize> = const { Cell::new(0) };
        static WORK: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) struct AllocationFailureGuard;

    impl Drop for AllocationFailureGuard {
        fn drop(&mut self) {
            FAIL_FIXED_ALLOCATION_AFTER.with(|remaining| remaining.set(0));
            SOURCE_BYTES.with(|bytes| bytes.set(0));
            WORK.with(|work| work.set(0));
        }
    }

    pub(super) fn fail_fixed_allocation_at(ordinal: usize) -> AllocationFailureGuard {
        assert!(ordinal > 0, "allocation fault ordinal must be positive");
        FAIL_FIXED_ALLOCATION_AFTER.with(|remaining| {
            assert_eq!(
                remaining.replace(ordinal),
                0,
                "allocation fault already armed"
            );
        });
        SOURCE_BYTES.with(|bytes| bytes.set(0));
        WORK.with(|work| work.set(0));
        AllocationFailureGuard
    }

    pub(super) fn take_fixed_allocation_failure() -> bool {
        FAIL_FIXED_ALLOCATION_AFTER.with(|remaining| match remaining.get() {
            0 => false,
            1 => {
                remaining.set(0);
                true
            }
            count => {
                remaining.set(count - 1);
                false
            }
        })
    }

    pub(super) fn fixed_allocation_failure_is_armed() -> bool {
        FAIL_FIXED_ALLOCATION_AFTER.with(|remaining| remaining.get() != 0)
    }

    pub(in crate::sweep) fn record_work(amount: usize) {
        WORK.with(|work| work.set(work.get().saturating_add(amount)));
    }

    pub(in crate::sweep) fn record_source_bytes(amount: usize) {
        SOURCE_BYTES.with(|bytes| bytes.set(bytes.get().saturating_add(amount)));
    }

    pub(super) fn source_bytes() -> usize {
        SOURCE_BYTES.with(Cell::get)
    }

    pub(super) fn work() -> usize {
        WORK.with(Cell::get)
    }
}

#[derive(Debug, Default)]
struct LazyCache {
    rows: ExactVec<u32>,
    scalar_keys: ExactVec<u32>,
    scalar_alt_keys: ExactVec<u32>,
    scalar_alt_cells: ExactVec<u32>,
    offsets: ExactVec<usize>,
    lengths: ExactVec<u32>,
    hashes: ExactVec<u64>,
    modes: ExactVec<u8>,
    items: ExactVec<u32>,
    state_len: usize,
    item_len: usize,
    initial: u32,
}

impl LazyCache {
    const fn new() -> Self {
        Self {
            rows: ExactVec::new(),
            scalar_keys: ExactVec::new(),
            scalar_alt_keys: ExactVec::new(),
            scalar_alt_cells: ExactVec::new(),
            offsets: ExactVec::new(),
            lengths: ExactVec::new(),
            hashes: ExactVec::new(),
            modes: ExactVec::new(),
            items: ExactVec::new(),
            state_len: 0,
            item_len: 0,
            initial: NO_STATE,
        }
    }

    fn reserved(
        state_capacity: usize,
        item_capacity: usize,
        total_bytes: usize,
    ) -> Result<Self, Error> {
        let row_cells = mul(state_capacity, BYTE_ALPHABET, Resource::ScratchBytes)?;
        let scalar_key_cells = mul(state_capacity, SCALAR_LEAD_SLOTS, Resource::ScratchBytes)?;
        Ok(Self {
            rows: reserved_slots(row_cells, total_bytes)?,
            scalar_keys: reserved_slots(scalar_key_cells, total_bytes)?,
            scalar_alt_keys: reserved_slots(scalar_key_cells, total_bytes)?,
            scalar_alt_cells: reserved_slots(scalar_key_cells, total_bytes)?,
            offsets: reserved_slots(state_capacity, total_bytes)?,
            lengths: reserved_slots(state_capacity, total_bytes)?,
            hashes: reserved_slots(state_capacity, total_bytes)?,
            modes: reserved_slots(state_capacity, total_bytes)?,
            items: reserved_slots(item_capacity, total_bytes)?,
            state_len: 0,
            item_len: 0,
            initial: NO_STATE,
        })
    }

    fn initialize_storage(
        &mut self,
        state_capacity: usize,
        item_capacity: usize,
        deferred: bool,
        meter: &mut SweepMeter,
    ) -> Result<(), Error> {
        let row_cells = mul(state_capacity, BYTE_ALPHABET, Resource::ScratchBytes)?;
        let scalar_key_cells = mul(state_capacity, SCALAR_LEAD_SLOTS, Resource::ScratchBytes)?;
        if deferred {
            validate_empty_reservation(&self.rows, row_cells)?;
            validate_empty_reservation(&self.scalar_keys, scalar_key_cells)?;
            validate_empty_reservation(&self.scalar_alt_keys, scalar_key_cells)?;
            validate_empty_reservation(&self.scalar_alt_cells, scalar_key_cells)?;
        } else {
            initialize_slots(&mut self.rows, row_cells, CELL_UNFILLED, meter)?;
            initialize_slots(
                &mut self.scalar_keys,
                scalar_key_cells,
                SCALAR_KEY_UNFILLED,
                meter,
            )?;
            initialize_slots(
                &mut self.scalar_alt_keys,
                scalar_key_cells,
                SCALAR_KEY_UNFILLED,
                meter,
            )?;
            initialize_slots(
                &mut self.scalar_alt_cells,
                scalar_key_cells,
                CELL_UNFILLED,
                meter,
            )?;
        }
        initialize_slots(&mut self.offsets, state_capacity, 0_usize, meter)?;
        initialize_slots(&mut self.lengths, state_capacity, 0_u32, meter)?;
        initialize_slots(&mut self.hashes, state_capacity, 0_u64, meter)?;
        initialize_slots(&mut self.modes, state_capacity, 0_u8, meter)?;
        initialize_slots(&mut self.items, item_capacity, 0_u32, meter)
    }

    fn initialize_state_rows(&mut self, state: usize) -> Result<(), Error> {
        if self.rows.len() == self.rows.capacity() {
            return Ok(());
        }
        let row_start = mul(state, BYTE_ALPHABET, Resource::ScratchBytes)?;
        let row_end = add(row_start, BYTE_ALPHABET, Resource::ScratchBytes)?;
        let scalar_start = mul(state, SCALAR_LEAD_SLOTS, Resource::ScratchBytes)?;
        let scalar_end = add(scalar_start, SCALAR_LEAD_SLOTS, Resource::ScratchBytes)?;
        if self.rows.len() != row_start
            || row_end > self.rows.capacity()
            || self.scalar_keys.len() != scalar_start
            || scalar_end > self.scalar_keys.capacity()
            || self.scalar_alt_keys.len() != scalar_start
            || scalar_end > self.scalar_alt_keys.capacity()
            || self.scalar_alt_cells.len() != scalar_start
            || scalar_end > self.scalar_alt_cells.capacity()
        {
            return Err(Error::InternalInvariant(
                "deferred lazy DFA row cache changed reserved shape",
            ));
        }
        push_repeated(&mut self.rows, BYTE_ALPHABET, CELL_UNFILLED)?;
        push_repeated(
            &mut self.scalar_keys,
            SCALAR_LEAD_SLOTS,
            SCALAR_KEY_UNFILLED,
        )?;
        push_repeated(
            &mut self.scalar_alt_keys,
            SCALAR_LEAD_SLOTS,
            SCALAR_KEY_UNFILLED,
        )?;
        push_repeated(&mut self.scalar_alt_cells, SCALAR_LEAD_SLOTS, CELL_UNFILLED)?;
        Ok(())
    }

    #[inline]
    fn state_bounds(&self, state: u32) -> Result<(usize, usize, bool), Error> {
        let state = usize::try_from(state)
            .map_err(|_| Error::InternalInvariant("lazy DFA state ID does not fit usize"))?;
        if state >= self.state_len {
            return Err(Error::InternalInvariant(
                "lazy DFA state ID outside retained cache",
            ));
        }
        let offset = *self.offsets.get(state).ok_or(Error::InternalInvariant(
            "lazy DFA state offset outside metadata",
        ))?;
        let length = usize::try_from(*self.lengths.get(state).ok_or(Error::InternalInvariant(
            "lazy DFA state length outside metadata",
        ))?)
        .map_err(|_| Error::InternalInvariant("lazy DFA state length does not fit usize"))?;
        let end = add(offset, length, Resource::ScratchBytes)?;
        if end > self.item_len || end > self.items.len() {
            return Err(Error::InternalInvariant(
                "lazy DFA state items outside retained arena",
            ));
        }
        let mode = *self.modes.get(state).ok_or(Error::InternalInvariant(
            "lazy DFA state mode outside metadata",
        ))? != 0;
        Ok((offset, length, mode))
    }

    #[inline]
    fn item(&self, state: u32, ordinal: usize) -> Result<u32, Error> {
        let (offset, length, _) = self.state_bounds(state)?;
        if ordinal >= length {
            return Err(Error::InternalInvariant(
                "lazy DFA item ordinal outside state",
            ));
        }
        self.items
            .get(offset + ordinal)
            .copied()
            .ok_or(Error::InternalInvariant("lazy DFA item outside arena"))
    }

    #[inline]
    fn cell(&self, state: u32, byte: u8) -> Result<u32, Error> {
        let state = usize::try_from(state)
            .map_err(|_| Error::InternalInvariant("lazy DFA state ID does not fit usize"))?;
        if state >= self.state_len {
            return Err(Error::InternalInvariant(
                "lazy DFA transition source outside cache",
            ));
        }
        let row = mul(state, BYTE_ALPHABET, Resource::ScratchBytes)?;
        self.rows
            .get(row + usize::from(byte))
            .copied()
            .ok_or(Error::InternalInvariant(
                "lazy DFA transition cell outside direct-index table",
            ))
    }

    #[inline]
    fn set_cell(&mut self, state: u32, byte: u8, cell: u32) -> Result<(), Error> {
        let state = usize::try_from(state)
            .map_err(|_| Error::InternalInvariant("lazy DFA state ID does not fit usize"))?;
        if state >= self.state_len {
            return Err(Error::InternalInvariant(
                "lazy DFA transition source outside cache",
            ));
        }
        let row = mul(state, BYTE_ALPHABET, Resource::ScratchBytes)?;
        *self
            .rows
            .get_mut(row + usize::from(byte))
            .ok_or(Error::InternalInvariant(
                "lazy DFA transition cell outside direct-index table",
            ))? = cell;
        Ok(())
    }

    #[inline]
    fn scalar_cell(&self, state: u32, byte: u8, scalar: Option<char>) -> Result<u32, Error> {
        let state = usize::try_from(state)
            .map_err(|_| Error::InternalInvariant("lazy DFA state ID does not fit usize"))?;
        if state >= self.state_len {
            return Err(Error::InternalInvariant(
                "lazy DFA scalar transition source outside cache",
            ));
        }
        let lead = scalar_lead_slot(byte)?;
        let key_index = add(
            mul(state, SCALAR_LEAD_SLOTS, Resource::ScratchBytes)?,
            lead,
            Resource::ScratchBytes,
        )?;
        let key = scalar.map_or(SCALAR_KEY_NONE, u32::from);
        if self.scalar_keys.get(key_index).copied() == Some(key) {
            return self.cell(
                u32::try_from(state)
                    .map_err(|_| Error::InternalInvariant("lazy DFA state ID does not fit u32"))?,
                byte,
            );
        }
        if self.scalar_alt_keys.get(key_index).copied() == Some(key) {
            return self
                .scalar_alt_cells
                .get(key_index)
                .copied()
                .ok_or(Error::InternalInvariant(
                    "lazy DFA alternate scalar cell outside cache",
                ));
        }
        Ok(CELL_UNFILLED)
    }

    #[inline]
    fn set_scalar_cell(
        &mut self,
        state: u32,
        byte: u8,
        scalar: Option<char>,
        cell: u32,
    ) -> Result<(), Error> {
        let state_index = usize::try_from(state)
            .map_err(|_| Error::InternalInvariant("lazy DFA state ID does not fit usize"))?;
        if state_index >= self.state_len {
            return Err(Error::InternalInvariant(
                "lazy DFA scalar transition source outside cache",
            ));
        }
        let lead = scalar_lead_slot(byte)?;
        let key_index = add(
            mul(state_index, SCALAR_LEAD_SLOTS, Resource::ScratchBytes)?,
            lead,
            Resource::ScratchBytes,
        )?;
        let key = scalar.map_or(SCALAR_KEY_NONE, u32::from);
        let primary = self
            .scalar_keys
            .get(key_index)
            .copied()
            .ok_or(Error::InternalInvariant(
                "lazy DFA scalar transition key outside cache",
            ))?;
        let alternate =
            self.scalar_alt_keys
                .get(key_index)
                .copied()
                .ok_or(Error::InternalInvariant(
                    "lazy DFA alternate scalar key outside cache",
                ))?;
        if primary == key || primary == SCALAR_KEY_UNFILLED {
            self.set_cell(state, byte, cell)?;
            self.scalar_keys[key_index] = key;
        } else if alternate == key || alternate == SCALAR_KEY_UNFILLED {
            self.scalar_alt_cells[key_index] = cell;
            self.scalar_alt_keys[key_index] = key;
        } else if key & 1 == 0 {
            self.set_cell(state, byte, cell)?;
            self.scalar_keys[key_index] = key;
        } else {
            self.scalar_alt_cells[key_index] = cell;
            self.scalar_alt_keys[key_index] = key;
        }
        Ok(())
    }

    fn intern(
        &mut self,
        items: &[u32],
        mode: bool,
        meter: &mut SweepMeter,
    ) -> Result<Interned, Error> {
        meter.charge_work(items.len())?;
        let hash = frontier_hash(items, mode);
        for state in 0..self.state_len {
            meter.charge_work(1)?;
            if self.modes[state] != u8::from(mode) || self.hashes[state] != hash {
                continue;
            }
            let offset = self.offsets[state];
            let length = usize::try_from(self.lengths[state]).map_err(|_| {
                Error::InternalInvariant("lazy DFA state length does not fit usize")
            })?;
            if length != items.len() {
                continue;
            }
            let end = add(offset, length, Resource::ScratchBytes)?;
            let retained = self.items.get(offset..end).ok_or(Error::InternalInvariant(
                "lazy DFA candidate state outside item arena",
            ))?;
            meter.charge_work(items.len())?;
            if retained == items {
                return Ok(Interned::State(u32::try_from(state).map_err(|_| {
                    Error::InternalInvariant("lazy DFA state ID does not fit u32")
                })?));
            }
        }
        if self.state_len == self.offsets.len() {
            return Ok(Interned::Full);
        }
        let end = add(self.item_len, items.len(), Resource::ScratchBytes)?;
        if end > self.items.len() {
            return Ok(Interned::Full);
        }
        let deferred = self.rows.len() != self.rows.capacity();
        meter.charge_work(new_state_initialization_work(items.len(), deferred)?)?;
        let state = self.state_len;
        self.initialize_state_rows(state)?;
        self.items[self.item_len..end].copy_from_slice(items);
        self.offsets[state] = self.item_len;
        self.lengths[state] = u32::try_from(items.len())
            .map_err(|_| Error::InternalInvariant("lazy DFA state length does not fit u32"))?;
        self.hashes[state] = hash;
        self.modes[state] = u8::from(mode);
        self.item_len = end;
        self.state_len = add(self.state_len, 1, Resource::ScratchBytes)?;
        Ok(Interned::State(u32::try_from(state).map_err(|_| {
            Error::InternalInvariant("lazy DFA state ID does not fit u32")
        })?))
    }

    /// Attempt to retain one runtime transition state using only the
    /// operation's speculative learning allowance. Failure never mutates the
    /// cache and hands the just-computed ordered frontier to inline execution.
    fn intern_speculative(
        &mut self,
        items: &[u32],
        mode: bool,
        meter: &mut SweepMeter,
    ) -> Result<Interned, Error> {
        if !meter.charge_cache_work(items.len())? {
            return Ok(Interned::WorkFull);
        }
        let hash = frontier_hash(items, mode);
        for state in 0..self.state_len {
            if !meter.charge_cache_work(1)? {
                return Ok(Interned::WorkFull);
            }
            if self.modes[state] != u8::from(mode) || self.hashes[state] != hash {
                continue;
            }
            let offset = self.offsets[state];
            let length = usize::try_from(self.lengths[state]).map_err(|_| {
                Error::InternalInvariant("lazy DFA state length does not fit usize")
            })?;
            if length != items.len() {
                continue;
            }
            let end = add(offset, length, Resource::ScratchBytes)?;
            let retained = self.items.get(offset..end).ok_or(Error::InternalInvariant(
                "lazy DFA candidate state outside item arena",
            ))?;
            if !meter.charge_cache_work(items.len())? {
                return Ok(Interned::WorkFull);
            }
            if retained == items {
                return Ok(Interned::State(u32::try_from(state).map_err(|_| {
                    Error::InternalInvariant("lazy DFA state ID does not fit u32")
                })?));
            }
        }
        if self.state_len == self.offsets.len() {
            return Ok(Interned::Full);
        }
        let end = add(self.item_len, items.len(), Resource::ScratchBytes)?;
        if end > self.items.len() {
            return Ok(Interned::Full);
        }
        let deferred = self.rows.len() != self.rows.capacity();
        if !meter.charge_cache_work(new_state_initialization_work(items.len(), deferred)?)? {
            return Ok(Interned::WorkFull);
        }
        let state = self.state_len;
        self.initialize_state_rows(state)?;
        self.items[self.item_len..end].copy_from_slice(items);
        self.offsets[state] = self.item_len;
        self.lengths[state] = u32::try_from(items.len())
            .map_err(|_| Error::InternalInvariant("lazy DFA state length does not fit u32"))?;
        self.hashes[state] = hash;
        self.modes[state] = u8::from(mode);
        self.item_len = end;
        self.state_len = add(self.state_len, 1, Resource::ScratchBytes)?;
        Ok(Interned::State(u32::try_from(state).map_err(|_| {
            Error::InternalInvariant("lazy DFA state ID does not fit u32")
        })?))
    }

    fn retained_bytes(&self) -> Result<usize, Error> {
        let rows = mul(
            self.rows.capacity(),
            size_of::<u32>(),
            Resource::ScratchBytes,
        )?;
        let offsets = mul(
            self.offsets.capacity(),
            size_of::<usize>(),
            Resource::ScratchBytes,
        )?;
        let lengths = mul(
            self.lengths.capacity(),
            size_of::<u32>(),
            Resource::ScratchBytes,
        )?;
        let hashes = mul(
            self.hashes.capacity(),
            size_of::<u64>(),
            Resource::ScratchBytes,
        )?;
        let modes = self.modes.capacity();
        let items = mul(
            self.items.capacity(),
            size_of::<u32>(),
            Resource::ScratchBytes,
        )?;
        let scalar_cache = add(
            add(
                mul(
                    self.scalar_keys.capacity(),
                    size_of::<u32>(),
                    Resource::ScratchBytes,
                )?,
                mul(
                    self.scalar_alt_keys.capacity(),
                    size_of::<u32>(),
                    Resource::ScratchBytes,
                )?,
                Resource::ScratchBytes,
            )?,
            mul(
                self.scalar_alt_cells.capacity(),
                size_of::<u32>(),
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )?;
        add(
            add(
                add(rows, scalar_cache, Resource::ScratchBytes)?,
                offsets,
                Resource::ScratchBytes,
            )?,
            add(
                add(
                    add(lengths, hashes, Resource::ScratchBytes)?,
                    modes,
                    Resource::ScratchBytes,
                )?,
                items,
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )
    }
}

#[inline]
fn frontier_hash(items: &[u32], mode: bool) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ u64::from(mode);
    for &item in items {
        hash ^= u64::from(item);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^ u64::try_from(items.len()).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Interned {
    State(u32),
    Full,
    WorkFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transition {
    Ready(u32),
    Inline { accepted: bool, pending: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwardState {
    Cached(u32),
    Inline { pending: bool },
}

/// Certify a scalar fixed-length continuation whose consuming graph is one
/// strictly descending sequence. Without splits or back edges, every retained
/// state is a bounded suffix frontier; broad branching continuations keep the
/// eager initialization that gives their first operation its full learning
/// allowance.
fn deferred_cache_initialization_eligible(
    program: &Program,
    meter: &mut SweepMeter,
) -> Result<bool, Error> {
    if !program.contains_scalar_transition()
        || program.contains_assertion()
        || program.split_count != 0
    {
        return Ok(false);
    }
    for (pc, inst) in program.insts.iter().enumerate() {
        meter.charge_work(1)?;
        let descending = match inst {
            Inst::Consume { next, .. } => *next < pc,
            Inst::ConsumeScalar { next_by_width, .. } => {
                next_by_width.iter().all(|&next| next < pc)
            }
            Inst::Fail | Inst::Match => true,
            Inst::Unfilled | Inst::Assert { .. } | Inst::Split { .. } | Inst::RootSplit { .. } => {
                false
            }
        };
        if !descending {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Plan-owned graph and cache storage retained across aggregate calls.
#[derive(Debug, Default)]
pub(super) struct Workspace {
    plan_id: Option<PlanId>,
    admitted: bool,
    seen: ExactVec<u64>,
    generation: u64,
    scratch: ExactVec<u32>,
    scratch_len: usize,
    frontier: ExactVec<u32>,
    frontier_len: usize,
    stack: ExactVec<u32>,
    stack_len: usize,
    cursors: ExactVec<usize>,
    reverse_epsilon_offsets: ExactVec<usize>,
    reverse_epsilon_sources: ExactVec<u32>,
    reverse_consume_offsets: ExactVec<usize>,
    reverse_consume_sources: ExactVec<u32>,
    reverse_consume_bytes: ExactVec<ByteSet>,
    forward: LazyCache,
    reverse: LazyCache,
    saturated: bool,
    retained_bytes: usize,
}

impl Workspace {
    pub(super) const fn new() -> Self {
        Self {
            plan_id: None,
            admitted: false,
            seen: ExactVec::new(),
            generation: 0,
            scratch: ExactVec::new(),
            scratch_len: 0,
            frontier: ExactVec::new(),
            frontier_len: 0,
            stack: ExactVec::new(),
            stack_len: 0,
            cursors: ExactVec::new(),
            reverse_epsilon_offsets: ExactVec::new(),
            reverse_epsilon_sources: ExactVec::new(),
            reverse_consume_offsets: ExactVec::new(),
            reverse_consume_sources: ExactVec::new(),
            reverse_consume_bytes: ExactVec::new(),
            forward: LazyCache::new(),
            reverse: LazyCache::new(),
            saturated: false,
            retained_bytes: 0,
        }
    }

    pub(super) const fn retained_bytes(&self) -> Option<usize> {
        if self.plan_id.is_some() {
            Some(self.retained_bytes)
        } else {
            None
        }
    }

    fn prepare(
        &mut self,
        plan_id: PlanId,
        program: &Program,
        limits: OperationLimits,
    ) -> Result<(bool, usize), Error> {
        let profile = cache_profile(program.insts.len());
        self.prepare_bounded(plan_id, program, limits, profile.states, profile.items)
    }

    fn prepare_bounded(
        &mut self,
        plan_id: PlanId,
        program: &Program,
        limits: OperationLimits,
        state_capacity: usize,
        max_items: usize,
    ) -> Result<(bool, usize), Error> {
        let upper = prospective_upper_bounds_with_run(
            program.insts.len(),
            state_capacity,
            max_items,
            program.continuation_nonaccepting_run(),
            None,
        )?;
        if self.plan_id == Some(plan_id) {
            // A warmed cache is still selected under the current invocation's
            // complete source-free policy. Recheck the same fixed-table and
            // conservative workspace envelope used by cold preparation; a
            // caller cannot inherit admission from an earlier, wider policy.
            if enforce_sweep_upper_bounds(upper, limits).is_err() {
                *self = Self::disabled(plan_id);
                return Ok((false, 0));
            }
            return Ok((self.admitted, 0));
        }
        *self = Self::new();
        if enforce_sweep_upper_bounds(upper, limits).is_err() {
            *self = Self::disabled(plan_id);
            return Ok((false, 0));
        }
        let built = (|| {
            let mut meter = SweepMeter::new(limits);
            let mut replacement = Self::build(
                plan_id,
                program,
                limits,
                state_capacity,
                max_items,
                &mut meter,
            )?;
            replacement.initialize(program, &mut meter)?;
            replacement.admitted = true;
            replacement.retained_bytes = replacement.actual_retained_bytes()?;
            enforce_workspace_bytes(replacement.retained_bytes, limits)?;
            Ok::<_, Error>((replacement, meter.work))
        })();
        let (replacement, work) = match built {
            Ok(result) => result,
            Err(Error::AllocationFailed { .. }) => {
                *self = Self::disabled(plan_id);
                return Ok((false, 0));
            }
            Err(error) => {
                *self = Self::new();
                return Err(error);
            }
        };
        *self = replacement;
        Ok((true, work))
    }

    fn disabled(plan_id: PlanId) -> Self {
        Self {
            plan_id: Some(plan_id),
            ..Self::new()
        }
    }

    fn build(
        plan_id: PlanId,
        program: &Program,
        limits: OperationLimits,
        state_capacity: usize,
        max_items: usize,
        meter: &mut SweepMeter,
    ) -> Result<Self, Error> {
        let states = program.insts.len();
        if states == 0 {
            return Err(Error::InternalInvariant(
                "lazy continuation requires a nonempty program",
            ));
        }
        if states > u32::MAX as usize {
            return Err(Error::ArithmeticOverflow {
                resource: Resource::ProgramStates,
            });
        }
        // Reserve the complete source-independent graph envelope so every
        // fallible fixed-arena allocation happens before initialization,
        // program census, or any other charged work. An allocator refusal at
        // any ordinal can therefore select the incumbent with zero abandoned
        // optional work.
        let epsilon_edges = mul(states, 2, Resource::ScratchBytes)?;
        // A scalar-consuming instruction can dispatch to one successor per
        // UTF-8 width. Reserving four incoming edges per program state keeps
        // the reverse graph exact-allocation and bounded without expanding
        // scalar classes into byte tries.
        let consume_edges = mul(states, 4, Resource::ScratchBytes)?;
        let item_capacity = mul(states, state_capacity, Resource::ScratchBytes)?
            .min(max_items)
            .max(states);
        let stack_slots = add(
            mul(states, 2, Resource::ScratchBytes)?,
            1,
            Resource::ScratchBytes,
        )?;
        let logical_bytes = logical_workspace_bytes(
            states,
            stack_slots,
            epsilon_edges,
            consume_edges,
            state_capacity,
            item_capacity,
        )?;
        enforce_workspace_bytes(logical_bytes, limits)?;

        let mut output = Self {
            plan_id: Some(plan_id),
            admitted: false,
            seen: reserved_slots(states, logical_bytes)?,
            generation: 0,
            scratch: reserved_slots(states, logical_bytes)?,
            scratch_len: 0,
            frontier: reserved_slots(states, logical_bytes)?,
            frontier_len: 0,
            stack: reserved_slots(stack_slots, logical_bytes)?,
            stack_len: 0,
            cursors: reserved_slots(states, logical_bytes)?,
            reverse_epsilon_offsets: reserved_slots(
                add(states, 1, Resource::ScratchBytes)?,
                logical_bytes,
            )?,
            reverse_epsilon_sources: reserved_slots(epsilon_edges, logical_bytes)?,
            reverse_consume_offsets: reserved_slots(
                add(states, 1, Resource::ScratchBytes)?,
                logical_bytes,
            )?,
            reverse_consume_sources: reserved_slots(consume_edges, logical_bytes)?,
            reverse_consume_bytes: reserved_slots(consume_edges, logical_bytes)?,
            forward: LazyCache::reserved(state_capacity, item_capacity, logical_bytes)?,
            reverse: LazyCache::reserved(state_capacity, item_capacity, logical_bytes)?,
            saturated: false,
            retained_bytes: 0,
        };
        let deferred_cache_initialization = program.insts.len() >= LARGE_DFA_PROGRAM_STATES
            || deferred_cache_initialization_eligible(program, meter)?;
        output.initialize_storage(
            states,
            stack_slots,
            epsilon_edges,
            consume_edges,
            state_capacity,
            item_capacity,
            deferred_cache_initialization,
            meter,
        )?;
        output.build_reverse_graph(program, meter)?;
        Ok(output)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "fixed arena dimensions are authenticated together before initialization"
    )]
    fn initialize_storage(
        &mut self,
        states: usize,
        stack_slots: usize,
        epsilon_edges: usize,
        consume_edges: usize,
        state_capacity: usize,
        item_capacity: usize,
        deferred_cache_initialization: bool,
        meter: &mut SweepMeter,
    ) -> Result<(), Error> {
        initialize_slots(&mut self.seen, states, 0_u64, meter)?;
        initialize_slots(&mut self.scratch, states, 0_u32, meter)?;
        initialize_slots(&mut self.frontier, states, 0_u32, meter)?;
        initialize_slots(&mut self.stack, stack_slots, 0_u32, meter)?;
        initialize_slots(&mut self.cursors, states, 0_usize, meter)?;
        initialize_slots(
            &mut self.reverse_epsilon_offsets,
            add(states, 1, Resource::ScratchBytes)?,
            0_usize,
            meter,
        )?;
        initialize_slots(
            &mut self.reverse_epsilon_sources,
            epsilon_edges,
            0_u32,
            meter,
        )?;
        initialize_slots(
            &mut self.reverse_consume_offsets,
            add(states, 1, Resource::ScratchBytes)?,
            0_usize,
            meter,
        )?;
        initialize_slots(
            &mut self.reverse_consume_sources,
            consume_edges,
            0_u32,
            meter,
        )?;
        initialize_slots(
            &mut self.reverse_consume_bytes,
            consume_edges,
            ByteSet::empty(),
            meter,
        )?;
        self.forward.initialize_storage(
            state_capacity,
            item_capacity,
            deferred_cache_initialization,
            meter,
        )?;
        self.reverse.initialize_storage(
            state_capacity,
            item_capacity,
            deferred_cache_initialization,
            meter,
        )
    }

    fn build_reverse_graph(
        &mut self,
        program: &Program,
        meter: &mut SweepMeter,
    ) -> Result<(), Error> {
        let states = program.insts.len();
        for inst in &program.insts {
            meter.charge_work(1)?;
            match inst {
                Inst::Split {
                    preferred,
                    fallback,
                }
                | Inst::RootSplit {
                    preferred,
                    fallback,
                } => {
                    meter.charge_work(2)?;
                    increment_edge_count(&mut self.reverse_epsilon_offsets, *preferred, states)?;
                    increment_edge_count(&mut self.reverse_epsilon_offsets, *fallback, states)?;
                }
                Inst::Consume { next, .. } => {
                    meter.charge_work(1)?;
                    increment_edge_count(&mut self.reverse_consume_offsets, *next, states)?;
                }
                Inst::ConsumeScalar { next_by_width, .. } => {
                    for (ordinal, &next) in next_by_width.iter().enumerate() {
                        if next_by_width[..ordinal].contains(&next) {
                            continue;
                        }
                        meter.charge_work(1)?;
                        increment_edge_count(&mut self.reverse_consume_offsets, next, states)?;
                    }
                }
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant(
                        "lazy continuation reached an unfilled program state",
                    ));
                }
                Inst::Assert { .. } => {
                    return Err(Error::InternalInvariant(
                        "lazy continuation admitted an unsupported instruction",
                    ));
                }
                Inst::Fail | Inst::Match => {}
            }
        }
        prefix_counts(&mut self.reverse_epsilon_offsets, meter)?;
        prefix_counts(&mut self.reverse_consume_offsets, meter)?;

        meter.charge_work(states)?;
        self.cursors
            .copy_from_slice(&self.reverse_epsilon_offsets[..states]);
        for (pc, inst) in program.insts.iter().enumerate() {
            meter.charge_work(1)?;
            let source = u32::try_from(pc).map_err(|_| {
                Error::InternalInvariant("program state does not fit lazy DFA item")
            })?;
            match inst {
                Inst::Split {
                    preferred,
                    fallback,
                }
                | Inst::RootSplit {
                    preferred,
                    fallback,
                } => {
                    meter.charge_work(2)?;
                    fill_source(
                        &mut self.cursors,
                        &mut self.reverse_epsilon_sources,
                        *preferred,
                        source,
                    )?;
                    fill_source(
                        &mut self.cursors,
                        &mut self.reverse_epsilon_sources,
                        *fallback,
                        source,
                    )?;
                }
                Inst::Unfilled
                | Inst::Fail
                | Inst::Match
                | Inst::Consume { .. }
                | Inst::ConsumeScalar { .. }
                | Inst::Assert { .. } => {}
            }
        }

        meter.charge_work(states)?;
        self.cursors
            .copy_from_slice(&self.reverse_consume_offsets[..states]);
        for (pc, inst) in program.insts.iter().enumerate() {
            meter.charge_work(1)?;
            match inst {
                Inst::Consume { bytes, next } => {
                    meter.charge_work(1)?;
                    self.fill_reverse_consume(*next, pc, *bytes)?;
                }
                Inst::ConsumeScalar { next_by_width, .. } => {
                    for (ordinal, &next) in next_by_width.iter().enumerate() {
                        if next_by_width[..ordinal].contains(&next) {
                            continue;
                        }
                        meter.charge_work(1)?;
                        self.fill_reverse_consume(next, pc, ByteSet::empty())?;
                    }
                }
                Inst::Unfilled
                | Inst::Fail
                | Inst::Match
                | Inst::Assert { .. }
                | Inst::Split { .. }
                | Inst::RootSplit { .. } => {}
            }
        }
        Ok(())
    }

    fn fill_reverse_consume(
        &mut self,
        next: usize,
        pc: usize,
        bytes: ByteSet,
    ) -> Result<(), Error> {
        let source = u32::try_from(pc)
            .map_err(|_| Error::InternalInvariant("program state does not fit lazy DFA item"))?;
        let slot = *self.cursors.get(next).ok_or(Error::InternalInvariant(
            "reverse consume destination outside cursor table",
        ))?;
        *self
            .reverse_consume_sources
            .get_mut(slot)
            .ok_or(Error::InternalInvariant(
                "reverse consume source outside edge arena",
            ))? = source;
        *self
            .reverse_consume_bytes
            .get_mut(slot)
            .ok_or(Error::InternalInvariant(
                "reverse consume byte set outside edge arena",
            ))? = bytes;
        self.cursors[next] = add(slot, 1, Resource::ScratchBytes)?;
        Ok(())
    }

    fn initialize(&mut self, program: &Program, meter: &mut SweepMeter) -> Result<(), Error> {
        self.begin_closure(meter)?;
        let accepted = self.expand_forward(program, program.entry, meter)?;
        if accepted {
            return Err(Error::InternalInvariant(
                "non-nullable lazy continuation accepted its initial boundary",
            ));
        }
        let initial = match self
            .forward
            .intern(&self.scratch[..self.scratch_len], false, meter)?
        {
            Interned::State(state) => state,
            Interned::Full => {
                return Err(Error::InternalInvariant(
                    "lazy forward cache cannot retain its initial state",
                ));
            }
            Interned::WorkFull => {
                return Err(Error::InternalInvariant(
                    "lazy forward preparation used speculative cache work",
                ));
            }
        };
        self.forward.initial = initial;

        self.begin_closure(meter)?;
        for (pc, inst) in program.insts.iter().enumerate() {
            meter.charge_work(1)?;
            if matches!(inst, Inst::Match) {
                self.expand_reverse(
                    u32::try_from(pc).map_err(|_| {
                        Error::InternalInvariant("program state does not fit lazy DFA item")
                    })?,
                    meter,
                )?;
            }
        }
        sort_exact(&mut self.scratch[..self.scratch_len], meter)?;
        let reverse_initial =
            match self
                .reverse
                .intern(&self.scratch[..self.scratch_len], false, meter)?
            {
                Interned::State(state) => state,
                Interned::Full => {
                    return Err(Error::InternalInvariant(
                        "lazy reverse cache cannot retain its initial state",
                    ));
                }
                Interned::WorkFull => {
                    return Err(Error::InternalInvariant(
                        "lazy reverse preparation used speculative cache work",
                    ));
                }
            };
        self.reverse.initial = reverse_initial;
        Ok(())
    }

    fn begin_closure(&mut self, meter: &mut SweepMeter) -> Result<(), Error> {
        self.scratch_len = 0;
        self.stack_len = 0;
        if self.generation == u64::MAX {
            meter.charge_work(self.seen.len())?;
            self.seen.fill(0);
            self.generation = 0;
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow {
                resource: Resource::ExecutionWork,
            })?;
        Ok(())
    }

    fn retain_scratch_as_frontier(&mut self) {
        core::mem::swap(&mut self.scratch, &mut self.frontier);
        self.frontier_len = self.scratch_len;
        self.scratch_len = 0;
    }

    fn clear_frontier(&mut self) {
        self.frontier_len = 0;
    }

    fn load_forward_initial(&mut self, _meter: &mut SweepMeter) -> Result<ForwardState, Error> {
        let initial = self.forward.initial;
        if initial == NO_STATE {
            return Err(Error::InternalInvariant(
                "prepared lazy forward cache lacks an initial state",
            ));
        }
        Ok(ForwardState::Cached(initial))
    }

    fn load_reverse_initial(&mut self, _meter: &mut SweepMeter) -> Result<ForwardState, Error> {
        let initial = self.reverse.initial;
        if initial == NO_STATE {
            return Err(Error::InternalInvariant(
                "prepared lazy reverse cache lacks an initial state",
            ));
        }
        Ok(ForwardState::Cached(initial))
    }

    #[inline]
    fn push_scratch(&mut self, pc: u32) -> Result<(), Error> {
        *self
            .scratch
            .get_mut(self.scratch_len)
            .ok_or(Error::InternalInvariant(
                "lazy DFA closure output exceeded program states",
            ))? = pc;
        self.scratch_len = add(self.scratch_len, 1, Resource::ProgramStates)?;
        Ok(())
    }

    #[inline]
    fn push_stack(&mut self, pc: u32) -> Result<(), Error> {
        *self
            .stack
            .get_mut(self.stack_len)
            .ok_or(Error::InternalInvariant(
                "lazy DFA closure stack exceeded edge census",
            ))? = pc;
        self.stack_len = add(self.stack_len, 1, Resource::ProgramStates)?;
        Ok(())
    }

    #[inline]
    fn pop_stack(&mut self) -> Option<u32> {
        self.stack_len = self.stack_len.checked_sub(1)?;
        self.stack.get(self.stack_len).copied()
    }

    fn expand_forward(
        &mut self,
        program: &Program,
        root: usize,
        meter: &mut SweepMeter,
    ) -> Result<bool, Error> {
        self.stack_len = 0;
        self.push_stack(
            u32::try_from(root).map_err(|_| {
                Error::InternalInvariant("program state does not fit lazy DFA item")
            })?,
        )?;
        while let Some(pc) = self.pop_stack() {
            meter.charge_work(1)?;
            let pc = usize::try_from(pc)
                .map_err(|_| Error::InternalInvariant("lazy DFA PC does not fit usize"))?;
            let seen = self.seen.get_mut(pc).ok_or(Error::InternalInvariant(
                "lazy forward closure PC outside program",
            ))?;
            if *seen == self.generation {
                continue;
            }
            *seen = self.generation;
            match program.instruction(pc)? {
                Inst::Fail => {}
                Inst::Match => return Ok(true),
                Inst::Consume { .. } | Inst::ConsumeScalar { .. } => {
                    self.push_scratch(u32::try_from(pc).map_err(|_| {
                        Error::InternalInvariant("program state does not fit lazy DFA item")
                    })?)?;
                }
                Inst::Split {
                    preferred,
                    fallback,
                }
                | Inst::RootSplit {
                    preferred,
                    fallback,
                } => {
                    self.push_stack(u32::try_from(*fallback).map_err(|_| {
                        Error::InternalInvariant("program state does not fit lazy DFA item")
                    })?)?;
                    self.push_stack(u32::try_from(*preferred).map_err(|_| {
                        Error::InternalInvariant("program state does not fit lazy DFA item")
                    })?)?;
                }
                Inst::Unfilled => {
                    return Err(Error::InternalInvariant(
                        "lazy forward closure reached an unfilled state",
                    ));
                }
                Inst::Assert { .. } => {
                    return Err(Error::InternalInvariant(
                        "lazy forward closure reached an unsupported instruction",
                    ));
                }
            }
        }
        Ok(false)
    }

    fn expand_reverse(&mut self, root: u32, meter: &mut SweepMeter) -> Result<(), Error> {
        self.stack_len = 0;
        self.push_stack(root)?;
        while let Some(pc) = self.pop_stack() {
            meter.charge_work(1)?;
            let pc_usize = usize::try_from(pc)
                .map_err(|_| Error::InternalInvariant("lazy DFA PC does not fit usize"))?;
            let seen = self.seen.get_mut(pc_usize).ok_or(Error::InternalInvariant(
                "lazy reverse closure PC outside program",
            ))?;
            if *seen == self.generation {
                continue;
            }
            *seen = self.generation;
            self.push_scratch(pc)?;
            let start =
                *self
                    .reverse_epsilon_offsets
                    .get(pc_usize)
                    .ok_or(Error::InternalInvariant(
                        "reverse epsilon offset outside graph",
                    ))?;
            let end =
                *self
                    .reverse_epsilon_offsets
                    .get(pc_usize + 1)
                    .ok_or(Error::InternalInvariant(
                        "reverse epsilon end offset outside graph",
                    ))?;
            for edge in start..end {
                self.push_stack(*self.reverse_epsilon_sources.get(edge).ok_or(
                    Error::InternalInvariant("reverse epsilon source outside graph"),
                )?)?;
            }
        }
        Ok(())
    }

    fn actual_retained_bytes(&self) -> Result<usize, Error> {
        let u64s = mul(
            self.seen.capacity(),
            size_of::<u64>(),
            Resource::ScratchBytes,
        )?;
        let u32s = add(
            add(
                add(
                    self.scratch.capacity(),
                    self.frontier.capacity(),
                    Resource::ScratchBytes,
                )?,
                self.stack.capacity(),
                Resource::ScratchBytes,
            )?,
            add(
                self.reverse_epsilon_sources.capacity(),
                self.reverse_consume_sources.capacity(),
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )?;
        let u32s = mul(u32s, size_of::<u32>(), Resource::ScratchBytes)?;
        let usizes = add(
            self.cursors.capacity(),
            add(
                self.reverse_epsilon_offsets.capacity(),
                self.reverse_consume_offsets.capacity(),
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )?;
        let usizes = mul(usizes, size_of::<usize>(), Resource::ScratchBytes)?;
        let byte_sets = mul(
            self.reverse_consume_bytes.capacity(),
            size_of::<ByteSet>(),
            Resource::ScratchBytes,
        )?;
        add(
            add(
                add(u64s, u32s, Resource::ScratchBytes)?,
                add(usizes, byte_sets, Resource::ScratchBytes)?,
                Resource::ScratchBytes,
            )?,
            add(
                self.forward.retained_bytes()?,
                self.reverse.retained_bytes()?,
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )
    }
}

/// Run the persistent lazy-DFA route.
///
/// Structural and complete mandatory-resource refusal is completed before the
/// workspace inspects source bytes. Preparation allocates exact fixed arenas
/// and its work is carried into execution. Cache capacity or speculative-work
/// saturation switches to the inline frontier at the already-advanced
/// position. The current operation completes without replay. Published
/// transitions remain reusable after match restarts and across later calls;
/// each call receives a fresh bounded learning allowance.
pub(super) fn reduce(
    plan_id: PlanId,
    program: &Program,
    haystack: &[u8],
    range: Range<usize>,
    kind: SweepKind,
    minimum_match_bytes: Option<usize>,
    limits: OperationLimits,
    workspace: &mut Workspace,
    mut visitor: Option<&mut dyn FnMut(crate::Span)>,
) -> Result<Option<SweepOutcome>, Error> {
    if program.contains_assertion()
        || program.contains_unicode_word_boundary()
        || program.start_domain.is_sparse()
    {
        return Ok(None);
    }
    let Some(minimum_match_bytes) = minimum_match_bytes.filter(|minimum| *minimum > 0) else {
        return Ok(None);
    };
    if range.start > range.end || range.end > haystack.len() {
        return Err(Error::InvalidRange {
            start: range.start,
            end: range.end,
            haystack_len: haystack.len(),
        });
    }
    let local_len = range.end - range.start;
    let boundaries = add(local_len, 1, Resource::Boundaries)?;
    enforce(boundaries, limits.max_boundaries, Resource::Boundaries)?;
    if workspace.plan_id == Some(plan_id) && !workspace.admitted {
        return Ok(None);
    }
    let profile = cache_profile(program.insts.len());
    let fixed = match prospective_upper_bounds_with_run(
        program.insts.len(),
        profile.states,
        profile.items,
        program.continuation_nonaccepting_run(),
        Some(minimum_match_bytes),
    ) {
        Ok(fixed) => fixed,
        Err(Error::ArithmeticOverflow { .. }) => return Ok(None),
        Err(error) => return Err(error),
    };
    let preparation_upper = if workspace.plan_id == Some(plan_id) {
        0
    } else {
        fixed.preparation_work
    };
    if preparation_upper > limits.max_work {
        return Ok(None);
    }
    let (admitted, preparation_work) = workspace.prepare(plan_id, program, limits)?;
    if !admitted {
        return Ok(None);
    }
    let absolute_base = range.start;
    let local = &haystack[range];
    let residual_work =
        limits
            .max_work
            .checked_sub(preparation_work)
            .ok_or(Error::InternalInvariant(
                "continuation preparation exceeded its admitted work",
            ))?;
    // Value-only execution is already observed-work bounded: unlike a
    // receipt-bearing operation, it may return the caller's exact resource
    // error after source access. Keep half of the remaining allowance for
    // mandatory frontier progress and use at most the other half to learn
    // reusable transitions. This lets programs with an unbounded
    // non-accepting continuation use the DFA without claiming a false linear
    // completion bound.
    let cache_work = (residual_work / 2).min(fixed.learning_work);
    let mut meter = SweepMeter::with_cache_budget(limits, cache_work);
    meter.charge_work(preparation_work)?;
    let result = execute_prepared(
        program,
        local,
        absolute_base,
        kind,
        workspace,
        &mut meter,
        &mut visitor,
    );
    result.map(Some)
}

fn execute_prepared(
    program: &Program,
    local: &[u8],
    absolute_base: usize,
    kind: SweepKind,
    workspace: &mut Workspace,
    meter: &mut SweepMeter,
    visitor: &mut Option<&mut dyn FnMut(crate::Span)>,
) -> Result<SweepOutcome, Error> {
    let mut prefix = SweepValue {
        count: 0,
        span_sum: 0,
    };
    let mut cursor = 0_usize;
    let mut position = cursor;
    let mut state = workspace.load_forward_initial(meter)?;
    let mut pending_end = None;
    let scalar_program = program.contains_scalar_transition();

    loop {
        if position == local.len() {
            let Some(end) = pending_end else {
                meter.enforce_terminal_limits()?;
                return Ok(SweepOutcome::Complete(complete_value(prefix, kind)));
            };
            commit(
                local,
                cursor,
                end,
                kind,
                program,
                &mut prefix,
                workspace,
                meter,
                absolute_base,
                visitor,
            )?;
            cursor = end;
            position = end;
            pending_end = None;
            if end == local.len() {
                meter.enforce_terminal_limits()?;
                return Ok(SweepOutcome::Complete(complete_value(prefix, kind)));
            }
            state = workspace.load_forward_initial(meter)?;
            continue;
        }

        meter.charge_work(1)?;
        let source = local.get(position..).ok_or(Error::InternalInvariant(
            "lazy forward source position outside input",
        ))?;
        let (byte, cacheable) = source_byte(scalar_program, source, meter)?;
        let transition = match state {
            ForwardState::Cached(cached) => build_forward_transition(
                program,
                cached,
                byte,
                source,
                scalar_program,
                cacheable,
                workspace,
                meter,
            )?,
            ForwardState::Inline { pending } => build_inline_forward_transition(
                program,
                byte,
                source,
                scalar_program,
                pending,
                workspace,
                meter,
            )?,
        };
        position = add(position, 1, Resource::Boundaries)?;
        let (accepted, next) = match transition {
            Transition::Ready(cell) => {
                let encoded = cell & CELL_STATE_MASK;
                (
                    cell & CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(ForwardState::Cached(encoded - 1))
                    },
                )
            }
            Transition::Inline { accepted, pending } => {
                (accepted, Some(ForwardState::Inline { pending }))
            }
        };
        if accepted {
            pending_end = Some(position);
        }
        if let Some(next) = next {
            state = next;
            continue;
        }

        let Some(end) = pending_end else {
            // An unanchored state always injects the initial closure at the
            // next boundary. Reaching dead without a pending match therefore
            // means the pattern's initial closure itself has no consumers.
            meter.enforce_terminal_limits()?;
            return Ok(SweepOutcome::Complete(complete_value(prefix, kind)));
        };
        commit(
            local,
            cursor,
            end,
            kind,
            program,
            &mut prefix,
            workspace,
            meter,
            absolute_base,
            visitor,
        )?;
        cursor = end;
        position = end;
        pending_end = None;
        state = workspace.load_forward_initial(meter)?;
    }
}

fn build_forward_transition(
    program: &Program,
    state: u32,
    byte: u8,
    source: &[u8],
    scalar_program: bool,
    cacheable: bool,
    workspace: &mut Workspace,
    meter: &mut SweepMeter,
) -> Result<Transition, Error> {
    let scalar = if cacheable {
        None
    } else {
        source_scalar(scalar_program, byte, source)
    };
    let cached = if cacheable {
        workspace.forward.cell(state, byte)?
    } else {
        workspace.forward.scalar_cell(state, byte, scalar)?
    };
    if cached != CELL_UNFILLED {
        return Ok(Transition::Ready(cached));
    }

    let scalar = if cacheable {
        source_scalar(scalar_program, byte, source)
    } else {
        scalar
    };
    let (_, length, pending) = workspace.forward.state_bounds(state)?;
    workspace.begin_closure(meter)?;
    let mut accepted = false;
    for ordinal in 0..length {
        let pc = workspace.forward.item(state, ordinal)?;
        meter.charge_work(1)?;
        match program.instruction(
            usize::try_from(pc)
                .map_err(|_| Error::InternalInvariant("lazy forward item does not fit usize"))?,
        )? {
            Inst::Consume { bytes, next } => {
                if bytes.contains(byte) && workspace.expand_forward(program, *next, meter)? {
                    accepted = true;
                    break;
                }
            }
            Inst::ConsumeScalar {
                scalars,
                next_by_width,
            } => {
                if let Some(next) = scalar_successor(scalars, next_by_width, scalar, meter)?
                    && workspace.expand_forward(program, next, meter)?
                {
                    accepted = true;
                    break;
                }
            }
            Inst::Unfilled
            | Inst::Fail
            | Inst::Match
            | Inst::Assert { .. }
            | Inst::Split { .. }
            | Inst::RootSplit { .. } => {
                return Err(Error::InternalInvariant(
                    "lazy forward state retained a non-consuming instruction",
                ));
            }
        }
    }
    if !accepted && !pending {
        accepted = workspace.expand_forward(program, program.entry, meter)?;
    }
    let next_pending = pending || accepted;
    let encoded = if workspace.scratch_len == 0 {
        0
    } else {
        match workspace.forward.intern_speculative(
            &workspace.scratch[..workspace.scratch_len],
            next_pending,
            meter,
        )? {
            Interned::State(next) => next.checked_add(1).ok_or(Error::InternalInvariant(
                "lazy DFA encoded state ID overflowed",
            ))?,
            Interned::Full | Interned::WorkFull => {
                workspace.saturated = true;
                workspace.retain_scratch_as_frontier();
                return Ok(Transition::Inline {
                    accepted,
                    pending: next_pending,
                });
            }
        }
    };
    let cell = encoded | if accepted { CELL_ACCEPT } else { 0 };
    if cacheable {
        workspace.forward.set_cell(state, byte, cell)?;
    } else {
        workspace
            .forward
            .set_scalar_cell(state, byte, scalar, cell)?;
    }
    Ok(Transition::Ready(cell))
}

fn build_inline_forward_transition(
    program: &Program,
    byte: u8,
    source: &[u8],
    scalar_program: bool,
    pending: bool,
    workspace: &mut Workspace,
    meter: &mut SweepMeter,
) -> Result<Transition, Error> {
    let scalar = source_scalar(scalar_program, byte, source);
    let length = workspace.frontier_len;
    workspace.begin_closure(meter)?;
    let mut accepted = false;
    for ordinal in 0..length {
        let pc = workspace
            .frontier
            .get(ordinal)
            .copied()
            .ok_or(Error::InternalInvariant(
                "inline forward frontier item outside arena",
            ))?;
        meter.charge_work(1)?;
        match program.instruction(
            usize::try_from(pc)
                .map_err(|_| Error::InternalInvariant("inline forward PC does not fit usize"))?,
        )? {
            Inst::Consume { bytes, next } => {
                if bytes.contains(byte) && workspace.expand_forward(program, *next, meter)? {
                    accepted = true;
                    break;
                }
            }
            Inst::ConsumeScalar {
                scalars,
                next_by_width,
            } => {
                if let Some(next) = scalar_successor(scalars, next_by_width, scalar, meter)?
                    && workspace.expand_forward(program, next, meter)?
                {
                    accepted = true;
                    break;
                }
            }
            Inst::Unfilled
            | Inst::Fail
            | Inst::Match
            | Inst::Assert { .. }
            | Inst::Split { .. }
            | Inst::RootSplit { .. } => {
                return Err(Error::InternalInvariant(
                    "inline forward frontier retained a non-consuming instruction",
                ));
            }
        }
    }
    if !accepted && !pending {
        accepted = workspace.expand_forward(program, program.entry, meter)?;
    }
    let next_pending = pending || accepted;
    if workspace.scratch_len == 0 {
        workspace.clear_frontier();
        let cell = if accepted { CELL_ACCEPT } else { 0 };
        return Ok(Transition::Ready(cell));
    }
    workspace.retain_scratch_as_frontier();
    Ok(Transition::Inline {
        accepted,
        pending: next_pending,
    })
}

fn commit(
    haystack: &[u8],
    cursor: usize,
    end: usize,
    kind: SweepKind,
    program: &Program,
    prefix: &mut SweepValue,
    workspace: &mut Workspace,
    meter: &mut SweepMeter,
    absolute_base: usize,
    visitor: &mut Option<&mut dyn FnMut(crate::Span)>,
) -> Result<(), Error> {
    if end <= cursor || end > haystack.len() {
        return Err(Error::InternalInvariant(
            "non-nullable lazy continuation selected an invalid endpoint",
        ));
    }
    let start = if matches!(kind, SweepKind::SpanSum | SweepKind::SpanVisit) {
        reverse_start(haystack, cursor, end, program, workspace, meter)?
    } else {
        end
    };
    meter.charge_event()?;
    let count = add(prefix.count, 1, Resource::OutputMatches)?;
    enforce(
        count,
        meter.limits.max_output_matches,
        Resource::OutputMatches,
    )?;
    let width = end.checked_sub(start).ok_or(Error::InternalInvariant(
        "lazy continuation start follows endpoint",
    ))?;
    let span_sum = if matches!(kind, SweepKind::SpanSum | SweepKind::SpanVisit) {
        let value = add(prefix.span_sum, width, Resource::SpanSum)?;
        enforce(value, meter.limits.max_span_sum, Resource::SpanSum)?;
        value
    } else {
        0
    };
    prefix.count = count;
    prefix.span_sum = span_sum;
    if kind == SweepKind::SpanVisit {
        let start = add(absolute_base, start, Resource::Boundaries)?;
        let end = add(absolute_base, end, Resource::Boundaries)?;
        let Some(visitor) = visitor.as_deref_mut() else {
            return Err(Error::InternalInvariant(
                "lazy span visitor kind lacked its callback",
            ));
        };
        visitor(crate::Span { start, end });
    }
    Ok(())
}

fn reverse_start(
    haystack: &[u8],
    cursor: usize,
    end: usize,
    program: &Program,
    workspace: &mut Workspace,
    meter: &mut SweepMeter,
) -> Result<usize, Error> {
    let entry = u32::try_from(program.entry)
        .map_err(|_| Error::InternalInvariant("reverse entry does not fit u32"))?;
    let mut state = workspace.load_reverse_initial(meter)?;
    let mut best = None;
    let mut position = end;
    let scalar_program = program.contains_scalar_transition();
    while position > cursor {
        position -= 1;
        meter.charge_work(1)?;
        let source = haystack.get(position..end).ok_or(Error::InternalInvariant(
            "lazy reverse source position outside input",
        ))?;
        let (byte, cacheable) = source_byte(scalar_program, source, meter)?;
        let transition = match state {
            ForwardState::Cached(cached) => build_reverse_transition(
                program,
                cached,
                byte,
                source,
                scalar_program,
                cacheable,
                entry,
                workspace,
                meter,
            )?,
            ForwardState::Inline { .. } => build_inline_reverse_transition(
                program,
                byte,
                source,
                scalar_program,
                entry,
                workspace,
                meter,
            )?,
        };
        let (accepted, next) = match transition {
            Transition::Ready(cell) => {
                let encoded = cell & CELL_STATE_MASK;
                (
                    cell & CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(ForwardState::Cached(encoded - 1))
                    },
                )
            }
            Transition::Inline { accepted, .. } => {
                (accepted, Some(ForwardState::Inline { pending: false }))
            }
        };
        if accepted {
            best = Some(position);
        }
        let Some(next) = next else {
            break;
        };
        state = next;
    }
    workspace.clear_frontier();
    best.ok_or(Error::InternalInvariant(
        "lazy reverse selector could not recover the selected match start",
    ))
}

fn build_reverse_transition(
    program: &Program,
    state: u32,
    byte: u8,
    source: &[u8],
    scalar_program: bool,
    cacheable: bool,
    entry: u32,
    workspace: &mut Workspace,
    meter: &mut SweepMeter,
) -> Result<Transition, Error> {
    let scalar = if cacheable {
        None
    } else {
        source_scalar(scalar_program, byte, source)
    };
    let cached = if cacheable {
        workspace.reverse.cell(state, byte)?
    } else {
        workspace.reverse.scalar_cell(state, byte, scalar)?
    };
    if cached != CELL_UNFILLED {
        return Ok(Transition::Ready(cached));
    }
    let scalar = if cacheable {
        source_scalar(scalar_program, byte, source)
    } else {
        scalar
    };
    let (_, length, _) = workspace.reverse.state_bounds(state)?;
    workspace.begin_closure(meter)?;
    for ordinal in 0..length {
        let destination = usize::try_from(workspace.reverse.item(state, ordinal)?)
            .map_err(|_| Error::InternalInvariant("lazy reverse item does not fit usize"))?;
        meter.charge_work(1)?;
        let start =
            *workspace
                .reverse_consume_offsets
                .get(destination)
                .ok_or(Error::InternalInvariant(
                    "reverse consume offset outside graph",
                ))?;
        let end = *workspace
            .reverse_consume_offsets
            .get(destination + 1)
            .ok_or(Error::InternalInvariant(
                "reverse consume end offset outside graph",
            ))?;
        for edge in start..end {
            meter.charge_work(1)?;
            let source =
                *workspace
                    .reverse_consume_sources
                    .get(edge)
                    .ok_or(Error::InternalInvariant(
                        "reverse consume source outside graph",
                    ))?;
            if reverse_consume_matches(
                program,
                source,
                destination,
                byte,
                scalar,
                workspace.reverse_consume_bytes.get(edge).copied().ok_or(
                    Error::InternalInvariant("reverse consume byte set outside graph"),
                )?,
                meter,
            )? {
                workspace.expand_reverse(source, meter)?;
            }
        }
    }
    let accepts = contains_exact(&workspace.scratch[..workspace.scratch_len], entry, meter)?;
    if !sort_speculative(&mut workspace.scratch[..workspace.scratch_len], meter)? {
        workspace.saturated = true;
        workspace.retain_scratch_as_frontier();
        return Ok(Transition::Inline {
            accepted: accepts,
            pending: false,
        });
    }
    let encoded = if workspace.scratch_len == 0 {
        0
    } else {
        match workspace.reverse.intern_speculative(
            &workspace.scratch[..workspace.scratch_len],
            false,
            meter,
        )? {
            Interned::State(next) => next.checked_add(1).ok_or(Error::InternalInvariant(
                "lazy reverse encoded state ID overflowed",
            ))?,
            Interned::Full | Interned::WorkFull => {
                workspace.saturated = true;
                workspace.retain_scratch_as_frontier();
                return Ok(Transition::Inline {
                    accepted: accepts,
                    pending: false,
                });
            }
        }
    };
    let cell = encoded | if accepts { CELL_ACCEPT } else { 0 };
    if cacheable {
        workspace.reverse.set_cell(state, byte, cell)?;
    } else {
        workspace
            .reverse
            .set_scalar_cell(state, byte, scalar, cell)?;
    }
    Ok(Transition::Ready(cell))
}

fn build_inline_reverse_transition(
    program: &Program,
    byte: u8,
    source: &[u8],
    scalar_program: bool,
    entry: u32,
    workspace: &mut Workspace,
    meter: &mut SweepMeter,
) -> Result<Transition, Error> {
    let scalar = source_scalar(scalar_program, byte, source);
    let length = workspace.frontier_len;
    workspace.begin_closure(meter)?;
    for ordinal in 0..length {
        let destination = usize::try_from(workspace.frontier.get(ordinal).copied().ok_or(
            Error::InternalInvariant("inline reverse frontier item outside arena"),
        )?)
        .map_err(|_| Error::InternalInvariant("inline reverse PC does not fit usize"))?;
        meter.charge_work(1)?;
        let start =
            *workspace
                .reverse_consume_offsets
                .get(destination)
                .ok_or(Error::InternalInvariant(
                    "inline reverse consume offset outside graph",
                ))?;
        let end = *workspace
            .reverse_consume_offsets
            .get(destination + 1)
            .ok_or(Error::InternalInvariant(
                "inline reverse consume end offset outside graph",
            ))?;
        for edge in start..end {
            meter.charge_work(1)?;
            let source =
                *workspace
                    .reverse_consume_sources
                    .get(edge)
                    .ok_or(Error::InternalInvariant(
                        "inline reverse consume source outside graph",
                    ))?;
            if reverse_consume_matches(
                program,
                source,
                destination,
                byte,
                scalar,
                workspace.reverse_consume_bytes.get(edge).copied().ok_or(
                    Error::InternalInvariant("inline reverse consume byte set outside graph"),
                )?,
                meter,
            )? {
                workspace.expand_reverse(source, meter)?;
            }
        }
    }
    let accepts = contains_exact(&workspace.scratch[..workspace.scratch_len], entry, meter)?;
    if workspace.scratch_len == 0 {
        workspace.clear_frontier();
        let cell = if accepts { CELL_ACCEPT } else { 0 };
        return Ok(Transition::Ready(cell));
    }
    workspace.retain_scratch_as_frontier();
    Ok(Transition::Inline {
        accepted: accepts,
        pending: false,
    })
}

#[inline]
fn source_byte(
    scalar_program: bool,
    source: &[u8],
    meter: &mut SweepMeter,
) -> Result<(u8, bool), Error> {
    let byte = *source.first().ok_or(Error::InternalInvariant(
        "lazy continuation source position outside input",
    ))?;
    if !scalar_program {
        meter.charge_sequential(1)?;
        return Ok((byte, true));
    }

    // A scalar transition inspects at most one complete UTF-8 scalar. The
    // first byte is included in this charge rather than counted once for the
    // byte symbol and again for the scalar symbol.
    meter.charge_sequential(scalar_source_accesses(source))?;
    // Valid multi-byte lead bytes do not identify a scalar by themselves, so
    // their transition requires the scalar-authenticated side key.
    // Continuation and invalid lead bytes always decode to no scalar and remain
    // safe in the ordinary byte-keyed cells.
    let cacheable = !matches!(byte, 0xC2..=0xF4);
    Ok((byte, cacheable))
}

#[inline]
fn scalar_lead_slot(byte: u8) -> Result<usize, Error> {
    if !matches!(byte, 0xC2..=0xF4) {
        return Err(Error::InternalInvariant(
            "lazy scalar cache received a non-lead byte",
        ));
    }
    Ok(usize::from(byte - SCALAR_LEAD_BASE))
}

#[inline]
fn source_scalar(scalar_program: bool, byte: u8, source: &[u8]) -> Option<char> {
    if !scalar_program {
        None
    } else if byte.is_ascii() {
        Some(char::from(byte))
    } else {
        decode_first_scalar(source)
    }
}

#[inline]
fn scalar_source_accesses(bytes: &[u8]) -> usize {
    let Some(&first) = bytes.first() else {
        return 0;
    };
    let width = match first {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => return 1,
    };
    if bytes.len() < width { 1 } else { width }
}

fn scalar_successor(
    scalars: &ScalarSet,
    next_by_width: &[usize; 4],
    scalar: Option<char>,
    meter: &mut SweepMeter,
) -> Result<Option<usize>, Error> {
    let Some(scalar) = scalar else {
        return Ok(None);
    };
    if !scalars.contains_with(scalar, || meter.charge_work(1))? {
        return Ok(None);
    }
    let width_index = scalar
        .len_utf8()
        .checked_sub(1)
        .ok_or(Error::InternalInvariant(
            "Unicode scalar has zero byte width",
        ))?;
    next_by_width
        .get(width_index)
        .copied()
        .map(Some)
        .ok_or(Error::InternalInvariant(
            "Unicode scalar width outside lazy dispatch",
        ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "reverse byte/scalar edge authentication is kept in one audited helper"
)]
fn reverse_consume_matches(
    program: &Program,
    source: u32,
    destination: usize,
    byte: u8,
    scalar: Option<char>,
    byte_set: ByteSet,
    meter: &mut SweepMeter,
) -> Result<bool, Error> {
    let source = usize::try_from(source)
        .map_err(|_| Error::InternalInvariant("reverse consume source does not fit usize"))?;
    match program.instruction(source)? {
        Inst::Consume { .. } => Ok(byte_set.contains(byte)),
        Inst::ConsumeScalar {
            scalars,
            next_by_width,
        } => Ok(scalar_successor(scalars, next_by_width, scalar, meter)?
            .is_some_and(|next| next == destination)),
        Inst::Unfilled
        | Inst::Fail
        | Inst::Match
        | Inst::Assert { .. }
        | Inst::Split { .. }
        | Inst::RootSplit { .. } => Err(Error::InternalInvariant(
            "reverse consume graph retained a non-consuming source",
        )),
    }
}

const fn complete_value(value: SweepValue, kind: SweepKind) -> SweepValue {
    SweepValue {
        count: value.count,
        span_sum: if matches!(kind, SweepKind::SpanSum | SweepKind::SpanVisit) {
            value.span_sum
        } else {
            0
        },
    }
}

fn sort_exact(values: &mut [u32], meter: &mut SweepMeter) -> Result<(), Error> {
    if values.len() < 2 {
        return Ok(());
    }
    for root in (0..values.len() / 2).rev() {
        sift_down(values, root, values.len(), meter)?;
    }
    for end in (1..values.len()).rev() {
        meter.charge_work(1)?;
        values.swap(0, end);
        sift_down(values, 0, end, meter)?;
    }
    Ok(())
}

fn contains_exact(values: &[u32], needle: u32, meter: &mut SweepMeter) -> Result<bool, Error> {
    for &value in values {
        meter.charge_work(1)?;
        if value == needle {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Sort a runtime reverse frontier only when its complete materialization fits
/// the speculative learning allowance. Charging the conservative heapsort
/// upper atomically ensures a refusal cannot leave a partially sorted
/// frontier; the unmetered implementation performs no work outside that
/// already charged envelope.
fn sort_speculative(values: &mut [u32], meter: &mut SweepMeter) -> Result<bool, Error> {
    if values.len() < 2 {
        return Ok(true);
    }
    let levels = usize::try_from(usize::BITS - values.len().leading_zeros()).map_err(|_| {
        Error::ArithmeticOverflow {
            resource: Resource::ExecutionWork,
        }
    })?;
    let upper = mul(
        mul(
            values.len(),
            add(levels, 1, Resource::ExecutionWork)?,
            Resource::ExecutionWork,
        )?,
        4,
        Resource::ExecutionWork,
    )?;
    if !meter.charge_cache_work(upper)? {
        return Ok(false);
    }
    for root in (0..values.len() / 2).rev() {
        sift_down_unmetered(values, root, values.len())?;
    }
    for end in (1..values.len()).rev() {
        values.swap(0, end);
        sift_down_unmetered(values, 0, end)?;
    }
    Ok(true)
}

fn sift_down_unmetered(values: &mut [u32], mut root: usize, end: usize) -> Result<(), Error> {
    loop {
        let Some(mut child) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            return Err(Error::ArithmeticOverflow {
                resource: Resource::ExecutionWork,
            });
        };
        if child >= end {
            return Ok(());
        }
        if child + 1 < end && values[child] < values[child + 1] {
            child += 1;
        }
        if values[root] >= values[child] {
            return Ok(());
        }
        values.swap(root, child);
        root = child;
    }
}

fn sift_down(
    values: &mut [u32],
    mut root: usize,
    end: usize,
    meter: &mut SweepMeter,
) -> Result<(), Error> {
    loop {
        let Some(mut child) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            return Err(Error::ArithmeticOverflow {
                resource: Resource::ExecutionWork,
            });
        };
        if child >= end {
            return Ok(());
        }
        if child + 1 < end {
            meter.charge_work(1)?;
            if values[child] < values[child + 1] {
                child += 1;
            }
        }
        meter.charge_work(1)?;
        if values[root] >= values[child] {
            return Ok(());
        }
        meter.charge_work(1)?;
        values.swap(root, child);
        root = child;
    }
}

fn increment_edge_count(offsets: &mut [usize], target: usize, states: usize) -> Result<(), Error> {
    if target >= states {
        return Err(Error::InternalInvariant(
            "lazy reverse edge target outside program",
        ));
    }
    let slot = offsets.get_mut(target + 1).ok_or(Error::InternalInvariant(
        "lazy reverse edge count outside offsets",
    ))?;
    *slot = add(*slot, 1, Resource::ScratchBytes)?;
    Ok(())
}

fn prefix_counts(offsets: &mut [usize], meter: &mut SweepMeter) -> Result<(), Error> {
    for index in 1..offsets.len() {
        meter.charge_work(1)?;
        offsets[index] = add(offsets[index], offsets[index - 1], Resource::ScratchBytes)?;
    }
    Ok(())
}

fn fill_source(
    cursors: &mut [usize],
    sources: &mut [u32],
    target: usize,
    source: u32,
) -> Result<(), Error> {
    let slot = *cursors.get(target).ok_or(Error::InternalInvariant(
        "lazy reverse edge target outside cursors",
    ))?;
    *sources.get_mut(slot).ok_or(Error::InternalInvariant(
        "lazy reverse edge source outside arena",
    ))? = source;
    cursors[target] = add(slot, 1, Resource::ScratchBytes)?;
    Ok(())
}

pub(super) fn upper_bounds(
    program_states: usize,
    max_nonaccepting_run: Option<usize>,
    minimum_match_bytes: Option<usize>,
) -> Result<ContinuationSweepUpperBounds, Error> {
    let profile = cache_profile(program_states);
    prospective_upper_bounds_with_run(
        program_states,
        profile.states,
        profile.items,
        max_nonaccepting_run,
        minimum_match_bytes,
    )
}

#[cfg(test)]
fn prospective_upper_bounds(
    states: usize,
    state_capacity: usize,
    max_items: usize,
) -> Result<ContinuationSweepUpperBounds, Error> {
    prospective_upper_bounds_with_run(states, state_capacity, max_items, None, None)
}

fn prospective_upper_bounds_with_run(
    states: usize,
    state_capacity: usize,
    max_items: usize,
    max_nonaccepting_run: Option<usize>,
    minimum_match_bytes: Option<usize>,
) -> Result<ContinuationSweepUpperBounds, Error> {
    if states == 0 {
        return Err(Error::InternalInvariant(
            "lazy continuation requires a nonempty program",
        ));
    }
    if states > u32::MAX as usize {
        return Err(Error::ArithmeticOverflow {
            resource: Resource::ProgramStates,
        });
    }
    let stack_slots = add(
        mul(states, 2, Resource::ScratchBytes)?,
        1,
        Resource::ScratchBytes,
    )?;
    let epsilon_edges = mul(states, 2, Resource::ScratchBytes)?;
    let consume_edges = mul(states, 4, Resource::ScratchBytes)?;
    let item_capacity = mul(states, state_capacity, Resource::ScratchBytes)?
        .min(max_items)
        .max(states);
    let workspace_bytes = logical_workspace_bytes(
        states,
        stack_slots,
        epsilon_edges,
        consume_edges,
        state_capacity,
        item_capacity,
    )?;
    let table_cells = mul(
        mul(
            state_capacity,
            BYTE_ALPHABET + SCALAR_LEAD_SLOTS,
            Resource::TableCells,
        )?,
        2,
        Resource::TableCells,
    )?;

    // Every fixed arena slot is initialized at most once. Split-free scalar
    // chains defer untouched cache rows, but this source-free envelope still
    // charges every possible write. The remaining setup traverses a graph
    // with at most 2S epsilon edges and sorts at most S reverse-closure PCs.
    // Sixty-four charged operations per state/log-level conservatively covers
    // graph census, prefix sums, closure expansion, heapsort, binary search
    // and both initial state copies.
    let workspace_slots = add(
        mul(states, 18, Resource::ExecutionWork)?,
        3,
        Resource::ExecutionWork,
    )?;
    let one_cache_slots = add(
        mul(
            state_capacity,
            BYTE_ALPHABET + 3 * SCALAR_LEAD_SLOTS + 4,
            Resource::ExecutionWork,
        )?,
        item_capacity,
        Resource::ExecutionWork,
    )?;
    let initialization_work = add(
        workspace_slots,
        mul(one_cache_slots, 2, Resource::ExecutionWork)?,
        Resource::ExecutionWork,
    )?;
    let log_levels = usize::try_from(usize::BITS - states.leading_zeros()).map_err(|_| {
        Error::ArithmeticOverflow {
            resource: Resource::ExecutionWork,
        }
    })?;
    let setup_work = mul(
        mul(states, log_levels, Resource::ExecutionWork)?,
        64,
        Resource::ExecutionWork,
    )?;
    let preparation_work = add(initialization_work, setup_work, Resource::ExecutionWork)?;
    Ok(ContinuationSweepUpperBounds {
        table_cells,
        workspace_bytes,
        preparation_work,
        learning_work: mul(preparation_work, 4, Resource::ExecutionWork)?,
        max_nonaccepting_run,
        minimum_match_bytes,
    })
}

pub(super) fn run_upper_bounds(
    input_bytes: usize,
    execution_state_work: usize,
    max_nonaccepting_run: Option<usize>,
    minimum_match_bytes: usize,
) -> Result<ContinuationSweepRunUpperBounds, Error> {
    if execution_state_work == 0 || minimum_match_bytes == 0 {
        return Err(Error::InternalInvariant(
            "continuation sweep requires nonzero execution-state work and match width",
        ));
    }
    let match_upper = input_bytes / minimum_match_bytes;
    let forward_visits = if let Some(nonaccepting) = max_nonaccepting_run {
        // One complete source pass plus at most `nonaccepting + 1` replayed
        // bytes per non-empty selected match (the extra byte is the
        // transition that kills the higher-priority frontier).
        let replay_per_match = add(nonaccepting, 1, Resource::SequentialBytes)?;
        add(
            input_bytes,
            mul(match_upper, replay_per_match, Resource::SequentialBytes)?,
            Resource::SequentialBytes,
        )?
    } else {
        // Without the acyclic certificate, every selected nonempty match
        // still advances the cursor by at least the authenticated minimum
        // width. Sum the worst complete suffix walks:
        // N + (N-W) + ... + (N-QW), Q=floor(N/W).
        let terms = add(match_upper, 1, Resource::SequentialBytes)?;
        let consumed = mul(match_upper, minimum_match_bytes, Resource::SequentialBytes)?;
        let last = input_bytes
            .checked_sub(consumed)
            .ok_or(Error::InternalInvariant(
                "continuation match-width quotient exceeded the input",
            ))?;
        if terms.is_multiple_of(2) {
            mul(
                terms / 2,
                add(input_bytes, last, Resource::SequentialBytes)?,
                Resource::SequentialBytes,
            )?
        } else {
            // An odd number of terms means `match_upper` is even, so the
            // endpoints have equal parity and can be halved without overflow.
            let half_endpoints = add(
                add(input_bytes / 2, last / 2, Resource::SequentialBytes)?,
                input_bytes % 2,
                Resource::SequentialBytes,
            )?;
            mul(terms, half_endpoints, Resource::SequentialBytes)?
        }
    };
    // A scalar-capable transition may inspect one complete UTF-8 scalar at a
    // byte boundary. The fixed envelope is public and state-count-only, so it
    // conservatively covers four source-byte accesses per forward or reverse
    // transition even when the concrete program is byte-only.
    let count_sequential_bytes = mul(forward_visits, 4, Resource::SequentialBytes)?;
    let span_sum_sequential_bytes = add(
        count_sequential_bytes,
        mul(input_bytes, 4, Resource::SequentialBytes)?,
        Resource::SequentialBytes,
    )?;
    let forward_step = add(execution_state_work, 2, Resource::ExecutionWork)?;
    // Inline reverse closure plus its linear acceptance probe is bounded by
    // twice the certified complete-program state work and one source unit.
    let reverse_step = add(
        mul(execution_state_work, 2, Resource::ExecutionWork)?,
        1,
        Resource::ExecutionWork,
    )?;
    let count_match = add(execution_state_work, 1, Resource::ExecutionWork)?;
    let span_match = reverse_step;
    // At most one generation wrap can occur in one representable operation;
    // execution-state work is at least the program-state count.
    let generation_reset = execution_state_work;
    let forward_work = mul(forward_visits, forward_step, Resource::ExecutionWork)?;
    let count_work = add(
        add(
            forward_work,
            mul(match_upper, count_match, Resource::ExecutionWork)?,
            Resource::ExecutionWork,
        )?,
        generation_reset,
        Resource::ExecutionWork,
    )?;
    let span_sum_work = add(
        add(
            add(
                forward_work,
                mul(input_bytes, reverse_step, Resource::ExecutionWork)?,
                Resource::ExecutionWork,
            )?,
            mul(match_upper, span_match, Resource::ExecutionWork)?,
            Resource::ExecutionWork,
        )?,
        generation_reset,
        Resource::ExecutionWork,
    )?;
    Ok(ContinuationSweepRunUpperBounds {
        count_work,
        span_sum_work,
        count_sequential_bytes,
        span_sum_sequential_bytes,
    })
}

fn logical_workspace_bytes(
    states: usize,
    stack_slots: usize,
    epsilon_edges: usize,
    consume_edges: usize,
    dfa_states: usize,
    dfa_items: usize,
) -> Result<usize, Error> {
    let graph_offsets = mul(
        add(
            mul(
                add(states, 1, Resource::ScratchBytes)?,
                2,
                Resource::ScratchBytes,
            )?,
            states,
            Resource::ScratchBytes,
        )?,
        size_of::<usize>(),
        Resource::ScratchBytes,
    )?;
    let graph_items = add(
        mul(
            add(epsilon_edges, consume_edges, Resource::ScratchBytes)?,
            size_of::<u32>(),
            Resource::ScratchBytes,
        )?,
        mul(consume_edges, size_of::<ByteSet>(), Resource::ScratchBytes)?,
        Resource::ScratchBytes,
    )?;
    let closure = add(
        mul(states, size_of::<u64>(), Resource::ScratchBytes)?,
        mul(
            add(
                mul(states, 2, Resource::ScratchBytes)?,
                stack_slots,
                Resource::ScratchBytes,
            )?,
            size_of::<u32>(),
            Resource::ScratchBytes,
        )?,
        Resource::ScratchBytes,
    )?;
    let one_cache = add(
        mul(
            mul(dfa_states, BYTE_ALPHABET, Resource::ScratchBytes)?,
            size_of::<u32>(),
            Resource::ScratchBytes,
        )?,
        add(
            add(
                mul(dfa_states, size_of::<usize>(), Resource::ScratchBytes)?,
                mul(
                    mul(dfa_states, 3 * SCALAR_LEAD_SLOTS, Resource::ScratchBytes)?,
                    size_of::<u32>(),
                    Resource::ScratchBytes,
                )?,
                Resource::ScratchBytes,
            )?,
            add(
                mul(dfa_states, size_of::<u32>(), Resource::ScratchBytes)?,
                add(
                    mul(dfa_states, size_of::<u64>(), Resource::ScratchBytes)?,
                    add(
                        dfa_states,
                        mul(dfa_items, size_of::<u32>(), Resource::ScratchBytes)?,
                        Resource::ScratchBytes,
                    )?,
                    Resource::ScratchBytes,
                )?,
                Resource::ScratchBytes,
            )?,
            Resource::ScratchBytes,
        )?,
        Resource::ScratchBytes,
    )?;
    add(
        add(graph_offsets, graph_items, Resource::ScratchBytes)?,
        add(
            closure,
            mul(one_cache, 2, Resource::ScratchBytes)?,
            Resource::ScratchBytes,
        )?,
        Resource::ScratchBytes,
    )
}

fn enforce_workspace_bytes(bytes: usize, limits: OperationLimits) -> Result<(), Error> {
    enforce(bytes, limits.max_scratch_bytes, Resource::ScratchBytes)?;
    enforce(
        bytes,
        limits.max_random_access_bytes,
        Resource::RandomAccessBytes,
    )?;
    enforce(bytes, limits.max_peak_bytes, Resource::PeakBytes)
}

fn enforce_sweep_upper_bounds(
    upper: ContinuationSweepUpperBounds,
    limits: OperationLimits,
) -> Result<(), Error> {
    enforce(
        upper.table_cells,
        limits.max_table_cells,
        Resource::TableCells,
    )?;
    enforce_workspace_bytes(upper.workspace_bytes, limits)
}

fn reserved_slots<T>(length: usize, total_bytes: usize) -> Result<ExactVec<T>, Error> {
    #[cfg(test)]
    if test_fault::take_fixed_allocation_failure() {
        return Err(Error::AllocationFailed {
            resource: Resource::ScratchBytes,
            items: total_bytes,
        });
    }
    ExactVec::try_with_capacity(length).map_err(|error| match error {
        CopyError::LayoutOverflow => Error::ArithmeticOverflow {
            resource: Resource::ScratchBytes,
        },
        CopyError::AllocationFailed => Error::AllocationFailed {
            resource: Resource::ScratchBytes,
            items: total_bytes,
        },
    })
}

fn initialize_slots<T: Copy>(
    output: &mut ExactVec<T>,
    length: usize,
    value: T,
    meter: &mut SweepMeter,
) -> Result<(), Error> {
    if !output.is_empty() || output.capacity() != length {
        return Err(Error::InternalInvariant(
            "reserved lazy workspace has an unexpected shape",
        ));
    }
    meter.charge_work(length)?;
    for _ in 0..length {
        output
            .try_push(value)
            .map_err(|_| Error::InternalInvariant("exact lazy workspace changed capacity"))?;
    }
    Ok(())
}

fn new_state_initialization_work(items: usize, deferred: bool) -> Result<usize, Error> {
    add(
        add(items, 1, Resource::ExecutionWork)?,
        if deferred {
            DEFERRED_ROW_INITIALIZATION_SLOTS
        } else {
            0
        },
        Resource::ExecutionWork,
    )
}

fn push_repeated<T: Copy>(output: &mut ExactVec<T>, length: usize, value: T) -> Result<(), Error> {
    for _ in 0..length {
        output.try_push(value).map_err(|_| {
            Error::InternalInvariant("reserved lazy cache changed capacity during initialization")
        })?;
    }
    Ok(())
}

fn validate_empty_reservation<T>(output: &ExactVec<T>, capacity: usize) -> Result<(), Error> {
    if !output.is_empty() || output.capacity() != capacity {
        return Err(Error::InternalInvariant(
            "reserved lazy row cache has an unexpected shape",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn allocated_slots<T: Copy>(
    length: usize,
    value: T,
    total_bytes: usize,
    meter: &mut SweepMeter,
) -> Result<ExactVec<T>, Error> {
    let mut output = reserved_slots(length, total_bytes)?;
    initialize_slots(&mut output, length, value, meter)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use regex_syntax::ParserBuilder;

    use super::{
        BYTE_ALPHABET, CELL_UNFILLED, FIXED_ARENA_ALLOCATIONS, MAX_DFA_ITEMS, MAX_DFA_STATES,
        SCALAR_LEAD_SLOTS, Workspace, allocated_slots, execute_prepared, prospective_upper_bounds,
        prospective_upper_bounds_with_run, reduce, run_upper_bounds,
    };
    use crate::sweep::{SweepKind, SweepMeter, SweepOutcome, SweepValue};
    use crate::{
        CompileLimits, CompiledRegex, Error, OperationLimits, Resource, RustByteProfile, Strategy,
    };

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

    fn compiled_unicode(pattern: &str) -> CompiledRegex {
        let hir = ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap();
        CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn deferred_eligible(regex: &CompiledRegex) -> bool {
        let mut meter = SweepMeter::new(OperationLimits::default());
        super::deferred_cache_initialization_eligible(&regex.program, &mut meter).unwrap()
    }

    fn expected(regex: &CompiledRegex, haystack: &[u8], range: Range<usize>) -> SweepValue {
        SweepValue {
            count: regex
                .count_value(
                    haystack,
                    range.clone(),
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
            span_sum: regex
                .span_sum_value(
                    haystack,
                    range,
                    Strategy::ReverseSequentialRows,
                    OperationLimits::default(),
                )
                .unwrap(),
        }
    }

    fn complete(
        regex: &CompiledRegex,
        haystack: &[u8],
        range: Range<usize>,
        kind: SweepKind,
        workspace: &mut Workspace,
    ) -> SweepValue {
        let outcome = reduce(
            regex.plan_id(),
            &regex.program,
            haystack,
            range,
            kind,
            regex.minimum_match_bytes,
            OperationLimits::default(),
            workspace,
            None,
        )
        .unwrap()
        .expect("byte program is lazy-DFA eligible");
        let SweepOutcome::Complete(value) = outcome;
        value
    }

    fn complete_bounded(
        regex: &CompiledRegex,
        haystack: &[u8],
        kind: SweepKind,
        state_capacity: usize,
        workspace: &mut Workspace,
    ) -> (SweepValue, usize, bool) {
        let (admitted, preparation_work) = workspace
            .prepare_bounded(
                regex.plan_id(),
                &regex.program,
                OperationLimits::default(),
                state_capacity,
                MAX_DFA_ITEMS,
            )
            .unwrap();
        assert!(admitted);
        let limits = OperationLimits::default();
        let mut meter =
            SweepMeter::with_cache_budget(limits, limits.max_work.saturating_sub(preparation_work));
        meter.charge_work(preparation_work).unwrap();
        let SweepOutcome::Complete(value) =
            execute_test(&regex.program, haystack, kind, workspace, &mut meter).unwrap();
        (value, meter.sequential, workspace.saturated)
    }

    fn complete_inline_accounted(
        regex: &CompiledRegex,
        haystack: &[u8],
        kind: SweepKind,
        workspace: &mut Workspace,
    ) -> (SweepValue, usize, usize) {
        let (admitted, preparation_work) = workspace
            .prepare_bounded(
                regex.plan_id(),
                &regex.program,
                OperationLimits::default(),
                MAX_DFA_STATES,
                MAX_DFA_ITEMS,
            )
            .unwrap();
        assert!(admitted);
        let mut meter = SweepMeter::with_cache_budget(OperationLimits::default(), 0);
        meter.charge_work(preparation_work).unwrap();
        let SweepOutcome::Complete(value) =
            execute_test(&regex.program, haystack, kind, workspace, &mut meter).unwrap();
        (
            value,
            meter.work.checked_sub(preparation_work).unwrap(),
            meter.sequential,
        )
    }

    fn execute_test(
        program: &crate::program::Program,
        haystack: &[u8],
        kind: SweepKind,
        workspace: &mut Workspace,
        meter: &mut SweepMeter,
    ) -> Result<SweepOutcome, Error> {
        let mut visitor = None;
        execute_prepared(program, haystack, 0, kind, workspace, meter, &mut visitor)
    }

    #[test]
    fn cache_profile_expands_only_for_large_programs() {
        assert_eq!(
            super::cache_profile(super::LARGE_DFA_PROGRAM_STATES - 1),
            super::CacheProfile {
                states: MAX_DFA_STATES,
                items: MAX_DFA_ITEMS,
            }
        );
        assert_eq!(
            super::cache_profile(super::LARGE_DFA_PROGRAM_STATES),
            super::CacheProfile {
                states: super::LARGE_DFA_STATES,
                items: super::LARGE_DFA_ITEMS,
            }
        );

        let small =
            super::upper_bounds(super::LARGE_DFA_PROGRAM_STATES - 1, None, Some(1)).unwrap();
        let large = super::upper_bounds(super::LARGE_DFA_PROGRAM_STATES, None, Some(1)).unwrap();
        assert!(large.table_cells > small.table_cells);
        assert!(large.workspace_bytes > small.workspace_bytes);
        assert!(large.preparation_work > small.preparation_work);
    }

    #[test]
    #[ignore = "allocates the complete large-program continuation cache"]
    fn large_profile_visits_exact_nonoverlapping_spans() {
        let regex = compiled("a{1000}a{1000}a{1000}a{1000}a{96}");
        assert!(regex.program.insts.len() >= super::LARGE_DFA_PROGRAM_STATES);
        let haystack = vec![b'a'; 8_193];
        let mut workspace = Workspace::new();
        let mut spans = Vec::new();
        let mut visitor = |span: crate::Span| spans.push((span.start, span.end));
        let outcome = reduce(
            regex.plan_id(),
            &regex.program,
            &haystack,
            0..haystack.len(),
            SweepKind::SpanVisit,
            regex.minimum_match_bytes,
            OperationLimits::default(),
            &mut workspace,
            Some(&mut visitor),
        )
        .unwrap()
        .expect("large positive-width program selects the continuation sweep");
        assert_eq!(
            outcome,
            SweepOutcome::Complete(SweepValue {
                count: 2,
                span_sum: 8_192,
            })
        );
        assert_eq!(spans, [(0, 4_096), (4_096, 8_192)]);
        assert_eq!(
            workspace.forward.offsets.capacity(),
            super::LARGE_DFA_STATES
        );
        assert_eq!(
            workspace.reverse.offsets.capacity(),
            super::LARGE_DFA_STATES
        );
    }

    #[test]
    fn frontier_hash_collision_still_compares_complete_state() {
        let mut meter = SweepMeter::new(OperationLimits::default());
        let mut cache = super::LazyCache::reserved(2, 8, 4_096).unwrap();
        cache.initialize_storage(2, 8, false, &mut meter).unwrap();
        assert_eq!(
            cache.intern(&[1, 2], false, &mut meter).unwrap(),
            super::Interned::State(0)
        );
        cache.hashes[0] = super::frontier_hash(&[3, 4], false);
        assert_eq!(
            cache.intern(&[3, 4], false, &mut meter).unwrap(),
            super::Interned::State(1)
        );
        assert_eq!(cache.state_len, 2);
        assert_eq!(&cache.items[..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn ordered_lazy_dfa_preserves_priority_non_greedy_and_raw_bytes() {
        let cases: &[(&str, &[u8])] = &[
            ("a|ab", b"abab"),
            ("ab|a", b"abab"),
            ("(?:a+b|a)", b"aaaaaaaaab--aaaa"),
            ("(?:a.*z|a)", b"aqqqa--az--a123z"),
            ("(?:ab|a)b", b"ababb"),
            ("(?:ab|b)", b"ab"),
            ("(?:a|ba)", b"ba"),
            ("(?:a|aa)b", b"aab"),
            ("(?:ab+c|a)", b"abbbx--abbbc"),
            ("a+?", b"aaaa"),
            ("a+", b"aaaa"),
            ("(?:a|aa)+b", b"aaaaab aaab"),
            ("(?:ab|ac)+?d", b"abacacdxxababd"),
            ("(?i:Sherlock|Watson)+", b"xxsHeRlOcKWatSONyy"),
            (r"(?:\xFF+\x00|\x80)", b"\xFF\xFF\x00a\x80\xC3\x28\xFF"),
        ];
        for &(pattern, haystack) in cases {
            let regex = compiled(pattern);
            let want = expected(&regex, haystack, 0..haystack.len());
            let mut count_workspace = Workspace::new();
            let mut sum_workspace = Workspace::new();
            assert_eq!(
                complete(
                    &regex,
                    haystack,
                    0..haystack.len(),
                    SweepKind::Count,
                    &mut count_workspace,
                )
                .count,
                want.count,
                "count pattern={pattern:?}"
            );
            assert_eq!(
                complete(
                    &regex,
                    haystack,
                    0..haystack.len(),
                    SweepKind::SpanSum,
                    &mut sum_workspace,
                )
                .span_sum,
                want.span_sum,
                "span-sum pattern={pattern:?}"
            );
        }
    }

    #[test]
    fn scalar_lazy_dfa_is_differential_across_widths_ranges_and_invalid_bytes() {
        let cases = [
            (
                r"[éè]+",
                b"\xC3\xAA--\xC3\xA9\xC3\xA8--\xC3\x28--\xC3\xA9".as_slice(),
            ),
            (
                r"[AéΩ🦀]+",
                b"xA\xC3\xA9\xCE\xA9\xF0\x9F\xA6\x80y--\xCE\xA9A".as_slice(),
            ),
            (
                r"(?:\p{Greek}{1,3}|[éè]+|[0-9]+)",
                b"\xCE\xA9\xCE\xB4--123--\xC3\xA9\xC3\xA8--\xFF--\xCE\xB1".as_slice(),
            ),
        ];
        for (pattern, haystack) in cases {
            let regex = compiled_unicode(pattern);
            assert!(regex.program.contains_scalar_transition());
            let mut count_workspace = Workspace::new();
            let mut sum_workspace = Workspace::new();
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let range = start..end;
                    let want = expected(&regex, haystack, range.clone());
                    let count = complete(
                        &regex,
                        haystack,
                        range.clone(),
                        SweepKind::Count,
                        &mut count_workspace,
                    );
                    let sum = complete(
                        &regex,
                        haystack,
                        range,
                        SweepKind::SpanSum,
                        &mut sum_workspace,
                    );
                    assert_eq!(
                        count.count, want.count,
                        "count pattern={pattern:?} start={start} end={end}"
                    );
                    assert_eq!(
                        sum.span_sum, want.span_sum,
                        "span pattern={pattern:?} start={start} end={end}"
                    );
                }
            }
        }
    }

    #[test]
    fn bounded_rewind_certificate_and_generic_adversary_bound_are_exact() {
        let regex = compiled("(?:a.*z|a)");
        assert_eq!(regex.program.continuation_nonaccepting_run(), None);
        assert_eq!(
            compiled("a+").program.continuation_nonaccepting_run(),
            Some(0)
        );
        assert_eq!(
            compiled("(?:a+b|a)")
                .program
                .continuation_nonaccepting_run(),
            None
        );
        assert_eq!(
            compiled("Tom.{10,25}river|river.{10,25}Tom")
                .program
                .continuation_nonaccepting_run(),
            Some(32)
        );
        assert_eq!(
            compiled("abcdefghijklmnopq")
                .program
                .continuation_nonaccepting_run(),
            Some(16)
        );
        for length in [4_usize, 8, 16, 32, 64] {
            let haystack = vec![b'a'; length];
            let mut workspace = Workspace::new();
            let (_, sequential, _) = complete_bounded(
                &regex,
                &haystack,
                SweepKind::SpanSum,
                MAX_DFA_STATES,
                &mut workspace,
            );
            let triangular = length * (length + 1) / 2;
            assert_eq!(sequential, triangular + length);
            let upper = run_upper_bounds(
                length,
                regex.program.execution_state_work(),
                regex.program.continuation_nonaccepting_run(),
                regex.minimum_match_bytes.unwrap(),
            )
            .unwrap();
            assert!(sequential <= upper.span_sum_sequential_bytes);
        }
    }

    #[test]
    fn authenticated_minimum_width_tightens_match_and_suffix_walk_bounds() {
        let one_byte = run_upper_bounds(100, 15, Some(3), 1).unwrap();
        let ten_bytes = run_upper_bounds(100, 15, Some(3), 10).unwrap();
        assert_eq!(one_byte.count_sequential_bytes, 2_000);
        assert_eq!(ten_bytes.count_sequential_bytes, 560);
        assert!(ten_bytes.count_work < one_byte.count_work);

        let generic_one_byte = run_upper_bounds(100, 15, None, 1).unwrap();
        let generic_ten_bytes = run_upper_bounds(100, 15, None, 10).unwrap();
        assert_eq!(generic_one_byte.count_sequential_bytes, 20_200);
        assert_eq!(generic_ten_bytes.count_sequential_bytes, 2_200);
        assert!(generic_ten_bytes.span_sum_work < generic_one_byte.span_sum_work);
    }

    #[test]
    fn workspace_plan_binding_distinguishes_equal_size_program_shapes() {
        let first = compiled("abcdefghijklmnopq");
        let second = compiled("abcdefghijklmnopx");
        assert_eq!(first.program.insts.len(), second.program.insts.len());
        assert_ne!(first.plan_id(), second.plan_id());

        let mut workspace = Workspace::new();
        assert!(
            workspace
                .prepare(first.plan_id(), &first.program, OperationLimits::default(),)
                .unwrap()
                .0
        );
        assert_eq!(workspace.plan_id, Some(first.plan_id()));
        assert!(
            workspace
                .prepare(
                    second.plan_id(),
                    &second.program,
                    OperationLimits::default(),
                )
                .unwrap()
                .0
        );
        assert_eq!(workspace.plan_id, Some(second.plan_id()));
    }

    #[test]
    fn ordered_lazy_dfa_is_exhaustively_differential_and_length_agnostic() {
        let patterns = [
            "(?:ab|a)+z",
            "(?:a+b|a)",
            "(?:ab|ac)+d",
            "(?:[ab][cd]|[cd][ab])+(?:x|yz)",
            "[ab]+[cd]+",
            "(?:a|bc)+d",
            "(?:a+?|b+)c",
            "(?:ab|a)b+",
        ];
        let alphabet = [b'a', b'b', b'c'];
        let mut haystack = Vec::new();
        let mut checked = 0_usize;
        for pattern in patterns {
            let regex = compiled(pattern);
            let mut count_workspace = Workspace::new();
            let mut sum_workspace = Workspace::new();
            for encoded in 0_usize..729 {
                haystack.clear();
                let mut value = encoded;
                let length = encoded % 7;
                for _ in 0..length {
                    haystack.push(alphabet[value % alphabet.len()]);
                    value /= alphabet.len();
                }
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let range = start..end;
                        let want = expected(&regex, &haystack, range.clone());
                        let count = complete(
                            &regex,
                            &haystack,
                            range.clone(),
                            SweepKind::Count,
                            &mut count_workspace,
                        );
                        let sum = complete(
                            &regex,
                            &haystack,
                            range,
                            SweepKind::SpanSum,
                            &mut sum_workspace,
                        );
                        assert_eq!(
                            count.count, want.count,
                            "count pattern={pattern:?} haystack={haystack:?} start={start} end={end}"
                        );
                        assert_eq!(
                            sum.span_sum, want.span_sum,
                            "span pattern={pattern:?} haystack={haystack:?} start={start} end={end}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 10_000);
    }

    #[test]
    fn mandatory_inline_bounds_cover_exhaustive_small_program_runs() {
        let patterns = [
            "abcdefghijklmnopq",
            "Tom.{1,3}river|river.{1,3}Tom",
            "(?:a+b|a)",
            "(?:a.*z|a)",
        ];
        let alphabet = [b'a', b'b', b'z'];
        let mut haystack = Vec::new();
        for pattern in patterns {
            let regex = compiled(pattern);
            let mut count_workspace = Workspace::new();
            let mut sum_workspace = Workspace::new();
            for encoded in 0_usize..243 {
                haystack.clear();
                let mut value = encoded;
                let length = encoded % 6;
                for _ in 0..length {
                    haystack.push(alphabet[value % alphabet.len()]);
                    value /= alphabet.len();
                }
                let upper = run_upper_bounds(
                    haystack.len(),
                    regex.program.execution_state_work(),
                    regex.program.continuation_nonaccepting_run(),
                    regex.minimum_match_bytes.unwrap(),
                )
                .unwrap();
                let (_, count_work, count_sequential) = complete_inline_accounted(
                    &regex,
                    &haystack,
                    SweepKind::Count,
                    &mut count_workspace,
                );
                assert!(count_work <= upper.count_work, "pattern={pattern:?}");
                assert!(
                    count_sequential <= upper.count_sequential_bytes,
                    "pattern={pattern:?}"
                );
                let (_, sum_work, sum_sequential) = complete_inline_accounted(
                    &regex,
                    &haystack,
                    SweepKind::SpanSum,
                    &mut sum_workspace,
                );
                assert!(sum_work <= upper.span_sum_work, "pattern={pattern:?}");
                assert!(
                    sum_sequential <= upper.span_sum_sequential_bytes,
                    "pattern={pattern:?}"
                );
            }
        }
    }

    #[test]
    fn inline_saturation_is_exhaustively_differential_on_small_inputs() {
        let patterns = ["(?:ab|a)+z", "(?:a+b|a)", "(?:ab|ac)+d"];
        let alphabet = [b'a', b'b', b'c'];
        let mut haystack = Vec::new();
        let mut saturated = 0_usize;
        for pattern in patterns {
            let regex = compiled(pattern);
            let mut count_workspace = Workspace::new();
            let mut sum_workspace = Workspace::new();
            for encoded in 0_usize..243 {
                haystack.clear();
                let mut value = encoded;
                let length = encoded % 6;
                for _ in 0..length {
                    haystack.push(alphabet[value % alphabet.len()]);
                    value /= alphabet.len();
                }
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let local = &haystack[start..end];
                        let want = expected(&regex, &haystack, start..end);
                        let (count, _, count_saturated) = complete_bounded(
                            &regex,
                            local,
                            SweepKind::Count,
                            1,
                            &mut count_workspace,
                        );
                        let (sum, _, sum_saturated) = complete_bounded(
                            &regex,
                            local,
                            SweepKind::SpanSum,
                            1,
                            &mut sum_workspace,
                        );
                        assert_eq!(
                            count.count, want.count,
                            "count pattern={pattern:?} local={local:?}"
                        );
                        assert_eq!(
                            sum.span_sum, want.span_sum,
                            "span pattern={pattern:?} local={local:?}"
                        );
                        saturated += usize::from(count_saturated || sum_saturated);
                    }
                }
            }
        }
        assert!(saturated > 1_000);
    }

    #[test]
    fn reverse_cache_saturation_hands_off_without_source_replay() {
        let cases: &[(&str, &[u8])] = &[
            ("(?:ab|ac|ad|ba|bc|bd)+z", b"bdacbcadabz"),
            ("(?:a+b|a)", b"aaaaaaaaab"),
            ("(?:ab|a)b+", b"ababbb"),
            ("a(?:bc|de|fg|hi)+z", b"adefgbciz"),
            ("abcdefghijklmnopq", b"abcdefghijklmnopq"),
        ];
        let mut selected = None;
        for &(pattern, haystack) in cases {
            let regex = compiled(pattern);
            let mut full = Workspace::new();
            let (value, sequential, saturated) = complete_bounded(
                &regex,
                haystack,
                SweepKind::SpanSum,
                MAX_DFA_STATES,
                &mut full,
            );
            assert!(!saturated);
            if full.reverse.state_len > full.forward.state_len {
                selected = Some((regex, haystack, value, sequential, full.forward.state_len));
                break;
            }
        }
        let (regex, haystack, want, full_sequential, forward_states) =
            selected.expect("test corpus must contain a reverse-wider path");
        let mut capped = Workspace::new();
        let (got, capped_sequential, saturated) = complete_bounded(
            &regex,
            haystack,
            SweepKind::SpanSum,
            forward_states,
            &mut capped,
        );
        assert!(saturated);
        assert_eq!(got, want);
        assert_eq!(capped_sequential, full_sequential);
        assert_eq!(capped.forward.state_len, forward_states);
        assert_eq!(capped.reverse.state_len, forward_states);
    }

    #[test]
    fn speculative_work_full_preserves_priority_and_reverse_frontiers() {
        let regex = compiled("(?:a+b|a)");
        let haystack = vec![b'a'; 128];
        let want = expected(&regex, &haystack, 0..haystack.len());
        for cache_work in [0_usize, 1] {
            let mut workspace = Workspace::new();
            let (admitted, preparation_work) = workspace
                .prepare(regex.plan_id(), &regex.program, OperationLimits::default())
                .unwrap();
            assert!(admitted);
            let mut meter = SweepMeter::with_cache_budget(OperationLimits::default(), cache_work);
            meter.charge_work(preparation_work).unwrap();
            let SweepOutcome::Complete(value) = execute_test(
                &regex.program,
                &haystack,
                SweepKind::Count,
                &mut workspace,
                &mut meter,
            )
            .unwrap();
            assert_eq!(value.count, want.count);
            assert!(workspace.saturated);
            assert_eq!(workspace.plan_id, Some(regex.plan_id()));
        }

        let reverse_regex = compiled("abcdefghijklmnopq");
        let reverse_haystack = b"xxabcdefghijklmnopqyyabcdefghijklmnopq";
        let reverse_want = expected(&reverse_regex, reverse_haystack, 0..reverse_haystack.len());
        let mut workspace = Workspace::new();
        let (admitted, preparation_work) = workspace
            .prepare(
                reverse_regex.plan_id(),
                &reverse_regex.program,
                OperationLimits::default(),
            )
            .unwrap();
        assert!(admitted);
        let limits = OperationLimits::default();
        let mut populate =
            SweepMeter::with_cache_budget(limits, limits.max_work.saturating_sub(preparation_work));
        populate.charge_work(preparation_work).unwrap();
        let SweepOutcome::Complete(count) = execute_test(
            &reverse_regex.program,
            reverse_haystack,
            SweepKind::Count,
            &mut workspace,
            &mut populate,
        )
        .unwrap();
        assert_eq!(count.count, reverse_want.count);
        assert!(!workspace.saturated);
        assert_eq!(workspace.reverse.state_len, 1);

        let mut no_reverse_learning = SweepMeter::with_cache_budget(OperationLimits::default(), 0);
        let SweepOutcome::Complete(sum) = execute_test(
            &reverse_regex.program,
            reverse_haystack,
            SweepKind::SpanSum,
            &mut workspace,
            &mut no_reverse_learning,
        )
        .unwrap();
        assert_eq!(sum.span_sum, reverse_want.span_sum);
        assert!(workspace.saturated);
    }

    #[test]
    fn saturated_cache_can_resume_learning_on_a_later_call() {
        let regex = compiled("(?:a+b|a)");
        let haystack = vec![b'a'; 128];
        let want = expected(&regex, &haystack, 0..haystack.len());
        let mut workspace = Workspace::new();
        let (admitted, preparation_work) = workspace
            .prepare(regex.plan_id(), &regex.program, OperationLimits::default())
            .unwrap();
        assert!(admitted);

        let mut first = SweepMeter::with_cache_budget(OperationLimits::default(), 0);
        first.charge_work(preparation_work).unwrap();
        let SweepOutcome::Complete(first_value) = execute_test(
            &regex.program,
            &haystack,
            SweepKind::Count,
            &mut workspace,
            &mut first,
        )
        .unwrap();
        assert_eq!(first_value.count, want.count);
        assert!(workspace.saturated);
        let retained_states = workspace.forward.state_len;

        let limits = OperationLimits::default();
        let mut second = SweepMeter::with_cache_budget(limits, limits.max_work);
        let SweepOutcome::Complete(second_value) = execute_test(
            &regex.program,
            &haystack,
            SweepKind::Count,
            &mut workspace,
            &mut second,
        )
        .unwrap();
        assert_eq!(second_value.count, want.count);
        assert!(workspace.forward.state_len > retained_states);
    }

    #[test]
    fn item_arena_saturation_hands_off_before_state_capacity() {
        let alternatives = (b'a'..=b'z')
            .map(|suffix| format!("abcdefghijklmnopq{}", char::from(suffix)))
            .collect::<Vec<_>>();
        let pattern = format!("(?:{})", alternatives.join("|"));
        let regex = compiled(&pattern);
        let haystack = alternatives.join("--").into_bytes();
        let want = expected(&regex, &haystack, 0..haystack.len());
        let mut workspace = Workspace::new();
        let max_items = regex.program.insts.len();
        let (admitted, preparation_work) = workspace
            .prepare_bounded(
                regex.plan_id(),
                &regex.program,
                OperationLimits::default(),
                MAX_DFA_STATES,
                max_items,
            )
            .unwrap();
        assert!(admitted);
        let limits = OperationLimits::default();
        let mut meter =
            SweepMeter::with_cache_budget(limits, limits.max_work.saturating_sub(preparation_work));
        meter.charge_work(preparation_work).unwrap();
        let SweepOutcome::Complete(value) = execute_test(
            &regex.program,
            &haystack,
            SweepKind::Count,
            &mut workspace,
            &mut meter,
        )
        .unwrap();
        assert_eq!(value.count, want.count);
        assert!(workspace.saturated);
        assert!(workspace.forward.state_len < MAX_DFA_STATES);
        assert!(workspace.forward.item_len <= max_items);
    }

    #[test]
    fn saturation_preserves_a_pending_endpoint_through_late_priority_death() {
        let regex = compiled("(?:abcdefghijklmnopqa+b|abcdefghijklmnopqa)");
        let mut haystack = b"abcdefghijklmnopq".to_vec();
        haystack.extend(core::iter::repeat_n(b'a', 4_096));
        let want = expected(&regex, &haystack, 0..haystack.len());

        let mut full = Workspace::new();
        let (full_value, full_sequential, full_saturated) = complete_bounded(
            &regex,
            &haystack,
            SweepKind::SpanSum,
            MAX_DFA_STATES,
            &mut full,
        );
        assert!(!full_saturated);
        assert_eq!(full_value, want);

        let mut capped = Workspace::new();
        let (capped_value, capped_sequential, capped_saturated) =
            complete_bounded(&regex, &haystack, SweepKind::SpanSum, 1, &mut capped);
        assert!(capped_saturated);
        assert_eq!(capped_value, want);
        assert_eq!(capped_sequential, full_sequential);
    }

    #[test]
    fn pessimistic_runtime_upper_is_not_a_source_free_value_refusal() {
        let pattern = "abcdefghijklmnopq";
        let regex = compiled(pattern);
        let haystack = pattern.as_bytes();
        let mut count_workspace = Workspace::new();
        let mut sum_workspace = Workspace::new();
        let _ = complete(
            &regex,
            haystack,
            0..haystack.len(),
            SweepKind::Count,
            &mut count_workspace,
        );
        let _ = complete(
            &regex,
            haystack,
            0..haystack.len(),
            SweepKind::SpanSum,
            &mut sum_workspace,
        );

        let runtime = run_upper_bounds(
            haystack.len(),
            regex.program.execution_state_work(),
            regex.program.continuation_nonaccepting_run(),
            regex.minimum_match_bytes.unwrap(),
        )
        .unwrap();
        let mut exact_count = OperationLimits::default();
        exact_count.max_work = runtime.count_work;
        exact_count.max_sequential_bytes = runtime.count_sequential_bytes;
        assert!(matches!(
            reduce(
                regex.plan_id(),
                &regex.program,
                haystack,
                0..haystack.len(),
                SweepKind::Count,
                regex.minimum_match_bytes,
                exact_count,
                &mut count_workspace,
                None,
            )
            .unwrap(),
            Some(SweepOutcome::Complete(_))
        ));
        exact_count.max_work -= 1;
        assert!(matches!(
            reduce(
                regex.plan_id(),
                &regex.program,
                haystack,
                0..haystack.len(),
                SweepKind::Count,
                regex.minimum_match_bytes,
                exact_count,
                &mut count_workspace,
                None,
            )
            .unwrap(),
            Some(SweepOutcome::Complete(_))
        ));

        let mut exact_sum = OperationLimits::default();
        exact_sum.max_work = runtime.span_sum_work;
        exact_sum.max_sequential_bytes = runtime.span_sum_sequential_bytes;
        assert!(matches!(
            reduce(
                regex.plan_id(),
                &regex.program,
                haystack,
                0..haystack.len(),
                SweepKind::SpanSum,
                regex.minimum_match_bytes,
                exact_sum,
                &mut sum_workspace,
                None,
            )
            .unwrap(),
            Some(SweepOutcome::Complete(_))
        ));
        exact_sum.max_sequential_bytes = 0;
        assert!(matches!(
            reduce(
                regex.plan_id(),
                &regex.program,
                haystack,
                0..haystack.len(),
                SweepKind::SpanSum,
                regex.minimum_match_bytes,
                exact_sum,
                &mut sum_workspace,
                None,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::SequentialBytes,
                ..
            })
        ));
    }

    #[test]
    fn cold_preparation_is_preflighted_but_value_runtime_is_observed() {
        let pattern = "abcdefghijklmnopq";
        let regex = compiled(pattern);
        let haystack = pattern.as_bytes();
        let fixed = prospective_upper_bounds_with_run(
            regex.program.insts.len(),
            MAX_DFA_STATES,
            MAX_DFA_ITEMS,
            regex.program.continuation_nonaccepting_run(),
            regex.minimum_match_bytes,
        )
        .unwrap();
        let runtime = run_upper_bounds(
            haystack.len(),
            regex.program.execution_state_work(),
            fixed.max_nonaccepting_run,
            regex.minimum_match_bytes.unwrap(),
        )
        .unwrap();
        let exact_work = fixed.preparation_work + runtime.count_work;

        let mut exact = OperationLimits::default();
        exact.max_work = exact_work;
        exact.max_sequential_bytes = runtime.count_sequential_bytes;
        let mut exact_workspace = Workspace::new();
        assert!(matches!(
            reduce(
                regex.plan_id(),
                &regex.program,
                haystack,
                0..haystack.len(),
                SweepKind::Count,
                regex.minimum_match_bytes,
                exact,
                &mut exact_workspace,
                None,
            )
            .unwrap(),
            Some(SweepOutcome::Complete(_))
        ));

        let mut below_pessimistic_runtime = exact;
        below_pessimistic_runtime.max_work -= 1;
        let mut observed_workspace = Workspace::new();
        assert!(matches!(
            reduce(
                regex.plan_id(),
                &regex.program,
                haystack,
                0..haystack.len(),
                SweepKind::Count,
                regex.minimum_match_bytes,
                below_pessimistic_runtime,
                &mut observed_workspace,
                None,
            )
            .unwrap(),
            Some(SweepOutcome::Complete(_))
        ));

        let mut below_fixed_preparation = exact;
        below_fixed_preparation.max_work = fixed.preparation_work - 1;
        let mut refused_workspace = Workspace::new();
        assert_eq!(
            reduce(
                regex.plan_id(),
                &regex.program,
                haystack,
                0..haystack.len(),
                SweepKind::Count,
                regex.minimum_match_bytes,
                below_fixed_preparation,
                &mut refused_workspace,
                None,
            )
            .unwrap(),
            None
        );
        assert_eq!(refused_workspace.plan_id, None);
    }

    #[test]
    fn cold_allocation_failures_are_work_and_source_free_and_preserve_the_incumbent() {
        let pattern = "abcdefghijklmnopq";
        let regex = compiled(pattern);
        let haystack = b"xxabcdefghijklmnopqyyabcdefghijklmnopq";
        let expected = regex
            .count_value(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();

        for ordinal in [1, FIXED_ARENA_ALLOCATIONS] {
            let mut workspace = Workspace::new();
            {
                let _fault = super::test_fault::fail_fixed_allocation_at(ordinal);
                assert_eq!(
                    reduce(
                        regex.plan_id(),
                        &regex.program,
                        haystack,
                        0..haystack.len(),
                        SweepKind::Count,
                        regex.minimum_match_bytes,
                        OperationLimits::default(),
                        &mut workspace,
                        None,
                    )
                    .unwrap(),
                    None
                );
                assert!(!super::test_fault::fixed_allocation_failure_is_armed());
                assert_eq!(super::test_fault::work(), 0);
                assert_eq!(super::test_fault::source_bytes(), 0);
            }
            assert_eq!(workspace.plan_id, Some(regex.plan_id()));
            assert!(!workspace.admitted);
            assert_eq!(workspace.retained_bytes, 0);
            assert_eq!(
                regex
                    .count_value(
                        haystack,
                        0..haystack.len(),
                        Strategy::ReverseSequentialRows,
                        OperationLimits::default(),
                    )
                    .unwrap(),
                expected,
                "allocator refusal ordinal={ordinal}"
            );
            assert_eq!(
                reduce(
                    regex.plan_id(),
                    &regex.program,
                    haystack,
                    0..haystack.len(),
                    SweepKind::Count,
                    regex.minimum_match_bytes,
                    OperationLimits::default(),
                    &mut workspace,
                    None,
                )
                .unwrap(),
                None,
                "sticky refusal ordinal={ordinal}"
            );
        }
    }

    #[test]
    fn fixed_workspace_initialization_writes_are_exactly_charged() {
        let mut exact_limits = OperationLimits::default();
        exact_limits.max_work = 4;
        let mut exact = SweepMeter::new(exact_limits);
        assert_eq!(
            allocated_slots(4, 0_u32, 16, &mut exact)
                .unwrap()
                .as_slice(),
            &[0_u32; 4]
        );
        assert_eq!(exact.work, 4);

        let mut one_below_limits = exact_limits;
        one_below_limits.max_work -= 1;
        let mut one_below = SweepMeter::new(one_below_limits);
        assert!(matches!(
            allocated_slots(4, 0_u32, 16, &mut one_below),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: 4,
                limit: 3,
            })
        ));
    }

    #[test]
    fn deferred_state_initialization_is_atomic_and_exactly_charged() {
        let items = [3_u32, 7, 11];
        let storage_work = 2 + 2 + 2 + 2 + 8;
        let state_work =
            items.len() + super::new_state_initialization_work(items.len(), true).unwrap();
        let required = storage_work + state_work;
        let exact_limits = OperationLimits {
            max_work: required,
            ..OperationLimits::default()
        };
        let mut exact_meter = SweepMeter::new(exact_limits);
        let mut exact = super::LazyCache::reserved(2, 8, 4_096).unwrap();
        exact
            .initialize_storage(2, 8, true, &mut exact_meter)
            .unwrap();
        assert_eq!(exact_meter.work, storage_work);
        assert_eq!(
            exact.intern(&items, true, &mut exact_meter).unwrap(),
            super::Interned::State(0)
        );
        assert_eq!(exact_meter.work, required);
        assert_eq!(exact.rows.len(), BYTE_ALPHABET);
        assert_eq!(exact.scalar_keys.len(), SCALAR_LEAD_SLOTS);
        assert_eq!(&exact.offsets[..1], &[0]);
        assert_eq!(&exact.lengths[..1], &[3]);
        assert_eq!(exact.hashes[0], super::frontier_hash(&items, true));
        assert_eq!(&exact.modes[..1], &[1]);
        assert_eq!(&exact.items[..items.len()], &items);

        let mut one_below_limits = exact_limits;
        one_below_limits.max_work -= 1;
        let mut one_below_meter = SweepMeter::new(one_below_limits);
        let mut one_below = super::LazyCache::reserved(2, 8, 4_096).unwrap();
        one_below
            .initialize_storage(2, 8, true, &mut one_below_meter)
            .unwrap();
        assert!(matches!(
            one_below.intern(&items, true, &mut one_below_meter),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required: observed,
                limit,
            }) if observed == required && limit + 1 == required
        ));
        assert_eq!(one_below_meter.work, storage_work + items.len());
        assert_eq!(one_below.state_len, 0);
        assert_eq!(one_below.item_len, 0);
        assert!(one_below.rows.is_empty());
        assert_eq!(one_below.items.len(), one_below.items.capacity());
    }

    #[test]
    fn published_preparation_upper_bounds_admit_exact_fixed_arenas() {
        let regex = compiled("(?:ab|ac|ad|ba|bc|bd)+z");
        let upper =
            prospective_upper_bounds(regex.program.insts.len(), MAX_DFA_STATES, MAX_DFA_ITEMS)
                .unwrap();
        let mut exact = OperationLimits::default();
        exact.max_table_cells = upper.table_cells;
        exact.max_random_access_bytes = upper.workspace_bytes;
        exact.max_scratch_bytes = upper.workspace_bytes;
        exact.max_peak_bytes = upper.workspace_bytes;
        exact.max_work = upper.preparation_work;
        let mut workspace = Workspace::new();
        let (admitted, actual_work) = workspace
            .prepare(regex.plan_id(), &regex.program, exact)
            .unwrap();
        assert!(admitted);
        assert!(actual_work <= upper.preparation_work);
        assert_eq!(workspace.retained_bytes, upper.workspace_bytes);

        let mut table_one_below = Workspace::new();
        let mut low_table = OperationLimits::default();
        low_table.max_table_cells = upper.table_cells - 1;
        assert_eq!(
            table_one_below
                .prepare(regex.plan_id(), &regex.program, low_table)
                .unwrap(),
            (false, 0)
        );
        assert_eq!(table_one_below.retained_bytes, 0);
    }

    #[test]
    fn cache_saturation_hands_off_inline_and_optional_limits_are_sticky() {
        let regex = compiled("(?:ab|ac|ad|ba|bc|bd)+z");
        let haystack = b"bdacbcadabz--bdacbcadabz";
        let want = expected(&regex, haystack, 0..haystack.len());
        let mut full = Workspace::new();
        let (full_count, full_sequential, full_saturated) = complete_bounded(
            &regex,
            haystack,
            SweepKind::Count,
            MAX_DFA_STATES,
            &mut full,
        );
        assert_eq!(full_count.count, want.count);
        assert!(!full_saturated);
        let retained = full.retained_bytes;
        let upper =
            prospective_upper_bounds(regex.program.insts.len(), MAX_DFA_STATES, MAX_DFA_ITEMS)
                .unwrap();

        let mut capped_count = Workspace::new();
        let (count, capped_count_sequential, count_saturated) =
            complete_bounded(&regex, haystack, SweepKind::Count, 1, &mut capped_count);
        assert_eq!(count.count, want.count);
        assert!(count_saturated);
        assert_eq!(capped_count_sequential, full_sequential);

        let mut full_sum = Workspace::new();
        let (full_sum_value, full_sum_sequential, full_sum_saturated) = complete_bounded(
            &regex,
            haystack,
            SweepKind::SpanSum,
            MAX_DFA_STATES,
            &mut full_sum,
        );
        assert_eq!(full_sum_value.span_sum, want.span_sum);
        assert!(!full_sum_saturated);

        let mut capped_sum = Workspace::new();
        let (sum, capped_sum_sequential, sum_saturated) =
            complete_bounded(&regex, haystack, SweepKind::SpanSum, 1, &mut capped_sum);
        assert_eq!(sum.span_sum, want.span_sum);
        assert!(sum_saturated);
        assert_eq!(capped_sum_sequential, full_sum_sequential);

        capped_count = Workspace::disabled(regex.plan_id());
        assert_eq!(
            reduce(
                regex.plan_id(),
                &regex.program,
                b"source-must-remain-uninspected",
                0..2,
                SweepKind::Count,
                regex.minimum_match_bytes,
                OperationLimits::default(),
                &mut capped_count,
                None,
            )
            .unwrap(),
            None
        );
        assert_eq!(capped_count.retained_bytes, 0);

        let mut warmed_one_below = OperationLimits::default();
        warmed_one_below.max_scratch_bytes = retained - 1;
        assert_eq!(
            full.prepare(regex.plan_id(), &regex.program, warmed_one_below)
                .unwrap(),
            (false, 0)
        );
        assert!(!full.admitted);
        assert_eq!(full.retained_bytes, 0);
        assert!(full.forward.rows.is_empty());
        assert_eq!(
            full.prepare(regex.plan_id(), &regex.program, OperationLimits::default())
                .unwrap(),
            (false, 0)
        );

        let mut warmed_low_table = Workspace::new();
        assert!(
            warmed_low_table
                .prepare(regex.plan_id(), &regex.program, OperationLimits::default())
                .unwrap()
                .0
        );
        let mut table_one_below = OperationLimits::default();
        table_one_below.max_table_cells = upper.table_cells - 1;
        assert_eq!(
            warmed_low_table
                .prepare(regex.plan_id(), &regex.program, table_one_below)
                .unwrap(),
            (false, 0)
        );
        assert!(!warmed_low_table.admitted);
        assert_eq!(warmed_low_table.retained_bytes, 0);
        assert!(warmed_low_table.forward.rows.is_empty());
        assert_eq!(
            warmed_low_table
                .prepare(regex.plan_id(), &regex.program, OperationLimits::default())
                .unwrap(),
            (false, 0)
        );

        let mut memory_limited = Workspace::new();
        let mut one_below = OperationLimits::default();
        one_below.max_scratch_bytes = retained - 1;
        assert_eq!(
            memory_limited
                .prepare(regex.plan_id(), &regex.program, one_below,)
                .unwrap(),
            (false, 0)
        );
        assert_eq!(memory_limited.retained_bytes, 0);

        for resource in [
            Resource::ScratchBytes,
            Resource::RandomAccessBytes,
            Resource::PeakBytes,
        ] {
            let mut warmed = Workspace::new();
            assert!(
                warmed
                    .prepare(regex.plan_id(), &regex.program, OperationLimits::default())
                    .unwrap()
                    .0
            );
            let mut low = OperationLimits::default();
            match resource {
                Resource::ScratchBytes => low.max_scratch_bytes = retained - 1,
                Resource::RandomAccessBytes => low.max_random_access_bytes = retained - 1,
                Resource::PeakBytes => low.max_peak_bytes = retained - 1,
                _ => unreachable!(),
            }
            assert_eq!(
                warmed
                    .prepare(regex.plan_id(), &regex.program, low)
                    .unwrap(),
                (false, 0)
            );
            assert_eq!(warmed.retained_bytes, 0);
            assert!(warmed.forward.rows.is_empty());
        }

        let mut work_limited = Workspace::new();
        let mut no_preparation_work = OperationLimits::default();
        no_preparation_work.max_work = 0;
        assert_eq!(
            reduce(
                regex.plan_id(),
                &regex.program,
                b"\xFF\x00source-must-remain-uninspected",
                0..2,
                SweepKind::Count,
                regex.minimum_match_bytes,
                no_preparation_work,
                &mut work_limited,
                None,
            )
            .unwrap(),
            None
        );
        assert_eq!(work_limited.retained_bytes, 0);
    }

    #[test]
    fn cross_plan_rebind_drops_old_cache_before_exact_peak_preflight() {
        let first = compiled("(?:ab|ac|ad|ba|bc|bd)+z");
        let second = compiled("(?:abcdefghijklmnopq|qrstuvwxyzabcdefg)+z");
        let prospective =
            prospective_upper_bounds(second.program.insts.len(), MAX_DFA_STATES, MAX_DFA_ITEMS)
                .unwrap()
                .workspace_bytes;

        let mut exact = Workspace::new();
        assert!(
            exact
                .prepare(first.plan_id(), &first.program, OperationLimits::default())
                .unwrap()
                .0
        );
        assert!(exact.retained_bytes > 0);
        let mut exact_peak = OperationLimits::default();
        exact_peak.max_peak_bytes = prospective;
        assert!(
            exact
                .prepare(second.plan_id(), &second.program, exact_peak)
                .unwrap()
                .0
        );

        let mut one_below = Workspace::new();
        assert!(
            one_below
                .prepare(first.plan_id(), &first.program, OperationLimits::default())
                .unwrap()
                .0
        );
        let mut low_peak = OperationLimits::default();
        low_peak.max_peak_bytes = prospective - 1;
        assert_eq!(
            one_below
                .prepare(second.plan_id(), &second.program, low_peak)
                .unwrap(),
            (false, 0)
        );
        assert_eq!(one_below.plan_id, Some(second.plan_id()));
        assert!(!one_below.admitted);
        assert_eq!(one_below.retained_bytes, 0);
        assert!(one_below.forward.rows.is_empty());
    }

    #[test]
    fn encountered_transitions_are_retained_without_eager_table_fill() {
        let regex = compiled_unicode(r"\w{5}\s\w{6}\s\w{7}");
        let haystack = b"alpha scalar unicode--words phrase letters7";
        assert!(deferred_eligible(&regex));
        let mut workspace = Workspace::new();
        let (admitted, _) = workspace
            .prepare(regex.plan_id(), &regex.program, OperationLimits::default())
            .unwrap();
        assert!(admitted);
        for cache in [&workspace.forward, &workspace.reverse] {
            let cells = cache.state_len * BYTE_ALPHABET;
            let scalar_cells = cache.state_len * SCALAR_LEAD_SLOTS;
            assert_eq!(cache.rows.len(), cells);
            assert_eq!(cache.scalar_keys.len(), scalar_cells);
            assert_eq!(cache.scalar_alt_keys.len(), scalar_cells);
            assert_eq!(cache.scalar_alt_cells.len(), scalar_cells);
            assert_eq!(cache.offsets.len(), cache.offsets.capacity());
            assert_eq!(cache.lengths.len(), cache.lengths.capacity());
            assert_eq!(cache.modes.len(), cache.modes.capacity());
            assert_eq!(cache.items.len(), cache.items.capacity());
            assert!(cache.rows.len() < cache.rows.capacity());
            assert!(
                cache.rows[..cells]
                    .iter()
                    .all(|&cell| cell == CELL_UNFILLED)
            );
        }
        assert!(matches!(
            reduce(
                regex.plan_id(),
                &regex.program,
                haystack,
                0..haystack.len(),
                SweepKind::SpanSum,
                regex.minimum_match_bytes,
                OperationLimits::default(),
                &mut workspace,
                None,
            )
            .unwrap(),
            Some(SweepOutcome::Complete(_))
        ));
        for cache in [&workspace.forward, &workspace.reverse] {
            let cells = cache.state_len * BYTE_ALPHABET;
            let scalar_cells = cache.state_len * SCALAR_LEAD_SLOTS;
            assert_eq!(cache.rows.len(), cells);
            assert_eq!(cache.scalar_keys.len(), scalar_cells);
            assert_eq!(cache.scalar_alt_keys.len(), scalar_cells);
            assert_eq!(cache.scalar_alt_cells.len(), scalar_cells);
            assert_eq!(cache.offsets.len(), cache.offsets.capacity());
            assert_eq!(cache.lengths.len(), cache.lengths.capacity());
            assert_eq!(cache.modes.len(), cache.modes.capacity());
            assert_eq!(cache.items.len(), cache.items.capacity());
            assert!(cache.rows.len() < cache.rows.capacity());
            assert!(
                cache.rows[..cells]
                    .iter()
                    .any(|&cell| cell != CELL_UNFILLED)
            );
            assert!(cache.rows[..cells].contains(&CELL_UNFILLED));
        }
    }

    #[test]
    fn deferred_scalar_chain_is_differential_across_mutated_invalid_sources() {
        let regex = compiled_unicode(r"\w{2}\s\w{3}");
        assert!(deferred_eligible(&regex));
        let mut count_workspace = Workspace::new();
        let mut sum_workspace = Workspace::new();
        let mut source = [0_u8; 96];
        let mut seed = 0xD1B5_4A32_D192_ED03_u64;
        for iteration in 0..512_usize {
            for byte in &mut source {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed.to_le_bytes()[0];
            }
            let template = match iteration % 4 {
                0 => b"ab cde".as_slice(),
                1 => b"\xC3\xA9x abc".as_slice(),
                2 => b"xy\t123".as_slice(),
                _ => b"\xF0\x9F\xA6\x80 zz qqq".as_slice(),
            };
            let offset = iteration % (source.len() - template.len() + 1);
            source[offset..offset + template.len()].copy_from_slice(template);
            let start = iteration % 17;
            let end = source.len() - (iteration % 13);
            let range = start.min(end)..end;
            let want = expected(&regex, &source, range.clone());
            let count = complete(
                &regex,
                &source,
                range.clone(),
                SweepKind::Count,
                &mut count_workspace,
            );
            let sum = complete(
                &regex,
                &source,
                range,
                SweepKind::SpanSum,
                &mut sum_workspace,
            );
            assert_eq!(count.count, want.count, "iteration={iteration}");
            assert_eq!(sum.span_sum, want.span_sum, "iteration={iteration}");
        }
    }

    #[test]
    fn branching_scalar_and_byte_continuations_keep_eager_cache_initialization() {
        for regex in [
            compiled_unicode(r"(?:\p{Greek}{1,3}|[éè]+|[0-9]+)"),
            compiled("(?:ab|ac|ad|ba|bc|bd)+z"),
        ] {
            assert!(!deferred_eligible(&regex));
            let mut workspace = Workspace::new();
            assert!(
                workspace
                    .prepare(regex.plan_id(), &regex.program, OperationLimits::default())
                    .unwrap()
                    .0
            );
            for cache in [&workspace.forward, &workspace.reverse] {
                assert_eq!(cache.rows.len(), cache.rows.capacity());
                assert_eq!(cache.scalar_keys.len(), cache.scalar_keys.capacity());
                assert_eq!(cache.offsets.len(), cache.offsets.capacity());
                assert_eq!(cache.items.len(), cache.items.capacity());
            }
        }
    }
}
