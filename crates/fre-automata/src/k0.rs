use core::mem::size_of;

use memchr::{memchr, memchr2, memchr3};

use crate::{
    plan::{
        ByteSet, StartFilterProof, StartPositionClass, StartPositionScanner, StartScanner,
        BYTE_START_BITMAP_POPULATION_WORK, BYTE_START_MEMBER_EXTRACTION_WORK,
        BYTE_START_SET_SCANNER_SELECTION_WORK, BYTE_START_SMALL_MAX_MEMBERS,
        START_FILTER_GUARD_MAX_CARDINALITY, START_FILTER_GUARD_SELECTION_WORK,
        START_FILTER_POSITION_COUNT, START_FILTER_SCANNER_SELECTION_WORK,
    },
    Automaton, EdgeKind, MatchSpan, OutputContract, ResourceKind, SearchAccounting, SearchError,
    SearchLimits, SearchWindow, SetupAccounting, StateRole, UnicodeLookMatcher,
};

const INVOCATION_RESET_WORK: u64 = 3;
const BYTE_ALPHABET: usize = 256;
const LAZY_MAX_STATES: usize = 64;
const LAZY_MAX_ITEMS: usize = 16_384;
const LAZY_CELL_ACCEPT: u32 = 1 << 31;
const LAZY_CELL_STATE_MASK: u32 = LAZY_CELL_ACCEPT - 1;
const LAZY_CELL_UNFILLED: u32 = u32::MAX;
const LAZY_NO_STATE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Default)]
struct Thread {
    state: u32,
    start: usize,
}

pub(crate) struct UntypedReport {
    pub(crate) found: Option<MatchSpan>,
    pub(crate) accounting: SearchAccounting,
}

/// Fixed logical dimensions needed by the K0 executor for one automaton shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLayout {
    states: usize,
    edges: usize,
    zero_width_edges: usize,
    closure_slots: usize,
    lazy_state_capacity: usize,
    lazy_item_capacity: usize,
    logical_bytes: usize,
    construction_work: u64,
}

impl WorkspaceLayout {
    pub(crate) fn for_automaton(automaton: &Automaton) -> Result<Self, SearchError> {
        Self::for_automaton_mode(automaton, false)
    }

    pub(crate) fn for_accelerated_automaton(automaton: &Automaton) -> Result<Self, SearchError> {
        Self::for_automaton_mode(automaton, true)
    }

    fn for_automaton_mode(automaton: &Automaton, enable_lazy: bool) -> Result<Self, SearchError> {
        let states = automaton.stats().states();
        let edges = automaton.stats().edges();
        let zero_width_edges = automaton.stats().zero_width_edges();
        let closure_slots =
            zero_width_edges
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "closure stack capacity",
                })?;
        let (lazy_state_capacity, lazy_item_capacity) = if enable_lazy {
            lazy_capacities(automaton)?
        } else {
            (0, 0)
        };
        let pike_bytes = scratch_bytes(states, edges, closure_slots)?;
        let lazy_bytes = lazy_scratch_bytes(states, lazy_state_capacity, lazy_item_capacity)?;
        let logical_bytes =
            pike_bytes
                .checked_add(lazy_bytes)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "workspace logical bytes",
                })?;
        let pike_initialized_slots = states
            .checked_add(states)
            .and_then(|value| value.checked_add(edges))
            .and_then(|value| value.checked_add(closure_slots))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace initialized slots",
            })?;
        let lazy_initialized_slots =
            lazy_initialized_slots(states, lazy_state_capacity, lazy_item_capacity)?;
        let initialized_slots = pike_initialized_slots
            .checked_add(lazy_initialized_slots)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace initialized slots",
            })?;
        let pike_allocations = usize::from(states != 0)
            .checked_add(usize::from(states != 0))
            .and_then(|value| value.checked_add(usize::from(edges != 0)))
            .and_then(|value| value.checked_add(usize::from(closure_slots != 0)))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace allocation count",
            })?;
        let lazy_allocations = if lazy_state_capacity == 0 { 0 } else { 8 };
        let non_empty_allocations = pike_allocations.checked_add(lazy_allocations).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "workspace allocation count",
            },
        )?;
        let construction_operations = initialized_slots.checked_add(non_empty_allocations).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "workspace construction work",
            },
        )?;
        let construction_work = u64::try_from(construction_operations).map_err(|_| {
            SearchError::ArithmeticOverflow {
                computation: "workspace construction work conversion",
            }
        })?;
        Ok(Self {
            states,
            edges,
            zero_width_edges,
            closure_slots,
            lazy_state_capacity,
            lazy_item_capacity,
            logical_bytes,
            construction_work,
        })
    }

    /// Number of automaton states for which generation/current slots exist.
    #[must_use]
    pub const fn states(self) -> usize {
        self.states
    }

    /// Number of next-boundary root slots.
    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }

    /// Number of zero-width edges in the compatible automaton shape.
    #[must_use]
    pub const fn zero_width_edges(self) -> usize {
        self.zero_width_edges
    }

    /// Number of fixed closure-stack slots.
    #[must_use]
    pub const fn closure_slots(self) -> usize {
        self.closure_slots
    }

    /// Required heap payload before allocator capacity rounding.
    #[must_use]
    pub const fn logical_bytes(self) -> usize {
        self.logical_bytes
    }

    /// Exact logical constructor charge for this layout.
    #[must_use]
    pub const fn construction_work(self) -> u64 {
        self.construction_work
    }
}

/// Hard limits applied while explicitly constructing reusable K0 workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLimits {
    /// Maximum logical operations allowed during workspace construction.
    pub max_setup_work: u64,
    /// Maximum retained heap payload bytes.
    pub max_scratch_bytes: usize,
}

impl WorkspaceLimits {
    /// Limits that accept every representable workspace layout.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_setup_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for WorkspaceLimits {
    fn default() -> Self {
        Self {
            max_setup_work: 2_000_000,
            max_scratch_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LazyInterned {
    State(u32),
    BudgetDeclined,
    CapacityFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LazyTransition {
    Ready(u32),
    Inline { accepted: bool, pending: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LazyState {
    Cached(u32),
    Inline { pending: bool },
}

/// Fixed ordered-subset rows owned by one exact immutable automaton session.
///
/// `modes` makes the pending selected-end bit part of state identity. The
/// transition graph is consequently contract-neutral: existence and
/// earliest-end stop on a cell's acceptance bit, while selected-end follows
/// the same row until the higher-priority retained prefix dies. Full-span
/// recovery is deliberately outside this first forward-only slice.
#[derive(Debug)]
struct LazyWorkspace {
    automaton_identity: u64,
    scratch: Vec<u32>,
    scratch_len: usize,
    frontier: Vec<u32>,
    frontier_len: usize,
    rows: Vec<u32>,
    offsets: Vec<usize>,
    lengths: Vec<u32>,
    modes: Vec<u8>,
    hashes: Vec<u64>,
    items: Vec<u32>,
    state_len: usize,
    item_len: usize,
    initial: u32,
    initialized: bool,
    declined: bool,
    saturated: bool,
}

impl LazyWorkspace {
    fn new(
        automaton: &Automaton,
        layout: WorkspaceLayout,
        total_bytes: usize,
    ) -> Result<Self, SearchError> {
        let state_capacity = layout.lazy_state_capacity;
        let item_capacity = layout.lazy_item_capacity;
        if state_capacity == 0 {
            return Ok(Self::disabled());
        }
        let row_cells =
            state_capacity
                .checked_mul(BYTE_ALPHABET)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA row cells",
                })?;
        Ok(Self {
            automaton_identity: automaton.identity(),
            scratch: allocate_slots(layout.states, 0_u32, total_bytes)?,
            scratch_len: 0,
            frontier: allocate_slots(layout.states, 0_u32, total_bytes)?,
            frontier_len: 0,
            rows: allocate_slots(row_cells, LAZY_CELL_UNFILLED, total_bytes)?,
            offsets: allocate_slots(state_capacity, 0_usize, total_bytes)?,
            lengths: allocate_slots(state_capacity, 0_u32, total_bytes)?,
            modes: allocate_slots(state_capacity, 0_u8, total_bytes)?,
            hashes: allocate_slots(state_capacity, 0_u64, total_bytes)?,
            items: allocate_slots(item_capacity, 0_u32, total_bytes)?,
            state_len: 0,
            item_len: 0,
            initial: LAZY_NO_STATE,
            initialized: false,
            declined: false,
            saturated: false,
        })
    }

    const fn disabled() -> Self {
        Self {
            automaton_identity: 0,
            scratch: Vec::new(),
            scratch_len: 0,
            frontier: Vec::new(),
            frontier_len: 0,
            rows: Vec::new(),
            offsets: Vec::new(),
            lengths: Vec::new(),
            modes: Vec::new(),
            hashes: Vec::new(),
            items: Vec::new(),
            state_len: 0,
            item_len: 0,
            initial: LAZY_NO_STATE,
            initialized: false,
            declined: true,
            saturated: false,
        }
    }

    fn is_allocated(&self) -> bool {
        !self.rows.is_empty()
    }

    fn is_bound_to(&self, automaton: &Automaton) -> bool {
        self.automaton_identity == automaton.identity()
    }

    fn retained_bytes(&self) -> Result<usize, SearchError> {
        let scratch = capacity_bytes::<u32>(&self.scratch, "lazy DFA scratch bytes")?;
        let frontier = capacity_bytes::<u32>(&self.frontier, "lazy DFA frontier bytes")?;
        let rows = capacity_bytes::<u32>(&self.rows, "lazy DFA row bytes")?;
        let offsets = capacity_bytes::<usize>(&self.offsets, "lazy DFA offset bytes")?;
        let lengths = capacity_bytes::<u32>(&self.lengths, "lazy DFA length bytes")?;
        let modes = capacity_bytes::<u8>(&self.modes, "lazy DFA mode bytes")?;
        let hashes = capacity_bytes::<u64>(&self.hashes, "lazy DFA hash bytes")?;
        let items = capacity_bytes::<u32>(&self.items, "lazy DFA item bytes")?;
        scratch
            .checked_add(frontier)
            .and_then(|value| value.checked_add(rows))
            .and_then(|value| value.checked_add(offsets))
            .and_then(|value| value.checked_add(lengths))
            .and_then(|value| value.checked_add(modes))
            .and_then(|value| value.checked_add(hashes))
            .and_then(|value| value.checked_add(items))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained lazy DFA bytes",
            })
    }

    fn state_bounds(&self, state: u32) -> Result<(usize, usize, bool), SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "lazy DFA state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA state is outside the retained cache",
            });
        }
        let offset = *self
            .offsets
            .get(state)
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA state offset is outside metadata",
            })?;
        let length = usize::try_from(*self.lengths.get(state).ok_or(
            SearchError::InternalInvariant {
                detail: "lazy DFA state length is outside metadata",
            },
        )?)
        .map_err(|_| SearchError::InternalInvariant {
            detail: "lazy DFA state length does not fit usize",
        })?;
        let end = offset
            .checked_add(length)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA state item end",
            })?;
        if end > self.item_len || end > self.items.len() {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA state items are outside the retained arena",
            });
        }
        let pending = *self
            .modes
            .get(state)
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA state mode is outside metadata",
            })?
            != 0;
        Ok((offset, length, pending))
    }

    fn item(&self, state: u32, ordinal: usize) -> Result<u32, SearchError> {
        let (offset, length, _) = self.state_bounds(state)?;
        if ordinal >= length {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA item ordinal is outside its state",
            });
        }
        let item = offset
            .checked_add(ordinal)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA item index",
            })?;
        self.items
            .get(item)
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA item is outside the retained arena",
            })
    }

    fn cell(&self, state: u32, byte: u8) -> Result<u32, SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "lazy DFA transition state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA transition state is outside the cache",
            });
        }
        let row = state
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA transition row",
            })?;
        let cell_index =
            row.checked_add(usize::from(byte))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA transition cell",
                })?;
        self.rows
            .get(cell_index)
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA transition cell is outside the direct table",
            })
    }

    fn set_cell(&mut self, state: u32, byte: u8, cell: u32) -> Result<(), SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "lazy DFA transition state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA transition source is outside the cache",
            });
        }
        let row = state
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA transition row",
            })?;
        let cell_index =
            row.checked_add(usize::from(byte))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA transition cell",
                })?;
        *self
            .rows
            .get_mut(cell_index)
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA transition cell is outside the direct table",
            })? = cell;
        Ok(())
    }

    fn intern_initial(
        &mut self,
        meter: &mut WorkMeter,
        position: usize,
    ) -> Result<u32, SearchError> {
        let item_count = self.scratch_len;
        if item_count == 0 || self.state_len != 0 || self.item_len != 0 {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA initial state has an invalid cache shape",
            });
        }
        if self.offsets.is_empty() || item_count > self.items.len() {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA initial state exceeds its fixed arena",
            });
        }
        let item_work = u64::try_from(item_count).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "lazy DFA initial item work",
        })?;
        meter.charge(item_work, position)?;
        let hash = lazy_hash(&self.scratch[..item_count], false);
        meter.charge(item_work, position)?;
        self.items[..item_count].copy_from_slice(&self.scratch[..item_count]);
        self.offsets[0] = 0;
        self.lengths[0] =
            u32::try_from(item_count).map_err(|_| SearchError::InternalInvariant {
                detail: "lazy DFA initial length does not fit u32",
            })?;
        self.modes[0] = 0;
        self.hashes[0] = hash;
        self.state_len = 1;
        self.item_len = item_count;
        self.scratch_len = 0;
        Ok(0)
    }

    fn intern_speculative(
        &mut self,
        pending: bool,
        meter: &mut WorkMeter,
        core_reserve: u64,
        position: usize,
    ) -> Result<LazyInterned, SearchError> {
        let item_count = self.scratch_len;
        let item_end =
            self.item_len
                .checked_add(item_count)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA speculative item end",
                })?;
        let can_publish = self.state_len < self.offsets.len() && item_end <= self.items.len();

        // Learning is optional. Require the complete worst-case comparison and
        // publication allowance before doing any of it; otherwise continue
        // from the already-advanced frontier inline.
        let comparison = self
            .state_len
            .checked_mul(
                item_count
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "lazy DFA comparison work",
                    })?,
            )
            .and_then(|work| work.checked_add(item_count))
            .and_then(|work| work.checked_add(if can_publish { item_count } else { 0 }))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA learning work",
            })?;
        let comparison =
            u64::try_from(comparison).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "lazy DFA learning work conversion",
            })?;
        let remaining = meter.remaining();
        let Some(optional) = remaining.checked_sub(core_reserve) else {
            return Ok(LazyInterned::BudgetDeclined);
        };
        if comparison > optional {
            return Ok(LazyInterned::BudgetDeclined);
        }

        let item_work = u64::try_from(item_count).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "lazy DFA item work",
        })?;
        meter.charge(item_work, position)?;
        let hash = lazy_hash(&self.scratch[..item_count], pending);
        for state in 0..self.state_len {
            meter.charge(1, position)?;
            if self.modes[state] != u8::from(pending)
                || self.hashes[state] != hash
                || usize::try_from(self.lengths[state]).map_err(|_| {
                    SearchError::InternalInvariant {
                        detail: "lazy DFA retained length does not fit usize",
                    }
                })? != item_count
            {
                continue;
            }
            let offset = self.offsets[state];
            let end = offset
                .checked_add(item_count)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA candidate state end",
                })?;
            meter.charge(item_work, position)?;
            if self.items.get(offset..end) == Some(&self.scratch[..item_count]) {
                self.scratch_len = 0;
                return Ok(LazyInterned::State(u32::try_from(state).map_err(|_| {
                    SearchError::InternalInvariant {
                        detail: "lazy DFA state does not fit u32",
                    }
                })?));
            }
        }

        if !can_publish {
            return Ok(LazyInterned::CapacityFull);
        }
        meter.charge(item_work, position)?;
        self.items[self.item_len..item_end].copy_from_slice(&self.scratch[..item_count]);
        let state = self.state_len;
        self.offsets[state] = self.item_len;
        self.lengths[state] =
            u32::try_from(item_count).map_err(|_| SearchError::InternalInvariant {
                detail: "lazy DFA item count does not fit u32",
            })?;
        self.modes[state] = u8::from(pending);
        self.hashes[state] = hash;
        self.item_len = item_end;
        self.state_len = self
            .state_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA state count",
            })?;
        self.scratch_len = 0;
        Ok(LazyInterned::State(u32::try_from(state).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "lazy DFA state does not fit u32",
            }
        })?))
    }

    fn retain_scratch_as_frontier(&mut self) -> Result<(), SearchError> {
        if self.scratch_len > self.frontier.len() || self.scratch.len() != self.frontier.len() {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA inline frontier exceeds its fixed arena",
            });
        }
        core::mem::swap(&mut self.scratch, &mut self.frontier);
        self.frontier_len = self.scratch_len;
        self.scratch_len = 0;
        Ok(())
    }
}

/// Caller-owned fixed-capacity storage for allocation-free repeated K0 calls.
///
/// All backing vectors retain their full initialized length. Separate logical
/// lengths control which thread slots are live, so execution cannot trigger a
/// reserve or resize. A workspace is compatible with every validated automaton
/// having the exact layout returned by [`Self::layout`].
#[derive(Debug)]
pub struct K0Workspace {
    layout: WorkspaceLayout,
    seen_at: Vec<u64>,
    generation: u64,
    current: Vec<Thread>,
    current_len: usize,
    roots: Vec<Thread>,
    roots_len: usize,
    stack: Vec<Thread>,
    stack_len: usize,
    lazy: LazyWorkspace,
    retained_bytes: usize,
    construction: SetupAccounting,
}

impl K0Workspace {
    /// Allocate and fully initialize fixed-capacity workspace for `automaton`.
    ///
    /// Both the logical payload and allocator-reported retained capacity are
    /// checked against `limits`. The returned object never grows implicitly.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] on arithmetic overflow, a setup/scratch limit,
    /// or a fallible allocation failure.
    pub fn new(automaton: &Automaton, limits: WorkspaceLimits) -> Result<Self, SearchError> {
        Self::new_mode(automaton, limits, false)
    }

    /// Allocate reusable K0 storage plus a bounded ordered lazy-DFA cache.
    ///
    /// Structurally ineligible automata retain exactly the ordinary Pike
    /// workspace. Context-free byte automata add fixed-capacity storage that
    /// never grows during a search; nullable and empty graphs discover their
    /// immutable decline on the first endpoint call and then remain on Pike.
    /// Facades with minimum-length metadata exclude those graphs before this
    /// constructor. Span operations still use Pike execution.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] on arithmetic overflow, a setup/scratch limit,
    /// or a fallible allocation failure.
    pub fn new_accelerated(
        automaton: &Automaton,
        limits: WorkspaceLimits,
    ) -> Result<Self, SearchError> {
        Self::new_mode(automaton, limits, true)
    }

    fn new_mode(
        automaton: &Automaton,
        limits: WorkspaceLimits,
        enable_lazy: bool,
    ) -> Result<Self, SearchError> {
        let layout = WorkspaceLayout::for_automaton_mode(automaton, enable_lazy)?;
        if layout.construction_work > limits.max_setup_work {
            return Err(SearchError::WorkspaceSetupWorkLimitExceeded {
                limit: limits.max_setup_work,
                needed: layout.construction_work,
            });
        }
        if layout.logical_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed: layout.logical_bytes,
                limit: limits.max_scratch_bytes,
            });
        }

        let seen_at = allocate_slots(layout.states, 0_u64, layout.logical_bytes)?;
        let current = allocate_slots(layout.states, Thread::default(), layout.logical_bytes)?;
        let roots = allocate_slots(layout.edges, Thread::default(), layout.logical_bytes)?;
        let stack = allocate_slots(
            layout.closure_slots,
            Thread::default(),
            layout.logical_bytes,
        )?;
        let lazy = LazyWorkspace::new(automaton, layout, layout.logical_bytes)?;
        let retained_bytes = retained_bytes(&seen_at, &current, &roots, &stack, &lazy)?;
        if retained_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed: retained_bytes,
                limit: limits.max_scratch_bytes,
            });
        }

        let construction = SetupAccounting {
            work: layout.construction_work,
            allocated_bytes: retained_bytes,
            initialized_bytes: layout.logical_bytes,
            retained_bytes,
            reused: false,
        };
        Ok(Self {
            layout,
            seen_at,
            generation: 0,
            current,
            current_len: 0,
            roots,
            roots_len: 0,
            stack,
            stack_len: 0,
            lazy,
            retained_bytes,
            construction,
        })
    }

    /// Fixed logical shape accepted by this workspace.
    #[must_use]
    pub const fn layout(&self) -> WorkspaceLayout {
        self.layout
    }

    /// Actual vector-capacity payload retained after construction.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Constructor allocation and initialization charges.
    #[must_use]
    pub const fn construction_accounting(&self) -> SetupAccounting {
        self.construction
    }

    fn begin_invocation(
        &mut self,
        required_generations: u64,
        meter: &mut WorkMeter,
        setup: &mut SetupAccounting,
        position: usize,
    ) -> Result<(), SearchError> {
        meter.charge(INVOCATION_RESET_WORK, position)?;
        setup.work = setup.work.checked_add(INVOCATION_RESET_WORK).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "search setup work",
            },
        )?;
        self.current_len = 0;
        self.roots_len = 0;
        self.stack_len = 0;
        self.lazy.frontier_len = 0;

        if self.generation > u64::MAX.saturating_sub(required_generations) {
            let clear_work =
                u64::try_from(self.seen_at.len()).map_err(|_| SearchError::ArithmeticOverflow {
                    computation: "generation reset work conversion",
                })?;
            meter.charge(clear_work, position)?;
            setup.work =
                setup
                    .work
                    .checked_add(clear_work)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "generation reset setup work",
                    })?;
            let clear_bytes = self.seen_at.len().checked_mul(size_of::<u64>()).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "generation reset initialized bytes",
                },
            )?;
            setup.initialized_bytes = setup.initialized_bytes.checked_add(clear_bytes).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "search setup initialized bytes",
                },
            )?;
            self.seen_at.fill(0);
            self.generation = 0;
        }
        Ok(())
    }

    fn begin_boundary(
        &mut self,
        meter: &mut WorkMeter,
        position: usize,
    ) -> Result<(), SearchError> {
        meter.charge(1, position)?;
        self.current_len = 0;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(SearchError::InternalInvariant {
                detail: "preflighted seen-table generation overflowed",
            })?;
        Ok(())
    }

    fn push_current(&mut self, thread: Thread) -> Result<(), SearchError> {
        let slot =
            self.current
                .get_mut(self.current_len)
                .ok_or(SearchError::InternalInvariant {
                    detail: "ordered current-state set exceeded state count",
                })?;
        *slot = thread;
        self.current_len =
            self.current_len
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "current-state logical length",
                })?;
        Ok(())
    }

    fn push_root(&mut self, thread: Thread) -> Result<(), SearchError> {
        let slot = self
            .roots
            .get_mut(self.roots_len)
            .ok_or(SearchError::InternalInvariant {
                detail: "next-boundary roots exceeded consuming edge count",
            })?;
        *slot = thread;
        self.roots_len = self
            .roots_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "next-boundary root logical length",
            })?;
        Ok(())
    }

    fn push_stack(&mut self, thread: Thread) -> Result<(), SearchError> {
        let slot = self
            .stack
            .get_mut(self.stack_len)
            .ok_or(SearchError::InternalInvariant {
                detail: "epsilon closure stack exceeded zero-width edge bound",
            })?;
        *slot = thread;
        self.stack_len = self
            .stack_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "closure stack logical length",
            })?;
        Ok(())
    }

    fn pop_stack(&mut self) -> Option<Thread> {
        self.stack_len = self.stack_len.checked_sub(1)?;
        self.stack.get(self.stack_len).copied()
    }
}

struct WorkMeter {
    limit: u64,
    consumed: u64,
}

impl WorkMeter {
    const fn new(limit: u64, consumed: u64) -> Self {
        Self { limit, consumed }
    }

    fn charge(&mut self, requested: u64, position: usize) -> Result<(), SearchError> {
        let next = self
            .consumed
            .checked_add(requested)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "search work counter",
            })?;
        if next > self.limit {
            return Err(SearchError::WorkLimitExceeded {
                limit: self.limit,
                consumed: self.consumed,
                requested,
                position,
            });
        }
        self.consumed = next;
        Ok(())
    }

    const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.consumed)
    }
}

pub(crate) fn search(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
    contract: OutputContract,
) -> Result<UntypedReport, SearchError> {
    validate_window(haystack, window)?;
    let layout = WorkspaceLayout::for_automaton(automaton)?;
    let cold_setup_work = layout
        .construction_work
        .checked_add(INVOCATION_RESET_WORK)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "one-shot setup work",
        })?;
    if cold_setup_work > limits.max_work {
        return Err(SearchError::WorkLimitExceeded {
            limit: limits.max_work,
            consumed: 0,
            requested: cold_setup_work,
            position: window.start(),
        });
    }
    let mut workspace = K0Workspace::new(
        automaton,
        WorkspaceLimits {
            max_setup_work: layout.construction_work,
            max_scratch_bytes: limits.max_scratch_bytes,
        },
    )?;
    let setup = workspace.construction_accounting();
    execute(
        automaton,
        haystack,
        window,
        &mut workspace,
        limits,
        setup,
        contract,
        false,
    )
}

pub(crate) fn search_with_workspace(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    contract: OutputContract,
) -> Result<UntypedReport, SearchError> {
    execute(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        SetupAccounting::empty(workspace.retained_bytes, true),
        contract,
        true,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the shared Pike/lazy entry authenticates one complete invocation"
)]
fn execute(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    mut setup: SetupAccounting,
    contract: OutputContract,
    allow_lazy: bool,
) -> Result<UntypedReport, SearchError> {
    validate_window(haystack, window)?;
    let may_use_lazy =
        allow_lazy && !matches!(contract, OutputContract::Span) && workspace.lazy.is_allocated();
    let (mut meter, setup_work) = prepare_invocation(
        automaton,
        workspace,
        window,
        limits,
        &mut setup,
        may_use_lazy,
    )?;
    // Cache learning is optional work. Preserve the ordinary reusable-work
    // certificate by reserving its complete transition allowance before any
    // initial-state publication or speculative interning. Unlimited callers
    // need no finite reserve.
    let window_bytes =
        window
            .end()
            .checked_sub(window.start())
            .ok_or(SearchError::InternalInvariant {
                detail: "validated search window has a descending range",
            })?;
    let lazy_core_reserve = if may_use_lazy && limits.max_work != u64::MAX {
        automaton
            .conservative_transition_work_bound(window_bytes)
            .unwrap_or(u64::MAX)
    } else {
        0
    };
    let start_proof = prepare_start_filter(automaton, workspace, &mut meter, window.start())?;
    let earliest = matches!(
        contract,
        OutputContract::Exists | OutputContract::EarliestEnd
    );
    let lazy = if may_use_lazy {
        execute_lazy_loop(
            automaton,
            haystack,
            window,
            workspace,
            &mut meter,
            contract,
            lazy_core_reserve,
            start_proof.proof().scanner.as_ref(),
            start_proof.proof().guard.as_ref(),
        )?
    } else {
        None
    };
    let (pending, boundaries) = if let Some(result) = lazy {
        result
    } else if let Some(scanner) = start_proof.proof().scanner.as_ref() {
        execute_filtered_loop(
            automaton,
            haystack,
            window,
            workspace,
            &mut meter,
            earliest,
            scanner,
            start_proof.proof().guard.as_ref(),
            start_proof.proof().force_haystack_start,
        )?
    } else {
        // Keep the common nullable/all-byte decline path free of scanner and
        // guard option tests at every examined boundary.
        debug_assert!(start_proof.proof().guard.is_none());
        debug_assert!(!start_proof.proof().force_haystack_start);
        execute_unfiltered_loop(automaton, haystack, window, workspace, &mut meter, earliest)?
    };

    let transition_work =
        meter
            .consumed
            .checked_sub(setup_work)
            .ok_or(SearchError::InternalInvariant {
                detail: "setup work exceeded total search work",
            })?;
    start_proof.publish(automaton);
    Ok(UntypedReport {
        found: pending,
        accounting: SearchAccounting::new(
            meter.consumed,
            setup,
            transition_work,
            workspace.retained_bytes,
            boundaries,
        ),
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the forward loop keeps endpoint commitment and cache handoff together"
)]
fn execute_lazy_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    contract: OutputContract,
    core_reserve: u64,
    scanner: Option<&StartPositionScanner>,
    guard: Option<&StartPositionClass>,
) -> Result<Option<(Option<MatchSpan>, usize)>, SearchError> {
    if !matches!(
        contract,
        OutputContract::Exists | OutputContract::EarliestEnd | OutputContract::SelectedEnd
    ) || !prepare_lazy(automaton, workspace, meter, core_reserve, window.start())?
    {
        return Ok(None);
    }

    let earliest = matches!(
        contract,
        OutputContract::Exists | OutputContract::EarliestEnd
    );
    let initial = workspace.lazy.initial;
    if initial == LAZY_NO_STATE {
        return Err(SearchError::InternalInvariant {
            detail: "initialized lazy DFA has no initial state",
        });
    }
    // Even a physically full cache retains useful prefix rows. Start from the
    // cached initial state and hand off only when an unfilled edge is reached.
    let mut state = LazyState::Cached(initial);
    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending_end = None;
    let mut entered = false;

    loop {
        if pending_end.is_none() && state == LazyState::Cached(initial) {
            if let Some(scanner) = scanner {
                position =
                    next_start_candidate(scanner, haystack, position, window.end(), guard, meter)?;
                if position == window.end() {
                    return Ok(Some((None, boundaries)));
                }
            }
        }
        if !entered {
            boundaries = boundaries
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA examined boundary count",
                })?;
            entered = true;
        }
        if position == window.end() {
            return Ok(Some((
                pending_end.map(|end| MatchSpan::new(window.start(), end)),
                boundaries,
            )));
        }

        // Charge the source step before indexing the validated window. A
        // warmed transition therefore costs one unit and performs one direct
        // row lookup; a cold transition additionally charges its closure and
        // optional learning work.
        meter.charge(1, position)?;
        let byte = *haystack
            .get(position)
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA source position exceeded the validated window",
            })?;
        let transition = match state {
            LazyState::Cached(cached) => build_lazy_cached_transition(
                automaton,
                cached,
                byte,
                workspace,
                meter,
                core_reserve,
                position,
            )?,
            LazyState::Inline { pending } => {
                build_lazy_inline_transition(automaton, byte, pending, workspace, meter, position)?
            }
        };
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA input position",
            })?;
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA examined boundary count",
            })?;

        let (accepted, next) = match transition {
            LazyTransition::Ready(cell) => {
                let encoded = cell & LAZY_CELL_STATE_MASK;
                (
                    cell & LAZY_CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(LazyState::Cached(encoded.checked_sub(1).ok_or(
                            SearchError::InternalInvariant {
                                detail: "lazy DFA encoded state underflowed",
                            },
                        )?))
                    },
                )
            }
            LazyTransition::Inline { accepted, pending } => {
                (accepted, Some(LazyState::Inline { pending }))
            }
        };
        if accepted {
            pending_end = Some(position);
            if earliest {
                return Ok(Some((
                    Some(MatchSpan::new(window.start(), position)),
                    boundaries,
                )));
            }
        }
        let Some(next) = next else {
            return Ok(Some((
                pending_end.map(|end| MatchSpan::new(window.start(), end)),
                boundaries,
            )));
        };
        state = next;
    }
}

fn prepare_lazy(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<bool, SearchError> {
    if !workspace.lazy.is_allocated()
        || !workspace.lazy.is_bound_to(automaton)
        || workspace.lazy.declined
    {
        return Ok(false);
    }
    if workspace.lazy.initialized {
        return Ok(true);
    }

    let states =
        u64::try_from(automaton.stats().states()).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "lazy DFA initial state count",
        })?;
    let epsilon_edges = u64::try_from(automaton.stats().zero_width_edges()).map_err(|_| {
        SearchError::ArithmeticOverflow {
            computation: "lazy DFA initial epsilon-edge count",
        }
    })?;
    let initial_upper = states
        .checked_mul(2)
        .and_then(|work| {
            epsilon_edges
                .checked_mul(2)
                .and_then(|edges| work.checked_add(edges))
        })
        .and_then(|work| work.checked_add(2))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA initial preparation work",
        })?;
    let remaining = meter.remaining();
    let Some(optional) = remaining.checked_sub(core_reserve) else {
        return Ok(false);
    };
    if initial_upper > optional {
        return Ok(false);
    }

    begin_lazy_closure(workspace, meter, position)?;
    let accepted = expand_lazy_root(automaton, automaton.start, workspace, meter, position)?;
    if accepted || workspace.lazy.scratch_len == 0 {
        // Nullable and empty-language graphs remain on Pike. This decision is
        // immutable for the exact bound automaton and is therefore sticky.
        workspace.lazy.scratch_len = 0;
        workspace.lazy.declined = true;
        return Ok(false);
    }
    let initial = workspace.lazy.intern_initial(meter, position)?;
    workspace.lazy.initial = initial;
    workspace.lazy.initialized = true;
    Ok(true)
}

fn begin_lazy_closure(
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<(), SearchError> {
    meter.charge(1, position)?;
    workspace.lazy.scratch_len = 0;
    workspace.stack_len = 0;
    workspace.generation =
        workspace
            .generation
            .checked_add(1)
            .ok_or(SearchError::InternalInvariant {
                detail: "preflighted lazy DFA generation overflowed",
            })?;
    Ok(())
}

fn push_lazy_scratch(workspace: &mut K0Workspace, state: u32) -> Result<(), SearchError> {
    *workspace
        .lazy
        .scratch
        .get_mut(workspace.lazy.scratch_len)
        .ok_or(SearchError::InternalInvariant {
            detail: "lazy DFA closure output exceeded automaton states",
        })? = state;
    workspace.lazy.scratch_len =
        workspace
            .lazy
            .scratch_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA closure output length",
            })?;
    Ok(())
}

fn expand_lazy_root(
    automaton: &Automaton,
    root: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<bool, SearchError> {
    workspace.stack_len = 0;
    workspace.push_stack(Thread {
        state: root,
        start: 0,
    })?;
    while let Some(thread) = workspace.pop_stack() {
        meter.charge(1, position)?;
        let state = crate::plan::plan_index(thread.state);
        if workspace.seen_at[state] == workspace.generation {
            continue;
        }
        workspace.seen_at[state] = workspace.generation;
        match automaton.roles[state] {
            StateRole::Accept => return Ok(true),
            StateRole::Consume => push_lazy_scratch(workspace, thread.state)?,
            StateRole::Split => {
                for edge in automaton.state_edges(thread.state).rev() {
                    meter.charge(1, position)?;
                    if automaton.edge_kinds[edge] != EdgeKind::Epsilon {
                        return Err(SearchError::InternalInvariant {
                            detail: "lazy DFA reached a non-epsilon split edge",
                        });
                    }
                    workspace.push_stack(Thread {
                        state: automaton.edge_targets[edge],
                        start: 0,
                    })?;
                }
            }
        }
    }
    Ok(false)
}

fn build_lazy_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let cached = workspace.lazy.cell(state, byte)?;
    if cached != LAZY_CELL_UNFILLED {
        return Ok(LazyTransition::Ready(cached));
    }

    let (_, length, pending) = workspace.lazy.state_bounds(state)?;
    begin_lazy_closure(workspace, meter, position)?;
    let mut accepted = false;
    'frontier: for ordinal in 0..length {
        let consuming = workspace.lazy.item(state, ordinal)?;
        for edge in automaton.state_edges(consuming) {
            meter.charge(1, position)?;
            if automaton.byte_starts[edge] <= byte
                && byte <= automaton.byte_ends[edge]
                && expand_lazy_root(
                    automaton,
                    automaton.edge_targets[edge],
                    workspace,
                    meter,
                    position,
                )?
            {
                accepted = true;
                break 'frontier;
            }
        }
    }
    if !accepted
        && !pending
        && expand_lazy_root(automaton, automaton.start, workspace, meter, position)?
    {
        return Err(SearchError::InternalInvariant {
            detail: "nonnullable lazy DFA accepted an injected empty match",
        });
    }
    finish_lazy_cached_transition(
        state,
        byte,
        accepted,
        pending,
        workspace,
        meter,
        core_reserve,
        position,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "cache publication authenticates one complete transition and its work reserve"
)]
fn finish_lazy_cached_transition(
    state: u32,
    byte: u8,
    accepted: bool,
    pending: bool,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let next_pending = pending || accepted;
    let encoded = if workspace.lazy.scratch_len == 0 {
        0
    } else {
        match workspace
            .lazy
            .intern_speculative(next_pending, meter, core_reserve, position)?
        {
            LazyInterned::State(next) => {
                next.checked_add(1).ok_or(SearchError::InternalInvariant {
                    detail: "lazy DFA encoded state overflowed",
                })?
            }
            LazyInterned::BudgetDeclined => {
                workspace.lazy.retain_scratch_as_frontier()?;
                return Ok(LazyTransition::Inline {
                    accepted,
                    pending: next_pending,
                });
            }
            LazyInterned::CapacityFull => {
                workspace.lazy.saturated = true;
                workspace.lazy.retain_scratch_as_frontier()?;
                return Ok(LazyTransition::Inline {
                    accepted,
                    pending: next_pending,
                });
            }
        }
    };
    let cell = encoded | if accepted { LAZY_CELL_ACCEPT } else { 0 };
    workspace.lazy.set_cell(state, byte, cell)?;
    Ok(LazyTransition::Ready(cell))
}

fn build_lazy_inline_transition(
    automaton: &Automaton,
    byte: u8,
    pending: bool,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let length = workspace.lazy.frontier_len;
    begin_lazy_closure(workspace, meter, position)?;
    let mut accepted = false;
    'frontier: for ordinal in 0..length {
        let consuming =
            *workspace
                .lazy
                .frontier
                .get(ordinal)
                .ok_or(SearchError::InternalInvariant {
                    detail: "lazy DFA inline frontier item is outside its arena",
                })?;
        for edge in automaton.state_edges(consuming) {
            meter.charge(1, position)?;
            if automaton.byte_starts[edge] <= byte
                && byte <= automaton.byte_ends[edge]
                && expand_lazy_root(
                    automaton,
                    automaton.edge_targets[edge],
                    workspace,
                    meter,
                    position,
                )?
            {
                accepted = true;
                break 'frontier;
            }
        }
    }
    if !accepted
        && !pending
        && expand_lazy_root(automaton, automaton.start, workspace, meter, position)?
    {
        return Err(SearchError::InternalInvariant {
            detail: "nonnullable inline lazy DFA accepted an injected empty match",
        });
    }
    let next_pending = pending || accepted;
    if workspace.lazy.scratch_len == 0 {
        workspace.lazy.frontier_len = 0;
        return Ok(LazyTransition::Ready(if accepted {
            LAZY_CELL_ACCEPT
        } else {
            0
        }));
    }
    workspace.lazy.retain_scratch_as_frontier()?;
    Ok(LazyTransition::Inline {
        accepted,
        pending: next_pending,
    })
}

fn execute_unfiltered_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    earliest: bool,
) -> Result<(Option<MatchSpan>, usize), SearchError> {
    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending = None;

    loop {
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "examined boundary count",
            })?;
        workspace.begin_boundary(meter, position)?;
        expand_boundary_roots(
            automaton,
            haystack,
            position,
            workspace,
            meter,
            &mut pending,
        )?;

        if earliest && pending.is_some() {
            break;
        }

        // All live states are higher priority than `pending`. If none remain,
        // the pending match is irrevocably selected.
        if workspace.current_len == 0 && (pending.is_some() || position == window.end()) {
            break;
        }
        if position == window.end() {
            break;
        }

        consume_current(automaton, haystack[position], position, workspace, meter)?;
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "input position",
            })?;
    }

    Ok((pending, boundaries))
}

#[allow(clippy::too_many_arguments)]
fn execute_filtered_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    earliest: bool,
    scanner: &StartPositionScanner,
    guard: Option<&StartPositionClass>,
    force_haystack_start: bool,
) -> Result<(Option<MatchSpan>, usize), SearchError> {
    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending = None;

    loop {
        if pending.is_none()
            && workspace.roots_len == 0
            // An absolute-start branch may contribute a match only at
            // original haystack boundary zero. Evaluate the full root there
            // once; the scanner is a proof for later boundaries.
            && !(force_haystack_start && position == 0)
        {
            position =
                next_start_candidate(scanner, haystack, position, window.end(), guard, meter)?;
            if position == window.end() {
                break;
            }
        }
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "examined boundary count",
            })?;
        workspace.begin_boundary(meter, position)?;
        expand_boundary_roots(
            automaton,
            haystack,
            position,
            workspace,
            meter,
            &mut pending,
        )?;

        if earliest && pending.is_some() {
            break;
        }

        // All live states are higher priority than `pending`. If none remain,
        // the pending match is irrevocably selected.
        if workspace.current_len == 0 && (pending.is_some() || position == window.end()) {
            break;
        }
        if position == window.end() {
            break;
        }

        consume_current(automaton, haystack[position], position, workspace, meter)?;
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "input position",
            })?;
    }

    Ok((pending, boundaries))
}

#[derive(Clone, Copy, Debug)]
struct StartPositionProof {
    sets: [ByteSet; START_FILTER_POSITION_COUNT],
    length: usize,
    force_haystack_start: bool,
}

impl StartPositionProof {
    const fn disabled() -> Self {
        Self {
            sets: [ByteSet::EMPTY; START_FILTER_POSITION_COUNT],
            length: 0,
            force_haystack_start: false,
        }
    }
}

fn derive_start_position_classes(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartPositionProof, SearchError> {
    let result = derive_start_position_classes_inner(automaton, workspace, meter, position);
    // The proof borrows the invocation's fixed workspace, but none of its
    // temporary logical entries may become live K0 execution state.
    workspace.current_len = 0;
    workspace.roots_len = 0;
    workspace.stack_len = 0;
    result
}

fn derive_start_position_classes_inner(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartPositionProof, SearchError> {
    let mut sets = [ByteSet::EMPTY; START_FILTER_POSITION_COUNT];
    let mut force_haystack_start = false;
    workspace.current_len = 0;
    workspace.roots_len = 0;
    workspace.stack_len = 0;

    for depth in 0..START_FILTER_POSITION_COUNT {
        begin_start_proof_depth(workspace)?;
        let frontier_len = if depth == 0 { 1 } else { workspace.roots_len };
        let mut reached_accept = false;
        let mut words = [0_u64; 4];

        for frontier_index in 0..frontier_len {
            workspace.stack_len = 0;
            let state = if depth == 0 {
                automaton.start
            } else {
                workspace.roots[frontier_index].state
            };
            workspace.push_stack(Thread { state, start: 0 })?;

            while let Some(thread) = workspace.pop_stack() {
                meter.charge(1, position)?;
                let state = thread.state;
                let state_index = crate::plan::plan_index(state);
                if workspace.seen_at[state_index] == workspace.generation {
                    continue;
                }
                workspace.seen_at[state_index] = workspace.generation;

                match automaton.roles[state_index] {
                    StateRole::Accept => {
                        reached_accept = true;
                        break;
                    }
                    StateRole::Consume => {
                        workspace.push_current(thread)?;
                        for edge in automaton.state_edges(state) {
                            meter.charge(1, position)?;
                            insert_byte_range(
                                &mut words,
                                automaton.byte_starts[edge],
                                automaton.byte_ends[edge],
                            );
                        }
                    }
                    StateRole::Split => {
                        for edge in automaton.state_edges(state).rev() {
                            meter.charge(1, position)?;
                            if automaton.edge_kinds[edge] == EdgeKind::AssertHaystackStart {
                                // Boundary zero is evaluated without filtering;
                                // every scanner-selected boundary is nonzero.
                                if depth == 0 {
                                    force_haystack_start = true;
                                }
                                continue;
                            }
                            // Every other assertion is conservatively relaxed
                            // to epsilon. This only enlarges the byte class.
                            workspace.push_stack(Thread {
                                state: automaton.edge_targets[edge],
                                start: 0,
                            })?;
                        }
                    }
                }
            }
            if reached_accept {
                break;
            }
        }

        // If a path can accept after exactly `depth` consumed bytes, no byte
        // at this or any later offset is required by every match.
        if reached_accept {
            return Ok(StartPositionProof {
                sets,
                length: depth,
                force_haystack_start,
            });
        }

        let set = ByteSet::from_words(words);
        sets[depth] = set;
        if set == ByteSet::EMPTY {
            // No nonzero-start path can consume the next required byte, so no
            // such path can ever accept.
            sets[0] = ByteSet::EMPTY;
            return Ok(StartPositionProof {
                sets,
                length: 1,
                force_haystack_start,
            });
        }
        let next_depth = depth
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter next proof depth",
            })?;
        if next_depth == START_FILTER_POSITION_COUNT {
            return Ok(StartPositionProof {
                sets,
                length: START_FILTER_POSITION_COUNT,
                force_haystack_start,
            });
        }

        // Build the exact consumed-depth frontier for the next class. Revisit
        // and charge every consuming edge before retaining its target.
        retain_next_start_frontier(automaton, workspace, meter, position)?;
    }

    Ok(StartPositionProof::disabled())
}

fn begin_start_proof_depth(workspace: &mut K0Workspace) -> Result<(), SearchError> {
    workspace.generation =
        workspace
            .generation
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter proof generation",
            })?;
    workspace.current_len = 0;
    Ok(())
}

fn retain_next_start_frontier(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<(), SearchError> {
    workspace.roots_len = 0;
    for current_index in 0..workspace.current_len {
        let state = workspace.current[current_index].state;
        for edge in automaton.state_edges(state) {
            meter.charge(1, position)?;
            workspace.push_root(Thread {
                state: automaton.edge_targets[edge],
                start: 0,
            })?;
        }
    }
    Ok(())
}

// Boxing the cold pending proof would add an allocation outside the authenticated
// workspace accounting. The warm published variant remains a borrowed pointer.
#[allow(clippy::large_enum_variant)]
enum InvocationStartProof<'a> {
    Published(&'a StartFilterProof),
    Pending(StartFilterProof),
}

impl InvocationStartProof<'_> {
    const fn proof(&self) -> &StartFilterProof {
        match self {
            Self::Published(proof) => proof,
            Self::Pending(proof) => proof,
        }
    }

    fn publish(self, automaton: &Automaton) {
        if let Self::Pending(proof) = self {
            // A concurrent successful invocation may already have published
            // the same proof for this immutable automaton.
            let _ = automaton.start_filter_proof.set(proof);
        }
    }
}

fn prepare_start_filter<'a>(
    automaton: &'a Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<InvocationStartProof<'a>, SearchError> {
    if let Some(proof) = automaton.start_filter_proof.get() {
        return Ok(InvocationStartProof::Published(proof));
    }

    let position_proof = derive_start_position_classes(automaton, workspace, meter, position)?;
    let (scanner, guard) = if position_proof.length == 0 {
        (None, None)
    } else {
        let selection = select_start_classes(
            &position_proof.sets[..position_proof.length],
            meter,
            position,
        )?;
        if selection.scanner.set == ByteSet::ALL && selection.guard.is_none() {
            (None, None)
        } else {
            let scanner = build_byte_start_scanner(
                selection.scanner.set,
                selection.scanner_cardinality,
                meter,
                position,
            )?;
            (
                Some(StartPositionScanner {
                    offset: selection.scanner.offset,
                    scanner,
                }),
                selection.guard,
            )
        }
    };

    let proof = StartFilterProof {
        // The forced boundary matters only when skipping is enabled.
        force_haystack_start: scanner.is_some() && position_proof.force_haystack_start,
        scanner,
        guard,
    };
    // Publish only after the entire search succeeds. A racing successful
    // caller may win first; both values come from the same immutable graph.
    Ok(InvocationStartProof::Pending(proof))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartClassSelection {
    scanner: StartPositionClass,
    scanner_cardinality: u32,
    guard: Option<StartPositionClass>,
}

const fn scanner_tie_rank(offset: u8) -> (bool, u8) {
    // Root first avoids hot-path rewind. Among later positions, deeper scans a
    // shorter suffix and rejects truncated windows earlier.
    (offset == 0, offset)
}

fn select_start_classes(
    sets: &[ByteSet],
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartClassSelection, SearchError> {
    debug_assert!(!sets.is_empty());
    debug_assert!(sets.len() <= START_FILTER_POSITION_COUNT);
    let mut cardinalities = [0_u32; START_FILTER_POSITION_COUNT];
    let mut scanner: Option<(u32, StartPositionClass)> = None;

    for (offset, &set) in sets.iter().enumerate() {
        meter.charge(
            u64::try_from(BYTE_START_BITMAP_POPULATION_WORK)
                .expect("byte bitmap population work fits u64"),
            position,
        )?;
        let cardinality = set.cardinality();
        cardinalities[offset] = cardinality;
        meter.charge(
            u64::try_from(START_FILTER_SCANNER_SELECTION_WORK)
                .expect("scanner selection work fits u64"),
            position,
        )?;
        let class = StartPositionClass {
            offset: u8::try_from(offset).expect("bounded start-filter offset fits u8"),
            set,
        };
        let replace = match scanner {
            None => true,
            Some((best_cardinality, best_class)) => {
                cardinality < best_cardinality
                    || (cardinality == best_cardinality
                        && scanner_tie_rank(class.offset) > scanner_tie_rank(best_class.offset))
            }
        };
        if replace {
            scanner = Some((cardinality, class));
        }
    }

    let (scanner_cardinality, scanner) =
        scanner.expect("a nonempty exact-position proof selects a scanner");
    let mut guard: Option<(u32, StartPositionClass)> = None;
    for (offset, &set) in sets.iter().enumerate() {
        if offset == usize::from(scanner.offset) {
            continue;
        }
        meter.charge(
            u64::try_from(START_FILTER_GUARD_SELECTION_WORK)
                .expect("guard selection work fits u64"),
            position,
        )?;
        let cardinality = cardinalities[offset];
        if cardinality > START_FILTER_GUARD_MAX_CARDINALITY {
            continue;
        }
        let class = StartPositionClass {
            offset: u8::try_from(offset).expect("bounded start-filter offset fits u8"),
            set,
        };
        let replace = match guard {
            None => true,
            Some((best_cardinality, best_class)) => {
                cardinality < best_cardinality
                    || (cardinality == best_cardinality && class.offset > best_class.offset)
            }
        };
        if replace {
            guard = Some((cardinality, class));
        }
    }

    Ok(StartClassSelection {
        scanner,
        scanner_cardinality,
        guard: guard.map(|(_, class)| class),
    })
}

#[cfg(test)]
fn byte_start_scanner(
    set: ByteSet,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartScanner, SearchError> {
    meter.charge(
        u64::try_from(BYTE_START_BITMAP_POPULATION_WORK)
            .expect("byte bitmap population work fits u64"),
        position,
    )?;
    let cardinality = set.cardinality();
    build_byte_start_scanner(set, cardinality, meter, position)
}

fn build_byte_start_scanner(
    set: ByteSet,
    cardinality: u32,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartScanner, SearchError> {
    debug_assert_eq!(set.cardinality(), cardinality);
    if cardinality == 0 {
        return Ok(StartScanner::Empty);
    }
    if usize::try_from(cardinality).expect("byte cardinality fits usize")
        <= BYTE_START_SMALL_MAX_MEMBERS
    {
        let extraction_work = usize::try_from(cardinality)
            .ok()
            .and_then(|members| members.checked_mul(BYTE_START_MEMBER_EXTRACTION_WORK))
            .and_then(|work| u64::try_from(work).ok())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "small byte start-scanner extraction work",
            })?;
        meter.charge(extraction_work, position)?;
        let mut bytes = [0_u8; BYTE_START_SMALL_MAX_MEMBERS];
        let mut length = 0usize;
        for (word_index, mut word) in set.words().into_iter().enumerate() {
            while word != 0 {
                let bit = word.trailing_zeros();
                let byte = word_index
                    .checked_mul(64)
                    .and_then(|offset| u8::try_from(offset).ok())
                    .expect("byte word offset fits u8")
                    .checked_add(u8::try_from(bit).expect("byte word bit fits u8"))
                    .expect("byte bitmap member fits u8");
                *bytes
                    .get_mut(length)
                    .expect("small byte scanner retains at most three bytes") = byte;
                length = length
                    .checked_add(1)
                    .expect("small byte scanner cardinality fits usize");
                word &= word
                    .checked_sub(1)
                    .expect("the small byte scanner word is nonzero");
            }
        }
        return Ok(match bytes[..length] {
            [byte] => StartScanner::One(byte),
            [first, second] => StartScanner::Two(first, second),
            [first, second, third] => StartScanner::Three(first, second, third),
            _ => unreachable!("one-to-three-byte set has matching scanner cardinality"),
        });
    }

    meter.charge(
        u64::try_from(BYTE_START_SET_SCANNER_SELECTION_WORK)
            .expect("byte bitmap scanner selection work fits u64"),
        position,
    )?;
    Ok(StartScanner::Set(set))
}

fn insert_byte_range(words: &mut [u64; 4], start: u8, end: u8) {
    let start_word = usize::from(start / 64);
    let end_word = usize::from(end / 64);
    let start_bit = u32::from(start % 64);
    let end_bit = u32::from(end % 64);
    let end_shift = 63_u32
        .checked_sub(end_bit)
        .expect("a byte-range bit index is at most 63");
    if start_word == end_word {
        words[start_word] |= (u64::MAX << start_bit) & (u64::MAX >> end_shift);
        return;
    }
    words[start_word] |= u64::MAX << start_bit;
    for word in &mut words[start_word + 1..end_word] {
        *word = u64::MAX;
    }
    words[end_word] |= u64::MAX >> end_shift;
}

fn next_start_candidate(
    scanner: &StartPositionScanner,
    haystack: &[u8],
    position: usize,
    end: usize,
    guard: Option<&StartPositionClass>,
    meter: &mut WorkMeter,
) -> Result<usize, SearchError> {
    let mut search = position;
    let scanner_offset = usize::from(scanner.offset);
    loop {
        let scan_start =
            search
                .checked_add(scanner_offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "start-filter scanner position",
                })?;
        if scan_start >= end {
            return Ok(end);
        }
        let scan_position =
            next_scanner_candidate(&scanner.scanner, haystack, scan_start, end, meter)?;
        if scan_position == end {
            return Ok(end);
        }
        let candidate =
            scan_position
                .checked_sub(scanner_offset)
                .ok_or(SearchError::InternalInvariant {
                    detail: "start-filter scanner matched before its exact offset",
                })?;
        let Some(guard) = guard else {
            return Ok(candidate);
        };
        let guard_position = candidate.checked_add(usize::from(guard.offset)).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "start-filter guard position",
            },
        )?;
        meter.charge(1, candidate)?;
        if guard_position >= end {
            return Ok(end);
        }
        if guard.set.contains(haystack[guard_position]) {
            return Ok(candidate);
        }
        search = candidate
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter next candidate",
            })?;
    }
}

fn next_scanner_candidate(
    scanner: &StartScanner,
    haystack: &[u8],
    position: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<usize, SearchError> {
    match scanner {
        StartScanner::Empty => Ok(end),
        StartScanner::One(byte) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr(*byte, source)
            })
        }
        StartScanner::Two(first, second) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr2(*first, *second, source)
            })
        }
        StartScanner::Three(first, second, third) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr3(*first, *second, *third, source)
            })
        }
        StartScanner::Set(set) => next_set_start_candidate(*set, haystack, position, end, meter),
    }
}

fn next_small_start_candidate(
    haystack: &[u8],
    position: usize,
    end: usize,
    meter: &mut WorkMeter,
    find: impl FnOnce(&[u8]) -> Option<usize>,
) -> Result<usize, SearchError> {
    let remaining = haystack
        .get(position..end)
        .ok_or(SearchError::InternalInvariant {
            detail: "start scanner range exceeded the validated search window",
        })?;
    let available = meter.limit.saturating_sub(meter.consumed);
    let admitted = usize::try_from(available)
        .unwrap_or(usize::MAX)
        .min(remaining.len());
    let relative = find(&remaining[..admitted]);
    let scanned = relative
        .map(|offset| {
            offset
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "small start-scanner matched extent",
                })
        })
        .transpose()?
        .unwrap_or(admitted);
    meter.charge(
        u64::try_from(scanned).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "small start-scanner work",
        })?,
        position,
    )?;

    if let Some(relative) = relative {
        return position
            .checked_add(relative)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "small start-scanner candidate",
            });
    }
    if admitted == remaining.len() {
        return Ok(end);
    }

    let refused_position =
        position
            .checked_add(admitted)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "small start-scanner refusal position",
            })?;
    meter.charge(1, refused_position)?;
    Err(SearchError::InternalInvariant {
        detail: "start scanner admitted progress beyond the work limit",
    })
}

fn next_set_start_candidate(
    set: ByteSet,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<usize, SearchError> {
    while position < end {
        meter.charge(1, position)?;
        if set.contains(haystack[position]) {
            return Ok(position);
        }
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "scalar start-set position",
            })?;
    }
    Ok(end)
}

fn prepare_invocation(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    window: SearchWindow,
    limits: SearchLimits,
    setup: &mut SetupAccounting,
    may_use_lazy: bool,
) -> Result<(WorkMeter, u64), SearchError> {
    let required_layout = WorkspaceLayout::for_automaton(automaton)?;
    if required_layout.states != workspace.layout.states
        || required_layout.edges != workspace.layout.edges
        || required_layout.zero_width_edges != workspace.layout.zero_width_edges
        || required_layout.closure_slots != workspace.layout.closure_slots
    {
        return Err(SearchError::WorkspaceLayoutMismatch {
            required_states: required_layout.states,
            actual_states: workspace.layout.states,
            required_edges: required_layout.edges,
            actual_edges: workspace.layout.edges,
            required_zero_width_edges: required_layout.zero_width_edges,
            actual_zero_width_edges: workspace.layout.zero_width_edges,
        });
    }
    if workspace.retained_bytes > limits.max_scratch_bytes {
        return Err(SearchError::ResourceLimit {
            resource: ResourceKind::ScratchBytes,
            needed: workspace.retained_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if setup.work > limits.max_work {
        return Err(SearchError::WorkLimitExceeded {
            limit: limits.max_work,
            consumed: 0,
            requested: setup.work,
            position: window.start(),
        });
    }

    let required_generations = window
        .end()
        .checked_sub(window.start())
        // Up to eight proof generations precede one generation for the initial
        // boundary and one for every admitted byte.
        .and_then(|length| length.checked_add(START_FILTER_POSITION_COUNT))
        .and_then(|length| length.checked_add(1))
        // An accelerated workspace may derive its immutable initial closure
        // once before entering the per-byte loop.
        .and_then(|length| length.checked_add(usize::from(may_use_lazy)))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "required boundary generations",
        })?;
    let required_generations =
        u64::try_from(required_generations).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "required boundary generation conversion",
        })?;
    let mut meter = WorkMeter::new(limits.max_work, setup.work);
    workspace.begin_invocation(required_generations, &mut meter, setup, window.start())?;
    let setup_work = meter.consumed;
    Ok((meter, setup_work))
}

fn expand_boundary_roots(
    automaton: &Automaton,
    haystack: &[u8],
    position: usize,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    pending: &mut Option<MatchSpan>,
) -> Result<(), SearchError> {
    let root_count = workspace.roots_len;
    let mut root_index = 0usize;
    while root_index < root_count {
        let root = workspace.roots[root_index];
        if let Some(found) = expand_root(automaton, haystack, position, root, workspace, meter)? {
            *pending = Some(found);
            break;
        }
        root_index = root_index
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "next-boundary root index",
            })?;
    }
    workspace.roots_len = 0;

    // A new start is lower priority than every still-live earlier start. Once
    // any match is pending, later starts can never win.
    if pending.is_none() {
        *pending = expand_root(
            automaton,
            haystack,
            position,
            Thread {
                state: automaton.start,
                start: position,
            },
            workspace,
            meter,
        )?;
    }
    Ok(())
}

fn consume_current(
    automaton: &Automaton,
    byte: u8,
    position: usize,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
) -> Result<(), SearchError> {
    meter.charge(1, position)?;
    let current_len = workspace.current_len;
    for index in 0..current_len {
        let thread = workspace.current[index];
        for edge in automaton.state_edges(thread.state) {
            meter.charge(1, position)?;
            debug_assert_eq!(automaton.edge_kinds[edge], EdgeKind::ByteRange);
            if automaton.byte_starts[edge] <= byte && byte <= automaton.byte_ends[edge] {
                workspace.push_root(Thread {
                    state: automaton.edge_targets[edge],
                    start: thread.start,
                })?;
            }
        }
    }
    Ok(())
}

fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), SearchError> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(SearchError::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len: haystack.len(),
        });
    }
    Ok(())
}

fn expand_root(
    automaton: &Automaton,
    haystack: &[u8],
    position: usize,
    root: Thread,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
) -> Result<Option<MatchSpan>, SearchError> {
    if position > haystack.len() {
        return Err(SearchError::InternalInvariant {
            detail: "assertion position exceeded original haystack",
        });
    }
    workspace.stack_len = 0;
    workspace.push_stack(root)?;

    while let Some(thread) = workspace.pop_stack() {
        meter.charge(1, position)?;
        let state = crate::plan::plan_index(thread.state);
        if workspace.seen_at[state] == workspace.generation {
            continue;
        }
        workspace.seen_at[state] = workspace.generation;

        match automaton.roles[state] {
            StateRole::Accept => return Ok(Some(MatchSpan::new(thread.start, position))),
            StateRole::Consume => workspace.push_current(thread)?,
            StateRole::Split => {
                // Reverse push produces forward edge order under a LIFO stack.
                for edge in automaton.state_edges(thread.state).rev() {
                    meter.charge(1, position)?;
                    let enabled = zero_width_edge_enabled(
                        automaton,
                        automaton.edge_kinds[edge],
                        haystack,
                        position,
                    )?;
                    if enabled {
                        workspace.push_stack(Thread {
                            state: automaton.edge_targets[edge],
                            start: thread.start,
                        })?;
                    }
                }
            }
        }
    }
    Ok(None)
}

pub(crate) fn zero_width_edge_enabled(
    automaton: &Automaton,
    kind: EdgeKind,
    haystack: &[u8],
    position: usize,
) -> Result<bool, SearchError> {
    zero_width_edge_enabled_with_line_terminator(
        automaton.line_terminator(),
        kind,
        haystack,
        position,
    )
}

pub(crate) fn zero_width_edge_enabled_with_line_terminator(
    line_terminator: u8,
    kind: EdgeKind,
    haystack: &[u8],
    position: usize,
) -> Result<bool, SearchError> {
    match kind {
        EdgeKind::Epsilon => Ok(true),
        EdgeKind::AssertHaystackStart => Ok(position == 0),
        EdgeKind::AssertHaystackEnd => Ok(position == haystack.len()),
        EdgeKind::AssertLineStartLf => Ok(position == 0
            || position
                .checked_sub(1)
                .and_then(|index| haystack.get(index))
                .is_some_and(|&byte| byte == line_terminator)),
        EdgeKind::AssertLineEndLf => {
            Ok(position == haystack.len() || haystack.get(position) == Some(&line_terminator))
        }
        EdgeKind::AssertLineStartCrlf => {
            let before = position
                .checked_sub(1)
                .and_then(|index| haystack.get(index));
            let after = haystack.get(position);
            Ok(position == 0
                || before == Some(&b'\n')
                || (before == Some(&b'\r') && after != Some(&b'\n')))
        }
        EdgeKind::AssertLineEndCrlf => {
            let before = position
                .checked_sub(1)
                .and_then(|index| haystack.get(index));
            let after = haystack.get(position);
            Ok(position == haystack.len()
                || after == Some(&b'\r')
                || (after == Some(&b'\n') && before != Some(&b'\r')))
        }
        EdgeKind::AssertWordAscii
        | EdgeKind::AssertWordAsciiNegate
        | EdgeKind::AssertWordStartAscii
        | EdgeKind::AssertWordEndAscii
        | EdgeKind::AssertWordStartHalfAscii
        | EdgeKind::AssertWordEndHalfAscii => {
            let word_before = position
                .checked_sub(1)
                .and_then(|index| haystack.get(index))
                .is_some_and(|&byte| is_ascii_word(byte));
            let word_after = haystack
                .get(position)
                .is_some_and(|&byte| is_ascii_word(byte));
            Ok(match kind {
                EdgeKind::AssertWordAscii => word_before != word_after,
                EdgeKind::AssertWordAsciiNegate => word_before == word_after,
                EdgeKind::AssertWordStartAscii => !word_before && word_after,
                EdgeKind::AssertWordEndAscii => word_before && !word_after,
                EdgeKind::AssertWordStartHalfAscii => !word_before,
                EdgeKind::AssertWordEndHalfAscii => !word_after,
                _ => {
                    return Err(SearchError::InternalInvariant {
                        detail: "word assertion dispatch changed variants",
                    });
                }
            })
        }
        kind @ (EdgeKind::AssertWordUnicode
        | EdgeKind::AssertWordUnicodeNegate
        | EdgeKind::AssertWordStartUnicode
        | EdgeKind::AssertWordEndUnicode
        | EdgeKind::AssertWordStartHalfUnicode
        | EdgeKind::AssertWordEndHalfUnicode) => {
            unicode_assertion_matches(kind, haystack, position)
        }
        EdgeKind::ByteRange => Err(SearchError::InternalInvariant {
            detail: "split state contained a consuming edge",
        }),
    }
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn unicode_assertion_matches(
    kind: EdgeKind,
    haystack: &[u8],
    position: usize,
) -> Result<bool, SearchError> {
    let look = match kind {
        EdgeKind::AssertWordUnicode => regex_syntax::hir::Look::WordUnicode,
        EdgeKind::AssertWordUnicodeNegate => regex_syntax::hir::Look::WordUnicodeNegate,
        EdgeKind::AssertWordStartUnicode => regex_syntax::hir::Look::WordStartUnicode,
        EdgeKind::AssertWordEndUnicode => regex_syntax::hir::Look::WordEndUnicode,
        EdgeKind::AssertWordStartHalfUnicode => regex_syntax::hir::Look::WordStartHalfUnicode,
        EdgeKind::AssertWordEndHalfUnicode => regex_syntax::hir::Look::WordEndHalfUnicode,
        _ => {
            return Err(SearchError::InternalInvariant {
                detail: "non-Unicode edge in Unicode assertion dispatch",
            });
        }
    };
    Ok(UnicodeLookMatcher::matches_prevalidated(
        look, haystack, position,
    ))
}

fn lazy_capacities(automaton: &Automaton) -> Result<(usize, usize), SearchError> {
    if automaton.stats().assertion_edges() != 0 {
        return Ok((0, 0));
    }
    let states = automaton.stats().states();
    if states == 0 || states > LAZY_MAX_ITEMS {
        return Ok((0, 0));
    }
    let item_capacity = states
        .checked_mul(LAZY_MAX_STATES)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA item capacity",
        })?
        .min(LAZY_MAX_ITEMS)
        .max(states);
    Ok((LAZY_MAX_STATES, item_capacity))
}

fn lazy_initialized_slots(
    states: usize,
    state_capacity: usize,
    item_capacity: usize,
) -> Result<usize, SearchError> {
    if state_capacity == 0 {
        return Ok(0);
    }
    let rows =
        state_capacity
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA initialized row slots",
            })?;
    states
        .checked_mul(2)
        .and_then(|slots| slots.checked_add(rows))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(item_capacity))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA initialized slots",
        })
}

fn lazy_scratch_bytes(
    states: usize,
    state_capacity: usize,
    item_capacity: usize,
) -> Result<usize, SearchError> {
    if state_capacity == 0 {
        return Ok(0);
    }
    let rows =
        state_capacity
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA row cells",
            })?;
    let state_u32s = states
        .checked_mul(2)
        .and_then(|slots| slots.checked_add(rows))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(item_capacity))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA u32 slots",
        })?;
    let u32_bytes =
        state_u32s
            .checked_mul(size_of::<u32>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA u32 bytes",
            })?;
    let offsets =
        state_capacity
            .checked_mul(size_of::<usize>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA offset bytes",
            })?;
    let modes = state_capacity;
    let hashes =
        state_capacity
            .checked_mul(size_of::<u64>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA hash bytes",
            })?;
    u32_bytes
        .checked_add(offsets)
        .and_then(|bytes| bytes.checked_add(modes))
        .and_then(|bytes| bytes.checked_add(hashes))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA scratch bytes",
        })
}

fn lazy_hash(items: &[u32], pending: bool) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ u64::from(pending);
    for &item in items {
        hash ^= u64::from(item);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn scratch_bytes(states: usize, edges: usize, stack: usize) -> Result<usize, SearchError> {
    let seen = states
        .checked_mul(size_of::<u64>())
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "seen scratch bytes",
        })?;
    let current =
        states
            .checked_mul(size_of::<Thread>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "current-thread scratch bytes",
            })?;
    let roots = edges
        .checked_mul(size_of::<Thread>())
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "root scratch bytes",
        })?;
    let closure =
        stack
            .checked_mul(size_of::<Thread>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "closure-stack scratch bytes",
            })?;
    seen.checked_add(current)
        .and_then(|value| value.checked_add(roots))
        .and_then(|value| value.checked_add(closure))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "total scratch bytes",
        })
}

fn allocate_slots<T: Copy>(
    length: usize,
    value: T,
    total_bytes: usize,
) -> Result<Vec<T>, SearchError> {
    let mut vector = Vec::new();
    vector
        .try_reserve_exact(length)
        .map_err(|_| SearchError::ScratchAllocationFailed {
            requested: total_bytes,
        })?;
    vector.resize(length, value);
    Ok(vector)
}

fn retained_bytes(
    seen_at: &Vec<u64>,
    current: &Vec<Thread>,
    roots: &Vec<Thread>,
    stack: &Vec<Thread>,
    lazy: &LazyWorkspace,
) -> Result<usize, SearchError> {
    let seen = seen_at.capacity().checked_mul(size_of::<u64>()).ok_or(
        SearchError::ArithmeticOverflow {
            computation: "retained seen scratch bytes",
        },
    )?;
    let current = current.capacity().checked_mul(size_of::<Thread>()).ok_or(
        SearchError::ArithmeticOverflow {
            computation: "retained current scratch bytes",
        },
    )?;
    let roots = roots.capacity().checked_mul(size_of::<Thread>()).ok_or(
        SearchError::ArithmeticOverflow {
            computation: "retained root scratch bytes",
        },
    )?;
    let stack = stack.capacity().checked_mul(size_of::<Thread>()).ok_or(
        SearchError::ArithmeticOverflow {
            computation: "retained closure scratch bytes",
        },
    )?;
    let lazy = lazy.retained_bytes()?;
    seen.checked_add(current)
        .and_then(|value| value.checked_add(roots))
        .and_then(|value| value.checked_add(stack))
        .and_then(|value| value.checked_add(lazy))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "total retained scratch bytes",
        })
}

fn capacity_bytes<T>(vector: &Vec<T>, computation: &'static str) -> Result<usize, SearchError> {
    vector
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(SearchError::ArithmeticOverflow { computation })
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::{scratch_bytes, WorkMeter, INVOCATION_RESET_WORK};
    use crate::{
        plan::{
            ByteSet, StartFilterProof, StartPositionClass, StartPositionScanner, StartScanner,
            BYTE_START_BITMAP_POPULATION_WORK, BYTE_START_MEMBER_EXTRACTION_WORK,
            BYTE_START_SET_SCANNER_SELECTION_WORK, BYTE_START_SMALL_MAX_MEMBERS,
            START_FILTER_GUARD_MAX_CARDINALITY, START_FILTER_GUARD_SELECTION_WORK,
            START_FILTER_POSITION_COUNT, START_FILTER_SCANNER_SELECTION_WORK,
        },
        Automaton, CompileLimits, EarliestEnd, EdgeKind, Exists, K0Workspace, MatchSpan, RawPlan,
        ResourceKind, SearchError, SearchLimits, SearchWindow, SelectedEnd, Span, StateRole,
        WorkspaceLimits,
    };

    fn ascii_literal(byte: u8) -> Automaton {
        ascii_root_bytes(&[byte])
    }

    fn ascii_root_bytes(bytes: &[u8]) -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![
                    0,
                    u32::try_from(bytes.len()).expect("test root fits u32"),
                    u32::try_from(bytes.len()).expect("test root fits u32"),
                ],
                edge_targets: vec![1; bytes.len()],
                edge_kinds: vec![EdgeKind::ByteRange; bytes.len()],
                byte_starts: bytes.to_vec(),
                byte_ends: bytes.to_vec(),
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn byte_chain(ranges: &[(u8, u8)]) -> Automaton {
        assert!(!ranges.is_empty());
        let edge_offset_slots = ranges
            .len()
            .checked_add(2)
            .expect("test chain offset count fits usize");
        let mut edge_offsets = Vec::with_capacity(edge_offset_slots);
        for offset in 0..=ranges.len() {
            edge_offsets.push(u32::try_from(offset).expect("test chain fits u32"));
        }
        edge_offsets.push(u32::try_from(ranges.len()).expect("test chain fits u32"));
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: (0..ranges.len())
                    .map(|_| StateRole::Consume)
                    .chain(core::iter::once(StateRole::Accept))
                    .collect(),
                edge_offsets,
                edge_targets: (1..=ranges.len())
                    .map(|target| u32::try_from(target).expect("test chain fits u32"))
                    .collect(),
                edge_kinds: vec![EdgeKind::ByteRange; ranges.len()],
                byte_starts: ranges.iter().map(|&(start, _)| start).collect(),
                byte_ends: ranges.iter().map(|&(_, end)| end).collect(),
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_byte_or_eight_byte_chain(
        absolute: u8,
        ranges: &[(u8, u8); START_FILTER_POSITION_COUNT],
    ) -> Automaton {
        let mut byte_starts = vec![0, 0, absolute];
        byte_starts.extend(ranges.iter().map(|&(start, _)| start));
        let mut byte_ends = vec![0, 0, absolute];
        byte_ends.extend(ranges.iter().map(|&(_, end)| end));
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                ],
                edge_offsets: vec![0, 2, 3, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                edge_targets: vec![1, 3, 2, 4, 5, 6, 7, 8, 9, 10, 2],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn factored_q_ab_z() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 1, 3, 4, 4],
                edge_targets: vec![1, 2, 2, 3],
                edge_kinds: vec![EdgeKind::ByteRange; 4],
                byte_starts: vec![b'Q', b'a', b'b', b'Z'],
                byte_ends: vec![b'Q', b'a', b'b', b'Z'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn expanded_q_ab_z() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 5, 6, 7, 8, 8],
                edge_targets: vec![1, 4, 2, 3, 7, 5, 6, 7],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'Q', b'a', b'Z', b'Q', b'b', b'Z'],
                byte_ends: vec![0, 0, b'Q', b'a', b'Z', b'Q', b'b', b'Z'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_foo() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 1, 2, 3, 4, 4],
                edge_targets: vec![1, 2, 3, 4],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, b'f', b'o', b'o'],
                byte_ends: vec![0, b'f', b'o', b'o'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_or_colon_foo() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 5, 6, 6],
                edge_targets: vec![2, 1, 2, 3, 4, 5],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b':', b'f', b'o', b'o'],
                byte_ends: vec![0, 0, b':', b'f', b'o', b'o'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_high_byte_or_colon_a() -> Automaton {
        // (?:\A\xff|:a)
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 5, 5],
                edge_targets: vec![1, 2, 4, 3, 4],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, 0xff, b':', b'a'],
                byte_ends: vec![0, 0, 0xff, b':', b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn assertion_or_colon(assertion: EdgeKind) -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 4],
                edge_targets: vec![1, 2, 3, 3],
                edge_kinds: vec![
                    assertion,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b':'],
                byte_ends: vec![0, 0, b'a', b':'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_nullable_or_colon() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 2, 3, 3],
                edge_targets: vec![2, 1, 2],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b':'],
                byte_ends: vec![0, 0, b':'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_or_colon_or_unasserted_empty() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 3, 4, 4],
                edge_targets: vec![2, 1, 2, 2],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, 0, b':'],
                byte_ends: vec![0, 0, 0, b':'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_or_colon_with_ordered_suffixes() -> Automaton {
        // (?:\A|:)ab(?:cd|c)(?:\z|!)
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 13],
                edge_targets: vec![2, 1, 2, 3, 4, 5, 7, 6, 8, 8, 10, 9, 10],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::AssertHaystackEnd,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b':', b'a', b'b', 0, 0, b'c', b'd', b'c', 0, 0, b'!'],
                byte_ends: vec![0, 0, b':', b'a', b'b', 0, 0, b'c', b'd', b'c', 0, 0, b'!'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn greedy_a_plus_or_a() -> Automaton {
        // (?:a+|a), with the greedy repetition first in priority order.
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 5, 6, 6],
                edge_targets: vec![1, 3, 2, 1, 4, 4],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', 0, 0, b'a'],
                byte_ends: vec![0, 0, b'a', 0, 0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn a_plus(greedy: bool) -> Automaton {
        let split_targets = if greedy { [0, 2] } else { [2, 0] };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Split, StateRole::Accept],
                edge_offsets: vec![0, 1, 3, 3],
                edge_targets: vec![1, split_targets[0], split_targets[1]],
                edge_kinds: vec![EdgeKind::ByteRange, EdgeKind::Epsilon, EdgeKind::Epsilon],
                byte_starts: vec![b'a', 0, 0],
                byte_ends: vec![b'a', 0, 0],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn ordered_a_or_ab(long_first: bool) -> Automaton {
        let (first, second) = if long_first { (1_u32, 4_u32) } else { (4, 1) };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 4, 5, 5],
                edge_targets: vec![first, second, 2, 3, 5],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b'b', b'a'],
                byte_ends: vec![0, 0, b'a', b'b', b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn greedy_binary_pair_plus_then_80() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 6, 7, 7],
                edge_targets: vec![1, 2, 3, 3, 0, 4, 5],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, 0x00, 0xff, 0, 0, 0x80],
                byte_ends: vec![0, 0, 0x00, 0xff, 0, 0, 0x80],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn existence_stops_at_first_accepting_boundary() {
        let automaton = greedy_a_plus_or_a();
        let haystack = b"aaaaaaaa";

        let exists = automaton
            .prepare::<Exists>()
            .search(haystack, SearchLimits::unlimited())
            .unwrap();
        let selected = automaton
            .prepare::<Span>()
            .search(haystack, SearchLimits::unlimited())
            .unwrap();

        assert_eq!(exists.output(), &true);
        assert_eq!(
            selected.output(),
            &Some(crate::MatchSpan::new(0, haystack.len()))
        );
        assert_eq!(exists.accounting().boundaries(), 2);
        assert_eq!(selected.accounting().boundaries(), 9);
        assert!(exists.accounting().work() < selected.accounting().work());
    }

    fn pin_without_start_filter(automaton: &Automaton) {
        automaton
            .start_filter_proof
            .set(StartFilterProof {
                scanner: None,
                guard: None,
                force_haystack_start: false,
            })
            .expect("fresh reference automaton");
    }

    fn bounded_words(alphabet: &[u8], maximum_len: usize) -> Vec<Vec<u8>> {
        let mut words = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::with_capacity(frontier.len().saturating_mul(alphabet.len()));
            for prefix in &frontier {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    words.push(word.clone());
                    next.push(word);
                }
            }
            frontier = next;
        }
        words
    }

    fn assert_all_windows_match_unspecialized(
        name: &str,
        specialized: &Automaton,
        reference: &Automaton,
        haystacks: &[Vec<u8>],
    ) {
        pin_without_start_filter(reference);
        let mut specialized_workspace =
            K0Workspace::new(specialized, WorkspaceLimits::unlimited()).unwrap();
        let mut reference_workspace =
            K0Workspace::new(reference, WorkspaceLimits::unlimited()).unwrap();

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let actual = specialized
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut specialized_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let expected = reference
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut reference_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        actual, expected,
                        "{name}: span mismatch for {haystack:?} in {start}..{end}"
                    );

                    let actual = specialized
                        .prepare::<EarliestEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut specialized_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let expected = reference
                        .prepare::<EarliestEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut reference_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        actual, expected,
                        "{name}: earliest-end mismatch for {haystack:?} in {start}..{end}"
                    );
                }
            }
        }
    }

    fn assert_chain_filter_matches_unspecialized(
        name: &str,
        ranges: &[(u8, u8)],
        expected: StartFilterProof,
        haystacks: &[Vec<u8>],
    ) -> Automaton {
        let specialized = byte_chain(ranges);
        let reference = byte_chain(ranges);
        assert_all_windows_match_unspecialized(name, &specialized, &reference, haystacks);
        assert_eq!(
            specialized
                .start_filter_proof
                .get()
                .expect("exhaustive search publishes proof"),
            &expected
        );
        specialized
    }

    fn byte_set(bytes: &[u8]) -> ByteSet {
        let mut words = [0_u64; 4];
        for &byte in bytes {
            super::insert_byte_range(&mut words, byte, byte);
        }
        ByteSet::from_words(words)
    }

    fn byte_range_set(start: u8, end: u8) -> ByteSet {
        let mut words = [0_u64; 4];
        super::insert_byte_range(&mut words, start, end);
        ByteSet::from_words(words)
    }

    fn scanner_for(bytes: &[u8]) -> StartScanner {
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let scanner = super::byte_start_scanner(byte_set(bytes), &mut meter, 0).unwrap();
        let expected_build_work = expected_scanner_selection_work(bytes.len());
        assert_eq!(meter.consumed, expected_build_work);
        scanner
    }

    const fn positioned_scanner(offset: u8, scanner: StartScanner) -> StartPositionScanner {
        StartPositionScanner { offset, scanner }
    }

    const fn root_scanner(scanner: StartScanner) -> StartPositionScanner {
        positioned_scanner(0, scanner)
    }

    fn expected_scanner_construction_work(members: usize) -> u64 {
        let construction = if members <= BYTE_START_SMALL_MAX_MEMBERS {
            members
                .checked_mul(BYTE_START_MEMBER_EXTRACTION_WORK)
                .unwrap()
        } else {
            BYTE_START_SET_SCANNER_SELECTION_WORK
        };
        u64::try_from(construction).unwrap()
    }

    fn expected_scanner_selection_work(members: usize) -> u64 {
        u64::try_from(BYTE_START_BITMAP_POPULATION_WORK)
            .unwrap()
            .checked_add(expected_scanner_construction_work(members))
            .unwrap()
    }

    fn expected_start_class_selection_work(positions: usize) -> u64 {
        u64::try_from(
            positions
                .checked_mul(
                    BYTE_START_BITMAP_POPULATION_WORK
                        .checked_add(START_FILTER_SCANNER_SELECTION_WORK)
                        .unwrap(),
                )
                .and_then(|work| {
                    positions
                        .saturating_sub(1)
                        .checked_mul(START_FILTER_GUARD_SELECTION_WORK)
                        .and_then(|guard| work.checked_add(guard))
                })
                .unwrap(),
        )
        .unwrap()
    }

    fn expected_filter_selection_work(positions: usize, scanner_members: usize) -> u64 {
        expected_start_class_selection_work(positions)
            .checked_add(expected_scanner_construction_work(scanner_members))
            .unwrap()
    }

    #[test]
    fn refused_work_is_never_charged() {
        let mut meter = WorkMeter::new(3, 0);
        meter.charge(2, 7).unwrap();
        let error = meter.charge(2, 8).unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 3,
                consumed: 2,
                requested: 2,
                position: 8
            }
        ));
        assert_eq!(meter.consumed, 2);
    }

    #[test]
    fn start_proof_stops_at_the_exact_work_limit() {
        let automaton = ascii_root_bytes(b"abcdef");
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let mut meter = WorkMeter::new(1, 0);
        let error =
            super::derive_start_position_classes(&automaton, &mut workspace, &mut meter, 23)
                .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 1,
                consumed: 1,
                requested: 1,
                position: 23
            }
        ));
        assert_eq!(meter.consumed, 1);
    }

    #[test]
    fn scratch_charge_grows_monotonically() {
        let small = scratch_bytes(2, 1, 1).unwrap();
        let more_states = scratch_bytes(3, 1, 1).unwrap();
        let more_edges = scratch_bytes(2, 2, 1).unwrap();
        let deeper_closure = scratch_bytes(2, 1, 2).unwrap();
        assert!(more_states > small);
        assert!(more_edges > small);
        assert!(deeper_closure > small);
    }

    #[test]
    fn start_scanner_selection_work_is_exact_and_precedes_construction() {
        let scanner_sets: &[&[u8]] = &[&[], b"a", b"ab", b"abc", b"abcd"];
        for &bytes in scanner_sets {
            let expected = expected_scanner_selection_work(bytes.len());

            let mut population_refusal = WorkMeter::new(
                u64::try_from(BYTE_START_BITMAP_POPULATION_WORK.checked_sub(1).unwrap()).unwrap(),
                0,
            );
            let error = super::byte_start_scanner(byte_set(bytes), &mut population_refusal, 17)
                .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    consumed: 0,
                    requested,
                    position: 17,
                    ..
                } if requested
                    == u64::try_from(BYTE_START_BITMAP_POPULATION_WORK).unwrap()
            ));

            let mut exact = WorkMeter::new(expected, 0);
            super::byte_start_scanner(byte_set(bytes), &mut exact, 17).unwrap();
            assert_eq!(exact.consumed, expected);

            let mut one_below = WorkMeter::new(expected.checked_sub(1).unwrap(), 0);
            let error = super::byte_start_scanner(byte_set(bytes), &mut one_below, 17).unwrap_err();
            let expected_tail = if bytes.is_empty() {
                u64::try_from(BYTE_START_BITMAP_POPULATION_WORK).unwrap()
            } else if bytes.len() <= BYTE_START_SMALL_MAX_MEMBERS {
                u64::try_from(
                    bytes
                        .len()
                        .checked_mul(BYTE_START_MEMBER_EXTRACTION_WORK)
                        .unwrap(),
                )
                .unwrap()
            } else {
                u64::try_from(BYTE_START_SET_SCANNER_SELECTION_WORK).unwrap()
            };
            let expected_consumed = if bytes.is_empty() {
                0
            } else {
                u64::try_from(BYTE_START_BITMAP_POPULATION_WORK).unwrap()
            };
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    consumed,
                    requested,
                    position: 17,
                    ..
                } if consumed == expected_consumed && requested == expected_tail
            ));
        }
    }

    #[test]
    fn byte_range_bitmap_matches_every_scalar_bound_pair() {
        for start in 0_u8..=u8::MAX {
            for end in start..=u8::MAX {
                let mut words = [0_u64; 4];
                super::insert_byte_range(&mut words, start, end);
                let set = ByteSet::from_words(words);
                for byte in 0_u8..=u8::MAX {
                    assert_eq!(
                        set.contains(byte),
                        (start..=end).contains(&byte),
                        "bitmap mismatch for {start:#04x}..={end:#04x} at {byte:#04x}"
                    );
                }
            }
        }
    }

    #[test]
    fn class_selection_is_exact_bounded_and_prefers_root_then_deepest_ties() {
        let sets = [
            byte_set(b"Q"),
            byte_set(b"ab"),
            ByteSet::ALL,
            byte_set(b"Z"),
        ];
        let expected = expected_start_class_selection_work(sets.len());

        let mut exact = WorkMeter::new(expected, 0);
        let selected = super::select_start_classes(&sets, &mut exact, 19).unwrap();
        assert_eq!(
            selected.scanner,
            StartPositionClass {
                offset: 0,
                set: byte_set(b"Q"),
            }
        );
        assert_eq!(selected.scanner_cardinality, 1);
        assert_eq!(
            selected.guard,
            Some(StartPositionClass {
                offset: 3,
                set: byte_set(b"Z"),
            })
        );
        assert_eq!(exact.consumed, expected);

        let mut one_below = WorkMeter::new(expected - 1, 0);
        let error = super::select_start_classes(&sets, &mut one_below, 19).unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit,
                consumed: 22,
                requested: 1,
                position: 19,
            } if limit == expected - 1
        ));

        let mut population_refusal = WorkMeter::new(3, 0);
        let error = super::select_start_classes(&sets, &mut population_refusal, 23).unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 3,
                consumed: 0,
                requested: 4,
                position: 23,
            }
        ));

        let tied = [byte_set(b"Q"), byte_set(b"a"), ByteSet::ALL, byte_set(b"Z")];
        let mut tied_meter = WorkMeter::new(u64::MAX, 0);
        let tied = super::select_start_classes(&tied, &mut tied_meter, 0).unwrap();
        assert_eq!(tied.scanner.offset, 0);
        assert_eq!(
            tied.guard.expect("two selective non-scanner classes"),
            StartPositionClass {
                offset: 3,
                set: byte_set(b"Z"),
            }
        );

        let shallow_is_smaller = [
            byte_set(b"Q"),
            byte_set(b"a"),
            ByteSet::ALL,
            byte_set(b"YZ"),
        ];
        let mut shallow_meter = WorkMeter::new(u64::MAX, 0);
        let shallow =
            super::select_start_classes(&shallow_is_smaller, &mut shallow_meter, 0).unwrap();
        assert_eq!(shallow.scanner.offset, 0);
        assert_eq!(
            shallow.guard.expect("two selective non-scanner classes"),
            StartPositionClass {
                offset: 1,
                set: byte_set(b"a"),
            }
        );

        let all_later = [byte_set(b"Q"), ByteSet::ALL, ByteSet::ALL, ByteSet::ALL];
        let mut all_meter = WorkMeter::new(u64::MAX, 0);
        let selected = super::select_start_classes(&all_later, &mut all_meter, 0).unwrap();
        assert_eq!(selected.scanner.offset, 0);
        assert_eq!(selected.guard, None);
        assert_eq!(all_meter.consumed, expected);

        let no_root_tie = [
            byte_set(b"ab"),
            byte_set(b"Z"),
            ByteSet::ALL,
            byte_set(b"Y"),
        ];
        let mut no_root_meter = WorkMeter::new(u64::MAX, 0);
        let selected = super::select_start_classes(&no_root_tie, &mut no_root_meter, 0).unwrap();
        assert_eq!(
            selected.scanner,
            StartPositionClass {
                offset: 3,
                set: byte_set(b"Y"),
            },
            "the deepest equal class wins only when offset zero is not tied"
        );
    }

    #[test]
    fn guard_selectivity_gate_retains_64_and_declines_65_through_256() {
        let maximum_eligible = byte_range_set(0, 63);
        assert_eq!(
            maximum_eligible.cardinality(),
            START_FILTER_GUARD_MAX_CARDINALITY
        );
        let mut maximum_meter = WorkMeter::new(u64::MAX, 0);
        let selected =
            super::select_start_classes(&[byte_set(b"Q"), maximum_eligible], &mut maximum_meter, 0)
                .unwrap();
        assert_eq!(selected.scanner.offset, 0);
        assert_eq!(
            selected.guard,
            Some(StartPositionClass {
                offset: 1,
                set: maximum_eligible,
            })
        );
        assert_eq!(
            maximum_meter.consumed,
            expected_start_class_selection_work(2)
        );

        for broad in [byte_range_set(0, 64), byte_range_set(0, 254), ByteSet::ALL] {
            assert!(broad.cardinality() > START_FILTER_GUARD_MAX_CARDINALITY);
            let mut broad_meter = WorkMeter::new(u64::MAX, 0);
            let selected =
                super::select_start_classes(&[byte_set(b"Q"), broad], &mut broad_meter, 0).unwrap();
            assert_eq!(selected.scanner.offset, 0);
            assert_eq!(selected.guard, None);
            assert_eq!(broad_meter.consumed, expected_start_class_selection_work(2));
        }

        let broad_then_tied_eligible = [
            byte_set(b"Q"),
            byte_range_set(0, 64),
            byte_set(b"Z"),
            byte_set(b"Y"),
        ];
        let mut eligible_meter = WorkMeter::new(u64::MAX, 0);
        let selected =
            super::select_start_classes(&broad_then_tied_eligible, &mut eligible_meter, 0).unwrap();
        assert_eq!(selected.scanner.offset, 0);
        assert_eq!(
            selected.guard,
            Some(StartPositionClass {
                offset: 3,
                set: byte_set(b"Y"),
            })
        );
        assert_eq!(
            eligible_meter.consumed,
            expected_start_class_selection_work(broad_then_tied_eligible.len())
        );
    }

    #[test]
    fn guarded_scanner_honors_window_end_and_exact_incremental_work() {
        let scanner = root_scanner(StartScanner::One(b'a'));
        let guard = StartPositionClass {
            offset: 1,
            set: byte_set(b"b"),
        };
        let haystack = b"_aaab_";

        let mut exact = WorkMeter::new(6, 0);
        assert_eq!(
            super::next_start_candidate(&scanner, haystack, 1, 5, Some(&guard), &mut exact,)
                .unwrap(),
            3
        );
        assert_eq!(exact.consumed, 6);

        let mut one_below = WorkMeter::new(5, 0);
        let error =
            super::next_start_candidate(&scanner, haystack, 1, 5, Some(&guard), &mut one_below)
                .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 5,
                consumed: 5,
                requested: 1,
                position: 3,
            }
        ));

        let mut clipped = WorkMeter::new(6, 0);
        assert_eq!(
            super::next_start_candidate(&scanner, haystack, 1, 4, Some(&guard), &mut clipped,)
                .unwrap(),
            4
        );
        assert_eq!(clipped.consumed, 6);

        let high_and_nul = StartPositionClass {
            offset: 2,
            set: byte_set(&[0, 0xff]),
        };
        let mut high_meter = WorkMeter::new(u64::MAX, 0);
        assert_eq!(
            super::next_start_candidate(
                &root_scanner(StartScanner::Set(byte_set(&[0x80, 0xfe]))),
                &[0x80, b'x', 0xff, 0xfe, b'x', 0],
                0,
                6,
                Some(&high_and_nul),
                &mut high_meter,
            )
            .unwrap(),
            0
        );
        assert_eq!(high_meter.consumed, 2);
    }

    #[test]
    fn byte_start_scanners_match_scalar_reference_for_every_window() {
        let scanner_sets: &[&[u8]] = &[
            &[],
            b"\0",
            b"a",
            b"ac",
            b"ac\x7f",
            b"\x80\xff",
            b"\0a\xff",
            b"abcd",
            b"\x3f\x40AB",
        ];
        let mut haystacks = bounded_words(
            &[
                b'?', b'@', b'A', b'B', b'a', b'b', b'c', b'd', b'x', 0x7f, 0x80, 0xff,
            ],
            3,
        );
        let mut long = vec![0x80; 65];
        for (position, byte) in [
            (1, b'a'),
            (15, b'b'),
            (16, b'c'),
            (31, b'd'),
            (32, 0x7f),
            (63, b'a'),
        ] {
            long[position] = byte;
        }
        haystacks.push(long);

        for &bytes in scanner_sets {
            let scanner = root_scanner(scanner_for(bytes));
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let expected = (start..end)
                            .find(|&position| bytes.contains(&haystack[position]))
                            .unwrap_or(end);
                        let mut meter = WorkMeter::new(u64::MAX, 0);
                        let actual = super::next_start_candidate(
                            &scanner, haystack, start, end, None, &mut meter,
                        )
                        .unwrap();
                        assert_eq!(
                            actual, expected,
                            "scanner {bytes:?} disagreed in {start}..{end} of {haystack:?}"
                        );

                        let expected_work = if bytes.is_empty() {
                            0
                        } else if expected == end {
                            u64::try_from(end - start).unwrap()
                        } else {
                            u64::try_from(expected - start + 1).unwrap()
                        };
                        assert_eq!(
                            meter.consumed, expected_work,
                            "scanner {bytes:?} charged unexpected scalar work in {start}..{end}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn exact_position_scanners_zero_through_seven_match_every_window() {
        let markers = [0, 0xff, b'Z', 0x80, b'!', 0x7f, b'/', 0xfe];

        for scanner_offset in 0..START_FILTER_POSITION_COUNT {
            let marker = markers[scanner_offset];
            let mut ranges = [(0, 0xff); START_FILTER_POSITION_COUNT];
            if scanner_offset == 0 {
                ranges[0] = (marker, marker);
            } else {
                ranges[0] = (b'A', b'B');
                ranges[scanner_offset] = (marker, marker);
            }

            let valid = ranges
                .iter()
                .enumerate()
                .map(|(offset, &(start, _))| {
                    if offset == scanner_offset {
                        return start;
                    }
                    match offset % 4 {
                        0 => start,
                        1 => 0,
                        2 => 0xff,
                        _ => 0x80,
                    }
                })
                .collect::<Vec<_>>();
            let mut haystacks = (0..=START_FILTER_POSITION_COUNT + 2)
                .map(|length| vec![b'x'; length])
                .collect::<Vec<_>>();
            haystacks.extend([
                valid.clone(),
                {
                    let mut source = vec![0xff, 0, 0x80];
                    source.extend_from_slice(&valid);
                    source.extend_from_slice(&[0, 0xff]);
                    source
                },
                {
                    let mut source = vec![marker; 19];
                    source[3..3 + valid.len()].copy_from_slice(&valid);
                    source
                },
                vec![0, 0xff, marker, 0x80, marker, 0x7f, 0xfe, marker],
            ]);

            let specialized = byte_chain(&ranges);
            let reference = byte_chain(&ranges);
            assert_all_windows_match_unspecialized(
                &format!("exact-position-scanner-{scanner_offset}"),
                &specialized,
                &reference,
                &haystacks,
            );

            let proof = specialized
                .start_filter_proof
                .get()
                .expect("all-window comparison publishes the exact-position proof");
            assert_eq!(
                proof.scanner,
                Some(positioned_scanner(
                    u8::try_from(scanner_offset).unwrap(),
                    StartScanner::One(marker),
                ))
            );
            assert_eq!(
                proof.guard,
                (scanner_offset != 0).then_some(StartPositionClass {
                    offset: 0,
                    set: byte_set(b"AB"),
                })
            );

            let mut workspace =
                K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
            for clipped_end in 0..=scanner_offset {
                let clipped = specialized
                    .prepare::<Span>()
                    .search_window_with_workspace(
                        &valid,
                        SearchWindow::new(0, clipped_end),
                        &mut workspace,
                        SearchLimits::unlimited(),
                    )
                    .unwrap();
                assert!(clipped.output().is_none());
                assert_eq!(
                    clipped.accounting().boundaries(),
                    0,
                    "offset {scanner_offset} admitted a start without its scanner byte"
                );
            }
            let published = specialized
                .start_filter_proof
                .get()
                .expect("proof remains published");
            assert!(
                core::ptr::eq(proof, published),
                "a warm call must borrow the original immutable proof"
            );
        }
    }

    #[test]
    fn offset_seven_scanner_preserves_absolute_start_and_work_bounds() {
        let ranges = [
            (b'A', b'B'),
            (0, 0xff),
            (0, 0xff),
            (0, 0xff),
            (0, 0xff),
            (0, 0xff),
            (0, 0xff),
            (b'Z', b'Z'),
        ];
        let valid = [b'A', 0, 0xff, 0x80, b'x', 0, 0xfe, b'Z'];
        let mut later = vec![b'x'; 17];
        later.extend_from_slice(&valid);
        let haystacks = vec![
            vec![],
            vec![0xfe],
            vec![0xfe, b'x', b'x'],
            valid.to_vec(),
            later.clone(),
            vec![0xfe, b'A', 0, 0xff, 0x80, b'x', 0, 0xfe],
        ];

        let specialized = absolute_byte_or_eight_byte_chain(0xfe, &ranges);
        let reference = absolute_byte_or_eight_byte_chain(0xfe, &ranges);
        assert_all_windows_match_unspecialized(
            "absolute-or-offset-seven",
            &specialized,
            &reference,
            &haystacks,
        );
        assert_eq!(
            specialized
                .start_filter_proof
                .get()
                .expect("absolute-start comparison publishes proof"),
            &StartFilterProof {
                scanner: Some(positioned_scanner(7, StartScanner::One(b'Z'))),
                guard: Some(StartPositionClass {
                    offset: 0,
                    set: byte_set(b"AB"),
                }),
                force_haystack_start: true,
            }
        );

        let mut workspace = K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
        let at_zero = specialized
            .prepare::<Span>()
            .search_with_workspace(b"\xfexxxxxxxZ", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(at_zero.output(), &Some(crate::MatchSpan::new(0, 1)));

        let bound = specialized
            .conservative_reused_work_bound(later.len())
            .unwrap();
        let warm = specialized
            .prepare::<Span>()
            .search_with_workspace(&later, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(warm.output(), &Some(crate::MatchSpan::new(17, 25)));
        assert!(warm.accounting().work() <= bound);

        let metered = absolute_byte_or_eight_byte_chain(0xfe, &ranges);
        let mut metered_workspace =
            K0Workspace::new(&metered, WorkspaceLimits::unlimited()).unwrap();
        let cold_bound = metered.conservative_reused_work_bound(later.len()).unwrap();
        let cold = metered
            .prepare::<Span>()
            .search_with_workspace(&later, &mut metered_workspace, SearchLimits::unlimited())
            .unwrap();
        let warm = metered
            .prepare::<Span>()
            .search_with_workspace(&later, &mut metered_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(cold.output(), warm.output());
        assert!(cold.accounting().work() <= cold_bound);
        assert!(
            cold.accounting().transition_work() > warm.accounting().transition_work(),
            "the cold offset-seven proof must be fully charged before publication"
        );
    }

    #[test]
    fn declined_filters_use_the_exact_scanner_free_accounting_path() {
        fn nullable() -> Automaton {
            Automaton::from_raw(
                RawPlan {
                    start: 0,
                    roles: vec![StateRole::Accept],
                    edge_offsets: vec![0, 0],
                    edge_targets: vec![],
                    edge_kinds: vec![],
                    byte_starts: vec![],
                    byte_ends: vec![],
                },
                CompileLimits::default(),
            )
            .unwrap()
        }

        for (name, specialized, reference, haystack, window) in [
            (
                "all-byte",
                byte_chain(&[(0, 0xff)]),
                byte_chain(&[(0, 0xff)]),
                vec![0, 0xff, b'x'],
                SearchWindow::new(1, 3),
            ),
            (
                "nullable",
                nullable(),
                nullable(),
                vec![0, 0xff, b'x'],
                SearchWindow::new(1, 3),
            ),
        ] {
            pin_without_start_filter(&reference);
            let mut specialized_workspace =
                K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
            let mut reference_workspace =
                K0Workspace::new(&reference, WorkspaceLimits::unlimited()).unwrap();
            specialized
                .prepare::<Span>()
                .search_window_with_workspace(
                    &haystack,
                    window,
                    &mut specialized_workspace,
                    SearchLimits::unlimited(),
                )
                .unwrap();
            let warm = specialized
                .prepare::<Span>()
                .search_window_with_workspace(
                    &haystack,
                    window,
                    &mut specialized_workspace,
                    SearchLimits::unlimited(),
                )
                .unwrap();
            let unfiltered = reference
                .prepare::<Span>()
                .search_window_with_workspace(
                    &haystack,
                    window,
                    &mut reference_workspace,
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(warm.output(), unfiltered.output(), "{name} output");
            assert_eq!(
                warm.accounting(),
                unfiltered.accounting(),
                "{name} scanner-free accounting"
            );
            assert!(specialized
                .start_filter_proof
                .get()
                .expect("successful cold call publishes decline")
                .scanner
                .is_none());
        }
    }

    #[test]
    fn full_byte_root_declines_start_filtering() {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 1],
                edge_targets: vec![1],
                edge_kinds: vec![EdgeKind::ByteRange],
                byte_starts: vec![0],
                byte_ends: vec![0xff],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        automaton
            .prepare::<Span>()
            .search_with_workspace(b"\xffA", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let proof = automaton
            .start_filter_proof
            .get()
            .expect("successful search publishes the declined proof");
        assert!(proof.scanner.is_none());
        assert!(!proof.force_haystack_start);
    }

    #[test]
    fn full_byte_root_uses_a_more_selective_broad_later_class() {
        let automaton = byte_chain(&[(0, 0xff), (0, 64)]);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let source = vec![0_u8; 257];
        let report = automaton
            .prepare::<Span>()
            .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(report.output(), &Some(crate::MatchSpan::new(0, 2)));
        assert!(report.accounting().boundaries() > 0);
        assert_eq!(
            automaton
                .start_filter_proof
                .get()
                .expect("successful search publishes later-position filter"),
            &StartFilterProof {
                scanner: Some(positioned_scanner(
                    1,
                    StartScanner::Set(byte_range_set(0, 64)),
                )),
                guard: None,
                force_haystack_start: false,
            }
        );
    }

    #[test]
    fn bounded_position_guards_match_unspecialized_search_on_dense_and_binary_inputs() {
        let mut haystacks = bounded_words(&[0, b'Q', b'Z', b'x', 0x7f, 0x80, 0xfe, 0xff], 3);
        haystacks.extend([
            vec![b'Q'; 129],
            vec![0xff; 129],
            {
                let mut source = vec![b'Q'; 129];
                source[64] = b'Z';
                source
            },
            {
                let mut source = vec![0xff; 129];
                source[63] = 0;
                source
            },
            vec![0, 0x80, 0, 0xff, b'Q', 0, b'Z'],
        ]);

        let q_any_z = assert_chain_filter_matches_unspecialized(
            "selective-root-dense-middle",
            &[(b'Q', b'Q'), (0, 0xff), (b'Z', b'Z')],
            StartFilterProof {
                scanner: Some(root_scanner(StartScanner::One(b'Q'))),
                guard: Some(StartPositionClass {
                    offset: 2,
                    set: byte_set(b"Z"),
                }),
                force_haystack_start: false,
            },
            &haystacks,
        );

        let all_then_z = assert_chain_filter_matches_unspecialized(
            "all-byte-root-with-selective-guard",
            &[(0, 0xff), (b'Z', b'Z')],
            StartFilterProof {
                scanner: Some(positioned_scanner(1, StartScanner::One(b'Z'))),
                guard: None,
                force_haystack_start: false,
            },
            &haystacks,
        );

        let high_then_nul = assert_chain_filter_matches_unspecialized(
            "high-byte-root-with-nul-guard",
            &[(0x80, 0xff), (0, 0), (0xfe, 0xff)],
            StartFilterProof {
                scanner: Some(positioned_scanner(1, StartScanner::One(0))),
                guard: Some(StartPositionClass {
                    offset: 2,
                    set: byte_set(&[0xfe, 0xff]),
                }),
                force_haystack_start: false,
            },
            &haystacks,
        );

        for (name, automaton, source) in [
            ("all-Q", &q_any_z, vec![b'Q'; 129]),
            ("all-high", &high_then_nul, vec![0xff; 129]),
            ("all-byte-root", &all_then_z, vec![b'x'; 129]),
        ] {
            let mut workspace = K0Workspace::new(automaton, WorkspaceLimits::unlimited()).unwrap();
            let report = automaton
                .prepare::<Span>()
                .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
                .unwrap();
            assert!(report.output().is_none(), "{name} unexpectedly matched");
            assert_eq!(
                report.accounting().boundaries(),
                0,
                "{name} should be rejected by the root-plus-guard filter"
            );
            assert!(
                report.accounting().work()
                    <= automaton
                        .conservative_reused_work_bound(source.len())
                        .unwrap(),
                "{name} exceeded its conservative work certificate"
            );
        }
    }

    #[test]
    fn passing_guard_candidates_respect_cold_and_warm_work_bounds() {
        let automaton = byte_chain(&[(b'Q', b'Q'), (0, 0xff), (b'Z', b'Z'), (b'A', b'Z')]);
        let source = b"QxZx".repeat(64);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let bound = automaton
            .conservative_reused_work_bound(source.len())
            .unwrap();

        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert!(cold.output().is_none());
        assert!(cold.accounting().boundaries() > 0);
        assert!(cold.accounting().work() <= bound);

        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(warm.output(), cold.output());
        assert!(warm.accounting().boundaries() > 0);
        assert!(warm.accounting().work() <= bound);
        assert!(warm.accounting().work() < cold.accounting().work());
    }

    #[test]
    fn an_accepting_shorter_branch_prevents_an_unsound_later_guard() {
        fn q_or_qxz() -> Automaton {
            Automaton::from_raw(
                RawPlan {
                    start: 0,
                    roles: vec![
                        StateRole::Split,
                        StateRole::Consume,
                        StateRole::Accept,
                        StateRole::Consume,
                        StateRole::Consume,
                        StateRole::Consume,
                    ],
                    edge_offsets: vec![0, 2, 3, 3, 4, 5, 6],
                    edge_targets: vec![1, 3, 2, 4, 5, 2],
                    edge_kinds: vec![
                        EdgeKind::Epsilon,
                        EdgeKind::Epsilon,
                        EdgeKind::ByteRange,
                        EdgeKind::ByteRange,
                        EdgeKind::ByteRange,
                        EdgeKind::ByteRange,
                    ],
                    byte_starts: vec![0, 0, b'Q', b'Q', b'x', b'Z'],
                    byte_ends: vec![0, 0, b'Q', b'Q', b'x', b'Z'],
                },
                CompileLimits::default(),
            )
            .unwrap()
        }

        let specialized = q_or_qxz();
        let reference = q_or_qxz();
        let mut haystacks = bounded_words(&[b'Q', b'x', b'Z', 0xff], 3);
        haystacks.push(b"xxxxQxxxx".to_vec());
        assert_all_windows_match_unspecialized(
            "accept-truncates-position-proof",
            &specialized,
            &reference,
            &haystacks,
        );
        assert_eq!(
            specialized
                .start_filter_proof
                .get()
                .expect("exhaustive search publishes proof"),
            &StartFilterProof {
                scanner: Some(root_scanner(StartScanner::One(b'Q'))),
                guard: None,
                force_haystack_start: false,
            }
        );
    }

    #[test]
    fn equivalent_factored_and_expanded_topologies_retain_the_same_filter() {
        let mut haystacks = bounded_words(&[0, b'Q', b'a', b'b', b'Z', 0xff], 3);
        haystacks.extend([
            b"QQQQQQQQQQQQ".to_vec(),
            b"xxQaZxxQbZ".to_vec(),
            vec![0xff, b'Q', b'a', b'Z', 0, b'Q', b'b', b'Z'],
        ]);

        let factored = factored_q_ab_z();
        let factored_reference = factored_q_ab_z();
        assert_all_windows_match_unspecialized(
            "factored-position-classes",
            &factored,
            &factored_reference,
            &haystacks,
        );
        let expanded = expanded_q_ab_z();
        let expanded_reference = expanded_q_ab_z();
        assert_all_windows_match_unspecialized(
            "expanded-position-classes",
            &expanded,
            &expanded_reference,
            &haystacks,
        );

        let expected = StartFilterProof {
            scanner: Some(root_scanner(StartScanner::One(b'Q'))),
            guard: Some(StartPositionClass {
                offset: 2,
                set: byte_set(b"Z"),
            }),
            force_haystack_start: false,
        };
        assert_eq!(factored.start_filter_proof.get(), Some(&expected));
        assert_eq!(expanded.start_filter_proof.get(), Some(&expected));

        let mut factored_workspace =
            K0Workspace::new(&factored, WorkspaceLimits::unlimited()).unwrap();
        let mut expanded_workspace =
            K0Workspace::new(&expanded, WorkspaceLimits::unlimited()).unwrap();
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let factored_output = factored
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut factored_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let expanded_output = expanded
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut expanded_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        factored_output, expanded_output,
                        "equivalent topology mismatch for {haystack:?} in {start}..{end}"
                    );
                }
            }
        }
    }

    #[test]
    fn start_scanners_honor_exact_admitted_work() {
        let scanners = [
            root_scanner(scanner_for(b"a")),
            root_scanner(scanner_for(b"ab")),
            root_scanner(scanner_for(b"abc")),
            root_scanner(scanner_for(b"abcd")),
        ];
        for scanner in &scanners {
            let mut exact = WorkMeter::new(10, 7);
            assert_eq!(
                super::next_start_candidate(scanner, b"_xxa_", 1, 4, None, &mut exact).unwrap(),
                3
            );
            assert_eq!(exact.consumed, 10);

            let mut before_candidate = WorkMeter::new(9, 7);
            let error =
                super::next_start_candidate(scanner, b"_xxa_", 1, 4, None, &mut before_candidate)
                    .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    limit: 9,
                    consumed: 9,
                    requested: 1,
                    position: 3,
                }
            ));

            let mut full_miss = WorkMeter::new(10, 7);
            assert_eq!(
                super::next_start_candidate(scanner, b"_xxx_", 1, 4, None, &mut full_miss).unwrap(),
                4
            );
            assert_eq!(full_miss.consumed, 10);

            let mut partial_miss = WorkMeter::new(9, 7);
            let error =
                super::next_start_candidate(scanner, b"_xxx_", 1, 4, None, &mut partial_miss)
                    .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    limit: 9,
                    consumed: 9,
                    requested: 1,
                    position: 3,
                }
            ));

            let mut exhausted = WorkMeter::new(7, 7);
            let error = super::next_start_candidate(scanner, b"_xxx_", 1, 4, None, &mut exhausted)
                .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    limit: 7,
                    consumed: 7,
                    requested: 1,
                    position: 1,
                }
            ));
        }

        let mut empty_meter = WorkMeter::new(7, 7);
        assert_eq!(
            super::next_start_candidate(
                &root_scanner(StartScanner::Empty),
                b"_xxx_",
                1,
                4,
                None,
                &mut empty_meter,
            )
            .unwrap(),
            4
        );
        assert_eq!(empty_meter.consumed, 7);

        let absolute = absolute_foo();
        let mut workspace = K0Workspace::new(&absolute, WorkspaceLimits::unlimited()).unwrap();
        absolute
            .prepare::<Span>()
            .search_with_workspace(b"x", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let proof = absolute
            .start_filter_proof
            .get()
            .expect("successful absolute search publishes its proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::Empty,
            })
        ));
    }

    #[test]
    fn start_scanner_cardinality_is_cached_without_copying() {
        let cases: &[&[u8]] = &[&[], b"a", b"ab", b"abc", b"abcd"];

        for &bytes in cases {
            let automaton = ascii_root_bytes(bytes);
            let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
            let cold = automaton
                .prepare::<Span>()
                .search_with_workspace(b"z", &mut workspace, SearchLimits::unlimited())
                .unwrap();
            let warm = automaton
                .prepare::<Span>()
                .search_with_workspace(b"z", &mut workspace, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(cold.output(), warm.output());
            let graph_work = if bytes.is_empty() {
                1
            } else {
                2_u64
                    .checked_add(u64::try_from(bytes.len()).unwrap().checked_mul(2).unwrap())
                    .unwrap()
            };
            let proof_work = graph_work
                .checked_add(expected_filter_selection_work(1, bytes.len()))
                .unwrap();
            assert_eq!(
                cold.accounting()
                    .transition_work()
                    .checked_sub(warm.accounting().transition_work()),
                Some(proof_work)
            );

            let proof = automaton
                .start_filter_proof
                .get()
                .expect("successful search publishes the start scanner");
            let scanner = proof
                .scanner
                .as_ref()
                .expect("a selective byte root enables start scanning");
            assert_eq!(scanner.offset, 0);
            assert!(matches!(
                (bytes, &scanner.scanner),
                (b"", StartScanner::Empty)
                    | (b"a", StartScanner::One(b'a'))
                    | (b"ab", StartScanner::Two(b'a', b'b'))
                    | (b"abc", StartScanner::Three(b'a', b'b', b'c'))
                    | (b"abcd", StartScanner::Set(_))
            ));

            let mut meter = WorkMeter::new(u64::MAX, 0);
            let invocation =
                super::prepare_start_filter(&automaton, &mut workspace, &mut meter, 0).unwrap();
            match invocation {
                super::InvocationStartProof::Published(borrowed) => {
                    assert!(core::ptr::eq(borrowed, proof));
                }
                super::InvocationStartProof::Pending(_) => {
                    panic!("cached scanner was unexpectedly rebuilt");
                }
            }
            assert_eq!(meter.consumed, 0);
        }
    }

    #[test]
    fn byte_start_specialization_is_once_per_automaton_and_clone() {
        let automaton = ascii_literal(b'a');
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(cold.output(), warm.output());
        let specialization_work = 4_u64
            .checked_add(expected_filter_selection_work(1, 1))
            .unwrap();
        assert_eq!(
            cold.accounting()
                .transition_work()
                .checked_sub(warm.accounting().transition_work()),
            Some(specialization_work)
        );
        let published = automaton
            .start_filter_proof
            .get()
            .expect("successful cold search publishes the proof");
        let mut cache_meter = WorkMeter::new(u64::MAX, 0);
        let cached =
            super::prepare_start_filter(&automaton, &mut workspace, &mut cache_meter, 0).unwrap();
        match cached {
            super::InvocationStartProof::Published(borrowed) => {
                assert!(
                    core::ptr::eq(borrowed, published),
                    "warm invocation must borrow the cached start scanner"
                );
            }
            super::InvocationStartProof::Pending(_) => {
                panic!("warm invocation unexpectedly rebuilt the proof");
            }
        }
        assert_eq!(cache_meter.consumed, 0);

        let cloned = automaton.clone();
        assert!(
            cloned.start_filter_proof.get().is_none(),
            "cloning must not copy uncharged first-use specialization"
        );
        let mut clone_workspace = K0Workspace::new(&cloned, WorkspaceLimits::unlimited()).unwrap();
        let clone_cold = cloned
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut clone_workspace, SearchLimits::unlimited())
            .unwrap();
        let clone_warm = cloned
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut clone_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            clone_cold
                .accounting()
                .transition_work()
                .checked_sub(clone_warm.accounting().transition_work()),
            Some(specialization_work)
        );
    }

    #[test]
    fn refused_scanner_selection_does_not_publish_unpaid_specialization() {
        let root = [b'a', b'b', b'c', b'd'];
        let automaton = ascii_root_bytes(&root);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        // The root proof visits its state and consuming edges, retains the
        // next frontier with a second edge pass, then observes accept.
        let proof_work = 2_u64
            .checked_add(u64::try_from(root.len()).unwrap().checked_mul(2).unwrap())
            .unwrap();
        let admitted = INVOCATION_RESET_WORK.checked_add(proof_work).unwrap();
        let population_work = u64::try_from(BYTE_START_BITMAP_POPULATION_WORK).unwrap();
        let error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut workspace,
                SearchLimits {
                    max_work: admitted,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                consumed,
                requested,
                ..
            } if consumed == admitted
                && requested == population_work
        ));
        assert!(automaton.start_filter_proof.get().is_none());

        // Once all bitmap words are admitted and counted, choosing this
        // position is the next indivisible selection charge.
        let population_admitted = admitted.checked_add(population_work).unwrap();
        let error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut workspace,
                SearchLimits {
                    max_work: population_admitted,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                consumed,
                requested,
                ..
            } if consumed == population_admitted
                && requested == u64::try_from(START_FILTER_SCANNER_SELECTION_WORK).unwrap()
        ));
        assert!(automaton.start_filter_proof.get().is_none());

        // A small scanner charges its member extraction after population and
        // exact-position selection, and likewise cannot publish on refusal.
        let small = ascii_literal(b'a');
        let mut small_workspace = K0Workspace::new(&small, WorkspaceLimits::unlimited()).unwrap();
        let small_proof_work = 4_u64;
        let small_extraction_limit = INVOCATION_RESET_WORK
            .checked_add(small_proof_work)
            .and_then(|work| work.checked_add(population_work))
            .and_then(|work| {
                work.checked_add(u64::try_from(START_FILTER_SCANNER_SELECTION_WORK).unwrap())
            })
            .unwrap();
        let error = small
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut small_workspace,
                SearchLimits {
                    max_work: small_extraction_limit,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                consumed,
                requested,
                ..
            } if consumed == small_extraction_limit
                && requested
                    == u64::try_from(BYTE_START_MEMBER_EXTRACTION_WORK).unwrap()
        ));
        assert!(small.start_filter_proof.get().is_none());
    }

    #[test]
    fn refused_class_selection_does_not_publish_unpaid_specialization() {
        let ranges = [(b'Q', b'Q'), (0, 0xff), (b'Z', b'Z')];
        let measured = byte_chain(&ranges);
        let mut measured_workspace =
            K0Workspace::new(&measured, WorkspaceLimits::unlimited()).unwrap();
        let mut proof_meter = WorkMeter::new(u64::MAX, 0);
        let proof = super::derive_start_position_classes(
            &measured,
            &mut measured_workspace,
            &mut proof_meter,
            0,
        )
        .unwrap();
        assert_eq!(proof.length, 3);

        let selection_work = expected_start_class_selection_work(proof.length);
        let one_below_selection = INVOCATION_RESET_WORK
            .checked_add(proof_meter.consumed)
            .and_then(|work| work.checked_add(selection_work))
            .and_then(|work| work.checked_sub(1))
            .unwrap();
        let automaton = byte_chain(&ranges);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"QxZ",
                &mut workspace,
                SearchLimits {
                    max_work: one_below_selection,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit,
                consumed,
                requested: 1,
                position: 0,
            } if limit == one_below_selection && consumed == one_below_selection
        ));
        assert!(
            automaton.start_filter_proof.get().is_none(),
            "a refused class comparison must not publish a partial proof"
        );

        automaton
            .prepare::<Span>()
            .search_with_workspace(b"QxZ", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            automaton
                .start_filter_proof
                .get()
                .expect("successful retry publishes complete proof")
                .guard,
            Some(StartPositionClass {
                offset: 2,
                set: byte_set(b"Z"),
            })
        );
    }

    #[test]
    fn failed_first_use_does_not_publish_unpaid_specialization() {
        let root = [b'a', b'b', b'c', b'd'];
        let automaton = ascii_root_bytes(&root);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let proof_work = 2_u64
            .checked_add(u64::try_from(root.len()).unwrap().checked_mul(2).unwrap())
            .unwrap();
        let specialization_admitted = INVOCATION_RESET_WORK
            .checked_add(proof_work)
            .and_then(|work| work.checked_add(expected_filter_selection_work(1, root.len())))
            .unwrap();
        let probe = ascii_root_bytes(&root);
        let mut probe_workspace = K0Workspace::new(&probe, WorkspaceLimits::unlimited()).unwrap();
        let full_cold_work = probe
            .prepare::<Span>()
            .search_with_workspace(b"za", &mut probe_workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        let late_error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut workspace,
                SearchLimits {
                    max_work: full_cold_work.checked_sub(1).unwrap(),
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            late_error,
            SearchError::WorkLimitExceeded { consumed, .. }
                if consumed > specialization_admitted
        ));
        assert!(
            automaton.start_filter_proof.get().is_none(),
            "a search that pays specialization but later fails must not publish it"
        );

        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(b"za", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert!(automaton.start_filter_proof.get().is_some());
        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(b"za", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let specialization_work = proof_work
            .checked_add(expected_filter_selection_work(1, root.len()))
            .unwrap();
        assert_eq!(
            cold.accounting()
                .transition_work()
                .checked_sub(warm.accounting().transition_work()),
            Some(specialization_work)
        );
        automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut workspace,
                SearchLimits {
                    max_work: warm.accounting().work(),
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap();

        let cloned = automaton.clone();
        let mut clone_workspace = K0Workspace::new(&cloned, WorkspaceLimits::unlimited()).unwrap();
        let clone_error = cloned
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut clone_workspace,
                SearchLimits {
                    max_work: warm.accounting().work(),
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(clone_error, SearchError::WorkLimitExceeded { .. }));
        assert!(cloned.start_filter_proof.get().is_none());
    }

    #[test]
    fn concurrent_first_use_is_correct_and_fully_charged() {
        let reference = ascii_literal(b'a');
        let mut reference_workspace =
            K0Workspace::new(&reference, WorkspaceLimits::unlimited()).unwrap();
        let cold_work = reference
            .prepare::<Span>()
            .search_with_workspace(
                b"zzzzzzza",
                &mut reference_workspace,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .accounting()
            .transition_work();
        let warm_work = reference
            .prepare::<Span>()
            .search_with_workspace(
                b"zzzzzzza",
                &mut reference_workspace,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .accounting()
            .transition_work();
        assert!(cold_work > warm_work);

        let automaton = Arc::new(ascii_literal(b'a'));
        let thread_count = 8;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = Vec::new();
        for _ in 0..thread_count {
            let automaton = Arc::clone(&automaton);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut workspace =
                    K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
                barrier.wait();
                let report = automaton
                    .prepare::<Span>()
                    .search_with_workspace(b"zzzzzzza", &mut workspace, SearchLimits::unlimited())
                    .unwrap();
                let work = report.accounting().transition_work();
                (report.into_output(), work)
            }));
        }

        let reports: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(reports
            .iter()
            .all(
                |(found, _)| found.as_ref().map(|span| (span.start(), span.end())) == Some((7, 8))
            ));
        assert!(
            reports
                .iter()
                .all(|(_, work)| *work == cold_work || *work == warm_work),
            "a racing caller must either derive and fully charge or use the published proof"
        );
        assert!(reports.iter().any(|(_, work)| *work == cold_work));
        assert!(automaton.start_filter_proof.get().is_some());
    }

    #[test]
    fn every_non_absolute_start_assertion_is_conservatively_relaxed() {
        let absolute = assertion_or_colon(EdgeKind::AssertHaystackStart);
        let mut absolute_workspace =
            K0Workspace::new(&absolute, WorkspaceLimits::unlimited()).unwrap();
        let mut absolute_meter = WorkMeter::new(u64::MAX, 0);
        let proof = super::derive_start_position_classes(
            &absolute,
            &mut absolute_workspace,
            &mut absolute_meter,
            0,
        )
        .unwrap();
        assert!(proof.force_haystack_start);
        assert_eq!(proof.sets[0].words(), [1_u64 << u32::from(b':'), 0, 0, 0]);

        let relaxed = [
            EdgeKind::AssertHaystackEnd,
            EdgeKind::AssertLineStartLf,
            EdgeKind::AssertLineEndLf,
            EdgeKind::AssertLineStartCrlf,
            EdgeKind::AssertLineEndCrlf,
            EdgeKind::AssertWordAscii,
            EdgeKind::AssertWordAsciiNegate,
            EdgeKind::AssertWordStartAscii,
            EdgeKind::AssertWordEndAscii,
            EdgeKind::AssertWordStartHalfAscii,
            EdgeKind::AssertWordEndHalfAscii,
            EdgeKind::AssertWordUnicode,
            EdgeKind::AssertWordUnicodeNegate,
            EdgeKind::AssertWordStartUnicode,
            EdgeKind::AssertWordEndUnicode,
            EdgeKind::AssertWordStartHalfUnicode,
            EdgeKind::AssertWordEndHalfUnicode,
        ];
        for assertion in relaxed {
            let automaton = assertion_or_colon(assertion);
            let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let proof =
                super::derive_start_position_classes(&automaton, &mut workspace, &mut meter, 0)
                    .unwrap();
            assert_eq!(
                proof.sets[0],
                byte_set(b"a:"),
                "{} did not conservatively retain both roots",
                assertion.name()
            );
            assert_eq!(proof.length, 1);
            assert!(
                !proof.force_haystack_start,
                "{} unexpectedly retained an absolute-start exception",
                assertion.name()
            );
        }
    }

    #[test]
    fn absolute_high_byte_branch_and_ascii_sibling_match_every_window() {
        let mut haystacks = bounded_words(&[b'x', b':', b'a', 0xff], 5);
        let mut late = vec![b'x'; 65];
        late.extend_from_slice(&[0xff, b':', b'a']);
        haystacks.push(late);

        let specialized = absolute_high_byte_or_colon_a();
        let reference = absolute_high_byte_or_colon_a();
        assert_all_windows_match_unspecialized(
            "absolute-high-byte-or-colon",
            &specialized,
            &reference,
            &haystacks,
        );

        let proof = specialized
            .start_filter_proof
            .get()
            .expect("exhaustive successful search publishes the proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::One(b':'),
            })
        ));
        assert_eq!(
            proof.guard,
            Some(StartPositionClass {
                offset: 1,
                set: byte_set(b"a"),
            })
        );

        let mut workspace = K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
        let at_zero = specialized
            .prepare::<Span>()
            .search_with_workspace(b"\xff:a", &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output()
            .expect("the absolute high-byte branch matches at zero");
        assert_eq!((at_zero.start(), at_zero.end()), (0, 1));

        let later = specialized
            .prepare::<Span>()
            .search_window_with_workspace(
                b"x\xff:a",
                SearchWindow::new(1, 4),
                &mut workspace,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .into_output()
            .expect("the ASCII sibling remains discoverable after a nonzero high byte");
        assert_eq!((later.start(), later.end()), (2, 4));
    }

    #[test]
    fn absolute_start_root_proof_matches_unspecialized_search_exhaustively() {
        type AutomatonFactory = fn() -> Automaton;

        let mut haystacks = bounded_words(b"x:fo", 5);
        let mut late_colon = vec![b'x'; 65];
        late_colon.extend_from_slice(b":foo");
        haystacks.push(late_colon);
        let mut dense_colons = vec![b':'; 33];
        dense_colons.extend_from_slice(b"foo");
        haystacks.push(dense_colons);

        let cases: &[(&str, AutomatonFactory)] = &[
            ("absolute-foo", absolute_foo),
            ("absolute-or-colon-foo", absolute_or_colon_foo),
            ("absolute-nullable-or-colon", absolute_nullable_or_colon),
            (
                "unasserted-nullable-sibling",
                absolute_or_colon_or_unasserted_empty,
            ),
        ];
        for &(name, build) in cases {
            let specialized = build();
            let reference = build();
            assert_all_windows_match_unspecialized(name, &specialized, &reference, &haystacks);
        }
    }

    #[test]
    fn factored_absolute_start_pattern_matches_unspecialized_search() {
        let haystacks = [
            b"".as_slice(),
            b"abc".as_slice(),
            b"abcd".as_slice(),
            b"abc!".as_slice(),
            b":abc".as_slice(),
            b":abcd".as_slice(),
            b":abc!".as_slice(),
            b"x:abc!".as_slice(),
            b":::x:abcd".as_slice(),
            b"abcdx:abc!".as_slice(),
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:abcd".as_slice(),
            b":::::::::::::::::::::::::::::::::abc!".as_slice(),
        ]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
        let specialized = absolute_or_colon_with_ordered_suffixes();
        let reference = absolute_or_colon_with_ordered_suffixes();
        assert_all_windows_match_unspecialized(
            "factored-absolute-start",
            &specialized,
            &reference,
            &haystacks,
        );
    }

    #[test]
    fn absolute_start_root_proof_is_transactional_and_exactly_metered() {
        let automaton = absolute_or_colon_foo();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let mut haystack = vec![b'x'; 64];
        haystack.extend_from_slice(b":foo");

        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let proof = automaton
            .start_filter_proof
            .get()
            .expect("successful search publishes the proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::One(b':'),
            })
        ));
        assert_eq!(
            proof.guard,
            Some(StartPositionClass {
                offset: 3,
                set: byte_set(b"o"),
            })
        );

        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let specialization_work = 16_u64
            .checked_add(expected_filter_selection_work(4, 1))
            .unwrap();
        assert_eq!(
            cold.accounting()
                .transition_work()
                .checked_sub(warm.accounting().transition_work()),
            Some(specialization_work)
        );
        assert_eq!(cold.output(), warm.output());
        assert_eq!(warm.output(), &Some(crate::MatchSpan::new(64, 68)));
        assert_eq!(warm.accounting().boundaries(), 6);
        assert_eq!(
            warm.accounting().work(),
            warm.accounting().setup_work() + warm.accounting().transition_work()
        );
        assert_eq!(
            warm.accounting().scratch_bytes(),
            workspace.retained_bytes()
        );
        assert!(warm.accounting().setup().reused());

        let exact = automaton
            .prepare::<Span>()
            .search_with_workspace(
                &haystack,
                &mut workspace,
                SearchLimits {
                    max_work: warm.accounting().work(),
                    max_scratch_bytes: warm.accounting().scratch_bytes(),
                },
            )
            .unwrap();
        assert_eq!(exact.output(), warm.output());
        assert_eq!(exact.accounting(), warm.accounting());

        let refused = automaton
            .prepare::<Span>()
            .search_with_workspace(
                &haystack,
                &mut workspace,
                SearchLimits {
                    max_work: warm.accounting().work() - 1,
                    max_scratch_bytes: warm.accounting().scratch_bytes(),
                },
            )
            .unwrap_err();
        assert!(matches!(refused, SearchError::WorkLimitExceeded { .. }));

        let unpublished = absolute_or_colon_foo();
        let mut unpublished_workspace =
            K0Workspace::new(&unpublished, WorkspaceLimits::unlimited()).unwrap();
        let cold_work = cold.accounting().work();
        let refused = unpublished
            .prepare::<Span>()
            .search_with_workspace(
                &haystack,
                &mut unpublished_workspace,
                SearchLimits {
                    max_work: cold_work - 1,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(refused, SearchError::WorkLimitExceeded { .. }));
        assert!(
            unpublished.start_filter_proof.get().is_none(),
            "a failed cold search must not publish the absolute-start proof"
        );
    }

    #[test]
    fn generation_rollover_is_preflighted_and_accounted_as_setup() {
        let required_generations = u64::try_from(
            1_usize
                .checked_add(START_FILTER_POSITION_COUNT)
                .and_then(|count| count.checked_add(1))
                .unwrap(),
        )
        .unwrap();
        let no_reset = ascii_literal(b'a');
        let mut no_reset_workspace =
            K0Workspace::new(&no_reset, WorkspaceLimits::unlimited()).unwrap();
        no_reset_workspace.generation = u64::MAX.checked_sub(required_generations).unwrap();
        let no_reset_report = no_reset
            .prepare::<Span>()
            .search_with_workspace(b"a", &mut no_reset_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(no_reset_report.accounting().setup_work(), 3);
        assert_eq!(no_reset_report.accounting().setup().initialized_bytes(), 0);

        let automaton = ascii_literal(b'a');
        let mut workspace =
            super::K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).expect("workspace");
        workspace.generation = u64::MAX
            .checked_sub(required_generations.checked_sub(1).unwrap())
            .unwrap();
        let before_reset = workspace.generation;

        let reset_work = 3_u64
            .checked_add(u64::try_from(automaton.stats().states()).unwrap())
            .unwrap();
        let error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"a",
                &mut workspace,
                SearchLimits {
                    max_work: reset_work - 1,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(error, SearchError::WorkLimitExceeded { .. }));
        assert_eq!(workspace.generation, before_reset);

        let report = automaton
            .prepare::<Span>()
            .search_with_workspace(b"a", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(report.accounting().setup_work(), reset_work);
        assert_eq!(
            report.accounting().setup().initialized_bytes(),
            automaton.stats().states() * size_of::<u64>()
        );
        assert_eq!(report.into_output().unwrap().end(), 1);
    }

    #[test]
    fn sparse_ascii_root_skips_impossible_starts_and_preserves_the_span() {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 2, 2],
                edge_targets: vec![1, 2],
                edge_kinds: vec![EdgeKind::ByteRange, EdgeKind::ByteRange],
                byte_starts: vec![b'0', b'/'],
                byte_ends: vec![b'9', b'/'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();

        let mut haystack = vec![b'x'; 96];
        haystack.extend_from_slice(b"5/");
        automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let miss = automaton
            .prepare::<Span>()
            .search_with_workspace(b"xxxx", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(miss.accounting().boundaries(), 0);
        assert!(miss.into_output().is_none());
        let report = automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let accounting = report.accounting();
        let found = report.into_output().unwrap();
        assert_eq!((found.start(), found.end()), (96, 98));
        assert_eq!(
            automaton
                .start_filter_proof
                .get()
                .expect("start proof should be initialized"),
            &StartFilterProof {
                scanner: Some(positioned_scanner(1, StartScanner::One(b'/'))),
                guard: Some(StartPositionClass {
                    offset: 0,
                    set: byte_range_set(b'0', b'9'),
                }),
                force_haystack_start: false,
            }
        );
        assert_eq!(accounting.boundaries(), 3);
        assert!(accounting.transition_work() < 120);
    }

    #[test]
    fn ranged_sparse_root_keeps_original_offsets() {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 1],
                edge_targets: vec![1],
                edge_kinds: vec![EdgeKind::ByteRange],
                byte_starts: vec![b'a'],
                byte_ends: vec![b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let haystack = b"a...............................a";
        let report = automaton
            .prepare::<Span>()
            .search_window_with_workspace(
                haystack,
                SearchWindow::new(1, haystack.len()),
                &mut workspace,
                SearchLimits::unlimited(),
            )
            .unwrap();
        let found = report.into_output().unwrap();
        assert_eq!((found.start(), found.end()), (32, 33));
    }

    #[test]
    fn nullable_declines_while_asserted_and_high_byte_roots_filter() {
        let nullable = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Accept],
                edge_offsets: vec![0, 0],
                edge_targets: vec![],
                edge_kinds: vec![],
                byte_starts: vec![],
                byte_ends: vec![],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut nullable_workspace =
            K0Workspace::new(&nullable, WorkspaceLimits::unlimited()).unwrap();
        let nullable_cold = nullable
            .prepare::<Span>()
            .search_with_workspace(b"", &mut nullable_workspace, SearchLimits::unlimited())
            .unwrap();
        let nullable_warm = nullable
            .prepare::<Span>()
            .search_with_workspace(b"", &mut nullable_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            nullable_cold
                .accounting()
                .transition_work()
                .checked_sub(nullable_warm.accounting().transition_work()),
            Some(1)
        );
        assert!(nullable
            .start_filter_proof
            .get()
            .expect("nullable proof should be initialized")
            .scanner
            .is_none());

        let asserted = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 2, 2],
                edge_targets: vec![1, 2],
                edge_kinds: vec![EdgeKind::AssertLineStartLf, EdgeKind::ByteRange],
                byte_starts: vec![0, b'a'],
                byte_ends: vec![0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut asserted_workspace =
            K0Workspace::new(&asserted, WorkspaceLimits::unlimited()).unwrap();
        asserted
            .prepare::<Span>()
            .search_with_workspace(b"a", &mut asserted_workspace, SearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            asserted
                .start_filter_proof
                .get()
                .expect("asserted proof should be initialized")
                .scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::One(b'a'),
            })
        ));

        let high = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 1],
                edge_targets: vec![1],
                edge_kinds: vec![EdgeKind::ByteRange],
                byte_starts: vec![0x80],
                byte_ends: vec![0xff],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut high_workspace = K0Workspace::new(&high, WorkspaceLimits::unlimited()).unwrap();
        high.prepare::<Span>()
            .search_with_workspace(&[0x80], &mut high_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            high.start_filter_proof
                .get()
                .expect("high-byte proof should be initialized")
                .scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::Set(ByteSet::from_words([0, 0, u64::MAX, u64::MAX,])),
            })
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all four typed contracts share one exhaustive window matrix"
    )]
    fn ordered_lazy_dfa_is_exhaustively_differential_for_every_contract_and_window() {
        let plans = [
            a_plus(true),
            a_plus(false),
            ordered_a_or_ab(true),
            ordered_a_or_ab(false),
            greedy_a_plus_or_a(),
            greedy_binary_pair_plus_then_80(),
            byte_chain(&[(0x00, 0xff), (b'Z', b'Z')]),
        ];
        let haystacks = bounded_words(&[0x00, b'a', b'b', 0x80, 0xff], 4);
        let mut checked = 0usize;

        for plan in &plans {
            let mut pike = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
            let mut accelerated =
                K0Workspace::new_accelerated(plan, WorkspaceLimits::unlimited()).unwrap();
            assert!(accelerated.retained_bytes() > pike.retained_bytes());

            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let want_exists = plan
                            .prepare::<Exists>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let got_exists = plan
                            .prepare::<Exists>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut accelerated,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            got_exists, want_exists,
                            "exists mismatch plan={plan:?}, source={haystack:?}, window={window:?}"
                        );

                        let want_earliest = plan
                            .prepare::<EarliestEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let got_earliest = plan
                            .prepare::<EarliestEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut accelerated,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            got_earliest, want_earliest,
                            "earliest mismatch plan={plan:?}, source={haystack:?}, window={window:?}"
                        );

                        let want_selected = plan
                            .prepare::<SelectedEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let got_selected = plan
                            .prepare::<SelectedEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut accelerated,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            got_selected, want_selected,
                            "selected mismatch plan={plan:?}, source={haystack:?}, window={window:?}"
                        );

                        let want_span = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let got_span = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut accelerated,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            got_span, want_span,
                            "span mismatch plan={plan:?}, source={haystack:?}, window={window:?}"
                        );
                        checked = checked.checked_add(1).unwrap();
                    }
                }
            }
            assert!(accelerated.lazy.initialized);
            assert!(!accelerated.lazy.declined);
        }
        assert!(checked > 10_000);
    }

    #[test]
    fn span_is_a_typed_pike_fallback_and_declined_graphs_keep_the_old_layout() {
        let eligible = a_plus(true);
        let ordinary = eligible.workspace_layout().unwrap();
        let accelerated = eligible.accelerated_workspace_layout().unwrap();
        assert!(accelerated.logical_bytes() > ordinary.logical_bytes());
        assert!(accelerated.construction_work() > ordinary.construction_work());

        let mut workspace =
            K0Workspace::new_accelerated(&eligible, WorkspaceLimits::unlimited()).unwrap();
        let span = eligible
            .prepare::<Span>()
            .search_with_workspace(b"baaa", &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output();
        assert_eq!(span, Some(MatchSpan::new(1, 4)));
        assert!(!workspace.lazy.initialized);
        assert!(!workspace.lazy.declined);

        let selected = eligible
            .prepare::<SelectedEnd>()
            .search_with_workspace(b"baaa", &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output();
        assert_eq!(selected, Some(4));
        assert!(workspace.lazy.initialized);

        let asserted = assertion_or_colon(EdgeKind::AssertLineStartLf);
        assert_eq!(
            asserted.accelerated_workspace_layout().unwrap(),
            asserted.workspace_layout().unwrap()
        );
        let ordinary_asserted = K0Workspace::new(&asserted, WorkspaceLimits::unlimited()).unwrap();
        let accelerated_asserted =
            K0Workspace::new_accelerated(&asserted, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(
            accelerated_asserted.retained_bytes(),
            ordinary_asserted.retained_bytes()
        );
        assert!(!accelerated_asserted.lazy.is_allocated());

        let nullable = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Accept],
                edge_offsets: vec![0, 0],
                edge_targets: vec![],
                edge_kinds: vec![],
                byte_starts: vec![],
                byte_ends: vec![],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut nullable_workspace =
            K0Workspace::new_accelerated(&nullable, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(
            nullable
                .prepare::<SelectedEnd>()
                .search_with_workspace(b"abc", &mut nullable_workspace, SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            Some(0)
        );
        assert!(nullable_workspace.lazy.declined);
        assert!(!nullable_workspace.lazy.initialized);
    }

    #[test]
    fn saturated_lazy_cache_continues_inline_without_replaying_and_stays_correct() {
        let plan = greedy_a_plus_or_a();
        let mut pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut accelerated =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();

        // Retain only the mandatory initial state. The first transition that
        // has a live successor must hand its just-computed frontier to inline
        // execution.
        accelerated.lazy.offsets.truncate(1);
        accelerated.lazy.lengths.truncate(1);
        accelerated.lazy.modes.truncate(1);
        accelerated.lazy.hashes.truncate(1);

        for haystack in [b"baaaaaax".as_slice(), b"aaaa", b"xaaaax", b"\xffaax"] {
            let want = plan
                .prepare::<SelectedEnd>()
                .search_with_workspace(haystack, &mut pike, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            let got = plan
                .prepare::<SelectedEnd>()
                .search_with_workspace(haystack, &mut accelerated, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            assert_eq!(got, want, "saturated source={haystack:?}");
        }
        assert!(accelerated.lazy.saturated);
        assert!(accelerated.lazy.initialized);
    }

    #[test]
    fn transient_learning_budget_refusal_preserves_cached_rows_and_can_retry() {
        let plan = a_plus(true);
        let certified = plan.conservative_reused_work_bound(2).unwrap();
        let mut fresh = K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let fresh_retained = fresh.retained_bytes();
        let certified_report = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(
                b"aa",
                &mut fresh,
                SearchLimits {
                    max_work: certified,
                    max_scratch_bytes: fresh_retained,
                },
            )
            .unwrap();
        assert_eq!(certified_report.output(), &Some(2));
        assert!(certified_report.accounting().work() <= certified);
        assert!(
            !fresh.lazy.initialized,
            "a fresh cache must leave the ordinary certificate reserved"
        );

        let mut workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();

        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(b"a", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(1)
        );
        let initial = workspace.lazy.initial;
        let pending = workspace.lazy.cell(initial, b'a').unwrap() & super::LAZY_CELL_STATE_MASK;
        let pending = pending.checked_sub(1).unwrap();
        assert_eq!(
            workspace.lazy.cell(pending, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED
        );

        let retained = workspace.retained_bytes();
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(
                    b"aa",
                    &mut workspace,
                    SearchLimits {
                        max_work: certified,
                        max_scratch_bytes: retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(2)
        );
        assert!(!workspace.lazy.saturated);
        assert_eq!(
            workspace.lazy.cell(pending, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED,
            "a bound-certified call must decline optional learning"
        );

        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(b"aa", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(2)
        );
        assert_ne!(
            workspace.lazy.cell(pending, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED,
            "a later call with surplus work must retry and publish the row"
        );
    }

    #[test]
    fn warmed_lazy_rows_remove_repeated_dense_pike_closure_work() {
        let plan = a_plus(true);
        let haystack = vec![b'a'; 4_096];
        let mut pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut accelerated =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();

        let _ = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(&haystack, &mut accelerated, SearchLimits::unlimited())
            .unwrap();
        let pike = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(&haystack, &mut pike, SearchLimits::unlimited())
            .unwrap();
        let accelerated = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(&haystack, &mut accelerated, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(accelerated.output(), pike.output());
        assert!(
            accelerated.accounting().transition_work() * 2 < pike.accounting().transition_work(),
            "warmed rows should replace repeated ordered closure"
        );
    }

    #[test]
    fn accelerated_workspace_limits_and_optional_preparation_are_pre_source_exact() {
        let plan = a_plus(true);
        let layout = plan.accelerated_workspace_layout().unwrap();
        let setup_error = K0Workspace::new_accelerated(
            &plan,
            WorkspaceLimits {
                max_setup_work: layout.construction_work() - 1,
                max_scratch_bytes: usize::MAX,
            },
        )
        .unwrap_err();
        assert_eq!(
            setup_error,
            SearchError::WorkspaceSetupWorkLimitExceeded {
                limit: layout.construction_work() - 1,
                needed: layout.construction_work(),
            }
        );
        let scratch_error = K0Workspace::new_accelerated(
            &plan,
            WorkspaceLimits {
                max_setup_work: u64::MAX,
                max_scratch_bytes: layout.logical_bytes() - 1,
            },
        )
        .unwrap_err();
        assert!(matches!(
            scratch_error,
            SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            } if needed == layout.logical_bytes() && limit == layout.logical_bytes() - 1
        ));

        let mut workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        pin_without_start_filter(&plan);
        let states = u64::try_from(plan.stats().states()).unwrap();
        let epsilon = u64::try_from(plan.stats().zero_width_edges()).unwrap();
        let initial_upper = states * 2 + epsilon * 2 + 2;
        let limits = SearchLimits {
            max_work: INVOCATION_RESET_WORK + initial_upper - 1,
            max_scratch_bytes: workspace.retained_bytes(),
        };
        let mut setup = crate::SetupAccounting::empty(workspace.retained_bytes(), true);
        let (mut meter, _) = super::prepare_invocation(
            &plan,
            &mut workspace,
            SearchWindow::new(0, 4),
            limits,
            &mut setup,
            true,
        )
        .unwrap();
        assert!(!super::prepare_lazy(&plan, &mut workspace, &mut meter, 0, 0).unwrap());
        assert_eq!(meter.consumed, INVOCATION_RESET_WORK);
        assert!(!workspace.lazy.initialized);
        assert!(!workspace.lazy.declined);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all accelerated endpoint contracts share the same exact-limit matrix"
    )]
    fn warmed_lazy_contracts_enforce_exact_and_one_below_work_limits() {
        let plan = a_plus(true);
        let haystack = b"baaaaa";
        let mut workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let retained = workspace.retained_bytes();

        let _ = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();

        let exists_work = plan
            .prepare::<Exists>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert!(plan
            .prepare::<Exists>()
            .search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: exists_work,
                    max_scratch_bytes: retained,
                },
            )
            .unwrap()
            .into_output());
        assert!(matches!(
            plan.prepare::<Exists>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: exists_work - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == exists_work - 1
        ));

        let earliest_work = plan
            .prepare::<EarliestEnd>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert_eq!(
            plan.prepare::<EarliestEnd>()
                .search_with_workspace(
                    haystack,
                    &mut workspace,
                    SearchLimits {
                        max_work: earliest_work,
                        max_scratch_bytes: retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(2)
        );
        assert!(matches!(
            plan.prepare::<EarliestEnd>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: earliest_work - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == earliest_work - 1
        ));

        let selected_work = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(
                    haystack,
                    &mut workspace,
                    SearchLimits {
                        max_work: selected_work,
                        max_scratch_bytes: retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(haystack.len())
        );
        assert!(matches!(
            plan.prepare::<SelectedEnd>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: selected_work - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == selected_work - 1
        ));

        assert!(matches!(
            plan.prepare::<SelectedEnd>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: retained - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == retained && limit == retained - 1
        ));
    }

    #[test]
    fn lazy_cache_is_bound_to_the_exact_immutable_automaton() {
        let first = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let second = byte_chain(&[(b'a', b'a'), (b'c', b'c')]);
        assert_eq!(first.workspace_layout(), second.workspace_layout());
        let mut workspace =
            K0Workspace::new_accelerated(&first, WorkspaceLimits::unlimited()).unwrap();

        assert_eq!(
            second
                .prepare::<SelectedEnd>()
                .search_with_workspace(b"zac", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(3)
        );
        assert!(!workspace.lazy.initialized);
        assert!(workspace.lazy.is_bound_to(&first));

        assert_eq!(
            first
                .prepare::<SelectedEnd>()
                .search_with_workspace(b"zab", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(3)
        );
        assert!(workspace.lazy.initialized);
    }
}
