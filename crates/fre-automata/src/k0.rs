use core::mem::size_of;

use fre_simd_kernels::{
    AsciiByteSet, AsciiByteSetClassifier, ASCII_CLASSIFIER_BUILD_WORK, ASCII_NARROW_BYTES,
    ASCII_WIDE_BYTES,
};

use crate::{
    Automaton, EdgeKind, MatchSpan, ResourceKind, SearchAccounting, SearchError, SearchLimits,
    SearchWindow, SetupAccounting, StateRole, UnicodeLookMatcher,
};

const INVOCATION_RESET_WORK: u64 = 3;

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
    logical_bytes: usize,
    construction_work: u64,
}

impl WorkspaceLayout {
    pub(crate) fn for_automaton(automaton: &Automaton) -> Result<Self, SearchError> {
        let states = automaton.stats().states();
        let edges = automaton.stats().edges();
        let zero_width_edges = automaton.stats().zero_width_edges();
        let closure_slots =
            zero_width_edges
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "closure stack capacity",
                })?;
        let logical_bytes = scratch_bytes(states, edges, closure_slots)?;
        let initialized_slots = states
            .checked_add(states)
            .and_then(|value| value.checked_add(edges))
            .and_then(|value| value.checked_add(closure_slots))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace initialized slots",
            })?;
        let non_empty_allocations = usize::from(states != 0)
            .checked_add(usize::from(states != 0))
            .and_then(|value| value.checked_add(usize::from(edges != 0)))
            .and_then(|value| value.checked_add(usize::from(closure_slots != 0)))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace allocation count",
            })?;
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
    start_set: Option<AsciiByteSet>,
    start_classifier: Option<AsciiByteSetClassifier>,
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
        let layout = WorkspaceLayout::for_automaton(automaton)?;
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
        let retained_bytes = retained_bytes(&seen_at, &current, &roots, &stack)?;
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
            start_set: None,
            start_classifier: None,
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
}

pub(crate) fn search(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
    earliest: bool,
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
        earliest,
    )
}

pub(crate) fn search_with_workspace(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    earliest: bool,
) -> Result<UntypedReport, SearchError> {
    execute(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        SetupAccounting::empty(workspace.retained_bytes, true),
        earliest,
    )
}

fn execute(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    mut setup: SetupAccounting,
    earliest: bool,
) -> Result<UntypedReport, SearchError> {
    validate_window(haystack, window)?;
    let (mut meter, setup_work) =
        prepare_invocation(automaton, workspace, window, limits, &mut setup)?;

    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending = None;

    loop {
        if pending.is_none() && workspace.roots_len == 0 {
            if let Some(classifier) = workspace.start_classifier.as_ref() {
                position =
                    next_start_candidate(classifier, haystack, position, window.end(), &mut meter)?;
                if position == window.end() {
                    break;
                }
            }
        }
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "examined boundary count",
            })?;
        workspace.begin_boundary(&mut meter, position)?;
        expand_boundary_roots(
            automaton,
            haystack,
            position,
            workspace,
            &mut meter,
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

        consume_current(
            automaton,
            haystack[position],
            position,
            workspace,
            &mut meter,
        )?;
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "input position",
            })?;
    }

    let transition_work =
        meter
            .consumed
            .checked_sub(setup_work)
            .ok_or(SearchError::InternalInvariant {
                detail: "setup work exceeded total search work",
            })?;
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

#[derive(Clone, Copy)]
struct StartByteProof {
    set: Option<AsciiByteSet>,
    work: u64,
}

fn derive_ascii_start_set(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
) -> Result<StartByteProof, SearchError> {
    workspace.stack_len = 0;
    workspace.generation =
        workspace
            .generation
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-byte proof generation",
            })?;
    workspace.push_stack(Thread {
        state: automaton.start,
        start: 0,
    })?;
    let mut words = [0_u64; 2];
    let mut work = 0_u64;

    while let Some(thread) = workspace.pop_stack() {
        let state = thread.state;
        work = work.saturating_add(1);
        let state_index = crate::plan::plan_index(state);
        if workspace.seen_at[state_index] == workspace.generation {
            continue;
        }
        workspace.seen_at[state_index] = workspace.generation;

        match automaton.roles[state_index] {
            // A nullable root must still examine every boundary.
            StateRole::Accept => {
                workspace.stack_len = 0;
                return Ok(StartByteProof { set: None, work });
            }
            StateRole::Consume => {
                for edge in automaton.state_edges(state) {
                    work = work.saturating_add(1);
                    let start = automaton.byte_starts[edge];
                    let end = automaton.byte_ends[edge];
                    // ASCII classifiers deliberately treat high bytes as
                    // nonmembers. Disable the proof if any high byte can
                    // begin a match.
                    if end >= 0x80 {
                        workspace.stack_len = 0;
                        return Ok(StartByteProof { set: None, work });
                    }
                    insert_ascii_range(&mut words, start, end);
                }
            }
            StateRole::Split => {
                for edge in automaton.state_edges(state).rev() {
                    work = work.saturating_add(1);
                    // Assertions vary by boundary and therefore cannot be
                    // skipped by a source-independent start-byte proof.
                    if automaton.edge_kinds[edge] != EdgeKind::Epsilon {
                        workspace.stack_len = 0;
                        return Ok(StartByteProof { set: None, work });
                    }
                    workspace.push_stack(Thread {
                        state: automaton.edge_targets[edge],
                        start: 0,
                    })?;
                }
            }
        }
    }
    let set = AsciiByteSet::from_words(words);
    Ok(StartByteProof {
        set: (set != AsciiByteSet::ALL).then_some(set),
        work,
    })
}

fn insert_ascii_range(words: &mut [u64; 2], start: u8, end: u8) {
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
    words[end_word] |= u64::MAX >> end_shift;
}

fn next_start_candidate(
    classifier: &AsciiByteSetClassifier,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<usize, SearchError> {
    while end.saturating_sub(position) >= ASCII_WIDE_BYTES {
        meter.charge(
            u64::try_from(ASCII_WIDE_BYTES).expect("classifier width fits u64"),
            position,
        )?;
        let block_end =
            position
                .checked_add(ASCII_WIDE_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "wide start-classifier block end",
                })?;
        let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("checked wide classifier extent");
        let members = classifier.classify_32(block).member_mask();
        if members != 0 {
            let offset =
                usize::try_from(members.trailing_zeros()).expect("wide classifier lane fits usize");
            return position
                .checked_add(offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "wide start-classifier candidate",
                });
        }
        position = block_end;
    }
    if end.saturating_sub(position) >= ASCII_NARROW_BYTES {
        meter.charge(
            u64::try_from(ASCII_NARROW_BYTES).expect("classifier width fits u64"),
            position,
        )?;
        let block_end =
            position
                .checked_add(ASCII_NARROW_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "narrow start-classifier block end",
                })?;
        let block: &[u8; ASCII_NARROW_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("checked narrow classifier extent");
        let members = classifier.classify_16(block).member_mask();
        if members != 0 {
            let offset = usize::try_from(members.trailing_zeros())
                .expect("narrow classifier lane fits usize");
            return position
                .checked_add(offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "narrow start-classifier candidate",
                });
        }
        position = block_end;
    }
    while position < end {
        meter.charge(1, position)?;
        if classifier.set().contains(haystack[position]) {
            return Ok(position);
        }
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "scalar start-classifier position",
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
) -> Result<(WorkMeter, u64), SearchError> {
    let required_layout = WorkspaceLayout::for_automaton(automaton)?;
    if required_layout != workspace.layout {
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
        // One proof generation precedes the ordinary boundary generations.
        .and_then(|length| length.checked_add(2))
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
    let start_proof = derive_ascii_start_set(automaton, workspace)?;
    meter.charge(start_proof.work, window.start())?;
    if start_proof.set != workspace.start_set {
        let classifier_work = u64::try_from(ASCII_CLASSIFIER_BUILD_WORK)
            .expect("ASCII classifier construction work fits u64");
        meter.charge(classifier_work, window.start())?;
        workspace.start_classifier = start_proof.set.map(AsciiByteSetClassifier::new);
        workspace.start_set = start_proof.set;
    }
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
    seen.checked_add(current)
        .and_then(|value| value.checked_add(roots))
        .and_then(|value| value.checked_add(stack))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "total retained scratch bytes",
        })
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{scratch_bytes, WorkMeter};
    use crate::{
        Automaton, CompileLimits, EdgeKind, K0Workspace, RawPlan, SearchError, SearchLimits,
        SearchWindow, Span, StateRole, WorkspaceLimits,
    };

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
    fn generation_rollover_is_preflighted_and_accounted_as_setup() {
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
        let mut workspace =
            super::K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).expect("workspace");
        workspace.generation = u64::MAX;

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
        assert_eq!(workspace.generation, u64::MAX);

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
        let report = automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let accounting = report.accounting();
        let found = report.into_output().unwrap();
        assert_eq!((found.start(), found.end()), (96, 98));
        assert_eq!(
            workspace
                .start_classifier
                .as_ref()
                .expect("ASCII digit root should retain a classifier")
                .set()
                .words(),
            [0x03ff_0000_0000_0000, 0]
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
    fn nullable_asserted_and_high_byte_roots_decline_skipping() {
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
        nullable
            .prepare::<Span>()
            .search_with_workspace(b"", &mut nullable_workspace, SearchLimits::unlimited())
            .unwrap();
        assert!(nullable_workspace.start_classifier.is_none());

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
        assert!(asserted_workspace.start_classifier.is_none());

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
        assert!(high_workspace.start_classifier.is_none());
    }
}
