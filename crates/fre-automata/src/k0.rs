use core::mem::size_of;

use memchr::{memchr, memchr2, memchr3};

use crate::{
    plan::{
        AsciiStartProof, AsciiStartScanner, AsciiStartSet, ASCII_START_BITMAP_POPULATION_WORK,
        ASCII_START_MEMBER_EXTRACTION_WORK, ASCII_START_SET_SCANNER_SELECTION_WORK,
        ASCII_START_SMALL_MAX_MEMBERS,
    },
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
    let start_proof =
        prepare_ascii_start_scanner(automaton, workspace, &mut meter, window.start())?;
    let start_scanner = start_proof.proof().scanner.as_ref();
    let force_haystack_start = start_proof.proof().force_haystack_start;

    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending = None;

    loop {
        if pending.is_none() && workspace.roots_len == 0 {
            if let Some(scanner) = start_scanner {
                // An absolute-start branch may contribute a match only at
                // original haystack boundary zero. Evaluate the full root
                // there once; the scanner is a proof for later boundaries.
                if !(force_haystack_start && position == 0) {
                    position = next_start_candidate(
                        scanner,
                        haystack,
                        position,
                        window.end(),
                        &mut meter,
                    )?;
                    if position == window.end() {
                        break;
                    }
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

#[derive(Clone, Copy, Debug)]
struct StartByteProof {
    set: Option<AsciiStartSet>,
    force_haystack_start: bool,
}

impl StartByteProof {
    const fn disabled() -> Self {
        Self {
            set: None,
            force_haystack_start: false,
        }
    }
}

fn derive_ascii_start_set(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
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
    let mut force_haystack_start = false;

    while let Some(thread) = workspace.pop_stack() {
        meter.charge(1, position)?;
        let state = thread.state;
        let state_index = crate::plan::plan_index(state);
        if workspace.seen_at[state_index] == workspace.generation {
            continue;
        }
        workspace.seen_at[state_index] = workspace.generation;

        match automaton.roles[state_index] {
            // A nullable root must still examine every boundary.
            StateRole::Accept => {
                workspace.stack_len = 0;
                return Ok(StartByteProof::disabled());
            }
            StateRole::Consume => {
                for edge in automaton.state_edges(state) {
                    meter.charge(1, position)?;
                    let start = automaton.byte_starts[edge];
                    let end = automaton.byte_ends[edge];
                    // ASCII scanners deliberately treat high bytes as
                    // nonmembers. Disable the proof if any high byte can
                    // begin a match.
                    if end >= 0x80 {
                        workspace.stack_len = 0;
                        return Ok(StartByteProof::disabled());
                    }
                    insert_ascii_range(&mut words, start, end);
                }
            }
            StateRole::Split => {
                for edge in automaton.state_edges(state).rev() {
                    meter.charge(1, position)?;
                    match automaton.edge_kinds[edge] {
                        EdgeKind::Epsilon => {
                            workspace.push_stack(Thread {
                                state: automaton.edge_targets[edge],
                                start: 0,
                            })?;
                        }
                        // This edge is statically disabled at every candidate
                        // boundary except original haystack start. The full
                        // root is evaluated at zero, so its target need not
                        // constrain the scanner for later boundaries.
                        EdgeKind::AssertHaystackStart => {
                            force_haystack_start = true;
                        }
                        // Every other assertion varies among nonzero
                        // boundaries and therefore refuses this proof.
                        _ => {
                            workspace.stack_len = 0;
                            return Ok(StartByteProof::disabled());
                        }
                    }
                }
            }
        }
    }
    let set = AsciiStartSet::from_words(words);
    Ok(StartByteProof {
        set: (set != AsciiStartSet::ALL).then_some(set),
        force_haystack_start,
    })
}

// Boxing the cold pending proof would add an allocation outside the authenticated
// workspace accounting. The warm published variant remains a borrowed pointer.
#[allow(clippy::large_enum_variant)]
enum InvocationStartProof<'a> {
    Published(&'a AsciiStartProof),
    Pending(AsciiStartProof),
}

impl InvocationStartProof<'_> {
    const fn proof(&self) -> &AsciiStartProof {
        match self {
            Self::Published(proof) => proof,
            Self::Pending(proof) => proof,
        }
    }

    fn publish(self, automaton: &Automaton) {
        if let Self::Pending(proof) = self {
            // A concurrent successful invocation may already have published
            // the same proof for this immutable automaton.
            let _ = automaton.ascii_start_proof.set(proof);
        }
    }
}

fn prepare_ascii_start_scanner<'a>(
    automaton: &'a Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<InvocationStartProof<'a>, SearchError> {
    if let Some(proof) = automaton.ascii_start_proof.get() {
        return Ok(InvocationStartProof::Published(proof));
    }

    let start_proof = derive_ascii_start_set(automaton, workspace, meter, position)?;
    let scanner = if let Some(set) = start_proof.set {
        Some(ascii_start_scanner(set, meter, position)?)
    } else {
        None
    };

    let proof = AsciiStartProof {
        // The forced boundary matters only when skipping is enabled.
        force_haystack_start: scanner.is_some() && start_proof.force_haystack_start,
        scanner,
    };
    // Publish only after the entire search succeeds. A racing successful
    // caller may win first; both values come from the same immutable graph.
    Ok(InvocationStartProof::Pending(proof))
}

fn ascii_start_scanner(
    set: AsciiStartSet,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<AsciiStartScanner, SearchError> {
    let [low, high] = set.words();
    meter.charge(
        u64::try_from(ASCII_START_BITMAP_POPULATION_WORK)
            .expect("ASCII bitmap population work fits u64"),
        position,
    )?;
    let cardinality = low.count_ones().saturating_add(high.count_ones());
    if cardinality == 0 {
        return Ok(AsciiStartScanner::Empty);
    }
    if usize::try_from(cardinality).expect("ASCII cardinality fits usize")
        <= ASCII_START_SMALL_MAX_MEMBERS
    {
        let extraction_work = usize::try_from(cardinality)
            .ok()
            .and_then(|members| members.checked_mul(ASCII_START_MEMBER_EXTRACTION_WORK))
            .and_then(|work| u64::try_from(work).ok())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "small ASCII start-scanner extraction work",
            })?;
        meter.charge(extraction_work, position)?;
        let mut bytes = [0_u8; ASCII_START_SMALL_MAX_MEMBERS];
        let mut length = 0usize;
        for (word_index, mut word) in [low, high].into_iter().enumerate() {
            while word != 0 {
                let bit = word.trailing_zeros();
                let byte = word_index
                    .checked_mul(64)
                    .and_then(|offset| u8::try_from(offset).ok())
                    .expect("ASCII word offset fits u8")
                    .checked_add(u8::try_from(bit).expect("ASCII word bit fits u8"))
                    .expect("ASCII byte fits u8");
                *bytes
                    .get_mut(length)
                    .expect("small ASCII scanner retains at most three bytes") = byte;
                length = length
                    .checked_add(1)
                    .expect("small ASCII scanner cardinality fits usize");
                word &= word
                    .checked_sub(1)
                    .expect("the small ASCII scanner word is nonzero");
            }
        }
        return Ok(match bytes[..length] {
            [byte] => AsciiStartScanner::One(byte),
            [first, second] => AsciiStartScanner::Two(first, second),
            [first, second, third] => AsciiStartScanner::Three(first, second, third),
            _ => unreachable!("one-to-three-byte ASCII set has matching scanner cardinality"),
        });
    }

    meter.charge(
        u64::try_from(ASCII_START_SET_SCANNER_SELECTION_WORK)
            .expect("ASCII bitmap scanner selection work fits u64"),
        position,
    )?;
    Ok(AsciiStartScanner::Set(set))
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
    scanner: &AsciiStartScanner,
    haystack: &[u8],
    position: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<usize, SearchError> {
    match scanner {
        AsciiStartScanner::Empty => Ok(end),
        AsciiStartScanner::One(byte) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr(*byte, source)
            })
        }
        AsciiStartScanner::Two(first, second) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr2(*first, *second, source)
            })
        }
        AsciiStartScanner::Three(first, second, third) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr3(*first, *second, *third, source)
            })
        }
        AsciiStartScanner::Set(set) => {
            next_set_start_candidate(*set, haystack, position, end, meter)
        }
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
    set: AsciiStartSet,
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
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::{scratch_bytes, WorkMeter, INVOCATION_RESET_WORK};
    use crate::{
        plan::{
            AsciiStartProof, AsciiStartScanner, AsciiStartSet, ASCII_START_BITMAP_POPULATION_WORK,
            ASCII_START_MEMBER_EXTRACTION_WORK, ASCII_START_SET_SCANNER_SELECTION_WORK,
            ASCII_START_SMALL_MAX_MEMBERS,
        },
        Automaton, CompileLimits, EarliestEnd, EdgeKind, K0Workspace, RawPlan, SearchError,
        SearchLimits, SearchWindow, Span, StateRole, WorkspaceLimits,
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

    fn pin_without_ascii_start_proof(automaton: &Automaton) {
        automaton
            .ascii_start_proof
            .set(AsciiStartProof {
                scanner: None,
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
        pin_without_ascii_start_proof(reference);
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

    fn ascii_set(bytes: &[u8]) -> AsciiStartSet {
        let mut words = [0_u64; 2];
        for &byte in bytes {
            assert!(byte < 0x80, "test start sets must be ASCII");
            super::insert_ascii_range(&mut words, byte, byte);
        }
        AsciiStartSet::from_words(words)
    }

    fn scanner_for(bytes: &[u8]) -> AsciiStartScanner {
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let scanner = super::ascii_start_scanner(ascii_set(bytes), &mut meter, 0).unwrap();
        let expected_build_work = expected_scanner_selection_work(bytes.len());
        assert_eq!(meter.consumed, expected_build_work);
        scanner
    }

    fn expected_scanner_selection_work(members: usize) -> u64 {
        let selection = if members <= ASCII_START_SMALL_MAX_MEMBERS {
            members
                .checked_mul(ASCII_START_MEMBER_EXTRACTION_WORK)
                .unwrap()
        } else {
            ASCII_START_SET_SCANNER_SELECTION_WORK
        };
        u64::try_from(
            ASCII_START_BITMAP_POPULATION_WORK
                .checked_add(selection)
                .unwrap(),
        )
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
            super::derive_ascii_start_set(&automaton, &mut workspace, &mut meter, 23).unwrap_err();
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
                u64::try_from(ASCII_START_BITMAP_POPULATION_WORK.checked_sub(1).unwrap()).unwrap(),
                0,
            );
            let error = super::ascii_start_scanner(ascii_set(bytes), &mut population_refusal, 17)
                .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    consumed: 0,
                    requested,
                    position: 17,
                    ..
                } if requested
                    == u64::try_from(ASCII_START_BITMAP_POPULATION_WORK).unwrap()
            ));

            let mut exact = WorkMeter::new(expected, 0);
            super::ascii_start_scanner(ascii_set(bytes), &mut exact, 17).unwrap();
            assert_eq!(exact.consumed, expected);

            let mut one_below = WorkMeter::new(expected.checked_sub(1).unwrap(), 0);
            let error =
                super::ascii_start_scanner(ascii_set(bytes), &mut one_below, 17).unwrap_err();
            let expected_tail = if bytes.is_empty() {
                u64::try_from(ASCII_START_BITMAP_POPULATION_WORK).unwrap()
            } else if bytes.len() <= ASCII_START_SMALL_MAX_MEMBERS {
                u64::try_from(
                    bytes
                        .len()
                        .checked_mul(ASCII_START_MEMBER_EXTRACTION_WORK)
                        .unwrap(),
                )
                .unwrap()
            } else {
                u64::try_from(ASCII_START_SET_SCANNER_SELECTION_WORK).unwrap()
            };
            let expected_consumed = if bytes.is_empty() {
                0
            } else {
                u64::try_from(ASCII_START_BITMAP_POPULATION_WORK).unwrap()
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
    fn ascii_start_scanners_match_scalar_reference_for_every_window() {
        let scanner_sets: &[&[u8]] = &[&[], b"a", b"ac", b"ac\x7f", b"abcd", b"\x3f\x40AB"];
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
            let scanner = scanner_for(bytes);
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let expected = (start..end)
                            .find(|&position| bytes.contains(&haystack[position]))
                            .unwrap_or(end);
                        let mut meter = WorkMeter::new(u64::MAX, 0);
                        let actual =
                            super::next_start_candidate(&scanner, haystack, start, end, &mut meter)
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
    fn full_ascii_root_declines_start_scanning() {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 1],
                edge_targets: vec![1],
                edge_kinds: vec![EdgeKind::ByteRange],
                byte_starts: vec![0],
                byte_ends: vec![0x7f],
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
            .ascii_start_proof
            .get()
            .expect("successful search publishes the declined proof");
        assert!(proof.scanner.is_none());
        assert!(!proof.force_haystack_start);
    }

    #[test]
    fn start_scanners_honor_exact_admitted_work() {
        let scanners = [
            scanner_for(b"a"),
            scanner_for(b"ab"),
            scanner_for(b"abc"),
            scanner_for(b"abcd"),
        ];
        for scanner in &scanners {
            let mut exact = WorkMeter::new(10, 7);
            assert_eq!(
                super::next_start_candidate(scanner, b"_xxa_", 1, 4, &mut exact).unwrap(),
                3
            );
            assert_eq!(exact.consumed, 10);

            let mut before_candidate = WorkMeter::new(9, 7);
            let error = super::next_start_candidate(scanner, b"_xxa_", 1, 4, &mut before_candidate)
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
                super::next_start_candidate(scanner, b"_xxx_", 1, 4, &mut full_miss).unwrap(),
                4
            );
            assert_eq!(full_miss.consumed, 10);

            let mut partial_miss = WorkMeter::new(9, 7);
            let error = super::next_start_candidate(scanner, b"_xxx_", 1, 4, &mut partial_miss)
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
            let error =
                super::next_start_candidate(scanner, b"_xxx_", 1, 4, &mut exhausted).unwrap_err();
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
                &AsciiStartScanner::Empty,
                b"_xxx_",
                1,
                4,
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
            .ascii_start_proof
            .get()
            .expect("successful absolute search publishes its proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(proof.scanner, Some(AsciiStartScanner::Empty)));
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
            let proof_work = 1_u64
                .checked_add(u64::try_from(bytes.len()).unwrap())
                .and_then(|work| work.checked_add(expected_scanner_selection_work(bytes.len())))
                .unwrap();
            assert_eq!(
                cold.accounting()
                    .transition_work()
                    .checked_sub(warm.accounting().transition_work()),
                Some(proof_work)
            );

            let proof = automaton
                .ascii_start_proof
                .get()
                .expect("successful search publishes the start scanner");
            let scanner = proof
                .scanner
                .as_ref()
                .expect("an ASCII root enables start scanning");
            assert!(matches!(
                (bytes, scanner),
                (b"", AsciiStartScanner::Empty)
                    | (b"a", AsciiStartScanner::One(b'a'))
                    | (b"ab", AsciiStartScanner::Two(b'a', b'b'))
                    | (b"abc", AsciiStartScanner::Three(b'a', b'b', b'c'))
                    | (b"abcd", AsciiStartScanner::Set(_))
            ));

            let mut meter = WorkMeter::new(u64::MAX, 0);
            let invocation =
                super::prepare_ascii_start_scanner(&automaton, &mut workspace, &mut meter, 0)
                    .unwrap();
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
    fn ascii_start_specialization_is_once_per_automaton_and_clone() {
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
        let specialization_work = 2_u64
            .checked_add(expected_scanner_selection_work(1))
            .unwrap();
        assert_eq!(
            cold.accounting()
                .transition_work()
                .checked_sub(warm.accounting().transition_work()),
            Some(specialization_work)
        );
        let published = automaton
            .ascii_start_proof
            .get()
            .expect("successful cold search publishes the proof");
        let mut cache_meter = WorkMeter::new(u64::MAX, 0);
        let cached =
            super::prepare_ascii_start_scanner(&automaton, &mut workspace, &mut cache_meter, 0)
                .unwrap();
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
            cloned.ascii_start_proof.get().is_none(),
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
        // The root proof costs one state plus one operation per edge. Admit
        // those plus invocation reset, then refuse before either bitmap
        // population operation.
        let proof_work = 1_u64
            .checked_add(u64::try_from(root.len()).unwrap())
            .unwrap();
        let admitted = INVOCATION_RESET_WORK.checked_add(proof_work).unwrap();
        let population_work = u64::try_from(ASCII_START_BITMAP_POPULATION_WORK).unwrap();
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
        assert!(automaton.ascii_start_proof.get().is_none());

        // Once both bitmap words are admitted and counted, retaining the
        // scalar set scanner is the next indivisible construction charge.
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
                && requested == u64::try_from(ASCII_START_SET_SCANNER_SELECTION_WORK).unwrap()
        ));
        assert!(automaton.ascii_start_proof.get().is_none());

        // A small scanner charges its member extraction after the same two
        // population operations and likewise cannot publish on refusal.
        let small = ascii_literal(b'a');
        let mut small_workspace = K0Workspace::new(&small, WorkspaceLimits::unlimited()).unwrap();
        let small_proof_work = 2_u64;
        let small_extraction_limit = INVOCATION_RESET_WORK
            .checked_add(small_proof_work)
            .and_then(|work| work.checked_add(population_work))
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
                    == u64::try_from(ASCII_START_MEMBER_EXTRACTION_WORK).unwrap()
        ));
        assert!(small.ascii_start_proof.get().is_none());
    }

    #[test]
    fn failed_first_use_does_not_publish_unpaid_specialization() {
        let root = [b'a', b'b', b'c', b'd'];
        let automaton = ascii_root_bytes(&root);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let proof_work = 1_u64
            .checked_add(u64::try_from(root.len()).unwrap())
            .unwrap();
        let specialization_admitted = INVOCATION_RESET_WORK
            .checked_add(proof_work)
            .and_then(|work| work.checked_add(expected_scanner_selection_work(root.len())))
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
            automaton.ascii_start_proof.get().is_none(),
            "a search that pays specialization but later fails must not publish it"
        );

        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(b"za", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert!(automaton.ascii_start_proof.get().is_some());
        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(b"za", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let specialization_work = proof_work
            .checked_add(expected_scanner_selection_work(root.len()))
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
        assert!(cloned.ascii_start_proof.get().is_none());
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
        assert!(automaton.ascii_start_proof.get().is_some());
    }

    #[test]
    fn every_non_absolute_start_assertion_disables_the_start_scanner_proof() {
        let absolute = assertion_or_colon(EdgeKind::AssertHaystackStart);
        let mut absolute_workspace =
            K0Workspace::new(&absolute, WorkspaceLimits::unlimited()).unwrap();
        let mut absolute_meter = WorkMeter::new(u64::MAX, 0);
        let proof = super::derive_ascii_start_set(
            &absolute,
            &mut absolute_workspace,
            &mut absolute_meter,
            0,
        )
        .unwrap();
        assert!(proof.force_haystack_start);
        assert_eq!(
            proof.set.expect("colon sibling remains skippable").words(),
            [1_u64 << u32::from(b':'), 0]
        );

        let refused = [
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
        for assertion in refused {
            let automaton = assertion_or_colon(assertion);
            let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let proof =
                super::derive_ascii_start_set(&automaton, &mut workspace, &mut meter, 0).unwrap();
            assert!(
                proof.set.is_none(),
                "{} unexpectedly retained a scanner set",
                assertion.name()
            );
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
            .ascii_start_proof
            .get()
            .expect("exhaustive successful search publishes the proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(proof.scanner, Some(AsciiStartScanner::One(b':'))));

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
            .ascii_start_proof
            .get()
            .expect("successful search publishes the proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(proof.scanner, Some(AsciiStartScanner::One(b':'))));

        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let specialization_work = 5_u64
            .checked_add(expected_scanner_selection_work(1))
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
            unpublished.ascii_start_proof.get().is_none(),
            "a failed cold search must not publish the absolute-start proof"
        );
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
                .ascii_start_proof
                .get()
                .expect("start proof should be initialized")
                .scanner
                .as_ref()
                .and_then(|scanner| match scanner {
                    AsciiStartScanner::Set(set) => Some(set.words()),
                    _ => None,
                })
                .expect("ASCII digit root should retain a bitmap scanner"),
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
            .ascii_start_proof
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
        assert!(asserted
            .ascii_start_proof
            .get()
            .expect("asserted proof should be initialized")
            .scanner
            .is_none());

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
        assert!(high
            .ascii_start_proof
            .get()
            .expect("high-byte proof should be initialized")
            .scanner
            .is_none());
    }
}
