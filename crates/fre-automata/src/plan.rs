use core::{marker::PhantomData, mem::size_of};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

use crate::{CompileError, MalformedPlan, Operation, ResourceKind, TypedPlan, WorkspaceLayout};

static NEXT_AUTOMATON_IDENTITY: AtomicU64 = AtomicU64::new(1);

fn next_automaton_identity() -> u64 {
    NEXT_AUTOMATON_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .unwrap_or_else(|_| panic!("automaton identity space exhausted"))
}

/// Number of exact consumed-byte positions retained by the bounded start
/// filter. Any of offsets zero through seven may supply the primary scanner;
/// at most one other position may supply a candidate guard.
pub(crate) const START_FILTER_POSITION_COUNT: usize = 8;
/// Largest consumed-byte offset inspected by the bounded start filter.
pub(crate) const START_FILTER_MAX_OFFSET: usize = START_FILTER_POSITION_COUNT - 1;
/// Maximum candidate guards retained by one immutable start-filter proof.
pub(crate) const START_FILTER_MAX_GUARDS: usize = 1;
/// Exact abstract work to count the members in all four byte-bitmap words.
pub(crate) const BYTE_START_BITMAP_POPULATION_WORK: usize = 4;
/// Exact abstract work to extract one small-scanner member from the bitmap.
pub(crate) const BYTE_START_MEMBER_EXTRACTION_WORK: usize = 1;
/// Largest cardinality represented by direct `memchr` scanners.
pub(crate) const BYTE_START_SMALL_MAX_MEMBERS: usize = 3;
/// Exact abstract work to retain a broad bitmap scanner.
pub(crate) const BYTE_START_SET_SCANNER_SELECTION_WORK: usize = 1;
/// Exact abstract work to compare one position with the incumbent scanner.
pub(crate) const START_FILTER_SCANNER_SELECTION_WORK: usize = 1;
/// Exact abstract work to compare one non-scanner position with the incumbent
/// guard.
pub(crate) const START_FILTER_GUARD_SELECTION_WORK: usize = 1;
/// Largest non-scanner byte class selective enough to retain as a guard.
/// Sixty-four members are one quarter of the complete 256-byte domain.
pub(crate) const START_FILTER_GUARD_MAX_CARDINALITY: u32 = 64;
/// Conservative selection bound: count and compare every exact-position set,
/// compare every non-scanner set for the optional guard, then construct the
/// largest direct scanner.
pub(crate) const START_FILTER_MAX_SELECTION_WORK: usize = START_FILTER_POSITION_COUNT
    * (BYTE_START_BITMAP_POPULATION_WORK + START_FILTER_SCANNER_SELECTION_WORK)
    + START_FILTER_MAX_OFFSET * START_FILTER_GUARD_SELECTION_WORK
    + BYTE_START_SMALL_MAX_MEMBERS * BYTE_START_MEMBER_EXTRACTION_WORK;

/// The structural role of a Thompson state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateRole {
    /// Ordered zero-width branching. All outgoing edges must be zero-width.
    Split,
    /// Ordered consuming branching. All outgoing edges must consume one byte.
    Consume,
    /// A successful match. Accept states have no outgoing edges.
    Accept,
}

impl StateRole {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Split => "split",
            Self::Consume => "consume",
            Self::Accept => "accept",
        }
    }
}

/// The kind of one graph edge. Payload byte bounds live in separate arrays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EdgeKind {
    /// Unconditional zero-width transition.
    Epsilon,
    /// Consume one byte in the inclusive range stored alongside this edge.
    ByteRange,
    /// Zero-width assertion at the beginning of the original haystack.
    AssertHaystackStart,
    /// Zero-width assertion at the end of the original haystack.
    AssertHaystackEnd,
    /// Zero-width assertion at original-haystack start or after the configured
    /// line-terminator byte. The variant name mirrors regex-syntax's
    /// historical `StartLF` name; LF is the default, not a hard-coded value.
    AssertLineStartLf,
    /// Zero-width assertion at original-haystack end or before the configured
    /// line-terminator byte. The variant name mirrors regex-syntax's
    /// historical `EndLF` name; LF is the default, not a hard-coded value.
    AssertLineEndLf,
    /// Zero-width CRLF-aware line start without splitting a CRLF pair.
    AssertLineStartCrlf,
    /// Zero-width CRLF-aware line end without splitting a CRLF pair.
    AssertLineEndCrlf,
    /// Zero-width ASCII word boundary; only `[A-Za-z0-9_]` are word bytes.
    AssertWordAscii,
    /// Zero-width negated ASCII word boundary assertion.
    AssertWordAsciiNegate,
    /// Zero-width start-of-ASCII-word assertion.
    AssertWordStartAscii,
    /// Zero-width end-of-ASCII-word assertion.
    AssertWordEndAscii,
    /// Zero-width left half of an ASCII word-start assertion.
    AssertWordStartHalfAscii,
    /// Zero-width right half of an ASCII word-end assertion.
    AssertWordEndHalfAscii,
    /// Zero-width positive Unicode word boundary using the UTS#18 `\w` set.
    AssertWordUnicode,
    /// Zero-width negated Unicode word boundary.
    AssertWordUnicodeNegate,
    /// Zero-width start-of-Unicode-word assertion.
    AssertWordStartUnicode,
    /// Zero-width end-of-Unicode-word assertion.
    AssertWordEndUnicode,
    /// Zero-width left half of a Unicode word-start assertion.
    AssertWordStartHalfUnicode,
    /// Zero-width right half of a Unicode word-end assertion.
    AssertWordEndHalfUnicode,
}

impl EdgeKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Epsilon => "epsilon",
            Self::ByteRange => "byte-range",
            Self::AssertHaystackStart => "start-assertion",
            Self::AssertHaystackEnd => "end-assertion",
            Self::AssertLineStartLf => "configured-line-start-assertion",
            Self::AssertLineEndLf => "configured-line-end-assertion",
            Self::AssertLineStartCrlf => "CRLF-line-start-assertion",
            Self::AssertLineEndCrlf => "CRLF-line-end-assertion",
            Self::AssertWordAscii => "ASCII-word-boundary-assertion",
            Self::AssertWordAsciiNegate => "ASCII-not-word-boundary-assertion",
            Self::AssertWordStartAscii => "ASCII-word-start-assertion",
            Self::AssertWordEndAscii => "ASCII-word-end-assertion",
            Self::AssertWordStartHalfAscii => "ASCII-word-start-half-assertion",
            Self::AssertWordEndHalfAscii => "ASCII-word-end-half-assertion",
            Self::AssertWordUnicode => "Unicode-word-boundary-assertion",
            Self::AssertWordUnicodeNegate => "Unicode-not-word-boundary-assertion",
            Self::AssertWordStartUnicode => "Unicode-word-start-assertion",
            Self::AssertWordEndUnicode => "Unicode-word-end-assertion",
            Self::AssertWordStartHalfUnicode => "Unicode-word-start-half-assertion",
            Self::AssertWordEndHalfUnicode => "Unicode-word-end-half-assertion",
        }
    }

    pub(crate) const fn is_zero_width(self) -> bool {
        !matches!(self, Self::ByteRange)
    }
}

/// Mutable interchange form accepted from a future lowering layer.
///
/// `edge_offsets` is a CSR offset table and must contain `roles.len() + 1`
/// entries. Edge `i` has target `edge_targets[i]`, kind `edge_kinds[i]`, and
/// inclusive byte bounds `byte_starts[i]..=byte_ends[i]`. Bounds for
/// zero-width edges must both be zero, avoiding ignored non-canonical payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPlan {
    pub start: u32,
    pub roles: Vec<StateRole>,
    pub edge_offsets: Vec<u32>,
    pub edge_targets: Vec<u32>,
    pub edge_kinds: Vec<EdgeKind>,
    pub byte_starts: Vec<u8>,
    pub byte_ends: Vec<u8>,
}

/// Hard construction limits for this standalone automata layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimits {
    pub max_states: usize,
    pub max_edges: usize,
    pub max_storage_bytes: usize,
    pub max_validation_work: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            max_states: 262_144,
            max_edges: 1_048_576,
            max_storage_bytes: 128 * 1024 * 1024,
            max_validation_work: 4_000_000,
        }
    }
}

/// Immutable dimensions and construction charges for a validated plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanStats {
    states: usize,
    edges: usize,
    zero_width_edges: usize,
    assertion_edges: usize,
    consuming_edges: usize,
    storage_bytes: usize,
    validation_work: usize,
}

impl PlanStats {
    #[must_use]
    pub const fn states(self) -> usize {
        self.states
    }

    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }

    #[must_use]
    pub const fn zero_width_edges(self) -> usize {
        self.zero_width_edges
    }

    pub(crate) const fn assertion_edges(self) -> usize {
        self.assertion_edges
    }

    #[must_use]
    pub const fn consuming_edges(self) -> usize {
        self.consuming_edges
    }

    /// Payload bytes in the immutable structure-of-arrays tables.
    #[must_use]
    pub const fn storage_bytes(self) -> usize {
        self.storage_bytes
    }

    #[must_use]
    pub const fn validation_work(self) -> usize {
        self.validation_work
    }
}

/// A half-open search range. Assertions retain original-haystack context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchWindow {
    start: usize,
    end: usize,
}

impl SearchWindow {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn full(haystack: &[u8]) -> Self {
        Self {
            start: 0,
            end: haystack.len(),
        }
    }

    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// Per-invocation hard limits. Both are checked; neither is a deadline.
///
/// `max_work` covers setup plus transitions. A one-shot call therefore charges
/// cold workspace construction, while a reusable call charges only logical
/// reset (and, extremely rarely, generation-table clearing) before transitions.
/// The first successful search on an immutable [`Automaton`] also charges its
/// bounded full-byte start-filter proof and scanner/guard selection. The
/// automaton retains that result, so later calls do not repeat or charge that
/// work; conservative work bounds cover the first-use case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_work: u64,
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work: 100_000_000,
            max_scratch_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Fixed full-byte bitmap retained by the portable start filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteSet([u64; 4]);

impl ByteSet {
    pub(crate) const EMPTY: Self = Self([0; 4]);
    pub(crate) const ALL: Self = Self([u64::MAX; 4]);

    pub(crate) const fn from_words(words: [u64; 4]) -> Self {
        Self(words)
    }

    pub(crate) const fn words(self) -> [u64; 4] {
        self.0
    }

    pub(crate) fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte / 64);
        let bit = u32::from(byte % 64);
        self.0[word] & (1_u64 << bit) != 0
    }

    pub(crate) fn cardinality(self) -> u32 {
        self.0
            .into_iter()
            .map(u64::count_ones)
            .fold(0_u32, u32::saturating_add)
    }
}

/// Immutable scanner selected from one proved exact-position byte set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartScanner {
    Empty,
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Set(ByteSet),
}

/// One sound byte class at an exact consumed-byte offset after match start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartPositionClass {
    pub(crate) offset: u8,
    pub(crate) set: ByteSet,
}

/// Scanner and exact consumed-byte offset used to recover candidate starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartPositionScanner {
    pub(crate) offset: u8,
    pub(crate) scanner: StartScanner,
}

/// Immutable bounded start-filter proof published after a successful search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartFilterProof {
    pub(crate) scanner: Option<StartPositionScanner>,
    pub(crate) guard: Option<StartPositionClass>,
    pub(crate) force_haystack_start: bool,
}

/// Immutable structure-of-arrays prioritized Thompson graph.
#[derive(Debug)]
pub struct Automaton {
    identity: u64,
    pub(crate) start: u32,
    pub(crate) roles: Box<[StateRole]>,
    pub(crate) edge_offsets: Box<[u32]>,
    pub(crate) edge_targets: Box<[u32]>,
    pub(crate) edge_kinds: Box<[EdgeKind]>,
    pub(crate) byte_starts: Box<[u8]>,
    pub(crate) byte_ends: Box<[u8]>,
    pub(crate) start_filter_proof: OnceLock<StartFilterProof>,
    line_terminator: u8,
    stats: PlanStats,
}

impl Clone for Automaton {
    fn clone(&self) -> Self {
        Self {
            identity: next_automaton_identity(),
            start: self.start,
            roles: self.roles.clone(),
            edge_offsets: self.edge_offsets.clone(),
            edge_targets: self.edge_targets.clone(),
            edge_kinds: self.edge_kinds.clone(),
            byte_starts: self.byte_starts.clone(),
            byte_ends: self.byte_ends.clone(),
            // A clone is a new immutable plan construction. Do not silently
            // copy first-use specialization that this instance has not paid
            // to derive.
            start_filter_proof: OnceLock::new(),
            line_terminator: self.line_terminator,
            stats: self.stats,
        }
    }
}

impl Automaton {
    /// Validate all dimensions, resource limits, roles, edge payloads, and
    /// targets before freezing the supplied vectors.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError::Malformed`] for any inconsistent graph table,
    /// [`CompileError::ResourceLimit`] when a declared hard limit is too low,
    /// or [`CompileError::ArithmeticOverflow`] when a charge cannot be
    /// represented. No partially validated automaton is returned.
    pub fn from_raw(raw: RawPlan, limits: CompileLimits) -> Result<Self, CompileError> {
        let stats = validate_raw(&raw, limits)?;
        Ok(Self {
            identity: next_automaton_identity(),
            start: raw.start,
            roles: raw.roles.into_boxed_slice(),
            edge_offsets: raw.edge_offsets.into_boxed_slice(),
            edge_targets: raw.edge_targets.into_boxed_slice(),
            edge_kinds: raw.edge_kinds.into_boxed_slice(),
            byte_starts: raw.byte_starts.into_boxed_slice(),
            byte_ends: raw.byte_ends.into_boxed_slice(),
            start_filter_proof: OnceLock::new(),
            line_terminator: b'\n',
            stats,
        })
    }

    /// Bind the byte observed by line-start and line-end assertion edges.
    ///
    /// The byte is immutable after publication and adds no heap storage. Raw
    /// standalone automata default to LF; profile-aware facades call this
    /// before exposing the validated plan. A retained start-filter proof cannot
    /// depend on this byte: context assertions are relaxed while proving byte
    /// classes, while an absolute haystack-start edge is handled separately.
    #[must_use]
    pub const fn with_line_terminator(mut self, line_terminator: u8) -> Self {
        self.line_terminator = line_terminator;
        self
    }

    /// Byte observed by line-start and line-end assertion edges.
    #[must_use]
    pub const fn line_terminator(&self) -> u8 {
        self.line_terminator
    }

    #[must_use]
    pub const fn stats(&self) -> PlanStats {
        self.stats
    }

    pub(crate) const fn identity(&self) -> u64 {
        self.identity
    }

    /// Compute the fixed K0 workspace shape without allocating it.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if its byte or work charge
    /// cannot be represented.
    pub fn workspace_layout(&self) -> Result<WorkspaceLayout, SearchError> {
        WorkspaceLayout::for_automaton(self)
    }

    /// Compute the fixed reusable-workspace shape including the bounded
    /// ordered lazy-DFA accelerator when this graph is structurally eligible.
    ///
    /// Ineligible graphs return the same layout as [`Self::workspace_layout`].
    /// Span searches do not use the accelerator; callers preparing a
    /// span-only workspace should retain the ordinary layout.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if its byte or work charge
    /// cannot be represented.
    pub fn accelerated_workspace_layout(&self) -> Result<WorkspaceLayout, SearchError> {
        WorkspaceLayout::for_accelerated_automaton(self)
    }

    /// Bind this graph to an output contract without adding a runtime mode flag
    /// to the K0 loop.
    #[must_use]
    pub const fn prepare<O: Operation>(&self) -> TypedPlan<'_, O> {
        TypedPlan {
            automaton: self,
            operation: PhantomData,
        }
    }

    /// A conservative certificate for transition work over `input_bytes`.
    ///
    /// The bound covers one initial boundary, one boundary per byte, all
    /// possible consuming-edge inspections, all zero-width closure attempts,
    /// duplicate roots, and per-boundary/per-byte bookkeeping. It excludes
    /// workspace construction and invocation setup. Early match commitment
    /// normally uses much less.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if the conservative bound
    /// cannot fit in a `u64`.
    pub fn conservative_transition_work_bound(
        &self,
        input_bytes: usize,
    ) -> Result<u64, SearchError> {
        let input = u64::try_from(input_bytes).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "input length conversion",
        })?;
        let edges =
            u64::try_from(self.stats.edges).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "edge count conversion",
            })?;
        let boundaries = input
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "work-bound boundary count",
            })?;
        let closure = edges
            .checked_mul(2)
            .and_then(|value| value.checked_add(2))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "work-bound closure charge",
            })?;
        let consume = edges
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "work-bound consume charge",
            })?;
        let automaton = boundaries
            .checked_mul(closure)
            .and_then(|value| {
                input
                    .checked_mul(consume)
                    .and_then(|tail| value.checked_add(tail))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative transition work bound",
            })?;
        // The first successful invocation on an immutable automaton derives
        // up to eight exact-position byte classes and selects a scanner plus
        // one guard. Each depth may inspect a state twice and a consuming edge
        // twice while building the next frontier, in addition to the ordinary
        // edge inspection. Later invocations read the automaton-owned result.
        let start_proof_per_position = u64::try_from(self.stats.states)
            .ok()
            .and_then(|states| states.checked_mul(2))
            .and_then(|states| {
                u64::try_from(self.stats.edges)
                    .ok()
                    .and_then(|edges| edges.checked_mul(3))
                    .and_then(|edges| states.checked_add(edges))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter per-position proof work bound",
            })?;
        let start_proof = start_proof_per_position
            .checked_mul(u64::try_from(START_FILTER_POSITION_COUNT).map_err(|_| {
                SearchError::ArithmeticOverflow {
                    computation: "start-filter position count conversion",
                }
            })?)
            .and_then(|work| {
                u64::try_from(START_FILTER_MAX_SELECTION_WORK)
                    .ok()
                    .and_then(|selection| work.checked_add(selection))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter proof work bound",
            })?;
        // A retained guard can pass at every candidate and therefore add work
        // on top of the full all-boundaries automaton bound.
        let guard = input
            .checked_mul(u64::try_from(START_FILTER_MAX_GUARDS).map_err(|_| {
                SearchError::ArithmeticOverflow {
                    computation: "start-filter guard count conversion",
                }
            })?)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter guard work bound",
            })?;
        automaton
            .checked_add(start_proof)
            .and_then(|work| work.checked_add(guard))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "transition work with start-filter proof",
            })
    }

    /// A conservative total-work certificate for a one-shot K0 call.
    ///
    /// This adds exact cold workspace construction and invocation reset to
    /// [`Self::conservative_transition_work_bound`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if the conservative bound
    /// cannot fit in a `u64`.
    pub fn conservative_work_bound(&self, input_bytes: usize) -> Result<u64, SearchError> {
        let transition = self.conservative_transition_work_bound(input_bytes)?;
        let setup = WorkspaceLayout::for_automaton(self)?
            .construction_work()
            .checked_add(3)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative one-shot setup work bound",
            })?;
        transition
            .checked_add(setup)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative total search work bound",
            })
    }

    /// A conservative total-work certificate for a reusable-workspace call.
    ///
    /// The setup term includes invocation reset and the rare worst case where
    /// the entire generation table must be cleared before `u64` rollover.
    /// Normal warm calls charge only three setup operations.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if the conservative bound
    /// cannot fit in a `u64`.
    pub fn conservative_reused_work_bound(&self, input_bytes: usize) -> Result<u64, SearchError> {
        let transition = self.conservative_transition_work_bound(input_bytes)?;
        let states =
            u64::try_from(self.stats.states).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "generation reset state count conversion",
            })?;
        let setup = states
            .checked_add(3)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative reused setup work bound",
            })?;
        transition
            .checked_add(setup)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative reused total work bound",
            })
    }

    pub(crate) fn state_edges(&self, state: u32) -> core::ops::Range<usize> {
        let state = plan_index(state);
        let next = state.saturating_add(1);
        plan_index(self.edge_offsets[state])..plan_index(self.edge_offsets[next])
    }
}

/// Convert a plan index after construction has proved it fits the host's
/// address space. All supported Rust targets have at least 32-bit `usize`, but
/// keeping the conversion explicit also makes the validation boundary clear.
pub(crate) fn plan_index(value: u32) -> usize {
    usize::try_from(value).expect("validated u32 plan index fits usize")
}

#[derive(Clone, Copy)]
struct Shape {
    states: usize,
    edges: usize,
    storage_bytes: usize,
    validation_work: usize,
}

fn validate_raw(raw: &RawPlan, limits: CompileLimits) -> Result<PlanStats, CompileError> {
    let shape = validate_shape(raw, limits)?;
    validate_offsets(&raw.edge_offsets, shape.edges)?;
    let (zero_width_edges, assertion_edges, consuming_edges) = validate_graph(raw, shape.states)?;
    Ok(PlanStats {
        states: shape.states,
        edges: shape.edges,
        zero_width_edges,
        assertion_edges,
        consuming_edges,
        storage_bytes: shape.storage_bytes,
        validation_work: shape.validation_work,
    })
}

fn validate_shape(raw: &RawPlan, limits: CompileLimits) -> Result<Shape, CompileError> {
    let states = raw.roles.len();
    let edges = raw.edge_targets.len();
    if states == 0 {
        return Err(MalformedPlan::EmptyStateTable.into());
    }
    check_index_space(ResourceKind::States, states)?;
    check_index_space(ResourceKind::Edges, edges)?;
    check_limit(ResourceKind::States, states, limits.max_states)?;
    check_limit(ResourceKind::Edges, edges, limits.max_edges)?;
    if usize::try_from(raw.start).map_or(true, |start| start >= states) {
        return Err(MalformedPlan::StartOutOfBounds {
            start: raw.start,
            states,
        }
        .into());
    }

    let expected_offsets = states
        .checked_add(1)
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "state offset count",
        })?;
    if raw.edge_offsets.len() != expected_offsets {
        return Err(MalformedPlan::OffsetCount {
            expected: expected_offsets,
            actual: raw.edge_offsets.len(),
        }
        .into());
    }
    validate_edge_array_lengths(raw, edges)?;

    let validation_work = states
        .checked_mul(2)
        .and_then(|value| {
            edges
                .checked_mul(2)
                .and_then(|edge_work| value.checked_add(edge_work))
        })
        .and_then(|value| value.checked_add(1))
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "validation work",
        })?;
    check_limit(
        ResourceKind::ValidationWork,
        validation_work,
        limits.max_validation_work,
    )?;
    let storage_bytes = storage_bytes(states, edges)?;
    check_limit(
        ResourceKind::StorageBytes,
        storage_bytes,
        limits.max_storage_bytes,
    )?;
    Ok(Shape {
        states,
        edges,
        storage_bytes,
        validation_work,
    })
}

fn check_index_space(resource: ResourceKind, count: usize) -> Result<(), CompileError> {
    if u32::try_from(count).is_err() {
        return Err(MalformedPlan::IndexSpaceExceeded { resource, count }.into());
    }
    Ok(())
}

fn validate_edge_array_lengths(raw: &RawPlan, edges: usize) -> Result<(), CompileError> {
    for (name, actual) in [
        ("edge_kinds", raw.edge_kinds.len()),
        ("byte_starts", raw.byte_starts.len()),
        ("byte_ends", raw.byte_ends.len()),
    ] {
        if actual != edges {
            return Err(MalformedPlan::EdgeArrayLength {
                array: name,
                expected: edges,
                actual,
            }
            .into());
        }
    }
    Ok(())
}

fn validate_graph(raw: &RawPlan, states: usize) -> Result<(usize, usize, usize), CompileError> {
    let mut zero_width_edges = 0usize;
    let mut assertion_edges = 0usize;
    let mut consuming_edges = 0usize;
    let mut has_accept = false;
    for state in 0..states {
        let next_state = state.saturating_add(1);
        let begin = plan_index(raw.edge_offsets[state]);
        let end = plan_index(raw.edge_offsets[next_state]);
        let role = raw.roles[state];
        if role == StateRole::Accept {
            has_accept = true;
            if begin != end {
                return Err(MalformedPlan::AcceptHasEdges {
                    state,
                    edges: end.saturating_sub(begin),
                }
                .into());
            }
            continue;
        }
        for edge in begin..end {
            if validate_edge(raw, states, state, edge, role)? {
                consuming_edges = checked_edge_increment(consuming_edges, "consuming edge count")?;
            } else {
                zero_width_edges =
                    checked_edge_increment(zero_width_edges, "zero-width edge count")?;
                if raw.edge_kinds[edge] != EdgeKind::Epsilon {
                    assertion_edges =
                        checked_edge_increment(assertion_edges, "assertion edge count")?;
                }
            }
        }
    }
    if !has_accept {
        return Err(MalformedPlan::MissingAcceptState.into());
    }
    Ok((zero_width_edges, assertion_edges, consuming_edges))
}

/// Returns true for a consuming edge and false for a zero-width edge.
fn validate_edge(
    raw: &RawPlan,
    states: usize,
    state: usize,
    edge: usize,
    role: StateRole,
) -> Result<bool, CompileError> {
    let target = raw.edge_targets[edge];
    if usize::try_from(target).map_or(true, |target| target >= states) {
        return Err(MalformedPlan::TargetOutOfBounds {
            edge,
            target,
            states,
        }
        .into());
    }
    let kind = raw.edge_kinds[edge];
    let role_accepts_kind = match role {
        StateRole::Split => kind.is_zero_width(),
        StateRole::Consume => kind == EdgeKind::ByteRange,
        StateRole::Accept => false,
    };
    if !role_accepts_kind {
        return Err(MalformedPlan::EdgeKindForState {
            state,
            edge,
            role: role.name(),
            kind: kind.name(),
        }
        .into());
    }
    if kind == EdgeKind::ByteRange {
        if raw.byte_starts[edge] > raw.byte_ends[edge] {
            return Err(MalformedPlan::InvalidByteRange {
                edge,
                start: raw.byte_starts[edge],
                end: raw.byte_ends[edge],
            }
            .into());
        }
        return Ok(true);
    }
    if raw.byte_starts[edge] != 0 || raw.byte_ends[edge] != 0 {
        return Err(MalformedPlan::NonCanonicalByteBounds {
            edge,
            start: raw.byte_starts[edge],
            end: raw.byte_ends[edge],
        }
        .into());
    }
    Ok(false)
}

fn checked_edge_increment(value: usize, computation: &'static str) -> Result<usize, CompileError> {
    value
        .checked_add(1)
        .ok_or(CompileError::ArithmeticOverflow { computation })
}

fn check_limit(resource: ResourceKind, needed: usize, limit: usize) -> Result<(), CompileError> {
    if needed > limit {
        return Err(CompileError::ResourceLimit {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn storage_bytes(states: usize, edges: usize) -> Result<usize, CompileError> {
    let offsets = states
        .checked_add(1)
        .and_then(|count| count.checked_mul(size_of::<u32>()))
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "offset table bytes",
        })?;
    let state_bytes =
        states
            .checked_mul(size_of::<StateRole>())
            .ok_or(CompileError::ArithmeticOverflow {
                computation: "state role bytes",
            })?;
    let per_edge = size_of::<u32>()
        .checked_add(size_of::<EdgeKind>())
        .and_then(|value| {
            size_of::<u8>()
                .checked_mul(2)
                .and_then(|bytes| value.checked_add(bytes))
        })
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "edge record bytes",
        })?;
    let edge_bytes = edges
        .checked_mul(per_edge)
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "edge table bytes",
        })?;
    offsets
        .checked_add(state_bytes)
        .and_then(|value| value.checked_add(edge_bytes))
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "automaton storage bytes",
        })
}

fn validate_offsets(offsets: &[u32], edges: usize) -> Result<(), CompileError> {
    if offsets[0] != 0 {
        return Err(MalformedPlan::FirstOffsetNotZero { actual: offsets[0] }.into());
    }
    let mut previous = 0u32;
    for (state, &offset) in offsets.iter().enumerate() {
        if offset < previous {
            return Err(MalformedPlan::OffsetDecreases {
                state: state.saturating_sub(1),
                from: previous,
                to: offset,
            }
            .into());
        }
        if usize::try_from(offset).map_or(true, |offset| offset > edges) {
            return Err(MalformedPlan::OffsetOutOfBounds {
                state: state.saturating_sub(1),
                offset,
                edges,
            }
            .into());
        }
        previous = offset;
    }
    if usize::try_from(previous) != Ok(edges) {
        return Err(MalformedPlan::FinalOffsetMismatch {
            final_offset: previous,
            edges,
        }
        .into());
    }
    Ok(())
}

use crate::SearchError;
