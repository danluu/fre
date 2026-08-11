use core::hash::{BuildHasherDefault, Hash, Hasher};
use core::cell::Cell;
use memchr::{memchr, memchr2, memchr3};
use std::collections::HashMap;
use std::rc::Rc;

use fre_automata::{EdgeKind, RawPlan, StateRole};
use fre_simd_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_WIDE_BLOCK_BYTES, ByteSet256, ByteSetClassifier,
};

use crate::{
    byte_frequency::{BYTE_FREQUENCY_DENOMINATOR, estimated_byte_frequency_units},
    error::CompileError,
    program::{AnchoredByteSet, OutputContract, ProgramFormatError},
};

pub(crate) const NO_STATE: u32 = u32::MAX;
/// Maximum determinization work that can be recorded in and safely replayed
/// from a stable serialized DFA artifact.
///
/// Requests may specify a smaller ceiling. Requests above this value are
/// reported verbatim in the compilation receipt and use this value as their
/// effective ceiling.
pub const MAX_STABLE_DFA_BUILD_WORK: u64 = 500_000_000;
/// Maximum pre-coalescing transition count admitted by the stable artifact.
///
/// Canonical artifacts prove that construction transitions do not exceed
/// recorded build work, so the work ceiling is also the exact global
/// transition ceiling.
pub const MAX_STABLE_DFA_TRANSITIONS: usize = 500_000_000;
/// Maximum state count admitted by stable canonical replay.
///
/// Every constructed state charges work and the work ceiling is lower than
/// the `u32` state-identifier ceiling on every supported target.
pub const MAX_STABLE_DFA_STATES: usize = 500_000_000;
// The complete-machine owner already retains canonical build work. Its two
// unused high bits record the in-memory replay identity without growing the
// runtime layout; stable serialization writes the exact untagged work and
// binds the same identity through the enclosing program version.
const CLASS_MASS_REPLAY_WORK_TAG: u64 = 1 << 63;
const ESTIMATED_FREQUENCY_REPLAY_WORK_TAG: u64 = 1 << 62;
const DFA_REPLAY_WORK_TAG_MASK: u64 =
    CLASS_MASS_REPLAY_WORK_TAG | ESTIMATED_FREQUENCY_REPLAY_WORK_TAG;
const _: () = assert!(MAX_STABLE_DFA_BUILD_WORK < ESTIMATED_FREQUENCY_REPLAY_WORK_TAG);
/// Endpoint rescue retains one compact ordered partial while building at most
/// one replacement attempt. State/transition limits are per attempt; compile
/// peak is therefore bounded by this fixed multiplier, plus the separately
/// capped endpoint-product scratch below. Work remains one aggregate limit.
const ENDPOINT_RESCUE_MAX_ATTEMPTS: usize = 2;
const _: () = assert!(MAX_STABLE_DFA_STATES <= usize::MAX / ENDPOINT_RESCUE_MAX_ATTEMPTS);
const _: () = assert!(MAX_STABLE_DFA_TRANSITIONS <= usize::MAX / ENDPOINT_RESCUE_MAX_ATTEMPTS);

/// Hard limits for complete ordered determinization.
///
/// The state and transition limits cover the forward and reverse machines
/// together. Hitting any limit declines the DFA optimization and leaves the
/// caller free to retain the universal ordered-NFA program. An endpoint rescue
/// may keep that first attempt's compact partial alive while constructing one
/// replacement under the same per-attempt state/transition limits, bounding
/// compile peak at two logical attempts. Its exact proof scratch is
/// independently capped; `max_work` is shared in aggregate across attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterminizeLimits {
    pub max_states: usize,
    pub max_transitions: usize,
    pub max_work: u64,
}

impl DeterminizeLimits {
    /// Maximum limits supported by the stable serialized-artifact contract.
    ///
    /// Despite the historical method name, work is intentionally bounded:
    /// canonical validation of an untrusted artifact must be replayable under
    /// a fixed ceiling.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_states: MAX_STABLE_DFA_STATES,
            max_transitions: MAX_STABLE_DFA_TRANSITIONS,
            max_work: MAX_STABLE_DFA_BUILD_WORK,
        }
    }

    /// Clamp caller limits to the stable serialized-artifact contract.
    #[must_use]
    pub const fn effective_for_stable_artifact(self) -> Self {
        Self {
            max_states: if self.max_states < MAX_STABLE_DFA_STATES {
                self.max_states
            } else {
                MAX_STABLE_DFA_STATES
            },
            max_transitions: if self.max_transitions < MAX_STABLE_DFA_TRANSITIONS {
                self.max_transitions
            } else {
                MAX_STABLE_DFA_TRANSITIONS
            },
            max_work: if self.max_work < MAX_STABLE_DFA_BUILD_WORK {
                self.max_work
            } else {
                MAX_STABLE_DFA_BUILD_WORK
            },
        }
    }
}

impl Default for DeterminizeLimits {
    /// Defaults for the explicitly selected optimizing compiler.
    ///
    /// Ordered subset construction can temporarily distinguish many priority
    /// orderings that the subsequent graph minimizer proves equivalent. The
    /// 262,144-state ceiling admits useful instances of that general shape and
    /// matches the automata layer's default graph scale. This can increase
    /// optimizing compile time and transient memory compared with the former
    /// 65,536-state ceiling; callers that prefer a smaller compilation budget
    /// can still provide lower explicit limits (or select fast mode). The
    /// independent transition and work ceilings continue to bound the attempt.
    fn default() -> Self {
        Self {
            max_states: 262_144,
            max_transitions: 16_777_216,
            max_work: MAX_STABLE_DFA_BUILD_WORK,
        }
    }
}

/// Shared logical-allocation ledger for one explicitly selected slow
/// determinization transaction.
///
/// Charges are monotonic within one construction attempt. This deliberately
/// over-counts short-lived scratch rather than trying to infer allocator
/// metadata or lifetime from `Vec` and `HashMap`. A declined ordered endpoint
/// attempt restores its checkpoint before the mutually exclusive
/// endpoint-pruned rescue only when it retained no transient native prefix.
#[derive(Clone, Debug)]
pub(crate) struct DeterminizeAllocationLedger {
    state: Rc<Cell<DeterminizeAllocationState>>,
}

#[derive(Clone, Copy, Debug)]
struct DeterminizeAllocationState {
    limit: usize,
    charged: usize,
    peak: usize,
    exhausted: bool,
}

impl DeterminizeAllocationLedger {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            state: Rc::new(Cell::new(DeterminizeAllocationState {
                limit,
                charged: 0,
                peak: 0,
                exhausted: false,
            })),
        }
    }

    fn charge_bytes(&self, bytes: usize) -> bool {
        let mut state = self.state.get();
        let Some(charged) = state.charged.checked_add(bytes) else {
            state.exhausted = true;
            self.state.set(state);
            return false;
        };
        if charged > state.limit {
            state.exhausted = true;
            self.state.set(state);
            return false;
        }
        state.charged = charged;
        state.peak = state.peak.max(charged);
        self.state.set(state);
        true
    }

    pub(crate) fn charge_elements<T>(&self, elements: usize) -> bool {
        let Some(bytes) = elements.checked_mul(core::mem::size_of::<T>()) else {
            let mut state = self.state.get();
            state.exhausted = true;
            self.state.set(state);
            return false;
        };
        self.charge_bytes(bytes)
    }

    /// Conservatively account for hash buckets, control bytes, and load-factor
    /// slack without depending on the standard library's private table layout.
    pub(crate) fn charge_map_entries<K, V>(&self, entries: usize) -> bool {
        let entry = core::mem::size_of::<K>()
            .saturating_add(core::mem::size_of::<V>())
            .saturating_add(1);
        let Some(bytes) = entries.checked_mul(entry).and_then(|bytes| bytes.checked_mul(2)) else {
            let mut state = self.state.get();
            state.exhausted = true;
            self.state.set(state);
            return false;
        };
        self.charge_bytes(bytes)
    }

    pub(crate) fn checkpoint(&self) -> usize {
        self.state.get().charged
    }

    pub(crate) fn restore(&self, checkpoint: usize) {
        let mut state = self.state.get();
        debug_assert!(checkpoint <= state.charged);
        state.charged = checkpoint;
        state.exhausted = false;
        self.state.set(state);
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.state.get().exhausted
    }

    pub(crate) fn peak_bytes(&self) -> usize {
        self.state.get().peak
    }
}

/// One graph-general stage in complete ordered determinization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeterminizationStage {
    AlphabetPartition,
    ForwardSubsetConstruction,
    ReverseSubsetConstruction,
    DfaStateMinimization,
    AlphabetColumnCoalescing,
}

/// Exact bounded resource that declined a determinization attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeterminizationResource {
    States {
        limit: usize,
        required: usize,
    },
    Transitions {
        limit: usize,
        required: usize,
    },
    Work {
        limit: u64,
        required: u64,
    },
    /// A fallible reservation failed. `requested_elements` and
    /// `element_size` describe the requested logical storage; allocator
    /// metadata is deliberately not guessed.
    Allocation {
        requested_elements: usize,
        element_size: usize,
    },
}

/// Structured provenance for an incomplete determinization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeterminizationDecline {
    pub stage: DeterminizationStage,
    pub resource: DeterminizationResource,
    pub work_completed: u64,
    pub states_completed: usize,
    pub transitions_completed: usize,
}

/// Deterministic trace of target-neutral determinization.
///
/// Stage and state/transition fields describe the construction whose artifact
/// was retained. `work_completed` is the exact aggregate compiler work: when
/// an endpoint-sensitive ordered construction declines and a bounded
/// dominance rescue is attempted, it includes both attempts and remains under
/// the single effective `max_work` ceiling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterminizationReport {
    pub requested_limits: DeterminizeLimits,
    pub effective_limits: DeterminizeLimits,
    pub attempted_stages: Box<[DeterminizationStage]>,
    pub completed_stages: Box<[DeterminizationStage]>,
    pub decline: Option<DeterminizationDecline>,
    pub work_completed: u64,
    pub states_completed: usize,
    pub transitions_completed: usize,
}

impl DeterminizationReport {
    pub(crate) fn not_attempted(requested_limits: DeterminizeLimits) -> Self {
        Self {
            requested_limits,
            effective_limits: requested_limits.effective_for_stable_artifact(),
            attempted_stages: Box::new([]),
            completed_stages: Box::new([]),
            decline: None,
            work_completed: 0,
            states_completed: 0,
            transitions_completed: 0,
        }
    }
}

/// Structural dimensions of a completed ordered DFA program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DfaStats {
    /// Classes produced directly from byte-range boundaries.
    pub boundary_classes: usize,
    /// Graph edge-membership classes used by ordered subset construction.
    ///
    /// This is no greater than [`Self::boundary_classes`]. Whole-machine
    /// column coalescing can reduce the alphabet further after construction.
    pub graph_classes: usize,
    /// Semantically distinct columns retained after whole-DFA coalescing.
    pub alphabet_classes: usize,
    /// Forward states produced by ordered subset construction, before
    /// language-independent DFA minimization.
    pub forward_states_before_minimization: usize,
    pub forward_states: usize,
    pub forward_transitions: usize,
    /// Reverse states produced by subset construction, before
    /// language-independent DFA minimization.
    pub reverse_states_before_minimization: usize,
    pub reverse_states: usize,
    pub reverse_transitions: usize,
    /// Exact canonical work for constructing this retained machine. A compile
    /// report separately includes work spent on any abandoned ordered attempt
    /// that preceded an endpoint-dominance rescue; stable replay needs only
    /// the work that deterministically reproduces this table.
    pub build_work: u64,
}

impl DfaStats {
    #[must_use]
    pub const fn states(self) -> usize {
        self.forward_states.saturating_add(self.reverse_states)
    }

    #[must_use]
    pub const fn transitions(self) -> usize {
        self.forward_transitions
            .saturating_add(self.reverse_transitions)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SelectedMatch {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

// Stable DFA state ordinals are bounded far below bit 31. Keep the semantic
// transition vectors in one word per cell instead of paying four bytes of
// struct padding for a one-bit outcome flag. The serialized representation is
// deliberately unchanged: it still writes a u32 destination, one Boolean,
// and three zero bytes per cell.
const SEMANTIC_CELL_FLAG: u32 = 1 << 31;
const SEMANTIC_CELL_NEXT_MASK: u32 = SEMANTIC_CELL_FLAG - 1;
const SEMANTIC_CELL_NO_STATE: u32 = SEMANTIC_CELL_NEXT_MASK;
const _: () = assert!(MAX_STABLE_DFA_STATES < SEMANTIC_CELL_NO_STATE as usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct ForwardCell(u32);

impl ForwardCell {
    pub(crate) const fn try_new(next: u32, accepted: bool) -> Option<Self> {
        let encoded_next = if next == NO_STATE {
            SEMANTIC_CELL_NO_STATE
        } else {
            if next >= SEMANTIC_CELL_NO_STATE {
                return None;
            }
            next
        };
        Some(Self(
            encoded_next | if accepted { SEMANTIC_CELL_FLAG } else { 0 },
        ))
    }

    pub(crate) const fn new(next: u32, accepted: bool) -> Self {
        let Some(cell) = Self::try_new(next, accepted) else {
            panic!("forward DFA state exceeds packed cell");
        };
        cell
    }

    pub(crate) const fn next(self) -> u32 {
        let next = self.0 & SEMANTIC_CELL_NEXT_MASK;
        if next == SEMANTIC_CELL_NO_STATE {
            NO_STATE
        } else {
            next
        }
    }

    pub(crate) const fn accepted(self) -> bool {
        self.0 & SEMANTIC_CELL_FLAG != 0
    }

    pub(crate) const fn with_next(self, next: u32) -> Self {
        Self::new(next, self.accepted())
    }
}

macro_rules! forward_cell {
    (next: $next:expr, accepted: $accepted:expr $(,)?) => {
        $crate::dfa::ForwardCell::new($next, $accepted)
    };
    (next: $next:expr, $accepted:ident $(,)?) => {
        $crate::dfa::ForwardCell::new($next, $accepted)
    };
    ($next:ident, accepted: $accepted:expr $(,)?) => {
        $crate::dfa::ForwardCell::new($next, $accepted)
    };
    ($next:ident, $accepted:ident $(,)?) => {
        $crate::dfa::ForwardCell::new($next, $accepted)
    };
}
pub(crate) use forward_cell;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct ReverseCell(u32);

impl ReverseCell {
    pub(crate) const fn try_new(next: u32, reaches_start: bool) -> Option<Self> {
        let encoded_next = if next == NO_STATE {
            SEMANTIC_CELL_NO_STATE
        } else {
            if next >= SEMANTIC_CELL_NO_STATE {
                return None;
            }
            next
        };
        Some(Self(
            encoded_next | if reaches_start { SEMANTIC_CELL_FLAG } else { 0 },
        ))
    }

    pub(crate) const fn new(next: u32, reaches_start: bool) -> Self {
        let Some(cell) = Self::try_new(next, reaches_start) else {
            panic!("reverse DFA state exceeds packed cell");
        };
        cell
    }

    pub(crate) const fn next(self) -> u32 {
        let next = self.0 & SEMANTIC_CELL_NEXT_MASK;
        if next == SEMANTIC_CELL_NO_STATE {
            NO_STATE
        } else {
            next
        }
    }

    pub(crate) const fn reaches_start(self) -> bool {
        self.0 & SEMANTIC_CELL_FLAG != 0
    }

    pub(crate) const fn with_next(self, next: u32) -> Self {
        Self::new(next, self.reaches_start())
    }
}

macro_rules! reverse_cell {
    (next: $next:expr, reaches_start: $reaches_start:expr $(,)?) => {
        $crate::dfa::ReverseCell::new($next, $reaches_start)
    };
    ($next:ident, $reaches_start:ident $(,)?) => {
        $crate::dfa::ReverseCell::new($next, $reaches_start)
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Alphabet {
    byte_to_class: [u8; 256],
    representatives: Box<[u8]>,
}

struct BuiltAlphabet {
    alphabet: Alphabet,
    boundary_classes: usize,
    graph_classes: usize,
}

#[derive(Clone, Copy)]
struct GraphMembershipPartition {
    boundary_to_graph: [u8; 256],
    classes: usize,
}

impl Alphabet {
    fn build_boundary(
        raw: &RawPlan,
        budget: &mut BuildBudget,
    ) -> Result<Option<Self>, CompileError> {
        let capacity = raw
            .edge_kinds
            .len()
            .checked_mul(2)
            .and_then(|value| value.checked_add(2))
            .ok_or(CompileError::InternalInvariant(
                "DFA alphabet boundary capacity overflowed",
            ))?;
        let Some(mut boundaries) = build_vec(capacity, budget) else {
            return Ok(None);
        };
        boundaries.push(0_u16);
        boundaries.push(256_u16);
        for edge in 0..raw.edge_kinds.len() {
            if !budget.charge(1) {
                return Ok(None);
            }
            if raw.edge_kinds[edge] != EdgeKind::ByteRange {
                continue;
            }
            boundaries.push(u16::from(raw.byte_starts[edge]));
            boundaries.push(u16::from(raw.byte_ends[edge]) + 1);
        }
        boundaries.sort_unstable();
        boundaries.dedup();

        let class_count =
            boundaries
                .len()
                .checked_sub(1)
                .ok_or(CompileError::InternalInvariant(
                    "DFA alphabet has no boundary interval",
                ))?;
        if class_count == 0 || class_count > 256 {
            return Err(CompileError::InternalInvariant(
                "DFA alphabet class count is outside 1..=256",
            ));
        }
        let mut byte_to_class = [0_u8; 256];
        let Some(mut representatives) = build_vec(class_count, budget) else {
            return Ok(None);
        };
        for class in 0..class_count {
            if !budget.charge(1) {
                return Ok(None);
            }
            let begin = *boundaries
                .get(class)
                .ok_or(CompileError::InternalInvariant(
                    "DFA alphabet boundary is absent",
                ))?;
            let end = *boundaries
                .get(class.checked_add(1).ok_or(CompileError::InternalInvariant(
                    "DFA alphabet class overflowed",
                ))?)
                .ok_or(CompileError::InternalInvariant(
                    "DFA alphabet end boundary is absent",
                ))?;
            if begin >= end || end > 256 {
                return Err(CompileError::InternalInvariant(
                    "DFA alphabet boundary interval is invalid",
                ));
            }
            let representative = u8::try_from(begin).map_err(|_| {
                CompileError::InternalInvariant("DFA alphabet representative exceeded u8")
            })?;
            representatives.push(representative);
            let class_u8 = u8::try_from(class)
                .map_err(|_| CompileError::InternalInvariant("DFA alphabet class exceeded u8"))?;
            for byte in begin..end {
                byte_to_class[usize::from(byte)] = class_u8;
            }
        }
        Ok(Some(Self {
            byte_to_class,
            representatives: representatives.into_boxed_slice(),
        }))
    }

    fn build(
        raw: &RawPlan,
        budget: &mut BuildBudget,
    ) -> Result<Option<BuiltAlphabet>, CompileError> {
        let Some(boundary_alphabet) = Self::build_boundary(raw, budget)? else {
            return Ok(None);
        };
        let boundary_classes = boundary_alphabet.classes();
        let Some(graph) =
            graph_membership_partition(raw, &boundary_alphabet.representatives, Some(budget))?
        else {
            return Ok(None);
        };
        let Some(mut graph_representatives) = build_vec(graph.classes, budget) else {
            return Ok(None);
        };
        let mut graph_byte_to_class = [0_u8; 256];
        for byte in 0_u16..=255 {
            if !budget.charge(1) {
                return Ok(None);
            }
            let byte_index = usize::from(byte);
            let boundary_class = usize::from(boundary_alphabet.byte_to_class[byte_index]);
            let graph_class = *graph.boundary_to_graph.get(boundary_class).ok_or(
                CompileError::InternalInvariant(
                    "DFA boundary class is outside the graph partition",
                ),
            )?;
            graph_byte_to_class[byte_index] = graph_class;
            if usize::from(graph_class) == graph_representatives.len() {
                graph_representatives.push(u8::try_from(byte).map_err(|_| {
                    CompileError::InternalInvariant("DFA graph representative exceeded u8")
                })?);
            }
        }
        if graph_representatives.len() != graph.classes {
            return Err(CompileError::InternalInvariant(
                "DFA graph partition did not use every class",
            ));
        }
        Ok(Some(BuiltAlphabet {
            alphabet: Self {
                byte_to_class: graph_byte_to_class,
                representatives: graph_representatives.into_boxed_slice(),
            },
            boundary_classes,
            graph_classes: graph.classes,
        }))
    }

    fn class(&self, byte: u8) -> usize {
        usize::from(self.byte_to_class[usize::from(byte)])
    }

    const fn classes(&self) -> usize {
        self.representatives.len()
    }
}

fn charge_optional(budget: &mut Option<&mut BuildBudget>, amount: u64) -> bool {
    budget
        .as_deref_mut()
        .is_none_or(|budget| budget.charge(amount))
}

/// Partition raw boundary intervals by the complete byte-range edge
/// membership signature. Refinement visits boundary representatives and
/// assigns every new class at its first byte, so numbering is canonical even
/// when equivalent intervals are disjoint.
fn graph_membership_partition(
    raw: &RawPlan,
    representatives: &[u8],
    mut budget: Option<&mut BuildBudget>,
) -> Result<Option<GraphMembershipPartition>, CompileError> {
    if representatives.is_empty() || representatives.len() > 256 {
        return Err(CompileError::InternalInvariant(
            "DFA graph partition width is outside 1..=256",
        ));
    }
    let mut current = [0_u8; 256];
    let mut classes = 1_usize;
    for (edge, &kind) in raw.edge_kinds.iter().enumerate() {
        if classes == representatives.len() {
            break;
        }
        if !charge_optional(&mut budget, 1) {
            return Ok(None);
        }
        match kind {
            EdgeKind::Epsilon => continue,
            EdgeKind::ByteRange => {}
            _ => {
                return Err(CompileError::InternalInvariant(
                    "assertion edge reached the assertion-free graph alphabet",
                ));
            }
        }
        let start = *raw
            .byte_starts
            .get(edge)
            .ok_or(CompileError::InternalInvariant(
                "DFA graph alphabet byte start is absent",
            ))?;
        let end = *raw
            .byte_ends
            .get(edge)
            .ok_or(CompileError::InternalInvariant(
                "DFA graph alphabet byte end is absent",
            ))?;
        let mut pair_to_new = [u16::MAX; 512];
        let mut refined = [0_u8; 256];
        let mut refined_classes = 0_usize;
        for (boundary, &representative) in representatives.iter().enumerate() {
            if !charge_optional(&mut budget, 1) {
                return Ok(None);
            }
            let old = usize::from(current[boundary]);
            if old >= classes {
                return Err(CompileError::InternalInvariant(
                    "DFA graph partition references an absent prior class",
                ));
            }
            let member = usize::from(start <= representative && representative <= end);
            let pair = old
                .checked_mul(2)
                .and_then(|value| value.checked_add(member))
                .ok_or(CompileError::InternalInvariant(
                    "DFA graph partition pair overflowed",
                ))?;
            let slot = pair_to_new
                .get_mut(pair)
                .ok_or(CompileError::InternalInvariant(
                    "DFA graph partition pair is outside the table",
                ))?;
            let new = if *slot == u16::MAX {
                let new = refined_classes;
                *slot = u16::try_from(new).map_err(|_| {
                    CompileError::InternalInvariant("DFA graph partition exceeded u16")
                })?;
                refined_classes =
                    refined_classes
                        .checked_add(1)
                        .ok_or(CompileError::InternalInvariant(
                            "DFA graph class count overflowed",
                        ))?;
                new
            } else {
                usize::from(*slot)
            };
            refined[boundary] = u8::try_from(new).map_err(|_| {
                CompileError::InternalInvariant("DFA graph partition exceeded 256 classes")
            })?;
        }
        if refined_classes < classes || refined_classes > representatives.len() {
            return Err(CompileError::InternalInvariant(
                "DFA graph refinement changed class count non-monotonically",
            ));
        }
        current = refined;
        classes = refined_classes;
    }
    Ok(Some(GraphMembershipPartition {
        boundary_to_graph: current,
        classes,
    }))
}

pub(crate) fn graph_alphabet_class_count(
    raw: &RawPlan,
    boundary_starts: &[bool; 256],
) -> Result<usize, ProgramFormatError> {
    let mut representatives = [0_u8; 256];
    let mut count = 0_usize;
    for (byte, &is_start) in boundary_starts.iter().enumerate() {
        if is_start {
            representatives[count] = u8::try_from(byte).map_err(|_| {
                ProgramFormatError::Malformed("DFA boundary representative exceeded u8")
            })?;
            count = count.checked_add(1).ok_or(ProgramFormatError::Malformed(
                "DFA boundary representative count overflowed",
            ))?;
        }
    }
    let partition = graph_membership_partition(raw, &representatives[..count], None)
        .map_err(|_| ProgramFormatError::Malformed("DFA graph alphabet is inconsistent"))?
        .ok_or(ProgramFormatError::Malformed(
            "DFA graph alphabet unexpectedly exhausted a budget",
        ))?;
    Ok(partition.classes)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ForwardKey {
    items: Vec<u32>,
    pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwardSemantics {
    /// Historical priority-preserving construction used to authenticate old
    /// stable artifacts.
    Ordered,
    /// Boolean membership observes neither priority nor selected endpoints.
    Exists,
    /// SelectedEnd and Span share the same selected-end transducer. Span start
    /// recovery remains on the untouched reverse/raw graph.
    EndpointPruned,
}

/// Canonical graph-class visitation order used while discovering forward
/// subset states.
///
/// Stable V1--V5 DFA artifacts use `Fifo`, while V6 uses
/// `DescendingClassMass`. Fresh optimizing compilation uses
/// `DescendingEstimatedClassFrequency`. Each distinct replay identity is
/// carried by the enclosing program format. None changes canonical table
/// columns; they change only which semantic states are discovered first when
/// a bounded construction stops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DfaReplayOrder {
    Fifo,
    DescendingClassMass,
    DescendingEstimatedClassFrequency,
}

const fn dfa_replay_work_tag(replay_order: DfaReplayOrder) -> u64 {
    match replay_order {
        DfaReplayOrder::Fifo => 0,
        DfaReplayOrder::DescendingClassMass => CLASS_MASS_REPLAY_WORK_TAG,
        DfaReplayOrder::DescendingEstimatedClassFrequency => {
            ESTIMATED_FREQUENCY_REPLAY_WORK_TAG
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ForwardDfa {
    initial_pending: bool,
    initial_terminal: bool,
    transitions: Vec<ForwardCell>,
    states: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartialForwardDfa {
    initial_pending: bool,
    initial_terminal: bool,
    transitions: Vec<ForwardCell>,
    /// Derived hot-loop representation of `transitions`. The stable wire
    /// format and native lowering continue to use the explicit cells above;
    /// portable retained-row execution needs only one 32-bit load per byte.
    /// An unauthenticated decoded payload leaves this absent until canonical
    /// regeneration returns a freshly derived machine.
    packed_transitions: Option<Vec<PackedForwardCell>>,
    /// Source-independent effect of every completed transition on a scalar
    /// proof that all live ordered threads share one match start. This is a
    /// derived in-memory certificate: stable artifacts regenerate it while
    /// canonically validating the retained table.
    start_actions: Vec<ForwardStartAction>,
    discovered_states: usize,
    complete_rows: usize,
    /// Semantic subset keys for exactly the incomplete suffix
    /// `complete_rows..discovered_states`. Endpoint contracts preserve
    /// Thompson priority; Exists stores graph-state order because K0 observes
    /// only set membership. Complete source rows need no key at runtime;
    /// entering this suffix is the authenticated K0 resume boundary.
    resume_keys: Vec<ForwardKey>,
}

const PARTIAL_CELL_ACCEPTED: u32 = 1 << 31;
const PARTIAL_CELL_HOLE_BASE: u32 = 1 << 30;
const PARTIAL_CELL_DEAD: u32 = PARTIAL_CELL_ACCEPTED - 1;
const _: () = assert!(MAX_STABLE_DFA_TRANSITIONS < PARTIAL_CELL_HOLE_BASE as usize);
const _: () = assert!(
    MAX_STABLE_DFA_STATES <= (PARTIAL_CELL_DEAD - PARTIAL_CELL_HOLE_BASE) as usize
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct PackedForwardCell(u32);

impl PackedForwardCell {
    fn from_cell(cell: ForwardCell, complete_rows: usize, classes: usize) -> Option<Self> {
        if classes == 0 {
            return None;
        }
        let next = if cell.next() == NO_STATE {
            PARTIAL_CELL_DEAD
        } else {
            let state = usize::try_from(cell.next()).ok()?;
            if state < complete_rows {
                let row = u32::try_from(state.checked_mul(classes)?).ok()?;
                if row >= PARTIAL_CELL_HOLE_BASE {
                    return None;
                }
                row
            } else {
                let resume = u32::try_from(state.checked_sub(complete_rows)?).ok()?;
                let hole = PARTIAL_CELL_HOLE_BASE.checked_add(resume)?;
                if hole >= PARTIAL_CELL_DEAD {
                    return None;
                }
                hole
            }
        };
        Some(Self(next | (u32::from(cell.accepted()) * PARTIAL_CELL_ACCEPTED)))
    }

    const fn accepted(self) -> bool {
        self.0 & PARTIAL_CELL_ACCEPTED != 0
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }

    /// Authenticate that this canonical retained-row cell is the exact
    /// packing of its semantic transition. Native lowering uses the semantic
    /// destination to choose a target-specific row/hole encoding, but it must
    /// never do so from data that differs from the portable executor's sealed
    /// representation.
    pub(crate) fn authenticates(
        self,
        cell: ForwardCell,
        complete_rows: usize,
        classes: usize,
    ) -> bool {
        Self::from_cell(cell, complete_rows, classes) == Some(self)
    }
}

enum ForwardBuildOutcome {
    Complete(ForwardDfa),
    Declined {
        partial: Option<PartialForwardDfa>,
        native_slow_partial: Option<NativeSlowPartialForward>,
    },
}

impl ForwardBuildOutcome {
    const fn declined() -> Self {
        Self::Declined {
            partial: None,
            native_slow_partial: None,
        }
    }
}

impl ForwardDfa {
    fn cell(&self, state: u32, class: usize, classes: usize) -> Option<ForwardCell> {
        let state = usize::try_from(state).ok()?;
        let index = state.checked_mul(classes)?.checked_add(class)?;
        self.transitions.get(index).copied()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReverseKey(Vec<u32>);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReverseDfa {
    transitions: Vec<ReverseCell>,
    states: usize,
}

impl ReverseDfa {
    fn cell(&self, state: u32, class: usize, classes: usize) -> Option<ReverseCell> {
        let state = usize::try_from(state).ok()?;
        let index = state.checked_mul(classes)?.checked_add(class)?;
        self.transitions.get(index).copied()
    }
}

/// A complete, alphabet-reduced, output-specialized DFA plus optional reverse
/// machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OrderedDfa {
    alphabet: Alphabet,
    forward: ForwardDfa,
    reverse: Option<ReverseDfa>,
    stats: DfaStats,
}

/// Canonical prefix of output-specialized subset construction retained when
/// bounded determinization declines.
///
/// Every stored row is complete for every graph alphabet class. A transition
/// may name a discovered state whose own row was not completed; execution
/// treats entry into that state as a side exit to the exact ordered-NFA
/// engine. The compact incomplete-state suffix retains either the canonical
/// ordered frontier and pending mode needed by endpoint contracts, or the
/// canonical set-valued frontier needed by Exists. The selected exact fallback
/// executor continues at the first unconsumed byte without replaying the
/// prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PartialDfa {
    alphabet: Alphabet,
    forward: PartialForwardDfa,
    effective_limits: DeterminizeLimits,
}

/// Compiler-owned completed-row prefix retained by the bounded slow AOT pass.
///
/// This is deliberately not a [`PartialDfa`]. It carries no portable packing,
/// start certificates, stable limits, or serialization ABI. A genuinely
/// incomplete forward prefix keeps the compiler's already-owned discovery
/// keys so a private object sidecar can bind exact K0 continuations without
/// replaying completed rows. A later-stage numeric decline can instead retain
/// a complete forward machine plus the already-built optional reverse machine
/// for ordinary direct native lowering.
#[derive(Debug)]
pub(crate) struct NativeSlowPartial {
    alphabet: Alphabet,
    forward: NativeSlowPartialForward,
    reverse: Option<ReverseDfa>,
    reverse_states_before_minimization: usize,
    retained_forward_minimized: bool,
    boundary_classes: usize,
    graph_classes: usize,
}

#[derive(Debug)]
struct NativeSlowPartialForward {
    initial_pending: bool,
    initial_terminal: bool,
    transitions: Vec<ForwardCell>,
    complete_rows: usize,
    discovered_states: usize,
    states_before_minimization: usize,
    /// Already-owned subset keys in discovery order. This is populated only
    /// for a genuinely incomplete prefix; completed candidates need no
    /// continuation sidecar.
    states: Vec<ForwardKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PartialDfaResult<T> {
    Complete(T),
    Resume(PartialDfaResume),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PartialDfaResume {
    /// Index in the compact incomplete-suffix resume-key array.
    pub(crate) state: usize,
    /// First byte not consumed by the retained table.
    pub(crate) position: usize,
    /// Most recent selected endpoint in the already-consumed prefix.
    pub(crate) pending_end: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwardStartAction {
    Drop,
    Propagate,
    Reset,
}

impl ForwardStartAction {
    const fn derive(source_len: usize, final_len: usize, injected_root: bool) -> Self {
        if !injected_root {
            return Self::Propagate;
        }
        if source_len == 0 {
            return if final_len == 0 {
                Self::Drop
            } else {
                Self::Reset
            };
        }
        if final_len == source_len {
            Self::Propagate
        } else {
            Self::Drop
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PartialDfaSelection {
    pub(crate) end: Option<usize>,
    pub(crate) start: Option<usize>,
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeDfaView<'a> {
    pub(crate) initial_state: u32,
    pub(crate) initial_pending: bool,
    pub(crate) initial_terminal: bool,
    pub(crate) byte_classes: &'a [u8; 256],
    pub(crate) class_count: usize,
    pub(crate) class_representatives: &'a [u8],
    pub(crate) forward_cells: &'a [ForwardCell],
    pub(crate) reverse_initial: Option<u32>,
    pub(crate) reverse_cells: &'a [ReverseCell],
}

/// Canonically packed completed rows from an authenticated incomplete DFA.
///
/// Unlike [`NativeDfaView`], destinations at or above the hole base name a
/// compact runtime-resume frontier rather than another native row. The packed
/// representation is exactly the one exercised by the portable retained-row
/// executor, so native lowering does not reinterpret semantic frontier data.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativePartialDfaView<'a> {
    /// Semantic completed rows. Destinations beyond the completed prefix are
    /// indices into the authenticated resume frontier.
    pub(crate) dfa: NativeDfaView<'a>,
    pub(crate) initial_pending: bool,
    pub(crate) initial_terminal: bool,
    pub(crate) byte_classes: &'a [u8; 256],
    pub(crate) class_count: usize,
    pub(crate) packed_cells: &'a [PackedForwardCell],
    pub(crate) complete_rows: usize,
    pub(crate) resume_states: usize,
    pub(crate) discovered_states: usize,
}

/// Maximum number of structurally ranked forward-DFA self-loop plans handed
/// to native code generation.
///
/// The analysis still accounts for every candidate in the completed table,
/// but retaining a fixed number keeps native code size and analysis storage
/// independent of DFA state count.
#[allow(dead_code, reason = "structural handoff for native code generation")]
pub(crate) const MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS: usize = 16;

/// Exact byte membership for one native self-loop skipping candidate.
///
/// Word zero contains bytes `0..=63`, with byte zero in its least-significant
/// bit. The remaining words continue in ascending byte order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code, reason = "structural handoff for native code generation")]
pub(crate) struct NativeByteMask256 {
    pub(crate) words: [u64; 4],
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
impl NativeByteMask256 {
    fn insert(&mut self, byte: u8) {
        let byte = usize::from(byte);
        let word = byte >> 6;
        let bit = byte & 63;
        self.words[word] |= 1_u64 << bit;
    }

    fn union_with(&mut self, other: Self) {
        for (destination, source) in self.words.iter_mut().zip(other.words) {
            *destination |= source;
        }
    }

    #[must_use]
    const fn complement(self) -> Self {
        let [first, second, third, fourth] = self.words;
        Self {
            words: [!first, !second, !third, !fourth],
        }
    }

    #[must_use]
    fn cardinality(self) -> u16 {
        self.words
            .iter()
            .map(|word| word.count_ones())
            .sum::<u32>()
            .try_into()
            .expect("a 256-bit mask cardinality fits u16")
    }

    #[cfg(test)]
    #[must_use]
    fn contains(self, byte: u8) -> bool {
        let byte = usize::from(byte);
        let word = byte >> 6;
        let bit = byte & 63;
        self.words[word] & (1_u64 << bit) != 0
    }
}

/// Observable transition behavior shared by every byte in a skip plan.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[allow(dead_code, reason = "structural handoff for native code generation")]
pub(crate) enum NativeSelfLoopAcceptance {
    /// Skipped transitions do not change the pending match end.
    #[default]
    NonAccepting,
    /// Every skipped transition accepts. Span/find code must set the pending
    /// end to the final skipped position; `Exists/is_match` code may return as
    /// soon as it observes the first byte in the run.
    Accepting,
}

/// One exact, table-proven per-state SIMD self-loop candidate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code, reason = "structural handoff for native code generation")]
pub(crate) struct NativeDfaSelfLoopSkipPlan {
    pub(crate) state: u32,
    pub(crate) acceptance: NativeSelfLoopAcceptance,
    pub(crate) membership: NativeByteMask256,
    pub(crate) complement: NativeByteMask256,
    pub(crate) membership_cardinality: u16,
    pub(crate) complement_cardinality: u16,
    /// Zero-based position in the deterministic structural ranking after all
    /// candidates have been considered.
    pub(crate) structural_rank: usize,
}

/// Fixed-cap result of inspecting every completed forward-DFA state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code, reason = "structural handoff for native code generation")]
pub(crate) struct NativeDfaSelfLoopSkipPlans {
    plans: [NativeDfaSelfLoopSkipPlan; MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS],
    retained_count: usize,
    pub(crate) analyzed_state_count: usize,
    pub(crate) candidate_count: usize,
    pub(crate) dropped_count: usize,
}

/// Exact byte set whose forward-table columns synchronize every state to the
/// fresh-search state without accepting.
///
/// This column property is useful only when combined with a separate graph
/// proof of a required terminal suffix candidate. After scanning the first
/// graph-required terminal candidate, no prior match can be pending; the last
/// synchronizing byte before it safely raises the fresh-search start to one
/// byte after that reset. The property does not infer a suffix or candidate
/// from source text and is not, by itself, permission to move a search start.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code, reason = "structural handoff for native code generation")]
pub(crate) struct NativeDfaSynchronizingReset {
    pub(crate) membership: NativeByteMask256,
    pub(crate) cardinality: u16,
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
impl NativeDfaSelfLoopSkipPlans {
    const fn empty(analyzed_state_count: usize) -> Self {
        Self {
            plans: [NativeDfaSelfLoopSkipPlan {
                state: 0,
                acceptance: NativeSelfLoopAcceptance::NonAccepting,
                membership: NativeByteMask256 { words: [0; 4] },
                complement: NativeByteMask256 { words: [0; 4] },
                membership_cardinality: 0,
                complement_cardinality: 0,
                structural_rank: 0,
            }; MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS],
            retained_count: 0,
            analyzed_state_count,
            candidate_count: 0,
            dropped_count: 0,
        }
    }

    #[must_use]
    pub(crate) fn as_slice(&self) -> &[NativeDfaSelfLoopSkipPlan] {
        &self.plans[..self.retained_count]
    }

    #[must_use]
    pub(crate) const fn retained_count(&self) -> usize {
        self.retained_count
    }

    #[must_use]
    pub(crate) const fn capacity() -> usize {
        MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS
    }

    fn consider(&mut self, plan: NativeDfaSelfLoopSkipPlan) -> Option<()> {
        self.candidate_count = self.candidate_count.checked_add(1)?;
        let insertion = self.as_slice().partition_point(|retained| {
            retained.membership_cardinality > plan.membership_cardinality
                || (retained.membership_cardinality == plan.membership_cardinality
                    && (retained.acceptance < plan.acceptance
                        || (retained.acceptance == plan.acceptance && retained.state < plan.state)))
        });
        if insertion < MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS {
            let destination = self
                .retained_count
                .min(MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS.saturating_sub(1));
            let mut cursor = destination;
            while cursor > insertion {
                self.plans[cursor] = self.plans[cursor.saturating_sub(1)];
                cursor = cursor.saturating_sub(1);
            }
            self.plans[insertion] = plan;
            self.retained_count = self
                .retained_count
                .checked_add(1)?
                .min(MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS);
        }
        Some(())
    }

    fn finish(&mut self) -> Option<()> {
        self.dropped_count = self.candidate_count.checked_sub(self.retained_count)?;
        for (rank, plan) in self.plans[..self.retained_count].iter_mut().enumerate() {
            plan.structural_rank = rank;
        }
        Some(())
    }
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
impl NativeDfaView<'_> {
    /// Derive exact SIMD-skippable byte sets from the finalized forward table.
    ///
    /// `None` conservatively declines the optimization if a view is not a
    /// complete, internally consistent table. Each retained plan contains all
    /// and only bytes whose transition from `state` is a self-loop with the
    /// advertised acceptance behavior. Accepting and non-accepting cells are
    /// never mixed into one plan.
    #[must_use]
    pub(crate) fn self_loop_skip_plans(&self) -> Option<NativeDfaSelfLoopSkipPlans> {
        if self.class_count == 0
            || self.class_count > 256
            || self.class_representatives.len() != self.class_count
            || self.forward_cells.is_empty()
            || !self.forward_cells.len().is_multiple_of(self.class_count)
        {
            return None;
        }
        let state_count = self.forward_cells.len().checked_div(self.class_count)?;
        let _ = u32::try_from(state_count).ok()?;

        let mut class_masks = [NativeByteMask256 { words: [0; 4] }; 256];
        for (byte, &class) in self.byte_classes.iter().enumerate() {
            let class = usize::from(class);
            if class >= self.class_count {
                return None;
            }
            class_masks[class].insert(u8::try_from(byte).ok()?);
        }

        let mut result = NativeDfaSelfLoopSkipPlans::empty(state_count);
        for state in 0..state_count {
            let state_u32 = u32::try_from(state).ok()?;
            let row = state.checked_mul(self.class_count)?;
            let mut non_accepting = NativeByteMask256::default();
            let mut accepting = NativeByteMask256::default();
            for (class, &class_mask) in class_masks[..self.class_count].iter().enumerate() {
                let cell = *self.forward_cells.get(row.checked_add(class)?)?;
                if cell.next() != state_u32 {
                    continue;
                }
                if cell.accepted() {
                    accepting.union_with(class_mask);
                } else {
                    non_accepting.union_with(class_mask);
                }
            }
            for (acceptance, membership) in [
                (NativeSelfLoopAcceptance::NonAccepting, non_accepting),
                (NativeSelfLoopAcceptance::Accepting, accepting),
            ] {
                let membership_cardinality = membership.cardinality();
                if membership_cardinality == 0 {
                    continue;
                }
                let complement = membership.complement();
                result.consider(NativeDfaSelfLoopSkipPlan {
                    state: state_u32,
                    acceptance,
                    membership,
                    complement,
                    membership_cardinality,
                    complement_cardinality: complement.cardinality(),
                    structural_rank: 0,
                })?;
            }
        }
        result.finish()?;
        Some(result)
    }

    /// Return bytes that non-acceptingly reset every completed forward state
    /// to `initial_state`.
    ///
    /// `Some` may contain an empty set. `None` conservatively declines when
    /// the view is malformed or the initial state is nullable: in the latter
    /// case a fresh search already has a pending match, so reset-plus-one is
    /// not an equivalent fresh-search boundary.
    #[must_use]
    pub(crate) fn synchronizing_reset_bytes(&self) -> Option<NativeDfaSynchronizingReset> {
        if self.initial_pending
            || self.initial_terminal
            || self.class_count == 0
            || self.class_count > 256
            || self.class_representatives.len() != self.class_count
            || self.forward_cells.is_empty()
            || !self.forward_cells.len().is_multiple_of(self.class_count)
        {
            return None;
        }
        let state_count = self.forward_cells.len().checked_div(self.class_count)?;
        let initial_state = usize::try_from(self.initial_state).ok()?;
        if initial_state >= state_count {
            return None;
        }

        let mut represented_classes = [false; 256];
        for &class in self.byte_classes {
            let class = usize::from(class);
            if class >= self.class_count {
                return None;
            }
            represented_classes[class] = true;
        }
        if represented_classes[..self.class_count]
            .iter()
            .any(|represented| !represented)
        {
            return None;
        }
        for (class, &representative) in self.class_representatives.iter().enumerate() {
            if usize::from(self.byte_classes[usize::from(representative)]) != class {
                return None;
            }
        }

        let mut qualifying_classes = [true; 256];
        for state in 0..state_count {
            let row = state.checked_mul(self.class_count)?;
            for (class, qualifies) in qualifying_classes[..self.class_count]
                .iter_mut()
                .enumerate()
            {
                let cell = *self.forward_cells.get(row.checked_add(class)?)?;
                if cell.next() != NO_STATE
                    && usize::try_from(cell.next())
                        .ok()
                        .is_none_or(|next| next >= state_count)
                {
                    return None;
                }
                if cell.accepted() || cell.next() != self.initial_state {
                    *qualifies = false;
                }
            }
        }

        let mut membership = NativeByteMask256::default();
        for (byte, &class) in self.byte_classes.iter().enumerate() {
            if qualifying_classes[usize::from(class)] {
                membership.insert(u8::try_from(byte).ok()?);
            }
        }
        Some(NativeDfaSynchronizingReset {
            membership,
            cardinality: membership.cardinality(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PartialDfaPrefixPlan {
    primary_depth: usize,
    scanner: PartialDfaPrefixScanner,
}

#[derive(Clone, Copy, Debug)]
enum PartialDfaPrefixScanner {
    Small {
        members: [u8; 3],
        count: usize,
    },
    Full {
        set: ByteSet256,
        classifier: ByteSetClassifier,
    },
}

impl PartialDfaPrefixPlan {
    pub(crate) fn derive(sets: &[AnchoredByteSet]) -> (Option<Self>, bool) {
        let Some((primary_depth, primary)) = sets
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, set)| set.cardinality() < 256)
            .min_by_key(|(depth, set)| (set.cardinality(), *depth))
        else {
            return (None, true);
        };
        let cardinality = usize::from(primary.cardinality());
        let scanner = if cardinality <= 3 {
            let mut members = [0_u8; 3];
            let mut count = 0usize;
            for byte in u8::MIN..=u8::MAX {
                if primary.contains(byte) {
                    members[count] = byte;
                    count += 1;
                }
            }
            if count != cardinality {
                return (None, false);
            }
            PartialDfaPrefixScanner::Small { members, count }
        } else {
            let set = ByteSet256::from_words(primary.words());
            PartialDfaPrefixScanner::Full {
                set,
                classifier: ByteSetClassifier::new(set),
            }
        };
        (
            Some(Self {
                primary_depth,
                scanner,
            }),
            true,
        )
    }

    pub(crate) const fn primary_depth(self) -> usize {
        self.primary_depth
    }

    fn find_primary(&self, primary: AnchoredByteSet, bytes: &[u8]) -> Option<usize> {
        match self.scanner {
            PartialDfaPrefixScanner::Small { members, count: 1 } => memchr(members[0], bytes),
            PartialDfaPrefixScanner::Small { members, count: 2 } => {
                memchr2(members[0], members[1], bytes)
            }
            PartialDfaPrefixScanner::Small { members, count: 3 } => {
                memchr3(members[0], members[1], members[2], bytes)
            }
            PartialDfaPrefixScanner::Small { .. } => {
                bytes.iter().position(|&byte| primary.contains(byte))
            }
            PartialDfaPrefixScanner::Full { set, classifier } => {
                find_byte_set_member(set, &classifier, bytes)
            }
        }
    }

    fn next_candidate(
        &self,
        sets: &[AnchoredByteSet],
        haystack: &[u8],
        mut start: usize,
        window_end: usize,
    ) -> Option<usize> {
        let maximum_start = window_end.checked_sub(sets.len())?;
        while start <= maximum_start {
            let primary_start = start.checked_add(self.primary_depth)?;
            let primary_end = maximum_start
                .checked_add(self.primary_depth)?
                .checked_add(1)?;
            let bytes = haystack.get(primary_start..primary_end)?;
            let primary = *sets.get(self.primary_depth)?;
            let hit = primary_start.checked_add(self.find_primary(primary, bytes)?)?;
            let candidate = hit.checked_sub(self.primary_depth)?;
            if sets
                .iter()
                .copied()
                .enumerate()
                // `find_primary` returned this exact byte from `primary`, so
                // its membership is already proved. In particular, a
                // one-position prefix needs no scalar verification after the
                // moving scanner finds a candidate.
                .filter(|(depth, _)| *depth != self.primary_depth)
                .all(|(depth, set)| {
                    candidate
                        .checked_add(depth)
                        .and_then(|position| haystack.get(position))
                        .is_some_and(|&byte| set.contains(byte))
                })
            {
                return Some(candidate);
            }
            start = candidate.checked_add(1)?;
        }
        None
    }
}

fn find_byte_set_member(
    set: ByteSet256,
    classifier: &ByteSetClassifier,
    bytes: &[u8],
) -> Option<usize> {
    let mut position = 0usize;
    while bytes.len().saturating_sub(position) >= BYTE_SET_WIDE_BLOCK_BYTES {
        let end = position.checked_add(BYTE_SET_WIDE_BLOCK_BYTES)?;
        let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = bytes.get(position..end)?.try_into().ok()?;
        let mask = classifier.classify_32(block).member_mask();
        if mask != 0 {
            return position.checked_add(mask.trailing_zeros() as usize);
        }
        position = end;
    }
    if bytes.len().saturating_sub(position) >= BYTE_SET_BLOCK_BYTES {
        let end = position.checked_add(BYTE_SET_BLOCK_BYTES)?;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = bytes.get(position..end)?.try_into().ok()?;
        let mask = classifier.classify_16(block).member_mask();
        if mask != 0 {
            return position.checked_add(mask.trailing_zeros() as usize);
        }
        position = end;
    }
    bytes.get(position..)?
        .iter()
        .position(|&byte| set.contains(byte))
        .and_then(|offset| position.checked_add(offset))
}

impl PartialDfa {
    /// Whether the canonical initial subset has already selected an empty
    /// match at the authoritative search-window start.
    ///
    /// For `Span`, every later endpoint selected while this bit remains in
    /// the ordered state still belongs to that same leftmost start. A caller
    /// that has completed the retained forward search can therefore recover
    /// the exact span without executing a reverse machine.
    pub(crate) const fn initial_pending(&self) -> bool {
        self.forward.initial_pending
    }

    pub(crate) const fn retained_dimensions(&self) -> (usize, usize) {
        (
            self.forward.complete_rows,
            self.forward.discovered_states,
        )
    }

    pub(crate) const fn effective_limits(&self) -> DeterminizeLimits {
        self.effective_limits
    }

    /// Expose a resource-fallback table to the ordinary native DFA lowering
    /// only when every discovered state has a completed row.
    ///
    /// Such an artifact is "partial" only in compiler provenance: a later
    /// optimization stage (or Span reverse construction) exhausted its
    /// budget after forward subset construction had already completed. With
    /// no retained frontier left to resume, the forward table is a complete
    /// endpoint transducer and needs no runtime helper.
    pub(crate) fn native_complete_view(&self) -> Option<NativeDfaView<'_>> {
        let complete = self.forward.complete_rows == self.forward.discovered_states
            && self.forward.resume_keys.is_empty();
        let expected_cells = self
            .forward
            .discovered_states
            .checked_mul(self.alphabet.classes())?;
        let packed = self.forward.packed_transitions.as_deref()?;
        let exact_extent = self.forward.transitions.len() == expected_cells;
        let authenticated_packing = packed.len() == expected_cells
            && packed
                .iter()
                .copied()
                .zip(self.forward.transitions.iter().copied())
                .all(|(packed, semantic)| {
                    packed.authenticates(
                        semantic,
                        self.forward.complete_rows,
                        self.alphabet.classes(),
                    )
                });
        let bounded_targets = self.forward.transitions.iter().all(|cell| {
            cell.next() == NO_STATE
                || usize::try_from(cell.next())
                    .ok()
                    .is_some_and(|next| next < self.forward.discovered_states)
        });
        if !complete || !exact_extent || !authenticated_packing || !bounded_targets {
            return None;
        }
        Some(NativeDfaView {
            initial_state: 0,
            initial_pending: self.forward.initial_pending,
            initial_terminal: self.forward.initial_terminal,
            byte_classes: &self.alphabet.byte_to_class,
            class_count: self.alphabet.classes(),
            class_representatives: &self.alphabet.representatives,
            forward_cells: &self.forward.transitions,
            reverse_initial: None,
            reverse_cells: &[],
        })
    }

    /// Expose the canonical completed-row prefix only when at least one row
    /// exists and at least one authenticated incomplete frontier remains.
    pub(crate) fn native_incomplete_view(&self) -> Option<NativePartialDfaView<'_>> {
        let classes = self.alphabet.classes();
        let resume_states = self
            .forward
            .discovered_states
            .checked_sub(self.forward.complete_rows)?;
        let expected_cells = self.forward.complete_rows.checked_mul(classes)?;
        let packed_cells = self.forward.packed_transitions.as_deref()?;
        if classes == 0
            || self.forward.complete_rows == 0
            || resume_states == 0
            || packed_cells.len() != expected_cells
            || self.forward.transitions.len() != expected_cells
            || self.forward.resume_keys.len() != resume_states
        {
            return None;
        }
        Some(NativePartialDfaView {
            dfa: NativeDfaView {
                initial_state: 0,
                initial_pending: self.forward.initial_pending,
                initial_terminal: self.forward.initial_terminal,
                byte_classes: &self.alphabet.byte_to_class,
                class_count: classes,
                class_representatives: &self.alphabet.representatives,
                forward_cells: &self.forward.transitions,
                reverse_initial: None,
                reverse_cells: &[],
            },
            initial_pending: self.forward.initial_pending,
            initial_terminal: self.forward.initial_terminal,
            byte_classes: &self.alphabet.byte_to_class,
            class_count: classes,
            packed_cells,
            complete_rows: self.forward.complete_rows,
            resume_states,
            discovered_states: self.forward.discovered_states,
        })
    }

    pub(crate) fn resume_frontier_count(&self) -> usize {
        self.forward.resume_keys.len()
    }

    /// Return the canonical pending-end mode for one compact resume state.
    ///
    /// The state is only an index into the partial artifact's authenticated
    /// incomplete-state suffix. Frontier contents remain private and are
    /// copied into a graph-bound [`fre_automata::K0ResumeSet`] when workspace
    /// preparation validates the complete table.
    pub(crate) fn resume_pending(&self, state: usize) -> Option<bool> {
        self.forward.resume_keys.get(state).map(|key| key.pending)
    }

    pub(crate) fn resume_item_count(&self) -> Result<usize, CompileError> {
        self.forward
            .resume_keys
            .iter()
            .try_fold(0usize, |total, key| total.checked_add(key.items.len()))
            .ok_or(CompileError::InternalInvariant(
                "partial DFA resume item count overflowed",
            ))
    }

    pub(crate) fn resume_frontiers(
        &self,
    ) -> impl ExactSizeIterator<Item = (&[u32], bool)> {
        self.forward
            .resume_keys
            .iter()
            .map(|key| (key.items.as_slice(), key.pending))
    }

    pub(crate) fn resume_frontier(&self, state: usize) -> Option<(&[u32], bool)> {
        self.forward
            .resume_keys
            .get(state)
            .map(|key| (key.items.as_slice(), key.pending))
    }

    fn from_complete_forward(
        alphabet: Alphabet,
        forward: ForwardDfa,
        budget: &mut BuildBudget,
    ) -> Result<Option<Self>, CompileError> {
        // An allocation decline cannot publish a canonical sidecar: allocator
        // history is deliberately absent from the stable wire provenance.
        if matches!(
            budget.decline.as_ref(),
            Some(DeterminizationDecline {
                resource: DeterminizationResource::Allocation { .. },
                ..
            })
        ) {
            return Ok(None);
        }
        let classes = alphabet.classes();
        let mut packed_transitions = Vec::new();
        if packed_transitions
            .try_reserve_exact(forward.transitions.len())
            .is_err()
        {
            budget.replace_decline_with_allocation::<PackedForwardCell>(
                forward.transitions.len(),
            );
            return Ok(None);
        }
        for &cell in &forward.transitions {
            packed_transitions.push(
                PackedForwardCell::from_cell(cell, forward.states, classes).ok_or(
                    CompileError::InternalInvariant(
                        "stable complete DFA cell exceeded the packed partial range",
                    ),
                )?,
            );
        }
        let effective_limits = budget.limits;
        Ok(Some(Self {
            alphabet,
            forward: PartialForwardDfa {
                initial_pending: forward.initial_pending,
                initial_terminal: forward.initial_terminal,
                transitions: forward.transitions,
                packed_transitions: Some(packed_transitions),
                start_actions: Vec::new(),
                discovered_states: forward.states,
                complete_rows: forward.states,
                resume_keys: Vec::new(),
            },
            effective_limits,
        }))
    }

    fn selected_end_impl<const EARLIEST: bool, const TRACK_START: bool>(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
        prefix_sets: &[AnchoredByteSet],
        prefix_plan: Option<PartialDfaPrefixPlan>,
    ) -> Result<PartialDfaResult<PartialDfaSelection>, CompileError> {
        let packed_transitions = self.forward.packed_transitions.as_deref().ok_or(
            CompileError::InternalInvariant(
                "partial DFA packed transitions were not canonically regenerated",
            ),
        )?;
        if self.forward.initial_pending && (EARLIEST || self.forward.initial_terminal) {
            return Ok(PartialDfaResult::Complete(PartialDfaSelection {
                end: Some(window_start),
                start: Some(window_start),
            }));
        }

        let tracks_start = TRACK_START
            && self.forward.start_actions.len() == self.forward.transitions.len();
        let mut row = 0_usize;
        let mut position = window_start;
        let mut pending_end = self.forward.initial_pending.then_some(window_start);
        let mut active_start = tracks_start.then_some(window_start);
        let mut pending_start = (tracks_start && self.forward.initial_pending)
            .then_some(window_start);
        while position < window_end {
            if row == 0
                && pending_end.is_none()
                && (!tracks_start || active_start == Some(position))
            {
                if let Some(filter) = prefix_plan {
                    let Some(candidate) =
                        filter.next_candidate(prefix_sets, haystack, position, window_end)
                    else {
                        return Ok(PartialDfaResult::Complete(PartialDfaSelection {
                            end: None,
                            start: None,
                        }));
                    };
                    position = candidate;
                    if tracks_start {
                        active_start = Some(candidate);
                    }
                }
            }
            let byte = *haystack
                .get(position)
                .ok_or(CompileError::InternalInvariant(
                    "partial DFA source position exceeded validated window",
                ))?;
            let index = row
                .checked_add(self.alphabet.class(byte))
                .ok_or(CompileError::InternalInvariant(
                    "partial DFA transition index overflowed",
                ))?;
            let cell = *packed_transitions.get(index).ok_or(
                CompileError::InternalInvariant("partial DFA row is incomplete"),
            )?;
            position = position
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "partial DFA input position overflowed",
                ))?;
            let next_start = if tracks_start {
                match *self.forward.start_actions.get(index).ok_or(
                    CompileError::InternalInvariant(
                        "partial DFA start certificate is incomplete",
                    ),
                )? {
                    ForwardStartAction::Drop => None,
                    ForwardStartAction::Propagate => active_start,
                    ForwardStartAction::Reset => Some(position),
                }
            } else {
                None
            };
            let mut next = cell.0;
            if cell.accepted() {
                pending_end = Some(position);
                pending_start = next_start;
                if EARLIEST {
                    return Ok(PartialDfaResult::Complete(PartialDfaSelection {
                        end: pending_end,
                        start: pending_start,
                    }));
                }
                next &= PARTIAL_CELL_ACCEPTED - 1;
            }
            if next == PARTIAL_CELL_DEAD {
                return Ok(PartialDfaResult::Complete(PartialDfaSelection {
                    end: pending_end,
                    start: pending_start,
                }));
            }
            if next >= PARTIAL_CELL_HOLE_BASE {
                // Entering an incomplete state after consuming the final
                // byte needs no row and therefore no K0 continuation.
                if position == window_end {
                    break;
                }
                let resume_state = usize::try_from(next - PARTIAL_CELL_HOLE_BASE).map_err(|_| {
                    CompileError::InternalInvariant("partial DFA resume state exceeded usize")
                })?;
                let key = self.forward.resume_keys.get(resume_state).ok_or(
                    CompileError::InternalInvariant("partial DFA resume key is absent"),
                )?;
                if key.pending != pending_end.is_some() {
                    return Err(CompileError::InternalInvariant(
                        "partial DFA resume key disagrees with its selected endpoint",
                    ));
                }
                return Ok(PartialDfaResult::Resume(PartialDfaResume {
                    state: resume_state,
                    position,
                    pending_end,
                }));
            }
            row = usize::try_from(next).map_err(|_| {
                CompileError::InternalInvariant("partial DFA row offset exceeded usize")
            })?;
            active_start = next_start;
        }
        Ok(PartialDfaResult::Complete(PartialDfaSelection {
            end: pending_end,
            start: pending_start,
        }))
    }

    pub(crate) fn exists(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
        prefix_sets: &[AnchoredByteSet],
        prefix_plan: Option<PartialDfaPrefixPlan>,
    ) -> Result<PartialDfaResult<bool>, CompileError> {
        Ok(
            match self.selected_end_impl::<true, false>(
                haystack,
                window_start,
                window_end,
                prefix_sets,
                prefix_plan,
            )? {
                PartialDfaResult::Complete(selection) => {
                    PartialDfaResult::Complete(selection.end.is_some())
                }
                PartialDfaResult::Resume(resume) => PartialDfaResult::Resume(resume),
            },
        )
    }

    pub(crate) fn selected_end(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
        prefix_sets: &[AnchoredByteSet],
        prefix_plan: Option<PartialDfaPrefixPlan>,
    ) -> Result<PartialDfaResult<Option<usize>>, CompileError> {
        Ok(match self.selected_end_impl::<false, false>(
            haystack,
            window_start,
            window_end,
            prefix_sets,
            prefix_plan,
        )? {
            PartialDfaResult::Complete(selection) => {
                PartialDfaResult::Complete(selection.end)
            }
            PartialDfaResult::Resume(resume) => PartialDfaResult::Resume(resume),
        })
    }

    pub(crate) fn selected_span_end(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
        prefix_sets: &[AnchoredByteSet],
        prefix_plan: Option<PartialDfaPrefixPlan>,
    ) -> Result<PartialDfaResult<PartialDfaSelection>, CompileError> {
        self.selected_end_impl::<false, true>(
            haystack,
            window_start,
            window_end,
            prefix_sets,
            prefix_plan,
        )
    }

    pub(crate) fn serialized_len(&self) -> Result<usize, CompileError> {
        let cells = self.forward.transitions.len().checked_mul(8).ok_or(
            CompileError::InternalInvariant("partial DFA serialization length overflowed"),
        )?;
        let expected_resume = self
            .forward
            .discovered_states
            .checked_sub(self.forward.complete_rows)
            .ok_or(CompileError::InternalInvariant(
                "partial DFA resume-state count underflowed",
            ))?;
        if self.forward.resume_keys.len() != expected_resume {
            return Err(CompileError::InternalInvariant(
                "partial DFA resume keys do not cover its incomplete suffix",
            ));
        }
        let resume_descriptors = expected_resume.checked_mul(4).ok_or(
            CompileError::InternalInvariant("partial DFA resume descriptor bytes overflowed"),
        )?;
        let resume_items = self.resume_item_count()?.checked_mul(4).ok_or(
            CompileError::InternalInvariant("partial DFA resume item bytes overflowed"),
        )?;
        316_usize
            .checked_add(self.alphabet.representatives.len())
            .and_then(|value| value.checked_add(cells))
            .and_then(|value| value.checked_add(resume_descriptors))
            .and_then(|value| value.checked_add(resume_items))
            .ok_or(CompileError::InternalInvariant(
                "partial DFA serialization length overflowed",
            ))
    }

    pub(crate) fn serialize_into(&self, bytes: &mut Vec<u8>) {
        put_u64(
            bytes,
            u64::try_from(self.effective_limits.max_states).unwrap_or(u64::MAX),
        );
        put_u64(
            bytes,
            u64::try_from(self.effective_limits.max_transitions).unwrap_or(u64::MAX),
        );
        put_u64(bytes, self.effective_limits.max_work);
        put_u32(
            bytes,
            u32::try_from(self.alphabet.classes()).unwrap_or(u32::MAX),
        );
        bytes.extend_from_slice(&self.alphabet.byte_to_class);
        bytes.extend_from_slice(&self.alphabet.representatives);
        put_u32(
            bytes,
            u32::try_from(self.forward.discovered_states).unwrap_or(u32::MAX),
        );
        put_u32(
            bytes,
            u32::try_from(self.forward.complete_rows).unwrap_or(u32::MAX),
        );
        put_u64(
            bytes,
            u64::try_from(self.forward.transitions.len()).unwrap_or(u64::MAX),
        );
        bytes.push(u8::from(self.forward.initial_pending));
        bytes.push(u8::from(self.forward.initial_terminal));
        bytes.extend_from_slice(&[0; 6]);
        put_u64(
            bytes,
            u64::try_from(self.resume_item_count().unwrap_or(usize::MAX)).unwrap_or(u64::MAX),
        );
        for cell in &self.forward.transitions {
            put_u32(bytes, cell.next());
            bytes.push(u8::from(cell.accepted()));
            bytes.extend_from_slice(&[0; 3]);
        }
        for key in &self.forward.resume_keys {
            let length = u32::try_from(key.items.len()).unwrap_or(u32::MAX) & 0x7fff_ffff;
            put_u32(bytes, length | (u32::from(key.pending) << 31));
            for &item in &key.items {
                put_u32(bytes, item);
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the stable partial-table wire shape and cross-field checks stay adjacent"
    )]
    pub(crate) fn deserialize(
        bytes: &[u8],
        construction_classes: (usize, usize),
        boundary_starts: &[bool; 256],
        roles: &[StateRole],
    ) -> Result<Self, ProgramFormatError> {
        let (boundary_classes, graph_classes) = construction_classes;
        let mut reader = DfaReader::new(bytes);
        let effective_limits = DeterminizeLimits {
            max_states: reader.usize_u64("partial DFA state limit is truncated")?,
            max_transitions: reader.usize_u64("partial DFA transition limit is truncated")?,
            max_work: reader.u64("partial DFA work limit is truncated")?,
        };
        if effective_limits.max_states > MAX_STABLE_DFA_STATES
            || effective_limits.max_transitions > MAX_STABLE_DFA_TRANSITIONS
            || effective_limits.max_work > MAX_STABLE_DFA_BUILD_WORK
        {
            return Err(ProgramFormatError::Malformed(
                "partial DFA limits exceed the stable construction bounds",
            ));
        }
        let class_count = usize::try_from(reader.u32("partial DFA class count is truncated")?)
            .map_err(|_| ProgramFormatError::Malformed("partial DFA class count exceeded usize"))?;
        if !(1..=256).contains(&class_count)
            || graph_classes == 0
            || graph_classes > boundary_classes
            || class_count > graph_classes
        {
            return Err(ProgramFormatError::Malformed(
                "partial DFA alphabet width is outside the graph partition",
            ));
        }
        let mut byte_to_class = [0_u8; 256];
        byte_to_class.copy_from_slice(
            reader.take(256, "partial DFA byte-class map is truncated")?,
        );
        if byte_to_class
            .iter()
            .any(|&class| usize::from(class) >= class_count)
        {
            return Err(ProgramFormatError::Malformed(
                "partial DFA byte-class map references an absent class",
            ));
        }
        for ((previous, current), &is_boundary) in byte_to_class
            .iter()
            .zip(byte_to_class.iter().skip(1))
            .zip(boundary_starts.iter().skip(1))
        {
            if current != previous && !is_boundary {
                return Err(ProgramFormatError::Malformed(
                    "partial DFA class map splits a raw byte-range partition",
                ));
            }
        }
        let representatives = reader
            .take(class_count, "partial DFA representatives are truncated")?
            .to_vec();
        let mut next_class = 0usize;
        for (byte, &encoded_class) in byte_to_class.iter().enumerate() {
            let class = usize::from(encoded_class);
            if class == next_class {
                if representatives.get(class).copied() != u8::try_from(byte).ok() {
                    return Err(ProgramFormatError::Malformed(
                        "partial DFA representative is not its class's first byte",
                    ));
                }
                next_class = next_class.checked_add(1).ok_or(
                    ProgramFormatError::Malformed("partial DFA class count overflowed"),
                )?;
            } else if class > next_class {
                return Err(ProgramFormatError::Malformed(
                    "partial DFA classes are not numbered by first occurrence",
                ));
            }
        }
        if next_class != class_count {
            return Err(ProgramFormatError::Malformed(
                "partial DFA class map does not use every declared class",
            ));
        }

        let discovered_states = usize::try_from(
            reader.u32("partial DFA discovered-state count is truncated")?,
        )
        .map_err(|_| ProgramFormatError::Malformed("partial DFA state count exceeded usize"))?;
        let complete_rows = usize::try_from(
            reader.u32("partial DFA complete-row count is truncated")?,
        )
        .map_err(|_| ProgramFormatError::Malformed("partial DFA row count exceeded usize"))?;
        if complete_rows == 0 || complete_rows > discovered_states {
            return Err(ProgramFormatError::Malformed(
                "partial DFA complete rows are outside discovered states",
            ));
        }
        if discovered_states > effective_limits.max_states {
            return Err(ProgramFormatError::Malformed(
                "partial DFA states exceed the recorded construction limit",
            ));
        }
        let reserved_transitions = discovered_states.checked_mul(graph_classes).ok_or(
            ProgramFormatError::Malformed("partial DFA reserved transitions overflowed"),
        )?;
        if reserved_transitions > effective_limits.max_transitions {
            return Err(ProgramFormatError::Malformed(
                "partial DFA states exceed the recorded transition limit",
            ));
        }
        let cell_count = reader.usize_u64("partial DFA cell count is truncated")?;
        let expected_cells = complete_rows.checked_mul(class_count).ok_or(
            ProgramFormatError::Malformed("partial DFA table shape overflowed"),
        )?;
        if cell_count != expected_cells {
            return Err(ProgramFormatError::Malformed(
                "partial DFA cell count does not match complete rows times classes",
            ));
        }
        let initial_pending = reader.boolean("partial DFA initial-pending flag is invalid")?;
        let initial_terminal = reader.boolean("partial DFA initial-terminal flag is invalid")?;
        reader.zeros(6, "partial DFA reserved bytes are non-zero")?;
        if initial_terminal && !initial_pending {
            return Err(ProgramFormatError::Malformed(
                "terminal partial DFA initial state is not pending",
            ));
        }
        let resume_item_count = reader.usize_u64("partial DFA resume item count is truncated")?;
        let resume_state_count = discovered_states.checked_sub(complete_rows).ok_or(
            ProgramFormatError::Malformed("partial DFA resume-state count underflowed"),
        )?;
        let maximum_resume_items = resume_state_count.checked_mul(roles.len()).ok_or(
            ProgramFormatError::Malformed("partial DFA resume item bound overflowed"),
        )?;
        if resume_item_count > maximum_resume_items
            || (resume_state_count == 0) != (resume_item_count == 0)
        {
            return Err(ProgramFormatError::Malformed(
                "partial DFA resume item count is outside its state bound",
            ));
        }
        let cell_bytes = cell_count
            .checked_mul(8)
            .ok_or(ProgramFormatError::Malformed("partial DFA cell bytes overflowed"))?;
        let resume_descriptor_bytes = resume_state_count.checked_mul(4).ok_or(
            ProgramFormatError::Malformed("partial DFA resume descriptors overflowed"),
        )?;
        let resume_item_bytes = resume_item_count.checked_mul(4).ok_or(
            ProgramFormatError::Malformed("partial DFA resume item bytes overflowed"),
        )?;
        let required_bytes = cell_bytes
            .checked_add(resume_descriptor_bytes)
            .and_then(|value| value.checked_add(resume_item_bytes))
            .ok_or(ProgramFormatError::Malformed(
                "partial DFA trailing payload bytes overflowed",
            ))?;
        if required_bytes > reader.remaining() {
            return Err(ProgramFormatError::Malformed(
                "partial DFA cells or resume states exceed the payload extent",
            ));
        }
        let mut transitions = dfa_reserve(cell_count, "partial DFA cell")?;
        for _ in 0..cell_count {
            let next = reader.u32("partial DFA cell is truncated")?;
            if next != NO_STATE
                && usize::try_from(next).map_or(true, |state| state >= discovered_states)
            {
                return Err(ProgramFormatError::Malformed(
                    "partial DFA cell references an undiscovered state",
                ));
            }
            let accepted = reader.boolean("partial DFA accepted flag is invalid")?;
            reader.zeros(3, "partial DFA cell reserved bytes are non-zero")?;
            let cell = forward_cell! { next, accepted };
            transitions.push(cell);
        }
        let mut resume_keys = dfa_reserve(resume_state_count, "partial DFA resume state")?;
        let mut decoded_resume_items = 0usize;
        for _ in 0..resume_state_count {
            let encoded = reader.u32("partial DFA resume descriptor is truncated")?;
            let pending = encoded & (1 << 31) != 0;
            let length = usize::try_from(encoded & 0x7fff_ffff).map_err(|_| {
                ProgramFormatError::Malformed("partial DFA resume length exceeded usize")
            })?;
            if length == 0 {
                return Err(ProgramFormatError::Malformed(
                    "partial DFA resume frontier is empty",
                ));
            }
            decoded_resume_items = decoded_resume_items.checked_add(length).ok_or(
                ProgramFormatError::Malformed("partial DFA resume item count overflowed"),
            )?;
            if decoded_resume_items > resume_item_count {
                return Err(ProgramFormatError::Malformed(
                    "partial DFA resume frontiers exceed their item count",
                ));
            }
            let mut items = dfa_reserve(length, "partial DFA resume item")?;
            for _ in 0..length {
                let item = reader.u32("partial DFA resume item is truncated")?;
                let state = usize::try_from(item).map_err(|_| {
                    ProgramFormatError::Malformed("partial DFA resume item exceeded usize")
                })?;
                if roles.get(state) != Some(&StateRole::Consume) {
                    return Err(ProgramFormatError::Malformed(
                        "partial DFA resume item is not a consuming state",
                    ));
                }
                if items.contains(&item) {
                    return Err(ProgramFormatError::Malformed(
                        "partial DFA resume frontier contains a duplicate state",
                    ));
                }
                items.push(item);
            }
            resume_keys.push(ForwardKey { items, pending });
        }
        if decoded_resume_items != resume_item_count {
            return Err(ProgramFormatError::Malformed(
                "partial DFA resume frontiers do not fill their item count",
            ));
        }
        reader.finish()?;
        Ok(Self {
            alphabet: Alphabet {
                byte_to_class,
                representatives: representatives.into_boxed_slice(),
            },
            forward: PartialForwardDfa {
                initial_pending,
                initial_terminal,
                transitions,
                // Canonical regeneration derives the executable packed table.
                // This decoded object is only a wire witness for
                // `same_wire_payload` and is never published directly.
                packed_transitions: None,
                start_actions: Vec::new(),
                discovered_states,
                complete_rows,
                resume_keys,
            },
            effective_limits,
        })
    }

    pub(crate) fn validate_canonical(
        &self,
        raw: &RawPlan,
        wants_span: bool,
        output: OutputContract,
        replay_order: DfaReplayOrder,
    ) -> Result<Self, ProgramFormatError> {
        // Exists partials may use canonical unordered frontiers. Try that
        // construction first, then the historical ordered construction so
        // pre-specialization stable artifacts remain readable.
        if output == OutputContract::Exists {
            let regenerated = determinize_impl(
                raw,
                false,
                self.effective_limits,
                ForwardSemantics::Exists,
                replay_order,
            )
            .map_err(|_| {
                ProgramFormatError::Malformed(
                    "existential partial DFA canonical regeneration returned an error",
                )
            })?;
            if let DeterminizeOutcome::Declined {
                partial: Some(regenerated),
                ..
            } = regenerated
                && regenerated.same_wire_payload(self)
            {
                return Ok(regenerated);
            }
        }
        let regenerated = determinize_impl(
            raw,
            wants_span,
            self.effective_limits,
            ForwardSemantics::Ordered,
            replay_order,
        )
        .map_err(|_| {
            ProgramFormatError::Malformed("partial DFA canonical regeneration returned an error")
        })?;
        let regenerated = match regenerated {
            DeterminizeOutcome::Complete { .. } => {
                return Err(ProgramFormatError::Malformed(
                    "partial DFA limits canonically produce a complete machine",
                ));
            }
            DeterminizeOutcome::Declined {
                report, partial, ..
            } => {
                if matches!(
                    report.decline,
                    Some(DeterminizationDecline {
                        resource: DeterminizationResource::Allocation { .. },
                        ..
                    })
                ) {
                    return Err(ProgramFormatError::Allocation(
                        "canonical partial DFA regeneration",
                    ));
                }
                partial.ok_or(ProgramFormatError::Malformed(
                    "partial DFA limits canonically retain no complete row",
                ))?
            }
        };
        if !regenerated.same_wire_payload(self) {
            return Err(ProgramFormatError::Malformed(
                "partial DFA payload is not the canonical retained prefix",
            ));
        }
        Ok(regenerated)
    }

    fn same_wire_payload(&self, other: &Self) -> bool {
        self.alphabet == other.alphabet
            && self.effective_limits == other.effective_limits
            && self.forward.initial_pending == other.forward.initial_pending
            && self.forward.initial_terminal == other.forward.initial_terminal
            && self.forward.transitions == other.forward.transitions
            && self.forward.discovered_states == other.forward.discovered_states
            && self.forward.complete_rows == other.forward.complete_rows
            && self.forward.resume_keys == other.forward.resume_keys
    }
}

impl NativeSlowPartial {
    fn from_incomplete_forward(
        alphabet: Alphabet,
        forward: NativeSlowPartialForward,
        boundary_classes: usize,
        graph_classes: usize,
    ) -> Self {
        Self {
            alphabet,
            forward,
            reverse: None,
            reverse_states_before_minimization: 0,
            retained_forward_minimized: false,
            boundary_classes,
            graph_classes,
        }
    }

    fn from_complete_forward(
        alphabet: Alphabet,
        forward: ForwardDfa,
        reverse: Option<ReverseDfa>,
        boundary_classes: usize,
        graph_classes: usize,
        states_before_minimization: usize,
        reverse_states_before_minimization: usize,
        retained_forward_minimized: bool,
    ) -> Self {
        let states = forward.states;
        Self {
            alphabet,
            forward: NativeSlowPartialForward {
                initial_pending: forward.initial_pending,
                initial_terminal: forward.initial_terminal,
                transitions: forward.transitions,
                complete_rows: states,
                discovered_states: states,
                states_before_minimization,
                states: Vec::new(),
            },
            reverse,
            reverse_states_before_minimization,
            retained_forward_minimized,
            boundary_classes,
            graph_classes,
        }
    }

    /// Return the shortest input length that can enter an incomplete row.
    ///
    /// The retained slow prefix owns subset states in FIFO discovery order,
    /// so a level scan over its numeric state intervals is an allocation-free
    /// breadth-first search. A hole reached after consuming byte `h` is not
    /// observable on an input of length `h`: the native executor finishes at
    /// the window boundary before asking for the missing row. It first needs
    /// a continuation on length `h + 1`.
    ///
    /// Exists accepts immediately and therefore does not observe the
    /// successor of an accepting transition. Endpoint contracts retain the
    /// selected endpoint and continue through that successor, so the same
    /// edge remains observable for `SelectedEnd` and `Span`.
    pub(crate) fn first_observable_hole_bytes(
        &self,
        output: OutputContract,
    ) -> Result<Option<usize>, CompileError> {
        let classes = self.alphabet.classes();
        let complete = self.forward.complete_rows;
        let discovered = self.forward.discovered_states;
        if classes == 0 || classes > 256 {
            return Err(CompileError::InternalInvariant(
                "slow partial DFA alphabet is outside 1..=256",
            ));
        }
        if complete == 0 || complete > discovered {
            return Err(CompileError::InternalInvariant(
                "slow partial DFA retained dimensions are invalid",
            ));
        }
        let expected_cells = complete.checked_mul(classes).ok_or(
            CompileError::InternalInvariant("slow partial DFA table extent overflowed"),
        )?;
        if self.forward.transitions.len() != expected_cells {
            return Err(CompileError::InternalInvariant(
                "slow partial DFA table extent is inconsistent",
            ));
        }
        if self.forward.initial_terminal && !self.forward.initial_pending {
            return Err(CompileError::InternalInvariant(
                "slow partial DFA initial terminal has no pending endpoint",
            ));
        }
        for cell in self.forward.transitions.iter().copied() {
            let next = cell.next();
            if next != NO_STATE
                && usize::try_from(next)
                    .ok()
                    .is_none_or(|state| state >= discovered)
            {
                return Err(CompileError::InternalInvariant(
                    "slow partial DFA transition exceeds discovered states",
                ));
            }
        }

        // A later-stage resource decline can retain a complete forward
        // machine in this owner. It has no continuation hole and deliberately
        // carries no discovery keys.
        if complete == discovered {
            return Ok(None);
        }
        if self.forward.states.len() != discovered {
            return Err(CompileError::InternalInvariant(
                "slow partial DFA discovery keys are incomplete",
            ));
        }
        if (output == OutputContract::Exists && self.forward.initial_pending)
            || (output != OutputContract::Exists && self.forward.initial_terminal)
        {
            return Ok(None);
        }

        let mut level_start = 0usize;
        let mut level_end = 1usize;
        let mut depth = 0usize;
        loop {
            let mut next_level_end = level_end;
            for state in level_start..level_end {
                let row = state.checked_mul(classes).ok_or(
                    CompileError::InternalInvariant("slow partial DFA row offset overflowed"),
                )?;
                for class in 0..classes {
                    let index = row.checked_add(class).ok_or(
                        CompileError::InternalInvariant("slow partial DFA cell offset overflowed"),
                    )?;
                    let cell = *self.forward.transitions.get(index).ok_or(
                        CompileError::InternalInvariant("slow partial DFA row is absent"),
                    )?;
                    if output == OutputContract::Exists && cell.accepted() {
                        continue;
                    }
                    let next = cell.next();
                    if next == NO_STATE {
                        continue;
                    }
                    let next = usize::try_from(next).map_err(|_| {
                        CompileError::InternalInvariant(
                            "slow partial DFA destination exceeded usize",
                        )
                    })?;
                    if next >= complete {
                        return depth.checked_add(1).map(Some).ok_or(
                            CompileError::InternalInvariant(
                                "slow partial DFA hole depth overflowed",
                            ),
                        );
                    }
                    let after_next = next.checked_add(1).ok_or(
                        CompileError::InternalInvariant(
                            "slow partial DFA level boundary overflowed",
                        ),
                    )?;
                    next_level_end = next_level_end.max(after_next);
                }
            }
            if next_level_end == level_end {
                return Ok(None);
            }
            level_start = level_end;
            level_end = next_level_end;
            depth = depth.checked_add(1).ok_or(CompileError::InternalInvariant(
                "slow partial DFA BFS depth overflowed",
            ))?;
        }
    }

    pub(crate) fn native_view(&self) -> NativeDfaView<'_> {
        NativeDfaView {
            initial_state: 0,
            initial_pending: self.forward.initial_pending,
            initial_terminal: self.forward.initial_terminal,
            byte_classes: &self.alphabet.byte_to_class,
            class_count: self.alphabet.classes(),
            class_representatives: &self.alphabet.representatives,
            forward_cells: &self.forward.transitions,
            reverse_initial: self.reverse.as_ref().map(|_| 0),
            reverse_cells: self
                .reverse
                .as_ref()
                .map_or(&[], |reverse| reverse.transitions.as_ref()),
        }
    }

    pub(crate) const fn retained_dimensions(&self) -> (usize, usize) {
        (self.forward.complete_rows, self.forward.discovered_states)
    }

    pub(crate) fn resume_frontiers(
        &self,
    ) -> Option<impl ExactSizeIterator<Item = (&[u32], bool)>> {
        let keys = self
            .forward
            .states
            .get(self.forward.complete_rows..self.forward.discovered_states)?;
        (!keys.is_empty()).then(|| {
            keys.iter()
                .map(|key| (key.items.as_slice(), key.pending))
        })
    }

    pub(crate) fn resume_item_count(&self) -> Option<usize> {
        self.resume_frontiers()?.try_fold(0usize, |total, (items, _)| {
            total.checked_add(items.len())
        })
    }

    pub(crate) const fn retained_forward_minimized(&self) -> bool {
        self.retained_forward_minimized
    }

    pub(crate) fn stats(&self, build_work: u64) -> DfaStats {
        DfaStats {
            boundary_classes: self.boundary_classes,
            graph_classes: self.graph_classes,
            alphabet_classes: self.alphabet.classes(),
            forward_states_before_minimization: self.forward.states_before_minimization,
            forward_states: self.forward.complete_rows,
            forward_transitions: self.forward.transitions.len(),
            reverse_states_before_minimization: self.reverse_states_before_minimization,
            reverse_states: self.reverse.as_ref().map_or(0, |reverse| reverse.states),
            reverse_transitions: self
                .reverse
                .as_ref()
                .map_or(0, |reverse| reverse.transitions.len()),
            build_work,
        }
    }
}

impl OrderedDfa {
    pub(crate) const fn replay_order(&self) -> DfaReplayOrder {
        if self.stats.build_work & ESTIMATED_FREQUENCY_REPLAY_WORK_TAG != 0 {
            DfaReplayOrder::DescendingEstimatedClassFrequency
        } else if self.stats.build_work & CLASS_MASS_REPLAY_WORK_TAG != 0 {
            DfaReplayOrder::DescendingClassMass
        } else {
            DfaReplayOrder::Fifo
        }
    }

    pub(crate) const fn stats(&self) -> DfaStats {
        let mut stats = self.stats;
        stats.build_work &= !DFA_REPLAY_WORK_TAG_MASK;
        stats
    }

    #[allow(dead_code, reason = "structural handoff for native code generation")]
    pub(crate) fn native_view(&self) -> NativeDfaView<'_> {
        NativeDfaView {
            initial_state: 0,
            initial_pending: self.forward.initial_pending,
            initial_terminal: self.forward.initial_terminal,
            byte_classes: &self.alphabet.byte_to_class,
            class_count: self.alphabet.classes(),
            class_representatives: &self.alphabet.representatives,
            forward_cells: &self.forward.transitions,
            reverse_initial: self.reverse.as_ref().map(|_| 0),
            reverse_cells: self
                .reverse
                .as_ref()
                .map_or(&[], |reverse| reverse.transitions.as_ref()),
        }
    }

    pub(crate) fn exists(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
    ) -> Result<bool, CompileError> {
        Ok(self
            .selected_end_impl(haystack, window_start, window_end, true)?
            .is_some())
    }

    pub(crate) fn selected_end(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
    ) -> Result<Option<usize>, CompileError> {
        self.selected_end_impl(haystack, window_start, window_end, false)
    }

    pub(crate) fn span(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
    ) -> Result<Option<SelectedMatch>, CompileError> {
        let Some(end) = self.selected_end_impl(haystack, window_start, window_end, false)? else {
            return Ok(None);
        };
        if self.forward.initial_pending {
            return Ok(Some(SelectedMatch {
                start: window_start,
                end,
            }));
        }
        let reverse = self
            .reverse
            .as_ref()
            .ok_or(CompileError::InternalInvariant(
                "span DFA has no reverse machine",
            ))?;
        let start = self
            .recover_start(reverse, haystack, window_start, end)?
            .ok_or(CompileError::InternalInvariant(
                "reverse DFA could not recover a forward-selected match",
            ))?;
        Ok(Some(SelectedMatch { start, end }))
    }

    fn selected_end_impl(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
        earliest: bool,
    ) -> Result<Option<usize>, CompileError> {
        if self.forward.initial_pending && (earliest || self.forward.initial_terminal) {
            return Ok(Some(window_start));
        }

        let classes = self.alphabet.classes();
        let mut state = 0_u32;
        let mut position = window_start;
        let mut pending_end = self.forward.initial_pending.then_some(window_start);
        while position < window_end {
            let byte = *haystack
                .get(position)
                .ok_or(CompileError::InternalInvariant(
                    "DFA source position exceeded validated window",
                ))?;
            let cell = self
                .forward
                .cell(state, self.alphabet.class(byte), classes)
                .ok_or(CompileError::InternalInvariant(
                    "DFA transition is outside the complete table",
                ))?;
            position = position
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "DFA input position overflowed",
                ))?;
            if cell.accepted() {
                pending_end = Some(position);
                if earliest {
                    return Ok(pending_end);
                }
            }
            if cell.next() == NO_STATE {
                return Ok(pending_end);
            }
            state = cell.next();
        }
        Ok(pending_end)
    }

    fn recover_start(
        &self,
        reverse: &ReverseDfa,
        haystack: &[u8],
        window_start: usize,
        selected_end: usize,
    ) -> Result<Option<usize>, CompileError> {
        let classes = self.alphabet.classes();
        let mut state = 0_u32;
        let mut cursor = selected_end;
        let mut candidate = None;
        while cursor > window_start {
            let source = cursor
                .checked_sub(1)
                .ok_or(CompileError::InternalInvariant(
                    "reverse DFA cursor underflowed",
                ))?;
            let byte = *haystack.get(source).ok_or(CompileError::InternalInvariant(
                "reverse DFA source exceeded validated window",
            ))?;
            let cell = reverse
                .cell(state, self.alphabet.class(byte), classes)
                .ok_or(CompileError::InternalInvariant(
                    "reverse DFA transition is outside the complete table",
                ))?;
            cursor = source;
            if cell.reaches_start() {
                // Execution moves right-to-left, so replacing the candidate
                // retains the earliest start that reaches the selected end.
                candidate = Some(cursor);
            }
            if cell.next() == NO_STATE {
                break;
            }
            state = cell.next();
        }
        Ok(candidate)
    }

    pub(crate) fn serialized_len(&self) -> Result<usize, CompileError> {
        let alphabet = 12_usize
            .checked_add(256)
            .and_then(|value| value.checked_add(self.alphabet.representatives.len()))
            .ok_or(CompileError::InternalInvariant(
                "DFA alphabet serialization length overflowed",
            ))?;
        let forward_cells = self.forward.transitions.len().checked_mul(8).ok_or(
            CompileError::InternalInvariant("forward DFA serialization length overflowed"),
        )?;
        let forward =
            20_usize
                .checked_add(forward_cells)
                .ok_or(CompileError::InternalInvariant(
                    "forward DFA serialization length overflowed",
                ))?;
        let reverse_cells = self
            .reverse
            .as_ref()
            .map_or(0, |reverse| reverse.transitions.len())
            .checked_mul(8)
            .ok_or(CompileError::InternalInvariant(
                "reverse DFA serialization length overflowed",
            ))?;
        let reverse =
            20_usize
                .checked_add(reverse_cells)
                .ok_or(CompileError::InternalInvariant(
                    "reverse DFA serialization length overflowed",
                ))?;
        alphabet
            .checked_add(forward)
            .and_then(|value| value.checked_add(reverse))
            .ok_or(CompileError::InternalInvariant(
                "DFA serialization length overflowed",
            ))
    }

    pub(crate) fn serialize_into(&self, bytes: &mut Vec<u8>) {
        put_u64(bytes, self.stats().build_work);
        put_u32(
            bytes,
            u32::try_from(self.alphabet.classes()).unwrap_or(u32::MAX),
        );
        bytes.extend_from_slice(&self.alphabet.byte_to_class);
        bytes.extend_from_slice(&self.alphabet.representatives);

        put_u32(
            bytes,
            u32::try_from(self.forward.states).unwrap_or(u32::MAX),
        );
        put_u64(
            bytes,
            u64::try_from(self.forward.transitions.len()).unwrap_or(u64::MAX),
        );
        bytes.push(u8::from(self.forward.initial_pending));
        bytes.push(u8::from(self.forward.initial_terminal));
        bytes.extend_from_slice(&[0; 2]);
        put_u32(
            bytes,
            u32::try_from(self.stats.forward_states_before_minimization).unwrap_or(u32::MAX),
        );
        for cell in &self.forward.transitions {
            put_u32(bytes, cell.next());
            bytes.push(u8::from(cell.accepted()));
            bytes.extend_from_slice(&[0; 3]);
        }

        let (states, transitions) = self.reverse.as_ref().map_or((0_usize, &[][..]), |reverse| {
            (reverse.states, reverse.transitions.as_ref())
        });
        put_u32(bytes, u32::try_from(states).unwrap_or(u32::MAX));
        put_u64(bytes, u64::try_from(transitions.len()).unwrap_or(u64::MAX));
        bytes.push(u8::from(self.reverse.is_some()));
        bytes.extend_from_slice(&[0; 3]);
        put_u32(
            bytes,
            u32::try_from(self.stats.reverse_states_before_minimization).unwrap_or(u32::MAX),
        );
        for cell in transitions {
            put_u32(bytes, cell.next());
            bytes.push(u8::from(cell.reaches_start()));
            bytes.extend_from_slice(&[0; 3]);
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the stable DFA wire order and its cross-field checks stay in one auditable decoder"
    )]
    pub(crate) fn deserialize(
        bytes: &[u8],
        output: OutputContract,
        exact_match_width: Option<usize>,
        construction_classes: (usize, usize),
        boundary_starts: &[bool; 256],
        replay_order: DfaReplayOrder,
    ) -> Result<Self, ProgramFormatError> {
        let (boundary_classes, graph_classes) = construction_classes;
        let mut reader = DfaReader::new(bytes);
        let build_work = reader.u64("DFA canonical build-work field is truncated")?;
        if build_work == 0 || build_work > MAX_STABLE_DFA_BUILD_WORK {
            return Err(ProgramFormatError::Malformed(
                "DFA canonical build work exceeds the stable bounds",
            ));
        }
        let class_count = usize::try_from(reader.u32("DFA class count is truncated")?)
            .map_err(|_| ProgramFormatError::Malformed("DFA class count exceeded usize"))?;
        if !(1..=256).contains(&class_count) {
            return Err(ProgramFormatError::Malformed(
                "DFA class count is outside 1..=256",
            ));
        }
        if graph_classes == 0 || graph_classes > boundary_classes {
            return Err(ProgramFormatError::Malformed(
                "DFA graph alphabet width is outside the boundary partition",
            ));
        }
        if class_count > graph_classes {
            return Err(ProgramFormatError::Malformed(
                "DFA has more classes than the graph alphabet partition",
            ));
        }
        let class_bytes = reader.take(256, "DFA byte-class map is truncated")?;
        let mut byte_to_class = [0_u8; 256];
        byte_to_class.copy_from_slice(class_bytes);
        if byte_to_class
            .iter()
            .any(|&class| usize::from(class) >= class_count)
        {
            return Err(ProgramFormatError::Malformed(
                "DFA byte-class map references an absent class",
            ));
        }
        for ((previous, current), &is_boundary) in byte_to_class
            .iter()
            .zip(byte_to_class.iter().skip(1))
            .zip(boundary_starts.iter().skip(1))
        {
            if current != previous && !is_boundary {
                return Err(ProgramFormatError::Malformed(
                    "DFA class map splits a raw byte-range partition",
                ));
            }
        }
        let representatives = reader
            .take(class_count, "DFA representatives are truncated")?
            .to_vec();
        let mut next_class = 0usize;
        for (byte, &encoded_class) in byte_to_class.iter().enumerate() {
            let class = usize::from(encoded_class);
            if class == next_class {
                if representatives.get(class).copied() != u8::try_from(byte).ok() {
                    return Err(ProgramFormatError::Malformed(
                        "DFA representative is not its class's first byte",
                    ));
                }
                next_class = next_class
                    .checked_add(1)
                    .ok_or(ProgramFormatError::Malformed(
                        "DFA canonical class count overflowed",
                    ))?;
            } else if class > next_class {
                return Err(ProgramFormatError::Malformed(
                    "DFA classes are not numbered by first occurrence",
                ));
            }
        }
        if next_class != class_count {
            return Err(ProgramFormatError::Malformed(
                "DFA class map does not use every declared class",
            ));
        }

        let forward_states =
            usize::try_from(reader.u32("forward DFA state count is truncated")?)
                .map_err(|_| ProgramFormatError::Malformed("forward state count exceeded usize"))?;
        if forward_states == 0 {
            return Err(ProgramFormatError::Malformed(
                "forward DFA has no initial state",
            ));
        }
        let forward_cell_count = reader.usize_u64("forward DFA cell count is truncated")?;
        let expected_forward =
            forward_states
                .checked_mul(class_count)
                .ok_or(ProgramFormatError::Malformed(
                    "forward DFA table shape overflowed",
                ))?;
        if forward_cell_count != expected_forward {
            return Err(ProgramFormatError::Malformed(
                "forward DFA cell count does not match states times classes",
            ));
        }
        let initial_pending = reader.boolean("forward initial-pending flag is invalid")?;
        let initial_terminal = reader.boolean("forward initial-terminal flag is invalid")?;
        reader.zeros(2, "forward DFA reserved bytes are non-zero")?;
        if initial_terminal && !initial_pending {
            return Err(ProgramFormatError::Malformed(
                "terminal forward initial state is not pending",
            ));
        }
        let forward_states_before_minimization =
            usize::try_from(reader.u32("forward pre-minimization state count is truncated")?)
                .map_err(|_| {
                    ProgramFormatError::Malformed(
                        "forward pre-minimization state count exceeded usize",
                    )
                })?;
        if forward_states_before_minimization < forward_states {
            return Err(ProgramFormatError::Malformed(
                "forward pre-minimization state count is smaller than the minimized machine",
            ));
        }
        let forward_cell_bytes =
            forward_cell_count
                .checked_mul(8)
                .ok_or(ProgramFormatError::Malformed(
                    "forward DFA cell byte count overflowed",
                ))?;
        if forward_cell_bytes > reader.remaining().saturating_sub(20) {
            return Err(ProgramFormatError::Malformed(
                "forward DFA cells exceed the payload extent",
            ));
        }
        let mut forward_cells = dfa_reserve(forward_cell_count, "forward DFA cell")?;
        for _ in 0..forward_cell_count {
            let next = reader.u32("forward DFA cell is truncated")?;
            if next != NO_STATE
                && usize::try_from(next).map_or(true, |state| state >= forward_states)
            {
                return Err(ProgramFormatError::Malformed(
                    "forward DFA cell references an absent state",
                ));
            }
            let accepted = reader.boolean("forward DFA accepted flag is invalid")?;
            reader.zeros(3, "forward DFA cell reserved bytes are non-zero")?;
            forward_cells.push(forward_cell! { next, accepted });
        }

        let reverse_states =
            usize::try_from(reader.u32("reverse DFA state count is truncated")?)
                .map_err(|_| ProgramFormatError::Malformed("reverse state count exceeded usize"))?;
        let reverse_cell_count = reader.usize_u64("reverse DFA cell count is truncated")?;
        let reverse_present = reader.boolean("reverse DFA presence flag is invalid")?;
        reader.zeros(3, "reverse DFA reserved bytes are non-zero")?;
        let reverse_states_before_minimization =
            usize::try_from(reader.u32("reverse pre-minimization state count is truncated")?)
                .map_err(|_| {
                    ProgramFormatError::Malformed(
                        "reverse pre-minimization state count exceeded usize",
                    )
                })?;
        let reverse = if reverse_present {
            if reverse_states == 0 {
                return Err(ProgramFormatError::Malformed(
                    "present reverse DFA has no initial state",
                ));
            }
            if reverse_states_before_minimization < reverse_states {
                return Err(ProgramFormatError::Malformed(
                    "reverse pre-minimization state count is smaller than the minimized machine",
                ));
            }
            let expected_reverse =
                reverse_states
                    .checked_mul(class_count)
                    .ok_or(ProgramFormatError::Malformed(
                        "reverse DFA table shape overflowed",
                    ))?;
            if reverse_cell_count != expected_reverse {
                return Err(ProgramFormatError::Malformed(
                    "reverse DFA cell count does not match states times classes",
                ));
            }
            let reverse_cell_bytes =
                reverse_cell_count
                    .checked_mul(8)
                    .ok_or(ProgramFormatError::Malformed(
                        "reverse DFA cell byte count overflowed",
                    ))?;
            if reverse_cell_bytes > reader.remaining() {
                return Err(ProgramFormatError::Malformed(
                    "reverse DFA cells exceed the payload extent",
                ));
            }
            let mut reverse_cells = dfa_reserve(reverse_cell_count, "reverse DFA cell")?;
            for _ in 0..reverse_cell_count {
                let next = reader.u32("reverse DFA cell is truncated")?;
                if next != NO_STATE
                    && usize::try_from(next).map_or(true, |state| state >= reverse_states)
                {
                    return Err(ProgramFormatError::Malformed(
                        "reverse DFA cell references an absent state",
                    ));
                }
                let reaches_start = reader.boolean("reverse DFA reaches-start flag is invalid")?;
                reader.zeros(3, "reverse DFA cell reserved bytes are non-zero")?;
                reverse_cells.push(reverse_cell! {
                    next,
                    reaches_start,
                });
            }
            Some(ReverseDfa {
                transitions: reverse_cells,
                states: reverse_states,
            })
        } else {
            if reverse_states != 0
                || reverse_cell_count != 0
                || reverse_states_before_minimization != 0
            {
                return Err(ProgramFormatError::Malformed(
                    "absent reverse DFA has non-zero dimensions",
                ));
            }
            None
        };
        let reverse_allowed = output == OutputContract::Span && !initial_pending;
        let reverse_required = reverse_allowed && exact_match_width.is_none();
        if reverse_required && reverse.is_none() || !reverse_allowed && reverse.is_some() {
            return Err(ProgramFormatError::Malformed(
                "reverse DFA presence does not match the output contract",
            ));
        }
        let construction_states = forward_states_before_minimization
            .checked_add(reverse_states_before_minimization)
            .ok_or(ProgramFormatError::Malformed(
                "pre-minimization DFA state count overflowed",
            ))?;
        let construction_transitions =
            construction_states
                .checked_mul(graph_classes)
                .ok_or(ProgramFormatError::Malformed(
                    "pre-minimization DFA transition count overflowed",
                ))?;
        let construction_states_work = u64::try_from(construction_states).map_err(|_| {
            ProgramFormatError::Malformed(
                "pre-minimization DFA state count exceeded the work representation",
            )
        })?;
        let construction_transitions_work =
            u64::try_from(construction_transitions).map_err(|_| {
                ProgramFormatError::Malformed(
                    "pre-minimization DFA transition count exceeded the work representation",
                )
            })?;
        if construction_states_work > build_work || construction_transitions_work > build_work {
            return Err(ProgramFormatError::Malformed(
                "pre-minimization DFA dimensions exceed the declared work bound",
            ));
        }
        reader.finish()?;

        Ok(Self {
            alphabet: Alphabet {
                byte_to_class,
                representatives: representatives.into_boxed_slice(),
            },
            forward: ForwardDfa {
                initial_pending,
                initial_terminal,
                transitions: forward_cells,
                states: forward_states,
            },
            reverse,
            stats: DfaStats {
                boundary_classes,
                graph_classes,
                alphabet_classes: class_count,
                forward_states_before_minimization,
                forward_states,
                forward_transitions: forward_cell_count,
                reverse_states_before_minimization,
                reverse_states,
                reverse_transitions: reverse_cell_count,
                build_work: build_work | dfa_replay_work_tag(replay_order),
            },
        })
    }

    pub(crate) fn validate_canonical(
        &self,
        raw: &RawPlan,
        output: OutputContract,
        replay_order: DfaReplayOrder,
    ) -> Result<(), ProgramFormatError> {
        let max_states = self
            .stats
            .forward_states_before_minimization
            .checked_add(self.stats.reverse_states_before_minimization)
            .ok_or(ProgramFormatError::Malformed(
                "DFA canonical state bound overflowed",
            ))?;
        // Construction reserves transition budget after graph-signature
        // coalescing and before whole-machine column coalescing.
        let max_transitions = max_states.checked_mul(self.stats.graph_classes).ok_or(
            ProgramFormatError::Malformed("DFA canonical transition bound overflowed"),
        )?;
        let limits = DeterminizeLimits {
            max_states,
            max_transitions,
            max_work: self.stats().build_work,
        };
        // Exists artifacts use unordered semantic subsets. Endpoint-rescued
        // artifacts use the separately proved pruned semantics. The enclosing
        // program version selects exactly one class replay order; only the
        // historical ordered semantic construction is tried as a second
        // semantic identity under that same replay order.
        if output == OutputContract::Exists {
            let regenerated = determinize_impl(
                raw,
                false,
                limits,
                ForwardSemantics::Exists,
                replay_order,
            )
            .map_err(|_| {
                ProgramFormatError::Malformed(
                    "existential DFA canonical regeneration returned an error",
                )
            })?;
            if matches!(
                regenerated,
                DeterminizeOutcome::Complete { ref machine, .. } if machine == self
            ) {
                return Ok(());
            }
        } else {
            let regenerated = determinize_impl(
                raw,
                self.reverse.is_some(),
                limits,
                ForwardSemantics::EndpointPruned,
                replay_order,
            )
            .map_err(|_| {
                ProgramFormatError::Malformed(
                    "endpoint-pruned DFA canonical regeneration returned an error",
                )
            })?;
            if matches!(
                regenerated,
                DeterminizeOutcome::Complete { ref machine, .. } if machine == self
            ) {
                return Ok(());
            }
        }
        let regenerated = determinize_impl(
            raw,
            self.reverse.is_some(),
            limits,
            ForwardSemantics::Ordered,
            replay_order,
        )
        .map_err(|_| {
            ProgramFormatError::Malformed("DFA canonical regeneration returned an error")
        })?;
        let regenerated = match regenerated {
            DeterminizeOutcome::Complete { machine, .. } => machine,
            DeterminizeOutcome::Declined { report, .. } => {
                if matches!(
                    report.decline,
                    Some(DeterminizationDecline {
                        resource: DeterminizationResource::Allocation { .. },
                        ..
                    })
                ) {
                    return Err(ProgramFormatError::Allocation("canonical DFA regeneration"));
                }
                return Err(ProgramFormatError::Malformed(
                    "DFA canonical regeneration exceeded its declared bounds",
                ));
            }
        };
        if regenerated != *self {
            return Err(ProgramFormatError::Malformed(
                "DFA payload is not the canonical machine for its raw plan",
            ));
        }
        Ok(())
    }
}

struct DfaReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> DfaReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(
        &mut self,
        length: usize,
        truncated: &'static str,
    ) -> Result<&'a [u8], ProgramFormatError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ProgramFormatError::Malformed("DFA offset overflowed"))?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ProgramFormatError::Malformed(truncated))?;
        self.cursor = end;
        Ok(value)
    }

    fn u32(&mut self, truncated: &'static str) -> Result<u32, ProgramFormatError> {
        Ok(u32::from_le_bytes(
            self.take(4, truncated)?
                .try_into()
                .map_err(|_| ProgramFormatError::Malformed(truncated))?,
        ))
    }

    fn usize_u64(&mut self, truncated: &'static str) -> Result<usize, ProgramFormatError> {
        usize::try_from(self.u64(truncated)?)
            .map_err(|_| ProgramFormatError::Malformed("DFA dimension exceeded usize"))
    }

    fn u64(&mut self, truncated: &'static str) -> Result<u64, ProgramFormatError> {
        Ok(u64::from_le_bytes(
            self.take(8, truncated)?
                .try_into()
                .map_err(|_| ProgramFormatError::Malformed(truncated))?,
        ))
    }

    fn boolean(&mut self, malformed: &'static str) -> Result<bool, ProgramFormatError> {
        match self.take(1, malformed)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProgramFormatError::Malformed(malformed)),
        }
    }

    fn zeros(&mut self, length: usize, malformed: &'static str) -> Result<(), ProgramFormatError> {
        if self.take(length, malformed)?.iter().any(|&byte| byte != 0) {
            return Err(ProgramFormatError::Malformed(malformed));
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), ProgramFormatError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(ProgramFormatError::Malformed(
                "trailing bytes follow the DFA",
            ))
        }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }
}

fn dfa_reserve<T>(capacity: usize, table: &'static str) -> Result<Vec<T>, ProgramFormatError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| ProgramFormatError::Allocation(table))?;
    Ok(values)
}

fn build_vec<T>(capacity: usize, budget: &mut BuildBudget) -> Option<Vec<T>> {
    if !budget.charge_allocation::<T>(capacity) {
        return None;
    }
    let mut values = Vec::new();
    if values.try_reserve_exact(capacity).is_err() {
        budget.allocation::<T>(capacity);
        return None;
    }
    Some(values)
}

fn ensure_vec_capacity<T>(values: &mut Vec<T>, capacity: usize, budget: &mut BuildBudget) -> bool {
    if values.capacity() >= capacity {
        return true;
    }
    let reserve_capacity = if budget.allocation_ledger.is_some() {
        values
            .capacity()
            .saturating_mul(2)
            .max(capacity)
            .max(4)
    } else {
        capacity
    };
    // A reallocating allocator may keep the complete old buffer live while
    // reserving its replacement. Charging every full prospective capacity,
    // combined with geometric slow-path growth, bounds that transient peak
    // without quadratic accounting for one-element worklist expansion.
    if !budget.charge_allocation::<T>(reserve_capacity) {
        return false;
    }
    let additional = reserve_capacity.saturating_sub(values.len());
    if values.try_reserve_exact(additional).is_err() {
        budget.allocation::<T>(capacity);
        return false;
    }
    true
}

fn clone_u32s(values: &[u32], budget: &mut BuildBudget) -> Option<Vec<u32>> {
    let mut cloned = build_vec(values.len(), budget)?;
    cloned.extend_from_slice(values);
    Some(cloned)
}

fn clone_forward_key(key: &ForwardKey, budget: &mut BuildBudget) -> Option<ForwardKey> {
    Some(ForwardKey {
        items: clone_u32s(&key.items, budget)?,
        pending: key.pending,
    })
}

fn clone_reverse_key(key: &ReverseKey, budget: &mut BuildBudget) -> Option<ReverseKey> {
    Some(ReverseKey(clone_u32s(&key.0, budget)?))
}

struct StableFnvHasher(u64);

impl Default for StableFnvHasher {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for StableFnvHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = self.0;
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.0 = hash;
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

type StableMap<K, V> = HashMap<K, V, BuildHasherDefault<StableFnvHasher>>;

fn build_map<K: Eq + Hash, V>(
    capacity: usize,
    budget: &mut BuildBudget,
) -> Option<StableMap<K, V>> {
    // Hash tables allocate a minimum bucket group even for one requested
    // entry. Keep the slow path's initial policy consistent with geometric
    // growth so the conservative table charge cannot undercount that group.
    let reserve_capacity = if budget.allocation_ledger.is_some() {
        capacity.max(4)
    } else {
        capacity
    };
    if !budget.charge_map_allocation::<K, V>(reserve_capacity) {
        return None;
    }
    let mut values = StableMap::default();
    if values.try_reserve(reserve_capacity).is_err() {
        budget.allocation::<(K, V)>(reserve_capacity);
        return None;
    }
    Some(values)
}

fn reserve_map<K: Eq + Hash, V>(
    values: &mut StableMap<K, V>,
    additional: usize,
    budget: &mut BuildBudget,
) -> bool {
    let Some(required) = values.len().checked_add(additional) else {
        budget.allocation::<(K, V)>(usize::MAX);
        return false;
    };
    if values.capacity() >= required {
        return true;
    }
    let reserve_capacity = if budget.allocation_ledger.is_some() {
        values
            .capacity()
            .saturating_mul(2)
            .max(required)
            .max(4)
    } else {
        required
    };
    if !budget.charge_map_allocation::<K, V>(reserve_capacity) {
        return false;
    }
    let reserve_additional = reserve_capacity.saturating_sub(values.len());
    if values.try_reserve(reserve_additional).is_err() {
        budget.allocation::<(K, V)>(reserve_capacity);
        return false;
    }
    true
}

#[allow(
    clippy::large_enum_variant,
    reason = "keeping the graph inline avoids an infallible allocation on the determinizer path"
)]
pub(crate) enum DeterminizeOutcome {
    Complete {
        machine: OrderedDfa,
        report: DeterminizationReport,
    },
    Declined {
        report: DeterminizationReport,
        partial: Option<PartialDfa>,
        native_slow_partial: Option<NativeSlowPartial>,
    },
}

impl DeterminizeOutcome {
    fn from_budget(
        machine: Option<OrderedDfa>,
        partial: Option<PartialDfa>,
        native_slow_partial: Option<NativeSlowPartial>,
        budget: BuildBudget,
    ) -> Self {
        // Allocation refusal is environmental rather than a canonical
        // consequence of the recorded numeric limits. Retaining such a table
        // would make strict replay depend on allocator history, so only
        // state/transition/work refusals publish a stable partial machine or
        // a transient native-only completed-row prefix.
        let allocation_declined = matches!(
            budget.decline,
            Some(DeterminizationDecline {
                resource: DeterminizationResource::Allocation { .. },
                ..
            })
        );
        let partial = (!allocation_declined).then_some(partial).flatten();
        let native_slow_partial = (!allocation_declined)
            .then_some(native_slow_partial)
            .flatten();
        let report = budget.into_report();
        match machine {
            Some(machine) => Self::Complete { machine, report },
            None => Self::Declined {
                report,
                partial,
                native_slow_partial,
            },
        }
    }

    const fn work_completed(&self) -> u64 {
        match self {
            Self::Complete { report, .. } | Self::Declined { report, .. } => {
                report.work_completed
            }
        }
    }

    fn account_prior_attempt(
        &mut self,
        prior_work: u64,
        requested_limits: DeterminizeLimits,
    ) -> Result<(), CompileError> {
        let effective_limits = requested_limits.effective_for_stable_artifact();
        let report = match self {
            Self::Complete { report, .. } => report,
            Self::Declined {
                report,
                partial,
                ..
            } => {
                if let Some(partial) = partial {
                    partial.effective_limits = effective_limits;
                }
                report
            }
        };
        report.requested_limits = requested_limits;
        report.effective_limits = effective_limits;
        report.work_completed = report.work_completed.checked_add(prior_work).ok_or(
            CompileError::InternalInvariant("endpoint-rescue report work overflowed"),
        )?;
        if let Some(decline) = &mut report.decline {
            decline.work_completed = decline.work_completed.checked_add(prior_work).ok_or(
                CompileError::InternalInvariant("endpoint-rescue decline work overflowed"),
            )?;
            if let DeterminizationResource::Work { limit, required } = &mut decline.resource {
                *limit = limit.checked_add(prior_work).ok_or(
                    CompileError::InternalInvariant("endpoint-rescue work limit overflowed"),
                )?;
                *required = required.checked_add(prior_work).ok_or(
                    CompileError::InternalInvariant("endpoint-rescue required work overflowed"),
                )?;
            }
        }
        Ok(())
    }

    fn account_discarded_rescue(&mut self, rescue_work: u64) -> Result<(), CompileError> {
        let Self::Declined { report, .. } = self else {
            return Err(CompileError::InternalInvariant(
                "completed ordered DFA received discarded rescue work",
            ));
        };
        report.work_completed = report.work_completed.checked_add(rescue_work).ok_or(
            CompileError::InternalInvariant("discarded endpoint-rescue work overflowed"),
        )?;
        if let Some(decline) = &mut report.decline {
            decline.work_completed = decline.work_completed.checked_add(rescue_work).ok_or(
                CompileError::InternalInvariant(
                    "discarded endpoint-rescue decline work overflowed",
                ),
            )?;
        }
        Ok(())
    }
}

fn retain_complete_forward_after_decline(
    alphabet: Alphabet,
    forward: ForwardDfa,
    reverse: Option<ReverseDfa>,
    boundary_classes: usize,
    graph_classes: usize,
    states_before_minimization: usize,
    reverse_states_before_minimization: usize,
    retained_forward_minimized: bool,
    budget: &mut BuildBudget,
) -> Result<(Option<PartialDfa>, Option<NativeSlowPartial>), CompileError> {
    match budget.partial_retention {
        PartialRetention::Stable => {
            drop(reverse);
            Ok((
                PartialDfa::from_complete_forward(alphabet, forward, budget)?,
                None,
            ))
        }
        PartialRetention::NativeSlow if budget.decline_allows_native_slow_partial() => Ok((
            None,
            Some(NativeSlowPartial::from_complete_forward(
                alphabet,
                forward,
                reverse,
                boundary_classes,
                graph_classes,
                states_before_minimization,
                reverse_states_before_minimization,
                retained_forward_minimized,
            )),
        )),
        PartialRetention::NativeSlow => Ok((None, None)),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the failure-atomic determinization stages and their partial-artifact policy stay adjacent"
)]
fn determinize_impl_with_allocation_ledger(
    raw: &RawPlan,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
    semantics: ForwardSemantics,
    replay_order: DfaReplayOrder,
    allocation_ledger: Option<DeterminizeAllocationLedger>,
) -> Result<DeterminizeOutcome, CompileError> {
    if raw
        .edge_kinds
        .iter()
        .any(|kind| !matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange))
    {
        return Err(CompileError::InternalInvariant(
            "assertion graph reached the assertion-free determinizer",
        ));
    }

    let mut budget = allocation_ledger.map_or_else(
        || BuildBudget::new(requested_limits),
        |ledger| BuildBudget::new_slow(requested_limits, ledger),
    );
    budget.begin_stage(DeterminizationStage::AlphabetPartition);
    let Some(built_alphabet) = Alphabet::build(raw, &mut budget)? else {
        return Ok(DeterminizeOutcome::from_budget(None, None, None, budget));
    };
    let BuiltAlphabet {
        mut alphabet,
        boundary_classes,
        graph_classes,
    } = built_alphabet;
    budget.complete_stage(DeterminizationStage::AlphabetPartition)?;
    budget.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
    let mut forward = match build_forward(raw, &alphabet, &mut budget, semantics, replay_order)? {
        ForwardBuildOutcome::Complete(forward) => forward,
        ForwardBuildOutcome::Declined {
            partial,
            native_slow_partial,
        } => {
            let (partial, native_slow_partial) = match (partial, native_slow_partial) {
                (Some(forward), None) => (Some(PartialDfa {
                    alphabet,
                    forward,
                    effective_limits: budget.limits,
                }), None),
                (None, Some(forward)) => (
                    None,
                    Some(NativeSlowPartial::from_incomplete_forward(
                        alphabet,
                        forward,
                        boundary_classes,
                        graph_classes,
                    )),
                ),
                (None, None) => (None, None),
                (Some(_), Some(_)) => {
                    return Err(CompileError::InternalInvariant(
                        "determinization retained two incompatible partial artifacts",
                    ));
                }
            };
            return Ok(DeterminizeOutcome::from_budget(
                None,
                partial,
                native_slow_partial,
                budget,
            ));
        }
    };
    budget.complete_stage(DeterminizationStage::ForwardSubsetConstruction)?;
    let forward_states_before_minimization = forward.states;
    let mut reverse = if wants_span && !forward.initial_pending {
        budget.begin_stage(DeterminizationStage::ReverseSubsetConstruction);
        let Some(reverse) = build_reverse(raw, &alphabet, &mut budget)? else {
            let (partial, native_slow_partial) = retain_complete_forward_after_decline(
                alphabet,
                forward,
                None,
                boundary_classes,
                graph_classes,
                forward_states_before_minimization,
                0,
                false,
                &mut budget,
            )?;
            return Ok(DeterminizeOutcome::from_budget(
                None,
                partial,
                native_slow_partial,
                budget,
            ));
        };
        budget.complete_stage(DeterminizationStage::ReverseSubsetConstruction)?;
        Some(reverse)
    } else {
        None
    };
    let reverse_states_before_minimization = reverse.as_ref().map_or(0, |machine| machine.states);
    budget.begin_stage(DeterminizationStage::DfaStateMinimization);
    let (minimization_complete, retained_forward_minimized) =
        minimize_dfa_states(&mut forward, &mut reverse, alphabet.classes(), &mut budget)?;
    if !minimization_complete {
        let (partial, native_slow_partial) = retain_complete_forward_after_decline(
            alphabet,
            forward,
            reverse,
            boundary_classes,
            graph_classes,
            forward_states_before_minimization,
            reverse_states_before_minimization,
            retained_forward_minimized,
            &mut budget,
        )?;
        return Ok(DeterminizeOutcome::from_budget(
            None,
            partial,
            native_slow_partial,
            budget,
        ));
    }
    budget.complete_stage(DeterminizationStage::DfaStateMinimization)?;
    budget.begin_stage(DeterminizationStage::AlphabetColumnCoalescing);
    if !coalesce_alphabet_columns(&mut alphabet, &mut forward, &mut reverse, &mut budget)? {
        let (partial, native_slow_partial) = retain_complete_forward_after_decline(
            alphabet,
            forward,
            reverse,
            boundary_classes,
            graph_classes,
            forward_states_before_minimization,
            reverse_states_before_minimization,
            false,
            &mut budget,
        )?;
        return Ok(DeterminizeOutcome::from_budget(
            None,
            partial,
            native_slow_partial,
            budget,
        ));
    }
    budget.complete_stage(DeterminizationStage::AlphabetColumnCoalescing)?;
    let forward_transitions = forward.transitions.len();
    let reverse_states = reverse.as_ref().map_or(0, |machine| machine.states);
    let reverse_transitions = reverse
        .as_ref()
        .map_or(0, |machine| machine.transitions.len());
    let stats = DfaStats {
        boundary_classes,
        graph_classes,
        alphabet_classes: alphabet.classes(),
        forward_states_before_minimization,
        forward_states: forward.states,
        forward_transitions,
        reverse_states_before_minimization,
        reverse_states,
        reverse_transitions,
        build_work: budget.work | dfa_replay_work_tag(replay_order),
    };
    let machine = OrderedDfa {
        alphabet,
        forward,
        reverse,
        stats,
    };
    Ok(DeterminizeOutcome::from_budget(
        Some(machine),
        None,
        None,
        budget,
    ))
}

fn determinize_impl(
    raw: &RawPlan,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
    semantics: ForwardSemantics,
    replay_order: DfaReplayOrder,
) -> Result<DeterminizeOutcome, CompileError> {
    determinize_impl_with_allocation_ledger(
        raw,
        wants_span,
        requested_limits,
        semantics,
        replay_order,
        None,
    )
}

/// Build the historical priority-preserving machine.
///
/// Keeping this entry point preserves canonical validation for previously
/// serialized programs and supplies an unquotiented semantic oracle for
/// differential tests.
#[allow(dead_code, reason = "stable FIFO replay oracle and compatibility fixture")]
pub(crate) fn determinize(
    raw: &RawPlan,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
) -> Result<DeterminizeOutcome, CompileError> {
    determinize_impl(
        raw,
        wants_span,
        requested_limits,
        ForwardSemantics::Ordered,
        DfaReplayOrder::Fifo,
    )
}

/// Build the current priority-preserving machine without an endpoint rescue.
///
/// This is used by exact accounting and canonical-compatibility checks that
/// need to distinguish the first ordered attempt from the optional second
/// endpoint-pruned attempt.
#[allow(dead_code, reason = "exact first-attempt accounting and compatibility fixture")]
pub(crate) fn determinize_current_ordered(
    raw: &RawPlan,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
) -> Result<DeterminizeOutcome, CompileError> {
    determinize_impl(
        raw,
        wants_span,
        requested_limits,
        ForwardSemantics::Ordered,
        DfaReplayOrder::DescendingEstimatedClassFrequency,
    )
}

/// Build an output-specialized semantic machine.
///
/// An existence query observes only whether any path accepts. It cannot
/// observe Thompson priority after an accepting transition, nor the order of
/// a nonaccepting subset. Canonicalizing those subsets avoids distinct DFA
/// states that differ only by priority. Its partial rows remain exact for a
/// Boolean query: a K0 continuation observes only the set of live consuming
/// states, never their priority order or a pending endpoint. Endpoint
/// contracts retain priority except where a bounded graph proof establishes
/// that an immediately lower-priority continuation reproduces every selected
/// end of its predecessor. Their retained frontiers can therefore still
/// resume in ordered K0 without replay.
pub(crate) fn determinize_for_output(
    raw: &RawPlan,
    output: OutputContract,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
) -> Result<DeterminizeOutcome, CompileError> {
    determinize_for_output_with_ledger(
        raw,
        output,
        wants_span,
        requested_limits,
        DfaReplayOrder::DescendingEstimatedClassFrequency,
        None,
    )
}

#[cfg(test)]
pub(crate) fn determinize_for_output_class_mass(
    raw: &RawPlan,
    output: OutputContract,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
) -> Result<DeterminizeOutcome, CompileError> {
    determinize_for_output_with_ledger(
        raw,
        output,
        wants_span,
        requested_limits,
        DfaReplayOrder::DescendingClassMass,
        None,
    )
}

/// Build an output-specialized machine while conservatively bounding every
/// fallible logical allocation made by the slow compiler.
///
/// The returned byte count is the maximum charged extent of either mutually
/// exclusive endpoint construction attempt. A numeric refusal may retain the
/// already-charged completed forward prefix for transient native lowering;
/// allocation refusal never does.
pub(crate) fn determinize_for_output_with_allocation_limit(
    raw: &RawPlan,
    output: OutputContract,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
    max_allocation_bytes: usize,
) -> Result<(DeterminizeOutcome, usize), CompileError> {
    let ledger = DeterminizeAllocationLedger::new(max_allocation_bytes);
    let outcome = determinize_for_output_with_ledger(
        raw,
        output,
        wants_span,
        requested_limits,
        DfaReplayOrder::DescendingEstimatedClassFrequency,
        Some(&ledger),
    )?;
    Ok((outcome, ledger.peak_bytes()))
}

fn determinize_for_output_with_ledger(
    raw: &RawPlan,
    output: OutputContract,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
    replay_order: DfaReplayOrder,
    allocation_ledger: Option<&DeterminizeAllocationLedger>,
) -> Result<DeterminizeOutcome, CompileError> {
    if output == OutputContract::Exists {
        return determinize_impl_with_allocation_ledger(
            raw,
            false,
            requested_limits,
            ForwardSemantics::Exists,
            replay_order,
            allocation_ledger.cloned(),
        );
    }
    let allocation_checkpoint = allocation_ledger.map_or(0, DeterminizeAllocationLedger::checkpoint);
    let ordered = determinize_impl_with_allocation_ledger(
        raw,
        wants_span,
        requested_limits,
        ForwardSemantics::Ordered,
        replay_order,
        allocation_ledger.cloned(),
    )?;
    let allocation_declined = matches!(
        ordered,
        DeterminizeOutcome::Declined {
            report: DeterminizationReport {
                decline: Some(DeterminizationDecline {
                    resource: DeterminizationResource::Allocation { .. },
                    ..
                }),
                ..
            },
            ..
        }
    );
    if matches!(ordered, DeterminizeOutcome::Complete { .. })
        || (allocation_declined
            && allocation_ledger.is_none_or(|ledger| !ledger.exhausted()))
    {
        return Ok(ordered);
    }
    if matches!(
        ordered,
        DeterminizeOutcome::Declined {
            report: DeterminizationReport {
                decline: None,
                ..
            },
            ..
        }
    ) {
        return Err(CompileError::InternalInvariant(
            "declined endpoint determinization has no resource",
        ));
    }
    if allocation_ledger.is_some()
        && matches!(
            ordered,
            DeterminizeOutcome::Declined {
                partial: Some(_),
                ..
            }
        )
    {
        return Err(CompileError::InternalInvariant(
            "slow endpoint determinization retained a partial machine",
        ));
    }
    let retained_native_slow_partial = matches!(
        ordered,
        DeterminizeOutcome::Declined {
            native_slow_partial: Some(_),
            ..
        }
    );
    if retained_native_slow_partial {
        // The ordered prefix remains live and owns allocations charged after
        // the checkpoint. Restoring that checkpoint for a simultaneous
        // endpoint-pruned attempt would make the ledger cease to be a hard
        // peak cap. The retained prefix is already useful either as a complete
        // direct machine or behind whole-search deopt, so keep it and skip the
        // mutually exclusive rescue.
        return Ok(ordered);
    }

    let effective_limits = requested_limits.effective_for_stable_artifact();
    let ordered_work = ordered.work_completed();
    let remaining_work = effective_limits.max_work.checked_sub(ordered_work).ok_or(
        CompileError::InternalInvariant("ordered endpoint work exceeded its effective limit"),
    )?;
    if remaining_work == 0 {
        return Ok(ordered);
    }

    if let Some(ledger) = allocation_ledger {
        // The retained-prefix case returned above. The ordered construction
        // reaching this point is fully dropped, so the endpoint-pruned rescue
        // may reuse the same hard logical byte budget without simultaneous
        // ownership.
        ledger.restore(allocation_checkpoint);
    }

    // Endpoint dominance is a failure-atomic rescue attempt, never a tax on a
    // construction that already fits the caller's limits. State and
    // transition storage restart from zero, while work receives only the
    // exact remainder of the original aggregate ceiling. A failed proof,
    // internal proof cap, or resource refusal returns the original ordered
    // partial prefix byte-for-byte and charges the discarded rescue work in
    // its report. Optimizing compilation may do two attempts, but their total
    // measured work never exceeds the caller's one hard limit.
    let mut rescue_limits = requested_limits;
    rescue_limits.max_work = remaining_work;
    let mut pruned = determinize_impl_with_allocation_ledger(
        raw,
        wants_span,
        rescue_limits,
        ForwardSemantics::EndpointPruned,
        replay_order,
        allocation_ledger.cloned(),
    )?;
    if matches!(pruned, DeterminizeOutcome::Complete { .. }) {
        pruned.account_prior_attempt(ordered_work, requested_limits)?;
        Ok(pruned)
    } else {
        let rescue_work = pruned.work_completed();
        let mut ordered = ordered;
        ordered.account_discarded_rescue(rescue_work)?;
        Ok(ordered)
    }
}

trait RefinementCell: Copy + Eq {
    fn next(self) -> u32;
    fn observable(self) -> bool;
    fn with_next(self, next: u32) -> Self;
}

impl RefinementCell for ForwardCell {
    fn next(self) -> u32 {
        ForwardCell::next(self)
    }

    fn observable(self) -> bool {
        self.accepted()
    }

    fn with_next(self, next: u32) -> Self {
        ForwardCell::with_next(self, next)
    }
}

impl RefinementCell for ReverseCell {
    fn next(self) -> u32 {
        ReverseCell::next(self)
    }

    fn observable(self) -> bool {
        self.reaches_start()
    }

    fn with_next(self, next: u32) -> Self {
        ReverseCell::with_next(self, next)
    }
}

struct MinimizedMachine<T> {
    transitions: Vec<T>,
    states: usize,
}

struct CanonicalPartitionOrder {
    group_to_new: Vec<u32>,
    new_to_group: Vec<usize>,
}

/// Minimize both complete machines by their transition/output behavior.
///
/// This pass has no access to the source pattern or Thompson-state identity.
/// It computes the fixed point of complete transition signatures, including
/// the per-transition observable bit and a distinct dead-state sentinel.
/// The second result bit records that the forward quotient committed even if
/// the following reverse quotient declined under the shared numeric budget.
fn minimize_dfa_states(
    forward: &mut ForwardDfa,
    reverse: &mut Option<ReverseDfa>,
    classes: usize,
    budget: &mut BuildBudget,
) -> Result<(bool, bool), CompileError> {
    let Some(minimized_forward) =
        minimize_complete_machine(&forward.transitions, forward.states, classes, budget)?
    else {
        return Ok((false, false));
    };
    forward.transitions = minimized_forward.transitions;
    forward.states = minimized_forward.states;

    if let Some(machine) = reverse {
        let Some(minimized_reverse) =
            minimize_complete_machine(&machine.transitions, machine.states, classes, budget)?
        else {
            return Ok((false, true));
        };
        machine.transitions = minimized_reverse.transitions;
        machine.states = minimized_reverse.states;
    }
    Ok((true, true))
}

/// Iteratively refine a Mealy-machine partition and emit its canonical
/// quotient. Partition numbers are assigned by first source-state occurrence;
/// quotient state numbers are then assigned by class-order BFS from state
/// zero, so neither tree shape nor randomized hashing can affect artifacts.
fn minimize_complete_machine<T: RefinementCell>(
    cells: &[T],
    states: usize,
    classes: usize,
    budget: &mut BuildBudget,
) -> Result<Option<MinimizedMachine<T>>, CompileError> {
    if states == 0 || classes == 0 {
        return Err(CompileError::InternalInvariant(
            "DFA minimization received an empty complete machine",
        ));
    }
    let expected = states
        .checked_mul(classes)
        .ok_or(CompileError::InternalInvariant(
            "DFA minimization table shape overflowed",
        ))?;
    if cells.len() != expected {
        return Err(CompileError::InternalInvariant(
            "DFA minimization received an incomplete table",
        ));
    }

    let Some((partition, partition_count)) = refine_partitions(cells, states, classes, budget)?
    else {
        return Ok(None);
    };
    canonical_quotient(cells, classes, &partition, partition_count, budget)
}

fn refine_partitions<T: RefinementCell>(
    cells: &[T],
    states: usize,
    classes: usize,
    budget: &mut BuildBudget,
) -> Result<Option<(Vec<u32>, usize)>, CompileError> {
    let Some(mut partition) = build_vec(states, budget) else {
        return Ok(None);
    };
    partition.resize(states, 0_u32);
    let mut partition_count = 1_usize;
    loop {
        if !budget.charge(1) {
            return Ok(None);
        }
        let Some(mut signatures): Option<StableMap<Vec<u64>, u32>> = build_map(states, budget)
        else {
            return Ok(None);
        };
        let Some(mut refined) = build_vec(states, budget) else {
            return Ok(None);
        };
        let mut refined_count = 0_usize;
        for state in 0..states {
            if !budget.charge(1) {
                return Ok(None);
            }
            let Some(signature) = refinement_signature(cells, state, classes, &partition, budget)?
            else {
                return Ok(None);
            };
            let id = match signatures.entry(signature) {
                std::collections::hash_map::Entry::Occupied(entry) => *entry.get(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let id = u32::try_from(refined_count).map_err(|_| {
                        CompileError::InternalInvariant(
                            "DFA refinement partition count exceeded u32",
                        )
                    })?;
                    entry.insert(id);
                    refined_count =
                        refined_count
                            .checked_add(1)
                            .ok_or(CompileError::InternalInvariant(
                                "DFA refinement partition count overflowed",
                            ))?;
                    id
                }
            };
            refined.push(id);
        }

        if refined_count < partition_count {
            return Err(CompileError::InternalInvariant(
                "DFA partition refinement merged a previously distinct partition",
            ));
        }
        if refined_count == partition_count {
            if refined != partition {
                return Err(CompileError::InternalInvariant(
                    "stable DFA partition lost its canonical numbering",
                ));
            }
            partition = refined;
            partition_count = refined_count;
            break;
        }
        partition = refined;
        partition_count = refined_count;
    }

    Ok(Some((partition, partition_count)))
}

fn refinement_signature<T: RefinementCell>(
    cells: &[T],
    state: usize,
    classes: usize,
    partition: &[u32],
    budget: &mut BuildBudget,
) -> Result<Option<Vec<u64>>, CompileError> {
    let row = state
        .checked_mul(classes)
        .ok_or(CompileError::InternalInvariant(
            "DFA refinement row overflowed",
        ))?;
    let Some(mut signature) = build_vec(classes, budget) else {
        return Ok(None);
    };
    for class in 0..classes {
        if !budget.charge(1) {
            return Ok(None);
        }
        let index = row
            .checked_add(class)
            .ok_or(CompileError::InternalInvariant(
                "DFA refinement cell index overflowed",
            ))?;
        let cell = *cells.get(index).ok_or(CompileError::InternalInvariant(
            "DFA refinement cell is outside the complete table",
        ))?;
        let destination = if cell.next() == NO_STATE {
            0_u64
        } else {
            let next = usize::try_from(cell.next()).map_err(|_| {
                CompileError::InternalInvariant("DFA refinement destination exceeded usize")
            })?;
            let destination_partition =
                *partition.get(next).ok_or(CompileError::InternalInvariant(
                    "DFA refinement destination is outside the state partition",
                ))?;
            u64::from(destination_partition).checked_add(1).ok_or(
                CompileError::InternalInvariant("DFA refinement partition encoding overflowed"),
            )?
        };
        signature.push(
            destination
                .checked_mul(2)
                .and_then(|value| value.checked_add(u64::from(cell.observable())))
                .ok_or(CompileError::InternalInvariant(
                    "DFA refinement signature encoding overflowed",
                ))?,
        );
    }
    Ok(Some(signature))
}

fn canonical_quotient<T: RefinementCell>(
    cells: &[T],
    classes: usize,
    partition: &[u32],
    partition_count: usize,
    budget: &mut BuildBudget,
) -> Result<Option<MinimizedMachine<T>>, CompileError> {
    let Some(representatives) = partition_representatives(partition, partition_count, budget)?
    else {
        return Ok(None);
    };
    let Some(order) =
        canonical_partition_order(cells, classes, partition, &representatives, budget)?
    else {
        return Ok(None);
    };
    let Some(transitions) = rewrite_quotient(
        cells,
        classes,
        partition,
        &representatives,
        &order.group_to_new,
        &order.new_to_group,
        budget,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(MinimizedMachine {
        transitions,
        states: partition_count,
    }))
}

fn partition_representatives(
    partition: &[u32],
    partition_count: usize,
    budget: &mut BuildBudget,
) -> Result<Option<Vec<usize>>, CompileError> {
    let Some(mut representatives) = build_vec(partition_count, budget) else {
        return Ok(None);
    };
    representatives.resize(partition_count, usize::MAX);
    for (state, &group) in partition.iter().enumerate() {
        if !budget.charge(1) {
            return Ok(None);
        }
        let group = usize::try_from(group).map_err(|_| {
            CompileError::InternalInvariant("DFA quotient partition exceeded usize")
        })?;
        let representative =
            representatives
                .get_mut(group)
                .ok_or(CompileError::InternalInvariant(
                    "DFA quotient references an absent partition",
                ))?;
        *representative = (*representative).min(state);
    }
    if representatives.contains(&usize::MAX) {
        return Err(CompileError::InternalInvariant(
            "DFA quotient contains an empty partition",
        ));
    }
    Ok(Some(representatives))
}

fn canonical_partition_order<T: RefinementCell>(
    cells: &[T],
    classes: usize,
    partition: &[u32],
    representatives: &[usize],
    budget: &mut BuildBudget,
) -> Result<Option<CanonicalPartitionOrder>, CompileError> {
    let initial_group = usize::try_from(*partition.first().ok_or(
        CompileError::InternalInvariant("DFA quotient has no initial state"),
    )?)
    .map_err(|_| CompileError::InternalInvariant("initial DFA partition exceeded usize"))?;
    let Some(mut group_to_new) = build_vec(representatives.len(), budget) else {
        return Ok(None);
    };
    group_to_new.resize(representatives.len(), NO_STATE);
    let Some(mut new_to_group) = build_vec(representatives.len(), budget) else {
        return Ok(None);
    };
    enqueue_partition(initial_group, &mut group_to_new, &mut new_to_group)?;
    let mut cursor = 0_usize;
    while new_to_group.len() < representatives.len() {
        while cursor < new_to_group.len() {
            let group = *new_to_group
                .get(cursor)
                .ok_or(CompileError::InternalInvariant(
                    "DFA quotient BFS cursor is outside its worklist",
                ))?;
            let representative =
                *representatives
                    .get(group)
                    .ok_or(CompileError::InternalInvariant(
                        "DFA quotient worklist references an absent partition",
                    ))?;
            if !enqueue_successors(
                cells,
                representative,
                classes,
                partition,
                &mut group_to_new,
                &mut new_to_group,
                budget,
            )? {
                return Ok(None);
            }
            cursor = cursor
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "DFA quotient BFS cursor overflowed",
                ))?;
        }

        if new_to_group.len() < representatives.len() {
            // Subset construction emits reachable states, but canonicalize
            // any defensive unreachable component by its smallest original
            // representative and then resume BFS.
            let group = representatives
                .iter()
                .enumerate()
                .filter(|(group, _)| group_to_new[*group] == NO_STATE)
                .min_by_key(|(_, representative)| **representative)
                .map(|(group, _)| group)
                .ok_or(CompileError::InternalInvariant(
                    "DFA quotient could not find an unnumbered partition",
                ))?;
            enqueue_partition(group, &mut group_to_new, &mut new_to_group)?;
        }
    }

    if usize::try_from(group_to_new[initial_group]).ok() != Some(0) {
        return Err(CompileError::InternalInvariant(
            "DFA quotient did not preserve the initial state as state zero",
        ));
    }
    Ok(Some(CanonicalPartitionOrder {
        group_to_new,
        new_to_group,
    }))
}

fn enqueue_successors<T: RefinementCell>(
    cells: &[T],
    representative: usize,
    classes: usize,
    partition: &[u32],
    group_to_new: &mut [u32],
    new_to_group: &mut Vec<usize>,
    budget: &mut BuildBudget,
) -> Result<bool, CompileError> {
    let row = representative
        .checked_mul(classes)
        .ok_or(CompileError::InternalInvariant(
            "DFA quotient BFS row overflowed",
        ))?;
    for class in 0..classes {
        if !budget.charge(1) {
            return Ok(false);
        }
        let cell = *cells
            .get(
                row.checked_add(class)
                    .ok_or(CompileError::InternalInvariant(
                        "DFA quotient BFS cell index overflowed",
                    ))?,
            )
            .ok_or(CompileError::InternalInvariant(
                "DFA quotient BFS cell is outside the complete table",
            ))?;
        if cell.next() == NO_STATE {
            continue;
        }
        let destination = usize::try_from(cell.next()).map_err(|_| {
            CompileError::InternalInvariant("DFA quotient destination exceeded usize")
        })?;
        let destination_group = usize::try_from(*partition.get(destination).ok_or(
            CompileError::InternalInvariant(
                "DFA quotient destination is outside the state partition",
            ),
        )?)
        .map_err(|_| {
            CompileError::InternalInvariant("DFA quotient destination partition exceeded usize")
        })?;
        if *group_to_new
            .get(destination_group)
            .ok_or(CompileError::InternalInvariant(
                "DFA quotient destination references an absent partition",
            ))?
            == NO_STATE
        {
            enqueue_partition(destination_group, group_to_new, new_to_group)?;
        }
    }
    Ok(true)
}

fn rewrite_quotient<T: RefinementCell>(
    cells: &[T],
    classes: usize,
    partition: &[u32],
    representatives: &[usize],
    group_to_new: &[u32],
    new_to_group: &[usize],
    budget: &mut BuildBudget,
) -> Result<Option<Vec<T>>, CompileError> {
    let capacity =
        new_to_group
            .len()
            .checked_mul(classes)
            .ok_or(CompileError::InternalInvariant(
                "minimized DFA table shape overflowed",
            ))?;
    let Some(mut minimized) = build_vec(capacity, budget) else {
        return Ok(None);
    };
    for &group in new_to_group {
        let representative = *representatives
            .get(group)
            .ok_or(CompileError::InternalInvariant(
                "minimized DFA state references an absent representative",
            ))?;
        let row = representative
            .checked_mul(classes)
            .ok_or(CompileError::InternalInvariant(
                "minimized DFA source row overflowed",
            ))?;
        for class in 0..classes {
            if !budget.charge(1) {
                return Ok(None);
            }
            let index = row
                .checked_add(class)
                .ok_or(CompileError::InternalInvariant(
                    "minimized DFA source index overflowed",
                ))?;
            let cell = *cells.get(index).ok_or(CompileError::InternalInvariant(
                "minimized DFA source is outside the complete table",
            ))?;
            let next = if cell.next() == NO_STATE {
                NO_STATE
            } else {
                let destination = usize::try_from(cell.next()).map_err(|_| {
                    CompileError::InternalInvariant("minimized DFA destination exceeded usize")
                })?;
                let destination_group = usize::try_from(*partition.get(destination).ok_or(
                    CompileError::InternalInvariant(
                        "minimized DFA destination is outside the state partition",
                    ),
                )?)
                .map_err(|_| {
                    CompileError::InternalInvariant(
                        "minimized DFA destination partition exceeded usize",
                    )
                })?;
                *group_to_new
                    .get(destination_group)
                    .ok_or(CompileError::InternalInvariant(
                        "minimized DFA destination partition was not renumbered",
                    ))?
            };
            minimized.push(cell.with_next(next));
        }
    }
    if minimized.len() != capacity {
        return Err(CompileError::InternalInvariant(
            "minimized DFA table is incomplete",
        ));
    }
    Ok(Some(minimized))
}

fn enqueue_partition(
    group: usize,
    group_to_new: &mut [u32],
    new_to_group: &mut Vec<usize>,
) -> Result<(), CompileError> {
    let destination = group_to_new
        .get_mut(group)
        .ok_or(CompileError::InternalInvariant(
            "DFA quotient enqueue references an absent partition",
        ))?;
    if *destination != NO_STATE {
        return Ok(());
    }
    *destination = u32::try_from(new_to_group.len())
        .map_err(|_| CompileError::InternalInvariant("minimized DFA state count exceeded u32"))?;
    new_to_group.push(group);
    Ok(())
}

/// Merge byte classes with identical behavior in every forward and reverse
/// state. Classes need not be adjacent: after determinization, table columns
/// are the semantic equivalence relation that matters.
fn coalesce_alphabet_columns(
    alphabet: &mut Alphabet,
    forward: &mut ForwardDfa,
    reverse: &mut Option<ReverseDfa>,
    budget: &mut BuildBudget,
) -> Result<bool, CompileError> {
    let old_classes = alphabet.classes();
    let Some(mut canonical) = build_vec(old_classes, budget) else {
        return Ok(false);
    };
    let Some(mut old_to_new) = build_vec(old_classes, budget) else {
        return Ok(false);
    };
    old_to_new.resize(old_classes, 0_u8);
    for (old, destination) in old_to_new.iter_mut().enumerate() {
        let mut equivalent = None;
        for (new, &candidate) in canonical.iter().enumerate() {
            if columns_equal(
                forward,
                reverse.as_ref(),
                old_classes,
                old,
                candidate,
                budget,
            )? {
                equivalent = Some(new);
                break;
            }
            if budget.declined {
                return Ok(false);
            }
        }
        let new = if let Some(equivalent) = equivalent {
            equivalent
        } else {
            let new = canonical.len();
            canonical.push(old);
            new
        };
        *destination = u8::try_from(new).map_err(|_| {
            CompileError::InternalInvariant("coalesced alphabet class count exceeded u8")
        })?;
    }
    if canonical.len() == old_classes {
        return Ok(true);
    }

    let Some(forward_cells) = compact_columns(
        &forward.transitions,
        forward.states,
        old_classes,
        &canonical,
        budget,
    )?
    else {
        return Ok(false);
    };
    let reverse_cells = if let Some(machine) = reverse.as_ref() {
        let Some(cells) = compact_columns(
            &machine.transitions,
            machine.states,
            old_classes,
            &canonical,
            budget,
        )?
        else {
            return Ok(false);
        };
        Some(cells)
    } else {
        None
    };

    let mut byte_to_class = [0_u8; 256];
    for (byte, destination) in byte_to_class.iter_mut().enumerate() {
        if !budget.charge(1) {
            return Ok(false);
        }
        let old = usize::from(alphabet.byte_to_class[byte]);
        *destination = *old_to_new.get(old).ok_or(CompileError::InternalInvariant(
            "alphabet byte map references an absent source class",
        ))?;
    }
    let Some(mut representatives) = build_vec(canonical.len(), budget) else {
        return Ok(false);
    };
    for &old in &canonical {
        if !budget.charge(1) {
            return Ok(false);
        }
        representatives.push(*alphabet.representatives.get(old).ok_or(
            CompileError::InternalInvariant("alphabet representative is outside source classes"),
        )?);
    }

    alphabet.byte_to_class = byte_to_class;
    alphabet.representatives = representatives.into_boxed_slice();
    forward.transitions = forward_cells;
    if let (Some(machine), Some(cells)) = (reverse.as_mut(), reverse_cells) {
        machine.transitions = cells;
    }
    Ok(true)
}

fn columns_equal(
    forward: &ForwardDfa,
    reverse: Option<&ReverseDfa>,
    classes: usize,
    left: usize,
    right: usize,
    budget: &mut BuildBudget,
) -> Result<bool, CompileError> {
    for state in 0..forward.states {
        if !budget.charge(1) {
            return Ok(false);
        }
        let row = state
            .checked_mul(classes)
            .ok_or(CompileError::InternalInvariant(
                "forward column comparison row overflowed",
            ))?;
        let left_index = row
            .checked_add(left)
            .ok_or(CompileError::InternalInvariant(
                "forward left-column index overflowed",
            ))?;
        let right_index = row
            .checked_add(right)
            .ok_or(CompileError::InternalInvariant(
                "forward right-column index overflowed",
            ))?;
        if forward.transitions.get(left_index) != forward.transitions.get(right_index) {
            return Ok(false);
        }
    }
    if let Some(reverse) = reverse {
        for state in 0..reverse.states {
            if !budget.charge(1) {
                return Ok(false);
            }
            let row = state
                .checked_mul(classes)
                .ok_or(CompileError::InternalInvariant(
                    "reverse column comparison row overflowed",
                ))?;
            let left_index = row
                .checked_add(left)
                .ok_or(CompileError::InternalInvariant(
                    "reverse left-column index overflowed",
                ))?;
            let right_index = row
                .checked_add(right)
                .ok_or(CompileError::InternalInvariant(
                    "reverse right-column index overflowed",
                ))?;
            if reverse.transitions.get(left_index) != reverse.transitions.get(right_index) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn compact_columns<T: Copy>(
    cells: &[T],
    states: usize,
    old_classes: usize,
    canonical: &[usize],
    budget: &mut BuildBudget,
) -> Result<Option<Vec<T>>, CompileError> {
    let capacity = states
        .checked_mul(canonical.len())
        .ok_or(CompileError::InternalInvariant(
            "coalesced DFA table shape overflowed",
        ))?;
    let Some(mut compact) = build_vec(capacity, budget) else {
        return Ok(None);
    };
    for state in 0..states {
        let row = state
            .checked_mul(old_classes)
            .ok_or(CompileError::InternalInvariant(
                "DFA column compaction row overflowed",
            ))?;
        for &old in canonical {
            if !budget.charge(1) {
                return Ok(None);
            }
            let source = row.checked_add(old).ok_or(CompileError::InternalInvariant(
                "DFA column compaction source overflowed",
            ))?;
            compact.push(*cells.get(source).ok_or(CompileError::InternalInvariant(
                "DFA column compaction source is outside the table",
            ))?);
        }
    }
    Ok(Some(compact))
}

/// Publish only the completed table prefix and incomplete frontier suffix.
///
/// Subset construction may have reserved storage for a much larger BFS
/// backlog before a limit declines. Moving those original vectors into the
/// optional sidecar would retain that abandoned capacity, so publication
/// fallibly copies/moves the exact logical payload into fresh compact owners.
/// Allocation failure simply declines the optional partial artifact.
fn compact_partial_forward(
    transitions: &[ForwardCell],
    start_actions: &[ForwardStartAction],
    states: Vec<ForwardKey>,
    complete_rows: usize,
    classes: usize,
    initial_pending: bool,
    initial_terminal: bool,
) -> Option<PartialForwardDfa> {
    if complete_rows == 0 || complete_rows > states.len() {
        return None;
    }
    let completed_cells = complete_rows.checked_mul(classes)?;
    let completed = transitions.get(..completed_cells)?;
    let mut compact_transitions = Vec::new();
    compact_transitions
        .try_reserve_exact(completed_cells)
        .ok()?;
    compact_transitions.extend_from_slice(completed);
    let mut packed_transitions = Vec::new();
    packed_transitions.try_reserve_exact(completed_cells).ok()?;
    for &cell in completed {
        packed_transitions.push(PackedForwardCell::from_cell(cell, complete_rows, classes)?);
    }
    let completed_actions = start_actions.get(..completed_cells)?;
    let mut compact_start_actions = Vec::new();
    compact_start_actions
        .try_reserve_exact(completed_cells)
        .ok()?;
    compact_start_actions.extend_from_slice(completed_actions);

    let discovered_states = states.len();
    let resume_count = discovered_states.checked_sub(complete_rows)?;
    let mut resume_keys = Vec::new();
    resume_keys.try_reserve_exact(resume_count).ok()?;
    resume_keys.extend(states.into_iter().skip(complete_rows));
    Some(PartialForwardDfa {
        initial_pending,
        initial_terminal,
        transitions: compact_transitions,
        packed_transitions: Some(packed_transitions),
        start_actions: compact_start_actions,
        discovered_states,
        complete_rows,
        resume_keys,
    })
}

/// Retain the slow compiler's already-owned completed rows and discovery keys
/// without making a fallible allocation after the resource refusal. Native
/// object lowering may copy the incomplete suffix into a private continuation
/// descriptor; keeping the original vector here does not allocate or change
/// the slow compiler's bounded accounting.
fn retain_native_slow_partial_forward(
    mut transitions: Vec<ForwardCell>,
    states: Vec<ForwardKey>,
    complete_rows: usize,
    classes: usize,
    initial_pending: bool,
    initial_terminal: bool,
) -> Option<NativeSlowPartialForward> {
    if complete_rows == 0 || complete_rows > states.len() || classes == 0 {
        return None;
    }
    let completed_cells = complete_rows.checked_mul(classes)?;
    if transitions.len() < completed_cells {
        return None;
    }
    transitions.truncate(completed_cells);
    let discovered_states = states.len();
    Some(NativeSlowPartialForward {
        initial_pending,
        initial_terminal,
        transitions,
        complete_rows,
        discovered_states,
        states_before_minimization: discovered_states,
        states,
    })
}

/// Maximum synchronized anchored-state pairs explored for one endpoint
/// dominance proof.
///
/// Refusing a larger proof is conservative: the ordered item remains in its
/// frontier. The bound keeps this optional canonicalization from replacing
/// one subset explosion with an unbounded product construction.
const ENDPOINT_DOMINANCE_MAX_PRODUCT_STATES: usize = 4_096;
/// Maximum total frontier items retained by one synchronized product proof.
/// Each item is held in both its worklist key and its stable interning key, so
/// this independently bounds proof scratch even when graph frontiers are wide.
const ENDPOINT_DOMINANCE_MAX_PRODUCT_ITEMS: usize = 65_536;
/// Maximum singleton-continuation relations memoized for one determinization.
const ENDPOINT_DOMINANCE_MAX_CACHED_PAIRS: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EndpointDominanceLimits {
    product_states: usize,
    product_items: usize,
    cached_pairs: usize,
}

impl Default for EndpointDominanceLimits {
    fn default() -> Self {
        Self {
            product_states: ENDPOINT_DOMINANCE_MAX_PRODUCT_STATES,
            product_items: ENDPOINT_DOMINANCE_MAX_PRODUCT_ITEMS,
            cached_pairs: ENDPOINT_DOMINANCE_MAX_CACHED_PAIRS,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct EndpointPair {
    preferred: ForwardKey,
    fallback: ForwardKey,
}

fn clone_endpoint_pair(pair: &EndpointPair, budget: &mut BuildBudget) -> Option<EndpointPair> {
    Some(EndpointPair {
        preferred: clone_forward_key(&pair.preferred, budget)?,
        fallback: clone_forward_key(&pair.fallback, budget)?,
    })
}

/// Bounded proofs that one consuming continuation can replace the immediately
/// preceding continuation of an endpoint-producing ordered frontier.
///
/// For a finite suffix, let `F_s` be the selected relative end produced by an
/// anchored ordered execution starting from consuming state `s`. If
/// `F_preferred(w) = Some(e)` implies `F_fallback(w) = Some(e)` for every
/// suffix `w`, then the ordered choice `preferred | fallback` has exactly the
/// same selected end as `fallback`: failure of the preferred branch already
/// selected the fallback, and success is reproduced at the same boundary.
/// This relation is deliberately checked only for adjacent frontier items, so
/// no intervening priority can become observable when the preferred item is
/// removed.
///
/// The proof is a synchronized product of the two exact anchored ordered
/// subset machines. At every reachable input boundary, once the preferred
/// side has a pending end, both sides must have last accepted on the same
/// transition. Therefore every possible finite-window stop observes either no
/// preferred result or equal selected ends. Empty frontiers are absorbing,
/// matching the early completion of anchored execution.
struct EndpointDominance {
    closure: ForwardClosure,
    cache: StableMap<(u32, u32), bool>,
    disabled: bool,
    limits: EndpointDominanceLimits,
}

impl EndpointDominance {
    fn new(raw: &RawPlan, budget: &mut BuildBudget) -> Option<Self> {
        Self::new_with_limits(raw, budget, EndpointDominanceLimits::default())
    }

    fn new_with_limits(
        raw: &RawPlan,
        budget: &mut BuildBudget,
        limits: EndpointDominanceLimits,
    ) -> Option<Self> {
        Some(Self {
            closure: ForwardClosure::new(raw, budget)?,
            cache: build_map(1, budget)?,
            disabled: false,
            limits,
        })
    }

    fn anchored_transition(
        &mut self,
        raw: &RawPlan,
        key: &ForwardKey,
        byte: u8,
        budget: &mut BuildBudget,
    ) -> Result<Option<(ForwardKey, bool)>, CompileError> {
        self.closure.begin();
        let mut accepted = false;
        'items: for &consuming in &key.items {
            if !budget.charge(1) {
                return Ok(None);
            }
            for edge in state_edges(raw, consuming)? {
                if !budget.charge(1) {
                    return Ok(None);
                }
                if raw.byte_starts[edge] <= byte
                    && byte <= raw.byte_ends[edge]
                    && self.closure.expand(raw, raw.edge_targets[edge], budget)?
                {
                    accepted = true;
                    break 'items;
                }
                if budget.declined {
                    return Ok(None);
                }
            }
        }
        let Some(items) = self.closure.copy_items(budget) else {
            return Ok(None);
        };
        Ok(Some((
            ForwardKey {
                items,
                pending: key.pending || accepted,
            },
            accepted,
        )))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the synchronized product proof remains one auditable transaction"
    )]
    fn proves_endpoint_inclusion(
        &mut self,
        raw: &RawPlan,
        alphabet: &Alphabet,
        preferred: u32,
        fallback: u32,
        budget: &mut BuildBudget,
    ) -> Result<Option<bool>, CompileError> {
        if !budget.charge(1) {
            return Ok(None);
        }
        if let Some(&proved) = self.cache.get(&(preferred, fallback)) {
            return Ok(Some(proved));
        }
        if self.disabled {
            return Ok(Some(false));
        }
        if self.cache.len() >= self.limits.cached_pairs {
            self.disabled = true;
            return Ok(Some(false));
        }
        if self.limits.product_states == 0 || self.limits.product_items < 2 {
            if !reserve_map(&mut self.cache, 1, budget) {
                return Ok(None);
            }
            self.cache.insert((preferred, fallback), false);
            return Ok(Some(false));
        }

        let Some(preferred_items) = clone_u32s(&[preferred], budget) else {
            return Ok(None);
        };
        let Some(fallback_items) = clone_u32s(&[fallback], budget) else {
            return Ok(None);
        };
        let initial = EndpointPair {
            preferred: ForwardKey {
                items: preferred_items,
                pending: false,
            },
            fallback: ForwardKey {
                items: fallback_items,
                pending: false,
            },
        };
        let Some(mut states) = build_vec(1, budget) else {
            return Ok(None);
        };
        let Some(initial_for_map) = clone_endpoint_pair(&initial, budget) else {
            return Ok(None);
        };
        states.push(initial);
        let Some(mut interned) = build_map(1, budget) else {
            return Ok(None);
        };
        interned.insert(initial_for_map, ());

        let mut cursor = 0usize;
        let mut retained_items = 2usize;
        let mut proved = true;
        'product: while cursor < states.len() {
            let Some(pair) = clone_endpoint_pair(
                states.get(cursor).ok_or(CompileError::InternalInvariant(
                    "endpoint-dominance worklist cursor is outside states",
                ))?,
                budget,
            ) else {
                return Ok(None);
            };
            cursor = cursor
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "endpoint-dominance worklist overflowed",
                ))?;

            if pair.preferred.pending && !pair.fallback.pending {
                proved = false;
                break;
            }
            // A failed, exhausted preferred continuation can never make the
            // implication observable on this suffix or any extension.
            if pair.preferred.items.is_empty() && !pair.preferred.pending {
                continue;
            }

            for &byte in alphabet.representatives.as_ref() {
                if !budget.charge(1) {
                    return Ok(None);
                }
                let Some((next_preferred, accepted_preferred)) =
                    self.anchored_transition(raw, &pair.preferred, byte, budget)?
                else {
                    return Ok(None);
                };
                let Some((next_fallback, accepted_fallback)) =
                    self.anchored_transition(raw, &pair.fallback, byte, budget)?
                else {
                    return Ok(None);
                };

                // Once the preferred side has selected an end, equality of
                // the last accepting boundary is preserved exactly when both
                // sides update together or neither updates. Its first accept
                // likewise has to be reproduced by the fallback now.
                if (pair.preferred.pending && accepted_preferred != accepted_fallback)
                    || (!pair.preferred.pending && accepted_preferred && !accepted_fallback)
                {
                    proved = false;
                    break 'product;
                }

                let next = EndpointPair {
                    preferred: next_preferred,
                    fallback: next_fallback,
                };
                if interned.contains_key(&next) {
                    continue;
                }
                if states.len() >= self.limits.product_states {
                    proved = false;
                    break 'product;
                }
                let next_items = next
                    .preferred
                    .items
                    .len()
                    .checked_add(next.fallback.items.len())
                    .ok_or(CompileError::InternalInvariant(
                        "endpoint-dominance retained item count overflowed",
                    ))?;
                let Some(next_retained_items) = retained_items.checked_add(next_items) else {
                    proved = false;
                    break 'product;
                };
                if next_retained_items > self.limits.product_items {
                    proved = false;
                    break 'product;
                }
                let next_len =
                    states
                        .len()
                        .checked_add(1)
                        .ok_or(CompileError::InternalInvariant(
                            "endpoint-dominance state count overflowed",
                        ))?;
                if !ensure_vec_capacity(&mut states, next_len, budget)
                    || !reserve_map(&mut interned, 1, budget)
                {
                    return Ok(None);
                }
                let Some(next_for_map) = clone_endpoint_pair(&next, budget) else {
                    return Ok(None);
                };
                states.push(next);
                interned.insert(next_for_map, ());
                retained_items = next_retained_items;
            }
        }

        if !reserve_map(&mut self.cache, 1, budget) {
            return Ok(None);
        }
        self.cache.insert((preferred, fallback), proved);
        Ok(Some(proved))
    }

    fn prune_items(
        &mut self,
        raw: &RawPlan,
        alphabet: &Alphabet,
        items: &mut Vec<u32>,
        budget: &mut BuildBudget,
    ) -> Result<Option<()>, CompileError> {
        let mut cursor = 0usize;
        while cursor + 1 < items.len() {
            let preferred = items[cursor];
            let fallback = items[cursor + 1];
            let Some(proved) =
                self.proves_endpoint_inclusion(raw, alphabet, preferred, fallback, budget)?
            else {
                return Ok(None);
            };
            if !proved {
                cursor += 1;
                continue;
            }
            let shifted = items.len().saturating_sub(cursor + 1);
            let shifted = u64::try_from(shifted).unwrap_or(u64::MAX);
            if !budget.charge(shifted) {
                return Ok(None);
            }
            items.remove(cursor);
            cursor = cursor.saturating_sub(1);
        }
        Ok(Some(()))
    }
}

fn prune_endpoint_items(
    analysis: &mut Option<EndpointDominance>,
    raw: &RawPlan,
    alphabet: &Alphabet,
    items: &mut Vec<u32>,
    budget: &mut BuildBudget,
) -> Result<Option<()>, CompileError> {
    if items.len() < 2 {
        return Ok(Some(()));
    }
    if analysis.is_none() {
        let Some(created) = EndpointDominance::new(raw, budget) else {
            return Ok(None);
        };
        *analysis = Some(created);
    }
    analysis
        .as_mut()
        .ok_or(CompileError::InternalInvariant(
            "endpoint-dominance analysis was not initialized",
        ))?
        .prune_items(raw, alphabet, items, budget)
}

#[derive(Clone, Copy)]
struct ForwardClassVisitOrder {
    classes: [u8; 256],
    len: usize,
}

impl ForwardClassVisitOrder {
    fn build(
        alphabet: &Alphabet,
        replay_order: DfaReplayOrder,
        budget: &mut BuildBudget,
    ) -> Result<Option<Self>, CompileError> {
        let len = alphabet.classes();
        if len == 0 || len > 256 {
            return Err(CompileError::InternalInvariant(
                "forward DFA class visit width is outside 1..=256",
            ));
        }
        let mut classes = [0_u8; 256];
        if replay_order == DfaReplayOrder::Fifo {
            for (class, slot) in classes[..len].iter_mut().enumerate() {
                *slot = u8::try_from(class).map_err(|_| {
                    CompileError::InternalInvariant("forward DFA class exceeded u8")
                })?;
            }
            return Ok(Some(Self { classes, len }));
        }

        // V6 ranks by raw-byte mass. Fresh compilation instead sums the
        // stable target-neutral byte-frequency units, conservatively capped
        // at their 256-unit probability denominator. Both scores stay in
        // 1..=256, so the same fixed counting sort, exact work charge and
        // stack scratch serve both replay identities. Class-id order inside
        // one score bucket is stable.
        let mut class_score = [0_u16; 256];
        for (byte, &class) in alphabet.byte_to_class.iter().enumerate() {
            if !budget.charge(1) {
                return Ok(None);
            }
            let class = usize::from(class);
            let score = class_score.get_mut(class).ok_or(
                CompileError::InternalInvariant(
                    "forward DFA byte map references an absent class",
                ),
            )?;
            let units = match replay_order {
                DfaReplayOrder::Fifo => {
                    return Err(CompileError::InternalInvariant(
                        "FIFO forward DFA reached ranked class construction",
                    ));
                }
                DfaReplayOrder::DescendingClassMass => 1,
                DfaReplayOrder::DescendingEstimatedClassFrequency => {
                    estimated_byte_frequency_units(u8::try_from(byte).map_err(|_| {
                        CompileError::InternalInvariant("forward DFA byte exceeded u8")
                    })?)
                }
            };
            *score = score
                .saturating_add(units)
                .min(BYTE_FREQUENCY_DENOMINATOR);
        }
        let mut bucket_cursor = [0_u16; 256];
        for &score in &class_score[..len] {
            if !budget.charge(1) {
                return Ok(None);
            }
            let bucket = usize::from(score.checked_sub(1).ok_or(
                CompileError::InternalInvariant("forward DFA class has zero byte score"),
            )?);
            let count = bucket_cursor.get_mut(bucket).ok_or(
                CompileError::InternalInvariant("forward DFA class score exceeded 256"),
            )?;
            *count = count.checked_add(1).ok_or(CompileError::InternalInvariant(
                "forward DFA score bucket overflowed",
            ))?;
        }
        let mut next = 0_u16;
        for bucket in (0..256).rev() {
            if !budget.charge(1) {
                return Ok(None);
            }
            let count = bucket_cursor[bucket];
            bucket_cursor[bucket] = next;
            next = next.checked_add(count).ok_or(CompileError::InternalInvariant(
                "forward DFA class-order offset overflowed",
            ))?;
        }
        if usize::from(next) != len {
            return Err(CompileError::InternalInvariant(
                "forward DFA class-order buckets lost a class",
            ));
        }
        for (class, &score) in class_score[..len].iter().enumerate() {
            if !budget.charge(1) {
                return Ok(None);
            }
            let bucket = usize::from(score - 1);
            let position = usize::from(bucket_cursor[bucket]);
            *classes.get_mut(position).ok_or(CompileError::InternalInvariant(
                "forward DFA class-order position is outside scratch",
            ))? = u8::try_from(class).map_err(|_| {
                CompileError::InternalInvariant("forward DFA class exceeded u8")
            })?;
            bucket_cursor[bucket] = bucket_cursor[bucket].checked_add(1).ok_or(
                CompileError::InternalInvariant("forward DFA class-order cursor overflowed"),
            )?;
        }
        Ok(Some(Self { classes, len }))
    }

    fn iter(&self) -> impl ExactSizeIterator<Item = usize> + '_ {
        self.classes[..self.len].iter().copied().map(usize::from)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "complete ordered subset construction is kept in one auditable worklist"
)]
fn build_forward(
    raw: &RawPlan,
    alphabet: &Alphabet,
    budget: &mut BuildBudget,
    semantics: ForwardSemantics,
    replay_order: DfaReplayOrder,
) -> Result<ForwardBuildOutcome, CompileError> {
    let Some(class_visit_order) = ForwardClassVisitOrder::build(alphabet, replay_order, budget)?
    else {
        return Ok(ForwardBuildOutcome::declined());
    };
    let existence_only = semantics == ForwardSemantics::Exists;
    let mut endpoint_dominance = None;
    let Some(mut closure) = ForwardClosure::new(raw, budget) else {
        return Ok(ForwardBuildOutcome::declined());
    };
    let initial_accepted = closure.expand(raw, raw.start, budget)?;
    if budget.declined {
        return Ok(ForwardBuildOutcome::declined());
    }
    let mut initial_items = if existence_only {
        if initial_accepted {
            Vec::new()
        } else {
            let Some(items) = closure.copy_items_canonical(raw, budget)? else {
                return Ok(ForwardBuildOutcome::declined());
            };
            items
        }
    } else {
        let Some(items) = closure.copy_items(budget) else {
            return Ok(ForwardBuildOutcome::declined());
        };
        items
    };
    if semantics == ForwardSemantics::EndpointPruned
        && prune_endpoint_items(
            &mut endpoint_dominance,
            raw,
            alphabet,
            &mut initial_items,
            budget,
        )?
        .is_none()
    {
        return Ok(ForwardBuildOutcome::declined());
    }
    let initial_terminal = initial_accepted && initial_items.is_empty();
    let initial = ForwardKey {
        items: initial_items,
        pending: initial_accepted,
    };
    if !budget.reserve_state(alphabet.classes()) {
        return Ok(ForwardBuildOutcome::declined());
    }

    let Some(mut states) = build_vec(1, budget) else {
        return Ok(ForwardBuildOutcome::declined());
    };
    let Some(initial_state) = clone_forward_key(&initial, budget) else {
        return Ok(ForwardBuildOutcome::declined());
    };
    states.push(initial_state);
    let Some(mut interned) = build_map(1, budget) else {
        return Ok(ForwardBuildOutcome::declined());
    };
    interned.insert(initial, 0_u32);
    let Some(mut transitions) = build_vec(alphabet.classes(), budget) else {
        return Ok(ForwardBuildOutcome::declined());
    };
    let Some(mut start_actions) = build_vec(alphabet.classes(), budget) else {
        return Ok(ForwardBuildOutcome::declined());
    };
    let mut cursor = 0usize;
    macro_rules! decline_with_complete_rows {
        () => {{
            return Ok(match budget.partial_retention {
                PartialRetention::NativeSlow if budget.decline_allows_native_slow_partial() => {
                    ForwardBuildOutcome::Declined {
                        partial: None,
                        native_slow_partial: retain_native_slow_partial_forward(
                            transitions,
                            states,
                            cursor,
                            alphabet.classes(),
                            initial_accepted,
                            initial_terminal,
                        ),
                    }
                }
                PartialRetention::NativeSlow => ForwardBuildOutcome::declined(),
                PartialRetention::Stable => ForwardBuildOutcome::Declined {
                    partial: compact_partial_forward(
                        &transitions,
                        &start_actions,
                        states,
                        cursor,
                        alphabet.classes(),
                        initial_accepted,
                        initial_terminal,
                    ),
                    native_slow_partial: None,
                },
            });
        }};
    }
    while cursor < states.len() {
        let Some(key) = clone_forward_key(
            states.get(cursor).ok_or(CompileError::InternalInvariant(
                "forward DFA worklist cursor is outside states",
            ))?,
            budget,
        ) else {
            decline_with_complete_rows!();
        };
        let mut row_cells = [forward_cell! {
            next: NO_STATE,
            accepted: false,
        }; 256];
        let mut row_start_actions = [ForwardStartAction::Drop; 256];
        for class in class_visit_order.iter() {
            let byte = *alphabet.representatives.get(class).ok_or(
                CompileError::InternalInvariant(
                    "forward DFA class visit references an absent representative",
                ),
            )?;
            if !budget.charge(1) {
                decline_with_complete_rows!();
            }
            closure.begin();
            let mut accepted = false;
            'items: for &consuming in &key.items {
                if !budget.charge(1) {
                    decline_with_complete_rows!();
                }
                for edge in state_edges(raw, consuming)? {
                    if !budget.charge(1) {
                        decline_with_complete_rows!();
                    }
                    if raw.byte_starts[edge] <= byte
                        && byte <= raw.byte_ends[edge]
                        && closure.expand(raw, raw.edge_targets[edge], budget)?
                    {
                        accepted = true;
                        break 'items;
                    }
                    if budget.declined {
                        decline_with_complete_rows!();
                    }
                }
            }
            let source_len = closure.items.len();
            let mut injected_root = false;
            if !accepted && !key.pending {
                injected_root = true;
                let injected = closure.expand(raw, raw.start, budget)?;
                if budget.declined {
                    decline_with_complete_rows!();
                }
                if injected {
                    return Err(CompileError::InternalInvariant(
                        "nonnullable ordered DFA accepted an injected empty match",
                    ));
                }
            }
            // Derive start provenance from the unpruned Thompson closure.
            // Endpoint pruning can delete a priority item with a different
            // start while preserving its end. Keeping the original action is
            // therefore deliberately conservative: a mixed-start transition
            // remains Drop, and Span recovers its start from the untouched
            // reverse/raw graph. Propagate and Reset cannot be invented by
            // the endpoint-only quotient.
            let start_action =
                ForwardStartAction::derive(source_len, closure.items.len(), injected_root);
            if semantics == ForwardSemantics::EndpointPruned
                && prune_endpoint_items(
                    &mut endpoint_dominance,
                    raw,
                    alphabet,
                    &mut closure.items,
                    budget,
                )?
                .is_none()
            {
                decline_with_complete_rows!();
            }
            let next_pending = !existence_only && (key.pending || accepted);
            let next_items = if existence_only {
                if accepted {
                    // Exists returns on this transition, so its successor is
                    // unobservable and must not create another subset state.
                    Vec::new()
                } else {
                    let Some(items) = closure.copy_items_canonical(raw, budget)? else {
                        decline_with_complete_rows!();
                    };
                    items
                }
            } else {
                let Some(items) = closure.copy_items(budget) else {
                    decline_with_complete_rows!();
                };
                items
            };
            let next = if next_items.is_empty() {
                NO_STATE
            } else {
                let next_key = ForwardKey {
                    items: next_items,
                    pending: next_pending,
                };
                if let Some(&known) = interned.get(&next_key) {
                    known
                } else {
                    if !budget.reserve_state(alphabet.classes()) {
                        decline_with_complete_rows!();
                    }
                    let id = u32::try_from(states.len()).map_err(|_| {
                        CompileError::InternalInvariant("forward DFA state count exceeded u32")
                    })?;
                    let Some(state_key) = clone_forward_key(&next_key, budget) else {
                        decline_with_complete_rows!();
                    };
                    let next_state_count =
                        states
                            .len()
                            .checked_add(1)
                            .ok_or(CompileError::InternalInvariant(
                                "forward DFA state storage overflowed",
                            ))?;
                    let next_transition_count = next_state_count
                        .checked_mul(alphabet.classes())
                        .ok_or(CompileError::InternalInvariant(
                            "forward DFA transition storage overflowed",
                        ))?;
                    if !ensure_vec_capacity(&mut states, next_state_count, budget)
                        || !ensure_vec_capacity(&mut transitions, next_transition_count, budget)
                        || !ensure_vec_capacity(&mut start_actions, next_transition_count, budget)
                        || !reserve_map(&mut interned, 1, budget)
                    {
                        decline_with_complete_rows!();
                    }
                    states.push(state_key);
                    interned.insert(next_key, id);
                    id
                }
            };
            row_cells[class] = forward_cell! { next, accepted };
            row_start_actions[class] = start_action;
        }
        // Discovery order is independent of the retained table layout. Every
        // completed row is committed only after all classes succeed and is
        // always stored in canonical class-id columns.
        for class in 0..alphabet.classes() {
            transitions.push(row_cells[class]);
            start_actions.push(row_start_actions[class]);
        }
        cursor = cursor
            .checked_add(1)
            .ok_or(CompileError::InternalInvariant(
                "forward DFA worklist overflowed",
            ))?;
    }

    let expected =
        states
            .len()
            .checked_mul(alphabet.classes())
            .ok_or(CompileError::InternalInvariant(
                "forward DFA table shape overflowed",
            ))?;
    if transitions.len() != expected || start_actions.len() != expected {
        return Err(CompileError::InternalInvariant(
            "forward DFA table or start certificate is incomplete",
        ));
    }
    Ok(ForwardBuildOutcome::Complete(ForwardDfa {
        initial_pending: initial_accepted,
        initial_terminal,
        transitions,
        states: states.len(),
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "complete reverse subset construction is kept in one auditable worklist"
)]
fn build_reverse(
    raw: &RawPlan,
    alphabet: &Alphabet,
    budget: &mut BuildBudget,
) -> Result<Option<ReverseDfa>, CompileError> {
    let Some(incoming) = Incoming::build(raw, budget)? else {
        return Ok(None);
    };
    let Some(mut closure) = ReverseClosure::new(raw, budget) else {
        return Ok(None);
    };
    closure.begin();
    for (state, role) in raw.roles.iter().copied().enumerate() {
        if !budget.charge(1) {
            return Ok(None);
        }
        if role == StateRole::Accept {
            let state = u32::try_from(state).map_err(|_| {
                CompileError::InternalInvariant("reverse Accept state exceeded u32")
            })?;
            closure.expand(raw, &incoming, state, budget)?;
            if budget.declined {
                return Ok(None);
            }
        }
    }
    closure.collect_frontier(raw, &incoming, budget)?;
    if budget.declined {
        return Ok(None);
    }
    let Some(initial_items) = closure.copy_items(budget) else {
        return Ok(None);
    };
    let initial = ReverseKey(initial_items);
    if !budget.reserve_state(alphabet.classes()) {
        return Ok(None);
    }

    let Some(mut states) = build_vec(1, budget) else {
        return Ok(None);
    };
    let Some(initial_state) = clone_reverse_key(&initial, budget) else {
        return Ok(None);
    };
    states.push(initial_state);
    let Some(mut interned) = build_map(1, budget) else {
        return Ok(None);
    };
    interned.insert(initial, 0_u32);
    let Some(mut transitions) = build_vec(alphabet.classes(), budget) else {
        return Ok(None);
    };
    let mut cursor = 0usize;
    while cursor < states.len() {
        let Some(key) = clone_reverse_key(
            states.get(cursor).ok_or(CompileError::InternalInvariant(
                "reverse DFA worklist cursor is outside states",
            ))?,
            budget,
        ) else {
            return Ok(None);
        };
        for &byte in alphabet.representatives.as_ref() {
            if !budget.charge(1) {
                return Ok(None);
            }
            closure.begin();
            let mut reaches_start = false;
            for &incoming_edge in &key.0 {
                if !budget.charge(1) {
                    return Ok(None);
                }
                let edge = usize::try_from(incoming_edge).map_err(|_| {
                    CompileError::InternalInvariant("reverse DFA edge index exceeded usize")
                })?;
                if raw.byte_starts[edge] <= byte && byte <= raw.byte_ends[edge] {
                    reaches_start |=
                        closure.expand(raw, &incoming, incoming.sources[edge], budget)?;
                    if budget.declined {
                        return Ok(None);
                    }
                }
            }
            closure.collect_frontier(raw, &incoming, budget)?;
            if budget.declined {
                return Ok(None);
            }
            let Some(next_items) = closure.copy_items(budget) else {
                return Ok(None);
            };
            let next = if next_items.is_empty() {
                NO_STATE
            } else {
                let next_key = ReverseKey(next_items);
                if let Some(&known) = interned.get(&next_key) {
                    known
                } else {
                    if !budget.reserve_state(alphabet.classes()) {
                        return Ok(None);
                    }
                    let id = u32::try_from(states.len()).map_err(|_| {
                        CompileError::InternalInvariant("reverse DFA state count exceeded u32")
                    })?;
                    let Some(state_key) = clone_reverse_key(&next_key, budget) else {
                        return Ok(None);
                    };
                    let next_state_count =
                        states
                            .len()
                            .checked_add(1)
                            .ok_or(CompileError::InternalInvariant(
                                "reverse DFA state storage overflowed",
                            ))?;
                    let next_transition_count = next_state_count
                        .checked_mul(alphabet.classes())
                        .ok_or(CompileError::InternalInvariant(
                            "reverse DFA transition storage overflowed",
                        ))?;
                    if !ensure_vec_capacity(&mut states, next_state_count, budget)
                        || !ensure_vec_capacity(&mut transitions, next_transition_count, budget)
                        || !reserve_map(&mut interned, 1, budget)
                    {
                        return Ok(None);
                    }
                    states.push(state_key);
                    interned.insert(next_key, id);
                    id
                }
            };
            transitions.push(reverse_cell! {
                next,
                reaches_start,
            });
        }
        cursor = cursor
            .checked_add(1)
            .ok_or(CompileError::InternalInvariant(
                "reverse DFA worklist overflowed",
            ))?;
    }

    let expected =
        states
            .len()
            .checked_mul(alphabet.classes())
            .ok_or(CompileError::InternalInvariant(
                "reverse DFA table shape overflowed",
            ))?;
    if transitions.len() != expected {
        return Err(CompileError::InternalInvariant(
            "reverse DFA table is incomplete",
        ));
    }
    Ok(Some(ReverseDfa {
        transitions,
        states: states.len(),
    }))
}

struct BuildBudget {
    requested_limits: DeterminizeLimits,
    limits: DeterminizeLimits,
    allocation_ledger: Option<DeterminizeAllocationLedger>,
    partial_retention: PartialRetention,
    work: u64,
    states: usize,
    transitions: usize,
    declined: bool,
    decline: Option<DeterminizationDecline>,
    current_stage: Option<DeterminizationStage>,
    // These two fixed five-entry vectors are receipt metadata, not graph
    // payload or construction scratch. They are deliberately outside the
    // slow allocation ledger so a byte-ceiling decline can always describe
    // the stage that declined.
    attempted_stages: Vec<DeterminizationStage>,
    completed_stages: Vec<DeterminizationStage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PartialRetention {
    Stable,
    NativeSlow,
}

impl BuildBudget {
    fn new(requested_limits: DeterminizeLimits) -> Self {
        Self {
            requested_limits,
            limits: requested_limits.effective_for_stable_artifact(),
            allocation_ledger: None,
            partial_retention: PartialRetention::Stable,
            work: 0,
            states: 0,
            transitions: 0,
            declined: false,
            decline: None,
            current_stage: None,
            attempted_stages: Vec::with_capacity(5),
            completed_stages: Vec::with_capacity(5),
        }
    }

    fn new_slow(
        requested_limits: DeterminizeLimits,
        allocation_ledger: DeterminizeAllocationLedger,
    ) -> Self {
        Self {
            requested_limits,
            limits: requested_limits.effective_for_stable_artifact(),
            allocation_ledger: Some(allocation_ledger),
            partial_retention: PartialRetention::NativeSlow,
            work: 0,
            states: 0,
            transitions: 0,
            declined: false,
            decline: None,
            current_stage: None,
            attempted_stages: Vec::with_capacity(5),
            completed_stages: Vec::with_capacity(5),
        }
    }

    fn begin_stage(&mut self, stage: DeterminizationStage) {
        debug_assert!(!self.declined);
        debug_assert!(self.current_stage.is_none());
        self.current_stage = Some(stage);
        self.attempted_stages.push(stage);
    }

    const fn retains_native_slow_partial(&self) -> bool {
        matches!(self.partial_retention, PartialRetention::NativeSlow)
    }

    fn decline_allows_native_slow_partial(&self) -> bool {
        self.retains_native_slow_partial()
            && matches!(
                self.decline,
                Some(DeterminizationDecline {
                    resource: DeterminizationResource::States { .. }
                        | DeterminizationResource::Transitions { .. }
                        | DeterminizationResource::Work { .. },
                    ..
                })
            )
    }

    fn complete_stage(&mut self, stage: DeterminizationStage) -> Result<(), CompileError> {
        if self.declined || self.current_stage != Some(stage) {
            return Err(CompileError::InternalInvariant(
                "DFA stage completed outside its active successful attempt",
            ));
        }
        self.completed_stages.push(stage);
        self.current_stage = None;
        Ok(())
    }

    fn decline(&mut self, resource: DeterminizationResource) {
        if self.decline.is_some() {
            self.declined = true;
            return;
        }
        self.declined = true;
        let stage = self
            .current_stage
            .unwrap_or(DeterminizationStage::AlphabetPartition);
        debug_assert!(
            self.current_stage.is_some(),
            "all determinization work runs inside a recorded stage"
        );
        self.decline = Some(DeterminizationDecline {
            stage,
            resource,
            work_completed: self.work,
            states_completed: self.states,
            transitions_completed: self.transitions,
        });
    }

    fn charge(&mut self, amount: u64) -> bool {
        let Some(next) = self.work.checked_add(amount) else {
            self.decline(DeterminizationResource::Work {
                limit: self.limits.max_work,
                required: u64::MAX,
            });
            return false;
        };
        if next > self.limits.max_work {
            self.decline(DeterminizationResource::Work {
                limit: self.limits.max_work,
                required: next,
            });
            return false;
        }
        self.work = next;
        true
    }

    fn reserve_state(&mut self, classes: usize) -> bool {
        let Some(states) = self.states.checked_add(1) else {
            self.decline(DeterminizationResource::States {
                limit: self.limits.max_states,
                required: usize::MAX,
            });
            return false;
        };
        let Some(transitions) = self.transitions.checked_add(classes) else {
            self.decline(DeterminizationResource::Transitions {
                limit: self.limits.max_transitions,
                required: usize::MAX,
            });
            return false;
        };
        if states > self.limits.max_states {
            self.decline(DeterminizationResource::States {
                limit: self.limits.max_states,
                required: states,
            });
            return false;
        }
        if transitions > self.limits.max_transitions {
            self.decline(DeterminizationResource::Transitions {
                limit: self.limits.max_transitions,
                required: transitions,
            });
            return false;
        }
        if !self.charge(1) {
            return false;
        }
        self.states = states;
        self.transitions = transitions;
        true
    }

    fn allocation<T>(&mut self, requested_elements: usize) {
        self.decline(DeterminizationResource::Allocation {
            requested_elements,
            element_size: core::mem::size_of::<T>(),
        });
    }

    fn charge_allocation<T>(&mut self, elements: usize) -> bool {
        let Some(ledger) = self.allocation_ledger.as_ref() else {
            return true;
        };
        if ledger.charge_elements::<T>(elements) {
            true
        } else {
            self.allocation::<T>(elements);
            false
        }
    }

    fn charge_map_allocation<K, V>(&mut self, entries: usize) -> bool {
        let Some(ledger) = self.allocation_ledger.as_ref() else {
            return true;
        };
        if ledger.charge_map_entries::<K, V>(entries) {
            true
        } else {
            self.allocation::<(K, V)>(entries);
            false
        }
    }

    /// A retained sidecar is optional, but failure to allocate its final
    /// executable representation is the reason it cannot be published. Replace
    /// an earlier numeric construction decline so the receipt does not imply
    /// that the canonical partial remained available.
    fn replace_decline_with_allocation<T>(&mut self, requested_elements: usize) {
        let stage = self
            .decline
            .as_ref()
            .map(|decline| decline.stage)
            .or(self.current_stage)
            .unwrap_or(DeterminizationStage::AlphabetPartition);
        debug_assert!(self.current_stage.is_some() || self.decline.is_some());
        self.declined = true;
        self.decline = Some(DeterminizationDecline {
            stage,
            resource: DeterminizationResource::Allocation {
                requested_elements,
                element_size: core::mem::size_of::<T>(),
            },
            work_completed: self.work,
            states_completed: self.states,
            transitions_completed: self.transitions,
        });
    }

    fn into_report(self) -> DeterminizationReport {
        DeterminizationReport {
            requested_limits: self.requested_limits,
            effective_limits: self.limits,
            attempted_stages: self.attempted_stages.into_boxed_slice(),
            completed_stages: self.completed_stages.into_boxed_slice(),
            decline: self.decline,
            work_completed: self.work,
            states_completed: self.states,
            transitions_completed: self.transitions,
        }
    }
}

struct ForwardClosure {
    seen: Vec<bool>,
    stack: Vec<u32>,
    items: Vec<u32>,
}

impl ForwardClosure {
    fn new(raw: &RawPlan, budget: &mut BuildBudget) -> Option<Self> {
        let mut seen = build_vec(raw.roles.len(), budget)?;
        seen.resize(raw.roles.len(), false);
        let Some(stack_capacity) = raw.edge_targets.len().checked_add(1) else {
            budget.allocation::<u32>(usize::MAX);
            return None;
        };
        Some(Self {
            seen,
            stack: build_vec(stack_capacity, budget)?,
            items: build_vec(raw.roles.len(), budget)?,
        })
    }

    fn begin(&mut self) {
        self.seen.fill(false);
        self.stack.clear();
        self.items.clear();
    }

    fn expand(
        &mut self,
        raw: &RawPlan,
        root: u32,
        budget: &mut BuildBudget,
    ) -> Result<bool, CompileError> {
        self.stack.clear();
        self.stack.push(root);
        while let Some(state) = self.stack.pop() {
            if !budget.charge(1) {
                return Ok(false);
            }
            let index = usize::try_from(state).map_err(|_| {
                CompileError::InternalInvariant("forward closure state exceeded usize")
            })?;
            let seen = self
                .seen
                .get_mut(index)
                .ok_or(CompileError::InternalInvariant(
                    "forward closure state is outside the validated graph",
                ))?;
            if *seen {
                continue;
            }
            *seen = true;
            match raw
                .roles
                .get(index)
                .copied()
                .ok_or(CompileError::InternalInvariant(
                    "forward closure role is outside the validated graph",
                ))? {
                StateRole::Accept => return Ok(true),
                StateRole::Consume => self.items.push(state),
                StateRole::Split => {
                    let edges = state_edges(raw, state)?;
                    for edge in edges.rev() {
                        if !budget.charge(1) {
                            return Ok(false);
                        }
                        if raw.edge_kinds[edge] != EdgeKind::Epsilon {
                            return Err(CompileError::InternalInvariant(
                                "assertion-free DFA reached a non-epsilon Split edge",
                            ));
                        }
                        self.stack.push(raw.edge_targets[edge]);
                    }
                }
                _ => {
                    return Err(CompileError::InternalInvariant(
                        "forward closure reached an unknown state role",
                    ));
                }
            }
        }
        Ok(false)
    }

    fn copy_items(&self, budget: &mut BuildBudget) -> Option<Vec<u32>> {
        clone_u32s(&self.items, budget)
    }

    /// Copy the consuming frontier in graph-state order.
    ///
    /// A complete nonaccepting closure has marked every reachable state in
    /// `seen`. Scanning that bitmap makes set canonicalization linear and its
    /// work receipt independent of a library sorting implementation.
    fn copy_items_canonical(
        &self,
        raw: &RawPlan,
        budget: &mut BuildBudget,
    ) -> Result<Option<Vec<u32>>, CompileError> {
        let Some(mut items) = build_vec(self.items.len(), budget) else {
            return Ok(None);
        };
        for (state, (&seen, &role)) in self.seen.iter().zip(&raw.roles).enumerate() {
            if !budget.charge(1) {
                return Ok(None);
            }
            if seen && role == StateRole::Consume {
                items.push(u32::try_from(state).map_err(|_| {
                    CompileError::InternalInvariant("forward closure state exceeded u32")
                })?);
            }
        }
        if items.len() != self.items.len() {
            return Err(CompileError::InternalInvariant(
                "canonical forward closure changed its consuming frontier",
            ));
        }
        Ok(Some(items))
    }
}

struct Incoming {
    sources: Vec<u32>,
    by_target: Vec<Vec<u32>>,
}

impl Incoming {
    fn build(raw: &RawPlan, budget: &mut BuildBudget) -> Result<Option<Self>, CompileError> {
        let Some(mut sources) = build_vec(raw.edge_targets.len(), budget) else {
            return Ok(None);
        };
        sources.resize(raw.edge_targets.len(), 0_u32);
        let Some(mut by_target) = build_vec(raw.roles.len(), budget) else {
            return Ok(None);
        };
        by_target.resize_with(raw.roles.len(), Vec::new);
        let Some(mut degrees) = build_vec(raw.roles.len(), budget) else {
            return Ok(None);
        };
        degrees.resize(raw.roles.len(), 0_usize);
        for source in 0..raw.roles.len() {
            let source_u32 = u32::try_from(source)
                .map_err(|_| CompileError::InternalInvariant("reverse source exceeded u32"))?;
            for edge in state_edges(raw, source_u32)? {
                if !budget.charge(1) {
                    return Ok(None);
                }
                sources[edge] = source_u32;
                let target = usize::try_from(raw.edge_targets[edge]).map_err(|_| {
                    CompileError::InternalInvariant("reverse target exceeded usize")
                })?;
                let degree = degrees
                    .get_mut(target)
                    .ok_or(CompileError::InternalInvariant(
                        "reverse target is outside the validated graph",
                    ))?;
                *degree = degree
                    .checked_add(1)
                    .ok_or(CompileError::InternalInvariant(
                        "reverse target degree overflowed",
                    ))?;
            }
        }
        for (row, &degree) in by_target.iter_mut().zip(&degrees) {
            // Every incoming edge is retained in one inner row. Account for
            // those separately allocated buffers as well as the outer
            // `Vec<Vec<_>>`; otherwise a wide reverse graph could evade the
            // slow compiler's byte ceiling even though its total row payload
            // is proportional to all raw edges.
            if !ensure_vec_capacity(row, degree, budget) {
                return Ok(None);
            }
        }
        for (edge, &target) in raw.edge_targets.iter().enumerate() {
            let target = usize::try_from(target)
                .map_err(|_| CompileError::InternalInvariant("reverse target exceeded usize"))?;
            let edge_u32 = u32::try_from(edge)
                .map_err(|_| CompileError::InternalInvariant("reverse edge exceeded u32"))?;
            by_target
                .get_mut(target)
                .ok_or(CompileError::InternalInvariant(
                    "reverse target is outside the validated graph",
                ))?
                .push(edge_u32);
        }
        Ok(Some(Self { sources, by_target }))
    }
}

struct ReverseClosure {
    seen: Vec<bool>,
    stack: Vec<u32>,
    items: Vec<u32>,
}

impl ReverseClosure {
    fn new(raw: &RawPlan, budget: &mut BuildBudget) -> Option<Self> {
        let mut seen = build_vec(raw.roles.len(), budget)?;
        seen.resize(raw.roles.len(), false);
        let Some(stack_capacity) = raw.edge_targets.len().checked_add(1) else {
            budget.allocation::<u32>(usize::MAX);
            return None;
        };
        Some(Self {
            seen,
            stack: build_vec(stack_capacity, budget)?,
            items: build_vec(raw.edge_targets.len(), budget)?,
        })
    }

    fn begin(&mut self) {
        self.seen.fill(false);
        self.stack.clear();
        self.items.clear();
    }

    fn expand(
        &mut self,
        raw: &RawPlan,
        incoming: &Incoming,
        root: u32,
        budget: &mut BuildBudget,
    ) -> Result<bool, CompileError> {
        self.stack.push(root);
        let mut reaches_start = false;
        while let Some(state) = self.stack.pop() {
            if !budget.charge(1) {
                return Ok(false);
            }
            let index = usize::try_from(state).map_err(|_| {
                CompileError::InternalInvariant("reverse closure state exceeded usize")
            })?;
            let seen = self
                .seen
                .get_mut(index)
                .ok_or(CompileError::InternalInvariant(
                    "reverse closure state is outside the validated graph",
                ))?;
            if *seen {
                continue;
            }
            *seen = true;
            reaches_start |= state == raw.start;
            for &edge in incoming
                .by_target
                .get(index)
                .ok_or(CompileError::InternalInvariant(
                    "reverse incoming row is outside the validated graph",
                ))?
            {
                if !budget.charge(1) {
                    return Ok(false);
                }
                let edge = usize::try_from(edge).map_err(|_| {
                    CompileError::InternalInvariant("reverse incoming edge exceeded usize")
                })?;
                let source = incoming.sources[edge];
                let source_index = usize::try_from(source).map_err(|_| {
                    CompileError::InternalInvariant("reverse incoming source exceeded usize")
                })?;
                match raw.roles[source_index] {
                    StateRole::Split => {
                        if raw.edge_kinds[edge] != EdgeKind::Epsilon {
                            return Err(CompileError::InternalInvariant(
                                "assertion-free reverse DFA reached a non-epsilon Split edge",
                            ));
                        }
                        self.stack.push(source);
                    }
                    StateRole::Consume => {}
                    StateRole::Accept => {
                        return Err(CompileError::InternalInvariant(
                            "reverse graph contains an outgoing Accept edge",
                        ));
                    }
                    _ => {
                        return Err(CompileError::InternalInvariant(
                            "reverse closure reached an unknown state role",
                        ));
                    }
                }
            }
        }
        Ok(reaches_start)
    }

    fn collect_frontier(
        &mut self,
        raw: &RawPlan,
        incoming: &Incoming,
        budget: &mut BuildBudget,
    ) -> Result<(), CompileError> {
        for target in 0..raw.roles.len() {
            if !budget.charge(1) {
                return Ok(());
            }
            if !self.seen[target] {
                continue;
            }
            for &edge in &incoming.by_target[target] {
                if !budget.charge(1) {
                    return Ok(());
                }
                let edge_index = usize::try_from(edge).map_err(|_| {
                    CompileError::InternalInvariant("reverse frontier edge exceeded usize")
                })?;
                let source = usize::try_from(incoming.sources[edge_index]).map_err(|_| {
                    CompileError::InternalInvariant("reverse frontier source exceeded usize")
                })?;
                if raw.roles[source] == StateRole::Consume {
                    self.items.push(edge);
                }
            }
        }
        Ok(())
    }

    fn copy_items(&self, budget: &mut BuildBudget) -> Option<Vec<u32>> {
        clone_u32s(&self.items, budget)
    }
}

fn state_edges(raw: &RawPlan, state: u32) -> Result<core::ops::Range<usize>, CompileError> {
    let state = usize::try_from(state)
        .map_err(|_| CompileError::InternalInvariant("DFA state index exceeded usize"))?;
    let next = state.checked_add(1).ok_or(CompileError::InternalInvariant(
        "DFA state offset overflowed",
    ))?;
    let begin = usize::try_from(*raw.edge_offsets.get(state).ok_or(
        CompileError::InternalInvariant("DFA state offset is outside the validated graph"),
    )?)
    .map_err(|_| CompileError::InternalInvariant("DFA edge offset exceeded usize"))?;
    let end = usize::try_from(*raw.edge_offsets.get(next).ok_or(
        CompileError::InternalInvariant("DFA state end offset is outside the validated graph"),
    )?)
    .map_err(|_| CompileError::InternalInvariant("DFA edge end offset exceeded usize"))?;
    Ok(begin..end)
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_native_slow_partial(
        classes: usize,
        complete_rows: usize,
        discovered_states: usize,
        initial_pending: bool,
        initial_terminal: bool,
        transitions: Vec<ForwardCell>,
    ) -> NativeSlowPartial {
        let mut byte_to_class = [0_u8; 256];
        for (byte, class) in byte_to_class.iter_mut().take(classes).enumerate() {
            *class = u8::try_from(byte).expect("synthetic class fits u8");
        }
        NativeSlowPartial {
            alphabet: Alphabet {
                byte_to_class,
                representatives: (0..classes)
                    .map(|class| u8::try_from(class).expect("synthetic class fits u8"))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            },
            forward: NativeSlowPartialForward {
                initial_pending,
                initial_terminal,
                transitions,
                complete_rows,
                discovered_states,
                states_before_minimization: discovered_states,
                states: (0..discovered_states)
                    .map(|state| ForwardKey {
                        items: vec![u32::try_from(state).expect("synthetic state fits u32")],
                        pending: false,
                    })
                    .collect(),
            },
            reverse: None,
            reverse_states_before_minimization: 0,
            retained_forward_minimized: false,
            boundary_classes: classes,
            graph_classes: classes,
        }
    }

    fn allocated_first_observable_hole_oracle(
        partial: &NativeSlowPartial,
        output: OutputContract,
    ) -> Option<usize> {
        if (output == OutputContract::Exists && partial.forward.initial_pending)
            || (output != OutputContract::Exists && partial.forward.initial_terminal)
        {
            return None;
        }
        let classes = partial.alphabet.classes();
        let complete = partial.forward.complete_rows;
        let mut seen = vec![false; complete];
        let mut queue = std::collections::VecDeque::new();
        seen[0] = true;
        queue.push_back((0usize, 0usize));
        while let Some((state, depth)) = queue.pop_front() {
            let row = state * classes;
            for cell in partial.forward.transitions[row..row + classes]
                .iter()
                .copied()
            {
                if output == OutputContract::Exists && cell.accepted() {
                    continue;
                }
                let next = cell.next();
                if next == NO_STATE {
                    continue;
                }
                let next = usize::try_from(next).expect("synthetic destination fits usize");
                if next >= complete {
                    return Some(depth + 1);
                }
                if !seen[next] {
                    seen[next] = true;
                    queue.push_back((next, depth + 1));
                }
            }
        }
        None
    }

    #[test]
    fn slow_partial_first_hole_bfs_matches_allocated_oracle() {
        let cases = [
            synthetic_native_slow_partial(
                2,
                2,
                3,
                false,
                false,
                vec![
                    forward_cell! { next: 1, accepted: false },
                    forward_cell! { next: NO_STATE, accepted: false },
                    forward_cell! { next: 2, accepted: false },
                    forward_cell! { next: 1, accepted: false },
                ],
            ),
            synthetic_native_slow_partial(
                2,
                3,
                4,
                false,
                false,
                vec![
                    forward_cell! { next: 1, accepted: false },
                    forward_cell! { next: 2, accepted: false },
                    forward_cell! { next: 3, accepted: false },
                    forward_cell! { next: 1, accepted: false },
                    forward_cell! { next: 2, accepted: false },
                    forward_cell! { next: 3, accepted: false },
                ],
            ),
            synthetic_native_slow_partial(
                1,
                1,
                2,
                false,
                false,
                vec![forward_cell! { next: 1, accepted: true }],
            ),
        ];
        for (case, partial) in cases.iter().enumerate() {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                assert_eq!(
                    partial.first_observable_hole_bytes(output).unwrap(),
                    allocated_first_observable_hole_oracle(partial, output),
                    "case {case}/{output:?}",
                );
            }
        }
        assert_eq!(
            cases[0]
                .first_observable_hole_bytes(OutputContract::SelectedEnd)
                .unwrap(),
            Some(2),
        );
        assert_eq!(
            cases[1]
                .first_observable_hole_bytes(OutputContract::SelectedEnd)
                .unwrap(),
            Some(2),
        );
        assert_eq!(
            cases[2]
                .first_observable_hole_bytes(OutputContract::Exists)
                .unwrap(),
            None,
        );
        assert_eq!(
            cases[2]
                .first_observable_hole_bytes(OutputContract::SelectedEnd)
                .unwrap(),
            Some(1),
        );
    }

    #[test]
    fn slow_partial_first_hole_respects_initial_terminals_and_rejects_bad_extent() {
        let exists_terminal = synthetic_native_slow_partial(
            1,
            1,
            2,
            true,
            false,
            vec![forward_cell! { next: 1, accepted: false }],
        );
        assert_eq!(
            exists_terminal
                .first_observable_hole_bytes(OutputContract::Exists)
                .unwrap(),
            None,
        );
        assert_eq!(
            exists_terminal
                .first_observable_hole_bytes(OutputContract::SelectedEnd)
                .unwrap(),
            Some(1),
        );

        let endpoint_terminal = synthetic_native_slow_partial(
            1,
            1,
            2,
            true,
            true,
            vec![forward_cell! { next: 1, accepted: false }],
        );
        for output in [OutputContract::SelectedEnd, OutputContract::Span] {
            assert_eq!(
                endpoint_terminal
                    .first_observable_hole_bytes(output)
                    .unwrap(),
                None,
            );
        }

        let mut malformed = synthetic_native_slow_partial(
            1,
            1,
            2,
            false,
            false,
            vec![forward_cell! { next: 1, accepted: false }],
        );
        malformed.forward.transitions[0] =
            forward_cell! { next: 2, accepted: false };
        assert!(matches!(
            malformed.first_observable_hole_bytes(OutputContract::Exists),
            Err(CompileError::InternalInvariant(_)),
        ));
        malformed.forward.transitions.clear();
        assert!(matches!(
            malformed.first_observable_hole_bytes(OutputContract::Exists),
            Err(CompileError::InternalInvariant(_)),
        ));
    }

    fn class_mass_test_alphabet() -> Alphabet {
        let mut byte_to_class = [2_u8; 256];
        byte_to_class[0] = 0;
        byte_to_class[1..201].fill(1);
        Alphabet {
            byte_to_class,
            representatives: vec![0, 1, 201].into_boxed_slice(),
        }
    }

    #[test]
    fn class_mass_visit_order_is_stable_and_exactly_metered() {
        let alphabet = class_mass_test_alphabet();
        let expected_work = 512 + 2 * 3;
        let limits = DeterminizeLimits {
            max_work: expected_work,
            ..DeterminizeLimits::unlimited()
        };
        let mut exact = BuildBudget::new(limits);
        exact.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
        let order = ForwardClassVisitOrder::build(
            &alphabet,
            DfaReplayOrder::DescendingClassMass,
            &mut exact,
        )
        .expect("valid class masses")
        .expect("exact class-order work");
        assert_eq!(order.iter().collect::<Vec<_>>(), [1, 2, 0]);
        assert_eq!(exact.work, expected_work);
        assert!(!exact.declined);

        let mut one_short = BuildBudget::new(DeterminizeLimits {
            max_work: expected_work - 1,
            ..DeterminizeLimits::unlimited()
        });
        one_short.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
        assert!(
            ForwardClassVisitOrder::build(
                &alphabet,
                DfaReplayOrder::DescendingClassMass,
                &mut one_short,
            )
            .expect("valid class masses")
            .is_none()
        );
        assert_eq!(one_short.work, expected_work - 1);
        assert_eq!(
            one_short.decline.as_ref().map(|decline| decline.resource),
            Some(DeterminizationResource::Work {
                limit: expected_work - 1,
                required: expected_work,
            })
        );

        let mut fifo = BuildBudget::new(DeterminizeLimits {
            max_work: 0,
            ..DeterminizeLimits::unlimited()
        });
        fifo.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
        let fifo_order = ForwardClassVisitOrder::build(
            &alphabet,
            DfaReplayOrder::Fifo,
            &mut fifo,
        )
        .expect("valid FIFO classes")
        .expect("FIFO order needs no new replay work");
        assert_eq!(fifo_order.iter().collect::<Vec<_>>(), [0, 1, 2]);
        assert_eq!(fifo.work, 0);
    }

    fn estimated_frequency_test_alphabet() -> Alphabet {
        let mut byte_to_class = [0_u8; 256];
        byte_to_class[1] = 1;
        byte_to_class[usize::from(b'e')] = 2;
        Alphabet {
            byte_to_class,
            representatives: vec![0, 1, b'e'].into_boxed_slice(),
        }
    }

    #[test]
    fn estimated_frequency_visit_order_is_stable_saturated_and_exactly_metered() {
        let alphabet = estimated_frequency_test_alphabet();
        let expected_work = 512 + 2 * 3;
        let mut exact = BuildBudget::new(DeterminizeLimits {
            max_work: expected_work,
            ..DeterminizeLimits::unlimited()
        });
        exact.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
        let order = ForwardClassVisitOrder::build(
            &alphabet,
            DfaReplayOrder::DescendingEstimatedClassFrequency,
            &mut exact,
        )
        .expect("valid estimated class frequencies")
        .expect("exact estimated-frequency ordering work");
        assert_eq!(order.iter().collect::<Vec<_>>(), [0, 2, 1]);
        assert_eq!(estimated_byte_frequency_units(1), 1);
        assert_eq!(estimated_byte_frequency_units(b'e'), 24);
        assert_eq!(exact.work, expected_work);
        assert!(!exact.declined);

        let mut one_short = BuildBudget::new(DeterminizeLimits {
            max_work: expected_work - 1,
            ..DeterminizeLimits::unlimited()
        });
        one_short.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
        assert!(
            ForwardClassVisitOrder::build(
                &alphabet,
                DfaReplayOrder::DescendingEstimatedClassFrequency,
                &mut one_short,
            )
            .expect("valid estimated class frequencies")
            .is_none()
        );
        assert_eq!(one_short.work, expected_work - 1);
        assert_eq!(
            one_short.decline.as_ref().map(|decline| decline.resource),
            Some(DeterminizationResource::Work {
                limit: expected_work - 1,
                required: expected_work,
            })
        );
    }

    fn weighted_branch_graph() -> RawPlan {
        RawPlan {
            start: 0,
            roles: vec![
                StateRole::Split,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            edge_offsets: vec![0, 2, 4, 5, 6, 7, 8, 9, 10, 10],
            edge_targets: vec![1, 8, 2, 5, 3, 4, 8, 6, 7, 8],
            edge_kinds: vec![
                EdgeKind::Epsilon,
                EdgeKind::Epsilon,
                EdgeKind::Epsilon,
                EdgeKind::Epsilon,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
                EdgeKind::ByteRange,
            ],
            byte_starts: vec![0, 0, 0, 0, b'a', b'a', b'a', b'b', b'b', b'b'],
            byte_ends: vec![0, 0, 0, 0, b'a', b'a', b'a', u8::MAX, u8::MAX, u8::MAX],
        }
    }

    fn estimated_frequency_branch_graph() -> RawPlan {
        let mut raw = weighted_branch_graph();
        raw.byte_starts[4..7].fill(1);
        raw.byte_ends[4..7].fill(1);
        raw.byte_starts[7..10].fill(b'e');
        raw.byte_ends[7..10].fill(b'e');
        raw
    }

    fn declined_partial_with_order(raw: &RawPlan, replay_order: DfaReplayOrder) -> PartialDfa {
        match determinize_impl(
            raw,
            false,
            DeterminizeLimits {
                max_states: 4,
                ..DeterminizeLimits::unlimited()
            },
            ForwardSemantics::Ordered,
            replay_order,
        )
        .expect("bounded ordered construction")
        {
            DeterminizeOutcome::Declined {
                report,
                partial: Some(partial),
                ..
            } => {
                assert_eq!(
                    report.decline.map(|decline| decline.resource),
                    Some(DeterminizationResource::States {
                        limit: 4,
                        required: 5,
                    })
                );
                partial
            }
            DeterminizeOutcome::Declined {
                report,
                partial: None,
                ..
            } => {
                panic!("bounded construction retained no rows: {report:?}")
            }
            DeterminizeOutcome::Complete { .. } => {
                panic!("four-state construction unexpectedly completed")
            }
        }
    }

    fn initial_completed_target_mass(partial: &PartialDfa) -> usize {
        let classes = partial.alphabet.classes();
        let row = partial
            .forward
            .transitions
            .get(..classes)
            .expect("completed initial row");
        partial
            .alphabet
            .byte_to_class
            .iter()
            .filter(|&&class| {
                let next = row[usize::from(class)].next();
                next != NO_STATE
                    && usize::try_from(next)
                        .ok()
                        .is_some_and(|next| next < partial.forward.complete_rows)
            })
            .count()
    }

    fn initial_completed_target_frequency_units(partial: &PartialDfa) -> u16 {
        let classes = partial.alphabet.classes();
        let row = partial
            .forward
            .transitions
            .get(..classes)
            .expect("completed initial row");
        partial
            .alphabet
            .byte_to_class
            .iter()
            .enumerate()
            .filter_map(|(byte, &class)| {
                let next = row[usize::from(class)].next();
                (next != NO_STATE
                    && usize::try_from(next)
                        .ok()
                        .is_some_and(|next| next < partial.forward.complete_rows))
                .then(|| {
                    estimated_byte_frequency_units(
                        u8::try_from(byte).expect("byte alphabet index"),
                    )
                })
            })
            .fold(0_u16, |sum, units| sum.saturating_add(units))
    }

    #[test]
    fn class_mass_order_commits_canonical_rows_and_prioritizes_wide_branches() {
        let raw = weighted_branch_graph();
        let fifo = declined_partial_with_order(&raw, DfaReplayOrder::Fifo);
        let ranked =
            declined_partial_with_order(&raw, DfaReplayOrder::DescendingClassMass);

        for partial in [&fifo, &ranked] {
            assert_eq!(partial.forward.complete_rows, 2);
            assert_eq!(partial.forward.discovered_states, 4);
            assert_eq!(
                partial.forward.transitions.len(),
                partial.forward.complete_rows * partial.alphabet.classes(),
                "the state-limit refusal occurred mid-row but published no partial row",
            );
            assert_eq!(
                partial.forward.start_actions.len(),
                partial.forward.transitions.len(),
            );
        }
        assert_eq!(initial_completed_target_mass(&fifo), 1);
        assert_eq!(initial_completed_target_mass(&ranked), 158);
        assert!(initial_completed_target_mass(&ranked) > initial_completed_target_mass(&fifo));

        // Canonical table columns remain class-id ordered even though the wide
        // class was evaluated first: its initial destination is state one.
        let wide_class = ranked.alphabet.class(b'b');
        let narrow_class = ranked.alphabet.class(b'a');
        assert_eq!(ranked.forward.transitions[wide_class].next(), 1);
        assert_eq!(ranked.forward.transitions[narrow_class].next(), 2);
        assert_eq!(fifo.forward.transitions[narrow_class].next(), 1);
        assert_eq!(fifo.forward.transitions[wide_class].next(), 2);
    }

    #[test]
    fn estimated_frequency_order_prioritizes_hot_equal_mass_branches() {
        let raw = estimated_frequency_branch_graph();
        let mass = declined_partial_with_order(&raw, DfaReplayOrder::DescendingClassMass);
        let frequency = declined_partial_with_order(
            &raw,
            DfaReplayOrder::DescendingEstimatedClassFrequency,
        );

        for partial in [&mass, &frequency] {
            assert_eq!(partial.forward.complete_rows, 2);
            assert_eq!(partial.forward.discovered_states, 4);
            assert_eq!(
                partial.forward.transitions.len(),
                partial.forward.complete_rows * partial.alphabet.classes(),
            );
        }
        assert_eq!(initial_completed_target_frequency_units(&mass), 1);
        assert_eq!(initial_completed_target_frequency_units(&frequency), 24);

        let rare_class = frequency.alphabet.class(1);
        let common_class = frequency.alphabet.class(b'e');
        assert_eq!(mass.forward.transitions[rare_class].next(), 1);
        assert_eq!(mass.forward.transitions[common_class].next(), 2);
        assert_eq!(frequency.forward.transitions[common_class].next(), 1);
        assert_eq!(frequency.forward.transitions[rare_class].next(), 2);
    }

    fn forward_with_work_limit(
        raw: &RawPlan,
        alphabet: &Alphabet,
        max_work: u64,
        replay_order: DfaReplayOrder,
    ) -> (ForwardBuildOutcome, BuildBudget) {
        let mut budget = BuildBudget::new(DeterminizeLimits {
            max_work,
            ..DeterminizeLimits::unlimited()
        });
        budget.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
        let outcome = build_forward(
            raw,
            alphabet,
            &mut budget,
            ForwardSemantics::Ordered,
            replay_order,
        )
        .expect("valid weighted branch graph");
        (outcome, budget)
    }

    #[test]
    fn ranked_work_decline_commits_only_the_last_exact_complete_row() {
        let raw = weighted_branch_graph();
        let alphabet = unlimited_graph_alphabet(&raw);
        let precharge = 512 + 2 * u64::try_from(alphabet.classes()).unwrap();
        for replay_order in [
            DfaReplayOrder::DescendingClassMass,
            DfaReplayOrder::DescendingEstimatedClassFrequency,
        ] {
            let exact = (precharge..20_000)
                .find(|&limit| {
                    matches!(
                        forward_with_work_limit(&raw, &alphabet, limit, replay_order).0,
                        ForwardBuildOutcome::Declined {
                            partial: Some(PartialForwardDfa {
                                complete_rows: 1,
                                ..
                            }),
                            ..
                        }
                    )
                })
                .expect("a bounded work limit commits exactly the initial row");
            assert!(exact > precharge);

            let (one_short, one_short_budget) =
                forward_with_work_limit(&raw, &alphabet, exact - 1, replay_order);
            assert!(matches!(
                one_short,
                ForwardBuildOutcome::Declined {
                    partial: None,
                    native_slow_partial: None,
                }
            ));
            assert_eq!(one_short_budget.work, exact - 1);

            let (outcome, budget) =
                forward_with_work_limit(&raw, &alphabet, exact, replay_order);
            let ForwardBuildOutcome::Declined {
                partial: Some(partial),
                ..
            } = outcome
            else {
                panic!("exact first-row work did not retain one row")
            };
            assert_eq!(partial.complete_rows, 1);
            assert!(partial.discovered_states > partial.complete_rows);
            assert_eq!(partial.transitions.len(), alphabet.classes());
            assert_eq!(partial.start_actions.len(), alphabet.classes());
            assert_eq!(budget.work, exact);
            assert!(matches!(
                budget.decline,
                Some(DeterminizationDecline {
                    stage: DeterminizationStage::ForwardSubsetConstruction,
                    resource: DeterminizationResource::Work { limit, required },
                    ..
                }) if limit == exact && required == exact + 1
            ));
        }
    }

    #[test]
    fn packed_partial_cells_round_trip_every_semantic_boundary() {
        assert_eq!(core::mem::size_of::<ForwardCell>(), 4);
        assert_eq!(core::mem::size_of::<ReverseCell>(), 4);
        assert_eq!(core::mem::size_of::<PackedForwardCell>(), 4);
        for next in [SEMANTIC_CELL_NO_STATE, SEMANTIC_CELL_FLAG] {
            for flag in [false, true] {
                assert!(ForwardCell::try_new(next, flag).is_none());
                assert!(ReverseCell::try_new(next, flag).is_none());
            }
        }
        for next in [0, MAX_STABLE_DFA_STATES as u32 - 1, NO_STATE] {
            for flag in [false, true] {
                let forward = ForwardCell::new(next, flag);
                assert_eq!(forward.next(), next);
                assert_eq!(forward.accepted(), flag);
                let reverse = ReverseCell::new(next, flag);
                assert_eq!(reverse.next(), next);
                assert_eq!(reverse.reaches_start(), flag);
            }
        }
        for (next, expected) in [
            (0, 0),
            (1, 3),
            (2, PARTIAL_CELL_HOLE_BASE),
            (3, PARTIAL_CELL_HOLE_BASE + 1),
            (NO_STATE, PARTIAL_CELL_DEAD),
        ] {
            for accepted in [false, true] {
                let packed =
                    PackedForwardCell::from_cell(forward_cell! { next, accepted }, 2, 3)
                        .expect("stable partial state fits packed cell");
                assert_eq!(packed.accepted(), accepted);
                assert_eq!(packed.0 & (PARTIAL_CELL_ACCEPTED - 1), expected);
            }
        }
        let outside_stable_range = forward_cell! {
            next: SEMANTIC_CELL_NO_STATE - 1,
            accepted: false,
        };
        assert!(PackedForwardCell::from_cell(outside_stable_range, 0, 1).is_none());

        let complete = forward_cell! {
            next: 1,
            accepted: false,
        };
        assert!(PackedForwardCell::from_cell(complete, 2, 0).is_none());
        assert_eq!(
            PackedForwardCell::from_cell(
                complete,
                2,
                PARTIAL_CELL_HOLE_BASE as usize - 1,
            )
            .expect("largest complete row below the hole tag")
            .0,
            PARTIAL_CELL_HOLE_BASE - 1,
        );
        assert!(
            PackedForwardCell::from_cell(complete, 2, PARTIAL_CELL_HOLE_BASE as usize)
                .is_none()
        );

        let last_hole_state = PARTIAL_CELL_DEAD - PARTIAL_CELL_HOLE_BASE - 1;
        assert_eq!(
            PackedForwardCell::from_cell(
                forward_cell! {
                    next: last_hole_state,
                    accepted: false,
                },
                0,
                1,
            )
            .expect("largest hole below the dead tag")
            .0,
            PARTIAL_CELL_DEAD - 1,
        );
        assert!(
            PackedForwardCell::from_cell(
                forward_cell! {
                    next: last_hole_state + 1,
                    accepted: false,
                },
                0,
                1,
            )
            .is_none()
        );
    }

    #[test]
    fn semantic_cell_allocation_ledger_charges_one_word_per_transition() {
        const CELLS: usize = 17;
        const BYTES: usize = CELLS * core::mem::size_of::<u32>();

        let forward_ledger = DeterminizeAllocationLedger::new(BYTES);
        let mut forward_budget = BuildBudget::new_slow(
            DeterminizeLimits::unlimited(),
            forward_ledger.clone(),
        );
        forward_budget.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
        let forward = build_vec::<ForwardCell>(CELLS, &mut forward_budget)
            .expect("one-word forward cells fit the exact byte ceiling");
        assert!(forward.capacity() >= CELLS);
        assert_eq!(forward_ledger.peak_bytes(), BYTES);
        assert!(!forward_budget.charge_allocation::<ForwardCell>(1));
        assert!(matches!(
            forward_budget.decline,
            Some(DeterminizationDecline {
                resource: DeterminizationResource::Allocation {
                    requested_elements: 1,
                    element_size: 4,
                },
                ..
            })
        ));

        let reverse_ledger = DeterminizeAllocationLedger::new(BYTES);
        let mut reverse_budget = BuildBudget::new_slow(
            DeterminizeLimits::unlimited(),
            reverse_ledger.clone(),
        );
        reverse_budget.begin_stage(DeterminizationStage::ReverseSubsetConstruction);
        let reverse = build_vec::<ReverseCell>(CELLS, &mut reverse_budget)
            .expect("one-word reverse cells fit the exact byte ceiling");
        assert!(reverse.capacity() >= CELLS);
        assert_eq!(reverse_ledger.peak_bytes(), BYTES);
    }

    #[test]
    fn packed_publication_allocation_replaces_numeric_decline_receipt() {
        let mut budget = BuildBudget::new(DeterminizeLimits::default());
        budget.begin_stage(DeterminizationStage::ReverseSubsetConstruction);
        assert!(budget.reserve_state(3));
        assert!(budget.charge(5));
        budget.decline(DeterminizationResource::Transitions {
            limit: 3,
            required: 4,
        });
        budget.replace_decline_with_allocation::<PackedForwardCell>(17);

        let report = budget.into_report();
        let decline = report.decline.expect("packed publication declined");
        assert_eq!(
            decline.stage,
            DeterminizationStage::ReverseSubsetConstruction
        );
        assert_eq!(decline.work_completed, 6);
        assert_eq!(decline.states_completed, 1);
        assert_eq!(decline.transitions_completed, 3);
        assert_eq!(
            decline.resource,
            DeterminizationResource::Allocation {
                requested_elements: 17,
                element_size: core::mem::size_of::<PackedForwardCell>(),
            }
        );
    }

    fn synthetic_partial(
        transitions: Vec<ForwardCell>,
        start_actions: Vec<ForwardStartAction>,
        complete_rows: usize,
        discovered_states: usize,
        resume_keys: Vec<ForwardKey>,
    ) -> PartialDfa {
        let mut packed_transitions = Vec::with_capacity(transitions.len());
        for &cell in &transitions {
            packed_transitions.push(
                PackedForwardCell::from_cell(cell, complete_rows, 1)
                    .expect("synthetic transition fits the packed table"),
            );
        }
        PartialDfa {
            alphabet: Alphabet {
                byte_to_class: [0; 256],
                representatives: vec![0].into_boxed_slice(),
            },
            forward: PartialForwardDfa {
                initial_pending: false,
                initial_terminal: false,
                transitions,
                packed_transitions: Some(packed_transitions),
                start_actions,
                discovered_states,
                complete_rows,
                resume_keys,
            },
            effective_limits: DeterminizeLimits::default(),
        }
    }

    fn one_row_hole(accepted: bool) -> PartialDfa {
        synthetic_partial(
            vec![forward_cell! { next: 1, accepted }],
            vec![ForwardStartAction::Propagate],
            1,
            2,
            vec![ForwardKey {
                items: vec![0],
                pending: accepted,
            }],
        )
    }

    #[test]
    fn complete_zero_frontier_view_requires_authenticated_packing() {
        let complete = synthetic_partial(
            vec![forward_cell! {
                next: 0,
                accepted: true,
            }],
            vec![ForwardStartAction::Propagate],
            1,
            1,
            Vec::new(),
        );
        assert!(complete.native_complete_view().is_some());
        assert!(complete.native_incomplete_view().is_none());

        let mut unauthenticated = complete;
        unauthenticated
            .forward
            .packed_transitions
            .as_mut()
            .expect("synthetic packing")[0] = PackedForwardCell(0);
        assert!(unauthenticated.native_complete_view().is_none());
    }

    #[test]
    fn final_byte_hole_commits_outputs_without_resuming() {
        let source = b"x";
        for accepted in [false, true] {
            let partial = one_row_hole(accepted);
            let expected_end = accepted.then_some(1);
            assert_eq!(
                partial.exists(source, 0, 1, &[], None).unwrap(),
                PartialDfaResult::Complete(accepted),
            );
            assert_eq!(
                partial.selected_end(source, 0, 1, &[], None).unwrap(),
                PartialDfaResult::Complete(expected_end),
            );
            assert_eq!(
                partial
                    .selected_span_end(source, 0, 1, &[], None)
                    .unwrap(),
                PartialDfaResult::Complete(PartialDfaSelection {
                    end: expected_end,
                    start: accepted.then_some(0),
                }),
            );
        }

        let accepted_dead = synthetic_partial(
            vec![forward_cell! {
                next: NO_STATE,
                accepted: true,
            }],
            vec![ForwardStartAction::Propagate],
            1,
            1,
            Vec::new(),
        );
        assert_eq!(
            accepted_dead
                .selected_span_end(source, 0, 1, &[], None)
                .unwrap(),
            PartialDfaResult::Complete(PartialDfaSelection {
                end: Some(1),
                start: Some(0),
            }),
        );
    }

    #[test]
    fn nonfinal_hole_resumes_unless_earliest_acceptance_is_complete() {
        let source = b"xx";
        let rejected = one_row_hole(false);
        let rejected_resume = PartialDfaResume {
            state: 0,
            position: 1,
            pending_end: None,
        };
        assert_eq!(
            rejected.exists(source, 0, 2, &[], None).unwrap(),
            PartialDfaResult::Resume(rejected_resume),
        );
        assert_eq!(
            rejected.selected_end(source, 0, 2, &[], None).unwrap(),
            PartialDfaResult::Resume(rejected_resume),
        );
        assert_eq!(
            rejected
                .selected_span_end(source, 0, 2, &[], None)
                .unwrap(),
            PartialDfaResult::Resume(rejected_resume),
        );

        let accepted = one_row_hole(true);
        assert_eq!(
            accepted.exists(source, 0, 2, &[], None).unwrap(),
            PartialDfaResult::Complete(true),
        );
        let accepted_resume = PartialDfaResume {
            state: 0,
            position: 1,
            pending_end: Some(1),
        };
        assert_eq!(
            accepted.selected_end(source, 0, 2, &[], None).unwrap(),
            PartialDfaResult::Resume(accepted_resume),
        );
        assert_eq!(
            accepted
                .selected_span_end(source, 0, 2, &[], None)
                .unwrap(),
            PartialDfaResult::Resume(accepted_resume),
        );
    }

    #[test]
    fn final_byte_hole_preserves_parallel_start_actions() {
        let source = b"xx";
        for (action, expected_start) in [
            (ForwardStartAction::Drop, None),
            (ForwardStartAction::Propagate, Some(0)),
            (ForwardStartAction::Reset, Some(1)),
        ] {
            let partial = synthetic_partial(
                vec![
                    forward_cell! {
                        next: 1,
                        accepted: false,
                    },
                    forward_cell! {
                        next: 2,
                        accepted: true,
                    },
                ],
                vec![action, ForwardStartAction::Propagate],
                2,
                3,
                vec![ForwardKey {
                    items: vec![0],
                    pending: true,
                }],
            );
            assert_eq!(
                partial
                    .selected_span_end(source, 0, 2, &[], None)
                    .unwrap(),
                PartialDfaResult::Complete(PartialDfaSelection {
                    end: Some(2),
                    start: expected_start,
                }),
                "{action:?}",
            );
        }
    }

    #[test]
    fn partial_prefix_full_byte_classifier_matches_scalar_at_every_alignment() {
        let mut words = [0_u64; 4];
        for byte in [0_u8, 17, 128, 255] {
            words[usize::from(byte) / 64] |= 1_u64 << (usize::from(byte) % 64);
        }
        let set = ByteSet256::from_words(words);
        let classifier = ByteSetClassifier::new(set);
        let source = (0_u8..=u8::MAX).cycle().take(384).collect::<Vec<_>>();
        for start in 0..32 {
            for length in 0..=96 {
                let bytes = &source[start..start + length];
                assert_eq!(
                    find_byte_set_member(set, &classifier, bytes),
                    bytes.iter().position(|&byte| set.contains(byte)),
                    "start={start}, length={length}"
                );
            }
        }

        let anchored = AnchoredByteSet::from_words(words);
        let (plan, supported) = PartialDfaPrefixPlan::derive(&[anchored]);
        assert!(supported);
        let plan = plan.expect("four-member prefix has a general classifier");
        assert_eq!(plan.next_candidate(&[anchored], b"zz\x11x", 0, 4), Some(2));

        let singleton = |byte: u8| {
            let mut words = [0_u64; 4];
            words[usize::from(byte) / 64] |= 1_u64 << (usize::from(byte) % 64);
            AnchoredByteSet::from_words(words)
        };
        let singleton_primary = singleton(b'q');
        let suffix = singleton(b'z');
        let (plan, supported) =
            PartialDfaPrefixPlan::derive(&[singleton_primary, suffix]);
        assert!(supported);
        let plan = plan.expect("selective two-position prefix");
        assert_eq!(plan.primary_depth(), 0);
        assert_eq!(
            plan.next_candidate(&[singleton_primary, suffix], b"qxqz", 0, 4),
            Some(2),
            "skipping the proved primary must still verify every secondary position"
        );
    }

    #[test]
    fn partial_publication_drops_abandoned_bfs_capacity() {
        let mut transitions = Vec::with_capacity(4_096);
        transitions.extend((0_u32..12).map(|next| forward_cell! {
            next,
            accepted: next % 2 == 0,
        }));
        let mut states = Vec::with_capacity(4_096);
        states.extend((0_u32..4).map(|item| ForwardKey {
            items: vec![item],
            pending: item % 2 == 1,
        }));

        let actions = vec![ForwardStartAction::Drop; transitions.len()];
        let partial = compact_partial_forward(&transitions, &actions, states, 2, 3, false, false)
            .expect("compact retained prefix");
        assert_eq!(partial.discovered_states, 4);
        assert_eq!(partial.complete_rows, 2);
        assert_eq!(partial.transitions, transitions[..6]);
        assert_eq!(partial.resume_keys.len(), 2);
        assert_eq!(partial.resume_keys[0].items, [2]);
        assert_eq!(partial.resume_keys[1].items, [3]);
        assert!(partial.transitions.capacity() < 4_096);
        assert!(partial.resume_keys.capacity() < 4_096);
    }

    fn lowered_assertion_free(pattern: &str) -> RawPlan {
        use fre_lower::{LowerLimits, OperationSemantics};
        use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern.to_owned(),
            CompatibilityProfile::RustBytes(RustProfile::default()),
        ))
        .expect("parse assertion-free fixture");
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust request returned non-Rust pattern");
        };
        fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("lower assertion-free fixture")
        .into_plan()
    }

    fn completed_machine(outcome: DeterminizeOutcome) -> OrderedDfa {
        match outcome {
            DeterminizeOutcome::Complete { machine, .. } => machine,
            DeterminizeOutcome::Declined { report, .. } => {
                panic!("unlimited complete-machine fixture declined: {report:?}")
            }
        }
    }

    #[test]
    fn complete_ranked_replays_preserve_canonical_tables_across_graph_families() {
        for pattern in [
            "a",
            "(?:a|b)c",
            "[a-z]+Q",
            "(?:ab|a[bc]|[d-f]{0,2})z",
            "a+Q|[b-c][a-b]{1,5}(?:x+|y+)",
            "(?:[a-c][x-z]?|[^q]{1,2})R",
        ] {
            let raw = lowered_assertion_free(pattern);
            for (semantics, wants_span) in [
                (ForwardSemantics::Exists, false),
                (ForwardSemantics::Ordered, false),
                (ForwardSemantics::Ordered, true),
                (ForwardSemantics::EndpointPruned, true),
            ] {
                let fifo = completed_machine(
                    determinize_impl(
                        &raw,
                        wants_span,
                        DeterminizeLimits::unlimited(),
                        semantics,
                        DfaReplayOrder::Fifo,
                    )
                    .expect("FIFO complete construction"),
                );
                let mut fifo_stats = fifo.stats();
                let fifo_work = fifo_stats.build_work;
                fifo_stats.build_work = 0;
                for replay_order in [
                    DfaReplayOrder::DescendingClassMass,
                    DfaReplayOrder::DescendingEstimatedClassFrequency,
                ] {
                    let ranked = completed_machine(
                        determinize_impl(
                            &raw,
                            wants_span,
                            DeterminizeLimits::unlimited(),
                            semantics,
                            replay_order,
                        )
                        .expect("ranked complete construction"),
                    );
                    assert_eq!(
                        ranked.alphabet, fifo.alphabet,
                        "{pattern:?}/{semantics:?}/{replay_order:?}",
                    );
                    assert_eq!(
                        ranked.forward, fifo.forward,
                        "{pattern:?}/{semantics:?}/{replay_order:?}",
                    );
                    assert_eq!(
                        ranked.reverse, fifo.reverse,
                        "{pattern:?}/{semantics:?}/{replay_order:?}",
                    );
                    let mut ranked_stats = ranked.stats();
                    let ranked_work = ranked_stats.build_work;
                    ranked_stats.build_work = 0;
                    assert_eq!(
                        ranked_stats, fifo_stats,
                        "{pattern:?}/{semantics:?}/{replay_order:?}",
                    );
                    assert!(
                        ranked_work > fifo_work,
                        "{pattern:?}/{semantics:?}/{replay_order:?}",
                    );
                }
            }
        }
    }

    fn byte_edge_signature(raw: &RawPlan, byte: u8) -> Vec<bool> {
        raw.edge_kinds
            .iter()
            .enumerate()
            .map(|(edge, &kind)| {
                kind == EdgeKind::ByteRange
                    && raw.byte_starts[edge] <= byte
                    && byte <= raw.byte_ends[edge]
            })
            .collect()
    }

    fn equivalent_consume_pair_graph() -> RawPlan {
        RawPlan {
            start: 0,
            roles: vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
            edge_offsets: vec![0, 1, 2, 2],
            edge_targets: vec![2, 2],
            edge_kinds: vec![EdgeKind::ByteRange, EdgeKind::ByteRange],
            byte_starts: vec![b'a', b'a'],
            byte_ends: vec![b'a', b'a'],
        }
    }

    fn unlimited_graph_alphabet(raw: &RawPlan) -> Alphabet {
        let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
        budget.begin_stage(DeterminizationStage::AlphabetPartition);
        let built = Alphabet::build(raw, &mut budget)
            .expect("valid graph alphabet")
            .expect("unlimited graph alphabet");
        budget
            .complete_stage(DeterminizationStage::AlphabetPartition)
            .expect("complete graph alphabet stage");
        built.alphabet
    }

    #[test]
    fn slow_allocation_ledger_charges_nested_reverse_incoming_rows() {
        let raw = equivalent_consume_pair_graph();
        let edge_count = raw.edge_targets.len();
        let state_count = raw.roles.len();
        let expected = edge_count * core::mem::size_of::<u32>()
            + state_count * core::mem::size_of::<Vec<u32>>()
            + state_count * core::mem::size_of::<usize>()
            // Slow-path vector growth has a four-element minimum.
            + 4 * core::mem::size_of::<u32>();

        let ledger = DeterminizeAllocationLedger::new(expected);
        let mut budget = BuildBudget::new_slow(DeterminizeLimits::unlimited(), ledger.clone());
        budget.begin_stage(DeterminizationStage::ReverseSubsetConstruction);
        assert!(
            Incoming::build(&raw, &mut budget)
                .expect("valid reverse graph")
                .is_some()
        );
        assert_eq!(ledger.peak_bytes(), expected);
        assert!(!budget.declined);

        let ledger = DeterminizeAllocationLedger::new(expected - 1);
        let mut budget = BuildBudget::new_slow(DeterminizeLimits::unlimited(), ledger);
        budget.begin_stage(DeterminizationStage::ReverseSubsetConstruction);
        assert!(
            Incoming::build(&raw, &mut budget)
                .expect("valid reverse graph")
                .is_none()
        );
        assert!(matches!(
            budget.decline,
            Some(DeterminizationDecline {
                stage: DeterminizationStage::ReverseSubsetConstruction,
                resource: DeterminizationResource::Allocation {
                    requested_elements: 4,
                    element_size: 4,
                },
                ..
            })
        ));
    }

    #[test]
    fn slow_allocation_decline_never_retains_a_partial_machine() {
        let raw = lowered_assertion_free("a+Q|[b-c][a-b]{1,5}(?:x+|y+)");
        let (outcome, peak) = determinize_for_output_with_allocation_limit(
            &raw,
            OutputContract::Span,
            true,
            DeterminizeLimits::unlimited(),
            0,
        )
        .expect("bounded slow determinization");
        assert_eq!(peak, 0);
        match outcome {
            DeterminizeOutcome::Declined {
                report,
                partial,
                native_slow_partial,
            } => {
                assert!(partial.is_none());
                assert!(native_slow_partial.is_none());
                assert!(matches!(
                    report.decline,
                    Some(DeterminizationDecline {
                        resource: DeterminizationResource::Allocation { .. },
                        ..
                    })
                ));
            }
            DeterminizeOutcome::Complete { .. } => {
                panic!("zero-byte slow allocation cap unexpectedly completed")
            }
        }
    }

    #[test]
    fn slow_numeric_decline_retains_only_the_charged_forward_prefix() {
        let raw = weighted_branch_graph();
        let allocation_limit = 16 * 1024 * 1024;
        let (outcome, peak) = determinize_for_output_with_allocation_limit(
            &raw,
            OutputContract::SelectedEnd,
            false,
            DeterminizeLimits {
                max_states: 4,
                ..DeterminizeLimits::unlimited()
            },
            allocation_limit,
        )
        .expect("bounded slow ordered construction");
        assert!(peak <= allocation_limit);
        let DeterminizeOutcome::Declined {
            report,
            partial: None,
            native_slow_partial: Some(partial),
        } = outcome
        else {
            panic!("numeric slow refusal did not retain transient native rows")
        };
        assert!(matches!(
            report.decline,
            Some(DeterminizationDecline {
                stage: DeterminizationStage::ForwardSubsetConstruction,
                resource: DeterminizationResource::States { .. },
                ..
            })
        ));
        let (complete_rows, discovered_states) = partial.retained_dimensions();
        assert!(complete_rows > 0);
        assert!(complete_rows < discovered_states);
        assert_eq!(
            partial.native_view().forward_cells.len(),
            complete_rows * partial.native_view().class_count
        );
        assert!(partial.native_view().forward_cells.iter().all(|cell| {
            cell.next() == NO_STATE
                || usize::try_from(cell.next())
                    .ok()
                    .is_some_and(|next| next < discovered_states)
        }));
    }

    fn first_slow_reverse_completion_work(raw: &RawPlan, allocation_limit: usize) -> u64 {
        let (complete, peak) = determinize_for_output_with_allocation_limit(
            raw,
            OutputContract::Span,
            true,
            DeterminizeLimits::unlimited(),
            allocation_limit,
        )
        .expect("complete slow reverse-stage oracle");
        assert!(peak <= allocation_limit);
        let DeterminizeOutcome::Complete { report, .. } = complete else {
            panic!("unlimited slow Span construction declined")
        };
        assert!(report
            .completed_stages
            .contains(&DeterminizationStage::ReverseSubsetConstruction));

        let mut low = 0_u64;
        let mut high = report.work_completed;
        while low < high {
            let middle = low + (high - low) / 2;
            let (outcome, bounded_peak) = determinize_for_output_with_allocation_limit(
                raw,
                OutputContract::Span,
                true,
                DeterminizeLimits {
                    max_work: middle,
                    ..DeterminizeLimits::unlimited()
                },
                allocation_limit,
            )
            .expect("bounded slow reverse-stage search");
            assert!(bounded_peak <= allocation_limit);
            let bounded_report = match &outcome {
                DeterminizeOutcome::Complete { report, .. }
                | DeterminizeOutcome::Declined { report, .. } => report,
            };
            if bounded_report
                .completed_stages
                .contains(&DeterminizationStage::ReverseSubsetConstruction)
            {
                high = middle;
            } else {
                low = middle
                    .checked_add(1)
                    .expect("bounded reverse-stage midpoint");
            }
        }
        low
    }

    #[test]
    fn slow_reverse_decline_retains_a_complete_forward_without_reverse() {
        let raw = lowered_assertion_free("a+Q|[b-c][a-b]{1,5}(?:x+|y+)");
        let allocation_limit = 32 * 1024 * 1024;
        let reverse_completion_work =
            first_slow_reverse_completion_work(&raw, allocation_limit);
        assert_eq!(
            first_slow_reverse_completion_work(&raw, allocation_limit),
            reverse_completion_work,
            "the exact reverse-stage boundary must be reproducible"
        );
        let decline_work = reverse_completion_work
            .checked_sub(1)
            .expect("reverse construction requires work");
        let run_decline = || {
            determinize_for_output_with_allocation_limit(
                &raw,
                OutputContract::Span,
                true,
                DeterminizeLimits {
                    max_work: decline_work,
                    ..DeterminizeLimits::unlimited()
                },
                allocation_limit,
            )
            .expect("bounded slow Span construction")
        };
        let (outcome, peak) = run_decline();
        let (replayed_outcome, replayed_peak) = run_decline();
        assert!(peak <= allocation_limit);
        assert_eq!(peak, replayed_peak);
        let (
            DeterminizeOutcome::Declined {
                report,
                partial: None,
                native_slow_partial: Some(partial),
            },
            DeterminizeOutcome::Declined {
                report: replayed_report,
                partial: None,
                native_slow_partial: Some(replayed_partial),
            },
        ) = (&outcome, &replayed_outcome)
        else {
            panic!("post-forward slow refusal did not retain transient native rows")
        };
        assert_eq!(report, replayed_report);
        assert_eq!(
            partial.retained_dimensions(),
            replayed_partial.retained_dimensions()
        );
        assert_eq!(
            partial.stats(report.work_completed),
            replayed_partial.stats(replayed_report.work_completed)
        );
        assert!(report
            .completed_stages
            .contains(&DeterminizationStage::ForwardSubsetConstruction));
        assert!(!report
            .completed_stages
            .contains(&DeterminizationStage::ReverseSubsetConstruction));
        let decline = report.decline.expect("reverse-stage work decline");
        assert_eq!(decline.stage, DeterminizationStage::ReverseSubsetConstruction);
        assert_eq!(
            decline.resource,
            DeterminizationResource::Work {
                limit: decline_work,
                required: reverse_completion_work,
            }
        );
        assert_eq!(decline.work_completed, decline_work);
        let (complete_rows, discovered_states) = partial.retained_dimensions();
        assert!(complete_rows > 0);
        assert_eq!(complete_rows, discovered_states);
        assert_eq!(partial.stats(report.work_completed).reverse_states, 0);
        assert_eq!(partial.native_view().reverse_initial, None);
        assert!(partial.native_view().reverse_cells.is_empty());
        assert!(!partial.retained_forward_minimized());
    }

    #[test]
    fn slow_late_decline_retains_the_completed_reverse_machine() {
        let raw = lowered_assertion_free("a+Q|[b-c][a-b]{1,5}(?:x+|y+)");
        let allocation_limit = 32 * 1024 * 1024;
        let (complete, _) = determinize_for_output_with_allocation_limit(
            &raw,
            OutputContract::Span,
            true,
            DeterminizeLimits::unlimited(),
            allocation_limit,
        )
        .expect("complete slow Span construction");
        let DeterminizeOutcome::Complete { report, .. } = complete else {
            panic!("unlimited slow Span construction declined")
        };
        let (outcome, peak) = determinize_for_output_with_allocation_limit(
            &raw,
            OutputContract::Span,
            true,
            DeterminizeLimits {
                max_work: report.work_completed.checked_sub(1).expect("nonzero slow work"),
                ..DeterminizeLimits::unlimited()
            },
            allocation_limit,
        )
        .expect("late bounded slow Span construction");
        assert!(peak <= allocation_limit);
        let DeterminizeOutcome::Declined {
            report,
            partial: None,
            native_slow_partial: Some(partial),
        } = outcome
        else {
            panic!("late slow refusal did not retain transient native rows")
        };
        assert!(report.decline.as_ref().is_some_and(|decline| {
            matches!(
                decline.stage,
                DeterminizationStage::DfaStateMinimization
                    | DeterminizationStage::AlphabetColumnCoalescing
            ) && matches!(decline.resource, DeterminizationResource::Work { .. })
        }));
        let (complete_rows, discovered_states) = partial.retained_dimensions();
        assert_eq!(complete_rows, discovered_states);
        let stats = partial.stats(report.work_completed);
        assert!(stats.reverse_states_before_minimization > 0);
        assert!(stats.reverse_states > 0);
        let view = partial.native_view();
        assert_eq!(view.reverse_initial, Some(0));
        assert!(!view.reverse_cells.is_empty());
        assert_eq!(
            view.reverse_cells.len(),
            stats.reverse_states * view.class_count
        );
    }

    #[test]
    fn endpoint_dominance_product_and_cache_caps_refuse_conservatively() {
        let raw = equivalent_consume_pair_graph();
        let alphabet = unlimited_graph_alphabet(&raw);

        let mut complete_budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let mut complete = EndpointDominance::new(&raw, &mut complete_budget)
            .expect("complete endpoint proof scratch");
        assert_eq!(
            complete
                .proves_endpoint_inclusion(&raw, &alphabet, 0, 1, &mut complete_budget)
                .expect("complete endpoint relation"),
            Some(true)
        );
        assert!(!complete_budget.declined);

        let mut product_budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let mut product_capped = EndpointDominance::new_with_limits(
            &raw,
            &mut product_budget,
            EndpointDominanceLimits {
                product_states: 1,
                ..EndpointDominanceLimits::default()
            },
        )
        .expect("product-capped endpoint proof scratch");
        assert_eq!(
            product_capped
                .proves_endpoint_inclusion(&raw, &alphabet, 0, 1, &mut product_budget)
                .expect("product-capped endpoint relation"),
            Some(false)
        );
        assert!(!product_budget.declined);

        let mut item_budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let mut item_capped = EndpointDominance::new_with_limits(
            &raw,
            &mut item_budget,
            EndpointDominanceLimits {
                product_items: 1,
                ..EndpointDominanceLimits::default()
            },
        )
        .expect("item-capped endpoint proof scratch");
        assert_eq!(
            item_capped
                .proves_endpoint_inclusion(&raw, &alphabet, 0, 1, &mut item_budget)
                .expect("item-capped endpoint relation"),
            Some(false)
        );
        assert!(!item_budget.declined);

        let mut cache_budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let mut cache_capped = EndpointDominance::new_with_limits(
            &raw,
            &mut cache_budget,
            EndpointDominanceLimits {
                cached_pairs: 0,
                ..EndpointDominanceLimits::default()
            },
        )
        .expect("cache-capped endpoint proof scratch");
        assert_eq!(
            cache_capped
                .proves_endpoint_inclusion(&raw, &alphabet, 0, 1, &mut cache_budget)
                .expect("cache-capped endpoint relation"),
            Some(false)
        );
        assert!(cache_capped.disabled);
        assert!(!cache_budget.declined);
    }

    #[test]
    fn endpoint_rescue_does_not_tax_an_exact_work_completed_baseline() {
        let raw = lowered_assertion_free("ab");
        let first = determinize_impl(
            &raw,
            true,
            DeterminizeLimits::unlimited(),
            ForwardSemantics::Ordered,
            DfaReplayOrder::DescendingEstimatedClassFrequency,
        )
        .expect("unlimited ordered baseline");
        let first_work = match first {
            DeterminizeOutcome::Complete { report, .. } => report.work_completed,
            DeterminizeOutcome::Declined { report, .. } => {
                panic!("unlimited ordered baseline declined: {report:?}")
            }
        };
        let limits = DeterminizeLimits {
            max_work: first_work,
            ..DeterminizeLimits::unlimited()
        };
        let ordered = determinize_impl(
            &raw,
            true,
            limits,
            ForwardSemantics::Ordered,
            DfaReplayOrder::DescendingEstimatedClassFrequency,
        )
        .expect("exact-work ordered baseline");
        let specialized = determinize_for_output(&raw, OutputContract::Span, true, limits)
            .expect("exact-work endpoint construction");
        match (ordered, specialized) {
            (
                DeterminizeOutcome::Complete {
                    machine: ordered_machine,
                    report: ordered_report,
                },
                DeterminizeOutcome::Complete {
                    machine: specialized_machine,
                    report: specialized_report,
                },
            ) => {
                assert_eq!(specialized_machine, ordered_machine);
                assert_eq!(specialized_report, ordered_report);
                assert_eq!(specialized_report.work_completed, first_work);
            }
            (ordered, specialized) => {
                panic!(
                    "exact baseline/rescue mismatch: ordered={:?}, specialized={:?}",
                    ordered.work_completed(),
                    specialized.work_completed()
                )
            }
        }
    }

    #[test]
    fn graph_alphabet_is_the_canonical_full_edge_membership_partition() {
        // The broad range is interrupted by a narrower edge, so both the
        // nonmatching intervals and the broad-only intervals recur at
        // disjoint byte positions.
        let raw = lowered_assertion_free("(?:[a-z]|mX)");
        let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
        budget.begin_stage(DeterminizationStage::AlphabetPartition);
        let built = Alphabet::build(&raw, &mut budget)
            .expect("valid graph alphabet")
            .expect("unlimited graph alphabet");
        budget
            .complete_stage(DeterminizationStage::AlphabetPartition)
            .expect("complete graph alphabet stage");

        assert!(built.graph_classes < built.boundary_classes);
        assert_eq!(built.graph_classes, built.alphabet.classes());
        for left in 0_u16..=255 {
            let left = u8::try_from(left).expect("byte");
            for right in 0_u16..=255 {
                let right = u8::try_from(right).expect("byte");
                assert_eq!(
                    built.alphabet.class(left) == built.alphabet.class(right),
                    byte_edge_signature(&raw, left) == byte_edge_signature(&raw, right),
                    "{left:#04x}/{right:#04x}"
                );
            }
        }
        for (class, &representative) in built.alphabet.representatives.iter().enumerate() {
            let first = (0_u16..=255)
                .map(|byte| u8::try_from(byte).expect("byte"))
                .find(|&byte| built.alphabet.class(byte) == class)
                .expect("represented graph class");
            assert_eq!(representative, first);
        }
    }

    #[test]
    fn graph_alphabet_work_limit_is_exact_and_transactional() {
        let raw = lowered_assertion_free("(?:[a-z]|mX)");
        let mut unrestricted = BuildBudget::new(DeterminizeLimits::unlimited());
        unrestricted.begin_stage(DeterminizationStage::AlphabetPartition);
        Alphabet::build(&raw, &mut unrestricted)
            .expect("valid graph alphabet")
            .expect("unlimited graph alphabet");
        unrestricted
            .complete_stage(DeterminizationStage::AlphabetPartition)
            .expect("complete graph alphabet stage");
        let exact_work = unrestricted.work;
        assert!(exact_work > 0);

        let mut limited = BuildBudget::new(DeterminizeLimits {
            max_work: exact_work - 1,
            ..DeterminizeLimits::unlimited()
        });
        limited.begin_stage(DeterminizationStage::AlphabetPartition);
        assert!(
            Alphabet::build(&raw, &mut limited)
                .expect("valid limited graph alphabet")
                .is_none()
        );
        let report = limited.into_report();
        assert_eq!(report.completed_stages.as_ref(), &[]);
        assert_eq!(
            report.decline,
            Some(DeterminizationDecline {
                stage: DeterminizationStage::AlphabetPartition,
                resource: DeterminizationResource::Work {
                    limit: exact_work - 1,
                    required: exact_work,
                },
                work_completed: exact_work - 1,
                states_completed: 0,
                transitions_completed: 0,
            })
        );

        let mut exact = BuildBudget::new(DeterminizeLimits {
            max_work: exact_work,
            ..DeterminizeLimits::unlimited()
        });
        exact.begin_stage(DeterminizationStage::AlphabetPartition);
        Alphabet::build(&raw, &mut exact)
            .expect("valid exact graph alphabet")
            .expect("exact graph alphabet budget");
        exact
            .complete_stage(DeterminizationStage::AlphabetPartition)
            .expect("complete exact graph alphabet stage");
        let report = exact.into_report();
        assert_eq!(report.work_completed, exact_work);
        assert_eq!(report.decline, None);
    }

    #[test]
    fn structural_refinement_merges_equivalent_forward_states() {
        let cells = [
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 2,
                accepted: false,
            },
            forward_cell! {
                next: 3,
                accepted: true,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: 3,
                accepted: true,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
        ];
        let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let minimized = minimize_complete_machine(&cells, 4, 2, &mut budget)
            .expect("valid table")
            .expect("sufficient budget");

        assert_eq!(minimized.states, 3);
        assert_eq!(
            minimized.transitions.as_slice(),
            &[
                forward_cell! {
                    next: 1,
                    accepted: false,
                },
                forward_cell! {
                    next: 1,
                    accepted: false,
                },
                forward_cell! {
                    next: 2,
                    accepted: true,
                },
                forward_cell! {
                    next: NO_STATE,
                    accepted: false,
                },
                forward_cell! {
                    next: NO_STATE,
                    accepted: false,
                },
                forward_cell! {
                    next: NO_STATE,
                    accepted: false,
                },
            ]
        );
    }

    #[test]
    fn observable_flags_and_dead_sentinel_participate_in_equivalence() {
        let cells = [
            reverse_cell! {
                next: 1,
                reaches_start: false,
            },
            reverse_cell! {
                next: 2,
                reaches_start: false,
            },
            reverse_cell! {
                next: NO_STATE,
                reaches_start: false,
            },
            reverse_cell! {
                next: 2,
                reaches_start: false,
            },
            reverse_cell! {
                next: NO_STATE,
                reaches_start: true,
            },
            reverse_cell! {
                next: NO_STATE,
                reaches_start: false,
            },
        ];
        let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let minimized = minimize_complete_machine(&cells, 3, 2, &mut budget)
            .expect("valid table")
            .expect("sufficient budget");

        // State 1 differs from state 2 both in its observable output and in
        // taking a real transition instead of the immediate-dead sentinel.
        assert_eq!(minimized.states, 3);
    }

    #[test]
    fn quotient_numbering_is_class_order_bfs_with_initial_state_zero() {
        let cells = [
            forward_cell! {
                next: 3,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: true,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: true,
            },
            forward_cell! {
                next: 2,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: true,
            },
        ];
        let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let minimized = minimize_complete_machine(&cells, 4, 2, &mut budget)
            .expect("valid table")
            .expect("sufficient budget");

        assert_eq!(minimized.states, 4);
        // Old state 3 is reached through the first class and therefore
        // becomes state 1; old state 1 becomes state 2.
        assert_eq!(minimized.transitions[0].next(), 1);
        assert_eq!(minimized.transitions[1].next(), 2);
        // Processing new state 1 then discovers old state 2 as new state 3.
        assert_eq!(minimized.transitions[2].next(), 3);
    }

    #[test]
    fn minimization_declines_cleanly_when_work_is_exhausted() {
        let cells = [forward_cell! {
            next: NO_STATE,
            accepted: false,
        }];
        let mut budget = BuildBudget::new(DeterminizeLimits {
            max_work: 0,
            ..DeterminizeLimits::unlimited()
        });
        budget.begin_stage(DeterminizationStage::DfaStateMinimization);
        assert!(
            minimize_complete_machine(&cells, 1, 1, &mut budget)
                .expect("valid table")
                .is_none()
        );
    }

    #[test]
    fn fallible_storage_decline_records_stage_and_exact_logical_request() {
        let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
        budget.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
        budget.allocation::<u64>(123);
        let report = budget.into_report();
        assert_eq!(
            report.decline,
            Some(DeterminizationDecline {
                stage: DeterminizationStage::ForwardSubsetConstruction,
                resource: DeterminizationResource::Allocation {
                    requested_elements: 123,
                    element_size: core::mem::size_of::<u64>(),
                },
                work_completed: 0,
                states_completed: 0,
                transitions_completed: 0,
            })
        );
    }

    #[test]
    fn generated_complete_machines_preserve_every_short_trace() {
        let mut seed = 0x243f_6a88_85a3_08d3_u64;
        for _ in 0..64 {
            let states = 1 + random_usize(&mut seed, 8);
            let classes = 1 + random_usize(&mut seed, 4);
            let mut cells = Vec::with_capacity(states * classes);
            for _ in 0..states * classes {
                let choice = next_random(&mut seed);
                let next = if choice.is_multiple_of(5) {
                    NO_STATE
                } else {
                    u32::try_from(random_usize(&mut seed, states)).expect("state fits u32")
                };
                cells.push(forward_cell! {
                    next,
                    accepted: next_random(&mut seed) & 1 != 0,
                });
            }

            let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
            let minimized = minimize_complete_machine(&cells, states, classes, &mut budget)
                .expect("generated table is valid")
                .expect("unlimited minimization");
            let mut replay_budget = BuildBudget::new(DeterminizeLimits::unlimited());
            let replayed = minimize_complete_machine(
                &minimized.transitions,
                minimized.states,
                classes,
                &mut replay_budget,
            )
            .expect("minimized table is valid")
            .expect("unlimited replay");
            assert_eq!(replayed.states, minimized.states);
            assert_eq!(replayed.transitions, minimized.transitions);
            for length in 0_u32..=5 {
                for mut encoded in 0..classes.pow(length) {
                    let mut input = vec![0_usize; usize::try_from(length).expect("small length")];
                    for class in &mut input {
                        *class = encoded % classes;
                        encoded /= classes;
                    }
                    assert_eq!(
                        trace(&cells, classes, &input),
                        trace(&minimized.transitions, classes, &input)
                    );
                }
            }
        }
    }

    #[test]
    fn self_loop_plans_keep_accepting_and_non_accepting_bytes_separate() {
        let mut byte_classes = [0_u8; 256];
        byte_classes[64..192].fill(1);
        byte_classes[192..].fill(2);
        let representatives = [0_u8, 64, 192];
        let cells = [
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: true,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
        ];
        let view = forward_native_view(&byte_classes, &representatives, &cells);
        let plans = assert_self_loop_plans_exact(&view);

        assert_eq!(plans.candidate_count, 3);
        assert_eq!(plans.retained_count(), 3);
        assert_eq!(plans.dropped_count, 0);
        assert_eq!(plans.as_slice()[0].state, 0);
        assert_eq!(
            plans.as_slice()[0].acceptance,
            NativeSelfLoopAcceptance::Accepting
        );
        assert_eq!(plans.as_slice()[0].membership_cardinality, 128);
        assert_eq!(plans.as_slice()[1].state, 0);
        assert_eq!(
            plans.as_slice()[1].acceptance,
            NativeSelfLoopAcceptance::NonAccepting
        );
        assert_eq!(plans.as_slice()[1].membership_cardinality, 64);
        assert_eq!(plans.as_slice()[2].state, 1);
        assert_eq!(plans.as_slice()[2].membership_cardinality, 64);
    }

    #[test]
    fn self_loop_plans_follow_minimized_and_coalesced_tables() {
        let mut byte_classes = [0_u8; 256];
        for (byte, class) in byte_classes.iter_mut().enumerate() {
            *class = u8::try_from(byte % 4).expect("four classes");
        }
        let mut alphabet = Alphabet {
            byte_to_class: byte_classes,
            representatives: vec![0_u8, 1, 2, 3].into_boxed_slice(),
        };
        let cells = [
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 2,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 3,
                accepted: true,
            },
            forward_cell! {
                next: 3,
                accepted: true,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 3,
                accepted: true,
            },
            forward_cell! {
                next: 3,
                accepted: true,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: 2,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: 3,
                accepted: true,
            },
        ];
        let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let minimized = minimize_complete_machine(&cells, 4, 4, &mut budget)
            .expect("valid complete table")
            .expect("unlimited minimization");
        assert!(minimized.states < 4);
        let mut forward = ForwardDfa {
            initial_pending: false,
            initial_terminal: false,
            transitions: minimized.transitions,
            states: minimized.states,
        };
        let mut reverse = None;
        coalesce_alphabet_columns(&mut alphabet, &mut forward, &mut reverse, &mut budget)
            .expect("valid complete tables")
            .then_some(())
            .expect("unlimited coalescing");
        assert!(alphabet.classes() < 4);

        let view = forward_native_view(
            &alphabet.byte_to_class,
            &alphabet.representatives,
            &forward.transitions,
        );
        assert_self_loop_plans_exact(&view);
    }

    #[test]
    fn generated_minimized_coalesced_dfas_have_exact_self_loop_plans() {
        let mut seed = 0x1319_8a2e_0370_7344_u64;
        for _ in 0..128 {
            let states = 2_usize
                .checked_add(random_usize(&mut seed, 10))
                .expect("small state count");
            let classes = 2_usize
                .checked_add(random_usize(&mut seed, 7))
                .expect("small class count");
            let mut byte_classes = [0_u8; 256];
            let rotation = random_usize(&mut seed, classes);
            for (byte, destination) in byte_classes.iter_mut().enumerate() {
                let rotated = byte.checked_add(rotation).expect("small byte rotation");
                *destination = u8::try_from(rotated % classes).expect("at most eight classes");
            }
            let mut representatives = vec![None; classes];
            for (byte, &class) in byte_classes.iter().enumerate() {
                let slot = &mut representatives[usize::from(class)];
                if slot.is_none() {
                    *slot = Some(u8::try_from(byte).expect("byte index"));
                }
            }
            let representatives = representatives
                .into_iter()
                .map(|representative| representative.expect("every class is represented"))
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let mut cells =
                Vec::with_capacity(states.checked_mul(classes).expect("small generated table"));
            for state in 0..states {
                let state_u32 = u32::try_from(state).expect("small state");
                let row = cells.len();
                for _ in 0..classes.saturating_sub(1) {
                    let choice = next_random(&mut seed) % 7;
                    let next = match choice {
                        0 | 1 => state_u32,
                        2 => NO_STATE,
                        _ => u32::try_from(random_usize(&mut seed, states))
                            .expect("small destination"),
                    };
                    cells.push(forward_cell! {
                        next,
                        accepted: next_random(&mut seed) & 1 != 0,
                    });
                }
                // The last source column exactly duplicates the first. This
                // guarantees that completed column coalescing is exercised.
                cells.push(cells[row]);
            }

            let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
            let minimized = minimize_complete_machine(&cells, states, classes, &mut budget)
                .expect("generated table is valid")
                .expect("unlimited minimization");
            let mut alphabet = Alphabet {
                byte_to_class: byte_classes,
                representatives,
            };
            let mut forward = ForwardDfa {
                initial_pending: false,
                initial_terminal: false,
                transitions: minimized.transitions,
                states: minimized.states,
            };
            let mut reverse = None;
            assert!(
                coalesce_alphabet_columns(&mut alphabet, &mut forward, &mut reverse, &mut budget,)
                    .expect("generated tables are valid")
            );
            assert!(alphabet.classes() < classes);
            let view = forward_native_view(
                &alphabet.byte_to_class,
                &alphabet.representatives,
                &forward.transitions,
            );
            assert_self_loop_plans_exact(&view);
            assert_synchronizing_reset_exact(&view);
        }
    }

    #[test]
    fn synchronizing_reset_is_an_exact_all_state_column_property() {
        let mut byte_classes = [0_u8; 256];
        byte_classes[32..96].fill(1);
        byte_classes[96..192].fill(2);
        byte_classes[192..].fill(3);
        let representatives = [0_u8, 32, 96, 192];
        let cells = [
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: true,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
        ];
        let view = forward_native_view(&byte_classes, &representatives, &cells);
        let reset = assert_synchronizing_reset_exact(&view);

        assert_eq!(reset.cardinality, 32);
        for byte in 0_u16..=255 {
            let byte = u8::try_from(byte).expect("byte range");
            assert_eq!(reset.membership.contains(byte), byte < 32);
        }
    }

    #[test]
    fn synchronizing_reset_reports_full_empty_and_nullable_edge_cases() {
        let byte_classes = [0_u8; 256];
        let representatives = [0_u8];
        let resetting_cells = [forward_cell! {
            next: 0,
            accepted: false,
        }];
        let resetting = forward_native_view(&byte_classes, &representatives, &resetting_cells);
        let full = assert_synchronizing_reset_exact(&resetting);
        assert_eq!(full.cardinality, 256);
        assert_eq!(full.membership.words, [u64::MAX; 4]);

        let nonzero_initial_cells = [
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
        ];
        let mut nonzero_initial =
            forward_native_view(&byte_classes, &representatives, &nonzero_initial_cells);
        nonzero_initial.initial_state = 1;
        let nonzero_full = assert_synchronizing_reset_exact(&nonzero_initial);
        assert_eq!(nonzero_full.cardinality, 256);

        for cell in [
            forward_cell! {
                next: 0,
                accepted: true,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
        ] {
            let cells = [cell];
            let view = forward_native_view(&byte_classes, &representatives, &cells);
            let empty = assert_synchronizing_reset_exact(&view);
            assert_eq!(empty.cardinality, 0);
            assert_eq!(empty.membership.words, [0; 4]);
        }

        let mut nullable = resetting;
        nullable.initial_pending = true;
        assert!(nullable.synchronizing_reset_bytes().is_none());
        let mut terminal = resetting;
        terminal.initial_terminal = true;
        assert!(terminal.synchronizing_reset_bytes().is_none());
    }

    #[test]
    fn self_loop_plan_cap_and_accounting_are_deterministic() {
        let states = MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS
            .checked_add(7)
            .expect("small test state count");
        let mut byte_classes = [0_u8; 256];
        byte_classes[200..].fill(1);
        let mut cells = Vec::with_capacity(states.checked_mul(2).expect("small table"));
        for state in 0..states {
            let state_u32 = u32::try_from(state).expect("small state");
            cells.push(forward_cell! {
                next: state_u32,
                accepted: false,
            });
            let next_state = state.checked_add(1).expect("small state successor");
            cells.push(if next_state < states {
                forward_cell! {
                    next: u32::try_from(next_state).expect("small state successor"),
                    accepted: false,
                }
            } else {
                forward_cell! {
                    next: NO_STATE,
                    accepted: true,
                }
            });
        }
        let mut budget = BuildBudget::new(DeterminizeLimits::unlimited());
        let minimized = minimize_complete_machine(&cells, states, 2, &mut budget)
            .expect("valid reachable chain")
            .expect("unlimited minimization");
        assert_eq!(minimized.states, states);
        let mut alphabet = Alphabet {
            byte_to_class: byte_classes,
            representatives: vec![0_u8, 200].into_boxed_slice(),
        };
        let mut forward = ForwardDfa {
            initial_pending: false,
            initial_terminal: false,
            transitions: minimized.transitions,
            states: minimized.states,
        };
        let mut reverse = None;
        assert!(
            coalesce_alphabet_columns(&mut alphabet, &mut forward, &mut reverse, &mut budget,)
                .expect("valid minimized table")
        );
        assert_eq!(alphabet.classes(), 2);
        let view = forward_native_view(
            &alphabet.byte_to_class,
            &alphabet.representatives,
            &forward.transitions,
        );
        let plans = assert_self_loop_plans_exact(&view);

        assert_eq!(plans.analyzed_state_count, states);
        assert_eq!(plans.candidate_count, states);
        assert_eq!(
            plans.retained_count(),
            NativeDfaSelfLoopSkipPlans::capacity()
        );
        assert_eq!(
            NativeDfaSelfLoopSkipPlans::capacity(),
            MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS
        );
        assert_eq!(plans.dropped_count, 7);
        for (state, plan) in plans.as_slice().iter().enumerate() {
            assert_eq!(plan.state, u32::try_from(state).expect("retained state"));
            assert_eq!(plan.structural_rank, state);
            assert_eq!(plan.membership_cardinality, 200);
        }
    }

    #[test]
    fn malformed_native_views_conservatively_decline_self_loop_analysis() {
        let byte_classes = [0_u8; 256];
        let representatives = [0_u8];
        let cells = [forward_cell! {
            next: 0,
            accepted: false,
        }];
        let valid = forward_native_view(&byte_classes, &representatives, &cells);
        assert!(valid.self_loop_skip_plans().is_some());

        let mut zero_classes = valid;
        zero_classes.class_count = 0;
        assert!(zero_classes.self_loop_skip_plans().is_none());

        let two_representatives = [0_u8, 1];
        let mut invalid_byte_class = valid;
        invalid_byte_class.class_count = 2;
        invalid_byte_class.class_representatives = &two_representatives;
        assert!(invalid_byte_class.self_loop_skip_plans().is_none());
    }

    #[test]
    fn malformed_native_views_conservatively_decline_reset_analysis() {
        let byte_classes = [0_u8; 256];
        let representatives = [0_u8];
        let cells = [forward_cell! {
            next: 0,
            accepted: false,
        }];
        let valid = forward_native_view(&byte_classes, &representatives, &cells);
        assert!(valid.synchronizing_reset_bytes().is_some());

        let mut absent_initial = valid;
        absent_initial.initial_state = 1;
        assert!(absent_initial.synchronizing_reset_bytes().is_none());

        let invalid_destination_cells = [forward_cell! {
            next: 1,
            accepted: false,
        }];
        let invalid_destination =
            forward_native_view(&byte_classes, &representatives, &invalid_destination_cells);
        assert!(invalid_destination.synchronizing_reset_bytes().is_none());

        let mut two_classes = [0_u8; 256];
        two_classes[128..].fill(1);
        let duplicate_representatives = [0_u8, 0];
        let two_cells = [
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
        ];
        let invalid_representative =
            forward_native_view(&two_classes, &duplicate_representatives, &two_cells);
        assert!(invalid_representative.synchronizing_reset_bytes().is_none());

        let unrepresented_classes = [0_u8; 256];
        let distinct_representatives = [0_u8, 1];
        let unrepresented = forward_native_view(
            &unrepresented_classes,
            &distinct_representatives,
            &two_cells,
        );
        assert!(unrepresented.synchronizing_reset_bytes().is_none());
    }

    fn forward_native_view<'a>(
        byte_classes: &'a [u8; 256],
        class_representatives: &'a [u8],
        forward_cells: &'a [ForwardCell],
    ) -> NativeDfaView<'a> {
        NativeDfaView {
            initial_state: 0,
            initial_pending: false,
            initial_terminal: false,
            byte_classes,
            class_count: class_representatives.len(),
            class_representatives,
            forward_cells,
            reverse_initial: None,
            reverse_cells: &[],
        }
    }

    fn assert_self_loop_plans_exact(view: &NativeDfaView<'_>) -> NativeDfaSelfLoopSkipPlans {
        let plans = view
            .self_loop_skip_plans()
            .expect("test view is a complete forward table");
        let state_count = view
            .forward_cells
            .len()
            .checked_div(view.class_count)
            .expect("nonzero class count");
        assert_eq!(plans.analyzed_state_count, state_count);

        let mut expected = Vec::new();
        for state in 0..state_count {
            for acceptance in [
                NativeSelfLoopAcceptance::NonAccepting,
                NativeSelfLoopAcceptance::Accepting,
            ] {
                let mut membership = NativeByteMask256::default();
                for byte in 0_u16..=255 {
                    let byte = u8::try_from(byte).expect("byte range");
                    let class = usize::from(view.byte_classes[usize::from(byte)]);
                    let row = state
                        .checked_mul(view.class_count)
                        .expect("small test table row");
                    let index = row.checked_add(class).expect("small test table index");
                    let cell = view.forward_cells[index];
                    if cell.next() == u32::try_from(state).expect("test state")
                        && cell.accepted()
                            == matches!(acceptance, NativeSelfLoopAcceptance::Accepting)
                    {
                        membership.insert(byte);
                    }
                }
                let membership_cardinality = membership.cardinality();
                if membership_cardinality != 0 {
                    expected.push(NativeDfaSelfLoopSkipPlan {
                        state: u32::try_from(state).expect("test state"),
                        acceptance,
                        membership,
                        complement: membership.complement(),
                        membership_cardinality,
                        complement_cardinality: membership.complement().cardinality(),
                        structural_rank: 0,
                    });
                }
            }
        }
        expected.sort_by(|left, right| {
            right
                .membership_cardinality
                .cmp(&left.membership_cardinality)
                .then_with(|| left.acceptance.cmp(&right.acceptance))
                .then_with(|| left.state.cmp(&right.state))
        });
        assert_eq!(plans.candidate_count, expected.len());
        assert_eq!(
            plans.retained_count(),
            expected.len().min(MAX_NATIVE_DFA_SELF_LOOP_SKIP_PLANS)
        );
        assert_eq!(
            plans.dropped_count,
            expected.len().saturating_sub(plans.retained_count())
        );

        for (rank, (actual, expected)) in plans.as_slice().iter().zip(expected.iter()).enumerate() {
            assert_eq!(actual.state, expected.state);
            assert_eq!(actual.acceptance, expected.acceptance);
            assert_eq!(actual.membership, expected.membership);
            assert_eq!(actual.complement, expected.complement);
            assert_eq!(
                actual.membership_cardinality,
                expected.membership_cardinality
            );
            assert_eq!(
                actual.complement_cardinality,
                expected.complement_cardinality
            );
            assert_eq!(actual.structural_rank, rank);
            assert_eq!(
                actual
                    .membership_cardinality
                    .checked_add(actual.complement_cardinality),
                Some(256)
            );
            for byte in 0_u16..=255 {
                let byte = u8::try_from(byte).expect("byte range");
                let class = usize::from(view.byte_classes[usize::from(byte)]);
                let row = usize::try_from(actual.state)
                    .expect("test state")
                    .checked_mul(view.class_count)
                    .expect("small test table row");
                let index = row.checked_add(class).expect("small test table index");
                let cell = view.forward_cells[index];
                let claimed = cell.next() == actual.state
                    && cell.accepted()
                        == matches!(actual.acceptance, NativeSelfLoopAcceptance::Accepting);
                assert_eq!(actual.membership.contains(byte), claimed);
                assert_eq!(actual.complement.contains(byte), !claimed);
            }
        }
        plans
    }

    fn assert_synchronizing_reset_exact(view: &NativeDfaView<'_>) -> NativeDfaSynchronizingReset {
        let reset = view
            .synchronizing_reset_bytes()
            .expect("test view supports a fresh-search reset");
        let state_count = view
            .forward_cells
            .len()
            .checked_div(view.class_count)
            .expect("nonzero class count");
        let mut expected_cardinality = 0_u16;
        for byte in 0_u16..=255 {
            let byte = u8::try_from(byte).expect("byte range");
            let class = usize::from(view.byte_classes[usize::from(byte)]);
            let mut qualifies = true;
            for state in 0..state_count {
                let row = state
                    .checked_mul(view.class_count)
                    .expect("small test table row");
                let index = row.checked_add(class).expect("small test table index");
                let cell = view.forward_cells[index];
                if cell.accepted() || cell.next() != view.initial_state {
                    qualifies = false;
                    break;
                }
            }
            assert_eq!(reset.membership.contains(byte), qualifies);
            if qualifies {
                expected_cardinality = expected_cardinality
                    .checked_add(1)
                    .expect("at most 256 qualifying bytes");
            }
        }
        assert_eq!(reset.cardinality, expected_cardinality);
        assert_eq!(reset.cardinality, reset.membership.cardinality());
        reset
    }

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_usize(state: &mut u64, modulus: usize) -> usize {
        let modulus = u64::try_from(modulus).expect("small modulus");
        usize::try_from(
            next_random(state)
                .checked_rem(modulus)
                .expect("nonzero modulus"),
        )
        .expect("result fits usize")
    }

    fn trace<T: RefinementCell>(cells: &[T], classes: usize, input: &[usize]) -> (Vec<bool>, bool) {
        let mut state = 0_u32;
        let mut observables = Vec::with_capacity(input.len());
        for &class in input {
            let row = usize::try_from(state)
                .expect("state fits usize")
                .checked_mul(classes)
                .expect("small generated row");
            let index = row.checked_add(class).expect("small generated index");
            let cell = cells[index];
            observables.push(cell.observable());
            if cell.next() == NO_STATE {
                return (observables, false);
            }
            state = cell.next();
        }
        (observables, true)
    }
}
