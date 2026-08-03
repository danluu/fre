use core::hash::{BuildHasherDefault, Hash, Hasher};
use memchr::{memchr, memchr2, memchr3};
use std::collections::HashMap;

use fre_automata::{EdgeKind, RawPlan, StateRole};
use fre_simd_kernels::{
    BYTE_SET_BLOCK_BYTES, BYTE_SET_WIDE_BLOCK_BYTES, ByteSet256, ByteSetClassifier,
};

use crate::{
    error::CompileError,
    program::{AnchoredByteSet, OutputContract, ProgramFormatError},
};

const NO_STATE: u32 = u32::MAX;
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

/// Hard limits for complete ordered determinization.
///
/// The state and transition limits cover the forward and reverse machines
/// together. Hitting any limit declines the DFA optimization and leaves the
/// caller free to retain the universal ordered-NFA program.
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

/// Complete deterministic trace of the target-neutral determinization route.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ForwardCell {
    pub(crate) next: u32,
    pub(crate) accepted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReverseCell {
    pub(crate) next: u32,
    pub(crate) reaches_start: bool,
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
    /// Source-independent effect of every completed transition on a scalar
    /// proof that all live ordered threads share one match start. This is a
    /// derived in-memory certificate: stable artifacts regenerate it while
    /// canonically validating the retained table.
    start_actions: Vec<ForwardStartAction>,
    discovered_states: usize,
    complete_rows: usize,
    /// Ordered subset keys for exactly the incomplete suffix
    /// `complete_rows..discovered_states`. Complete source rows need no key at
    /// runtime; entering this suffix is the authenticated K0 resume boundary.
    resume_keys: Vec<ForwardKey>,
}

enum ForwardBuildOutcome {
    Complete(ForwardDfa),
    Declined(Option<PartialForwardDfa>),
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

/// A complete, alphabet-reduced ordered DFA plus optional reverse machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OrderedDfa {
    alphabet: Alphabet,
    forward: ForwardDfa,
    reverse: Option<ReverseDfa>,
    stats: DfaStats,
}

/// Canonical prefix of ordered subset construction retained when bounded
/// determinization declines.
///
/// Every stored row is complete for every graph alphabet class. A transition
/// may name a discovered state whose own row was not completed; execution
/// treats entry into that state as a side exit to the exact ordered-NFA
/// engine. The compact incomplete-state suffix retains the canonical ordered
/// consuming frontier and pending mode, so K0 continues at the first
/// unconsumed byte without replaying the prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PartialDfa {
    alphabet: Alphabet,
    forward: PartialForwardDfa,
    effective_limits: DeterminizeLimits,
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
                if cell.next != state_u32 {
                    continue;
                }
                if cell.accepted {
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
                if cell.next != NO_STATE
                    && usize::try_from(cell.next)
                        .ok()
                        .is_none_or(|next| next >= state_count)
                {
                    return None;
                }
                if cell.accepted || cell.next != self.initial_state {
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

    pub(crate) fn resume_frontier_count(&self) -> usize {
        self.forward.resume_keys.len()
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

    fn from_complete_forward(
        alphabet: Alphabet,
        forward: ForwardDfa,
        effective_limits: DeterminizeLimits,
    ) -> Self {
        Self {
            alphabet,
            forward: PartialForwardDfa {
                initial_pending: forward.initial_pending,
                initial_terminal: forward.initial_terminal,
                transitions: forward.transitions,
                start_actions: Vec::new(),
                discovered_states: forward.states,
                complete_rows: forward.states,
                resume_keys: Vec::new(),
            },
            effective_limits,
        }
    }

    fn selected_end_impl(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
        earliest: bool,
        track_start: bool,
        prefix_sets: &[AnchoredByteSet],
        prefix_plan: Option<PartialDfaPrefixPlan>,
    ) -> Result<PartialDfaResult<PartialDfaSelection>, CompileError> {
        if self.forward.initial_pending && (earliest || self.forward.initial_terminal) {
            return Ok(PartialDfaResult::Complete(PartialDfaSelection {
                end: Some(window_start),
                start: Some(window_start),
            }));
        }

        let classes = self.alphabet.classes();
        let tracks_start = track_start
            && self.forward.start_actions.len() == self.forward.transitions.len();
        let mut state = 0_u32;
        let mut position = window_start;
        let mut pending_end = self.forward.initial_pending.then_some(window_start);
        let mut active_start = tracks_start.then_some(window_start);
        let mut pending_start = (tracks_start && self.forward.initial_pending)
            .then_some(window_start);
        while position < window_end {
            let source = usize::try_from(state).map_err(|_| {
                CompileError::InternalInvariant("partial DFA state exceeded usize")
            })?;
            if source >= self.forward.complete_rows {
                let resume_state = source.checked_sub(self.forward.complete_rows).ok_or(
                    CompileError::InternalInvariant("partial DFA resume-state underflowed"),
                )?;
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
            if source == 0
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
            let index = source
                .checked_mul(classes)
                .and_then(|row| row.checked_add(self.alphabet.class(byte)))
                .ok_or(CompileError::InternalInvariant(
                    "partial DFA transition index overflowed",
                ))?;
            let cell = *self.forward.transitions.get(index).ok_or(
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
            if cell.accepted {
                pending_end = Some(position);
                pending_start = next_start;
                if earliest {
                    return Ok(PartialDfaResult::Complete(PartialDfaSelection {
                        end: pending_end,
                        start: pending_start,
                    }));
                }
            }
            if cell.next == NO_STATE {
                return Ok(PartialDfaResult::Complete(PartialDfaSelection {
                    end: pending_end,
                    start: pending_start,
                }));
            }
            if usize::try_from(cell.next)
                .ok()
                .is_none_or(|next| next >= self.forward.discovered_states)
            {
                return Err(CompileError::InternalInvariant(
                    "partial DFA transition references an undiscovered state",
                ));
            }
            state = cell.next;
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
            match self.selected_end_impl(
                haystack,
                window_start,
                window_end,
                true,
                false,
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
        Ok(match self.selected_end_impl(
            haystack,
            window_start,
            window_end,
            false,
            false,
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
        self.selected_end_impl(
            haystack,
            window_start,
            window_end,
            false,
            true,
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
            put_u32(bytes, cell.next);
            bytes.push(u8::from(cell.accepted));
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
            transitions.push(ForwardCell { next, accepted });
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
    ) -> Result<Self, ProgramFormatError> {
        let regenerated = determinize(raw, wants_span, self.effective_limits).map_err(|_| {
            ProgramFormatError::Malformed("partial DFA canonical regeneration returned an error")
        })?;
        let regenerated = match regenerated {
            DeterminizeOutcome::Complete { .. } => {
                return Err(ProgramFormatError::Malformed(
                    "partial DFA limits canonically produce a complete machine",
                ));
            }
            DeterminizeOutcome::Declined { report, partial } => {
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
        let same_wire_payload = regenerated.alphabet == self.alphabet
            && regenerated.effective_limits == self.effective_limits
            && regenerated.forward.initial_pending == self.forward.initial_pending
            && regenerated.forward.initial_terminal == self.forward.initial_terminal
            && regenerated.forward.transitions == self.forward.transitions
            && regenerated.forward.discovered_states == self.forward.discovered_states
            && regenerated.forward.complete_rows == self.forward.complete_rows
            && regenerated.forward.resume_keys == self.forward.resume_keys;
        if !same_wire_payload {
            return Err(ProgramFormatError::Malformed(
                "partial DFA payload is not the canonical retained prefix",
            ));
        }
        Ok(regenerated)
    }
}

impl OrderedDfa {
    pub(crate) const fn stats(&self) -> DfaStats {
        self.stats
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
            if cell.accepted {
                pending_end = Some(position);
                if earliest {
                    return Ok(pending_end);
                }
            }
            if cell.next == NO_STATE {
                return Ok(pending_end);
            }
            state = cell.next;
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
            if cell.reaches_start {
                // Execution moves right-to-left, so replacing the candidate
                // retains the earliest start that reaches the selected end.
                candidate = Some(cursor);
            }
            if cell.next == NO_STATE {
                break;
            }
            state = cell.next;
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
        put_u64(bytes, self.stats.build_work);
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
            put_u32(bytes, cell.next);
            bytes.push(u8::from(cell.accepted));
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
            put_u32(bytes, cell.next);
            bytes.push(u8::from(cell.reaches_start));
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
            forward_cells.push(ForwardCell { next, accepted });
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
                reverse_cells.push(ReverseCell {
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
                build_work,
            },
        })
    }

    pub(crate) fn validate_canonical(&self, raw: &RawPlan) -> Result<(), ProgramFormatError> {
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
        let regenerated = determinize(
            raw,
            self.reverse.is_some(),
            DeterminizeLimits {
                max_states,
                max_transitions,
                max_work: self.stats.build_work,
            },
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
    let additional = capacity.saturating_sub(values.len());
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
    let mut values = StableMap::default();
    if values.try_reserve(capacity).is_err() {
        budget.allocation::<(K, V)>(capacity);
        return None;
    }
    Some(values)
}

fn reserve_map<K: Eq + Hash, V>(
    values: &mut StableMap<K, V>,
    additional: usize,
    budget: &mut BuildBudget,
) -> bool {
    if values.try_reserve(additional).is_err() {
        budget.allocation::<(K, V)>(values.len().saturating_add(additional));
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
    },
}

impl DeterminizeOutcome {
    fn from_budget(
        machine: Option<OrderedDfa>,
        partial: Option<PartialDfa>,
        budget: BuildBudget,
    ) -> Self {
        // Allocation refusal is environmental rather than a canonical
        // consequence of the recorded numeric limits. Retaining such a table
        // would make strict replay depend on allocator history, so only
        // state/transition/work refusals publish a stable partial machine.
        let partial = if matches!(
            budget.decline,
            Some(DeterminizationDecline {
                resource: DeterminizationResource::Allocation { .. },
                ..
            })
        ) {
            None
        } else {
            partial
        };
        let report = budget.into_report();
        match machine {
            Some(machine) => Self::Complete { machine, report },
            None => Self::Declined { report, partial },
        }
    }
}

pub(crate) fn determinize(
    raw: &RawPlan,
    wants_span: bool,
    requested_limits: DeterminizeLimits,
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

    let mut budget = BuildBudget::new(requested_limits);
    budget.begin_stage(DeterminizationStage::AlphabetPartition);
    let Some(built_alphabet) = Alphabet::build(raw, &mut budget)? else {
        return Ok(DeterminizeOutcome::from_budget(None, None, budget));
    };
    let BuiltAlphabet {
        mut alphabet,
        boundary_classes,
        graph_classes,
    } = built_alphabet;
    budget.complete_stage(DeterminizationStage::AlphabetPartition)?;
    budget.begin_stage(DeterminizationStage::ForwardSubsetConstruction);
    let mut forward = match build_forward(raw, &alphabet, &mut budget)? {
        ForwardBuildOutcome::Complete(forward) => forward,
        ForwardBuildOutcome::Declined(partial) => {
            let partial = partial.map(|forward| PartialDfa {
                alphabet,
                forward,
                effective_limits: budget.limits,
            });
            return Ok(DeterminizeOutcome::from_budget(None, partial, budget));
        }
    };
    budget.complete_stage(DeterminizationStage::ForwardSubsetConstruction)?;
    let mut reverse = if wants_span && !forward.initial_pending {
        budget.begin_stage(DeterminizationStage::ReverseSubsetConstruction);
        let Some(reverse) = build_reverse(raw, &alphabet, &mut budget)? else {
            let partial = PartialDfa::from_complete_forward(alphabet, forward, budget.limits);
            return Ok(DeterminizeOutcome::from_budget(
                None,
                Some(partial),
                budget,
            ));
        };
        budget.complete_stage(DeterminizationStage::ReverseSubsetConstruction)?;
        Some(reverse)
    } else {
        None
    };
    let forward_states_before_minimization = forward.states;
    let reverse_states_before_minimization = reverse.as_ref().map_or(0, |machine| machine.states);
    budget.begin_stage(DeterminizationStage::DfaStateMinimization);
    if !minimize_dfa_states(&mut forward, &mut reverse, alphabet.classes(), &mut budget)? {
        let partial = PartialDfa::from_complete_forward(alphabet, forward, budget.limits);
        return Ok(DeterminizeOutcome::from_budget(
            None,
            Some(partial),
            budget,
        ));
    }
    budget.complete_stage(DeterminizationStage::DfaStateMinimization)?;
    budget.begin_stage(DeterminizationStage::AlphabetColumnCoalescing);
    if !coalesce_alphabet_columns(&mut alphabet, &mut forward, &mut reverse, &mut budget)? {
        let partial = PartialDfa::from_complete_forward(alphabet, forward, budget.limits);
        return Ok(DeterminizeOutcome::from_budget(
            None,
            Some(partial),
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
        build_work: budget.work,
    };
    let machine = OrderedDfa {
        alphabet,
        forward,
        reverse,
        stats,
    };
    Ok(DeterminizeOutcome::from_budget(Some(machine), None, budget))
}

trait RefinementCell: Copy + Eq {
    fn next(self) -> u32;
    fn observable(self) -> bool;
    fn with_next(self, next: u32) -> Self;
}

impl RefinementCell for ForwardCell {
    fn next(self) -> u32 {
        self.next
    }

    fn observable(self) -> bool {
        self.accepted
    }

    fn with_next(self, next: u32) -> Self {
        Self {
            next,
            accepted: self.accepted,
        }
    }
}

impl RefinementCell for ReverseCell {
    fn next(self) -> u32 {
        self.next
    }

    fn observable(self) -> bool {
        self.reaches_start
    }

    fn with_next(self, next: u32) -> Self {
        Self {
            next,
            reaches_start: self.reaches_start,
        }
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
fn minimize_dfa_states(
    forward: &mut ForwardDfa,
    reverse: &mut Option<ReverseDfa>,
    classes: usize,
    budget: &mut BuildBudget,
) -> Result<bool, CompileError> {
    let Some(minimized_forward) =
        minimize_complete_machine(&forward.transitions, forward.states, classes, budget)?
    else {
        return Ok(false);
    };
    forward.transitions = minimized_forward.transitions;
    forward.states = minimized_forward.states;

    if let Some(machine) = reverse {
        let Some(minimized_reverse) =
            minimize_complete_machine(&machine.transitions, machine.states, classes, budget)?
        else {
            return Ok(false);
        };
        machine.transitions = minimized_reverse.transitions;
        machine.states = minimized_reverse.states;
    }
    Ok(true)
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
        start_actions: compact_start_actions,
        discovered_states,
        complete_rows,
        resume_keys,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "complete ordered subset construction is kept in one auditable worklist"
)]
fn build_forward(
    raw: &RawPlan,
    alphabet: &Alphabet,
    budget: &mut BuildBudget,
) -> Result<ForwardBuildOutcome, CompileError> {
    let Some(mut closure) = ForwardClosure::new(raw, budget) else {
        return Ok(ForwardBuildOutcome::Declined(None));
    };
    let initial_accepted = closure.expand(raw, raw.start, budget)?;
    if budget.declined {
        return Ok(ForwardBuildOutcome::Declined(None));
    }
    let Some(initial_items) = closure.copy_items(budget) else {
        return Ok(ForwardBuildOutcome::Declined(None));
    };
    let initial_terminal = initial_accepted && initial_items.is_empty();
    let initial = ForwardKey {
        items: initial_items,
        pending: initial_accepted,
    };
    if !budget.reserve_state(alphabet.classes()) {
        return Ok(ForwardBuildOutcome::Declined(None));
    }

    let Some(mut states) = build_vec(1, budget) else {
        return Ok(ForwardBuildOutcome::Declined(None));
    };
    let Some(initial_state) = clone_forward_key(&initial, budget) else {
        return Ok(ForwardBuildOutcome::Declined(None));
    };
    states.push(initial_state);
    let Some(mut interned) = build_map(1, budget) else {
        return Ok(ForwardBuildOutcome::Declined(None));
    };
    interned.insert(initial, 0_u32);
    let Some(mut transitions) = build_vec(alphabet.classes(), budget) else {
        return Ok(ForwardBuildOutcome::Declined(None));
    };
    let Some(mut start_actions) = build_vec(alphabet.classes(), budget) else {
        return Ok(ForwardBuildOutcome::Declined(None));
    };
    let mut cursor = 0usize;
    macro_rules! decline_with_complete_rows {
        () => {{
            let partial = compact_partial_forward(
                &transitions,
                &start_actions,
                states,
                cursor,
                alphabet.classes(),
                initial_accepted,
                initial_terminal,
            );
            return Ok(ForwardBuildOutcome::Declined(partial));
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
        for &byte in alphabet.representatives.as_ref() {
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
            let start_action = ForwardStartAction::derive(
                source_len,
                closure.items.len(),
                injected_root,
            );
            let next_pending = key.pending || accepted;
            let Some(next_items) = closure.copy_items(budget) else {
                decline_with_complete_rows!();
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
                        || !ensure_vec_capacity(
                            &mut start_actions,
                            next_transition_count,
                            budget,
                        )
                        || !reserve_map(&mut interned, 1, budget)
                    {
                        decline_with_complete_rows!();
                    }
                    states.push(state_key);
                    interned.insert(next_key, id);
                    id
                }
            };
            transitions.push(ForwardCell { next, accepted });
            start_actions.push(start_action);
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
            transitions.push(ReverseCell {
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
    work: u64,
    states: usize,
    transitions: usize,
    declined: bool,
    decline: Option<DeterminizationDecline>,
    current_stage: Option<DeterminizationStage>,
    attempted_stages: Vec<DeterminizationStage>,
    completed_stages: Vec<DeterminizationStage>,
}

impl BuildBudget {
    fn new(requested_limits: DeterminizeLimits) -> Self {
        Self {
            requested_limits,
            limits: requested_limits.effective_for_stable_artifact(),
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
            if row.try_reserve_exact(degree).is_err() {
                budget.allocation::<u32>(degree);
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
    }

    #[test]
    fn partial_publication_drops_abandoned_bfs_capacity() {
        let mut transitions = Vec::with_capacity(4_096);
        transitions.extend((0_u32..12).map(|next| ForwardCell {
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
            ForwardCell {
                next: 1,
                accepted: false,
            },
            ForwardCell {
                next: 2,
                accepted: false,
            },
            ForwardCell {
                next: 3,
                accepted: true,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: 3,
                accepted: true,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
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
                ForwardCell {
                    next: 1,
                    accepted: false,
                },
                ForwardCell {
                    next: 1,
                    accepted: false,
                },
                ForwardCell {
                    next: 2,
                    accepted: true,
                },
                ForwardCell {
                    next: NO_STATE,
                    accepted: false,
                },
                ForwardCell {
                    next: NO_STATE,
                    accepted: false,
                },
                ForwardCell {
                    next: NO_STATE,
                    accepted: false,
                },
            ]
        );
    }

    #[test]
    fn observable_flags_and_dead_sentinel_participate_in_equivalence() {
        let cells = [
            ReverseCell {
                next: 1,
                reaches_start: false,
            },
            ReverseCell {
                next: 2,
                reaches_start: false,
            },
            ReverseCell {
                next: NO_STATE,
                reaches_start: false,
            },
            ReverseCell {
                next: 2,
                reaches_start: false,
            },
            ReverseCell {
                next: NO_STATE,
                reaches_start: true,
            },
            ReverseCell {
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
            ForwardCell {
                next: 3,
                accepted: false,
            },
            ForwardCell {
                next: 1,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: true,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: true,
            },
            ForwardCell {
                next: 2,
                accepted: false,
            },
            ForwardCell {
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
        assert_eq!(minimized.transitions[0].next, 1);
        assert_eq!(minimized.transitions[1].next, 2);
        // Processing new state 1 then discovers old state 2 as new state 3.
        assert_eq!(minimized.transitions[2].next, 3);
    }

    #[test]
    fn minimization_declines_cleanly_when_work_is_exhausted() {
        let cells = [ForwardCell {
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
                cells.push(ForwardCell {
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
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: true,
            },
            ForwardCell {
                next: 1,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
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
            ForwardCell {
                next: 1,
                accepted: false,
            },
            ForwardCell {
                next: 1,
                accepted: false,
            },
            ForwardCell {
                next: 2,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
                next: 3,
                accepted: true,
            },
            ForwardCell {
                next: 3,
                accepted: true,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: 1,
                accepted: false,
            },
            ForwardCell {
                next: 3,
                accepted: true,
            },
            ForwardCell {
                next: 3,
                accepted: true,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: 2,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
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
                    cells.push(ForwardCell {
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
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: true,
            },
            ForwardCell {
                next: 1,
                accepted: false,
            },
            ForwardCell {
                next: NO_STATE,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
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
        let resetting_cells = [ForwardCell {
            next: 0,
            accepted: false,
        }];
        let resetting = forward_native_view(&byte_classes, &representatives, &resetting_cells);
        let full = assert_synchronizing_reset_exact(&resetting);
        assert_eq!(full.cardinality, 256);
        assert_eq!(full.membership.words, [u64::MAX; 4]);

        let nonzero_initial_cells = [
            ForwardCell {
                next: 1,
                accepted: false,
            },
            ForwardCell {
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
            ForwardCell {
                next: 0,
                accepted: true,
            },
            ForwardCell {
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
            cells.push(ForwardCell {
                next: state_u32,
                accepted: false,
            });
            let next_state = state.checked_add(1).expect("small state successor");
            cells.push(if next_state < states {
                ForwardCell {
                    next: u32::try_from(next_state).expect("small state successor"),
                    accepted: false,
                }
            } else {
                ForwardCell {
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
        let cells = [ForwardCell {
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
        let cells = [ForwardCell {
            next: 0,
            accepted: false,
        }];
        let valid = forward_native_view(&byte_classes, &representatives, &cells);
        assert!(valid.synchronizing_reset_bytes().is_some());

        let mut absent_initial = valid;
        absent_initial.initial_state = 1;
        assert!(absent_initial.synchronizing_reset_bytes().is_none());

        let invalid_destination_cells = [ForwardCell {
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
            ForwardCell {
                next: 0,
                accepted: false,
            },
            ForwardCell {
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
                    if cell.next == u32::try_from(state).expect("test state")
                        && cell.accepted
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
                let claimed = cell.next == actual.state
                    && cell.accepted
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
                if cell.accepted || cell.next != view.initial_state {
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
