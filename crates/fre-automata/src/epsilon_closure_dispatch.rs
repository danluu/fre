//! Canonical priority-DFS programs for assertion-free Pike closures.
//!
//! Ordinary Pike expansion repeatedly decodes the same immutable split rows,
//! pushes their targets in reverse order, and pops them again in priority
//! order.  For an optimizing ordered-NFA artifact, this sidecar unfolds each
//! state that can actually begin a boundary closure into that exact pop order.
//! Runtime `seen` generations remain authoritative: every instruction carries
//! the end of its unfolded subtree, so a previously visited state skips all of
//! the work that the scalar stack would also suppress.
//!
//! Only ancestor backedges are folded while deriving a program.  A repeated
//! DAG node is unfolded at every occurrence because an earlier occurrence can
//! lie below a subtree skipped by state shared with a higher-priority root.
//! Fixed work, expansion, retained-byte, and graph-relative ceilings make that
//! conservative duplication safe for untrusted graphs.  Refusal leaves the
//! universal scalar Pike implementation unchanged.

use core::{fmt, mem::size_of};

use crate::plan::{plan_index, Automaton, StateRole};

// Retained program offsets are bounded below 2^30, leaving the high bit as a
// branch-friendly tag that cannot collide with instruction storage.
const ROOT_SENTINEL_BIT: u32 = 1 << 31;
const NO_PROGRAM: u32 = ROOT_SENTINEL_BIT;
const DIRECT_CONSUME: u32 = ROOT_SENTINEL_BIT | 1;
const DIRECT_ACCEPT: u32 = ROOT_SENTINEL_BIT | 2;
const ACTION_SHIFT: u32 = 30;
const SUBTREE_END_MASK: u32 = (1_u32 << ACTION_SHIFT) - 1;

// The sidecar is a compiler optimization, not part of the language.  These
// graph-independent ceilings bound both fresh compilation and canonical wire
// rederivation.  The graph-relative ceiling additionally rejects path
// explosion well before either absolute ceiling on ordinary small graphs.
const MAX_DERIVATION_WORK: usize = 64 * 1024 * 1024;
const MAX_COMPILER_SCRATCH_BYTES: usize = 64 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROGRAM_EXPANSION_FACTOR: usize = 4;
const MAX_RETAINED_TO_GRAPH_FACTOR: usize = 2;

// A one-edge split merely exchanges one scalar loop iteration for one program
// instruction.  Two zero-width edges are the smallest closure for which the
// program removes multiple target/kind loads and stack operations.
const MIN_ELIMINATED_EDGE_VISITS: usize = 2;

/// Allocation failure after a graph has deterministically qualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpsilonClosureDispatchAllocationError {
    requested_bytes: usize,
}

impl EpsilonClosureDispatchAllocationError {
    /// Exact logical retained extent or compiler scratch extent requested.
    #[must_use]
    pub const fn requested_bytes(self) -> usize {
        self.requested_bytes
    }
}

impl fmt::Display for EpsilonClosureDispatchAllocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "could not allocate {0} bytes for epsilon-closure dispatch",
            self.requested_bytes
        )
    }
}

impl std::error::Error for EpsilonClosureDispatchAllocationError {}

/// Runtime action encoded beside one canonical Pike pop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClosureAction {
    Split = 0,
    Consume = 1,
    Accept = 2,
    // Reaching this instruction proves that its state is an active ancestor,
    // hence already marked in the current generation.  Keeping a distinct
    // action turns a derivation bug into an invariant error instead of a
    // silently incomplete closure.
    SeenBackedge = 3,
}

impl ClosureAction {
    const fn encoded(self) -> u32 {
        match self {
            Self::Split => 0,
            Self::Consume => 1,
            Self::Accept => 2,
            Self::SeenBackedge => 3,
        }
    }
}

/// One compact state visit in an unfolded priority-DFS program.
///
/// Three `u32` words avoid target-width restrictions while retaining a
/// 30-bit program-local subtree end. The third word deliberately stores Split
/// edge work instead of recovering it from two CSR-offset loads in every hot
/// unseen Split. The >=2-edge admission floor, <=4x graph expansion ceiling,
/// and <=2x graph-storage retained ceiling bound that cache-space tradeoff.
/// The 64 MiB absolute ceiling admits fewer than 2^30 such instructions, so
/// every encoded end is representable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct ClosureInstruction {
    state: u32,
    subtree_end_and_action: u32,
    edge_work: u32,
}

/// One boundary root classified by the same state-index lookup that locates
/// compiled Split bytecode. Leaf sentinels let runtime settle the common
/// Consume/Accept cases without first probing the instruction arena.
pub(crate) enum ClosureRoot<'a> {
    Program(&'a [ClosureInstruction]),
    Consume,
    Accept,
    Scalar,
}

impl ClosureInstruction {
    const fn placeholder(state: u32, action: ClosureAction, edge_work: u32) -> Self {
        Self {
            state,
            subtree_end_and_action: action.encoded() << ACTION_SHIFT,
            edge_work,
        }
    }

    fn finish(&mut self, subtree_end: usize) {
        let subtree_end = u32::try_from(subtree_end)
            .expect("bounded epsilon-closure program end fits u32");
        debug_assert_eq!(subtree_end & !SUBTREE_END_MASK, 0);
        self.subtree_end_and_action =
            (self.subtree_end_and_action & !SUBTREE_END_MASK) | subtree_end;
    }

    #[inline]
    pub(crate) const fn state(self) -> u32 {
        self.state
    }

    #[inline]
    pub(crate) fn subtree_end(self) -> usize {
        plan_index(self.subtree_end_and_action & SUBTREE_END_MASK)
    }

    #[inline]
    pub(crate) const fn action(self) -> ClosureAction {
        match self.subtree_end_and_action >> ACTION_SHIFT {
            0 => ClosureAction::Split,
            1 => ClosureAction::Consume,
            2 => ClosureAction::Accept,
            _ => ClosureAction::SeenBackedge,
        }
    }

    #[inline]
    pub(crate) const fn edge_work(self) -> u32 {
        self.edge_work
    }
}

/// Immutable Split programs and leaf actions indexed by the only states that
/// can begin a forward boundary closure: the automaton start and every target
/// of a consuming edge.
///
/// The thin one-element owner keeps the optional sidecar to one pointer in
/// [`Automaton`] while retaining exact fallible allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct EpsilonClosureDispatch(Box<[EpsilonClosureDispatchData; 1]>);

#[derive(Clone, Debug, Eq, PartialEq)]
struct EpsilonClosureDispatchData {
    program_offsets: Box<[u32]>,
    instructions: Box<[ClosureInstruction]>,
    retained_bytes: usize,
    admitted_programs: usize,
    eliminated_edge_visits: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProgramShape {
    instructions: usize,
    edge_visits: usize,
}

impl ProgramShape {
    const fn admitted(self) -> bool {
        self.edge_visits >= MIN_ELIMINATED_EDGE_VISITS
    }
}

#[derive(Clone, Copy)]
struct CountFrame {
    state: u32,
    next_edge: usize,
    end_edge: usize,
}

#[derive(Clone, Copy)]
struct EmitFrame {
    state: u32,
    next_edge: usize,
    end_edge: usize,
    instruction: usize,
}

#[derive(Clone, Copy)]
struct DispatchShape {
    programs: usize,
    instructions: usize,
    eliminated_edge_visits: usize,
    retained_bytes: usize,
    derivation_work: usize,
}

impl EpsilonClosureDispatch {
    pub(crate) fn derive(
        automaton: &Automaton,
    ) -> Result<Option<Self>, EpsilonClosureDispatchAllocationError> {
        let Some((shape, roots)) = derive_shape_and_roots(automaton)? else {
            return Ok(None);
        };
        if shape.programs == 0 {
            return Ok(None);
        }

        let Some(scratch_bytes) = bounded_compiler_scratch_bytes(automaton.roles.len())? else {
            // The immutable preflight already made this refusal, but retain
            // the cap at the allocation boundary as an independent guard.
            return Ok(None);
        };
        let mut active = exact_filled(
            automaton.roles.len(),
            0_u8,
            scratch_bytes,
        )?;
        let mut count_frames = exact_vec(automaton.roles.len(), scratch_bytes)?;
        let mut emit_frames = exact_vec(automaton.roles.len(), scratch_bytes)?;
        let mut program_offsets = exact_filled(
            automaton.roles.len(),
            NO_PROGRAM,
            shape.retained_bytes,
        )?;
        let mut instructions = exact_vec(shape.instructions, shape.retained_bytes)?;

        let graph_instruction_limit = graph_instruction_limit(automaton).unwrap_or(0);
        let mut emitted_programs = 0usize;
        let mut emitted_edge_visits = 0usize;
        let mut derivation_work = 0usize;
        for (state, &is_root) in roots.iter().enumerate() {
            if is_root == 0 {
                continue;
            }
            match automaton.roles[state] {
                StateRole::Consume => {
                    program_offsets[state] = DIRECT_CONSUME;
                    continue;
                }
                StateRole::Accept => {
                    program_offsets[state] = DIRECT_ACCEPT;
                    continue;
                }
                StateRole::Split => {}
            }
            let root = u32::try_from(state).expect("validated state index fits u32");
            let program_shape = count_program(
                automaton,
                root,
                &mut active,
                &mut count_frames,
                graph_instruction_limit,
                &mut derivation_work,
            )
            .expect("the preflighted epsilon-closure program remains bounded");
            if !program_shape.admitted() {
                continue;
            }
            program_offsets[state] = u32::try_from(instructions.len())
                .expect("bounded epsilon-closure instruction offset fits u32");
            emit_program(
                automaton,
                root,
                &mut active,
                &mut emit_frames,
                &mut instructions,
                program_shape,
            );
            emitted_programs = emitted_programs
                .checked_add(1)
                .expect("preflighted epsilon-closure program count");
            emitted_edge_visits = emitted_edge_visits
                .checked_add(program_shape.edge_visits)
                .expect("preflighted epsilon-closure edge visits");
        }
        debug_assert!(derivation_work <= shape.derivation_work);
        debug_assert_eq!(instructions.len(), shape.instructions);
        debug_assert_eq!(emitted_programs, shape.programs);
        debug_assert_eq!(emitted_edge_visits, shape.eliminated_edge_visits);

        let data = EpsilonClosureDispatchData {
            program_offsets: program_offsets.into_boxed_slice(),
            instructions: instructions.into_boxed_slice(),
            retained_bytes: shape.retained_bytes,
            admitted_programs: shape.programs,
            eliminated_edge_visits: shape.eliminated_edge_visits,
        };
        let mut owner = exact_vec(1, shape.retained_bytes)?;
        owner.push(data);
        let owner: Box<[EpsilonClosureDispatchData]> = owner.into_boxed_slice();
        let owner = owner.try_into().map_err(|_| {
            EpsilonClosureDispatchAllocationError {
                requested_bytes: shape.retained_bytes,
            }
        })?;
        Ok(Some(Self(owner)))
    }

    #[inline]
    pub(crate) fn root(&self, state: u32) -> ClosureRoot<'_> {
        let data = &self.0[0];
        let Some(&encoded) = data.program_offsets.get(plan_index(state)) else {
            return ClosureRoot::Scalar;
        };
        if encoded & ROOT_SENTINEL_BIT != 0 {
            return match encoded {
                DIRECT_CONSUME => ClosureRoot::Consume,
                DIRECT_ACCEPT => ClosureRoot::Accept,
                _ => ClosureRoot::Scalar,
            };
        }
        let begin = plan_index(encoded);
        let Some(first) = data.instructions.get(begin).copied() else {
            return ClosureRoot::Scalar;
        };
        let length = first.subtree_end();
        let Some(end) = begin.checked_add(length) else {
            return ClosureRoot::Scalar;
        };
        data.instructions
            .get(begin..end)
            .map_or(ClosureRoot::Scalar, ClosureRoot::Program)
    }

    pub(crate) const fn retained_bytes(&self) -> usize {
        self.0[0].retained_bytes
    }

    #[cfg(test)]
    pub(crate) const fn admitted_programs(&self) -> usize {
        self.0[0].admitted_programs
    }

    #[cfg(test)]
    pub(crate) const fn eliminated_edge_visits(&self) -> usize {
        self.0[0].eliminated_edge_visits
    }

    #[cfg(test)]
    pub(crate) fn instruction_count(&self) -> usize {
        self.0[0].instructions.len()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "root discovery, exact sizing, and all resource ceilings form one failure-atomic preflight"
)]
fn derive_shape_and_roots(
    automaton: &Automaton,
) -> Result<
    Option<(DispatchShape, Vec<u8>)>,
    EpsilonClosureDispatchAllocationError,
> {
    if automaton.stats().assertion_edges() != 0
        || automaton.stats().zero_width_edges() < MIN_ELIMINATED_EDGE_VISITS
    {
        return Ok(None);
    }
    let states = automaton.roles.len();
    let Some(scratch_bytes) = bounded_compiler_scratch_bytes(states)? else {
        return Ok(None);
    };
    let mut roots = exact_filled(states, 0_u8, scratch_bytes)?;
    roots[plan_index(automaton.start)] = 1;
    let mut derivation_work = 0usize;
    if !try_admit_derivation_work(&mut derivation_work, states)? {
        return Ok(None);
    }
    for (state, &role) in automaton.roles.iter().enumerate() {
        if role != StateRole::Consume {
            continue;
        }
        for edge in state_edges(automaton, state) {
            if !try_admit_derivation_work(&mut derivation_work, 1)? {
                return Ok(None);
            }
            roots[plan_index(automaton.edge_targets[edge])] = 1;
        }
    }
    debug_assert!(derivation_work <= MAX_DERIVATION_WORK);

    let graph_instruction_limit = graph_instruction_limit(automaton).unwrap_or(0);
    if graph_instruction_limit == 0 {
        return Ok(None);
    }
    let mut active = exact_filled(states, 0_u8, scratch_bytes)?;
    let mut frames = exact_vec(states, scratch_bytes)?;
    let mut programs = 0usize;
    let mut instructions = 0usize;
    let mut eliminated_edge_visits = 0usize;
    for (state, &is_root) in roots.iter().enumerate() {
        if is_root == 0 || automaton.roles[state] != StateRole::Split {
            continue;
        }
        let root = u32::try_from(state).expect("validated state index fits u32");
        let Some(program) = count_program(
            automaton,
            root,
            &mut active,
            &mut frames,
            graph_instruction_limit,
            &mut derivation_work,
        ) else {
            return Ok(None);
        };
        if derivation_work > MAX_DERIVATION_WORK {
            return Ok(None);
        }
        if !program.admitted() {
            continue;
        }
        programs = programs.checked_add(1).ok_or(
            EpsilonClosureDispatchAllocationError {
                requested_bytes: usize::MAX,
            },
        )?;
        instructions = instructions.checked_add(program.instructions).ok_or(
            EpsilonClosureDispatchAllocationError {
                requested_bytes: usize::MAX,
            },
        )?;
        eliminated_edge_visits = eliminated_edge_visits
            .checked_add(program.edge_visits)
            .ok_or(EpsilonClosureDispatchAllocationError {
                requested_bytes: usize::MAX,
            })?;
        if instructions > graph_instruction_limit {
            return Ok(None);
        }
    }
    if programs == 0 {
        return Ok(Some((
            DispatchShape {
                programs: 0,
                instructions: 0,
                eliminated_edge_visits: 0,
                retained_bytes: 0,
                derivation_work,
            },
            roots,
        )));
    }

    // Reserve the second count pass used to select programs during exact
    // emission, plus one emission visit per retained instruction.
    derivation_work = derivation_work
        .checked_mul(2)
        .and_then(|work| work.checked_add(instructions))
        .ok_or(EpsilonClosureDispatchAllocationError {
            requested_bytes: usize::MAX,
        })?;
    if derivation_work > MAX_DERIVATION_WORK {
        return Ok(None);
    }
    let retained_bytes = states
        .checked_mul(size_of::<u32>())
        .and_then(|bytes| {
            instructions
                .checked_mul(size_of::<ClosureInstruction>())
                .and_then(|more| bytes.checked_add(more))
        })
        .and_then(|bytes| bytes.checked_add(size_of::<EpsilonClosureDispatchData>()))
        .ok_or(EpsilonClosureDispatchAllocationError {
            requested_bytes: usize::MAX,
        })?;
    let graph_relative_limit = automaton
        .stats()
        .storage_bytes()
        .saturating_mul(MAX_RETAINED_TO_GRAPH_FACTOR);
    if retained_bytes > MAX_RETAINED_BYTES
        || retained_bytes > graph_relative_limit
        || instructions > usize::try_from(SUBTREE_END_MASK).unwrap_or(usize::MAX)
        || u32::try_from(instructions).is_err()
    {
        return Ok(None);
    }
    Ok(Some((
        DispatchShape {
            programs,
            instructions,
            eliminated_edge_visits,
            retained_bytes,
            derivation_work,
        },
        roots,
    )))
}

fn graph_instruction_limit(automaton: &Automaton) -> Option<usize> {
    let graph_items = automaton
        .stats()
        .states()
        .checked_add(automaton.stats().zero_width_edges())?;
    let relative = graph_items.checked_mul(MAX_PROGRAM_EXPANSION_FACTOR)?;
    let retained = MAX_RETAINED_BYTES.checked_div(size_of::<ClosureInstruction>())?;
    Some(relative.min(retained).min(plan_index(SUBTREE_END_MASK)))
}

fn compiler_scratch_bytes(
    states: usize,
) -> Result<usize, EpsilonClosureDispatchAllocationError> {
    states
        .checked_mul(2)
        .and_then(|bytes| {
            states
                .checked_mul(size_of::<CountFrame>())
                .and_then(|more| bytes.checked_add(more))
        })
        .and_then(|bytes| {
            states
                .checked_mul(size_of::<EmitFrame>())
                .and_then(|more| bytes.checked_add(more))
        })
        .ok_or(EpsilonClosureDispatchAllocationError {
            requested_bytes: usize::MAX,
        })
}

fn bounded_compiler_scratch_bytes(
    states: usize,
) -> Result<Option<usize>, EpsilonClosureDispatchAllocationError> {
    let bytes = compiler_scratch_bytes(states)?;
    // Refuse before allocating even the root bitmap. The later exact
    // compiler scratch allocations are a subset of this combined extent.
    Ok((bytes <= MAX_COMPILER_SCRATCH_BYTES).then_some(bytes))
}

fn try_admit_derivation_work(
    consumed: &mut usize,
    requested: usize,
) -> Result<bool, EpsilonClosureDispatchAllocationError> {
    let next = consumed.checked_add(requested).ok_or(
        EpsilonClosureDispatchAllocationError {
            requested_bytes: usize::MAX,
        },
    )?;
    if next > MAX_DERIVATION_WORK {
        return Ok(false);
    }
    *consumed = next;
    Ok(true)
}

fn count_program(
    automaton: &Automaton,
    root: u32,
    active: &mut [u8],
    frames: &mut Vec<CountFrame>,
    instruction_limit: usize,
    derivation_work: &mut usize,
) -> Option<ProgramShape> {
    debug_assert!(active.iter().all(|&entry| entry == 0));
    frames.clear();
    let mut shape = ProgramShape::default();

    let visit = |state: u32,
                 active: &mut [u8],
                 frames: &mut Vec<CountFrame>,
                 shape: &mut ProgramShape,
                 derivation_work: &mut usize|
     -> Option<()> {
        shape.instructions = shape.instructions.checked_add(1)?;
        *derivation_work = derivation_work.checked_add(1)?;
        if shape.instructions > instruction_limit || *derivation_work > MAX_DERIVATION_WORK {
            return None;
        }
        let index = plan_index(state);
        if active[index] != 0 {
            return Some(());
        }
        if automaton.roles[index] != StateRole::Split {
            return Some(());
        }
        let edges = automaton.state_edges(state);
        shape.edge_visits = shape.edge_visits.checked_add(edges.len())?;
        active[index] = 1;
        frames.push(CountFrame {
            state,
            next_edge: edges.start,
            end_edge: edges.end,
        });
        Some(())
    };

    visit(
        root,
        active,
        frames,
        &mut shape,
        derivation_work,
    )?;
    while let Some(frame) = frames.last_mut() {
        if frame.next_edge < frame.end_edge {
            let edge = frame.next_edge;
            frame.next_edge = frame.next_edge.checked_add(1)?;
            *derivation_work = derivation_work.checked_add(1)?;
            let target = automaton.edge_targets[edge];
            visit(
                target,
                active,
                frames,
                &mut shape,
                derivation_work,
            )?;
        } else {
            let state = frame.state;
            frames.pop();
            active[plan_index(state)] = 0;
        }
    }
    Some(shape)
}

fn emit_visit(
    automaton: &Automaton,
    state: u32,
    base: usize,
    active: &mut [u8],
    frames: &mut Vec<EmitFrame>,
    instructions: &mut Vec<ClosureInstruction>,
    emitted_edge_visits: &mut usize,
) {
    let index = plan_index(state);
    if active[index] != 0 {
        let instruction = instructions.len();
        instructions.push(ClosureInstruction::placeholder(
            state,
            ClosureAction::SeenBackedge,
            0,
        ));
        let subtree_end = instruction
            .checked_add(1)
            .and_then(|end| end.checked_sub(base))
            .expect("the bounded program-local backedge end is ordered");
        instructions[instruction].finish(subtree_end);
        return;
    }
    let action = match automaton.roles[index] {
        StateRole::Split => ClosureAction::Split,
        StateRole::Consume => ClosureAction::Consume,
        StateRole::Accept => ClosureAction::Accept,
    };
    let edges = automaton.state_edges(state);
    let edge_work = if action == ClosureAction::Split {
        u32::try_from(edges.len()).expect("validated edge row length fits u32")
    } else {
        0
    };
    let instruction = instructions.len();
    instructions.push(ClosureInstruction::placeholder(state, action, edge_work));
    if action == ClosureAction::Split {
        *emitted_edge_visits = emitted_edge_visits
            .checked_add(edges.len())
            .expect("preflighted epsilon-closure edge visits");
        active[index] = 1;
        frames.push(EmitFrame {
            state,
            next_edge: edges.start,
            end_edge: edges.end,
            instruction,
        });
    } else {
        let subtree_end = instruction
            .checked_add(1)
            .and_then(|end| end.checked_sub(base))
            .expect("the bounded program-local leaf end is ordered");
        instructions[instruction].finish(subtree_end);
    }
}

fn emit_program(
    automaton: &Automaton,
    root: u32,
    active: &mut [u8],
    frames: &mut Vec<EmitFrame>,
    instructions: &mut Vec<ClosureInstruction>,
    expected: ProgramShape,
) {
    debug_assert!(active.iter().all(|&entry| entry == 0));
    frames.clear();
    let base = instructions.len();
    let mut emitted_edge_visits = 0usize;

    emit_visit(
        automaton,
        root,
        base,
        active,
        frames,
        instructions,
        &mut emitted_edge_visits,
    );
    while let Some(frame) = frames.last_mut() {
        if frame.next_edge < frame.end_edge {
            let edge = frame.next_edge;
            frame.next_edge = frame
                .next_edge
                .checked_add(1)
                .expect("preflighted epsilon-closure edge cursor");
            emit_visit(
                automaton,
                automaton.edge_targets[edge],
                base,
                active,
                frames,
                instructions,
                &mut emitted_edge_visits,
            );
        } else {
            let frame = frames.pop().expect("the current emit frame exists");
            active[plan_index(frame.state)] = 0;
            let subtree_end = instructions
                .len()
                .checked_sub(base)
                .expect("the bounded program end follows its base");
            instructions[frame.instruction].finish(subtree_end);
        }
    }
    debug_assert_eq!(
        instructions.len().checked_sub(base),
        Some(expected.instructions)
    );
    debug_assert_eq!(emitted_edge_visits, expected.edge_visits);
}

fn state_edges(automaton: &Automaton, state: usize) -> core::ops::Range<usize> {
    let next = state
        .checked_add(1)
        .expect("validated automaton state has a following CSR offset");
    plan_index(automaton.edge_offsets[state])..plan_index(automaton.edge_offsets[next])
}

fn exact_vec<T>(
    length: usize,
    requested_bytes: usize,
) -> Result<Vec<T>, EpsilonClosureDispatchAllocationError> {
    let mut values = Vec::new();
    values.try_reserve_exact(length).map_err(|_| {
        EpsilonClosureDispatchAllocationError { requested_bytes }
    })?;
    if values.capacity() != length {
        return Err(EpsilonClosureDispatchAllocationError { requested_bytes });
    }
    Ok(values)
}

fn exact_filled<T: Clone>(
    length: usize,
    value: T,
    requested_bytes: usize,
) -> Result<Vec<T>, EpsilonClosureDispatchAllocationError> {
    let mut values = exact_vec(length, requested_bytes)?;
    values.resize(length, value);
    Ok(values)
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{
        ClosureAction, ClosureInstruction, ClosureRoot, EpsilonClosureDispatchData,
        MAX_RETAINED_TO_GRAPH_FACTOR,
    };
    use crate::{Automaton, CompileLimits, EdgeKind, RawPlan, StateRole};

    fn branching_cycle(asserted: bool) -> Automaton {
        let first_kind = if asserted {
            EdgeKind::AssertHaystackStart
        } else {
            EdgeKind::Epsilon
        };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 4, 5, 5],
                edge_targets: vec![1, 2, 0, 3, 0],
                edge_kinds: vec![
                    first_kind,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, 0, 0, b'a'],
                byte_ends: vec![0, 0, 0, 0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn branching_leaf_roots() -> Automaton {
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
                edge_targets: vec![1, 4, 2, 3, 5],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b'b', b'c'],
                byte_ends: vec![0, 0, b'a', b'b', b'c'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_program_unfolds_priority_and_marks_only_ancestor_backedges() {
        let mut automaton = branching_cycle(false);
        assert!(automaton.try_enable_epsilon_closure_dispatch().unwrap());
        let dispatch = automaton.epsilon_closure_dispatch.as_ref().unwrap();
        assert_eq!(dispatch.admitted_programs(), 1);
        assert!(dispatch.eliminated_edge_visits() >= 4);
        let ClosureRoot::Program(program) = dispatch.root(0) else {
            panic!("the admitted start Split has compiled bytecode");
        };
        assert!(
            matches!(dispatch.root(1), ClosureRoot::Scalar),
            "non-root Split has no descriptor"
        );
        assert_eq!(program[0].state(), 0);
        assert_eq!(program[0].action(), ClosureAction::Split);
        assert_eq!(program[0].subtree_end(), program.len());
        assert!(program
            .iter()
            .any(|instruction| instruction.action() == ClosureAction::SeenBackedge));
        assert!(automaton.epsilon_closure_dispatch_retained_bytes() > 0);
        assert_eq!(
            automaton.epsilon_closure_dispatch_retained_bytes(),
            automaton.stats().states() * size_of::<u32>()
                + dispatch.instruction_count() * size_of::<ClosureInstruction>()
                + size_of::<EpsilonClosureDispatchData>()
        );
        assert_eq!(size_of::<ClosureInstruction>(), 12);
        assert!(
            automaton.epsilon_closure_dispatch_retained_bytes()
                <= automaton
                    .stats()
                    .storage_bytes()
                    .checked_mul(MAX_RETAINED_TO_GRAPH_FACTOR)
                    .unwrap()
        );

        let cloned = automaton.clone();
        assert_eq!(
            cloned.epsilon_closure_dispatch,
            automaton.epsilon_closure_dispatch
        );
    }

    #[test]
    fn root_lookup_classifies_boundary_leaves_without_instruction_entries() {
        let mut automaton = branching_leaf_roots();
        assert!(automaton.try_enable_epsilon_closure_dispatch().unwrap());
        let dispatch = automaton.epsilon_closure_dispatch.as_ref().unwrap();
        assert!(matches!(dispatch.root(0), ClosureRoot::Program(_)));
        assert!(matches!(dispatch.root(1), ClosureRoot::Scalar));
        assert!(matches!(dispatch.root(2), ClosureRoot::Consume));
        assert!(matches!(dispatch.root(3), ClosureRoot::Accept));
        assert!(matches!(dispatch.root(4), ClosureRoot::Scalar));
        assert!(matches!(dispatch.root(5), ClosureRoot::Accept));
    }

    #[test]
    fn assertions_and_trivial_closures_decline_without_partial_state() {
        let mut asserted = branching_cycle(true);
        assert!(!asserted.try_enable_epsilon_closure_dispatch().unwrap());
        assert!(!asserted.has_epsilon_closure_dispatch());

        let mut literal = Automaton::from_raw(
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
        assert!(!literal.try_enable_epsilon_closure_dispatch().unwrap());
        assert_eq!(literal.epsilon_closure_dispatch_retained_bytes(), 0);
    }

    #[test]
    fn exponentially_unfolding_dag_hits_the_graph_relative_ceiling() {
        const LEVELS: usize = 10;
        let split_states = LEVELS * 2;
        let consume = split_states;
        let accept = consume + 1;
        let mut roles = vec![StateRole::Split; split_states];
        roles.extend([StateRole::Consume, StateRole::Accept]);
        let mut offsets = Vec::with_capacity(roles.len() + 1);
        let mut targets = Vec::new();
        let mut kinds = Vec::new();
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        offsets.push(0);
        for state in 0..roles.len() {
            if state < split_states {
                let level = state / 2;
                if level + 1 < LEVELS {
                    let next = (level + 1) * 2;
                    targets.extend([
                        u32::try_from(next).unwrap(),
                        u32::try_from(next + 1).unwrap(),
                    ]);
                    kinds.extend([EdgeKind::Epsilon; 2]);
                    starts.extend([0; 2]);
                    ends.extend([0; 2]);
                } else {
                    targets.extend([u32::try_from(consume).unwrap(); 2]);
                    kinds.extend([EdgeKind::Epsilon; 2]);
                    starts.extend([0; 2]);
                    ends.extend([0; 2]);
                }
            } else if state == consume {
                targets.push(u32::try_from(accept).unwrap());
                kinds.push(EdgeKind::ByteRange);
                starts.push(b'a');
                ends.push(b'a');
            }
            offsets.push(u32::try_from(targets.len()).unwrap());
        }
        let mut automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles,
                edge_offsets: offsets,
                edge_targets: targets,
                edge_kinds: kinds,
                byte_starts: starts,
                byte_ends: ends,
            },
            CompileLimits::default(),
        )
        .unwrap();
        assert!(!automaton.try_enable_epsilon_closure_dispatch().unwrap());
        assert!(!automaton.has_epsilon_closure_dispatch());
    }

    #[test]
    fn compiler_scratch_cap_declines_transactionally_and_overflow_is_an_error() {
        let bytes_per_state = super::compiler_scratch_bytes(1).unwrap();
        let threshold_states = super::MAX_COMPILER_SCRATCH_BYTES / bytes_per_state;
        let threshold_bytes = super::bounded_compiler_scratch_bytes(threshold_states)
            .unwrap()
            .expect("the greatest whole-state extent below the cap is admitted");
        assert!(threshold_bytes <= super::MAX_COMPILER_SCRATCH_BYTES);
        assert_eq!(
            super::bounded_compiler_scratch_bytes(threshold_states.checked_add(1).unwrap()),
            Ok(None),
            "one state over the fixed scratch ceiling declines without allocating"
        );
        assert_eq!(
            super::bounded_compiler_scratch_bytes(usize::MAX),
            Err(super::EpsilonClosureDispatchAllocationError {
                requested_bytes: usize::MAX
            })
        );
    }

    #[test]
    fn derivation_work_declines_at_one_over_without_scanning_more_edges() {
        let mut work = super::MAX_DERIVATION_WORK.checked_sub(1).unwrap();
        assert_eq!(super::try_admit_derivation_work(&mut work, 1), Ok(true));
        assert_eq!(work, super::MAX_DERIVATION_WORK);
        assert_eq!(super::try_admit_derivation_work(&mut work, 1), Ok(false));
        assert_eq!(
            work,
            super::MAX_DERIVATION_WORK,
            "declined work is not committed"
        );

        work = usize::MAX;
        assert_eq!(
            super::try_admit_derivation_work(&mut work, 1),
            Err(super::EpsilonClosureDispatchAllocationError {
                requested_bytes: usize::MAX
            })
        );
    }
}
