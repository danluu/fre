//! DFA-table proof for replay-free guarded prefixes.
//!
//! Native candidate filters have already proved that bytes at the candidate
//! satisfy the graph-derived anchored-prefix constraints. Replaying those
//! bytes through the scalar DFA is unnecessary when bounded table analysis
//! proves that every guarded prefix reaches one common live, non-accepting
//! state. This pass computes that fact from the finalized DFA and the same
//! target-neutral prefix facts used by the guards.
//!
//! The optional two-byte relation guard is significant: independent prefix
//! columns admit a Cartesian product that can contain impossible pairs. When
//! that exact guard is active, the first two transitions are enumerated from
//! its graph-derived relation. Later columns remain conservative independent
//! sets. Intermediate state divergence is retained, so a later byte (or the
//! exact pair as a unit) may safely reconverge.

#![allow(
    dead_code,
    reason = "the bounded proof is an isolated handoff for native lowering"
)]

use core::mem::size_of;

use crate::{
    dfa::ForwardCell,
    prefix_relation::{self, PrefixRelation},
    program::{AnchoredByteSet, NativeProgramView},
};

const NO_STATE: u32 = u32::MAX;

/// Maximum completed DFA states inspected by this optional proof.
pub(crate) const MAX_PREFIX_FAST_FORWARD_STATES: usize = 65_536;
/// Maximum completed forward cells admitted by this optional proof.
pub(crate) const MAX_PREFIX_FAST_FORWARD_CELLS: usize = 16_777_216;
/// Maximum deterministic table and byte-set work charged by this proof.
pub(crate) const MAX_PREFIX_FAST_FORWARD_WORK: u64 = 1_000_000;
/// Maximum auxiliary storage reserved by this proof.
pub(crate) const MAX_PREFIX_FAST_FORWARD_MEMORY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "uniform max_ names make every independent ceiling explicit"
)]
struct PrefixFastForwardLimits {
    max_states: usize,
    max_cells: usize,
    max_work: u64,
    max_memory_bytes: usize,
}

impl Default for PrefixFastForwardLimits {
    fn default() -> Self {
        Self {
            max_states: MAX_PREFIX_FAST_FORWARD_STATES,
            max_cells: MAX_PREFIX_FAST_FORWARD_CELLS,
            max_work: MAX_PREFIX_FAST_FORWARD_WORK,
            max_memory_bytes: MAX_PREFIX_FAST_FORWARD_MEMORY_BYTES,
        }
    }
}

/// A replay-free DFA entry after a successful anchored-prefix guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrefixFastForwardPlan {
    /// Number of bytes by which native code may advance the input cursor.
    pub(crate) consumed_bytes: u8,
    /// Forward-DFA state after all skipped transitions.
    pub(crate) target_state: u32,
}

#[derive(Clone, Copy, Debug)]
struct Budget {
    limit: u64,
    used: u64,
}

impl Budget {
    const fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    fn charge(&mut self, amount: u64) -> Option<()> {
        let next = self.used.checked_add(amount)?;
        if next > self.limit {
            return None;
        }
        self.used = next;
        Some(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckedStep {
    Live(u32),
    AcceptOrDead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Advance {
    Complete,
    AcceptOrDead,
}

struct FrontierWorkspace {
    current: Vec<u32>,
    next: Vec<u32>,
    seen_generation: Vec<u32>,
    generation: u32,
}

impl FrontierWorkspace {
    fn new(states: usize, memory_limit: usize) -> Option<Self> {
        let bytes = states.checked_mul(size_of::<u32>())?.checked_mul(3)?;
        if bytes > memory_limit {
            return None;
        }
        let mut current = Vec::new();
        current.try_reserve_exact(states).ok()?;
        let mut next = Vec::new();
        next.try_reserve_exact(states).ok()?;
        let mut seen_generation = Vec::new();
        seen_generation.try_reserve_exact(states).ok()?;
        seen_generation.resize(states, 0);
        Some(Self {
            current,
            next,
            seen_generation,
            generation: 0,
        })
    }

    fn begin_next(&mut self) -> Option<()> {
        self.generation = self.generation.checked_add(1)?;
        self.next.clear();
        Some(())
    }

    fn insert_next(&mut self, state: u32) -> Option<()> {
        let index = usize::try_from(state).ok()?;
        let seen = self.seen_generation.get_mut(index)?;
        if *seen != self.generation {
            *seen = self.generation;
            self.next.push(state);
        }
        Some(())
    }

    fn finish_next(&mut self) {
        core::mem::swap(&mut self.current, &mut self.next);
    }

    fn singleton(&self) -> Option<u32> {
        let [state] = self.current.as_slice() else {
            return None;
        };
        Some(*state)
    }
}

struct SetMembers {
    words: [u64; 4],
    word: usize,
}

impl SetMembers {
    const fn new(set: AnchoredByteSet) -> Self {
        Self {
            words: set.words(),
            word: 0,
        }
    }
}

impl Iterator for SetMembers {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        while self.word < self.words.len() {
            let bits = self.words[self.word];
            if bits == 0 {
                self.word = self.word.checked_add(1)?;
                continue;
            }
            let bit = bits.trailing_zeros();
            self.words[self.word] &= bits.checked_sub(1)?;
            let byte = self
                .word
                .checked_mul(64)?
                .checked_add(usize::try_from(bit).ok()?)?;
            return u8::try_from(byte).ok();
        }
        None
    }
}

fn set_contains(set: AnchoredByteSet, byte: u8) -> bool {
    let index = usize::from(byte);
    set.words()[index / 64] & (1_u64 << (index % 64)) != 0
}

fn validate_view(
    view: NativeProgramView<'_>,
    limits: PrefixFastForwardLimits,
    budget: &mut Budget,
) -> Option<usize> {
    let dfa = view.dfa;
    if dfa.initial_pending
        || dfa.initial_terminal
        || dfa.class_count == 0
        || dfa.class_count > 256
        || dfa.class_representatives.len() != dfa.class_count
        || dfa.forward_cells.is_empty()
        || dfa.forward_cells.len() > limits.max_cells
        || !dfa.forward_cells.len().is_multiple_of(dfa.class_count)
        || view.anchored_prefix.sets().is_empty()
    {
        return None;
    }
    let states = dfa.forward_cells.len().checked_div(dfa.class_count)?;
    if states == 0 || states > limits.max_states {
        return None;
    }
    let initial = usize::try_from(dfa.initial_state).ok()?;
    if initial >= states {
        return None;
    }

    let mut represented = [false; 256];
    for &class in dfa.byte_classes {
        budget.charge(1)?;
        let class = usize::from(class);
        if class >= dfa.class_count {
            return None;
        }
        represented[class] = true;
    }
    if represented[..dfa.class_count]
        .iter()
        .any(|present| !present)
    {
        return None;
    }
    for (class, &representative) in dfa.class_representatives.iter().enumerate() {
        budget.charge(1)?;
        if usize::from(dfa.byte_classes[usize::from(representative)]) != class {
            return None;
        }
    }
    if view
        .anchored_prefix
        .sets()
        .iter()
        .any(|set| set.cardinality() == 0)
    {
        return None;
    }
    Some(states)
}

fn checked_step(
    view: NativeProgramView<'_>,
    states: usize,
    state: u32,
    byte: u8,
    budget: &mut Budget,
) -> Option<CheckedStep> {
    budget.charge(1)?;
    let state = usize::try_from(state).ok()?;
    if state >= states {
        return None;
    }
    let class = usize::from(view.dfa.byte_classes[usize::from(byte)]);
    if class >= view.dfa.class_count {
        return None;
    }
    let row = state.checked_mul(view.dfa.class_count)?;
    let cell: ForwardCell = *view.dfa.forward_cells.get(row.checked_add(class)?)?;
    if cell.next != NO_STATE
        && usize::try_from(cell.next)
            .ok()
            .is_none_or(|next| next >= states)
    {
        return None;
    }
    if cell.accepted || cell.next == NO_STATE {
        Some(CheckedStep::AcceptOrDead)
    } else {
        Some(CheckedStep::Live(cell.next))
    }
}

fn advance_independent(
    view: NativeProgramView<'_>,
    states: usize,
    set: AnchoredByteSet,
    workspace: &mut FrontierWorkspace,
    budget: &mut Budget,
) -> Option<Advance> {
    workspace.begin_next()?;
    for state_index in 0..workspace.current.len() {
        let state = workspace.current[state_index];
        for byte in SetMembers::new(set) {
            match checked_step(view, states, state, byte, budget)? {
                CheckedStep::Live(target) => workspace.insert_next(target)?,
                CheckedStep::AcceptOrDead => return Some(Advance::AcceptOrDead),
            }
        }
    }
    if workspace.next.is_empty() {
        return None;
    }
    workspace.finish_next();
    Some(Advance::Complete)
}

fn validate_relation(
    relation: &PrefixRelation,
    first_column: AnchoredByteSet,
    second_column: AnchoredByteSet,
    budget: &mut Budget,
) -> Option<AnchoredByteSet> {
    if relation.groups().is_empty() || relation.pair_count() == 0 {
        return None;
    }
    let mut first_words = [0_u64; 4];
    let mut first_seen = [false; 256];
    let mut pair_count = 0_u32;
    for group in relation.groups() {
        if group.first().cardinality() == 0 || group.second().cardinality() == 0 {
            return None;
        }
        for first in SetMembers::new(group.first()) {
            budget.charge(1)?;
            if !set_contains(first_column, first) || first_seen[usize::from(first)] {
                return None;
            }
            first_seen[usize::from(first)] = true;
            let index = usize::from(first);
            first_words[index / 64] |= 1_u64 << (index % 64);
        }
        for second in SetMembers::new(group.second()) {
            budget.charge(1)?;
            if !set_contains(second_column, second) {
                return None;
            }
        }
        pair_count = pair_count.checked_add(
            u32::from(group.first().cardinality())
                .checked_mul(u32::from(group.second().cardinality()))?,
        )?;
    }
    let first_set = AnchoredByteSet::from_words(first_words);
    if first_set != relation.viable_first() || pair_count != relation.pair_count() {
        return None;
    }
    Some(first_set)
}

fn advance_exact_pair(
    view: NativeProgramView<'_>,
    states: usize,
    relation: &PrefixRelation,
    workspace: &mut FrontierWorkspace,
    budget: &mut Budget,
) -> Option<Advance> {
    workspace.begin_next()?;
    for group in relation.groups() {
        for first in SetMembers::new(group.first()) {
            let first_target =
                match checked_step(view, states, view.dfa.initial_state, first, budget)? {
                    CheckedStep::Live(target) => target,
                    CheckedStep::AcceptOrDead => return Some(Advance::AcceptOrDead),
                };
            for second in SetMembers::new(group.second()) {
                match checked_step(view, states, first_target, second, budget)? {
                    CheckedStep::Live(target) => workspace.insert_next(target)?,
                    CheckedStep::AcceptOrDead => return Some(Advance::AcceptOrDead),
                }
            }
        }
    }
    if workspace.next.is_empty() {
        return None;
    }
    workspace.finish_next();
    Some(Advance::Complete)
}

fn record_singleton(
    workspace: &FrontierWorkspace,
    consumed_bytes: usize,
    best: &mut Option<PrefixFastForwardPlan>,
) -> Option<()> {
    if let Some(target_state) = workspace.singleton() {
        *best = Some(PrefixFastForwardPlan {
            consumed_bytes: u8::try_from(consumed_bytes).ok()?,
            target_state,
        });
    }
    Some(())
}

/// Derive the longest bounded replay-free prefix for one native DFA.
///
/// `exact_two_byte_relation_guard` must be true only when native lowering will
/// execute the exact relation produced by [`prefix_relation::derive`] before
/// taking this fast-forward. Returning `None` conservatively retains ordinary
/// DFA replay.
#[must_use]
pub(crate) fn derive(
    view: NativeProgramView<'_>,
    exact_two_byte_relation_guard: bool,
) -> Option<PrefixFastForwardPlan> {
    derive_with_limits(
        view,
        exact_two_byte_relation_guard,
        PrefixFastForwardLimits::default(),
    )
}

fn derive_with_limits(
    view: NativeProgramView<'_>,
    exact_two_byte_relation_guard: bool,
    limits: PrefixFastForwardLimits,
) -> Option<PrefixFastForwardPlan> {
    let mut budget = Budget::new(limits.max_work);
    let states = validate_view(view, limits, &mut budget)?;
    let mut workspace = FrontierWorkspace::new(states, limits.max_memory_bytes)?;
    workspace.current.push(view.dfa.initial_state);
    let sets = view.anchored_prefix.sets();
    let mut best = None;
    let mut next_position = 0;

    if exact_two_byte_relation_guard {
        let [first, second, ..] = sets else {
            return None;
        };
        let relation = prefix_relation::derive(view.raw)?;
        let viable_first = validate_relation(&relation, *first, *second, &mut budget)?;
        if advance_independent(view, states, viable_first, &mut workspace, &mut budget)?
            == Advance::AcceptOrDead
        {
            return None;
        }
        record_singleton(&workspace, 1, &mut best)?;

        // The exact pair relation is rooted at the initial state, not at the
        // possibly merged first-byte frontier above.
        if advance_exact_pair(view, states, &relation, &mut workspace, &mut budget)?
            == Advance::AcceptOrDead
        {
            return best;
        }
        record_singleton(&workspace, 2, &mut best)?;
        next_position = 2;
    }

    for (position, &set) in sets.iter().enumerate().skip(next_position) {
        if advance_independent(view, states, set, &mut workspace, &mut budget)?
            == Advance::AcceptOrDead
        {
            return best;
        }
        record_singleton(&workspace, position.checked_add(1)?, &mut best)?;
    }
    best
}

#[cfg(test)]
mod tests {
    use fre_automata::{Automaton, CompileLimits as AutomatonLimits};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;
    use crate::{
        CompileMode, DeterminizeLimits, OutputContract, dfa::NativeDfaView,
        program::CompiledProgram,
    };

    fn program(pattern: &str) -> CompiledProgram {
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern.to_owned(),
            CompatibilityProfile::RustBytes(RustProfile::default()),
        ))
        .unwrap_or_else(|error| panic!("parse {pattern:?}: {error}"));
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust parse returned a non-Rust pattern");
        };
        let raw = fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("lower {pattern:?}: {error}"))
        .into_plan();
        let automaton = Automaton::from_raw(raw.clone(), AutomatonLimits::default())
            .unwrap_or_else(|error| panic!("validate {pattern:?}: {error}"));
        CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Exists,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        )
        .unwrap_or_else(|error| panic!("determinize {pattern:?}: {error}"))
    }

    fn transition(view: NativeProgramView<'_>, state: u32, byte: u8) -> ForwardCell {
        let row = usize::try_from(state)
            .expect("oracle state")
            .checked_mul(view.dfa.class_count)
            .expect("oracle row");
        let class = usize::from(view.dfa.byte_classes[usize::from(byte)]);
        view.dfa.forward_cells[row.checked_add(class).expect("oracle cell")]
    }

    fn cartesian_prefixes(sets: &[AnchoredByteSet], depth: usize) -> Vec<Vec<u8>> {
        let mut prefixes = vec![Vec::new()];
        for &set in &sets[..depth] {
            let mut next = Vec::new();
            for prefix in prefixes {
                for byte in SetMembers::new(set) {
                    let mut extended = prefix.clone();
                    extended.push(byte);
                    next.push(extended);
                }
            }
            prefixes = next;
        }
        prefixes
    }

    fn guarded_prefixes(
        view: NativeProgramView<'_>,
        exact_relation: bool,
        depth: usize,
    ) -> Vec<Vec<u8>> {
        if !exact_relation || depth < 2 {
            if exact_relation {
                let relation = prefix_relation::derive(view.raw).expect("test relation");
                let mut first = relation
                    .groups()
                    .iter()
                    .flat_map(|group| SetMembers::new(group.first()))
                    .collect::<Vec<_>>();
                first.sort_unstable();
                first.dedup();
                return first.into_iter().map(|byte| vec![byte]).collect();
            }
            return cartesian_prefixes(view.anchored_prefix.sets(), depth);
        }

        let relation = prefix_relation::derive(view.raw).expect("test relation");
        let mut prefixes = Vec::new();
        for group in relation.groups() {
            for first in SetMembers::new(group.first()) {
                for second in SetMembers::new(group.second()) {
                    prefixes.push(vec![first, second]);
                }
            }
        }
        for &set in &view.anchored_prefix.sets()[2..depth] {
            let mut next = Vec::new();
            for prefix in prefixes {
                for byte in SetMembers::new(set) {
                    let mut extended = prefix.clone();
                    extended.push(byte);
                    next.push(extended);
                }
            }
            prefixes = next;
        }
        prefixes
    }

    fn brute_plan(
        view: NativeProgramView<'_>,
        exact_relation: bool,
    ) -> Option<PrefixFastForwardPlan> {
        let mut best = None;
        for depth in 1..=view.anchored_prefix.sets().len() {
            let prefixes = guarded_prefixes(view, exact_relation, depth);
            let mut destination = None;
            let mut divergent = false;
            let mut unsafe_transition = false;
            for prefix in prefixes {
                let mut state = view.dfa.initial_state;
                for byte in prefix {
                    let cell = transition(view, state, byte);
                    if cell.accepted || cell.next == NO_STATE {
                        unsafe_transition = true;
                        break;
                    }
                    state = cell.next;
                }
                if unsafe_transition {
                    break;
                }
                if destination.is_some_and(|existing| existing != state) {
                    divergent = true;
                } else {
                    destination = Some(state);
                }
            }
            if unsafe_transition {
                break;
            }
            if !divergent {
                best = destination.map(|target_state| PrefixFastForwardPlan {
                    consumed_bytes: u8::try_from(depth).expect("bounded test prefix"),
                    target_state,
                });
            }
        }
        best
    }

    fn assert_plan_replays(view: NativeProgramView<'_>, exact_relation: bool) {
        let plan = derive(view, exact_relation).expect("expected fast-forward plan");
        let prefixes = guarded_prefixes(view, exact_relation, usize::from(plan.consumed_bytes));
        assert!(!prefixes.is_empty());
        for prefix in prefixes {
            let mut state = view.dfa.initial_state;
            for byte in prefix {
                let cell = transition(view, state, byte);
                assert!(!cell.accepted, "fast-forward traversed acceptance");
                assert_ne!(cell.next, NO_STATE, "fast-forward traversed death");
                state = cell.next;
            }
            assert_eq!(state, plan.target_state);
        }
    }

    #[test]
    fn literal_skips_every_transition_before_acceptance() {
        let compiled = program("abcdef");
        let view = compiled.native_dfa_view().expect("ordered DFA");
        let plan = derive(view, false).expect("literal fast-forward");
        assert_eq!(plan.consumed_bytes, 5);
        assert_plan_replays(view, false);

        let one = program("a");
        assert!(derive(one.native_dfa_view().expect("ordered DFA"), false).is_none());
    }

    #[test]
    fn exact_pair_guard_recovers_alternation_reconvergence() {
        let compiled = program("(?:ab|cd)Z");
        let view = compiled.native_dfa_view().expect("ordered DFA");
        assert!(derive(view, false).is_none());
        let plan = derive(view, true).expect("relation reconvergence");
        assert_eq!(plan.consumed_bytes, 2);
        assert_plan_replays(view, true);
    }

    #[test]
    fn independent_columns_continue_after_pair_reconvergence() {
        let compiled = program("(?:abQX|cdQX)");
        let view = compiled.native_dfa_view().expect("ordered DFA");
        let plan = derive(view, true).expect("continued relation fast-forward");
        assert_eq!(plan.consumed_bytes, 3);
        assert_plan_replays(view, true);
    }

    #[test]
    fn divergence_and_acceptance_bound_the_safe_prefix() {
        let compiled = program("(?:abX|acY)");
        let view = compiled.native_dfa_view().expect("ordered DFA");
        let plan = derive(view, true).expect("one-byte common prefix");
        assert_eq!(plan.consumed_bytes, 1);
        assert_plan_replays(view, true);

        let accepting_pair = program("(?:ab|cd)");
        assert!(derive(accepting_pair.native_dfa_view().expect("ordered DFA"), true).is_none());
    }

    #[test]
    fn malformed_shapes_and_every_resource_ceiling_decline() {
        let compiled = program("abcdef");
        let view = compiled.native_dfa_view().expect("ordered DFA");

        let mut malformed = view;
        malformed.dfa.class_count = 0;
        assert!(derive(malformed, false).is_none());

        let mut malformed = view;
        malformed.dfa.forward_cells = &view.dfa.forward_cells[..view.dfa.forward_cells.len() - 1];
        assert!(derive(malformed, false).is_none());

        let mut nullable = view;
        nullable.dfa.initial_pending = true;
        assert!(derive(nullable, false).is_none());

        let defaults = PrefixFastForwardLimits::default();
        for limits in [
            PrefixFastForwardLimits {
                max_states: 0,
                ..defaults
            },
            PrefixFastForwardLimits {
                max_cells: 0,
                ..defaults
            },
            PrefixFastForwardLimits {
                max_work: 0,
                ..defaults
            },
            PrefixFastForwardLimits {
                max_memory_bytes: 0,
                ..defaults
            },
        ] {
            assert!(derive_with_limits(view, false, limits).is_none());
        }
    }

    #[derive(Clone, Copy)]
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        fn bounded(&mut self, bound: u64) -> u64 {
            self.next().checked_rem(bound).expect("nonzero RNG bound")
        }
    }

    fn randomized_table_oracle(pattern: &str, exact_relation: bool, iterations: usize) {
        let compiled = program(pattern);
        let base = compiled.native_dfa_view().expect("ordered DFA");
        let byte_classes = core::array::from_fn(|index| u8::try_from(index).expect("byte class"));
        let representatives = byte_classes;
        let states = 8_usize;
        let mut rng = Rng(0x243f_6a88_85a3_08d3);
        let mut successful = 0_usize;

        for iteration in 0..iterations {
            let mut cells = Vec::with_capacity(states * 256);
            for _ in 0..states * 256 {
                let roll = rng.bounded(32);
                cells.push(ForwardCell {
                    next: if roll == 0 {
                        NO_STATE
                    } else {
                        u32::try_from(rng.bounded(u64::try_from(states).expect("state bound")))
                            .expect("random state")
                    },
                    accepted: roll == 1,
                });
            }

            // Regularly force a long safe chain on every independent column;
            // intervening iterations retain arbitrary divergence and stops.
            if iteration.is_multiple_of(4) {
                for (position, &set) in base.anchored_prefix.sets().iter().enumerate() {
                    for state in 0..states {
                        for byte in SetMembers::new(set) {
                            let index = state
                                .checked_mul(256)
                                .and_then(|row| row.checked_add(usize::from(byte)))
                                .expect("forced cell");
                            cells[index] = ForwardCell {
                                next: u32::try_from(
                                    position
                                        .checked_add(1)
                                        .and_then(|next| next.checked_rem(states))
                                        .expect("forced state"),
                                )
                                .expect("forced state fits u32"),
                                accepted: false,
                            };
                        }
                    }
                }
            }

            let mut view = base;
            view.dfa = NativeDfaView {
                initial_state: 0,
                initial_pending: false,
                initial_terminal: false,
                byte_classes: &byte_classes,
                class_count: 256,
                class_representatives: &representatives,
                forward_cells: &cells,
                reverse_initial: None,
                reverse_cells: &[],
            };
            let actual = derive(view, exact_relation);
            let expected = brute_plan(view, exact_relation);
            assert_eq!(actual, expected, "randomized machine {iteration}");
            if actual.is_some() {
                successful = successful.checked_add(1).expect("successful plan count");
                assert_plan_replays(view, exact_relation);
            }
        }
        assert!(successful > 0, "randomized oracle exercised no plans");
    }

    #[test]
    fn randomized_independent_guard_oracle_is_replay_equivalent() {
        randomized_table_oracle("[a-d][e-h][i-l]Z", false, 96);
    }

    #[test]
    fn randomized_exact_relation_oracle_is_replay_equivalent() {
        randomized_table_oracle("(?:ab|cd|ef|gh)[i-l]Z", true, 96);
    }
}
