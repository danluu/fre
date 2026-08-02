//! Strict graph proof and portable mask primitives for a root ASCII run.
//!
//! This module deliberately recognizes only complete automata whose language
//! and ordered priority are exactly one positive repetition of one nonempty
//! ASCII byte set. It fails closed for assertions, alternation, concatenated
//! unequal classes, nullable roots, mixed split priority, unreachable states,
//! and graph encodings outside the lowering shapes proved below.

use fre_simd_kernels::AsciiByteSet;

use crate::{k0::insert_byte_range, plan::Automaton, StateRole};

/// Largest minimum that can be proved from one current 32-byte membership
/// block plus one 32-byte lookahead block.
pub(crate) const ROOT_CORRIDOR_MASK_MAXIMUM_MINIMUM: u32 = 32;

/// Complete structural description of one positive root ASCII-set run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootRunDescriptor {
    set: AsciiByteSet,
    minimum: u32,
    maximum: Option<u32>,
    greedy: bool,
}

impl RootRunDescriptor {
    /// The exact nonempty ASCII set consumed by every repetition.
    pub(crate) const fn set(self) -> AsciiByteSet {
        self.set
    }

    /// The positive number of required member bytes.
    pub(crate) const fn minimum(self) -> u32 {
        self.minimum
    }

    /// The inclusive finite maximum, or `None` for an unbounded run.
    pub(crate) const fn maximum(self) -> Option<u32> {
        self.maximum
    }

    /// Whether ordered optional/loop splits prefer another member.
    ///
    /// Exact repetitions have no priority-bearing split and normalize this
    /// value to `true`.
    pub(crate) const fn greedy(self) -> bool {
        self.greedy
    }
}

/// Prospective work envelope for one optional descriptor attempt.
///
/// The structural walk authenticates one state-role lookup or consuming/split
/// edge per charged unit. A malformed cycle may revisit a state before the
/// complete-state ownership check rejects it, so the prospective envelope
/// admits `states * edges + 8 * states + 2`. Execution reports the exact
/// operations actually performed, not this envelope.
pub(crate) fn root_run_inspection_work(automaton: &Automaton) -> Option<u64> {
    let states = u64::try_from(automaton.stats().states()).ok()?;
    let edges = u64::try_from(automaton.stats().edges()).ok()?;
    states.checked_mul(edges.checked_add(8)?)?.checked_add(2)
}

/// Exact result of one admitted graph inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootRunInspection {
    descriptor: Option<RootRunDescriptor>,
    work: u64,
}

impl RootRunInspection {
    pub(crate) const fn descriptor(self) -> Option<RootRunDescriptor> {
        self.descriptor
    }

    pub(crate) const fn work(self) -> u64 {
        self.work
    }
}

#[derive(Debug, Default)]
struct InspectionMeter {
    work: u64,
}

impl InspectionMeter {
    fn charge(&mut self, amount: u64) {
        // The caller admits the walk only when the conservative envelope is
        // representable, and every actual walk is bounded by that envelope.
        self.work = self.work.saturating_add(amount);
    }
}

/// Prove that the complete automaton is exactly one positive ASCII-set run.
///
/// The admitted finite graph is a nonempty chain of required consuming
/// states followed by zero or more optional diamonds. Every diamond has one
/// consuming arm and one continuation arm, and both arms join at the same
/// next split or accept state. The admitted unbounded graph replaces the last
/// optional continuation with a split that returns to the immediately
/// preceding consuming state. This is exactly the shape emitted by the
/// capture-free lowerer for a one-byte class repetition.
///
/// Requiring the walked state count to equal the complete immutable state
/// table excludes unreachable suffixes and additional accepts. Every admitted
/// non-loop transition advances to a state with a different structural role;
/// revisiting one of those states necessarily forms a cycle, which the state
/// count bound rejects before publication. `Automaton` validation has already
/// proved role-specific edge kinds, canonical zero-width payloads, valid byte
/// ranges and edge targets, and edge-free accepts; this proof consumes those
/// immutable invariants rather than revalidating them.
#[cfg(test)]
pub(crate) fn inspect_root_run(automaton: &Automaton) -> Option<RootRunDescriptor> {
    inspect_root_run_accounted(automaton).descriptor()
}

/// Inspect one graph and retain the exact number of authenticated table items.
#[cold]
#[inline(never)]
pub(crate) fn inspect_root_run_accounted(automaton: &Automaton) -> RootRunInspection {
    let mut meter = InspectionMeter::default();
    let descriptor = inspect_root_run_inner(automaton, &mut meter);
    RootRunInspection {
        descriptor,
        work: meter.work,
    }
}

fn inspect_root_run_inner(
    automaton: &Automaton,
    meter: &mut InspectionMeter,
) -> Option<RootRunDescriptor> {
    meter.charge(2);
    if automaton.roles.is_empty() || automaton.stats().has_assertions() {
        return None;
    }

    let state_count = automaton.roles.len();
    let mut state = automaton.start;
    let mut walked = 0_usize;
    let mut required = 0_u32;
    let mut repeated_set = None;
    let mut preceding_consume = None;
    let mut preceding_target = None;

    while state_role(automaton, state, meter)? == StateRole::Consume {
        if walked >= state_count {
            return None;
        }
        let (set, next) = consume_transition(automaton, state, meter)?;
        retain_equal_set(&mut repeated_set, set)?;
        required = required.checked_add(1)?;
        walked = walked.checked_add(1)?;
        preceding_consume = Some(state);
        preceding_target = Some(next);
        state = next;
    }

    if required == 0 {
        return None;
    }
    let set = repeated_set?;
    if state_role(automaton, state, meter)? == StateRole::Accept {
        walked = walked.checked_add(1)?;
        return (walked == state_count).then_some(RootRunDescriptor {
            set,
            minimum: required,
            maximum: Some(required),
            greedy: true,
        });
    }

    let mut maximum = required;
    let mut split_priority = None;
    loop {
        if walked >= state_count || state_role(automaton, state, meter)? != StateRole::Split {
            return None;
        }
        let choice = split_choice(automaton, state, meter)?;
        retain_equal_priority(&mut split_priority, choice.greedy)?;
        walked = walked.checked_add(1)?;

        if choice.member == preceding_consume? {
            if preceding_target? != state
                || state_role(automaton, choice.continuation, meter)? != StateRole::Accept
            {
                return None;
            }
            walked = walked.checked_add(1)?;
            return (walked == state_count).then_some(RootRunDescriptor {
                set,
                minimum: required,
                maximum: None,
                greedy: split_priority?,
            });
        }

        if walked >= state_count {
            return None;
        }
        let (optional_set, join) = consume_transition(automaton, choice.member, meter)?;
        if optional_set != set || join != choice.continuation {
            return None;
        }
        maximum = maximum.checked_add(1)?;
        walked = walked.checked_add(1)?;
        preceding_consume = Some(choice.member);
        preceding_target = Some(join);
        state = choice.continuation;

        match state_role(automaton, state, meter)? {
            StateRole::Split => {}
            StateRole::Accept => {
                walked = walked.checked_add(1)?;
                return (walked == state_count).then_some(RootRunDescriptor {
                    set,
                    minimum: required,
                    maximum: Some(maximum),
                    greedy: split_priority?,
                });
            }
            StateRole::Consume => return None,
        }
    }
}

/// Concatenate one classified current block and its lookahead block.
///
/// Bit `i` describes current lane `i` for `i < 32`; bits `32..=63` describe
/// lookahead lanes `0..=31`.
pub(crate) fn root_corridor_member_window(current: u32, lookahead: u32) -> u64 {
    u64::from(current) | (u64::from(lookahead) << 32)
}

/// Return current-block lanes that begin at least `minimum` member bytes.
///
/// The result is zero for a zero minimum or a minimum above 32. For an
/// admitted minimum this uses a fixed six-element doubling table: table entry
/// `k` marks starts of member runs of length `2^k`, and the set bits of the
/// requested minimum combine those runs in `O(log minimum)` operations. No
/// member/nonmember run is walked.
#[inline(never)]
pub(crate) fn qualifying_start_mask(members: u64, minimum: u32) -> u32 {
    if minimum == 0 || minimum > ROOT_CORRIDOR_MASK_MAXIMUM_MINIMUM {
        return 0;
    }

    let mut powers = [0_u64; 6];
    powers[0] = members;
    let mut level = 1_usize;
    while level < powers.len() {
        let preceding_level = level.checked_sub(1).expect("positive level");
        let preceding_span = 1_u32
            .checked_shl(u32::try_from(preceding_level).expect("the fixed level fits u32"))
            .expect("the fixed power-of-two span fits u32");
        powers[level] = powers[preceding_level] & (powers[preceding_level] >> preceding_span);
        level = level.checked_add(1).expect("the fixed level count fits");
    }

    let mut qualified = u64::MAX;
    let mut offset = 0_u32;
    let mut chunks = minimum;
    let mut level = 0_usize;
    while chunks != 0 {
        if chunks & 1 != 0 {
            qualified &= powers[level] >> offset;
            let span = 1_u32
                .checked_shl(u32::try_from(level).expect("the fixed level fits u32"))
                .expect("the fixed power-of-two span fits u32");
            offset = offset
                .checked_add(span)
                .expect("the admitted minimum is at most 32");
        }
        chunks >>= 1;
        level = level.checked_add(1).expect("the fixed level count fits");
    }

    u32::try_from(qualified & u64::from(u32::MAX))
        .expect("the result is explicitly restricted to current-block lanes")
}

/// Scalar predicate for a single current-block candidate.
///
/// This is useful for short scalar tails and is also an independent oracle
/// for the bit-parallel mask. It fails closed outside the same 32-byte
/// current-plus-lookahead proof domain.
#[cfg(test)]
pub(crate) fn scalar_start_qualifies(members: u64, start: u32, minimum: u32) -> bool {
    if start >= 32 || minimum == 0 || minimum > ROOT_CORRIDOR_MASK_MAXIMUM_MINIMUM {
        return false;
    }
    match start.checked_add(minimum) {
        Some(end) if end <= 64 => {}
        Some(_) | None => return false,
    }
    let width_mask = u64::MAX >> (64_u32.saturating_sub(minimum));
    let required = width_mask << start;
    members & required == required
}

/// Remove and return the earliest qualified current-block lane.
///
/// The remaining bits are a compact residual that can be retained across
/// iterator yields without reclassifying either source block.
pub(crate) fn take_first_qualified_start(residual: &mut u32) -> Option<u32> {
    if *residual == 0 {
        return None;
    }
    let first = residual.trailing_zeros();
    *residual &= residual.wrapping_sub(1);
    Some(first)
}

/// Count the member prefix at `start`, capped by `limit`, in one 64-bit window.
///
/// This is intended for the one candidate selected from a qualified mask, not
/// for walking every run in a block.
pub(crate) fn member_prefix_length(members: u64, start: u32, limit: u32) -> u32 {
    if start >= 64 || limit == 0 {
        return 0;
    }
    let available = 64_u32
        .checked_sub(start)
        .expect("a validated window start is below 64");
    (!members.wrapping_shr(start))
        .trailing_zeros()
        .min(available)
        .min(limit)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SplitChoice {
    member: u32,
    continuation: u32,
    greedy: bool,
}

fn state_role(automaton: &Automaton, state: u32, meter: &mut InspectionMeter) -> Option<StateRole> {
    meter.charge(1);
    automaton.roles.get(usize::try_from(state).ok()?).copied()
}

#[cold]
fn consume_transition(
    automaton: &Automaton,
    state: u32,
    meter: &mut InspectionMeter,
) -> Option<(AsciiByteSet, u32)> {
    if state_role(automaton, state, meter)? != StateRole::Consume {
        return None;
    }
    let mut edges = automaton.state_edges(state);
    let first = edges.next()?;
    meter.charge(1);
    let target = automaton.edge_targets[first];
    let mut words = [0_u64; 4];
    insert_byte_range(
        &mut words,
        automaton.byte_starts[first],
        automaton.byte_ends[first],
    );
    for edge in edges {
        meter.charge(1);
        if automaton.edge_targets[edge] != target {
            return None;
        }
        insert_byte_range(
            &mut words,
            automaton.byte_starts[edge],
            automaton.byte_ends[edge],
        );
    }
    let [low, high, upper_low, upper_high] = words;
    if upper_low != 0 || upper_high != 0 {
        return None;
    }
    let set = AsciiByteSet::from_words([low, high]);
    (set != AsciiByteSet::EMPTY).then_some((set, target))
}

#[cold]
fn split_choice(
    automaton: &Automaton,
    state: u32,
    meter: &mut InspectionMeter,
) -> Option<SplitChoice> {
    if state_role(automaton, state, meter)? != StateRole::Split {
        return None;
    }
    let range = automaton.state_edges(state);
    if range.len() != 2 {
        return None;
    }
    let mut edges = range;
    let first = edges.next()?;
    let second = edges.next()?;
    meter.charge(2);
    let first_target = automaton.edge_targets[first];
    let second_target = automaton.edge_targets[second];
    match (
        state_role(automaton, first_target, meter)?,
        state_role(automaton, second_target, meter)?,
    ) {
        (StateRole::Consume, StateRole::Split | StateRole::Accept) => Some(SplitChoice {
            member: first_target,
            continuation: second_target,
            greedy: true,
        }),
        (StateRole::Split | StateRole::Accept, StateRole::Consume) => Some(SplitChoice {
            member: second_target,
            continuation: first_target,
            greedy: false,
        }),
        _ => None,
    }
}

fn retain_equal_set(slot: &mut Option<AsciiByteSet>, set: AsciiByteSet) -> Option<()> {
    match *slot {
        Some(retained) if retained != set => None,
        Some(_) => Some(()),
        None => {
            *slot = Some(set);
            Some(())
        }
    }
}

fn retain_equal_priority(slot: &mut Option<bool>, greedy: bool) -> Option<()> {
    match *slot {
        Some(retained) if retained != greedy => None,
        Some(_) => Some(()),
        None => {
            *slot = Some(greedy);
            Some(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        inspect_root_run, inspect_root_run_accounted, member_prefix_length, qualifying_start_mask,
        root_corridor_member_window, root_run_inspection_work, scalar_start_qualifies,
        take_first_qualified_start, RootRunDescriptor,
    };
    use crate::{Automaton, CompileLimits, EdgeKind, RawPlan, StateRole};
    use fre_simd_kernels::AsciiByteSet;

    #[derive(Clone, Copy)]
    struct TestEdge {
        target: u32,
        kind: EdgeKind,
        start: u8,
        end: u8,
    }

    impl TestEdge {
        const fn byte(target: u32, start: u8, end: u8) -> Self {
            Self {
                target,
                kind: EdgeKind::ByteRange,
                start,
                end,
            }
        }

        const fn epsilon(target: u32) -> Self {
            Self {
                target,
                kind: EdgeKind::Epsilon,
                start: 0,
                end: 0,
            }
        }

        const fn assertion(target: u32) -> Self {
            Self {
                target,
                kind: EdgeKind::AssertHaystackStart,
                start: 0,
                end: 0,
            }
        }
    }

    fn automaton(start: u32, roles: Vec<StateRole>, edges: Vec<Vec<TestEdge>>) -> Automaton {
        assert_eq!(roles.len(), edges.len());
        let mut edge_offsets =
            Vec::with_capacity(roles.len().checked_add(1).expect("test offset slot"));
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        edge_offsets.push(0);
        for outgoing in edges {
            for edge in outgoing {
                edge_targets.push(edge.target);
                edge_kinds.push(edge.kind);
                byte_starts.push(edge.start);
                byte_ends.push(edge.end);
            }
            edge_offsets
                .push(u32::try_from(edge_targets.len()).expect("the small test graph fits u32"));
        }
        Automaton::from_raw(
            RawPlan {
                start,
                roles,
                edge_offsets,
                edge_targets,
                edge_kinds,
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .expect("valid test graph")
    }

    fn ascii_range(start: u8, end: u8) -> AsciiByteSet {
        let mut words = [0_u64; 2];
        for byte in start..=end {
            words[usize::from(byte >> 6)] |= 1_u64 << u32::from(byte & 63);
        }
        AsciiByteSet::from_words(words)
    }

    fn exact_three() -> Automaton {
        automaton(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![TestEdge::byte(1, b'a', b'z')],
                vec![TestEdge::byte(2, b'a', b'z')],
                vec![TestEdge::byte(3, b'a', b'z')],
                vec![],
            ],
        )
    }

    fn finite_two_four(greedy: bool) -> Automaton {
        let ordered = |member, continuation| {
            if greedy {
                vec![TestEdge::epsilon(member), TestEdge::epsilon(continuation)]
            } else {
                vec![TestEdge::epsilon(continuation), TestEdge::epsilon(member)]
            }
        };
        automaton(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![
                vec![TestEdge::byte(1, b'a', b'z')],
                vec![TestEdge::byte(4, b'a', b'z')],
                vec![TestEdge::byte(5, b'a', b'z')],
                vec![TestEdge::byte(6, b'a', b'z')],
                ordered(2, 5),
                ordered(3, 6),
                vec![],
            ],
        )
    }

    fn unbounded_two(greedy: bool) -> Automaton {
        let split = if greedy {
            vec![TestEdge::epsilon(1), TestEdge::epsilon(3)]
        } else {
            vec![TestEdge::epsilon(3), TestEdge::epsilon(1)]
        };
        automaton(
            0,
            vec![
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Accept,
            ],
            vec![
                vec![TestEdge::byte(1, b'a', b'z')],
                vec![TestEdge::byte(2, b'a', b'z')],
                split,
                vec![],
            ],
        )
    }

    #[test]
    fn strict_descriptor_accepts_exact_finite_and_unbounded_root_runs() {
        let set = ascii_range(b'a', b'z');
        let assert_accounted = |graph: &Automaton, expected: RootRunDescriptor| {
            let envelope = root_run_inspection_work(graph).expect("small graph has an envelope");
            let inspection = inspect_root_run_accounted(graph);
            assert!(inspection.work() <= envelope);
            assert_eq!(inspection.descriptor(), Some(expected));
            assert_eq!(inspect_root_run(graph), Some(expected));
        };
        assert_accounted(
            &exact_three(),
            RootRunDescriptor {
                set,
                minimum: 3,
                maximum: Some(3),
                greedy: true,
            },
        );
        for greedy in [false, true] {
            assert_accounted(
                &finite_two_four(greedy),
                RootRunDescriptor {
                    set,
                    minimum: 2,
                    maximum: Some(4),
                    greedy,
                },
            );
            assert_accounted(
                &unbounded_two(greedy),
                RootRunDescriptor {
                    set,
                    minimum: 2,
                    maximum: None,
                    greedy,
                },
            );
        }
    }

    #[test]
    fn descriptor_unions_multi_range_ascii_classes() {
        let graph = automaton(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![
                vec![
                    TestEdge::byte(1, b'0', b'9'),
                    TestEdge::byte(1, b'A', b'Z'),
                    TestEdge::byte(1, b'a', b'z'),
                ],
                vec![],
            ],
        );
        let descriptor = inspect_root_run(&graph).expect("one exact ASCII class is eligible");
        assert_eq!(descriptor.minimum(), 1);
        assert_eq!(descriptor.maximum(), Some(1));
        assert!(descriptor.greedy());
        for byte in 0_u8..=0x7f {
            assert_eq!(
                descriptor.set().contains(byte),
                byte.is_ascii_alphanumeric()
            );
        }
    }

    #[test]
    fn descriptor_fails_closed_for_nullable_asserted_and_non_ascii_graphs() {
        let star = automaton(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![
                vec![TestEdge::epsilon(1), TestEdge::epsilon(2)],
                vec![TestEdge::byte(0, b'a', b'a')],
                vec![],
            ],
        );
        assert_eq!(inspect_root_run(&star), None);

        let asserted = automaton(
            0,
            vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            vec![
                vec![TestEdge::assertion(1)],
                vec![TestEdge::byte(2, b'a', b'a')],
                vec![],
            ],
        );
        assert_eq!(inspect_root_run(&asserted), None);

        let high_byte = automaton(
            0,
            vec![StateRole::Consume, StateRole::Accept],
            vec![vec![TestEdge::byte(1, 0x7f, 0x80)], vec![]],
        );
        assert_eq!(inspect_root_run(&high_byte), None);
    }

    #[test]
    fn descriptor_fails_closed_for_unequal_classes_and_mixed_priority() {
        let unequal = automaton(
            0,
            vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
            vec![
                vec![TestEdge::byte(1, b'a', b'a')],
                vec![TestEdge::byte(2, b'b', b'b')],
                vec![],
            ],
        );
        assert_eq!(inspect_root_run(&unequal), None);

        let mixed = automaton(
            0,
            vec![
                StateRole::Consume,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Split,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![TestEdge::byte(1, b'a', b'a')],
                vec![TestEdge::epsilon(2), TestEdge::epsilon(3)],
                vec![TestEdge::byte(3, b'a', b'a')],
                vec![TestEdge::epsilon(5), TestEdge::epsilon(4)],
                vec![TestEdge::byte(5, b'a', b'a')],
                vec![],
            ],
        );
        assert_eq!(inspect_root_run(&mixed), None);
    }

    #[test]
    fn descriptor_requires_the_recognized_corridor_to_own_the_complete_graph() {
        let extra_accept = automaton(
            0,
            vec![StateRole::Consume, StateRole::Accept, StateRole::Accept],
            vec![vec![TestEdge::byte(1, b'a', b'a')], vec![], vec![]],
        );
        assert_eq!(inspect_root_run(&extra_accept), None);

        let alternative = automaton(
            0,
            vec![
                StateRole::Split,
                StateRole::Consume,
                StateRole::Consume,
                StateRole::Accept,
            ],
            vec![
                vec![TestEdge::epsilon(1), TestEdge::epsilon(2)],
                vec![TestEdge::byte(3, b'a', b'a')],
                vec![TestEdge::byte(3, b'a', b'a')],
                vec![],
            ],
        );
        assert_eq!(inspect_root_run(&alternative), None);
    }

    fn scalar_mask(members: u64, minimum: u32) -> u32 {
        let mut result = 0_u32;
        for start in 0_u32..32 {
            if scalar_start_qualifies(members, start, minimum) {
                result |= 1_u32 << start;
            }
        }
        result
    }

    #[test]
    fn bit_qualification_matches_scalar_for_every_sixteen_bit_mask() {
        for raw in 0_u32..=u32::from(u16::MAX) {
            let raw = u64::from(raw);
            let members = raw | (raw << 16) | (raw << 32) | (raw << 48);
            for minimum in 0_u32..=33 {
                assert_eq!(
                    qualifying_start_mask(members, minimum),
                    scalar_mask(members, minimum),
                    "members={members:#018x}, minimum={minimum}"
                );
            }
        }
    }

    #[test]
    fn qualification_covers_every_current_block_alignment_and_threshold_edge() {
        for start in 0_u32..32 {
            for minimum in 1_u32..=32 {
                for delta in [-1_i32, 0, 1] {
                    let signed_length = i32::try_from(minimum).expect("small minimum") + delta;
                    let length = u32::try_from(signed_length.max(0)).expect("nonnegative length");
                    let available = 64_u32.checked_sub(start).expect("start is in window");
                    let length = length.min(available);
                    let run = if length == 0 {
                        0
                    } else {
                        (u64::MAX >> (64_u32.saturating_sub(length))) << start
                    };
                    let mask = qualifying_start_mask(run, minimum);
                    assert_eq!(
                        mask & (1_u32 << start) != 0,
                        length >= minimum,
                        "start={start}, minimum={minimum}, length={length}"
                    );
                }
            }
        }
    }

    #[test]
    fn residual_selection_is_ordered_and_does_not_revisit_lanes() {
        let mut residual = 0b1011_0100_u32;
        let mut lanes = Vec::new();
        while let Some(lane) = take_first_qualified_start(&mut residual) {
            lanes.push(lane);
        }
        assert_eq!(lanes, [2, 4, 5, 7]);
        assert_eq!(residual, 0);
    }

    #[test]
    fn window_and_member_prefix_helpers_cross_the_block_boundary() {
        let members = root_corridor_member_window(0xf000_0000, 0x0000_001f);
        assert!(scalar_start_qualifies(members, 28, 9));
        assert_eq!(member_prefix_length(members, 28, u32::MAX), 9);
        assert_eq!(member_prefix_length(members, 28, 6), 6);
        assert_eq!(member_prefix_length(members, 27, u32::MAX), 0);
    }
}
