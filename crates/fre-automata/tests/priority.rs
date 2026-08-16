// Fixture sizes are statically tiny; direct arithmetic keeps the exhaustive
// oracle and exact one-below limit cases readable on the crate's Rust 1.74
// baseline.
#![allow(
    clippy::allow_attributes_without_reason,
    clippy::arithmetic_side_effects
)]

use fre_automata::{
    ActionCapabilities, Automaton, CompileLimits, DirectCount, DirectReduceLimits, DirectSpanSum,
    EdgeKind, EmptyMatchProgress, ExecutionActual, ForcedExecution, MatchLengthProof, PatternAction,
    PatternOrdinal, PreparationError, PreparationLimits, PreparationResource, PriorityAutomataFacts,
    PriorityExecutionKernel, PriorityStaticWorkspaceError, PriorityStaticWorkspaceLimits,
    PriorityTarget, RawPlan, ReduceError, StateRole, PRIORITY_ACCOUNTING_ID,
    PRIORITY_STATIC_WORKSPACE_ACCOUNTING_ID,
};

#[derive(Clone)]
struct State {
    role: StateRole,
    edges: Vec<Edge>,
    ordinal: Option<u32>,
}

#[derive(Clone, Copy)]
struct Edge {
    target: u32,
    kind: EdgeKind,
    start: u8,
    end: u8,
}

impl Edge {
    const fn epsilon(target: u32) -> Self {
        Self {
            target,
            kind: EdgeKind::Epsilon,
            start: 0,
            end: 0,
        }
    }

    const fn byte(target: u32, byte: u8) -> Self {
        Self {
            target,
            kind: EdgeKind::ByteRange,
            start: byte,
            end: byte,
        }
    }

    const fn assertion(target: u32, kind: EdgeKind) -> Self {
        Self {
            target,
            kind,
            start: 0,
            end: 0,
        }
    }
}

fn split(edges: Vec<Edge>) -> State {
    State {
        role: StateRole::Split,
        edges,
        ordinal: None,
    }
}

fn consume(edges: Vec<Edge>) -> State {
    State {
        role: StateRole::Consume,
        edges,
        ordinal: None,
    }
}

fn accept(ordinal: u32) -> State {
    State {
        role: StateRole::Accept,
        edges: Vec::new(),
        ordinal: Some(ordinal),
    }
}

fn fact_parts(states: Vec<State>) -> (Automaton, Vec<Option<PatternAction>>) {
    let mut edge_offsets = vec![0];
    let mut edge_targets = Vec::new();
    let mut edge_kinds = Vec::new();
    let mut byte_starts = Vec::new();
    let mut byte_ends = Vec::new();
    let mut roles = Vec::new();
    let mut actions = Vec::new();
    for state in states {
        roles.push(state.role);
        actions.push(state.ordinal.map(|ordinal| {
            PatternAction::new(PatternOrdinal::new(ordinal), ActionCapabilities::all())
        }));
        for edge in state.edges {
            edge_targets.push(edge.target);
            edge_kinds.push(edge.kind);
            byte_starts.push(edge.start);
            byte_ends.push(edge.end);
        }
        edge_offsets.push(u32::try_from(edge_targets.len()).expect("small test graph"));
    }
    let automaton = Automaton::from_raw(
        RawPlan {
            start: 0,
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        },
        CompileLimits::default(),
    )
    .expect("valid test graph");
    (automaton, actions)
}

fn facts(states: Vec<State>, proof: MatchLengthProof) -> PriorityAutomataFacts {
    let (automaton, actions) = fact_parts(states);
    PriorityAutomataFacts::new(automaton, actions, proof, EmptyMatchProgress::Byte)
}

fn literal(bytes: &[u8]) -> PriorityAutomataFacts {
    let mut states = Vec::new();
    for (index, &byte) in bytes.iter().enumerate() {
        states.push(consume(vec![Edge::byte(
            u32::try_from(index + 1).expect("small literal"),
            byte,
        )]));
    }
    states.push(accept(0));
    facts(states, MatchLengthProof::Exact(bytes.len()))
}

fn short_first() -> PriorityAutomataFacts {
    // a|ab
    facts(
        vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(3)]),
            consume(vec![Edge::byte(2, b'a')]),
            accept(0),
            consume(vec![Edge::byte(4, b'a')]),
            consume(vec![Edge::byte(5, b'b')]),
            accept(0),
        ],
        MatchLengthProof::Finite {
            minimum_bytes: 1,
            maximum_bytes: 2,
        },
    )
}

fn long_first() -> PriorityAutomataFacts {
    // ab|a
    facts(
        vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(4)]),
            consume(vec![Edge::byte(2, b'a')]),
            consume(vec![Edge::byte(3, b'b')]),
            accept(0),
            consume(vec![Edge::byte(5, b'a')]),
            accept(0),
        ],
        MatchLengthProof::Finite {
            minimum_bytes: 1,
            maximum_bytes: 2,
        },
    )
}

fn overlapping_candidate_fallback() -> PriorityAutomataFacts {
    // ab|a represented as overlapping ordered edges from one consuming state.
    // At `a` without a following `b`, the first static candidate is present
    // but has no dynamic reverse outcome, so the second candidate must win.
    facts(
        vec![
            consume(vec![Edge::byte(1, b'a'), Edge::byte(3, b'a')]),
            consume(vec![Edge::byte(2, b'b')]),
            accept(0),
            accept(1),
        ],
        MatchLengthProof::Finite {
            minimum_bytes: 1,
            maximum_bytes: 2,
        },
    )
}

fn unicode_word_a() -> PriorityAutomataFacts {
    facts(
        vec![
            split(vec![Edge::assertion(1, EdgeKind::AssertWordUnicode)]),
            consume(vec![Edge::byte(2, b'a')]),
            accept(0),
        ],
        MatchLengthProof::Exact(1),
    )
}

fn star(greedy: bool) -> PriorityAutomataFacts {
    let edges = if greedy {
        vec![Edge::epsilon(1), Edge::epsilon(2)]
    } else {
        vec![Edge::epsilon(2), Edge::epsilon(1)]
    };
    facts(
        vec![split(edges), consume(vec![Edge::byte(0, b'a')]), accept(0)],
        MatchLengthProof::Unbounded,
    )
}

fn zero_width_cycle() -> PriorityAutomataFacts {
    facts(
        vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(2)]),
            split(vec![Edge::epsilon(0)]),
            accept(0),
        ],
        MatchLengthProof::Exact(0),
    )
}

fn suffix_trap() -> PriorityAutomataFacts {
    // (?:a+b|a), with the unbounded branch at higher priority.
    facts(
        vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(5)]),
            consume(vec![Edge::byte(2, b'a')]),
            split(vec![Edge::epsilon(1), Edge::epsilon(3)]),
            consume(vec![Edge::byte(4, b'b')]),
            accept(0),
            consume(vec![Edge::byte(6, b'a')]),
            accept(0),
        ],
        MatchLengthProof::Unbounded,
    )
}

fn end_anchored_star() -> PriorityAutomataFacts {
    // a*\z, with the consuming loop preferred over the end assertion.
    facts(
        vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(2)]),
            consume(vec![Edge::byte(0, b'a')]),
            split(vec![Edge::assertion(3, EdgeKind::AssertHaystackEnd)]),
            accept(0),
        ],
        MatchLengthProof::Unbounded,
    )
}

fn words(max_len: usize) -> Vec<Vec<u8>> {
    let mut words = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in frontier {
            for byte in [b'a', b'b'] {
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

fn words_from_alphabet(max_len: usize, alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut words = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in frontier {
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

#[derive(Clone, Copy, Debug)]
enum GeneratedRepetition {
    One,
    OptionalGreedy,
    OptionalLazy,
    StarGreedy,
    StarLazy,
}

impl GeneratedRepetition {
    const fn range(self) -> (usize, Option<usize>) {
        match self {
            Self::One => (1, Some(1)),
            Self::OptionalGreedy | Self::OptionalLazy => (0, Some(1)),
            Self::StarGreedy | Self::StarLazy => (0, None),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct GeneratedArm {
    byte: u8,
    repetition: GeneratedRepetition,
    line_start: bool,
    line_end: bool,
}

fn generated_arms() -> Vec<GeneratedArm> {
    let mut arms = Vec::new();
    for byte in [b'a', b'b'] {
        for repetition in [
            GeneratedRepetition::One,
            GeneratedRepetition::OptionalGreedy,
            GeneratedRepetition::OptionalLazy,
            GeneratedRepetition::StarGreedy,
            GeneratedRepetition::StarLazy,
        ] {
            for (line_start, line_end) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                arms.push(GeneratedArm {
                    byte,
                    repetition,
                    line_start,
                    line_end,
                });
            }
        }
    }
    arms
}

fn push_state(states: &mut Vec<State>, state: State) -> u32 {
    let index = u32::try_from(states.len()).expect("bounded generated graph");
    states.push(state);
    index
}

fn generated_arm_graph(states: &mut Vec<State>, arm: GeneratedArm, ordinal: u32) -> u32 {
    let terminal = push_state(states, accept(ordinal));
    let suffix = if arm.line_end {
        push_state(
            states,
            split(vec![Edge::assertion(terminal, EdgeKind::AssertLineEndLf)]),
        )
    } else {
        terminal
    };
    let repetition = match arm.repetition {
        GeneratedRepetition::One => push_state(states, consume(vec![Edge::byte(suffix, arm.byte)])),
        GeneratedRepetition::OptionalGreedy | GeneratedRepetition::OptionalLazy => {
            let consuming = push_state(states, consume(vec![Edge::byte(suffix, arm.byte)]));
            let branches = if matches!(arm.repetition, GeneratedRepetition::OptionalGreedy) {
                vec![Edge::epsilon(consuming), Edge::epsilon(suffix)]
            } else {
                vec![Edge::epsilon(suffix), Edge::epsilon(consuming)]
            };
            push_state(states, split(branches))
        }
        GeneratedRepetition::StarGreedy | GeneratedRepetition::StarLazy => {
            let loop_split = push_state(states, split(Vec::new()));
            let consuming = push_state(states, consume(vec![Edge::byte(loop_split, arm.byte)]));
            states[usize::try_from(loop_split).unwrap()].edges =
                if matches!(arm.repetition, GeneratedRepetition::StarGreedy) {
                    vec![Edge::epsilon(consuming), Edge::epsilon(suffix)]
                } else {
                    vec![Edge::epsilon(suffix), Edge::epsilon(consuming)]
                };
            loop_split
        }
    };
    if arm.line_start {
        push_state(
            states,
            split(vec![Edge::assertion(
                repetition,
                EdgeKind::AssertLineStartLf,
            )]),
        )
    } else {
        repetition
    }
}

fn generated_facts(first: GeneratedArm, second: GeneratedArm) -> PriorityAutomataFacts {
    let mut states = vec![split(Vec::new())];
    let first_start = generated_arm_graph(&mut states, first, 0);
    let second_start = generated_arm_graph(&mut states, second, 1);
    states[0].edges = vec![Edge::epsilon(first_start), Edge::epsilon(second_start)];

    let first_range = first.repetition.range();
    let second_range = second.repetition.range();
    let minimum_bytes = first_range.0.min(second_range.0);
    let maximum_bytes = match (first_range.1, second_range.1) {
        (Some(first), Some(second)) => Some(first.max(second)),
        (None, _) | (_, None) => None,
    };
    let proof = match maximum_bytes {
        None => MatchLengthProof::Unbounded,
        Some(maximum_bytes) if minimum_bytes == maximum_bytes => {
            MatchLengthProof::Exact(minimum_bytes)
        }
        Some(maximum_bytes) => MatchLengthProof::Finite {
            minimum_bytes,
            maximum_bytes,
        },
    };
    facts(states, proof)
}

fn line_start_lf(haystack: &[u8], position: usize) -> bool {
    position == 0 || haystack.get(position.wrapping_sub(1)) == Some(&b'\n')
}

fn line_end_lf(haystack: &[u8], position: usize) -> bool {
    position == haystack.len() || haystack.get(position) == Some(&b'\n')
}

fn reference_arm_end(arm: GeneratedArm, haystack: &[u8], start: usize) -> Option<usize> {
    if arm.line_start && !line_start_lf(haystack, start) {
        return None;
    }
    let mut run_end = start;
    while haystack.get(run_end) == Some(&arm.byte) {
        run_end += 1;
    }
    let candidate_matches_suffix = |end| !arm.line_end || line_end_lf(haystack, end);
    match arm.repetition {
        GeneratedRepetition::One => {
            let end = start.checked_add(1)?;
            (run_end >= end && candidate_matches_suffix(end)).then_some(end)
        }
        GeneratedRepetition::OptionalGreedy => {
            if run_end > start && candidate_matches_suffix(start + 1) {
                Some(start + 1)
            } else {
                candidate_matches_suffix(start).then_some(start)
            }
        }
        GeneratedRepetition::OptionalLazy => {
            if candidate_matches_suffix(start) {
                Some(start)
            } else {
                (run_end > start && candidate_matches_suffix(start + 1)).then_some(start + 1)
            }
        }
        GeneratedRepetition::StarGreedy => (start..=run_end)
            .rev()
            .find(|&end| candidate_matches_suffix(end)),
        GeneratedRepetition::StarLazy => {
            (start..=run_end).find(|&end| candidate_matches_suffix(end))
        }
    }
}

fn reference_reduce(first: GeneratedArm, second: GeneratedArm, haystack: &[u8]) -> (u64, u64, u64) {
    let mut count = 0u64;
    let mut span_bytes = 0u64;
    let mut ordinal_sum = 0u64;
    let mut position = 0usize;
    while position <= haystack.len() {
        let selected = reference_arm_end(first, haystack, position)
            .map(|end| (0u64, end))
            .or_else(|| reference_arm_end(second, haystack, position).map(|end| (1u64, end)));
        let Some((ordinal, end)) = selected else {
            if position == haystack.len() {
                break;
            }
            position += 1;
            continue;
        };
        count += 1;
        span_bytes += u64::try_from(end - position).unwrap();
        ordinal_sum += ordinal;
        if end == position {
            if position == haystack.len() {
                break;
            }
            position += 1;
        } else {
            position = end;
        }
    }
    (count, span_bytes, ordinal_sum)
}

fn count(
    source: PriorityAutomataFacts,
    route: ForcedExecution,
    haystack: &[u8],
) -> (u64, fre_automata::ExecutionActual) {
    let plan = source
        .prepare_forced::<DirectCount>(
            route,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("prepared count");
    let report = plan
        .execute_forced(haystack, DirectReduceLimits::unlimited())
        .expect("forced count");
    (*report.output(), report.actual())
}

fn span_sum(source: PriorityAutomataFacts, route: ForcedExecution, haystack: &[u8]) -> u64 {
    *source
        .prepare_forced::<DirectSpanSum>(
            route,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("prepared span sum")
        .execute_forced(haystack, DirectReduceLimits::unlimited())
        .expect("forced span sum")
        .output()
}

fn one_below_usize(value: usize) -> usize {
    value.checked_sub(1).expect("positive exact limit")
}

fn one_below_u64(value: u64) -> u64 {
    value.checked_sub(1).expect("positive exact limit")
}

#[test]
fn all_forced_routes_produce_direct_count_and_span_sum() {
    let haystack = b"zababxabab";
    for route in [
        ForcedExecution::Sparse,
        ForcedExecution::FiniteHorizon,
        ForcedExecution::FullDfa,
        ForcedExecution::LazyDfa,
    ] {
        let (matches, actual) = count(literal(b"ab"), route, haystack);
        assert_eq!(matches, 4, "{route:?}");
        assert_eq!(actual.selected_span_bytes, 8, "{route:?}");
        assert_eq!(span_sum(literal(b"ab"), route, haystack), 8, "{route:?}");
    }
}

#[test]
fn priority_accounting_identity_binds_exact_peak_and_selected_span_schema() {
    assert_eq!(
        PRIORITY_ACCOUNTING_ID,
        "fre-automata.priority-preparation.v6"
    );
}

#[test]
fn exhaustive_short_literals_and_haystacks_match_a_span_sequence_oracle() {
    for pattern in words(3) {
        for haystack in words(5) {
            let spans = if pattern.is_empty() {
                (0..=haystack.len())
                    .map(|position| (position, position))
                    .collect::<Vec<_>>()
            } else {
                let mut spans = Vec::new();
                let mut position = 0usize;
                while position + pattern.len() <= haystack.len() {
                    if haystack[position..].starts_with(&pattern) {
                        spans.push((position, position + pattern.len()));
                        position += pattern.len();
                    } else {
                        position += 1;
                    }
                }
                spans
            };
            let expected_count = u64::try_from(spans.len()).unwrap();
            let expected_sum = spans.iter().fold(0u64, |sum, &(start, end)| {
                sum + u64::try_from(end - start).unwrap()
            });
            let routes: &[ForcedExecution] = if pattern.is_empty() {
                &[ForcedExecution::Sparse, ForcedExecution::FiniteHorizon]
            } else {
                &[
                    ForcedExecution::Sparse,
                    ForcedExecution::FiniteHorizon,
                    ForcedExecution::FullDfa,
                    ForcedExecution::LazyDfa,
                ]
            };
            for &route in routes {
                let (actual_count, actual) = count(literal(&pattern), route, &haystack);
                assert_eq!(
                    actual_count, expected_count,
                    "{route:?}/{pattern:?}/{haystack:?}/{spans:?}"
                );
                assert_eq!(
                    actual.selected_span_bytes, expected_sum,
                    "{route:?}/{pattern:?}/{haystack:?}/{spans:?}"
                );
                assert_eq!(
                    span_sum(literal(&pattern), route, &haystack),
                    expected_sum,
                    "{route:?}/{pattern:?}/{haystack:?}/{spans:?}"
                );
            }
        }
    }
}

#[test]
fn exhaustive_small_prioritized_graphs_match_independent_ordered_reference() {
    let arms = generated_arms();
    let haystacks = words_from_alphabet(3, b"ab\n");
    for &first in &arms {
        for &second in &arms {
            let source = generated_facts(first, second);
            let routes: &[ForcedExecution] =
                &[ForcedExecution::Sparse, ForcedExecution::FiniteHorizon];
            for &route in routes {
                let count_plan = source
                    .clone()
                    .prepare_forced::<DirectCount>(
                        route,
                        PriorityTarget::portable(),
                        PreparationLimits::unlimited(),
                    )
                    .expect("generated count plan");
                let span_plan = source
                    .clone()
                    .prepare_forced::<DirectSpanSum>(
                        route,
                        PriorityTarget::portable(),
                        PreparationLimits::unlimited(),
                    )
                    .expect("generated span plan");
                for haystack in &haystacks {
                    let expected = reference_reduce(first, second, haystack);
                    let count_report = count_plan
                        .execute_forced(haystack, DirectReduceLimits::unlimited())
                        .expect("generated count execution");
                    let span_report = span_plan
                        .execute_forced(haystack, DirectReduceLimits::unlimited())
                        .expect("generated span execution");
                    assert_eq!(
                        (
                            *count_report.output(),
                            count_report.actual().selected_span_bytes,
                            count_report.actual().selected_ordinal_sum,
                        ),
                        expected,
                        "{route:?}/{first:?}/{second:?}/{haystack:?}"
                    );
                    assert_eq!(
                        *span_report.output(),
                        expected.1,
                        "{route:?}/{first:?}/{second:?}/{haystack:?}"
                    );
                    assert_eq!(
                        span_report.actual().selected_span_bytes,
                        expected.1,
                        "{route:?}/{first:?}/{second:?}/{haystack:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn sparse_rows_preserve_priority_greediness_and_byte_empty_progress() {
    assert_eq!(count(short_first(), ForcedExecution::Sparse, b"abab").0, 2);
    assert_eq!(span_sum(short_first(), ForcedExecution::Sparse, b"abab"), 2);
    assert_eq!(count(long_first(), ForcedExecution::Sparse, b"abab").0, 2);
    assert_eq!(span_sum(long_first(), ForcedExecution::Sparse, b"abab"), 4);

    assert_eq!(count(star(true), ForcedExecution::Sparse, b"aa").0, 2);
    assert_eq!(span_sum(star(true), ForcedExecution::Sparse, b"aa"), 2);
    assert_eq!(count(star(false), ForcedExecution::Sparse, b"aa").0, 3);
    assert_eq!(span_sum(star(false), ForcedExecution::Sparse, b"aa"), 0);
}

#[test]
fn finite_horizon_matches_sparse_for_variable_width_priority() {
    for source in [short_first(), long_first()] {
        for haystack in [b"".as_slice(), b"a", b"ab", b"abab", b"zzab"] {
            assert_eq!(
                count(source.clone(), ForcedExecution::FiniteHorizon, haystack).0,
                count(source.clone(), ForcedExecution::Sparse, haystack).0
            );
            assert_eq!(
                span_sum(source.clone(), ForcedExecution::FiniteHorizon, haystack),
                span_sum(source.clone(), ForcedExecution::Sparse, haystack)
            );
        }
    }
}

#[test]
fn input_bounded_sparse_fallback_matches_sparse_for_unbounded_priority_and_assertions() {
    for (source, haystacks) in [
        (
            star(true),
            vec![b"".as_slice(), b"a", b"aa", b"baaa", b"aaab"],
        ),
        (
            star(false),
            vec![b"".as_slice(), b"a", b"aa", b"baaa", b"aaab"],
        ),
        (
            suffix_trap(),
            vec![b"".as_slice(), b"a", b"aa", b"aaa", b"aaab"],
        ),
        (
            end_anchored_star(),
            vec![b"".as_slice(), b"a", b"aa", b"baaa", b"aaab"],
        ),
    ] {
        let plan = source
            .clone()
            .prepare_forced::<DirectCount>(
                ForcedExecution::FiniteHorizon,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .expect("input-bounded finite route prepares");
        assert_eq!(plan.kernel(), PriorityExecutionKernel::InputBoundedReverse);
        for haystack in haystacks {
            let input_bounded = plan
                .execute_forced(haystack, DirectReduceLimits::unlimited())
                .expect("input-bounded count executes");
            let sparse = count(source.clone(), ForcedExecution::Sparse, haystack);
            assert_eq!(*input_bounded.output(), sparse.0, "{haystack:?}");
            assert_eq!(
                input_bounded.actual().selected_span_bytes,
                sparse.1.selected_span_bytes,
                "{haystack:?}"
            );
            assert_eq!(
                span_sum(source.clone(), ForcedExecution::FiniteHorizon, haystack),
                span_sum(source.clone(), ForcedExecution::Sparse, haystack),
                "{haystack:?}"
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn selected_kernel_requires_explicit_target_capability_and_dependencies() {
    let mut classic_full_without_sparse = PriorityTarget::portable();
    classic_full_without_sparse.sparse = false;
    let classic_full = literal(b"ab")
        .prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            classic_full_without_sparse,
            PreparationLimits::unlimited(),
        )
        .expect("classic FullDfa does not require the sparse fallback substrate");
    assert_eq!(classic_full.kernel(), PriorityExecutionKernel::FullDfa);

    let mut classic_lazy_without_sparse = PriorityTarget::portable();
    classic_lazy_without_sparse.sparse = false;
    let classic_lazy = literal(b"ab")
        .prepare_forced::<DirectCount>(
            ForcedExecution::LazyDfa,
            classic_lazy_without_sparse,
            PreparationLimits::unlimited(),
        )
        .expect("classic LazyDfa does not require the sparse fallback substrate");
    assert_eq!(classic_lazy.kernel(), PriorityExecutionKernel::LazyDfa);

    // The finite request bit alone cannot authenticate a route that executes
    // the sparse substrate beneath its input-length preflight.
    let mut missing_sparse_dependency = PriorityTarget::portable();
    missing_sparse_dependency.sparse = false;
    assert!(matches!(
        suffix_trap().prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            missing_sparse_dependency,
            PreparationLimits::unlimited(),
        ),
        Err(PreparationError::UnsupportedTargetKernel {
            execution: ForcedExecution::FiniteHorizon,
            kernel: PriorityExecutionKernel::InputBoundedReverse,
        })
    ));

    let mut missing_full_tagged_sparse = PriorityTarget::portable();
    missing_full_tagged_sparse.sparse = false;
    // A zero tagged-table cap would refuse a tagged build. The typed target
    // refusal must win before that route-specific resource gate is reached.
    let mut zero_tagged_table_limit = PreparationLimits::unlimited();
    zero_tagged_table_limit.max_tagged_dispatch_states = 0;
    assert!(matches!(
        short_first().prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            missing_full_tagged_sparse,
            zero_tagged_table_limit,
        ),
        Err(PreparationError::UnsupportedTargetKernel {
            execution: ForcedExecution::FullDfa,
            kernel: PriorityExecutionKernel::FullTaggedReverse,
        })
    ));

    let mut missing_lazy_tagged_sparse = PriorityTarget::portable();
    missing_lazy_tagged_sparse.sparse = false;
    assert!(matches!(
        short_first().prepare_forced::<DirectCount>(
            ForcedExecution::LazyDfa,
            missing_lazy_tagged_sparse,
            zero_tagged_table_limit,
        ),
        Err(PreparationError::UnsupportedTargetKernel {
            execution: ForcedExecution::LazyDfa,
            kernel: PriorityExecutionKernel::LazyTaggedReverse,
        })
    ));

    let portable = PriorityTarget::portable();
    for (facts, execution, kernel) in [
        (
            literal(b"ab"),
            ForcedExecution::Sparse,
            PriorityExecutionKernel::SparseReverse,
        ),
        (
            short_first(),
            ForcedExecution::FiniteHorizon,
            PriorityExecutionKernel::FiniteHorizonReverse,
        ),
        (
            suffix_trap(),
            ForcedExecution::FiniteHorizon,
            PriorityExecutionKernel::InputBoundedReverse,
        ),
        (
            literal(b"ab"),
            ForcedExecution::FullDfa,
            PriorityExecutionKernel::FullDfa,
        ),
        (
            literal(b"ab"),
            ForcedExecution::LazyDfa,
            PriorityExecutionKernel::LazyDfa,
        ),
        (
            short_first(),
            ForcedExecution::FullDfa,
            PriorityExecutionKernel::FullTaggedReverse,
        ),
        (
            short_first(),
            ForcedExecution::LazyDfa,
            PriorityExecutionKernel::LazyTaggedReverse,
        ),
    ] {
        let plan = facts
            .prepare_forced::<DirectCount>(execution, portable, PreparationLimits::unlimited())
            .expect("portable target must admit every concrete kernel");
        assert_eq!(plan.kernel(), kernel, "{execution:?}");
    }
}

#[test]
fn sparse_assertions_cycles_empty_language_and_ordinals_are_exact() {
    let line_a = facts(
        vec![
            split(vec![Edge::assertion(1, EdgeKind::AssertLineStartLf)]),
            consume(vec![Edge::byte(2, b'a')]),
            accept(0),
        ],
        MatchLengthProof::Exact(1),
    );
    assert_eq!(count(line_a, ForcedExecution::Sparse, b"za\na").0, 1);

    assert_eq!(
        count(zero_width_cycle(), ForcedExecution::Sparse, b"abc").0,
        4
    );

    let empty = facts(vec![consume(vec![]), accept(0)], MatchLengthProof::Empty);
    assert_eq!(count(empty.clone(), ForcedExecution::Sparse, b"abc").0, 0);
    assert_eq!(count(empty, ForcedExecution::FiniteHorizon, b"abc").0, 0);

    let second_terminal = facts(
        vec![
            split(vec![
                Edge::assertion(1, EdgeKind::AssertWordAscii),
                Edge::epsilon(2),
            ]),
            accept(0),
            accept(1),
        ],
        MatchLengthProof::Exact(0),
    );
    let (_, actual) = count(second_terminal, ForcedExecution::Sparse, b"");
    assert_eq!(actual.match_events, 1);
    assert_eq!(actual.selected_ordinal_sum, 1);

    let unicode_boundary = facts(
        vec![
            split(vec![Edge::assertion(1, EdgeKind::AssertWordUnicode)]),
            accept(0),
        ],
        MatchLengthProof::Exact(0),
    );
    assert_eq!(
        count(unicode_boundary, ForcedExecution::Sparse, &[0xFF, b'a']).0,
        2
    );
}

#[test]
fn suffix_restart_adversary_has_linear_n_2n_4n_charged_work() {
    let mut work = Vec::new();
    for length in [64, 128, 256] {
        let haystack = vec![b'a'; length];
        let (matches, actual) = count(suffix_trap(), ForcedExecution::Sparse, &haystack);
        assert_eq!(matches, u64::try_from(length).unwrap());
        work.push(actual.work);
        assert_eq!(
            actual.sparse_root_evaluations,
            (length + 1) * 7,
            "one reverse row per boundary/state"
        );
    }
    assert_eq!(work[2] - work[1], 2 * (work[1] - work[0]));
}

#[test]
#[allow(clippy::too_many_lines)]
fn input_bounded_is_sparse_equivalent_at_n_2n_4n() {
    // `suffix_trap` has an unbounded higher-priority arm, so a forced finite
    // request must publish the explicit input-bounded sparse-equivalent
    // kernel. Its horizon is the input length rather than a static ring.
    let input_count = suffix_trap()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("input-bounded count plan");
    let sparse_count = suffix_trap()
        .prepare_forced::<DirectCount>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("sparse count plan");
    let input_span = suffix_trap()
        .prepare_forced::<DirectSpanSum>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("input-bounded span plan");
    let sparse_span = suffix_trap()
        .prepare_forced::<DirectSpanSum>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("sparse span plan");

    assert_eq!(
        input_count.kernel(),
        PriorityExecutionKernel::InputBoundedReverse
    );
    assert_eq!(
        input_span.kernel(),
        PriorityExecutionKernel::InputBoundedReverse
    );
    assert!(input_count.kernel().is_sparse_equivalent_fallback());
    assert!(input_span.kernel().is_sparse_equivalent_fallback());
    assert!(!sparse_count.kernel().is_sparse_equivalent_fallback());
    assert!(!sparse_span.kernel().is_sparse_equivalent_fallback());

    let mut work = Vec::new();
    let mut scratch = Vec::new();
    let mut source = Vec::new();
    for length in [64, 128, 256] {
        let haystack = vec![b'a'; length];
        let input_prospective = input_count
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .expect("input-bounded prospective");
        let sparse_prospective = sparse_count
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .expect("sparse prospective");
        let input_span_prospective = input_span
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .expect("input-bounded SpanSum prospective");
        let sparse_span_prospective = sparse_span
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .expect("sparse SpanSum prospective");
        assert_eq!(
            input_prospective, sparse_prospective,
            "input-bounded Count P ledger is sparse-equivalent at {length} bytes"
        );
        assert_eq!(
            input_span_prospective, sparse_span_prospective,
            "input-bounded SpanSum P ledger is sparse-equivalent at {length} bytes"
        );
        assert_eq!(
            input_prospective, input_span_prospective,
            "input-bounded Count and SpanSum P ledgers agree at {length} bytes"
        );
        assert_eq!(
            sparse_prospective, sparse_span_prospective,
            "sparse Count and SpanSum P ledgers agree at {length} bytes"
        );

        let input_count_report = input_count
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("input-bounded count execution");
        let sparse_count_report = sparse_count
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("sparse count execution");
        let input_span_report = input_span
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("input-bounded span execution");
        let sparse_span_report = sparse_span
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("sparse span execution");

        assert_eq!(
            input_count_report.output(),
            sparse_count_report.output(),
            "Count semantic parity at {length} bytes"
        );
        assert_eq!(
            input_span_report.output(),
            sparse_span_report.output(),
            "SpanSum semantic parity at {length} bytes"
        );
        assert_eq!(
            input_count_report.actual(),
            sparse_count_report.actual(),
            "input-bounded execution remains sparse-equivalent at {length} bytes"
        );
        assert_eq!(
            input_span_report.actual(),
            sparse_span_report.actual(),
            "input-bounded SpanSum execution remains sparse-equivalent at {length} bytes"
        );
        assert_eq!(
            input_count_report.prospective(),
            input_prospective,
            "input-bounded Count report binds its preflight at {length} bytes"
        );
        assert_eq!(
            sparse_count_report.prospective(),
            sparse_prospective,
            "sparse Count report binds its preflight at {length} bytes"
        );
        assert_eq!(
            input_span_report.prospective(),
            input_span_prospective,
            "input-bounded SpanSum report binds its preflight at {length} bytes"
        );
        assert_eq!(
            sparse_span_report.prospective(),
            sparse_span_prospective,
            "sparse SpanSum report binds its preflight at {length} bytes"
        );
        assert_eq!(
            *input_count_report.output(),
            u64::try_from(length).expect("small scaling fixture"),
            "one selected `a` arm per input byte"
        );
        assert_eq!(
            *input_span_report.output(),
            u64::try_from(length).expect("small scaling fixture"),
            "selected span bytes at {length} bytes"
        );

        for (actual, prospective, route_and_operation) in [
            (
                input_count_report.actual(),
                input_prospective,
                "input-bounded Count",
            ),
            (
                sparse_count_report.actual(),
                sparse_prospective,
                "sparse Count",
            ),
            (
                input_span_report.actual(),
                input_span_prospective,
                "input-bounded SpanSum",
            ),
            (
                sparse_span_report.actual(),
                sparse_span_prospective,
                "sparse SpanSum",
            ),
        ] {
            assert_eq!(
                actual.source_bytes, length,
                "{route_and_operation} source accounting at {length} bytes"
            );
            assert_eq!(
                actual.scratch_bytes, prospective.scratch_bytes,
                "{route_and_operation} scratch binds P at {length} bytes"
            );
            assert_eq!(
                actual.boundary_rows, prospective.boundary_rows,
                "{route_and_operation} boundary rows bind P at {length} bytes"
            );
            assert_eq!(
                actual.sparse_root_evaluations,
                prospective.boundary_rows * 7,
                "{route_and_operation} sparse root rows at {length} bytes"
            );
            assert_eq!(
                actual.suffix_reducer_steps, prospective.boundary_rows,
                "{route_and_operation} reducer rows at {length} bytes"
            );
            assert!(
                actual.work <= prospective.work_upper_bound,
                "{route_and_operation} work stays within P at {length} bytes"
            );
            assert!(
                actual.match_events <= prospective.match_events_upper_bound,
                "{route_and_operation} match events stay within P at {length} bytes"
            );
            assert_eq!(
                actual.allocation_attempts, prospective.allocation_attempts,
                "{route_and_operation} allocations bind P at {length} bytes"
            );
        }

        let actual = input_count_report.actual();
        work.push(actual.work);
        scratch.push(actual.scratch_bytes);
        source.push(actual.source_bytes);
    }

    assert_eq!(source, vec![64, 128, 256]);
    assert_eq!(work[2] - work[1], 2 * (work[1] - work[0]));
    assert_eq!(scratch[2] - scratch[1], 2 * (scratch[1] - scratch[0]));
}

#[test]
fn finite_retention_plateaus_while_input_bounded_grows() {
    // `short_first` has a two-byte static match-width bound, so its finite
    // route retains exactly four rows once N exceeds that ring width. The
    // unbounded suffix trap instead retains every source boundary.
    let finite = short_first()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("finite-retention plan");
    let input_bounded = suffix_trap()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("input-bounded plan");

    assert_eq!(
        finite.kernel(),
        PriorityExecutionKernel::FiniteHorizonReverse
    );
    assert_eq!(finite.static_reducer_retention_bytes(), Some(2));
    assert!(!finite.kernel().is_sparse_equivalent_fallback());
    assert_eq!(
        input_bounded.kernel(),
        PriorityExecutionKernel::InputBoundedReverse
    );
    assert_eq!(input_bounded.static_reducer_retention_bytes(), None);
    assert!(input_bounded.kernel().is_sparse_equivalent_fallback());

    let mut finite_work = Vec::new();
    let mut finite_scratch = Vec::new();
    let mut input_work = Vec::new();
    let mut input_scratch = Vec::new();
    for length in [64, 128, 256] {
        let haystack = vec![b'a'; length];
        let finite_prospective = finite
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .expect("finite-retention prospective");
        let input_prospective = input_bounded
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .expect("input-bounded prospective");
        let finite_report = finite
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("finite-retention execution");
        let input_report = input_bounded
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("input-bounded execution");

        let finite_actual = finite_report.actual();
        assert_eq!(
            *finite_report.output(),
            u64::try_from(length).expect("small scaling fixture"),
            "finite semantic result at {length} bytes"
        );
        assert_eq!(finite_actual.source_bytes, length);
        assert_eq!(finite_actual.boundary_rows, length + 1);
        assert_eq!(finite_actual.suffix_reducer_steps, length + 1);
        assert_eq!(finite_actual.sparse_root_evaluations, (length + 1) * 6);
        assert_eq!(
            finite_actual.scratch_bytes,
            finite_prospective.scratch_bytes
        );
        finite_work.push(finite_actual.work);
        finite_scratch.push(finite_actual.scratch_bytes);

        let input_actual = input_report.actual();
        assert_eq!(
            *input_report.output(),
            u64::try_from(length).expect("small scaling fixture"),
            "input-bounded semantic result at {length} bytes"
        );
        assert_eq!(input_actual.source_bytes, length);
        assert_eq!(input_actual.boundary_rows, length + 1);
        assert_eq!(input_actual.suffix_reducer_steps, length + 1);
        assert_eq!(input_actual.sparse_root_evaluations, (length + 1) * 7);
        assert_eq!(input_actual.scratch_bytes, input_prospective.scratch_bytes);
        input_work.push(input_actual.work);
        input_scratch.push(input_actual.scratch_bytes);
    }

    assert_eq!(finite_scratch[0], finite_scratch[1]);
    assert_eq!(finite_scratch[1], finite_scratch[2]);
    assert!(finite_scratch[0] < input_scratch[0]);
    assert_eq!(
        finite_work[2] - finite_work[1],
        2 * (finite_work[1] - finite_work[0])
    );
    assert_eq!(
        input_work[2] - input_work[1],
        2 * (input_work[1] - input_work[0])
    );
    assert_eq!(
        input_scratch[2] - input_scratch[1],
        2 * (input_scratch[1] - input_scratch[0])
    );
}

#[test]
fn full_tagged_reverse_scales_at_n_2n_4n() {
    assert_tagged_reverse_scales_at_n_2n_4n(
        ForcedExecution::FullDfa,
        PriorityExecutionKernel::FullTaggedReverse,
    );
}

#[test]
fn lazy_tagged_reverse_scales_at_n_2n_4n() {
    assert_tagged_reverse_scales_at_n_2n_4n(
        ForcedExecution::LazyDfa,
        PriorityExecutionKernel::LazyTaggedReverse,
    );
}

#[allow(clippy::too_many_lines)]
fn assert_tagged_reverse_scales_at_n_2n_4n(
    route: ForcedExecution,
    expected_kernel: PriorityExecutionKernel,
) {
    // The variable-width priority graph selects a tagged reverse kernel
    // instead of the classic fixed-width DFA path.
    let tagged_count = suffix_trap()
        .prepare_forced::<DirectCount>(
            route,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("tagged count plan");
    let tagged_span = suffix_trap()
        .prepare_forced::<DirectSpanSum>(
            route,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("tagged span plan");
    let sparse_count = suffix_trap()
        .prepare_forced::<DirectCount>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("sparse count plan");
    let sparse_span = suffix_trap()
        .prepare_forced::<DirectSpanSum>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("sparse span plan");

    assert_eq!(tagged_count.kernel(), expected_kernel, "{route:?}");
    assert_eq!(tagged_count.kernel(), tagged_span.kernel(), "{route:?}");

    let mut work = Vec::new();
    let mut scratch = Vec::new();
    let mut source = Vec::new();
    for length in [64, 128, 256] {
        let haystack = vec![b'a'; length];
        let prospective = tagged_count
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .expect("tagged prospective");
        let tagged_count_report = tagged_count
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("tagged count execution");
        let sparse_count_report = sparse_count
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("sparse count execution");
        let tagged_span_report = tagged_span
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("tagged span execution");
        let sparse_span_report = sparse_span
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .expect("sparse span execution");

        assert_eq!(
            tagged_count_report.output(),
            sparse_count_report.output(),
            "Count semantic parity for {route:?}/{length}"
        );
        assert_eq!(
            tagged_span_report.output(),
            sparse_span_report.output(),
            "SpanSum semantic parity for {route:?}/{length}"
        );
        assert_eq!(
            tagged_count_report.actual().selected_span_bytes,
            sparse_count_report.actual().selected_span_bytes,
            "selected spans for {route:?}/{length}"
        );
        assert_eq!(
            tagged_count_report.actual().selected_ordinal_sum,
            sparse_count_report.actual().selected_ordinal_sum,
            "selected ordinals for {route:?}/{length}"
        );
        assert_eq!(
            *tagged_count_report.output(),
            u64::try_from(length).expect("small scaling fixture"),
            "one selected `a` arm per input byte for {route:?}"
        );
        assert_eq!(
            *tagged_span_report.output(),
            u64::try_from(length).expect("small scaling fixture"),
            "selected span bytes for {route:?}/{length}"
        );

        let actual = tagged_count_report.actual();
        assert_eq!(actual.source_bytes, length, "{route:?}/{length}");
        assert_eq!(actual.scratch_bytes, prospective.scratch_bytes, "{route:?}");
        assert_eq!(actual.boundary_rows, length + 1, "{route:?}");
        assert_eq!(actual.sparse_root_evaluations, 0, "{route:?}");
        assert_eq!(actual.sparse_closure_visits, 0, "{route:?}");
        assert_eq!(actual.sparse_edge_visits, 0, "{route:?}");
        assert!(actual.tagged_state_evaluations > 0, "{route:?}");
        assert!(actual.tagged_edge_visits > 0, "{route:?}");
        work.push(actual.work);
        scratch.push(actual.scratch_bytes);
        source.push(actual.source_bytes);
    }

    assert_eq!(source, vec![64, 128, 256], "{route:?}");
    assert_eq!(
        work[2] - work[1],
        2 * (work[1] - work[0]),
        "{route:?} work is affine in N"
    );
    assert_eq!(
        scratch[2] - scratch[1],
        2 * (scratch[1] - scratch[0]),
        "{route:?} scratch is affine in N"
    );
}

#[test]
fn forged_length_proofs_are_refused_before_route_publication() {
    // Rebuild the identical graph with too-small, too-large, and unbounded
    // caller assertions. Intrinsic graph analysis rejects all three.
    for proof in [
        MatchLengthProof::Exact(1),
        MatchLengthProof::Exact(3),
        MatchLengthProof::Unbounded,
    ] {
        let states = vec![
            consume(vec![Edge::byte(1, b'a')]),
            consume(vec![Edge::byte(2, b'b')]),
            accept(0),
        ];
        let forged = facts(states, proof);
        assert!(matches!(
            forged.clone().prepare_forced::<DirectCount>(
                ForcedExecution::Sparse,
                PriorityTarget::portable(),
                PreparationLimits::unlimited()
            ),
            Err(PreparationError::MatchLengthProofMismatch { .. })
        ));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn full_and_lazy_tagged_reverse_routes_preserve_variable_width_and_assertions() {
    let nullable = facts(vec![accept(0)], MatchLengthProof::Exact(0));
    for route in [ForcedExecution::FullDfa, ForcedExecution::LazyDfa] {
        let nullable_plan = nullable
            .clone()
            .prepare_forced::<DirectCount>(
                route,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .expect("nullable nonempty language selects a tagged plan");
        assert_eq!(
            nullable_plan.kernel(),
            match route {
                ForcedExecution::FullDfa => PriorityExecutionKernel::FullTaggedReverse,
                ForcedExecution::LazyDfa => PriorityExecutionKernel::LazyTaggedReverse,
                _ => unreachable!("tagged fixture only forces Full/Lazy"),
            }
        );
        for haystack in [b"".as_slice(), b"a".as_slice()] {
            let expected_count = count(nullable.clone(), ForcedExecution::Sparse, haystack).0;
            let expected_span = span_sum(nullable.clone(), ForcedExecution::Sparse, haystack);
            let actual = nullable_plan
                .execute_forced(haystack, DirectReduceLimits::unlimited())
                .expect("nullable tagged execution");
            assert_eq!(*actual.output(), expected_count, "{route:?}/{haystack:?}");
            assert_eq!(
                span_sum(nullable.clone(), route, haystack),
                expected_span,
                "{route:?}/{haystack:?}"
            );
        }

        for (source, haystack) in [
            (short_first(), b"abab".as_slice()),
            (long_first(), b"abab".as_slice()),
            (overlapping_candidate_fallback(), b"aaba".as_slice()),
            (unicode_word_a(), &[0xFF, b'a', b' ', b'a'][..]),
            (star(true), b"aa".as_slice()),
            (star(false), b"aa".as_slice()),
        ] {
            let expected_count = count(source.clone(), ForcedExecution::Sparse, haystack).0;
            let expected_span = span_sum(source.clone(), ForcedExecution::Sparse, haystack);
            let plan = source
                .clone()
                .prepare_forced::<DirectCount>(
                    route,
                    PriorityTarget::portable(),
                    PreparationLimits::unlimited(),
                )
                .expect("tagged plan");
            assert_eq!(
                plan.kernel(),
                match route {
                    ForcedExecution::FullDfa => PriorityExecutionKernel::FullTaggedReverse,
                    ForcedExecution::LazyDfa => PriorityExecutionKernel::LazyTaggedReverse,
                    _ => unreachable!("tagged fixture only forces Full/Lazy"),
                },
                "{route:?}/{haystack:?}"
            );
            let preparation = plan.preparation_accounting();
            assert_eq!(preparation.dfa_states, 0, "{route:?}");
            assert_eq!(preparation.transition_cells, 0, "{route:?}");
            assert_eq!(preparation.subset_items, 0, "{route:?}");
            assert!(preparation.tagged_dispatch_states > 0, "{route:?}");
            assert!(preparation.tagged_dispatch_cells > 0, "{route:?}");
            assert!(preparation.tagged_candidate_items > 0, "{route:?}");
            let prospective = plan
                .prospective(haystack.len(), DirectReduceLimits::unlimited())
                .expect("tagged prospective");
            let report = plan
                .execute_forced(haystack, DirectReduceLimits::unlimited())
                .expect("tagged execution");
            let actual = report.actual();
            assert_eq!(
                *report.output(),
                expected_count,
                "Count {route:?}/{haystack:?}"
            );
            assert_eq!(
                span_sum(source.clone(), route, haystack),
                expected_span,
                "SpanSum {route:?}/{haystack:?}"
            );
            assert_eq!(
                actual.tagged_dispatch_states, prospective.tagged_dispatch_states_capacity,
                "{route:?}"
            );
            assert_eq!(
                actual.tagged_dispatch_cells, prospective.tagged_dispatch_cells_capacity,
                "{route:?}"
            );
            assert_eq!(
                actual.tagged_candidate_items, prospective.tagged_candidate_items_capacity,
                "{route:?}"
            );
            assert_eq!(actual.sparse_root_evaluations, 0, "{route:?}");
            assert_eq!(actual.sparse_closure_visits, 0, "{route:?}");
            assert_eq!(actual.sparse_edge_visits, 0, "{route:?}");
            assert!(actual.tagged_state_evaluations > 0, "{route:?}");
            assert!(actual.tagged_edge_visits > 0, "{route:?}");
            match route {
                ForcedExecution::FullDfa => {
                    assert_eq!(prospective.tagged_cache_cells_capacity, 0);
                    assert_eq!(actual.tagged_cache_cells, 0);
                    assert_eq!(actual.tagged_cache_hits, 0);
                    assert_eq!(actual.tagged_cache_misses, 0);
                    assert_eq!(actual.tagged_cache_inserts, 0);
                    assert_eq!(actual.tagged_cache_evictions, 0);
                }
                ForcedExecution::LazyDfa => {
                    assert!(prospective.tagged_cache_cells_capacity > 0);
                    assert_eq!(
                        actual.tagged_cache_cells,
                        prospective.tagged_cache_cells_capacity
                    );
                    assert_eq!(actual.tagged_cache_misses, actual.tagged_cache_inserts);
                    assert!(actual.tagged_cache_evictions <= actual.tagged_cache_inserts);
                }
                _ => unreachable!("tagged fixture only forces Full/Lazy"),
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn tagged_reverse_runtime_limits_are_exact_and_one_below_before_source() {
    let haystack = b"abab";
    for route in [ForcedExecution::FullDfa, ForcedExecution::LazyDfa] {
        let plan = short_first()
            .prepare_forced::<DirectCount>(
                route,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .expect("tagged reverse plan");
        let prospective = plan
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .expect("tagged reverse prospective");
        assert_eq!(prospective.dfa_states_capacity, 0, "{route:?}");
        assert_eq!(prospective.dfa_cells_capacity, 0, "{route:?}");
        assert_eq!(prospective.subset_items_capacity, 0, "{route:?}");
        assert!(prospective.tagged_dispatch_states_capacity > 0, "{route:?}");
        assert!(prospective.tagged_dispatch_cells_capacity > 0, "{route:?}");
        assert!(prospective.tagged_candidate_items_capacity > 0, "{route:?}");
        assert_eq!(
            prospective.tagged_cache_cells_capacity,
            usize::from(route == ForcedExecution::LazyDfa) * haystack.len(),
            "{route:?}"
        );
        let exact = DirectReduceLimits {
            max_work: prospective.work_upper_bound,
            max_scratch_bytes: prospective.scratch_bytes,
            max_boundary_rows: prospective.boundary_rows,
            max_match_events: prospective.match_events_upper_bound,
            max_dfa_states: 0,
            max_dfa_cells: 0,
            max_subset_items: 0,
            max_tagged_dispatch_states: prospective.tagged_dispatch_states_capacity,
            max_tagged_dispatch_cells: prospective.tagged_dispatch_cells_capacity,
            max_tagged_candidate_items: prospective.tagged_candidate_items_capacity,
            max_tagged_cache_cells: prospective.tagged_cache_cells_capacity,
            max_allocation_attempts: prospective.allocation_attempts,
        };
        let report = plan
            .execute_forced(haystack, exact)
            .expect("exact tagged reverse limits");
        assert_eq!(*report.output(), 2, "{route:?}");
        assert_eq!(
            report.actual().suffix_reducer_steps,
            prospective.boundary_rows,
            "{route:?}"
        );
        let mut one_below = vec![
            DirectReduceLimits {
                max_work: one_below_u64(exact.max_work),
                ..exact
            },
            DirectReduceLimits {
                max_scratch_bytes: one_below_usize(exact.max_scratch_bytes),
                ..exact
            },
            DirectReduceLimits {
                max_boundary_rows: one_below_usize(exact.max_boundary_rows),
                ..exact
            },
            DirectReduceLimits {
                max_match_events: one_below_usize(exact.max_match_events),
                ..exact
            },
            DirectReduceLimits {
                max_allocation_attempts: one_below_usize(exact.max_allocation_attempts),
                ..exact
            },
            DirectReduceLimits {
                max_tagged_dispatch_states: one_below_usize(exact.max_tagged_dispatch_states),
                ..exact
            },
            DirectReduceLimits {
                max_tagged_dispatch_cells: one_below_usize(exact.max_tagged_dispatch_cells),
                ..exact
            },
            DirectReduceLimits {
                max_tagged_candidate_items: one_below_usize(exact.max_tagged_candidate_items),
                ..exact
            },
        ];
        if route == ForcedExecution::LazyDfa {
            let one_byte = plan
                .prospective(1, DirectReduceLimits::unlimited())
                .expect("one-byte lazy tagged prospective");
            assert_eq!(one_byte.tagged_cache_cells_capacity, 1);
            assert!(matches!(
                plan.execute_forced(
                    b"a",
                    DirectReduceLimits {
                        max_tagged_cache_cells: 0,
                        ..DirectReduceLimits::unlimited()
                    }
                ),
                Err(ReduceError::TaggedCacheCellsLimit { .. })
            ));
        }
        for limits in one_below.drain(..) {
            assert!(
                plan.execute_forced(haystack, limits).is_err(),
                "{route:?}/{limits:?}"
            );
        }
    }
}

#[test]
fn tagged_reverse_preparation_limits_are_exact_and_one_below() {
    for route in [ForcedExecution::FullDfa, ForcedExecution::LazyDfa] {
        let probe = short_first()
            .prepare_forced::<DirectCount>(
                route,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .expect("tagged reverse preparation");
        let accounting = probe.preparation_accounting();
        let exact = PreparationLimits {
            max_pattern_terminals: accounting.pattern_terminals,
            max_dfa_states: accounting.dfa_states,
            max_transition_cells: accounting.transition_cells,
            max_subset_items: accounting.subset_items,
            max_tagged_dispatch_states: accounting.tagged_dispatch_states,
            max_tagged_dispatch_cells: accounting.tagged_dispatch_cells,
            max_tagged_candidate_items: accounting.tagged_candidate_items,
            max_work: accounting.work,
            max_persistent_bytes: accounting.persistent_bytes,
            max_peak_bytes: accounting.peak_bytes,
            max_allocation_attempts: accounting.allocation_attempts,
        };
        assert_eq!(accounting.dfa_states, 0, "{route:?}");
        assert_eq!(accounting.transition_cells, 0, "{route:?}");
        assert_eq!(accounting.subset_items, 0, "{route:?}");
        assert!(accounting.tagged_dispatch_states > 0, "{route:?}");
        assert!(accounting.tagged_dispatch_cells > 0, "{route:?}");
        assert!(accounting.tagged_candidate_items > 0, "{route:?}");
        short_first()
            .prepare_forced::<DirectCount>(route, PriorityTarget::portable(), exact)
            .expect("exact tagged reverse preparation limits");
        for limits in [
            PreparationLimits {
                max_work: one_below_u64(exact.max_work),
                ..exact
            },
            PreparationLimits {
                max_persistent_bytes: one_below_usize(exact.max_persistent_bytes),
                ..exact
            },
            PreparationLimits {
                max_peak_bytes: one_below_usize(exact.max_peak_bytes),
                ..exact
            },
            PreparationLimits {
                max_allocation_attempts: one_below_usize(exact.max_allocation_attempts),
                ..exact
            },
            PreparationLimits {
                max_tagged_dispatch_states: one_below_usize(exact.max_tagged_dispatch_states),
                ..exact
            },
            PreparationLimits {
                max_tagged_dispatch_cells: one_below_usize(exact.max_tagged_dispatch_cells),
                ..exact
            },
            PreparationLimits {
                max_tagged_candidate_items: one_below_usize(exact.max_tagged_candidate_items),
                ..exact
            },
        ] {
            assert!(
                short_first()
                    .prepare_forced::<DirectCount>(route, PriorityTarget::portable(), limits)
                    .is_err(),
                "{route:?}/{limits:?}"
            );
        }
    }
}

#[test]
fn lazy_tagged_cache_caches_only_static_candidate_starts_and_evicts_safely() {
    let source = overlapping_candidate_fallback();
    let haystack = b"aaba";
    let expected = count(source.clone(), ForcedExecution::Sparse, haystack).0;
    let plan = source
        .clone()
        .prepare_forced::<DirectCount>(
            ForcedExecution::LazyDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("lazy tagged plan");
    let cached = plan
        .execute_forced(haystack, DirectReduceLimits::unlimited())
        .expect("lazy tagged cached execution");
    assert_eq!(*cached.output(), expected);
    assert!(cached.actual().tagged_cache_hits > 0);
    assert_eq!(
        cached.actual().tagged_cache_misses,
        cached.actual().tagged_cache_inserts
    );

    let one_below = plan
        .execute_forced(
            haystack,
            DirectReduceLimits {
                max_tagged_cache_cells: haystack.len() - 1,
                ..DirectReduceLimits::unlimited()
            },
        )
        .expect("one-below positive lazy tagged cache execution");
    assert_eq!(*one_below.output(), expected);
    assert_eq!(one_below.actual().tagged_cache_cells, haystack.len() - 1);

    let evicted = plan
        .execute_forced(
            haystack,
            DirectReduceLimits {
                max_tagged_cache_cells: 1,
                ..DirectReduceLimits::unlimited()
            },
        )
        .expect("one-cell lazy tagged execution");
    assert_eq!(*evicted.output(), expected);
    assert_eq!(evicted.actual().tagged_cache_cells, 1);
    assert!(evicted.actual().tagged_cache_evictions > 0);
    assert_eq!(
        evicted.actual().tagged_cache_misses,
        evicted.actual().tagged_cache_inserts
    );
}

#[test]
fn swapped_pattern_ordinals_are_not_a_canonical_priority_sidecar() {
    let swapped = facts(
        vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(3)]),
            consume(vec![Edge::byte(2, b'a')]),
            accept(1),
            consume(vec![Edge::byte(4, b'a')]),
            accept(0),
        ],
        MatchLengthProof::Exact(1),
    );
    assert!(matches!(
        swapped.prepare_forced::<DirectCount>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited()
        ),
        Err(PreparationError::NonCanonicalPatternOrder { .. })
    ));
}

#[test]
fn unicode_scalar_progress_is_an_explicit_pre_source_refusal() {
    let mut edge_offsets = vec![0];
    edge_offsets.push(0);
    let automaton = Automaton::from_raw(
        RawPlan {
            start: 0,
            roles: vec![StateRole::Accept],
            edge_offsets,
            edge_targets: vec![],
            edge_kinds: vec![],
            byte_starts: vec![],
            byte_ends: vec![],
        },
        CompileLimits::default(),
    )
    .unwrap();
    let source = PriorityAutomataFacts::new(
        automaton,
        vec![Some(PatternAction::new(
            PatternOrdinal::new(0),
            ActionCapabilities::all(),
        ))],
        MatchLengthProof::Exact(0),
        EmptyMatchProgress::UnicodeScalar,
    );
    assert!(matches!(
        source.prepare_forced::<DirectCount>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited()
        ),
        Err(PreparationError::UnsupportedUnicodeEmptyProgress)
    ));
}

#[test]
fn intrinsically_empty_preparation_peak_tracks_only_simultaneously_live_vectors() {
    let state_count = 2usize;
    let empty = facts(
        vec![consume(Vec::new()), accept(0)],
        MatchLengthProof::Empty,
    );
    let probe = empty
        .clone()
        .prepare_forced::<DirectCount>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let accounting = probe.preparation_accounting();
    let empty_match_length_scratch =
        state_count * (core::mem::size_of::<usize>() + core::mem::size_of::<u32>());
    let pattern_order_scratch = state_count * 2 * core::mem::size_of::<Option<PatternOrdinal>>();
    let evaluation_order_bytes = state_count * core::mem::size_of::<u32>();
    let evaluation_build_scratch =
        state_count * (core::mem::size_of::<usize>() + 2 * core::mem::size_of::<u32>());
    let base_persistent = accounting.persistent_bytes - evaluation_order_bytes;
    assert_eq!(
        accounting.peak_bytes,
        base_persistent
            + empty_match_length_scratch
                .max(pattern_order_scratch)
                .max(evaluation_build_scratch)
    );
    assert_eq!(accounting.allocation_attempts, 8);
    assert_eq!(accounting.prospective.peak_bytes, accounting.peak_bytes);
    assert_eq!(
        accounting.prospective.allocation_attempts,
        accounting.allocation_attempts
    );

    let exact = PreparationLimits {
        max_pattern_terminals: accounting.pattern_terminals,
        max_dfa_states: accounting.dfa_states,
        max_transition_cells: accounting.transition_cells,
        max_subset_items: accounting.subset_items,
        max_tagged_dispatch_states: accounting.tagged_dispatch_states,
        max_tagged_dispatch_cells: accounting.tagged_dispatch_cells,
        max_tagged_candidate_items: accounting.tagged_candidate_items,
        max_work: accounting.work,
        max_persistent_bytes: accounting.persistent_bytes,
        max_peak_bytes: accounting.peak_bytes,
        max_allocation_attempts: accounting.allocation_attempts,
    };
    empty
        .clone()
        .prepare_forced::<DirectCount>(ForcedExecution::Sparse, PriorityTarget::portable(), exact)
        .unwrap();
    match empty.prepare_forced::<DirectCount>(
        ForcedExecution::Sparse,
        PriorityTarget::portable(),
        PreparationLimits {
            max_peak_bytes: exact.max_peak_bytes - 1,
            ..exact
        },
    ) {
        Err(PreparationError::ResourceLimit {
            resource,
            needed,
            limit,
        }) => {
            assert_eq!(resource, PreparationResource::PeakBytes);
            assert_eq!(needed, exact.max_peak_bytes);
            assert_eq!(limit, exact.max_peak_bytes - 1);
        }
        other => panic!("unexpected one-below result: {other:?}"),
    }

    // A reachable accept adds the maximum forward DP after Kahn has published
    // its order. The previous minimum DP is dropped first, so this is the
    // exact largest simultaneously-live acyclic analysis footprint.
    let nonempty = literal(b"a")
        .prepare_forced::<DirectCount>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap()
        .preparation_accounting();
    let nonempty_match_length_scratch =
        state_count * (core::mem::size_of::<u32>() + core::mem::size_of::<Option<usize>>());
    let nonempty_base_persistent = nonempty.persistent_bytes - evaluation_order_bytes;
    assert_eq!(
        nonempty.peak_bytes,
        nonempty_base_persistent
            + nonempty_match_length_scratch
                .max(pattern_order_scratch)
                .max(evaluation_build_scratch)
    );
    assert_eq!(nonempty.allocation_attempts, 9);
}

#[test]
#[allow(clippy::too_many_lines)]
fn full_dfa_every_preparation_dimension_has_exact_and_one_below_behavior() {
    let probe = literal(b"aba")
        .prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let accounting = probe.preparation_accounting();
    assert_eq!(
        (
            accounting.prospective.pattern_terminals,
            accounting.prospective.dfa_states,
            accounting.prospective.transition_cells,
            accounting.prospective.subset_items,
            accounting.prospective.work,
            accounting.prospective.persistent_bytes,
            accounting.prospective.peak_bytes,
            accounting.prospective.allocation_attempts,
        ),
        (
            accounting.pattern_terminals,
            accounting.dfa_states,
            accounting.transition_cells,
            accounting.subset_items,
            accounting.work,
            accounting.persistent_bytes,
            accounting.peak_bytes,
            accounting.allocation_attempts,
        )
    );
    let exact = PreparationLimits {
        max_pattern_terminals: accounting.pattern_terminals,
        max_dfa_states: accounting.dfa_states,
        max_transition_cells: accounting.transition_cells,
        max_subset_items: accounting.subset_items,
        max_tagged_dispatch_states: accounting.tagged_dispatch_states,
        max_tagged_dispatch_cells: accounting.tagged_dispatch_cells,
        max_tagged_candidate_items: accounting.tagged_candidate_items,
        max_work: accounting.work,
        max_persistent_bytes: accounting.persistent_bytes,
        max_peak_bytes: accounting.peak_bytes,
        max_allocation_attempts: accounting.allocation_attempts,
    };
    literal(b"aba")
        .prepare_forced::<DirectCount>(ForcedExecution::FullDfa, PriorityTarget::portable(), exact)
        .unwrap();

    let cases = [
        (
            PreparationResource::PatternTerminals,
            PreparationLimits {
                max_pattern_terminals: exact.max_pattern_terminals - 1,
                ..exact
            },
        ),
        (
            PreparationResource::DfaStates,
            PreparationLimits {
                max_dfa_states: exact.max_dfa_states - 1,
                ..exact
            },
        ),
        (
            PreparationResource::TransitionCells,
            PreparationLimits {
                max_transition_cells: exact.max_transition_cells - 1,
                ..exact
            },
        ),
        (
            PreparationResource::SubsetItems,
            PreparationLimits {
                max_subset_items: exact.max_subset_items - 1,
                ..exact
            },
        ),
        (
            PreparationResource::PersistentBytes,
            PreparationLimits {
                max_persistent_bytes: exact.max_persistent_bytes - 1,
                ..exact
            },
        ),
        (
            PreparationResource::PeakBytes,
            PreparationLimits {
                max_peak_bytes: exact.max_peak_bytes - 1,
                ..exact
            },
        ),
        (
            PreparationResource::AllocationAttempts,
            PreparationLimits {
                max_allocation_attempts: exact.max_allocation_attempts - 1,
                ..exact
            },
        ),
    ];
    for (resource, limits) in cases {
        assert!(
            matches!(
                literal(b"aba").prepare_forced::<DirectCount>(
                    ForcedExecution::FullDfa,
                    PriorityTarget::portable(),
                    limits
                ),
                Err(PreparationError::ResourceLimit {
                    resource: actual,
                    ..
                }) if actual == resource
            ),
            "{resource:?}"
        );
    }
    assert!(matches!(
        literal(b"aba").prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits {
                max_work: exact.max_work - 1,
                ..exact
            }
        ),
        Err(PreparationError::WorkLimit { .. })
    ));
}

#[test]
fn sparse_runtime_preflight_dimensions_are_exact_and_one_below() {
    let plan = short_first()
        .prepare_forced::<DirectCount>(
            ForcedExecution::Sparse,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let haystack = b"abab";
    let prospective = plan
        .prospective(haystack.len(), DirectReduceLimits::unlimited())
        .unwrap();
    let exact = DirectReduceLimits {
        max_work: prospective.work_upper_bound,
        max_scratch_bytes: prospective.scratch_bytes,
        max_boundary_rows: prospective.boundary_rows,
        max_match_events: prospective.match_events_upper_bound,
        max_dfa_states: 0,
        max_dfa_cells: 0,
        max_subset_items: 0,
        max_tagged_dispatch_states: 0,
        max_tagged_dispatch_cells: 0,
        max_tagged_candidate_items: 0,
        max_tagged_cache_cells: 0,
        max_allocation_attempts: prospective.allocation_attempts,
    };
    plan.execute_forced(haystack, exact).unwrap();
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_work: exact.max_work - 1,
                ..exact
            }
        ),
        Err(ReduceError::WorkLimit { .. })
    ));
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_scratch_bytes: exact.max_scratch_bytes - 1,
                ..exact
            }
        ),
        Err(ReduceError::ScratchLimit { .. })
    ));
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_boundary_rows: exact.max_boundary_rows - 1,
                ..exact
            }
        ),
        Err(ReduceError::BoundaryRowsLimit { .. })
    ));
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_match_events: exact.max_match_events - 1,
                ..exact
            }
        ),
        Err(ReduceError::MatchEventsLimit { .. })
    ));
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_allocation_attempts: exact.max_allocation_attempts - 1,
                ..exact
            }
        ),
        Err(ReduceError::AllocationAttemptsLimit { .. })
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn input_bounded_sparse_fallback_runtime_preflight_is_exact_and_one_below() {
    let haystack = b"aaaa";
    let plan = suffix_trap()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .expect("input-bounded finite route prepares");
    assert_eq!(plan.kernel(), PriorityExecutionKernel::InputBoundedReverse);
    let prospective = plan
        .prospective(haystack.len(), DirectReduceLimits::unlimited())
        .expect("input-bounded prospective");
    let exact = DirectReduceLimits {
        max_work: prospective.work_upper_bound,
        max_scratch_bytes: prospective.scratch_bytes,
        max_boundary_rows: prospective.boundary_rows,
        max_match_events: prospective.match_events_upper_bound,
        max_dfa_states: 0,
        max_dfa_cells: 0,
        max_subset_items: 0,
        max_tagged_dispatch_states: 0,
        max_tagged_dispatch_cells: 0,
        max_tagged_candidate_items: 0,
        max_tagged_cache_cells: 0,
        max_allocation_attempts: prospective.allocation_attempts,
    };
    let report = plan
        .execute_forced(haystack, exact)
        .expect("exact input-bounded limits");
    assert_eq!(*report.output(), 4);
    assert_eq!(
        report.actual().suffix_reducer_steps,
        prospective.boundary_rows
    );
    assert_eq!(report.actual().scratch_bytes, prospective.scratch_bytes);
    assert_eq!(
        report.actual().allocation_attempts,
        prospective.allocation_attempts
    );

    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_work: one_below_u64(exact.max_work),
                ..exact
            }
        ),
        Err(ReduceError::WorkLimit {
            consumed,
            requested,
            limit,
        }) if consumed == 0
            && requested == exact.max_work
            && limit == one_below_u64(exact.max_work)
    ));
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_scratch_bytes: one_below_usize(exact.max_scratch_bytes),
                ..exact
            }
        ),
        Err(ReduceError::ScratchLimit { needed, limit })
            if needed == exact.max_scratch_bytes && limit == one_below_usize(exact.max_scratch_bytes)
    ));
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_boundary_rows: one_below_usize(exact.max_boundary_rows),
                ..exact
            }
        ),
        Err(ReduceError::BoundaryRowsLimit { needed, limit })
            if needed == exact.max_boundary_rows && limit == one_below_usize(exact.max_boundary_rows)
    ));
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_match_events: one_below_usize(exact.max_match_events),
                ..exact
            }
        ),
        Err(ReduceError::MatchEventsLimit { needed, limit })
            if needed == exact.max_match_events && limit == one_below_usize(exact.max_match_events)
    ));
    assert!(matches!(
        plan.execute_forced(
            haystack,
            DirectReduceLimits {
                max_allocation_attempts: one_below_usize(exact.max_allocation_attempts),
                ..exact
            }
        ),
        Err(ReduceError::AllocationAttemptsLimit { needed, limit })
            if needed == exact.max_allocation_attempts
                && limit == one_below_usize(exact.max_allocation_attempts)
    ));
}

#[test]
fn cyclic_sparse_and_finite_preflights_are_exact_and_one_below() {
    let haystack = b"abc";
    for route in [ForcedExecution::Sparse, ForcedExecution::FiniteHorizon] {
        let plan = zero_width_cycle()
            .prepare_forced::<DirectCount>(
                route,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap();
        let prospective = plan
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .unwrap();
        assert_eq!(prospective.allocation_attempts, 5, "{route:?}");
        let exact = DirectReduceLimits {
            max_work: prospective.work_upper_bound,
            max_scratch_bytes: prospective.scratch_bytes,
            max_boundary_rows: prospective.boundary_rows,
            max_match_events: prospective.match_events_upper_bound,
            max_dfa_states: 0,
            max_dfa_cells: 0,
            max_subset_items: 0,
            max_tagged_dispatch_states: 0,
            max_tagged_dispatch_cells: 0,
            max_tagged_candidate_items: 0,
            max_tagged_cache_cells: 0,
            max_allocation_attempts: prospective.allocation_attempts,
        };
        let report = plan.execute_forced(haystack, exact).unwrap();
        assert_eq!(*report.output(), 4, "{route:?}");
        assert_eq!(report.actual().allocation_attempts, 5, "{route:?}");
        assert_eq!(
            report.actual().suffix_reducer_steps,
            prospective.boundary_rows,
            "{route:?}"
        );
        assert!(report.actual().work <= prospective.work_upper_bound);
        assert!(report.actual().scratch_bytes <= prospective.scratch_bytes);
        assert!(report.actual().match_events <= prospective.match_events_upper_bound);

        for limits in [
            DirectReduceLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
            DirectReduceLimits {
                max_scratch_bytes: exact.max_scratch_bytes - 1,
                ..exact
            },
            DirectReduceLimits {
                max_boundary_rows: exact.max_boundary_rows - 1,
                ..exact
            },
            DirectReduceLimits {
                max_match_events: exact.max_match_events - 1,
                ..exact
            },
            DirectReduceLimits {
                max_allocation_attempts: exact.max_allocation_attempts - 1,
                ..exact
            },
        ] {
            assert!(plan.execute_forced(haystack, limits).is_err(), "{route:?}");
        }
    }
}

#[test]
fn full_and_lazy_publish_route_specific_cells_and_refuse_one_below() {
    let haystack = b"abababa";
    let full = literal(b"ab")
        .prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let full_p = full
        .prospective(haystack.len(), DirectReduceLimits::unlimited())
        .unwrap();
    assert!(full_p.dfa_states_capacity > 0);
    assert!(full_p.dfa_cells_capacity >= 256);
    assert!(matches!(
        full.execute_forced(
            haystack,
            DirectReduceLimits {
                max_dfa_cells: full_p.dfa_cells_capacity - 1,
                ..DirectReduceLimits::unlimited()
            }
        ),
        Err(ReduceError::DfaCellsLimit { .. })
    ));

    let lazy = literal(b"ab")
        .prepare_forced::<DirectCount>(
            ForcedExecution::LazyDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let report = lazy
        .execute_forced(haystack, DirectReduceLimits::unlimited())
        .unwrap();
    let actual = report.actual();
    assert_eq!(actual.dfa_transitions, haystack.len());
    assert!(actual.dfa_states > 1);
    assert!(actual.dfa_cells > 1);
    assert!(actual.subset_items > 0);
    assert!(actual.lazy_cache_hits > 0);
    assert_eq!(actual.lazy_cache_misses, actual.lazy_cache_inserts);
    for limits in [
        DirectReduceLimits {
            max_dfa_states: actual.dfa_states - 1,
            ..DirectReduceLimits::unlimited()
        },
        DirectReduceLimits {
            max_subset_items: actual.subset_items - 1,
            ..DirectReduceLimits::unlimited()
        },
    ] {
        assert!(lazy.execute_forced(haystack, limits).is_err());
    }
    assert!(matches!(
        lazy.execute_forced(
            haystack,
            DirectReduceLimits {
                max_dfa_cells: 0,
                ..DirectReduceLimits::unlimited()
            }
        ),
        Err(ReduceError::DfaCellsLimit { .. })
    ));
    let evicted = lazy
        .execute_forced(
            haystack,
            DirectReduceLimits {
                max_dfa_cells: 1,
                ..DirectReduceLimits::unlimited()
            },
        )
        .unwrap();
    assert_eq!(*evicted.output(), 3);
    assert!(evicted.actual().lazy_cache_evictions > 0);
}

fn without_run_allocations(mut actual: ExecutionActual) -> ExecutionActual {
    actual.allocation_attempts = 0;
    actual
}

#[test]
fn intrinsic_match_length_constructor_preserves_preparation_validation() {
    let states = vec![
        consume(vec![Edge::byte(1, b'a')]),
        consume(vec![Edge::byte(2, b'b')]),
        accept(0),
    ];
    let (automaton, actions) = fact_parts(states.clone());
    let intrinsic = PriorityAutomataFacts::new_with_intrinsic_match_length(
        automaton,
        actions,
        EmptyMatchProgress::Byte,
    )
    .prepare_forced::<DirectCount>(
        ForcedExecution::FullDfa,
        PriorityTarget::portable(),
        PreparationLimits::unlimited(),
    )
    .unwrap();
    assert_eq!(intrinsic.kernel(), PriorityExecutionKernel::FullDfa);
    assert_eq!(
        *intrinsic
            .execute_forced(b"zabab", DirectReduceLimits::unlimited())
            .unwrap()
            .output(),
        2
    );

    let (automaton, mut actions) = fact_parts(states.clone());
    actions[2] = None;
    assert!(matches!(
        PriorityAutomataFacts::new_with_intrinsic_match_length(
            automaton,
            actions,
            EmptyMatchProgress::Byte,
        )
        .prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        ),
        Err(PreparationError::MissingAcceptAction { state: 2 })
    ));

    let (automaton, actions) = fact_parts(states);
    assert!(matches!(
        PriorityAutomataFacts::new(
            automaton,
            actions,
            MatchLengthProof::Exact(1),
            EmptyMatchProgress::Byte,
        )
        .prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        ),
        Err(PreparationError::MatchLengthProofMismatch {
            declared: MatchLengthProof::Exact(1),
            intrinsic: MatchLengthProof::Exact(2),
        })
    ));
}

#[test]
fn full_and_finite_static_workspaces_are_reusable_and_differential() {
    let full = literal(b"ab")
        .prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let mut full_workspace = full
        .prepare_static_workspace(PriorityStaticWorkspaceLimits {
            max_setup_work: 0,
            max_scratch_bytes: 0,
            max_allocation_attempts: 0,
        })
        .unwrap()
        .unwrap();
    assert_eq!(full_workspace.accounting().scratch_bytes, 0);
    assert_eq!(full_workspace.accounting().allocation_attempts, 0);

    let count = short_first()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let span = short_first()
        .prepare_forced::<DirectSpanSum>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let mut count_workspace = count
        .prepare_static_workspace(PriorityStaticWorkspaceLimits::unlimited())
        .unwrap()
        .unwrap();
    let mut span_workspace = span
        .prepare_static_workspace(PriorityStaticWorkspaceLimits::unlimited())
        .unwrap()
        .unwrap();
    let accounting = count_workspace.accounting();
    assert_eq!(accounting.reducer_ring_entries, 4);
    assert_eq!(accounting.outcome_row_slots, 12);
    assert_eq!(accounting.allocation_attempts, 3);
    assert_eq!(span_workspace.accounting(), accounting);

    let warm_limits = DirectReduceLimits {
        max_allocation_attempts: 0,
        ..DirectReduceLimits::unlimited()
    };
    for haystack in words(5) {
        let mut expected_count_prospective = count
            .prospective(haystack.len(), DirectReduceLimits::unlimited())
            .unwrap();
        expected_count_prospective.allocation_attempts = 0;
        assert_eq!(
            count
                .prospective_with_workspace(haystack.len(), &count_workspace, warm_limits)
                .unwrap(),
            expected_count_prospective,
            "{haystack:?}"
        );
        let cold_full = full
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .unwrap();
        let warm_full = full
            .execute_forced_with_workspace(&haystack, &mut full_workspace, warm_limits)
            .unwrap();
        assert_eq!(warm_full, cold_full, "{haystack:?}");

        let cold_count = count
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .unwrap();
        let warm_count = count
            .execute_forced_with_workspace(&haystack, &mut count_workspace, warm_limits)
            .unwrap();
        assert_eq!(warm_count.output(), cold_count.output(), "{haystack:?}");
        assert_eq!(
            warm_count.actual(),
            without_run_allocations(cold_count.actual()),
            "{haystack:?}"
        );
        assert_eq!(warm_count.prospective().allocation_attempts, 0);

        let cold_span = span
            .execute_forced(&haystack, DirectReduceLimits::unlimited())
            .unwrap();
        let warm_span = span
            .execute_forced_with_workspace(&haystack, &mut span_workspace, warm_limits)
            .unwrap();
        assert_eq!(warm_span.output(), cold_span.output(), "{haystack:?}");
        assert_eq!(
            warm_span.actual(),
            without_run_allocations(cold_span.actual()),
            "{haystack:?}"
        );
        assert_eq!(warm_span.actual().selected_span_bytes, *warm_span.output());
    }
}

#[test]
fn cyclic_static_workspace_resets_logically_and_plan_binding_is_exact() {
    let plan = zero_width_cycle()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let mut workspace = plan
        .prepare_static_workspace(PriorityStaticWorkspaceLimits::unlimited())
        .unwrap()
        .unwrap();
    let accounting = workspace.accounting();
    assert_eq!(accounting.reducer_ring_entries, 2);
    assert_eq!(accounting.generation_stamp_slots, 3);
    assert_eq!(accounting.allocation_attempts, 5);
    let limits = DirectReduceLimits {
        max_allocation_attempts: 0,
        ..DirectReduceLimits::unlimited()
    };
    for haystack in [b"abba".as_slice(), b"".as_slice(), b"a".as_slice(), b"bbb"] {
        let cold = plan
            .execute_forced(haystack, DirectReduceLimits::unlimited())
            .unwrap();
        let warm = plan
            .execute_forced_with_workspace(haystack, &mut workspace, limits)
            .unwrap();
        assert_eq!(warm.output(), cold.output(), "{haystack:?}");
        assert_eq!(
            warm.actual(),
            without_run_allocations(cold.actual()),
            "{haystack:?}"
        );
    }

    let other = zero_width_cycle()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    assert!(matches!(
        other.execute_forced_with_workspace(b"a", &mut workspace, limits),
        Err(ReduceError::StaticWorkspaceMismatch { .. })
    ));
    assert!(plan
        .execute_forced_with_workspace(b"a", &mut workspace, limits)
        .is_ok());
}

#[test]
fn detached_priority_route_preserves_identity_ledgers_and_results() {
    let wrapper_full = literal(b"ab")
        .prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let (full_automaton, full_route) = literal(b"ab")
        .prepare_forced_parts::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let wrapper_count = short_first()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let wrapper_span = short_first()
        .prepare_forced::<DirectSpanSum>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();

    let states = vec![
        split(vec![Edge::epsilon(1), Edge::epsilon(3)]),
        consume(vec![Edge::byte(2, b'a')]),
        accept(0),
        consume(vec![Edge::byte(4, b'a')]),
        consume(vec![Edge::byte(5, b'b')]),
        accept(0),
    ];
    let (automaton, actions) = fact_parts(states.clone());
    let original_identity = automaton.identity();
    let (count_automaton, count_route) = PriorityAutomataFacts::new(
        automaton,
        actions,
        MatchLengthProof::Finite {
            minimum_bytes: 1,
            maximum_bytes: 2,
        },
        EmptyMatchProgress::Byte,
    )
    .prepare_forced_parts::<DirectCount>(
        ForcedExecution::FiniteHorizon,
        PriorityTarget::portable(),
        PreparationLimits::unlimited(),
    )
    .unwrap();
    assert_eq!(count_automaton.identity(), original_identity);

    let (automaton, actions) = fact_parts(states);
    let (span_automaton, span_route) = PriorityAutomataFacts::new(
        automaton,
        actions,
        MatchLengthProof::Finite {
            minimum_bytes: 1,
            maximum_bytes: 2,
        },
        EmptyMatchProgress::Byte,
    )
    .prepare_forced_parts::<DirectSpanSum>(
        ForcedExecution::FiniteHorizon,
        PriorityTarget::portable(),
        PreparationLimits::unlimited(),
    )
    .unwrap();

    assert_eq!(
        full_route.preparation_accounting(),
        wrapper_full.preparation_accounting()
    );
    assert_eq!(
        count_route.preparation_accounting(),
        wrapper_count.preparation_accounting()
    );
    assert_eq!(
        span_route.preparation_accounting(),
        wrapper_span.preparation_accounting()
    );
    let limits = DirectReduceLimits::unlimited();
    for haystack in words(4) {
        assert_eq!(
            full_route
                .execute_forced(&full_automaton, &haystack, limits)
                .unwrap(),
            wrapper_full.execute_forced(&haystack, limits).unwrap(),
            "{haystack:?}"
        );
        assert_eq!(
            count_route
                .prospective(&count_automaton, haystack.len(), limits)
                .unwrap(),
            wrapper_count.prospective(haystack.len(), limits).unwrap(),
            "{haystack:?}"
        );
        assert_eq!(
            count_route
                .execute_forced(&count_automaton, &haystack, limits)
                .unwrap(),
            wrapper_count.execute_forced(&haystack, limits).unwrap(),
            "{haystack:?}"
        );
        assert_eq!(
            span_route
                .execute_forced(&span_automaton, &haystack, limits)
                .unwrap(),
            wrapper_span.execute_forced(&haystack, limits).unwrap(),
            "{haystack:?}"
        );
    }
}

#[test]
fn detached_route_and_wrapper_clone_reject_mismatched_bindings() {
    let (automaton, route) = literal(b"ab")
        .prepare_forced_parts::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let wrong_automaton = automaton.clone();
    assert!(matches!(
        route.prospective(&wrong_automaton, 1, DirectReduceLimits::unlimited()),
        Err(ReduceError::PreparedRouteAutomatonMismatch)
    ));
    assert!(matches!(
        route.execute_forced(&wrong_automaton, b"ab", DirectReduceLimits::unlimited()),
        Err(ReduceError::PreparedRouteAutomatonMismatch)
    ));
    assert!(matches!(
        route.prepare_static_workspace(
            &wrong_automaton,
            PriorityStaticWorkspaceLimits::unlimited(),
        ),
        Err(PriorityStaticWorkspaceError::PreparedRouteAutomatonMismatch)
    ));

    let original = literal(b"ab")
        .prepare_forced::<DirectCount>(
            ForcedExecution::FullDfa,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let mut original_workspace = original
        .prepare_static_workspace(PriorityStaticWorkspaceLimits::unlimited())
        .unwrap()
        .unwrap();
    let cloned = original.clone();
    assert_eq!(
        cloned.preparation_accounting(),
        original.preparation_accounting()
    );
    assert_eq!(
        cloned
            .execute_forced(b"zabab", DirectReduceLimits::unlimited())
            .unwrap()
            .output(),
        &2
    );
    assert!(matches!(
        cloned.execute_forced_with_workspace(
            b"ab",
            &mut original_workspace,
            DirectReduceLimits::unlimited(),
        ),
        Err(ReduceError::StaticWorkspaceMismatch { .. })
    ));
    assert!(original
        .execute_forced_with_workspace(
            b"ab",
            &mut original_workspace,
            DirectReduceLimits::unlimited(),
        )
        .is_ok());
}

#[test]
fn static_workspace_limits_and_unsupported_routes_are_typed() {
    assert_eq!(
        PRIORITY_STATIC_WORKSPACE_ACCOUNTING_ID,
        "fre-automata.priority-static-workspace.v1"
    );
    let plan = short_first()
        .prepare_forced::<DirectCount>(
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            PreparationLimits::unlimited(),
        )
        .unwrap();
    let accounting = plan
        .prepare_static_workspace(PriorityStaticWorkspaceLimits::unlimited())
        .unwrap()
        .unwrap()
        .accounting();
    let exact = PriorityStaticWorkspaceLimits {
        max_setup_work: accounting.setup_work,
        max_scratch_bytes: accounting.scratch_bytes,
        max_allocation_attempts: accounting.allocation_attempts,
    };
    plan.prepare_static_workspace(exact).unwrap().unwrap();
    assert!(matches!(
        plan.prepare_static_workspace(PriorityStaticWorkspaceLimits {
            max_setup_work: exact.max_setup_work - 1,
            ..exact
        }),
        Err(PriorityStaticWorkspaceError::SetupWorkLimit { needed, limit })
            if needed == exact.max_setup_work && limit + 1 == needed
    ));
    assert!(matches!(
        plan.prepare_static_workspace(PriorityStaticWorkspaceLimits {
            max_scratch_bytes: exact.max_scratch_bytes - 1,
            ..exact
        }),
        Err(PriorityStaticWorkspaceError::ScratchLimit { needed, limit })
            if needed == exact.max_scratch_bytes && limit + 1 == needed
    ));
    assert!(matches!(
        plan.prepare_static_workspace(PriorityStaticWorkspaceLimits {
            max_allocation_attempts: exact.max_allocation_attempts - 1,
            ..exact
        }),
        Err(PriorityStaticWorkspaceError::AllocationAttemptsLimit { needed, limit })
            if needed == exact.max_allocation_attempts && limit + 1 == needed
    ));

    let unsupported = [
        short_first()
            .prepare_forced::<DirectCount>(
                ForcedExecution::Sparse,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap(),
        suffix_trap()
            .prepare_forced::<DirectCount>(
                ForcedExecution::FiniteHorizon,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap(),
        short_first()
            .prepare_forced::<DirectCount>(
                ForcedExecution::FullDfa,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap(),
        literal(b"ab")
            .prepare_forced::<DirectCount>(
                ForcedExecution::LazyDfa,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap(),
        short_first()
            .prepare_forced::<DirectCount>(
                ForcedExecution::LazyDfa,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap(),
    ];
    assert_eq!(unsupported[0].kernel(), PriorityExecutionKernel::SparseReverse);
    assert_eq!(unsupported[1].kernel(), PriorityExecutionKernel::InputBoundedReverse);
    assert_eq!(unsupported[2].kernel(), PriorityExecutionKernel::FullTaggedReverse);
    assert_eq!(unsupported[3].kernel(), PriorityExecutionKernel::LazyDfa);
    assert_eq!(unsupported[4].kernel(), PriorityExecutionKernel::LazyTaggedReverse);
    for plan in unsupported {
        assert!(plan
            .prepare_static_workspace(PriorityStaticWorkspaceLimits::unlimited())
            .unwrap()
            .is_none());
    }
}
