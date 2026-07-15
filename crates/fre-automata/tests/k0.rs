use fre_automata::{
    Automaton, CompileError, CompileLimits, EdgeKind, Exists, K0Workspace, MalformedPlan,
    MatchSpan, OutputContract, RawPlan, ResourceKind, SearchError, SearchLimits, SearchWindow,
    SelectedEnd, Span, StateRole, WorkspaceLimits,
};

#[derive(Clone)]
struct State {
    role: StateRole,
    edges: Vec<Edge>,
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
    }
}

fn consume(edges: Vec<Edge>) -> State {
    State {
        role: StateRole::Consume,
        edges,
    }
}

fn accept() -> State {
    State {
        role: StateRole::Accept,
        edges: Vec::new(),
    }
}

fn raw(start: u32, states: Vec<State>) -> RawPlan {
    let mut edge_offsets = Vec::with_capacity(states.len().saturating_add(1));
    let mut edge_targets = Vec::new();
    let mut edge_kinds = Vec::new();
    let mut byte_starts = Vec::new();
    let mut byte_ends = Vec::new();
    edge_offsets.push(0);
    for state in &states {
        for edge in &state.edges {
            edge_targets.push(edge.target);
            edge_kinds.push(edge.kind);
            byte_starts.push(edge.start);
            byte_ends.push(edge.end);
        }
        edge_offsets.push(u32::try_from(edge_targets.len()).expect("small test graph"));
    }
    RawPlan {
        start,
        roles: states.into_iter().map(|state| state.role).collect(),
        edge_offsets,
        edge_targets,
        edge_kinds,
        byte_starts,
        byte_ends,
    }
}

fn compile(states: Vec<State>) -> Automaton {
    Automaton::from_raw(raw(0, states), CompileLimits::default()).expect("valid test automaton")
}

fn assertion(kind: EdgeKind) -> Automaton {
    compile(vec![split(vec![Edge::assertion(1, kind)]), accept()])
}

fn assertion_at(kind: EdgeKind, haystack: &[u8], at: usize) -> bool {
    assertion(kind)
        .prepare::<Span>()
        .search_window(
            haystack,
            SearchWindow::new(at, at),
            SearchLimits::unlimited(),
        )
        .expect("unlimited assertion search")
        .into_output()
        .is_some()
}

fn literal(bytes: &[u8]) -> Automaton {
    let mut states = Vec::with_capacity(bytes.len().saturating_add(1));
    for (index, &byte) in bytes.iter().enumerate() {
        states.push(consume(vec![Edge::byte(
            u32::try_from(index.saturating_add(1)).expect("small literal"),
            byte,
        )]));
    }
    states.push(accept());
    compile(states)
}

fn find(plan: &Automaton, haystack: &[u8]) -> Option<MatchSpan> {
    plan.prepare::<Span>()
        .search(haystack, SearchLimits::unlimited())
        .expect("unlimited search")
        .into_output()
}

#[test]
fn operation_contracts_are_typed() {
    let plan = literal(b"ab");
    let span = plan
        .prepare::<Span>()
        .search(b"zab", SearchLimits::unlimited())
        .unwrap();
    let end = plan
        .prepare::<SelectedEnd>()
        .search(b"zab", SearchLimits::unlimited())
        .unwrap();
    let exists = plan
        .prepare::<Exists>()
        .search(b"zab", SearchLimits::unlimited())
        .unwrap();

    assert_eq!(plan.prepare::<Span>().contract(), OutputContract::Span);
    assert_eq!(span.into_output(), Some(MatchSpan::new(1, 3)));
    assert_eq!(end.into_output(), Some(3));
    assert!(exists.into_output());
}

#[test]
fn exhaustive_literals_match_a_direct_reference() {
    let patterns = words(3);
    let haystacks = words(5);
    for pattern in &patterns {
        let plan = literal(pattern);
        for haystack in &haystacks {
            let expected = if pattern.is_empty() {
                Some(MatchSpan::new(0, 0))
            } else {
                haystack
                    .windows(pattern.len())
                    .position(|window| window == pattern)
                    .map(|start| MatchSpan::new(start, start + pattern.len()))
            };
            assert_eq!(
                find(&plan, haystack),
                expected,
                "pattern={pattern:?}, haystack={haystack:?}"
            );
        }
    }
}

#[test]
fn ordered_alternation_prefers_the_first_successful_path() {
    // a|ab: the first branch wins even though the second is longer.
    let short_first = compile(vec![
        split(vec![Edge::epsilon(1), Edge::epsilon(3)]),
        consume(vec![Edge::byte(2, b'a')]),
        accept(),
        consume(vec![Edge::byte(4, b'a')]),
        consume(vec![Edge::byte(5, b'b')]),
        accept(),
    ]);
    // ab|a: the higher-priority path remains live past the lower-priority
    // accept and therefore selects the longer first branch.
    let long_first = compile(vec![
        split(vec![Edge::epsilon(1), Edge::epsilon(4)]),
        consume(vec![Edge::byte(2, b'a')]),
        consume(vec![Edge::byte(3, b'b')]),
        accept(),
        consume(vec![Edge::byte(5, b'a')]),
        accept(),
    ]);

    assert_eq!(find(&short_first, b"ab"), Some(MatchSpan::new(0, 1)));
    assert_eq!(find(&long_first, b"ab"), Some(MatchSpan::new(0, 2)));
    assert_eq!(find(&long_first, b"ax"), Some(MatchSpan::new(0, 1)));
}

#[test]
fn edge_order_represents_greedy_and_lazy_repetition() {
    // a*: consuming edge first is greedy.
    let greedy = compile(vec![
        split(vec![Edge::epsilon(1), Edge::epsilon(2)]),
        consume(vec![Edge::byte(0, b'a')]),
        accept(),
    ]);
    // a*?: accept edge first is lazy.
    let lazy = compile(vec![
        split(vec![Edge::epsilon(2), Edge::epsilon(1)]),
        consume(vec![Edge::byte(0, b'a')]),
        accept(),
    ]);

    assert_eq!(find(&greedy, b"aaab"), Some(MatchSpan::new(0, 3)));
    assert_eq!(find(&lazy, b"aaab"), Some(MatchSpan::new(0, 0)));
}

#[test]
fn earliest_start_dominates_later_starts() {
    let greedy = compile(vec![
        consume(vec![Edge::byte(1, b'a')]),
        split(vec![Edge::epsilon(0), Edge::epsilon(2)]),
        accept(),
    ]);
    assert_eq!(find(&greedy, b"baaa"), Some(MatchSpan::new(1, 4)));
}

#[test]
fn empty_matches_and_epsilon_cycles_terminate() {
    assert_eq!(find(&literal(b""), b"abc"), Some(MatchSpan::new(0, 0)));

    let cycle = compile(vec![
        split(vec![Edge::epsilon(1), Edge::epsilon(2)]),
        split(vec![Edge::epsilon(0)]),
        accept(),
    ]);
    assert_eq!(find(&cycle, b"abc"), Some(MatchSpan::new(0, 0)));
}

#[test]
fn deep_epsilon_graph_does_not_use_the_native_stack() {
    const DEPTH: usize = 50_000;
    let mut states = Vec::with_capacity(DEPTH + 1);
    for target in 1..=DEPTH {
        states.push(split(vec![Edge::epsilon(
            u32::try_from(target).expect("test depth fits u32"),
        )]));
    }
    states.push(accept());
    let plan = compile(states);
    assert_eq!(find(&plan, b""), Some(MatchSpan::new(0, 0)));
}

#[test]
fn anchors_use_original_haystack_context() {
    let start_a = compile(vec![
        split(vec![Edge::assertion(1, EdgeKind::AssertHaystackStart)]),
        consume(vec![Edge::byte(2, b'a')]),
        accept(),
    ]);
    let a_end = compile(vec![
        consume(vec![Edge::byte(1, b'a')]),
        split(vec![Edge::assertion(2, EdgeKind::AssertHaystackEnd)]),
        accept(),
    ]);

    assert_eq!(find(&start_a, b"ab"), Some(MatchSpan::new(0, 1)));
    assert_eq!(find(&start_a, b"ba"), None);
    assert_eq!(find(&a_end, b"ba"), Some(MatchSpan::new(1, 2)));
    assert_eq!(find(&a_end, b"ab"), None);

    let ranged_start = start_a
        .prepare::<Span>()
        .search_window(b"za", SearchWindow::new(1, 2), SearchLimits::unlimited())
        .unwrap();
    let ranged_end = a_end
        .prepare::<Span>()
        .search_window(b"az", SearchWindow::new(0, 1), SearchLimits::unlimited())
        .unwrap();
    assert_eq!(ranged_start.into_output(), None);
    assert_eq!(ranged_end.into_output(), None);
}

#[test]
fn positive_unicode_word_boundary_is_scalar_exact_on_arbitrary_bytes() {
    let kind = EdgeKind::AssertWordUnicode;
    let cases: &[(&[u8], &[(usize, bool)])] = &[
        (b"", &[(0, false)]),
        ("α".as_bytes(), &[(0, true), (1, false), (2, true)]),
        (
            " α-β ".as_bytes(),
            &[(0, false), (1, true), (3, true), (4, true), (6, true), (7, false)],
        ),
        ("\u{301}".as_bytes(), &[(0, true), (2, true)]),
        ("\u{203F}".as_bytes(), &[(0, true), (3, true)]),
        ("\u{200C}".as_bytes(), &[(0, true), (3, true)]),
        ("😀".as_bytes(), &[(0, false), (1, false), (4, false)]),
        (&[0xFF, b'a', 0xFF], &[(0, false), (1, true), (2, true), (3, false)]),
        (&[0xCE], &[(0, false), (1, false)]),
        (&[0xC0, 0x80], &[(0, false), (1, false), (2, false)]),
    ];
    for &(haystack, positions) in cases {
        for &(at, expected) in positions {
            assert_eq!(
                assertion_at(kind, haystack, at),
                expected,
                "haystack={haystack:?}, at={at}"
            );
        }
    }
}

const ASSERTION_KINDS: [EdgeKind; 10] = [
    EdgeKind::AssertHaystackStart,
    EdgeKind::AssertHaystackEnd,
    EdgeKind::AssertLineStartLf,
    EdgeKind::AssertLineEndLf,
    EdgeKind::AssertWordAscii,
    EdgeKind::AssertWordAsciiNegate,
    EdgeKind::AssertWordStartAscii,
    EdgeKind::AssertWordEndAscii,
    EdgeKind::AssertWordStartHalfAscii,
    EdgeKind::AssertWordEndHalfAscii,
];

fn reference_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_digit() || byte.is_ascii_alphabetic()
}

fn reference_assertion(kind: EdgeKind, haystack: &[u8], at: usize) -> bool {
    let before = at.checked_sub(1).and_then(|index| haystack.get(index));
    let after = haystack.get(at);
    let word_before = before.is_some_and(|&byte| reference_ascii_word(byte));
    let word_after = after.is_some_and(|&byte| reference_ascii_word(byte));
    match kind {
        EdgeKind::AssertHaystackStart => at == 0,
        EdgeKind::AssertHaystackEnd => at == haystack.len(),
        EdgeKind::AssertLineStartLf => at == 0 || before.is_some_and(|&byte| byte == b'\n'),
        EdgeKind::AssertLineEndLf => {
            at == haystack.len() || after.is_some_and(|&byte| byte == b'\n')
        }
        EdgeKind::AssertWordAscii => word_before != word_after,
        EdgeKind::AssertWordAsciiNegate => word_before == word_after,
        EdgeKind::AssertWordStartAscii => !word_before && word_after,
        EdgeKind::AssertWordEndAscii => word_before && !word_after,
        EdgeKind::AssertWordStartHalfAscii => !word_before,
        EdgeKind::AssertWordEndHalfAscii => !word_after,
        _ => panic!("reference received a non-assertion edge"),
    }
}

#[test]
fn assertion_edges_match_an_independent_absolute_byte_oracle() {
    let mut haystacks = vec![Vec::new()];
    haystacks.extend((u8::MIN..=u8::MAX).map(|byte| vec![byte]));
    let alphabet = [b'a', b'Z', b'9', b'_', b'-', b'\n', 0xFF];
    for &first in &alphabet {
        for &second in &alphabet {
            haystacks.push(vec![first, second]);
        }
    }

    for kind in ASSERTION_KINDS {
        let plan = assertion(kind);
        for haystack in &haystacks {
            for at in 0..=haystack.len() {
                let actual = plan
                    .prepare::<Span>()
                    .search_window(
                        haystack,
                        SearchWindow::new(at, at),
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .into_output();
                let expected =
                    reference_assertion(kind, haystack, at).then_some(MatchSpan::new(at, at));
                assert_eq!(actual, expected, "{kind:?}/{haystack:?}/{at}");
            }
        }
    }
}

#[test]
fn assertions_may_observe_outside_a_range_but_consumption_may_not() {
    let line_start_a = compile(vec![
        split(vec![Edge::assertion(1, EdgeKind::AssertLineStartLf)]),
        consume(vec![Edge::byte(2, b'a')]),
        accept(),
    ]);
    let word_start_a = compile(vec![
        split(vec![Edge::assertion(1, EdgeKind::AssertWordStartAscii)]),
        consume(vec![Edge::byte(2, b'a')]),
        accept(),
    ]);

    for plan in [&line_start_a, &word_start_a] {
        assert_eq!(
            plan.prepare::<Span>()
                .search_window(b"\na", SearchWindow::new(1, 1), SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            None
        );
    }
    assert_eq!(
        line_start_a
            .prepare::<Span>()
            .search_window(b"\na", SearchWindow::new(1, 2), SearchLimits::unlimited())
            .unwrap()
            .into_output(),
        Some(MatchSpan::new(1, 2))
    );
    assert_eq!(
        word_start_a
            .prepare::<Span>()
            .search_window(b"-a", SearchWindow::new(1, 2), SearchLimits::unlimited())
            .unwrap()
            .into_output(),
        Some(MatchSpan::new(1, 2))
    );
    assert_eq!(
        word_start_a
            .prepare::<Span>()
            .search_window(b"aa", SearchWindow::new(1, 2), SearchLimits::unlimited())
            .unwrap()
            .into_output(),
        None
    );
}

#[test]
fn every_short_run_respects_the_conservative_work_bound() {
    let plans = [
        literal(b"ab"),
        compile(vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(2)]),
            consume(vec![Edge::byte(0, b'a')]),
            accept(),
        ]),
        compile(vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(2)]),
            split(vec![Edge::epsilon(0)]),
            accept(),
        ]),
        assertion(EdgeKind::AssertWordAscii),
    ];

    for plan in &plans {
        let mut workspace = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
        for haystack in words(6) {
            let bound = plan.conservative_work_bound(haystack.len()).unwrap();
            let report = plan
                .prepare::<Span>()
                .search(
                    &haystack,
                    SearchLimits {
                        max_work: bound,
                        max_scratch_bytes: usize::MAX,
                    },
                )
                .unwrap();
            assert!(report.accounting().work() <= bound);

            let reused_bound = plan.conservative_reused_work_bound(haystack.len()).unwrap();
            let reused = plan
                .prepare::<Span>()
                .search_with_workspace(
                    &haystack,
                    &mut workspace,
                    SearchLimits {
                        max_work: reused_bound,
                        max_scratch_bytes: usize::MAX,
                    },
                )
                .unwrap();
            assert!(reused.accounting().work() <= reused_bound);
        }
    }
}

#[test]
fn exact_work_and_scratch_limits_fail_before_overrun() {
    let plan = literal(b"never");
    let successful = plan
        .prepare::<Span>()
        .search(b"a haystack", SearchLimits::unlimited())
        .unwrap();
    let charged = successful.accounting().work();
    let exact = plan
        .prepare::<Span>()
        .search(
            b"a haystack",
            SearchLimits {
                max_work: charged,
                max_scratch_bytes: usize::MAX,
            },
        )
        .unwrap();
    assert_eq!(exact.accounting().work(), charged);

    let error = plan
        .prepare::<Span>()
        .search(
            b"a haystack",
            SearchLimits {
                max_work: charged - 1,
                max_scratch_bytes: usize::MAX,
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        SearchError::WorkLimitExceeded {
            limit,
            consumed,
            ..
        } if limit == charged - 1 && consumed <= limit
    ));

    let error = plan
        .prepare::<Span>()
        .search(
            b"a haystack",
            SearchLimits {
                max_work: u64::MAX,
                max_scratch_bytes: 0,
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        SearchError::ResourceLimit {
            resource: ResourceKind::ScratchBytes,
            needed,
            limit: 0
        } if needed > 0
    ));
}

#[test]
fn reusable_workspace_is_allocation_free_and_matches_cold_calls() {
    let plans = [
        literal(b"ab"),
        compile(vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(2)]),
            consume(vec![Edge::byte(0, b'a')]),
            accept(),
        ]),
        compile(vec![
            split(vec![Edge::epsilon(1), Edge::epsilon(3)]),
            consume(vec![Edge::byte(2, b'a')]),
            accept(),
            consume(vec![Edge::byte(4, b'b')]),
            accept(),
        ]),
    ];

    for plan in &plans {
        let mut workspace = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
        let retained = workspace.retained_bytes();
        let construction = workspace.construction_accounting();
        assert!(!construction.reused());
        assert_eq!(construction.allocated_bytes(), retained);
        assert_eq!(
            construction.initialized_bytes(),
            plan.workspace_layout().unwrap().logical_bytes()
        );

        for haystack in words(5) {
            let cold = plan
                .prepare::<Span>()
                .search(&haystack, SearchLimits::unlimited())
                .unwrap();
            let reused = plan
                .prepare::<Span>()
                .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(reused.output(), cold.output());
            assert_eq!(
                reused.accounting().transition_work(),
                cold.accounting().transition_work()
            );
            assert_eq!(reused.accounting().setup_work(), 3);
            assert_eq!(
                reused.accounting().work(),
                reused
                    .accounting()
                    .setup_work()
                    .checked_add(reused.accounting().transition_work())
                    .unwrap()
            );
            assert!(reused.accounting().setup().reused());
            assert_eq!(reused.accounting().setup().allocated_bytes(), 0);
            assert_eq!(reused.accounting().setup().initialized_bytes(), 0);
            assert_eq!(reused.accounting().scratch_bytes(), retained);
            assert_eq!(workspace.retained_bytes(), retained);
        }
    }
}

#[test]
fn workspace_limits_and_exact_reuse_boundaries_are_enforced() {
    let plan = literal(b"abc");
    let layout = plan.workspace_layout().unwrap();
    let error = K0Workspace::new(
        &plan,
        WorkspaceLimits {
            max_setup_work: layout.construction_work() - 1,
            max_scratch_bytes: usize::MAX,
        },
    )
    .unwrap_err();
    assert_eq!(
        error,
        SearchError::WorkspaceSetupWorkLimitExceeded {
            limit: layout.construction_work() - 1,
            needed: layout.construction_work()
        }
    );

    let error = K0Workspace::new(
        &plan,
        WorkspaceLimits {
            max_setup_work: u64::MAX,
            max_scratch_bytes: layout.logical_bytes() - 1,
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SearchError::ResourceLimit {
            resource: ResourceKind::ScratchBytes,
            needed,
            limit
        } if needed == layout.logical_bytes() && limit == layout.logical_bytes() - 1
    ));

    let probe = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
    let retained = probe.retained_bytes();
    drop(probe);
    let mut workspace = K0Workspace::new(
        &plan,
        WorkspaceLimits {
            max_setup_work: layout.construction_work(),
            max_scratch_bytes: retained,
        },
    )
    .unwrap();
    let retained = workspace.retained_bytes();
    let successful = plan
        .prepare::<Span>()
        .search_with_workspace(b"zabc", &mut workspace, SearchLimits::unlimited())
        .unwrap();
    let exact_work = successful.accounting().work();
    let exact = plan
        .prepare::<Span>()
        .search_with_workspace(
            b"zabc",
            &mut workspace,
            SearchLimits {
                max_work: exact_work,
                max_scratch_bytes: retained,
            },
        )
        .unwrap();
    assert_eq!(exact.output(), &Some(MatchSpan::new(1, 4)));

    let error = plan
        .prepare::<Span>()
        .search_with_workspace(
            b"zabc",
            &mut workspace,
            SearchLimits {
                max_work: exact_work,
                max_scratch_bytes: retained - 1,
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        SearchError::ResourceLimit {
            resource: ResourceKind::ScratchBytes,
            needed,
            limit
        } if needed == retained && limit == retained - 1
    ));

    let error = plan
        .prepare::<Span>()
        .search_with_workspace(
            b"zabc",
            &mut workspace,
            SearchLimits {
                max_work: exact_work - 1,
                max_scratch_bytes: retained,
            },
        )
        .unwrap_err();
    assert!(matches!(error, SearchError::WorkLimitExceeded { .. }));
}

#[test]
fn failed_calls_and_shape_compatible_plan_changes_cannot_expose_stale_slots() {
    let plan_a = literal(b"a");
    let plan_b = literal(b"b");
    assert_eq!(
        plan_a.workspace_layout().unwrap(),
        plan_b.workspace_layout().unwrap()
    );
    let mut workspace = K0Workspace::new(&plan_a, WorkspaceLimits::unlimited()).unwrap();

    let error = plan_a
        .prepare::<Span>()
        .search_with_workspace(
            b"aaaa",
            &mut workspace,
            SearchLimits {
                max_work: 5,
                max_scratch_bytes: usize::MAX,
            },
        )
        .unwrap_err();
    assert!(matches!(error, SearchError::WorkLimitExceeded { .. }));

    assert_eq!(
        plan_b
            .prepare::<Span>()
            .search_with_workspace(b"aaab", &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output(),
        Some(MatchSpan::new(3, 4))
    );
    assert_eq!(
        plan_a
            .prepare::<Span>()
            .search_with_workspace(b"bbbb", &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output(),
        None
    );
}

#[test]
fn incompatible_workspace_is_rejected_without_growth() {
    let small = literal(b"a");
    let large = literal(b"abcdef");
    let mut workspace = K0Workspace::new(&small, WorkspaceLimits::unlimited()).unwrap();
    let retained = workspace.retained_bytes();
    let error = large
        .prepare::<Span>()
        .search_with_workspace(b"abcdef", &mut workspace, SearchLimits::unlimited())
        .unwrap_err();
    assert!(matches!(error, SearchError::WorkspaceLayoutMismatch { .. }));
    assert_eq!(workspace.retained_bytes(), retained);
}

#[test]
fn invalid_windows_are_explicit_errors() {
    let error = literal(b"a")
        .prepare::<Span>()
        .search_window(b"abc", SearchWindow::new(2, 1), SearchLimits::unlimited())
        .unwrap_err();
    assert_eq!(
        error,
        SearchError::InvalidWindow {
            start: 2,
            end: 1,
            haystack_len: 3
        }
    );
}

#[test]
fn malformed_plans_are_rejected_at_the_boundary() {
    let empty = RawPlan {
        start: 0,
        roles: vec![],
        edge_offsets: vec![],
        edge_targets: vec![],
        edge_kinds: vec![],
        byte_starts: vec![],
        byte_ends: vec![],
    };
    assert_eq!(
        Automaton::from_raw(empty, CompileLimits::default()).unwrap_err(),
        CompileError::Malformed(MalformedPlan::EmptyStateTable)
    );

    let bad_target = raw(0, vec![consume(vec![Edge::byte(7, b'a')]), accept()]);
    assert!(matches!(
        Automaton::from_raw(bad_target, CompileLimits::default()),
        Err(CompileError::Malformed(MalformedPlan::TargetOutOfBounds {
            edge: 0,
            ..
        }))
    ));

    let wrong_kind = raw(0, vec![split(vec![Edge::byte(1, b'a')]), accept()]);
    assert!(matches!(
        Automaton::from_raw(wrong_kind, CompileLimits::default()),
        Err(CompileError::Malformed(MalformedPlan::EdgeKindForState {
            state: 0,
            edge: 0,
            ..
        }))
    ));

    let accept_edges = raw(
        0,
        vec![State {
            role: StateRole::Accept,
            edges: vec![Edge::epsilon(0)],
        }],
    );
    assert!(matches!(
        Automaton::from_raw(accept_edges, CompileLimits::default()),
        Err(CompileError::Malformed(MalformedPlan::AcceptHasEdges {
            state: 0,
            edges: 1
        }))
    ));

    let mut descending_range = raw(0, vec![consume(vec![Edge::byte(1, b'a')]), accept()]);
    descending_range.byte_starts[0] = b'z';
    assert!(matches!(
        Automaton::from_raw(descending_range, CompileLimits::default()),
        Err(CompileError::Malformed(MalformedPlan::InvalidByteRange {
            edge: 0,
            ..
        }))
    ));

    let no_accept = raw(0, vec![consume(vec![])]);
    assert_eq!(
        Automaton::from_raw(no_accept, CompileLimits::default()).unwrap_err(),
        CompileError::Malformed(MalformedPlan::MissingAcceptState)
    );
}

#[test]
fn compile_resources_are_checked_before_freezing() {
    let proposed = raw(0, vec![consume(vec![Edge::byte(1, b'a')]), accept()]);
    let error = Automaton::from_raw(
        proposed,
        CompileLimits {
            max_states: 1,
            ..CompileLimits::default()
        },
    )
    .unwrap_err();
    assert_eq!(
        error,
        CompileError::ResourceLimit {
            resource: ResourceKind::States,
            needed: 2,
            limit: 1
        }
    );
}

fn words(max_len: usize) -> Vec<Vec<u8>> {
    let mut result = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in frontier {
            for byte in [b'a', b'b'] {
                let mut word = prefix.clone();
                word.push(byte);
                result.push(word.clone());
                next.push(word);
            }
        }
        frontier = next;
    }
    result
}
