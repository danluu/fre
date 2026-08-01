#![forbid(unsafe_code)]

use fre_automata::{
    Automaton, CompileLimits, EdgeKind, K0Workspace, MatchSpan, RawPlan, SearchLimits, SelectedEnd,
    Span, StateRole, WorkspaceLimits,
};

const ROOT_START: u8 = 0x20;
const ROOT_END: u8 = 0x60;
const SUFFIX_START: u8 = 0x80;
const SUFFIX_END: u8 = 0xff;

fn range_then_range() -> Automaton {
    let root = (ROOT_START..=ROOT_END).collect::<Vec<_>>();
    let root_edges = u32::try_from(root.len()).expect("small root class");
    let edge_count = root_edges.checked_add(1).expect("small edge count");
    Automaton::from_raw(
        RawPlan {
            start: 0,
            roles: vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
            edge_offsets: vec![0, root_edges, edge_count, edge_count],
            edge_targets: root.iter().map(|_| 1).chain(core::iter::once(2)).collect(),
            edge_kinds: vec![EdgeKind::ByteRange; usize::try_from(edge_count).unwrap()],
            byte_starts: root
                .iter()
                .copied()
                .chain(core::iter::once(SUFFIX_START))
                .collect(),
            byte_ends: root
                .into_iter()
                .chain(core::iter::once(SUFFIX_END))
                .collect(),
        },
        CompileLimits::default(),
    )
    .expect("valid range-pair automaton")
}

fn restart_source() -> [u8; 32] {
    let mut source = [0_u8; 32];
    for candidate in [16_usize, 20, 24, 28] {
        source[candidate] = 0x40;
    }
    source[29] = SUFFIX_START;
    source
}

fn scalar_first(source: &[u8], start: usize, end: usize) -> Option<MatchSpan> {
    if start > end || end > source.len() {
        return None;
    }
    (start..end).find_map(|at| {
        let next = at.checked_add(1)?;
        if next < end
            && (ROOT_START..=ROOT_END).contains(&source[at])
            && (SUFFIX_START..=SUFFIX_END).contains(&source[next])
        {
            Some(MatchSpan::new(at, next + 1))
        } else {
            None
        }
    })
}

#[test]
fn exact_parent_and_candidate_publish_comparable_warm_restart_work() {
    let plan = range_then_range();
    let source = restart_source();
    let expected = scalar_first(&source, 0, source.len());
    assert_eq!(expected, Some(MatchSpan::new(28, 30)));

    let mut accelerated =
        K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
    let retained = accelerated.retained_bytes();
    let cold = plan
        .prepare::<SelectedEnd>()
        .search_with_workspace(&source, &mut accelerated, SearchLimits::unlimited())
        .unwrap();
    assert_eq!(cold.into_output(), expected.map(MatchSpan::end));
    let warm = plan
        .prepare::<SelectedEnd>()
        .search_with_workspace(&source, &mut accelerated, SearchLimits::unlimited())
        .unwrap();
    assert_eq!(*warm.output(), expected.map(MatchSpan::end));
    assert_eq!(warm.accounting().scratch_bytes(), retained);
    eprintln!("K0_RETAINED_RANGE_WARM_WORK={}", warm.accounting().work());

    let mut bidirectional =
        K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
    let cold_span = plan
        .prepare::<Span>()
        .search_with_workspace(&source, &mut bidirectional, SearchLimits::unlimited())
        .unwrap();
    assert_eq!(cold_span.output(), &expected);
    let warm_span = plan
        .prepare::<Span>()
        .search_with_workspace(&source, &mut bidirectional, SearchLimits::unlimited())
        .unwrap();
    assert_eq!(warm_span.output(), &expected);
    eprintln!(
        "K0_RETAINED_RANGE_BIDIRECTIONAL_SPAN_WARM_WORK={}",
        warm_span.accounting().work()
    );

    let mut ordinary = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
    let fallback = plan
        .prepare::<Span>()
        .search_with_workspace(&source, &mut ordinary, SearchLimits::unlimited())
        .unwrap();
    assert_eq!(fallback.into_output(), expected);
    eprintln!(
        "K0_RETAINED_RANGE_ORDINARY_WORK={}",
        plan.prepare::<Span>()
            .search_with_workspace(&source, &mut ordinary, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work()
    );
}
