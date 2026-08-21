#![forbid(unsafe_code)]

use fre::{
    PlanKind, PlanSelection, PortableTextBuilder, PortableTextRegex, SearchLimits,
    SearchSessionLimits,
};

fn assert_same_debug<T: core::fmt::Debug, E: core::fmt::Debug>(
    left: &Result<T, E>,
    right: &Result<T, E>,
) {
    assert_eq!(format!("{left:?}"), format!("{right:?}"));
}

#[test]
fn text_session_shortest_values_match_immutable_results_at_every_byte_start() {
    let cases = [
        (
            PortableTextBuilder::new(r"(?:αβ|γδ)+Z")
                .plan_selection(PlanSelection::ForceK0)
                .build()
                .expect("forced K0 Unicode alternation"),
            PlanKind::K0,
            "☃αβγδαβZx",
        ),
        (
            PortableTextBuilder::new(r"(?:[A-Za-z0-9_]{2,8}:)+END")
                .plan_selection(PlanSelection::ForceK0)
                .build()
                .expect("forced K0 class suffix"),
            PlanKind::K0,
            "☃ab:CD:xy_9:END--",
        ),
        (
            PortableTextRegex::new("東京").expect("exact text literal"),
            PlanKind::ExactLiteral,
            "☃xx東京yy",
        ),
        (
            PortableTextRegex::new(r"\b\w{2,}\b").expect("Unicode word run"),
            PlanKind::UnicodeWordRun,
            "☃ rust 東京",
        ),
        (
            PortableTextBuilder::new("(?:a*)*")
                .plan_selection(PlanSelection::ForceK0)
                .build()
                .expect("nullable K0"),
            PlanKind::K0,
            "☃bbb",
        ),
    ];

    for (regex, expected_plan, haystack) in cases {
        assert_eq!(regex.build_report().portable.plan, expected_plan);
        let mut session = regex
            .fixed_search_session(SearchSessionLimits::unlimited())
            .expect("fixed text session");
        session
            .prepare_k0_start_filter(SearchSessionLimits::unlimited())
            .expect("optional K0 proof");
        assert_eq!(
            regex
                .shortest_match_value(haystack, SearchLimits::unlimited())
                .expect("immutable full shortest"),
            session
                .shortest_match_value(haystack, SearchLimits::unlimited())
                .expect("session full shortest"),
        );
        for start in 0..=haystack.len() + 1 {
            let immutable =
                regex.shortest_match_at_value(haystack, start, SearchLimits::unlimited());
            let reusable =
                session.shortest_match_at_value(haystack, start, SearchLimits::unlimited());
            assert_same_debug(&immutable, &reusable);
            if let Ok(Some(end)) = reusable {
                assert!(haystack.is_char_boundary(end));
            }
        }
    }
}

#[test]
fn text_session_shortest_values_preserve_limits_context_and_recovery() {
    let regex = PortableTextBuilder::new(r"(?:αβ|γδ)+Z")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("forced K0 text regex");
    let mut session = regex
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("fixed text session");
    session
        .prepare_k0_start_filter(SearchSessionLimits::unlimited())
        .expect("optional K0 proof");
    let haystack = "☃αβγδαβZx";
    let expected = regex
        .shortest_match_value(haystack, SearchLimits::unlimited())
        .unwrap();

    let finite = SearchLimits {
        max_work: u64::MAX - 1,
        max_scratch_bytes: usize::MAX,
    };
    assert_eq!(
        session
            .shortest_match_value(haystack, finite)
            .expect("finite incumbent route"),
        expected,
    );
    assert!(
        session
            .shortest_match_value(
                haystack,
                SearchLimits {
                    max_work: 0,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .is_err()
    );
    assert_eq!(
        session
            .shortest_match_value(haystack, SearchLimits::unlimited())
            .expect("recovery after refusal"),
        expected,
    );

    let contextual = PortableTextBuilder::new(r"\bchew\b")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("contextual K0 text regex");
    let mut contextual_session = contextual
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("contextual session");
    assert_eq!(
        contextual_session
            .shortest_match_at_value("eschew", 2, SearchLimits::unlimited())
            .unwrap(),
        None,
    );

    let greedy = PortableTextBuilder::new("a+")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("greedy K0 text regex");
    let mut greedy_session = greedy
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("greedy session");
    assert_eq!(
        greedy_session
            .shortest_match_value("aaaaa", SearchLimits::unlimited())
            .unwrap(),
        Some(1),
    );
    assert_eq!(greedy.find("aaaaa").map(|matched| matched.end()), Some(5));
}
