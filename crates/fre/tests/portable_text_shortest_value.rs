#![forbid(unsafe_code)]

use fre::{PlanKind, PlanSelection, PortableTextBuilder, PortableTextRegex, SearchLimits};

fn assert_same_debug<T: core::fmt::Debug, E: core::fmt::Debug>(
    left: &Result<T, E>,
    right: &Result<T, E>,
) {
    assert_eq!(format!("{left:?}"), format!("{right:?}"));
}

#[test]
fn text_shortest_values_match_accounted_results_at_every_byte_start() {
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
        assert_eq!(
            regex
                .shortest_match(haystack, SearchLimits::unlimited())
                .expect("accounted full shortest")
                .0,
            regex
                .shortest_match_value(haystack, SearchLimits::unlimited())
                .expect("value full shortest"),
        );
        for start in 0..=haystack.len() + 1 {
            let accounted = regex
                .shortest_match_at(haystack, start, SearchLimits::unlimited())
                .map(|(end, _accounting)| end);
            let value = regex.shortest_match_at_value(haystack, start, SearchLimits::unlimited());
            assert_same_debug(&accounted, &value);
            if let Ok(Some(end)) = value {
                assert!(haystack.is_char_boundary(end));
            }
        }
    }
}

#[test]
fn text_shortest_values_preserve_earliest_end_and_assertion_context() {
    let greedy = PortableTextBuilder::new("a+")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("greedy K0 text regex");
    assert_eq!(
        greedy
            .shortest_match_value("aaaaa", SearchLimits::unlimited())
            .unwrap(),
        Some(1),
    );
    assert_eq!(greedy.find("aaaaa").map(|matched| matched.end()), Some(5));

    let contextual = PortableTextBuilder::new(r"\bchew\b")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("contextual K0 text regex");
    assert_eq!(
        contextual
            .shortest_match_at_value("eschew", 2, SearchLimits::unlimited())
            .unwrap(),
        None,
    );

    let scalar = PortableTextRegex::new("αβ").expect("exact scalar literal");
    for interior_start in [1, 2] {
        assert_eq!(
            scalar
                .shortest_match_at_value("☃αβ", interior_start, SearchLimits::unlimited())
                .unwrap(),
            Some("☃αβ".len()),
        );
    }
}

#[test]
fn text_shortest_values_preserve_exact_work_and_refusal_errors() {
    let cases = [
        PortableTextBuilder::new(r"(?:αβ|γδ)+Z")
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .expect("forced K0 text regex"),
        PortableTextRegex::new("東京").expect("exact text literal"),
    ];
    let haystacks = ["xαβγδαβZy", "xx東京yy"];

    for (regex, haystack) in cases.into_iter().zip(haystacks) {
        let (expected, accounting) = regex
            .shortest_match(haystack, SearchLimits::unlimited())
            .expect("unlimited accounted shortest");
        let work = accounting.work_or_linear_terms();
        assert!(work > 0);
        let exact = SearchLimits {
            max_work: work,
            max_scratch_bytes: usize::MAX,
        };
        assert_eq!(
            regex
                .shortest_match(haystack, exact)
                .expect("exact accounted shortest")
                .0,
            expected,
        );
        assert_eq!(
            regex
                .shortest_match_value(haystack, exact)
                .expect("exact value shortest"),
            expected,
        );

        let refused = SearchLimits {
            max_work: 0,
            max_scratch_bytes: usize::MAX,
        };
        let accounted = regex
            .shortest_match(haystack, refused)
            .map(|(end, _accounting)| end);
        let value = regex.shortest_match_value(haystack, refused);
        assert!(accounted.is_err());
        assert_same_debug(&accounted, &value);
    }
}
