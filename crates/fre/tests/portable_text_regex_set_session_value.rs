#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableRegexSetExecutionError, PortableRegexSetRunLimits,
    PortableRegexSetSessionLimits, PortableTextProof, PortableTextRegexSet,
    PortableTextRegexSetBuilder, PortableTextRegexSetSearchSession, SearchLimits,
};

fn session(set: &PortableTextRegexSet) -> PortableTextRegexSetSearchSession<'_> {
    set.search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed text-set session")
}

#[test]
fn value_existence_matches_accounted_and_upstream_at_every_utf8_offset() {
    let patterns = ["!", "[a-z]+", "é", "東京", r"\bbar\b", r"(?m)^bar$"];
    let set = PortableTextRegexSet::new(patterns).expect("mixed text set");
    let upstream = regex::RegexSet::new(patterns).expect("upstream text set");
    let mut accounted = session(&set);
    let mut value = session(&set);
    let limits = PortableRegexSetRunLimits {
        max_output_matches: 0,
        max_output_bytes: 0,
        ..PortableRegexSetRunLimits::unlimited()
    };

    for haystack in ["", "!", "é\nbar\n東京", "🦀 none"] {
        for start in 0..=haystack.len() {
            let expected = upstream.is_match_at(haystack, start);
            let incumbent = accounted
                .is_match_at(haystack, start, limits)
                .unwrap_or_else(|error| panic!("accounted {haystack:?}/{start}: {error}"))
                .0;
            assert_eq!(incumbent, expected, "accounted {haystack:?}/{start}");
            assert_eq!(
                value
                    .is_match_value_at(haystack, start, limits)
                    .unwrap_or_else(|error| panic!("value {haystack:?}/{start}: {error}")),
                expected,
                "value {haystack:?}/{start}",
            );
        }
        assert_eq!(
            value
                .is_match_value(haystack, limits)
                .expect("whole-haystack value search"),
            upstream.is_match(haystack),
        );
    }

    let invalid = "é".len() + 1;
    assert_eq!(
        value
            .is_match_value_at("é", invalid, limits)
            .expect_err("invalid value start"),
        PortableRegexSetExecutionError::InvalidStart {
            start: invalid,
            haystack_len: "é".len(),
        },
    );
}

#[test]
fn value_existence_preserves_finite_cumulative_and_refusal_semantics() {
    let patterns = ["!", "[a-z]+", r"(?-u:[0-9]+)"];
    let set = PortableTextRegexSet::new(patterns).expect("finite-limit text set");
    let haystack = "東京";
    let unlimited = PortableRegexSetRunLimits::unlimited();
    let finite_success = PortableRegexSetRunLimits {
        max_total_work: u64::MAX - 1,
        ..unlimited
    };
    assert_eq!(
        session(&set)
            .is_match_value(haystack, finite_success)
            .expect("finite aggregate value search"),
        session(&set)
            .is_match(haystack, finite_success)
            .expect("finite aggregate accounted search")
            .0,
    );

    let zero_total = PortableRegexSetRunLimits {
        max_total_work: 0,
        ..unlimited
    };
    assert_eq!(
        session(&set)
            .is_match_value(haystack, zero_total)
            .expect_err("value aggregate work refusal"),
        session(&set)
            .is_match(haystack, zero_total)
            .expect_err("accounted aggregate work refusal"),
    );

    for pattern in [
        SearchLimits {
            max_work: 0,
            ..SearchLimits::unlimited()
        },
        SearchLimits {
            max_scratch_bytes: 0,
            ..SearchLimits::unlimited()
        },
    ] {
        let finite = PortableRegexSetRunLimits {
            pattern,
            ..unlimited
        };
        assert_eq!(
            session(&set)
                .is_match_value(haystack, finite)
                .expect_err("value constituent refusal"),
            session(&set)
                .is_match(haystack, finite)
                .expect_err("accounted constituent refusal"),
        );
    }

    let first_work = PortableTextRegexSet::new([patterns[0]])
        .expect("first-pattern singleton")
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("first-pattern session")
        .is_match(haystack, unlimited)
        .expect("first-pattern accounted search")
        .1
        .work;
    let exact_first = PortableRegexSetRunLimits {
        max_total_work: first_work,
        ..unlimited
    };
    assert_eq!(
        session(&set)
            .is_match_value(haystack, exact_first)
            .expect_err("value cumulative refusal"),
        session(&set)
            .is_match(haystack, exact_first)
            .expect_err("accounted cumulative refusal"),
    );
}

#[test]
fn value_existence_preserves_source_order_assertions_and_session_reuse() {
    let patterns = ["never", r"(?m)^(?:ab|cd)+Z$", "[a-z][0-9]"];
    let set = PortableTextRegexSet::new(patterns).expect("ordered assertion text set");
    let asserted = set.pattern_build_report(1).expect("asserted report");
    assert_eq!(asserted.portable.plan, PlanKind::K0);
    assert!(matches!(
        &asserted.proof,
        PortableTextProof::IdenticalUtf8Hir {
            has_look_assertions: true,
            ..
        }
    ));

    let upstream = regex::RegexSet::new(patterns).expect("upstream assertion text set");
    let mut accounted = session(&set);
    let mut value = session(&set);
    let limits = PortableRegexSetRunLimits::unlimited();
    for haystack in ["ababZ", "x\ncdZ\ny", "a7", "none", "cdZ", "a7"] {
        let expected = upstream.is_match(haystack);
        assert_eq!(
            accounted
                .is_match(haystack, limits)
                .expect("accounted alternating search")
                .0,
            expected,
        );
        assert_eq!(
            value
                .is_match_value(haystack, limits)
                .expect("value alternating search"),
            expected,
        );
    }

    let one_search = PortableRegexSetRunLimits {
        max_pattern_searches: 1,
        ..limits
    };
    assert_eq!(
        session(&set)
            .is_match_value("a7", one_search)
            .expect_err("value pattern-search refusal"),
        session(&set)
            .is_match("a7", one_search)
            .expect_err("accounted pattern-search refusal"),
    );
}

#[test]
fn compact_text_routes_preserve_every_interior_utf8_offset() {
    let patterns = [
        "東京",
        "é",
        r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]",
        r"\A[ab]+Z",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let set = PortableTextRegexSetBuilder::new(&patterns)
        .unicode(false)
        .build()
        .expect("all-non-K0 text set");
    let plans = (0..set.len())
        .map(|index| {
            set.pattern_build_report(index)
                .expect("text plan")
                .portable
                .plan
        })
        .collect::<Vec<_>>();
    assert!(
        plans.iter().all(|plan| *plan != PlanKind::K0),
        "unexpected text compact plans: {plans:?}"
    );
    assert!(plans.contains(&PlanKind::ExactLiteral));
    assert!(plans.contains(&PlanKind::FixedPredicateWord64));
    assert!(plans.contains(&PlanKind::ForwardAnchored));
    let upstream = regex::RegexSetBuilder::new(&patterns)
        .unicode(false)
        .build()
        .expect("upstream text set");
    let mut session = session(&set);
    assert!(session.setup_report().session_capacity_bytes > 0);
    assert_eq!(
        session.setup_report().charged_retained_bytes,
        session.setup_report().session_capacity_bytes
    );
    let unlimited = PortableRegexSetRunLimits::unlimited();
    let finite = PortableRegexSetRunLimits {
        max_total_work: u64::MAX - 1,
        ..unlimited
    };
    let haystack = "ababZxé\n東京y--Qacegikmortvx0--";

    for start in 0..=haystack.len() {
        let expected_ids = upstream
            .matches_at(haystack, start)
            .into_iter()
            .collect::<Vec<_>>();
        let actual = session
            .matches_at(haystack, start, unlimited)
            .unwrap_or_else(|error| panic!("matches offset {start}: {error}"));
        assert_eq!(
            actual.iter().collect::<Vec<_>>(),
            expected_ids,
            "start {start}"
        );
        assert_eq!(actual.report().start, start);

        let expected = upstream.is_match_at(haystack, start);
        let (accounted, report) = session
            .is_match_at(haystack, start, unlimited)
            .unwrap_or_else(|error| panic!("accounted offset {start}: {error}"));
        assert_eq!(accounted, expected, "start {start}");
        assert_eq!(report.start, start);
        assert_eq!(
            session
                .is_match_value_at(haystack, start, unlimited)
                .unwrap_or_else(|error| panic!("value offset {start}: {error}")),
            expected,
            "start {start}",
        );
        assert_eq!(
            session.is_match_value_at(haystack, start, finite),
            set.is_match_at(haystack, start, finite)
                .map(|(matched, _report)| matched),
            "finite start {start}",
        );

        let mut flags = vec![false; patterns.len() + 1];
        flags[patterns.len()] = true;
        let any = session
            .matches_read_at_value_unlimited(&mut flags, haystack, start)
            .unwrap_or_else(|error| panic!("caller flags offset {start}: {error}"));
        assert_eq!(any, !expected_ids.is_empty(), "start {start}");
        for index in 0..patterns.len() {
            assert_eq!(flags[index], expected_ids.contains(&index), "start {start}");
        }
        assert!(flags[patterns.len()]);
    }
}
