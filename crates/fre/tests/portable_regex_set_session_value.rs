#![forbid(unsafe_code)]

use fre::{
    PlanKind, PortableRegexSet, PortableRegexSetBuilder, PortableRegexSetExecutionError,
    PortableRegexSetRunLimits, PortableRegexSetSearchSession, PortableRegexSetSessionLimits,
    SearchLimits,
};

const PATTERNS: [&str; 3] = ["!", "[a-z]+", r"(?-u:[0-9]+)"];

fn session(set: &PortableRegexSet) -> PortableRegexSetSearchSession<'_> {
    set.search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed set session")
}

#[test]
fn value_existence_matches_accounted_source_order_and_ranges() {
    let set = PortableRegexSet::new(PATTERNS).expect("mixed-plan set");
    let mut accounted = session(&set);
    let mut value = session(&set);
    let limits = PortableRegexSetRunLimits {
        max_output_matches: 0,
        max_output_bytes: 0,
        ..PortableRegexSetRunLimits::unlimited()
    };
    let cases: &[(&[u8], usize, bool)] = &[
        (b"!", 0, true),
        (b"abc", 0, true),
        (b"123", 0, true),
        (b"\xFF", 0, false),
        (b"!abc123", 1, true),
        (b"!abc123", 4, true),
        (b"!abc123", 7, false),
    ];
    for &(haystack, start, expected) in cases {
        let incumbent = accounted
            .is_match_at(haystack, start, limits)
            .expect("accounted set search")
            .0;
        assert_eq!(incumbent, expected);
        assert_eq!(
            value
                .is_match_value_at(haystack, start, limits)
                .expect("value set search"),
            incumbent,
        );
        if start == 0 {
            assert_eq!(
                value
                    .is_match_value(haystack, limits)
                    .expect("full value set search"),
                incumbent,
            );
        }
    }

    let invalid = PATTERNS.len() + b"short".len();
    assert_eq!(
        value
            .is_match_value_at(b"short", invalid, limits)
            .expect_err("invalid value start"),
        PortableRegexSetExecutionError::InvalidStart {
            start: invalid,
            haystack_len: b"short".len(),
        },
    );
}

#[test]
fn value_existence_preserves_finite_refusals_and_pattern_search_limits() {
    let set = PortableRegexSet::new(PATTERNS).expect("mixed-plan set");
    let haystack = b"\xFF";
    let unlimited = PortableRegexSetRunLimits::unlimited();
    let finite_success = PortableRegexSetRunLimits {
        max_total_work: u64::MAX - 1,
        ..unlimited
    };
    assert_eq!(
        session(&set)
            .is_match_value(haystack, finite_success)
            .expect("finite aggregate work"),
        session(&set)
            .is_match(haystack, finite_success)
            .expect("accounted finite aggregate work")
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

    let ordered = PortableRegexSet::new(["z", "[a-z][0-9]", "q"]).expect("ordered mixed-plan set");
    let one_search = PortableRegexSetRunLimits {
        max_pattern_searches: 1,
        ..unlimited
    };
    assert_eq!(
        session(&ordered)
            .is_match_value(b"a7", one_search)
            .expect_err("value pattern-search refusal"),
        session(&ordered)
            .is_match(b"a7", one_search)
            .expect_err("accounted pattern-search refusal"),
    );
}

#[test]
fn compact_exact_fixed_and_native_routes_match_upstream_at_every_offset() {
    let patterns = [
        "needle",
        r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]",
        r"\A[ab]+Z",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let set = PortableRegexSetBuilder::new(&patterns)
        .unicode(false)
        .build()
        .expect("all-non-K0 byte set");
    let plans = (0..set.len())
        .map(|index| set.pattern_build_report(index).expect("byte plan").plan)
        .collect::<Vec<_>>();
    assert!(plans.iter().all(|plan| *plan != PlanKind::K0));
    assert!(plans.contains(&PlanKind::ExactLiteral));
    assert!(plans.contains(&PlanKind::FixedPredicateWord64));
    assert!(plans.contains(&PlanKind::ForwardAnchored));

    let upstream = regex::bytes::RegexSetBuilder::new(&patterns)
        .unicode(false)
        .build()
        .expect("upstream byte set");
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

    for haystack in [
        b"".as_slice(),
        b"xxneedle",
        b"--Qacegikmortvx0--",
        b"ababZtail",
        b"\xFFnone",
    ] {
        for start in 0..=haystack.len() {
            let expected_ids = upstream
                .matches_at(haystack, start)
                .into_iter()
                .collect::<Vec<_>>();
            let actual = session
                .matches_at(haystack, start, unlimited)
                .unwrap_or_else(|error| panic!("matches {haystack:?}/{start}: {error}"));
            assert_eq!(actual.iter().collect::<Vec<_>>(), expected_ids);
            assert_eq!(actual.report().start, start);

            let expected = upstream.is_match_at(haystack, start);
            let (accounted, report) = session
                .is_match_at(haystack, start, unlimited)
                .unwrap_or_else(|error| panic!("accounted {haystack:?}/{start}: {error}"));
            assert_eq!(accounted, expected);
            assert_eq!(report.start, start);
            assert_eq!(
                session
                    .is_match_value_at(haystack, start, unlimited)
                    .unwrap_or_else(|error| panic!("value {haystack:?}/{start}: {error}")),
                expected,
            );
            assert_eq!(
                session.is_match_value_at(haystack, start, finite),
                set.is_match_at(haystack, start, finite)
                    .map(|(matched, _report)| matched),
            );
        }
    }
}
