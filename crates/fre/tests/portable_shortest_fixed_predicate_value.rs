#![forbid(unsafe_code)]

use fre::{PlanKind, PortableBuilder, PortableRegex, SearchAccounting, SearchError, SearchLimits};

const ONE_ANCHOR_PATTERN: &str = r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]";
const GENERAL_PAIR_PATTERN: &str = r"[abc][def][ghi][jkl][mno][pqr][stu][vwx]";

fn fixed(pattern: &str) -> PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("fixed-predicate fixture failed: {error:?}"));
    assert_eq!(regex.build_report().plan, PlanKind::FixedPredicateWord64);
    regex
}

fn assert_fixed_work_error(error: SearchError) {
    assert!(matches!(
        error,
        SearchError::FixedPredicateWord64(fre::FixedPredicateWord64SearchError::WorkLimit { .. })
    ));
}

#[test]
fn fixed_predicate_shortest_values_match_accounted_results_at_every_boundary() {
    for (pattern, haystack) in [
        (ONE_ANCHOR_PATTERN, b"--Qacegikmortvx0--".as_slice()),
        (GENERAL_PAIR_PATTERN, b"xxxxxxxadgjmpsv--".as_slice()),
    ] {
        let regex = fixed(pattern);
        let limits = SearchLimits::unlimited();
        assert_eq!(
            regex.shortest_match_value(haystack, limits).unwrap(),
            regex.shortest_match(haystack, limits).unwrap().0,
            "full search pattern={pattern:?}",
        );
        for start in 0..=haystack.len() {
            let accounted = regex.shortest_match_at(haystack, start, limits).unwrap().0;
            assert_eq!(
                regex
                    .shortest_match_at_value(haystack, start, limits)
                    .unwrap(),
                accounted,
                "pattern={pattern:?}, start={start}",
            );
            assert_eq!(
                regex
                    .find_window_value(
                        haystack,
                        fre::SearchWindow::new(start, haystack.len()),
                        limits,
                    )
                    .unwrap()
                    .map(fre::Match::end),
                accounted,
                "fixed-width selected span and earliest end diverged pattern={pattern:?}, start={start}",
            );
        }

        let invalid_start = haystack.len() + 1;
        assert_eq!(
            regex
                .shortest_match_at_value(haystack, invalid_start, limits)
                .unwrap_err(),
            regex
                .shortest_match_at(haystack, invalid_start, limits)
                .unwrap_err(),
            "invalid range error changed for pattern={pattern:?}",
        );
    }
}

#[test]
fn ordinary_fixed_predicate_endpoints_match_immutable_values_at_every_boundary() {
    for (pattern, haystack) in [
        (ONE_ANCHOR_PATTERN, b"--Qacegikmortvx0--".as_slice()),
        (GENERAL_PAIR_PATTERN, b"xxxxxxxadgjmpsv--".as_slice()),
    ] {
        let regex = fixed(pattern);
        let mut ordinary = regex.ordinary_session().unwrap();
        for start in 0..=haystack.len() {
            let expected = regex
                .shortest_match_at_value(haystack, start, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(
                ordinary.first_acceptance_at(haystack, start),
                Ok(expected),
                "endpoint pattern={pattern:?}, start={start}",
            );
            assert_eq!(
                ordinary.is_match_at(haystack, start),
                Ok(expected.is_some()),
                "existence pattern={pattern:?}, start={start}",
            );
        }

        let invalid_start = haystack.len() + 1;
        assert_eq!(
            ordinary
                .first_acceptance_at(haystack, invalid_start)
                .unwrap_err(),
            regex
                .shortest_match_at_value(haystack, invalid_start, SearchLimits::unlimited(),)
                .unwrap_err(),
            "invalid range error changed for pattern={pattern:?}",
        );
    }
}

#[test]
fn fixed_predicate_shortest_value_closes_at_exact_work_with_zero_scratch() {
    let regex = fixed(ONE_ANCHOR_PATTERN);
    for haystack in [
        b"---Qacegikmortvx0---".as_slice(),
        b"--------------------".as_slice(),
    ] {
        let (expected, accounting) = regex
            .shortest_match(haystack, SearchLimits::unlimited())
            .unwrap();
        let SearchAccounting::FixedPredicateWord64(accounting) = accounting else {
            panic!("fixed-predicate shortest search published another accounting family");
        };
        assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
        assert!(accounting.upper_bounds.work > 0);

        let exact = SearchLimits {
            max_work: accounting.upper_bounds.work,
            max_scratch_bytes: 0,
        };
        assert_eq!(
            regex.shortest_match_value(haystack, exact).unwrap(),
            expected,
        );
        assert_eq!(regex.shortest_match(haystack, exact).unwrap().0, expected);

        let one_below = SearchLimits {
            max_work: accounting.upper_bounds.work - 1,
            max_scratch_bytes: 0,
        };
        let value_error = regex.shortest_match_value(haystack, one_below).unwrap_err();
        let accounted_error = regex.shortest_match(haystack, one_below).unwrap_err();
        assert_eq!(value_error, accounted_error);
        assert_fixed_work_error(value_error);
    }
}

#[test]
fn fixed_predicate_shortest_value_preserves_first_end_and_ranged_order() {
    let regex = fixed(ONE_ANCHOR_PATTERN);
    let haystack = b"Qacegikmortvx0-Qacegikmortvx1";
    let limits = SearchLimits::unlimited();

    assert_eq!(
        regex.shortest_match_value(haystack, limits).unwrap(),
        Some(14),
    );
    assert_eq!(
        regex.shortest_match_at_value(haystack, 1, limits).unwrap(),
        Some(29),
    );
    assert_eq!(
        regex.shortest_match_at_value(haystack, 15, limits).unwrap(),
        Some(29),
    );
    assert_eq!(
        regex.shortest_match_at_value(haystack, 16, limits).unwrap(),
        None,
    );
}
