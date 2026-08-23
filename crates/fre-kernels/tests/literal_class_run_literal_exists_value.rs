#![allow(
    clippy::arithmetic_side_effects,
    reason = "exhaustive generators are bounded to small test inputs"
)]

use fre_kernels::{
    LiteralClassRunLiteralBuildLimits as BuildLimits, LiteralClassRunLiteralPlan,
    LiteralClassRunLiteralSearchLimits as SearchLimits, Window,
};

fn plan(prefix: &[u8], ranges: &[(u8, u8)], suffix: &[u8]) -> LiteralClassRunLiteralPlan {
    LiteralClassRunLiteralPlan::build(
        prefix,
        ranges.iter().copied(),
        suffix,
        BuildLimits::unlimited(),
    )
    .unwrap()
}

fn byte_strings(maximum_length: usize, alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..maximum_length {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                all.push(value.clone());
                next.push(value);
            }
        }
        frontier = next;
    }
    all
}

#[test]
fn existence_values_match_accounted_search_for_every_small_window() {
    let plans = [
        plan(b"p", &[(b'x', b'y')], b"q"),
        plan(b"p", &[(b'x', b'y')], b"qq"),
        plan(b"p", &[(b'x', b'y')], b""),
        plan(b"", &[(b'x', b'y')], b"q"),
    ];
    for haystack in byte_strings(4, b"pqxy\xff") {
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let window = Window::new(start, end);
                for candidate in &plans {
                    let expected = candidate
                        .shortest_window(&haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .0
                        .is_some();
                    assert_eq!(
                        candidate
                            .is_match_window_value(&haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected,
                        "haystack={haystack:?} window={start}..{end}"
                    );
                }
            }
        }
    }
}

#[test]
fn ordinary_full_values_match_incumbent_for_every_resolved_geometry() {
    let guarded = LiteralClassRunLiteralPlan::build_complete_ascii_word_run(
        b"",
        [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')].into_iter(),
        b"nn",
        BuildLimits::unlimited(),
    )
    .unwrap();
    let plans = [
        (plan(b"pp", &[(b'x', b'y')], b"q"), b"pqxy!".as_slice()),
        (plan(b"p", &[(b'x', b'y')], b"qq"), b"pqxy!".as_slice()),
        (plan(b"", &[(b'a', b'b')], b"aba"), b"ab!".as_slice()),
        (guarded, b"an_!".as_slice()),
    ];
    for (candidate, alphabet) in plans {
        for haystack in byte_strings(6, alphabet) {
            let expected_span = candidate
                .find(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0;
            let expected_exists = candidate
                .shortest(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0
                .is_some();
            assert_eq!(
                candidate.is_match_full_ordinary_value(&haystack).unwrap(),
                expected_exists,
                "haystack={haystack:?}"
            );
            assert_eq!(
                candidate.find_full_ordinary_value(&haystack).unwrap(),
                expected_span,
                "haystack={haystack:?}"
            );
        }
    }
}

#[test]
fn ordinary_full_find_matches_incumbent_for_every_resolved_geometry() {
    let guarded = LiteralClassRunLiteralPlan::build_complete_ascii_word_run(
        b"",
        [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')].into_iter(),
        b"nn",
        BuildLimits::unlimited(),
    )
    .unwrap();
    let plans = [
        (plan(b"pp", &[(b'x', b'y')], b"q"), b"pqxy!".as_slice()),
        (plan(b"p", &[(b'x', b'y')], b"qq"), b"pqxy!".as_slice()),
        (plan(b"", &[(b'a', b'b')], b"aba"), b"ab!".as_slice()),
        (guarded, b"an_!".as_slice()),
    ];
    for (candidate, alphabet) in plans {
        for haystack in byte_strings(6, alphabet) {
            let expected = candidate
                .find(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(
                candidate.find_full_ordinary_value(&haystack).unwrap(),
                expected,
                "haystack={haystack:?}",
            );
        }
    }
}

#[test]
fn ordinary_full_find_retries_overlapping_general_suffix_after_rejection() {
    let candidate = plan(b"", &[(b'y', b'y')], b"xyx");
    let haystack = b"xyxyx";
    let expected = Some((1, 5));

    assert_eq!(
        candidate.find_full_ordinary_value(haystack).unwrap(),
        expected,
    );
    assert_eq!(
        candidate
            .find(haystack, SearchLimits::unlimited())
            .unwrap()
            .0,
        expected,
    );
}

#[test]
fn existence_values_preserve_finite_refusal_invalid_and_fallback_contracts() {
    let candidate = plan(b"aa", &[(b'0', b'1')], b"QZ");
    let haystack = b"!aa0101QZ!aa001QZ!";
    let window = Window::full(haystack);
    let (expected, accounting) = candidate
        .shortest_window(haystack, window, SearchLimits::unlimited())
        .unwrap();
    assert!(expected.is_some());
    assert!(accounting.work > 0);
    assert!(accounting.candidate_visits > 0);
    let exact = SearchLimits {
        max_work_upper_bound: u64::try_from(accounting.work).unwrap(),
        max_candidate_visits: accounting.candidate_visits,
        max_scratch_bytes: accounting.scratch_bytes,
    };
    let work_refusal = SearchLimits {
        max_work_upper_bound: exact.max_work_upper_bound - 1,
        ..exact
    };
    let candidate_refusal = SearchLimits {
        max_candidate_visits: exact.max_candidate_visits - 1,
        ..exact
    };
    let custom = SearchLimits {
        max_work_upper_bound: u64::MAX,
        max_candidate_visits: usize::MAX,
        max_scratch_bytes: 0,
    };

    for limits in [exact, custom] {
        assert_eq!(
            candidate
                .is_match_window_value(haystack, window, limits)
                .unwrap(),
            candidate
                .shortest_window(haystack, window, limits)
                .unwrap()
                .0
                .is_some()
        );
    }
    for limits in [work_refusal, candidate_refusal] {
        assert_eq!(
            candidate
                .is_match_window_value(haystack, window, limits)
                .unwrap_err(),
            candidate
                .shortest_window(haystack, window, limits)
                .unwrap_err()
        );
    }
    for invalid in [
        Window::new(haystack.len(), haystack.len() - 1),
        Window::new(0, haystack.len() + 1),
    ] {
        assert_eq!(
            candidate
                .is_match_window_value(haystack, invalid, SearchLimits::unlimited())
                .unwrap_err(),
            candidate
                .shortest_window(haystack, invalid, SearchLimits::unlimited())
                .unwrap_err()
        );
    }

    let inside = plan(b"", &[(b'a', b'b')], b"aba");
    let inside_haystack = b"!aababa!";
    assert_eq!(
        inside
            .is_match_window_value(
                inside_haystack,
                Window::full(inside_haystack),
                SearchLimits::unlimited(),
            )
            .unwrap(),
        inside
            .shortest_window(
                inside_haystack,
                Window::full(inside_haystack),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0
            .is_some()
    );

    let guarded = LiteralClassRunLiteralPlan::build_complete_ascii_word_run(
        b"",
        [(b'0', b'9'), (b'A', b'Z'), (b'_', b'_'), (b'a', b'z')].into_iter(),
        b"ing",
        BuildLimits::unlimited(),
    )
    .unwrap();
    let guarded_haystack = b"!testing!";
    for guarded_window in [Window::full(guarded_haystack), Window::new(1, 8)] {
        assert_eq!(
            guarded
                .is_match_window_value(guarded_haystack, guarded_window, SearchLimits::unlimited(),)
                .unwrap(),
            guarded
                .shortest_window(guarded_haystack, guarded_window, SearchLimits::unlimited(),)
                .unwrap()
                .0
                .is_some()
        );
    }
}
