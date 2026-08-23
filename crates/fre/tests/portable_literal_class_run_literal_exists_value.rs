#![allow(
    clippy::arithmetic_side_effects,
    reason = "exhaustive generators are bounded to small test inputs"
)]

use fre::{
    LITERAL_CLASS_RUN_LITERAL_PLAN_ID, PlanKind, PortableBuilder, PortableTextRegex,
    SearchAccounting, SearchLimits, SearchSessionLimits, SearchWindow,
};

fn portable(pattern: &str) -> fre::PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"));
    assert_eq!(
        regex.build_report().plan,
        PlanKind::LiteralClassRunLiteral,
        "pattern={pattern:?}"
    );
    assert_eq!(
        regex.runtime_implementation_id(),
        LITERAL_CLASS_RUN_LITERAL_PLAN_ID
    );
    regex
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
fn literal_class_run_existence_values_match_every_window_and_session() {
    for (pattern, alphabet, maximum_length) in [
        (r"ab[xy]+cd", b"abcdxy\xff".as_slice(), 5),
        (r"a[xy]+bbbb", b"abxy\xff".as_slice(), 6),
        (r"item[0-2]+", b"item0\xff".as_slice(), 5),
    ] {
        let regex = portable(pattern);
        let clone = regex.clone();
        let mut session = clone
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        for haystack in byte_strings(maximum_length, alphabet) {
            let full = SearchWindow::full(&haystack);
            let expected_full = regex
                .is_match_window(&haystack, full, SearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(
                regex.is_match(&haystack),
                expected_full,
                "ordinary pattern={pattern:?} haystack={haystack:?}"
            );
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = regex
                        .is_match_window(&haystack, window, SearchLimits::unlimited())
                        .unwrap()
                        .0;
                    assert_eq!(
                        regex
                            .is_match_window_value(&haystack, window, SearchLimits::unlimited(),)
                            .unwrap(),
                        expected,
                        "immutable pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                    );
                    assert_eq!(
                        session
                            .is_match_window_value(&haystack, window, SearchLimits::unlimited(),)
                            .unwrap(),
                        expected,
                        "session pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                    );
                }
            }
        }
    }
}

#[test]
fn complete_ascii_word_ordinary_values_match_accounted_search_exhaustively() {
    let regex = portable(r"\b\w+nn\b");
    for haystack in byte_strings(6, b"an_!\xff") {
        let (expected, accounting) = regex
            .find_accounted(&haystack, SearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            accounting,
            SearchAccounting::LiteralClassRunLiteral(_)
        ));
        assert_eq!(
            regex.find(&haystack),
            expected,
            "ordinary find haystack={haystack:?}"
        );
        assert_eq!(
            regex.is_match(&haystack),
            expected.is_some(),
            "ordinary is_match haystack={haystack:?}"
        );
        assert_eq!(
            regex
                .find_value(&haystack, SearchLimits::unlimited())
                .unwrap(),
            expected,
            "finite value haystack={haystack:?}"
        );
    }
}

#[test]
fn literal_class_run_existence_values_preserve_resources_errors_and_fallbacks() {
    let regex = portable(r"aa[01]+QZ");
    let haystack = b"!aa0101QZ!aa001QZ!";
    let window = SearchWindow::full(haystack);
    let (expected, accounting) = regex
        .is_match_window(haystack, window, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
        panic!("literal/class-run fixture published another accounting family");
    };
    assert!(accounting.work > 0);
    let exact = SearchLimits {
        max_work: u64::try_from(accounting.work).unwrap(),
        max_scratch_bytes: accounting.scratch_bytes,
    };
    let refusing = SearchLimits {
        max_work: exact.max_work - 1,
        ..exact
    };
    let custom = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: 0,
    };
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();

    assert_eq!(
        regex
            .is_match_window_value(haystack, window, SearchLimits::unlimited())
            .unwrap(),
        expected
    );
    assert_eq!(
        session
            .is_match_window_value(haystack, window, SearchLimits::unlimited())
            .unwrap(),
        expected
    );
    for limits in [exact, custom] {
        assert_eq!(
            regex
                .is_match_window_value(haystack, window, limits)
                .unwrap(),
            regex.is_match_window(haystack, window, limits).unwrap().0
        );
        assert_eq!(
            session
                .is_match_window_value(haystack, window, limits)
                .unwrap(),
            expected
        );
    }
    assert_eq!(
        regex
            .is_match_window_value(haystack, window, refusing)
            .unwrap_err(),
        regex
            .is_match_window(haystack, window, refusing)
            .unwrap_err()
    );
    assert_eq!(
        session
            .is_match_window_value(haystack, window, refusing)
            .unwrap_err(),
        regex
            .is_match_window(haystack, window, refusing)
            .unwrap_err()
    );
    for invalid in [
        SearchWindow::new(haystack.len(), haystack.len() - 1),
        SearchWindow::new(0, haystack.len() + 1),
    ] {
        assert_eq!(
            regex
                .is_match_window_value(haystack, invalid, SearchLimits::unlimited())
                .unwrap_err(),
            regex
                .is_match_window(haystack, invalid, SearchLimits::unlimited())
                .unwrap_err()
        );
    }

    for (fallback, source) in [
        (portable(r"[ab]+aba"), b"!aababa!".as_slice()),
        (portable(r"\b\w+ing\b"), b"!testing!".as_slice()),
    ] {
        let expected = fallback
            .is_match_window(
                source,
                SearchWindow::full(source),
                SearchLimits::unlimited(),
            )
            .unwrap()
            .0;
        assert_eq!(fallback.is_match(source), expected);
        assert_eq!(
            fallback
                .is_match_window_value(
                    source,
                    SearchWindow::full(source),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
            expected
        );
    }
}

#[test]
fn text_ordinary_values_delegate_to_the_resolved_byte_route() {
    for (pattern, haystacks) in [
        (
            r"(?-u:[ab]+aba)",
            ["", "!", "!aababa!", "éaababa", "abab!"],
        ),
        (
            r"(?-u:\b\w+ing\b)",
            ["", "!", "!testing!", "étesting!", "singing!"],
        ),
    ] {
        let regex = PortableTextRegex::new(pattern).expect("ASCII text corridor");
        assert_eq!(
            regex.build_report().portable.plan,
            PlanKind::LiteralClassRunLiteral
        );
        for haystack in haystacks {
            let expected = regex
                .find_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(regex.find(haystack), expected, "haystack={haystack:?}");
            assert_eq!(
                regex.is_match(haystack),
                expected.is_some(),
                "haystack={haystack:?}"
            );
        }
    }
}
