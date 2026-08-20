#![allow(
    clippy::arithmetic_side_effects,
    reason = "exhaustive generators are bounded to small test inputs"
)]

use fre::{
    LITERAL_CLASS_RUN_GENERAL_SEARCH_PLAN_ID, PlanKind, PortableBuilder, SearchAccounting,
    SearchLimits, SearchSessionLimits, SearchWindow,
};
use regex::bytes::RegexBuilder;

fn portable(pattern: &str) -> fre::PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"));
    assert_eq!(regex.build_report().plan, PlanKind::LiteralClassRunLiteral);
    assert_eq!(
        regex.runtime_implementation_id(),
        LITERAL_CLASS_RUN_GENERAL_SEARCH_PLAN_ID
    );
    regex
}

fn oracle(pattern: &str) -> regex::bytes::Regex {
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("oracle build failed for {pattern:?}: {error}"))
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
fn generalized_shortest_values_match_every_window_and_prefix_fallback() {
    for (pattern, alphabet) in [
        (r"a[ab]*c", b"abc!".as_slice()),
        (r"a[ab]+c", b"abc!".as_slice()),
        (r"a[^z\r\n]*z", b"abz\xff".as_slice()),
        (r"a[bc]*", b"abc!".as_slice()),
    ] {
        let regex = portable(pattern);
        let oracle = oracle(pattern);
        let clone = regex.clone();
        let mut session = clone
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        for haystack in byte_strings(5, alphabet) {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = oracle
                        .shortest_match(&haystack[start..end])
                        .map(|relative_end| start + relative_end);
                    assert_eq!(
                        session
                            .shortest_match_window_value(
                                &haystack,
                                SearchWindow::new(start, end),
                                SearchLimits::unlimited(),
                            )
                            .unwrap(),
                        expected,
                        "pattern={pattern:?} haystack={haystack:?} window={start}..{end}"
                    );
                    if end == haystack.len() {
                        assert_eq!(
                            regex
                                .shortest_match_at_value(
                                    &haystack,
                                    start,
                                    SearchLimits::unlimited(),
                                )
                                .unwrap(),
                            expected,
                            "immutable pattern={pattern:?} haystack={haystack:?} start={start}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn generalized_shortest_value_preserves_resources_errors_and_session_inheritance() {
    let regex = portable(r"a[ab]+c");
    let haystack = b"!aabc!abbc!";
    let window = SearchWindow::full(haystack);
    let (expected, accounting) = regex
        .shortest_match(haystack, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
        panic!("generalized shortest fixture published another accounting family");
    };
    assert!(accounting.work > 0);
    let exact = SearchLimits {
        max_work: u64::try_from(accounting.work).unwrap(),
        max_scratch_bytes: 0,
    };
    let refusing = SearchLimits {
        max_work: exact.max_work - 1,
        max_scratch_bytes: 0,
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
            .shortest_match_value(haystack, SearchLimits::unlimited())
            .unwrap(),
        expected
    );
    assert_eq!(
        session
            .shortest_match_window_value(haystack, window, SearchLimits::unlimited())
            .unwrap(),
        expected
    );
    assert_eq!(
        regex.shortest_match_value(haystack, exact).unwrap(),
        regex.shortest_match(haystack, exact).unwrap().0
    );
    assert_eq!(
        session
            .shortest_match_window_value(haystack, window, exact)
            .unwrap(),
        expected
    );
    assert_eq!(
        regex.shortest_match_value(haystack, custom).unwrap(),
        regex.shortest_match(haystack, custom).unwrap().0
    );
    assert_eq!(
        regex.shortest_match_value(haystack, refusing).unwrap_err(),
        regex.shortest_match(haystack, refusing).unwrap_err()
    );
    assert_eq!(
        session
            .shortest_match_window_value(haystack, window, refusing)
            .unwrap_err(),
        regex.shortest_match(haystack, refusing).unwrap_err()
    );

    for invalid in [
        SearchWindow::new(haystack.len(), haystack.len() - 1),
        SearchWindow::new(0, haystack.len() + 1),
    ] {
        assert_eq!(
            session
                .shortest_match_window_value(haystack, invalid, SearchLimits::unlimited())
                .unwrap_err(),
            regex
                .find_window(haystack, invalid, SearchLimits::unlimited())
                .unwrap_err()
        );
    }

    let guarded = portable(r"\b[A-Za-z]+TRAILER\b");
    let guarded_haystack = b"!abcTRAILER!";
    assert_eq!(
        guarded
            .shortest_match_value(guarded_haystack, SearchLimits::unlimited())
            .unwrap(),
        guarded
            .shortest_match(guarded_haystack, SearchLimits::unlimited())
            .unwrap()
            .0
    );

    let prefix_only = portable(r"a[bc]*");
    let prefix_haystack = b"!abcb!ac!";
    assert_eq!(
        prefix_only
            .shortest_match_value(prefix_haystack, SearchLimits::unlimited())
            .unwrap(),
        Some(2)
    );
}
