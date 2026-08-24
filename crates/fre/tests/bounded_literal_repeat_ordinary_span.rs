#![forbid(unsafe_code)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "the bounded exhaustive generators and fixture offsets are test-only"
)]

use fre::{
    Match, PlanKind, PortableBuilder, PortableFindIterLimits, PortableFindIterRunLimits,
    SearchLimits, SearchSessionLimits, SearchWindow,
};
use regex::bytes::{Regex, RegexBuilder};

const DIRECT_WINDOW_BYTES: usize = 1_024;

fn portable(pattern: &str) -> fre::PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"));
    assert_eq!(regex.build_report().plan, PlanKind::K0, "{pattern:?}");
    assert_eq!(regex.runtime_implementation_id(), "k0", "{pattern:?}");
    regex
}

fn portable_auto(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"))
}

fn oracle(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("oracle build failed for {pattern:?}: {error}"))
}

fn span(matched: Option<Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

fn oracle_span(regex: &Regex, haystack: &[u8]) -> Option<(usize, usize)> {
    regex
        .find(haystack)
        .map(|matched| (matched.start(), matched.end()))
}

fn padded(fragment: &[u8], offset: usize, length: usize) -> Vec<u8> {
    assert!(offset + fragment.len() <= length);
    let mut haystack = vec![b'!'; length];
    haystack[offset..offset + fragment.len()].copy_from_slice(fragment);
    haystack
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

fn assert_ordinary_parity(pattern: &str, fragment: &[u8], offset: usize) {
    let portable = portable(pattern);
    let oracle = oracle(pattern);
    let haystack = padded(fragment, offset, DIRECT_WINDOW_BYTES);
    assert_eq!(
        span(portable.find(&haystack)),
        oracle_span(&oracle, &haystack),
        "pattern={pattern:?} fragment={fragment:?} offset={offset}",
    );
}

#[test]
fn every_small_bound_and_priority_matches_the_pinned_oracle() {
    for minimum in 1..=4 {
        for maximum in minimum..=4 {
            for lazy in [false, true] {
                let priority = if lazy { "?" } else { "" };
                let pattern = format!(r"(?:ab){{{minimum},{maximum}}}{priority}c");
                let portable = PortableBuilder::new(&pattern)
                    .unicode(false)
                    .build()
                    .unwrap_or_else(|error| {
                        panic!("portable build failed for {pattern:?}: {error}")
                    });
                if minimum != maximum {
                    assert_eq!(portable.build_report().plan, PlanKind::K0, "{pattern:?}");
                    assert_eq!(portable.runtime_implementation_id(), "k0", "{pattern:?}");
                }
                let oracle = oracle(&pattern);

                for repeats in 0..=maximum + 2 {
                    let mut fragment = b"x".to_vec();
                    fragment.extend_from_slice(&b"ab".repeat(repeats));
                    fragment.push(b'c');
                    fragment.extend_from_slice(b"xabababcx");
                    for offset in [0, 1, 257, DIRECT_WINDOW_BYTES - fragment.len()] {
                        let haystack = padded(&fragment, offset, DIRECT_WINDOW_BYTES);
                        assert_eq!(
                            span(portable.find(&haystack)),
                            oracle_span(&oracle, &haystack),
                            "pattern={pattern:?} repeats={repeats} offset={offset}",
                        );
                    }
                }

                let mut competing = b"x".to_vec();
                competing.extend_from_slice(&b"ab".repeat(maximum + 2));
                competing.extend_from_slice(b"cx");
                competing.extend_from_slice(&b"ab".repeat(minimum));
                competing.extend_from_slice(b"cx");
                let haystack = padded(&competing, 503, DIRECT_WINDOW_BYTES);
                assert_eq!(
                    span(portable.find(&haystack)),
                    oracle_span(&oracle, &haystack),
                    "competing pattern={pattern:?}",
                );
            }
        }
    }
}

#[test]
fn exhaustive_overlap_prefix_capture_and_tail_shapes_match_the_pinned_oracle() {
    let cases = [
        (r"(?:a){1,3}b", b"abx".as_slice(), 6),
        (r"(?:a){1,3}?b", b"abx".as_slice(), 6),
        (r"(?:aa){1,3}b", b"ab".as_slice(), 7),
        (r"(?:aa){1,3}?b", b"ab".as_slice(), 7),
        (r"(?:aba){1,2}c", b"abc".as_slice(), 7),
        (r"(?:aba){1,2}?c", b"abc".as_slice(), 7),
        (r"((?:ab){2,4})(c)", b"abc".as_slice(), 7),
        (r"(?:abab){1,2}cab", b"abc".as_slice(), 7),
    ];

    for (pattern, alphabet, maximum_length) in cases {
        let portable = portable_auto(pattern);
        let oracle = oracle(pattern);
        for fragment in byte_strings(maximum_length, alphabet) {
            let offset = 503;
            let haystack = padded(&fragment, offset, DIRECT_WINDOW_BYTES);
            assert_eq!(
                span(portable.find(&haystack)),
                oracle_span(&oracle, &haystack),
                "pattern={pattern:?} fragment={fragment:?}",
            );
        }
    }

    for (pattern, fragment) in [
        (r"(?:ab){2,4}cab", b"xababababcabx".as_slice()),
        (r"(?:ab){2,4}?cab", b"xababababcabx".as_slice()),
        (r"(?:abab){2,4}cab", b"xababababababababcabx".as_slice()),
        (r"(?:abab){2,4}?cab", b"xababababababababcabx".as_slice()),
    ] {
        assert_ordinary_parity(pattern, fragment, 499);
    }
}

fn oracle_window_span(
    regex: &Regex,
    haystack: &[u8],
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    regex
        .find(&haystack[start..end])
        .map(|matched| (start + matched.start(), start + matched.end()))
}

fn iterator_spans<I, E>(iterator: I) -> Vec<(usize, usize)>
where
    I: IntoIterator<Item = Result<Match, E>>,
    E: core::fmt::Debug,
{
    iterator
        .into_iter()
        .map(|matched| {
            let matched = matched.expect("portable iteration succeeds");
            (matched.start(), matched.end())
        })
        .collect()
}

#[test]
fn ordinary_value_accounted_session_iteration_and_windows_stay_identical() {
    for pattern in [r"(?:ab){2,5}c", r"(?:ab){2,5}?c"] {
        let portable = portable(pattern);
        let oracle = oracle(pattern);
        let mut haystack = vec![b'x'; 4_093];
        haystack[17..28].copy_from_slice(b"abababababc");
        haystack[3_000..3_007].copy_from_slice(b"abababc");
        let expected = oracle_span(&oracle, &haystack);
        let expected_iter = oracle
            .find_iter(&haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let expected_end = expected.map(|(_, end)| end);

        assert_eq!(span(portable.find(&haystack)), expected, "{pattern:?}");
        assert_eq!(
            portable.is_match(&haystack),
            expected.is_some(),
            "{pattern:?}"
        );
        let (accounted, accounting) = portable
            .find_accounted(&haystack, SearchLimits::unlimited())
            .expect("accounted find");
        assert_eq!(span(accounted), expected, "{pattern:?}");
        assert_eq!(accounting.plan(), PlanKind::K0, "{pattern:?}");
        assert_eq!(
            span(
                portable
                    .find_value(&haystack, SearchLimits::unlimited())
                    .expect("value find"),
            ),
            expected,
            "{pattern:?}",
        );
        assert_eq!(
            portable
                .selected_end(&haystack, SearchLimits::unlimited())
                .expect("accounted selected end")
                .0,
            expected_end,
            "{pattern:?}",
        );
        assert_eq!(
            portable
                .selected_end_value(&haystack, SearchLimits::unlimited())
                .expect("value selected end"),
            expected_end,
            "{pattern:?}",
        );
        assert_eq!(
            portable
                .shortest_match(&haystack, SearchLimits::unlimited())
                .expect("shortest match")
                .0,
            oracle.shortest_match(&haystack),
            "{pattern:?}",
        );
        assert_eq!(
            portable
                .is_match_accounted(&haystack, SearchLimits::unlimited())
                .expect("accounted existence")
                .0,
            expected.is_some(),
            "{pattern:?}",
        );
        assert_eq!(
            portable
                .is_match_value(&haystack, SearchLimits::unlimited())
                .expect("value existence"),
            expected.is_some(),
            "{pattern:?}",
        );

        assert_eq!(
            iterator_spans(
                portable
                    .find_iter(&haystack, PortableFindIterLimits::unlimited())
                    .expect("fresh accounted iterator"),
            ),
            expected_iter,
            "{pattern:?}",
        );
        assert_eq!(
            iterator_spans(
                portable
                    .find_iter_value(&haystack, PortableFindIterLimits::unlimited())
                    .expect("fresh value iterator"),
            ),
            expected_iter,
            "{pattern:?}",
        );

        let mut session = portable
            .search_session(SearchSessionLimits::unlimited())
            .expect("K0 session");
        assert_eq!(session.runtime_implementation_id(), "k0");
        let (session_find, session_accounting) = session
            .find(&haystack, SearchLimits::unlimited())
            .expect("session find");
        assert_eq!(span(session_find), expected, "{pattern:?}");
        assert_eq!(session_accounting.plan(), PlanKind::K0, "{pattern:?}");
        assert_eq!(
            span(
                session
                    .find_value(&haystack, SearchLimits::unlimited())
                    .expect("session value find"),
            ),
            expected,
            "{pattern:?}",
        );
        assert_eq!(
            iterator_spans(session.find_iter(&haystack, PortableFindIterRunLimits::unlimited()),),
            expected_iter,
            "{pattern:?}",
        );
        assert_eq!(
            iterator_spans(
                session.find_iter_value(&haystack, PortableFindIterRunLimits::unlimited()),
            ),
            expected_iter,
            "{pattern:?}",
        );

        for (start, end) in [
            (0, haystack.len()),
            (0, 27),
            (0, 28),
            (17, 28),
            (18, 28),
            (20, 28),
            (28, haystack.len()),
            (2_999, 3_007),
            (3_000, 3_006),
            (3_000, 3_007),
            (3_001, 3_007),
        ] {
            let expected = oracle_window_span(&oracle, &haystack, start, end);
            let window = SearchWindow::new(start, end);
            assert_eq!(
                span(
                    portable
                        .find_window(&haystack, window, SearchLimits::unlimited())
                        .expect("accounted window find")
                        .0,
                ),
                expected,
                "pattern={pattern:?} window={start}..{end}",
            );
            assert_eq!(
                span(
                    portable
                        .find_window_value(&haystack, window, SearchLimits::unlimited())
                        .expect("value window find"),
                ),
                expected,
                "pattern={pattern:?} window={start}..{end}",
            );
        }

        for length in [1_023, 1_024, 4_093] {
            let overlong = b"ababababababc";
            let offset = length - overlong.len();
            let boundary = padded(overlong, offset, length);
            assert_eq!(
                span(portable.find(&boundary)),
                oracle_span(&oracle, &boundary),
                "pattern={pattern:?} boundary length={length}",
            );
        }

        let absent = vec![b'x'; 4_093];
        assert_eq!(portable.find(&absent), None, "{pattern:?}");
        assert!(!portable.is_match(&absent), "{pattern:?}");
    }
}
