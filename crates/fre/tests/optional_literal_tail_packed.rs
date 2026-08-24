#![forbid(unsafe_code)]

use fre::{
    Match, NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID, PlanKind, PlanSelection, PortableBuilder,
    PortableFindIterLimits, PortableFindIterRunLimits, SearchAccounting, SearchLimits,
    SearchSessionLimits, SearchWindow,
};

const PRIORITY_PATTERNS: [&str; 4] = [
    r"(?-u:(?:ab|a)?b)",
    r"(?-u:(?:a|ab)?b)",
    r"(?-u:(?:ab|a)??b)",
    r"(?-u:(?:a|ab)??b)",
];

fn span(matched: Option<Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

fn enumerate_haystacks(alphabet: &[u8], maximum: usize, mut visit: impl FnMut(&[u8])) {
    fn recurse(
        alphabet: &[u8],
        remaining: usize,
        haystack: &mut Vec<u8>,
        visit: &mut impl FnMut(&[u8]),
    ) {
        visit(haystack);
        if remaining == 0 {
            return;
        }
        for &byte in alphabet {
            haystack.push(byte);
            recurse(alphabet, remaining - 1, haystack, visit);
            haystack.pop();
        }
    }

    recurse(alphabet, maximum, &mut Vec::new(), &mut visit);
}

fn upstream_window_span(
    upstream: &regex::bytes::Regex,
    haystack: &[u8],
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    upstream.find(&haystack[start..end]).map(|matched| {
        (
            start.checked_add(matched.start()).unwrap(),
            start.checked_add(matched.end()).unwrap(),
        )
    })
}

#[test]
fn optional_literal_tail_matches_upstream_across_every_small_source_and_window() {
    for pattern in PRIORITY_PATTERNS {
        let portable = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"));
        assert_eq!(portable.build_report().plan, PlanKind::PackedLiteralSet);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("upstream build failed for {pattern:?}: {error}"));
        let mut session = portable
            .search_session(SearchSessionLimits::unlimited())
            .expect("packed reusable session");
        let mut ordinary = portable
            .ordinary_session()
            .expect("packed ordinary session");

        enumerate_haystacks(b"abx", 5, |haystack| {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(portable.is_match(haystack), expected.is_some());
            assert_eq!(span(portable.find(haystack)), expected);
            assert_eq!(
                portable
                    .is_match_value(haystack, SearchLimits::unlimited())
                    .unwrap(),
                expected.is_some(),
            );
            assert_eq!(
                span(
                    portable
                        .find_value(haystack, SearchLimits::unlimited())
                        .unwrap(),
                ),
                expected,
            );
            let (reported, accounting) = portable
                .find_accounted(haystack, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(span(reported), expected);
            assert!(matches!(accounting, SearchAccounting::PackedLiteralSet(_)));
            let (exists, accounting) = portable
                .is_match_accounted(haystack, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(exists, expected.is_some());
            assert!(matches!(accounting, SearchAccounting::PackedLiteralSet(_)));

            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(
                    span(
                        portable
                            .find_at(haystack, start, SearchLimits::unlimited())
                            .unwrap()
                            .0,
                    ),
                    expected,
                );
                assert_eq!(
                    span(
                        session
                            .find_at_value(haystack, start, SearchLimits::unlimited())
                            .unwrap(),
                    ),
                    expected,
                );
                assert_eq!(span(ordinary.find_at(haystack, start).unwrap()), expected);
                assert_eq!(
                    ordinary.is_match_at(haystack, start).unwrap(),
                    expected.is_some()
                );
            }

            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = upstream_window_span(&upstream, haystack, start, end);
                    let (reported, accounting) = portable
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(span(reported), expected);
                    assert!(matches!(accounting, SearchAccounting::PackedLiteralSet(_)));
                    assert_eq!(
                        span(
                            portable
                                .find_window_value(haystack, window, SearchLimits::unlimited())
                                .unwrap(),
                        ),
                        expected,
                    );
                    let (exists, accounting) = portable
                        .is_match_window(haystack, window, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(exists, expected.is_some());
                    assert!(matches!(accounting, SearchAccounting::PackedLiteralSet(_)));
                    assert_eq!(
                        portable
                            .is_match_window_value(haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected.is_some(),
                    );
                    assert_eq!(
                        span(
                            session
                                .find_window_value(haystack, window, SearchLimits::unlimited(),)
                                .unwrap(),
                        ),
                        expected,
                    );
                    assert_eq!(
                        session
                            .is_match_window_value(haystack, window, SearchLimits::unlimited())
                            .unwrap(),
                        expected.is_some(),
                    );
                }
            }
        });
    }
}

#[test]
fn optional_literal_tail_keeps_priority_duplicates_iteration_and_boundaries() {
    for (pattern, expected) in [
        (PRIORITY_PATTERNS[0], Some((0, 3))),
        (PRIORITY_PATTERNS[1], Some((0, 2))),
        (PRIORITY_PATTERNS[2], Some((0, 3))),
        (PRIORITY_PATTERNS[3], Some((0, 2))),
    ] {
        let portable = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(portable.build_report().plan, PlanKind::PackedLiteralSet);
        assert_eq!(span(portable.find(b"abb")), expected, "pattern={pattern:?}");
        assert_eq!(span(portable.find(b"b")), Some((0, 1)));
    }

    let duplicate_pattern = r"(?-u:(?:ab|ab|a)?b)";
    let duplicate = PortableBuilder::new(duplicate_pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(duplicate.build_report().plan, PlanKind::PackedLiteralSet);
    let duplicate_upstream = regex::bytes::RegexBuilder::new(duplicate_pattern)
        .unicode(false)
        .build()
        .unwrap();
    let duplicate_haystack = b"abb-b-ababb-abb";
    let expected = duplicate_upstream
        .find_iter(duplicate_haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    let actual = duplicate
        .find_iter(duplicate_haystack, PortableFindIterLimits::unlimited())
        .unwrap()
        .map(|matched| span(Some(matched.unwrap())).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    let mut session = duplicate
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    let retained = session
        .find_iter(duplicate_haystack, PortableFindIterRunLimits::unlimited())
        .map(|matched| span(Some(matched.unwrap())).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(retained, expected);
    let mut ordinary = duplicate.ordinary_session().unwrap();
    let mut visited = Vec::new();
    ordinary
        .try_visit_spans(duplicate_haystack, |matched| {
            visited.push((matched.start(), matched.end()));
            Ok::<bool, ()>(true)
        })
        .unwrap()
        .unwrap();
    assert_eq!(visited, expected);

    for pattern in PRIORITY_PATTERNS {
        let portable = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        for length in [0_usize, 1, 2, 3, 30, 31, 32, 63, 64, 1023, 1024] {
            let miss = vec![b'x'; length];
            let mut tail_hit = miss.clone();
            tail_hit.push(b'b');
            let mut priority_hit = miss.clone();
            priority_hit.extend_from_slice(b"abb");
            for haystack in [&miss, &tail_hit, &priority_hit] {
                assert_eq!(portable.is_match(haystack), upstream.is_match(haystack));
                assert_eq!(
                    span(portable.find(haystack)),
                    upstream
                        .find(haystack)
                        .map(|matched| (matched.start(), matched.end())),
                );
            }
        }
    }
}

fn many_literal_optional_pattern(branches: usize) -> String {
    let alternatives = (1..=branches)
        .map(|byte| format!(r"\x{byte:02X}q"))
        .collect::<Vec<_>>()
        .join("|");
    format!(r"(?-u:(?:{alternatives})?q)")
}

#[test]
fn optional_literal_tail_admission_is_mutually_exclusive_bounded_and_fail_open() {
    let old_direct = PortableBuilder::new(r"(?-u:(?:ab|a)?z)")
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(old_direct.build_report().plan, PlanKind::RequiredLiteral);
    assert_eq!(
        old_direct.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );

    let forced = PortableBuilder::new(PRIORITY_PATTERNS[0])
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap();
    assert_eq!(forced.build_report().plan, PlanKind::K0);

    for pattern in [
        r"(?-u:(?:(ab)|a)?b)",
        r"(?-u:(?:[ac]|ab)?b)",
        r"(?-u:(?:a\b|ab)?b)",
        r"(?-u:(?:a+|ab)?b)",
        r"(?-u:(?:|a)?b)",
        r"(?-u:(?:ab|a)?[bc])",
        r"(?-u:x(?:ab|a)?b)",
    ] {
        let portable = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("fallback build failed for {pattern:?}: {error}"));
        assert_ne!(
            portable.build_report().plan,
            PlanKind::PackedLiteralSet,
            "unsafe shape admitted: {pattern:?}",
        );
    }

    let at_limit = PortableBuilder::new(&many_literal_optional_pattern(63))
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(at_limit.build_report().plan, PlanKind::PackedLiteralSet);
    let over_limit = PortableBuilder::new(&many_literal_optional_pattern(64))
        .unicode(false)
        .build()
        .unwrap();
    assert_ne!(over_limit.build_report().plan, PlanKind::PackedLiteralSet);
}
