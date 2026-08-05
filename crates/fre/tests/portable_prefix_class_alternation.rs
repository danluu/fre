use fre::{
    BuildError, BuildLimits, PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits,
    SearchAccounting, SearchError, SearchLimits, SearchSessionLimits, SearchWindow,
};
use regex::bytes::{Regex, RegexBuilder};

const PATTERN: &str = r"(?:ab[0-9]+|cd[A-Z]+)";

fn oracle(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("oracle regex")
}

fn automatic(pattern: &str) -> fre::PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .expect("portable prefix/class regex");
    assert_eq!(
        regex.build_report().plan,
        PlanKind::PrefixClassAlternation,
        "pattern={pattern}",
    );
    regex
}

fn assert_differential(actual: &fre::PortableRegex, expected: &Regex, haystack: &[u8]) {
    let expected_find = expected
        .find(haystack)
        .map(|matched| (matched.start(), matched.end()));
    let (found, accounting) = actual
        .find(haystack, SearchLimits::unlimited())
        .expect("prefix/class find");
    assert_eq!(
        found.map(|matched| (matched.start(), matched.end())),
        expected_find,
        "find haystack={haystack:?}",
    );
    assert!(matches!(
        accounting,
        SearchAccounting::PrefixClassAlternation(_)
    ));
    assert_eq!(
        actual
            .find_value(haystack, SearchLimits::unlimited())
            .expect("value find")
            .map(|matched| (matched.start(), matched.end())),
        expected_find,
    );
    assert_eq!(
        actual
            .is_match(haystack, SearchLimits::unlimited())
            .expect("accounted is_match")
            .0,
        expected.is_match(haystack),
    );
    assert_eq!(
        actual
            .is_match_value(haystack, SearchLimits::unlimited())
            .expect("value is_match"),
        expected.is_match(haystack),
    );
    assert_eq!(
        actual
            .shortest_match(haystack, SearchLimits::unlimited())
            .expect("shortest match")
            .0,
        expected.shortest_match(haystack),
    );
    assert_eq!(
        actual
            .selected_end(haystack, SearchLimits::unlimited())
            .expect("selected end")
            .0,
        expected_find.map(|(_, end)| end),
    );

    let expected_matches: Vec<_> = expected
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect();
    let actual_matches: Vec<_> = actual
        .find_iter_value(haystack, PortableFindIterLimits::unlimited())
        .expect("prefix/class iterator")
        .map(|matched| {
            let matched = matched.expect("prefix/class iterator search");
            (matched.start(), matched.end())
        })
        .collect();
    assert_eq!(actual_matches, expected_matches, "iter haystack={haystack:?}");

    let session = actual
        .search_session(SearchSessionLimits::unlimited())
        .expect("native session");
    assert_eq!(
        session
            .find_value(haystack, SearchLimits::unlimited())
            .expect("session find")
            .map(|matched| (matched.start(), matched.end())),
        expected_find,
    );
}

#[test]
fn exhaustive_small_byte_language_matches_oracle() {
    fn visit(
        depth: usize,
        haystack: &mut Vec<u8>,
        alphabet: &[u8],
        actual: &fre::PortableRegex,
        expected: &Regex,
    ) {
        assert_differential(actual, expected, haystack);
        if depth == 5 {
            return;
        }
        for &byte in alphabet {
            haystack.push(byte);
            visit(depth + 1, haystack, alphabet, actual, expected);
            haystack.pop();
        }
    }

    let actual = automatic(PATTERN);
    let expected = oracle(PATTERN);
    visit(
        0,
        &mut Vec::new(),
        &[b'a', b'b', b'c', b'd', b'0', b'9', b'A', b'Z', 0xff],
        &actual,
        &expected,
    );
}

#[test]
fn source_priority_duplicates_dense_rejections_and_long_runs_match_oracle() {
    let cases = [
        (
            r"(?:ab[0-9A-Z]+|ab[0-9]+)",
            b"xxab12Z-ab77-abQ".as_slice(),
        ),
        (
            r"(?:ab[0-9]+|cd[0-9]+)",
            b"ababababababxababxabab0cd9999999999999999999!".as_slice(),
        ),
        (
            r"(?:(ab[0-9]+)|(cd[A-Z]+))",
            b"\xffcdAZZZ!ab123!cdQ".as_slice(),
        ),
        (
            r"(?:xy[ab]+|uv[bc]+)",
            b"uvbbbbc!xyaaaaaab!uvc".as_slice(),
        ),
    ];
    for (pattern, haystack) in cases {
        assert_differential(&automatic(pattern), &oracle(pattern), haystack);
    }
}

#[test]
fn every_window_matches_slice_oracle() {
    let actual = automatic(PATTERN);
    let expected = oracle(PATTERN);
    let haystack = b"\xffab12!xcdAZZZ!ab9cdQ\x80";
    for start in 0..=haystack.len() {
        for end in start..=haystack.len() {
            let expected_find = expected
                .find(&haystack[start..end])
                .map(|matched| (start + matched.start(), start + matched.end()));
            let expected_shortest = expected
                .shortest_match(&haystack[start..end])
                .map(|matched_end| start + matched_end);
            let (found, _) = actual
                .find_window(
                    haystack,
                    SearchWindow::new(start, end),
                    SearchLimits::unlimited(),
                )
                .expect("window find");
            assert_eq!(
                found.map(|matched| (matched.start(), matched.end())),
                expected_find,
                "window={start}..{end}",
            );
            assert_eq!(
                actual
                    .is_match_window_value(
                        haystack,
                        SearchWindow::new(start, end),
                        SearchLimits::unlimited(),
                    )
                    .expect("window existence"),
                expected_find.is_some(),
            );
            if end == haystack.len() {
                assert_eq!(
                    actual
                        .shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .expect("suffix shortest")
                        .0,
                    expected_shortest,
                );
            }
        }
    }
    assert!(matches!(
        actual.find_window(
            haystack,
            SearchWindow::new(2, 1),
            SearchLimits::unlimited(),
        ),
        Err(SearchError::PrefixClassAlternation(_))
    ));
}

#[test]
fn earliest_end_differs_from_selected_greedy_end() {
    let actual = automatic(r"(?:ab[0-9]+|cdef[A-Z]+)");
    let haystack = b"ab123456789-cdefQ";
    let selected = actual
        .find_value(haystack, SearchLimits::unlimited())
        .unwrap()
        .unwrap();
    assert_eq!((0, 11), (selected.start(), selected.end()));
    assert_eq!(
        Some(3),
        actual
            .shortest_match(haystack, SearchLimits::unlimited())
            .unwrap()
            .0,
    );
}

#[test]
fn force_k0_bypasses_prefix_class_route() {
    let forced = PortableBuilder::new(PATTERN)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("forced K0");
    assert_eq!(forced.build_report().plan, PlanKind::K0);
    let auto = automatic(PATTERN);
    for haystack in [b"ab12".as_slice(), b"xcdAZ!", b"absent", b"\xffab9\x80"] {
        assert_eq!(
            auto.find_value(haystack, SearchLimits::unlimited()).unwrap(),
            forced
                .find_value(haystack, SearchLimits::unlimited())
                .unwrap(),
        );
    }
}

#[test]
fn search_limits_use_the_published_source_independent_envelope() {
    let actual = automatic(PATTERN);
    let haystack = b"xxxxxxxxab12345";
    let (_, accounting) = actual
        .find(haystack, SearchLimits::unlimited())
        .expect("baseline search");
    let SearchAccounting::PrefixClassAlternation(accounting) = accounting else {
        panic!("prefix/class accounting was not selected")
    };
    let exact = u64::try_from(accounting.upper_bounds.work).expect("small work bound");
    actual
        .find(
            haystack,
            SearchLimits {
                max_work: exact,
                max_scratch_bytes: accounting.upper_bounds.scratch_bytes,
            },
        )
        .expect("exact work envelope");
    assert!(matches!(
        actual.find(
            haystack,
            SearchLimits {
                max_work: exact - 1,
                max_scratch_bytes: accounting.upper_bounds.scratch_bytes,
            },
        ),
        Err(SearchError::PrefixClassAlternation(_))
    ));
    assert!(accounting.actual.prefix_candidates <= accounting.upper_bounds.prefix_candidates);
    assert!(accounting.actual.class_bytes <= accounting.upper_bounds.class_bytes);
}

#[test]
fn planner_and_persistent_limits_are_exact_at_publication() {
    let baseline = automatic(PATTERN);
    let report = baseline.build_report();
    let build = baseline
        .prefix_class_alternation_build_accounting()
        .expect("prefix/class build accounting");
    assert_eq!(build.persistent_bytes, report.plan_storage_bytes);
    assert_eq!(
        report.charged_persistent_bytes,
        report.source_storage_bytes
            + report.capture_name_storage_bytes
            + build.persistent_bytes,
    );

    let mut exact_planner = BuildLimits::default();
    exact_planner.max_planner_work = report.planner_work;
    PortableBuilder::new(PATTERN)
        .unicode(false)
        .limits(exact_planner)
        .build()
        .expect("exact planner limit");
    let mut below_planner = exact_planner;
    below_planner.max_planner_work -= 1;
    assert!(matches!(
        PortableBuilder::new(PATTERN)
            .unicode(false)
            .limits(below_planner)
            .build(),
        Err(BuildError::PlannerWorkLimit { .. })
    ));

    let mut exact_persistent = BuildLimits::default();
    exact_persistent.max_persistent_bytes = report.charged_persistent_bytes;
    PortableBuilder::new(PATTERN)
        .unicode(false)
        .limits(exact_persistent)
        .build()
        .expect("exact persistent limit");
    let mut below_persistent = exact_persistent;
    below_persistent.max_persistent_bytes -= 1;
    assert!(matches!(
        PortableBuilder::new(PATTERN)
            .unicode(false)
            .limits(below_persistent)
            .build(),
        Err(BuildError::PersistentBytesLimit { .. })
            | Err(BuildError::PrefixClassAlternation(_))
    ));
}

#[test]
fn calls_are_plan_local_and_observe_same_address_mutation() {
    let digits = automatic(r"(?:ab[0-9]+|cd[0-9]+)");
    let letters = automatic(r"(?:ab[A-Z]+|cd[A-Z]+)");
    let mut haystack = b"xab12!".to_vec();
    let address = haystack.as_ptr();
    assert!(digits
        .is_match_value(&haystack, SearchLimits::unlimited())
        .unwrap());
    assert!(!letters
        .is_match_value(&haystack, SearchLimits::unlimited())
        .unwrap());
    haystack[3..5].copy_from_slice(b"AZ");
    assert_eq!(haystack.as_ptr(), address);
    assert!(!digits
        .is_match_value(&haystack, SearchLimits::unlimited())
        .unwrap());
    assert!(letters
        .is_match_value(&haystack, SearchLimits::unlimited())
        .unwrap());
}

#[test]
fn regret_and_semantic_refusals_never_select_the_route() {
    for pattern in [
        r"a[0-9]+|b[A-Z]+",
        r"aba[0-9]+|cdc[A-Z]+",
        r"ab[0-9]+?|cd[A-Z]+",
        r"ab[0-9]{1,3}|cd[A-Z]+",
        r"ab[0-9]+x|cd[A-Z]+",
        r"^ab[0-9]+|cd[A-Z]+",
        r"ab[0-9]+|cd[A-Z]+|ef[a-z]+",
    ] {
        let built = PortableBuilder::new(pattern).unicode(false).build();
        if let Ok(regex) = built {
            assert_ne!(
                regex.build_report().plan,
                PlanKind::PrefixClassAlternation,
                "unexpectedly admitted {pattern}",
            );
        }
    }
    let unicode = PortableBuilder::new(r"ab[λ]+|cd[μ]+")
        .unicode(true)
        .build();
    if let Ok(regex) = unicode {
        assert_ne!(regex.build_report().plan, PlanKind::PrefixClassAlternation);
    }
}
