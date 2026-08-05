#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildLimits, PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits,
    PortableFindIterRunLimits, SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
    SearchWindow,
};
use fre_kernels::{
    DispatchedPrefixClassAlternationPlan as KernelDispatchedPlan,
    PrefixClassAlternationBuildLimits as KernelBuildLimits,
    PrefixClassAlternationPlan as KernelPlan,
    PrefixClassAlternationSearchAccounting as KernelSearchAccounting,
    PrefixClassAlternationSearchLimits as KernelSearchLimits, SimdDispatchContext,
    Window as KernelWindow,
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

fn exact_kernel_limits(accounting: KernelSearchAccounting) -> KernelSearchLimits {
    KernelSearchLimits {
        max_work_upper_bound: u64::try_from(accounting.upper_bounds.work)
            .expect("small kernel work bound"),
        max_scratch_bytes: accounting.upper_bounds.scratch_bytes,
    }
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
fn equal_start_retries_branch_one_after_branch_zero_class_rejection() {
    let pattern = r"(?:ab[0-9]+|ab[A-Z]+)";
    let actual = automatic(pattern);
    let expected = oracle(pattern);
    let haystack = b"abQ";
    assert_differential(&actual, &expected, haystack);
    assert_eq!(
        Some((0, 3)),
        actual
            .find_value(haystack, SearchLimits::unlimited())
            .expect("equal-start branch-one match")
            .map(|matched| (matched.start(), matched.end()))
    );
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
fn earliest_end_compares_live_starts_and_equal_start_alternatives() {
    let later_start = automatic(r"(?:abcd[0-9]+|bc[d]+)");
    let later_start_oracle = oracle(r"(?:abcd[0-9]+|bc[d]+)");
    let haystack = b"abcd0";
    assert_differential(&later_start, &later_start_oracle, haystack);
    assert_eq!(Some(4), later_start_oracle.shortest_match(haystack));
    assert_eq!(
        Some(5),
        later_start_oracle.find(haystack).map(|matched| matched.end())
    );

    let equal_start = automatic(r"(?:abcd[0-9]+|ab[c]+)");
    let equal_start_oracle = oracle(r"(?:abcd[0-9]+|ab[c]+)");
    assert_differential(&equal_start, &equal_start_oracle, haystack);
    assert_eq!(Some(3), equal_start_oracle.shortest_match(haystack));
    assert_eq!(
        Some(5),
        equal_start_oracle.find(haystack).map(|matched| matched.end())
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
fn exists_shortest_and_invalid_end_preserve_operation_envelopes() {
    let actual = automatic(PATTERN);
    let haystack = b"xxab123!cdAZ";

    let (expected_exists, exists_accounting) = actual
        .is_match(haystack, SearchLimits::unlimited())
        .expect("baseline existence search");
    let SearchAccounting::PrefixClassAlternation(exists_accounting) = exists_accounting else {
        panic!("prefix/class existence accounting was not selected")
    };
    assert_eq!(
        fre::PREFIX_CLASS_ALTERNATION_EXISTS_OPERATION_ID,
        exists_accounting.identity.operation_id
    );
    let exact_exists = SearchLimits {
        max_work: u64::try_from(exists_accounting.upper_bounds.work)
            .expect("small existence bound"),
        max_scratch_bytes: exists_accounting.upper_bounds.scratch_bytes,
    };
    assert_eq!(
        expected_exists,
        actual
            .is_match(haystack, exact_exists)
            .expect("exact existence envelope")
            .0
    );
    let below_exists = SearchLimits {
        max_work: exact_exists.max_work.checked_sub(1).expect("positive bound"),
        ..exact_exists
    };
    assert!(matches!(
        actual.is_match(haystack, below_exists),
        Err(SearchError::PrefixClassAlternation(_))
    ));

    let (expected_shortest, shortest_accounting) = actual
        .shortest_match(haystack, SearchLimits::unlimited())
        .expect("baseline shortest search");
    let SearchAccounting::PrefixClassAlternation(shortest_accounting) = shortest_accounting else {
        panic!("prefix/class shortest accounting was not selected")
    };
    assert_eq!(
        fre::PREFIX_CLASS_ALTERNATION_SHORTEST_SEARCH_OPERATION_ID,
        shortest_accounting.identity.operation_id
    );
    let exact_shortest = SearchLimits {
        max_work: u64::try_from(shortest_accounting.upper_bounds.work)
            .expect("small shortest bound"),
        max_scratch_bytes: shortest_accounting.upper_bounds.scratch_bytes,
    };
    assert_eq!(
        expected_shortest,
        actual
            .shortest_match(haystack, exact_shortest)
            .expect("exact shortest envelope")
            .0
    );
    let below_shortest = SearchLimits {
        max_work: exact_shortest
            .max_work
            .checked_sub(1)
            .expect("positive bound"),
        ..exact_shortest
    };
    assert!(matches!(
        actual.shortest_match(haystack, below_shortest),
        Err(SearchError::PrefixClassAlternation(_))
    ));

    let invalid_end = haystack.len().checked_add(1).expect("small haystack");
    let invalid = SearchWindow::new(0, invalid_end);
    assert!(matches!(
        actual.find_window(haystack, invalid, SearchLimits::unlimited()),
        Err(SearchError::PrefixClassAlternation(_))
    ));
    assert!(matches!(
        actual.is_match_window(haystack, invalid, SearchLimits::unlimited()),
        Err(SearchError::PrefixClassAlternation(_))
    ));
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
fn accounting_iterator_and_native_session_observe_same_address_mutation() {
    let actual = automatic(r"(?:ab[0-9]+|cd[0-9]+)");
    let expected = [(1, 5), (6, 10), (11, 14)];
    let mut haystack = b"xab12!cd34!ab5".to_vec();
    let address = haystack.as_ptr();

    {
        let mut matches = actual
            .find_iter(&haystack, PortableFindIterLimits::unlimited())
            .expect("fresh accounting iterator");
        assert_eq!(None, matches.workspace_setup_accounting());
        let mut spans = Vec::new();
        for matched in matches.by_ref() {
            let matched = matched.expect("fresh accounting iterator item");
            spans.push((matched.start(), matched.end()));
        }
        assert_eq!(expected.as_slice(), spans.as_slice());
        let accounting = matches.accounting();
        assert_eq!(expected.len(), accounting.matches);
        assert_eq!(expected.len() + 1, accounting.search_calls);
        assert!(accounting.work_or_linear_terms > 0);
    }

    let mut session = actual
        .search_session(SearchSessionLimits::unlimited())
        .expect("native prefix/class session");
    assert_eq!(None, session.workspace_setup_accounting());
    let (exists, exists_accounting) = session
        .is_match(&haystack, SearchLimits::unlimited())
        .expect("session existence");
    assert!(exists);
    assert!(matches!(
        exists_accounting,
        SearchAccounting::PrefixClassAlternation(_)
    ));
    let (shortest, shortest_accounting) = session
        .shortest_match(&haystack, SearchLimits::unlimited())
        .expect("session shortest");
    assert_eq!(Some(4), shortest);
    assert!(matches!(
        shortest_accounting,
        SearchAccounting::PrefixClassAlternation(_)
    ));

    {
        let mut matches = session.find_iter(
            &haystack,
            PortableFindIterRunLimits::unlimited(),
        );
        let mut spans = Vec::new();
        for matched in matches.by_ref() {
            let matched = matched.expect("session accounting iterator item");
            spans.push((matched.start(), matched.end()));
        }
        assert_eq!(expected.as_slice(), spans.as_slice());
        let accounting = matches.accounting();
        assert_eq!(expected.len(), accounting.matches);
        assert_eq!(expected.len() + 1, accounting.search_calls);
    }

    haystack[3..5].copy_from_slice(b"AZ");
    haystack[8..10].copy_from_slice(b"QR");
    haystack[13] = b'Z';
    assert_eq!(address, haystack.as_ptr());
    assert!(!session
        .is_match(&haystack, SearchLimits::unlimited())
        .expect("mutated session existence")
        .0);
    assert_eq!(
        None,
        session
            .shortest_match(&haystack, SearchLimits::unlimited())
            .expect("mutated session shortest")
            .0
    );
    let mut matches = session.find_iter(
        &haystack,
        PortableFindIterRunLimits::unlimited(),
    );
    assert!(matches.next().is_none());
    let accounting = matches.accounting();
    assert_eq!(0, accounting.matches);
    assert_eq!(1, accounting.search_calls);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the conditional dispatched parity grid keeps every ordinary projection and exact refusal adjacent"
)]
fn dispatched_ordinary_search_matches_scalar_across_windows_and_limits() {
    let dispatch = SimdDispatchContext::capture();
    let scalar = KernelPlan::build(
        [b"ab", b"cd"],
        [
            [(b'0', b'9')].into_iter(),
            [(b'A', b'Z')].into_iter(),
        ],
        KernelBuildLimits::unlimited(),
    )
    .expect("scalar prefix/class kernel");
    let haystack = b"xab123!cdAZ!ab9cdQ";
    let invalid = KernelWindow::new(0, haystack.len() + 1);
    assert!(scalar
        .shortest_in(haystack, invalid, KernelSearchLimits::unlimited())
        .is_err());
    if !KernelPlan::run_scanners_usable(dispatch) {
        return;
    }
    let dispatched = KernelDispatchedPlan::build_with_dispatch(
        dispatch,
        [b"ab", b"cd"],
        [
            [(b'0', b'9')].into_iter(),
            [(b'A', b'Z')].into_iter(),
        ],
        KernelBuildLimits::unlimited(),
    )
    .expect("dispatched prefix/class kernel");

    for start in 0..=haystack.len() {
        for end in start..=haystack.len() {
            let window = KernelWindow::new(start, end);
            assert_eq!(
                scalar
                    .find_in(haystack, window, KernelSearchLimits::unlimited())
                    .expect("scalar window find")
                    .0,
                dispatched
                    .find_in(haystack, window, KernelSearchLimits::unlimited())
                    .expect("dispatched window find")
                    .0,
                "find window={start}..{end}",
            );
            assert_eq!(
                scalar
                    .is_match_in(haystack, window, KernelSearchLimits::unlimited())
                    .expect("scalar window exists")
                    .0,
                dispatched
                    .is_match_in(haystack, window, KernelSearchLimits::unlimited())
                    .expect("dispatched window exists")
                    .0,
                "exists window={start}..{end}",
            );
            assert_eq!(
                scalar
                    .shortest_in(haystack, window, KernelSearchLimits::unlimited())
                    .expect("scalar window shortest")
                    .0,
                dispatched
                    .shortest_in(haystack, window, KernelSearchLimits::unlimited())
                    .expect("dispatched window shortest")
                    .0,
                "shortest window={start}..{end}",
            );
        }
    }

    let full = KernelWindow::full(haystack);
    let (scalar_find, scalar_find_accounting) = scalar
        .find_in(haystack, full, KernelSearchLimits::unlimited())
        .expect("scalar baseline find");
    let (dispatched_find, dispatched_find_accounting) = dispatched
        .find_in(haystack, full, KernelSearchLimits::unlimited())
        .expect("dispatched baseline find");
    let scalar_find_exact = exact_kernel_limits(scalar_find_accounting);
    let dispatched_find_exact = exact_kernel_limits(dispatched_find_accounting);
    assert_eq!(
        scalar_find,
        scalar
            .find_in(haystack, full, scalar_find_exact)
            .expect("scalar exact find")
            .0
    );
    assert_eq!(
        dispatched_find,
        dispatched
            .find_in(haystack, full, dispatched_find_exact)
            .expect("dispatched exact find")
            .0
    );
    assert!(scalar
        .find_in(
            haystack,
            full,
            KernelSearchLimits {
                max_work_upper_bound: scalar_find_exact.max_work_upper_bound - 1,
                ..scalar_find_exact
            },
        )
        .is_err());
    assert!(dispatched
        .find_in(
            haystack,
            full,
            KernelSearchLimits {
                max_work_upper_bound: dispatched_find_exact.max_work_upper_bound - 1,
                ..dispatched_find_exact
            },
        )
        .is_err());

    let (scalar_exists, scalar_exists_accounting) = scalar
        .is_match_in(haystack, full, KernelSearchLimits::unlimited())
        .expect("scalar baseline exists");
    let (dispatched_exists, dispatched_exists_accounting) = dispatched
        .is_match_in(haystack, full, KernelSearchLimits::unlimited())
        .expect("dispatched baseline exists");
    let scalar_exists_exact = exact_kernel_limits(scalar_exists_accounting);
    let dispatched_exists_exact = exact_kernel_limits(dispatched_exists_accounting);
    assert_eq!(
        scalar_exists,
        scalar
            .is_match_in(haystack, full, scalar_exists_exact)
            .expect("scalar exact exists")
            .0
    );
    assert_eq!(
        dispatched_exists,
        dispatched
            .is_match_in(haystack, full, dispatched_exists_exact)
            .expect("dispatched exact exists")
            .0
    );
    assert!(scalar
        .is_match_in(
            haystack,
            full,
            KernelSearchLimits {
                max_work_upper_bound: scalar_exists_exact.max_work_upper_bound - 1,
                ..scalar_exists_exact
            },
        )
        .is_err());
    assert!(dispatched
        .is_match_in(
            haystack,
            full,
            KernelSearchLimits {
                max_work_upper_bound: dispatched_exists_exact.max_work_upper_bound - 1,
                ..dispatched_exists_exact
            },
        )
        .is_err());

    let (scalar_shortest, scalar_shortest_accounting) = scalar
        .shortest_in(haystack, full, KernelSearchLimits::unlimited())
        .expect("scalar baseline shortest");
    let (dispatched_shortest, dispatched_shortest_accounting) = dispatched
        .shortest_in(haystack, full, KernelSearchLimits::unlimited())
        .expect("dispatched baseline shortest");
    let scalar_shortest_exact = exact_kernel_limits(scalar_shortest_accounting);
    let dispatched_shortest_exact = exact_kernel_limits(dispatched_shortest_accounting);
    assert_eq!(
        scalar_shortest,
        scalar
            .shortest_in(haystack, full, scalar_shortest_exact)
            .expect("scalar exact shortest")
            .0
    );
    assert_eq!(
        dispatched_shortest,
        dispatched
            .shortest_in(haystack, full, dispatched_shortest_exact)
            .expect("dispatched exact shortest")
            .0
    );
    assert!(scalar
        .shortest_in(
            haystack,
            full,
            KernelSearchLimits {
                max_work_upper_bound: scalar_shortest_exact.max_work_upper_bound - 1,
                ..scalar_shortest_exact
            },
        )
        .is_err());
    assert!(dispatched
        .shortest_in(
            haystack,
            full,
            KernelSearchLimits {
                max_work_upper_bound: dispatched_shortest_exact.max_work_upper_bound - 1,
                ..dispatched_shortest_exact
            },
        )
        .is_err());

    assert!(dispatched
        .shortest_in(haystack, invalid, KernelSearchLimits::unlimited())
        .is_err());
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
