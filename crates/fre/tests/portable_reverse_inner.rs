use fre::{
    BuildLimits, PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits,
    REVERSE_INNER_UNION_ACCOUNTING_ID, REVERSE_INNER_UNION_PLAN_ID, SearchAccounting,
    SearchError, SearchLimits, SearchSessionLimits, SearchWindow,
};
use regex::bytes::{Regex, RegexBuilder};

const PATTERN: &str = r"(?:[abλ]+aa[abλ]+|[abλ]+b[abλ]+)";

fn oracle(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("oracle regex")
}

fn fre(pattern: &str) -> fre::PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("portable regex");
    assert_eq!(regex.build_report().plan, PlanKind::ReverseInner);
    regex
}

fn assert_differential(actual: &fre::PortableRegex, expected: &Regex, haystack: &[u8]) {
    let expected_find = expected
        .find(haystack)
        .map(|matched| (matched.start(), matched.end()));
    let (found, accounting) = actual
        .find_accounted(haystack, SearchLimits::unlimited())
        .expect("reverse-inner find");
    assert_eq!(
        found.map(|matched| (matched.start(), matched.end())),
        expected_find,
        "find haystack={haystack:?}",
    );
    assert!(matches!(accounting, SearchAccounting::ReverseInner(_)));
    assert_eq!(
        actual
            .is_match_value(haystack, SearchLimits::unlimited())
            .expect("reverse-inner is_match"),
        expected.is_match(haystack),
        "is_match haystack={haystack:?}",
    );
    assert_eq!(
        actual
            .shortest_match(haystack, SearchLimits::unlimited())
            .expect("reverse-inner shortest")
            .0,
        expected.shortest_match(haystack),
        "shortest haystack={haystack:?}",
    );
    assert_eq!(
        actual
            .selected_end(haystack, SearchLimits::unlimited())
            .expect("reverse-inner selected end")
            .0,
        expected_find.map(|(_, end)| end),
        "selected end haystack={haystack:?}",
    );

    let expected_matches: Vec<_> = expected
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect();
    let actual_matches: Vec<_> = actual
        .find_iter_value(haystack, PortableFindIterLimits::unlimited())
        .expect("reverse-inner iterator")
        .map(|matched| {
            let matched = matched.expect("reverse-inner iteration search");
            (matched.start(), matched.end())
        })
        .collect();
    assert_eq!(actual_matches, expected_matches, "iteration haystack={haystack:?}");
}

fn assert_full_differential(pattern: &str, haystack: &[u8]) {
    assert_differential(&fre(pattern), &oracle(pattern), haystack);
}

#[test]
fn exhaustive_small_unicode_and_invalid_byte_language() {
    fn visit(
        depth: usize,
        haystack: &mut Vec<u8>,
        tokens: &[&[u8]],
        actual: &fre::PortableRegex,
        expected: &Regex,
    ) {
        assert_differential(actual, expected, haystack);
        if depth == 5 {
            return;
        }
        for token in tokens {
            let old_len = haystack.len();
            haystack.extend_from_slice(token);
            visit(depth + 1, haystack, tokens, actual, expected);
            haystack.truncate(old_len);
        }
    }

    let tokens: [&[u8]; 6] = [b"a", b"b", b"x", "λ".as_bytes(), b"\x80", b"\xff"];
    let actual = fre(PATTERN);
    let expected = oracle(PATTERN);
    visit(0, &mut Vec::new(), &tokens, &actual, &expected);
}

#[test]
fn every_small_window_matches_the_slice_oracle() {
    let regex = fre(PATTERN);
    let expected = oracle(PATTERN);
    let haystack = b"\xff\x80\xce\xbbaaab\xce\xbbxbaaab\xce\xbb\xed\xa0\x80";
    for start in 0..=haystack.len() {
        for end in start..=haystack.len() {
            let expected_find = expected
                .find(&haystack[start..end])
                .map(|matched| (start + matched.start(), start + matched.end()));
            let expected_shortest = expected
                .shortest_match(&haystack[start..end])
                .map(|matched_end| start + matched_end);
            let (found, _) = regex
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
            if end == haystack.len() {
                let (shortest, _) = regex
                    .shortest_match_at(haystack, start, SearchLimits::unlimited())
                    .expect("suffix-window shortest");
                assert_eq!(shortest, expected_shortest, "suffix window={start}..{end}");
            }
        }
    }
}

#[test]
fn overlap_duplicates_and_source_order_do_not_change_group_zero() {
    for pattern in [
        r"[abλ]+aa[abλ]+",
        r"(?:[abλ]+(?:aa)[abλ]+|[abλ]+(?:a)[abλ]+|[abλ]+(?:aa)[abλ]+)",
        r"[abλ]+(?:(?:aa)[abλ]+|(?:a)[abλ]+|(?:aa)[abλ]+)",
        r"(([abλ]+)(aa)([abλ]+))|(([abλ]+)(a)([abλ]+))",
    ] {
        for haystack in [
            b"".as_slice(),
            b"a",
            b"aa",
            b"aaa",
            b"aaaa",
            b"aaaaa",
            b"xaaaaxaaaaax",
        ] {
            assert_full_differential(pattern, haystack);
        }
    }
}

#[test]
fn force_k0_bypasses_reverse_inner() {
    let forced = PortableBuilder::new(PATTERN)
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("forced K0");
    assert_eq!(forced.build_report().plan, PlanKind::K0);
    let automatic = fre(PATTERN);
    for haystack in [b"xaaabx".as_slice(), b"x\xffbaaabx", b"nomatch"] {
        assert_eq!(
            automatic
                .find_value(haystack, SearchLimits::unlimited())
                .expect("automatic search"),
            forced
                .find_value(haystack, SearchLimits::unlimited())
                .expect("forced search"),
        );
    }
}

#[test]
fn accounting_refuses_one_below_source_independent_work_bound() {
    let regex = fre(PATTERN);
    let haystack = b"\xff\xce\xbbaaab\xce\xbb-xbaaabx-\x80aaaa";
    let (_, accounting) = regex
        .find_accounted(haystack, SearchLimits::unlimited())
        .expect("baseline search");
    let SearchAccounting::ReverseInner(accounting) = accounting else {
        panic!("reverse-inner accounting was not selected");
    };
    let exact = u64::try_from(accounting.upper_bounds.work).expect("small work bound");
    regex
        .find_accounted(
            haystack,
            SearchLimits {
                max_work: exact,
                max_scratch_bytes: accounting.upper_bounds.scratch_bytes,
            },
        )
        .expect("exact work limit");
    assert!(matches!(
        regex.find_accounted(
            haystack,
            SearchLimits {
                max_work: exact - 1,
                max_scratch_bytes: accounting.upper_bounds.scratch_bytes,
            },
        ),
        Err(SearchError::ReverseInner(_))
    ));
}

#[test]
fn calls_are_plan_local_and_observe_same_address_mutation() {
    let aa = fre(r"[abcλ]+(?:aa|bc)[abcλ]+");
    let bb = fre(r"[abcλ]+(?:bb|ac)[abcλ]+");
    assert_eq!(aa.runtime_implementation_id(), REVERSE_INNER_UNION_PLAN_ID);
    assert_eq!(bb.runtime_implementation_id(), REVERSE_INNER_UNION_PLAN_ID);
    let mut haystack = b"xaaabx".to_vec();
    let address = haystack.as_ptr();
    assert!(aa.is_match_value(&haystack, SearchLimits::unlimited()).unwrap());
    assert!(!bb.is_match_value(&haystack, SearchLimits::unlimited()).unwrap());
    haystack[1..5].copy_from_slice(b"abbb");
    assert_eq!(haystack.as_ptr(), address);
    assert!(!aa.is_match_value(&haystack, SearchLimits::unlimited()).unwrap());
    assert!(bb.is_match_value(&haystack, SearchLimits::unlimited()).unwrap());

    haystack[1..5].copy_from_slice(b"aaab");
    assert_eq!(haystack.as_ptr(), address);
    let mut aa_session = aa
        .search_session(SearchSessionLimits::unlimited())
        .expect("aa native session");
    let mut bb_session = bb
        .search_session(SearchSessionLimits::unlimited())
        .expect("bb native session");
    assert!(aa_session.workspace_setup_accounting().is_none());
    assert!(bb_session.workspace_setup_accounting().is_none());
    assert!(aa_session
        .is_match_value(&haystack, SearchLimits::unlimited())
        .unwrap());
    assert!(!bb_session
        .is_match_value(&haystack, SearchLimits::unlimited())
        .unwrap());
    haystack[1..5].copy_from_slice(b"abbb");
    assert_eq!(haystack.as_ptr(), address);
    assert!(!aa_session
        .is_match_value(&haystack, SearchLimits::unlimited())
        .unwrap());
    assert!(bb_session
        .is_match_value(&haystack, SearchLimits::unlimited())
        .unwrap());
}

#[test]
fn middle_alternation_auto_uses_union_and_matches_force_k0() {
    let pattern = r"[a-zλ]+(?:ab|cd|ef|gh)[a-zλ]+";
    let automatic = fre(pattern);
    let forced = PortableBuilder::new(pattern)
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("forced K0 middle alternation");
    assert_eq!(forced.build_report().plan, PlanKind::K0);
    let haystack = b"xxabcdyy-\xce\xbbzzefqq\xce\xbb-absent";
    let (_, accounting) = automatic
        .find_accounted(haystack, SearchLimits::unlimited())
        .expect("adaptive union search");
    let SearchAccounting::ReverseInner(accounting) = accounting else {
        panic!("middle alternation search retained another route");
    };
    assert_eq!(accounting.identity.plan_id, REVERSE_INNER_UNION_PLAN_ID);
    assert_eq!(
        accounting.identity.accounting_id,
        REVERSE_INNER_UNION_ACCOUNTING_ID
    );
    assert_eq!(
        automatic
            .find_value(haystack, SearchLimits::unlimited())
            .expect("automatic middle alternation search"),
        forced
            .find_value(haystack, SearchLimits::unlimited())
            .expect("forced middle alternation search")
    );
}

#[test]
fn structural_gate_keeps_ascii_byte_dense_and_negated_classes_off_reverse_inner() {
    for pattern in [
        r"[a-z]+ab[a-z]+",
        r"(?-u:[a-z]+ab[a-z]+)",
        r"[\x00-\x7Fλ]+ab[\x00-\x7Fλ]+",
        r"[^x]+ab[^x]+",
    ] {
        let automatic = PortableBuilder::new(pattern)
            .unicode(true)
            .build()
            .expect("automatic structural-gate fallback");
        assert_ne!(
            automatic.build_report().plan,
            PlanKind::ReverseInner,
            "structurally broad class entered reverse-inner: {pattern}"
        );
    }
}

#[test]
fn structural_gate_uses_exact_ascii_and_non_ascii_population_boundaries() {
    const CANONICAL_UNICODE_LETTER_RANGES: usize = 677;
    let mut limits = BuildLimits::default();
    limits.literal_class_run_literal.max_class_ranges = CANONICAL_UNICODE_LETTER_RANGES;
    for pattern in [
        r"[\x00-\x3Fλ]+01[\x00-\x3Fλ]+",
        r"[a\u{10000}-\u{53DDF}]+a[a\u{10000}-\u{53DDF}]+",
        r"\pL+ab\pL+",
        r"[a-zλ]+ab[a-zλ]+",
    ] {
        assert_eq!(
            PortableBuilder::new(pattern)
                .unicode(true)
                .limits(limits)
                .build()
                .expect("sparse boundary build")
                .build_report()
                .plan,
            PlanKind::ReverseInner,
            "sparse boundary class was refused: {pattern}"
        );
    }
    for pattern in [
        r"[\x00-\x40λ]+01[\x00-\x40λ]+",
        r"[\x00-\x3F]+01[\x00-\x3F]+",
        r"[a\u{10000}-\u{53DE0}]+a[a\u{10000}-\u{53DE0}]+",
        r"[^\x40-\x7F]+01[^\x40-\x7F]+",
    ] {
        assert_ne!(
            PortableBuilder::new(pattern)
                .unicode(true)
                .limits(limits)
                .build()
                .expect("broad boundary fallback build")
                .build_report()
                .plan,
            PlanKind::ReverseInner,
            "broad boundary class entered reverse-inner: {pattern}"
        );
    }
}

#[test]
fn unsound_shapes_are_never_selected() {
    for pattern in [
        r"[ab]*a[ab]+",
        r"[ab]+?a[ab]+",
        r"[ab]+a[ab]*",
        r"[ab]+a[bc]+",
        r"[ab]+A[ab]+",
        r"[ab]+(?:a)?[ab]+",
        r"[ab]{1,3}a[ab]+",
        r"[ab]+a[ab]{1,3}",
        r"^[ab]+a[ab]+",
    ] {
        let built = PortableBuilder::new(pattern).unicode(true).build();
        if let Ok(regex) = built {
            assert_ne!(
                regex.build_report().plan,
                PlanKind::ReverseInner,
                "unexpectedly admitted {pattern}",
            );
        }
    }
}
