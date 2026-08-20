use fre::{
    BuildError, NullableOptionalChainSearchError, PlanKind, PlanSelection, PortableBuilder,
    PortableFindIterLimits, PortableTextBuilder, SearchAccounting, SearchError, SearchLimits,
    SearchSessionLimits, SearchWindow, NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
};

fn build_auto(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("auto build failed for {pattern:?}: {error:?}"))
}

fn build_k0(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap_or_else(|error| panic!("K0 build failed for {pattern:?}: {error:?}"))
}

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
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
            recurse(alphabet, remaining.saturating_sub(1), haystack, visit);
            haystack.pop();
        }
    }

    recurse(alphabet, maximum, &mut Vec::new(), &mut visit);
}

#[test]
fn overlapping_and_duplicate_predicates_match_pinned_bytes_and_k0() {
    let patterns = [
        r"(?-u:[ab]?[ab]?z)",
        r"(?-u:[ab]??[ab]??z)",
        r"(?-u:a{0,3}a{0,2}z)",
        r"(?-u:[ab]{0,2}[bc]{0,2}zz)",
        r"(?-u:[ab]{0,3}?[ab]{0,2}zaz)",
        r"(?-u:(a?)([ab]??)z)",
    ];
    for pattern in patterns {
        let auto = build_auto(pattern);
        let k0 = build_k0(pattern);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(auto.build_report().plan, PlanKind::RequiredLiteral);
        assert_eq!(auto.runtime_implementation_id(), NULLABLE_OPTIONAL_CHAIN_PLAN_ID);
        assert_eq!(k0.build_report().plan, PlanKind::K0);

        enumerate_haystacks(b"abcz", 5, |haystack| {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, accounting) = auto
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap();
                assert_eq!(span(actual), expected, "{pattern:?}/{haystack:?}/{start}");
                assert!(matches!(
                    accounting,
                    SearchAccounting::NullableOptionalChain(_)
                ));
                assert_eq!(
                    span(k0
                        .find_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0),
                    expected,
                    "K0 {pattern:?}/{haystack:?}/{start}"
                );
                assert_eq!(
                    auto.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    upstream.shortest_match_at(haystack, start),
                    "shortest {pattern:?}/{haystack:?}/{start}"
                );
                assert_eq!(
                    auto.is_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    expected.is_some(),
                    "exists {pattern:?}/{haystack:?}/{start}"
                );
            }
        });
    }
}

#[test]
fn iteration_preserves_leftmost_priority_and_overlap_horizon() {
    let pattern = r"(?-u:[ab]??[ab]?z)";
    let auto = build_auto(pattern);
    let upstream = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    for haystack in [
        b"zaazabzz".as_slice(),
        b"aaazaaz".as_slice(),
        b"cccc".as_slice(),
    ] {
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let actual = auto
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .unwrap()
            .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn admission_is_bounded_by_the_fixed_stage_representation() {
    let maximum = format!("(?-u:{}z)", "a?".repeat(64));
    let over_limit = format!("(?-u:{}z)", "a?".repeat(65));
    let maximum = build_auto(&maximum);
    assert_eq!(maximum.build_report().plan, PlanKind::RequiredLiteral);
    assert_eq!(maximum.runtime_implementation_id(), NULLABLE_OPTIONAL_CHAIN_PLAN_ID);
    assert_ne!(
        build_auto(&over_limit).runtime_implementation_id(),
        NULLABLE_OPTIONAL_CHAIN_PLAN_ID
    );
}

#[test]
fn sixty_four_stages_search_through_the_high_mask_bit() {
    let pattern = format!("(?-u:{}tail)", "a?".repeat(64));
    let haystack = format!("{}tail", "a".repeat(64));
    let regex = build_auto(&pattern);
    let (matched, accounting) = regex
        .find_accounted(haystack.as_bytes(), SearchLimits::unlimited())
        .unwrap();
    assert_eq!(span(matched), Some((0, haystack.len())));
    assert!(matches!(
        accounting,
        SearchAccounting::NullableOptionalChain(_)
    ));
    assert_eq!(
        regex
            .selected_end(haystack.as_bytes(), SearchLimits::unlimited())
            .unwrap()
            .0,
        Some(haystack.len())
    );
}

#[test]
fn overlapping_tail_head_declines_to_the_existing_fallback() {
    let pattern = r"(?-u:[ab]?[ab]?aba)";
    let haystack = b"ababa";
    let auto = build_auto(pattern);
    let fallback = build_k0(pattern);
    assert_ne!(auto.runtime_implementation_id(), NULLABLE_OPTIONAL_CHAIN_PLAN_ID);
    assert_eq!(
        span(auto.find_accounted(haystack, SearchLimits::unlimited()).unwrap().0),
        span(
            fallback
                .find_accounted(haystack, SearchLimits::unlimited())
                .unwrap()
                .0,
        )
    );
    assert_eq!(
        auto.shortest_match(haystack, SearchLimits::unlimited()).unwrap().0,
        fallback
            .shortest_match(haystack, SearchLimits::unlimited())
            .unwrap()
            .0
    );
    assert_eq!(
        auto.selected_end(haystack, SearchLimits::unlimited()).unwrap().0,
        fallback
            .selected_end(haystack, SearchLimits::unlimited())
            .unwrap()
            .0
    );
}

#[test]
fn bounded_windows_and_selected_end_match_the_pinned_priority() {
    let pattern = r"(?-u:[ab]{0,3}?[ab]{0,2}zaz)";
    let haystack = b"xxabzazyyabzaz";
    let regex = build_auto(pattern);
    let upstream = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    for window in [SearchWindow::new(2, 7), SearchWindow::new(3, 7), SearchWindow::new(8, 14)] {
        let window_haystack = &haystack[window.start()..window.end()];
        let expected = upstream
            .find(window_haystack)
            .map(|matched| {
                (
                    window.start().checked_add(matched.start()).unwrap(),
                    window.start().checked_add(matched.end()).unwrap(),
                )
            });
        assert_eq!(
            span(
                regex
                    .find_window(haystack, window, SearchLimits::unlimited())
                    .unwrap()
                    .0
            ),
            expected,
            "window={window:?}"
        );
    }
    assert_eq!(
        regex.selected_end(haystack, SearchLimits::unlimited()).unwrap().0,
        upstream.find(haystack).map(|matched| matched.end())
    );
}

#[test]
fn span_work_limit_accepts_the_exact_bound_and_rejects_one_below() {
    let regex = build_auto(r"(?-u:[ab]{0,3}?[ab]{0,2}zaz)");
    let haystack = b"xxabzazyyabzaz";
    let (_, accounting) = regex
        .find_accounted(haystack, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::NullableOptionalChain(accounting) = accounting else {
        panic!("expected nullable optional-chain accounting");
    };
    let exact = SearchLimits {
        max_work: accounting.work_upper_bound,
        max_scratch_bytes: 0,
    };
    assert!(regex.find_accounted(haystack, exact).is_ok());
    assert!(regex.selected_end(haystack, exact).is_ok());
    let below = SearchLimits {
        max_work: accounting.work_upper_bound.checked_sub(1).unwrap(),
        max_scratch_bytes: 0,
    };
    assert!(matches!(
        regex.find_accounted(haystack, below),
        Err(SearchError::NullableOptionalChain(
            NullableOptionalChainSearchError::WorkLimit { needed, limit }
        )) if needed == accounting.work_upper_bound && limit == below.max_work
    ));
    assert!(matches!(
        regex.selected_end(haystack, below),
        Err(SearchError::NullableOptionalChain(
            NullableOptionalChainSearchError::WorkLimit { needed, limit }
        )) if needed == accounting.work_upper_bound && limit == below.max_work
    ));
}

#[test]
fn admitted_head_disjoint_shortest_exhaustively_matches_pinned_regex() {
    let cases = [
        r"(?-u:[ab]?[ab]?zaz)",
        r"(?-u:[ab]{0,3}?[ab]{0,2}zaz)",
    ];
    for pattern in cases {
        let auto = build_auto(pattern);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            auto.runtime_implementation_id(),
            NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
            "pattern={pattern:?}"
        );
        enumerate_haystacks(b"abz", 8, |haystack| {
            for start in 0..=haystack.len() {
                assert_eq!(
                    auto.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    upstream.shortest_match_at(haystack, start),
                    "shortest pattern={pattern:?} haystack={haystack:?} start={start}"
                );
                assert_eq!(
                    span(
                        auto.find_at(haystack, start, SearchLimits::unlimited())
                            .unwrap()
                            .0
                    ),
                    upstream
                        .find_at(haystack, start)
                        .map(|matched| (matched.start(), matched.end())),
                    "find pattern={pattern:?} haystack={haystack:?} start={start}"
                );
            }
            assert_eq!(
                auto.selected_end(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                upstream.find(haystack).map(|matched| matched.end()),
                "selected pattern={pattern:?} haystack={haystack:?}"
            );
        });
    }
}

#[test]
fn declined_head_overlap_exhaustively_matches_the_existing_k0_fallback() {
    let cases = [
        r"(?-u:[ab]?[ab]?aba)",
        r"(?-u:[ab]??[ab]??aba)",
        r"(?-u:[ab]{0,3}?[ab]{0,2}aba)",
        r"(?-u:[ab]?[ab]?abab)",
    ];
    for pattern in cases {
        let auto = build_auto(pattern);
        let fallback = build_k0(pattern);
        assert_ne!(
            auto.runtime_implementation_id(),
            NULLABLE_OPTIONAL_CHAIN_PLAN_ID,
            "pattern={pattern:?}"
        );
        enumerate_haystacks(b"abz", 8, |haystack| {
            for start in 0..=haystack.len() {
                assert_eq!(
                    auto.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    fallback
                        .shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    "shortest pattern={pattern:?} haystack={haystack:?} start={start}"
                );
                assert_eq!(
                    span(
                        auto.find_at(haystack, start, SearchLimits::unlimited())
                            .unwrap()
                            .0
                    ),
                    span(
                        fallback
                            .find_at(haystack, start, SearchLimits::unlimited())
                            .unwrap()
                            .0
                    ),
                    "find pattern={pattern:?} haystack={haystack:?} start={start}"
                );
            }
            assert_eq!(
                auto.selected_end(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                fallback
                    .selected_end(haystack, SearchLimits::unlimited())
                    .unwrap()
                    .0,
                "selected pattern={pattern:?} haystack={haystack:?}"
            );
        });
    }
}

#[test]
fn persistent_limit_is_checked_at_the_exact_projected_total() {
    let pattern = r"(?-u:a?b?c?d?e?f?g?h?tail)";
    let baseline = build_auto(pattern);
    let needed = baseline.build_report().charged_persistent_bytes;
    assert_eq!(baseline.runtime_implementation_id(), NULLABLE_OPTIONAL_CHAIN_PLAN_ID);
    let exact = PortableBuilder::new(pattern)
        .unicode(false)
        .max_persistent_bytes(needed)
        .build()
        .unwrap();
    assert_eq!(exact.build_report().charged_persistent_bytes, needed);
    assert_eq!(exact.runtime_implementation_id(), NULLABLE_OPTIONAL_CHAIN_PLAN_ID);
    let below_limit = needed.checked_sub(1).unwrap();
    assert!(matches!(
        PortableBuilder::new(pattern)
            .unicode(false)
            .max_persistent_bytes(below_limit)
            .build(),
        Err(BuildError::PersistentBytesLimit {
            needed: actual_needed,
            limit,
        }) if actual_needed == needed && limit == below_limit
    ));
}

#[test]
fn text_facade_does_not_select_the_byte_optional_chain_route() {
    let pattern = r"a?b?c?d?tail";
    let text = PortableTextBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    let (_, accounting) = text
        .find_accounted("abcdtail", SearchLimits::unlimited())
        .unwrap();
    assert!(!matches!(
        accounting,
        SearchAccounting::NullableOptionalChain(_)
    ));
    let session = text
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    assert_ne!(session.runtime_implementation_id(), NULLABLE_OPTIONAL_CHAIN_PLAN_ID);
}
