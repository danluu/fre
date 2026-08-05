use fre::{
    BuildError, NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID, NullableOptionalChainSearchError,
    PlanKind, PlanSelection, PortableBuilder, PortableCapturesReadError,
    PortableFindIterLimits, SearchAccounting, SearchError, SearchLimits, SearchWindow,
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
fn variable_tokens_prefix_sharing_and_ambiguity_match_upstream_and_k0() {
    let patterns = [
        r"(?-u:(?:a|aa|ba){0,3}z)",
        r"(?-u:(?:aa|a|ba){0,3}z)",
        r"(?-u:(?:a|aa|ba){0,3}?z)",
        r"(?-u:(?:(a|aa|ba)){0,3}z)",
    ];
    for pattern in patterns {
        let auto = build_auto(pattern);
        let k0 = build_k0(pattern);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(auto.build_report().plan, PlanKind::RequiredLiteral);
        assert_eq!(
            auto.runtime_implementation_id(),
            NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
            "pattern={pattern:?}",
        );
        assert_eq!(k0.build_report().plan, PlanKind::K0);

        enumerate_haystacks(b"abz", 7, |haystack| {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, accounting) = auto
                    .find_at(haystack, start, SearchLimits::unlimited())
                    .unwrap();
                assert_eq!(span(actual), expected, "{pattern:?}/{haystack:?}/{start}");
                let SearchAccounting::NullableOptionalChain(accounting) = accounting else {
                    panic!("finite-token route lost its direct accounting");
                };
                assert_eq!(accounting.plan_id, NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID);
                assert_eq!(
                    span(
                        k0.find_at(haystack, start, SearchLimits::unlimited())
                            .unwrap()
                            .0,
                    ),
                    expected,
                    "K0 {pattern:?}/{haystack:?}/{start}",
                );
                assert_eq!(
                    auto.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    upstream.shortest_match_at(haystack, start),
                    "shortest {pattern:?}/{haystack:?}/{start}",
                );
                assert_eq!(
                    auto.is_match_at(haystack, start, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    expected.is_some(),
                    "exists {pattern:?}/{haystack:?}/{start}",
                );
            }
        });
    }
}

#[test]
fn mixed_width_dictionary_preserves_windows_iteration_and_selected_end() {
    let pattern = r"(?-u:(?:\x21\x31|\x21\x32|\x22){0,5}\x7d)";
    let auto = build_auto(pattern);
    let upstream = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(
        auto.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
    let haystack = b"xx!1!2\x22}yy\x22!1}zz";
    for window in [
        SearchWindow::full(haystack),
        SearchWindow::new(2, 9),
        SearchWindow::new(3, 9),
        SearchWindow::new(10, 15),
    ] {
        let sliced = &haystack[window.start()..window.end()];
        let expected = upstream.find(sliced).map(|matched| {
            (
                window.start().checked_add(matched.start()).unwrap(),
                window.start().checked_add(matched.end()).unwrap(),
            )
        });
        assert_eq!(
            span(
                auto.find_window(haystack, window, SearchLimits::unlimited())
                    .unwrap()
                    .0,
            ),
            expected,
        );
    }
    assert_eq!(
        auto.selected_end(haystack, SearchLimits::unlimited())
            .unwrap()
            .0,
        upstream.find(haystack).map(|matched| matched.end()),
    );
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

#[test]
fn tail_head_anywhere_in_a_token_declines_the_direct_route() {
    for pattern in [
        r"(?-u:(?:ab|cd){0,3}ba)",
        r"(?-u:(?:xa|bc){0,3}az)",
        r"(?-u:(?:pq|rzs){0,3}z)",
    ] {
        let auto = build_auto(pattern);
        let k0 = build_k0(pattern);
        assert_ne!(
            auto.runtime_implementation_id(),
            NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
            "pattern={pattern:?}",
        );
        enumerate_haystacks(b"abcdxyz", 4, |haystack| {
            assert_eq!(
                span(auto.find(haystack, SearchLimits::unlimited()).unwrap().0),
                span(k0.find(haystack, SearchLimits::unlimited()).unwrap().0),
                "pattern={pattern:?} haystack={haystack:?}",
            );
        });
    }
}

#[test]
fn repetition_and_prefix_horizon_boundaries_are_exact() {
    let repeat_maximum = build_auto(r"(?-u:(?:ab|cd){0,63}z)");
    assert_eq!(
        repeat_maximum.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
    assert_ne!(
        build_auto(r"(?-u:(?:ab|cd){0,64}z)").runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );

    let horizon_maximum = build_auto(r"(?-u:(?:abcdefgh|ABCDEFGH){0,63}z)");
    assert_eq!(
        horizon_maximum.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
    assert_ne!(
        build_auto(r"(?-u:(?:abcdefghi|ABCDEFGHI){0,63}z)").runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );

    let token64_a = "a".repeat(64);
    let token64_b = "b".repeat(64);
    let exact_512 = format!(r"(?-u:(?:{token64_a}|{token64_b}){{0,8}}z)");
    assert_eq!(
        build_auto(&exact_512).runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
    let token65_a = "a".repeat(65);
    let token65_b = "b".repeat(65);
    let overlong_token = format!(r"(?-u:(?:{token65_a}|{token65_b}){{0,1}}z)");
    assert_ne!(
        build_auto(&overlong_token).runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
    let token57_a = "a".repeat(57);
    let token57_b = "b".repeat(57);
    let horizon_513 = format!(r"(?-u:(?:{token57_a}|{token57_b}){{0,9}}z)");
    assert_ne!(
        build_auto(&horizon_513).runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
}

#[test]
fn dictionary_count_and_total_byte_boundaries_are_exact() {
    let tokens32 = (0..32)
        .map(|index| format!("t{index:07}"))
        .collect::<Vec<_>>();
    assert_eq!(tokens32.iter().map(String::len).sum::<usize>(), 256);
    let exact = format!(r"(?-u:(?:{}){{0,1}}z)", tokens32.join("|"));
    assert_eq!(
        build_auto(&exact).runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );

    let tokens33 = (0..33)
        .map(|index| format!("q{index:05}"))
        .collect::<Vec<_>>();
    assert!(tokens33.iter().map(String::len).sum::<usize>() < 256);
    let too_many = format!(r"(?-u:(?:{}){{0,1}}z)", tokens33.join("|"));
    assert_ne!(
        build_auto(&too_many).runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );

    let mut tokens257 = (0..32)
        .map(|index| format!("r{index:07}"))
        .collect::<Vec<_>>();
    tokens257[31].push('x');
    assert_eq!(tokens257.iter().map(String::len).sum::<usize>(), 257);
    let too_many_bytes = format!(r"(?-u:(?:{}){{0,1}}z)", tokens257.join("|"));
    assert_ne!(
        build_auto(&too_many_bytes).runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
}

#[test]
fn captures_and_greedy_modes_keep_match_span_parity() {
    let patterns = [
        r"(?-u:((?:ab|cd){0,3})(z))",
        r"(?-u:((?:ab|cd){0,3}?)(z))",
        r"(?-u:(?:(ab)|(cd)){0,3}z)",
    ];
    for pattern in patterns {
        let auto = build_auto(pattern);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(
            auto.runtime_implementation_id(),
            NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
            "pattern={pattern:?}",
        );
        for haystack in [b"abcdabz".as_slice(), b"xxcdz".as_slice(), b"z".as_slice()] {
            assert_eq!(
                span(auto.find(haystack, SearchLimits::unlimited()).unwrap().0),
                upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end())),
            );
        }
        let mut locations = auto.capture_locations();
        assert!(matches!(
            auto.captures_read(&mut locations, b"abcdabz", SearchLimits::unlimited()),
            Err(PortableCapturesReadError::ExplicitCapturesUnsupported { .. })
        ));
    }
}

#[test]
fn span_work_limit_accepts_the_bound_and_rejects_one_below() {
    let regex = build_auto(r"(?-u:(?:a|aa|ba){0,5}z)");
    let haystack = b"xxaabaabazyy";
    let (_, accounting) = regex.find(haystack, SearchLimits::unlimited()).unwrap();
    let SearchAccounting::NullableOptionalChain(accounting) = accounting else {
        panic!("expected nullable finite-token accounting");
    };
    assert_eq!(accounting.plan_id, NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID);
    let exact = SearchLimits {
        max_work: accounting.work_upper_bound,
        max_scratch_bytes: usize::from(accounting.scratch_bytes),
    };
    assert_eq!(
        usize::from(accounting.scratch_bytes),
        513 * core::mem::size_of::<u64>(),
    );
    assert_eq!(accounting.actual_scratch_bytes, accounting.scratch_bytes);
    assert!(regex.find(haystack, exact).is_ok());
    assert!(regex.selected_end(haystack, exact).is_ok());
    let below = SearchLimits {
        max_work: accounting.work_upper_bound.checked_sub(1).unwrap(),
        max_scratch_bytes: 0,
    };
    assert!(matches!(
        regex.find(haystack, below),
        Err(SearchError::NullableOptionalChain(
            NullableOptionalChainSearchError::WorkLimit { needed, limit }
        )) if needed == accounting.work_upper_bound && limit == below.max_work
    ));
    let scratch_below = SearchLimits {
        max_work: accounting.work_upper_bound,
        max_scratch_bytes: usize::from(accounting.scratch_bytes.checked_sub(1).unwrap()),
    };
    assert!(matches!(
        regex.find(haystack, scratch_below),
        Err(SearchError::NullableOptionalChain(
            NullableOptionalChainSearchError::ScratchLimit { needed, limit }
        )) if needed == usize::from(accounting.scratch_bytes)
            && limit == scratch_below.max_scratch_bytes
    ));
    let scratch_free = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: 0,
    };
    assert!(regex.is_match(haystack, scratch_free).is_ok());
    assert!(regex.shortest_match(haystack, scratch_free).is_ok());

    let no_tail = b"xxaabaabayy";
    let (matched, no_tail_accounting) = regex
        .find(no_tail, SearchLimits::unlimited())
        .unwrap();
    assert!(matched.is_none());
    let SearchAccounting::NullableOptionalChain(no_tail_accounting) = no_tail_accounting else {
        panic!("expected nullable finite-token accounting");
    };
    assert_eq!(no_tail_accounting.scratch_bytes, accounting.scratch_bytes);
    assert_eq!(no_tail_accounting.actual_scratch_bytes, 0);
    let no_tail_below = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: usize::from(no_tail_accounting.scratch_bytes) - 1,
    };
    assert!(matches!(
        regex.find(no_tail, no_tail_below),
        Err(SearchError::NullableOptionalChain(
            NullableOptionalChainSearchError::ScratchLimit { needed, limit }
        )) if needed == usize::from(no_tail_accounting.scratch_bytes)
            && limit == no_tail_below.max_scratch_bytes
    ));
}

#[test]
fn persistent_limit_is_checked_at_the_exact_projected_total() {
    let pattern = r"(?-u:(?:ab|cd|efg|hijk){0,7}z)";
    let baseline = build_auto(pattern);
    let needed = baseline.build_report().charged_persistent_bytes;
    assert_eq!(
        baseline.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
    let exact = PortableBuilder::new(pattern)
        .unicode(false)
        .max_persistent_bytes(needed)
        .build()
        .unwrap();
    assert_eq!(exact.build_report().charged_persistent_bytes, needed);
    assert_eq!(
        exact.runtime_implementation_id(),
        NULLABLE_FINITE_TOKEN_REPEAT_PLAN_ID,
    );
    let below = needed.checked_sub(1).unwrap();
    assert!(matches!(
        PortableBuilder::new(pattern)
            .unicode(false)
            .max_persistent_bytes(below)
            .build(),
        Err(BuildError::PersistentBytesLimit { needed: actual, limit })
            if actual == needed && limit == below
    ));
}
