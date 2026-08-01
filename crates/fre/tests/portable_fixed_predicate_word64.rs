use fre::{
    BuildError, BuildLimits, EXPLAIN_SCHEMA_VERSION, FixedPredicateWord64Reducer, PlanKind,
    PlanSelection, PortableBuilder, PortableCapturesReadError, PortableFindIterLimits, RustProfile,
    SearchAccounting, SearchError, SearchLimits, SearchSessionLimits, SearchWindow,
};

const ONE_ANCHOR_PATTERN: &str = r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]";
const TWO_ANCHOR_PATTERN: &str = r"[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]";
const SHIFT_AND_PATTERN: &str = r"[abc][def][ghi][jkl][mno][pqr][stu][vwx]";

fn build_auto(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("Auto build failed for {pattern:?}: {error:?}"))
}

fn build_k0(pattern: &str) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap_or_else(|error| panic!("forced K0 build failed for {pattern:?}: {error:?}"))
}

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

#[test]
fn default_large_cartesian_languages_select_each_fixed_predicate_reducer() {
    let cases: [(&str, &[u8], FixedPredicateWord64Reducer); 3] = [
        (
            ONE_ANCHOR_PATTERN,
            b"--Qacegikmortvx0--",
            FixedPredicateWord64Reducer::OneByteAnchor,
        ),
        (
            TWO_ANCHOR_PATTERN,
            b"--acegikmortvx0--",
            FixedPredicateWord64Reducer::TwoByteAnchor,
        ),
        (
            SHIFT_AND_PATTERN,
            b"--adgjmpsv--",
            FixedPredicateWord64Reducer::ShiftAnd,
        ),
    ];
    for (pattern, haystack, reducer) in cases {
        let regex = build_auto(pattern);
        assert_eq!(regex.build_report().plan, PlanKind::FixedPredicateWord64);
        assert!(regex.build_report().lowering.is_none());
        assert_eq!(regex.build_report().states, 0);
        assert_eq!(regex.build_report().edges, 0);
        assert_eq!(
            regex.build_report().charged_persistent_bytes,
            regex
                .build_report()
                .source_storage_bytes
                .checked_add(regex.build_report().capture_name_storage_bytes)
                .and_then(|bytes| bytes.checked_add(regex.build_report().plan_storage_bytes))
                .unwrap()
        );
        let (matched, accounting) = regex.find(haystack, SearchLimits::unlimited()).unwrap();
        assert!(matched.is_some(), "pattern={pattern:?}");
        let SearchAccounting::FixedPredicateWord64(accounting) = accounting else {
            panic!("fixed-predicate route published another accounting family");
        };
        assert_eq!(accounting.identity.reducer, reducer);
        assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
        assert_eq!(accounting.actual.scratch_bytes, 0);
    }
}

#[test]
fn fixed_predicate_facade_matches_forced_k0_for_all_windows_endpoints_and_iteration() {
    let native = build_auto(ONE_ANCHOR_PATTERN);
    let k0 = build_k0(ONE_ANCHOR_PATTERN);
    assert_eq!(native.build_report().plan, PlanKind::FixedPredicateWord64);
    assert_eq!(k0.build_report().plan, PlanKind::K0);

    let mut haystack = b"miss-Qacegikmortvx1-gap-Qbdfhjlnpsuwy0-tail".to_vec();
    haystack.extend_from_slice(&[0, 0x80, 0xFF]);
    let limits = SearchLimits::unlimited();
    for start in 0..=haystack.len() {
        for end in start..=haystack.len() {
            let window = SearchWindow::new(start, end);
            let (native_match, native_accounting) =
                native.find_window(&haystack, window, limits).unwrap();
            let (k0_match, _) = k0.find_window(&haystack, window, limits).unwrap();
            assert_eq!(span(native_match), span(k0_match), "window={start}..{end}");
            assert!(matches!(
                native_accounting,
                SearchAccounting::FixedPredicateWord64(_)
            ));
            assert_eq!(
                span(native.find_window_value(&haystack, window, limits).unwrap()),
                span(k0.find_window_value(&haystack, window, limits).unwrap()),
                "compact window={start}..{end}"
            );
            assert_eq!(
                native.is_match_window(&haystack, window, limits).unwrap().0,
                k0.is_match_window(&haystack, window, limits).unwrap().0,
                "exists window={start}..{end}"
            );
            assert_eq!(
                native
                    .is_match_window_value(&haystack, window, limits)
                    .unwrap(),
                k0.is_match_window_value(&haystack, window, limits).unwrap(),
                "compact exists window={start}..{end}"
            );
        }
        assert_eq!(
            span(native.find_at(&haystack, start, limits).unwrap().0),
            span(k0.find_at(&haystack, start, limits).unwrap().0)
        );
        assert_eq!(
            native
                .shortest_match_at(&haystack, start, limits)
                .unwrap()
                .0,
            k0.shortest_match_at(&haystack, start, limits).unwrap().0
        );
    }
    assert_eq!(
        native.selected_end(&haystack, limits).unwrap().0,
        k0.selected_end(&haystack, limits).unwrap().0
    );

    let native_matches: Result<Vec<_>, _> = native
        .find_iter(&haystack, PortableFindIterLimits::unlimited())
        .unwrap()
        .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
        .collect();
    let k0_matches: Result<Vec<_>, _> = k0
        .find_iter(&haystack, PortableFindIterLimits::unlimited())
        .unwrap()
        .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
        .collect();
    assert_eq!(native_matches.unwrap(), k0_matches.unwrap());

    let native_fields: Result<Vec<_>, _> = native
        .split(&haystack, PortableFindIterLimits::unlimited())
        .unwrap()
        .map(|field| field.map(<[u8]>::to_vec))
        .collect();
    let k0_fields: Result<Vec<_>, _> = k0
        .split(&haystack, PortableFindIterLimits::unlimited())
        .unwrap()
        .map(|field| field.map(<[u8]>::to_vec))
        .collect();
    assert_eq!(native_fields.unwrap(), k0_fields.unwrap());
}

#[test]
fn fixed_predicate_sessions_retain_no_workspace() {
    let regex = build_auto(ONE_ANCHOR_PATTERN);
    assert_eq!(regex.build_report().plan, PlanKind::FixedPredicateWord64);
    let haystack = b"miss-Qacegikmortvx1-tail";
    let limits = SearchLimits::unlimited();

    let mut full = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("native full session needs no setup allocation");
    assert_eq!(full.workspace_setup_accounting(), None);
    assert_eq!(
        full.runtime_implementation_id(),
        regex.runtime_implementation_id()
    );
    assert_eq!(
        span(full.find_value(haystack, limits).unwrap()),
        span(regex.find_value(haystack, limits).unwrap())
    );

    let mut endpoint = regex
        .endpoint_search_session(SearchSessionLimits::unlimited())
        .expect("native endpoint session needs no setup allocation");
    assert_eq!(endpoint.workspace_setup_accounting(), None);
    assert_eq!(
        endpoint.runtime_implementation_id(),
        regex.runtime_implementation_id()
    );
    assert_eq!(
        endpoint.selected_end(haystack, limits).unwrap().0,
        regex.selected_end(haystack, limits).unwrap().0
    );
}

#[test]
fn fixed_predicate_limits_close_at_exact_planner_persistent_and_search_bounds() {
    let baseline = build_auto(ONE_ANCHOR_PATTERN);
    let report = baseline.build_report();
    assert!(report.planner_work > 0);
    assert!(report.charged_persistent_bytes > 0);

    let mut exact_planner = BuildLimits::default();
    exact_planner.max_planner_work = report.planner_work;
    let exact = PortableBuilder::new(ONE_ANCHOR_PATTERN)
        .unicode(false)
        .limits(exact_planner)
        .build()
        .unwrap();
    assert_eq!(exact.build_report().planner_work, report.planner_work);
    let mut below_planner = exact_planner;
    below_planner.max_planner_work = report.planner_work - 1;
    assert!(matches!(
        PortableBuilder::new(ONE_ANCHOR_PATTERN)
            .unicode(false)
            .limits(below_planner)
            .build(),
        Err(BuildError::PlannerWorkLimit { .. })
    ));

    let exact_persistent = PortableBuilder::new(ONE_ANCHOR_PATTERN)
        .unicode(false)
        .max_persistent_bytes(report.charged_persistent_bytes)
        .build()
        .unwrap();
    assert_eq!(
        exact_persistent.build_report().charged_persistent_bytes,
        report.charged_persistent_bytes
    );
    assert!(matches!(
        PortableBuilder::new(ONE_ANCHOR_PATTERN)
            .unicode(false)
            .max_persistent_bytes(report.charged_persistent_bytes - 1)
            .build(),
        Err(BuildError::PersistentBytesLimit { .. })
    ));

    let haystack = b"--Qacegikmortvx0--";
    let (_, accounting) = baseline.find(haystack, SearchLimits::unlimited()).unwrap();
    let SearchAccounting::FixedPredicateWord64(accounting) = accounting else {
        panic!("expected fixed-predicate accounting");
    };
    let exact_search = SearchLimits {
        max_work: accounting.upper_bounds.work,
        max_scratch_bytes: 0,
    };
    assert!(baseline.find(haystack, exact_search).is_ok());
    assert!(baseline.find_value(haystack, exact_search).is_ok());
    let below_search = SearchLimits {
        max_work: accounting.upper_bounds.work - 1,
        max_scratch_bytes: 0,
    };
    assert!(matches!(
        baseline.find(haystack, below_search),
        Err(SearchError::FixedPredicateWord64(
            fre::FixedPredicateWord64SearchError::WorkLimit { .. }
        ))
    ));
    assert!(matches!(
        baseline.find_value(haystack, below_search),
        Err(SearchError::FixedPredicateWord64(
            fre::FixedPredicateWord64SearchError::WorkLimit { .. }
        ))
    ));
}

#[test]
fn fixed_predicate_admission_preserves_finite_incumbents_and_k0_refusals() {
    assert_eq!(
        build_auto("abc").build_report().plan,
        PlanKind::ExactLiteral
    );
    assert_eq!(
        build_auto("ab|ac|ad").build_report().plan,
        PlanKind::PackedLiteralSet
    );
    let dfa = PortableBuilder::new("ab|ac|ad")
        .unicode(false)
        .limits(BuildLimits {
            packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
                max_patterns: 0,
                ..fre_kernels::PackedLiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        })
        .build()
        .unwrap();
    assert_eq!(dfa.build_report().plan, PlanKind::LiteralSetDfa);

    let mut width_65 = String::new();
    for index in 0..65 {
        width_65.push_str(if index % 2 == 0 { "[abc]" } else { "[def]" });
    }
    assert_eq!(build_auto(&width_65).build_report().plan, PlanKind::K0);

    let asserted = format!("{SHIFT_AND_PATTERN}$");
    assert_eq!(build_auto(&asserted).build_report().plan, PlanKind::K0);
    let alternation = format!("(?:{SHIFT_AND_PATTERN}|[xyz]{SHIFT_AND_PATTERN})");
    assert_eq!(build_auto(&alternation).build_report().plan, PlanKind::K0);
    assert_eq!(
        build_auto("[abc]{8,9}[def]{8,9}").build_report().plan,
        PlanKind::K0
    );
}

#[test]
fn unicode_classes_and_profiles_remain_k0_and_match_regex_bytes() {
    let patterns = [
        (r"\p{Greek}Q[ab][cd][ef][gh][ij][kl][mn][op]", true),
        (r"(?u:\p{Greek})Q[ab][cd][ef][gh][ij][kl][mn][op]", false),
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        "xxαQacegikmozz".as_bytes(),
        "βQbdfhjlnp αQacegikmo".as_bytes(),
        b"\xffQacegikmo",
    ];
    for profile in [RustProfile::regex_1_12_4(), RustProfile::rebar_1_12_4()] {
        for &(pattern, unicode) in &patterns {
            let regex = PortableBuilder::new(pattern)
                .profile(profile.clone())
                .unicode(unicode)
                .build()
                .unwrap_or_else(|error| {
                    panic!("Unicode fallback build failed for {pattern:?}: {error:?}")
                });
            assert_eq!(
                regex.build_report().plan,
                PlanKind::K0,
                "pattern={pattern:?}, profile={profile:?}"
            );
            let upstream = regex::bytes::RegexBuilder::new(pattern)
                .unicode(unicode)
                .build()
                .unwrap();
            for &haystack in haystacks {
                let expected = upstream
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let (actual, accounting) = regex.find(haystack, SearchLimits::unlimited()).unwrap();
                assert_eq!(span(actual), expected, "pattern={pattern:?}");
                assert!(matches!(accounting, SearchAccounting::K0(_)));
                assert_eq!(
                    regex
                        .is_match_value(haystack, SearchLimits::unlimited())
                        .unwrap(),
                    expected.is_some(),
                    "exists pattern={pattern:?}"
                );
                assert_eq!(
                    regex
                        .selected_end(haystack, SearchLimits::unlimited())
                        .unwrap()
                        .0,
                    expected.map(|(_, end)| end),
                    "selected-end pattern={pattern:?}"
                );
            }
        }
    }
}

#[test]
fn fixed_predicate_capture_metadata_and_explicit_capture_refusal_are_preserved() {
    let captured_pattern = format!(r"(?P<lead>Q){}", &ONE_ANCHOR_PATTERN[1..]);
    let captured = build_auto(&captured_pattern);
    assert_eq!(captured.build_report().plan, PlanKind::FixedPredicateWord64);
    assert_eq!(captured.captures_len(), 2);
    assert_eq!(
        captured.capture_names().collect::<Vec<_>>(),
        vec![None, Some("lead")]
    );
    let mut locations = captured.capture_locations();
    assert!(matches!(
        captured.captures_read(&mut locations, b"Qacegikmortvx0", SearchLimits::unlimited()),
        Err(PortableCapturesReadError::ExplicitCapturesUnsupported { captures: 1 })
    ));
    assert_eq!(locations.get(0), None);
    assert_eq!(locations.get(1), None);
}

#[test]
fn fixed_predicate_schema_is_pinned_to_nine() {
    assert_eq!(EXPLAIN_SCHEMA_VERSION, 9);
}
