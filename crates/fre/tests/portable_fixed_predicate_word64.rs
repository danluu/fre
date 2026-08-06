use fre::{
    BuildError, BuildLimits, EXPLAIN_SCHEMA_VERSION, FixedPredicateWord64Reducer, PlanKind,
    PlanSelection, PortableBuilder, PortableCapturesReadError, PortableFindIterLimits, RustProfile,
    SearchAccounting, SearchError, SearchLimits, SearchSessionLimits, SearchWindow,
};

const ONE_ANCHOR_PATTERN: &str = r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]";
const TWO_ANCHOR_PATTERN: &str = r"[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]";
const GENERAL_PAIR_PATTERN: &str = r"[abc][def][ghi][jkl][mno][pqr][stu][vwx]";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatrixReducer {
    One,
    Two,
    GeneralPair,
}

fn matrix_pattern(width: usize, reducer: MatrixReducer, anchor_offset: Option<usize>) -> String {
    let mut pattern = String::new();
    for position in 0..width {
        if Some(position) == anchor_offset {
            let anchor = match (reducer, position) {
                (MatrixReducer::One, 0) => "e",
                (MatrixReducer::One, _) if position + 1 == width => "/",
                (MatrixReducer::One, _) => r"\x01",
                (MatrixReducer::Two, 0) => "[e0]",
                (MatrixReducer::Two, _) if position + 1 == width => "[/0]",
                (MatrixReducer::Two, _) => r"[\x01\x02]",
                (MatrixReducer::GeneralPair, _) => {
                    panic!("general pair has no exact-anchor offset")
                }
            };
            pattern.push_str(anchor);
        } else {
            pattern.push_str(match position % 3 {
                0 => "[abc]",
                1 => "[d-g]",
                _ => "[h-l]",
            });
        }
    }
    pattern
}

fn raw_shift_and_pattern(width: usize) -> String {
    r"[\x00-\x7E]".repeat(width)
}

fn matrix_word(width: usize, reducer: MatrixReducer, anchor_offset: Option<usize>) -> Vec<u8> {
    (0..width)
        .map(|position| {
            if Some(position) == anchor_offset {
                match (reducer, position) {
                    (MatrixReducer::One, 0) | (MatrixReducer::Two, 0) => b'e',
                    (MatrixReducer::One, _) if position + 1 == width => b'/',
                    (MatrixReducer::Two, _) if position + 1 == width => b'/',
                    (MatrixReducer::One | MatrixReducer::Two, _) => 1,
                    (MatrixReducer::GeneralPair, _) => {
                        panic!("general pair has no exact-anchor offset")
                    }
                }
            } else {
                match position % 3 {
                    0 => b'a',
                    1 => b'd',
                    _ => b'h',
                }
            }
        })
        .collect()
}

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
fn default_large_cartesian_languages_select_certified_fixed_reducers() {
    let cases: [(&str, &[u8], Option<FixedPredicateWord64Reducer>); 3] = [
        (
            ONE_ANCHOR_PATTERN,
            b"--Qacegikmortvx0--",
            Some(FixedPredicateWord64Reducer::OneByteAnchor),
        ),
        (
            TWO_ANCHOR_PATTERN,
            b"--acegikmortvx0--",
            Some(FixedPredicateWord64Reducer::TwoByteAnchor),
        ),
        (
            GENERAL_PAIR_PATTERN,
            b"--adgjmpsv--",
            Some(FixedPredicateWord64Reducer::ShiftAnd),
        ),
    ];
    for (pattern, haystack, reducer) in cases {
        let regex = build_auto(pattern);
        let (matched, accounting) = regex.find(haystack, SearchLimits::unlimited()).unwrap();
        assert!(matched.is_some(), "pattern={pattern:?}");
        if let Some(reducer) = reducer {
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
            let SearchAccounting::FixedPredicateWord64(accounting) = accounting else {
                panic!("fixed-predicate route published another accounting family");
            };
            assert_eq!(accounting.identity.reducer, reducer);
            assert_eq!(
                accounting.identity.primary_finder.is_some(),
                pattern == GENERAL_PAIR_PATTERN
            );
            assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
            assert_eq!(accounting.actual.scratch_bytes, 0);
        } else {
            assert_eq!(regex.build_report().plan, PlanKind::K0);
            assert!(matches!(accounting, SearchAccounting::K0(_)));
        }
    }
}

#[test]
fn fixed_predicate_auto_route_matrix_admits_selective_words_through_width_64() {
    for width in [12, 15, 16, 17, 24, 32, 48, 64] {
        for reducer in [
            MatrixReducer::One,
            MatrixReducer::Two,
            MatrixReducer::GeneralPair,
        ] {
            let offsets = match reducer {
                MatrixReducer::One | MatrixReducer::Two => {
                    vec![Some(0), Some(width / 2), Some(width - 1)]
                }
                MatrixReducer::GeneralPair => vec![None],
            };
            for anchor_offset in offsets {
                let pattern = matrix_pattern(width, reducer, anchor_offset);
                let regex = build_auto(&pattern);
                let word = matrix_word(width, reducer, anchor_offset);
                let (matched, accounting) = regex
                    .find(&word, SearchLimits::unlimited())
                    .unwrap_or_else(|error| {
                        panic!(
                            "matrix search failed width={width} reducer={reducer:?} offset={anchor_offset:?}: {error:?}"
                        )
                    });
                assert_eq!(span(matched), Some((0, width)));
                assert_eq!(
                    regex.build_report().plan,
                    PlanKind::FixedPredicateWord64,
                    "width={width} reducer={reducer:?} offset={anchor_offset:?}"
                );
                let SearchAccounting::FixedPredicateWord64(accounting) = accounting else {
                    panic!(
                        "admitted matrix route lost fixed accounting width={width} reducer={reducer:?} offset={anchor_offset:?}"
                    );
                };
                let expected = match reducer {
                    MatrixReducer::One => FixedPredicateWord64Reducer::OneByteAnchor,
                    MatrixReducer::Two => FixedPredicateWord64Reducer::TwoByteAnchor,
                    MatrixReducer::GeneralPair => FixedPredicateWord64Reducer::ShiftAnd,
                };
                assert_eq!(accounting.identity.reducer, expected);
                assert_eq!(
                    accounting.identity.primary_finder.is_some(),
                    reducer == MatrixReducer::GeneralPair
                );
                let session = regex
                    .search_session(SearchSessionLimits::unlimited())
                    .unwrap();
                assert_eq!(session.workspace_setup_accounting(), None);
            }
        }
    }

    let folded_16 = format!("(?i:{})", "a".repeat(16));
    assert_eq!(
        build_auto(&folded_16).build_report().plan,
        PlanKind::FixedPredicateWord64
    );
    let folded_17 = format!("(?i:{})", "a".repeat(17));
    assert_eq!(
        build_auto(&folded_17).build_report().plan,
        PlanKind::FixedPredicateWord64,
        "an anchored fixed-width proof must stay on the fixed engine"
    );
}

fn matrix_haystacks(
    width: usize,
    reducer: MatrixReducer,
    anchor_offset: Option<usize>,
) -> Vec<Vec<u8>> {
    let word = matrix_word(width, reducer, anchor_offset);
    let mut early = word.clone();
    early.extend_from_slice(&[0x7f; 19]);

    let mut late = vec![0x7f; width * 3 + 17];
    late.extend_from_slice(&word);

    let absent = vec![0x7f; width * 4 + 31];

    let mut rejected = vec![0x7f; width * 4 + 31];
    if let Some(offset) = anchor_offset {
        for start in (1..rejected.len().saturating_sub(width)).step_by(5) {
            rejected[start + offset] = word[offset];
        }
    }

    let mut dense = Vec::new();
    for _ in 0..4 {
        dense.extend_from_slice(&word);
        dense.push(0x7f);
    }
    vec![early, late, absent, rejected, dense]
}

fn structural_wide_case(
    width: usize,
    verification_positions: usize,
    anchor_pattern: &str,
) -> (String, Vec<u8>) {
    assert!(width > 16);
    assert!(verification_positions < width);
    let anchor_offset = width / 2;
    let verification_offsets: Vec<_> = (0..width)
        .filter(|&position| position != anchor_offset)
        .take(verification_positions)
        .collect();
    assert_eq!(verification_offsets.len(), verification_positions);

    let mut pattern = String::new();
    let mut word = vec![0x80; width];
    for position in 0..width {
        if position == anchor_offset {
            pattern.push_str(anchor_pattern);
            word[position] = b'Q';
        } else if verification_offsets.contains(&position) {
            pattern.push_str("[a-c]");
            word[position] = b'b';
        } else {
            pattern.push_str(r"[\x00-\xFF]");
        }
    }
    (pattern, word)
}

fn structural_wide_haystacks(word: &[u8]) -> Vec<Vec<u8>> {
    let width = word.len();
    let anchor_offset = width / 2;
    let mut early = word.to_vec();
    early.extend_from_slice(&[0xFF; 19]);

    let mut late = vec![0xFF; width * 3 + 17];
    late.extend_from_slice(word);

    let absent = vec![0xFF; width * 4 + 31];

    let mut rejected = absent.clone();
    for start in (1..rejected.len().saturating_sub(width)).step_by(5) {
        rejected[start + anchor_offset] = b'Q';
    }

    let mut dense = Vec::new();
    for _ in 0..4 {
        dense.extend_from_slice(word);
        dense.push(0xFF);
    }
    vec![early, late, absent, rejected, dense]
}

fn assert_structural_wide_parity(
    width: usize,
    verification_positions: usize,
    expected_plan: PlanKind,
) {
    assert_structural_wide_parity_with_anchor(width, verification_positions, "Q", expected_plan);
}

fn assert_structural_wide_parity_with_anchor(
    width: usize,
    verification_positions: usize,
    anchor_pattern: &str,
    expected_plan: PlanKind,
) {
    let (pattern, word) = structural_wide_case(width, verification_positions, anchor_pattern);
    let auto = build_auto(&pattern);
    let k0 = build_k0(&pattern);
    assert_eq!(
        auto.build_report().plan,
        expected_plan,
        "width={width} verification_positions={verification_positions}"
    );
    assert_eq!(k0.build_report().plan, PlanKind::K0);

    for haystack in structural_wide_haystacks(&word) {
        let limits = SearchLimits::unlimited();
        let (auto_match, accounting) = auto.find(&haystack, limits).unwrap();
        assert_eq!(
            span(auto_match),
            span(k0.find(&haystack, limits).unwrap().0)
        );
        assert_eq!(
            matches!(accounting, SearchAccounting::FixedPredicateWord64(_)),
            expected_plan == PlanKind::FixedPredicateWord64
        );
        assert_eq!(
            span(auto.find_value(&haystack, limits).unwrap()),
            span(k0.find_value(&haystack, limits).unwrap())
        );
        assert_eq!(
            auto.is_match_value(&haystack, limits).unwrap(),
            k0.is_match_value(&haystack, limits).unwrap()
        );
        assert_eq!(
            auto.shortest_match(&haystack, limits).unwrap().0,
            k0.shortest_match(&haystack, limits).unwrap().0
        );
        assert_eq!(
            auto.selected_end(&haystack, limits).unwrap().0,
            k0.selected_end(&haystack, limits).unwrap().0
        );

        let auto_matches: Result<Vec<_>, _> = auto
            .find_iter(&haystack, PortableFindIterLimits::unlimited())
            .unwrap()
            .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
            .collect();
        let k0_matches: Result<Vec<_>, _> = k0
            .find_iter(&haystack, PortableFindIterLimits::unlimited())
            .unwrap()
            .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
            .collect();
        assert_eq!(auto_matches.unwrap(), k0_matches.unwrap());

        let mut auto_session = auto
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let mut k0_session = k0.search_session(SearchSessionLimits::unlimited()).unwrap();
        assert_eq!(
            auto_session.workspace_setup_accounting().is_none(),
            expected_plan == PlanKind::FixedPredicateWord64
        );
        assert_eq!(
            span(auto_session.find_value(&haystack, limits).unwrap()),
            span(k0_session.find_value(&haystack, limits).unwrap())
        );
    }

    let mut guarded = vec![0xFF; 7];
    let window_start = guarded.len();
    guarded.extend_from_slice(&word);
    let window_end = guarded.len();
    guarded.extend_from_slice(&[0xFF; 7]);
    guarded.extend_from_slice(&word);
    let window = SearchWindow::new(window_start, window_end);
    assert_eq!(
        span(
            auto.find_window(&guarded, window, SearchLimits::unlimited())
                .unwrap()
                .0
        ),
        span(
            k0.find_window(&guarded, window, SearchLimits::unlimited())
                .unwrap()
                .0
        )
    );
}

#[test]
fn wide_auto_admission_counts_only_nonuniversal_verification_positions() {
    for (width, verification_positions) in [
        (64, 0),
        (17, 1),
        (24, 4),
        (32, 8),
        (48, 15),
        (64, 15),
        (17, 16),
        (24, 17),
        (32, 24),
        (48, 31),
        (48, 47),
        (64, 63),
    ] {
        assert_structural_wide_parity(
            width,
            verification_positions,
            PlanKind::FixedPredicateWord64,
        );
    }

    assert_structural_wide_parity_with_anchor(64, 15, "[QR]", PlanKind::FixedPredicateWord64);
    assert_structural_wide_parity_with_anchor(64, 63, "[QR]", PlanKind::FixedPredicateWord64);
}

#[test]
fn wide_universal_positions_charge_no_verification_work() {
    let (pattern, _) = structural_wide_case(64, 0, "Q");
    let regex = build_auto(&pattern);
    let haystack = vec![0xFF; 1024];
    let (matched, accounting) = regex.find(&haystack, SearchLimits::unlimited()).unwrap();
    assert_eq!(matched, None);
    let SearchAccounting::FixedPredicateWord64(accounting) = accounting else {
        panic!("wide V=0 route lost fixed-predicate accounting");
    };
    assert_eq!(accounting.upper_bounds.predicate_checks, 0);
    assert_eq!(accounting.actual.predicate_checks, 0);
    assert_eq!(accounting.actual.shift_and_transitions, 0);
}

#[test]
fn wide_set_fallback_can_handoff_to_shift_and() {
    let width = 48;
    let anchor_offset = width / 2;
    let mut pattern = String::new();
    for position in 0..width {
        if position == anchor_offset {
            pattern.push('Q');
        } else if position == 0 {
            pattern.push_str("[BDFH]");
        } else if position == 1 {
            pattern.push_str("[0-2X-Z]");
        } else if position < 15 {
            pattern.push_str("[A-Z]");
        } else {
            pattern.push_str(r"[\x00-\xFF]");
        }
    }
    let regex = build_auto(&pattern);
    assert_eq!(regex.build_report().plan, PlanKind::FixedPredicateWord64);

    let mut haystack = vec![b'B'; 512];
    for start in 0..=haystack.len() - width {
        haystack[start + anchor_offset] = b'Q';
    }
    let (_, accounting) = regex.find(&haystack, SearchLimits::unlimited()).unwrap();
    let SearchAccounting::FixedPredicateWord64(accounting) = accounting else {
        panic!("wide set-fallback route lost fixed-predicate accounting");
    };
    assert!(accounting.actual.finder_scanned_bytes > 0);
    assert!(accounting.actual.shift_and_transitions > 0);
    assert!(accounting.actual.predicate_checks > 0);
}

#[test]
fn fixed_predicate_v2_routes_match_k0_across_search_session_and_window_apis() {
    let cases = [
        (12, MatrixReducer::One, Some(0)),
        (15, MatrixReducer::Two, Some(15 / 2)),
        (16, MatrixReducer::One, Some(15)),
        (16, MatrixReducer::GeneralPair, None),
        (17, MatrixReducer::One, Some(17 / 2)),
        (24, MatrixReducer::Two, Some(24 / 2)),
    ];
    for (width, reducer, anchor_offset) in cases {
        let pattern = matrix_pattern(width, reducer, anchor_offset);
        let auto = build_auto(&pattern);
        let k0 = build_k0(&pattern);
        assert_eq!(auto.build_report().plan, PlanKind::FixedPredicateWord64);
        for haystack in matrix_haystacks(width, reducer, anchor_offset) {
            let limits = SearchLimits::unlimited();
            assert_eq!(
                span(auto.find(&haystack, limits).unwrap().0),
                span(k0.find(&haystack, limits).unwrap().0)
            );
            assert_eq!(
                span(auto.find_value(&haystack, limits).unwrap()),
                span(k0.find_value(&haystack, limits).unwrap())
            );
            assert_eq!(
                auto.is_match_value(&haystack, limits).unwrap(),
                k0.is_match_value(&haystack, limits).unwrap()
            );
            assert_eq!(
                auto.shortest_match(&haystack, limits).unwrap().0,
                k0.shortest_match(&haystack, limits).unwrap().0
            );
            assert_eq!(
                auto.selected_end(&haystack, limits).unwrap().0,
                k0.selected_end(&haystack, limits).unwrap().0
            );

            let auto_matches: Result<Vec<_>, _> = auto
                .find_iter(&haystack, PortableFindIterLimits::unlimited())
                .unwrap()
                .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                .collect();
            let k0_matches: Result<Vec<_>, _> = k0
                .find_iter(&haystack, PortableFindIterLimits::unlimited())
                .unwrap()
                .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
                .collect();
            assert_eq!(auto_matches.unwrap(), k0_matches.unwrap());

            let mut auto_session = auto
                .search_session(SearchSessionLimits::unlimited())
                .unwrap();
            let mut k0_session = k0.search_session(SearchSessionLimits::unlimited()).unwrap();
            assert!(auto_session.workspace_setup_accounting().is_none());
            assert_eq!(
                span(auto_session.find_value(&haystack, limits).unwrap()),
                span(k0_session.find_value(&haystack, limits).unwrap())
            );

            let mut auto_endpoint = auto
                .endpoint_search_session(SearchSessionLimits::unlimited())
                .unwrap();
            let mut k0_endpoint = k0
                .endpoint_search_session(SearchSessionLimits::unlimited())
                .unwrap();
            assert_eq!(
                auto_endpoint.selected_end(&haystack, limits).unwrap().0,
                k0_endpoint.selected_end(&haystack, limits).unwrap().0
            );
        }

        let word = matrix_word(width, reducer, anchor_offset);
        let mut guarded = word.clone();
        guarded.extend_from_slice(&[0x7f; 7]);
        let window_start = guarded.len();
        guarded.extend_from_slice(&word);
        let window_end = guarded.len();
        guarded.extend_from_slice(&[0x7f; 7]);
        guarded.extend_from_slice(&word);
        let window = SearchWindow::new(window_start, window_end);
        assert_eq!(
            span(
                auto.find_window(&guarded, window, SearchLimits::unlimited())
                    .unwrap()
                    .0
            ),
            span(
                k0.find_window(&guarded, window, SearchLimits::unlimited())
                    .unwrap()
                    .0
            )
        );
        assert!(
            auto.find_window(&guarded, SearchWindow::new(1, 0), SearchLimits::unlimited())
                .is_err()
        );
        assert!(
            auto.find_window(
                &guarded,
                SearchWindow::new(0, guarded.len() + 1),
                SearchLimits::unlimited()
            )
            .is_err()
        );
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
fn declined_fixed_predicate_inspections_preserve_exact_cumulative_planner_work() {
    let cases = [
        raw_shift_and_pattern(16),
        raw_shift_and_pattern(17),
        raw_shift_and_pattern(24),
    ];
    for pattern in cases {
        let baseline = build_auto(&pattern);
        let report = baseline.build_report();
        assert_eq!(report.plan, PlanKind::K0);
        assert!(report.planner_work > 0);

        let mut exact_limits = BuildLimits::default();
        exact_limits.max_planner_work = report.planner_work;
        let exact = PortableBuilder::new(&pattern)
            .unicode(false)
            .limits(exact_limits)
            .build()
            .unwrap();
        assert_eq!(exact.build_report().plan, PlanKind::K0);
        assert_eq!(exact.build_report().planner_work, report.planner_work);

        let mut below_limits = exact_limits;
        below_limits.max_planner_work = report.planner_work - 1;
        assert!(matches!(
            PortableBuilder::new(&pattern)
                .unicode(false)
                .limits(below_limits)
                .build(),
            Err(BuildError::PlannerWorkLimit { needed, limit })
                if needed == report.planner_work && limit == report.planner_work - 1
        ));
    }
}

#[test]
fn fixed_predicate_admission_preserves_finite_incumbents_and_structural_refusals() {
    assert_eq!(
        build_auto("abc").build_report().plan,
        PlanKind::ExactLiteral
    );
    assert_eq!(
        build_auto("alpha|beta|gamma").build_report().plan,
        PlanKind::PackedLiteralSet
    );
    let dfa = PortableBuilder::new("alpha|beta|gamma")
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

    let asserted = format!("{GENERAL_PAIR_PATTERN}$");
    assert_eq!(build_auto(&asserted).build_report().plan, PlanKind::K0);
    let alternation = format!("(?:{GENERAL_PAIR_PATTERN}|[xyz]{GENERAL_PAIR_PATTERN})");
    assert_eq!(build_auto(&alternation).build_report().plan, PlanKind::K0);
    assert_eq!(
        build_auto("[abc]{8,9}[def]{8,9}").build_report().plan,
        PlanKind::BoundedByteClassSequence
    );
}

#[test]
fn fixed_predicate_precedes_finite_products_but_not_true_alternation() {
    let pattern = r"(?-u:[\x80-\x9F]Q)";
    let fixed = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(fixed.build_report().plan, PlanKind::FixedPredicateWord64);

    let two_byte_anchor = build_auto("[ab][cde]");
    assert_eq!(
        two_byte_anchor.build_report().plan,
        PlanKind::FixedPredicateWord64,
        "an exact two-byte anchor preserves precedence over a fitting finite product"
    );
    let (_, two_byte_accounting) = two_byte_anchor
        .find(b"--ad--", SearchLimits::unlimited())
        .unwrap();
    assert!(matches!(
        two_byte_accounting,
        SearchAccounting::FixedPredicateWord64(accounting)
            if accounting.identity.reducer == FixedPredicateWord64Reducer::TwoByteAnchor
    ));

    let alternation = PortableBuilder::new("(?:alpha|beta|gamma)")
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(alternation.build_report().plan, PlanKind::PackedLiteralSet);

    let upstream = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    for first in u8::MIN..=u8::MAX {
        for second in u8::MIN..=u8::MAX {
            let haystack = [first, second];
            let expected = upstream
                .find(&haystack)
                .map(|matched| (matched.start(), matched.end()));
            let actual = fixed
                .find(&haystack, SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(actual, expected, "haystack={haystack:?}");
        }
    }

    let required = fixed.build_report().planner_work;
    assert!(required > 0);
    assert!(
        PortableBuilder::new(pattern)
            .unicode(false)
            .limits(BuildLimits {
                max_planner_work: required,
                ..BuildLimits::default()
            })
            .build()
            .is_ok()
    );
    assert!(matches!(
        PortableBuilder::new(pattern)
            .unicode(false)
            .limits(BuildLimits {
                max_planner_work: required - 1,
                ..BuildLimits::default()
            })
            .build(),
        Err(BuildError::PlannerWorkLimit { .. })
    ));
}

#[test]
fn cost_declined_fixed_product_preserves_finite_route_and_planner_receipt() {
    let pattern = "[abc][def]";
    let finite = build_auto(pattern);
    assert_eq!(finite.build_report().plan, PlanKind::PackedLiteralSet);

    let build_with_finite_envelope = |max_patterns, max_pattern_bytes| {
        PortableBuilder::new(pattern)
            .unicode(false)
            .limits(BuildLimits {
                literal_set: fre_kernels::LiteralSetBuildLimits {
                    max_patterns,
                    max_pattern_bytes,
                    ..fre_kernels::LiteralSetBuildLimits::default()
                },
                ..BuildLimits::default()
            })
            .build()
            .unwrap()
    };
    assert_eq!(
        build_with_finite_envelope(4, 24).build_report().plan,
        PlanKind::FixedPredicateWord64,
        "a configured four-pattern envelope cannot retain the finite incumbent"
    );
    assert_eq!(
        build_with_finite_envelope(15, 24).build_report().plan,
        PlanKind::PackedLiteralSet,
        "the exact finite construction peak preserves incumbent precedence"
    );
    for (max_patterns, max_pattern_bytes) in [(14, 24), (15, 23), (9, 18)] {
        assert_eq!(
            build_with_finite_envelope(max_patterns, max_pattern_bytes)
                .build_report()
                .plan,
            PlanKind::FixedPredicateWord64,
            "envelope={max_patterns} patterns/{max_pattern_bytes} bytes"
        );
    }

    for (limits, expected_plan) in [
        (BuildLimits::default(), PlanKind::PackedLiteralSet),
        (
            BuildLimits {
                literal_set: fre_kernels::LiteralSetBuildLimits {
                    max_patterns: 4,
                    max_pattern_bytes: 24,
                    ..fre_kernels::LiteralSetBuildLimits::default()
                },
                ..BuildLimits::default()
            },
            PlanKind::FixedPredicateWord64,
        ),
    ] {
        let baseline = PortableBuilder::new(pattern)
            .unicode(false)
            .limits(limits)
            .build()
            .unwrap();
        let required = baseline.build_report().planner_work;
        assert!(required > 0);
        let exact = PortableBuilder::new(pattern)
            .unicode(false)
            .limits(BuildLimits {
                max_planner_work: required,
                ..limits
            })
            .build()
            .unwrap();
        assert_eq!(exact.build_report().plan, expected_plan);
        assert_eq!(exact.build_report().planner_work, required);
        assert!(matches!(
            PortableBuilder::new(pattern)
                .unicode(false)
                .limits(BuildLimits {
                    max_planner_work: required - 1,
                    ..limits
                })
                .build(),
            Err(BuildError::PlannerWorkLimit { needed, limit })
                if needed == required && limit == required - 1
        ));
    }
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
fn fixed_predicate_schema_is_pinned_to_fourteen() {
    assert_eq!(EXPLAIN_SCHEMA_VERSION, 14);
}
