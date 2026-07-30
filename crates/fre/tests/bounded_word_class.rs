#![forbid(unsafe_code)]

use fre::{
    BuildError, BuildLimits, Match, PlanKind, PlanSelection, PortableBuilder,
    PortableFindIterLimits, PortableFindIterRunLimits, RustProfile, SearchError, SearchLimits,
    SearchSessionLimits, SearchWindow, UnicodeWordRunError,
};
use regex_automata::{Input, meta::Regex as MetaRegex, util::syntax};

const PLAN_ID: &str = "bounded-word-class-linear-full-byte-v4";

fn fre_regex(pattern: &str, unicode: bool) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(unicode)
        .plan_selection(PlanSelection::Auto)
        .build()
        .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"))
}

fn meta_regex(pattern: &str, unicode: bool) -> MetaRegex {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(syntax::Config::new().utf8(false).unicode(unicode))
        .build(pattern)
        .unwrap_or_else(|error| panic!("pinned oracle rejected {pattern:?}: {error}"))
}

fn upstream_regex(pattern: &str, unicode: bool) -> regex::bytes::Regex {
    let mut builder = regex::bytes::RegexBuilder::new(pattern);
    builder.unicode(unicode);
    builder
        .build()
        .unwrap_or_else(|error| panic!("pinned bytes oracle rejected {pattern:?}: {error}"))
}

fn spans(matches: impl Iterator<Item = Match>) -> Vec<(usize, usize)> {
    matches
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

fn byte_strings(max_len: usize, alphabet: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                next.push(value);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}

fn scalar_strings(max_len: usize, alphabet: &[char]) -> Vec<Vec<u8>> {
    let mut all = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &scalar in alphabet {
                let mut value = prefix.clone();
                value.push(scalar);
                next.push(value);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all.into_iter().map(String::into_bytes).collect()
}

#[test]
fn generated_small_classes_lengths_windows_and_malformed_bytes_match_k0_and_pinned() {
    let ascii_patterns = [
        r"(?-u:\b[A-F]{1,1}\b)",
        r"(?-u:\b[A-F]{2,4}\b)",
        r"(?-u:\b[A/_-]{1,3}\b)",
        r"(?-u:\b[^A-F]{2,5}\b)",
        r"(?-u:\b[\x80-\xFFQ]{1,}\b)",
    ];
    let ascii_haystacks = byte_strings(4, &[b'A', b'G', b'-', b'_', b' ', 0xFF]);
    for pattern in ascii_patterns {
        let fre = fre_regex(pattern, false);
        let oracle = meta_regex(pattern, false);
        for haystack in &ascii_haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = oracle
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let actual = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .expect("generated ASCII search")
                        .0
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                }
            }
        }
    }

    let unicode_patterns = [
        r"\b\p{L}{1,3}\b",
        r"\b[\p{Greek}_-]{2,4}\b",
        r"\b[^\p{L}]{1,2}\b",
        r"\b[\p{L}\p{N}_-]{2,}\b",
    ];
    let mut unicode_haystacks = scalar_strings(3, &['α', 'A', '-', '_', '1', '😀']);
    unicode_haystacks.extend([
        vec![0xFF, b'A', b'B'],
        vec![0xCE],
        vec![0xED, 0xA0, 0x80, b'A'],
    ]);
    for pattern in unicode_patterns {
        let fre = fre_regex(pattern, true);
        let oracle = meta_regex(pattern, true);
        let k0 = PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .expect("generated Unicode K0");
        for haystack in &unicode_haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = oracle
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let actual = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .expect("generated Unicode search")
                        .0
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                }
                assert_eq!(
                    fre.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .expect("generated native shortest")
                        .0,
                    k0.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .expect("generated K0 shortest")
                        .0,
                    "shortest {pattern:?}/{haystack:?}/{start}"
                );
            }
        }
    }
}

#[test]
fn bounded_ascii_and_unicode_classes_match_every_window() {
    let cases: &[(&str, bool, bool)] = &[
        (r"(?-u:\b[A-Za-z]{3,9}\b)", false, true),
        (r"(?-u:\b[A-F]{2,5}\b)", false, true),
        (r"(?-u:\b[A/_-]{2,5}\b)", false, true),
        (r"(?-u:\b[^A-Za-z]{1,4}\b)", false, true),
        (r"(?-u:\b[\x80-\xFFQ]{1,3}\b)", false, true),
        (r"(?-u:\b[A-Z]{2,}\b)", false, true),
        (r"\b\p{L}{2,8}\b", true, true),
        (r"\b[\p{Greek}_-]{1,4}\b", true, true),
        (r"\b[^\p{L}]{1,3}\b", true, true),
        (r"\b[\p{L}\p{N}_-]{2,}\b", true, true),
        (r"\b\w{2,8}\b", true, true),
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"A",
        b" ABCDEFX ABC DEF ",
        b"zABCz ABCD XY ABCDEFGHIJ",
        b"A-A/A __ -- 42",
        b"QQ\xFFQ \x80\x81Q",
        " αβγδεζηθ αβ A_1-β 😀雪42 ".as_bytes(),
        "\u{301}α-\u{203F}β\u{200C} ".as_bytes(),
        &[0xFF, b'A', b'B', 0xCE, 0xFF, b'C', b'D', 0x80],
        &[0xF0, 0x9F, 0x98, 0x80, b'A', b'B', 0xED, 0xA0, 0x80],
    ];

    for &(pattern, unicode, native) in cases {
        let fre = fre_regex(pattern, unicode);
        let oracle = meta_regex(pattern, unicode);
        let k0 = PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(unicode)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .expect("forced K0 comparison");
        if native {
            assert_eq!(fre.build_report().plan, PlanKind::UnicodeWordRun);
            assert_eq!(fre.runtime_implementation_id(), PLAN_ID);
        } else {
            assert_ne!(fre.runtime_implementation_id(), PLAN_ID);
        }
        let mut session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("native session");
        if native {
            assert_eq!(session.workspace_setup_accounting(), None);
        } else {
            assert!(session.workspace_setup_accounting().is_some());
        }

        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = oracle
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let window = SearchWindow::new(start, end);
                    let (actual, accounting) = fre
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap_or_else(|error| {
                            panic!(
                                "FRE search failed for {pattern:?}/{haystack:?}/{start}..{end}: {error}"
                            )
                        });
                    assert_eq!(accounting.plan(), fre.build_report().plan);
                    assert_eq!(
                        actual.map(|matched| (matched.start(), matched.end())),
                        expected,
                        "cold {pattern:?}/{haystack:?}/{start}..{end}"
                    );
                    let reused = session
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .expect("native session search");
                    assert_eq!(reused.0, actual);
                    if native {
                        assert_eq!(reused.1, accounting);
                    } else {
                        assert_eq!(reused.1.plan(), accounting.plan());
                    }
                }
                assert_eq!(
                    fre.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .expect("native shortest search")
                        .0,
                    k0.shortest_match_at(haystack, start, SearchLimits::unlimited())
                        .expect("K0 shortest search")
                        .0,
                    "shortest {pattern:?}/{haystack:?}/{start}"
                );
            }
        }
    }
}

#[test]
fn selected_greedy_end_shortest_end_and_nonoverlap_match_pinned_bytes() {
    let cases: &[(&str, bool, &[u8])] = &[
        (r"(?-u:\b[A/_-]{2,5}\b)", false, b"A-A/A A-A A/A/A"),
        (
            r"(?-u:\b[A-Za-z]{3,9}\b)",
            false,
            b"ABC ABCDEFGHI ABCDEFX ABCD",
        ),
        (
            r"\b[\p{Greek}_-]{1,4}\b",
            true,
            "α-β_ γ-δ-ε αβγδε".as_bytes(),
        ),
        (r"\b[\p{L}\p{N}_-]{2,}\b", true, "α-β_42 😀 A-1".as_bytes()),
    ];

    for &(pattern, unicode, haystack) in cases {
        let fre = fre_regex(pattern, unicode);
        let oracle = upstream_regex(pattern, unicode);
        let k0 = PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(unicode)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .expect("forced K0 comparison");
        let expected = oracle
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let actual = fre
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .expect("native iterator")
            .collect::<Result<Vec<_>, _>>()
            .expect("native iterator item");
        assert_eq!(spans(actual.into_iter()), expected, "{pattern:?}");
        assert_eq!(
            fre.shortest_match(haystack, SearchLimits::unlimited())
                .expect("shortest search")
                .0,
            k0.shortest_match(haystack, SearchLimits::unlimited())
                .expect("K0 shortest search")
                .0,
            "{pattern:?}"
        );
        assert_eq!(
            fre.find(haystack, SearchLimits::unlimited())
                .expect("selected search")
                .0
                .map(Match::end),
            oracle.find(haystack).map(|matched| matched.end()),
            "{pattern:?}"
        );

        let mut session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("native reusable session");
        let reused = session
            .find_iter(haystack, PortableFindIterRunLimits::unlimited())
            .collect::<Result<Vec<_>, _>>()
            .expect("reused iterator");
        assert_eq!(spans(reused.into_iter()), expected, "{pattern:?}");
    }
}

#[test]
fn long_over_max_runs_and_word_run_nonmembers_do_not_create_partial_matches() {
    let ascii = fre_regex(r"(?-u:\b[A-F]{2,5}\b)", false);
    let unicode = fre_regex(r"\b\p{L}{2,8}\b", true);
    let long_ascii = format!(
        " {} {} {} ",
        "A".repeat(200_000),
        "AFZ".repeat(50_000),
        "FACE"
    );
    let long_unicode = format!(" {} {} {} ", "α".repeat(30_000), "α1".repeat(20_000), "βγ");

    for (fre, oracle, haystack) in [
        (
            &ascii,
            upstream_regex(r"(?-u:\b[A-F]{2,5}\b)", false),
            long_ascii.as_bytes(),
        ),
        (
            &unicode,
            upstream_regex(r"\b\p{L}{2,8}\b", true),
            long_unicode.as_bytes(),
        ),
    ] {
        let expected = oracle
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let actual = fre
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .expect("iterator")
            .collect::<Result<Vec<_>, _>>()
            .expect("iterator item");
        assert_eq!(spans(actual.into_iter()), expected);
    }
}

#[test]
fn bounded_mixed_runs_stop_after_lookahead_and_iterate_in_linear_work() {
    let pattern = r"(?-u:\b[\w-]{1,8}\b)";
    let fre = fre_regex(pattern, false);
    let oracle = upstream_regex(pattern, false);
    assert_eq!(fre.runtime_implementation_id(), PLAN_ID);

    let alternating = |length: usize| {
        (0..length)
            .map(|index| if index % 2 == 0 { b'a' } else { b'-' })
            .collect::<Vec<_>>()
    };
    let mut first_work = None;
    for length in [4_096_usize, 8_192] {
        let haystack = alternating(length);
        let (matched, accounting) = fre
            .find(&haystack, SearchLimits::unlimited())
            .expect("bounded-lookahead find");
        assert_eq!(
            matched.map(|span| (span.start(), span.end())),
            oracle
                .find(&haystack)
                .map(|span| (span.start(), span.end()))
        );
        assert_eq!(matched.expect("early mixed-run match").range(), 0..8);
        if let Some(expected) = first_work {
            assert_eq!(
                accounting.work_or_linear_terms(),
                expected,
                "doubling the untouched suffix must not enlarge first-match work"
            );
        } else {
            first_work = Some(accounting.work_or_linear_terms());
        }
        assert!(accounting.work_or_linear_terms() < 128);
    }

    let haystack = alternating(16_384);
    let expected = oracle
        .find_iter(&haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    let mut iterator = fre
        .find_iter(&haystack, PortableFindIterLimits::unlimited())
        .expect("bounded-lookahead iterator");
    let actual = iterator
        .by_ref()
        .collect::<Result<Vec<_>, _>>()
        .expect("bounded-lookahead iterator item");
    assert_eq!(spans(actual.into_iter()), expected);
    let accounting = iterator.accounting();
    assert_eq!(accounting.matches, expected.len());
    assert_eq!(accounting.search_calls, expected.len() + 1);
    assert!(
        accounting.work_or_linear_terms
            <= u64::try_from(haystack.len())
                .unwrap()
                .checked_mul(8)
                .unwrap(),
        "bounded mixed-run iteration must remain linear: {accounting:?}"
    );
}

#[test]
fn selected_ascii_word_long_absent_sparse_and_short_dense_match_without_extra_work() {
    let pattern = r"(?-u:\b[A-Za-z]{3,9}\b)";
    let fre = fre_regex(pattern, false);
    let oracle = upstream_regex(pattern, false);
    assert_eq!(fre.runtime_implementation_id(), PLAN_ID);

    let length = 128_usize
        .checked_mul(1_024)
        .and_then(|length| length.checked_add(17))
        .unwrap();
    let absent = vec![b'-'; length];
    let (matched, accounting) = fre
        .find(&absent, SearchLimits::unlimited())
        .expect("long absent selected-word scan");
    assert_eq!(matched, None);
    assert_eq!(
        accounting.work_or_linear_terms(),
        u64::try_from(length).unwrap()
    );

    let start = 37;
    let (matched, accounting) = fre
        .find_at(&absent, start, SearchLimits::unlimited())
        .expect("long absent selected-word find_at");
    assert_eq!(matched, None);
    assert_eq!(
        accounting.work_or_linear_terms(),
        u64::try_from(length - start).unwrap()
    );

    let mut sparse = absent;
    let planted = length * 3 / 4;
    sparse[planted..planted + 8].copy_from_slice(b"Alphabet");
    let expected = oracle
        .find(&sparse)
        .map(|matched| (matched.start(), matched.end()));
    let (actual, _) = fre
        .find(&sparse, SearchLimits::unlimited())
        .expect("long sparse selected-word scan");
    assert_eq!(
        actual.map(|matched| (matched.start(), matched.end())),
        expected
    );
    assert_eq!(
        actual.expect("planted sparse match").range(),
        planted..planted + 8
    );

    let short_dense = b"---Alpha---Beta---Gamma---";
    assert_eq!(
        spans(
            fre.find_iter(short_dense, PortableFindIterLimits::unlimited())
                .expect("short dense iterator")
                .collect::<Result<Vec<_>, _>>()
                .expect("short dense item")
                .into_iter()
        ),
        oracle
            .find_iter(short_dense)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn nullable_and_lazy_shapes_keep_their_existing_plans_and_iterator_progress() {
    let cases = [
        (r"(?-u:\b[A-Z]{0,3}\b)", false, b" AA - Z ".as_slice()),
        (r"(?-u:\b[A-Z]{2,8}?\b)", false, b" AA AAAA ".as_slice()),
        (r"\b\p{L}{0,3}\b", true, " α ββ ".as_bytes()),
        (r"\b\p{L}{2,8}?\b", true, " αβ αβγδ ".as_bytes()),
    ];
    for (pattern, unicode, haystack) in cases {
        let fre = fre_regex(pattern, unicode);
        assert_ne!(fre.runtime_implementation_id(), PLAN_ID, "{pattern:?}");
        let oracle = upstream_regex(pattern, unicode);
        let expected = oracle
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let actual = fre
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .expect("fallback iterator")
            .collect::<Result<Vec<_>, _>>()
            .expect("fallback iterator item");
        assert_eq!(spans(actual.into_iter()), expected, "{pattern:?}");
    }
}

#[test]
fn established_exact_word_routes_are_unchanged() {
    for (pattern, unicode, expected_id) in [
        (r"(?-u:\b\w{2,}\b)", false, "ascii-word-run-linear-v1"),
        (r"\b\w{2,}\b", true, "unicode-word-run-linear-v1"),
    ] {
        let fre = fre_regex(pattern, unicode);
        assert_eq!(fre.build_report().plan, PlanKind::UnicodeWordRun);
        assert_eq!(fre.runtime_implementation_id(), expected_id);
    }
}

#[test]
fn planner_storage_clone_and_search_limits_are_exactly_enforced() {
    let pattern = r"\b[\p{Greek}\p{Cyrillic}A-Z_-]{2,12}\b";
    let baseline = fre_regex(pattern, true);
    assert_eq!(baseline.runtime_implementation_id(), PLAN_ID);
    let report = baseline.build_report();

    let exact_planner = PortableBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .limits(BuildLimits {
            max_planner_work: report.planner_work,
            ..BuildLimits::default()
        })
        .build()
        .expect("exact planner boundary");
    assert_eq!(
        exact_planner.build_report().planner_work,
        report.planner_work
    );
    assert!(matches!(
        PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .limits(BuildLimits {
                max_planner_work: report.planner_work - 1,
                ..BuildLimits::default()
            })
            .build(),
        Err(BuildError::PlannerWorkLimit { .. })
    ));

    let exact_storage = PortableBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .limits(BuildLimits {
            max_persistent_bytes: report.charged_persistent_bytes,
            ..BuildLimits::default()
        })
        .build()
        .expect("exact persistent boundary");
    assert_eq!(
        exact_storage.build_report().charged_persistent_bytes,
        report.charged_persistent_bytes
    );
    assert!(matches!(
        PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .limits(BuildLimits {
                max_persistent_bytes: report.charged_persistent_bytes - 1,
                ..BuildLimits::default()
            })
            .build(),
        Err(BuildError::PersistentBytesLimit { .. })
    ));

    let cloned = baseline.clone();
    assert_eq!(cloned.runtime_implementation_id(), PLAN_ID);
    assert_eq!(cloned.build_report(), baseline.build_report());
    let haystack = " -- ΑΒΓ-ДЕЖ ABC_X -- ".as_bytes();
    assert_eq!(
        cloned
            .find(haystack, SearchLimits::unlimited())
            .expect("clone search"),
        baseline
            .find(haystack, SearchLimits::unlimited())
            .expect("source search")
    );

    let (_, accounting) = baseline
        .find(haystack, SearchLimits::unlimited())
        .expect("work probe");
    let exact_work = SearchLimits {
        max_work: accounting.work_or_linear_terms(),
        max_scratch_bytes: 0,
    };
    assert!(baseline.find(haystack, exact_work).is_ok());
    assert!(matches!(
        baseline.find(
            haystack,
            SearchLimits {
                max_work: exact_work.max_work - 1,
                max_scratch_bytes: 0,
            }
        ),
        Err(SearchError::UnicodeWordRun(
            UnicodeWordRunError::WorkLimitExceeded { .. }
        ))
    ));
    assert!(matches!(
        baseline.find_window(haystack, SearchWindow::new(2, 1), SearchLimits::unlimited()),
        Err(SearchError::UnicodeWordRun(
            UnicodeWordRunError::InvalidWindow { .. }
        ))
    ));
}
