#![forbid(unsafe_code)]

use fre::{
    BuildLimits, Match, PlanKind, PlanSelection, PortableBuilder, PortableFindIterAccounting,
    PortableFindIterError, PortableFindIterLimits, PortableRegex, RustProfile, SearchError,
    SearchLimits, SearchSessionLimits,
};

const UPSTREAM_REVISION: &str = "7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1";
const UPSTREAM_PACKAGE_SHA256: &str =
    "f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba";
const UPSTREAM_PATH: &str = "src/regex/bytes.rs";
const UPSTREAM_SHA256: &str = "fae9e125ff320e85fe5e59e2a32ae24d85f6ca9f38c737c4e929a8376b9b53b0";
const UPSTREAM_API_IDS: &[&str] = &["bytes_regex_find_iter"];
const UPSTREAM_DOCTEST_IDS: &[&str] = &["bytes_regex_find_iter_words"];

#[test]
fn authenticated_bytes_find_iter_inventory_has_no_silent_omissions() {
    let profile = RustProfile::regex_1_12_4();
    assert_eq!(profile.regex.vcs_revision.commit(), UPSTREAM_REVISION);
    assert_eq!(profile.regex.checksum, UPSTREAM_PACKAGE_SHA256);
    assert_eq!(UPSTREAM_PATH, "src/regex/bytes.rs");
    assert_eq!(UPSTREAM_SHA256.len(), 64);
    assert_eq!(UPSTREAM_API_IDS, ["bytes_regex_find_iter"]);
    assert_eq!(UPSTREAM_DOCTEST_IDS, ["bytes_regex_find_iter_words"]);
}

#[test]
fn pinned_bytes_find_iter_doctest_passes() {
    let regex = PortableRegex::new(r"\b\w{13}\b").expect("portable doctest regex");
    let haystack = b"Retroactively relinquishing remunerations is reprehensible.";
    let (matched, accounting) = collect(&regex, haystack, PortableFindIterLimits::unlimited())
        .expect("portable doctest iteration");
    let words: Vec<_> = matched
        .iter()
        .map(|matched| &haystack[matched.range()])
        .collect();
    assert_eq!(
        words,
        vec![
            &b"Retroactively"[..],
            &b"relinquishing"[..],
            &b"remunerations"[..],
            &b"reprehensible"[..],
        ]
    );
    assert_eq!(accounting.matches, 4);
    assert!(accounting.search_calls > accounting.matches);
    assert!(accounting.work_or_linear_terms > 0);
}

#[derive(Clone, Copy, Debug)]
struct DifferentialCase {
    pattern: &'static str,
    unicode: bool,
    selection: PlanSelection,
    force_literal_set_dfa: bool,
    expected_plan: PlanKind,
}

#[test]
fn find_iter_matches_pinned_bytes_across_every_portable_plan() {
    let haystacks: &[&[u8]] = &[
        b"",
        b"ab",
        b"abab",
        b"xxfoobaz-alphaZ-Sherlock",
        " αβ ab 雪_42 ".as_bytes(),
        &[0xFF, b'a', b'b', b'Z', 0x80],
    ];

    for case in differential_cases() {
        let fre = build_case(case);
        assert_eq!(fre.build_report().plan, case.expected_plan, "{case:?}");
        let mut upstream = regex::bytes::RegexBuilder::new(case.pattern);
        upstream.unicode(case.unicode);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {case:?}: {error}"));

        for &haystack in haystacks {
            let expected: Vec<_> = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            let (actual, accounting) = collect(&fre, haystack, PortableFindIterLimits::unlimited())
                .unwrap_or_else(|error| panic!("portable iteration failed for {case:?}: {error}"));
            let actual: Vec<_> = actual
                .iter()
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            assert_eq!(actual, expected, "case={case:?}, haystack={haystack:?}");
            assert_eq!(accounting.matches, expected.len());
            assert!(accounting.search_calls >= accounting.matches);
        }
    }
}

#[test]
fn borrowed_find_iter_matches_pinned_bytes_across_every_portable_plan() {
    let haystacks: &[&[u8]] = &[
        b"",
        b"ab",
        b"abab",
        b"xxfoobaz-alphaZ-Sherlock",
        " αβ ab 雪_42 ".as_bytes(),
        &[0xFF, b'a', b'b', b'Z', 0x80],
    ];

    for case in differential_cases() {
        let fre = build_case(case);
        let mut upstream = regex::bytes::RegexBuilder::new(case.pattern);
        upstream.unicode(case.unicode);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("pinned regex rejected {case:?}: {error}"));

        for &haystack in haystacks {
            let expected: Vec<_> = upstream
                .find_iter(haystack)
                .map(|matched| (matched.range(), matched.as_bytes().to_vec()))
                .collect();
            let _ = collect(&fre, haystack, PortableFindIterLimits::unlimited()).unwrap_or_else(
                |error| panic!("iterator-path warm-up failed for {case:?}: {error}"),
            );
            let mut iterator = fre
                .find_iter_borrowed(haystack, PortableFindIterLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!("borrowed iterator construction failed for {case:?}: {error}")
                });
            let mut actual = Vec::new();
            for matched in iterator.by_ref() {
                let matched = matched.unwrap_or_else(|error| {
                    panic!("borrowed iteration failed for {case:?}: {error}")
                });
                let bytes: &[u8] = matched.into();
                let range: core::ops::Range<usize> = matched.into();
                assert_eq!(matched.as_bytes(), bytes);
                actual.push((range, bytes.to_vec()));
            }
            assert_eq!(actual, expected, "case={case:?}, haystack={haystack:?}");
            assert!(iterator.next().is_none(), "borrowed iterator must fuse");

            let borrowed_accounting = iterator.accounting();
            let (_, offset_accounting) =
                collect(&fre, haystack, PortableFindIterLimits::unlimited()).unwrap_or_else(
                    |error| panic!("offset accounting probe failed for {case:?}: {error}"),
                );
            assert_eq!(borrowed_accounting, offset_accounting);
        }
    }
}

#[test]
fn borrowed_find_iter_preserves_limit_errors_workspace_and_fusion() {
    let regex = PortableBuilder::new("")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("empty portable regex");
    let _ = collect(&regex, b"ab", PortableFindIterLimits::unlimited())
        .expect("warm empty-pattern iterator path");
    let (_, probe) = collect(&regex, b"ab", PortableFindIterLimits::unlimited())
        .expect("unlimited accounting probe");
    let limits = PortableFindIterLimits {
        max_search_calls: probe.search_calls - 1,
        ..PortableFindIterLimits::unlimited()
    };
    let mut matches = regex
        .find_iter_borrowed(b"ab", limits)
        .expect("borrowed iterator workspace construction");
    assert!(
        matches
            .workspace_setup_accounting()
            .expect("forced K0 must retain one workspace")
            .retained_bytes()
            > 0
    );

    let mut emitted = 0_usize;
    let error = loop {
        match matches.next() {
            Some(Ok(_)) => emitted = emitted.saturating_add(1),
            Some(Err(error)) => break error,
            None => panic!("borrowed iterator silently exhausted below its exact limit"),
        }
    };
    assert_eq!(emitted, probe.matches);
    assert_eq!(
        error,
        PortableFindIterError::SearchCallLimit {
            needed: probe.search_calls,
            limit: probe.search_calls - 1,
        }
    );
    assert_eq!(matches.accounting().search_calls, probe.search_calls - 1);
    assert!(matches.next().is_none(), "terminal refusal must fuse");
}

fn differential_cases() -> [DifferentialCase; 8] {
    [
        DifferentialCase {
            pattern: "ab",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::ExactLiteral,
        },
        DifferentialCase {
            pattern: "a|ab",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::PackedLiteralSet,
        },
        DifferentialCase {
            pattern: "foobar|foobaz|fooquux",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: true,
            expected_plan: PlanKind::LiteralSetDfa,
        },
        DifferentialCase {
            pattern: "[a-z]+Z",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::RequiredLiteral,
        },
        DifferentialCase {
            pattern: r"\A[a-z]+Z",
            unicode: false,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::ForwardAnchored,
        },
        DifferentialCase {
            pattern: r"\b\w{2,}\b",
            unicode: true,
            selection: PlanSelection::Auto,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::UnicodeWordRun,
        },
        DifferentialCase {
            pattern: "(?:ab)+",
            unicode: false,
            selection: PlanSelection::ForceK0,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::K0,
        },
        DifferentialCase {
            pattern: "",
            unicode: false,
            selection: PlanSelection::ForceK0,
            force_literal_set_dfa: false,
            expected_plan: PlanKind::K0,
        },
    ]
}

#[test]
fn empty_progress_is_byte_wise_and_anchors_keep_original_context() {
    let arbitrary = [0xE2, 0x98, 0x83, 0xFF];
    let empty = PortableBuilder::new("")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("empty portable regex");
    let upstream = regex::bytes::Regex::new("").expect("pinned empty regex");
    let expected: Vec<_> = upstream
        .find_iter(&arbitrary)
        .map(|matched| matched.range())
        .collect();
    let (actual, accounting) = collect(&empty, &arbitrary, PortableFindIterLimits::unlimited())
        .expect("empty portable iteration");
    assert_eq!(
        actual
            .iter()
            .map(|matched| matched.range())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(accounting.matches, arbitrary.len() + 1);
    assert_eq!(accounting.suppressed_empty, arbitrary.len() + 1);

    let contextual = PortableBuilder::new(r"\A|a$")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("contextual portable regex");
    let (actual, _) = collect(&contextual, b"ba", PortableFindIterLimits::unlimited())
        .expect("contextual iteration");
    assert_eq!(
        actual
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>(),
        vec![(0, 0), (1, 2)]
    );
}

#[test]
fn nullable_k0_iteration_preserves_priority_and_empty_progress_across_reused_searches() {
    let patterns = ["a*", "a*?", "a?", "a??", "(?:|ab)", "(?:ab|)"];
    let haystacks: &[&[u8]] = &[
        b"",
        b"a",
        b"aaaa",
        b"baab",
        &[0xff, b'a', b'b', 0x80, b'a'],
        &[0xc3, 0x28, b'a', b'b'],
    ];

    for pattern in patterns {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap_or_else(|error| panic!("nullable K0 build failed for {pattern:?}: {error}"));
        assert_eq!(regex.build_report().plan, PlanKind::K0, "{pattern:?}");
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pinned build failed for {pattern:?}: {error}"));

        for &haystack in haystacks {
            let expected: Vec<_> = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            for repetition in 0..3 {
                let (actual, accounting) =
                    collect(&regex, haystack, PortableFindIterLimits::unlimited()).unwrap_or_else(
                        |error| {
                            panic!(
                                "nullable K0 iteration failed for {pattern:?}/{haystack:?} \
                                 repetition {repetition}: {error}"
                            )
                        },
                    );
                let actual: Vec<_> = actual
                    .iter()
                    .map(|matched| (matched.start(), matched.end()))
                    .collect();
                assert_eq!(
                    actual, expected,
                    "nullable K0 iteration mismatch for {pattern:?}/{haystack:?}"
                );
                assert_eq!(accounting.matches, expected.len());
                assert!(accounting.search_calls >= accounting.matches);
            }
        }
    }
}

#[test]
fn nullable_iterator_sessions_use_tight_source_free_setup_and_preserve_public_fallbacks() {
    let haystack = b"abcdabcdabcdabcdabcdabcdabcdabc";
    assert_eq!(haystack.len(), 31);
    let mut setup_sizes = Vec::new();

    for pattern in ["", "a*", "(?:ab)*", "(?:abc)*", "(?:abcd)*"] {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap_or_else(|error| panic!("nullable K0 build failed for {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pinned build failed for {pattern:?}: {error}"));
        let expected: Vec<_> = upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect();

        let mut probe = regex
            .find_iter(haystack, PortableFindIterLimits::unlimited())
            .unwrap_or_else(|error| {
                panic!("nullable iterator setup failed for {pattern:?}: {error}")
            });
        let setup = probe
            .workspace_setup_accounting()
            .expect("forced K0 iterator retains one workspace");
        let actual = probe
            .by_ref()
            .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual, expected, "{pattern:?}: unlimited offsets");
        assert!(probe.next().is_none(), "{pattern:?}: fused offsets");

        let exact_limits = PortableFindIterLimits {
            session: SearchSessionLimits {
                max_setup_work: setup.work(),
                max_scratch_bytes: setup.retained_bytes(),
            },
            ..PortableFindIterLimits::unlimited()
        };
        let mut exact = regex
            .find_iter_borrowed(haystack, exact_limits)
            .unwrap_or_else(|error| panic!("exact nullable setup failed for {pattern:?}: {error}"));
        assert_eq!(exact.workspace_setup_accounting(), Some(setup));
        let exact_matches = exact
            .by_ref()
            .map(|matched| {
                matched.map(|matched| {
                    let range = matched.range();
                    (range.start, range.end)
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(exact_matches, expected, "{pattern:?}: exact borrowed");
        assert!(exact.next().is_none(), "{pattern:?}: fused borrowed");

        let fallback_limits = PortableFindIterLimits {
            session: SearchSessionLimits {
                max_setup_work: setup.work() - 1,
                max_scratch_bytes: usize::MAX,
            },
            ..PortableFindIterLimits::unlimited()
        };
        let mut fallback = regex
            .find_iter(haystack, fallback_limits)
            .unwrap_or_else(|error| panic!("ordinary fallback failed for {pattern:?}: {error}"));
        let fallback_setup = fallback
            .workspace_setup_accounting()
            .expect("forced K0 fallback retains ordinary workspace");
        assert!(
            fallback_setup.work() < setup.work(),
            "{pattern:?}: one-below must select the smaller ordinary tier"
        );
        let fallback_matches = fallback
            .by_ref()
            .map(|matched| matched.map(|matched| (matched.start(), matched.end())))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(fallback_matches, expected, "{pattern:?}: ordinary fallback");
        setup_sizes.push((setup.work(), setup.retained_bytes()));
    }

    for adjacent in setup_sizes.windows(2) {
        assert!(
            adjacent[0].0 < adjacent[1].0,
            "construction work must track the proven state space"
        );
        assert!(
            adjacent[0].1 < adjacent[1].1,
            "retained bytes must track the proven state space"
        );
    }
}

#[test]
fn whole_iterator_search_call_limit_is_exact_and_terminal() {
    let regex = PortableBuilder::new("")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("empty portable regex");
    let _ = collect(&regex, b"ab", PortableFindIterLimits::unlimited())
        .expect("warm empty-pattern iterator path");
    let (_, probe) = collect(&regex, b"ab", PortableFindIterLimits::unlimited())
        .expect("unlimited accounting probe");
    assert_eq!(probe.search_calls, 6);
    assert_eq!(probe.matches, 3);
    assert_eq!(probe.suppressed_empty, 3);

    let exact_limits = PortableFindIterLimits {
        max_search_calls: probe.search_calls,
        ..PortableFindIterLimits::unlimited()
    };
    let (_, exact) = collect(&regex, b"ab", exact_limits).expect("exact search-call limit");
    assert_eq!(exact, probe);

    let below_limits = PortableFindIterLimits {
        max_search_calls: probe.search_calls - 1,
        ..PortableFindIterLimits::unlimited()
    };
    let mut below = regex
        .find_iter(b"ab", below_limits)
        .expect("below-limit iterator construction");
    let mut matches = 0;
    let error = loop {
        match below.next() {
            Some(Ok(_)) => matches += 1,
            Some(Err(error)) => break error,
            None => panic!("below-limit iterator silently exhausted"),
        }
    };
    assert_eq!(matches, probe.matches);
    assert_eq!(
        error,
        PortableFindIterError::SearchCallLimit {
            needed: probe.search_calls,
            limit: probe.search_calls - 1,
        }
    );
    assert_eq!(below.accounting().search_calls, probe.search_calls - 1);
    assert!(below.next().is_none(), "terminal error must fuse iterator");
}

#[test]
fn per_search_refusal_is_visible_and_k0_workspace_is_reused() {
    let regex = PortableBuilder::new("(?:ab)+")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("K0 iterator regex");
    let limits = PortableFindIterLimits {
        search: SearchLimits {
            max_work: 0,
            ..SearchLimits::unlimited()
        },
        ..PortableFindIterLimits::unlimited()
    };
    let mut matches = regex
        .find_iter(b"abab", limits)
        .expect("K0 iterator workspace");
    let setup = matches
        .workspace_setup_accounting()
        .expect("K0 iterator must retain one workspace");
    assert!(setup.retained_bytes() > 0);
    assert!(matches!(
        matches.next(),
        Some(Err(PortableFindIterError::Search(SearchError::K0(_))))
    ));
    assert_eq!(matches.accounting().search_calls, 1);
    assert!(
        matches.next().is_none(),
        "search refusal must fuse iterator"
    );
}

#[test]
fn k0_cursor_matches_uncursored_sessions_and_exact_accounting() {
    let cases: &[(&str, &[u8])] = &[
        ("", &[0xFF, b'a', 0x80]),
        ("a", b"aaaaaaaaaaaaaaaa"),
        ("z+", b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaz"),
        ("(?:ab)+", b"xxababyyabzzababab"),
        (r"(?m:^a$)", b"x\na\nb\na\n"),
        (r"\b[a-z]+\b", &[0xFF, b'a', b'b', b' ', b'z', 0x80]),
    ];

    for &(pattern, haystack) in cases {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap_or_else(|error| panic!("forced K0 build failed for {pattern:?}: {error}"));
        assert_eq!(regex.build_report().plan, PlanKind::K0);

        // Give both fresh workspaces the same immutable start-filter state.
        regex
            .find(haystack, SearchLimits::unlimited())
            .unwrap_or_else(|error| panic!("proof warm-up failed for {pattern:?}: {error}"));

        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let expected = upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();

        let (cursor_matches, cursor_accounting) =
            collect(&regex, haystack, PortableFindIterLimits::unlimited())
                .unwrap_or_else(|error| panic!("cursor failed for {pattern:?}: {error}"));
        let (ordinary_matches, ordinary_accounting) =
            collect_uncursored(&regex, haystack, PortableFindIterLimits::unlimited())
                .unwrap_or_else(|error| panic!("ordinary session failed for {pattern:?}: {error}"));
        let cursor_spans = cursor_matches
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        let ordinary_spans = ordinary_matches
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        assert_eq!(cursor_spans, expected, "cursor pattern={pattern:?}");
        assert_eq!(ordinary_spans, expected, "ordinary pattern={pattern:?}");
        assert_eq!(
            cursor_accounting, ordinary_accounting,
            "accounting pattern={pattern:?}"
        );

        let retained = regex
            .search_session(fre::SearchSessionLimits::unlimited())
            .unwrap()
            .workspace_setup_accounting()
            .unwrap()
            .retained_bytes();
        let finite = PortableFindIterLimits {
            search: SearchLimits {
                max_work: 1_000_000,
                max_scratch_bytes: retained,
            },
            max_search_calls: ordinary_accounting.search_calls,
            ..PortableFindIterLimits::unlimited()
        };
        let (finite_cursor_matches, finite_cursor_accounting) = collect(&regex, haystack, finite)
            .unwrap_or_else(|error| panic!("finite cursor failed for {pattern:?}: {error}"));
        let (finite_ordinary_matches, finite_ordinary_accounting) =
            collect_uncursored(&regex, haystack, finite).unwrap_or_else(|error| {
                panic!("finite ordinary session failed for {pattern:?}: {error}")
            });
        assert_eq!(finite_cursor_matches, finite_ordinary_matches);
        assert_eq!(finite_cursor_accounting, finite_ordinary_accounting);
    }

    // An exact workspace-only scratch allowance cannot retain the optional
    // automaton-owned start proof. The cursor must preserve the ordinary
    // repeated derivation and its per-search charges rather than silently
    // retaining unaccounted state.
    let cold = PortableBuilder::new("(?:ab)+")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("cold finite K0 build");
    let retained = cold
        .search_session(fre::SearchSessionLimits::unlimited())
        .unwrap()
        .workspace_setup_accounting()
        .unwrap()
        .retained_bytes();
    let finite = PortableFindIterLimits {
        search: SearchLimits {
            max_work: 1_000_000,
            max_scratch_bytes: retained,
        },
        ..PortableFindIterLimits::unlimited()
    };
    let (cursor_matches, cursor_accounting) =
        collect(&cold, b"ababxxabab", finite).expect("cold finite cursor");
    let (ordinary_matches, ordinary_accounting) =
        collect_uncursored(&cold, b"ababxxabab", finite).expect("cold finite ordinary session");
    assert_eq!(cursor_matches, ordinary_matches);
    assert_eq!(cursor_accounting, ordinary_accounting);
}

fn build_case(case: DifferentialCase) -> PortableRegex {
    let limits = if case.force_literal_set_dfa {
        BuildLimits {
            packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
                max_patterns: 0,
                ..fre_kernels::PackedLiteralSetBuildLimits::default()
            },
            ..BuildLimits::default()
        }
    } else {
        BuildLimits::default()
    };
    PortableBuilder::new(case.pattern)
        .profile(RustProfile::regex_1_12_4())
        .unicode(case.unicode)
        .limits(limits)
        .plan_selection(case.selection)
        .build()
        .unwrap_or_else(|error| panic!("portable regex rejected {case:?}: {error}"))
}

fn collect(
    regex: &PortableRegex,
    haystack: &[u8],
    limits: PortableFindIterLimits,
) -> Result<(Vec<Match>, PortableFindIterAccounting), PortableFindIterError> {
    let mut iterator = regex
        .find_iter(haystack, limits)
        .map_err(PortableFindIterError::Search)?;
    let mut matches = Vec::new();
    for matched in iterator.by_ref() {
        matches.push(matched?);
    }
    Ok((matches, iterator.accounting()))
}

fn collect_uncursored(
    regex: &PortableRegex,
    haystack: &[u8],
    limits: PortableFindIterLimits,
) -> Result<(Vec<Match>, PortableFindIterAccounting), PortableFindIterError> {
    let mut session = regex
        .search_session(limits.session)
        .map_err(PortableFindIterError::Search)?;
    let mut start = 0_usize;
    let mut last_match_end = None;
    let mut results = Vec::new();
    let mut accounting = PortableFindIterAccounting::default();

    loop {
        let needed = accounting.search_calls.checked_add(1).ok_or(
            PortableFindIterError::AccountingOverflow {
                counter: "search-call",
            },
        )?;
        if needed > limits.max_search_calls {
            return Err(PortableFindIterError::SearchCallLimit {
                needed,
                limit: limits.max_search_calls,
            });
        }
        accounting.search_calls = needed;
        let (found, search_accounting) = session
            .find_at(haystack, start, limits.search)
            .map_err(PortableFindIterError::Search)?;
        accounting.work_or_linear_terms = accounting
            .work_or_linear_terms
            .checked_add(search_accounting.work_or_linear_terms())
            .ok_or(PortableFindIterError::AccountingOverflow { counter: "work" })?;
        let Some(found) = found else {
            break;
        };
        if found.is_empty() && last_match_end == Some(found.end()) {
            accounting.suppressed_empty = accounting.suppressed_empty.checked_add(1).ok_or(
                PortableFindIterError::AccountingOverflow {
                    counter: "suppressed-empty",
                },
            )?;
            if start == haystack.len() {
                break;
            }
            start = start.saturating_add(1);
            continue;
        }
        start = found.end();
        last_match_end = Some(found.end());
        accounting.matches = accounting
            .matches
            .checked_add(1)
            .ok_or(PortableFindIterError::AccountingOverflow { counter: "match" })?;
        results.push(found);
    }
    Ok((results, accounting))
}
