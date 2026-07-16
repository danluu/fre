#![allow(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic is over exhaustive test inputs of at most three bytes"
)]

use fre::{
    BuildError, BuildLimits, K0SearchError, PlanKind, PlanSelection, PortableBuilder, RustProfile,
    SearchAccounting, SearchLimits, SearchSessionLimits, SearchWindow,
};
use fre_lower::{LowerError, UnsupportedFeature};
use regex_automata::{Input, meta::Regex as MetaRegex, util::syntax};
use regex_syntax::hir::Look;

const ASSERTION_CASES: [(Look, &str); 10] = [
    (Look::Start, r"\A"),
    (Look::End, r"\z"),
    (Look::StartLF, r"(?m:^)"),
    (Look::EndLF, r"(?m:$)"),
    (Look::WordAscii, r"\b"),
    (Look::WordAsciiNegate, r"\B"),
    (Look::WordStartAscii, r"\b{start}"),
    (Look::WordEndAscii, r"\b{end}"),
    (Look::WordStartHalfAscii, r"\b{start-half}"),
    (Look::WordEndHalfAscii, r"\b{end-half}"),
];

fn portable(pattern: &str, selection: PlanSelection) -> fre::PortableRegex {
    PortableBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .plan_selection(selection)
        .build()
        .unwrap_or_else(|error| panic!("portable build failed for {pattern:?}: {error}"))
}

fn pinned(pattern: &str) -> MetaRegex {
    pinned_with_unicode(pattern, false)
}

fn pinned_with_unicode(pattern: &str, unicode: bool) -> MetaRegex {
    MetaRegex::builder()
        .configure(MetaRegex::config().utf8_empty(false))
        .syntax(syntax::Config::new().utf8(false).unicode(unicode))
        .build(pattern)
        .unwrap_or_else(|error| panic!("pinned oracle rejected {pattern:?}: {error}"))
}

fn pinned_with_line_terminator(pattern: &str, line_terminator: u8) -> MetaRegex {
    MetaRegex::builder()
        .configure(
            MetaRegex::config()
                .utf8_empty(false)
                .line_terminator(line_terminator),
        )
        .syntax(
            syntax::Config::new()
                .utf8(false)
                .unicode(false)
                .line_terminator(line_terminator),
        )
        .build(pattern)
        .unwrap_or_else(|error| {
            panic!(
                "pinned oracle rejected {pattern:?} with line byte {line_terminator:#04X}: {error}"
            )
        })
}

fn independent_is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_digit() || byte.is_ascii_uppercase() || byte.is_ascii_lowercase()
}

fn independent_assertion(look: Look, haystack: &[u8], at: usize) -> bool {
    assert!(at <= haystack.len());
    let before = at.checked_sub(1).and_then(|index| haystack.get(index));
    let after = haystack.get(at);
    let word_before = before.is_some_and(|&byte| independent_is_ascii_word(byte));
    let word_after = after.is_some_and(|&byte| independent_is_ascii_word(byte));
    match look {
        Look::Start => at == 0,
        Look::End => at == haystack.len(),
        Look::StartLF => at == 0 || before.is_some_and(|&byte| byte == b'\n'),
        Look::EndLF => at == haystack.len() || after.is_some_and(|&byte| byte == b'\n'),
        Look::WordAscii => word_before != word_after,
        Look::WordAsciiNegate => word_before == word_after,
        Look::WordStartAscii => !word_before && word_after,
        Look::WordEndAscii => word_before && !word_after,
        Look::WordStartHalfAscii => !word_before,
        Look::WordEndHalfAscii => !word_after,
        unsupported => panic!("independent oracle received unsupported look {unsupported:?}"),
    }
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
                all.push(value.clone());
                next.push(value);
            }
        }
        frontier = next;
    }
    all
}

#[test]
fn every_portable_assertion_matches_pinned_ranges_and_an_independent_oracle() {
    let mut haystacks = byte_strings(3, &[b'a', b'Z', b'9', b'_', b'-', b'\n', 0xFF]);
    haystacks.extend((u8::MIN..=u8::MAX).map(|byte| vec![byte]));
    haystacks.sort();
    haystacks.dedup();
    assert_eq!(haystacks.len(), 649);

    for (look, pattern) in ASSERTION_CASES {
        let fre = portable(pattern, PlanSelection::ForceK0);
        let upstream = pinned(pattern);
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        assert_eq!(fre.build_report().lowering.unwrap().states(), 2);

        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let independent = (start..=end)
                        .find(|&at| independent_assertion(look, haystack, at))
                        .map(|at| (at, at));
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(
                        expected, independent,
                        "pinned/independent {look:?}/{haystack:?}/{start}..{end}"
                    );

                    let (actual, accounting) = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("K0 search failed {look:?}/{haystack:?}/{start}..{end}: {error}")
                        });
                    assert_eq!(accounting.plan(), PlanKind::K0);
                    assert_eq!(
                        actual.map(|matched| (matched.start(), matched.end())),
                        independent,
                        "portable/independent {look:?}/{haystack:?}/{start}..{end}"
                    );
                }
            }
        }
    }
}

#[test]
fn assertions_composed_with_consumption_match_pinned_ranged_search() {
    const PATTERNS: &[&str] = &[
        r"(?m:^)[A-Za-z_]+",
        r"[A-Za-z_]+(?m:$)",
        r"\b[0-9A-Za-z_]+\b",
        r"\B-\B",
        r"\b{start}[A-Za-z_]+",
        r"[A-Za-z_]+\b{end}",
        r"\b{start-half}.",
        r".\b{end-half}",
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"a",
        b"-a-",
        b"aa",
        b"\na\n",
        b"x\na\nx",
        &[0xFF],
        &[b'a', 0xFF, b'-', b'_', b'\n'],
    ];

    for pattern in PATTERNS {
        let fre = portable(pattern, PlanSelection::ForceK0);
        let upstream = pinned(pattern);
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let actual = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "portable search failed {pattern:?}/{haystack:?}/{start}..{end}: {error}"
                            )
                        })
                        .0
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                }
            }
        }
    }
}

#[test]
fn reusable_portable_k0_session_matches_cold_assertions_over_all_windows() {
    const PATTERNS: &[&str] = &[
        r"(?m:^)[A-Za-z_]+",
        r"[A-Za-z_]+(?m:$)",
        r"\b[0-9A-Za-z_]{2,}\b",
        r"\B-\B",
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"a",
        b"-a-",
        b"\na\n",
        &[b'a', 0xFF, b'-', b'_', b'\n'],
    ];

    for pattern in PATTERNS {
        let regex = portable(pattern, PlanSelection::ForceK0);
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap_or_else(|error| panic!("session build failed for {pattern:?}: {error}"));
        assert_eq!(session.runtime_implementation_id(), "k0");
        let construction = session
            .workspace_setup_accounting()
            .expect("K0 session must retain one workspace");
        assert!(!construction.reused());
        assert!(construction.allocated_bytes() > 0);
        assert!(construction.initialized_bytes() > 0);
        assert_eq!(
            construction.allocated_bytes(),
            construction.retained_bytes()
        );

        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let cold = regex
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap();
                    let reused = session
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(reused.0, cold.0, "{pattern:?}/{haystack:?}/{start}..{end}");
                    let (
                        SearchAccounting::K0(cold_accounting),
                        SearchAccounting::K0(reused_accounting),
                    ) = (cold.1, reused.1)
                    else {
                        panic!("forced K0 returned another accounting family")
                    };
                    assert_eq!(
                        reused_accounting.transition_work(),
                        cold_accounting.transition_work()
                    );
                    assert_eq!(reused_accounting.boundaries(), cold_accounting.boundaries());
                    assert_eq!(
                        reused_accounting.scratch_bytes(),
                        cold_accounting.scratch_bytes()
                    );
                    assert!(reused_accounting.setup().reused());
                    assert_eq!(reused_accounting.setup().allocated_bytes(), 0);
                    assert_eq!(
                        reused_accounting.setup().retained_bytes(),
                        construction.retained_bytes()
                    );
                }
            }

            let cold_exists = regex.is_match(haystack, SearchLimits::unlimited()).unwrap();
            let reused_exists = session
                .is_match(haystack, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(reused_exists.0, cold_exists.0);
            let cold_end = regex
                .selected_end(haystack, SearchLimits::unlimited())
                .unwrap();
            let reused_end = session
                .selected_end(haystack, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(reused_end.0, cold_end.0);
            let cold_find = regex.find(haystack, SearchLimits::unlimited()).unwrap();
            let reused_find = session.find(haystack, SearchLimits::unlimited()).unwrap();
            assert_eq!(reused_find.0, cold_find.0);
        }
    }
}

#[test]
fn portable_search_session_has_tight_k0_setup_limits_and_preserves_native_dispatch() {
    let k0 = portable(r"\b[0-9A-Za-z_]+\b", PlanSelection::ForceK0);
    let probe = k0
        .search_session(SearchSessionLimits::unlimited())
        .expect("unlimited K0 session");
    let setup = probe.workspace_setup_accounting().unwrap();
    let error = k0
        .search_session(SearchSessionLimits {
            max_setup_work: setup.work() - 1,
            max_scratch_bytes: usize::MAX,
        })
        .expect_err("one-below setup work must refuse");
    assert!(matches!(
        error,
        fre::SearchError::K0(K0SearchError::WorkspaceSetupWorkLimitExceeded { limit, needed })
            if limit == setup.work() - 1 && needed == setup.work()
    ));
    assert!(matches!(
        k0.search_session(SearchSessionLimits {
            max_setup_work: u64::MAX,
            max_scratch_bytes: setup.retained_bytes() - 1,
        }),
        Err(fre::SearchError::K0(K0SearchError::ResourceLimit {
            needed,
            limit,
            ..
        }))
            if needed == setup.retained_bytes() && limit == setup.retained_bytes() - 1
    ));

    let literal = portable("Sherlock", PlanSelection::Auto);
    assert_eq!(literal.build_report().plan, PlanKind::ExactLiteral);
    let mut session = literal
        .search_session(SearchSessionLimits::unlimited())
        .expect("native session requires no workspace");
    assert_eq!(
        session.runtime_implementation_id(),
        literal.runtime_implementation_id()
    );
    assert_eq!(session.workspace_setup_accounting(), None);
    assert_eq!(
        session
            .is_match(b"xxSherlock", SearchLimits::unlimited())
            .unwrap(),
        literal
            .is_match(b"xxSherlock", SearchLimits::unlimited())
            .unwrap()
    );
}

#[test]
fn portable_search_session_recovers_after_per_call_limit_failures() {
    let regex = portable(r"\b[0-9A-Za-z_]+\b", PlanSelection::ForceK0);
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("unlimited K0 session");
    let setup = session.workspace_setup_accounting().unwrap();
    let haystack = b"--alpha_123--";
    let expected = session
        .find(haystack, SearchLimits::unlimited())
        .expect("baseline reused search");
    let SearchAccounting::K0(expected_accounting) = expected.1 else {
        panic!("forced K0 returned another accounting family")
    };
    assert!(expected_accounting.transition_work() > 0);

    assert!(matches!(
        session.find(
            haystack,
            SearchLimits {
                max_work: expected_accounting.transition_work() - 1,
                max_scratch_bytes: usize::MAX,
            },
        ),
        Err(fre::SearchError::K0(
            K0SearchError::WorkLimitExceeded { .. }
        ))
    ));
    assert_eq!(
        session
            .find(haystack, SearchLimits::unlimited())
            .expect("session must recover after work refusal")
            .0,
        expected.0
    );

    assert!(matches!(
        session.find(
            haystack,
            SearchLimits {
                max_work: u64::MAX,
                max_scratch_bytes: setup.retained_bytes() - 1,
            },
        ),
        Err(fre::SearchError::K0(K0SearchError::ResourceLimit { .. }))
    ));
    assert_eq!(
        session
            .find(haystack, SearchLimits::unlimited())
            .expect("session must recover after scratch refusal")
            .0,
        expected.0
    );
}

#[test]
fn portable_search_session_preserves_every_native_plan_family() {
    let packed = portable("a|ab", PlanSelection::Auto);
    assert_eq!(packed.build_report().plan, PlanKind::PackedLiteralSet);

    let dfa_limits = BuildLimits {
        packed_literal_set: fre_kernels::PackedLiteralSetBuildLimits {
            max_patterns: 0,
            ..fre_kernels::PackedLiteralSetBuildLimits::default()
        },
        ..BuildLimits::default()
    };
    let dfa = PortableBuilder::new("foobar|foobaz|fooquux")
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .limits(dfa_limits)
        .build()
        .expect("forced literal-set DFA");
    assert_eq!(dfa.build_report().plan, PlanKind::LiteralSetDfa);

    let cases = [
        (
            portable("Sherlock", PlanSelection::Auto),
            PlanKind::ExactLiteral,
        ),
        (packed, PlanKind::PackedLiteralSet),
        (dfa, PlanKind::LiteralSetDfa),
        (
            portable("[a-z]+Z", PlanSelection::Auto),
            PlanKind::RequiredLiteral,
        ),
        (
            portable(r"\A[a-z]+Z", PlanSelection::Auto),
            PlanKind::ForwardAnchored,
        ),
    ];
    let haystack = b"xxfoobaz-alphaZ-Sherlock";

    for (regex, expected_plan) in cases {
        assert_eq!(regex.build_report().plan, expected_plan);
        let expected_id = regex.runtime_implementation_id();
        let expected = regex.find(haystack, SearchLimits::unlimited()).unwrap();
        let mut session = regex
            .search_session(SearchSessionLimits {
                max_setup_work: 0,
                max_scratch_bytes: 0,
            })
            .expect("native sessions allocate no K0 workspace");
        assert_eq!(session.runtime_implementation_id(), expected_id);
        assert_eq!(session.workspace_setup_accounting(), None);
        assert_eq!(
            session.find(haystack, SearchLimits::unlimited()).unwrap(),
            expected
        );
    }
}

#[test]
fn generic_ascii_word_and_lf_line_shapes_route_without_approximation() {
    let cases: &[(&str, &[&[u8]], PlanKind, &str)] = &[
        (
            r"\b[0-9A-Za-z_]{12,}\b",
            &[
                b"tiny words",
                b"a sufficiently_long_identifier here",
                b"joined_sufficiently_long_identifier_tail",
                &[b'-', 0xFF, b'a', b'b', b'c'],
            ],
            PlanKind::UnicodeWordRun,
            "ascii-word-run-linear-v1",
        ),
        (
            r"(?m)^Sherlock Holmes$",
            &[
                b"Sherlock Holmes",
                b"prefix Sherlock Holmes suffix",
                b"prefix\nSherlock Holmes\nsuffix",
                b"Sherlock Holmes\r\n",
            ],
            PlanKind::K0,
            "k0",
        ),
    ];

    for &(pattern, haystacks, expected_plan, expected_runtime) in cases {
        let fre = portable(pattern, PlanSelection::Auto);
        let upstream = pinned(pattern);
        assert_eq!(fre.build_report().plan, expected_plan);
        assert_eq!(fre.runtime_implementation_id(), expected_runtime);
        for &haystack in haystacks {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let (actual, accounting) = fre
                .find(haystack, SearchLimits::unlimited())
                .unwrap_or_else(|error| panic!("portable search failed for {pattern:?}: {error}"));
            assert_eq!(accounting.plan(), expected_plan);
            assert_eq!(
                actual.map(|matched| (matched.start(), matched.end())),
                expected,
                "{pattern:?}/{haystack:?}"
            );
        }
    }
}

#[test]
fn unicode_scalar_classes_match_pinned_ranges_without_consuming_invalid_utf8() {
    const RUFF: &str = r"^[ \t\f]*#.*?coding[:=][ \t]*utf-?8";
    let patterns = [".", "[α-ω]+", RUFF];
    let haystacks: &[&[u8]] = &[
        b"",
        "αβ x".as_bytes(),
        "😀".as_bytes(),
        &[0xFF, b'x'],
        &[0xCE],
        &[0xC0, 0x80],
        &[0xED, 0xA0, 0x80],
        b"# -*- coding: utf-8 -*-",
        b"x # coding: utf-8",
        &[
            b'#', b' ', 0xFF, b'c', b'o', b'd', b'i', b'n', b'g', b':', b' ', b'u', b't', b'f',
            b'-', b'8',
        ],
    ];

    for pattern in patterns {
        let fre = PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap_or_else(|error| panic!("Unicode K0 build failed for {pattern:?}: {error}"));
        let upstream = pinned_with_unicode(pattern, true);
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let actual = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "Unicode K0 search failed {pattern:?}/{haystack:?}/{start}..{end}: {error}"
                            )
                        })
                        .0
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                }
            }
        }
    }
}

#[test]
fn positive_unicode_word_boundaries_match_pinned_ranges_on_arbitrary_bytes() {
    const PATTERNS: &[&str] = &[r"\b", r"\b\w{2,}\b", r"\b\w{25,}\b"];
    let haystacks: &[&[u8]] = &[
        b"",
        b"--alphabetic_identifier--",
        "--αβγ--".as_bytes(),
        "\u{301}\u{301}".as_bytes(),
        "\u{203F}\u{203F}".as_bytes(),
        "\u{200C}\u{200C}".as_bytes(),
        "😀alpha😀".as_bytes(),
        &[0xFF, b'a', b'b', 0xFF],
        &[0xCE],
        &[0xC0, 0x80],
        &[0xED, 0xA0, 0x80],
    ];

    for &pattern in PATTERNS {
        let fre = PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap_or_else(|error| panic!("Unicode K0 build failed for {pattern:?}: {error}"));
        let upstream = pinned_with_unicode(pattern, true);
        assert_eq!(fre.build_report().plan, PlanKind::K0);
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let actual = fre
                        .find_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "Unicode K0 search failed {pattern:?}/{haystack:?}/{start}..{end}: {error}"
                            )
                        })
                        .0
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                }
            }
        }
    }
}

#[test]
fn unicode_word_runs_select_a_linear_plan_and_match_pinned_ranges() {
    const PATTERNS: &[&str] = &[r"\b\w{2,}\b", r"\b\w{25,}\b"];
    let haystacks: &[&[u8]] = &[
        b"",
        b"--alphabetic_identifier--",
        "--αβγ--".as_bytes(),
        "\u{301}\u{301}".as_bytes(),
        "\u{203F}\u{203F}".as_bytes(),
        "😀alpha😀".as_bytes(),
        &[0xFF, b'a', b'b', 0xFF],
        &[0xCE],
        &[0xC0, 0x80],
        &[0xED, 0xA0, 0x80],
    ];

    for &pattern in PATTERNS {
        let fre = PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .plan_selection(PlanSelection::Auto)
            .build()
            .unwrap_or_else(|error| panic!("Unicode word-run build failed: {error}"));
        let upstream = pinned_with_unicode(pattern, true);
        assert_eq!(fre.build_report().plan, PlanKind::UnicodeWordRun);
        assert_eq!(
            fre.runtime_implementation_id(),
            "unicode-word-run-linear-v1"
        );
        let mut session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("word-run session uses no workspace");
        assert_eq!(session.workspace_setup_accounting(), None);

        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let (actual, accounting) = fre
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(accounting.plan(), PlanKind::UnicodeWordRun);
                    assert_eq!(
                        actual.map(|matched| (matched.start(), matched.end())),
                        expected,
                        "cold {pattern:?}/{haystack:?}/{start}..{end}"
                    );
                    let reused = session
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(reused.1.plan(), PlanKind::UnicodeWordRun);
                    assert_eq!(reused.0, actual);
                }
            }
        }
    }
}

#[test]
fn ascii_word_runs_select_a_byte_linear_plan_and_match_pinned_ranges() {
    const PATTERNS: &[&str] = &[r"\b\w{1,}\b", r"\b\w{8,}\b", r"\b\w{25,}\b"];
    let haystacks: &[&[u8]] = &[
        b"",
        b"--alphabetic_identifier--",
        "--αβγ--".as_bytes(),
        "😀alpha😀".as_bytes(),
        &[0xFF, b'a', b'b', 0xFF],
        &[b'a', 0xFF, b'b'],
        &[0xCE],
        &[0xC0, 0x80],
        &[0xED, 0xA0, 0x80],
    ];

    for &pattern in PATTERNS {
        let fre = PortableBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .plan_selection(PlanSelection::Auto)
            .build()
            .unwrap_or_else(|error| panic!("ASCII word-run build failed: {error}"));
        let upstream = pinned_with_unicode(pattern, false);
        assert_eq!(fre.build_report().plan, PlanKind::UnicodeWordRun);
        assert_eq!(fre.runtime_implementation_id(), "ascii-word-run-linear-v1");
        let mut session = fre
            .search_session(SearchSessionLimits::unlimited())
            .expect("word-run session uses no workspace");
        assert_eq!(session.workspace_setup_accounting(), None);

        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = upstream
                        .find(Input::new(haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()));
                    let (actual, accounting) = fre
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(accounting.plan(), PlanKind::UnicodeWordRun);
                    assert_eq!(
                        actual.map(|matched| (matched.start(), matched.end())),
                        expected,
                        "cold {pattern:?}/{haystack:?}/{start}..{end}"
                    );
                    let reused = session
                        .find_window(haystack, window, SearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(reused.1.plan(), PlanKind::UnicodeWordRun);
                    assert_eq!(reused.0, actual);
                }
            }
        }
    }
}

#[test]
fn crlf_and_nonpositive_unicode_word_assertions_remain_exact_typed_refusals() {
    let crlf = PortableBuilder::new(r"(?mR:$)")
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect_err("CRLF-aware end assertion must remain unsupported");
    assert!(matches!(
        crlf,
        BuildError::Lower(LowerError::Unsupported(UnsupportedFeature::LookAssertion(
            Look::EndCRLF
        )))
    ));

    let local_ascii_pattern = r"(?-u:\b)a";
    let local_ascii = PortableBuilder::new(local_ascii_pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("a locally ASCII assertion remains exact in a Unicode profile");
    let haystack: &[u8] = &[0xFF, b'a'];
    let expected = pinned_with_unicode(local_ascii_pattern, true)
        .find(haystack)
        .map(|matched| (matched.start(), matched.end()));
    let actual = local_ascii
        .find(haystack, SearchLimits::unlimited())
        .unwrap()
        .0
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(actual, expected);

    let unicode = PortableBuilder::new(r"\B")
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect_err("negated Unicode word boundary must remain unsupported");
    assert!(matches!(
        unicode,
        BuildError::Lower(LowerError::Unsupported(UnsupportedFeature::LookAssertion(
            Look::WordUnicodeNegate
        )))
    ));
}

#[test]
fn representative_configured_line_bytes_match_pinned_ranged_search_and_reuse() {
    const PATTERNS: &[&str] = &[r"(?m:^a)", r"(?m:a$)", r"(?m:^$)", r"(?m:^a$)"];
    const LINE_TERMINATORS: &[u8] = &[0x00, b'\r', 0xFF];

    for &line_terminator in LINE_TERMINATORS {
        let haystacks = byte_strings(3, &[b'a', b'b', b'\n', line_terminator]);
        for pattern in PATTERNS {
            let fre = PortableBuilder::new(*pattern)
                .profile(RustProfile::regex_1_12_4())
                .unicode(false)
                .line_terminator(line_terminator)
                .plan_selection(PlanSelection::ForceK0)
                .build()
                .unwrap_or_else(|error| {
                    panic!(
                        "portable build failed for {pattern:?} with line byte \
                         {line_terminator:#04X}: {error}"
                    )
                });
            assert_eq!(fre.build_report().plan, PlanKind::K0);
            assert_eq!(
                fre.profile(),
                &fre::CompatibilityProfile::RustBytes({
                    let mut profile = RustProfile::regex_1_12_4();
                    profile.options.unicode = false;
                    profile.options.line_terminator = line_terminator;
                    profile
                })
            );
            let upstream = pinned_with_line_terminator(pattern, line_terminator);
            let mut session = fre
                .search_session(SearchSessionLimits::unlimited())
                .expect("configured K0 session");

            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let expected = upstream
                            .find(Input::new(haystack).span(start..end))
                            .map(|matched| (matched.start(), matched.end()));
                        let cold = fre
                            .find_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0
                            .map(|matched| (matched.start(), matched.end()));
                        let reused = session
                            .find_window(haystack, window, SearchLimits::unlimited())
                            .unwrap()
                            .0
                            .map(|matched| (matched.start(), matched.end()));
                        assert_eq!(
                            cold, expected,
                            "cold {pattern:?}/{line_terminator:#04X}/{haystack:?}/{start}..{end}"
                        );
                        assert_eq!(
                            reused, expected,
                            "reused {pattern:?}/{line_terminator:#04X}/{haystack:?}/{start}..{end}"
                        );
                    }
                }
            }
        }
    }
}
