use fre_automata::{EdgeKind, MatchSpan, SearchLimits, SearchWindow, Span};
use fre_lower::{
    LowerError, LowerLimits, LowerResource, OperationSemantics, UnsupportedFeature, lower,
    lower_hir_raw, lower_raw, lower_utf8_start_guarded,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile, parse,
};
fn profile(unicode: bool) -> CompatibilityProfile {
    let mut profile = RustProfile::rebar_1_12_4();
    profile.options.unicode = unicode;
    CompatibilityProfile::RustBytes(profile)
}

fn parsed(pattern: &str, unicode: bool) -> RustParsed {
    let record = parse(ParseRequest::rust(pattern, profile(unicode))).expect("pattern parses");
    match record.pattern {
        CanonicalPattern::Rust(parsed) => parsed,
        CanonicalPattern::Re2(_) => panic!("Rust request returned parsed RE2"),
        CanonicalPattern::Re2Literal(_) => panic!("Rust request returned RE2 literal"),
    }
}

fn find(pattern: &str, haystack: &[u8]) -> Option<MatchSpan> {
    let parsed = parsed(pattern, false);
    lower(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("supported pattern lowers")
    .automaton()
    .prepare::<Span>()
    .search(haystack, SearchLimits::unlimited())
    .expect("K0 search succeeds")
    .into_output()
}

fn find_unicode(pattern: &str, haystack: &[u8]) -> Option<MatchSpan> {
    let parsed = parsed(pattern, true);
    lower(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("supported Unicode pattern lowers")
    .automaton()
    .prepare::<Span>()
    .search(haystack, SearchLimits::unlimited())
    .expect("K0 Unicode search succeeds")
    .into_output()
}

fn tuple(span: Option<MatchSpan>) -> Option<(usize, usize)> {
    span.map(|span| (span.start(), span.end()))
}

fn find_window(pattern: &str, haystack: &[u8], window: SearchWindow) -> Option<(usize, usize)> {
    let parsed = parsed(pattern, false);
    let found = lower(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("supported assertion pattern lowers")
    .automaton()
    .prepare::<Span>()
    .search_window(haystack, window, SearchLimits::unlimited())
    .expect("K0 ranged search succeeds")
    .into_output();
    tuple(found)
}

#[test]
fn syntax_to_lowering_to_k0_handles_the_safe_byte_subset() {
    assert_eq!(tuple(find("", b"abc")), Some((0, 0)));
    assert_eq!(tuple(find("ab[0-3]", b"zzab2xx")), Some((2, 5)));
    assert_eq!(tuple(find("ab[0-3]", b"zzab9xx")), None);
    assert_eq!(tuple(find(r"(?-u:\xFF)", &[0xFF])), Some((0, 1)));
    assert_eq!(tuple(find("(?:ab|cd)+", b"xcdabz")), Some((1, 5)));
    assert_eq!(tuple(find("a{2,4}", b"zaaaaax")), Some((1, 5)));
}

#[test]
fn unicode_scalar_classes_lower_to_exact_utf8_byte_paths() {
    assert_eq!(
        tuple(find_unicode("[α-ω]+", "xαβz".as_bytes())),
        Some((1, 5))
    );
    assert_eq!(tuple(find_unicode(".", "😀".as_bytes())), Some((0, 4)));
    assert_eq!(tuple(find_unicode(".", &[0xFF, b'x'])), Some((1, 2)));
    assert_eq!(tuple(find_unicode(".", &[0xCE])), None);
    assert_eq!(tuple(find_unicode(".", &[0xC0, 0x80])), None);
    assert_eq!(tuple(find_unicode(".", &[0xED, 0xA0, 0x80])), None);

    let ruff = r"^[ \t\f]*#.*?coding[:=][ \t]*utf-?8";
    assert_eq!(
        tuple(find_unicode(ruff, b"# -*- coding: utf-8 -*-")),
        Some((0, b"# -*- coding: utf-8".len()))
    );
    assert_eq!(tuple(find_unicode(ruff, b"x # coding: utf-8")), None);
}

#[test]
fn unicode_class_expansion_retains_typed_construction_limits() {
    let unicode = parsed(".", true);
    let limits = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_states: 1,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&unicode, OperationSemantics::CaptureFree, limits),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::States,
            ..
        })
    ));
}

#[test]
fn lowering_maps_each_portable_assertion_to_a_distinct_edge_kind() {
    const CASES: &[(&str, EdgeKind)] = &[
        (r"\A", EdgeKind::AssertHaystackStart),
        (r"\z", EdgeKind::AssertHaystackEnd),
        (r"(?m:^)", EdgeKind::AssertLineStartLf),
        (r"(?m:$)", EdgeKind::AssertLineEndLf),
        (r"(?Rm:^)", EdgeKind::AssertLineStartCrlf),
        (r"(?Rm:$)", EdgeKind::AssertLineEndCrlf),
        (r"\b", EdgeKind::AssertWordAscii),
        (r"\B", EdgeKind::AssertWordAsciiNegate),
        (r"\b{start}", EdgeKind::AssertWordStartAscii),
        (r"\b{end}", EdgeKind::AssertWordEndAscii),
        (r"\b{start-half}", EdgeKind::AssertWordStartHalfAscii),
        (r"\b{end-half}", EdgeKind::AssertWordEndHalfAscii),
    ];

    for &(pattern, expected) in CASES {
        let parsed = parsed(pattern, false);
        let lowered = lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("failed to lower {pattern:?}: {error}"));
        assert_eq!(
            lowered.plan().edge_kinds.as_slice(),
            &[expected],
            "{pattern:?}"
        );
        assert_eq!(lowered.stats().states(), 2, "{pattern:?}");
        assert_eq!(lowered.stats().edges(), 1, "{pattern:?}");
    }
}

#[test]
fn lowering_maps_every_unicode_word_boundary_without_approximating_it() {
    let cases = [
        (r"\b", EdgeKind::AssertWordUnicode),
        (r"\B", EdgeKind::AssertWordUnicodeNegate),
        (r"\b{start}", EdgeKind::AssertWordStartUnicode),
        (r"\b{end}", EdgeKind::AssertWordEndUnicode),
        (r"\b{start-half}", EdgeKind::AssertWordStartHalfUnicode),
        (r"\b{end-half}", EdgeKind::AssertWordEndHalfUnicode),
    ];
    for (pattern, expected) in cases {
        let parsed = parsed(pattern, true);
        let lowered = lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("failed to lower {pattern:?}: {error}"));
        assert_eq!(lowered.plan().edge_kinds.as_slice(), &[expected]);
    }
    assert_eq!(
        tuple(find_unicode(r"\b\w{2,}\b", "-αβ-".as_bytes())),
        Some((1, 5))
    );
    assert_eq!(
        tuple(find_unicode(r"\b\w{2,}\b", &[0xFF, b'a', b'b', 0xFF])),
        Some((1, 3))
    );
}

#[test]
fn ordered_priority_and_repeat_greed_are_preserved() {
    assert_eq!(tuple(find("a|ab", b"ab")), Some((0, 1)));
    assert_eq!(tuple(find("ab|a", b"ab")), Some((0, 2)));
    assert_eq!(tuple(find("a*", b"aaab")), Some((0, 3)));
    assert_eq!(tuple(find("a*?", b"aaab")), Some((0, 0)));
    assert_eq!(tuple(find("a{1,3}", b"aaaa")), Some((0, 3)));
    assert_eq!(tuple(find("a{1,3}?", b"aaaa")), Some((0, 1)));
}

#[test]
fn nullable_unbounded_cycles_require_a_capture_free_normalization_proof() {
    for pattern in [
        "(?:a*)*",
        "(?:a*)+",
        "(?:a?)*",
        "(?:a?)*?",
        "(?:a*)*?",
        "(?:a*)+?",
        "(?:a*){1,}?",
        "(?:a?)+?",
        "(?:[ab]*){3,}",
        "(?:a*|b)*",
        "(a*|b)*",
        "((a*|b))*",
    ] {
        let parsed = parsed(pattern, false);
        let lowered = lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
        assert_eq!(lowered.stats().normalized_nullable_repetitions(), 1);
    }

    for pattern in [
        "(?:a*?)*?",
        "(?:a?){3,}?",
        "(?:a*){2,}?",
        "(?:a|)*",
        "(?:b|a*)*",
    ] {
        let parsed = parsed(pattern, false);
        assert!(
            matches!(
                lower_raw(
                    &parsed,
                    OperationSemantics::CaptureFree,
                    LowerLimits::default()
                ),
                Err(LowerError::Unsupported(
                    UnsupportedFeature::UncertifiedUnboundedRepetition
                ))
            ),
            "pattern={pattern:?}"
        );
    }

    let never = regex_syntax::hir::Hir::fail();
    assert_eq!(never.properties().minimum_len(), None);
    let unknown_body_min = regex_syntax::hir::Hir::repetition(regex_syntax::hir::Repetition {
        min: 1,
        max: None,
        greedy: true,
        sub: Box::new(never),
    });
    assert!(matches!(
        lower_hir_raw(
            &unknown_body_min,
            OperationSemantics::CaptureFree,
            LowerLimits::default()
        ),
        Err(LowerError::Unsupported(
            UnsupportedFeature::UncertifiedUnboundedRepetition
        ))
    ));
}

#[test]
fn ordered_nullable_alternative_star_matches_upstream_in_continuations() {
    let patterns = [
        "(a*|b)*",
        "((a*|b))*",
        "(?:a*|b)*c",
        "(?:a*|b)*b",
        "(?:a*|b)*a",
        "(?:a*|b)*$",
        "^(?:a*|b)*$",
        "(?:a*|b)*(?:b|bc)",
        "(?:a*|b)*a?",
    ];
    let mut haystacks = vec![
        Vec::new(),
        b"b".to_vec(),
        b"bbb".to_vec(),
        b"a".to_vec(),
        b"aaab".to_vec(),
        b"aba".to_vec(),
        b"c".to_vec(),
        b"bc".to_vec(),
        b"abc".to_vec(),
        b"bbbc".to_vec(),
        b"xbc".to_vec(),
        b"abb".to_vec(),
        b"ba".to_vec(),
        b"abba".to_vec(),
        "ébc".as_bytes().to_vec(),
    ];
    let alphabet = [b'a', b'b', b'c'];
    for len in 1..=6 {
        let count = alphabet
            .len()
            .pow(u32::try_from(len).expect("short byte word"));
        for mut number in 0..count {
            let mut haystack = vec![0; len];
            for byte in &mut haystack {
                *byte = alphabet[number % alphabet.len()];
                number /= alphabet.len();
            }
            haystacks.push(haystack);
        }
    }

    for pattern in patterns {
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        let parsed = parsed(pattern, false);
        let lowered = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        assert_eq!(lowered.stats().normalized_nullable_repetitions(), 1);
        for haystack in &haystacks {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let actual = lowered
                .automaton()
                .prepare::<Span>()
                .search(haystack, SearchLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!("pattern={pattern:?}, haystack={haystack:?}: {error}")
                })
                .into_output();
            assert_eq!(tuple(actual), expected, "{pattern:?}, {haystack:?}");
        }
    }

    for (pattern, expected_erased) in [("(a*|b)*", 1), ("((a*|b))*", 2)] {
        let lowered = lower_raw(
            &parsed(pattern, false),
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("FRE rejected {pattern:?}: {error}"));
        assert_eq!(lowered.stats().erased_captures(), expected_erased);
    }
}

#[test]
fn ordered_empty_first_repetitions_match_pinned_upstream_at_every_start() {
    let patterns = [r"(?:|a)*", r"(?:|a)+", r"(?:|ab)*", r"(?:|[ab])+"];
    let haystacks = words(5);

    for pattern in patterns {
        let parsed = parsed(pattern, false);
        let lowered = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
        assert_eq!(lowered.stats().normalized_nullable_repetitions(), 1);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pinned upstream rejected {pattern:?}: {error}"));
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = lowered
                    .automaton()
                    .prepare::<Span>()
                    .search_window(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("pattern={pattern:?}, haystack={haystack:?}, start={start}: {error}")
                    })
                    .into_output();
                assert_eq!(
                    tuple(actual),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}, start={start}"
                );
            }
        }
    }
}

#[test]
fn ordered_empty_first_repetition_proof_remains_narrow() {
    for pattern in [
        r"(?:a|)*",
        r"(?:|a)*?",
        r"(?:|a){2,}",
        r"(?:|a?)*",
        r"(?:|a|b)*",
        r"(?:|ab)*b",
    ] {
        let parsed = parsed(pattern, false);
        assert!(
            matches!(
                lower_raw(
                    &parsed,
                    OperationSemantics::CaptureFree,
                    LowerLimits::default()
                ),
                Err(LowerError::Unsupported(
                    UnsupportedFeature::UncertifiedUnboundedRepetition
                ))
            ),
            "pattern={pattern:?}"
        );
    }
}

#[test]
fn normalized_nullable_repetitions_match_upstream_group_zero() {
    let patterns = [
        "(?:a*)*",
        "(?:a*)+",
        "(?:a?)*",
        "(?:a?)*?",
        "(?:[ab]*){3,}",
        "X(?:.?){0,}Y",
        "X(?:.?){3,}Y",
        "X(?:(?:.*)*)Y",
        "(?:(?:.*)*?)=",
        "(?:(?:.*)+?)=",
        "(?:(?:.?)+?)=",
        "(?:(?:.*){1,}?)=",
    ];
    let haystacks: [&[u8]; 16] = [
        b"", b"a", b"aa", b"ab", b"ba", b"bbb", b"X", b"Y", b"XY", b"XaY", b"XabY", b"XabYcY",
        b"aXabYcY", b"a=b=c", b"\n", b"X\nY",
    ];
    for pattern in patterns {
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let parsed = parsed(pattern, false);
        let lowered = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
        assert_eq!(lowered.stats().normalized_nullable_repetitions(), 1);
        for haystack in haystacks {
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            let actual = lowered
                .automaton()
                .prepare::<Span>()
                .search(haystack, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            assert_eq!(
                tuple(actual),
                expected,
                "pattern={pattern:?}, haystack={haystack:?}"
            );
        }
    }
}

#[test]
fn ordered_word_look_nullable_plus_matches_pinned_upstream_at_every_start() {
    let patterns = [
        r"(?:(?-u:\b)|(?u:h))+",
        r"(?:(?-u:\B)|(?su:.))+",
        r"(?:(?-u:\b)|(?u:[\u{0}-W]))+",
        r"(?:(?u:\b)|(?s-u:.))+",
        r"(?:(?u:\b)|(?-u:.))+",
    ];
    let mut haystacks = vec![
        Vec::new(),
        b"h".to_vec(),
        b"oB".to_vec(),
        "\u{fef80}".as_bytes().to_vec(),
        b"0".to_vec(),
        b"ab!cd".to_vec(),
        b"!ab cd!".to_vec(),
        vec![0xFF, b'a', b'!', b'B', 0x80],
        vec![b'a', 0x80, 0x80, 0x80, 0x80],
    ];
    let alphabet = [b'a', b'B', b'!', b' ', 0x80, 0xFF];
    for len in 1..=4 {
        let count = alphabet
            .len()
            .pow(u32::try_from(len).expect("short byte word"));
        for mut number in 0..count {
            let mut haystack = vec![0; len];
            for byte in &mut haystack {
                *byte = alphabet[number % alphabet.len()];
                number /= alphabet.len();
            }
            haystacks.push(haystack);
        }
    }

    for pattern in patterns {
        let parsed = parsed(pattern, true);
        let lowered = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
        assert_eq!(lowered.stats().normalized_nullable_repetitions(), 1);
        let mut upstream = regex::bytes::RegexBuilder::new(pattern);
        upstream.unicode(true);
        let upstream = upstream
            .build()
            .unwrap_or_else(|error| panic!("pinned upstream rejected {pattern:?}: {error}"));
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = lowered
                    .automaton()
                    .prepare::<Span>()
                    .search_window(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("pattern={pattern:?}, haystack={haystack:?}, start={start}: {error}")
                    })
                    .into_output();
                assert_eq!(
                    tuple(actual),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}, start={start}"
                );
            }
        }
    }
}

#[test]
fn ordered_word_look_nullable_plus_proof_remains_narrow() {
    for pattern in [
        r"(?:a|\b)+",
        r"(?:\b|a)+?",
        r"(?:\b|a){2,}",
        r"(?:\b|a+)+",
        r"(?:\b|a|bc)+",
        r"(?:(?u:\B)|(?s-u:.))+",
    ] {
        let parsed = parsed(pattern, false);
        assert!(
            matches!(
                lower_raw(
                    &parsed,
                    OperationSemantics::CaptureFree,
                    LowerLimits::default()
                ),
                Err(LowerError::Unsupported(
                    UnsupportedFeature::UncertifiedUnboundedRepetition
                ))
            ),
            "pattern={pattern:?}"
        );
    }
}

#[test]
fn ordered_unicode_word_look_nullable_plus_resources_are_exact() {
    for pattern in [r"(?:(?u:\b)|(?s-u:.))+", r"(?:(?u:\b)|(?-u:.))+"] {
        let parsed = parsed(pattern, true);
        let exact = lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
        let stats = exact.stats();

        let exact_limits = LowerLimits {
            max_work: stats.work(),
            automata: fre_automata::CompileLimits {
                max_states: stats.states(),
                max_edges: stats.edges(),
                ..fre_automata::CompileLimits::default()
            },
            ..LowerLimits::default()
        };
        assert_eq!(
            lower_raw(&parsed, OperationSemantics::CaptureFree, exact_limits)
                .expect("exact work, state and edge limits succeed")
                .stats(),
            stats,
            "pattern={pattern:?}"
        );

        let work_short = LowerLimits {
            max_work: stats.work() - 1,
            ..LowerLimits::default()
        };
        assert!(
            matches!(
                lower_raw(&parsed, OperationSemantics::CaptureFree, work_short),
                Err(LowerError::ResourceLimit {
                    resource: LowerResource::Work,
                    needed,
                    limit,
                }) if needed > limit && limit == stats.work() - 1
            ),
            "pattern={pattern:?}"
        );

        let states_short = LowerLimits {
            automata: fre_automata::CompileLimits {
                max_states: stats.states() - 1,
                ..fre_automata::CompileLimits::default()
            },
            ..LowerLimits::default()
        };
        assert!(
            matches!(
                lower_raw(&parsed, OperationSemantics::CaptureFree, states_short),
                Err(LowerError::ResourceLimit {
                    resource: LowerResource::States,
                    needed,
                    limit,
                }) if needed > limit
                    && limit == u64::try_from(stats.states() - 1).expect("small state count")
            ),
            "pattern={pattern:?}"
        );

        let edges_short = LowerLimits {
            automata: fre_automata::CompileLimits {
                max_edges: stats.edges() - 1,
                ..fre_automata::CompileLimits::default()
            },
            ..LowerLimits::default()
        };
        assert!(
            matches!(
                lower_raw(&parsed, OperationSemantics::CaptureFree, edges_short),
                Err(LowerError::ResourceLimit {
                    resource: LowerResource::Edges,
                    needed,
                    limit,
                }) if needed > limit
                    && limit == u64::try_from(stats.edges() - 1).expect("small edge count")
            ),
            "pattern={pattern:?}"
        );
    }
}

#[test]
fn ordered_start_look_nullable_repetitions_match_pinned_upstream_at_every_start() {
    let patterns = [
        r"(?m)(?:^|a)+",
        r"(?m)(?:^|a)*",
        r"(?Rm)(?:^|a)+",
        r"(?Rm)(?:^|a)*",
        r"(?:^|a)+",
        r"(?:^|a)*",
        r"(?m:(?:^|a)+b)",
        r"(?m:(?:^|[a\n])+)",
        r"(?m:(?:^|ab)*)",
    ];
    let alphabet = [b'a', b'b', b'\n', b'\r'];
    let mut haystacks = vec![Vec::new()];
    for len in 1..=5 {
        let count = alphabet
            .len()
            .pow(u32::try_from(len).expect("short byte word"));
        for mut number in 0..count {
            let mut haystack = vec![0; len];
            for byte in &mut haystack {
                *byte = alphabet[number % alphabet.len()];
                number /= alphabet.len();
            }
            haystacks.push(haystack);
        }
    }

    for pattern in patterns {
        let parsed = parsed(pattern, false);
        let lowered = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
        assert_eq!(lowered.stats().normalized_nullable_repetitions(), 1);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pinned upstream rejected {pattern:?}: {error}"));
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = lowered
                    .automaton()
                    .prepare::<Span>()
                    .search_window(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("pattern={pattern:?}, haystack={haystack:?}, start={start}: {error}")
                    })
                    .into_output();
                assert_eq!(
                    tuple(actual),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}, start={start}"
                );
            }
        }
    }

    assert_eq!(tuple(find(r"(?m:(?:^|a)+b)", b"ab")), Some((0, 2)));
}

#[test]
fn ordered_start_look_nullable_repetition_proof_and_resources_are_exact() {
    for pattern in [
        r"(?:a|^)+",
        r"(?:^|a)+?",
        r"(?:^|a){2,}",
        r"(?:^|a|b)+",
        r"(?:^$|a)+",
        r"(?:$|a)+",
        r"(?:^|a*)+",
        r"(?:^|a?)*",
    ] {
        let parsed = parsed(pattern, false);
        assert!(
            matches!(
                lower_raw(
                    &parsed,
                    OperationSemantics::CaptureFree,
                    LowerLimits::default()
                ),
                Err(LowerError::Unsupported(
                    UnsupportedFeature::UncertifiedUnboundedRepetition
                ))
            ),
            "pattern={pattern:?}"
        );
    }

    let parsed = parsed(r"(?m)(?:^|a)+", false);
    let exact = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("certified start-look repetition lowers");
    let stats = exact.stats();
    let exact_work = stats.work();
    let exact_storage = (stats.states() + 1) * core::mem::size_of::<u32>()
        + stats.states() * core::mem::size_of::<fre_automata::StateRole>()
        + stats.edges()
            * (core::mem::size_of::<u32>()
                + core::mem::size_of::<EdgeKind>()
                + 2 * core::mem::size_of::<u8>());
    let exact_storage_u64 = u64::try_from(exact_storage).expect("small graph storage fits u64");

    let exact_limits = LowerLimits {
        max_work: exact_work,
        automata: fre_automata::CompileLimits {
            max_storage_bytes: exact_storage,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert_eq!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, exact_limits)
            .expect("exact work and storage limits succeed")
            .stats(),
        stats
    );

    let work_short = LowerLimits {
        max_work: exact_work - 1,
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, work_short),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            needed,
            limit,
        }) if needed > limit && limit == exact_work - 1
    ));

    let storage_short = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_storage_bytes: exact_storage - 1,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, storage_short),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StorageBytes,
            needed,
            limit,
        }) if needed == exact_storage_u64 && limit == exact_storage_u64 - 1
    ));
}

#[test]
fn ordered_empty_nullable_repetitions_match_pinned_upstream_at_every_start() {
    let patterns = [
        r"(?:|a)*",
        r"(?:|a)+",
        r"(?:|a)+b",
        r"(?:|[a\n])*b?",
        r"(?:|ab)+",
        r"x(?:|[ab])+b",
    ];
    let alphabet = [b'a', b'b', b'\n', b'x'];
    let mut haystacks = vec![Vec::new()];
    for len in 1..=5 {
        let count = alphabet
            .len()
            .pow(u32::try_from(len).expect("short byte word"));
        for mut number in 0..count {
            let mut haystack = vec![0; len];
            for byte in &mut haystack {
                *byte = alphabet[number % alphabet.len()];
                number /= alphabet.len();
            }
            haystacks.push(haystack);
        }
    }

    for pattern in patterns {
        let parsed = parsed(pattern, false);
        let lowered = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("pattern={pattern:?}: {error}"));
        assert_eq!(lowered.stats().normalized_nullable_repetitions(), 1);
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("pinned upstream rejected {pattern:?}: {error}"));
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                let expected = upstream
                    .find_at(haystack, start)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = lowered
                    .automaton()
                    .prepare::<Span>()
                    .search_window(
                        haystack,
                        SearchWindow::new(start, haystack.len()),
                        SearchLimits::unlimited(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("pattern={pattern:?}, haystack={haystack:?}, start={start}: {error}")
                    })
                    .into_output();
                assert_eq!(
                    tuple(actual),
                    expected,
                    "pattern={pattern:?}, haystack={haystack:?}, start={start}"
                );
            }
        }
    }

    assert_eq!(tuple(find(r"(?:|a)+b", b"ab")), Some((0, 2)));
}

#[test]
fn ordered_empty_nullable_repetition_proof_and_resources_are_exact() {
    for pattern in [
        r"(?:a|)*",
        r"(?:|a)*?",
        r"(?:|a){2,}",
        r"(?:|a|b)*",
        r"(?:||a)*",
        r"(?:|a?)*",
        r"(?:|a*)+",
        r"(?:|(?:^|a))*",
    ] {
        let parsed = parsed(pattern, false);
        assert!(
            matches!(
                lower_raw(
                    &parsed,
                    OperationSemantics::CaptureFree,
                    LowerLimits::default()
                ),
                Err(LowerError::Unsupported(
                    UnsupportedFeature::UncertifiedUnboundedRepetition
                ))
            ),
            "pattern={pattern:?}"
        );
    }

    let parsed = parsed(r"(?:|a)+", false);
    let exact = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("certified empty-first repetition lowers");
    let stats = exact.stats();
    let exact_work = stats.work();
    let exact_storage = (stats.states() + 1) * core::mem::size_of::<u32>()
        + stats.states() * core::mem::size_of::<fre_automata::StateRole>()
        + stats.edges()
            * (core::mem::size_of::<u32>()
                + core::mem::size_of::<EdgeKind>()
                + 2 * core::mem::size_of::<u8>());
    let exact_storage_u64 = u64::try_from(exact_storage).expect("small graph storage fits u64");

    let exact_limits = LowerLimits {
        max_work: exact_work,
        automata: fre_automata::CompileLimits {
            max_storage_bytes: exact_storage,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert_eq!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, exact_limits)
            .expect("exact work and storage limits succeed")
            .stats(),
        stats
    );

    let work_short = LowerLimits {
        max_work: exact_work - 1,
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, work_short),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            needed,
            limit,
        }) if needed > limit && limit == exact_work - 1
    ));

    let storage_short = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_storage_bytes: exact_storage - 1,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, storage_short),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StorageBytes,
            needed,
            limit,
        }) if needed == exact_storage_u64 && limit == exact_storage_u64 - 1
    ));
}

#[test]
fn anchors_retain_original_haystack_context_for_ranged_search() {
    let start = parsed("^a", false);
    let start = lower(
        &start,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .unwrap();
    let end = parsed("a$", false);
    let end = lower(
        &end,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .unwrap();

    let ranged_start = start
        .automaton()
        .prepare::<Span>()
        .search_window(b"za", SearchWindow::new(1, 2), SearchLimits::unlimited())
        .unwrap()
        .into_output();
    let ranged_end = end
        .automaton()
        .prepare::<Span>()
        .search_window(b"az", SearchWindow::new(0, 1), SearchLimits::unlimited())
        .unwrap()
        .into_output();

    assert_eq!(ranged_start, None);
    assert_eq!(ranged_end, None);
    assert_eq!(tuple(find("^a", b"ab")), Some((0, 1)));
    assert_eq!(tuple(find("a$", b"ba")), Some((1, 2)));
}

#[test]
fn utf8_start_guard_is_exact_and_resource_bounded() {
    let haystack = "a\u{1d6c3}".as_bytes();
    let window = SearchWindow::new(1, haystack.len());
    for pattern in [r"(?-u:\b{start-half})", r"(?-u:\B)"] {
        let parsed = parsed(pattern, true);
        let unguarded = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("ordinary bytes lowering");
        let unguarded = unguarded
            .automaton()
            .prepare::<Span>()
            .search_window(haystack, window, SearchLimits::unlimited())
            .expect("ordinary bytes search")
            .into_output()
            .expect("ordinary bytes match");
        assert!(
            !core::str::from_utf8(haystack)
                .expect("fixture is UTF-8")
                .is_char_boundary(unguarded.start()),
            "pattern={pattern:?}, unguarded={unguarded:?}"
        );

        let guarded = lower_utf8_start_guarded(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("guarded lowering");
        assert!(guarded.stats().utf8_start_guarded());
        let expected_work = guarded.stats().work();
        let guarded_match = guarded
            .automaton()
            .prepare::<Span>()
            .search_window(haystack, window, SearchLimits::unlimited())
            .expect("guarded search")
            .into_output()
            .expect("guarded match");
        assert_eq!(
            (guarded_match.start(), guarded_match.end()),
            (haystack.len(), haystack.len()),
            "pattern={pattern:?}"
        );

        let exact = lower_utf8_start_guarded(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                max_work: expected_work,
                ..LowerLimits::default()
            },
        )
        .expect("exact guarded work limit");
        assert_eq!(exact.stats().work(), expected_work);
        assert!(matches!(
            lower_utf8_start_guarded(
                &parsed,
                OperationSemantics::CaptureFree,
                LowerLimits {
                    max_work: expected_work - 1,
                    ..LowerLimits::default()
                },
            ),
            Err(LowerError::ResourceLimit {
                resource: LowerResource::Work,
                ..
            })
        ));
    }
}

#[test]
fn lf_and_ascii_word_assertions_retain_original_haystack_context() {
    assert_eq!(
        find_window("(?m:^a)", b"\na", SearchWindow::new(1, 2)),
        Some((1, 2))
    );
    assert_eq!(find_window("(?m:^a)", b"xa", SearchWindow::new(1, 2)), None);
    assert_eq!(
        find_window("(?m:a$)", b"a\n", SearchWindow::new(0, 1)),
        Some((0, 1))
    );
    assert_eq!(
        find_window(r"\ba", b"-a", SearchWindow::new(1, 2)),
        Some((1, 2))
    );
    assert_eq!(
        find_window(r"\Ba", b"aa", SearchWindow::new(1, 2)),
        Some((1, 2))
    );
    assert_eq!(
        find_window(r"\b{start}a", b"-a", SearchWindow::new(1, 2)),
        Some((1, 2))
    );
    assert_eq!(
        find_window(r"a\b{end}", b"a-", SearchWindow::new(0, 1)),
        Some((0, 1))
    );
    assert_eq!(
        find_window(r"\b{start-half}-", b"--", SearchWindow::new(1, 2)),
        Some((1, 2))
    );
    assert_eq!(
        find_window(r"-\b{end-half}", b"--", SearchWindow::new(0, 1)),
        Some((0, 1))
    );

    // Invalid bytes are ordinary non-word bytes, never surrogate Unicode
    // scalars. Across leading and trailing assertions, context on either side
    // of the requested range is visible while consumption remains inside it.
    assert_eq!(
        find_window(r"\b\xFF", &[b'a', 0xFF], SearchWindow::new(1, 2)),
        Some((1, 2))
    );
    assert_eq!(
        find_window(r"\B\xFF", &[b'-', 0xFF], SearchWindow::new(1, 2)),
        Some((1, 2))
    );
    assert_eq!(
        find_window(r"\xFF\b", &[0xFF, b'a'], SearchWindow::new(0, 1)),
        Some((0, 1))
    );
    assert_eq!(
        find_window(r"\xFF\B", &[0xFF, b'-'], SearchWindow::new(0, 1)),
        Some((0, 1))
    );
}

#[test]
fn unsupported_semantics_are_never_silently_approximated() {
    let no_capture_nodes = parsed("abc", false);
    assert!(matches!(
        lower_raw(
            &no_capture_nodes,
            OperationSemantics::CaptureSensitive,
            LowerLimits::default()
        ),
        Err(LowerError::Unsupported(
            UnsupportedFeature::CaptureSensitiveOperation
        ))
    ));

    let captured = parsed("(a)+", false);
    let lowered = lower_raw(
        &captured,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("capture annotations may be erased for a capture-free operation");
    assert_eq!(lowered.stats().erased_captures(), 1);
    let expanded_capture = parsed("(a){3}", false);
    let lowered = lower_raw(
        &expanded_capture,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .unwrap();
    assert_eq!(lowered.stats().erased_captures(), 1);
}

#[test]
fn every_construction_budget_fails_explicitly() {
    let repeated = parsed("a{100}", false);

    let work = LowerLimits {
        max_work: 0,
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&repeated, OperationSemantics::CaptureFree, work),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            needed: 1,
            limit: 0
        })
    ));

    let stack = LowerLimits {
        max_stack_items: 16,
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&repeated, OperationSemantics::CaptureFree, stack),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StackItems,
            ..
        })
    ));

    let states = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_states: 2,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&repeated, OperationSemantics::CaptureFree, states),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::States,
            ..
        })
    ));

    let edges = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_edges: 1,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(
            &parsed("[a-cx-z]", false),
            OperationSemantics::CaptureFree,
            edges
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Edges,
            ..
        })
    ));

    let storage = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_storage_bytes: 0,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(
            &parsed("a", false),
            OperationSemantics::CaptureFree,
            storage
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StorageBytes,
            ..
        })
    ));

    let validation = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_validation_work: 0,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(
            &parsed("a", false),
            OperationSemantics::CaptureFree,
            validation
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::ValidationWork,
            ..
        })
    ));
}

#[test]
fn completed_work_charge_is_an_exact_replayable_limit() {
    let parsed = parsed("(?:ab|a){2,5}c+?", false);
    let successful = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .unwrap();
    let charged = successful.stats().work();
    assert!(charged > 0);

    let exact = LowerLimits {
        max_work: charged,
        ..LowerLimits::default()
    };
    assert_eq!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, exact)
            .unwrap()
            .stats()
            .work(),
        charged
    );

    let short = LowerLimits {
        max_work: charged - 1,
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, short),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            needed,
            limit,
        }) if needed > limit && limit == charged - 1
    ));
}

#[test]
fn deep_flat_concatenation_uses_an_explicit_checked_stack() {
    const TERMS: usize = 20_000;
    std::thread::Builder::new()
        .name("tiny-stack-lowering".to_owned())
        .stack_size(128 * 1024)
        .spawn(|| {
            let pattern = "a?".repeat(TERMS);
            let parsed = parsed(&pattern, false);
            let lowered = lower_raw(
                &parsed,
                OperationSemantics::CaptureFree,
                LowerLimits::default(),
            )
            .expect("flat HIR lowers without native recursion");
            assert!(lowered.stats().states() >= TERMS * 2);
            assert!(lowered.stats().peak_stack_items() >= TERMS);
        })
        .unwrap()
        .join()
        .expect("tiny-stack lowering thread did not panic");
}

#[test]
fn supported_subset_matches_pinned_rebar_regex_baseline() {
    // This exact crates.io release is the Rebar baseline adapter, not the
    // explicitly selected Rebar 1.12.4 release-stack profile.
    const PATTERNS: &[&str] = &[
        "",
        "a",
        "ab",
        "a|ab",
        "ab|a",
        "a*",
        "a*?",
        "a+",
        "a+?",
        "a{1,3}",
        "a{1,3}?",
        "[a-c]+",
        "(?:ab|a)+",
        "^a*$",
        "(?:ab)?c",
        "(ab|a)+",
        r"(?m:^)",
        r"(?m:$)",
        r"\b",
        r"\B",
        r"\b{start}",
        r"\b{end}",
        r"\b{start-half}",
        r"\b{end-half}",
    ];

    let haystacks = words(6);
    for &pattern in PATTERNS {
        let parsed = parsed(pattern, false);
        let fre = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap();
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("baseline accepts supported pattern");
        for haystack in &haystacks {
            let actual = fre
                .automaton()
                .prepare::<Span>()
                .search(haystack, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            let expected = upstream
                .find(haystack)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(
                tuple(actual),
                expected,
                "pattern={pattern:?}, haystack={haystack:?}"
            );
        }
    }
}

fn words(max_len: usize) -> Vec<Vec<u8>> {
    let mut result = vec![Vec::new()];
    for len in 1..=max_len {
        let count = 3usize.pow(u32::try_from(len).expect("short word length"));
        for mut number in 0..count {
            let mut word = vec![b'a'; len];
            for byte in &mut word {
                *byte = [b'a', b'b', b'c'][number % 3];
                number /= 3;
            }
            result.push(word);
        }
    }
    result
}
