use fre_automata::{MatchSpan, SearchLimits, SearchWindow, Span};
use fre_lower::{
    LowerError, LowerLimits, LowerResource, OperationSemantics, UnsupportedFeature, lower,
    lower_hir_raw, lower_raw,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile, parse,
};

fn profile(unicode: bool) -> CompatibilityProfile {
    let mut profile = RustProfile::default();
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

fn tuple(span: Option<MatchSpan>) -> Option<(usize, usize)> {
    span.map(|span| (span.start(), span.end()))
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
fn ordered_priority_and_repeat_greed_are_preserved() {
    assert_eq!(tuple(find("a|ab", b"ab")), Some((0, 1)));
    assert_eq!(tuple(find("ab|a", b"ab")), Some((0, 2)));
    assert_eq!(tuple(find("a*", b"aaab")), Some((0, 3)));
    assert_eq!(tuple(find("a*?", b"aaab")), Some((0, 0)));
    assert_eq!(tuple(find("a{1,3}", b"aaaa")), Some((0, 3)));
    assert_eq!(tuple(find("a{1,3}?", b"aaaa")), Some((0, 1)));
}

#[test]
fn nullable_unbounded_cycles_are_rejected_until_priority_is_certified() {
    for pattern in ["(?:a*)*", "(?:a*?)*?", "(?:|a)*", "(?:a|)*"] {
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
fn unsupported_semantics_are_never_silently_approximated() {
    let unicode = parsed("[α-ω]", true);
    assert!(matches!(
        lower_raw(
            &unicode,
            OperationSemantics::CaptureFree,
            LowerLimits::default()
        ),
        Err(LowerError::Unsupported(UnsupportedFeature::UnicodeClass))
    ));

    let multiline = parsed("(?m:^a)", false);
    assert!(matches!(
        lower_raw(
            &multiline,
            OperationSemantics::CaptureFree,
            LowerLimits::default()
        ),
        Err(LowerError::Unsupported(UnsupportedFeature::LookAssertion(
            _
        )))
    ));

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
    // separate regex 1.13.0 source-profile admission oracle.
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
