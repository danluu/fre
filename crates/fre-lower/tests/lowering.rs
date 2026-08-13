use fre_automata::{
    EdgeKind, Exists, K0Workspace, MatchSpan, SearchLimits, SearchWindow, Span, WorkspaceLimits,
};
use fre_lower::{
    LowerError, LowerLimits, LowerResource, OperationSemantics, UnsupportedFeature, lower,
    lower_general, lower_hir, lower_hir_concat_slice, lower_hir_raw, lower_raw,
    lower_utf8_start_guarded,
};
use fre_syntax::{
    CanonicalPattern, CompatibilityProfile, ParseRequest, RustParsed, RustProfile, parse,
};
use regex_syntax::hir::{Hir, HirKind};
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

fn find_hir(hir: &Hir, haystack: &[u8]) -> Option<(usize, usize)> {
    let found = lower_hir(hir, OperationSemantics::CaptureFree, LowerLimits::default())
        .expect("HIR lowers")
        .automaton()
        .prepare::<Span>()
        .search(haystack, SearchLimits::unlimited())
        .expect("K0 HIR search succeeds")
        .into_output();
    tuple(found)
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
fn embedded_literal_trie_preserves_prefix_priority_and_fallback() {
    let short_first = Hir::concat(vec![
        Hir::alternation(vec![
            Hir::literal(*b"a"),
            Hir::literal(*b"ab"),
            Hir::literal(*b"x"),
        ]),
        Hir::literal(*b"c"),
    ]);
    assert_eq!(find_hir(&short_first, b"abc"), Some((0, 3)));

    let long_first = Hir::concat(vec![
        Hir::alternation(vec![
            Hir::literal(*b"ab"),
            Hir::literal(*b"a"),
            Hir::literal(*b"x"),
        ]),
        Hir::literal(*b"b"),
    ]);
    assert_eq!(find_hir(&long_first, b"ab"), Some((0, 2)));

    let duplicate_barrier = Hir::concat(vec![
        Hir::alternation(vec![
            Hir::literal(*b"a"),
            Hir::literal(*b"ab"),
            Hir::literal(*b"a"),
            Hir::literal(*b"ac"),
            Hir::literal(*b"x"),
        ]),
        Hir::literal(*b"d"),
    ]);
    assert_eq!(find_hir(&duplicate_barrier, b"acd"), Some((0, 3)));

    assert_eq!(
        tuple(find(r"(?:sam|samwise|frodo)\b", b"samwise ")),
        Some((0, 7))
    );
    assert_eq!(tuple(find(r"(?:zapper|z|zap|foo)q", b"zapq")), Some((0, 4)));
    assert_eq!(
        tuple(find(r"(?:zapper|z|zap|foo)q", b"zapperq")),
        Some((0, 7))
    );
    assert_eq!(tuple(find(r"(?:ab|a|ac|z)", b"ab")), Some((0, 2)));
    assert_eq!(tuple(find(r"(?:ab|a|ac|z)", b"ac")), Some((0, 1)));
    assert_eq!(tuple(find(r"(?:zapper|z|zap|foo)", b"zap")), Some((0, 1)));

    assert_eq!(tuple(find(r"(?:a|ba|z)", b"ba")), Some((0, 2)));
    assert_eq!(
        find_window(r"(?:a|ba|z)", b"ba", SearchWindow::new(1, 2)),
        Some((1, 2))
    );
    assert_eq!(tuple(find(r"(?:ing|thing|x)", b"thing")), Some((0, 5)));
    assert_eq!(
        find_window(r"(?:ing|thing|x)", b"thing", SearchWindow::new(1, 5),),
        Some((2, 5))
    );
}

#[test]
fn embedded_literal_trie_preserves_order_around_empty_branches() {
    assert_eq!(tuple(find(r"(?:|a|x)b", b"ab")), Some((0, 2)));
    assert_eq!(tuple(find(r"(?:a||x)b", b"b")), Some((0, 1)));
    assert_eq!(tuple(find(r"(?:a||b|x)b", b"bb")), Some((0, 1)));
    assert_eq!(tuple(find(r"(?:x|a|)b", b"ab")), Some((0, 2)));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture closes every independently reported resource boundary"
)]
fn embedded_literal_trie_reduces_shared_prefix_graphs_with_exact_limits() {
    let parsed = parsed(
        r"(?:customer-created|customer-deleted|customer-updated|order-created|invoice-created)",
        false,
    );
    let HirKind::Alternation(branches) = parsed.hir.kind() else {
        panic!("fixture must remain a direct alternation");
    };
    let literal_bytes = branches
        .iter()
        .map(|branch| match branch.kind() {
            HirKind::Literal(literal) => literal.0.len(),
            other => panic!("fixture branch was not literal: {other:?}"),
        })
        .sum::<usize>();
    let naive_states = literal_bytes + 2;
    let naive_edges = literal_bytes + branches.len();

    let lowered = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("shared-prefix alternation lowers");
    let stats = lowered.stats();
    assert!(stats.states() < naive_states, "{stats:?}");
    assert!(stats.edges() < naive_edges, "{stats:?}");
    let validated = lower(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("shared-prefix alternation validates");
    assert_eq!(validated.stats(), stats);
    let plan_stats = validated.automaton().stats();

    let exact = LowerLimits {
        max_work: stats.work(),
        max_stack_items: stats.peak_stack_items(),
        automata: fre_automata::CompileLimits {
            max_states: stats.states(),
            max_edges: stats.edges(),
            max_storage_bytes: plan_stats.storage_bytes(),
            max_validation_work: plan_stats.validation_work(),
        },
    };
    assert_eq!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, exact)
            .expect("exact literal-trie limits replay")
            .stats(),
        stats
    );
    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                max_work: stats.work() - 1,
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            ..
        })
    ));
    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                automata: fre_automata::CompileLimits {
                    max_states: stats.states() - 1,
                    ..fre_automata::CompileLimits::default()
                },
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::States,
            ..
        })
    ));
    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                automata: fre_automata::CompileLimits {
                    max_edges: stats.edges() - 1,
                    ..fre_automata::CompileLimits::default()
                },
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Edges,
            ..
        })
    ));
    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                max_stack_items: stats.peak_stack_items() - 1,
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StackItems,
            ..
        })
    ));
    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                automata: fre_automata::CompileLimits {
                    max_storage_bytes: plan_stats.storage_bytes() - 1,
                    ..fre_automata::CompileLimits::default()
                },
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StorageBytes,
            ..
        })
    ));
    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                automata: fre_automata::CompileLimits {
                    max_validation_work: plan_stats.validation_work() - 1,
                    ..fre_automata::CompileLimits::default()
                },
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::ValidationWork,
            ..
        })
    ));
}

#[test]
fn embedded_literal_trie_has_the_expected_sparse_graph_shape() {
    let parsed = parsed(r"(?:bar|baz|foo)", false);
    let HirKind::Alternation(branches) = parsed.hir.kind() else {
        panic!("shape fixture must remain a direct alternation");
    };
    assert!(
        branches
            .iter()
            .all(|branch| matches!(branch.kind(), HirKind::Literal(_)))
    );
    let lowered = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("sparse literal trie lowers");
    assert_eq!((lowered.stats().states(), lowered.stats().edges()), (6, 7));
    assert_eq!(
        lowered.plan().roles[usize::try_from(lowered.plan().start).unwrap()],
        fre_automata::StateRole::Consume
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the generated oracle keeps construction and all-window comparisons together"
)]
fn embedded_literal_trie_matches_an_independent_ordered_oracle_in_every_window() {
    fn oracle(
        branches: &[Vec<u8>],
        suffix: &[u8],
        haystack: &[u8],
        window: SearchWindow,
    ) -> Option<(usize, usize)> {
        for start in window.start()..=window.end() {
            for branch in branches {
                let Some(branch_end) = start.checked_add(branch.len()) else {
                    continue;
                };
                let Some(end) = branch_end.checked_add(suffix.len()) else {
                    continue;
                };
                if end > window.end() {
                    continue;
                }
                if haystack.get(start..branch_end) == Some(branch.as_slice())
                    && haystack.get(branch_end..end) == Some(suffix)
                {
                    return Some((start, end));
                }
            }
        }
        None
    }

    let catalog = [
        Vec::new(),
        b"a".to_vec(),
        b"b".to_vec(),
        b"aa".to_vec(),
        b"ab".to_vec(),
    ];
    let haystacks = words(3);
    for first in &catalog {
        for second in &catalog {
            for third in &catalog {
                // The distinct two-byte sentinel prevents regex-syntax's HIR
                // smart constructor from folding this focused alternation into
                // a class or lifting one common prefix out of every branch.
                let branches = vec![first.clone(), second.clone(), third.clone(), b"cc".to_vec()];
                let alternatives = branches
                    .iter()
                    .map(|bytes| {
                        if bytes.is_empty() {
                            Hir::empty()
                        } else {
                            Hir::literal(bytes.clone())
                        }
                    })
                    .collect();
                let alternative = Hir::alternation(alternatives);
                let HirKind::Alternation(actual) = alternative.kind() else {
                    panic!("focused literal alternation was simplified: {alternative:?}");
                };
                assert_eq!(actual.len(), branches.len());
                assert!(
                    actual.iter().all(|branch| matches!(
                        branch.kind(),
                        HirKind::Empty | HirKind::Literal(_)
                    ))
                );
                let hir = Hir::concat(vec![alternative, Hir::literal(*b"c")]);
                let lowered = lower_hir(
                    &hir,
                    OperationSemantics::CaptureFree,
                    LowerLimits::default(),
                )
                .expect("generated literal trie lowers");
                let automaton = lowered.automaton();
                let mut workspace = K0Workspace::new(automaton, WorkspaceLimits::unlimited())
                    .expect("generated literal trie workspace");

                for haystack in &haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let expected = oracle(&branches, b"c", haystack, window);
                            let actual = automaton
                                .prepare::<Span>()
                                .search_window_with_workspace(
                                    haystack,
                                    window,
                                    &mut workspace,
                                    SearchLimits::unlimited(),
                                )
                                .expect("generated Span search")
                                .into_output();
                            assert_eq!(
                                tuple(actual),
                                expected,
                                "branches={branches:?}, haystack={haystack:?}, window={window:?}"
                            );
                            let exists = automaton
                                .prepare::<Exists>()
                                .search_window_with_workspace(
                                    haystack,
                                    window,
                                    &mut workspace,
                                    SearchLimits::unlimited(),
                                )
                                .expect("generated Exists search")
                                .into_output();
                            assert_eq!(
                                exists,
                                expected.is_some(),
                                "branches={branches:?}, haystack={haystack:?}, window={window:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn embedded_literal_trie_handles_binary_unicode_capture_and_long_arms() {
    let binary = Hir::alternation(vec![
        Hir::literal(vec![0x80, b'a']),
        Hir::literal(vec![0x80, b'b']),
        Hir::literal(vec![0xFF]),
        Hir::literal(vec![0x00]),
    ]);
    assert_eq!(find_hir(&binary, &[7, 0x80, b'b']), Some((1, 3)));
    assert_eq!(find_hir(&binary, &[7, 0xFF]), Some((1, 2)));
    assert_eq!(find_hir(&binary, &[7, 0x00]), Some((1, 2)));

    let unicode = Hir::alternation(vec![
        Hir::literal("αx".as_bytes().to_vec()),
        Hir::literal("αy".as_bytes().to_vec()),
        Hir::literal("β".as_bytes().to_vec()),
    ]);
    assert_eq!(
        find_hir(&unicode, "..αy".as_bytes()),
        Some((2, "..αy".len()))
    );

    let captured = parsed(r"((?:foo|foobar|x))q", false);
    assert!(matches!(
        lower_raw(
            &captured,
            OperationSemantics::CaptureSensitive,
            LowerLimits {
                max_work: 0,
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::Unsupported(
            UnsupportedFeature::CaptureSensitiveOperation
        ))
    ));
    assert_eq!(
        lower_raw(
            &captured,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("capture-transparent literal trie lowers")
        .stats()
        .erased_captures(),
        1
    );

    let mut shared = vec![b'a'; 4_096];
    let mut left = shared.clone();
    left.push(b'b');
    shared.push(b'c');
    let long = Hir::alternation(vec![
        Hir::literal(left),
        Hir::literal(shared),
        Hir::literal(*b"z"),
    ]);
    let lowered = lower_hir_raw(
        &long,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("long literal trie lowers without recursive traversal");
    assert!(lowered.stats().states() < 4_110);
}

#[test]
fn embedded_literal_trie_declines_before_exceeding_its_scratch_cap() {
    // This exceeds the logical 8 MiB scratch payload even on 32-bit targets,
    // while the ordinary graph remains below the default state limit.
    const ARM_BYTES: usize = 90_000;
    let hir = Hir::alternation(vec![
        Hir::literal(vec![b'a'; ARM_BYTES]),
        Hir::literal(vec![b'b'; ARM_BYTES]),
    ]);
    let HirKind::Alternation(branches) = hir.kind() else {
        panic!("scratch-cap fixture must remain a direct alternation");
    };
    assert_eq!(branches.len(), 2);

    let lowered = lower_hir_raw(
        &hir,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("oversized optional trie falls back to ordinary lowering");
    let ordinary_dimension = ARM_BYTES * 2 + 2;
    assert_eq!(lowered.stats().states(), ordinary_dimension);
    assert_eq!(lowered.stats().edges(), ordinary_dimension);
}

#[test]
fn embedded_literal_trie_declines_before_optional_search_exhausts_work() {
    const DUPLICATES: usize = 50_000;
    let mut branches = Vec::with_capacity(1 + 256 + DUPLICATES);
    branches.push(Hir::empty());
    branches.extend((u8::MIN..=u8::MAX).map(|byte| Hir::literal(vec![byte])));
    branches.extend((0..DUPLICATES).map(|_| Hir::literal(vec![u8::MAX])));
    let hir = Hir::alternation(branches);
    let HirKind::Alternation(branches) = hir.kind() else {
        panic!("work-authority fixture must remain a direct alternation");
    };
    assert_eq!(branches.len(), 1 + 256 + DUPLICATES);

    let lowered = lower_hir_raw(
        &hir,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("expensive optional trie search declines to ordinary lowering");
    let ordinary_states = branches.len() + 2;
    let ordinary_edges = branches.len() * 2;
    assert_eq!(lowered.stats().states(), ordinary_states);
    assert_eq!(lowered.stats().edges(), ordinary_edges);
}

#[test]
fn embedded_literal_trie_skewed_fanout_replays_its_reported_work_exactly() {
    const ARMS: u8 = 100;
    const TAIL_BYTES: usize = 500;
    let branches = (0..ARMS)
        .map(|first| {
            let mut literal = Vec::with_capacity(TAIL_BYTES + 1);
            literal.push(first);
            literal.extend(std::iter::repeat_n(b'a', TAIL_BYTES));
            Hir::literal(literal)
        })
        .collect();
    let hir = Hir::alternation(branches);
    let HirKind::Alternation(actual) = hir.kind() else {
        panic!("skewed-fanout fixture must remain a direct alternation");
    };
    assert_eq!(actual.len(), usize::from(ARMS));

    let probe = lower_hir_raw(
        &hir,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("skewed-fanout trie lowers");
    assert_eq!(probe.stats().states(), 50_002);
    let replay = lower_hir_raw(
        &hir,
        OperationSemantics::CaptureFree,
        LowerLimits {
            max_work: probe.stats().work(),
            ..LowerLimits::default()
        },
    )
    .expect("reported trie work is an exact replay authority");
    assert_eq!(replay.stats(), probe.stats());
}

#[test]
fn embedded_literal_trie_reuses_wide_active_chains_without_crossing_a_barrier() {
    let mut branches = (u8::MIN..=u8::MAX)
        .map(|byte| Hir::literal(vec![byte, b'x']))
        .collect::<Vec<_>>();
    branches.extend([
        Hir::literal(vec![0, b'y']),
        Hir::literal(vec![127, b'y']),
        Hir::literal(vec![255, b'y']),
        Hir::empty(),
        Hir::literal(vec![0, b'z']),
        Hir::literal(vec![127, b'z']),
        Hir::literal(vec![255, b'z']),
    ]);
    let alternative = Hir::alternation(branches);
    let HirKind::Alternation(actual) = alternative.kind() else {
        panic!("wide-chain fixture must remain a direct alternation");
    };
    assert_eq!(actual.len(), 263);
    let hir = Hir::concat(vec![alternative, Hir::literal(*b"q")]);

    for haystack in [
        [0, b'x', b'q'],
        [0, b'y', b'q'],
        [127, b'y', b'q'],
        [255, b'y', b'q'],
        [0, b'z', b'q'],
        [127, b'z', b'q'],
        [255, b'z', b'q'],
    ] {
        assert_eq!(find_hir(&hir, &haystack), Some((0, 3)), "{haystack:?}");
    }
}

#[test]
fn empty_arm_literal_tries_are_sound_inside_general_nullable_repetitions() {
    fn contains_literal_trie(hir: &Hir) -> bool {
        if let HirKind::Alternation(branches) = hir.kind()
            && branches.len() > 1
            && branches
                .iter()
                .all(|branch| matches!(branch.kind(), HirKind::Empty | HirKind::Literal(_)))
        {
            return true;
        }
        match hir.kind() {
            HirKind::Capture(capture) => contains_literal_trie(&capture.sub),
            HirKind::Repetition(repetition) => contains_literal_trie(&repetition.sub),
            HirKind::Concat(parts) | HirKind::Alternation(parts) => {
                parts.iter().any(contains_literal_trie)
            }
            HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => false,
        }
    }

    const PATTERNS: &[&str] = &[
        r"(?:(?:|a|x))*?b",
        r"(?:(?:a||b|x))+c",
        r"(?:(?:|ab|x)){0,3}?c",
    ];
    let haystacks = words(5);
    for pattern in PATTERNS {
        let parsed = parsed(pattern, false);
        assert!(
            contains_literal_trie(&parsed.hir),
            "fixture no longer reaches literal-trie lowering: {pattern:?}"
        );
        let fre = lower_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("general lowering failed for {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        let automaton = fre.automaton();
        let mut workspace = K0Workspace::new(automaton, WorkspaceLimits::unlimited())
            .expect("general nullable literal-trie workspace");
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = upstream.find(&haystack[start..end]).map(|matched| {
                        (start + matched.start(), start + matched.end())
                    });
                    let actual = automaton
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut workspace,
                            SearchLimits::unlimited(),
                        )
                        .expect("general nullable literal-trie Span search")
                        .into_output();
                    assert_eq!(
                        tuple(actual),
                        expected,
                        "pattern={pattern:?}, haystack={haystack:?}, window={window:?}"
                    );
                    let exists = automaton
                        .prepare::<Exists>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut workspace,
                            SearchLimits::unlimited(),
                        )
                        .expect("general nullable literal-trie Exists search")
                        .into_output();
                    assert_eq!(
                        exists,
                        expected.is_some(),
                        "pattern={pattern:?}, haystack={haystack:?}, window={window:?}"
                    );
                }
            }
        }
    }
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
fn compressed_unicode_classes_match_upstream_across_ranges_and_malformed_bytes() {
    const PATTERNS: &[&str] = &[
        r"\w",
        r"\w{2,4}\s+\p{Greek}+",
        r"[\u{7F}-\u{800}]{1,3}",
        r"[\u{D7FF}\u{E000}-\u{10FFFF}]+",
        r"[^\p{ASCII}]{1,2}",
        r"(?:\pL|[0-9_])+\s+\p{Greek}{2}",
    ];
    let malformed = [
        0xFF, b'a', 0x80, 0xC0, 0x80, b' ', 0xED, 0xA0, 0x80, b'_', 0xF4, 0x90, 0x80, 0x80,
    ];
    let truncated = [0x7F, 0xC2, b' ', 0xE0, 0xA0, b' ', 0xF0, 0x90, 0x80];
    let mut scalar_boundaries = Vec::new();
    for scalar in [
        '\0',
        '\u{7F}',
        '\u{80}',
        '\u{7FF}',
        '\u{800}',
        '\u{D7FF}',
        '\u{E000}',
        '\u{FFFF}',
        '\u{10000}',
        '\u{10FFFF}',
    ] {
        let mut encoded = [0_u8; 4];
        scalar_boundaries.extend_from_slice(scalar.encode_utf8(&mut encoded).as_bytes());
        scalar_boundaries.push(b' ');
    }
    let haystacks = [
        b"".as_slice(),
        b"ASCII words_123 and spaces".as_slice(),
        "αβ γδε ЖЮ 東京 😀".as_bytes(),
        malformed.as_slice(),
        truncated.as_slice(),
        scalar_boundaries.as_slice(),
    ];

    for pattern in PATTERNS {
        let parsed = parsed(pattern, true);
        let fre = lower(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("failed to lower {pattern:?}: {error}"));
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(true)
            .build()
            .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"));
        for haystack in haystacks {
            let actual = fre
                .automaton()
                .prepare::<Span>()
                .search(haystack, SearchLimits::unlimited())
                .unwrap_or_else(|error| {
                    panic!("FRE search failed for {pattern:?}/{haystack:?}: {error}")
                })
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

#[test]
fn repeated_unicode_word_classes_fit_the_k0_lazy_dfa_envelope() {
    const PATTERN: &str = r"\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}\s+\w{5}";
    const K0_LAZY_GRAPH_STATE_LIMIT: usize = 16_384;

    let parsed = parsed(PATTERN, true);
    let lowered = lower(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("repeated Unicode classes lower");
    let stats = lowered.stats();
    assert_eq!((stats.states(), stats.edges()), (11_115, 45_789));
    assert!(stats.states() < K0_LAZY_GRAPH_STATE_LIMIT);
    assert!(
        lowered
            .automaton()
            .accelerated_workspace_layout()
            .unwrap()
            .logical_bytes()
            > lowered
                .automaton()
                .workspace_layout()
                .unwrap()
                .logical_bytes()
    );
    let automaton = lowered.automaton();
    let mut accelerated = K0Workspace::new_accelerated(automaton, WorkspaceLimits::unlimited())
        .expect("compressed graph admits accelerated K0 workspace");
    let found = automaton
        .prepare::<Exists>()
        .search_with_workspace(
            b"alpha bravo charl delta eagle foxtt gamma",
            &mut accelerated,
            SearchLimits::unlimited(),
        )
        .expect("accelerated K0 search succeeds")
        .into_output();
    assert!(found);

    let exact = LowerLimits {
        max_work: stats.work(),
        automata: fre_automata::CompileLimits {
            max_states: stats.states(),
            max_edges: stats.edges(),
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    let replay = lower_raw(&parsed, OperationSemantics::CaptureFree, exact)
        .expect("exact Unicode DAG limits replay");
    assert_eq!(replay.stats(), stats);

    let one_work_short = LowerLimits {
        max_work: stats.work() - 1,
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, one_work_short),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            ..
        })
    ));
    let one_state_short = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_states: stats.states() - 1,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, one_state_short),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::States,
            ..
        })
    ));
    let one_edge_short = LowerLimits {
        automata: fre_automata::CompileLimits {
            max_edges: stats.edges() - 1,
            ..fre_automata::CompileLimits::default()
        },
        ..LowerLimits::default()
    };
    assert!(matches!(
        lower_raw(&parsed, OperationSemantics::CaptureFree, one_edge_short),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Edges,
            ..
        })
    ));
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
fn flat_ascii_look_alternation_uses_the_complete_truth_lattice() {
    let cases = [
        (r"(?-u:\b|\B)", EdgeKind::Epsilon),
        (r"(?-u:\B|\b)", EdgeKind::Epsilon),
        (r"(?-u:(\b)|(\B))", EdgeKind::Epsilon),
        (r"(?-u:\b{start}|\b{end})", EdgeKind::AssertWordAscii),
        (
            r"(?-u:\b{start}|\b{start-half})",
            EdgeKind::AssertWordStartHalfAscii,
        ),
    ];
    for (pattern, expected) in cases {
        let parsed = parsed(pattern, false);
        let lowered = lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("failed to lower {pattern:?}: {error}"));
        assert_eq!(lowered.plan().edge_kinds.as_slice(), &[expected], "{pattern:?}");
        assert_eq!(lowered.stats().states(), 2, "{pattern:?}");
        assert_eq!(lowered.stats().edges(), 1, "{pattern:?}");
    }

    let malformed = [0xFF, 0x80, b'a'];
    for at in 0..=malformed.len() {
        assert_eq!(
            find_window(
                r"(?-u:\b|\B)",
                &malformed,
                SearchWindow::new(at, at),
            ),
            Some((at, at)),
            "at={at}"
        );
    }
}

#[test]
fn flat_ascii_look_alternation_is_removed_inside_consuming_loops() {
    let pattern = r"(?:(?-u:\b|\B)[ab])+z";
    let parsed = parsed(pattern, false);
    let lowered = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("embedded exhaustive ASCII look lowers");
    assert!(lowered.plan().edge_kinds.iter().all(|kind| !matches!(
        kind,
        EdgeKind::AssertWordAscii | EdgeKind::AssertWordAsciiNegate
    )));
    assert_eq!(tuple(find(pattern, &[0xFF, b'a', b'a', b'b', b'z'])), Some((1, 5)));

    let general = lower_general(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("general lowering accepts the same embedded proof");
    assert_eq!(
        tuple(
            general
                .automaton()
                .prepare::<Span>()
                .search(
                    &[0xFF, b'a', b'a', b'b', b'z'],
                    SearchLimits::unlimited(),
                )
                .expect("general embedded search succeeds")
                .into_output(),
        ),
        Some((1, 5))
    );
}

#[test]
fn unicode_exhaustive_look_alternation_is_not_erased_on_byte_boundaries() {
    let parsed = parsed(r"\b|\B", true);
    let lowered = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("Unicode look alternation lowers");
    assert!(
        lowered
            .plan()
            .edge_kinds
            .contains(&EdgeKind::AssertWordUnicode)
    );
    assert!(
        lowered
            .plan()
            .edge_kinds
            .contains(&EdgeKind::AssertWordUnicodeNegate)
    );

    let automaton = lower(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("Unicode look alternation validates");
    assert_eq!(
        automaton
            .automaton()
            .prepare::<Span>()
            .search(&[0x80], SearchLimits::unlimited())
            .expect("malformed-byte search succeeds")
            .into_output(),
        None
    );
    let alpha = "α".as_bytes();
    assert_eq!(
        automaton
            .automaton()
            .prepare::<Span>()
            .search_window(
                alpha,
                SearchWindow::new(1, 1),
                SearchLimits::unlimited(),
            )
            .expect("continuation-boundary search succeeds")
            .into_output(),
        None
    );
}

#[test]
fn flat_ascii_reduction_preserves_the_synthesized_utf8_start_guard() {
    let parsed = parsed(r"(?-u:\b|\B)", true);
    let guarded = lower_utf8_start_guarded(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("guarded exhaustive ASCII look lowers");
    assert_eq!(guarded.stats().states(), 5);
    assert_eq!(guarded.stats().edges(), 5);

    let alpha = "α".as_bytes();
    assert_eq!(
        guarded
            .automaton()
            .prepare::<Span>()
            .search_window(
                alpha,
                SearchWindow::new(1, 1),
                SearchLimits::unlimited(),
            )
            .expect("guarded continuation-boundary search succeeds")
            .into_output(),
        None
    );
}

#[test]
fn flat_ascii_look_alternation_has_exact_resource_boundaries() {
    let parsed = parsed(r"(?-u:(\b)|(\B))", false);
    let lowered = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("capture-transparent assertion proof lowers");
    let exact_work = lowered.stats().work();

    let exact = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits {
            max_work: exact_work,
            ..LowerLimits::default()
        },
    )
    .expect("exact assertion-algebra work limit passes");
    assert_eq!(exact.stats().work(), exact_work);
    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                max_work: exact_work - 1,
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            needed,
            limit,
        }) if needed == exact_work && limit == exact_work - 1
    ));

    for automata in [
        fre_automata::CompileLimits {
            max_states: 1,
            ..fre_automata::CompileLimits::default()
        },
        fre_automata::CompileLimits {
            max_edges: 0,
            ..fre_automata::CompileLimits::default()
        },
    ] {
        assert!(matches!(
            lower_raw(
                &parsed,
                OperationSemantics::CaptureFree,
                LowerLimits {
                    automata,
                    ..LowerLimits::default()
                },
            ),
            Err(LowerError::ResourceLimit { .. })
        ));
    }
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

    for pattern in ["(?:a*?)*?", "(?:a?){3,}?", "(?:a*){2,}?", "(?:b|a*)*"] {
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
fn general_nullable_repetition_lowering_needs_no_source_recipe() {
    let patterns = [
        "(?:a*?)*?",
        "(?:a?){3,}?",
        "(?:a*){2,}?",
        "(?:b|a*)*",
        "(?:a??|aa)*?",
        "(?:a*?|b)*?",
        "(?:(?:a?)|(?:b?))+",
        "(?:(?:a*?)|(?:b))*?c",
    ];
    let haystacks = words(4);
    for pattern in patterns {
        let parsed = parsed(pattern, false);
        let lowered = lower_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("general lowering rejected {pattern:?}: {error}"));
        assert_eq!(lowered.stats().normalized_nullable_repetitions(), 0);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let actual = lowered
                        .automaton()
                        .prepare::<Span>()
                        .search_window(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let expected = oracle
                        .find_at(&haystack[..end], start)
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(
                        tuple(actual),
                        expected,
                        "pattern={pattern:?}, haystack={haystack:?}, window={start}..{end}"
                    );
                }
            }
        }
    }
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
fn ordered_consuming_empty_repetitions_match_pinned_upstream_at_every_start() {
    let patterns = [
        r"(?:a|)*",
        r"(?:a|)+",
        r"(?:a|)*b",
        r"(?:[ab]|)+c?",
        r"(?:(a)|)*b",
    ];
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
fn ordered_consuming_empty_repetition_proof_and_resources_remain_exact() {
    for pattern in [
        r"(?:a|)*?",
        r"(?:a|){2,}",
        r"(?:ab|)*b",
        r"(?:a+|)*",
        r"(?:a|b|)*",
        r"(?:a|a?)*",
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

    let parsed = parsed(r"(?:[ab]|)+", false);
    let exact = lower_raw(
        &parsed,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("certified consuming-empty repetition lowers");
    let stats = exact.stats();
    let exact_work = stats.work();
    let exact_storage = (stats.states() + 1) * core::mem::size_of::<u32>()
        + stats.states() * core::mem::size_of::<fre_automata::StateRole>()
        + stats.edges()
            * (core::mem::size_of::<u32>()
                + core::mem::size_of::<EdgeKind>()
                + 2 * core::mem::size_of::<u8>())
        + fre_automata::Automaton::BYTE_CLASS_MAP_RETAINED_BYTES;
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

    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                max_work: exact_work - 1,
                ..LowerLimits::default()
            }
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            needed,
            limit,
        }) if needed > limit && limit == exact_work - 1
    ));

    assert!(matches!(
        lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits {
                automata: fre_automata::CompileLimits {
                    max_storage_bytes: exact_storage - 1,
                    ..fre_automata::CompileLimits::default()
                },
                ..LowerLimits::default()
            }
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StorageBytes,
            needed,
            limit,
        }) if needed == exact_storage_u64 && limit == exact_storage_u64 - 1
    ));
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
                + 2 * core::mem::size_of::<u8>())
        + fre_automata::Automaton::BYTE_CLASS_MAP_RETAINED_BYTES;
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
                + 2 * core::mem::size_of::<u8>())
        + fre_automata::Automaton::BYTE_CLASS_MAP_RETAINED_BYTES;
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
fn borrowed_concat_slice_lowering_matches_owned_hir_and_censuses_captures() {
    let parsed = parsed(r"(ab)(?:c|de)(f+)", false);
    let HirKind::Concat(parts) = parsed.hir.kind() else {
        panic!("focused borrowed-concat fixture must retain a concat root");
    };
    let borrowed = lower_hir_concat_slice(
        parts,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("borrowed concat slice lowers");
    let owned_hir = Hir::concat(parts.to_vec());
    let owned = lower_hir(
        &owned_hir,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("equivalent owned concat lowers");

    assert_eq!(borrowed.stats().erased_captures(), 2);
    assert_eq!(
        borrowed.stats().erased_captures(),
        owned.stats().erased_captures(),
    );
    assert_eq!(borrowed.stats().states(), owned.stats().states());
    assert_eq!(borrowed.stats().edges(), owned.stats().edges());
    assert_eq!(borrowed.automaton().stats(), owned.automaton().stats());
    for haystack in [
        &b"abcf"[..],
        &b"xxabdeffffyy"[..],
        &b"abdf"[..],
        &b""[..],
    ] {
        let borrowed_output = borrowed
            .automaton()
            .prepare::<Span>()
            .search(haystack, SearchLimits::unlimited())
            .expect("borrowed concat search succeeds")
            .into_output();
        let owned_output = owned
            .automaton()
            .prepare::<Span>()
            .search(haystack, SearchLimits::unlimited())
            .expect("owned concat search succeeds")
            .into_output();
        assert_eq!(borrowed_output, owned_output, "haystack={haystack:?}");
    }

    assert!(matches!(
        lower_hir_concat_slice(
            parts,
            OperationSemantics::CaptureSensitive,
            LowerLimits::default(),
        ),
        Err(LowerError::Unsupported(
            UnsupportedFeature::CaptureSensitiveOperation
        ))
    ));
}

#[test]
fn borrowed_concat_slice_lowering_closes_every_reported_resource_axis() {
    let parsed = parsed(r"(ab)(?:c|de)(f+)", false);
    let HirKind::Concat(parts) = parsed.hir.kind() else {
        panic!("focused borrowed-concat fixture must retain a concat root");
    };
    let baseline = lower_hir_concat_slice(
        parts,
        OperationSemantics::CaptureFree,
        LowerLimits::default(),
    )
    .expect("borrowed concat baseline lowers");
    let stats = baseline.stats();
    let plan_stats = baseline.automaton().stats();
    let exact = LowerLimits {
        max_work: stats.work(),
        max_stack_items: stats.peak_stack_items(),
        automata: fre_automata::CompileLimits {
            max_states: stats.states(),
            max_edges: stats.edges(),
            max_storage_bytes: plan_stats.storage_bytes(),
            max_validation_work: plan_stats.validation_work(),
        },
    };
    assert_eq!(
        lower_hir_concat_slice(parts, OperationSemantics::CaptureFree, exact)
            .expect("exact borrowed-concat limits replay")
            .stats(),
        stats,
    );

    let work_limit = stats.work().checked_sub(1).unwrap();
    assert!(matches!(
        lower_hir_concat_slice(
            parts,
            OperationSemantics::CaptureFree,
            LowerLimits {
                max_work: work_limit,
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Work,
            needed,
            limit,
        }) if needed > limit && limit == work_limit
    ));

    let stack_limit = stats.peak_stack_items().checked_sub(1).unwrap();
    assert!(matches!(
        lower_hir_concat_slice(
            parts,
            OperationSemantics::CaptureFree,
            LowerLimits {
                max_stack_items: stack_limit,
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StackItems,
            needed,
            limit,
        }) if needed > limit
            && limit == u64::try_from(stack_limit).expect("small stack limit")
    ));

    let state_limit = stats.states().checked_sub(1).unwrap();
    assert!(matches!(
        lower_hir_concat_slice(
            parts,
            OperationSemantics::CaptureFree,
            LowerLimits {
                automata: fre_automata::CompileLimits {
                    max_states: state_limit,
                    ..fre_automata::CompileLimits::default()
                },
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::States,
            needed,
            limit,
        }) if needed > limit
            && limit == u64::try_from(state_limit).expect("small state limit")
    ));

    let edge_limit = stats.edges().checked_sub(1).unwrap();
    assert!(matches!(
        lower_hir_concat_slice(
            parts,
            OperationSemantics::CaptureFree,
            LowerLimits {
                automata: fre_automata::CompileLimits {
                    max_edges: edge_limit,
                    ..fre_automata::CompileLimits::default()
                },
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::Edges,
            needed,
            limit,
        }) if needed > limit
            && limit == u64::try_from(edge_limit).expect("small edge limit")
    ));

    let storage_limit = plan_stats.storage_bytes().checked_sub(1).unwrap();
    assert!(matches!(
        lower_hir_concat_slice(
            parts,
            OperationSemantics::CaptureFree,
            LowerLimits {
                automata: fre_automata::CompileLimits {
                    max_storage_bytes: storage_limit,
                    ..fre_automata::CompileLimits::default()
                },
                ..LowerLimits::default()
            },
        ),
        Err(LowerError::ResourceLimit {
            resource: LowerResource::StorageBytes,
            needed,
            limit,
        }) if needed > limit
            && limit == u64::try_from(storage_limit).expect("small storage limit")
    ));
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
