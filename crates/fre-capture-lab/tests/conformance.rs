#![allow(
    clippy::arithmetic_side_effects,
    reason = "small deterministic test-domain enumeration uses proven tiny integers"
)]

use std::fmt::Write as _;
use std::sync::Arc;

use fre_capture_lab::{
    AggregateLimits, Assertion, Ast, BuildError, BuildLimits, CandidateKind, CaptureGroupSlot,
    CaptureProfile, CaptureRecord, Greed, GroupRecord, HISTORY_EXACT_WORKSPACE_ACCOUNTING_VERSION,
    HISTORY_EXACT_WORKSPACE_ALGORITHM_VERSION, HistoryRegex, InlineRegex, MaskedInclusiveRange,
    MatchKind as CaptureMatchKind, PARTICIPATION_QUOTIENT_CAPTURE_BITS, Program, ResourceKind,
    SearchConfig, SearchError, SearchLimits, Span, Window,
};
use regex::bytes::Regex;
use regex_automata::{Anchored, Input, MatchKind, meta, util::syntax};

fn bounded_reference_with_match_kind(pattern: &str, match_kind: MatchKind) -> meta::Regex {
    meta::Regex::builder()
        .configure(
            meta::Regex::config()
                .match_kind(match_kind)
                .utf8_empty(false),
        )
        .syntax(syntax::Config::default().utf8(false))
        .build(pattern)
        .unwrap()
}

fn pair(ast: &Ast) -> (InlineRegex, HistoryRegex) {
    let program = Arc::new(Program::compile(ast, BuildLimits::default()).unwrap());
    (
        InlineRegex::from_program(Arc::clone(&program)),
        HistoryRegex::from_program(program),
    )
}

fn reference(pattern: &str, haystack: &[u8], window: Window) -> Option<CaptureRecord> {
    reference_with_match_kind(pattern, haystack, window, MatchKind::LeftmostFirst, false)
}

fn reference_with_match_kind(
    pattern: &str,
    haystack: &[u8],
    window: Window,
    match_kind: MatchKind,
    anchored: bool,
) -> Option<CaptureRecord> {
    let names = Regex::new(pattern)
        .unwrap()
        .capture_names()
        .map(|name| name.map(str::to_owned))
        .collect::<Vec<_>>();
    let re = bounded_reference_with_match_kind(pattern, match_kind);
    let mut captures = re.create_captures();
    let anchored = if anchored {
        Anchored::Yes
    } else {
        Anchored::No
    };
    re.captures(
        Input::new(haystack)
            .span(window.start..window.end)
            .anchored(anchored),
        &mut captures,
    );
    captures.is_match().then(|| {
        assert_eq!(names.len(), captures.group_len());
        let groups = names
            .into_iter()
            .enumerate()
            .map(|(index, name)| GroupRecord {
                index: u32::try_from(index).unwrap(),
                name,
                span: captures.get_group(index).map(|matched| Span {
                    start: matched.start,
                    end: matched.end,
                }),
            })
            .collect();
        CaptureRecord { groups }
    })
}

fn reference_iter(pattern: &str, haystack: &[u8], window: Window) -> Vec<CaptureRecord> {
    reference_iter_with_match_kind(pattern, haystack, window, MatchKind::LeftmostFirst, false)
}

fn reference_iter_with_match_kind(
    pattern: &str,
    haystack: &[u8],
    window: Window,
    match_kind: MatchKind,
    anchored: bool,
) -> Vec<CaptureRecord> {
    let names = Regex::new(pattern)
        .unwrap()
        .capture_names()
        .map(|name| name.map(str::to_owned))
        .collect::<Vec<_>>();
    let re = bounded_reference_with_match_kind(pattern, match_kind);
    let anchored = if anchored {
        Anchored::Yes
    } else {
        Anchored::No
    };
    re.captures_iter(
        Input::new(haystack)
            .span(window.start..window.end)
            .anchored(anchored),
    )
    .map(|captures| CaptureRecord {
        groups: names
            .iter()
            .enumerate()
            .map(|(index, name)| GroupRecord {
                index: u32::try_from(index).unwrap(),
                name: name.clone(),
                span: captures.get_group(index).map(|matched| Span {
                    start: matched.start,
                    end: matched.end,
                }),
            })
            .collect(),
    })
    .collect()
}

fn assert_case(ast: &Ast, haystack: &[u8], window: Window) {
    let pattern = render(ast);
    let expected = reference(&pattern, haystack, window);
    let (inline, history) = pair(ast);
    let inline_got = inline
        .captures(haystack, window, SearchLimits::default())
        .unwrap();
    let history_got = history
        .captures(haystack, window, SearchLimits::default())
        .unwrap();
    assert_eq!(
        expected, inline_got.captures,
        "inline mismatch: pattern={pattern:?}, haystack={haystack:?}, window={window:?}"
    );
    assert_eq!(
        expected, history_got.captures,
        "history mismatch: pattern={pattern:?}, haystack={haystack:?}, window={window:?}"
    );
    if history_got.report.candidate == CandidateKind::BoundedBacktracker {
        let prospective = history
            .bounded_backtrack_prospective(window, window.start, SearchConfig::LEFTMOST)
            .unwrap()
            .expect("bounded report requires a bounded prospective");
        assert!(prospective.closes_report(&history_got.report));
    }
    assert!(
        inline_got.report.state_visits
            <= 4 * inline.program().state_len() * (window.end - window.start + 1)
    );
    assert!(
        history_got.report.state_visits
            <= 4 * history.program().state_len() * (window.end - window.start + 1)
    );
}

#[test]
fn bounded_backtracker_is_source_independent_and_restores_captures() {
    let ast = Ast::alt([
        Ast::concat([Ast::Byte(b'a').capture(1), Ast::Byte(b'!')]),
        Ast::Byte(b'a').capture(2),
    ]);
    let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
    let window = Window::all(b"za");
    let prospective = regex
        .bounded_backtrack_prospective(window, 0, SearchConfig::LEFTMOST)
        .unwrap()
        .expect("short leftmost search is eligible");
    let outcome = regex
        .captures(b"za", window, SearchLimits::default())
        .unwrap();
    assert_eq!(outcome.report.candidate, CandidateKind::BoundedBacktracker);
    assert!(prospective.closes_report(&outcome.report));
    assert_eq!(outcome.captures, reference("(?:(a)!)|(a)", b"za", window));
    let captures = outcome.captures.unwrap();
    assert_eq!(captures.groups[1].span, None);
    assert_eq!(captures.groups[2].span, Some(Span { start: 1, end: 2 }));

    let exact_scratch = SearchLimits {
        max_scratch_bytes: prospective.scratch_bytes,
        ..SearchLimits::default()
    };
    assert_eq!(
        regex
            .captures(b"za", window, exact_scratch)
            .unwrap()
            .report
            .candidate,
        CandidateKind::BoundedBacktracker
    );
    let canonical_scratch = regex
        .search_prospective(window, window.start)
        .unwrap()
        .scratch_bytes;
    if canonical_scratch < prospective.scratch_bytes {
        let one_below_scratch = SearchLimits {
            max_scratch_bytes: prospective.scratch_bytes - 1,
            ..SearchLimits::default()
        };
        assert_ne!(
            regex
                .captures(b"za", window, one_below_scratch)
                .unwrap()
                .report
                .candidate,
            CandidateKind::BoundedBacktracker
        );
    }

    let anchored = SearchConfig::LEFTMOST.anchored(true);
    let anchored_outcome = regex
        .captures_with_config(b"za", window, anchored, SearchLimits::default())
        .unwrap();
    assert_eq!(
        anchored_outcome.report.candidate,
        CandidateKind::BoundedBacktracker
    );
    assert!(anchored_outcome.captures.is_none());
    assert_eq!(anchored_outcome.report.starts_injected, 1);

    let force_canonical = SearchLimits {
        max_slot_copies: 0,
        ..SearchLimits::default()
    };
    let canonical = regex.captures(b"za", window, force_canonical).unwrap();
    assert_eq!(canonical.report.candidate, CandidateKind::PersistentHistory);
    assert_eq!(canonical.captures, reference("(?:(a)!)|(a)", b"za", window));

    let long = vec![b'!'; 257];
    let long_window = Window::all(&long);
    let long_bounded = regex
        .bounded_backtrack_prospective(long_window, 0, SearchConfig::LEFTMOST)
        .unwrap()
        .expect("window size is governed by structural admission");
    let force_structural_fallback = SearchLimits {
        max_slot_copies: long_bounded.slot_copies - 1,
        ..SearchLimits::default()
    };
    assert_eq!(
        regex
            .captures(&long, long_window, force_structural_fallback)
            .unwrap()
            .report
            .candidate,
        CandidateKind::PersistentHistory
    );
    assert_eq!(
        regex
            .captures_with_config(
                b"za",
                window,
                SearchConfig::EARLIEST,
                SearchLimits::default()
            )
            .unwrap()
            .report
            .candidate,
        CandidateKind::PersistentHistory
    );
}

#[test]
fn bounded_backtracker_shape_counts_only_real_save_and_frame_states() {
    let sparse =
        HistoryRegex::compile(&Ast::Byte(b'a').capture(4), BuildLimits::default()).unwrap();
    let shape = sparse.program_shape();
    assert_eq!(shape.slots, 10);
    assert_eq!(shape.save_states, 4);

    let prospective = sparse
        .bounded_backtrack_prospective(Window::all(b"a"), 0, SearchConfig::LEFTMOST)
        .unwrap()
        .unwrap();
    let outcome = sparse
        .captures(b"a", Window::all(b"a"), SearchLimits::default())
        .unwrap();
    assert_eq!(outcome.report.candidate, CandidateKind::BoundedBacktracker);
    assert!(prospective.closes_report(&outcome.report));
}

#[test]
fn start_prefilter_proof_is_structural_bounded_and_metered() {
    let long = 128;
    let cases = [
        (
            Ast::concat([
                Ast::Byte(b'a').repeat(0, Some(1), Greed::Greedy),
                Ast::Byte(b'b'),
            ]),
            true,
        ),
        (Ast::alt([Ast::Byte(b'a'), Ast::Byte(b'c')]), true),
        (Ast::Byte(b'a').repeat(0, Some(0), Greed::Greedy), false),
        (Ast::Class(Vec::new()), false),
        (
            Ast::concat([
                Ast::Assert(Assertion::WordAscii),
                Ast::Class(vec![(b'x', b'z')]).capture(1),
            ]),
            true,
        ),
    ];
    for (ast, scanner_expected) in cases {
        let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
        let haystack = vec![b'q'; long];
        let outcome = regex
            .captures(&haystack, Window::all(&haystack), SearchLimits::default())
            .unwrap();
        if scanner_expected {
            assert_eq!(outcome.report.starts_injected, 0, "ast={ast:?}");
            assert!(outcome.report.bytes_examined >= long, "ast={ast:?}");
        }
    }

    let ast = Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]);
    let exact = Program::compile(&ast, BuildLimits::default()).unwrap();
    let report = exact.build_report().clone();
    assert_eq!(
        Program::compile(
            &ast,
            BuildLimits {
                max_compile_work: report.compile_work,
                max_program_bytes: report.program_bytes,
                ..BuildLimits::default()
            },
        )
        .unwrap()
        .build_report(),
        &report
    );
    assert!(matches!(
        Program::compile(
            &ast,
            BuildLimits {
                max_compile_work: report.compile_work - 1,
                ..BuildLimits::default()
            },
        ),
        Err(BuildError::Resource {
            kind: ResourceKind::CompileWork,
            ..
        })
    ));
    assert!(matches!(
        Program::compile(
            &ast,
            BuildLimits {
                max_program_bytes: report.program_bytes - 1,
                ..BuildLimits::default()
            },
        ),
        Err(BuildError::Resource {
            kind: ResourceKind::ProgramBytes,
            ..
        })
    ));

    let wide = Ast::Class(vec![(0, u8::MAX)]);
    let wide_report = Program::compile(&wide, BuildLimits::default())
        .unwrap()
        .build_report()
        .clone();
    assert!(wide_report.compile_work < 64);
    assert!(matches!(
        Program::compile(
            &wide,
            BuildLimits {
                max_compile_work: wide_report.compile_work - 1,
                ..BuildLimits::default()
            },
        ),
        Err(BuildError::Resource {
            kind: ResourceKind::CompileWork,
            ..
        })
    ));
}

#[test]
fn start_byte_prefilter_routes_close_the_legacy_receipt() {
    let long = 128;
    for ast in [
        Ast::Byte(b'a'),
        Ast::alt([Ast::Byte(b'a'), Ast::Byte(b'b')]),
        Ast::Class(vec![(b'a', b'c')]),
    ] {
        let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
        let haystack = vec![b'x'; long];
        let window = Window::all(&haystack);
        let prospective = regex
            .bounded_backtrack_prospective(window, 0, SearchConfig::LEFTMOST)
            .unwrap()
            .unwrap();
        let outcome = regex
            .captures(&haystack, window, SearchLimits::default())
            .unwrap();
        assert_eq!(outcome.report.candidate, CandidateKind::BoundedBacktracker);
        assert_eq!(outcome.report.starts_injected, 0);
        assert!(outcome.report.bytes_examined >= long);
        assert!(prospective.closes_report(&outcome.report));
    }

    for (ast, haystack, config, expected_starts) in [
        (
            Ast::alt([
                Ast::Byte(b'a'),
                Ast::Byte(b'b'),
                Ast::Byte(b'c'),
                Ast::Byte(b'd'),
            ]),
            vec![b'x'; long],
            SearchConfig::LEFTMOST,
            long + 1,
        ),
        (
            Ast::Byte(b'a').repeat(0, Some(1), Greed::Greedy),
            vec![b'x'; long],
            SearchConfig::LEFTMOST,
            1,
        ),
        (Ast::Byte(b'a'), vec![b'x'; 63], SearchConfig::LEFTMOST, 64),
        (
            Ast::Byte(b'a'),
            vec![b'x'; long],
            SearchConfig::LEFTMOST.anchored(true),
            1,
        ),
    ] {
        let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
        let window = Window::all(&haystack);
        let outcome = regex
            .captures_with_config(&haystack, window, config, SearchLimits::default())
            .unwrap();
        assert_eq!(outcome.report.starts_injected, expected_starts);
        assert!(
            regex
                .bounded_backtrack_prospective(window, 0, config)
                .unwrap()
                .unwrap()
                .closes_report(&outcome.report)
        );
    }
}

#[test]
fn start_byte_prefilter_preserves_priority_context_and_adaptive_terminal() {
    let ast = Ast::alt([
        Ast::concat([Ast::Byte(b'a').capture(1), Ast::Byte(b'b')]),
        Ast::concat([Ast::Byte(b'a').capture(2), Ast::Byte(b'c')]),
    ]);
    let mut haystack = vec![b'x'; 144];
    haystack[7] = b'a';
    let last = haystack.len() - 2;
    haystack[last] = b'a';
    haystack[last + 1] = b'c';
    let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
    let outcome = regex
        .captures(&haystack, Window::all(&haystack), SearchLimits::default())
        .unwrap();
    assert_eq!(
        outcome.captures,
        reference("(?:(a)b)|(?:(a)c)", &haystack, Window::all(&haystack))
    );
    let captures = outcome.captures.unwrap();
    assert_eq!(captures.groups[1].span, None);
    assert_eq!(
        captures.groups[2].span,
        Some(Span {
            start: last,
            end: last + 1
        })
    );
    assert_eq!(outcome.report.starts_injected, 2);

    let dense = vec![b'a'; 144];
    let no_match = HistoryRegex::compile(
        &Ast::concat([Ast::Byte(b'a'), Ast::Class(vec![(b'b', b'c')])]),
        BuildLimits::default(),
    )
    .unwrap();
    let outcome = no_match
        .captures(&dense, Window::all(&dense), SearchLimits::default())
        .unwrap();
    assert!(outcome.captures.is_none());
    assert_eq!(outcome.report.starts_injected, dense.len());
    let prospective = no_match
        .bounded_backtrack_prospective(Window::all(&dense), 0, SearchConfig::LEFTMOST)
        .unwrap()
        .unwrap();
    assert!(prospective.closes_report(&outcome.report));

    let mut periodic = vec![b'x'; 4_096];
    for at in (0..periodic.len()).step_by(8) {
        periodic[at] = b'a';
    }
    let outcome = no_match
        .captures(&periodic, Window::all(&periodic), SearchLimits::default())
        .unwrap();
    assert!(outcome.captures.is_none());
    assert_eq!(outcome.report.starts_injected, periodic.len() / 8);
    assert!(
        no_match
            .bounded_backtrack_prospective(Window::all(&periodic), 0, SearchConfig::LEFTMOST,)
            .unwrap()
            .unwrap()
            .closes_report(&outcome.report)
    );

    let contextual_ast = Ast::concat([Ast::Assert(Assertion::StartLf), Ast::Byte(b'a').capture(1)]);
    let contextual = HistoryRegex::compile(&contextual_ast, BuildLimits::default()).unwrap();
    let mut source = vec![b'x'; 132];
    source[1] = b'\n';
    source[2] = b'a';
    let window = Window {
        start: 2,
        end: source.len(),
    };
    let outcome = contextual
        .captures(&source, window, SearchLimits::default())
        .unwrap();
    assert_eq!(
        outcome.captures,
        reference(&render(&contextual_ast), &source, window)
    );
    assert_eq!(outcome.report.starts_injected, 1);
}

#[test]
fn start_byte_prefilter_handles_nul_proof_word_edges_and_final_byte() {
    for ast in [
        Ast::Byte(0).capture(1),
        Ast::Class(vec![(63, 65)]).capture(1),
    ] {
        let final_byte = match &ast {
            Ast::Capture { child, .. } => match child.as_ref() {
                Ast::Byte(byte) => *byte,
                Ast::Class(_) => 64,
                _ => unreachable!("the test fixtures have one consuming child"),
            },
            _ => unreachable!("the test fixtures are captures"),
        };
        let mut haystack = vec![b'x'; 128];
        *haystack.last_mut().unwrap() = final_byte;
        let window = Window::all(&haystack);
        let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
        let outcome = regex
            .captures(&haystack, window, SearchLimits::default())
            .unwrap();
        assert_eq!(
            outcome.captures,
            reference(&render(&ast), &haystack, window)
        );
        assert_eq!(outcome.report.starts_injected, 1);
        assert_eq!(outcome.report.bytes_examined, haystack.len() + 1);
    }
}

#[test]
fn activated_prefilter_matches_baseline_over_generated_small_cases() {
    let prefix = vec![b'x'; 128];
    let mut comparisons = 0_usize;
    for ast in generated_bases()
        .into_iter()
        .flat_map(|base| wrappers(&base))
    {
        let regex = pair(&ast).1;
        for tail in generated_haystacks(3) {
            let mut haystack = prefix.clone();
            haystack.extend_from_slice(&tail);
            let window = Window::all(&haystack);
            let expected = reference(&render(&ast), &haystack, window);
            let got = regex
                .captures(&haystack, window, SearchLimits::default())
                .unwrap();
            assert_eq!(got.captures, expected, "ast={ast:?}, tail={tail:?}");
            if got.report.starts_injected < haystack.len() + 1 {
                let forced = regex
                    .captures_from_with_config(
                        &haystack,
                        window,
                        window.start,
                        SearchConfig::LEFTMOST,
                        SearchLimits::default(),
                    )
                    .unwrap();
                assert_eq!(forced.report.candidate, CandidateKind::PersistentHistory);
                assert_eq!(forced.captures, got.captures);
            }
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 3_510);
}

#[test]
fn exact_prefix_prefilter_preserves_context_priority_nul_repeat_and_final_match() {
    let alternatives = Ast::alt([
        Ast::concat([Ast::Byte(b'a').capture(1), Ast::Byte(b'b'), Ast::Byte(b'c')]),
        Ast::concat([Ast::Byte(b'a').capture(2), Ast::Byte(b'b'), Ast::Byte(b'd')]),
    ]);
    let mut alternative_source = vec![b'x'; 160];
    for at in (3..120).step_by(7) {
        alternative_source[at] = b'a';
    }
    let alternative_start = alternative_source.len() - 3;
    alternative_source[alternative_start..].copy_from_slice(b"abd");

    let contextual = Ast::concat([
        Ast::Assert(Assertion::StartLf),
        Ast::Byte(b'a').capture(1),
        Ast::Class(vec![(b'b', b'b')]),
    ]);
    let mut contextual_source = vec![b'x'; 160];
    contextual_source[154..157].copy_from_slice(b"\nab");

    let nul = Ast::alt([
        Ast::concat([Ast::Byte(0), Ast::Byte(b'b'), Ast::Byte(b'c')]),
        Ast::concat([Ast::Byte(0), Ast::Byte(b'b'), Ast::Byte(b'd')]),
    ])
    .capture(1);
    let mut nul_source = vec![b'x'; 160];
    let nul_start = nul_source.len() - 3;
    nul_source[nul_start..].copy_from_slice(&[0, b'b', b'd']);

    let repeated = Ast::concat([
        Ast::Byte(b'a').repeat(2, None, Greed::Greedy),
        Ast::Byte(b'b'),
    ])
    .capture(1);
    let mut repeated_source = vec![b'x'; 160];
    for at in (1..120).step_by(5) {
        repeated_source[at] = b'a';
    }
    repeated_source[151..154].copy_from_slice(b"aab");

    let common_three = Ast::alt([
        Ast::concat([
            Ast::Byte(b'a'),
            Ast::Byte(b'b'),
            Ast::Byte(b'c'),
            Ast::Byte(b'x'),
        ]),
        Ast::concat([
            Ast::Byte(b'a'),
            Ast::Byte(b'b'),
            Ast::Byte(b'c'),
            Ast::Byte(b'y'),
        ]),
    ]);
    let mut common_three_source = vec![b'x'; 160];
    common_three_source[156..].copy_from_slice(b"abcy");

    for (ast, source) in [
        (alternatives, alternative_source),
        (contextual, contextual_source),
        (nul, nul_source),
        (repeated, repeated_source),
        (common_three, common_three_source),
    ] {
        let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
        let window = Window::all(&source);
        let outcome = regex
            .captures(&source, window, SearchLimits::default())
            .unwrap();
        assert_eq!(
            outcome.captures,
            reference(&render(&ast), &source, window),
            "ast={ast:?}",
        );
        assert_eq!(outcome.report.candidate, CandidateKind::BoundedBacktracker);
        assert_eq!(outcome.report.starts_injected, 1, "ast={ast:?}");
        let prospective = regex
            .bounded_backtrack_prospective(window, window.start, SearchConfig::LEFTMOST)
            .unwrap()
            .unwrap();
        assert!(prospective.closes_report(&outcome.report), "ast={ast:?}");
    }
}

#[test]
fn exact_prefix_prefilter_adapts_on_dense_and_keeps_periodic_scans() {
    let ast = Ast::alt([
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'c')]),
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'd')]),
    ]);
    let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();

    let dense = b"abx".repeat(96);
    let dense_outcome = regex
        .captures(&dense, Window::all(&dense), SearchLimits::default())
        .unwrap();
    assert!(dense_outcome.captures.is_none());
    assert!(dense_outcome.report.starts_injected > 96);
    assert!(dense_outcome.report.starts_injected < dense.len());
    let dense_prospective = regex
        .bounded_backtrack_prospective(Window::all(&dense), 0, SearchConfig::LEFTMOST)
        .unwrap()
        .unwrap();
    assert!(dense_prospective.closes_report(&dense_outcome.report));

    let mut periodic = vec![b'x'; 4_096];
    for at in (0..periodic.len()).step_by(16) {
        periodic[at] = b'a';
        periodic[at + 1] = b'b';
    }
    let periodic_outcome = regex
        .captures(&periodic, Window::all(&periodic), SearchLimits::default())
        .unwrap();
    assert!(periodic_outcome.captures.is_none());
    assert_eq!(periodic_outcome.report.starts_injected, periodic.len() / 16);
    let periodic_prospective = regex
        .bounded_backtrack_prospective(Window::all(&periodic), 0, SearchConfig::LEFTMOST)
        .unwrap()
        .unwrap();
    assert!(periodic_prospective.closes_report(&periodic_outcome.report));
}

#[test]
fn exact_prefix_prefilter_matches_generated_suffixes_and_leaves_controls_inactive() {
    let patterns = [
        Ast::concat([
            Ast::Byte(b'a'),
            Ast::Byte(b'b'),
            Ast::Byte(b'a').repeat(0, Some(2), Greed::Greedy),
        ]),
        Ast::alt([
            Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]),
            Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'a')]),
        ]),
        Ast::concat([
            Ast::Byte(b'a').repeat(2, None, Greed::Lazy),
            Ast::Byte(b'b'),
        ]),
        Ast::concat([
            Ast::Assert(Assertion::WordAscii),
            Ast::Byte(b'a'),
            Ast::Byte(b'b'),
        ]),
    ];
    let tails = generated_haystacks(4);
    let mut comparisons = 0_usize;
    for ast in patterns {
        let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
        for tail in &tails {
            let mut source = vec![b'x'; 128];
            source.extend_from_slice(tail);
            let window = Window::all(&source);
            let outcome = regex
                .captures(&source, window, SearchLimits::default())
                .unwrap();
            assert_eq!(
                outcome.captures,
                reference(&render(&ast), &source, window),
                "ast={ast:?}, tail={tail:?}",
            );
            let prospective = regex
                .bounded_backtrack_prospective(window, 0, SearchConfig::LEFTMOST)
                .unwrap()
                .unwrap();
            assert!(prospective.closes_report(&outcome.report));
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 124);

    let exact = HistoryRegex::compile(
        &Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]),
        BuildLimits::default(),
    )
    .unwrap();
    let short = vec![b'x'; 63];
    let short_outcome = exact
        .captures(&short, Window::all(&short), SearchLimits::default())
        .unwrap();
    assert_eq!(short_outcome.report.starts_injected, short.len() + 1);

    let long = vec![b'x'; 128];
    let anchored = exact
        .captures_with_config(
            &long,
            Window::all(&long),
            SearchConfig::LEFTMOST.anchored(true),
            SearchLimits::default(),
        )
        .unwrap();
    assert_eq!(anchored.report.starts_injected, 1);

    let nullable = HistoryRegex::compile(
        &Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]).repeat(0, None, Greed::Greedy),
        BuildLimits::default(),
    )
    .unwrap();
    let nullable_outcome = nullable
        .captures(&long, Window::all(&long), SearchLimits::default())
        .unwrap();
    assert_eq!(nullable_outcome.report.starts_injected, 1);
    assert_eq!(
        nullable_outcome.captures.unwrap().overall(),
        Some(Span { start: 0, end: 0 })
    );
}

#[test]
fn exact_span_query_returns_long_nongreedy_history_and_clean_nonmatch() {
    let ast = Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Lazy);
    let regex = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
    let haystack = b"aaa";
    let window = Window::all(haystack);

    let outcome = regex
        .captures_exact(
            haystack,
            window,
            Span { start: 0, end: 3 },
            SearchLimits::default(),
        )
        .unwrap();
    let captures = outcome.captures.unwrap();
    assert_eq!(captures.overall(), Some(Span { start: 0, end: 3 }));
    assert_eq!(captures.groups[1].span, Some(Span { start: 2, end: 3 }));

    let nonmatch = regex
        .captures_exact(
            haystack,
            window,
            Span { start: 1, end: 1 },
            SearchLimits::default(),
        )
        .unwrap();
    assert!(nonmatch.captures.is_none());
}

#[test]
fn participation_quotient_matches_prioritized_tagged_histories() {
    fn assert_projection(ast: &Ast, haystack: &[u8], span: Span) {
        let regex = HistoryRegex::compile(ast, BuildLimits::default()).expect("history build");
        let full = regex
            .captures_exact(
                haystack,
                Window::all(haystack),
                span,
                SearchLimits::default(),
            )
            .expect("full exact replay");
        let projected = regex
            .captures_participation_exact(
                haystack,
                Window::all(haystack),
                span,
                SearchLimits::default(),
            )
            .expect("quotient exact replay");
        let expected = full.captures.as_ref().map(|captures| {
            captures
                .groups
                .iter()
                .skip(1)
                .filter(|group| group.span.is_some())
                .count()
        });
        let expected_mask = full.captures.as_ref().map(|captures| {
            captures
                .groups
                .iter()
                .enumerate()
                .fold(0_u64, |mask, (index, group)| {
                    if group.span.is_some() {
                        mask | (1_u64 << index)
                    } else {
                        mask
                    }
                })
        });
        assert_eq!(projected.participating_captures, expected);
        assert_eq!(projected.participation_mask, expected_mask);
        assert!(projected.prospective.closes_report(&projected.report));
        assert_eq!(projected.report.slot_copies, 0);
        assert_eq!(projected.report.history_nodes, 0);
        assert_eq!(projected.report.history_walk, 0);
    }

    let first_arm_has_two = Ast::alt([
        Ast::Byte(b'a').capture(2).capture(1),
        Ast::Byte(b'a').capture(3),
    ]);
    assert_projection(&first_arm_has_two, b"a", Span { start: 0, end: 1 });

    let first_arm_has_one = Ast::alt([
        Ast::Byte(b'a').capture(1),
        Ast::Byte(b'a').capture(3).capture(2),
    ]);
    assert_projection(&first_arm_has_one, b"a", Span { start: 0, end: 1 });

    // The higher-priority arm opens capture 1 and shares the first byte with
    // the winner, but then dies. Its partial tag state must not leak into the
    // lower-priority arm's same-span winner.
    let higher_priority_open_then_dies = Ast::alt([
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]).capture(1),
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'c')]).capture(2),
    ]);
    assert_projection(
        &higher_priority_open_then_dies,
        b"ac",
        Span { start: 0, end: 2 },
    );

    // A capture completed by an earlier repetition remains the canonical
    // participating slot even when the last repetition takes another arm.
    let repeated_prior =
        Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'b')]).repeat(1, None, Greed::Greedy);
    assert_projection(&repeated_prior, b"ab", Span { start: 0, end: 2 });

    let optional = Ast::concat([
        Ast::Byte(b'a').capture(1).repeat(0, Some(1), Greed::Greedy),
        Ast::Byte(b'b'),
    ]);
    assert_projection(&optional, b"b", Span { start: 0, end: 1 });

    assert_projection(
        &Ast::Empty.named(1, "empty"),
        b"",
        Span { start: 0, end: 0 },
    );
    assert_projection(&Ast::Byte(b'a').capture(1), b"b", Span { start: 0, end: 1 });
}

#[test]
fn reusable_participation_workspace_matches_full_history_on_random_replays() {
    fn next(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *seed
    }

    let patterns = [
        Ast::concat([
            Ast::Class(vec![(b'a', b'c')]).capture(1),
            Ast::Byte(b'b').capture(2).repeat(0, Some(1), Greed::Greedy),
        ]),
        Ast::alt([
            Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]).capture(1),
            Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'c')]).capture(2),
        ]),
        Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'b')]).repeat(1, None, Greed::Greedy),
        Ast::concat([
            Ast::Assert(Assertion::StartCrlf),
            Ast::Byte(b'a').capture(1),
            Ast::Assert(Assertion::EndCrlf),
        ]),
    ];
    let alphabet = [b'a', b'b', b'c', b'\r', b'\n', 0xff];
    let limits = SearchLimits::default();
    let mut seed = 0x70a7_c1a5_5eed_u64;
    let alphabet_len = u64::try_from(alphabet.len()).expect("bounded alphabet length");

    for ast in patterns {
        let regex = HistoryRegex::compile(&ast, BuildLimits::default()).expect("history build");
        let mut workspace = regex
            .prepare_participation_exact_workspace(Span { start: 0, end: 0 }, limits)
            .expect("participation workspace");
        for _ in 0..1_024 {
            let length = usize::try_from(next(&mut seed) % 49).expect("bounded length");
            let mut haystack = Vec::with_capacity(length);
            for _ in 0..length {
                let index = usize::try_from(next(&mut seed) % alphabet_len)
                    .expect("bounded alphabet index");
                haystack.push(alphabet[index]);
            }
            let boundaries = u64::try_from(length)
                .expect("bounded haystack length")
                .checked_add(1)
                .expect("bounded boundary count");
            let start = usize::try_from(next(&mut seed) % boundaries).expect("bounded start");
            let suffix_boundaries = u64::try_from(length - start)
                .expect("bounded suffix length")
                .checked_add(1)
                .expect("bounded suffix boundary count");
            let end =
                start + usize::try_from(next(&mut seed) % suffix_boundaries).expect("bounded end");
            let span = Span { start, end };
            let full = regex
                .captures_exact(&haystack, Window::all(&haystack), span, limits)
                .expect("full exact replay");
            let expected_mask = full.captures.as_ref().map(|captures| {
                captures
                    .groups
                    .iter()
                    .enumerate()
                    .fold(0_u64, |mask, (index, group)| {
                        mask | (u64::from(group.span.is_some()) << index)
                    })
            });
            let ordinary = regex
                .captures_participation_exact(&haystack, Window::all(&haystack), span, limits)
                .expect("ordinary participation replay");
            let reused = regex
                .captures_participation_exact_with_workspace(
                    &mut workspace,
                    &haystack,
                    Window::all(&haystack),
                    span,
                    limits,
                )
                .expect("reused participation replay");
            assert_eq!(
                reused, ordinary,
                "ast={ast:?} haystack={haystack:?} span={span:?}"
            );
            assert_eq!(reused.participation_mask, expected_mask);
        }
    }
}

#[test]
fn participation_quotient_has_exact_limits_and_zero_history_ledger() {
    let ast = Ast::alt([
        Ast::Byte(b'a').capture(2).capture(1),
        Ast::Byte(b'a').capture(3),
    ]);
    let regex = HistoryRegex::compile(&ast, BuildLimits::default()).expect("history build");
    let span = Span { start: 0, end: 1 };
    let prospective = regex
        .participation_exact_prospective(span)
        .expect("quotient prospective");
    assert_eq!(prospective.starts_injected, 1);
    assert_eq!(prospective.bytes_examined, 1);
    assert_eq!(prospective.slot_copies, 0);
    assert_eq!(prospective.history_nodes, 0);
    assert_eq!(prospective.history_walk, 0);
    let exact = SearchLimits {
        max_state_visits: prospective.state_visits,
        max_slot_copies: 0,
        max_history_nodes: 0,
        max_history_walk: 0,
        max_scratch_bytes: prospective.scratch_bytes,
    };
    let outcome = regex
        .captures_participation_exact(b"a", Window::all(b"a"), span, exact)
        .expect("exact quotient limits");
    assert_eq!(outcome.participating_captures, Some(2));
    assert_eq!(outcome.participation_mask, Some(0b111));
    assert_eq!(outcome.prospective, prospective);
    assert!(prospective.closes_report(&outcome.report));

    let one_below_visits = SearchLimits {
        max_state_visits: prospective.state_visits - 1,
        ..exact
    };
    assert_eq!(
        regex.captures_participation_exact(b"a", Window::all(b"a"), span, one_below_visits),
        Err(SearchError::Resource {
            kind: ResourceKind::StateVisits,
            required: prospective.state_visits,
            limit: prospective.state_visits - 1,
        })
    );

    let one_below_scratch = SearchLimits {
        max_scratch_bytes: prospective.scratch_bytes - 1,
        ..exact
    };
    assert_eq!(
        regex.captures_participation_exact(b"a", Window::all(b"a"), span, one_below_scratch),
        Err(SearchError::Resource {
            kind: ResourceKind::ScratchBytes,
            required: prospective.scratch_bytes,
            limit: prospective.scratch_bytes - 1,
        })
    );
    assert_eq!(
        regex.participation_exact_prospective(Span { start: 1, end: 0 }),
        Err(SearchError::InvalidWindow)
    );
}

#[test]
fn participation_quotient_boundary_has_generic_history_fallback() {
    assert_eq!(PARTICIPATION_QUOTIENT_CAPTURE_BITS, 63);
    let admitted =
        HistoryRegex::compile(&Ast::Byte(b'a').capture(63), BuildLimits::default()).unwrap();
    let admitted_outcome = admitted
        .captures_participation_exact(
            b"a",
            Window::all(b"a"),
            Span { start: 0, end: 1 },
            SearchLimits::default(),
        )
        .expect("63-user-capture quotient");
    assert_eq!(admitted_outcome.participating_captures, Some(1));
    assert_eq!(
        admitted_outcome.participation_mask,
        Some(1_u64 | (1_u64 << 63))
    );

    let fallback =
        HistoryRegex::compile(&Ast::Byte(b'a').capture(64), BuildLimits::default()).unwrap();
    assert_eq!(
        fallback.participation_exact_prospective(Span { start: 0, end: 1 }),
        Err(SearchError::InvalidProgram)
    );
    assert!(
        fallback
            .captures_exact(
                b"a",
                Window::all(b"a"),
                Span { start: 0, end: 1 },
                SearchLimits::default()
            )
            .expect("full history remains available")
            .captures
            .is_some()
    );
}

#[test]
fn directed_rust_capture_semantics() {
    let cases = [
        (
            Ast::alt([Ast::Byte(b'a'), Ast::Byte(b'b').capture(2)])
                .capture(1)
                .repeat(0, None, Greed::Greedy),
            b"ba".as_slice(),
        ),
        (
            Ast::concat([
                Ast::Byte(b'a').repeat(0, Some(1), Greed::Greedy),
                Ast::Byte(b'b'),
            ])
            .capture(1)
            .repeat(0, None, Greed::Greedy),
            b"ab".as_slice(),
        ),
        (
            Ast::Byte(b'a')
                .capture(2)
                .repeat(0, Some(1), Greed::Greedy)
                .capture(1)
                .repeat(0, None, Greed::Greedy),
            b"aa".as_slice(),
        ),
        (
            Ast::alt([Ast::Empty, Ast::Byte(b'a').named(2, "x")])
                .capture(1)
                .repeat(0, None, Greed::Greedy),
            b"a".as_slice(),
        ),
        (
            Ast::alt([
                Ast::Byte(b'a').capture(1),
                Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'a')]).capture(2),
            ]),
            b"aa".as_slice(),
        ),
        (
            Ast::concat([
                Ast::Byte(b'a').capture(1).repeat(0, Some(1), Greed::Greedy),
                Ast::Byte(b'b').capture(2).repeat(0, Some(1), Greed::Lazy),
            ]),
            b"a".as_slice(),
        ),
    ];
    for (ast, haystack) in cases {
        assert_case(&ast, haystack, Window::all(haystack));
    }
}

#[test]
fn earliest_end_preserves_priority_capture_history() {
    let cases = [
        (
            Ast::Byte(b'a').repeat(1, None, Greed::Greedy).capture(1),
            b"aaa".as_slice(),
            SearchConfig::EARLIEST,
            vec![
                (Span { start: 0, end: 1 }, Some(Span { start: 0, end: 1 })),
                (Span { start: 1, end: 2 }, Some(Span { start: 1, end: 2 })),
                (Span { start: 2, end: 3 }, Some(Span { start: 2, end: 3 })),
            ],
        ),
        (
            Ast::alt([
                Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'c')]),
                Ast::Byte(b'a'),
            ])
            .capture(1),
            b"abc".as_slice(),
            SearchConfig::EARLIEST,
            vec![(Span { start: 0, end: 1 }, Some(Span { start: 0, end: 1 }))],
        ),
        (
            Ast::concat([
                Ast::Start,
                Ast::alt([
                    Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'c')]),
                    Ast::Byte(b'a'),
                ])
                .capture(1),
            ]),
            b"abc".as_slice(),
            SearchConfig::EARLIEST,
            vec![(Span { start: 0, end: 1 }, Some(Span { start: 0, end: 1 }))],
        ),
        (
            Ast::concat([
                Ast::alt([
                    Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'c')]),
                    Ast::Byte(b'a'),
                ])
                .capture(1),
                Ast::End,
            ]),
            b"abc".as_slice(),
            SearchConfig::EARLIEST,
            vec![(Span { start: 0, end: 3 }, Some(Span { start: 0, end: 3 }))],
        ),
        (
            Ast::alt([
                Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b'), Ast::Byte(b'c')]),
                Ast::Byte(b'b'),
            ])
            .capture(1),
            b"abc".as_slice(),
            SearchConfig::EARLIEST.anchored(true),
            vec![(Span { start: 0, end: 3 }, Some(Span { start: 0, end: 3 }))],
        ),
    ];

    for (ast, haystack, config, expected) in cases {
        let (inline, history) = pair(&ast);
        for observed in [
            inline
                .captures_iter_with_config(
                    haystack,
                    Window::all(haystack),
                    config,
                    AggregateLimits::default(),
                )
                .unwrap()
                .captures,
            history
                .captures_iter_with_config(
                    haystack,
                    Window::all(haystack),
                    config,
                    AggregateLimits::default(),
                )
                .unwrap()
                .captures,
        ] {
            let spans = observed
                .iter()
                .map(|record| {
                    (
                        record.overall().unwrap(),
                        record.groups.get(1).and_then(|group| group.span),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(spans, expected);
        }
    }
}

#[test]
fn earliest_end_selects_first_priority_history_at_accepting_boundary() {
    let ast = Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'a').capture(2)]);
    let expected = CaptureRecord {
        groups: vec![
            GroupRecord {
                index: 0,
                name: None,
                span: Some(Span { start: 0, end: 1 }),
            },
            GroupRecord {
                index: 1,
                name: None,
                span: Some(Span { start: 0, end: 1 }),
            },
            GroupRecord {
                index: 2,
                name: None,
                span: None,
            },
        ],
    };
    let (inline, history) = pair(&ast);
    assert_eq!(
        inline
            .captures_with_config(
                b"a",
                Window::all(b"a"),
                SearchConfig::EARLIEST,
                SearchLimits::default(),
            )
            .unwrap()
            .captures,
        Some(expected.clone())
    );
    assert_eq!(
        history
            .captures_with_config(
                b"a",
                Window::all(b"a"),
                SearchConfig::EARLIEST,
                SearchLimits::default(),
            )
            .unwrap()
            .captures,
        Some(expected)
    );
}

fn assert_all_match_kind(
    ast: &Ast,
    haystack: &[u8],
    overall: Span,
    group_one: Option<Span>,
    group_two: Option<Span>,
    anchored: bool,
) {
    let config = SearchConfig::LEFTMOST
        .match_kind(CaptureMatchKind::All)
        .anchored(anchored);
    let (inline, history) = pair(ast);
    let pattern = render(ast);
    let expected = reference_with_match_kind(
        &pattern,
        haystack,
        Window::all(haystack),
        MatchKind::All,
        anchored,
    )
    .unwrap();
    for observed in [
        inline
            .captures_with_config(
                haystack,
                Window::all(haystack),
                config,
                SearchLimits::default(),
            )
            .unwrap()
            .captures
            .unwrap(),
        history
            .captures_with_config(
                haystack,
                Window::all(haystack),
                config,
                SearchLimits::default(),
            )
            .unwrap()
            .captures
            .unwrap(),
    ] {
        assert_eq!(observed, expected);
        assert_eq!(observed.overall(), Some(overall));
        assert_eq!(observed.groups[1].span, group_one);
        if let Some(group) = observed.groups.get(2) {
            assert_eq!(group.span, group_two);
        }
    }
    let expected = reference_iter_with_match_kind(
        &pattern,
        haystack,
        Window::all(haystack),
        MatchKind::All,
        anchored,
    );
    assert_eq!(
        inline
            .captures_iter_with_config(
                haystack,
                Window::all(haystack),
                config,
                AggregateLimits::default(),
            )
            .unwrap()
            .captures,
        expected
    );
    assert_eq!(
        history
            .captures_iter_with_config(
                haystack,
                Window::all(haystack),
                config,
                AggregateLimits::default(),
            )
            .unwrap()
            .captures,
        expected
    );
}

#[test]
fn all_match_kind_selects_last_end_without_losing_equal_end_priority() {
    for (ast, haystack, overall, group_one, group_two, anchored) in [
        (
            Ast::alt([
                Ast::Byte(b'a').capture(1),
                Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'a')]).capture(2),
            ]),
            b"aa".as_slice(),
            Span { start: 0, end: 2 },
            None,
            Some(Span { start: 0, end: 2 }),
            false,
        ),
        (
            Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'a').capture(2)]),
            b"a".as_slice(),
            Span { start: 0, end: 1 },
            Some(Span { start: 0, end: 1 }),
            None,
            false,
        ),
        (
            Ast::Byte(b'a').capture(1),
            b"aba".as_slice(),
            Span { start: 2, end: 3 },
            Some(Span { start: 2, end: 3 }),
            None,
            false,
        ),
        (
            Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Lazy),
            b"aaa".as_slice(),
            Span { start: 0, end: 3 },
            Some(Span { start: 2, end: 3 }),
            None,
            true,
        ),
    ] {
        assert_all_match_kind(&ast, haystack, overall, group_one, group_two, anchored);
    }
}

#[test]
fn sparse_capture_indices_materialize_explicit_unmatched_slots() {
    let ast = Ast::Byte(b'a').capture(2);
    let constrained = BuildLimits {
        max_captures: 1,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(&ast, constrained),
        Err(BuildError::Resource {
            kind: ResourceKind::Captures,
            required: 2,
            limit: 1,
        })
    ));
    let (inline, history) = pair(&ast);
    assert_eq!(inline.program().build_report().captures, 2);
    let expected = Some(CaptureRecord {
        groups: vec![
            GroupRecord {
                index: 0,
                name: None,
                span: Some(Span { start: 0, end: 1 }),
            },
            GroupRecord {
                index: 1,
                name: None,
                span: None,
            },
            GroupRecord {
                index: 2,
                name: None,
                span: Some(Span { start: 0, end: 1 }),
            },
        ],
    });
    assert_eq!(
        inline
            .captures(b"a", Window::all(b"a"), SearchLimits::default())
            .unwrap()
            .captures,
        expected
    );
    assert_eq!(
        history
            .captures(b"a", Window::all(b"a"), SearchLimits::default())
            .unwrap()
            .captures,
        expected
    );
}

#[test]
fn nested_repeat_capture_catalog_matches_pinned_regex() {
    let catalog = [
        Ast::Byte(b'a')
            .capture(2)
            .repeat(0, Some(1), Greed::Greedy)
            .capture(1)
            .repeat(1, None, Greed::Greedy),
        Ast::Byte(b'a')
            .capture(2)
            .repeat(0, Some(1), Greed::Lazy)
            .capture(1)
            .repeat(1, None, Greed::Lazy),
        Ast::alt([
            Ast::Byte(b'a').capture(2),
            Ast::Byte(b'b').capture(3).repeat(0, Some(1), Greed::Greedy),
        ])
        .capture(1)
        .repeat(0, None, Greed::Greedy),
        Ast::Byte(b'a')
            .capture(2)
            .repeat(0, Some(1), Greed::Greedy)
            .capture(1)
            .repeat(2, None, Greed::Greedy),
        Ast::alt([Ast::Byte(b'a').capture(2), Ast::Byte(b'b').capture(3)])
            .capture(1)
            .repeat(1, Some(3), Greed::Lazy),
        Ast::concat([
            Ast::Byte(b'a')
                .named(2, "inner")
                .repeat(0, Some(1), Greed::Greedy),
            Ast::Byte(b'b'),
        ])
        .named(1, "outer")
        .repeat(0, None, Greed::Greedy),
        Ast::Byte(b'a')
            .capture(3)
            .repeat(0, Some(1), Greed::Greedy)
            .capture(2)
            .repeat(0, Some(1), Greed::Lazy)
            .capture(1)
            .repeat(0, None, Greed::Greedy),
        Ast::concat([
            Ast::Byte(b'a').capture(1).repeat(0, None, Greed::Greedy),
            Ast::Byte(b'a').capture(2).repeat(0, None, Greed::Lazy),
        ]),
    ];
    for ast in catalog {
        for haystack in generated_haystacks(4) {
            assert_case(&ast, &haystack, Window::all(&haystack));
            let mut embedded = vec![b'x'];
            embedded.extend_from_slice(&haystack);
            embedded.push(b'y');
            assert_case(
                &ast,
                &embedded,
                Window {
                    start: 1,
                    end: haystack.len() + 1,
                },
            );
        }
    }
}

#[test]
fn byte_classes_include_non_utf8_haystacks() {
    let ast = Ast::Class(vec![(0, 1), (b'a', b'c'), (0xFF, 0xFF)])
        .capture(1)
        .repeat(1, None, Greed::Greedy);
    for haystack in [
        b"abc".as_slice(),
        &[0xFF, b'a'],
        &[0x80, 0xFF],
        &[0, 1, b'c'],
    ] {
        assert_case(&ast, haystack, Window::all(haystack));
    }
}

#[test]
fn window_offsets_and_anchor_context_are_exact() {
    let ast = Ast::concat([Ast::Start, Ast::Byte(b'a').named(1, "letter"), Ast::End]);
    let haystack = b"xay";
    assert_case(&ast, haystack, Window { start: 1, end: 2 });
    assert_case(&ast, haystack, Window { start: 0, end: 2 });
}

#[test]
fn bounded_window_keeps_left_ascii_word_context() {
    let ast = Ast::concat([
        Ast::Assert(Assertion::WordAscii),
        Ast::Byte(b'a').capture(1),
    ]);
    let (inline, history) = pair(&ast);
    let haystack = b"za a";
    let window = Window { start: 1, end: 3 };

    assert_eq!(
        inline
            .captures(haystack, window, SearchLimits::default())
            .unwrap()
            .captures,
        None
    );
    assert_eq!(
        history
            .captures(haystack, window, SearchLimits::default())
            .unwrap()
            .captures,
        None
    );
}

#[test]
fn bounded_windows_preserve_all_assertion_context_and_clip_matches() {
    let cases = [
        (
            Ast::concat([
                Ast::Assert(Assertion::WordAscii),
                Ast::Byte(b'a').capture(1),
            ]),
            b"za a".as_slice(),
            Window { start: 1, end: 3 },
        ),
        (
            Ast::concat([
                Ast::Byte(b'a').capture(1),
                Ast::Assert(Assertion::WordAscii),
            ]),
            b"az ".as_slice(),
            Window { start: 0, end: 1 },
        ),
        (
            Ast::concat([
                Ast::Assert(Assertion::WordUnicode),
                Ast::Byte(b'a').capture(1),
            ]),
            "éa ".as_bytes(),
            Window { start: 2, end: 3 },
        ),
        (
            Ast::concat([
                Ast::Byte(b'a').capture(1),
                Ast::Assert(Assertion::WordUnicode),
            ]),
            "aé".as_bytes(),
            Window { start: 0, end: 1 },
        ),
        (
            Ast::concat([
                Ast::Assert(Assertion::WordUnicode),
                Ast::Byte(b'a').capture(1),
                Ast::Assert(Assertion::WordUnicode),
            ]),
            "é a!".as_bytes(),
            Window { start: 3, end: 4 },
        ),
        (
            Ast::concat([Ast::Start, Ast::Byte(b'a').capture(1)]),
            b"za".as_slice(),
            Window { start: 1, end: 2 },
        ),
        (
            Ast::concat([Ast::Byte(b'a').capture(1), Ast::End]),
            b"az".as_slice(),
            Window { start: 0, end: 1 },
        ),
        (
            Ast::concat([Ast::Assert(Assertion::StartLf), Ast::Byte(b'a').capture(1)]),
            b"x\na".as_slice(),
            Window { start: 2, end: 3 },
        ),
        (
            Ast::Byte(b'a').repeat(1, None, Greed::Greedy).capture(1),
            b"zaaaz".as_slice(),
            Window { start: 2, end: 4 },
        ),
    ];
    for (ast, haystack, window) in cases {
        assert_case(&ast, haystack, window);
    }

    let empty = Ast::Empty.capture(1);
    let pattern = render(&empty);
    let haystack = b"abcd";
    let window = Window { start: 1, end: 3 };
    let expected = reference_iter(&pattern, haystack, window);
    assert_eq!(
        expected
            .iter()
            .filter_map(CaptureRecord::overall)
            .collect::<Vec<_>>(),
        vec![
            Span { start: 1, end: 1 },
            Span { start: 2, end: 2 },
            Span { start: 3, end: 3 },
        ]
    );
    let (inline, history) = pair(&empty);
    assert_eq!(
        inline
            .captures_iter(haystack, window, AggregateLimits::default())
            .unwrap()
            .captures,
        expected
    );
    assert_eq!(
        history
            .captures_iter(haystack, window, AggregateLimits::default())
            .unwrap()
            .captures,
        expected
    );
}

#[test]
fn contextual_line_and_word_assertions_match_pinned_regex() {
    let assertions = [
        Assertion::StartLf,
        Assertion::EndLf,
        Assertion::StartCrlf,
        Assertion::EndCrlf,
        Assertion::WordAscii,
        Assertion::WordAsciiNegate,
        Assertion::WordStartAscii,
        Assertion::WordEndAscii,
        Assertion::WordStartHalfAscii,
        Assertion::WordEndHalfAscii,
        Assertion::WordUnicode,
        Assertion::WordUnicodeNegate,
        Assertion::WordStartUnicode,
        Assertion::WordEndUnicode,
        Assertion::WordStartHalfUnicode,
        Assertion::WordEndHalfUnicode,
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"a-\n_b\r\nc\rd",
        "é-東京_42\n".as_bytes(),
        &[0xFF, b'a', 0x80, b'_', b'\n'],
    ];
    for assertion in assertions {
        let ast = Ast::Assert(assertion).capture(1);
        for &haystack in haystacks {
            if core::str::from_utf8(haystack).is_err()
                && matches!(
                    assertion,
                    Assertion::WordUnicodeNegate
                        | Assertion::WordStartUnicode
                        | Assertion::WordEndUnicode
                        | Assertion::WordStartHalfUnicode
                        | Assertion::WordEndHalfUnicode
                )
            {
                continue;
            }
            assert_case(&ast, haystack, Window::all(haystack));
            let mut embedded = Vec::with_capacity(haystack.len() + 2);
            embedded.push(b'x');
            embedded.extend_from_slice(haystack);
            embedded.push(b'y');
            assert_case(
                &ast,
                &embedded,
                Window {
                    start: 1,
                    end: haystack.len() + 1,
                },
            );
        }
    }
}

#[test]
fn exhaustive_small_generated_single_matches() {
    let bases = generated_bases();
    let haystacks = generated_haystacks(4);
    let mut comparisons = 0_usize;
    for base in bases {
        for ast in wrappers(&base) {
            for haystack in &haystacks {
                assert_case(&ast, haystack, Window::all(haystack));
                let mut embedded = Vec::with_capacity(haystack.len() + 2);
                embedded.push(b'x');
                embedded.extend_from_slice(haystack);
                embedded.push(b'y');
                assert_case(
                    &ast,
                    &embedded,
                    Window {
                        start: 1,
                        end: haystack.len() + 1,
                    },
                );
                comparisons += 2;
            }
        }
    }
    assert_eq!(comparisons, 14_508);
}

#[test]
fn exhaustive_small_generated_anchored_matches() {
    let bases = generated_bases();
    let haystacks = generated_haystacks(4);
    let config = SearchConfig::LEFTMOST.anchored(true);
    let mut comparisons = 0_usize;
    for base in bases {
        for ast in wrappers(&base) {
            let pattern = render(&ast);
            let history = pair(&ast).1;
            for haystack in &haystacks {
                let mut embedded = Vec::with_capacity(haystack.len() + 2);
                embedded.push(b'x');
                embedded.extend_from_slice(haystack);
                embedded.push(b'y');
                for (source, window) in [
                    (haystack.as_slice(), Window::all(haystack)),
                    (
                        embedded.as_slice(),
                        Window {
                            start: 1,
                            end: haystack.len() + 1,
                        },
                    ),
                ] {
                    let expected = reference_with_match_kind(
                        &pattern,
                        source,
                        window,
                        MatchKind::LeftmostFirst,
                        true,
                    );
                    let got = history
                        .captures_with_config(source, window, config, SearchLimits::default())
                        .unwrap();
                    assert_eq!(
                        expected, got.captures,
                        "anchored mismatch: pattern={pattern:?}, haystack={source:?}, window={window:?}"
                    );
                    assert_eq!(got.report.candidate, CandidateKind::BoundedBacktracker);
                    let prospective = history
                        .bounded_backtrack_prospective(window, window.start, config)
                        .unwrap()
                        .unwrap();
                    assert!(prospective.closes_report(&got.report));
                    comparisons += 1;
                }
            }
        }
    }
    assert_eq!(comparisons, 14_508);
}

#[test]
fn aggregate_empty_suppression_matches_pinned_regex() {
    let cases = [
        Ast::Empty.capture(1),
        Ast::Byte(b'a').capture(1).repeat(0, None, Greed::Greedy),
        Ast::Byte(b'a').capture(1).repeat(0, None, Greed::Lazy),
        Ast::alt([Ast::Byte(b'a').capture(1), Ast::Empty]),
        Ast::alt([Ast::Empty, Ast::Byte(b'a').capture(1)]),
    ];
    for ast in cases {
        let pattern = render(&ast);
        let (inline, history) = pair(&ast);
        for haystack in [b"".as_slice(), b"a", b"ba", b"aa"] {
            let window = Window::all(haystack);
            let expected = reference_iter(&pattern, haystack, window);
            let inline_got = inline
                .captures_iter(haystack, window, AggregateLimits::default())
                .unwrap();
            let history_got = history
                .captures_iter(haystack, window, AggregateLimits::default())
                .unwrap();
            assert_eq!(
                expected, inline_got.captures,
                "inline {pattern:?} {haystack:?}"
            );
            assert_eq!(
                expected, history_got.captures,
                "history {pattern:?} {haystack:?}"
            );
        }
    }
}

#[test]
fn build_resource_dimensions_refuse_explicitly() {
    let ast = Ast::Byte(b'a').capture(1);
    let ast_nodes = BuildLimits {
        max_ast_nodes: 0,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(&ast, ast_nodes),
        Err(BuildError::Resource {
            kind: ResourceKind::AstNodes,
            ..
        })
    ));
    let ast_depth = BuildLimits {
        max_ast_depth: 1,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(&ast, ast_depth),
        Err(BuildError::Resource {
            kind: ResourceKind::AstDepth,
            ..
        })
    ));
    let captures = BuildLimits {
        max_captures: 0,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(&ast, captures),
        Err(BuildError::Resource {
            kind: ResourceKind::Captures,
            ..
        })
    ));
    let expansion = BuildLimits {
        max_repeat_expansion: 1,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(
            &Ast::Byte(b'a').repeat(0, Some(2), Greed::Greedy),
            expansion,
        ),
        Err(BuildError::Resource {
            kind: ResourceKind::RepeatExpansion,
            ..
        })
    ));
    let tiny_build = BuildLimits {
        max_states: 1,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(&ast, tiny_build),
        Err(BuildError::Resource {
            kind: ResourceKind::States,
            ..
        })
    ));
    let patch_entries = BuildLimits {
        max_patch_entries: 0,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(&ast, patch_entries),
        Err(BuildError::Resource {
            kind: ResourceKind::PatchEntries,
            ..
        })
    ));
    let compile_work = BuildLimits {
        max_compile_work: 0,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(&ast, compile_work),
        Err(BuildError::Resource {
            kind: ResourceKind::CompileWork,
            ..
        })
    ));
    let program_bytes = BuildLimits {
        max_program_bytes: 1,
        ..BuildLimits::default()
    };
    assert!(matches!(
        Program::compile(&ast, program_bytes),
        Err(BuildError::Resource {
            kind: ResourceKind::ProgramBytes,
            ..
        })
    ));
}

#[test]
fn search_resource_dimensions_refuse_explicitly() {
    let ast = Ast::Byte(b'a').capture(1);
    let (inline, history) = pair(&ast);
    let tiny_visits = SearchLimits {
        max_state_visits: 1,
        ..SearchLimits::default()
    };
    assert!(matches!(
        inline.captures(b"a", Window::all(b"a"), tiny_visits),
        Err(SearchError::Resource {
            kind: ResourceKind::StateVisits,
            ..
        })
    ));
    let tiny_copies = SearchLimits {
        max_slot_copies: 1,
        ..SearchLimits::default()
    };
    assert!(matches!(
        inline.captures(b"a", Window::all(b"a"), tiny_copies),
        Err(SearchError::Resource {
            kind: ResourceKind::SlotCopies,
            ..
        })
    ));
    let tiny_history = SearchLimits {
        max_history_nodes: 1,
        ..SearchLimits::default()
    };
    assert!(matches!(
        history.captures_from_with_config(
            b"a",
            Window::all(b"a"),
            0,
            SearchConfig::LEFTMOST,
            tiny_history
        ),
        Err(SearchError::Resource {
            kind: ResourceKind::HistoryNodes,
            ..
        })
    ));
    let tiny_walk = SearchLimits {
        max_history_walk: 1,
        ..SearchLimits::default()
    };
    assert!(matches!(
        history.captures_from_with_config(
            b"a",
            Window::all(b"a"),
            0,
            SearchConfig::LEFTMOST,
            tiny_walk
        ),
        Err(SearchError::Resource {
            kind: ResourceKind::HistoryWalk,
            ..
        })
    ));
    let tiny_scratch = SearchLimits {
        max_scratch_bytes: 1,
        ..SearchLimits::default()
    };
    assert!(matches!(
        history.captures_from_with_config(
            b"a",
            Window::all(b"a"),
            0,
            SearchConfig::LEFTMOST,
            tiny_scratch
        ),
        Err(SearchError::Resource {
            kind: ResourceKind::ScratchBytes,
            ..
        })
    ));
}

#[test]
fn history_start_ceiling_is_an_explicit_filtered_domain() {
    let ast = Ast::concat([
        Ast::Byte(b'a'),
        Ast::Byte(b'b'),
        Ast::Byte(b'c'),
        Ast::Byte(b'd'),
        Ast::Byte(b'e'),
    ])
    .capture(1);
    let history = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
    let haystack = b"xxabcdeyy";
    let window = Window::all(haystack);
    let limits = SearchLimits::default();
    let baseline = history
        .captures_from_with_config(haystack, window, 0, SearchConfig::LEFTMOST, limits)
        .unwrap();
    assert_eq!(
        baseline.captures.as_ref().and_then(CaptureRecord::overall),
        Some(Span { start: 2, end: 7 })
    );

    let restrictive = history
        .captures_from_with_config_start_ceiling(
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            Some(1),
            limits,
        )
        .unwrap();
    assert!(restrictive.captures.is_none());

    let tight = history
        .captures_from_with_config_start_ceiling(
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            Some(2),
            limits,
        )
        .unwrap();
    assert_eq!(tight.captures, baseline.captures);
    assert_eq!(tight.report.starts_injected, 3);
    assert!(
        tight.report.bytes_examined > 2,
        "the root admitted at the ceiling must remain live after it"
    );

    let miss = b"xxxxxx";
    let miss_window = Window::all(miss);
    let ordinary_miss = history
        .captures_from_with_config(miss, miss_window, 0, SearchConfig::LEFTMOST, limits)
        .unwrap();
    let capped_miss = history
        .captures_from_with_config_start_ceiling(
            miss,
            miss_window,
            0,
            SearchConfig::LEFTMOST,
            miss_window.end.checked_sub(5),
            limits,
        )
        .unwrap();
    assert_eq!(capped_miss.captures, ordinary_miss.captures);
    assert!(capped_miss.captures.is_none());
    assert!(capped_miss.report.state_visits < ordinary_miss.report.state_visits);
    assert!(capped_miss.report.history_nodes < ordinary_miss.report.history_nodes);
    assert!(capped_miss.report.starts_injected < ordinary_miss.report.starts_injected);
    assert_eq!(
        capped_miss.report.admitted_scratch_bytes,
        ordinary_miss.report.admitted_scratch_bytes
    );
    assert_eq!(
        capped_miss.report.admitted_scratch_bytes,
        history
            .search_prospective(miss_window, 0)
            .unwrap()
            .scratch_bytes
    );

    let complete_domain = history
        .captures_from_with_config_start_ceiling(
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            Some(usize::MAX),
            limits,
        )
        .unwrap();
    assert_eq!(complete_domain, baseline);

    let prospective = history.search_prospective(window, 0).unwrap();
    let empty = history
        .captures_from_with_config_start_ceiling(
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            None,
            limits,
        )
        .unwrap();
    assert!(empty.captures.is_none());
    assert_eq!(empty.report.state_visits, 0);
    assert_eq!(empty.report.history_nodes, 0);
    assert_eq!(empty.report.starts_injected, 0);
    assert_eq!(empty.report.bytes_examined, 0);
    assert_eq!(
        empty.report.admitted_scratch_bytes,
        prospective.scratch_bytes
    );

    let cutoff_from = 7;
    let cutoff = 4;
    let prospective = history.search_prospective(window, cutoff_from).unwrap();
    let empty = history
        .captures_from_with_config_start_ceiling(
            haystack,
            window,
            cutoff_from,
            SearchConfig::LEFTMOST,
            Some(cutoff),
            limits,
        )
        .unwrap();
    assert!(empty.captures.is_none());
    assert_eq!(empty.report.state_visits, 0);
    assert_eq!(empty.report.history_nodes, 0);
    assert_eq!(empty.report.starts_injected, 0);
    assert_eq!(empty.report.bytes_examined, 0);
    assert_eq!(
        empty.report.admitted_scratch_bytes,
        prospective.scratch_bytes
    );

    let exact_admission = SearchLimits {
        max_state_visits: prospective.state_visits,
        max_history_nodes: prospective.history_nodes,
        max_history_walk: prospective.history_walk,
        max_scratch_bytes: prospective.scratch_bytes,
        ..limits
    };
    let empty_search = |limits| {
        history.captures_from_with_config_start_ceiling(
            haystack,
            window,
            cutoff_from,
            SearchConfig::LEFTMOST,
            Some(cutoff),
            limits,
        )
    };
    let one_below = prospective.state_visits - 1;
    assert_eq!(
        empty_search(SearchLimits {
            max_state_visits: one_below,
            ..exact_admission
        }),
        Err(SearchError::Resource {
            kind: ResourceKind::StateVisits,
            required: prospective.state_visits,
            limit: one_below,
        })
    );
    let one_below = prospective.history_nodes - 1;
    assert_eq!(
        empty_search(SearchLimits {
            max_history_nodes: one_below,
            ..exact_admission
        }),
        Err(SearchError::Resource {
            kind: ResourceKind::HistoryNodes,
            required: prospective.history_nodes,
            limit: one_below,
        })
    );
    let one_below = prospective.history_walk - 1;
    assert_eq!(
        empty_search(SearchLimits {
            max_history_walk: one_below,
            ..exact_admission
        }),
        Err(SearchError::Resource {
            kind: ResourceKind::HistoryWalk,
            required: prospective.history_walk,
            limit: one_below,
        })
    );
    let one_below = prospective.scratch_bytes - 1;
    assert_eq!(
        empty_search(SearchLimits {
            max_scratch_bytes: one_below,
            ..exact_admission
        }),
        Err(SearchError::Resource {
            kind: ResourceKind::ScratchBytes,
            required: prospective.scratch_bytes,
            limit: one_below,
        })
    );
}

#[test]
fn history_masked_start_filter_restricts_only_new_roots() {
    let ast = Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'-'), Ast::Byte(b'b')]).capture(1);
    let history = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
    let classifier = MaskedInclusiveRange::new(0x20, b'a', b'z').expect("ordered ASCII range");
    assert!(MaskedInclusiveRange::new(0, b'z', b'a').is_none());
    for byte in 0_u8..=u8::MAX {
        assert_eq!(classifier.matches(byte), byte.is_ascii_alphabetic());
    }

    let haystack = b"--a-b--";
    let window = Window::all(haystack);
    let limits = SearchLimits::default();
    let baseline = history
        .captures_from_with_config(haystack, window, 0, SearchConfig::LEFTMOST, limits)
        .unwrap();
    let filtered = history
        .captures_from_with_config_start_ceiling_filtered(
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            Some(window.end),
            classifier,
            limits,
        )
        .unwrap();
    assert_eq!(filtered.captures, baseline.captures);
    assert_eq!(
        filtered.captures.as_ref().and_then(CaptureRecord::overall),
        Some(Span { start: 2, end: 5 })
    );
    assert!(filtered.report.state_visits < baseline.report.state_visits);
    assert!(filtered.report.history_nodes < baseline.report.history_nodes);
    assert!(filtered.report.starts_injected < baseline.report.starts_injected);
    assert_eq!(
        filtered.report.bytes_examined,
        baseline.report.bytes_examined
    );

    let tight_ceiling = history
        .captures_from_with_config_start_ceiling_filtered(
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            Some(2),
            classifier,
            limits,
        )
        .unwrap();
    assert_eq!(
        tight_ceiling
            .captures
            .as_ref()
            .and_then(CaptureRecord::overall),
        Some(Span { start: 2, end: 5 }),
        "the root at the ceiling must finish through an unrestricted live thread"
    );
    let one_below_ceiling = history
        .captures_from_with_config_start_ceiling_filtered(
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            Some(1),
            classifier,
            limits,
        )
        .unwrap();
    assert!(one_below_ceiling.captures.is_none());

    let false_classifier = MaskedInclusiveRange::new(0, b'0', b'9').expect("ordered digit range");
    let restricted = history
        .captures_from_with_config_start_ceiling_filtered(
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            Some(window.end),
            false_classifier,
            limits,
        )
        .unwrap();
    assert!(restricted.captures.is_none());

    // A punctuation rejection with no live thread cannot be treated as
    // future-domain exhaustion: the later alphabetic root must still match.
    let later = b"-a-b";
    let later_window = Window::all(later);
    let later_filtered = history
        .captures_from_with_config_start_ceiling_filtered(
            later,
            later_window,
            0,
            SearchConfig::LEFTMOST,
            Some(later_window.end),
            classifier,
            limits,
        )
        .unwrap();
    assert_eq!(
        later_filtered
            .captures
            .as_ref()
            .and_then(CaptureRecord::overall),
        Some(Span { start: 1, end: 4 })
    );

    // Validation and incumbent history admission still precede the admitted
    // empty filtered domain.
    let empty = b"";
    let empty_window = Window::all(empty);
    let prospective = history.search_prospective(empty_window, 0).unwrap();
    let empty_outcome = history
        .captures_from_with_config_start_ceiling_filtered(
            empty,
            empty_window,
            0,
            SearchConfig::LEFTMOST,
            Some(0),
            classifier,
            limits,
        )
        .unwrap();
    assert!(empty_outcome.captures.is_none());
    assert_eq!(empty_outcome.report.state_visits, 0);
    assert_eq!(empty_outcome.report.starts_injected, 0);
    assert_eq!(
        empty_outcome.report.admitted_scratch_bytes,
        prospective.scratch_bytes
    );
    let exact_admission = SearchLimits {
        max_state_visits: prospective.state_visits,
        max_history_nodes: prospective.history_nodes,
        max_history_walk: prospective.history_walk,
        max_scratch_bytes: prospective.scratch_bytes,
        ..limits
    };
    let empty_search = |limits| {
        history.captures_from_with_config_start_ceiling_filtered(
            empty,
            empty_window,
            0,
            SearchConfig::LEFTMOST,
            Some(0),
            classifier,
            limits,
        )
    };
    let one_below = prospective.state_visits - 1;
    assert_eq!(
        empty_search(SearchLimits {
            max_state_visits: one_below,
            ..exact_admission
        }),
        Err(SearchError::Resource {
            kind: ResourceKind::StateVisits,
            required: prospective.state_visits,
            limit: one_below,
        })
    );
    let one_below = prospective.history_nodes - 1;
    assert_eq!(
        empty_search(SearchLimits {
            max_history_nodes: one_below,
            ..exact_admission
        }),
        Err(SearchError::Resource {
            kind: ResourceKind::HistoryNodes,
            required: prospective.history_nodes,
            limit: one_below,
        })
    );
    let one_below = prospective.history_walk - 1;
    assert_eq!(
        empty_search(SearchLimits {
            max_history_walk: one_below,
            ..exact_admission
        }),
        Err(SearchError::Resource {
            kind: ResourceKind::HistoryWalk,
            required: prospective.history_walk,
            limit: one_below,
        })
    );
    let one_below = prospective.scratch_bytes - 1;
    assert_eq!(
        empty_search(SearchLimits {
            max_scratch_bytes: one_below,
            ..exact_admission
        }),
        Err(SearchError::Resource {
            kind: ResourceKind::ScratchBytes,
            required: prospective.scratch_bytes,
            limit: one_below,
        })
    );

    assert_eq!(
        history.captures_from_with_config_start_ceiling_filtered(
            empty,
            Window { start: 1, end: 0 },
            0,
            SearchConfig::LEFTMOST,
            None,
            classifier,
            SearchLimits {
                max_state_visits: 0,
                max_history_nodes: 0,
                max_history_walk: 0,
                max_scratch_bytes: 0,
                ..limits
            },
        ),
        Err(SearchError::InvalidWindow),
        "window validation precedes admission and an empty filtered domain"
    );
}

#[test]
fn retained_history_workspace_reuses_exact_group_slots_transactionally() {
    let ast = Ast::concat([
        Ast::Byte(b'a').capture(1).repeat(0, Some(1), Greed::Greedy),
        Ast::Empty.capture(2),
        Ast::Byte(b'b'),
    ]);
    let history = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
    let haystack = b"\xFFbab";
    let window = Window::all(haystack);
    let limits = SearchLimits::default();
    let mut workspace = history
        .prepare_exact_workspace(haystack.len(), limits)
        .expect("retained history workspace");
    let mut slots = vec![CaptureGroupSlot::UNMATCHED; 3];

    for from in [0, 2] {
        let expected = history
            .captures_from_with_config(haystack, window, from, SearchConfig::LEFTMOST, limits)
            .expect("allocating history search")
            .captures
            .expect("expected capture record");
        let actual = history
            .captures_from_slots_with_workspace(
                &mut workspace,
                haystack,
                window,
                from,
                SearchConfig::LEFTMOST,
                &mut slots,
                limits,
            )
            .expect("retained history search");
        assert!(actual.matched);
        assert_eq!(slots.len(), expected.groups.len());
        for (slot, group) in slots.iter().zip(&expected.groups) {
            assert_eq!(slot.span(), group.span);
        }
    }

    let published = slots.clone();
    let refused = history.captures_from_slots_with_workspace(
        &mut workspace,
        haystack,
        window,
        0,
        SearchConfig::LEFTMOST,
        &mut slots,
        SearchLimits {
            max_state_visits: 0,
            ..limits
        },
    );
    assert!(matches!(
        refused,
        Err(SearchError::Resource {
            kind: ResourceKind::StateVisits,
            ..
        })
    ));
    assert_eq!(slots, published, "refusal must not publish partial slots");
}

#[test]
fn admitted_history_workspace_closes_nullable_empty_and_malformed_searches() {
    let ast = Ast::Byte(b'a').repeat(0, None, Greed::Greedy).capture(1);
    let history = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
    let limits = SearchLimits::default();
    let mut workspace = history
        .prepare_exact_workspace(3, limits)
        .expect("nullable retained history workspace");
    assert_eq!(
        workspace.usage().algorithm_version,
        HISTORY_EXACT_WORKSPACE_ALGORITHM_VERSION
    );
    assert_eq!(
        workspace.usage().accounting_version,
        HISTORY_EXACT_WORKSPACE_ACCOUNTING_VERSION
    );
    let mut slots = vec![CaptureGroupSlot::UNMATCHED; 2];

    for haystack in [b"".as_slice(), b"bbb", b"aaa", b"\xFF"] {
        let window = Window::all(haystack);
        let prospective = history
            .search_prospective(window, 0)
            .expect("source-independent history prospective");
        let exact = SearchLimits {
            max_state_visits: prospective.state_visits,
            max_history_nodes: prospective.history_nodes,
            max_history_walk: prospective.history_walk,
            max_scratch_bytes: prospective.scratch_bytes,
            ..limits
        };
        let expected = history
            .captures_from_with_config(haystack, window, 0, SearchConfig::LEFTMOST, exact)
            .expect("allocating exact-limit history search");
        let actual = history
            .captures_from_slots_with_workspace(
                &mut workspace,
                haystack,
                window,
                0,
                SearchConfig::LEFTMOST,
                &mut slots,
                exact,
            )
            .expect("retained exact-limit history search");
        assert_eq!(actual.report, expected.report);
        let expected = expected
            .captures
            .expect("nullable expression always matches");
        for (slot, group) in slots.iter().zip(&expected.groups) {
            assert_eq!(slot.span(), group.span);
        }
    }

    for (haystack, span, expected) in [
        (b"\xFF".as_slice(), Span { start: 0, end: 1 }, None),
        (
            b"".as_slice(),
            Span { start: 0, end: 0 },
            Some(Span { start: 0, end: 0 }),
        ),
        (
            b"aaa",
            Span { start: 0, end: 3 },
            Some(Span { start: 0, end: 3 }),
        ),
    ] {
        let outcome = history
            .captures_exact_slots_with_workspace(
                &mut workspace,
                haystack,
                Window::all(haystack),
                span,
                &mut slots,
            )
            .expect("retained exact-span history replay");
        assert_eq!(outcome.matched, expected.is_some());
        assert_eq!(slots[0].span(), expected);
        assert_eq!(slots[1].span(), expected);
    }

    let haystack = b"aaa";
    let window = Window::all(haystack);
    let prospective = history.search_prospective(window, 0).unwrap();
    let exact = SearchLimits {
        max_state_visits: prospective.state_visits,
        max_history_nodes: prospective.history_nodes,
        max_history_walk: prospective.history_walk,
        max_scratch_bytes: prospective.scratch_bytes,
        ..limits
    };
    let published = slots.clone();
    for (kind, one_below) in [
        (
            ResourceKind::StateVisits,
            SearchLimits {
                max_state_visits: prospective.state_visits - 1,
                ..exact
            },
        ),
        (
            ResourceKind::HistoryNodes,
            SearchLimits {
                max_history_nodes: prospective.history_nodes - 1,
                ..exact
            },
        ),
        (
            ResourceKind::HistoryWalk,
            SearchLimits {
                max_history_walk: prospective.history_walk - 1,
                ..exact
            },
        ),
    ] {
        let refused = history.captures_from_slots_with_workspace(
            &mut workspace,
            haystack,
            window,
            0,
            SearchConfig::LEFTMOST,
            &mut slots,
            one_below,
        );
        assert!(matches!(
            refused,
            Err(SearchError::Resource {
                kind: actual,
                ..
            }) if actual == kind
        ));
        assert_eq!(
            slots, published,
            "admission refusal published partial slots"
        );
    }
}

#[test]
fn history_admission_charges_only_save_states_per_boundary() {
    let ast = Ast::Byte(b'a').repeat(50, Some(50), Greed::Greedy);
    let history = HistoryRegex::compile(&ast, BuildLimits::default()).unwrap();
    let limits = SearchLimits {
        max_history_nodes: 4,
        max_history_walk: 4,
        ..SearchLimits::default()
    };
    let outcome = history
        .captures_from_with_config(b"x", Window::all(b"x"), 0, SearchConfig::LEFTMOST, limits)
        .expect("two group-zero Save states over two boundaries fit four nodes");
    assert!(outcome.captures.is_none());
    assert!(outcome.report.history_nodes <= 4);

    let one_node_short = SearchLimits {
        max_history_nodes: 3,
        max_history_walk: 4,
        ..SearchLimits::default()
    };
    assert!(matches!(
        history.captures_from_with_config(
            b"x",
            Window::all(b"x"),
            0,
            SearchConfig::LEFTMOST,
            one_node_short
        ),
        Err(SearchError::Resource {
            kind: ResourceKind::HistoryNodes,
            required: 4,
            limit: 3,
        })
    ));
}

#[test]
fn aggregate_resource_dimensions_refuse_explicitly() {
    let ast = Ast::Byte(b'a').capture(1);
    let (inline, _) = pair(&ast);
    let no_searches = AggregateLimits {
        max_searches: 0,
        ..AggregateLimits::default()
    };
    assert!(matches!(
        inline.captures_iter(b"a", Window::all(b"a"), no_searches),
        Err(SearchError::Resource {
            kind: ResourceKind::Searches,
            ..
        })
    ));
    let no_results = AggregateLimits {
        max_results: 0,
        ..AggregateLimits::default()
    };
    assert!(matches!(
        inline.captures_iter(b"a", Window::all(b"a"), no_results),
        Err(SearchError::Resource {
            kind: ResourceKind::Results,
            ..
        })
    ));
}

#[test]
fn persistent_reducer_counts_participation_without_retaining_winners() {
    let ast = Ast::alt([Ast::Byte(b'a').capture(2), Ast::Byte(b'b').capture(3)])
        .capture(1)
        .repeat(1, None, Greed::Greedy);
    let pattern = render(&ast);
    let expected_records = reference_iter(&pattern, b"abba cab", Window::all(b"abba cab"));
    let expected = expected_records
        .iter()
        .flat_map(|record| &record.groups)
        .filter(|group| group.span.is_some())
        .count();
    let (_, history) = pair(&ast);
    let outcome = history
        .count_captures_nonempty(
            b"abba cab",
            Window::all(b"abba cab"),
            AggregateLimits::default(),
        )
        .unwrap();
    assert_eq!(outcome.count, expected);
    assert_eq!(outcome.matches, expected_records.len());
    assert!(outcome.total_history_nodes <= outcome.total_state_visits);
    assert!(outcome.total_history_walk <= outcome.total_history_nodes);
}

#[test]
fn persistent_reducer_exposes_group_event_and_empty_match_boundaries() {
    let (_, history) = pair(&Ast::Byte(b'a').capture(1));
    let no_events = AggregateLimits {
        max_capture_events: 0,
        ..AggregateLimits::default()
    };
    assert!(matches!(
        history.count_captures_nonempty(b"a", Window::all(b"a"), no_events),
        Err(SearchError::Resource {
            kind: ResourceKind::CaptureEvents,
            ..
        })
    ));

    let (_, empty) = pair(&Ast::Empty.capture(1));
    assert_eq!(
        empty.count_captures_nonempty(b"a", Window::all(b"a"), AggregateLimits::default()),
        Err(SearchError::EmptyMatch)
    );
}

#[test]
fn re2_profile_is_typed_and_cannot_be_claimed_before_oracle_gate() {
    assert!(matches!(
        Program::compile_for(
            &Ast::Byte(b'a'),
            CaptureProfile::Re2Commit972a15Pending,
            BuildLimits::default(),
        ),
        Err(BuildError::ProfilePending(
            CaptureProfile::Re2Commit972a15Pending
        ))
    ));
}

#[test]
fn work_growth_obeys_linear_single_search_certificate() {
    let ast = Ast::alt([
        Ast::Byte(b'a').capture(1),
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]).capture(2),
    ])
    .repeat(0, None, Greed::Greedy);
    let (inline, history) = pair(&ast);
    let mut previous_inline = None;
    let mut previous_history = None;
    for length in [16_usize, 32, 64, 128, 256] {
        let haystack = vec![b'a'; length];
        let inline_work = inline
            .captures(&haystack, Window::all(&haystack), SearchLimits::default())
            .unwrap()
            .report
            .state_visits;
        let history_work = history
            .captures(&haystack, Window::all(&haystack), SearchLimits::default())
            .unwrap()
            .report
            .state_visits;
        if let Some(previous) = previous_inline {
            assert!(inline_work <= previous * 3);
        }
        if let Some(previous) = previous_history {
            assert!(history_work <= previous * 3);
        }
        previous_inline = Some(inline_work);
        previous_history = Some(history_work);
    }
}

fn generated_bases() -> Vec<Ast> {
    let atoms = vec![Ast::Empty, Ast::Byte(b'a'), Ast::Byte(b'b')];
    let mut bases = atoms.clone();
    for left in &atoms {
        for right in &atoms {
            bases.push(Ast::concat([left.clone(), right.clone()]));
            bases.push(Ast::alt([left.clone(), right.clone()]));
        }
    }
    for atom in &atoms {
        bases.push(atom.clone().repeat(0, Some(1), Greed::Greedy));
        bases.push(atom.clone().repeat(0, Some(1), Greed::Lazy));
        bases.push(atom.clone().repeat(0, None, Greed::Greedy));
        bases.push(atom.clone().repeat(0, None, Greed::Lazy));
        bases.push(atom.clone().repeat(1, None, Greed::Greedy));
        bases.push(atom.clone().repeat(0, Some(2), Greed::Greedy));
    }
    assert_eq!(bases.len(), 39);
    bases
}

fn wrappers(base: &Ast) -> Vec<Ast> {
    vec![
        base.clone().capture(1),
        Ast::concat([
            base.clone().capture(1).repeat(0, Some(1), Greed::Greedy),
            Ast::Byte(b'b').capture(2).repeat(0, Some(1), Greed::Lazy),
        ]),
        base.clone().capture(1).repeat(0, Some(2), Greed::Greedy),
        Ast::alt([base.clone().capture(2), Ast::Byte(b'b').capture(3)]).capture(1),
        base.clone().named(1, "named"),
        base.clone()
            .capture(2)
            .repeat(0, Some(1), Greed::Lazy)
            .capture(1),
    ]
}

fn generated_haystacks(max_len: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    for length in 0..=max_len {
        let count = 1_usize << length;
        for bits in 0..count {
            let mut haystack = Vec::with_capacity(length);
            for bit in 0..length {
                let byte = if bits & (1_usize << bit) == 0 {
                    b'a'
                } else {
                    b'b'
                };
                haystack.push(byte);
            }
            result.push(haystack);
        }
    }
    result
}

fn render(ast: &Ast) -> String {
    match ast {
        Ast::Empty => "(?:)".to_owned(),
        Ast::Byte(byte) => match byte {
            b'a' | b'b' | b'x' | b'y' => char::from(*byte).to_string(),
            _ => format!(r"(?-u:\x{byte:02X})"),
        },
        Ast::Class(ranges) => {
            let mut source = "(?-u:[".to_owned();
            for &(start, end) in ranges {
                if start == end {
                    write!(source, r"\x{start:02X}").unwrap();
                } else {
                    write!(source, r"\x{start:02X}-\x{end:02X}").unwrap();
                }
            }
            source.push_str("])");
            source
        }
        Ast::Concat(children) => {
            let body = children.iter().map(render).collect::<String>();
            format!("(?:{body})")
        }
        Ast::Alt(children) => {
            let body = children.iter().map(render).collect::<Vec<_>>().join("|");
            format!("(?:{body})")
        }
        Ast::Repeat {
            child,
            min,
            max,
            greed,
        } => {
            let quantifier = match (*min, *max) {
                (0, Some(1)) => "?".to_owned(),
                (0, None) => "*".to_owned(),
                (1, None) => "+".to_owned(),
                (minimum, Some(maximum)) if minimum == maximum => format!("{{{minimum}}}"),
                (minimum, Some(maximum)) => format!("{{{minimum},{maximum}}}"),
                (minimum, None) => format!("{{{minimum},}}"),
            };
            let lazy = if *greed == Greed::Lazy { "?" } else { "" };
            format!("(?:{}){quantifier}{lazy}", render(child))
        }
        Ast::Capture {
            name: Some(name),
            child,
            ..
        } => {
            format!("(?P<{name}>{})", render(child))
        }
        Ast::Capture {
            name: None, child, ..
        } => format!("({})", render(child)),
        Ast::Start => r"\A".to_owned(),
        Ast::End => r"\z".to_owned(),
        Ast::Assert(assertion) => match assertion {
            Assertion::Start => r"\A",
            Assertion::End => r"\z",
            Assertion::StartLf => r"(?m:^)",
            Assertion::EndLf => r"(?m:$)",
            Assertion::StartLine(_) | Assertion::EndLine(_) => {
                panic!("parameterized line assertions require a configured reference builder")
            }
            Assertion::StartCrlf => r"(?Rm:^)",
            Assertion::EndCrlf => r"(?Rm:$)",
            Assertion::WordAscii => r"(?-u:\b)",
            Assertion::WordAsciiNegate => r"(?-u:\B)",
            Assertion::WordStartAscii => r"(?-u:\b{start})",
            Assertion::WordEndAscii => r"(?-u:\b{end})",
            Assertion::WordStartHalfAscii => r"(?-u:\b{start-half})",
            Assertion::WordEndHalfAscii => r"(?-u:\b{end-half})",
            Assertion::WordUnicode => r"\b",
            Assertion::WordUnicodeNegate => r"\B",
            Assertion::WordStartUnicode => r"\b{start}",
            Assertion::WordEndUnicode => r"\b{end}",
            Assertion::WordStartHalfUnicode => r"\b{start-half}",
            Assertion::WordEndHalfUnicode => r"\b{end-half}",
        }
        .to_owned(),
    }
}
