#![allow(
    clippy::arithmetic_side_effects,
    reason = "bounded test-domain enumeration uses proven tiny integers"
)]

use std::fmt::Write as _;
use std::sync::Arc;

use fre_capture_lab::{
    Assertion, Ast, BuildLimits, CaptureGroupSlot, Greed, HistoryRegex, OnePassCaptureBuildError,
    OnePassCaptureBuildLimits, OnePassCaptureBuildResource, OnePassCapturePlan,
    OnePassCaptureRefusal, Program, ResourceKind, SearchConfig, SearchError, SearchLimits, Span,
    Window,
};
use regex_automata::{Anchored, Input, meta, util::syntax};

fn pair(ast: &Ast) -> (HistoryRegex, OnePassCapturePlan) {
    let program = Arc::new(Program::compile(ast, BuildLimits::default()).expect("program build"));
    let history = HistoryRegex::from_program(Arc::clone(&program));
    let onepass =
        OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default())
            .expect("one-pass build");
    (history, onepass)
}

fn haystacks(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
    fn extend(output: &mut Vec<Vec<u8>>, alphabet: &[u8], current: &mut Vec<u8>, left: usize) {
        output.push(current.clone());
        if left == 0 {
            return;
        }
        for &byte in alphabet {
            current.push(byte);
            extend(output, alphabet, current, left - 1);
            current.pop();
        }
    }

    let mut output = Vec::new();
    extend(&mut output, alphabet, &mut Vec::new(), max_len);
    output
}

fn assert_all_exact_spans(ast: &Ast, inputs: &[Vec<u8>]) {
    let (history, onepass) = pair(ast);
    let mut workspace = onepass
        .create_workspace(SearchLimits::default())
        .expect("workspace");
    for haystack in inputs {
        for window_start in 0..=haystack.len() {
            for window_end in window_start..=haystack.len() {
                let window = Window {
                    start: window_start,
                    end: window_end,
                };
                for start in window_start..=window_end {
                    for end in start..=window_end {
                        let span = Span { start, end };
                        let expected = history
                            .captures_exact(haystack, window, span, SearchLimits::default())
                            .unwrap_or_else(|error| {
                                panic!(
                                    "history failed for ast={ast:?}, haystack={haystack:?}, \
                                     window={window:?}, span={span:?}: {error:?}"
                                )
                            });
                        let got = onepass
                            .captures_exact(
                                &mut workspace,
                                haystack,
                                window,
                                span,
                                SearchLimits::default(),
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "one-pass failed for ast={ast:?}, haystack={haystack:?}, \
                                     window={window:?}, span={span:?}: {error:?}"
                                )
                            });
                        assert_eq!(
                            expected.captures, got.captures,
                            "ast={ast:?}, haystack={haystack:?}, window={window:?}, span={span:?}"
                        );
                        assert_eq!(got.report.history_nodes, 0);
                        assert_eq!(got.report.history_walk, 0);
                    }
                }
            }
        }
    }
}

fn assert_all_anchored_searches(ast: &Ast, inputs: &[Vec<u8>]) {
    assert_all_anchored_searches_with_terminator(ast, inputs, b'\n');
}

fn assert_all_anchored_searches_with_terminator(
    ast: &Ast,
    inputs: &[Vec<u8>],
    line_terminator: u8,
) {
    let source = render(ast);
    let reference = meta::Regex::builder()
        .configure(
            meta::Regex::config()
                .utf8_empty(false)
                .line_terminator(line_terminator),
        )
        .syntax(
            syntax::Config::default()
                .utf8(false)
                .line_terminator(line_terminator),
        )
        .build(&source)
        .unwrap_or_else(|error| panic!("Rust build failed for {source:?}: {error}"));
    let (history, onepass) = pair(ast);
    let mut workspace = onepass
        .create_search_workspace(SearchLimits::default())
        .expect("search workspace");
    let mut groups = vec![CaptureGroupSlot::UNMATCHED; history.program().group_len()];
    for haystack in inputs {
        for window_start in 0..=haystack.len() {
            for window_end in window_start..=haystack.len() {
                let window = Window {
                    start: window_start,
                    end: window_end,
                };
                for from in window_start..=window_end {
                    let expected = history
                        .captures_from_with_config(
                            haystack,
                            window,
                            from,
                            SearchConfig::LEFTMOST.anchored(true),
                            SearchLimits::default(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "history failed for ast={ast:?}, haystack={haystack:?}, \
                                 window={window:?}, from={from}: {error:?}"
                            )
                        });
                    let got = onepass
                        .captures_anchored_slots(
                            &mut workspace,
                            haystack,
                            window,
                            from,
                            &mut groups,
                            SearchLimits::default(),
                        )
                        .unwrap_or_else(|error| {
                            panic!(
                                "one-pass failed for ast={ast:?}, haystack={haystack:?}, \
                                 window={window:?}, from={from}: {error:?}"
                            )
                        });
                    let mut inline_groups =
                        vec![CaptureGroupSlot::UNMATCHED; history.program().group_len()];
                    let inline = onepass
                        .try_captures_anchored_inline(
                            haystack,
                            window,
                            from,
                            &mut inline_groups,
                            SearchLimits::default(),
                        )
                        .expect("inline anchored search")
                        .expect("small schema must fit inline search storage");
                    assert_eq!(got.matched, expected.captures.is_some());
                    assert_eq!(inline.matched, got.matched);
                    assert_eq!(inline_groups, groups);
                    let mut rust = reference.create_captures();
                    reference.captures(
                        Input::new(haystack)
                            .span(from..window_end)
                            .anchored(Anchored::Yes),
                        &mut rust,
                    );
                    assert_eq!(
                        got.matched,
                        rust.is_match(),
                        "Rust match mismatch for source={source:?}, haystack={haystack:?}, \
                         window={window:?}, from={from}"
                    );
                    if got.matched {
                        assert_eq!(groups.len(), rust.group_len());
                        for (index, slot) in groups.iter().enumerate() {
                            let expected_span = rust.get_group(index).map(|matched| Span {
                                start: matched.start,
                                end: matched.end,
                            });
                            assert_eq!(
                                slot.span(),
                                expected_span,
                                "Rust capture {index} mismatch for source={source:?}, \
                                 haystack={haystack:?}, window={window:?}, from={from}"
                            );
                        }
                    }
                    if let Some(expected) = expected.captures {
                        assert_eq!(groups.len(), expected.groups.len());
                        for (slot, group) in groups.iter().zip(expected.groups) {
                            assert_eq!(slot.span(), group.span);
                        }
                    } else {
                        assert!(
                            groups
                                .iter()
                                .all(|slot| *slot == CaptureGroupSlot::UNMATCHED)
                        );
                    }
                    assert_eq!(got.report.history_nodes, 0);
                    assert_eq!(got.report.history_walk, 0);
                    assert_eq!(got.report.starts_injected, 1);
                }
            }
        }
    }
}

fn render(ast: &Ast) -> String {
    match ast {
        Ast::Empty => "(?:)".to_owned(),
        Ast::Byte(byte) => format!(r"(?-u:\x{byte:02X})"),
        Ast::Class(ranges) => {
            let mut source = "(?-u:[".to_owned();
            for &(start, end) in ranges {
                if start == end {
                    write!(source, r"\x{start:02X}").expect("write to String");
                } else {
                    write!(source, r"\x{start:02X}-\x{end:02X}").expect("write to String");
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
        } => format!("(?P<{name}>{})", render(child)),
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
            Assertion::StartLine(_) => r"(?m:^)",
            Assertion::EndLine(_) => r"(?m:$)",
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

fn assert_exact_suffixes_against_rust(ast: &Ast, inputs: &[Vec<u8>]) {
    // The appended absolute-end assertion forces Rust's ordinary anchored
    // capture search to consume the complete requested suffix. This gives an
    // independent exact-span oracle even for lazy repetitions, while Input's
    // nonzero span start preserves original-haystack look-around context.
    let source = format!("(?:{})\\z", render(ast));
    let reference = meta::Regex::builder()
        .configure(meta::Regex::config().utf8_empty(false))
        .syntax(syntax::Config::default().utf8(false))
        .build(&source)
        .unwrap_or_else(|error| panic!("Rust build failed for {source:?}: {error}"));
    let program = Arc::new(Program::compile(ast, BuildLimits::default()).expect("program"));
    let plan = OnePassCapturePlan::try_from_program(
        Arc::clone(&program),
        OnePassCaptureBuildLimits::default(),
    )
    .expect("one-pass plan");
    let mut workspace = plan
        .create_workspace(SearchLimits::default())
        .expect("workspace");
    for haystack in inputs {
        for start in 0..=haystack.len() {
            let span = Span {
                start,
                end: haystack.len(),
            };
            let mut expected = reference.create_captures();
            reference.captures(
                Input::new(haystack)
                    .span(start..haystack.len())
                    .anchored(Anchored::Yes),
                &mut expected,
            );
            let got = plan
                .captures_exact(
                    &mut workspace,
                    haystack,
                    Window::all(haystack),
                    span,
                    SearchLimits::default(),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "one-pass failed for source={source:?}, haystack={haystack:?}, \
                         span={span:?}: {error:?}"
                    )
                });
            assert_eq!(
                expected.is_match(),
                got.captures.is_some(),
                "match mismatch for source={source:?}, haystack={haystack:?}, span={span:?}"
            );
            let Some(got) = got.captures else {
                continue;
            };
            assert_eq!(got.overall(), Some(span));
            assert_eq!(expected.group_len(), got.groups.len());
            for index in 1..expected.group_len() {
                let expected_span = expected.get_group(index).map(|matched| Span {
                    start: matched.start,
                    end: matched.end,
                });
                assert_eq!(
                    expected_span, got.groups[index].span,
                    "capture {index} mismatch for source={source:?}, haystack={haystack:?}, \
                     span={span:?}"
                );
            }
        }
    }
}

#[test]
fn generated_one_pass_graphs_match_persistent_history_on_every_exact_span() {
    let mut asts = vec![
        Ast::Empty,
        Ast::Byte(b'a'),
        Ast::Byte(b'a').capture(1),
        Ast::alt([Ast::Byte(b'a'), Ast::Byte(b'b')]),
        Ast::concat([Ast::Byte(b'a'), Ast::Byte(b'b')]),
        Ast::concat([
            Ast::Byte(b'a').repeat(0, None, Greed::Greedy),
            Ast::Byte(b'b'),
        ]),
        Ast::concat([
            Ast::Byte(b'a').repeat(0, None, Greed::Lazy),
            Ast::Byte(b'b'),
        ]),
        Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Greedy),
        Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Lazy),
        Ast::alt([Ast::Empty, Ast::Byte(b'a')]),
        Ast::alt([Ast::Byte(b'a'), Ast::Empty]),
        Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'b').capture(2)]),
        Ast::Byte(b'a')
            .capture(2)
            .repeat(1, None, Greed::Greedy)
            .capture(1),
    ];
    for greed in [Greed::Greedy, Greed::Lazy] {
        for first in [b'a', b'b'] {
            let second = if first == b'a' { b'b' } else { b'a' };
            asts.push(Ast::concat([
                Ast::Byte(first).repeat(0, Some(2), greed),
                Ast::Byte(second),
            ]));
            asts.push(Ast::alt([
                Ast::Byte(first).capture(1),
                Ast::concat([Ast::Byte(second), Ast::Byte(first)]).capture(2),
            ]));
        }
    }
    let atoms = [
        Ast::Empty,
        Ast::Byte(b'a'),
        Ast::Byte(b'b'),
        Ast::Class(vec![(b'a', b'b')]),
    ];
    for atom in &atoms {
        for greed in [Greed::Greedy, Greed::Lazy] {
            for maximum in [Some(1), Some(2), None] {
                asts.push(atom.clone().repeat(0, maximum, greed).capture(1));
            }
        }
    }
    for left in &atoms {
        for right in &atoms {
            asts.push(Ast::concat([left.clone(), right.clone()]).capture(1));
            asts.push(Ast::alt([left.clone(), right.clone()]).capture(1));
        }
    }
    let inputs = haystacks(b"abx", 3);
    let mut admitted = 0_usize;
    for ast in asts {
        let program = Arc::new(Program::compile(&ast, BuildLimits::default()).expect("program"));
        if OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default())
            .is_ok()
        {
            admitted += 1;
            assert_all_exact_spans(&ast, &inputs);
            assert_exact_suffixes_against_rust(&ast, &inputs);
            assert_all_anchored_searches(&ast, &inputs);
        }
    }
    assert!(
        admitted >= 50,
        "generated admission unexpectedly narrow: {admitted}"
    );
}

#[test]
fn anchored_leftmost_search_matches_history_for_priority_and_assertion_graphs() {
    let asts = [
        Ast::Empty,
        Ast::Byte(b'a'),
        Ast::alt([Ast::Byte(b'a'), Ast::Byte(b'b')]),
        Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Greedy),
        Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Lazy),
        Ast::concat([
            Ast::Byte(b'a').repeat(0, Some(2), Greed::Greedy),
            Ast::Byte(b'b').capture(1),
        ]),
        Ast::concat([
            Ast::Byte(b'a').repeat(0, Some(2), Greed::Lazy),
            Ast::Byte(b'b').capture(1),
        ]),
        Ast::concat([
            Ast::Assert(Assertion::WordAscii),
            Ast::Byte(b'a').capture(1),
        ]),
        Ast::concat([
            Ast::Byte(b'a').capture(1),
            Ast::Assert(Assertion::WordEndAscii),
        ]),
    ];
    let inputs = haystacks(b" ab", 3);
    for ast in asts {
        // This also reconstructs a fresh v3 plan for the incumbent exact
        // oracle above, guarding target-row metadata decoding in both APIs.
        assert_all_anchored_searches(&ast, &inputs);
        assert_all_exact_spans(&ast, &inputs);
    }
}

#[test]
fn anchored_search_matches_rust_for_line_unicode_and_nullable_priority_edges() {
    let malformed = vec![
        Vec::new(),
        b"a".to_vec(),
        b"\r\na\r\n".to_vec(),
        vec![0xFF, b'a'],
        vec![b'a', 0xFF],
        vec![0xC3, b'a', 0x80],
    ];
    for ast in [
        Ast::concat([
            Ast::Assert(Assertion::StartCrlf),
            Ast::Byte(b'a').capture(1),
        ]),
        Ast::concat([Ast::Byte(b'a').capture(1), Ast::Assert(Assertion::EndCrlf)]),
        Ast::concat([
            Ast::Assert(Assertion::WordUnicode),
            Ast::Byte(b'a').capture(1),
        ]),
        Ast::concat([
            Ast::Byte(b'a').capture(1),
            Ast::Assert(Assertion::WordEndUnicode),
        ]),
    ] {
        assert_all_anchored_searches(&ast, &malformed);
    }

    let custom_inputs = vec![
        Vec::new(),
        b"a".to_vec(),
        b"xa".to_vec(),
        b"ax".to_vec(),
        b"xax".to_vec(),
    ];
    for ast in [
        Ast::concat([
            Ast::Assert(Assertion::StartLine(b'x')),
            Ast::Byte(b'a').capture(1),
        ]),
        Ast::concat([
            Ast::Byte(b'a').capture(1),
            Ast::Assert(Assertion::EndLine(b'x')),
        ]),
    ] {
        assert_all_anchored_searches_with_terminator(&ast, &custom_inputs, b'x');
    }

    let priority_inputs = haystacks(b"ab", 4);
    for greed in [Greed::Greedy, Greed::Lazy] {
        for ast in [
            Ast::alt([
                Ast::concat([
                    Ast::Byte(b'a').repeat(0, Some(2), greed).capture(1),
                    Ast::Byte(b'b'),
                ]),
                Ast::Empty,
            ]),
            Ast::alt([
                Ast::Empty,
                Ast::Byte(b'a').repeat(1, Some(2), greed).capture(1),
            ]),
        ] {
            assert_all_anchored_searches(&ast, &priority_inputs);
        }
    }
}

#[test]
fn anchored_search_rolls_back_capture_slots_after_a_partial_greedy_extension() {
    let ast = Ast::concat([
        Ast::Byte(b'a').capture(1).repeat(0, None, Greed::Greedy),
        Ast::concat([Ast::Byte(b'b'), Ast::Byte(b'c').capture(2), Ast::Byte(b'd')]).repeat(
            0,
            Some(1),
            Greed::Greedy,
        ),
    ]);
    let (history, plan) = pair(&ast);
    assert!(
        !plan.post_accept_live_tags_stable(),
        "a capture write reachable after acceptance must retain the general snapshot path"
    );
    let haystack = b"aabcX";
    let expected = history
        .captures_with_config(
            haystack,
            Window::all(haystack),
            SearchConfig::LEFTMOST.anchored(true),
            SearchLimits::default(),
        )
        .expect("history rollback oracle")
        .captures
        .expect("earlier accepting match");
    let mut workspace = plan
        .create_search_workspace(SearchLimits::default())
        .expect("search workspace");
    let mut groups = vec![CaptureGroupSlot::UNMATCHED; history.program().group_len()];
    let got = plan
        .captures_anchored_slots(
            &mut workspace,
            haystack,
            Window::all(haystack),
            0,
            &mut groups,
            SearchLimits::default(),
        )
        .expect("one-pass rollback search");
    assert!(got.matched);
    for (slot, group) in groups.iter().zip(expected.groups) {
        assert_eq!(slot.span(), group.span);
    }
    assert_eq!(groups[0].span(), Some(Span { start: 0, end: 2 }));
    assert_eq!(groups[2], CaptureGroupSlot::UNMATCHED);
}

#[test]
fn certified_post_accept_stability_defers_one_snapshot_and_preserves_assertions() {
    let ast = Ast::concat([
        Ast::Byte(b'a').capture(1),
        Ast::Byte(b'b').repeat(1, None, Greed::Greedy),
        Ast::Assert(Assertion::WordEndAscii),
    ]);
    let (history, plan) = pair(&ast);
    assert!(plan.post_accept_live_tags_stable());

    for haystack in [b"ab!".as_slice(), b"abbb!", b"abbbx", b"abbb"] {
        let expected = history
            .captures_with_config(
                haystack,
                Window::all(haystack),
                SearchConfig::LEFTMOST.anchored(true),
                SearchLimits::default(),
            )
            .expect("history stable-accept oracle");
        let mut workspace = plan
            .create_search_workspace(SearchLimits::default())
            .expect("stable-accept workspace");
        let mut groups = vec![CaptureGroupSlot::UNMATCHED; history.program().group_len()];
        let got = plan
            .captures_anchored_slots(
                &mut workspace,
                haystack,
                Window::all(haystack),
                0,
                &mut groups,
                SearchLimits::default(),
            )
            .expect("stable-accept search");
        assert_eq!(got.matched, expected.captures.is_some(), "{haystack:?}");
        if let Some(expected) = expected.captures {
            for (slot, group) in groups.iter().zip(expected.groups) {
                assert_eq!(slot.span(), group.span, "{haystack:?}");
            }
            let overall = groups[0].span().expect("stable overall span");
            let mut exact_workspace = plan
                .create_workspace(SearchLimits::default())
                .expect("stable exact workspace");
            let exact = plan
                .captures_exact(
                    &mut exact_workspace,
                    haystack,
                    Window::all(haystack),
                    overall,
                    SearchLimits::default(),
                )
                .expect("stable exact replay");
            assert!(exact.captures.is_some());
            assert_eq!(
                got.report.slot_copies,
                exact.report.slot_copies + plan.capture_slot_count(),
                "the stable path performs exactly one complete candidate snapshot"
            );
        } else {
            assert!(groups.iter().all(|group| *group == CaptureGroupSlot::UNMATCHED));
        }
    }
}

#[test]
fn anchored_search_limits_workspace_identity_and_output_transaction_close() {
    let ast = Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Greedy);
    let program = Arc::new(Program::compile(&ast, BuildLimits::default()).expect("program"));
    let first = OnePassCapturePlan::try_from_program(
        Arc::clone(&program),
        OnePassCaptureBuildLimits::default(),
    )
    .expect("first plan");
    let second =
        OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default())
            .expect("second plan");
    let mut workspace = first
        .create_search_workspace(SearchLimits::default())
        .expect("search workspace");
    let haystack = b"aaa";
    let window = Window::all(haystack);
    let group_count = 2_usize;
    let slot_count = group_count * 2;
    let length = haystack.len();
    let boundaries = length + 1;
    let action_boundaries = length + boundaries;
    let required_state_visits =
        boundaries + action_boundaries * first.build_report().max_action_assertions;
    let required_slot_copies =
        boundaries * slot_count + action_boundaries * first.build_report().max_action_tag_actions;
    let exact_scratch = workspace.scratch_bytes();
    let exact = SearchLimits {
        max_state_visits: required_state_visits,
        max_slot_copies: required_slot_copies,
        max_scratch_bytes: exact_scratch,
        ..SearchLimits::default()
    };
    let mut output = vec![CaptureGroupSlot::UNMATCHED; group_count];
    assert!(
        first
            .captures_anchored_slots(&mut workspace, haystack, window, 0, &mut output, exact,)
            .expect("exact anchored limits")
            .matched
    );
    let unchanged = output.clone();

    for (limits, expected) in [
        (
            SearchLimits {
                max_state_visits: required_state_visits - 1,
                ..exact
            },
            SearchError::Resource {
                kind: ResourceKind::StateVisits,
                required: required_state_visits,
                limit: required_state_visits - 1,
            },
        ),
        (
            SearchLimits {
                max_slot_copies: required_slot_copies - 1,
                ..exact
            },
            SearchError::Resource {
                kind: ResourceKind::SlotCopies,
                required: required_slot_copies,
                limit: required_slot_copies - 1,
            },
        ),
        (
            SearchLimits {
                max_scratch_bytes: exact_scratch - 1,
                ..exact
            },
            SearchError::Resource {
                kind: ResourceKind::ScratchBytes,
                required: exact_scratch,
                limit: exact_scratch - 1,
            },
        ),
    ] {
        assert_eq!(
            first
                .captures_anchored_slots(&mut workspace, haystack, window, 0, &mut output, limits,)
                .unwrap_err(),
            expected
        );
        assert_eq!(output, unchanged);
    }
    assert_eq!(
        second
            .captures_anchored_slots(
                &mut workspace,
                haystack,
                window,
                0,
                &mut output,
                SearchLimits::default(),
            )
            .unwrap_err(),
        SearchError::InvalidProgram
    );
    assert_eq!(output, unchanged);

    let inline_scratch = core::mem::size_of::<[[usize; 32]; 2]>();
    assert!(
        first
            .try_captures_anchored_inline(
                haystack,
                window,
                0,
                &mut output,
                SearchLimits {
                    max_scratch_bytes: inline_scratch,
                    ..exact
                },
            )
            .expect("exact inline scratch")
            .expect("small inline schema")
            .matched
    );
    let inline_unchanged = output.clone();
    assert!(
        first
            .try_captures_anchored_inline(
                haystack,
                window,
                0,
                &mut output,
                SearchLimits {
                    max_scratch_bytes: inline_scratch - 1,
                    ..exact
                },
            )
            .expect("inline scratch refusal")
            .is_none()
    );
    assert_eq!(output, inline_unchanged);

    let group_stack_bytes = 16 * core::mem::size_of::<CaptureGroupSlot>();
    let combined_scratch = inline_scratch + group_stack_bytes;
    let admitted_limits = SearchLimits {
        max_scratch_bytes: combined_scratch,
        ..exact
    };
    let owner = first.owner_seal();
    let admission = owner
        .anchored_inline_admission(length, group_stack_bytes, admitted_limits)
        .expect("preadmitted inline bounds")
        .expect("small preadmitted schema");
    assert_eq!(
        admission.prospective(),
        first
            .anchored_search_prospective(length)
            .expect("ordinary anchored prospective")
    );
    assert_eq!(admission.prospective().state_visits, required_state_visits);
    assert_eq!(admission.prospective().slot_copies, required_slot_copies);
    let mut ordinary_output = vec![CaptureGroupSlot::UNMATCHED; group_count];
    let ordinary = first
        .try_captures_anchored_inline(
            haystack,
            window,
            0,
            &mut ordinary_output,
            admitted_limits,
        )
        .expect("ordinary inline execution")
        .expect("ordinary small inline schema");
    let admitted = first
        .captures_anchored_full_inline_admitted(admission, haystack, &mut output)
        .expect("preadmitted inline execution");
    assert_eq!(admitted, ordinary);
    assert_eq!(output, ordinary_output);
    let preadmitted_unchanged = output.clone();
    for (limits, expected) in [
        (
            SearchLimits {
                max_state_visits: required_state_visits - 1,
                ..admitted_limits
            },
            SearchError::Resource {
                kind: ResourceKind::StateVisits,
                required: required_state_visits,
                limit: required_state_visits - 1,
            },
        ),
        (
            SearchLimits {
                max_slot_copies: required_slot_copies - 1,
                ..admitted_limits
            },
            SearchError::Resource {
                kind: ResourceKind::SlotCopies,
                required: required_slot_copies,
                limit: required_slot_copies - 1,
            },
        ),
        (
            SearchLimits {
                max_scratch_bytes: combined_scratch - 1,
                ..admitted_limits
            },
            SearchError::Resource {
                kind: ResourceKind::ScratchBytes,
                required: combined_scratch,
                limit: combined_scratch - 1,
            },
        ),
    ] {
        assert_eq!(
            owner
                .anchored_inline_admission(length, group_stack_bytes, limits)
                .unwrap_err(),
            expected
        );
        assert_eq!(output, preadmitted_unchanged);
    }
    assert_eq!(
        second
            .captures_anchored_full_inline_admitted(admission, haystack, &mut output)
            .unwrap_err(),
        SearchError::InvalidProgram
    );
    assert_eq!(output, preadmitted_unchanged);
    assert_eq!(
        first
            .captures_anchored_full_inline_admitted(admission, b"aa", &mut output)
            .unwrap_err(),
        SearchError::InvalidProgram
    );
    assert_eq!(output, preadmitted_unchanged);
    let mut wrong_schema = [CaptureGroupSlot::UNMATCHED; 1];
    assert_eq!(
        first
            .captures_anchored_full_inline_admitted(
                admission,
                haystack,
                &mut wrong_schema,
            )
            .unwrap_err(),
        SearchError::InvalidProgram
    );
    assert_eq!(wrong_schema, [CaptureGroupSlot::UNMATCHED; 1]);
}

#[test]
fn cyclic_capture_tags_overwrite_fixed_slots_without_history() {
    let ast = Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Greedy);
    let (history, onepass) = pair(&ast);
    assert!(onepass.build_report().direct_tag_masks);
    let mut workspace = onepass
        .create_workspace(SearchLimits::default())
        .expect("workspace");
    for end in 1..=5 {
        let haystack = b"aaaaa";
        let span = Span { start: 0, end };
        let expected = history
            .captures_exact(
                haystack,
                Window::all(haystack),
                span,
                SearchLimits::default(),
            )
            .expect("history exact");
        let got = onepass
            .captures_exact(
                &mut workspace,
                haystack,
                Window::all(haystack),
                span,
                SearchLimits::default(),
            )
            .expect("one-pass exact");
        assert_eq!(expected.captures, got.captures);
        let captures = got.captures.expect("match");
        assert_eq!(
            captures.groups[1].span,
            Some(Span {
                start: end - 1,
                end
            })
        );
        assert_eq!(got.report.history_nodes, 0);
        assert_eq!(got.report.slot_copies, 2 * end + 2);
    }
}

#[test]
fn wider_or_assertion_bearing_actions_use_the_general_table_fallback() {
    let asserted = Ast::concat([
        Ast::Assert(Assertion::WordAscii),
        Ast::Byte(b'a').capture(1),
    ]);
    let (asserted_history, asserted_plan) = pair(&asserted);
    assert!(!asserted_plan.build_report().direct_tag_masks);
    let mut asserted_workspace = asserted_plan
        .create_workspace(SearchLimits::default())
        .expect("asserted workspace");
    let asserted_span = Span { start: 1, end: 2 };
    let expected = asserted_history
        .captures_exact(
            b" a",
            Window::all(b" a"),
            asserted_span,
            SearchLimits::default(),
        )
        .expect("asserted history");
    let got = asserted_plan
        .captures_exact(
            &mut asserted_workspace,
            b" a",
            Window::all(b" a"),
            asserted_span,
            SearchLimits::default(),
        )
        .expect("asserted one-pass");
    assert_eq!(expected.captures, got.captures);

    let wide = Ast::concat((1..=16).map(|index| Ast::Byte(b'a').capture(index)));
    let (wide_history, wide_plan) = pair(&wide);
    assert!(!wide_plan.build_report().direct_tag_masks);
    let mut wide_workspace = wide_plan
        .create_workspace(SearchLimits::default())
        .expect("wide workspace");
    let haystack = [b'a'; 16];
    let span = Span { start: 0, end: 16 };
    let expected = wide_history
        .captures_exact(
            &haystack,
            Window::all(&haystack),
            span,
            SearchLimits::default(),
        )
        .expect("wide history");
    let got = wide_plan
        .captures_exact(
            &mut wide_workspace,
            &haystack,
            Window::all(&haystack),
            span,
            SearchLimits::default(),
        )
        .expect("wide one-pass");
    assert_eq!(expected.captures, got.captures);
}

#[test]
fn all_assertion_variants_preserve_full_haystack_and_window_context() {
    let assertions = [
        Assertion::Start,
        Assertion::End,
        Assertion::StartLf,
        Assertion::EndLf,
        Assertion::StartLine(b'X'),
        Assertion::EndLine(b'X'),
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
    let inputs = vec![
        b"a".to_vec(),
        b"xa y".to_vec(),
        b"\na\r\n".to_vec(),
        b"XaX".to_vec(),
        "δaβ".as_bytes().to_vec(),
        vec![0xFF, b'a', 0x80],
    ];
    for assertion in assertions {
        let before = Ast::concat([Ast::Assert(assertion), Ast::Byte(b'a').capture(1)]);
        let after = Ast::concat([Ast::Byte(b'a').capture(1), Ast::Assert(assertion)]);
        assert_all_exact_spans(&before, &inputs);
        assert_all_exact_spans(&after, &inputs);
    }
}

#[test]
fn overlapping_paths_refuse_before_a_plan_is_published() {
    let ambiguous_repeat = Ast::concat([
        Ast::Byte(b'a').repeat(0, None, Greed::Greedy),
        Ast::Byte(b'a'),
    ]);
    let program = Arc::new(
        Program::compile(&ambiguous_repeat, BuildLimits::default()).expect("program build"),
    );
    assert_eq!(
        OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default(),)
            .unwrap_err(),
        OnePassCaptureBuildError::NotOnePass(OnePassCaptureRefusal::ConflictingTransition)
    );

    let capture_ambiguous = Ast::alt([Ast::Byte(b'a').capture(1), Ast::Byte(b'a').capture(2)]);
    let program = Arc::new(
        Program::compile(&capture_ambiguous, BuildLimits::default()).expect("program build"),
    );
    assert_eq!(
        OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default(),)
            .unwrap_err(),
        OnePassCaptureBuildError::NotOnePass(OnePassCaptureRefusal::ConflictingTransition)
    );
}

#[test]
fn conditional_and_unconditional_epsilon_merge_refuses_before_publication() {
    // On `xa` at span 1..2 the preferred word-boundary branch fails, but the
    // unconditional branch still permits `a`. A compiler that merely marks
    // the shared continuation as seen would publish the asserted path alone
    // and incorrectly report no match.
    let conditional_merge = Ast::concat([
        Ast::alt([Ast::Assert(Assertion::WordAscii), Ast::Empty]),
        Ast::Byte(b'a').capture(1),
    ]);
    let program = Arc::new(
        Program::compile(&conditional_merge, BuildLimits::default()).expect("program build"),
    );
    let history = HistoryRegex::from_program(Arc::clone(&program));
    assert!(
        history
            .captures_exact(
                b"xa",
                Window::all(b"xa"),
                Span { start: 1, end: 2 },
                SearchLimits::default(),
            )
            .expect("history exact")
            .captures
            .is_some()
    );
    assert_eq!(
        OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default())
            .unwrap_err(),
        OnePassCaptureBuildError::NotOnePass(OnePassCaptureRefusal::MultipleEpsilonPaths)
    );
}

#[test]
fn byte_partition_merges_noncontiguous_equivalent_bytes() {
    let ast = Ast::alt([Ast::Byte(b'a'), Ast::Byte(b'z')]);
    let (_, plan) = pair(&ast);
    assert_eq!(plan.build_report().byte_classes, 3);
    assert_eq!(
        plan.build_report().transitions,
        plan.build_report().states * plan.build_report().byte_classes
    );
}

#[test]
fn construction_state_work_and_immutable_byte_boundaries_are_exact() {
    let ast = Ast::concat([
        Ast::Byte(b'a').capture(1).repeat(0, None, Greed::Greedy),
        Ast::Byte(b'b'),
    ]);
    let program = Arc::new(Program::compile(&ast, BuildLimits::default()).expect("program build"));
    let baseline = OnePassCapturePlan::try_from_program(
        Arc::clone(&program),
        OnePassCaptureBuildLimits::default(),
    )
    .expect("baseline");
    let report = *baseline.build_report();
    assert!(baseline.post_accept_live_tags_stable());
    let stability_proof_work = report
        .states
        .checked_add(report.transitions)
        .and_then(|work| work.checked_add(1))
        .expect("stability proof work");
    let mandatory_compile_work = report
        .compile_work
        .checked_sub(stability_proof_work)
        .expect("mandatory compile work");

    let dimensions = [
        (
            OnePassCaptureBuildResource::States,
            report.states,
            OnePassCaptureBuildLimits {
                max_states: report.states,
                ..OnePassCaptureBuildLimits::default()
            },
        ),
        (
            OnePassCaptureBuildResource::CompileWork,
            mandatory_compile_work,
            OnePassCaptureBuildLimits {
                max_compile_work: mandatory_compile_work,
                ..OnePassCaptureBuildLimits::default()
            },
        ),
        (
            OnePassCaptureBuildResource::ImmutableBytes,
            report.program_bytes,
            OnePassCaptureBuildLimits {
                max_program_bytes: report.program_bytes,
                ..OnePassCaptureBuildLimits::default()
            },
        ),
    ];
    for (resource, exact, limits) in dimensions {
        let exact_plan = OnePassCapturePlan::try_from_program(Arc::clone(&program), limits)
            .unwrap_or_else(|error| panic!("exact {resource:?}={exact} failed: {error:?}"));
        if resource == OnePassCaptureBuildResource::CompileWork {
            assert_eq!(exact_plan.build_report().compile_work, mandatory_compile_work);
            assert!(!exact_plan.post_accept_live_tags_stable());
        }
        let mut one_below = limits;
        match resource {
            OnePassCaptureBuildResource::States => one_below.max_states = exact - 1,
            OnePassCaptureBuildResource::CompileWork => one_below.max_compile_work = exact - 1,
            OnePassCaptureBuildResource::ImmutableBytes => {
                one_below.max_program_bytes = exact - 1;
            }
        }
        assert!(matches!(
            OnePassCapturePlan::try_from_program(Arc::clone(&program), one_below),
            Err(OnePassCaptureBuildError::Resource {
                resource: got,
                required,
                limit,
            }) if got == resource && required > limit
        ));
    }
}

#[test]
fn accounted_construction_preserves_work_for_declined_attempts() {
    let ambiguous = Ast::concat([
        Ast::Byte(b'a').capture(1).repeat(0, None, Greed::Greedy),
        Ast::Byte(b'a').capture(2),
    ]);
    let ambiguous = Arc::new(
        Program::compile(&ambiguous, BuildLimits::default()).expect("ambiguous program build"),
    );
    let declined = OnePassCapturePlan::try_from_program_accounted(
        ambiguous,
        OnePassCaptureBuildLimits::default(),
    )
    .expect_err("ambiguous graph must decline");
    assert!(matches!(
        declined.source,
        OnePassCaptureBuildError::NotOnePass(_)
    ));
    assert!(declined.compile_work > 0);

    let eligible = Ast::concat([
        Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Greedy),
        Ast::Byte(b'b'),
    ]);
    let eligible = Arc::new(
        Program::compile(&eligible, BuildLimits::default()).expect("eligible program build"),
    );
    let baseline = OnePassCapturePlan::try_from_program_accounted(
        Arc::clone(&eligible),
        OnePassCaptureBuildLimits::default(),
    )
    .expect("eligible accounted build");
    assert!(baseline.post_accept_live_tags_stable());
    let report = *baseline.build_report();
    let stability_proof_work = report
        .states
        .checked_add(report.transitions)
        .and_then(|work| work.checked_add(1))
        .expect("stability proof work");
    let mandatory_compile_work = report
        .compile_work
        .checked_sub(stability_proof_work)
        .expect("mandatory compile work");
    let declined_proof = OnePassCapturePlan::try_from_program_accounted(
        Arc::clone(&eligible),
        OnePassCaptureBuildLimits {
            max_compile_work: report.compile_work - 1,
            ..OnePassCaptureBuildLimits::default()
        },
    )
    .expect("one-below optional proof must retain the incumbent plan");
    assert!(!declined_proof.post_accept_live_tags_stable());
    assert_eq!(declined_proof.build_report().compile_work, mandatory_compile_work);
    let refused = OnePassCapturePlan::try_from_program_accounted(
        eligible,
        OnePassCaptureBuildLimits {
            max_compile_work: mandatory_compile_work - 1,
            ..OnePassCaptureBuildLimits::default()
        },
    )
    .expect_err("one-below mandatory compile work must refuse");
    assert_eq!(refused.compile_work, mandatory_compile_work - 1);
    assert!(matches!(
        refused.source,
        OnePassCaptureBuildError::Resource {
            resource: OnePassCaptureBuildResource::CompileWork,
            required,
            limit,
        } if required == mandatory_compile_work && limit == mandatory_compile_work - 1
    ));
}

#[test]
fn inline_exact_workspace_is_exact_at_32_slots_and_declines_wider_schemas() {
    fn plan(groups: u32) -> OnePassCapturePlan {
        let ast = Ast::concat((1..=groups).map(|index| Ast::Byte(b'a').capture(index)));
        let program = Arc::new(
            Program::compile(&ast, BuildLimits::default()).expect("wide inline program build"),
        );
        OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default())
            .expect("wide inline one-pass build")
    }

    let boundary = plan(15);
    let haystack = [b'a'; 15];
    let span = Span { start: 0, end: 15 };
    let inline = boundary
        .try_captures_exact_inline(
            &haystack,
            Window::all(&haystack),
            span,
            SearchLimits::default(),
        )
        .expect("inline exact execution")
        .expect("32-slot schema must use inline storage");
    assert_eq!(
        inline.report.admitted_scratch_bytes,
        core::mem::size_of::<[usize; 32]>()
    );
    let mut heap = boundary
        .create_workspace(SearchLimits::default())
        .expect("heap comparison workspace");
    let heap = boundary
        .captures_exact(
            &mut heap,
            &haystack,
            Window::all(&haystack),
            span,
            SearchLimits::default(),
        )
        .expect("heap exact execution");
    assert_eq!(inline.captures, heap.captures);
    assert_eq!(inline.report.state_visits, heap.report.state_visits);
    assert_eq!(inline.report.slot_copies, heap.report.slot_copies);
    assert!(
        boundary
            .try_captures_exact_inline(
                &haystack,
                Window::all(&haystack),
                span,
                SearchLimits {
                    max_scratch_bytes: core::mem::size_of::<[usize; 32]>() - 1,
                    ..SearchLimits::default()
                },
            )
            .expect("inline one-below refusal")
            .is_none()
    );

    let wider = plan(16);
    let wider_haystack = [b'a'; 16];
    assert!(
        wider
            .try_captures_exact_inline(
                &wider_haystack,
                Window::all(&wider_haystack),
                Span { start: 0, end: 16 },
                SearchLimits::default(),
            )
            .expect("wide source-free inline refusal")
            .is_none()
    );
}

#[test]
fn assertion_actions_are_admitted_and_reported_as_execution_work() {
    let ast = Ast::concat([
        Ast::Start,
        Ast::Assert(Assertion::StartLf),
        Ast::Assert(Assertion::StartLine(b'X')),
        Ast::Assert(Assertion::WordStartHalfAscii),
        Ast::Byte(b'a').capture(1),
        Ast::Assert(Assertion::WordEndHalfAscii),
        Ast::Assert(Assertion::EndLine(b'X')),
        Ast::Assert(Assertion::EndLf),
        Ast::End,
    ]);
    let (_, plan) = pair(&ast);
    let haystack = b"a";
    let span = Span { start: 0, end: 1 };
    assert_eq!(plan.build_report().assertions, 8);
    assert_eq!(plan.build_report().max_action_assertions, 4);
    let admitted_state_visits = 2 * (1 + plan.build_report().max_action_assertions);
    let exact = SearchLimits {
        max_state_visits: admitted_state_visits,
        ..SearchLimits::default()
    };
    let outcome = plan
        .try_captures_exact_inline(haystack, Window::all(haystack), span, exact)
        .expect("assertion execution")
        .expect("small schema uses inline storage");
    assert!(outcome.captures.is_some());
    assert_eq!(outcome.report.state_visits, 10);

    let one_below = SearchLimits {
        max_state_visits: admitted_state_visits - 1,
        ..SearchLimits::default()
    };
    assert_eq!(
        plan.try_captures_exact_inline(haystack, Window::all(haystack), span, one_below)
            .unwrap_err(),
        SearchError::Resource {
            kind: ResourceKind::StateVisits,
            required: admitted_state_visits,
            limit: admitted_state_visits - 1,
        }
    );

    let false_ast = Ast::concat([
        Ast::Assert(Assertion::WordAsciiNegate),
        Ast::Byte(b'a').capture(1),
    ]);
    let (_, false_plan) = pair(&false_ast);
    let false_outcome = false_plan
        .try_captures_exact_inline(
            haystack,
            Window::all(haystack),
            span,
            SearchLimits::default(),
        )
        .expect("false assertion execution")
        .expect("small false schema uses inline storage");
    assert!(false_outcome.captures.is_none());
    assert_eq!(false_outcome.report.state_visits, 2);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario closes workspace identity and every exact one-below execution gate"
)]
fn execution_boundaries_and_workspace_identity_fail_closed() {
    let ast = Ast::Byte(b'a').capture(1).repeat(1, None, Greed::Greedy);
    let program = Arc::new(Program::compile(&ast, BuildLimits::default()).expect("program build"));
    let first = OnePassCapturePlan::try_from_program(
        Arc::clone(&program),
        OnePassCaptureBuildLimits::default(),
    )
    .expect("first plan");
    let second =
        OnePassCapturePlan::try_from_program(program, OnePassCaptureBuildLimits::default())
            .expect("second plan");
    assert_ne!(first.identity(), second.identity());
    let mut workspace = first
        .create_workspace(SearchLimits::default())
        .expect("workspace");
    assert_eq!(workspace.plan_identity(), first.identity());
    let exact_scratch = workspace.scratch_bytes();
    assert!(exact_scratch > 0);
    assert_eq!(
        first
            .create_workspace(SearchLimits {
                max_scratch_bytes: exact_scratch - 1,
                ..SearchLimits::default()
            })
            .unwrap_err(),
        SearchError::Resource {
            kind: ResourceKind::ScratchBytes,
            required: exact_scratch,
            limit: exact_scratch - 1,
        }
    );

    let haystack = b"aaa";
    let span = Span { start: 0, end: 3 };
    assert_eq!(
        second
            .captures_exact(
                &mut workspace,
                haystack,
                Window::all(haystack),
                span,
                SearchLimits::default(),
            )
            .unwrap_err(),
        SearchError::InvalidProgram
    );

    let exact = SearchLimits {
        max_scratch_bytes: workspace.scratch_bytes(),
        max_state_visits: 4,
        max_slot_copies: 4 * first.build_report().max_action_tag_actions,
        ..SearchLimits::default()
    };
    assert!(
        first
            .captures_exact(&mut workspace, haystack, Window::all(haystack), span, exact,)
            .expect("exact limits")
            .captures
            .is_some()
    );

    let mut too_few_visits = exact;
    too_few_visits.max_state_visits -= 1;
    assert_eq!(
        first
            .captures_exact(
                &mut workspace,
                haystack,
                Window::all(haystack),
                span,
                too_few_visits,
            )
            .unwrap_err(),
        SearchError::Resource {
            kind: ResourceKind::StateVisits,
            required: 4,
            limit: 3,
        }
    );

    let mut too_few_writes = exact;
    too_few_writes.max_slot_copies -= 1;
    assert!(matches!(
        first.captures_exact(
            &mut workspace,
            haystack,
            Window::all(haystack),
            span,
            too_few_writes,
        ),
        Err(SearchError::Resource {
            kind: ResourceKind::SlotCopies,
            ..
        })
    ));

    let mut too_little_scratch = exact;
    too_little_scratch.max_scratch_bytes -= 1;
    assert!(matches!(
        first.captures_exact(
            &mut workspace,
            haystack,
            Window::all(haystack),
            span,
            too_little_scratch,
        ),
        Err(SearchError::Resource {
            kind: ResourceKind::ScratchBytes,
            ..
        })
    ));

    assert!(
        first
            .captures_exact(&mut workspace, haystack, Window::all(haystack), span, exact,)
            .expect("workspace remains usable")
            .captures
            .is_some()
    );
}

#[test]
fn workspace_construction_checks_actual_retained_capacity() {
    let (_, plan) = pair(&Ast::Byte(b'a').capture(1));
    let expected = plan
        .workspace_usage(SearchLimits::default())
        .expect("source-free workspace usage");
    let workspace = plan
        .create_workspace(SearchLimits::default())
        .expect("baseline workspace");
    assert_eq!(expected, workspace.usage());
    let exact_bytes = workspace.scratch_bytes();
    let mut exact = SearchLimits {
        max_scratch_bytes: exact_bytes,
        ..SearchLimits::default()
    };
    assert_eq!(
        plan.create_workspace(exact)
            .expect("exact workspace")
            .scratch_bytes(),
        exact_bytes
    );
    exact.max_scratch_bytes -= 1;
    assert!(matches!(
        plan.create_workspace(exact),
        Err(SearchError::Resource {
            kind: ResourceKind::ScratchBytes,
            required,
            limit,
        }) if required == exact_bytes && limit + 1 == required
    ));
}
