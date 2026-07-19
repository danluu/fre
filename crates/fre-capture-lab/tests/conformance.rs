#![allow(
    clippy::arithmetic_side_effects,
    reason = "small deterministic test-domain enumeration uses proven tiny integers"
)]

use std::fmt::Write as _;
use std::sync::Arc;

use fre_capture_lab::{
    AggregateLimits, Assertion, Ast, BuildError, BuildLimits, CaptureProfile, CaptureRecord, Greed,
    GroupRecord, HistoryRegex, InlineRegex, MatchKind as CaptureMatchKind, Program, ResourceKind,
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
        history.captures(b"a", Window::all(b"a"), tiny_history),
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
        history.captures(b"a", Window::all(b"a"), tiny_walk),
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
        history.captures(b"a", Window::all(b"a"), tiny_scratch),
        Err(SearchError::Resource {
            kind: ResourceKind::ScratchBytes,
            ..
        })
    ));
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
        .captures(b"x", Window::all(b"x"), limits)
        .expect("two group-zero Save states over two boundaries fit four nodes");
    assert!(outcome.captures.is_none());
    assert!(outcome.report.history_nodes <= 4);

    let one_node_short = SearchLimits {
        max_history_nodes: 3,
        max_history_walk: 4,
        ..SearchLimits::default()
    };
    assert!(matches!(
        history.captures(b"x", Window::all(b"x"), one_node_short),
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
