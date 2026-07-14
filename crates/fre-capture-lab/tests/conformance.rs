#![allow(
    clippy::arithmetic_side_effects,
    reason = "small deterministic test-domain enumeration uses proven tiny integers"
)]

use std::fmt::Write as _;
use std::sync::Arc;

use fre_capture_lab::{
    AggregateLimits, Ast, BuildError, BuildLimits, CaptureProfile, CaptureRecord, Greed,
    GroupRecord, HistoryRegex, InlineRegex, Program, ResourceKind, SearchError, SearchLimits, Span,
    Window,
};
use regex::bytes::Regex;

fn pair(ast: &Ast) -> (InlineRegex, HistoryRegex) {
    let program = Arc::new(Program::compile(ast, BuildLimits::default()).unwrap());
    (
        InlineRegex::from_program(Arc::clone(&program)),
        HistoryRegex::from_program(program),
    )
}

fn reference(pattern: &str, haystack: &[u8], window: Window) -> Option<CaptureRecord> {
    let re = Regex::new(pattern).unwrap();
    let slice = &haystack[window.start..window.end];
    re.captures(slice).map(|captures| {
        let names = re.capture_names().collect::<Vec<_>>();
        let groups = captures
            .iter()
            .enumerate()
            .map(|(index, matched)| GroupRecord {
                index: u32::try_from(index).unwrap(),
                name: names[index].map(str::to_owned),
                span: matched.map(|matched| Span {
                    start: matched.start() + window.start,
                    end: matched.end() + window.start,
                }),
            })
            .collect();
        CaptureRecord { groups }
    })
}

fn reference_iter(pattern: &str, haystack: &[u8], window: Window) -> Vec<CaptureRecord> {
    let re = Regex::new(pattern).unwrap();
    let names = re.capture_names().collect::<Vec<_>>();
    re.captures_iter(&haystack[window.start..window.end])
        .map(|captures| CaptureRecord {
            groups: captures
                .iter()
                .enumerate()
                .map(|(index, matched)| GroupRecord {
                    index: u32::try_from(index).unwrap(),
                    name: names[index].map(str::to_owned),
                    span: matched.map(|matched| Span {
                        start: matched.start() + window.start,
                        end: matched.end() + window.start,
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
    }
}
