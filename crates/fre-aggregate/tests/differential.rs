#![allow(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic is over small, asserted test-corpus dimensions"
)]

use fre_aggregate::{
    CompileLimits, CompiledRegex, Error, OperationLimits, Resource, RustByteProfile, Span,
    Strategy, Unsupported,
};
use fre_iterator_lab::{Ast as LabAst, CompileLimits as LabLimits, Greed, GuardedRegex};
use fre_reference::{
    Ast as ReferenceAst, ByteRange as ReferenceByteRange, Greed as ReferenceGreed,
    Limits as ReferenceLimits, ReferenceRegex,
};
use regex_automata::{Input, meta::Regex as MetaRegex};
use regex_syntax::hir::{Hir, Look};

const STRATEGIES: [Strategy; 2] = [Strategy::FullTable, Strategy::ReverseSequentialRows];
type LimitMutation = fn(&mut CompileLimits);

fn parse(pattern: &str) -> Hir {
    regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(pattern)
        .unwrap_or_else(|error| panic!("failed to parse {pattern:?}: {error}"))
}

fn parse_unicode(pattern: &str) -> Hir {
    regex_syntax::ParserBuilder::new()
        .unicode(true)
        .utf8(false)
        .build()
        .parse(pattern)
        .unwrap_or_else(|error| panic!("failed to parse Unicode {pattern:?}: {error}"))
}

fn compile_unicode(pattern: &str) -> CompiledRegex {
    CompiledRegex::from_hir(
        &parse_unicode(pattern),
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
    .unwrap_or_else(|error| panic!("failed to compile Unicode {pattern:?}: {error}"))
}

fn upstream_unicode(pattern: &str, haystack: &[u8]) -> Vec<Span> {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .unwrap_or_else(|error| panic!("upstream rejected Unicode {pattern:?}: {error}"))
        .find_iter(haystack)
        .map(|matched| Span {
            start: matched.start(),
            end: matched.end(),
        })
        .collect()
}

fn upstream_unicode_range(
    pattern: &str,
    haystack: &[u8],
    range: core::ops::Range<usize>,
) -> Vec<Span> {
    let config = MetaRegex::config().utf8_empty(false);
    let syntax = regex_automata::util::syntax::Config::new()
        .unicode(true)
        .utf8(false);
    MetaRegex::builder()
        .configure(config)
        .syntax(syntax)
        .build(pattern)
        .unwrap_or_else(|error| {
            panic!("pinned Unicode range oracle rejected {pattern:?}: {error}")
        })
        .find_iter(Input::new(haystack).span(range))
        .map(|matched| Span {
            start: matched.start(),
            end: matched.end(),
        })
        .collect()
}

fn compile(pattern: &str) -> CompiledRegex {
    CompiledRegex::from_hir(
        &parse(pattern),
        RustByteProfile::PINNED_1_12_4,
        CompileLimits::default(),
    )
    .unwrap_or_else(|error| panic!("failed to compile {pattern:?}: {error}"))
}

fn upstream(pattern: &str, haystack: &[u8]) -> Vec<Span> {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"))
        .find_iter(haystack)
        .map(|matched| Span {
            start: matched.start(),
            end: matched.end(),
        })
        .collect()
}

fn upstream_range(pattern: &str, haystack: &[u8], range: core::ops::Range<usize>) -> Vec<Span> {
    let config = MetaRegex::config().utf8_empty(false);
    let syntax = regex_automata::util::syntax::Config::new()
        .unicode(false)
        .utf8(false);
    MetaRegex::builder()
        .configure(config)
        .syntax(syntax)
        .build(pattern)
        .unwrap_or_else(|error| panic!("pinned range oracle rejected {pattern:?}: {error}"))
        .find_iter(Input::new(haystack).span(range))
        .map(|matched| Span {
            start: matched.start(),
            end: matched.end(),
        })
        .collect()
}

fn parse_unicode_byte_stable(pattern: &str) -> Hir {
    regex_syntax::ParserBuilder::new()
        .unicode(true)
        .utf8(false)
        .build()
        .parse(pattern)
        .unwrap_or_else(|error| panic!("failed to parse Unicode pattern {pattern:?}: {error}"))
}

fn compile_unicode_byte_stable(pattern: &str) -> Result<CompiledRegex, Error> {
    CompiledRegex::from_hir(
        &parse_unicode_byte_stable(pattern),
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
}

fn upstream_unicode_byte_stable_range(
    pattern: &str,
    haystack: &[u8],
    range: core::ops::Range<usize>,
) -> Vec<Span> {
    let config = MetaRegex::config().utf8_empty(false);
    let syntax = regex_automata::util::syntax::Config::new()
        .unicode(true)
        .utf8(false);
    MetaRegex::builder()
        .configure(config)
        .syntax(syntax)
        .build(pattern)
        .unwrap_or_else(|error| panic!("pinned Unicode oracle rejected {pattern:?}: {error}"))
        .find_iter(Input::new(haystack).span(range))
        .map(|matched| Span {
            start: matched.start(),
            end: matched.end(),
        })
        .collect()
}

fn upstream_unicode_byte_stable(pattern: &str, haystack: &[u8]) -> Vec<Span> {
    upstream_unicode_byte_stable_range(pattern, haystack, 0..haystack.len())
}

#[test]
fn unicode_on_byte_stable_hir_matches_rebar_profile_and_rejects_unicode_classes() {
    let cases: [(&str, &[u8]); 6] = [
        ("", &[0xFF, 0x80]),
        ("雪+", "x雪雪y☃".as_bytes()),
        ("(?:雪a|☃b)", "☃b雪a雪b".as_bytes()),
        (r"[a-c]+", &[0xFF, b'a', b'b', b'd', b'c']),
        (r"(?-u:\xFF+)", &[b'a', 0xFF, 0xFF, b'b']),
        (r"\A(?:a|雪)+\z", "a雪a".as_bytes()),
    ];
    for (pattern, haystack) in cases {
        let regex = compile_unicode_byte_stable(pattern)
            .unwrap_or_else(|error| panic!("byte-stable compile failed for {pattern:?}: {error}"));
        let expected = upstream_unicode_byte_stable(pattern, haystack);
        for strategy in STRATEGIES {
            let actual = regex
                .admit_spans(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(actual.as_slice(), expected, "{strategy:?}/{pattern:?}");
        }
    }

    assert!(matches!(
        compile_unicode_byte_stable(r"\pL"),
        Err(Error::Unsupported(Unsupported::UnicodeClass))
    ));
    assert!(matches!(
        compile_unicode_byte_stable("[雪-雫]"),
        Err(Error::Unsupported(Unsupported::UnicodeClass))
    ));
}

#[test]
fn unicode_word_boundary_matches_pinned_rust_at_absolute_byte_ranges() {
    let regex = compile_unicode_byte_stable(r"\b").unwrap();
    let haystacks: [&[u8]; 4] = [
        b"",
        b"ascii word",
        "雪-Ж_é".as_bytes(),
        " a\u{0301}\u{200C}☃ ".as_bytes(),
    ];
    for haystack in haystacks {
        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let range = start..end;
                let expected = upstream_unicode_byte_stable_range(r"\b", haystack, range.clone());
                for strategy in STRATEGIES {
                    let actual = regex
                        .admit_spans(
                            haystack,
                            range.clone(),
                            strategy,
                            OperationLimits::default(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("{strategy:?} failed {haystack:?} {range:?}: {error}")
                        });
                    assert_eq!(
                        expected,
                        actual.as_slice(),
                        "{strategy:?} {haystack:?} {range:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn unicode_word_boundary_refuses_malformed_utf8_before_publication() {
    let regex = compile_unicode_byte_stable(r"\b").unwrap();
    let haystacks: [&[u8]; 4] = [
        &[0xFF, b'a', 0x80],
        &[b'a', 0xE9, b'b'],
        &[0xC0, 0x80, b'a'],
        &[b'a', 0xED, 0xA0, 0x80],
    ];
    for haystack in haystacks {
        for strategy in STRATEGIES {
            assert!(matches!(
                regex.admit_count(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits::default()
                ),
                Err(Error::InvalidUtf8ForUnicodeWordBoundary)
            ));
            assert!(matches!(
                regex.admit_spans(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits::default()
                ),
                Err(Error::InvalidUtf8ForUnicodeWordBoundary)
            ));
        }
    }
}

#[test]
fn directed_nested_nullable_priority_and_invalid_bytes_match_rust_1_12_4() {
    let patterns = [
        "",
        r"\xFF",
        r"[a-c\xFF]",
        r"\A(?:a|)*\z",
        r"(?:|a)*",
        r"(?:a|)*",
        r"(?:a*?)*?",
        r"(?:(?:|a){1,2}?b?)*",
        r"(?:(?:a?|b*)+?c){0,3}",
        r"(?:\A|a?)*(?:\z|b)",
        r"(?:(?:a{0,2}?|b+){1,3})*?",
        r"(?:|a){2,}",
        r"(?:|a){2,}?",
        r"(?:a+b|a)",
    ];
    let haystacks: [&[u8]; 10] = [
        b"",
        b"a",
        b"b",
        b"aa",
        b"ab",
        b"ba",
        b"aaa",
        b"abc",
        &[0xFF],
        &[b'a', 0xFF, b'b'],
    ];
    for pattern in patterns {
        let regex = compile(pattern);
        for haystack in haystacks {
            let expected = upstream(pattern, haystack);
            for strategy in STRATEGIES {
                let actual = regex
                    .admit_spans(
                        haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("{strategy:?} failed for {pattern:?} {haystack:?}: {error}")
                    });
                assert_eq!(
                    expected,
                    actual.as_slice(),
                    "{strategy:?} {pattern:?} {haystack:?}"
                );
                assert_eq!(expected, actual.iter().collect::<Vec<_>>());
                let count = regex
                    .admit_count(
                        haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(expected.len(), count.value());
                let sum = regex
                    .admit_span_sum(
                        haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(
                    expected
                        .iter()
                        .map(|span| span.end - span.start)
                        .sum::<usize>(),
                    sum.value()
                );
            }
        }
    }
}

#[test]
fn unicode_scalar_paths_cover_all_widths_invalid_bytes_and_nullable_priority() {
    let patterns = [
        r"[Aé雪🦀]",
        r"(?:🦀|雪|é|a)",
        r"(?:é|(?-u:\xFF)|.)",
        r"(?:雪?)*?",
        r"\A(?:[a-z]|雪|🦀)*\z",
        r"(?i:σ)",
    ];
    let haystacks: [&[u8]; 9] = [
        b"",
        b"ASCII",
        "aé雪🦀z".as_bytes(),
        "Σσς".as_bytes(),
        &[0xFF],
        &[0x80, b'a', 0xC3, 0xA9, 0xFF],
        &[0xF0, 0x80, 0x80, 0x80],
        &[0xED, 0xA0, 0x80],
        &[b'a', 0xFF, b'z'],
    ];
    for pattern in patterns {
        let regex = compile_unicode(pattern);
        for haystack in haystacks {
            let expected = upstream_unicode(pattern, haystack);
            for strategy in STRATEGIES {
                let actual = regex
                    .admit_spans(
                        haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(
                    expected,
                    actual.as_slice(),
                    "{strategy:?} {pattern:?} {haystack:?}"
                );
            }
        }
    }
}

#[test]
fn unicode_profile_and_utf8_expansion_are_identity_and_resource_dimensions() {
    let ascii = Hir::literal(b"a".to_vec());
    let unicode_on = CompiledRegex::from_hir(
        &ascii,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
    .unwrap();
    let unicode_off = CompiledRegex::from_hir(
        &ascii,
        RustByteProfile::PINNED_1_12_4,
        CompileLimits::default(),
    )
    .unwrap();
    assert_ne!(unicode_on.plan_id(), unicode_off.plan_id());

    let hir = parse_unicode(r"[\x00-\u{10FFFF}]");
    let baseline = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
    .unwrap();
    let accounting = baseline.compile_accounting();
    assert!(accounting.utf8_sequences >= 4);
    assert!(accounting.utf8_byte_ranges > accounting.utf8_sequences);

    let mut exact = CompileLimits {
        max_utf8_sequences: accounting.utf8_sequences,
        max_utf8_byte_ranges: accounting.utf8_byte_ranges,
        ..CompileLimits::default()
    };
    CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        exact,
    )
    .unwrap();

    exact.max_utf8_sequences -= 1;
    expect_resource(
        CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            exact,
        ),
        Resource::Utf8Sequences,
    );
    exact.max_utf8_sequences = accounting.utf8_sequences;
    exact.max_utf8_byte_ranges -= 1;
    expect_resource(
        CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            exact,
        ),
        Resource::Utf8ByteRanges,
    );
}

#[test]
fn unicode_ranges_keep_byte_offsets_and_original_anchor_context() {
    let haystack = [
        b'x', 0xC3, 0xA9, b'/', 0xE9, 0x9B, 0xAA, b'/', 0xF0, 0x9F, 0xA6, 0x80, 0xFF,
        b'z',
    ];
    let ranges = [
        0..haystack.len(),
        1..3,
        2..3,
        4..7,
        5..7,
        8..12,
        9..12,
        12..13,
        haystack.len()..haystack.len(),
    ];
    for pattern in [r".", r"[é雪🦀]", r"\A(?:.|(?-u:\xFF))*\z", r""] {
        let regex = compile_unicode(pattern);
        for range in &ranges {
            let expected = upstream_unicode_range(pattern, &haystack, range.clone());
            for strategy in STRATEGIES {
                let actual = regex
                    .admit_spans(
                        &haystack,
                        range.clone(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(
                    expected,
                    actual.as_slice(),
                    "{strategy:?} {pattern:?} {range:?}"
                );
            }
        }
    }
}

#[test]
fn reverse_suffix_bug_regressions_follow_independent_naive_leftmost_first_oracle() {
    let any_except_lf = ReferenceAst::Class(vec![
        ReferenceByteRange::new(0, 9).unwrap(),
        ReferenceByteRange::new(11, u8::MAX).unwrap(),
    ]);
    let ascii_letter = ReferenceAst::Class(vec![
        ReferenceByteRange::new(b'A', b'Z').unwrap(),
        ReferenceByteRange::new(b'a', b'z').unwrap(),
    ]);
    let cases = [
        (
            r".abb|b",
            ReferenceAst::Alt(vec![
                ReferenceAst::Concat(vec![
                    any_except_lf,
                    ReferenceAst::Byte(b'a'),
                    ReferenceAst::Byte(b'b'),
                    ReferenceAst::Byte(b'b'),
                ]),
                ReferenceAst::Byte(b'b'),
            ]),
        ),
        (
            r"(?:[A-Za-z]ab)?b",
            ReferenceAst::Concat(vec![
                ReferenceAst::Repeat {
                    child: Box::new(ReferenceAst::Concat(vec![
                        ascii_letter,
                        ReferenceAst::Byte(b'a'),
                        ReferenceAst::Byte(b'b'),
                    ])),
                    min: 0,
                    max: Some(1),
                    greed: ReferenceGreed::Greedy,
                },
                ReferenceAst::Byte(b'b'),
            ]),
        ),
    ];
    for (pattern, ast) in cases {
        let oracle = ReferenceRegex::new(ast, ReferenceLimits::default()).unwrap();
        let expected: Vec<_> = oracle
            .find_all_rust_reference(b"zabb")
            .unwrap()
            .into_iter()
            .map(|matched| (matched.span.start, matched.span.end))
            .collect();
        assert_eq!(expected, vec![(0, 4)], "independent oracle {pattern:?}");

        let regex = compile(pattern);
        for strategy in STRATEGIES {
            let spans = regex
                .admit_spans(b"zabb", 0..4, strategy, OperationLimits::default())
                .unwrap();
            assert_eq!(
                spans
                    .iter()
                    .map(|span| (span.start, span.end))
                    .collect::<Vec<_>>(),
                expected,
                "aggregate {strategy:?} {pattern:?}"
            );
            assert_eq!(
                regex
                    .admit_count(b"zabb", 0..4, strategy, OperationLimits::default(),)
                    .unwrap()
                    .value(),
                1
            );
        }
    }
}

#[test]
fn late_priority_fallback_sequence_has_linear_whole_operation_certificate() {
    // A suffix-restarted matcher can be quadratic here: at every start, the
    // preferred `a+b` branch may inspect the remaining `a` run before the
    // one-byte fallback is selected. The whole-operation recurrence must solve
    // all starts together instead.
    let regex = compile(r"(?:a+b|a)");
    let mut work_by_strategy = [Vec::new(), Vec::new()];
    for &length in &[64_usize, 128, 256] {
        let haystack = vec![b'a'; length];
        let expected = (0..length)
            .map(|start| Span {
                start,
                end: start + 1,
            })
            .collect::<Vec<_>>();
        for (strategy_index, strategy) in STRATEGIES.into_iter().enumerate() {
            let admitted = regex
                .admit_spans(
                    &haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(expected, admitted.as_slice(), "{strategy:?}");
            let certificate = admitted.certificate();
            assert_eq!(length + 1, certificate.boundaries);
            assert_eq!(length, certificate.output_matches);
            assert_eq!(length, certificate.span_sum);
            if strategy == Strategy::FullTable {
                assert_eq!(
                    certificate.states * certificate.boundaries,
                    certificate.table_cells
                );
            } else {
                assert_eq!(0, certificate.table_cells);
                assert!(certificate.log_bytes > 0);
            }
            work_by_strategy[strategy_index].push(certificate.work_bound);
        }
    }
    for work in work_by_strategy {
        let first_delta = work[1] - work[0];
        let second_delta = work[2] - work[1];
        assert_eq!(first_delta * 2, second_delta, "work={work:?}");
    }
}

#[test]
fn operation_ranges_confine_consumption_but_assert_against_original_haystack() {
    let haystack = b"x\nfoo_bar\nz\xFF";
    let ranges = [
        0..haystack.len(),
        2..9,
        3..6,
        1..1,
        2..2,
        9..9,
        haystack.len()..haystack.len(),
    ];
    let patterns = [
        r"\A",
        r"\z",
        r"(?m:^)",
        r"(?m:$)",
        r"\b",
        r"\B",
        r"\b{start}",
        r"\b{end}",
        r"\b{start-half}",
        r"\b{end-half}",
        r"\bfoo\b",
        r"(?m:^foo_bar$)",
        r"(?:|o)*",
    ];
    for pattern in patterns {
        let regex = compile(pattern);
        for range in &ranges {
            let expected = upstream_range(pattern, haystack, range.clone());
            for strategy in STRATEGIES {
                let actual = regex
                    .admit_spans(
                        haystack,
                        range.clone(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(
                    expected,
                    actual.as_slice(),
                    "{strategy:?} {pattern:?} {range:?}"
                );
            }
        }
    }
    assert!(matches!(
        compile("a").admit_count(
            haystack,
            3..haystack.len() + 1,
            Strategy::FullTable,
            OperationLimits::default()
        ),
        Err(Error::InvalidRange { .. })
    ));
}

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

fn independent_is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_digit() || byte.is_ascii_uppercase() || byte.is_ascii_lowercase()
}

fn independent_assertion(look: Look, haystack: &[u8], at: usize) -> bool {
    assert!(at <= haystack.len());
    let before = at
        .checked_sub(1)
        .and_then(|index| haystack.get(index))
        .is_some_and(|&byte| independent_is_ascii_word(byte));
    let after = haystack
        .get(at)
        .is_some_and(|&byte| independent_is_ascii_word(byte));
    match look {
        Look::Start => at == 0,
        Look::End => at == haystack.len(),
        Look::StartLF => at == 0 || haystack[at - 1] == b'\n',
        Look::EndLF => at == haystack.len() || haystack[at] == b'\n',
        Look::WordAscii => before != after,
        Look::WordAsciiNegate => before == after,
        Look::WordStartAscii => !before && after,
        Look::WordEndAscii => before && !after,
        Look::WordStartHalfAscii => !before,
        Look::WordEndHalfAscii => !after,
        unsupported => panic!("independent oracle received unsupported look {unsupported:?}"),
    }
}

fn independent_assertion_spans(
    look: Look,
    haystack: &[u8],
    range: core::ops::Range<usize>,
) -> Vec<Span> {
    (range.start..=range.end)
        .filter(|&at| independent_assertion(look, haystack, at))
        .map(|at| Span { start: at, end: at })
        .collect()
}

#[test]
fn every_admitted_assertion_matches_pinned_rust_and_independent_byte_oracle() {
    let mut haystacks = byte_strings(3, &[b'a', b'Z', b'9', b'_', b'-', b'\n', 0xFF]);
    haystacks.extend((u8::MIN..=u8::MAX).map(|byte| vec![byte]));
    haystacks.sort();
    haystacks.dedup();
    assert_eq!(649, haystacks.len());

    let mut oracle_cases = 0_usize;
    let mut engine_comparisons = 0_usize;
    for (look, pattern) in ASSERTION_CASES {
        let regex = CompiledRegex::from_hir(
            &Hir::look(look),
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap_or_else(|error| panic!("failed to compile {look:?}: {error}"));
        assert_eq!(regex.compile_accounting().look_assertions, 1);
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let range = start..end;
                    let independent = independent_assertion_spans(look, haystack, range.clone());
                    let pinned = upstream_range(pattern, haystack, range.clone());
                    assert_eq!(
                        independent, pinned,
                        "independent/pinned {look:?} {haystack:?} {range:?}"
                    );
                    oracle_cases += 1;
                    for strategy in STRATEGIES {
                        let actual = regex
                            .admit_spans(
                                haystack,
                                range.clone(),
                                strategy,
                                OperationLimits::default(),
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "{strategy:?} failed {look:?} {haystack:?} {range:?}: {error}"
                                )
                            });
                        assert_eq!(
                            independent,
                            actual.as_slice(),
                            "{strategy:?} {look:?} {haystack:?} {range:?}"
                        );
                        engine_comparisons += 1;
                    }
                }
            }
        }
    }
    assert_eq!(44_930, oracle_cases);
    assert_eq!(89_860, engine_comparisons);
}

#[test]
fn nested_nullable_assertions_preserve_priority_and_same_boundary_acyclicity() {
    let patterns = [
        r"(?:(?m:^)|\b|a)*",
        r"(?:\B|a)*?",
        r"(?:(?:\b{start-half}|a){1,2}?)*",
        r"(?m:^\w*$)",
        r"\b(?:a|_+)\b",
    ];
    let haystacks: [&[u8]; 8] = [
        b"",
        b"a",
        b"_",
        b"-a",
        b"a_",
        b"\na\n",
        &[0xFF, b'a'],
        &[b'a', 0xFF, b'\n'],
    ];
    for pattern in patterns {
        let regex = compile(pattern);
        for haystack in haystacks {
            let expected = upstream(pattern, haystack);
            for strategy in STRATEGIES {
                let actual = regex
                    .admit_spans(
                        haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("{strategy:?} failed {pattern:?} {haystack:?}: {error}")
                    });
                assert_eq!(expected, actual.as_slice(), "{strategy:?} {pattern:?}");
            }
        }
    }
}

#[test]
fn assertion_execution_accounting_and_work_limits_are_exact() {
    let regex = compile(r"(?:\b|(?m:^))");
    assert_eq!(regex.compile_accounting().look_assertions, 2);
    let haystack = b"a\n_";
    for strategy in STRATEGIES {
        let baseline = regex
            .admit_spans(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        let accounting = baseline.accounting();
        let construction_checks = 2 * baseline.certificate().boundaries;
        if strategy == Strategy::FullTable {
            assert_eq!(construction_checks, accounting.assertion_checks);
        } else {
            assert!(accounting.assertion_checks > construction_checks);
        }
        assert!(accounting.assertion_checks <= accounting.transition_checks);
        assert!(accounting.work <= baseline.certificate().work_bound);

        regex
            .admit_spans(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: baseline.certificate().work_bound,
                    ..OperationLimits::default()
                },
            )
            .unwrap();
        expect_resource(
            regex.admit_spans(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: baseline.certificate().work_bound - 1,
                    ..OperationLimits::default()
                },
            ),
            Resource::ExecutionWork,
        );
    }
}

#[derive(Clone, Debug)]
enum SmallAst {
    Empty,
    Byte(u8),
    Any,
    Start,
    End,
    Concat(Box<Self>, Box<Self>),
    Alt(Box<Self>, Box<Self>),
    Repeat {
        child: Box<Self>,
        min: u32,
        max: Option<u32>,
        greedy: bool,
    },
}

impl SmallAst {
    fn pattern(&self) -> String {
        match self {
            Self::Empty => "(?:)".to_owned(),
            Self::Byte(byte) => format!(r"\x{byte:02X}"),
            Self::Any => "(?s:.)".to_owned(),
            Self::Start => r"\A".to_owned(),
            Self::End => r"\z".to_owned(),
            Self::Concat(left, right) => format!("{}{}", left.pattern(), right.pattern()),
            Self::Alt(left, right) => format!("(?:{}|{})", left.pattern(), right.pattern()),
            Self::Repeat {
                child,
                min,
                max,
                greedy,
            } => {
                let quantifier = match (*min, *max) {
                    (0, None) => "*".to_owned(),
                    (1, None) => "+".to_owned(),
                    (0, Some(1)) => "?".to_owned(),
                    (minimum, None) => format!("{{{minimum},}}"),
                    (minimum, Some(maximum)) if minimum == maximum => {
                        format!("{{{minimum}}}")
                    }
                    (minimum, Some(maximum)) => format!("{{{minimum},{maximum}}}"),
                };
                format!(
                    "(?:{}){quantifier}{}",
                    child.pattern(),
                    if *greedy { "" } else { "?" }
                )
            }
        }
    }

    fn lab(&self) -> LabAst {
        match self {
            Self::Empty => LabAst::Empty,
            Self::Byte(byte) => LabAst::Byte(*byte),
            Self::Any => LabAst::AnyByte,
            Self::Start => LabAst::StartText,
            Self::End => LabAst::EndText,
            Self::Concat(left, right) => LabAst::Concat(vec![left.lab(), right.lab()]),
            Self::Alt(left, right) => LabAst::Alt(vec![left.lab(), right.lab()]),
            Self::Repeat {
                child,
                min,
                max,
                greedy,
            } => LabAst::Repetition {
                child: Box::new(child.lab()),
                min: *min,
                max: *max,
                greed: if *greedy { Greed::Greedy } else { Greed::Lazy },
            },
        }
    }
}

#[test]
fn exhaustive_small_hir_agrees_with_upstream_and_independent_guarded_lab() {
    let asts = small_asts(3);
    let haystacks = byte_strings(2, &[b'a', b'b', 0xFF]);
    assert_eq!(510, asts.len(), "small AST corpus changed");
    assert_eq!(13, haystacks.len(), "small haystack corpus changed");
    for ast in asts {
        let pattern = ast.pattern();
        let regex = compile(&pattern);
        let guarded = GuardedRegex::new(
            &ast.lab(),
            LabLimits {
                max_work: 20_000_000,
                ..LabLimits::default()
            },
        )
        .unwrap_or_else(|error| panic!("guarded compiler rejected {pattern:?}: {error}"));
        for haystack in &haystacks {
            let expected = upstream(&pattern, haystack);
            let guarded_spans = guarded
                .find_all_guarded_dp(haystack)
                .unwrap_or_else(|error| panic!("guarded failed {pattern:?}: {error}"))
                .matches
                .into_iter()
                .map(|span| Span {
                    start: span.start,
                    end: span.end,
                })
                .collect::<Vec<_>>();
            assert_eq!(expected, guarded_spans, "guarded {pattern:?} {haystack:?}");
            for strategy in STRATEGIES {
                let actual = regex
                    .admit_spans(
                        haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("{strategy:?} failed {pattern:?} {haystack:?}: {error}")
                    });
                assert_eq!(expected, actual.as_slice(), "{strategy:?} {pattern:?}");
            }
        }
    }
}

#[test]
fn exhaustive_nested_nullable_hir_matches_upstream_complete_sequences() {
    let asts = small_asts(4);
    let haystacks = byte_strings(2, &[b'a', b'b', b'\n', 0xFF]);
    assert_eq!(5_310, asts.len(), "nested AST corpus changed");
    assert_eq!(21, haystacks.len(), "nested haystack corpus changed");
    let mut comparisons = 0_usize;
    for ast in asts {
        let pattern = ast.pattern();
        let regex = compile(&pattern);
        for haystack in &haystacks {
            let expected = upstream(&pattern, haystack);
            for strategy in STRATEGIES {
                let actual = regex
                    .admit_spans(
                        haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap_or_else(|error| {
                        panic!("{strategy:?} failed {pattern:?} {haystack:?}: {error}")
                    });
                assert_eq!(
                    expected,
                    actual.as_slice(),
                    "{strategy:?} {pattern:?} {haystack:?}"
                );
                comparisons += 1;
            }
        }
    }
    assert_eq!(223_020, comparisons);
}

fn small_asts(max_size: usize) -> Vec<SmallAst> {
    let mut exact = vec![Vec::new(); max_size + 1];
    exact[1] = vec![
        SmallAst::Empty,
        SmallAst::Byte(b'a'),
        SmallAst::Byte(b'b'),
        SmallAst::Any,
        SmallAst::Start,
        SmallAst::End,
    ];
    let repetitions = [
        (0, None, true),
        (0, None, false),
        (1, None, true),
        (1, None, false),
        (0, Some(1), true),
        (0, Some(1), false),
        (1, Some(2), true),
        (1, Some(2), false),
    ];
    for size in 2..=max_size {
        for child in exact[size - 1].clone() {
            for (min, max, greedy) in repetitions {
                exact[size].push(SmallAst::Repeat {
                    child: Box::new(child.clone()),
                    min,
                    max,
                    greedy,
                });
            }
        }
        let payload = size - 1;
        for left_size in 1..payload {
            let right_size = payload - left_size;
            for left in exact[left_size].clone() {
                for right in exact[right_size].clone() {
                    exact[size].push(SmallAst::Concat(
                        Box::new(left.clone()),
                        Box::new(right.clone()),
                    ));
                    exact[size].push(SmallAst::Alt(Box::new(left.clone()), Box::new(right)));
                }
            }
        }
    }
    exact.into_iter().flatten().collect()
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
fn unsupported_hir_is_a_typed_refusal() {
    let unicode = regex_syntax::hir::Hir::class(regex_syntax::hir::Class::Unicode(
        regex_syntax::hir::ClassUnicode::new([regex_syntax::hir::ClassUnicodeRange::new('é', 'ê')]),
    ));
    assert!(matches!(
        CompiledRegex::from_hir(
            &unicode,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default()
        ),
        Err(Error::Unsupported(Unsupported::UnicodeClass))
    ));
    let capture = regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse("(a)")
        .unwrap();
    assert!(matches!(
        CompiledRegex::from_hir(
            &capture,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default()
        ),
        Err(Error::Unsupported(Unsupported::Capture))
    ));
    let unsupported_looks = [
        Look::StartCRLF,
        Look::EndCRLF,
        Look::WordUnicodeNegate,
        Look::WordStartUnicode,
        Look::WordEndUnicode,
        Look::WordStartHalfUnicode,
        Look::WordEndHalfUnicode,
    ];
    for look in unsupported_looks {
        assert!(matches!(
            CompiledRegex::from_hir(
                &Hir::look(look),
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default()
            ),
            Err(Error::Unsupported(Unsupported::Look(actual))) if actual == look
        ));
    }
}

#[test]
fn explicit_whole_match_capture_erasure_is_exact_and_semantically_transparent() {
    let captured_hir = parse(r"(?P<outer>(?P<inner>a))");
    let captured = CompiledRegex::from_hir_erasing_captures_for_whole_match(
        &captured_hir,
        RustByteProfile::PINNED_1_12_4,
        CompileLimits::default(),
    )
    .unwrap();
    let plain = compile("a");
    let accounting = captured.compile_accounting();
    assert_eq!(accounting.captures_erased, 2);
    assert_eq!(accounting.capture_erasure_work, 4);
    assert!(accounting.capture_erasure_work <= accounting.work);
    assert_eq!(captured.plan_id(), plain.plan_id());
    assert_eq!(plain.compile_accounting().captures_erased, 0);
    assert_eq!(plain.compile_accounting().capture_erasure_work, 0);

    for haystack in [b"".as_slice(), b"a", b"baab"] {
        let expected = upstream(r"(?P<outer>(?P<inner>a))", haystack);
        for strategy in STRATEGIES {
            let spans = captured
                .admit_spans(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(spans.iter().collect::<Vec<_>>(), expected);
            let count = captured
                .admit_count(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(count.value(), expected.len());
            let span_sum = captured
                .admit_span_sum(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(
                span_sum.value(),
                expected.iter().map(|span| span.end - span.start).sum()
            );
        }
    }
}

#[test]
fn whole_match_capture_compiler_exact_limits_succeed_and_one_below_refuses() {
    let hir = parse(r"(?P<outer>(?:a|(?P<inner>[b-d])){1,2}?)");
    let baseline = CompiledRegex::from_hir_erasing_captures_for_whole_match(
        &hir,
        RustByteProfile::PINNED_1_12_4,
        CompileLimits::default(),
    )
    .unwrap();
    let stats = baseline.compile_accounting();
    assert_eq!(stats.captures_erased, 2);
    let exact = CompileLimits {
        max_hir_nodes: stats.hir_nodes,
        max_hir_depth: stats.hir_depth,
        max_hir_stack_items: stats.peak_hir_stack_items,
        max_literal_bytes: stats.literal_bytes,
        max_class_ranges: stats.class_ranges,
        max_look_assertions: stats.look_assertions,
        max_program_states: stats.program_states,
        max_temporary_states: stats.temporary_states_peak,
        max_program_bytes: stats.program_bytes,
        max_work: stats.work,
        ..CompileLimits::default()
    };
    CompiledRegex::from_hir_erasing_captures_for_whole_match(
        &hir,
        RustByteProfile::PINNED_1_12_4,
        exact,
    )
    .unwrap();
    let cases: [(Resource, LimitMutation); 9] = [
        (Resource::HirNodes, |limits| limits.max_hir_nodes -= 1),
        (Resource::HirDepth, |limits| limits.max_hir_depth -= 1),
        (Resource::HirStackItems, |limits| {
            limits.max_hir_stack_items -= 1;
        }),
        (Resource::LiteralBytes, |limits| {
            limits.max_literal_bytes -= 1;
        }),
        (Resource::ClassRanges, |limits| {
            limits.max_class_ranges -= 1;
        }),
        (Resource::ProgramStates, |limits| {
            limits.max_program_states -= 1;
        }),
        (Resource::TemporaryStates, |limits| {
            limits.max_temporary_states -= 1;
        }),
        (Resource::ProgramBytes, |limits| {
            limits.max_program_bytes -= 1;
        }),
        (Resource::CompileWork, |limits| limits.max_work -= 1),
    ];
    for (resource, lower) in cases {
        let mut limits = exact;
        lower(&mut limits);
        expect_resource(
            CompiledRegex::from_hir_erasing_captures_for_whole_match(
                &hir,
                RustByteProfile::PINNED_1_12_4,
                limits,
            ),
            resource,
        );
    }
}

#[test]
fn plan_and_operation_identities_are_deterministic_and_typed() {
    let first = compile(r"(?:(?:|a){1,2}?b?)*");
    let second = compile(r"(?:(?:|a){1,2}?b?)*");
    assert_eq!(first.plan_id(), second.plan_id());
    assert_ne!(compile("a*").plan_id(), compile("a*?").plan_id());
    let unicode_off_hir = parse("a+");
    let unicode_off = CompiledRegex::from_hir(
        &unicode_off_hir,
        RustByteProfile::PINNED_1_12_4,
        CompileLimits::default(),
    )
    .unwrap();
    let unicode_on_hir = parse_unicode_byte_stable("a+");
    let unicode_on = CompiledRegex::from_hir(
        &unicode_on_hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
    .unwrap();
    assert_ne!(unicode_off.plan_id(), unicode_on.plan_id());
    let mut assertion_ids = ASSERTION_CASES
        .iter()
        .map(|(look, _)| {
            let first = CompiledRegex::from_hir(
                &Hir::look(*look),
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
            let repeated = CompiledRegex::from_hir(
                &Hir::look(*look),
                RustByteProfile::PINNED_1_12_4,
                CompileLimits::default(),
            )
            .unwrap();
            assert_eq!(first.plan_id(), repeated.plan_id());
            first.plan_id()
        })
        .collect::<Vec<_>>();
    assertion_ids.sort_unstable();
    assertion_ids.dedup();
    assert_eq!(ASSERTION_CASES.len(), assertion_ids.len());
    let spans = first
        .admit_spans(b"ab", 0..2, Strategy::FullTable, OperationLimits::default())
        .unwrap();
    let spans_again = second
        .admit_spans(b"ab", 0..2, Strategy::FullTable, OperationLimits::default())
        .unwrap();
    let rows = first
        .admit_spans(
            b"ab",
            0..2,
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    let count = first
        .admit_count(b"ab", 0..2, Strategy::FullTable, OperationLimits::default())
        .unwrap();
    assert_eq!(
        spans.certificate().operation_id,
        spans_again.certificate().operation_id
    );
    assert_ne!(
        spans.certificate().operation_id,
        rows.certificate().operation_id
    );
    assert_ne!(
        spans.certificate().operation_id,
        count.certificate().operation_id
    );
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "consuming opaque success values keeps refusal assertions generic"
)]
fn expect_resource<T>(result: Result<T, Error>, resource: Resource) {
    assert!(
        matches!(result, Err(Error::ResourceLimit { resource: actual, .. }) if actual == resource),
        "expected resource refusal {resource:?}"
    );
}

#[test]
fn compiler_exact_limits_succeed_and_one_below_refuses() {
    let hir = parse(r"(?:(?:a|[b-d]){1,2}?|\A)*\z");
    let baseline = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4,
        CompileLimits::default(),
    )
    .unwrap();
    let stats = baseline.compile_accounting();
    let exact = CompileLimits {
        max_hir_nodes: stats.hir_nodes,
        max_hir_depth: stats.hir_depth,
        max_hir_stack_items: stats.peak_hir_stack_items,
        max_literal_bytes: stats.literal_bytes,
        max_class_ranges: stats.class_ranges,
        max_look_assertions: stats.look_assertions,
        max_program_states: stats.program_states,
        max_temporary_states: stats.temporary_states_peak,
        max_program_bytes: stats.program_bytes,
        max_work: stats.work,
        ..CompileLimits::default()
    };
    CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, exact).unwrap();
    let cases: [(Resource, LimitMutation); 10] = [
        (Resource::HirNodes, |limits| limits.max_hir_nodes -= 1),
        (Resource::HirDepth, |limits| limits.max_hir_depth -= 1),
        (Resource::HirStackItems, |limits| {
            limits.max_hir_stack_items -= 1;
        }),
        (Resource::LiteralBytes, |limits| {
            limits.max_literal_bytes -= 1;
        }),
        (Resource::ClassRanges, |limits| {
            limits.max_class_ranges -= 1;
        }),
        (Resource::LookAssertions, |limits| {
            limits.max_look_assertions -= 1;
        }),
        (Resource::ProgramStates, |limits| {
            limits.max_program_states -= 1;
        }),
        (Resource::TemporaryStates, |limits| {
            limits.max_temporary_states -= 1;
        }),
        (Resource::ProgramBytes, |limits| {
            limits.max_program_bytes -= 1;
        }),
        (Resource::CompileWork, |limits| limits.max_work -= 1),
    ];
    for (resource, lower) in cases {
        let mut limits = exact;
        lower(&mut limits);
        expect_resource(
            CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, limits),
            resource,
        );
    }
}

#[test]
fn repetition_expansion_is_quota_bounded_before_uncontrolled_growth() {
    let mut pattern = "a".to_owned();
    for _ in 0..12 {
        pattern = format!("(?:{pattern})*");
    }
    let hir = parse(&pattern);
    let limits = CompileLimits {
        max_program_states: 128,
        max_temporary_states: 256,
        ..CompileLimits::default()
    };
    assert!(matches!(
        CompiledRegex::from_hir(&hir, RustByteProfile::PINNED_1_12_4, limits),
        Err(Error::ResourceLimit {
            resource: Resource::ProgramStates | Resource::TemporaryStates,
            ..
        })
    ));

    let bounded = parse("a{7}");
    CompiledRegex::from_hir(
        &bounded,
        RustByteProfile::PINNED_1_12_4,
        CompileLimits {
            max_repeat_bound: 7,
            ..CompileLimits::default()
        },
    )
    .unwrap();
    expect_resource(
        CompiledRegex::from_hir(
            &bounded,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits {
                max_repeat_bound: 6,
                ..CompileLimits::default()
            },
        ),
        Resource::RepeatBound,
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table keeps every exact-success/one-below executor resource paired"
)]
fn operation_exact_limits_succeed_and_one_below_refuses() {
    let regex = compile(r"(?:(?:|a){1,2}?b?)*");
    for strategy in STRATEGIES {
        let baseline = regex
            .admit_spans(b"aab", 0..3, strategy, OperationLimits::default())
            .unwrap();
        let certificate = baseline.certificate();
        let expected_evaluations = certificate.states * certificate.boundaries;
        assert_eq!(
            expected_evaluations,
            baseline.accounting().state_evaluations
        );
        assert!(baseline.accounting().work <= certificate.work_bound);
        assert!(
            baseline.accounting().sequential_bytes_written
                + baseline.accounting().sequential_bytes_read
                <= certificate.sequential_bytes_bound
        );
        let exact = OperationLimits {
            max_boundaries: certificate.boundaries,
            max_table_cells: certificate.table_cells,
            max_random_access_bytes: certificate.random_access_bytes,
            max_scratch_bytes: certificate.scratch_bytes,
            max_log_bytes: certificate.log_bytes,
            max_sequential_bytes: certificate.sequential_bytes_bound,
            max_match_events: certificate.match_events,
            max_output_matches: certificate.output_matches,
            max_output_bytes: certificate.output_bytes,
            max_span_sum: certificate.span_sum,
            max_peak_bytes: certificate.peak_bytes,
            max_work: certificate.work_bound,
        };
        regex.admit_spans(b"aab", 0..3, strategy, exact).unwrap();
        let mut cases: Vec<(Resource, OperationLimits)> = Vec::new();
        let mut lower = exact;
        lower.max_boundaries -= 1;
        cases.push((Resource::Boundaries, lower));
        if certificate.table_cells > 0 {
            let mut lower = exact;
            lower.max_table_cells -= 1;
            cases.push((Resource::TableCells, lower));
        }
        if certificate.random_access_bytes > 0 {
            let mut lower = exact;
            lower.max_random_access_bytes -= 1;
            cases.push((Resource::RandomAccessBytes, lower));
        }
        if certificate.scratch_bytes > 0 {
            let mut lower = exact;
            lower.max_scratch_bytes -= 1;
            cases.push((Resource::ScratchBytes, lower));
        }
        if certificate.log_bytes > 0 {
            let mut lower = exact;
            lower.max_log_bytes -= 1;
            cases.push((Resource::LogBytes, lower));
        }
        if certificate.sequential_bytes_bound > 0 {
            let mut lower = exact;
            lower.max_sequential_bytes -= 1;
            cases.push((Resource::SequentialBytes, lower));
        }
        if certificate.match_events > 0 {
            let mut lower = exact;
            lower.max_match_events -= 1;
            cases.push((Resource::MatchEvents, lower));
        }
        if certificate.output_matches > 0 {
            let mut lower = exact;
            lower.max_output_matches -= 1;
            cases.push((Resource::OutputMatches, lower));
        }
        if certificate.output_bytes > 0 {
            let mut lower = exact;
            lower.max_output_bytes -= 1;
            cases.push((Resource::OutputBytes, lower));
        }
        if certificate.peak_bytes > 0 {
            let mut lower = exact;
            lower.max_peak_bytes -= 1;
            cases.push((Resource::PeakBytes, lower));
        }
        let mut lower = exact;
        lower.max_work -= 1;
        cases.push((Resource::ExecutionWork, lower));
        for (resource, limits) in cases {
            expect_resource(regex.admit_spans(b"aab", 0..3, strategy, limits), resource);
        }
        let sum = regex
            .admit_span_sum(b"aab", 0..3, strategy, OperationLimits::default())
            .unwrap();
        regex
            .admit_span_sum(
                b"aab",
                0..3,
                strategy,
                OperationLimits {
                    max_span_sum: sum.value(),
                    ..OperationLimits::default()
                },
            )
            .unwrap();
        if sum.value() > 0 {
            let limits = OperationLimits {
                max_span_sum: sum.value() - 1,
                ..OperationLimits::default()
            };
            expect_resource(
                regex.admit_span_sum(b"aab", 0..3, strategy, limits),
                Resource::SpanSum,
            );
        }
    }
}
