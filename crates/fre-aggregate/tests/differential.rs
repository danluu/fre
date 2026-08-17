#![allow(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic is over small, asserted test-corpus dimensions"
)]

use fre_aggregate::{
    CompileLimits, CompiledRegex, Error, ExecutionAccounting, OperationLimits,
    OperationPhysicalRoute, OperationPrepublicationFallback, Resource, RowStorage, RustByteProfile,
    Span, Strategy, Unsupported,
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
type OperationLimitMutation = fn(&mut OperationLimits) -> usize;
type StorageGate = (Resource, usize, fn(&mut OperationLimits, usize));

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

fn compile_unicode_casefold(pattern: &str) -> CompiledRegex {
    let hir = regex_syntax::ParserBuilder::new()
        .unicode(true)
        .utf8(false)
        .case_insensitive(true)
        .build()
        .parse(pattern)
        .unwrap_or_else(|error| panic!("failed to parse Unicode casefold {pattern:?}: {error}"));
    CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
    .unwrap_or_else(|error| panic!("failed to compile Unicode casefold {pattern:?}: {error}"))
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

fn assert_scalar_program_compile_limits(hir: &Hir, program_states: usize, program_bytes: usize) {
    let exact = CompileLimits {
        max_program_states: program_states,
        max_program_bytes: program_bytes,
        ..CompileLimits::default()
    };
    CompiledRegex::from_hir(
        hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        exact,
    )
    .unwrap();

    let mut lower_states = exact;
    lower_states.max_program_states -= 1;
    expect_resource(
        CompiledRegex::from_hir(
            hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            lower_states,
        ),
        Resource::ProgramStates,
    );
    let mut lower_bytes = exact;
    lower_bytes.max_program_bytes -= 1;
    expect_resource(
        CompiledRegex::from_hir(
            hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            lower_bytes,
        ),
        Resource::ProgramBytes,
    );
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
        .unwrap_or_else(|error| panic!("pinned Unicode range oracle rejected {pattern:?}: {error}"))
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
fn unicode_on_hir_matches_rebar_profile_with_scalar_classes() {
    let cases: [(&str, &[u8]); 8] = [
        ("", &[0xFF, 0x80]),
        ("雪+", "x雪雪y☃".as_bytes()),
        ("(?:雪a|☃b)", "☃b雪a雪b".as_bytes()),
        (r"[a-c]+", &[0xFF, b'a', b'b', b'd', b'c']),
        (r"(?-u:\xFF+)", &[b'a', 0xFF, 0xFF, b'b']),
        (r"\A(?:a|雪)+\z", "a雪a".as_bytes()),
        (r"\pL", "A1雪!".as_bytes()),
        ("[雪-雫]", "雨雪雫電".as_bytes()),
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
fn unicode_word_property_is_cached_by_the_budgeted_identity_pass() {
    let hir = parse_unicode_byte_stable(r"\b[a-z]+\b");
    let observed = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
    .unwrap();
    let accounting = observed.compile_accounting();
    assert_eq!(
        accounting.unicode_word_boundary_checks,
        accounting.program_states
    );
    assert!(accounting.requires_utf8_validation);
    for pattern in [r"\b", r"\b(?:a|ab|abc|abcd|abcde){1,3}\b"] {
        let sized = compile_unicode_byte_stable(pattern)
            .unwrap()
            .compile_accounting();
        assert_eq!(sized.unicode_word_boundary_checks, sized.program_states);
        assert!(sized.requires_utf8_validation);
    }
    assert!(
        !compile_unicode_byte_stable("[a-z]+")
            .unwrap()
            .compile_accounting()
            .requires_utf8_validation
    );

    let exact = CompileLimits {
        max_work: accounting.work,
        ..CompileLimits::default()
    };
    let exact_accounting = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        exact,
    )
    .unwrap()
    .compile_accounting();
    assert_eq!(exact_accounting, accounting);
    expect_exact_resource(
        CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits {
                max_work: accounting.work - 1,
                ..CompileLimits::default()
            },
        ),
        Resource::CompileWork,
        accounting.work,
        accounting.work - 1,
    );
}

#[test]
fn unicode_word_validation_scales_with_input_not_program_size() {
    let small = compile_unicode_byte_stable(r"\b").unwrap();
    let large = compile_unicode_byte_stable(r"\b(?:a|ab|abc|abcd|abcde){1,3}\b").unwrap();
    assert!(small.state_count() < large.state_count());
    for bytes in [64, 128, 256] {
        let haystack = vec![b'a'; bytes];
        for regex in [&small, &large] {
            let report = regex
                .admit_count(
                    &haystack,
                    0..haystack.len(),
                    Strategy::FullTable,
                    OperationLimits::default(),
                )
                .unwrap();
            assert_eq!(report.accounting().utf8_validation_work, bytes);
            assert_eq!(
                report.accounting().work,
                report.accounting().utf8_validation_work
                    + report.accounting().state_evaluations
                    + report.accounting().transition_checks
                    + report.accounting().root_probes
                    + report.accounting().replay_steps
                    + report.accounting().successful_paths
            );
            assert!(report.certificate().work_bound >= bytes);
            assert!(report.certificate().sequential_bytes_bound >= bytes);
        }
    }

    let no_boundary = compile_unicode_byte_stable(r"(?-u:\xFF)+").unwrap();
    let invalid = [0xFF; 8];
    let report = no_boundary
        .admit_count(
            &invalid,
            0..invalid.len(),
            Strategy::FullTable,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(report.accounting().utf8_validation_work, 0);
    assert_eq!(report.accounting().sequential_bytes_read, 0);
}

#[test]
fn unicode_word_utf8_validation_limits_are_prospective() {
    let regex = compile_unicode_byte_stable(r"\b[a-z]+\b").unwrap();
    let haystack = b"alpha beta gamma delta";
    for strategy in STRATEGIES {
        let baseline = regex
            .admit_count(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(baseline.accounting().utf8_validation_work, haystack.len());
        assert!(baseline.accounting().sequential_bytes_read >= haystack.len());

        let exact = OperationLimits {
            max_work: baseline.certificate().work_bound,
            max_sequential_bytes: baseline.certificate().sequential_bytes_bound,
            ..OperationLimits::default()
        };
        regex
            .admit_count(haystack, 0..haystack.len(), strategy, exact)
            .unwrap();
        let mut one_below_work = exact;
        one_below_work.max_work -= 1;
        expect_resource(
            regex.admit_count(haystack, 0..haystack.len(), strategy, one_below_work),
            Resource::ExecutionWork,
        );
        let mut one_below_sequential = exact;
        one_below_sequential.max_sequential_bytes -= 1;
        expect_resource(
            regex.admit_count(haystack, 0..haystack.len(), strategy, one_below_sequential),
            Resource::SequentialBytes,
        );
    }
}

#[test]
fn observed_unicode_word_utf8_validation_has_exact_work_limits() {
    let regex = compile_unicode_byte_stable(r"\b[a-z]+\b").unwrap();
    let haystack = b"alpha beta gamma delta";
    let observed = regex
        .admit_spans_observed(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    let observed_work = observed.accounting().work;
    regex
        .admit_spans_observed(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits {
                max_work: observed_work,
                ..OperationLimits::default()
            },
        )
        .unwrap();
    expect_resource(
        regex.admit_spans_observed(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits {
                max_work: observed_work - 1,
                ..OperationLimits::default()
            },
        ),
        Resource::ExecutionWork,
    );
}

#[test]
fn invalid_utf8_validation_obeys_prospective_limits() {
    let regex = compile_unicode_byte_stable(r"\b[a-z]+\b").unwrap();
    let invalid = [b'a', 0xFF, b'b', b'c'];
    expect_exact_resource(
        regex.admit_count(
            &invalid,
            0..invalid.len(),
            Strategy::FullTable,
            OperationLimits {
                max_work: invalid.len() - 1,
                ..OperationLimits::default()
            },
        ),
        Resource::ExecutionWork,
        invalid.len(),
        invalid.len() - 1,
    );
    assert!(matches!(
        regex.admit_count(
            &invalid,
            0..invalid.len(),
            Strategy::FullTable,
            OperationLimits {
                max_work: invalid.len(),
                max_sequential_bytes: invalid.len(),
                ..OperationLimits::default()
            },
        ),
        Err(Error::InvalidUtf8ForUnicodeWordBoundary)
    ));
    expect_exact_resource(
        regex.admit_count(
            &invalid,
            0..invalid.len(),
            Strategy::FullTable,
            OperationLimits {
                max_work: invalid.len(),
                max_sequential_bytes: invalid.len() - 1,
                ..OperationLimits::default()
            },
        ),
        Resource::SequentialBytes,
        invalid.len(),
        invalid.len() - 1,
    );
}

#[test]
fn unicode_word_subranges_charge_full_haystack_with_range_precedence() {
    let regex = compile_unicode_byte_stable(r"\b[a-z]+\b").unwrap();
    let haystack = b"!!alpha??";
    let report = regex
        .admit_count(
            haystack,
            2..7,
            Strategy::FullTable,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(report.accounting().utf8_validation_work, haystack.len());
    assert!(report.accounting().sequential_bytes_read >= haystack.len());
    expect_exact_resource(
        regex.admit_count(
            haystack,
            2..7,
            Strategy::FullTable,
            OperationLimits {
                max_work: haystack.len() - 1,
                ..OperationLimits::default()
            },
        ),
        Resource::ExecutionWork,
        haystack.len(),
        haystack.len() - 1,
    );
    expect_exact_resource(
        regex.admit_count(
            haystack,
            2..7,
            Strategy::FullTable,
            OperationLimits {
                max_sequential_bytes: haystack.len() - 1,
                ..OperationLimits::default()
            },
        ),
        Resource::SequentialBytes,
        haystack.len(),
        haystack.len() - 1,
    );

    let invalid_outside = [0xFF, b'a', b'b'];
    assert!(matches!(
        regex.admit_count(
            &invalid_outside,
            1..3,
            Strategy::FullTable,
            OperationLimits::default(),
        ),
        Err(Error::InvalidUtf8ForUnicodeWordBoundary)
    ));
    let invalid_start = invalid_outside.len();
    let invalid_end = invalid_start - 1;
    assert!(matches!(
        regex.admit_count(
            &invalid_outside,
            invalid_start..invalid_end,
            Strategy::FullTable,
            OperationLimits::default(),
        ),
        Err(Error::InvalidRange {
            start,
            end,
            haystack_len: 3,
        }) if start == invalid_start && end == invalid_end
    ));
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
fn required_suffix_sparse_rows_preserve_priority_and_exact_work_admission() {
    let cases: [(&str, &[u8]); 4] = [
        (r"[a-z]+ing", b"!!!!zzing!!!!aing!!!!"),
        (r"(?:zabb|b)", b"!zabb!b!zabb!"),
        (r"(?:a+?x|aa+x)", b"!aaaax!aax!"),
        (r"(?-u:[a-z\xFF]+)ing", b"!a\xFFing!zzing!"),
    ];
    for (pattern, haystack) in cases {
        let mut expanded = Vec::new();
        for _ in 0..128 {
            expanded.extend_from_slice(haystack);
        }
        let regex = compile(pattern);
        let expected = upstream(pattern, &expanded);
        let dense = regex
            .admit_spans(
                &expanded,
                0..expanded.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        let mut sparse_limits = OperationLimits {
            max_work: dense.certificate().work_bound - 1,
            ..OperationLimits::default()
        };
        let sparse = regex
            .admit_spans(
                &expanded,
                0..expanded.len(),
                Strategy::ReverseSequentialRows,
                sparse_limits,
            )
            .unwrap_or_else(|error| panic!("sparse {pattern:?} failed: {error}"));
        assert_eq!(expected, sparse.as_slice(), "{pattern:?}");
        assert!(sparse.accounting().work < dense.certificate().work_bound);
        assert_eq!(
            Some(RowStorage::SplitDecisions),
            sparse.certificate().row_storage
        );
        assert!(sparse.accounting().replay_steps > 0);
        assert_eq!(
            sparse_limits.max_work,
            sparse.certificate().work_bound,
            "the sparse certificate records its dynamic admission cap"
        );

        let exact_work = sparse.accounting().work;
        sparse_limits.max_work = exact_work;
        let exact = regex
            .admit_spans(
                &expanded,
                0..expanded.len(),
                Strategy::ReverseSequentialRows,
                sparse_limits,
            )
            .unwrap();
        assert_eq!(expected, exact.as_slice());
        sparse_limits.max_work = exact_work - 1;
        assert!(matches!(
            regex.admit_spans(
                &expanded,
                0..expanded.len(),
                Strategy::ReverseSequentialRows,
                sparse_limits,
            ),
            Err(Error::ResourceLimit {
                resource: Resource::ExecutionWork,
                required,
                limit,
            }) if required == limit + 1
        ));
    }
}

#[test]
fn terminal_byte_class_sparse_rows_preserve_priority_invalid_bytes_and_exact_work() {
    let pattern = r#"["'][^"']{0,30}[?!.]["']"#;
    let haystack = b"\"?\"|'x!'|\"a\r\n?\"|'\xFF?'|\"?\"?\"|nope";
    let regex = compile(pattern);
    assert_eq!(
        (
            regex.compile_accounting().required_suffixes,
            regex.compile_accounting().required_suffix_bytes,
        ),
        (2, 2)
    );
    let expected = upstream(pattern, haystack);
    let dense = regex
        .admit_spans(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    let mut limits = OperationLimits {
        max_work: dense.certificate().work_bound - 1,
        ..OperationLimits::default()
    };
    let sparse = regex
        .admit_spans(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        )
        .unwrap();
    assert_eq!(expected, sparse.as_slice());
    assert!(sparse.accounting().work < dense.certificate().work_bound);

    limits.max_work = sparse.accounting().work;
    assert_eq!(
        expected,
        regex
            .admit_spans(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap()
            .as_slice()
    );
    limits.max_work -= 1;
    assert!(matches!(
        regex.admit_spans(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        ),
        Err(Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            required,
            limit,
        }) if required == limit + 1
    ));
}

fn terminal_frontier_fixture() -> (&'static str, Vec<u8>) {
    let pattern = r"cargo[\\/](?:registry|registrx|registru|registra|registb|registc|registd|registe)[\\/]src[\\/][^/]+[\\/](?:a.*z|a)[\\/]";
    let chunk = b"xxcargo/registry/src/one/a/ cargo\\registry\\src\\two\\axyz\\ cargo/registry/src/\xFF/a/ cargo!cargo/registry/src/three/a/ cargcargo/registry/src/no/a/";
    (pattern, chunk.repeat(96))
}

fn forced_terminal_frontier(pattern: &str, haystack: &[u8]) -> (OperationLimits, usize) {
    let regex = compile(pattern);
    let dense = regex
        .admit_spans(
            haystack,
            0..haystack.len(),
            Strategy::FullTable,
            OperationLimits::default(),
        )
        .unwrap();
    assert!(!dense.certificate().terminal_frontier);
    (OperationLimits::default(), dense.certificate().work_bound)
}

#[test]
fn terminal_frontier_preserves_slashes_priority_unbounded_middle_and_malformed_bytes() {
    let (pattern, haystack) = terminal_frontier_fixture();
    let expected = upstream(pattern, &haystack);
    let regex = compile(pattern);
    let compile = regex.compile_accounting();
    assert_eq!(compile.required_suffixes, 0);
    assert_eq!(compile.required_suffix_bytes, 0);
    assert_eq!(compile.terminal_frontier_prefix_bytes, 5);
    assert_eq!(compile.terminal_frontier_bytes, 2);
    let (limits, _) = forced_terminal_frontier(pattern, &haystack);
    let actual = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        )
        .unwrap_or_else(|error| panic!("terminal frontier failed: {error}"));
    assert_eq!(expected, actual.as_slice());
    assert!(actual.certificate().terminal_frontier);
    assert!(actual.accounting().frontier_peak_states > 0);
    assert!(actual.accounting().frontier_insertions > 0);
    assert_eq!(
        actual.accounting().frontier_evaluations,
        actual.accounting().state_evaluations
    );
    assert!(actual.accounting().frontier_source_bytes < haystack.len() * 5);
    assert!(actual.accounting().frontier_source_bytes > haystack.len() * 2);
}

#[test]
fn terminal_frontier_exact_existing_component_limits_admit_without_widening() {
    let (pattern, haystack) = terminal_frontier_fixture();
    let regex = compile(pattern);
    let (limits, _) = forced_terminal_frontier(pattern, &haystack);
    let baseline = regex
        .admit_spans_observed(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        )
        .unwrap();
    let certificate = baseline.certificate();
    assert!(certificate.terminal_frontier);
    assert_eq!(
        certificate.row_storage,
        Some(RowStorage::ReachableEndpoints)
    );
    assert_eq!(certificate.work_bound, limits.max_work);
    assert!(certificate.random_access_bytes <= limits.max_random_access_bytes);
    assert!(certificate.scratch_bytes <= limits.max_scratch_bytes);
    assert!(certificate.log_bytes <= limits.max_log_bytes);
    assert!(certificate.sequential_bytes_bound <= limits.max_sequential_bytes);
    assert!(certificate.peak_bytes <= limits.max_peak_bytes);
    assert!(baseline.accounting().work <= limits.max_work);

    let exact = OperationLimits {
        max_random_access_bytes: certificate.random_access_bytes,
        max_scratch_bytes: certificate.scratch_bytes,
        max_log_bytes: certificate.log_bytes,
        max_sequential_bytes: certificate.sequential_bytes_bound,
        max_peak_bytes: certificate.peak_bytes,
        max_work: limits.max_work,
        ..limits
    };
    regex
        .admit_spans_observed(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            exact,
        )
        .unwrap();
    assert!(
        baseline.accounting().frontier_insertions <= baseline.accounting().frontier_bookkeeping
    );
    assert!(baseline.accounting().frontier_evaluations <= baseline.accounting().work);
    assert!(
        baseline.accounting().frontier_source_bytes
            <= baseline.certificate().sequential_bytes_bound
    );
}

#[test]
fn terminal_frontier_ineligible_controls_stay_on_existing_routes() {
    let controls = [
        r"cargo[/]x[/]",
        r"[cC]argo[/].*[/]",
        r"(?:cargo)?[/].*[/]",
        r".*cargo[/].*[/]",
    ];
    for pattern in controls {
        let accounting = compile(pattern).compile_accounting();
        assert_eq!(accounting.terminal_frontier_prefix_bytes, 0, "{pattern}");
        assert_eq!(accounting.terminal_frontier_bytes, 0, "{pattern}");
    }
    let scalar = compile_unicode(r"cargo[/].*[/]").compile_accounting();
    assert_eq!(scalar.terminal_frontier_prefix_bytes, 0);
    assert_eq!(scalar.terminal_frontier_bytes, 0);
}

#[test]
fn terminal_frontier_required_prefix_absence_skips_slash_dense_frontier_work() {
    let pattern = r"cargo[\\/].*[\\/]";
    let haystack = b"/\\//\\/not-the-required-prefix/\\//\\/".repeat(256);
    let regex = compile(pattern);
    let actual = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert!(actual.as_slice().is_empty());
    assert!(actual.certificate().terminal_frontier);
    assert_eq!(actual.accounting().frontier_insertions, 0);
    assert_eq!(actual.accounting().frontier_evaluations, 0);
    assert_eq!(actual.accounting().frontier_peak_states, 0);
    assert_eq!(actual.accounting().frontier_bytes, 0);
    assert!(actual.accounting().frontier_source_bytes > 0);
}

#[test]
fn rustsec_literal_and_root_alternate_controls_keep_existing_routes() {
    let controls = [
        r"cargo/registry/src/[^/]+/(?:[0-9A-Za-z_-]+)-(?:[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/",
        r"cargo\\registry\\src\\[^\\]+\\(?:[0-9A-Za-z_-]+)-(?:[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)\\",
        r"cargo/registry/src/[^/]+/(?:[0-9A-Za-z_-]+)-(?:[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)/|cargo\\registry\\src\\[^\\]+\\(?:[0-9A-Za-z_-]+)-(?:[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z+.-]*)\\",
    ];
    let haystack =
        b"cargo/registry/src/example/a-1.2.3/ cargo\\registry\\src\\example\\b-2.3.4\\".repeat(32);
    for pattern in controls {
        let regex = compile(pattern);
        assert_eq!(regex.compile_accounting().terminal_frontier_bytes, 0);
        let expected = upstream(pattern, &haystack);
        let actual = regex
            .admit_spans(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(actual.as_slice(), expected, "{pattern}");
        assert!(!actual.certificate().terminal_frontier, "{pattern}");
    }
}

#[test]
fn required_suffix_sparse_rows_meter_scalar_decode_and_replay() {
    let pattern = r"[é雪]+ing";
    let mut chunk = "!é雪ing!雪雪ing!éing!".as_bytes().to_vec();
    chunk.extend_from_slice(&[0xFF, b'!', 0xE9, 0x9B, b'i', b'n', b'g', b'!']);
    let mut haystack = Vec::new();
    for _ in 0..128 {
        haystack.extend_from_slice(&chunk);
    }
    let regex = compile_unicode(pattern);
    let compile = regex.compile_accounting();
    assert!(compile.has_scalar_transitions);
    assert_eq!(
        (compile.required_suffixes, compile.required_suffix_bytes),
        (1, 3)
    );
    let expected = upstream_unicode(pattern, &haystack);
    let dense = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    let mut limits = OperationLimits {
        max_work: dense.certificate().work_bound - 1,
        ..OperationLimits::default()
    };
    let sparse = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        )
        .unwrap();
    assert_eq!(expected, sparse.as_slice());
    assert_eq!(
        Some(RowStorage::SplitDecisions),
        sparse.certificate().row_storage
    );
    assert!(sparse.accounting().replay_steps > 0);
    assert!(sparse.accounting().transition_checks > 0);
    assert!(sparse.accounting().work < dense.certificate().work_bound);

    let exact_work = sparse.accounting().work;
    limits.max_work = exact_work;
    let exact = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        )
        .unwrap();
    assert_eq!(expected, exact.as_slice());
    limits.max_work = exact_work - 1;
    assert!(matches!(
        regex.admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        ),
        Err(Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            required,
            limit,
        }) if required == limit + 1
    ));
}

#[test]
fn unicode_casefold_literal_domains_seed_semantic_scalar_verification() {
    let pattern = "Шерлок Холмс";
    let regex = compile_unicode_casefold(pattern);
    assert_eq!(
        (
            regex.compile_accounting().required_suffixes,
            regex.compile_accounting().required_suffix_bytes,
        ),
        (3, 7)
    );

    let mut haystack = vec![0xFF, 0x80];
    haystack.extend_from_slice(
        "ШЕРЛОК ХОЛМС|шерлок холмс|Шерлок Холмс|шЕрЛоК хОлМс|Шерлок Холм".as_bytes(),
    );
    haystack.extend_from_slice(&[0xF4, 0x90, 0x80, 0x80]);
    let expected = regex::bytes::RegexBuilder::new(pattern)
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap()
        .find_iter(&haystack)
        .count();
    assert_eq!(expected, 4);

    let dense = regex
        .admit_count(
            &haystack,
            0..haystack.len(),
            Strategy::FullTable,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(dense.value(), expected);
    assert_eq!(
        dense.certificate().physical_route,
        OperationPhysicalRoute::DenseRows
    );

    let sparse = regex
        .admit_count(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(sparse.value(), expected);
    assert_eq!(
        sparse.certificate().physical_route,
        OperationPhysicalRoute::RequiredSuffixRows
    );
    assert_eq!(
        sparse.certificate().row_storage,
        Some(RowStorage::SplitDecisions)
    );
    assert!(sparse.accounting().work < dense.certificate().work_bound);

    let exact_work = sparse.accounting().work;
    let exact = regex
        .admit_count(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits {
                max_work: exact_work,
                ..OperationLimits::default()
            },
        )
        .unwrap();
    assert_eq!(exact.value(), expected);
    assert_eq!(exact.accounting().work, exact_work);

    assert!(matches!(
        regex.admit_count(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits {
                max_work: exact_work - 1,
                ..OperationLimits::default()
            },
        ),
        Err(Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            required,
            limit,
        }) if required == limit + 1
    ));
}

#[test]
fn required_literal_census_composes_with_unicode_casefold_suffix_domains() {
    let pattern = "QШерлок Холмс";
    let hir = regex_syntax::ParserBuilder::new()
        .unicode(true)
        .utf8(false)
        .case_insensitive(true)
        .build()
        .parse(pattern)
        .unwrap();
    let regex = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
    .unwrap();
    // The ASCII Q/q domain and the intervening ASCII space remain two
    // independent theorems in canonical source order.
    assert_eq!(regex.compile_accounting().required_literal_sets, 2);
    assert_eq!(regex.compile_accounting().required_literal_source_passes, 2);
    assert_eq!(
        (
            regex.compile_accounting().required_suffixes,
            regex.compile_accounting().required_suffix_bytes,
        ),
        (3, 7)
    );

    let missing_required_literal = "Шерлок Холмс".as_bytes();
    let missing = regex
        .admit_count_attempt(
            missing_required_literal,
            0..missing_required_literal.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(missing.admitted.value(), 0);
    assert_eq!(
        missing.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(
        missing.receipt.identity.prepublication_fallback,
        OperationPrepublicationFallback::None
    );
    assert_eq!(
        missing.receipt.actual.required_literal_source_bytes,
        missing_required_literal.len()
    );
    assert_eq!(
        missing.receipt.actual.required_literal_comparisons,
        missing_required_literal.len()
    );
    assert_eq!(missing.receipt.actual.state_evaluations, 0);
    assert_eq!(missing.receipt.actual_allocations, 0);
    assert_eq!(missing.receipt.actual.random_access_bytes_read, 0);
    assert_eq!(missing.receipt.actual.log_bytes, 0);
    assert!(missing.receipt.authenticates_success());

    let matching = "qшерлок холмс".as_bytes();
    let expected = regex::bytes::RegexBuilder::new(pattern)
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap()
        .find_iter(matching)
        .count();
    let hit = regex
        .admit_count_attempt(
            matching,
            0..matching.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(hit.admitted.value(), expected);
    assert_eq!(expected, 1);
    assert_eq!(
        hit.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(
        hit.receipt.identity.prepublication_fallback,
        OperationPrepublicationFallback::None
    );
    let required_prefix = matching.iter().position(|&byte| byte == b' ').unwrap() + 1;
    let required_service_bytes = required_prefix + 1;
    assert_eq!(
        hit.receipt.actual.required_literal_source_bytes,
        required_service_bytes
    );
    assert_eq!(
        hit.receipt.actual.required_literal_comparisons,
        required_service_bytes
    );
    assert!(hit.receipt.actual.state_evaluations > 0);
    assert!(hit.receipt.authenticates_success());
}

#[test]
fn unicode_casefold_sparse_receipts_meter_exact_source_for_all_reducers() {
    let regex = compile_unicode_casefold("k");
    let haystack = b"K";

    let count = regex
        .admit_count_attempt(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(count.admitted.value(), 1);
    assert_eq!(
        count.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(count.receipt.actual.random_access_bytes_read, 4);
    assert_eq!(count.receipt.actual, count.admitted.accounting());
    assert!(count.receipt.authenticates_success());
    assert!(
        count
            .receipt
            .prospective
            .is_some_and(|prospective| prospective.contains(count.receipt.actual))
    );

    let spans = regex
        .admit_spans_with_receipt(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(spans.admitted.as_slice(), &[Span { start: 0, end: 1 }]);
    assert_eq!(
        spans.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(spans.receipt.actual.random_access_bytes_read, 5);
    assert_eq!(spans.receipt.actual, spans.admitted.accounting());
    assert!(spans.receipt.authenticates_success());
    assert!(
        spans
            .receipt
            .prospective
            .is_some_and(|prospective| prospective.contains(spans.receipt.actual))
    );

    let sum = regex
        .admit_span_sum_with_receipt(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(sum.admitted.value(), 1);
    assert_eq!(
        sum.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(sum.receipt.actual.random_access_bytes_read, 4);
    assert_eq!(sum.receipt.actual, sum.admitted.accounting());
    assert!(sum.receipt.authenticates_success());
    assert!(
        sum.receipt
            .prospective
            .is_some_and(|prospective| prospective.contains(sum.receipt.actual))
    );
}

#[test]
fn required_suffix_receipts_meter_multibyte_scalars_and_assertions_exactly() {
    // Each row exercises a different UTF-8 width. The expected A values are
    // the deterministic sum of short-circuit seed comparisons, reverse input
    // loads, cached scalar decodes, and the selected replay decode.
    for (pattern, haystack, expected_source_bytes) in [
        ("σ", "Σ".as_bytes(), 10),
        ("k", "\u{212A}".as_bytes(), 22),
        ("\u{10428}", "\u{10400}".as_bytes(), 22),
    ] {
        let regex = compile_unicode_casefold(pattern);
        let result = regex
            .admit_count_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(result.admitted.value(), 1, "{pattern:?}");
        assert_eq!(
            result.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RequiredSuffixRows),
            "{pattern:?}"
        );
        assert_eq!(
            result.receipt.actual.random_access_bytes_read, expected_source_bytes,
            "{pattern:?}"
        );
        assert!(result.receipt.actual.transition_checks > 0, "{pattern:?}");
        assert!(result.receipt.authenticates_success(), "{pattern:?}");
    }

    let asserted = compile(r"\ba");
    let mut observed = None;
    let result = asserted
        .admit_count_observed_with_required_suffix_receipt_observer(
            b"a",
            0..1,
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
            usize::MAX,
            |prospective| {
                observed = Some(prospective);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(result.admitted.value(), 1);
    assert_eq!(result.receipt.prospective, observed);
    assert_eq!(
        result.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(result.receipt.actual.random_access_bytes_read, 6);
    assert!(result.receipt.actual.assertion_checks > 0);
    assert!(result.receipt.authenticates_success());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the four storage gates retain their complete route, P, A, and closure assertions"
)]
fn automatic_unicode_suffix_receipt_publishes_before_all_storage_gates() {
    // An unrestricted start keeps the observed selector away from the
    // start-domain accelerator, while the case-folded terminal class still
    // selects automatic sparse suffix verification.
    let regex = compile_unicode_casefold(".*k");
    let haystack = b"K";
    let baseline = regex
        .admit_count_attempt(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(baseline.admitted.value(), 1);
    assert_eq!(
        baseline.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    let prospective = baseline
        .receipt
        .prospective
        .expect("automatic suffix receipt must publish P");
    assert!(prospective.contains(baseline.receipt.actual));

    let exact = OperationLimits {
        max_random_access_bytes: prospective.random_access_bytes,
        max_scratch_bytes: prospective.scratch_bytes,
        max_log_bytes: prospective.log_bytes,
        max_sequential_bytes: prospective.sequential_bytes,
        ..OperationLimits::default()
    };
    for (name, required) in [
        ("random access", prospective.random_access_bytes),
        ("scratch", prospective.scratch_bytes),
        ("log", prospective.log_bytes),
        ("sequential", prospective.sequential_bytes),
    ] {
        assert!(required > 0, "{name} P must be nonzero");
    }
    let exact_success = regex
        .admit_count_attempt(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            exact,
        )
        .unwrap();
    assert_eq!(exact_success.admitted.value(), 1);
    assert_eq!(exact_success.receipt.prospective, Some(prospective));
    assert_eq!(
        exact_success.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(
        exact_success.receipt.actual.random_access_bytes_read,
        baseline.receipt.actual.random_access_bytes_read
    );
    assert!(exact_success.receipt.authenticates_success());

    let gates: [StorageGate; 4] = [
        (
            Resource::RandomAccessBytes,
            prospective.random_access_bytes,
            |limits, value| limits.max_random_access_bytes = value - 1,
        ),
        (
            Resource::ScratchBytes,
            prospective.scratch_bytes,
            |limits, value| limits.max_scratch_bytes = value - 1,
        ),
        (
            Resource::LogBytes,
            prospective.log_bytes,
            |limits, value| limits.max_log_bytes = value - 1,
        ),
        (
            Resource::SequentialBytes,
            prospective.sequential_bytes,
            |limits, value| limits.max_sequential_bytes = value - 1,
        ),
    ];
    for (resource, required, lower) in gates {
        let mut limits = exact;
        lower(&mut limits, required);
        let failure = regex
            .admit_count_attempt(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                limits,
            )
            .unwrap_err();
        assert_eq!(
            failure.source,
            Error::ResourceLimit {
                resource,
                required,
                limit: required - 1,
            }
        );
        assert_eq!(
            failure.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::RequiredSuffixRows)
        );
        assert_eq!(failure.receipt.prospective, Some(prospective));
        assert_eq!(failure.receipt.actual, ExecutionAccounting::default());
        assert_eq!(failure.receipt.actual_allocations, 0);
        assert!(failure.receipt.identity.authenticates_limits(limits));
        assert!(failure.receipt.authenticates_canonical());
        assert!(failure.closes());
    }
}

#[test]
fn automatic_unicode_suffix_observed_work_is_exact_and_closes_one_below() {
    let regex = compile_unicode_casefold(".*k");
    let haystack = b"K";
    let baseline = regex
        .count_value_attempt(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(baseline.value, 1);
    assert_eq!(
        baseline.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert!(baseline.receipt.actual.random_access_bytes_read > 0);
    let exact_work = baseline.receipt.actual.work;
    assert!(exact_work > 0);

    let exact_limits = OperationLimits {
        max_work: exact_work,
        ..OperationLimits::default()
    };
    let exact = regex
        .count_value_attempt(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            exact_limits,
        )
        .unwrap();
    assert_eq!(exact.value, 1);
    assert_eq!(
        exact.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(exact.receipt.actual.work, exact_work);
    assert_eq!(
        exact.receipt.actual.random_access_bytes_read,
        baseline.receipt.actual.random_access_bytes_read
    );
    assert_eq!(
        exact
            .receipt
            .prospective
            .expect("observed exact-work success must publish P")
            .work_bound,
        exact_work
    );
    assert!(exact.receipt.authenticates_success());

    let one_below = OperationLimits {
        max_work: exact_work - 1,
        ..OperationLimits::default()
    };
    let failure = regex
        .count_value_attempt(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            one_below,
        )
        .unwrap_err();
    assert_eq!(
        failure.source,
        Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            required: exact_work,
            limit: exact_work - 1,
        }
    );
    assert_eq!(
        failure.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    let refusal_prospective = failure
        .receipt
        .prospective
        .expect("observed one-below refusal must retain P");
    assert_eq!(refusal_prospective.work_bound, exact_work - 1);
    assert!(refusal_prospective.contains(failure.receipt.actual));
    assert!(failure.receipt.identity.authenticates_limits(one_below));
    assert!(failure.receipt.authenticates_canonical());
    assert!(failure.closes());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the shared suffix-path test keeps baseline, exact, and one-below receipts together"
)]
fn ordinary_required_suffix_receipt_uses_the_same_exact_source_ledger() {
    let regex = compile("ab");
    let haystack = b"ab";
    assert_eq!(
        (
            regex.compile_accounting().required_suffixes,
            regex.compile_accounting().required_suffix_bytes,
        ),
        (1, 2)
    );

    let mut observed = None;
    let baseline = regex
        .admit_count_observed_with_required_suffix_receipt_observer(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
            usize::MAX,
            |prospective| {
                observed = Some(prospective);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(baseline.admitted.value(), 1);
    assert_eq!(
        baseline.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(baseline.receipt.prospective, observed);
    assert_eq!(baseline.receipt.actual.random_access_bytes_read, 6);
    assert_eq!(baseline.receipt.actual, baseline.admitted.accounting());
    assert!(baseline.receipt.authenticates_success());
    assert!(
        baseline
            .receipt
            .prospective
            .is_some_and(|prospective| prospective.contains(baseline.receipt.actual))
    );

    let exact_work = baseline.receipt.actual.work;
    let exact_limits = OperationLimits {
        max_work: exact_work,
        ..OperationLimits::default()
    };
    let mut exact_prospective = None;
    let exact = regex
        .admit_count_observed_with_required_suffix_receipt_observer(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            exact_limits,
            usize::MAX,
            |prospective| {
                exact_prospective = Some(prospective);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(exact.admitted.value(), 1);
    assert_eq!(exact.receipt.prospective, exact_prospective);
    assert_eq!(exact.receipt.actual.work, exact_work);
    assert_eq!(exact.receipt.actual.random_access_bytes_read, 6);
    assert!(exact.receipt.authenticates_success());

    let one_below = OperationLimits {
        max_work: exact_work - 1,
        ..OperationLimits::default()
    };
    let mut refusal_prospective = None;
    let failure = regex
        .admit_count_observed_with_required_suffix_receipt_observer(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            one_below,
            usize::MAX,
            |prospective| {
                refusal_prospective = Some(prospective);
                Ok(())
            },
        )
        .unwrap_err();
    assert_eq!(
        failure.source,
        Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            required: exact_work,
            limit: exact_work - 1,
        }
    );
    assert_eq!(
        failure.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::RequiredSuffixRows)
    );
    assert_eq!(failure.receipt.prospective, refusal_prospective);
    assert!(
        failure
            .receipt
            .prospective
            .is_some_and(|prospective| prospective.contains(failure.receipt.actual))
    );
    assert!(failure.receipt.identity.authenticates_limits(one_below));
    assert!(failure.receipt.authenticates_canonical());
    assert!(failure.closes());
}

#[test]
fn unicode_casefold_suffix_domains_cover_width_changes_and_wide_refusal() {
    for (pattern, haystack) in [("k", "Kk\u{212A}!".as_bytes()), ("σ", "Σσς!".as_bytes())] {
        let regex = compile_unicode_casefold(pattern);
        let expected = regex::bytes::RegexBuilder::new(pattern)
            .unicode(true)
            .case_insensitive(true)
            .build()
            .unwrap()
            .find_iter(haystack)
            .count();
        let actual = regex
            .admit_count(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(actual.value(), expected, "{pattern}");
        assert_eq!(
            actual.certificate().physical_route,
            OperationPhysicalRoute::RequiredSuffixRows,
            "{pattern}"
        );
    }

    let wide = compile_unicode("[a-z]");
    assert_eq!(wide.compile_accounting().required_suffixes, 0);
    assert_eq!(wide.compile_accounting().required_suffix_bytes, 0);
    let wide_fallback = wide
        .admit_count_attempt(
            b"a",
            0..1,
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(wide_fallback.admitted.value(), 1);
    assert_eq!(
        wide_fallback.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::DenseRows)
    );
    assert!(wide_fallback.receipt.authenticates_success());
}

#[test]
fn forced_suffix_ordinary_and_observed_preserve_route_with_an_observed_prefix() {
    let pattern = r"\b[a-z]+ing\b";
    let haystack = b"!wording! thing singing! wording?".repeat(64);
    let expected = upstream_unicode_byte_stable(pattern, &haystack);
    let regex = compile_unicode_byte_stable(pattern).unwrap();
    assert_eq!(regex.compile_accounting().required_suffix_bytes, 3);
    let dense = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    let forced_work = dense.certificate().work_bound - 1;
    let limits = OperationLimits {
        max_work: forced_work,
        ..OperationLimits::default()
    };
    let ordinary = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        )
        .unwrap();
    let observed = regex
        .admit_spans_observed(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        )
        .unwrap();
    assert_eq!(ordinary.as_slice(), expected.as_slice());
    assert_eq!(observed.as_slice(), expected.as_slice());
    assert_eq!(ordinary.as_slice(), observed.as_slice());
    assert_eq!(
        ordinary.certificate().operation_id(),
        observed.certificate().operation_id()
    );
    assert_eq!(
        ordinary.certificate().physical_route,
        OperationPhysicalRoute::RequiredSuffixRows
    );
    assert_eq!(
        ordinary.certificate().prepublication_fallback,
        observed.certificate().prepublication_fallback
    );
    assert_eq!(
        observed.certificate().sequential_bytes_bound,
        ordinary
            .certificate()
            .sequential_bytes_bound
            .checked_add(haystack.len())
            .unwrap()
    );
    let observed_prefix_bytes = observed.accounting().required_literal_source_bytes;
    let observed_prefix_comparisons = observed.accounting().required_literal_comparisons;
    assert!(observed_prefix_bytes > 0 && observed_prefix_bytes <= haystack.len());
    assert!(observed_prefix_comparisons >= observed_prefix_bytes);
    let mut normalized_observed = observed.accounting().clone();
    normalized_observed.required_literal_source_bytes = 0;
    normalized_observed.required_literal_comparisons = 0;
    normalized_observed.sequential_bytes_read = normalized_observed
        .sequential_bytes_read
        .checked_sub(observed_prefix_bytes)
        .unwrap();
    normalized_observed.work = normalized_observed
        .work
        .checked_sub(
            observed_prefix_bytes
                .checked_add(observed_prefix_comparisons)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(normalized_observed, ordinary.accounting());
    assert_eq!(ordinary.certificate().work_bound, forced_work);
    assert!(ordinary.accounting().work <= forced_work);
    assert!(ordinary.accounting().work < dense.certificate().work_bound);
}

#[test]
fn required_suffix_sparse_rows_choose_the_narrower_endpoint_log() {
    let pattern = (1..=40)
        .map(|length| format!(r"a{{{length}}}x"))
        .collect::<Vec<_>>()
        .join("|");
    let haystack = b"!aaaaax!aaaaaaaaaax!".repeat(64);
    let regex = compile(&format!(r"(?:{pattern})"));
    let expected = upstream(&format!(r"(?:{pattern})"), &haystack);
    let dense = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    let sparse = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits {
                max_work: dense.certificate().work_bound - 1,
                ..OperationLimits::default()
            },
        )
        .unwrap();
    assert_eq!(expected, sparse.as_slice());
    assert_eq!(
        Some(RowStorage::ReachableEndpoints),
        sparse.certificate().row_storage
    );
    assert_eq!(0, sparse.accounting().replay_steps);
    assert!(sparse.accounting().work < dense.certificate().work_bound);
}

#[test]
fn sparse_suffix_selection_is_bounded_and_ineligible_inputs_stay_dense() {
    let one = compile(r"[a-z]+ing").compile_accounting();
    assert_eq!((one.required_suffixes, one.required_suffix_bytes), (1, 3));
    let alternatives = compile(r"(?:foo|bar)").compile_accounting();
    assert_eq!(
        (
            alternatives.required_suffixes,
            alternatives.required_suffix_bytes
        ),
        (2, 6)
    );
    let nullable = compile(r"(?:foo|)");
    let accounting = nullable.compile_accounting();
    assert_eq!(
        (
            accounting.required_suffixes,
            accounting.required_suffix_bytes
        ),
        (0, 0)
    );
    let dense = nullable
        .admit_count(
            b"foofoo",
            0..6,
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    let limits = OperationLimits {
        max_work: dense.certificate().work_bound - 1,
        ..OperationLimits::default()
    };
    assert!(matches!(
        nullable.admit_count(b"foofoo", 0..6, Strategy::ReverseSequentialRows, limits,),
        Err(Error::ResourceLimit {
            resource: Resource::ExecutionWork,
            ..
        })
    ));

    let unicode_word = compile_unicode_byte_stable(r"\b[a-z]+ing\b").unwrap();
    assert_eq!(unicode_word.compile_accounting().required_suffix_bytes, 3);
    assert!(matches!(
        unicode_word.admit_count(
            &[b'a', 0xFF, b'i', b'n', b'g'],
            0..5,
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        ),
        Err(Error::InvalidUtf8ForUnicodeWordBoundary)
    ));
}

#[test]
#[ignore = "16 MiB Rebar-scale semantic canary; run explicitly"]
fn required_suffix_sparse_rows_cross_the_rebar_work_refusal_boundary() {
    const HAYSTACK_LEN: usize = 16 * 1_048_576;
    const MATCHES: usize = 4_096;
    let mut haystack = vec![b'!'; HAYSTACK_LEN];
    for ordinal in 0..MATCHES {
        let start = ordinal * 4_096;
        haystack[start..start + 7].copy_from_slice(b"wording");
    }
    let regex = compile(r"[a-zA-Z]+ing");
    let limits = OperationLimits {
        max_boundaries: HAYSTACK_LEN + 1,
        max_match_events: MATCHES,
        max_output_matches: MATCHES,
        max_span_sum: HAYSTACK_LEN,
        ..OperationLimits::default()
    };
    let count = regex
        .admit_count(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            limits,
        )
        .unwrap();
    assert_eq!(count.value(), MATCHES);
    assert_eq!(count.certificate().work_bound, limits.max_work);
    assert_eq!(
        Some(RowStorage::SplitDecisions),
        count.certificate().row_storage
    );
    assert_eq!(1, count.certificate().row_record_bytes);
    assert!(count.accounting().work < limits.max_work);
    assert!(count.accounting().state_evaluations < HAYSTACK_LEN);
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
fn scalar_native_unicode_classes_bound_states_rows_and_search_work() {
    let pattern = r"^\w{5}\s\w{6}\s\w{7}$";
    let hir = parse_unicode(pattern);
    let regex = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        CompileLimits::default(),
    )
    .unwrap();
    let compile = regex.compile_accounting();
    assert!(compile.class_ranges > 100);
    assert!(regex.state_count() < 128, "states={}", regex.state_count());
    assert!(compile.has_scalar_transitions);
    assert!(compile.execution_state_work > compile.program_states);
    assert!(compile.max_scalar_search_checks > 1);

    assert_scalar_program_compile_limits(&hir, compile.program_states, compile.program_bytes);

    let cases: [&[u8]; 4] = [
        b"alpha beta12 seven77",
        "αβγδε привет русский".as_bytes(),
        b"alpha beta12 seven7!",
        b"alpha beta12 seve\xFF77",
    ];
    for haystack in cases {
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
            assert_eq!(actual.iter().collect::<Vec<_>>(), expected);
        }
    }

    let haystack = "αβγδε привет русский".as_bytes();
    let rows = regex
        .admit_count(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(rows.value(), 1);
    let certificate = rows.certificate();
    let expected_work_bound = certificate.boundaries()
        * (compile.execution_state_work + usize::from(compile.has_scalar_transitions))
        + certificate.boundaries() * 4
        + certificate.states * certificate.boundaries() * (4 + compile.max_scalar_search_checks);
    assert_eq!(certificate.work_bound, expected_work_bound);
    assert_eq!(
        certificate.random_access_bytes,
        regex.state_count() * 2 * core::mem::size_of::<usize>()
    );
    assert!(rows.accounting().work <= certificate.work_bound);
    regex
        .admit_count(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits {
                max_work: certificate.work_bound,
                ..OperationLimits::default()
            },
        )
        .unwrap();
    expect_resource(
        regex.admit_count(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits {
                max_work: certificate.work_bound - 1,
                ..OperationLimits::default()
            },
        ),
        Resource::ExecutionWork,
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the adversarial fixture keeps compile and execution quota boundaries together"
)]
fn huge_scalar_class_nested_stars_preflight_clone_work_and_persistent_bytes() {
    const RANGE_COUNT: u32 = 1 << 16;
    let ranges = (0..RANGE_COUNT).map(|index| {
        let scalar = char::from_u32(0x1_0000 + index * 2).expect("valid non-BMP scalar");
        regex_syntax::hir::ClassUnicodeRange::new(scalar, scalar)
    });
    let mut hir = Hir::class(regex_syntax::hir::Class::Unicode(
        regex_syntax::hir::ClassUnicode::new(ranges),
    ));
    let generous = CompileLimits {
        max_program_bytes: 128 << 20,
        max_work: 64 << 20,
        ..CompileLimits::default()
    };
    let plain = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        generous,
    )
    .unwrap()
    .compile_accounting();
    for _ in 0..2 {
        hir = Hir::repetition(regex_syntax::hir::Repetition {
            min: 0,
            max: None,
            greedy: true,
            sub: Box::new(hir),
        });
    }

    let regex = CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        generous,
    )
    .unwrap();
    let compile = regex.compile_accounting();
    assert_eq!(
        compile.class_ranges,
        usize::try_from(RANGE_COUNT).expect("range count fits usize")
    );
    assert!(compile.program_bytes > plain.program_bytes + (4 << 20));
    assert!(
        compile.work
            > plain.work + usize::try_from(RANGE_COUNT).expect("range count fits usize") * 4
    );

    let exact = CompileLimits {
        max_program_bytes: compile.program_bytes,
        max_work: compile.work,
        ..generous
    };
    CompiledRegex::from_hir(
        &hir,
        RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
        exact,
    )
    .unwrap();
    expect_resource(
        CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits {
                max_program_bytes: compile.program_bytes - 1,
                ..generous
            },
        ),
        Resource::ProgramBytes,
    );
    expect_resource(
        CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits {
                max_work: compile.work - 1,
                ..generous
            },
        ),
        Resource::CompileWork,
    );
    expect_resource(
        CompiledRegex::from_hir(
            &hir,
            RustByteProfile::PINNED_1_12_4_UNICODE_ON_BYTE_STABLE,
            CompileLimits {
                max_program_bytes: 1,
                ..generous
            },
        ),
        Resource::ProgramBytes,
    );

    let haystack = "𐀀x𐀂".as_bytes();
    for strategy in STRATEGIES {
        let admitted = regex
            .admit_count(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        let work = admitted.accounting().work;
        assert!(work > 0);
        assert_eq!(
            admitted.value(),
            regex
                .count_value(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits {
                        max_work: work,
                        ..OperationLimits::default()
                    },
                )
                .unwrap()
        );
        expect_resource(
            regex.count_value(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: work - 1,
                    ..OperationLimits::default()
                },
            ),
            Resource::ExecutionWork,
        );
    }
}

#[test]
fn scalar_transitions_reject_malformed_sequences_without_crossing_byte_boundaries() {
    let pattern = r"[é雪🦀]+";
    let regex = compile_unicode(pattern);
    let cases: [&[u8]; 8] = [
        "é雪🦀".as_bytes(),
        b"\xC3",
        b"\xC3x",
        b"\xE9\x9B",
        b"\xF0\x9F\xA6",
        b"\xC0\xAF",
        b"\xED\xA0\x80",
        b"\xF4\x90\x80\x80",
    ];
    for haystack in cases {
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
            assert_eq!(actual.as_slice(), expected, "{strategy:?} {haystack:?}");
        }
    }
}

#[test]
fn unicode_ranges_keep_byte_offsets_and_original_anchor_context() {
    let haystack = [
        b'x', 0xC3, 0xA9, b'/', 0xE9, 0x9B, 0xAA, b'/', 0xF0, 0x9F, 0xA6, 0x80, 0xFF, b'z',
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
            assert_eq!(length + 1, certificate.boundaries());
            assert_eq!(length, certificate.output_matches);
            assert_eq!(length, certificate.span_sum);
            if strategy == Strategy::FullTable {
                assert_eq!(
                    certificate.states * certificate.boundaries(),
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
fn crlf_and_directional_unicode_assertions_match_pinned_rust() {
    let crlf_haystacks: &[&[u8]] = &[b"", b"a\r\nb\rc\nd", b"\r\n\r\n"];
    for pattern in [r"(?Rm:^)", r"(?Rm:$)"] {
        let regex = compile(pattern);
        for &haystack in crlf_haystacks {
            let expected = upstream(pattern, haystack);
            for strategy in STRATEGIES {
                let actual = regex
                    .admit_spans(
                        haystack,
                        0..haystack.len(),
                        strategy,
                        OperationLimits::default(),
                    )
                    .unwrap();
                assert_eq!(actual.as_slice(), expected, "{strategy:?} {pattern:?}");
            }
        }
    }

    let unicode_haystacks: &[&[u8]] = &[
        b"",
        b"ascii - 42",
        "é-東京_42".as_bytes(),
        "雪 Ж".as_bytes(),
    ];
    for pattern in [
        r"\B",
        r"\b{start}",
        r"\b{end}",
        r"\b{start-half}",
        r"\b{end-half}",
    ] {
        let regex = compile_unicode(pattern);
        for &haystack in unicode_haystacks {
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
                assert_eq!(actual.as_slice(), expected, "{strategy:?} {pattern:?}");
            }
        }
    }
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
        let construction_checks = 2 * baseline.certificate().boundaries();
        if strategy == Strategy::FullTable {
            assert_eq!(construction_checks, accounting.assertion_checks);
        } else {
            assert!(accounting.assertion_checks > construction_checks);
        }
        assert!(accounting.assertion_checks <= accounting.transition_checks);
        assert!(accounting.work <= baseline.certificate().work_bound);
        assert_eq!(
            accounting.work,
            accounting.state_evaluations
                + accounting.transition_checks
                + accounting.root_probes
                + accounting.replay_steps
                + accounting.successful_paths,
            "{strategy:?} admitted work must equal the disjoint charged counters"
        );

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
fn sparse_start_count_and_sum_match_pinned_rust_at_every_byte_range() {
    let patterns = [
        r"\A(?:a|ab)*b?",
        r"\A(?:a*?b|ab*)",
        r"\A(?:|a)*",
        r"(?m:^)(?:a|ab)*b?",
        r"(?m:^)(?:a*?b|ab*)",
        r"(?m:^)(?:)",
        r"(?Rm:^)(?:a|ab)*?b?",
        r"(?Rm:^)(?:)",
        r"(?m:^)((?:a|ab)*)(b?)",
    ];
    let haystacks: &[&[u8]] = &[
        b"",
        b"a",
        b"ab",
        b"\r\n",
        b"a\nab\rb\r\n",
        &[0xFF, b'a', b'\n', 0x80, b'b'],
    ];
    let config = MetaRegex::config().utf8_empty(false);
    let syntax = regex_automata::util::syntax::Config::new()
        .unicode(false)
        .utf8(false);
    for pattern in patterns {
        let expected_route = if matches!(pattern, r"(?m:^)(?:)" | r"(?Rm:^)(?:)") {
            OperationPhysicalRoute::RootAssertion
        } else {
            OperationPhysicalRoute::StartDomain
        };
        let hir = parse(pattern);
        let compiled = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &hir,
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let oracle = MetaRegex::builder()
            .configure(config.clone())
            .syntax(syntax)
            .build(pattern)
            .unwrap_or_else(|error| {
                panic!("pinned sparse-start oracle rejected {pattern:?}: {error}")
            });
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let range = start..end;
                    let expected = oracle
                        .find_iter(Input::new(haystack).span(range.clone()))
                        .map(|matched| Span {
                            start: matched.start(),
                            end: matched.end(),
                        })
                        .collect::<Vec<_>>();
                    let count = compiled
                        .count_value_attempt(
                            haystack,
                            range.clone(),
                            Strategy::ReverseSequentialRows,
                            OperationLimits::default(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("count failed {pattern:?} {haystack:?} {range:?}: {error}")
                        });
                    assert_eq!(
                        count.value,
                        expected.len(),
                        "{pattern:?} {haystack:?} {range:?}"
                    );
                    assert_eq!(count.receipt.identity.physical_route, Some(expected_route));
                    let sum = compiled
                        .span_sum_value_with_receipt(
                            haystack,
                            range.clone(),
                            Strategy::ReverseSequentialRows,
                            OperationLimits::default(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("sum failed {pattern:?} {haystack:?} {range:?}: {error}")
                        });
                    assert_eq!(
                        sum.value,
                        expected
                            .iter()
                            .map(|span| span.end.checked_sub(span.start).unwrap())
                            .sum::<usize>(),
                        "{pattern:?} {haystack:?} {range:?}"
                    );
                    assert_eq!(sum.receipt.identity.physical_route, Some(expected_route));
                }
            }
        }
    }
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
    assert_eq!(None, spans.certificate().row_storage);
    assert_eq!(0, spans.certificate().row_record_bytes);
    assert!(rows.certificate().row_storage.is_some());
    assert_eq!(
        rows.certificate().log_bytes,
        rows.certificate().row_record_bytes * rows.certificate().boundaries()
    );
    assert_eq!(
        spans.certificate().operation_id(),
        spans_again.certificate().operation_id()
    );
    assert_ne!(
        spans.certificate().operation_id(),
        rows.certificate().operation_id()
    );
    assert_ne!(
        spans.certificate().operation_id(),
        count.certificate().operation_id()
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

#[allow(
    clippy::needless_pass_by_value,
    reason = "consuming opaque success values keeps exact refusal assertions generic"
)]
fn expect_exact_resource<T>(
    result: Result<T, Error>,
    resource: Resource,
    required: usize,
    limit: usize,
) {
    assert!(
        matches!(
            result,
            Err(Error::ResourceLimit {
                resource: actual,
                required: actual_required,
                limit: actual_limit,
            }) if actual == resource && actual_required == required && actual_limit == limit
        ),
        "expected exact {resource:?} refusal requiring {required} with limit {limit}"
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
        let expected_evaluations = certificate.states * certificate.boundaries();
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
            max_boundaries: certificate.boundaries(),
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

#[test]
fn span_diagnostics_can_use_observed_work_without_losing_evidence() {
    let regex = compile(r"(?:(?:|a){1,2}?b?)*");
    let haystack = b"aab";
    for strategy in STRATEGIES {
        let diagnostic_spans = regex
            .admit_spans(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        let span_work = diagnostic_spans.accounting().work;
        assert!(span_work < diagnostic_spans.certificate().work_bound);
        let observed_limits = OperationLimits {
            max_work: span_work,
            ..OperationLimits::default()
        };
        let observed_spans = regex
            .admit_spans_observed(haystack, 0..haystack.len(), strategy, observed_limits)
            .unwrap();
        assert_eq!(diagnostic_spans.as_slice(), observed_spans.as_slice());
        assert!(
            diagnostic_spans
                .certificate()
                .authenticates_limits(OperationLimits::default())
        );
        assert!(
            observed_spans
                .certificate()
                .authenticates_limits(observed_limits)
        );
        let mut normalized_observed_certificate = observed_spans.certificate().clone();
        normalized_observed_certificate.operation_limits_id =
            diagnostic_spans.certificate().operation_limits_id;
        assert_eq!(
            diagnostic_spans.certificate(),
            &normalized_observed_certificate
        );
        assert_eq!(diagnostic_spans.accounting(), observed_spans.accounting());
        expect_resource(
            regex.admit_spans(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: span_work,
                    ..OperationLimits::default()
                },
            ),
            Resource::ExecutionWork,
        );
        expect_resource(
            regex.admit_spans_observed(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: span_work - 1,
                    ..OperationLimits::default()
                },
            ),
            Resource::ExecutionWork,
        );
    }
}

#[test]
fn value_reducers_enforce_observed_work_instead_of_replay_upper_bound() {
    let regex = compile(r"(?:(?:|a){1,2}?b?)*");
    let haystack = b"aab";
    for strategy in STRATEGIES {
        let admitted_count = regex
            .admit_count(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        let count_work = admitted_count.accounting().work;
        assert!(count_work < admitted_count.certificate().work_bound);
        assert_eq!(
            admitted_count.value(),
            regex
                .count_value(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits {
                        max_work: count_work,
                        ..OperationLimits::default()
                    },
                )
                .unwrap()
        );
        expect_resource(
            regex.count_value(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: count_work - 1,
                    ..OperationLimits::default()
                },
            ),
            Resource::ExecutionWork,
        );

        let admitted_sum = regex
            .admit_span_sum(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits::default(),
            )
            .unwrap();
        let sum_work = admitted_sum.accounting().work;
        assert!(sum_work < admitted_sum.certificate().work_bound);
        assert_eq!(
            admitted_sum.value(),
            regex
                .span_sum_value(
                    haystack,
                    0..haystack.len(),
                    strategy,
                    OperationLimits {
                        max_work: sum_work,
                        ..OperationLimits::default()
                    },
                )
                .unwrap()
        );
        expect_resource(
            regex.span_sum_value(
                haystack,
                0..haystack.len(),
                strategy,
                OperationLimits {
                    max_work: sum_work - 1,
                    ..OperationLimits::default()
                },
            ),
            Resource::ExecutionWork,
        );
    }
}

#[test]
fn reverse_rows_choose_narrow_reachable_endpoints_without_changing_selection() {
    let cases: [(&str, &[u8]); 3] = [
        (
            r"(?:a|bb|ccc|dddd|eeeee|ffffff|ggggggg|hhhhhhhh|iiiiiiiii|jjjjjjjjjj)+?",
            b"xajjjjjjjjjjbbiiiiiiiiiyddddz",
        ),
        (
            r"(?:|ab|bcd|cdef|defgh|efghij|fghijkl|ghijklmn|hijklmnop|ijklmnopqr)",
            b"zabijklmnopqrx",
        ),
        (
            r"(?m)^(?:alpha|bravo|charlie|delta|echo|foxtrot|golf|hotel|india|juliett)$",
            b"alpha\nnope\njuliett\ncharlie",
        ),
    ];
    for (pattern, haystack) in cases {
        let regex = compile(pattern);
        let expected = upstream(pattern, haystack);
        let full = regex
            .admit_spans(
                haystack,
                0..haystack.len(),
                Strategy::FullTable,
                OperationLimits::default(),
            )
            .unwrap();
        let rows = regex
            .admit_spans(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
            )
            .unwrap();
        assert_eq!(expected, full.as_slice(), "full table: {pattern:?}");
        assert_eq!(expected, rows.as_slice(), "borrowed rows: {pattern:?}");
        assert_eq!(full.as_slice(), rows.as_slice(), "strategy: {pattern:?}");
        let certificate = rows.certificate();
        assert_eq!(
            Some(RowStorage::ReachableEndpoints),
            certificate.row_storage
        );
        assert_eq!(1, certificate.row_record_bytes);
        assert_eq!(certificate.boundaries(), certificate.log_bytes);
        assert_eq!(0, rows.accounting().replay_steps);
        assert!(
            rows.accounting().sequential_bytes_written + rows.accounting().sequential_bytes_read
                <= certificate.sequential_bytes_bound
        );
    }
}

#[test]
fn equal_width_reverse_rows_keep_split_decisions() {
    let regex = compile(r"(?:a|bb)");
    let rows = regex
        .admit_spans(
            b"a",
            0..1,
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(
        Some(RowStorage::SplitDecisions),
        rows.certificate().row_storage
    );
    assert_eq!(1, rows.certificate().row_record_bytes);
    assert!(rows.accounting().replay_steps > 0);
}

fn sparse_endpoint_pattern() -> String {
    let fillers = (1..=40)
        .map(|length| format!(r"z{{{length}}}"))
        .collect::<Vec<_>>()
        .join("|");
    format!(r"(?:ab|a|\xFFa|\xFF||{fillers})")
}

#[test]
fn reverse_rows_select_sparse_reachable_endpoints_without_semantic_changes() {
    let pattern = sparse_endpoint_pattern();
    let haystack = b"ab\xFFa\xFFx";
    let expected = upstream(&pattern, haystack);
    let full = compile(&pattern)
        .admit_spans(
            haystack,
            0..haystack.len(),
            Strategy::FullTable,
            OperationLimits::default(),
        )
        .unwrap();
    let regex = compile(&pattern);
    let rows = regex
        .admit_spans(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(expected, full.as_slice());
    assert_eq!(expected, rows.as_slice());
    assert_eq!(
        Some(RowStorage::ReachableEndpoints),
        rows.certificate().row_storage
    );
    assert_eq!(1, rows.certificate().row_record_bytes);
    assert_eq!(
        rows.certificate().boundaries(),
        rows.certificate().log_bytes
    );
    let accounting = rows.accounting();
    assert_eq!(0, accounting.replay_steps);
    assert_eq!(
        rows.certificate().states * rows.certificate().boundaries(),
        accounting.state_evaluations
    );
    assert_eq!(
        rows.certificate().log_bytes,
        accounting.sequential_bytes_written
    );
    assert_eq!(
        rows.certificate().log_bytes * 2,
        accounting.sequential_bytes_read
    );
    assert_eq!(
        rows.certificate().log_bytes * 3,
        rows.certificate().sequential_bytes_bound
    );
    assert_eq!(
        accounting.work,
        accounting.state_evaluations
            + accounting.transition_checks
            + accounting.root_probes
            + accounting.replay_steps
            + accounting.successful_paths
    );
}

#[test]
fn reachable_endpoint_exact_limits_succeed_and_one_below_refuses() {
    let pattern = sparse_endpoint_pattern();
    let haystack = b"ab\xFFa\xFFx";
    let regex = compile(&pattern);
    let rows = regex
        .admit_spans(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    let certificate = rows.certificate();
    let exact = OperationLimits {
        max_boundaries: certificate.boundaries(),
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
    regex
        .admit_spans(
            haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            exact,
        )
        .unwrap();

    let cases: [(Resource, usize, OperationLimitMutation); 4] = [
        (Resource::LogBytes, exact.max_log_bytes, |limits| {
            limits.max_log_bytes -= 1;
            limits.max_log_bytes
        }),
        (
            Resource::SequentialBytes,
            exact.max_sequential_bytes,
            |limits| {
                limits.max_sequential_bytes -= 1;
                limits.max_sequential_bytes
            },
        ),
        (Resource::ExecutionWork, exact.max_work, |limits| {
            limits.max_work -= 1;
            limits.max_work
        }),
        (Resource::PeakBytes, exact.max_peak_bytes, |limits| {
            limits.max_peak_bytes -= 1;
            limits.max_peak_bytes
        }),
    ];
    for (resource, required, lower) in cases {
        let mut below = exact;
        let limit = lower(&mut below);
        expect_exact_resource(
            regex.admit_spans(
                haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                below,
            ),
            resource,
            required,
            limit,
        );
    }
}

#[test]
fn reachable_endpoints_preserve_unicode_paths_and_invalid_bytes() {
    let fillers = (1..=24)
        .map(|length| format!(r"z{{{length}}}"))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = format!(r"(?:🦀|雪|é|a|(?-u:\xFF)||{fillers})");
    let haystack = [
        &[0xFF][..],
        "aé雪🦀".as_bytes(),
        &[0x80, b'a', 0xC3, 0xA9, 0xFF],
    ]
    .concat();
    let expected = upstream_unicode(&pattern, &haystack);
    let regex = compile_unicode(&pattern);
    let rows = regex
        .admit_spans(
            &haystack,
            0..haystack.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
        )
        .unwrap();
    assert_eq!(expected, rows.as_slice());
    assert_eq!(
        Some(RowStorage::ReachableEndpoints),
        rows.certificate().row_storage
    );
    assert_eq!(0, rows.accounting().replay_steps);
}

#[test]
fn receipt_bounded_pair_span_visit_matches_hostile_oracles_and_refuses_before_callbacks() {
    let fixtures = [
        (r"Holmes.{0,25}Watson|Watson.{0,25}Holmes", {
            let mut haystack = b"x".repeat(8_192);
            haystack[17..30].copy_from_slice(b"Holmes Watson");
            haystack[4_117..4_130].copy_from_slice(b"Watson Holmes");
            haystack
        }),
        (
            r"Holmes.{0,25}Watson|Watson.{0,25}Holmes",
            b"Holmes Watsonx".repeat(586),
        ),
        (r"Holmes.{0,25}Watson|Watson.{0,25}Holmes", {
            let mut haystack = b"Holmesx".repeat(1_170);
            haystack.extend_from_slice(b"Watson");
            haystack
        }),
        (
            r"Holmes.{0,25}Watson|Watson.{0,25}Holmes",
            b"z".repeat(8_192),
        ),
        (
            r"a[xy]{1,3}b|b[xy]{1,3}a",
            b"axxb---byxa--ayb--bxxxa--a\xffb".repeat(256),
        ),
        (
            r"a.{1,2}b|b.{1,2}a",
            b"a\xffb--b\0a--axyb--b\na".repeat(384),
        ),
        (r"Tom.{10,25}river|river.{10,25}Tom", {
            let mut haystack = b"x".repeat(8_192);
            haystack[31..49].copy_from_slice(b"Tom0123456789river");
            haystack[4_111..4_134].copy_from_slice(b"river012345678901234Tom");
            haystack
        }),
    ];
    for (fixture_index, (pattern, haystack)) in fixtures.into_iter().enumerate() {
        let regex = CompiledRegex::from_hir_erasing_captures_for_whole_match(
            &parse(pattern),
            RustByteProfile::PINNED_1_12_4,
            CompileLimits::default(),
        )
        .unwrap();
        let expected = upstream(pattern, &haystack);
        let mut visited = Vec::new();
        let visit = regex
            .admit_span_visit_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits::default(),
                |span| visited.push(span),
            )
            .unwrap();
        assert_eq!(visited, expected, "{pattern:?}, fixture {fixture_index}");
        assert_eq!(
            visit.admitted.matches(),
            expected.len(),
            "{pattern:?}, fixture {fixture_index}"
        );
        assert_eq!(
            visit.receipt.identity.physical_route,
            Some(OperationPhysicalRoute::StateByteSpanSum),
            "{pattern:?}, fixture {fixture_index}"
        );
        let prospective = visit.receipt.prospective.unwrap();
        assert_eq!(prospective.span_sum, haystack.len());
        assert!(prospective.contains(visit.receipt.actual));

        let mut refused_callbacks = 0_usize;
        let refusal = regex
            .admit_span_visit_with_receipt(
                &haystack,
                0..haystack.len(),
                Strategy::ReverseSequentialRows,
                OperationLimits {
                    max_span_sum: prospective.span_sum - 1,
                    ..OperationLimits::default()
                },
                |_| refused_callbacks += 1,
            )
            .unwrap_err();
        assert_eq!(
            refused_callbacks, 0,
            "{pattern:?}, fixture {fixture_index}"
        );
        assert!(matches!(
            refusal.source,
            Error::ResourceLimit {
                resource: Resource::SpanSum,
                ..
            }
        ));
        assert_eq!(refusal.receipt.actual, ExecutionAccounting::default());
        assert_eq!(refusal.receipt.actual_allocations, 0);
    }

    let small = b"Holmes Watson";
    let regex = CompiledRegex::from_hir_erasing_captures_for_whole_match(
        &parse(r"Holmes.{0,25}Watson|Watson.{0,25}Holmes"),
        RustByteProfile::PINNED_1_12_4,
        CompileLimits::default(),
    )
    .unwrap();
    let mut small_visited = Vec::new();
    let visit = regex
        .admit_span_visit_with_receipt(
            small,
            0..small.len(),
            Strategy::ReverseSequentialRows,
            OperationLimits::default(),
            |span| small_visited.push(span),
        )
        .unwrap();
    assert_eq!(
        small_visited,
        upstream(r"Holmes.{0,25}Watson|Watson.{0,25}Holmes", small)
    );
    assert_eq!(
        visit.receipt.identity.physical_route,
        Some(OperationPhysicalRoute::StateByteSpanSum)
    );
}
