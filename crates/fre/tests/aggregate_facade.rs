use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateContinuationSemantics, AggregateEngineError, AggregateExactLiteralSemantics,
    AggregateExecutionDetails, AggregateExecutionSource, AggregateLiteralIneligibility,
    AggregateOperation, AggregatePlanIdentity, AggregatePlanKind, AggregatePlanSelection,
    AggregateResource, AggregateRunLimits, AggregateStrategy, LiteralAggregateBuildError,
    LiteralAggregateBuildLimits, LiteralAggregateOperation, LiteralAggregateReduceError, PlanKind,
    PortableBuilder, RustProfile, SearchLimits,
};
use regex_syntax::hir::Look;

const STRATEGIES: [AggregateStrategy; 2] = [
    AggregateStrategy::FullTable,
    AggregateStrategy::ReverseSequentialRows,
];

fn aggregate_builder(pattern: impl Into<String>) -> AggregateBuilder {
    AggregateBuilder::new(pattern).profile(RustProfile::rebar_1_12_4())
}

#[test]
fn compile_artifact_is_complete_isolated_and_verifiable_across_pattern_families() {
    let cases: [(&str, &[u8], bool, u64, AggregatePlanKind); 4] = [
        ("aba", b"abaaba", false, 2, AggregatePlanKind::ExactLiteral),
        (
            r"a|bc",
            b"abc",
            false,
            2,
            AggregatePlanKind::FiniteOrderedLiterals,
        ),
        (
            r"(?:a+b|a)",
            b"aaaab",
            false,
            1,
            AggregatePlanKind::ContinuationProgram,
        ),
        (
            r"(?P<word>[a-z]+)",
            b"Ab C",
            true,
            2,
            AggregatePlanKind::ContinuationProgram,
        ),
    ];
    for (pattern, haystack, case_insensitive, expected, plan) in cases {
        let first = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(case_insensitive)
            .build_compile()
            .expect("fresh compile artifact");
        let second = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(case_insensitive)
            .build_compile()
            .expect("independent compile artifact");
        assert_eq!(first.build_report().operation, AggregateOperation::Compile);
        assert_eq!(first.build_report().plan, plan);
        assert!(!std::sync::Arc::ptr_eq(
            &first.build_report().syntax_key,
            &second.build_report().syntax_key,
        ));
        assert_eq!(first.build_report(), second.build_report());

        let verified = first
            .verify_count(haystack, AggregateRunLimits::default())
            .expect("untimed verification");
        assert_eq!(verified.value(), expected);
        assert_eq!(
            verified.report().identity.operation,
            AggregateOperation::Compile
        );
    }
}

#[test]
fn compile_artifact_preserves_typed_failure_and_work_accounting() {
    assert!(matches!(
        aggregate_builder("(").unicode(false).build_compile(),
        Err(AggregateBuildError::Syntax {
            operation: AggregateOperation::Compile,
            ..
        })
    ));
    let no_planner_work = AggregateBuildLimits {
        max_literal_planner_work: 0,
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        aggregate_builder("literal")
            .unicode(false)
            .limits(no_planner_work)
            .build_compile(),
        Err(AggregateBuildError::LiteralPlannerWorkLimit {
            operation: AggregateOperation::Compile,
            needed: 1,
            limit: 0,
            ..
        })
    ));

    let compiled = aggregate_builder(r"a(?:b|c)+")
        .unicode(false)
        .build_compile()
        .expect("accounted continuation compile");
    let AggregateBuildAccounting::Continuation(accounting) = compiled.build_report().build else {
        panic!("non-literal family should retain continuation accounting")
    };
    assert!(accounting.hir_nodes > 0);
    assert!(accounting.program_states > 0);
    assert!(accounting.program_bytes > 0);
    assert!(accounting.work >= accounting.hir_nodes);
    assert_eq!(
        compiled.build_report().retained_capacity_bytes,
        accounting.program_bytes
    );

    let literal = aggregate_builder("needle")
        .unicode(false)
        .build_compile()
        .expect("baseline literal compile");
    let AggregateBuildAccounting::ExactLiteral(literal_accounting) = literal.build_report().build
    else {
        panic!("literal family should retain exact allocation accounting")
    };
    assert!(literal_accounting.persistent_bytes > 0);
    let one_below_persistent = AggregateBuildLimits {
        exact_literal: LiteralAggregateBuildLimits {
            max_persistent_bytes: literal_accounting.persistent_bytes - 1,
            ..LiteralAggregateBuildLimits::default()
        },
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        aggregate_builder("needle")
            .unicode(false)
            .limits(one_below_persistent)
            .build_compile(),
        Err(AggregateBuildError::ExactLiteralBuild {
            operation: AggregateOperation::Compile,
            source: LiteralAggregateBuildError::PersistentLimit { .. },
            ..
        })
    ));
}

fn portable_builder(pattern: impl Into<String>) -> PortableBuilder {
    PortableBuilder::new(pattern).profile(RustProfile::rebar_1_12_4())
}

#[test]
fn selected_rebar_profile_reaches_reports_and_option_updates_preserve_stamps() {
    let expected = RustProfile::rebar_1_12_4();
    let aggregate = aggregate_builder("a")
        .unicode(false)
        .case_insensitive(true)
        .build_count()
        .expect("Rebar-profile aggregate builds");
    let fre_syntax::CompatibilityProfile::RustBytes(actual) =
        &aggregate.build_report().syntax_key.profile
    else {
        panic!("aggregate report retained another profile family")
    };
    assert_eq!(actual.regex, expected.regex);
    assert_eq!(actual.regex_automata, expected.regex_automata);
    assert_eq!(actual.regex_syntax, expected.regex_syntax);
    assert_eq!(actual.constructor, expected.constructor);
    assert!(!actual.options.unicode);
    assert!(actual.options.case_insensitive);

    let portable = portable_builder("a")
        .unicode(false)
        .build()
        .expect("Rebar-profile portable plan builds");
    assert_eq!(&portable.build_report().profile, portable.profile());
    let fre_syntax::CompatibilityProfile::RustBytes(actual) = &portable.build_report().profile
    else {
        panic!("portable report retained another profile family")
    };
    assert_eq!(actual.regex, expected.regex);
    assert_eq!(actual.regex_automata, expected.regex_automata);
    assert_eq!(actual.regex_syntax, expected.regex_syntax);
    assert_eq!(actual.constructor, expected.constructor);
    assert!(!actual.options.unicode);
}

fn upstream(pattern: &str, haystack: &[u8], case_insensitive: bool) -> Vec<(usize, usize)> {
    upstream_profile(pattern, haystack, case_insensitive, false)
}

fn upstream_profile(
    pattern: &str,
    haystack: &[u8],
    case_insensitive: bool,
    unicode: bool,
) -> Vec<(usize, usize)> {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(unicode)
        .case_insensitive(case_insensitive)
        .build()
        .unwrap_or_else(|error| panic!("upstream rejected {pattern:?}: {error}"))
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

fn continuation_details(
    details: &AggregateExecutionDetails,
) -> (
    &fre::AggregateOperationCertificate,
    &fre::AggregateExecutionAccounting,
) {
    match details {
        AggregateExecutionDetails::Continuation {
            certificate,
            accounting,
        } => (certificate, accounting),
        AggregateExecutionDetails::ExactLiteral(_) => {
            panic!("expected continuation execution details")
        }
        AggregateExecutionDetails::FiniteOrderedLiterals { .. } => {
            panic!("expected continuation execution details")
        }
    }
}

#[test]
fn operation_specific_continuation_facades_match_rust_for_directed_global_sequences() {
    let cases: [(&str, &[u8], bool); 15] = [
        ("", b"", false),
        ("", b"ab", false),
        ("a*?", b"aa", false),
        (r"(?:a+b|a)", b"aaaa", false),
        (r"(?:a+b|a)", b"aaaab", false),
        (r"(?:(?:|a){1,2}?b?)*", b"aab", false),
        (r"(?:|a){2,}?", b"aa", false),
        (r"[a-c\xFF]+", &[b'a', 0xFF, b'd', b'c'], false),
        (r"\A(?:a|)*\z", b"aa", false),
        (r"\b[a-z]+\b", b"_alpha beta!gamma42 \xFFdelta", false),
        (r"\Bfoo\B", b"xfooy foo zfoo_foo", false),
        (r"\b{start}[a-z]+\b{end}", b"_alpha beta!gamma42", false),
        (r"(?m:^sherlock$)", b"sherlock\nnot\nsherlock\n", false),
        (r"(?P<word>[a-z]+)", b"ab  c", false),
        ("sherlock", b"SHERLOCK sherlock", true),
    ];

    for (pattern, haystack, case_insensitive) in cases {
        let expected = upstream(pattern, haystack, case_insensitive);
        let expected_sum = u64::try_from(
            expected
                .iter()
                .map(|(start, end)| end - start)
                .sum::<usize>(),
        )
        .unwrap();
        for strategy in STRATEGIES {
            let builder = || {
                aggregate_builder(pattern)
                    .unicode(false)
                    .case_insensitive(case_insensitive)
                    .plan_selection(AggregatePlanSelection::ForceContinuation)
                    .strategy(strategy)
            };
            let spans = builder()
                .build_spans()
                .unwrap_or_else(|error| panic!("spans build {pattern:?}/{strategy:?}: {error}"))
                .spans(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("spans run {pattern:?}/{strategy:?}: {error}"));
            let actual: Vec<_> = spans
                .iter()
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            assert_eq!(actual, expected, "spans {pattern:?}/{strategy:?}");
            assert_eq!(spans.len(), expected.len());
            let (certificate, _) = continuation_details(&spans.report().details);
            assert_eq!(certificate.range, 0..haystack.len());

            let count = builder()
                .build_count()
                .unwrap_or_else(|error| panic!("count build {pattern:?}/{strategy:?}: {error}"))
                .count(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("count run {pattern:?}/{strategy:?}: {error}"));
            assert_eq!(count.value(), u64::try_from(expected.len()).unwrap());

            let span_sum = builder()
                .build_span_sum()
                .unwrap_or_else(|error| panic!("sum build {pattern:?}/{strategy:?}: {error}"))
                .span_sum(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("sum run {pattern:?}/{strategy:?}: {error}"));
            assert_eq!(span_sum.value(), expected_sum);
        }
    }
}

#[test]
fn unicode_word_and_crlf_assertions_remain_typed_refusals() {
    assert!(matches!(
        aggregate_builder(r"\b")
            .unicode(true)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count(),
        Err(AggregateBuildError::ContinuationCompile {
            source: AggregateEngineError::Unsupported(fre::AggregateUnsupported::Look(
                Look::WordUnicode,
            )),
            ..
        })
    ));

    let mut crlf_profile = RustProfile::regex_1_12_4();
    crlf_profile.options.crlf = true;
    assert!(matches!(
        AggregateBuilder::new(r"(?m:^)")
            .profile(crlf_profile)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count(),
        Err(AggregateBuildError::ContinuationCompile {
            source: AggregateEngineError::Unsupported(fre::AggregateUnsupported::Look(
                Look::StartCRLF,
            )),
            ..
        })
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the exact/continuation/audited/value-only differential matrix is clearest together"
)]
fn exact_literal_auto_and_forced_results_match_continuation_and_rust() {
    let cases: [(&str, &[&[u8]]); 6] = [
        ("", &[b"", b"abc", &[0xFF, 0x00]]),
        ("abc", &[b"", b"abc", b"xxabcabcx", &[0xFF, 0x00]]),
        (r"a\x62c", &[b"abc", b"zabcabc"]),
        (r"((abc))", &[b"xxabcabcx", &[0xFF, b'a', b'b', b'c']]),
        (r"\xFF\x00", &[&[0xFF, 0x00, 0xFF, 0x00], &[0xFF]]),
        ("aba", &[b"ababa", b"abaaba"]),
    ];

    for (pattern, haystacks) in cases {
        for haystack in haystacks {
            let expected = upstream(pattern, haystack, false);
            let expected_count = u64::try_from(expected.len()).unwrap();
            let expected_sum = expected
                .iter()
                .map(|(start, end)| u64::try_from(end - start).unwrap())
                .sum::<u64>();

            let auto_count = aggregate_builder(pattern)
                .unicode(false)
                .build_count()
                .unwrap();
            let forced_count = aggregate_builder(pattern)
                .unicode(false)
                .plan_selection(AggregatePlanSelection::ForceExactLiteral)
                .build_count()
                .unwrap();
            let continuation_count = aggregate_builder(pattern)
                .unicode(false)
                .plan_selection(AggregatePlanSelection::ForceContinuation)
                .build_count()
                .unwrap();
            assert_eq!(
                auto_count.build_report().plan,
                AggregatePlanKind::ExactLiteral
            );
            assert_eq!(auto_count.build_report().continuation_strategy, None);
            assert!(matches!(
                auto_count.build_report().build,
                AggregateBuildAccounting::ExactLiteral(_)
            ));
            for actual in [
                auto_count
                    .count(haystack, AggregateRunLimits::default())
                    .unwrap()
                    .value(),
                auto_count
                    .count_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                forced_count
                    .count(haystack, AggregateRunLimits::default())
                    .unwrap()
                    .value(),
                forced_count
                    .count_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                continuation_count
                    .count(haystack, AggregateRunLimits::default())
                    .unwrap()
                    .value(),
                continuation_count
                    .count_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
            ] {
                assert_eq!(actual, expected_count, "count {pattern:?}/{haystack:?}");
            }

            let auto_sum = aggregate_builder(pattern)
                .unicode(false)
                .build_span_sum()
                .unwrap();
            let forced_sum = aggregate_builder(pattern)
                .unicode(false)
                .plan_selection(AggregatePlanSelection::ForceExactLiteral)
                .build_span_sum()
                .unwrap();
            let continuation_sum = aggregate_builder(pattern)
                .unicode(false)
                .plan_selection(AggregatePlanSelection::ForceContinuation)
                .build_span_sum()
                .unwrap();
            for actual in [
                auto_sum
                    .span_sum(haystack, AggregateRunLimits::default())
                    .unwrap()
                    .value(),
                auto_sum
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                forced_sum
                    .span_sum(haystack, AggregateRunLimits::default())
                    .unwrap()
                    .value(),
                forced_sum
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                continuation_sum
                    .span_sum(haystack, AggregateRunLimits::default())
                    .unwrap()
                    .value(),
                continuation_sum
                    .span_sum_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
            ] {
                assert_eq!(actual, expected_sum, "span sum {pattern:?}/{haystack:?}");
            }
        }
    }
}

struct UnicodeExactOracle {
    upstream: regex::bytes::Regex,
    auto_count: fre::AggregateCountRegex,
    forced_count: fre::AggregateCountRegex,
    auto_sum: fre::AggregateSpanSumRegex,
    forced_sum: fre::AggregateSpanSumRegex,
}

impl UnicodeExactOracle {
    fn new(pattern: &str) -> Self {
        let upstream = regex::bytes::RegexBuilder::new(pattern)
            .unicode(true)
            .case_insensitive(false)
            .build()
            .unwrap_or_else(|error| panic!("Unicode oracle rejected {pattern:?}: {error}"));
        let builder = || aggregate_builder(pattern).unicode(true);
        let auto_count = builder().build_count().unwrap();
        let forced_count = builder()
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_count()
            .unwrap();
        let auto_sum = builder().build_span_sum().unwrap();
        let forced_sum = builder()
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_span_sum()
            .unwrap();
        for (identity, operation) in [
            (
                auto_count.build_report().plan_identity,
                LiteralAggregateOperation::Count,
            ),
            (
                forced_count.build_report().plan_identity,
                LiteralAggregateOperation::Count,
            ),
            (
                auto_sum.build_report().plan_identity,
                LiteralAggregateOperation::SpanSum,
            ),
            (
                forced_sum.build_report().plan_identity,
                LiteralAggregateOperation::SpanSum,
            ),
        ] {
            assert!(matches!(
                identity,
                AggregatePlanIdentity::ExactLiteral(identity)
                    if identity.semantics
                        == AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
                        && identity.kernel.operation == operation
            ));
        }
        Self {
            upstream,
            auto_count,
            forced_count,
            auto_sum,
            forced_sum,
        }
    }

    fn assert_haystack(&self, pattern: &str, haystack: &[u8]) {
        let expected: Vec<_> = self
            .upstream
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect();
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end.checked_sub(*start).unwrap()).unwrap())
            .sum::<u64>();
        let limits = AggregateRunLimits::default();
        for actual in [
            self.auto_count.count(haystack, limits).unwrap().value(),
            self.auto_count.count_value(haystack, limits).unwrap(),
            self.forced_count.count(haystack, limits).unwrap().value(),
            self.forced_count.count_value(haystack, limits).unwrap(),
        ] {
            assert_eq!(actual, expected_count, "count {pattern:?}/{haystack:?}");
        }
        for actual in [
            self.auto_sum.span_sum(haystack, limits).unwrap().value(),
            self.auto_sum.span_sum_value(haystack, limits).unwrap(),
            self.forced_sum.span_sum(haystack, limits).unwrap().value(),
            self.forced_sum.span_sum_value(haystack, limits).unwrap(),
        ] {
            assert_eq!(actual, expected_sum, "span sum {pattern:?}/{haystack:?}");
        }
    }
}

#[test]
fn unicode_nonempty_exact_literals_match_pinned_rust_on_exhaustive_arbitrary_bytes() {
    let cases = [
        ("a", "a"),
        ("é", "é"),
        ("雪", "雪"),
        ("🦀", "🦀"),
        (r"\u{00E9}", "é"),
        (r"\x{96EA}", "雪"),
        (r"\u{1F980}", "🦀"),
        (r"(?-u:\xC3\xA9)", "é"),
        (r"\.", "."),
        (r"\*", "*"),
    ];
    for (pattern, literal) in cases {
        let oracle = UnicodeExactOracle::new(pattern);
        oracle.assert_haystack(pattern, b"");
        for first in u8::MIN..=u8::MAX {
            oracle.assert_haystack(pattern, &[first]);
            for second in u8::MIN..=u8::MAX {
                oracle.assert_haystack(pattern, &[first, second]);
            }
        }

        let needle = literal.as_bytes();
        let mut surrounded = Vec::with_capacity(needle.len() + 2);
        surrounded.push(0);
        surrounded.extend_from_slice(needle);
        surrounded.push(0);
        for before in u8::MIN..=u8::MAX {
            surrounded[0] = before;
            for after in u8::MIN..=u8::MAX {
                let last = surrounded.len() - 1;
                surrounded[last] = after;
                oracle.assert_haystack(pattern, &surrounded);
            }
        }

        let mut mutated = needle.to_vec();
        for index in 0..needle.len() {
            for byte in u8::MIN..=u8::MAX {
                mutated.copy_from_slice(needle);
                mutated[index] = byte;
                oracle.assert_haystack(pattern, &mutated);
            }
        }
    }
}

fn raw_nonoverlapping_matches(
    needle: &[u8],
    haystack: &[u8],
    range: core::ops::Range<usize>,
) -> Vec<(usize, usize)> {
    assert!(!needle.is_empty());
    let mut matches = Vec::new();
    let mut at = range.start;
    while at <= range.end.saturating_sub(needle.len()) {
        let Some(relative) = haystack[at..range.end]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            break;
        };
        let start = at.checked_add(relative).unwrap();
        let end = start.checked_add(needle.len()).unwrap();
        matches.push((start, end));
        at = end;
    }
    matches
}

#[test]
fn unicode_nonempty_literal_raw_search_matches_pinned_input_spans() {
    use regex_automata::{Input, meta::Regex, util::syntax};

    let cases = [("a", "a"), ("é", "é"), ("雪", "雪"), ("🦀", "🦀")];
    for (pattern, literal) in cases {
        let regex = Regex::builder()
            .configure(Regex::config().utf8_empty(false))
            .syntax(syntax::Config::new().utf8(false).unicode(true))
            .build(pattern)
            .unwrap();
        let needle = literal.as_bytes();
        let haystacks = [
            needle.to_vec(),
            [b"\xFF\x80".as_slice(), needle, b"\xC0\xAF".as_slice()].concat(),
            [b"\xF0\x80".as_slice(), needle, b"\xED\xA0\x80".as_slice()].concat(),
            [needle, needle, b"\x80\xFF".as_slice()].concat(),
        ];
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = raw_nonoverlapping_matches(needle, &haystack, start..end);
                    let actual: Vec<_> = regex
                        .find_iter(Input::new(&haystack).span(start..end))
                        .map(|matched| (matched.start(), matched.end()))
                        .collect();
                    assert_eq!(actual, expected, "{pattern:?}/{haystack:?}/{start}..{end}");
                }
            }
        }
    }
}

#[test]
fn unicode_empty_bytes_oracle_and_facade_use_every_byte_boundary() {
    let oracle = regex::bytes::RegexBuilder::new("")
        .unicode(true)
        .build()
        .unwrap();
    for haystack in ["☃".as_bytes(), &[0xFF, 0x80][..]] {
        let actual: Vec<_> = oracle
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect();
        let expected: Vec<_> = (0..=haystack.len()).map(|at| (at, at)).collect();
        assert_eq!(
            actual, expected,
            "pinned bytes oracle must use byte boundaries"
        );
    }

    for pattern in ["", r"(?:)"] {
        let count = aggregate_builder(pattern).build_count().unwrap();
        assert!(matches!(
            count.build_report().plan_identity,
            AggregatePlanIdentity::Continuation(identity)
                if identity.semantics
                    == AggregateContinuationSemantics::UnicodeOnByteStableHir
        ));
        assert_eq!(
            count
                .count_value(&[0xFF, 0x80], AggregateRunLimits::default())
                .unwrap(),
            3
        );
        let span_sum = aggregate_builder(pattern).build_span_sum().unwrap();
        assert_eq!(
            span_sum
                .span_sum_value(&[0xFF, 0x80], AggregateRunLimits::default())
                .unwrap(),
            0
        );
        assert!(matches!(
            aggregate_builder(pattern)
                .plan_selection(AggregatePlanSelection::ForceExactLiteral)
                .build_span_sum(),
            Err(AggregateBuildError::ExactLiteralIneligible {
                operation: AggregateOperation::SpanSum,
                reason: AggregateLiteralIneligibility::UnicodeEmptyOutsideAdmission,
                ..
            })
        ));
    }
}

#[test]
fn unicode_byte_stable_continuations_match_pinned_bytes_oracle_for_all_operations() {
    let cases: [(&str, &[u8], bool); 8] = [
        ("", &[0xFF, 0x80], false),
        ("雪+", "x雪雪y☃".as_bytes(), false),
        ("(?:雪a|☃b)", "☃b雪a雪b".as_bytes(), false),
        (r"[a-c]+", &[0xFF, b'a', b'b', b'd', b'c'], false),
        (r"(?-u:\xFF+)", &[b'a', 0xFF, 0xFF, b'b'], false),
        (r"\A(?:a|雪)+\z", "a雪a".as_bytes(), false),
        (r"(?-u:\b[a-z]+\b)", b" ab-xyz ", false),
        (r"(?-i:a+)", b"AAa b", true),
    ];
    for (pattern, haystack, case_insensitive) in cases {
        let expected = upstream_profile(pattern, haystack, case_insensitive, true);
        let expected_sum = expected
            .iter()
            .map(|(start, end)| end - start)
            .sum::<usize>();
        for strategy in STRATEGIES {
            let builder = || {
                aggregate_builder(pattern)
                    .case_insensitive(case_insensitive)
                    .plan_selection(AggregatePlanSelection::ForceContinuation)
                    .strategy(strategy)
            };
            let spans = builder()
                .build_spans()
                .unwrap_or_else(|error| panic!("spans build {pattern:?}/{strategy:?}: {error}"))
                .spans(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("spans run {pattern:?}/{strategy:?}: {error}"));
            let actual = spans
                .iter()
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "spans {pattern:?}/{strategy:?}");
            assert!(matches!(
                spans.report().identity.plan_identity,
                AggregatePlanIdentity::Continuation(identity)
                    if identity.semantics
                        == AggregateContinuationSemantics::UnicodeOnByteStableHir
            ));

            let count = builder()
                .build_count()
                .unwrap_or_else(|error| panic!("count build {pattern:?}/{strategy:?}: {error}"))
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("count run {pattern:?}/{strategy:?}: {error}"));
            assert_eq!(count, u64::try_from(expected.len()).unwrap());

            let span_sum = builder()
                .build_span_sum()
                .unwrap_or_else(|error| panic!("sum build {pattern:?}/{strategy:?}: {error}"))
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("sum run {pattern:?}/{strategy:?}: {error}"));
            assert_eq!(span_sum, u64::try_from(expected_sum).unwrap());
        }
    }
}

#[test]
fn unicode_profile_local_raw_valid_utf8_literal_is_hir_eligible() {
    let pattern = r"(?-u:\xC3\xA9)";
    let haystack = [0xFF, 0xC3, 0xA9, 0x80, 0xC3, 0xA9];
    let expected = upstream_profile(pattern, &haystack, false, true);
    assert_eq!(expected, vec![(1, 3), (4, 6)]);

    for selection in [
        AggregatePlanSelection::Auto,
        AggregatePlanSelection::ForceExactLiteral,
    ] {
        let count = aggregate_builder(pattern)
            .plan_selection(selection)
            .build_count()
            .unwrap();
        assert!(matches!(
            count.build_report().plan_identity,
            AggregatePlanIdentity::ExactLiteral(identity)
                if identity.semantics
                    == AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
                    && identity.kernel.operation == LiteralAggregateOperation::Count
        ));
        assert_eq!(
            count
                .count(&haystack, AggregateRunLimits::default())
                .unwrap()
                .value(),
            2
        );
        assert_eq!(
            count
                .count_value(&haystack, AggregateRunLimits::default())
                .unwrap(),
            2
        );

        let sum = aggregate_builder(pattern)
            .plan_selection(selection)
            .build_span_sum()
            .unwrap();
        assert_eq!(
            sum.span_sum(&haystack, AggregateRunLimits::default())
                .unwrap()
                .value(),
            4
        );
        assert_eq!(
            sum.span_sum_value(&haystack, AggregateRunLimits::default())
                .unwrap(),
            4
        );
    }
}

#[test]
fn unicode_profile_local_raw_byte_literal_uses_byte_stable_continuation() {
    let pattern = r"(?-u:\xFF)";
    let haystack = [0xFF, b'a', 0xFF];
    let oracle = regex::bytes::RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .unwrap();
    let matches: Vec<_> = oracle
        .find_iter(&haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect();
    assert_eq!(matches, vec![(0, 1), (2, 3)]);

    let count = aggregate_builder(pattern).build_count().unwrap();
    assert!(matches!(
        count.build_report().plan_identity,
        AggregatePlanIdentity::Continuation(identity)
            if identity.semantics == AggregateContinuationSemantics::UnicodeOnByteStableHir
    ));
    assert_eq!(
        count
            .count_value(&haystack, AggregateRunLimits::default())
            .unwrap(),
        2
    );
    assert!(matches!(
        aggregate_builder(pattern)
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_count(),
        Err(AggregateBuildError::ExactLiteralIneligible {
            reason: AggregateLiteralIneligibility::UnicodeLiteralNotUtf8,
            ..
        })
    ));
}

#[test]
fn unicode_exact_literal_scope_and_identity_are_explicit_and_no_fallback() {
    let unicode = aggregate_builder("a").build_count().unwrap();
    let bytes = aggregate_builder("a").unicode(false).build_count().unwrap();
    assert_ne!(
        unicode.build_report().plan_identity,
        bytes.build_report().plan_identity
    );
    assert!(matches!(
        unicode.build_report().plan_identity,
        AggregatePlanIdentity::ExactLiteral(identity)
            if identity.semantics
                == AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
    ));
    assert!(matches!(
        bytes.build_report().plan_identity,
        AggregatePlanIdentity::ExactLiteral(identity)
            if identity.semantics == AggregateExactLiteralSemantics::UnicodeOffByteBoundaries
    ));

    for pattern in [r"a|b", r"[ab]", r"(a)", r"\Aa", r"a+"] {
        let continuation = aggregate_builder(pattern).build_count().unwrap();
        assert!(matches!(
            continuation.build_report().plan_identity,
            AggregatePlanIdentity::Continuation(identity)
                if identity.semantics
                    == AggregateContinuationSemantics::UnicodeOnByteStableHir
        ));
        assert!(matches!(
            aggregate_builder(pattern)
                .plan_selection(AggregatePlanSelection::ForceExactLiteral)
                .build_count(),
            Err(AggregateBuildError::ExactLiteralIneligible {
                reason: AggregateLiteralIneligibility::UnicodeCanonicalRootNotNonemptyLiteral,
                ..
            })
        ));
    }
    assert!(matches!(
        aggregate_builder("рус")
            .case_insensitive(true)
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_count(),
        Err(AggregateBuildError::ExactLiteralIneligible {
            reason: AggregateLiteralIneligibility::UnicodeCaseInsensitiveOutsideAdmission,
            ..
        })
    ));
    let local_case_sensitive = aggregate_builder(r"(?-i:a)")
        .case_insensitive(true)
        .build_count()
        .unwrap();
    assert!(matches!(
        local_case_sensitive.build_report().plan_identity,
        AggregatePlanIdentity::Continuation(identity)
            if identity.semantics == AggregateContinuationSemantics::UnicodeOnByteStableHir
    ));
    assert!(matches!(
        aggregate_builder(r"(?-i:a)")
            .case_insensitive(true)
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_count(),
        Err(AggregateBuildError::ExactLiteralIneligible {
            reason: AggregateLiteralIneligibility::UnicodeCaseInsensitiveOutsideAdmission,
            ..
        })
    ));
    let forced = aggregate_builder("雪")
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    assert_eq!(
        forced.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    let spans = aggregate_builder("雪").build_spans().unwrap();
    assert_eq!(
        spans.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
}

#[test]
fn unicode_singleton_case_folds_use_byte_stable_continuation() {
    let folded_russian = aggregate_builder("рус")
        .case_insensitive(true)
        .build_count()
        .unwrap();
    assert!(matches!(
        folded_russian.build_report().plan_identity,
        AggregatePlanIdentity::Continuation(identity)
            if identity.semantics == AggregateContinuationSemantics::UnicodeOnByteStableHir
    ));
    assert_eq!(
        folded_russian
            .count("РУС рус".as_bytes(), AggregateRunLimits::default())
            .unwrap()
            .value(),
        2
    );

    let folded_kelvin = aggregate_builder(r"(?i:k)").build_count().unwrap();
    let kelvin_haystack = [b'K', b'k', 0xE2, 0x84, 0xAA];
    assert_eq!(
        folded_kelvin
            .count(&kelvin_haystack, AggregateRunLimits::default())
            .unwrap()
            .value(),
        3
    );
    assert!(matches!(
        aggregate_builder(r"(?i:\pL)").build_count(),
        Err(AggregateBuildError::ContinuationCompile {
            source: AggregateEngineError::Unsupported(fre::AggregateUnsupported::UnicodeClass),
            ..
        })
    ));
}

fn unicode_exact_build_error(limits: AggregateBuildLimits) -> AggregateBuildError {
    aggregate_builder("雪")
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(limits)
        .build_count()
        .unwrap_err()
}

fn unicode_exact_count_error(
    regex: &fre::AggregateCountRegex,
    haystack: &[u8],
    limits: AggregateRunLimits,
) -> LiteralAggregateReduceError {
    let audited = regex.count(haystack, limits).unwrap_err();
    let value = regex.count_value(haystack, limits).unwrap_err();
    assert_eq!(value.identity, audited.identity);
    assert_eq!(value.source, audited.source);
    assert!(matches!(
        audited.identity.plan_identity,
        AggregatePlanIdentity::ExactLiteral(identity)
            if identity.semantics
                == AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal
    ));
    match audited.source {
        AggregateExecutionSource::ExactLiteral(source) => source,
        source => panic!("Unicode exact literal attempted another engine: {source:?}"),
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "every Unicode exact-literal planner/build/reducer dimension is checked at and below its boundary"
)]
fn unicode_nonempty_exact_literal_limits_are_exact_and_one_below() {
    let baseline = aggregate_builder("雪")
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count()
        .unwrap();
    let AggregateBuildAccounting::ExactLiteral(build) = baseline.build_report().build else {
        panic!("forced Unicode literal selected another plan")
    };
    assert_eq!(baseline.build_report().planner_work, 1);
    assert_eq!(baseline.build_report().captures_erased, 0);

    let exact_build = AggregateBuildLimits {
        max_literal_planner_work: 1,
        exact_literal: fre::LiteralAggregateBuildLimits {
            max_needle_bytes: build.needle_bytes,
            max_build_work: build.work_upper_bound,
            max_scratch_bytes: build.scratch_bytes,
            max_persistent_bytes: build.persistent_bytes,
            max_peak_bytes: build.peak_bytes,
        },
        ..AggregateBuildLimits::default()
    };
    aggregate_builder("雪")
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(exact_build)
        .build_count()
        .unwrap();

    let mut one_below_build = exact_build;
    one_below_build.max_literal_planner_work = 0;
    assert!(matches!(
        unicode_exact_build_error(one_below_build),
        AggregateBuildError::LiteralPlannerWorkLimit {
            needed: 1,
            limit: 0,
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_needle_bytes -= 1;
    assert!(matches!(
        unicode_exact_build_error(one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::NeedleLimit { .. },
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_build_work -= 1;
    assert!(matches!(
        unicode_exact_build_error(one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::WorkLimit { .. },
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_scratch_bytes -= 1;
    assert!(matches!(
        unicode_exact_build_error(one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::ScratchLimit { .. },
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_persistent_bytes -= 1;
    assert!(matches!(
        unicode_exact_build_error(one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::PersistentLimit { .. },
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_peak_bytes -= 1;
    assert!(matches!(
        unicode_exact_build_error(one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::PeakLimit { .. },
            ..
        }
    ));

    let haystack = [b"\xFF\x80".as_slice(), "雪雪".as_bytes(), b"\xC0"].concat();
    let audited = baseline
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::ExactLiteral(accounting) = audited.report().details else {
        panic!("forced Unicode literal executed another plan")
    };
    assert_eq!(audited.value(), 2);
    assert_eq!(
        baseline
            .count_value(&haystack, AggregateRunLimits::default())
            .unwrap(),
        2
    );
    let upper = accounting.upper_bounds;
    assert!(upper.linear_terms > 0);
    assert!(upper.match_events > 0);
    assert!(upper.count > 0);
    assert!(upper.reducer_steps > 0);
    assert_eq!(upper.scratch_bytes, 0);
    assert!(upper.peak_bytes > 0);

    let mut exact_run = AggregateRunLimits::default();
    exact_run.exact_literal.max_linear_terms = upper.linear_terms;
    exact_run.exact_literal.max_match_events = upper.match_events;
    exact_run.exact_literal.max_count = upper.count;
    exact_run.exact_literal.max_span_sum = upper.span_sum;
    exact_run.exact_literal.max_reducer_steps = upper.reducer_steps;
    exact_run.exact_literal.max_scratch_bytes = upper.scratch_bytes;
    exact_run.exact_literal.max_peak_bytes = upper.peak_bytes;
    assert_eq!(baseline.count(&haystack, exact_run).unwrap().value(), 2);
    assert_eq!(baseline.count_value(&haystack, exact_run).unwrap(), 2);

    let mut one_below_run = exact_run;
    one_below_run.exact_literal.max_linear_terms -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, one_below_run),
        LiteralAggregateReduceError::LinearTermsLimit { .. }
    ));
    one_below_run = exact_run;
    one_below_run.exact_literal.max_match_events -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, one_below_run),
        LiteralAggregateReduceError::MatchEventsLimit { .. }
    ));
    one_below_run = exact_run;
    one_below_run.exact_literal.max_count -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, one_below_run),
        LiteralAggregateReduceError::CountLimit { .. }
    ));
    one_below_run = exact_run;
    one_below_run.exact_literal.max_reducer_steps -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, one_below_run),
        LiteralAggregateReduceError::ReducerStepsLimit { .. }
    ));
    one_below_run = exact_run;
    one_below_run.exact_literal.max_peak_bytes -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, one_below_run),
        LiteralAggregateReduceError::PeakLimit { .. }
    ));

    let sum = aggregate_builder("雪")
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(exact_build)
        .build_span_sum()
        .unwrap();
    assert_eq!(sum.span_sum(&haystack, exact_run).unwrap().value(), 6);
    assert_eq!(sum.span_sum_value(&haystack, exact_run).unwrap(), 6);
    one_below_run = exact_run;
    one_below_run.exact_literal.max_span_sum -= 1;
    let audited_error = sum.span_sum(&haystack, one_below_run).unwrap_err();
    let value_error = sum.span_sum_value(&haystack, one_below_run).unwrap_err();
    assert_eq!(value_error.identity, audited_error.identity);
    assert_eq!(value_error.source, audited_error.source);
    assert!(matches!(
        audited_error.source,
        AggregateExecutionSource::ExactLiteral(LiteralAggregateReduceError::SpanSumLimit { .. })
    ));
}

#[test]
fn captures_are_erased_only_at_the_typed_whole_match_boundary() {
    let regex = aggregate_builder(r"(?P<outer>(?P<inner>a))")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    let report = regex.build_report();
    let AggregateBuildAccounting::Continuation(compiler) = report.build else {
        panic!("forced continuation selected another plan")
    };
    assert_eq!(report.captures_erased, 2);
    assert_eq!(report.capture_erasure_work, 4);
    assert_eq!(compiler.captures_erased, report.captures_erased);
    assert_eq!(compiler.capture_erasure_work, report.capture_erasure_work);
    assert!(report.capture_erasure_work <= compiler.work);
    assert_eq!(
        regex
            .count(b"baab", AggregateRunLimits::default())
            .unwrap()
            .value(),
        2
    );

    let uncaptured = aggregate_builder("a")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    assert_eq!(
        report.plan_identity,
        uncaptured.build_report().plan_identity
    );
    assert_ne!(report.syntax_key, uncaptured.build_report().syntax_key);
    assert_ne!(
        regex.cache_identity(AggregateRunLimits::default()),
        uncaptured.cache_identity(AggregateRunLimits::default())
    );

    assert_eq!(
        aggregate_builder("")
            .build_count()
            .unwrap()
            .count_value(b"baab", AggregateRunLimits::default())
            .unwrap(),
        5
    );
    assert_eq!(
        aggregate_builder("a")
            .build_count()
            .unwrap()
            .count_value(b"baab", AggregateRunLimits::default())
            .unwrap(),
        2
    );
}

#[test]
fn exact_literal_eligibility_is_canonical_and_operation_specific() {
    assert!(matches!(
        aggregate_builder("abc")
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_spans(),
        Err(AggregateBuildError::ExactLiteralIneligible {
            reason: AggregateLiteralIneligibility::SpanOperation,
            ..
        })
    ));
    for pattern in [r"\Aabc", r"abc\z", r"a|b", r"(?i:a)"] {
        assert!(
            matches!(
                aggregate_builder(pattern)
                    .unicode(false)
                    .plan_selection(AggregatePlanSelection::ForceExactLiteral)
                    .build_count(),
                Err(AggregateBuildError::ExactLiteralIneligible {
                    reason: AggregateLiteralIneligibility::CanonicalRootNotLiteralOrEmpty,
                    ..
                })
            ),
            "{pattern:?}"
        );
    }

    let nested = aggregate_builder("((abc))")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count()
        .unwrap();
    assert_eq!(nested.build_report().captures_erased, 2);
    assert_eq!(nested.build_report().capture_erasure_work, 2);
    assert_eq!(nested.build_report().planner_work, 3);

    let work = nested.build_report().planner_work;
    let mut limits = AggregateBuildLimits {
        max_literal_planner_work: work,
        ..AggregateBuildLimits::default()
    };
    aggregate_builder("((abc))")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(limits)
        .build_count()
        .unwrap();
    limits.max_literal_planner_work = work - 1;
    assert!(matches!(
        aggregate_builder("((abc))")
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .limits(limits)
            .build_count(),
        Err(AggregateBuildError::LiteralPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == work && limit == work - 1
    ));
}

#[test]
fn exact_literal_identity_is_semantic_and_does_not_publish_strategy() {
    let captured = aggregate_builder("(needle)")
        .unicode(false)
        .build_count()
        .unwrap();
    let plain = aggregate_builder("needle")
        .unicode(false)
        .build_count()
        .unwrap();
    let sum = aggregate_builder("needle")
        .unicode(false)
        .build_span_sum()
        .unwrap();
    let continuation = aggregate_builder("needle")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();

    assert_eq!(
        captured.build_report().plan_identity,
        plain.build_report().plan_identity
    );
    assert_ne!(
        captured.build_report().syntax_key,
        plain.build_report().syntax_key
    );
    assert_ne!(
        plain.build_report().plan_identity,
        sum.build_report().plan_identity
    );
    assert!(matches!(
        plain.build_report().plan_identity,
        AggregatePlanIdentity::ExactLiteral(identity)
            if identity.kernel.operation == LiteralAggregateOperation::Count
                && identity.semantics
                    == AggregateExactLiteralSemantics::UnicodeOffByteBoundaries
    ));
    assert!(matches!(
        sum.build_report().plan_identity,
        AggregatePlanIdentity::ExactLiteral(identity)
            if identity.kernel.operation == LiteralAggregateOperation::SpanSum
                && identity.semantics
                    == AggregateExactLiteralSemantics::UnicodeOffByteBoundaries
    ));
    assert_eq!(plain.build_report().continuation_strategy, None);
    assert_eq!(
        continuation.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_ne!(
        plain.cache_identity(AggregateRunLimits::default()),
        continuation.cache_identity(AggregateRunLimits::default())
    );
}

#[test]
fn absolute_anchors_use_the_complete_original_haystack() {
    let limits = AggregateRunLimits::default();
    let anchored = aggregate_builder(r"\Afoo\z")
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(anchored.count(b"xxfoo", limits).unwrap().value(), 0);

    let end_anchored = aggregate_builder(r"foo\z")
        .unicode(false)
        .build_spans()
        .unwrap();
    let spans = end_anchored.spans(b"xxfoo", limits).unwrap();
    assert_eq!(
        spans
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>(),
        vec![(2, 5)]
    );
    let (certificate, _) = continuation_details(&spans.report().details);
    assert_eq!(certificate.range, 0..5);
}

#[test]
fn strategy_operation_limits_and_capacity_are_part_of_continuation_identity() {
    let full = aggregate_builder(r"(?:a+b|a)")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .strategy(AggregateStrategy::FullTable)
        .build_count()
        .unwrap();
    let rows = aggregate_builder(r"(?:a+b|a)")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .strategy(AggregateStrategy::ReverseSequentialRows)
        .build_count()
        .unwrap();
    let sum = aggregate_builder(r"(?:a+b|a)")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .strategy(AggregateStrategy::FullTable)
        .build_span_sum()
        .unwrap();
    let AggregateBuildAccounting::Continuation(compiler) = full.build_report().build else {
        panic!("forced continuation selected another plan")
    };
    assert_eq!(
        full.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        full.build_report().plan_identity,
        rows.build_report().plan_identity
    );
    assert_eq!(
        full.build_report().plan_identity,
        sum.build_report().plan_identity
    );
    assert_eq!(
        full.build_report().retained_capacity_bytes,
        compiler.program_bytes
    );
    assert!(compiler.work > 0);

    let limits = AggregateRunLimits::default();
    assert_ne!(full.cache_identity(limits), rows.cache_identity(limits));
    assert_ne!(full.cache_identity(limits), sum.cache_identity(limits));
    let admitted = full.count(b"aaaa", limits).unwrap();
    assert_eq!(admitted.value(), 4);
    assert_eq!(full.count_value(b"aaaa", limits).unwrap(), 4);
    assert_eq!(admitted.report().identity, full.cache_identity(limits));
    let (certificate, accounting) = continuation_details(&admitted.report().details);
    assert_eq!(certificate.strategy, AggregateStrategy::FullTable);
    assert_eq!(certificate.range, 0..4);
    assert!(accounting.work <= certificate.work_bound);

    let required = certificate.random_access_bytes;
    assert!(required > 0);
    let mut refused_limits = limits;
    refused_limits.continuation.max_random_access_bytes = required - 1;
    let error = full.count(b"aaaa", refused_limits).unwrap_err();
    let value_error = full.count_value(b"aaaa", refused_limits).unwrap_err();
    assert_eq!(
        error.identity.as_ref(),
        &full.cache_identity(refused_limits)
    );
    assert_eq!(value_error.identity, error.identity);
    assert_eq!(value_error.source, error.source);
    assert_eq!(
        error.identity.continuation_strategy,
        Some(AggregateStrategy::FullTable)
    );
    assert!(matches!(
        error.source,
        AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::RandomAccessBytes,
            required: actual,
            limit,
        }) if actual == required && limit == required - 1
    ));
}

#[test]
fn value_only_success_skips_source_arc_clone_for_both_selected_plans() {
    for (pattern, selection, haystack) in [
        (
            "aba",
            AggregatePlanSelection::ForceExactLiteral,
            &b"ababaaba"[..],
        ),
        (
            r"(?:a+b|a)",
            AggregatePlanSelection::ForceContinuation,
            &b"aaaabaaaa"[..],
        ),
    ] {
        let count = aggregate_builder(pattern)
            .unicode(false)
            .plan_selection(selection)
            .build_count()
            .unwrap();
        assert_eq!(
            std::sync::Arc::strong_count(&count.build_report().syntax_key),
            1
        );
        let hot = count
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(
            std::sync::Arc::strong_count(&count.build_report().syntax_key),
            1
        );
        let audited = count
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(hot, audited.value());
        assert_eq!(
            std::sync::Arc::strong_count(&count.build_report().syntax_key),
            2
        );
        drop(audited);
        assert_eq!(
            std::sync::Arc::strong_count(&count.build_report().syntax_key),
            1
        );

        let sum = aggregate_builder(pattern)
            .unicode(false)
            .plan_selection(selection)
            .build_span_sum()
            .unwrap();
        assert_eq!(
            std::sync::Arc::strong_count(&sum.build_report().syntax_key),
            1
        );
        let hot = sum
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(
            std::sync::Arc::strong_count(&sum.build_report().syntax_key),
            1
        );
        let audited = sum
            .span_sum(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(hot, audited.value());
        assert_eq!(
            std::sync::Arc::strong_count(&sum.build_report().syntax_key),
            2
        );
        drop(audited);
        assert_eq!(
            std::sync::Arc::strong_count(&sum.build_report().syntax_key),
            1
        );
    }
}

fn exact_build_error(limits: AggregateBuildLimits) -> LiteralAggregateBuildError {
    match aggregate_builder("needle")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(limits)
        .build_count()
    {
        Err(AggregateBuildError::ExactLiteralBuild { source, .. }) => source,
        other => panic!("expected exact-literal build refusal, got {other:?}"),
    }
}

#[test]
fn every_nonzero_exact_literal_build_quota_is_checked_at_and_one_below() {
    let baseline = aggregate_builder("needle")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count()
        .unwrap();
    let AggregateBuildAccounting::ExactLiteral(accounting) = baseline.build_report().build else {
        panic!("forced exact literal selected another plan")
    };
    assert!(accounting.needle_bytes > 0);
    assert!(accounting.work_upper_bound > 0);
    assert!(accounting.scratch_bytes > 0);
    assert!(accounting.persistent_bytes > 0);
    assert!(accounting.peak_bytes > 0);

    let mut limits = AggregateBuildLimits::default();
    limits.exact_literal.max_needle_bytes = accounting.needle_bytes;
    limits.exact_literal.max_build_work = accounting.work_upper_bound;
    limits.exact_literal.max_scratch_bytes = accounting.scratch_bytes;
    limits.exact_literal.max_persistent_bytes = accounting.persistent_bytes;
    limits.exact_literal.max_peak_bytes = accounting.peak_bytes;
    aggregate_builder("needle")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(limits)
        .build_count()
        .unwrap();

    let mut one_below = limits;
    one_below.exact_literal.max_needle_bytes -= 1;
    assert!(matches!(
        exact_build_error(one_below),
        LiteralAggregateBuildError::NeedleLimit { .. }
    ));
    one_below = limits;
    one_below.exact_literal.max_build_work -= 1;
    assert!(matches!(
        exact_build_error(one_below),
        LiteralAggregateBuildError::WorkLimit { .. }
    ));
    one_below = limits;
    one_below.exact_literal.max_scratch_bytes -= 1;
    assert!(matches!(
        exact_build_error(one_below),
        LiteralAggregateBuildError::ScratchLimit { .. }
    ));
    one_below = limits;
    one_below.exact_literal.max_persistent_bytes -= 1;
    assert!(matches!(
        exact_build_error(one_below),
        LiteralAggregateBuildError::PersistentLimit { .. }
    ));
    one_below = limits;
    one_below.exact_literal.max_peak_bytes -= 1;
    assert!(matches!(
        exact_build_error(one_below),
        LiteralAggregateBuildError::PeakLimit { .. }
    ));

    let mut auto_refusal = AggregateBuildLimits::default();
    auto_refusal.exact_literal.max_needle_bytes = accounting.needle_bytes - 1;
    assert!(matches!(
        aggregate_builder("needle")
            .unicode(false)
            .limits(auto_refusal)
            .build_count(),
        Err(AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::NeedleLimit { .. },
            selection: AggregatePlanSelection::Auto,
            ..
        })
    ));
}

fn exact_reduce_error(
    regex: &fre::AggregateCountRegex,
    limits: AggregateRunLimits,
) -> LiteralAggregateReduceError {
    let error = regex.count(b"needleneedleXneedle", limits).unwrap_err();
    assert_eq!(error.identity.plan, AggregatePlanKind::ExactLiteral);
    match error.source {
        AggregateExecutionSource::ExactLiteral(source) => source,
        source => panic!("selected exact plan attempted another engine: {source:?}"),
    }
}

fn exact_reduce_value_error(
    regex: &fre::AggregateCountRegex,
    limits: AggregateRunLimits,
) -> LiteralAggregateReduceError {
    let error = regex
        .count_value(b"needleneedleXneedle", limits)
        .unwrap_err();
    assert_eq!(error.identity.plan, AggregatePlanKind::ExactLiteral);
    match error.source {
        AggregateExecutionSource::ExactLiteral(source) => source,
        source => panic!("selected exact plan attempted another engine: {source:?}"),
    }
}

#[test]
fn every_nonzero_exact_literal_reduce_quota_is_checked_at_and_one_below() {
    let count = aggregate_builder("needle")
        .unicode(false)
        .build_count()
        .unwrap();
    let haystack = b"needleneedleXneedle";
    let baseline = count
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::ExactLiteral(accounting) = baseline.report().details else {
        panic!("auto literal selected continuation")
    };
    let upper = accounting.upper_bounds;
    assert!(upper.linear_terms > 0);
    assert!(upper.match_events > 0);
    assert!(upper.count > 0);
    assert!(upper.reducer_steps > 0);
    assert!(upper.peak_bytes > 0);
    assert_eq!(upper.scratch_bytes, 0);

    let mut exact = AggregateRunLimits::default();
    exact.exact_literal.max_linear_terms = upper.linear_terms;
    exact.exact_literal.max_match_events = upper.match_events;
    exact.exact_literal.max_count = upper.count;
    exact.exact_literal.max_span_sum = upper.span_sum;
    exact.exact_literal.max_reducer_steps = upper.reducer_steps;
    exact.exact_literal.max_scratch_bytes = upper.scratch_bytes;
    exact.exact_literal.max_peak_bytes = upper.peak_bytes;
    count.count(haystack, exact).unwrap();
    assert_eq!(
        count.count_value(haystack, exact).unwrap(),
        baseline.value()
    );

    let mut one_below = exact;
    one_below.exact_literal.max_linear_terms -= 1;
    assert!(matches!(
        exact_reduce_error(&count, one_below),
        LiteralAggregateReduceError::LinearTermsLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, one_below),
        LiteralAggregateReduceError::LinearTermsLimit { .. }
    ));
    one_below = exact;
    one_below.exact_literal.max_match_events -= 1;
    assert!(matches!(
        exact_reduce_error(&count, one_below),
        LiteralAggregateReduceError::MatchEventsLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, one_below),
        LiteralAggregateReduceError::MatchEventsLimit { .. }
    ));
    one_below = exact;
    one_below.exact_literal.max_count -= 1;
    assert!(matches!(
        exact_reduce_error(&count, one_below),
        LiteralAggregateReduceError::CountLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, one_below),
        LiteralAggregateReduceError::CountLimit { .. }
    ));
    one_below = exact;
    one_below.exact_literal.max_reducer_steps -= 1;
    assert!(matches!(
        exact_reduce_error(&count, one_below),
        LiteralAggregateReduceError::ReducerStepsLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, one_below),
        LiteralAggregateReduceError::ReducerStepsLimit { .. }
    ));
    one_below = exact;
    one_below.exact_literal.max_peak_bytes -= 1;
    assert!(matches!(
        exact_reduce_error(&count, one_below),
        LiteralAggregateReduceError::PeakLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, one_below),
        LiteralAggregateReduceError::PeakLimit { .. }
    ));

    let sum = aggregate_builder("needle")
        .unicode(false)
        .build_span_sum()
        .unwrap();
    sum.span_sum(haystack, exact).unwrap();
    let expected_sum = u64::try_from(haystack.len() - 1).unwrap();
    assert_eq!(sum.span_sum_value(haystack, exact).unwrap(), expected_sum);
    one_below = exact;
    one_below.exact_literal.max_span_sum -= 1;
    let error = sum.span_sum(haystack, one_below).unwrap_err();
    let value_error = sum.span_sum_value(haystack, one_below).unwrap_err();
    assert_eq!(value_error.identity, error.identity);
    assert_eq!(value_error.source, error.source);
    assert!(matches!(
        error.source,
        AggregateExecutionSource::ExactLiteral(LiteralAggregateReduceError::SpanSumLimit { .. })
    ));
}

#[test]
fn capture_compile_work_limit_is_exact_and_single_search_routing_is_unchanged() {
    let pattern = r"(?P<outer>(?:a|(?P<inner>[b-d])){1,2}?)";
    let baseline = aggregate_builder(pattern)
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    let AggregateBuildAccounting::Continuation(compiler) = baseline.build_report().build else {
        panic!("forced continuation selected another plan")
    };
    let work = compiler.work;
    assert!(work > 0);
    let mut exact_limits = AggregateBuildLimits::default();
    exact_limits.continuation.max_work = work;
    aggregate_builder(pattern)
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .limits(exact_limits)
        .build_count()
        .unwrap();
    exact_limits.continuation.max_work = work - 1;
    assert!(matches!(
        aggregate_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .limits(exact_limits)
            .build_count(),
        Err(AggregateBuildError::ContinuationCompile {
            source: AggregateEngineError::ResourceLimit {
                resource: AggregateResource::CompileWork,
                required,
                limit,
            },
            ..
        }) if required == work && limit == work - 1
    ));

    let portable = portable_builder("foo").unicode(false).build().unwrap();
    assert_eq!(portable.build_report().plan, PlanKind::ExactLiteral);
    let (matched, _) = portable.find(b"xxfoo", SearchLimits::default()).unwrap();
    let matched = matched.unwrap();
    assert_eq!((matched.start(), matched.end()), (2, 5));
}

#[test]
fn finite_ordered_plan_preserves_priority_nullable_captures_and_invalid_bytes() {
    let cases: [(&str, &[u8]); 6] = [
        (r"a|ab", b"ab"),
        (r"ab|a", b"ab"),
        (r"(?:|a)", b"aa"),
        (r"[a-c]x|d", b"axdcz"),
        (r"(?P<outer>a|bc)", b"bcaa"),
        (r"\xFFa|a", &[0xFF, b'a', b'a']),
    ];
    for (pattern, haystack) in cases {
        let expected = upstream(pattern, haystack, false);
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum::<u64>();
        let auto_count = aggregate_builder(pattern)
            .unicode(false)
            .build_count()
            .unwrap();
        let auto_sum = aggregate_builder(pattern)
            .unicode(false)
            .build_span_sum()
            .unwrap();
        let continuation_count = aggregate_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap();
        assert_eq!(
            auto_count.build_report().plan,
            AggregatePlanKind::FiniteOrderedLiterals,
            "{pattern:?}"
        );
        assert_eq!(
            auto_sum.build_report().plan,
            AggregatePlanKind::FiniteOrderedLiterals,
            "{pattern:?}"
        );
        assert!(matches!(
            auto_count.build_report().build,
            AggregateBuildAccounting::FiniteOrderedLiterals(_)
        ));
        assert_eq!(
            auto_count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_count,
            "{pattern:?}"
        );
        assert_eq!(
            auto_sum
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_sum,
            "{pattern:?}"
        );
        assert_eq!(
            continuation_count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_count,
            "{pattern:?} continuation"
        );
        assert_ne!(
            auto_count.cache_identity(AggregateRunLimits::default()),
            continuation_count.cache_identity(AggregateRunLimits::default())
        );
    }
}

#[test]
fn finite_ordered_plan_charges_one_reverse_transition_per_byte_and_all_dp_state() {
    let horizon = 64_usize;
    let haystack_len = 4_096_usize;
    let pattern = format!("{}b|a", "a".repeat(horizon));
    let haystack = vec![b'a'; haystack_len];
    let regex = aggregate_builder(pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    let AggregateBuildAccounting::FiniteOrderedLiterals(build) = regex.build_report().build else {
        panic!("finite adversary selected another plan")
    };
    assert!(build.kernel.dfa_cells_actual <= build.kernel.dfa_cells_upper_bound);
    assert!(build.kernel.persistent_bytes > 0);
    assert!(build.materialized_capacity_bytes > 0);
    assert_eq!(
        build.extraction_work,
        u64::try_from(regex.build_report().planner_work).unwrap()
    );
    assert_eq!(
        build.combined_work_upper_bound,
        build.extraction_work + build.kernel.build_work_upper_bound
    );

    let result = regex
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(result.value(), u64::try_from(haystack_len).unwrap());
    let AggregateExecutionDetails::FiniteOrderedLiterals {
        upper_bounds,
        actual,
    } = result.report().details
    else {
        panic!("finite adversary reported another executor")
    };
    assert_eq!(actual.transitions, haystack_len);
    assert_eq!(actual.reducer_steps, haystack_len + 1);
    assert_eq!(actual.ring_initializations, horizon + 2);
    assert_eq!(
        actual.total_work,
        actual.transitions + actual.reducer_steps + actual.ring_initializations
    );
    assert_eq!(actual.total_work, upper_bounds.total_work);
    assert_eq!(actual.scratch_bytes, upper_bounds.scratch_bytes);
    assert!(actual.peak_bytes >= build.kernel.persistent_bytes);

    let mut one_below = AggregateRunLimits::default();
    one_below.finite_ordered_literals.max_total_work = upper_bounds.total_work - 1;
    assert!(matches!(
        regex.count_value(&haystack, one_below),
        Err(error) if matches!(
            error.source,
            AggregateExecutionSource::FiniteOrderedLiterals(
                fre::OrderedLiteralAggregateReduceError::TotalWorkLimit {
                    needed,
                    limit,
                }
            ) if needed == upper_bounds.total_work && limit == upper_bounds.total_work - 1
        )
    ));
}

#[test]
fn finite_ordered_planner_and_dense_state_limits_are_exact_rejections() {
    let baseline = aggregate_builder(r"a|bc|[d-f]")
        .unicode(false)
        .build_span_sum()
        .unwrap();
    let planner_work = u64::try_from(baseline.build_report().planner_work).unwrap();
    let AggregateBuildAccounting::FiniteOrderedLiterals(build) = baseline.build_report().build
    else {
        panic!("finite limit baseline selected another plan")
    };
    let mut exact = AggregateBuildLimits {
        max_finite_planner_work: planner_work,
        finite_ordered_literals: fre::OrderedLiteralAggregateBuildLimits {
            max_patterns: build.kernel.patterns,
            max_pattern_bytes: build.kernel.pattern_bytes,
            max_identity_bytes: build.kernel.identity_bytes,
            max_trie_states: build.kernel.trie_states_upper_bound,
            max_dfa_cells: build.kernel.dfa_cells_upper_bound,
            max_build_work: build.combined_work_upper_bound,
            max_scratch_bytes: build.kernel.scratch_bytes,
            max_persistent_bytes: build.kernel.persistent_bytes,
            max_peak_bytes: build.combined_peak_bytes,
        },
        ..AggregateBuildLimits::default()
    };
    aggregate_builder(r"a|bc|[d-f]")
        .unicode(false)
        .limits(exact)
        .build_span_sum()
        .unwrap();

    exact.max_finite_planner_work = planner_work - 1;
    assert!(matches!(
        aggregate_builder(r"a|bc|[d-f]")
            .unicode(false)
            .limits(exact)
            .build_span_sum(),
        Err(AggregateBuildError::FinitePlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit == planner_work - 1
    ));

    exact.max_finite_planner_work = planner_work;
    exact.finite_ordered_literals.max_dfa_cells = build.kernel.dfa_cells_upper_bound - 1;
    assert!(matches!(
        aggregate_builder(r"a|bc|[d-f]")
            .unicode(false)
            .limits(exact)
            .build_span_sum(),
        Err(AggregateBuildError::FiniteOrderedLiteralBuild {
            source: fre::OrderedLiteralAggregateBuildError::DfaCellsLimit {
                needed,
                limit,
            },
            ..
        }) if needed == build.kernel.dfa_cells_upper_bound
            && limit == build.kernel.dfa_cells_upper_bound - 1
    ));
}
