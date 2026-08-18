use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateContinuationSemantics, AggregateCountRegex, AggregateCountResult,
    AggregateEngineError, AggregateExactLiteralSemantics, AggregateExecutionAttemptIdentity,
    AggregateExecutionDetails, AggregateExecutionError, AggregateExecutionSource,
    AggregateFiniteLiteralSemantics, AggregateFixedClassSandwichSemantics,
    AggregateGuardedAsciiWordSemantics, AggregateLiteralIneligibility, AggregateOperation,
    AggregateOperationAttemptKind, AggregateOperationCounterValue,
    AggregateOperationHotCounterReceipt, AggregatePlanIdentity, AggregatePlanKind,
    AggregatePlanSelection, AggregateResource, AggregateRunLimits, AggregateSpanSumRegex,
    AggregateSpanSumResult, AggregateStrategy, AggregateUnicodeScalarSemantics,
    BOUNDED_AFFIX_PLAN_ID, BOUNDED_CONTEXT_SPAN_SUM_OPERATION_ID, BoundedContextReduceError,
    DISPATCHED_PREFIX_CLASS_ALTERNATION_PLAN_ID, DISPATCHED_UNICODE_SCALAR_AGGREGATE_PLAN_ID,
    FixedClassSandwichOperation, FixedClassSandwichReduceError, FixedPredicateWord64Operation,
    LITERAL_AGGREGATE_ACCOUNTING_VERSION, LITERAL_AGGREGATE_ALGORITHM_VERSION,
    LiteralAggregateActualCounters, LiteralAggregateBuildError, LiteralAggregateBuildLimits,
    LiteralAggregateDeclaredFallback, LiteralAggregateOperation, LiteralAggregateOperationIdentity,
    LiteralAggregateReduceError, PREFIX_CLASS_ALTERNATION_SPAN_SUM_OPERATION_ID, PlanKind,
    PortableBuilder, PrefixClassAlternationReduceError, RustProfile, SearchLimits,
    SimdDispatchContext, SimdFeature, UnicodeScalarAggregateOperation,
    UnicodeScalarAggregateReduceError, UNICODE_SCALAR_CURSOR_COUNT_OPERATION_ID,
    UNICODE_SCALAR_CURSOR_COUNT_PLAN_ID, guarded_ascii_word,
};
const STRATEGIES: [AggregateStrategy; 2] = [
    AggregateStrategy::FullTable,
    AggregateStrategy::ReverseSequentialRows,
];

fn aggregate_builder(pattern: impl Into<String>) -> AggregateBuilder {
    AggregateBuilder::new(pattern).profile(RustProfile::rebar_1_12_4())
}

#[test]
fn aggregate_exact_receipt_publication_remains_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AggregateCountRegex>();
    assert_send_sync::<AggregateSpanSumRegex>();
    assert_send_sync::<AggregateCountResult>();
    assert_send_sync::<AggregateSpanSumResult>();
    assert_send_sync::<AggregateExecutionError>();
}

fn assert_bounded_affix_span_limit_closure(span_regex: &AggregateSpanSumRegex) {
    let AggregatePlanIdentity::BoundedContext(span_identity) =
        span_regex.build_report().plan_identity
    else {
        panic!("bounded-affix span-sum identity");
    };
    let covered = b" ing  walking\t";
    let mut exact_span_limits = AggregateRunLimits::default();
    exact_span_limits.bounded_context.max_count = 14;
    let covered_result = span_regex.span_sum(covered, exact_span_limits).unwrap();
    assert_eq!(covered_result.value(), 14);
    let AggregateExecutionDetails::BoundedContextSpanSum(accounting) =
        covered_result.report().details()
    else {
        panic!("bounded-affix span-sum execution accounting");
    };
    assert_eq!(accounting.identity, span_identity.kernel);
    assert_eq!(accounting.upper_bounds.span_sum, 14);
    assert_eq!(accounting.actual.span_sum, 14);
    assert_eq!(accounting.actual.match_events, 2);
    assert!(
        accounting.actual.span_sum <= accounting.upper_bounds.span_sum,
        "the exact result must close inside its prospective receipt"
    );
    assert_eq!(
        span_regex
            .span_sum_value(covered, exact_span_limits)
            .unwrap(),
        14
    );
    let mut one_below_span_limits = exact_span_limits;
    one_below_span_limits.bounded_context.max_count = 13;
    assert_ne!(
        span_regex.cache_identity(exact_span_limits),
        span_regex.cache_identity(one_below_span_limits)
    );
    let audited_error = span_regex
        .span_sum(covered, one_below_span_limits)
        .unwrap_err();
    let value_error = span_regex
        .span_sum_value(covered, one_below_span_limits)
        .unwrap_err();
    assert_eq!(value_error.identity, audited_error.identity);
    assert_eq!(value_error.source, audited_error.source);
    assert!(audited_error.has_closed_direct_attempt());
    assert!(matches!(
        audited_error.source,
        AggregateExecutionSource::BoundedContext(BoundedContextReduceError::SpanSumLimit {
            needed: 14,
            limit: 13
        })
    ));
}

fn assert_bounded_affix_planner_limits(pattern: &str, planner_work: usize) {
    let below_planner_work = planner_work.checked_sub(1).unwrap();
    assert!(
        aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(false)
            .limits(AggregateBuildLimits {
                max_bounded_affix_planner_work: planner_work,
                ..AggregateBuildLimits::default()
            })
            .build_count()
            .is_ok()
    );
    assert!(
        aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(false)
            .limits(AggregateBuildLimits {
                max_bounded_affix_planner_work: planner_work,
                ..AggregateBuildLimits::default()
            })
            .build_span_sum()
            .is_ok()
    );
    assert!(matches!(
        aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(false)
            .limits(AggregateBuildLimits {
                max_bounded_affix_planner_work: below_planner_work,
                ..AggregateBuildLimits::default()
            })
            .build_count(),
        Err(AggregateBuildError::BoundedAffixPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit == below_planner_work
    ));
    assert!(matches!(
        aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(false)
            .limits(AggregateBuildLimits {
                max_bounded_affix_planner_work: below_planner_work,
                ..AggregateBuildLimits::default()
            })
            .build_span_sum(),
        Err(AggregateBuildError::BoundedAffixPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit == below_planner_work
    ));
}

#[test]
fn unicode_off_bounded_affix_routes_and_matches_greedy_oracle() {
    let pattern = r"\s[A-Za-z]{0,12}ing\s";
    let haystack = b" ing  walking\t thing\n012ing x \xFFing\r";
    let expected_spans = upstream(pattern, haystack, false);
    let expected = expected_spans.len();
    let expected_span_sum = expected_spans
        .iter()
        .map(|(start, end)| u64::try_from(end - start).unwrap())
        .sum::<u64>();
    let regex = aggregate_builder(pattern)
        .unicode(false)
        .case_insensitive(false)
        .build_count()
        .unwrap();
    assert_eq!(regex.build_report().plan, AggregatePlanKind::BoundedContext);
    let AggregatePlanIdentity::BoundedContext(identity) = regex.build_report().plan_identity else {
        panic!("bounded-affix identity");
    };
    assert_eq!(identity.kernel.plan_id, BOUNDED_AFFIX_PLAN_ID);
    assert_eq!(regex.build_report().bounded_context_planner_work, 0);
    let planner_work = regex.build_report().bounded_affix_planner_work;
    assert!(planner_work > 0);
    assert_eq!(
        regex
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        u64::try_from(expected).unwrap()
    );
    assert_eq!(
        regex
            .count_value(b" ing ing ", AggregateRunLimits::default())
            .unwrap(),
        1
    );
    let span_regex = aggregate_builder(pattern)
        .unicode(false)
        .case_insensitive(false)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        span_regex.build_report().plan,
        AggregatePlanKind::BoundedContext
    );
    let AggregatePlanIdentity::BoundedContext(span_identity) =
        span_regex.build_report().plan_identity
    else {
        panic!("bounded-affix span-sum identity");
    };
    assert_eq!(span_identity.kernel.plan_id, BOUNDED_AFFIX_PLAN_ID);
    assert_eq!(
        span_identity.kernel.operation_id,
        BOUNDED_CONTEXT_SPAN_SUM_OPERATION_ID
    );
    assert_eq!(
        span_regex
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        expected_span_sum
    );
    assert_bounded_affix_span_limit_closure(&span_regex);
    assert_bounded_affix_planner_limits(pattern, planner_work);
}

#[test]
fn bounded_affix_generalizes_to_classes_shared_endpoints_and_malformed_bytes() {
    for (pattern, haystack) in [
        (r"[ab][cd]{0,2}dc[ab]", b"adcaaaddabdcba".as_slice()),
        (
            r"[\xFE-\xFF][ab]{0,2}ab[\xFE-\xFF]",
            b"\xFFab\xFE\x80\xFEaab\xFF".as_slice(),
        ),
    ] {
        let expected = upstream(pattern, haystack, false).len();
        let regex = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(false)
            .build_count()
            .unwrap();
        let AggregatePlanIdentity::BoundedContext(identity) = regex.build_report().plan_identity
        else {
            panic!("bounded-affix route for {pattern:?}");
        };
        assert_eq!(identity.kernel.plan_id, BOUNDED_AFFIX_PLAN_ID);
        assert_eq!(
            regex
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            u64::try_from(expected).unwrap()
        );
        let expected_span_sum = upstream(pattern, haystack, false)
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum::<u64>();
        let span_regex = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(false)
            .build_span_sum()
            .unwrap();
        let AggregatePlanIdentity::BoundedContext(identity) =
            span_regex.build_report().plan_identity
        else {
            panic!("bounded-affix span-sum route for {pattern:?}");
        };
        assert_eq!(identity.kernel.plan_id, BOUNDED_AFFIX_PLAN_ID);
        assert_eq!(
            span_regex
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_span_sum
        );
    }
}

#[test]
fn bounded_affix_noneligible_shapes_fall_through_with_independent_work_budgets() {
    for pattern in [r"[ab][bc]{0,2}bc[xy]", r"[ab][cd]{0,2}xy[ab]"] {
        let haystack = b"abcdxyabcbcx";
        let expected = upstream(pattern, haystack, false).len();
        let regex = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(false)
            .build_count()
            .expect("noneligible affix must retain the general fallback");
        assert_ne!(regex.build_report().plan, AggregatePlanKind::BoundedContext);
        assert_eq!(
            regex
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            u64::try_from(expected).unwrap()
        );

        let affix_work = regex.build_report().bounded_affix_planner_work;
        let context_work = regex.build_report().bounded_context_planner_work;
        assert!(affix_work > 0);
        assert!(context_work > 0);
        let exact_limits = AggregateBuildLimits {
            max_bounded_affix_planner_work: affix_work,
            max_bounded_context_planner_work: context_work,
            ..AggregateBuildLimits::default()
        };
        let exact = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(false)
            .limits(exact_limits)
            .build_count()
            .expect("exact combined affix/fallback inspection quota");
        assert_eq!(exact.build_report().bounded_affix_planner_work, affix_work);
        assert_eq!(
            exact.build_report().bounded_context_planner_work,
            context_work
        );

        let below_affix = AggregateBuildLimits {
            max_bounded_affix_planner_work: affix_work - 1,
            max_bounded_context_planner_work: context_work,
            ..AggregateBuildLimits::default()
        };
        assert!(matches!(
            aggregate_builder(pattern)
                .unicode(false)
                .case_insensitive(false)
                .limits(below_affix)
                .build_count(),
            Err(AggregateBuildError::BoundedAffixPlannerWorkLimit {
                needed,
                limit,
                ..
            }) if needed == affix_work && limit == affix_work - 1
        ));

        let below_context = AggregateBuildLimits {
            max_bounded_affix_planner_work: affix_work,
            max_bounded_context_planner_work: context_work - 1,
            ..AggregateBuildLimits::default()
        };
        assert!(matches!(
            aggregate_builder(pattern)
                .unicode(false)
                .case_insensitive(false)
                .limits(below_context)
                .build_count(),
            Err(AggregateBuildError::BoundedContextPlannerWorkLimit {
                needed,
                limit,
                ..
            }) if needed == context_work && limit == context_work - 1
        ));
    }
}

#[test]
fn bounded_affix_preinspection_preserves_legacy_context_exact_boundary() {
    let pattern = r"[a-z]{2}\s+[\s\S]{0,2}R[\s\S]{0,2}\s+[a-z]{2}";
    let count = aggregate_builder(pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    let compile = aggregate_builder(pattern)
        .unicode(false)
        .build_compile()
        .unwrap();
    assert_eq!(count.build_report().plan, AggregatePlanKind::BoundedContext);
    assert_eq!(
        compile.build_report().plan,
        AggregatePlanKind::BoundedContext
    );
    assert!(count.build_report().bounded_affix_planner_work > 0);
    assert_eq!(compile.build_report().bounded_affix_planner_work, 0);
    assert_eq!(
        count.build_report().bounded_context_planner_work,
        compile.build_report().bounded_context_planner_work
    );

    let affix_work = count.build_report().bounded_affix_planner_work;
    let context_work = count.build_report().bounded_context_planner_work;
    let exact = AggregateBuildLimits {
        max_bounded_affix_planner_work: affix_work,
        max_bounded_context_planner_work: context_work,
        ..AggregateBuildLimits::default()
    };
    assert!(
        aggregate_builder(pattern)
            .unicode(false)
            .limits(exact)
            .build_count()
            .is_ok()
    );
    let below_legacy = AggregateBuildLimits {
        max_bounded_affix_planner_work: affix_work,
        max_bounded_context_planner_work: context_work - 1,
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        aggregate_builder(pattern)
            .unicode(false)
            .limits(below_legacy)
            .build_count(),
        Err(AggregateBuildError::BoundedContextPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == context_work && limit == context_work - 1
    ));
}

#[test]
fn compile_artifact_is_complete_isolated_and_verifiable_across_pattern_families() {
    let cases: [(&str, &[u8], bool, u64, AggregatePlanKind); 3] = [
        ("aba", b"abaaba", false, 2, AggregatePlanKind::ExactLiteral),
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
            verified.report().cache_identity().operation,
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
            ..
        } => (certificate, accounting),
        AggregateExecutionDetails::ImpossibleMatchDomain(_)
        | AggregateExecutionDetails::ExactLiteral(_)
        | AggregateExecutionDetails::UnicodeScalar(_)
        | AggregateExecutionDetails::UnicodeScalarCursorCount(_)
        | AggregateExecutionDetails::WordRun(_)
        | AggregateExecutionDetails::LiteralAssertions(_)
        | AggregateExecutionDetails::BlockingDelimiter(_)
        | AggregateExecutionDetails::TokenPhrase(_)
        | AggregateExecutionDetails::FixedClassSandwich(_)
        | AggregateExecutionDetails::GraphemeScalarDfa(_)
        | AggregateExecutionDetails::BoundedClassSequence(_)
        | AggregateExecutionDetails::BoundedSeparatedFields(_)
        | AggregateExecutionDetails::DelimiterFieldSpans(_)
        | AggregateExecutionDetails::PrefixClassAlternation(_)
        | AggregateExecutionDetails::LiteralClassRunLiteral(_)
        | AggregateExecutionDetails::ReverseInner(_)
        | AggregateExecutionDetails::BoundedLiteralPair(_)
        | AggregateExecutionDetails::BoundedContext(_)
        | AggregateExecutionDetails::BoundedContextSpanSum(_)
        | AggregateExecutionDetails::FixedAbsoluteDomain(_)
        | AggregateExecutionDetails::PackedFiniteLiteral { .. }
        | AggregateExecutionDetails::FiniteLiteral { .. }
        | AggregateExecutionDetails::SparseFiniteLiteral { .. }
        | AggregateExecutionDetails::GuardedAsciiWord(_)
        | AggregateExecutionDetails::GuardedUnicodeWord(_)
        | AggregateExecutionDetails::FixedPredicateWord64(_)
        | AggregateExecutionDetails::ContinuationSweep { .. } => {
            panic!("expected continuation execution details")
        }
    }
}

fn assert_continuation_certificate_preserves_prospective(
    certificate: &fre::AggregateOperationCertificate,
    prospective: &fre::AggregateOperationProspective,
) {
    assert_eq!(certificate.states, prospective.states);
    assert_eq!(certificate.boundaries(), prospective.boundaries);
    assert_eq!(certificate.table_cells, prospective.table_cells);
    assert_eq!(certificate.row_storage, prospective.row_storage);
    assert_eq!(certificate.row_record_bytes, prospective.row_record_bytes);
    assert_eq!(certificate.terminal_frontier, prospective.terminal_frontier);
    assert_eq!(certificate.work_bound, prospective.work_bound);
    assert_eq!(
        certificate.random_access_bytes,
        prospective.random_access_bytes
    );
    assert_eq!(certificate.scratch_bytes, prospective.scratch_bytes);
    assert_eq!(certificate.log_bytes, prospective.log_bytes);
    assert_eq!(
        certificate.sequential_bytes_bound,
        prospective.sequential_bytes
    );
    assert_eq!(certificate.match_events, prospective.match_events);
    assert_eq!(certificate.output_matches, prospective.output_matches);
    assert_eq!(certificate.output_bytes, prospective.output_bytes);
    assert_eq!(certificate.span_sum, prospective.span_sum);
    assert_eq!(certificate.peak_bytes, prospective.peak_bytes);
}

#[test]
fn operation_specific_continuation_facades_match_rust_for_directed_global_sequences() {
    let cases: [(&str, &[u8], bool); 16] = [
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
        (
            r"(?:(?:alpha|beta|nil|\d)+\)*;?((?:\s|-)*.*(?:.*:.*)))",
            b"alpha \n x:y\nmiss\nbeta z:w",
            false,
        ),
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
            let (certificate, _) = continuation_details(spans.report().details());
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
#[allow(
    clippy::too_many_lines,
    reason = "count and span-sum exact/one-below matrices share one mechanism fixture"
)]
fn continuation_value_reducers_use_exact_work_for_byte_progress_and_unicode_offsets() {
    let unicode_haystack = ["Aé雪🦀".as_bytes(), &[0xFF, 0x80], "雪éA".as_bytes()].concat();
    let cases: [(&str, &[u8], bool); 2] = [
        (r"(?:|a|z{64}[q-r])", &[b'a', 0xFF, b'a'], false),
        (r"(?:[Aé雪🦀]+|z{64}[q-r])", &unicode_haystack, true),
    ];

    for (pattern, haystack, unicode) in cases {
        let expected = upstream_profile(pattern, haystack, false, unicode);
        let expected_count = u64::try_from(expected.len()).unwrap();
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
                    .unicode(unicode)
                    .plan_selection(AggregatePlanSelection::ForceContinuation)
                    .strategy(strategy)
            };

            let count = builder().build_count().unwrap();
            let audited = count
                .count(haystack, AggregateRunLimits::default())
                .unwrap();
            assert_eq!(audited.value(), expected_count);
            let (certificate, accounting) = continuation_details(audited.report().details());
            assert!(accounting.work < certificate.work_bound);

            let mut exact = AggregateRunLimits::default();
            exact.continuation.max_work = accounting.work;
            assert_eq!(count.count_value(haystack, exact).unwrap(), expected_count);
            let audited_error = count.count(haystack, exact).unwrap_err();
            assert!(matches!(
                audited_error.source,
                AggregateExecutionSource::Continuation(
                    AggregateEngineError::ResourceLimit {
                        resource: AggregateResource::ExecutionWork,
                        required,
                        limit,
                    }
                ) if required == certificate.work_bound && limit == accounting.work
            ));

            let mut below = exact;
            below.continuation.max_work -= 1;
            let value_error = count.count_value(haystack, below).unwrap_err();
            assert!(matches!(
                value_error.source,
                AggregateExecutionSource::Continuation(
                    AggregateEngineError::ResourceLimit {
                        resource: AggregateResource::ExecutionWork,
                        required,
                        limit,
                    }
                ) if required == limit + 1 && limit + 1 == accounting.work
            ));

            let span_sum = builder().build_span_sum().unwrap();
            let audited = span_sum
                .span_sum(haystack, AggregateRunLimits::default())
                .unwrap();
            assert_eq!(audited.value(), expected_sum);
            let (certificate, accounting) = continuation_details(audited.report().details());
            assert!(accounting.work < certificate.work_bound);

            exact.continuation.max_work = accounting.work;
            assert_eq!(
                span_sum.span_sum_value(haystack, exact).unwrap(),
                expected_sum
            );
            let audited_error = span_sum.span_sum(haystack, exact).unwrap_err();
            assert!(matches!(
                audited_error.source,
                AggregateExecutionSource::Continuation(
                    AggregateEngineError::ResourceLimit {
                        resource: AggregateResource::ExecutionWork,
                        required,
                        limit,
                    }
                ) if required == certificate.work_bound && limit == accounting.work
            ));

            below = exact;
            below.continuation.max_work -= 1;
            let value_error = span_sum.span_sum_value(haystack, below).unwrap_err();
            assert!(matches!(
                value_error.source,
                AggregateExecutionSource::Continuation(
                    AggregateEngineError::ResourceLimit {
                        resource: AggregateResource::ExecutionWork,
                        required,
                        limit,
                    }
                ) if required == limit + 1 && limit + 1 == accounting.work
            ));
        }
    }
}

#[test]
fn unicode_word_boundary_routes_through_continuation_exactly() {
    let haystack = "ascii snow雪_ Ж".as_bytes();
    let expected = regex::bytes::RegexBuilder::new(r"\b")
        .unicode(true)
        .build()
        .unwrap()
        .find_iter(haystack)
        .count();
    let compiled = aggregate_builder(r"\b")
        .unicode(true)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    assert_eq!(
        compiled.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    let count = compiled
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(count.value(), u64::try_from(expected).unwrap());
}

#[test]
fn crlf_assertions_route_through_the_exact_continuation() {
    let mut crlf_profile = RustProfile::regex_1_12_4();
    crlf_profile.options.crlf = true;
    let haystack = b"a\r\nb\rc\nd";
    let expected = regex::bytes::Regex::new(r"(?Rm:^)")
        .unwrap()
        .find_iter(haystack)
        .count();
    let compiled = AggregateBuilder::new(r"(?m:^)")
        .profile(crlf_profile)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .expect("CRLF continuation");
    assert_eq!(
        compiled
            .count(haystack, AggregateRunLimits::default())
            .unwrap()
            .value(),
        u64::try_from(expected).unwrap()
    );
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
                    == AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir
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
                spans.report().cache_identity().plan_identity,
                AggregatePlanIdentity::Continuation(identity)
                    if identity.semantics
                        == AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir
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
            if identity.semantics == AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir
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
#[allow(
    clippy::too_many_lines,
    reason = "one count/span-sum route matrix keeps shared identity and oracle assertions adjacent"
)]
fn guarded_ascii_word_dictionary_routes_raw_and_factored_count_forms() {
    let patterns = [
        r"(?:\b(as)\b)|(?:\b(break)\b)|(?:\b(Self)\b)|(?:\b(ab)\b)|(?:\b(ba)\b)",
        r"\b(?:as|break|Self|ab|ba)\b",
    ];
    let haystack = b"as break xas as_ _as Self ab ba aba \xFFas\xFF";
    for pattern in patterns {
        let matches = upstream(pattern, haystack, false);
        let expected = u64::try_from(matches.len()).unwrap();
        let expected_span_sum = matches
            .iter()
            .try_fold(0_u64, |sum, (start, end)| {
                sum.checked_add(u64::try_from(end - start).unwrap())
            })
            .unwrap();
        let regex = aggregate_builder(pattern)
            .unicode(false)
            .build_count()
            .unwrap();
        assert_eq!(
            regex.build_report().plan,
            AggregatePlanKind::GuardedAsciiWordDictionary
        );
        let AggregatePlanIdentity::GuardedAsciiWord(identity) = regex.build_report().plan_identity
        else {
            panic!("guarded dictionary identity");
        };
        assert_eq!(
            identity.semantics,
            AggregateGuardedAsciiWordSemantics::UnicodeOffMaximalAsciiWords
        );
        assert_eq!(identity.dictionary, guarded_ascii_word::PLAN_ID);
        assert_eq!(identity.packing, guarded_ascii_word::PACKING_ID);
        assert_eq!(identity.lookup, guarded_ascii_word::LOOKUP_ID);
        assert_eq!(identity.fingerprint, guarded_ascii_word::FINGERPRINT_ID);
        assert_eq!(identity.operation, guarded_ascii_word::COUNT_OPERATION_ID);
        let AggregateBuildAccounting::GuardedAsciiWord(build) = regex.build_report().build else {
            panic!("guarded dictionary build accounting");
        };
        let dictionary_actual = build.dictionary.actual().unwrap();
        assert!(dictionary_actual.published);
        assert!(build.allocations_actual <= build.allocations_upper_bound);
        assert!(build.initialized_bytes_actual <= build.initialized_bytes_upper_bound);
        assert!(build.peak_bytes_actual_upper_bound <= build.peak_bytes_upper_bound);
        assert_eq!(
            regex.build_report().retained_capacity_bytes,
            dictionary_actual.persistent_bytes
        );

        let result = regex
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(result.value(), expected);
        let AggregateExecutionDetails::GuardedAsciiWord(accounting) = result.report().details()
        else {
            panic!("guarded dictionary execution accounting");
        };
        assert_eq!(
            accounting.operation_id,
            guarded_ascii_word::COUNT_OPERATION_ID
        );
        assert_eq!(accounting.actual.bytes_classified, haystack.len());
        assert_eq!(accounting.actual.matches, expected);
        assert!(accounting.actual.total_work <= accounting.upper_bounds.total_work);

        let compiled = aggregate_builder(pattern)
            .unicode(false)
            .build_compile()
            .unwrap();
        assert_eq!(
            compiled.build_report().plan,
            AggregatePlanKind::GuardedAsciiWordDictionary
        );
        assert_eq!(
            compiled
                .verify_count(haystack, AggregateRunLimits::default())
                .unwrap()
                .value(),
            expected
        );

        let span_sum = aggregate_builder(pattern)
            .unicode(false)
            .build_span_sum()
            .unwrap();
        assert_eq!(
            span_sum.build_report().plan,
            AggregatePlanKind::GuardedAsciiWordDictionary
        );
        let AggregatePlanIdentity::GuardedAsciiWord(identity) =
            span_sum.build_report().plan_identity
        else {
            panic!("guarded span-sum identity");
        };
        assert_eq!(
            identity.operation,
            guarded_ascii_word::SPAN_SUM_OPERATION_ID
        );
        let result = span_sum
            .span_sum(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(result.value(), expected_span_sum);
        let AggregateExecutionDetails::GuardedAsciiWord(accounting) = result.report().details()
        else {
            panic!("guarded span-sum execution accounting");
        };
        assert_eq!(
            accounting.operation_id,
            guarded_ascii_word::SPAN_SUM_OPERATION_ID
        );
        assert_eq!(accounting.actual.matches, expected);
        assert_eq!(accounting.actual.span_sum, expected_span_sum);
    }
}

#[test]
fn guarded_ascii_word_inherits_every_finite_build_cap_exactly() {
    const PATTERN: &str = r"\b(?:as|break|Self|ab|ba)\b";

    fn selected(finite_literal: fre::OrderedLiteralAggregateBuildLimits) -> AggregatePlanKind {
        aggregate_builder(PATTERN)
            .unicode(false)
            .limits(AggregateBuildLimits {
                finite_literal,
                ..AggregateBuildLimits::default()
            })
            .build_count()
            .unwrap()
            .build_report()
            .plan
    }

    let baseline = aggregate_builder(PATTERN)
        .unicode(false)
        .build_count()
        .unwrap();
    let AggregateBuildAccounting::GuardedAsciiWord(build) = baseline.build_report().build else {
        panic!("guarded baseline build accounting");
    };
    let prospective = build.dictionary.prospective;
    let defaults = AggregateBuildLimits::default().finite_literal;

    let mut exact = defaults;
    exact.max_identity_bytes = prospective.identity_bytes;
    assert_eq!(
        selected(exact),
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    exact.max_identity_bytes -= 1;
    assert_eq!(selected(exact), AggregatePlanKind::ContinuationProgram);

    let mut exact = defaults;
    exact.max_build_work = prospective.build_work;
    assert_eq!(
        selected(exact),
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    exact.max_build_work -= 1;
    assert_eq!(selected(exact), AggregatePlanKind::ContinuationProgram);

    let mut exact = defaults;
    exact.max_persistent_bytes = prospective.persistent_bytes;
    assert_eq!(
        selected(exact),
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    exact.max_persistent_bytes -= 1;
    assert_eq!(selected(exact), AggregatePlanKind::ContinuationProgram);

    let mut exact = defaults;
    exact.max_peak_bytes = build.peak_bytes_upper_bound;
    assert_eq!(
        selected(exact),
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    exact.max_peak_bytes -= 1;
    assert_eq!(selected(exact), AggregatePlanKind::ContinuationProgram);

    let mut low = 0_usize;
    let mut high = defaults.max_scratch_bytes;
    assert_eq!(
        selected(defaults),
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    while low < high {
        let middle = low + (high - low) / 2;
        let mut limits = defaults;
        limits.max_scratch_bytes = middle;
        if selected(limits) == AggregatePlanKind::GuardedAsciiWordDictionary {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    assert!(low > 0);
    let mut exact = defaults;
    exact.max_scratch_bytes = low;
    assert_eq!(
        selected(exact),
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    exact.max_scratch_bytes -= 1;
    assert_eq!(selected(exact), AggregatePlanKind::ContinuationProgram);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the exact and one-below matrix covers every independently enforced resource"
)]
fn guarded_ascii_word_execution_limits_refuse_before_source_access() {
    let regex = aggregate_builder(r"\b(?:as|break|Self|ab|ba)\b")
        .unicode(false)
        .build_count()
        .unwrap();
    let haystack = b"as break other Self ab ba";
    let result = regex
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::GuardedAsciiWord(accounting) = result.report().details() else {
        panic!("guarded execution accounting");
    };
    let upper = accounting.upper_bounds;
    let exact_finite = fre::OrderedLiteralAggregateReduceLimits {
        max_transitions: upper.haystack_bytes,
        max_match_events: upper.candidate_words,
        max_count: upper.matches,
        max_reducer_steps: upper.lookup_steps,
        max_total_work: upper.total_work,
        max_peak_bytes: upper.peak_bytes,
        ..fre::OrderedLiteralAggregateReduceLimits::default()
    };
    let exact = AggregateRunLimits {
        finite_literal: exact_finite,
        ..AggregateRunLimits::default()
    };
    assert_eq!(regex.count_value(haystack, exact).unwrap(), result.value());

    let cases = [
        (
            guarded_ascii_word::ReduceResource::HaystackBytes,
            fre::OrderedLiteralAggregateReduceLimits {
                max_transitions: upper.haystack_bytes - 1,
                ..exact_finite
            },
        ),
        (
            guarded_ascii_word::ReduceResource::CandidateWords,
            fre::OrderedLiteralAggregateReduceLimits {
                max_match_events: upper.candidate_words - 1,
                ..exact_finite
            },
        ),
        (
            guarded_ascii_word::ReduceResource::Count,
            fre::OrderedLiteralAggregateReduceLimits {
                max_count: upper.matches - 1,
                ..exact_finite
            },
        ),
        (
            guarded_ascii_word::ReduceResource::LookupSteps,
            fre::OrderedLiteralAggregateReduceLimits {
                max_reducer_steps: upper.lookup_steps - 1,
                ..exact_finite
            },
        ),
        (
            guarded_ascii_word::ReduceResource::TotalWork,
            fre::OrderedLiteralAggregateReduceLimits {
                max_total_work: upper.total_work - 1,
                ..exact_finite
            },
        ),
        (
            guarded_ascii_word::ReduceResource::PeakBytes,
            fre::OrderedLiteralAggregateReduceLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..exact_finite
            },
        ),
    ];
    for (resource, finite_literal) in cases {
        let error = regex
            .count(
                haystack,
                AggregateRunLimits {
                    finite_literal,
                    ..AggregateRunLimits::default()
                },
            )
            .unwrap_err();
        assert!(error.has_closed_direct_attempt());
        let AggregateExecutionSource::GuardedAsciiWord(source) = error.source else {
            panic!("guarded execution source");
        };
        assert!(matches!(
            source.kind,
            guarded_ascii_word::ReduceErrorKind::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
        assert_eq!(source.actual, guarded_ascii_word::ReduceActual::default());
        assert_eq!(source.upper_bounds, Some(upper));
    }

    let span_sum = aggregate_builder(r"\b(?:as|break|Self|ab|ba)\b")
        .unicode(false)
        .build_span_sum()
        .unwrap();
    let error = span_sum
        .span_sum(
            haystack,
            AggregateRunLimits {
                finite_literal: fre::OrderedLiteralAggregateReduceLimits {
                    max_span_sum: upper.span_sum - 1,
                    ..exact_finite
                },
                ..AggregateRunLimits::default()
            },
        )
        .unwrap_err();
    assert!(error.has_closed_direct_attempt());
    let AggregateExecutionSource::GuardedAsciiWord(source) = error.source else {
        panic!("guarded span-sum execution source");
    };
    assert!(matches!(
        source.kind,
        guarded_ascii_word::ReduceErrorKind::ResourceLimit {
            resource: guarded_ascii_word::ReduceResource::SpanSum,
            needed,
            limit,
        } if needed == upper.span_sum && limit == upper.span_sum - 1
    ));
    assert_eq!(source.actual, guarded_ascii_word::ReduceActual::default());
    assert_eq!(source.upper_bounds, Some(upper));
}

#[test]
fn guarded_ascii_word_scope_includes_span_sum_and_unicode_uses_its_distinct_owner() {
    let pattern = r"\b(?:as|break|Self|ab|ba)\b";
    assert_eq!(
        aggregate_builder(pattern)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::GuardedUnicodeWordLiteralSet
    );
    assert_eq!(
        aggregate_builder(pattern)
            .unicode(false)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::GuardedAsciiWordDictionary
    );
    assert_eq!(
        aggregate_builder(pattern)
            .unicode(false)
            .build_spans()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        aggregate_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
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

    for pattern in [r"a|b", r"[ab]", r"(a)"] {
        let finite = aggregate_builder(pattern).build_count().unwrap();
        assert!(matches!(
            finite.build_report().plan_identity,
            AggregatePlanIdentity::FiniteLiteral(identity)
                if identity.semantics
                    == AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
        ));
    }
    for pattern in [r"\Aa", r"a+"] {
        let continuation = aggregate_builder(pattern).build_count().unwrap();
        assert!(matches!(
            continuation.build_report().plan_identity,
            AggregatePlanIdentity::Continuation(identity)
                if identity.semantics == AggregateContinuationSemantics::UnicodeOnUtf8ScalarHir
        ));
    }
    for pattern in [r"a|b", r"[ab]", r"(a)", r"\Aa", r"a+"] {
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
        AggregatePlanIdentity::FiniteLiteral(identity)
            if identity.semantics
                == AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
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
fn unicode_singleton_case_folds_use_byte_stable_finite_dfa() {
    let folded_russian = aggregate_builder("рус")
        .case_insensitive(true)
        .build_count()
        .unwrap();
    assert!(matches!(
        folded_russian.build_report().plan_identity,
        AggregatePlanIdentity::FiniteLiteral(identity)
            if identity.semantics
                == AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
    ));
    assert_eq!(
        folded_russian
            .count("РУС рус".as_bytes(), AggregateRunLimits::default())
            .unwrap()
            .value(),
        2
    );

    let folded_kelvin = aggregate_builder(r"(?i:k)").build_count().unwrap();
    assert!(matches!(
        folded_kelvin.build_report().plan_identity,
        AggregatePlanIdentity::FiniteLiteral(identity)
            if identity.semantics
                == AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
    ));
    let kelvin_haystack = [b'K', b'k', 0xE2, 0x84, 0xAA];
    assert_eq!(
        folded_kelvin
            .count(&kelvin_haystack, AggregateRunLimits::default())
            .unwrap()
            .value(),
        3
    );
    let broad_folded_property = aggregate_builder(r"(?i:\pL)").build_count().unwrap();
    assert_eq!(
        broad_folded_property.build_report().plan,
        AggregatePlanKind::UnicodeScalarClass
    );
    assert_eq!(
        broad_folded_property
            .count_value("A雪1".as_bytes(), AggregateRunLimits::default())
            .unwrap(),
        2
    );
}

#[test]
fn unicode_scalar_count_value_matches_audited_count_for_short_input() {
    std::thread::Builder::new()
        .name("unicode-scalar-count-value-short-input".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let regex = aggregate_builder(r"\pL").build_count().unwrap();
            let haystack = "Δ".as_bytes();
            assert_eq!(
                regex.build_report().plan,
                AggregatePlanKind::UnicodeScalarClass
            );
            assert_eq!(
                regex
                    .count_value(haystack, AggregateRunLimits::default())
                    .unwrap(),
                regex
                    .count(haystack, AggregateRunLimits::default())
                    .unwrap()
                    .value()
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn unicode_scalar_value_paths_match_reports_and_replayed_errors_across_modes() {
    std::thread::Builder::new()
        .name("unicode-scalar-value-paths".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let haystack = b"ab--\xCE\xB1\xCE\xB2\xFF\xE9\x9B\xAA\xE9\x9B\xAAz";
            for pattern in [
                r"\pL",
                r"\pL+",
                r"\pL+?",
                r"\pL{2,4}",
                r"\pL{2,4}?",
                r"\pL{3,}",
            ] {
                let count = aggregate_builder(pattern).build_count().unwrap();
                let counted = count
                    .count(haystack, AggregateRunLimits::default())
                    .unwrap();
                let count_work = match counted.report().details() {
                    AggregateExecutionDetails::UnicodeScalar(accounting) => {
                        accounting.upper_bounds.work
                    }
                    AggregateExecutionDetails::UnicodeScalarCursorCount(accounting) => {
                        accounting.upper_bounds.work
                    }
                    _ => panic!("count {pattern:?} selected another execution family"),
                };
                let mut exact_count_limits = AggregateRunLimits::default();
                exact_count_limits.unicode_scalar.max_work = count_work;
                for _ in 0..2 {
                    assert_eq!(
                        count.count_value(haystack, exact_count_limits).unwrap(),
                        counted.value(),
                        "count {pattern:?}"
                    );
                }
                let mut below_count_limits = exact_count_limits;
                below_count_limits.unicode_scalar.max_work =
                    count_work.checked_sub(1).unwrap();
                let audited_count_error = count.count(haystack, below_count_limits).unwrap_err();
                let value_count_error =
                    count.count_value(haystack, below_count_limits).unwrap_err();
                assert_eq!(value_count_error.identity, audited_count_error.identity);
                assert_eq!(value_count_error.source, audited_count_error.source);
                assert!(value_count_error.has_closed_direct_attempt());

                let span_sum = aggregate_builder(pattern).build_span_sum().unwrap();
                let summed = span_sum
                    .span_sum(haystack, AggregateRunLimits::default())
                    .unwrap();
                let AggregateExecutionDetails::UnicodeScalar(span_accounting) =
                    summed.report().details()
                else {
                    panic!("span sum {pattern:?} selected another execution family")
                };
                let mut exact_span_limits = AggregateRunLimits::default();
                exact_span_limits.unicode_scalar.max_work = span_accounting.upper_bounds.work;
                for _ in 0..2 {
                    assert_eq!(
                        span_sum
                            .span_sum_value(haystack, exact_span_limits)
                            .unwrap(),
                        summed.value(),
                        "span sum {pattern:?}"
                    );
                }
                let mut below_span_limits = exact_span_limits;
                below_span_limits.unicode_scalar.max_work =
                    span_accounting.upper_bounds.work.checked_sub(1).unwrap();
                let audited_span_error =
                    span_sum.span_sum(haystack, below_span_limits).unwrap_err();
                let value_span_error = span_sum
                    .span_sum_value(haystack, below_span_limits)
                    .unwrap_err();
                assert_eq!(value_span_error.identity, audited_span_error.identity);
                assert_eq!(value_span_error.source, audited_span_error.source);
                assert!(value_span_error.has_closed_direct_attempt());
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

fn assert_unicode_scalar_cursor_count_route(pattern: &str, haystack: &[u8], expected_count: u64) {
    let count = aggregate_builder(pattern).build_count().unwrap();
    let AggregateBuildAccounting::UnicodeScalarCursorCount(build) = count.build_report().build
    else {
        panic!("Count {pattern:?} did not retain the cursor owner")
    };
    assert_eq!(build.persistent_bytes, count.build_report().retained_capacity_bytes);
    assert!(build.work > build.scalar.work);
    assert_eq!(build.scratch_bytes, build.scalar.scratch_bytes);
    let AggregatePlanIdentity::UnicodeScalar(identity) = count.build_report().plan_identity else {
        panic!("Count {pattern:?} retained another semantic identity")
    };
    assert_eq!(identity.kernel.plan_id, UNICODE_SCALAR_CURSOR_COUNT_PLAN_ID);
    assert_eq!(
        identity.kernel.operation_id,
        UNICODE_SCALAR_CURSOR_COUNT_OPERATION_ID
    );
    assert_eq!(identity.kernel.operation, UnicodeScalarAggregateOperation::Count);

    let retained = count
        .retained_full_window_upper_bounds(haystack.len())
        .unwrap()
        .expect("cursor Count publishes a retained full-window envelope");
    let fre::AggregateRetainedFullWindowUpperBounds::UnicodeScalarCursorCount(upper) = retained
    else {
        panic!("cursor Count published another upper-bound family")
    };
    assert!(count
        .prepare_unicode_scalar_count(haystack.len(), AggregateRunLimits::default())
        .unwrap()
        .is_none());
    let counted = count
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counted.value(), expected_count, "{pattern:?}");
    assert!(counted.report().has_closed_direct_attempt());
    let owner = counted
        .report()
        .direct_owner()
        .expect("cursor Count retains its direct owner");
    assert_eq!(owner.identity().schema_version, 52);
    assert_eq!(owner.identity().algorithm_version, 3);
    assert_eq!(owner.identity().accounting_version, 2);
    let AggregateExecutionDetails::UnicodeScalarCursorCount(accounting) =
        counted.report().details()
    else {
        panic!("cursor Count {pattern:?} published another detail family")
    };
    assert_eq!(accounting.upper_bounds, upper);
    assert_eq!(accounting.actual.count, expected_count);
    assert_eq!(
        accounting.actual.cursor_semantic_prefix_bytes
            + accounting.actual.scalar_semantic_suffix_bytes,
        haystack.len()
    );
    assert_eq!(
        accounting.actual.control_work,
        accounting.actual.search_calls + usize::try_from(expected_count).unwrap()
    );
    assert!(accounting.actual.search_calls <= accounting.upper_bounds.search_calls);

    let mut exact = AggregateRunLimits::default();
    exact.unicode_scalar.max_work = upper.work;
    assert_eq!(count.count_value(haystack, exact).unwrap(), expected_count);
    let mut one_below = exact;
    one_below.unicode_scalar.max_work = upper.work.checked_sub(1).unwrap();
    assert!(count
        .prepare_unicode_scalar_count(haystack.len(), one_below)
        .unwrap()
        .is_none());
    let audited_error = count.count(haystack, one_below).unwrap_err();
    let value_error = count.count_value(haystack, one_below).unwrap_err();
    assert_eq!(value_error.identity, audited_error.identity);
    assert_eq!(value_error.source, audited_error.source);
    assert!(value_error.has_closed_direct_attempt());
    assert!(matches!(
        audited_error.source,
        AggregateExecutionSource::UnicodeScalar(
            UnicodeScalarAggregateReduceError::WorkLimit { needed, limit }
        ) if needed == upper.work && limit == upper.work - 1
    ));
}

fn assert_unicode_scalar_cursor_compile_route(pattern: &str, haystack: &[u8], expected_count: u64) {
    let compiled = aggregate_builder(pattern).build_compile().unwrap();
    assert!(matches!(
        compiled.build_report().build,
        AggregateBuildAccounting::UnicodeScalarCursorCount(_)
    ));
    assert_eq!(
        compiled
            .verify_count(haystack, AggregateRunLimits::default())
            .unwrap()
            .value(),
        expected_count
    );
}

fn assert_unicode_scalar_span_sum_route(pattern: &str, haystack: &[u8], expected_span_sum: u64) {
    let span_sum = aggregate_builder(pattern).build_span_sum().unwrap();
    assert!(matches!(
        span_sum.build_report().build,
        AggregateBuildAccounting::UnicodeScalar(_)
    ));
    let summed = span_sum
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(summed.value(), expected_span_sum);
    assert!(summed.report().has_closed_direct_attempt());
    assert!(matches!(
        summed.report().details(),
        AggregateExecutionDetails::UnicodeScalar(_)
    ));
}

#[test]
fn unicode_scalar_cursor_count_facade_is_distinct_and_preserves_span_sum() {
    let cases: [(&str, &[u8]); 2] = [
        (r"\p{Greek}+", b"A--\xCE\xB1\xCE\xB2\xFF\xCE\xA9--Z"),
        (r"(?s:.){2,3}?", b"a\n\xFF\xE9\x9B\xAA\x80bc"),
    ];
    for (pattern, haystack) in cases {
        let expected = upstream_profile(pattern, haystack, false, true);
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_span_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum::<u64>();

        assert_unicode_scalar_cursor_count_route(pattern, haystack, expected_count);
        assert_unicode_scalar_cursor_compile_route(pattern, haystack, expected_count);
        assert_unicode_scalar_span_sum_route(pattern, haystack, expected_span_sum);
    }
}

#[test]
fn unicode_root_scalar_classes_stream_once_for_count_span_sum_and_compile_verify() {
    let cases: [(&str, &[u8], bool); 8] = [
        (".", b"a\n\xFF\xE9\x9B\xAA\x80", false),
        ("(?s:.)", b"a\n\xFF\xE9\x9B\xAA\x80", false),
        (r"\pL", "A雪1δ Ж".as_bytes(), false),
        (r"\p{Greek}", "Aαδ雪Ω".as_bytes(), false),
        (r"\p{Sm}", "a+×÷雪".as_bytes(), false),
        (r"\d", "1१雪".as_bytes(), false),
        (r"\s", "a\u{2003}\t雪".as_bytes(), false),
        (r"\w", "a\u{203F}\u{0301}雪!".as_bytes(), false),
    ];
    for (pattern, haystack, case_insensitive) in cases {
        let expected = upstream_profile(pattern, haystack, case_insensitive, true);
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum::<u64>();

        let count = aggregate_builder(pattern)
            .case_insensitive(case_insensitive)
            .build_count()
            .unwrap_or_else(|error| panic!("count build {pattern:?}: {error}"));
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::UnicodeScalarClass
        );
        assert_eq!(count.build_report().continuation_strategy, None);
        assert!(matches!(
            count.build_report().plan_identity,
            AggregatePlanIdentity::UnicodeScalar(identity)
                if identity.semantics
                    == AggregateUnicodeScalarSemantics::UnicodeOnRootClassUtf8False
                    && identity.kernel.operation == UnicodeScalarAggregateOperation::Count
        ));
        let build = match count.build_report().build {
            AggregateBuildAccounting::UnicodeScalar(build) => build,
            AggregateBuildAccounting::UnicodeScalarCursorCount(build) => build.scalar,
            _ => panic!("root scalar class selected another build family"),
        };
        assert!(build.source_ranges > 0);
        assert!(build.retained_non_ascii_ranges > 0);
        assert!(count.build_report().unicode_scalar_planner_work >= 2);
        assert!(
            count.build_report().unicode_scalar_planner_work
                <= build.source_ranges.checked_add(1).unwrap()
        );
        assert_eq!(
            build.persistent_bytes,
            count.build_report().retained_capacity_bytes
        );

        let counted = count
            .count(haystack, AggregateRunLimits::default())
            .unwrap_or_else(|error| panic!("count run {pattern:?}: {error}"));
        assert_eq!(counted.value(), expected_count, "pattern={pattern:?}");
        match counted.report().details() {
            AggregateExecutionDetails::UnicodeScalar(accounting) => {
                assert_eq!(accounting.actual.input_bytes_advanced, haystack.len());
                assert_eq!(accounting.actual.scratch_bytes, 0);
                assert!(accounting.actual.work <= accounting.upper_bounds.work);
                assert_eq!(
                    accounting.actual.valid_scalars + accounting.actual.invalid_bytes,
                    accounting.actual.ascii_bitmap_tests
                        + accounting.actual.non_ascii_membership_tests
                        + accounting.actual.invalid_bytes
                );
            }
            AggregateExecutionDetails::UnicodeScalarCursorCount(accounting) => {
                assert_eq!(accounting.actual.input_bytes_advanced, haystack.len());
                assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
                assert_eq!(
                    accounting.actual.cursor_semantic_prefix_bytes
                        + accounting.actual.scalar_semantic_suffix_bytes,
                    haystack.len()
                );
                assert_eq!(accounting.actual.count, expected_count);
            }
            _ => panic!("root scalar count executed another family"),
        }

        let sum = aggregate_builder(pattern)
            .case_insensitive(case_insensitive)
            .build_span_sum()
            .unwrap_or_else(|error| panic!("sum build {pattern:?}: {error}"));
        assert!(matches!(
            sum.build_report().plan_identity,
            AggregatePlanIdentity::UnicodeScalar(identity)
                if identity.kernel.operation == UnicodeScalarAggregateOperation::SpanSum
        ));
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("sum run {pattern:?}: {error}")),
            expected_sum,
            "pattern={pattern:?}"
        );

        let compiled = aggregate_builder(pattern)
            .case_insensitive(case_insensitive)
            .build_compile()
            .unwrap_or_else(|error| panic!("compile build {pattern:?}: {error}"));
        assert_eq!(
            compiled.build_report().plan,
            AggregatePlanKind::UnicodeScalarClass
        );
        assert_eq!(
            compiled
                .verify_count(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("compile verify {pattern:?}: {error}"))
                .value(),
            expected_count
        );
    }
}

#[test]
fn exactly_one_unicode_scalar_facade_gates_the_distinct_owner_on_sve2() {
    const PATTERN: &str = r"[0-9A-Z_a-zα-ω雪]";

    let dispatch = SimdDispatchContext::capture();
    let sve2 = dispatch
        .capabilities()
        .usable()
        .contains(SimdFeature::ArmSve)
        && dispatch
            .capabilities()
            .usable()
            .contains(SimdFeature::ArmSve2);
    let count = aggregate_builder(PATTERN).build_count().unwrap();
    let span_sum = aggregate_builder(PATTERN).build_span_sum().unwrap();
    let AggregatePlanIdentity::UnicodeScalar(count_identity) = count.build_report().plan_identity
    else {
        panic!("the exactly-one Count selected another plan family");
    };
    assert_eq!(
        count_identity.kernel.plan_id,
        if sve2 {
            DISPATCHED_UNICODE_SCALAR_AGGREGATE_PLAN_ID
        } else {
            UNICODE_SCALAR_CURSOR_COUNT_PLAN_ID
        }
    );
    let AggregatePlanIdentity::UnicodeScalar(span_sum_identity) =
        span_sum.build_report().plan_identity
    else {
        panic!("the exactly-one SpanSum selected another plan family");
    };
    assert_eq!(
        span_sum_identity.kernel.plan_id == DISPATCHED_UNICODE_SCALAR_AGGREGATE_PLAN_ID,
        sve2
    );
    match count.build_report().build {
        AggregateBuildAccounting::UnicodeScalar(build) => {
            assert!(sve2);
            assert_eq!(build.ascii_classifier_build_work, 132);
            assert!(build.ascii_classifier_bytes > 0);
            assert!(build.dispatched_owner_bytes > 0);
        }
        AggregateBuildAccounting::UnicodeScalarCursorCount(build) => {
            assert!(!sve2);
            assert_eq!(build.scalar.ascii_classifier_build_work, 0);
            assert_eq!(build.scalar.ascii_classifier_bytes, 0);
            assert_eq!(build.scalar.dispatched_owner_bytes, 0);
        }
        _ => panic!("the exactly-one class retained another build receipt"),
    }

    let haystack = [
        b"aZ_09!?".repeat(10),
        "αω雪🦀".as_bytes().to_vec(),
        b"\xFFabc".repeat(8),
    ]
    .concat();
    let expected = upstream_profile(PATTERN, &haystack, false, true);
    let counted = count
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    let summed = span_sum
        .span_sum(&haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counted.value(), u64::try_from(expected.len()).unwrap());
    assert_eq!(
        summed.value(),
        expected
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum()
    );
    match counted.report().details() {
        AggregateExecutionDetails::UnicodeScalar(accounting) => {
            assert!(sve2);
            assert!(accounting.actual.ascii_block_classifications > 0);
            assert!(accounting.upper_bounds.ascii_block_classifications > 0);
            assert!(accounting.actual.work <= accounting.upper_bounds.work);
        }
        AggregateExecutionDetails::UnicodeScalarCursorCount(accounting) => {
            assert!(!sve2);
            assert_eq!(accounting.identity.plan_id, UNICODE_SCALAR_CURSOR_COUNT_PLAN_ID);
            assert_eq!(accounting.actual.count, u64::try_from(expected.len()).unwrap());
        }
        _ => panic!("the exactly-one class executed another plan family"),
    }
}

#[test]
#[ignore = "manual release-mode end-to-end benchmark; requires Linux/AArch64 with OS-usable SVE2"]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the ignored paired timing harness keeps route proof, alternating batches, checksums, and one parseable record together"
)]
fn measure_routed_unicode_scalar_ascii_blocks() {
    use fre_kernels::{
        UnicodeScalarAggregateBuildLimits as KernelBuildLimits, UnicodeScalarAggregatePlan,
        UnicodeScalarAggregateReduceLimits as KernelReduceLimits,
    };
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    // Retain non-ASCII members so the facade cannot normalize this semantic
    // class into the finite-literal route while the timed corpus stays ASCII.
    const PATTERN: &str = r"[0-9A-Z_a-zα-ω雪]";
    const HAYSTACK_BYTES: usize = 1 << 20;

    let dispatch = SimdDispatchContext::capture();
    assert!(
        dispatch
            .capabilities()
            .usable()
            .contains(SimdFeature::ArmSve)
            && dispatch
                .capabilities()
                .usable()
                .contains(SimdFeature::ArmSve2),
        "this benchmark requires OS-usable SVE and SVE2"
    );
    let scalar = UnicodeScalarAggregatePlan::build(
        [
            ('0', '9'),
            ('A', 'Z'),
            ('_', '_'),
            ('a', 'z'),
            ('α', 'ω'),
            ('雪', '雪'),
        ],
        KernelBuildLimits::unlimited(),
    )
    .unwrap();
    let routed = aggregate_builder(PATTERN).build_count().unwrap();
    assert_eq!(
        routed.build_report().plan,
        AggregatePlanKind::UnicodeScalarClass
    );
    assert!(matches!(
        routed.build_report().plan_identity,
        AggregatePlanIdentity::UnicodeScalar(identity)
            if identity.kernel.plan_id == DISPATCHED_UNICODE_SCALAR_AGGREGATE_PLAN_ID
    ));
    let AggregateBuildAccounting::UnicodeScalar(routed_build) = routed.build_report().build else {
        panic!("routed facade retained another build receipt");
    };
    assert_eq!(routed_build.ascii_classifier_build_work, 132);
    assert!(routed_build.ascii_classifier_bytes > 0);
    assert!(routed_build.dispatched_owner_bytes > 0);

    let batches = 9_u32;
    let calls_per_batch = 8_u32;
    let ascii = b"abc_XYZ0123 !-\t"
        .iter()
        .copied()
        .cycle()
        .take(HAYSTACK_BYTES)
        .collect::<Vec<_>>();
    let mut mixed_unit = b"abc_XYZ0123 !-\t".to_vec();
    mixed_unit.extend_from_slice("αω雪🦀".as_bytes());
    let mixed = mixed_unit
        .iter()
        .copied()
        .cycle()
        .take(HAYSTACK_BYTES)
        .collect::<Vec<_>>();
    let unicode = "αω雪🦀"
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(HAYSTACK_BYTES)
        .collect::<Vec<_>>();

    for (scenario, haystack) in [
        ("ascii_1m", ascii),
        ("mixed_1m", mixed),
        ("unicode_1m", unicode),
    ] {
        let expected = scalar
            .count(&haystack, KernelReduceLimits::unlimited())
            .unwrap()
            .count;
        assert_eq!(
            routed
                .count_value(&haystack, AggregateRunLimits::default())
                .unwrap(),
            expected
        );

        let mut scalar_elapsed = Duration::ZERO;
        let mut facade_elapsed = Duration::ZERO;
        let mut scalar_checksum = 0_u64;
        let mut facade_checksum = 0_u64;
        for batch in 0..batches {
            let mut time_scalar = || {
                let started = Instant::now();
                for _ in 0..calls_per_batch {
                    let value = scalar
                        .count(black_box(&haystack), KernelReduceLimits::unlimited())
                        .unwrap()
                        .count;
                    scalar_checksum =
                        scalar_checksum.wrapping_add(black_box(value).wrapping_add(1));
                }
                scalar_elapsed += started.elapsed();
            };
            let mut time_facade = || {
                let started = Instant::now();
                for _ in 0..calls_per_batch {
                    let value = routed
                        .count_value(black_box(&haystack), AggregateRunLimits::default())
                        .unwrap();
                    facade_checksum =
                        facade_checksum.wrapping_add(black_box(value).wrapping_add(1));
                }
                facade_elapsed += started.elapsed();
            };
            if batch & 1 == 0 {
                time_scalar();
                time_facade();
            } else {
                time_facade();
                time_scalar();
            }
        }
        assert_eq!(facade_checksum, scalar_checksum);
        println!(
            "UNICODE_SCALAR_ASCII_BLOCK_FACADE_BENCH scenario={scenario} operation=count \
             policy=sve2_only route=unicode_scalar scalar_ns={} facade_ns={} \
             facade_over_scalar={:.6} classifier_build_work={} classifier_bytes={} \
             owner_bytes={} checksum={facade_checksum}",
            scalar_elapsed.as_nanos(),
            facade_elapsed.as_nanos(),
            facade_elapsed.as_secs_f64() / scalar_elapsed.as_secs_f64(),
            routed_build.ascii_classifier_build_work,
            routed_build.ascii_classifier_bytes,
            routed_build.dispatched_owner_bytes,
        );
    }
}

// rebar-row:curated/10-bounded-repeat/capitals@rust/regex
#[test]
fn bounded_capitals_count_selects_linear_plan_at_hand_derived_work_boundary() {
    let pattern = r"(?:[A-Z][a-z]+\s*){10,100}";
    let haystack = b"Aa Bb Cc Dd Ee Ff Gg Hh Ii Jj!";
    let expected = upstream(pattern, haystack, false);
    assert_eq!(expected, vec![(0, 29)]);

    let regex = aggregate_builder(pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::BoundedClassSequence
    );
    let AggregateBuildAccounting::BoundedClassSequence(build) = regex.build_report().build else {
        panic!("assigned capitals row did not retain bounded sequence accounting")
    };
    assert_eq!(build.allocations, 0);
    assert_eq!(build.reserves, 0);
    assert_eq!(build.temporary_copies, 0);

    let planner_work = regex.build_report().bounded_class_sequence_planner_work;
    let prior_fixed_work = regex.build_report().fixed_class_sandwich_planner_work;
    let exact_planner = AggregateBuildLimits {
        // The preceding fixed-sandwich inspection keeps its old exact quota;
        // the new optimizer has a separately authenticated planner limit.
        max_fixed_class_sandwich_planner_work: prior_fixed_work,
        max_bounded_class_sequence_planner_work: planner_work,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        aggregate_builder(pattern)
            .unicode(false)
            .limits(exact_planner)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::BoundedClassSequence
    );
    let one_below_planner = AggregateBuildLimits {
        max_fixed_class_sandwich_planner_work: prior_fixed_work,
        max_bounded_class_sequence_planner_work: planner_work.checked_sub(1).unwrap(),
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        aggregate_builder(pattern)
            .unicode(false)
            .limits(one_below_planner)
            .build_count(),
        Err(AggregateBuildError::BoundedClassSequencePlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit.checked_add(1) == Some(planner_work)
    ));

    // N=30, so 28*N+8 = 848. The sole complete match is 0..29;
    // the terminal `!` is inspected but excluded from the greedy match.
    let exact_work = 848;
    let exact = AggregateRunLimits {
        bounded_class_sequence: fre::BoundedClassSequenceReduceLimits {
            max_work: exact_work,
            ..fre::BoundedClassSequenceReduceLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let counted = regex.count(haystack, exact).unwrap();
    assert_eq!(counted.value(), 1);
    let AggregateExecutionDetails::BoundedClassSequence(accounting) = counted.report().details()
    else {
        panic!("assigned capitals row did not execute bounded sequence plan")
    };
    assert_eq!(accounting.upper_bounds.work, exact_work);

    let one_below = AggregateRunLimits {
        bounded_class_sequence: fre::BoundedClassSequenceReduceLimits {
            max_work: 847,
            ..fre::BoundedClassSequenceReduceLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let error = regex.count(haystack, one_below).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::BoundedClassSequence(
            fre::BoundedClassSequenceReduceError::WorkLimit { needed, limit }
        ) if needed == exact_work && limit.checked_add(1) == Some(exact_work)
    ));
}

fn assert_bounded_separated_ip_planner_boundary(pattern: &str, regex: &fre::AggregateCountRegex) {
    let planner_work = regex.build_report().bounded_separated_fields_planner_work;
    assert!(planner_work > 0);
    let prior_work = regex.build_report().bounded_class_sequence_planner_work;
    let exact_planner = AggregateBuildLimits {
        max_bounded_class_sequence_planner_work: prior_work,
        max_bounded_separated_fields_planner_work: planner_work,
        ..AggregateBuildLimits::default()
    };
    assert!(
        aggregate_builder(pattern)
            .unicode(false)
            .limits(exact_planner)
            .build_count()
            .is_ok()
    );
    assert!(matches!(
        aggregate_builder(pattern)
            .unicode(false)
            .limits(AggregateBuildLimits {
                max_bounded_separated_fields_planner_work: planner_work
                    .checked_sub(1)
                    .unwrap(),
                ..exact_planner
            })
            .build_count(),
        Err(AggregateBuildError::BoundedSeparatedFieldsPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit.checked_add(1) == Some(planner_work)
    ));
}

// rebar-row:imported/mariomka/ip@rust/regex
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one route test keeps diagnostic and compact value exact/one-below contracts adjacent"
)]
fn bounded_separated_ip_count_selects_typed_plan_and_exact_work_boundary() {
    let pattern =
        r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9])";
    let haystack = b"0.0.0.0 255.255.255.255 256.1.1.1 10.20.30.40";
    let expected = upstream(pattern, haystack, false);
    let regex = aggregate_builder(pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::BoundedSeparatedFields
    );
    assert!(matches!(
        regex.build_report().plan_identity,
        AggregatePlanIdentity::BoundedSeparatedFields(identity)
            if identity.kernel.plan_id == fre::BOUNDED_SEPARATED_FIELDS_PLAN_ID
    ));
    assert!(matches!(
        regex.build_report().build,
        AggregateBuildAccounting::BoundedSeparatedFields(build)
            if build.allocations == 0 && build.reserves == 0
    ));

    assert_bounded_separated_ip_planner_boundary(pattern, &regex);

    let exact_work = haystack.len() * 78 + 8;
    let exact_sequential = haystack.len() * 50;
    let exact_run = AggregateRunLimits {
        bounded_separated_fields: fre::BoundedSeparatedFieldsReduceLimits {
            max_work: exact_work,
            max_sequential_bytes: exact_sequential,
            ..fre::BoundedSeparatedFieldsReduceLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let counted = regex.count(haystack, exact_run).unwrap();
    let expected_count = u64::try_from(expected.len()).unwrap();
    assert_eq!(counted.value(), expected_count);
    assert_eq!(
        regex.count_value(haystack, exact_run).unwrap(),
        expected_count
    );
    let AggregateExecutionDetails::BoundedSeparatedFields(accounting) = counted.report().details()
    else {
        panic!("assigned IP row did not execute bounded separated-field plan")
    };
    assert_eq!(accounting.upper_bounds.work, exact_work);
    assert_eq!(accounting.upper_bounds.sequential_bytes, exact_sequential);
    assert_eq!(accounting.upper_bounds.random_access_bytes, 0);
    assert_eq!(
        accounting.actual.sequential_bytes,
        accounting
            .actual
            .separator_inspections
            .checked_add(accounting.actual.class_comparisons)
            .unwrap()
    );
    assert!(accounting.actual.sequential_bytes <= exact_sequential);
    assert_eq!(accounting.actual.random_access_bytes, 0);
    let work_one_below = AggregateRunLimits {
        bounded_separated_fields: fre::BoundedSeparatedFieldsReduceLimits {
            max_work: exact_work - 1,
            ..fre::BoundedSeparatedFieldsReduceLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let value_error = regex.count_value(haystack, work_one_below).unwrap_err();
    assert!(value_error.has_closed_direct_attempt());
    assert!(matches!(
        value_error.source,
        AggregateExecutionSource::BoundedSeparatedFields(
            fre::BoundedSeparatedFieldsReduceError::WorkLimit { needed, limit }
        ) if needed == exact_work && limit + 1 == exact_work
    ));
    let error = regex.count(haystack, work_one_below).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::BoundedSeparatedFields(
            fre::BoundedSeparatedFieldsReduceError::WorkLimit { needed, limit }
        ) if needed == exact_work && limit + 1 == exact_work
    ));
    let sequential_one_below = AggregateRunLimits {
        bounded_separated_fields: fre::BoundedSeparatedFieldsReduceLimits {
            max_sequential_bytes: exact_sequential - 1,
            ..fre::BoundedSeparatedFieldsReduceLimits::default()
        },
        ..AggregateRunLimits::default()
    };
    let value_error = regex
        .count_value(haystack, sequential_one_below)
        .unwrap_err();
    assert!(value_error.has_closed_direct_attempt());
    assert!(matches!(
        value_error.source,
        AggregateExecutionSource::BoundedSeparatedFields(
            fre::BoundedSeparatedFieldsReduceError::SequentialLimit { needed, limit }
        ) if needed == exact_sequential && limit + 1 == exact_sequential
    ));
    let error = regex.count(haystack, sequential_one_below).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::BoundedSeparatedFields(
            fre::BoundedSeparatedFieldsReduceError::SequentialLimit { needed, limit }
        ) if needed == exact_sequential && limit + 1 == exact_sequential
    ));
}

// rebar-row:curated/10-bounded-repeat/capitals@rust/regex
#[test]
fn bounded_class_sequence_differentials_compare_complete_spans_across_semantic_edges() {
    let invalid = [
        b'A', b'a', b' ', b'B', b'b', 0xFF, b'C', b'c', b' ', b'D', b'd',
    ];
    let cases: [(&str, &[u8], bool, bool, bool); 9] = [
        (
            r"(?:(?<h>[A-Z])(?<b>[a-z]+)(?<t> *)){2,3}",
            b"Aa Bb Cc!",
            false,
            false,
            true,
        ),
        (
            r"(?m:^(?:[A-Z][a-z]+ *){2,3}$)",
            b"Aa Bb\nCc Dd\n",
            false,
            false,
            false,
        ),
        (
            r"(?:[A-Z][a-z]+ *){2,3}",
            b"aa BB Cc dd",
            false,
            true,
            false,
        ),
        (r"(?:[A][b]+ *){2,3}", b"ab AB!", false, true, true),
        (r"(?:[A-Z][a-z]+ *){2,3}", &invalid, false, false, true),
        (r"(?:[A-Z][a-z]+ *){2,3}", &invalid, true, false, false),
        (
            r"(?:[^\x00-\x40\x5B-\xFF][a-z&&[^x]]+[ \t]*){2,3}",
            b"Aa Bb\tCx Dd ",
            false,
            false,
            true,
        ),
        (r"(?:[a&&b][a-z]+ *){2,3}", b"Aa Bb", false, false, false),
        (
            r"(?:[A-Z][a-z]+ *){2,3}",
            b"!Aa Bb Cc?Dd Ee!",
            false,
            false,
            true,
        ),
    ];
    for (pattern, haystack, unicode, case_insensitive, direct) in cases {
        let windows = [0..haystack.len(), 1.min(haystack.len())..haystack.len()];
        for window in windows {
            let slice = &haystack[window];
            let expected = upstream_profile(pattern, slice, case_insensitive, unicode);
            let spans = aggregate_builder(pattern)
                .unicode(unicode)
                .case_insensitive(case_insensitive)
                .plan_selection(AggregatePlanSelection::ForceContinuation)
                .build_spans()
                .unwrap_or_else(|error| panic!("span build {pattern:?}: {error}"))
                .spans(slice, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("span run {pattern:?}/{slice:?}: {error}"));
            let actual = spans
                .iter()
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "complete spans {pattern:?}/{slice:?}");

            let count = aggregate_builder(pattern)
                .unicode(unicode)
                .case_insensitive(case_insensitive)
                .build_count()
                .unwrap_or_else(|error| panic!("count build {pattern:?}: {error}"));
            assert_eq!(
                count.build_report().plan == AggregatePlanKind::BoundedClassSequence,
                direct,
                "selection {pattern:?}/{slice:?}"
            );
            let count = count
                .count_value(slice, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("count run {pattern:?}/{slice:?}: {error}"));
            assert_eq!(count, u64::try_from(expected.len()).unwrap());
        }
    }
}

// rebar-row:curated/10-bounded-repeat/capitals@rust/regex
#[test]
fn bounded_capitals_execution_work_scales_at_n_2n_and_4n() {
    type BoundedCapitalsCase = (&'static [u8], usize, &'static [(usize, usize)]);
    let pattern = r"(?:[A-Z][a-z]+\s*){10,100}";
    let cases: [BoundedCapitalsCase; 3] = [
        (b"AaBbCcDdEeFfGgHhIiJj!", 596, &[(0, 20)]),
        (
            b"AaBbCcDdEeFfGgHhIiJj!AaBbCcDdEeFfGgHhIiJj!",
            1_184,
            &[(0, 20), (21, 41)],
        ),
        (
            b"AaBbCcDdEeFfGgHhIiJj!AaBbCcDdEeFfGgHhIiJj!AaBbCcDdEeFfGgHhIiJj!AaBbCcDdEeFfGgHhIiJj!",
            2_360,
            &[(0, 20), (21, 41), (42, 62), (63, 83)],
        ),
    ];
    let regex = aggregate_builder(pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    for (haystack, hand_work, hand_spans) in cases {
        assert_eq!(
            upstream(pattern, haystack, false).as_slice(),
            hand_spans,
            "complete hand-derived spans at N={}",
            haystack.len()
        );
        let counted = regex
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(counted.value(), u64::try_from(hand_spans.len()).unwrap());
        let AggregateExecutionDetails::BoundedClassSequence(accounting) =
            counted.report().details()
        else {
            panic!("assigned capitals row did not execute bounded sequence plan")
        };
        // The fixed finalization charge is 8; the remaining 28*N term is
        // therefore exactly doubled by the 2N witness and quadrupled by 4N.
        assert_eq!(accounting.upper_bounds.work, hand_work);
        assert_eq!(
            accounting.upper_bounds.work.checked_sub(8).unwrap(),
            haystack.len().checked_mul(28).unwrap()
        );
    }
}

// rebar-row:curated/10-bounded-repeat/capitals@rust/regex
#[test]
fn bounded_class_sequence_structural_work_is_linear_in_canonical_ranges() {
    let compact = aggregate_builder(r"(?:[A-C][a-c]+\x20*){2,3}")
        .unicode(false)
        .build_count()
        .unwrap();
    let doubled = aggregate_builder(r"(?:[A-CE-G][a-ce-g]+[\x09\x20]*){2,3}")
        .unicode(false)
        .build_count()
        .unwrap();
    let quadrupled =
        aggregate_builder(r"(?:[A-CE-GI-KM-O][a-ce-gi-km-o]+[\x01\x03\x05\x07]*){2,3}")
            .unicode(false)
            .build_count()
            .unwrap();
    let AggregateBuildAccounting::BoundedClassSequence(compact_build) =
        compact.build_report().build
    else {
        panic!("compact sequence did not select the bounded plan")
    };
    let AggregateBuildAccounting::BoundedClassSequence(doubled_build) =
        doubled.build_report().build
    else {
        panic!("doubled-range sequence did not select the bounded plan")
    };
    let AggregateBuildAccounting::BoundedClassSequence(quadrupled_build) =
        quadrupled.build_report().build
    else {
        panic!("quadrupled-range sequence did not select the bounded plan")
    };
    assert_eq!(compact_build.source_ranges, 3);
    assert_eq!(doubled_build.source_ranges, 6);
    assert_eq!(quadrupled_build.source_ranges, 12);
    // One range visit plus the 2Q-3 three-merge comparison bound gives 3Q.
    let fixed_work = compact
        .build_report()
        .bounded_class_sequence_planner_work
        .checked_sub(compact_build.source_ranges.checked_mul(3).unwrap())
        .unwrap();
    for (plan, ranges) in [(&doubled, 6_usize), (&quadrupled, 12_usize)] {
        assert_eq!(
            plan.build_report().bounded_class_sequence_planner_work,
            fixed_work
                .checked_add(ranges.checked_mul(3).unwrap())
                .unwrap()
        );
    }
}

#[test]
fn fixed_class_sandwich_matches_pinned_bytes_oracle_for_both_unicode_profiles() {
    let cases: [(&str, bool, &[u8]); 4] = [
        (r"[a-q][^u-z]{3}x", false, b"apppx--a\xFF\xFF\xFFx--auuux"),
        (r"[a-q][^u-z]{3}x", false, b"aqqqxapppxapx"),
        (
            r"[a-q][^u-z]{3}[x\xE0-\xFF]",
            true,
            "a雪δéx--aöööà--auuux".as_bytes(),
        ),
        (
            r"[a-q][^u-z]{3}[x\xE0-\xFF]",
            true,
            b"a\xFFbcx--apppx--a\xE2\x98\x83\xE2\x88\x9E\xC3\xA9x",
        ),
    ];
    for (pattern, unicode, haystack) in cases {
        let expected = upstream_profile(pattern, haystack, false, unicode);
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end.checked_sub(*start).unwrap()).unwrap())
            .sum::<u64>();
        let count = aggregate_builder(pattern)
            .unicode(unicode)
            .build_count()
            .unwrap_or_else(|error| panic!("count build {pattern:?}: {error}"));
        assert_eq!(
            count.build_report().plan,
            if unicode {
                AggregatePlanKind::FixedClassSandwich
            } else {
                AggregatePlanKind::FixedPredicateWord64
            }
        );
        assert_eq!(count.build_report().continuation_strategy, None);
        assert!(count.build_report().fixed_class_sandwich_planner_work > 5);
        if unicode {
            assert!(matches!(
                count.build_report().plan_identity,
                AggregatePlanIdentity::FixedClassSandwich(identity)
                    if identity.kernel.operation == FixedClassSandwichOperation::Count
                        && identity.semantics
                            == AggregateFixedClassSandwichSemantics::UnicodeOnScalarClassesUtf8False
            ));
        } else {
            assert!(matches!(
                count.build_report().plan_identity,
                AggregatePlanIdentity::FixedPredicateWord64(identity)
                    if identity.operation == FixedPredicateWord64Operation::Count
            ));
        }
        let counted = count
            .count(haystack, AggregateRunLimits::default())
            .unwrap_or_else(|error| panic!("count run {pattern:?}: {error}"));
        assert_eq!(counted.value(), expected_count, "pattern={pattern:?}");
        match counted.report().details() {
            AggregateExecutionDetails::FixedClassSandwich(accounting) if unicode => {
                assert_eq!(accounting.actual.input_bytes_advanced, haystack.len());
                assert!(accounting.actual.work <= accounting.upper_bounds.work);
            }
            AggregateExecutionDetails::FixedPredicateWord64(accounting) if !unicode => {
                assert!(accounting.actual.transitions <= accounting.upper_bounds.transitions);
                assert!(accounting.actual.work_charged <= accounting.upper_bounds.work);
            }
            details => panic!("fixed class count used unexpected execution family: {details:?}"),
        }

        let sum = aggregate_builder(pattern)
            .unicode(unicode)
            .build_span_sum()
            .unwrap();
        assert!(matches!(
            sum.build_report().plan_identity,
            AggregatePlanIdentity::FixedClassSandwich(identity)
                if identity.kernel.operation == FixedClassSandwichOperation::SpanSum
        ));
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_sum
        );
        let compiled = aggregate_builder(pattern)
            .unicode(unicode)
            .build_compile()
            .unwrap();
        assert_eq!(
            compiled.build_report().plan,
            AggregatePlanKind::FixedClassSandwich
        );
        assert_eq!(
            compiled
                .verify_count(haystack, AggregateRunLimits::default())
                .unwrap()
                .value(),
            expected_count
        );
    }
}

#[test]
fn fixed_class_sandwich_erases_nested_captures_with_exact_planner_accounting() {
    let cases: [(&str, bool, &[u8]); 2] = [
        (
            r"(?P<all>(?P<p>[a-q])(?P<run>(?P<m>[^u-z]){3})(?P<s>x))",
            false,
            b"apppx--a\xFF\xFF\xFFx--auuux",
        ),
        (
            r"(?P<all>(?P<p>[a-q])(?P<run>(?P<m>[^u-z]){3})(?P<s>[x\xE0-\xFF]))",
            true,
            "a雪δéx--aöööà--auuux".as_bytes(),
        ),
    ];

    for (pattern, unicode, haystack) in cases {
        let expected = upstream_profile(pattern, haystack, false, unicode);
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end.checked_sub(*start).unwrap()).unwrap())
            .sum::<u64>();
        let count = aggregate_builder(pattern)
            .unicode(unicode)
            .build_count()
            .unwrap_or_else(|error| panic!("captured count build {pattern:?}: {error}"));
        let report = count.build_report();
        assert_eq!(
            report.plan,
            if unicode {
                AggregatePlanKind::FixedClassSandwich
            } else {
                AggregatePlanKind::FixedPredicateWord64
            }
        );
        assert_eq!(report.captures_erased, 5);
        assert_eq!(report.capture_erasure_work, if unicode { 5 } else { 10 });
        assert_eq!(report.syntax.captures, 5);
        assert!(report.fixed_class_sandwich_planner_work > report.capture_erasure_work);
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_count,
            "pattern={pattern:?}"
        );

        let sum = aggregate_builder(pattern)
            .unicode(unicode)
            .build_span_sum()
            .unwrap_or_else(|error| panic!("captured span-sum build {pattern:?}: {error}"));
        assert_eq!(
            sum.build_report().plan,
            AggregatePlanKind::FixedClassSandwich
        );
        assert_eq!(sum.build_report().captures_erased, 5);
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_sum,
            "pattern={pattern:?}"
        );

        let compiled = aggregate_builder(pattern)
            .unicode(unicode)
            .build_compile()
            .unwrap_or_else(|error| panic!("captured compile build {pattern:?}: {error}"));
        assert_eq!(
            compiled.build_report().plan,
            AggregatePlanKind::FixedClassSandwich
        );
        assert_eq!(compiled.build_report().captures_erased, 5);
        assert_eq!(
            compiled
                .verify_count(haystack, AggregateRunLimits::default())
                .unwrap()
                .value(),
            expected_count,
            "pattern={pattern:?}"
        );

        let planner_work = report.fixed_class_sandwich_planner_work;
        let limits = AggregateBuildLimits {
            max_fixed_class_sandwich_planner_work: planner_work.checked_sub(1).unwrap(),
            ..AggregateBuildLimits::default()
        };
        assert!(matches!(
            aggregate_builder(pattern)
                .unicode(unicode)
                .limits(limits)
                .build_count(),
            Err(AggregateBuildError::FixedClassSandwichPlannerWorkLimit {
                needed,
                limit,
                ..
            }) if needed == planner_work && limit.checked_add(1) == Some(planner_work)
        ));
    }
}

#[test]
fn fixed_class_sandwich_count_prefers_fixed_predicate_through_width_64() {
    let width_64_pattern = r"[a-q][^u-z]{62}x";
    let mut width_64_haystack = vec![b'a'];
    width_64_haystack.extend(core::iter::repeat_n(b'p', 62));
    width_64_haystack.push(b'x');
    let width_64 = aggregate_builder(width_64_pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        width_64.build_report().plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    assert!(matches!(
        width_64.build_report().plan_identity,
        AggregatePlanIdentity::FixedPredicateWord64(identity)
            if identity.operation == FixedPredicateWord64Operation::Count
                && identity.width == 64
    ));
    assert_eq!(
        width_64
            .count_value(&width_64_haystack, AggregateRunLimits::default())
            .unwrap(),
        1
    );
    let audited = width_64
        .count(&width_64_haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FixedPredicateWord64(accounting) = audited.report().details()
    else {
        panic!("width-64 count did not execute the fixed-predicate plan")
    };
    let mut run_limits = AggregateRunLimits::default();
    run_limits.finite_literal.max_total_work =
        usize::try_from(accounting.upper_bounds.work.checked_sub(1).unwrap()).unwrap();
    let error = width_64.count(&width_64_haystack, run_limits).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::FixedPredicateWord64(
            fre::FixedPredicateWord64ReduceError::WorkLimit { .. }
        )
    ));

    assert_eq!(
        aggregate_builder(width_64_pattern)
            .unicode(false)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::FixedClassSandwich
    );
    assert_eq!(
        aggregate_builder(width_64_pattern)
            .unicode(false)
            .build_compile()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::FixedClassSandwich
    );
    assert_eq!(
        aggregate_builder(width_64_pattern)
            .unicode(false)
            .build_spans()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );

    let width_65_pattern = r"[a-q][^u-z]{63}x";
    let mut width_65_haystack = vec![b'a'];
    width_65_haystack.extend(core::iter::repeat_n(b'p', 63));
    width_65_haystack.push(b'x');
    let width_65 = aggregate_builder(width_65_pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        width_65.build_report().plan,
        AggregatePlanKind::FixedClassSandwich
    );
    assert_eq!(
        width_65
            .count_value(&width_65_haystack, AggregateRunLimits::default())
            .unwrap(),
        1
    );
    let planner_work = width_65.build_report().fixed_class_sandwich_planner_work;
    let limits = AggregateBuildLimits {
        max_fixed_class_sandwich_planner_work: planner_work.checked_sub(1).unwrap(),
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        aggregate_builder(width_65_pattern)
            .unicode(false)
            .limits(limits)
            .build_count(),
        Err(AggregateBuildError::FixedClassSandwichPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit.checked_add(1) == Some(planner_work)
    ));

    let audited = width_65
        .count(&width_65_haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FixedClassSandwich(accounting) = audited.report().details()
    else {
        panic!("fixed class plan executed another family")
    };
    assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
    let mut run_limits = AggregateRunLimits::default();
    run_limits.fixed_class_sandwich.max_work = accounting.upper_bounds.work.checked_sub(1).unwrap();
    let error = width_65.count(&width_65_haystack, run_limits).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::FixedClassSandwich(
            FixedClassSandwichReduceError::WorkLimit { .. }
        )
    ));

    for ineligible in [
        r"[a-q][^u-z]{2,3}x",
        r"[a-q][^u-z]+x",
        r"[a-q][^u-z]{3}xy",
        r"[a-q][^u-z]{3}x!",
    ] {
        assert_ne!(
            aggregate_builder(ineligible)
                .unicode(false)
                .build_count()
                .unwrap()
                .build_report()
                .plan,
            AggregatePlanKind::FixedClassSandwich,
            "pattern={ineligible:?}"
        );
    }
}

#[test]
fn rebar_row_curated_10_bounded_repeat_context_selects_linear_count() {
    // rebar-row:curated/10-bounded-repeat/context@rust/regex
    let pattern = r"[A-Za-z]{10}\s+[\s\S]{0,100}Result[\s\S]{0,100}\s+[A-Za-z]{10}";
    let haystack = b"prefix ABCDEFGHIJ 12Result34 KLMNOPQRST suffix\nUVWXYZabcd Result efghijklMN";
    let expected = upstream_profile(pattern, haystack, false, false);
    let regex = aggregate_builder(pattern)
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(regex.build_report().plan, AggregatePlanKind::BoundedContext);
    assert!(regex.build_report().bounded_context_planner_work > 0);
    assert!(matches!(
        regex.build_report().plan_identity,
        AggregatePlanIdentity::BoundedContext(identity)
            if identity.kernel.plan_id == fre::BOUNDED_CONTEXT_PLAN_ID
    ));
    let counted = regex
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counted.value(), u64::try_from(expected.len()).unwrap());
    assert!(matches!(
        counted.report().details(),
        AggregateExecutionDetails::BoundedContext(_)
    ));
}

#[test]
fn rebar_row_curated_10_bounded_repeat_context_exact_limit_and_one_below() {
    // rebar-row:curated/10-bounded-repeat/context@rust/regex
    // Hand calculation, not SUT output: `[a-z]{2}\s+.{0,2}R.{0,2}\s+[a-z]{2}`
    // on `aa R bb` has N=7, L=1, T=2 and S=12*floor(7/3)=24.
    // Thus W=21*7+11*1+3*24+40=270. Limit 270 admits complete span
    // 0..7/count 1; limit 269 refuses before allocation/traversal with no fallback.
    let regex = aggregate_builder(r"[a-z]{2}\s+[\s\S]{0,2}R[\s\S]{0,2}\s+[a-z]{2}")
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(regex.build_report().plan, AggregatePlanKind::BoundedContext);
    let mut exact = AggregateRunLimits::default();
    exact.bounded_context.max_work = 270;
    assert_eq!(regex.count_value(b"aa R bb", exact).unwrap(), 1);
    exact.bounded_context.max_work = 269;
    let error = regex.count_value(b"aa R bb", exact).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::BoundedContext(BoundedContextReduceError::WorkLimit {
            needed: 270,
            limit: 269,
        })
    ));
}

#[test]
fn rebar_row_curated_10_bounded_repeat_context_complete_span_matrix() {
    // rebar-row:curated/10-bounded-repeat/context@rust/regex
    // Complete spans, rather than counts, cover captures, assertions, folding,
    // malformed UTF-8, complement/intersection classes, empty language, and
    // sliced boundary windows. Ineligible shapes remain on their old identity.
    let cases: [(&str, &[u8], bool); 7] = [
        (
            r"(?P<all>[A-Za-z]{2} +[\s\S]{0,2}(?P<lit>R)[\s\S]{0,2} +[A-Za-z]{2})",
            b"aa R bb--cc 1R2 dd",
            false,
        ),
        (
            r"\A[a-z]{2} +[\s\S]{0,2}R[\s\S]{0,2} +[a-z]{2}\z",
            b"aa R bb",
            false,
        ),
        (
            r"[a-z]{2} +[\s\S]{0,2}r[\s\S]{0,2} +[a-z]{2}",
            b"AA R bb",
            true,
        ),
        (
            r"[a-z]{2} +[\s\S]{0,2}R[\s\S]{0,2} +[a-z]{2}",
            b"aa \xFFR\xFE bb",
            false,
        ),
        (
            r"[a-z&&[^q]]{2} +[\s\S]{0,2}R[\s\S]{0,2} +[^0-9 ]{2}",
            b"aa 1R2 bb",
            false,
        ),
        (
            r"[a&&b]{2} +[\s\S]{0,2}R[\s\S]{0,2} +[a-z]{2}",
            b"aa R bb",
            false,
        ),
        (
            r"[a-z]{2} +[\s\S]{0,2}R[\s\S]{0,2} +[a-z]{2}",
            b"xxaa R bbyy",
            false,
        ),
    ];
    for (pattern, haystack, case_insensitive) in cases {
        let expected = upstream_profile(pattern, haystack, case_insensitive, false);
        let spans = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(case_insensitive)
            .build_spans()
            .unwrap()
            .spans(haystack, AggregateRunLimits::default())
            .unwrap();
        let actual = spans
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "pattern={pattern:?}");
    }

    let whole = b"xxaa R bbyy";
    let window = &whole[2..9];
    let pattern = r"[a-z]{2} +[\s\S]{0,2}R[\s\S]{0,2} +[a-z]{2}";
    let expected = upstream_profile(pattern, window, false, false);
    let spans = aggregate_builder(pattern)
        .unicode(false)
        .build_spans()
        .unwrap()
        .spans(window, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(
        spans
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>(),
        expected
    );
}

#[test]
fn unicode_scalar_plus_uses_the_run_automaton_for_greedy_and_lazy_reduction() {
    let cases: [(&str, &[u8], AggregateUnicodeScalarSemantics); 5] = [
        (
            r"\pL+",
            b"abc--\xCE\xB1\xCE\xB2\xFFZ",
            AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreGreedyUtf8False,
        ),
        (
            r"\pL+?",
            b"abc--\xCE\xB1\xCE\xB2\xFFZ",
            AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreLazyUtf8False,
        ),
        (
            r"(?P<run>[a-z]+)",
            b"ab--c\xFFde",
            AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreGreedyUtf8False,
        ),
        (
            r"(?P<atom>[a-z])+?",
            b"ab--c\xFFde",
            AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreLazyUtf8False,
        ),
        (
            r"(?s:.)+",
            b"A\n\xFF\xE9\x9B\xAA\x80Z",
            AggregateUnicodeScalarSemantics::UnicodeOnRootClassOneOrMoreGreedyUtf8False,
        ),
    ];
    for (pattern, haystack, semantics) in cases {
        let expected = upstream_profile(pattern, haystack, false, true);
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum::<u64>();
        let count = aggregate_builder(pattern).build_count().unwrap();
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::UnicodeScalarClass
        );
        assert!(matches!(
            count.build_report().plan_identity,
            AggregatePlanIdentity::UnicodeScalar(identity)
                if identity.semantics == semantics
                    && identity.kernel.repetition.is_run()
                    && identity.kernel.operation == UnicodeScalarAggregateOperation::Count
        ));
        let AggregateBuildAccounting::UnicodeScalarCursorCount(build) =
            count.build_report().build
        else {
            panic!("scalar repetition selected another build family")
        };
        assert!(build.scalar.repetition.is_run());
        let counted = count
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(counted.value(), expected_count, "pattern={pattern:?}");
        let AggregateExecutionDetails::UnicodeScalarCursorCount(accounting) =
            counted.report().details()
        else {
            panic!("scalar repetition executed another family")
        };
        assert!(accounting.upper_bounds.reducer_steps > 0);
        assert!(accounting.actual.search_calls <= accounting.upper_bounds.search_calls);
        assert_eq!(accounting.upper_bounds.scratch_bytes, 0);

        let sum = aggregate_builder(pattern).build_span_sum().unwrap();
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_sum,
            "pattern={pattern:?}"
        );
    }
}

#[test]
fn unicode_scalar_greedy_star_erases_only_zero_length_matches_for_span_sum() {
    let cases: [(&str, &[u8], bool); 7] = [
        (".*", b"", false),
        (".*", b"abc\n\xFF\xE9\x9B\xAA\x80z", false),
        ("(?s:.)*", b"a\n\xFF\xE9\x9B\xAA\x80z", false),
        (r"\pL*", "ab--αβ--雪1".as_bytes(), false),
        (r"(?P<run>\pL*)", "ab--αβ--雪1".as_bytes(), false),
        (r"(?P<atom>\pL)*", "ab--αβ--雪1".as_bytes(), false),
        (r"[k]*", b"kK--kk", true),
    ];
    for (pattern, haystack, case_insensitive) in cases {
        let expected = upstream_profile(pattern, haystack, case_insensitive, true);
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum::<u64>();

        let sum = aggregate_builder(pattern)
            .case_insensitive(case_insensitive)
            .build_span_sum()
            .unwrap_or_else(|error| panic!("sum build {pattern:?}: {error}"));
        assert_eq!(
            sum.build_report().plan,
            AggregatePlanKind::UnicodeScalarClass,
            "pattern={pattern:?}"
        );
        assert!(matches!(
            sum.build_report().plan_identity,
            AggregatePlanIdentity::UnicodeScalar(identity)
                if identity.semantics
                    == AggregateUnicodeScalarSemantics::UnicodeOnRootClassZeroOrMoreGreedySpanSumUtf8False
                    && identity.kernel.repetition
                        == fre::UnicodeScalarAggregateRepetition::OneOrMoreGreedy
                    && identity.kernel.operation == UnicodeScalarAggregateOperation::SpanSum
        ));
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("sum run {pattern:?}: {error}")),
            expected_sum,
            "pattern={pattern:?}"
        );

        let count = aggregate_builder(pattern)
            .case_insensitive(case_insensitive)
            .build_count()
            .unwrap_or_else(|error| panic!("count build {pattern:?}: {error}"));
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::ContinuationProgram,
            "count must retain nullable semantics for {pattern:?}"
        );
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap_or_else(|error| panic!("count run {pattern:?}: {error}")),
            expected_count,
            "pattern={pattern:?}"
        );

        assert_eq!(
            aggregate_builder(pattern)
                .case_insensitive(case_insensitive)
                .build_compile()
                .unwrap_or_else(|error| panic!("compile build {pattern:?}: {error}"))
                .build_report()
                .plan,
            AggregatePlanKind::ContinuationProgram,
            "compile must retain nullable semantics for {pattern:?}"
        );
    }

    for non_equivalent in [r"\pL*?", r"\pL{0,4}"] {
        assert_eq!(
            aggregate_builder(non_equivalent)
                .build_span_sum()
                .unwrap()
                .build_report()
                .plan,
            AggregatePlanKind::ContinuationProgram
        );
    }
    assert_eq!(
        aggregate_builder(r"\pL{0,}")
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::UnicodeScalarClass
    );
}

#[test]
fn unicode_scalar_counted_repetition_is_direct_across_operations_and_positions() {
    let cases: [(&str, &[u8]); 11] = [
        (r"\pL{2,4}", b"ab--cdef--g"),
        (r"\pL{2,4}?", b"ab--cdef--g"),
        (r"\pL{3,}", "αβγ--雪雪雪雪".as_bytes()),
        (r"\pL{2}", b"--ab--"),
        (r"\pL{2,4}", b"ab----------------"),
        (r"\pL{2,4}", b"----------------ab"),
        (r"\pL{2,4}", b"\xFFa\x80bcde\xE2\x82"),
        (r".{2,3}", b"ab\ncd\xFFef"),
        (r"(?s:.){2,3}", b"ab\ncd\xFFef"),
        (r"(?P<run>\pL{2,4})", "ab--αβγ".as_bytes()),
        (r"(?P<atom>\pL){2,4}", "ab--αβγ".as_bytes()),
    ];
    for (pattern, haystack) in cases {
        let expected = upstream_profile(pattern, haystack, false, true);
        let expected_count = u64::try_from(expected.len()).unwrap();
        let expected_sum = expected
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum::<u64>();

        let count = aggregate_builder(pattern).build_count().unwrap();
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::UnicodeScalarClass
        );
        assert!(matches!(
            count.build_report().plan_identity,
            AggregatePlanIdentity::UnicodeScalar(identity)
                if identity.semantics
                    == AggregateUnicodeScalarSemantics::UnicodeOnRootClassRepeatedUtf8False
                    && matches!(
                        identity.kernel.repetition,
                        fre::UnicodeScalarAggregateRepetition::RepeatedGreedy { .. }
                            | fre::UnicodeScalarAggregateRepetition::RepeatedLazy { .. }
                    )
        ));
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_count,
            "count {pattern:?}/{haystack:?}"
        );
        let sum = aggregate_builder(pattern).build_span_sum().unwrap();
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_sum,
            "span sum {pattern:?}/{haystack:?}"
        );
        let compiled = aggregate_builder(pattern).build_compile().unwrap();
        assert_eq!(
            compiled.build_report().plan,
            AggregatePlanKind::UnicodeScalarClass
        );
        assert_eq!(
            compiled
                .verify_count(haystack, AggregateRunLimits::default())
                .unwrap()
                .value(),
            expected_count,
            "compile verify {pattern:?}/{haystack:?}"
        );
    }

    for nullable in [r"\pL*", r"\pL{0,4}"] {
        assert_eq!(
            aggregate_builder(nullable)
                .build_count()
                .unwrap()
                .build_report()
                .plan,
            AggregatePlanKind::ContinuationProgram
        );
    }
}

#[test]
fn counted_scalar_direct_owner_closes_success_and_terminal_for_count_and_span_sum() {
    let haystack = "ab--αβγ--z".as_bytes();
    for pattern in [r"\pL{2,4}", r"\pL{2,4}?"] {
        let count = aggregate_builder(pattern).build_count().unwrap();
        let counted = count
            .count(haystack, AggregateRunLimits::default())
            .unwrap();
        assert!(counted.report().has_closed_direct_attempt());
        let count_owner = counted
            .report()
            .direct_owner()
            .expect("counted scalar count success must retain its direct owner");
        assert_eq!(
            count_owner.identity().route,
            fre::AggregateDirectRoute::UnicodeScalar
        );
        assert!(count_owner.authenticates(counted.report().identity()));

        let mut refused = AggregateRunLimits::default();
        refused.unicode_scalar.max_work = 0;
        let count_error = count.count(haystack, refused).unwrap_err();
        assert!(count_error.has_closed_direct_attempt());
        let count_receipt = count_error
            .direct_receipt()
            .expect("counted scalar count refusal must retain its direct receipt");
        assert_eq!(count_receipt.owner(), &count_owner);
        assert!(count_receipt.authenticates_source(&count_error.source));
        assert!(matches!(
            count_error.source,
            AggregateExecutionSource::UnicodeScalar(
                UnicodeScalarAggregateReduceError::WorkLimit { .. }
            )
        ));

        let compiled = aggregate_builder(pattern).build_compile().unwrap();
        assert!(matches!(
            compiled.build_report().plan_identity,
            AggregatePlanIdentity::UnicodeScalar(identity)
                if identity.kernel.operation == UnicodeScalarAggregateOperation::Count
        ));
        let verified = compiled
            .verify_count(haystack, AggregateRunLimits::default())
            .unwrap();
        assert!(verified.report().has_closed_direct_attempt());
        let compile_owner = verified
            .report()
            .direct_owner()
            .expect("counted scalar compile verification must retain its direct owner");
        assert_eq!(
            compile_owner.identity().operation,
            AggregateOperation::Compile
        );
        assert!(compile_owner.authenticates(verified.report().identity()));

        let compile_error = compiled.verify_count(haystack, refused).unwrap_err();
        assert!(compile_error.has_closed_direct_attempt());
        let compile_receipt = compile_error
            .direct_receipt()
            .expect("counted scalar compile refusal must retain its direct receipt");
        assert_eq!(compile_receipt.owner(), &compile_owner);
        assert!(compile_receipt.authenticates_source(&compile_error.source));
        assert!(matches!(
            compile_error.source,
            AggregateExecutionSource::UnicodeScalar(
                UnicodeScalarAggregateReduceError::WorkLimit { .. }
            )
        ));

        let span_sum = aggregate_builder(pattern).build_span_sum().unwrap();
        let summed = span_sum
            .span_sum(haystack, AggregateRunLimits::default())
            .unwrap();
        assert!(summed.report().has_closed_direct_attempt());
        let span_sum_owner = summed
            .report()
            .direct_owner()
            .expect("counted scalar span-sum success must retain its direct owner");
        assert_eq!(
            span_sum_owner.identity().route,
            fre::AggregateDirectRoute::UnicodeScalar
        );
        assert!(span_sum_owner.authenticates(summed.report().identity()));

        let span_sum_error = span_sum.span_sum(haystack, refused).unwrap_err();
        assert!(span_sum_error.has_closed_direct_attempt());
        let span_sum_receipt = span_sum_error
            .direct_receipt()
            .expect("counted scalar span-sum refusal must retain its direct receipt");
        assert_eq!(span_sum_receipt.owner(), &span_sum_owner);
        assert!(span_sum_receipt.authenticates_source(&span_sum_error.source));
        assert!(matches!(
            span_sum_error.source,
            AggregateExecutionSource::UnicodeScalar(
                UnicodeScalarAggregateReduceError::WorkLimit { .. }
            )
        ));
    }
}

#[test]
fn ordered_captured_unicode_repetitions_use_one_bounded_scalar_run() {
    // Authenticated Rebar obligations:
    // - unicode/overlapping-words/english@rust/regex
    // - unicode/overlapping-words/russian@rust/regex
    let pattern = r"(\p{L}{14})|(\p{L}{13})|(\p{L}{12})|(\p{L}{11})|(\p{L}{10})|(\p{L}{9})|(\p{L}{8})|(\p{L}{7})|(\p{L}{6})|(\p{L}{5})";
    let limits = AggregateBuildLimits {
        max_unicode_scalar_planner_work: 8_192,
        ..AggregateBuildLimits::default()
    };
    let regex = aggregate_builder(pattern)
        .unicode(true)
        .limits(limits)
        .build_count()
        .expect("uniform captured alternation");
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::UnicodeScalarClass
    );
    assert_eq!(regex.build_report().captures_erased, 10);
    assert!(matches!(
        regex.build_report().plan_identity,
        AggregatePlanIdentity::UnicodeScalar(identity)
            if identity.semantics
                == AggregateUnicodeScalarSemantics::UnicodeOnUniformCapturedAlternationRepeatedUtf8False
                && identity.participating_captures_per_match == 1
                && matches!(
                    identity.kernel.repetition,
                    fre::UnicodeScalarAggregateRepetition::RepeatedGreedy {
                        minimum: 5,
                        maximum: Some(14),
                    }
                )
    ));
    for haystack in [
        "abcdefghijklmn--abcde--абвгдежзийклмн".as_bytes(),
        "abcd\nабвгде\r\nabcdefghijklmnop".as_bytes(),
        b"\xFFabcdefghijklmn\x80abcde".as_slice(),
    ] {
        let expected = u64::try_from(upstream_profile(pattern, haystack, false, true).len())
            .expect("upstream count");
        assert_eq!(
            regex
                .count_value(haystack, AggregateRunLimits::default())
                .expect("scalar count"),
            expected,
            "{haystack:?}"
        );
    }

    for ineligible in [
        r"(\p{L}{13})|(\p{L}{14})",
        r"(\p{L}{14})|(\p{L}{12})",
        r"(\p{L}{2})|(\p{N}{1})",
        r"((\p{L}{2}))|(\p{L}{1})",
        r"([\s\S]{2})|([\s\S]{1})",
        r"(\p{L}{2}?)|(\p{L}{1})",
    ] {
        let fallback = aggregate_builder(ineligible)
            .unicode(true)
            .limits(limits)
            .build_count();
        match fallback {
            Ok(fallback) => assert_ne!(
                fallback.build_report().plan,
                AggregatePlanKind::UnicodeScalarClass,
                "ineligible normalization {ineligible:?}"
            ),
            Err(AggregateBuildError::ContinuationCompile { .. }) => {}
            Err(error) => panic!("unexpected fallback {ineligible:?}: {error}"),
        }
    }
}

#[test]
fn unicode_scalar_root_captures_are_transparent_and_limits_remain_typed() {
    let pattern = r"(?P<scalar>\pL)";
    let haystack = "A雪1δ".as_bytes();
    let regex = aggregate_builder(pattern).build_count().unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::UnicodeScalarClass
    );
    assert_eq!(regex.build_report().captures_erased, 1);
    assert_eq!(regex.build_report().capture_erasure_work, 1);
    let planner_work = regex.build_report().unicode_scalar_planner_work;
    assert!(planner_work > 2);
    assert_eq!(
        regex
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        3
    );

    let build_limits = AggregateBuildLimits {
        max_unicode_scalar_planner_work: planner_work - 1,
        ..AggregateBuildLimits::default()
    };
    assert!(matches!(
        aggregate_builder(pattern)
            .limits(build_limits)
            .build_count(),
        Err(AggregateBuildError::UnicodeScalarPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit == planner_work - 1
    ));

    let audited = regex
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    let range_comparisons = match audited.report().details() {
        AggregateExecutionDetails::UnicodeScalar(accounting) => {
            accounting.upper_bounds.range_comparisons
        }
        AggregateExecutionDetails::UnicodeScalarCursorCount(accounting) => {
            accounting.upper_bounds.range_comparisons
        }
        _ => panic!("root scalar class executed another plan"),
    };
    assert!(range_comparisons > 0);
    let mut run_limits = AggregateRunLimits::default();
    run_limits.unicode_scalar.max_range_comparisons = range_comparisons - 1;
    let error = regex.count(haystack, run_limits).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::UnicodeScalar(
            UnicodeScalarAggregateReduceError::RangeComparisonsLimit { .. }
        )
    ));
    assert!(
        error
            .identity
            .as_cache_identity()
            .is_some_and(|identity| identity.plan == AggregatePlanKind::UnicodeScalarClass)
    );
}

#[test]
fn unicode_scalar_planner_charges_each_canonical_range_and_has_a_tight_limit() {
    // The first three canonical ranges are non-ASCII singletons. Only the
    // fourth and last range proves eligibility, so selection must charge the
    // root class node and all four range examinations.
    let late_eligible = r"[\u{100}\u{102}\u{104}\u{106}-\u{107}]";
    let regex = aggregate_builder(late_eligible).build_count().unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::UnicodeScalarClass
    );
    assert_eq!(regex.build_report().unicode_scalar_planner_work, 5);
    let build = match regex.build_report().build {
        AggregateBuildAccounting::UnicodeScalar(build) => build,
        AggregateBuildAccounting::UnicodeScalarCursorCount(build) => build.scalar,
        _ => panic!("late eligible scalar class selected another build family"),
    };
    assert_eq!(build.source_ranges, 4);

    let mut exact = AggregateBuildLimits {
        max_unicode_scalar_planner_work: 5,
        ..AggregateBuildLimits::default()
    };
    aggregate_builder(late_eligible)
        .limits(exact)
        .build_count()
        .unwrap();
    exact.max_unicode_scalar_planner_work = 4;
    assert!(matches!(
        aggregate_builder(late_eligible).limits(exact).build_count(),
        Err(AggregateBuildError::UnicodeScalarPlannerWorkLimit {
            needed: 5,
            limit: 4,
            ..
        })
    ));

    // With no qualifying range, every singleton is still examined and
    // charged before the class is handed to the continuation frontier.
    let all_singletons = r"[\u{100}\u{102}\u{104}\u{106}]";
    assert!(matches!(
        aggregate_builder(all_singletons)
            .limits(exact)
            .build_count(),
        Err(AggregateBuildError::UnicodeScalarPlannerWorkLimit {
            needed: 5,
            limit: 4,
            ..
        })
    ));

    let nested = format!("(({late_eligible}))");
    let nested_regex = aggregate_builder(&nested).build_count().unwrap();
    assert_eq!(
        nested_regex.build_report().plan,
        AggregatePlanKind::UnicodeScalarClass
    );
    assert_eq!(nested_regex.build_report().syntax.hir_nodes, 3);
    assert_eq!(nested_regex.build_report().syntax.captures, 2);
    assert_eq!(nested_regex.build_report().captures_erased, 2);
    assert_eq!(nested_regex.build_report().unicode_scalar_planner_work, 7);
    let mut nested_limits = AggregateBuildLimits {
        max_unicode_scalar_planner_work: 7,
        ..AggregateBuildLimits::default()
    };
    aggregate_builder(&nested)
        .limits(nested_limits)
        .build_count()
        .unwrap();
    nested_limits.max_unicode_scalar_planner_work = 6;
    assert!(matches!(
        aggregate_builder(&nested)
            .limits(nested_limits)
            .build_count(),
        Err(AggregateBuildError::UnicodeScalarPlannerWorkLimit {
            needed: 7,
            limit: 6,
            ..
        })
    ));
}

#[test]
fn unicode_scalar_selection_admits_composition_and_preserves_existing_paths() {
    assert_eq!(
        aggregate_builder("雪")
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ExactLiteral
    );
    for pattern in [r"[a-z]", r"(?i:k)"] {
        assert_eq!(
            aggregate_builder(pattern)
                .build_count()
                .unwrap()
                .build_report()
                .plan,
            AggregatePlanKind::FiniteLiteralDfa,
            "pattern={pattern:?}"
        );
    }
    for pattern in [r"\A\pL", r"\pL\z"] {
        assert_eq!(
            aggregate_builder(pattern)
                .build_count()
                .unwrap()
                .build_report()
                .plan,
            AggregatePlanKind::ContinuationProgram,
            "pattern={pattern:?}"
        );
    }
    for pattern in [r"\pL+", r"\pL+?", r"[a-z]+"] {
        assert_eq!(
            aggregate_builder(pattern)
                .build_count()
                .unwrap()
                .build_report()
                .plan,
            AggregatePlanKind::UnicodeScalarClass,
            "pattern={pattern:?}"
        );
    }
    assert_eq!(
        aggregate_builder(r"\pL")
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        aggregate_builder(r"\pL+")
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        aggregate_builder(r"\pL")
            .build_spans()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
}

fn unicode_exact_build_error(limits: &AggregateBuildLimits) -> AggregateBuildError {
    aggregate_builder("雪")
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(*limits)
        .build_count()
        .unwrap_err()
}

fn unicode_exact_count_error(
    regex: &fre::AggregateCountRegex,
    haystack: &[u8],
    limits: &AggregateRunLimits,
) -> LiteralAggregateReduceError {
    let audited = regex.count(haystack, *limits).unwrap_err();
    let value = regex.count_value(haystack, *limits).unwrap_err();
    assert_eq!(value.identity, audited.identity);
    assert_eq!(value.source, audited.source);
    assert!(audited.has_closed_direct_attempt());
    assert!(value.has_closed_direct_attempt());
    let audited_nested = *audited
        .exact_literal_receipt()
        .expect("Unicode exact refusal nested kernel receipt");
    let value_nested = *value
        .exact_literal_receipt()
        .expect("Unicode exact value refusal nested kernel receipt");
    assert_eq!(value_nested, audited_nested);
    assert_eq!(
        audited_nested.identity,
        LiteralAggregateOperationIdentity::for_operation(LiteralAggregateOperation::Count)
    );
    assert_eq!(
        audited_nested.identity.declared_fallback,
        LiteralAggregateDeclaredFallback::None
    );
    assert_eq!(
        audited_nested.identity.algorithm_version,
        LITERAL_AGGREGATE_ALGORITHM_VERSION
    );
    assert_eq!(
        audited_nested.identity.accounting_version,
        LITERAL_AGGREGATE_ACCOUNTING_VERSION
    );
    assert_eq!(audited_nested.invocation.haystack_bytes, haystack.len());
    assert_eq!(audited_nested.invocation.limits, limits.exact_literal);
    assert!(audited_nested.invocation.plan_origin.is_bound());
    assert!(audited_nested.prospective.is_some());
    assert_eq!(
        audited_nested.actual,
        LiteralAggregateActualCounters::default()
    );
    assert_eq!(audited_nested.actual_allocations, 0);
    assert!(audited_nested.retains_bounded_actual());
    assert!(
        audited
            .direct_receipt()
            .expect("Unicode exact refusal terminal receipt")
            .authenticates_source(&audited.source)
    );
    assert!(
        audited
            .identity
            .as_cache_identity()
            .is_some_and(|identity| {
                matches!(identity.plan_identity, AggregatePlanIdentity::ExactLiteral(plan)
                if plan.semantics
                    == AggregateExactLiteralSemantics::UnicodeOnNonemptyUtf8Literal)
            })
    );
    match audited.source {
        AggregateExecutionSource::ExactLiteral(source) => source,
        source => panic!("Unicode exact literal attempted another engine: {source:?}"),
    }
}

fn assert_exact_success_receipt(
    report: &fre::AggregateExecutionReport,
    operation: LiteralAggregateOperation,
    haystack_len: usize,
) {
    let AggregateExecutionDetails::ExactLiteral(details) = report.details() else {
        panic!("forced exact literal executed another plan");
    };
    assert_eq!(
        details.identity,
        LiteralAggregateOperationIdentity::for_operation(operation)
    );
    assert_eq!(
        details.identity.declared_fallback,
        LiteralAggregateDeclaredFallback::None
    );
    assert_eq!(
        details.identity.algorithm_version,
        LITERAL_AGGREGATE_ALGORITHM_VERSION
    );
    assert_eq!(
        details.identity.accounting_version,
        LITERAL_AGGREGATE_ACCOUNTING_VERSION
    );
    assert_eq!(details.invocation.haystack_bytes, haystack_len);
    assert!(details.invocation.plan_origin.is_bound());
    assert_eq!(details.receipt().prospective, Some(details.upper_bounds));
    assert!(details.accounting().closes_receipt(details.receipt()));
    assert_eq!(details.actual.operation_allocations, 0);
    assert_eq!(details.actual_allocations, 0);
    assert!(details.retains_bounded_actual());
    assert!(report.has_closed_direct_attempt());
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
        unicode_exact_build_error(&one_below_build),
        AggregateBuildError::LiteralPlannerWorkLimit {
            needed: 1,
            limit: 0,
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_needle_bytes -= 1;
    assert!(matches!(
        unicode_exact_build_error(&one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::NeedleLimit { .. },
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_build_work -= 1;
    assert!(matches!(
        unicode_exact_build_error(&one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::WorkLimit { .. },
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_scratch_bytes -= 1;
    assert!(matches!(
        unicode_exact_build_error(&one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::ScratchLimit { .. },
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_persistent_bytes -= 1;
    assert!(matches!(
        unicode_exact_build_error(&one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::PersistentLimit { .. },
            ..
        }
    ));
    one_below_build = exact_build;
    one_below_build.exact_literal.max_peak_bytes -= 1;
    assert!(matches!(
        unicode_exact_build_error(&one_below_build),
        AggregateBuildError::ExactLiteralBuild {
            source: LiteralAggregateBuildError::PeakLimit { .. },
            ..
        }
    ));

    let haystack = [b"\xFF\x80".as_slice(), "雪雪".as_bytes(), b"\xC0"].concat();
    let audited = baseline
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::ExactLiteral(accounting) = audited.report().details() else {
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
    assert_eq!(
        accounting.identity,
        LiteralAggregateOperationIdentity::for_operation(LiteralAggregateOperation::Count)
    );
    assert_eq!(accounting.invocation.haystack_bytes, haystack.len());
    assert!(accounting.invocation.plan_origin.is_bound());
    assert_eq!(
        accounting.invocation.limits,
        AggregateRunLimits::default().exact_literal
    );
    assert_eq!(accounting.actual_allocations, 0);
    assert!(accounting.retains_bounded_actual());
    assert!(accounting.accounting().closes_receipt(accounting.receipt()));
    assert!(audited.report().direct_owner().is_some());
    assert!(audited.report().has_closed_direct_attempt());
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
        unicode_exact_count_error(&baseline, &haystack, &one_below_run),
        LiteralAggregateReduceError::LinearTermsLimit { .. }
    ));
    one_below_run = exact_run;
    one_below_run.exact_literal.max_match_events -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, &one_below_run),
        LiteralAggregateReduceError::MatchEventsLimit { .. }
    ));
    one_below_run = exact_run;
    one_below_run.exact_literal.max_count -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, &one_below_run),
        LiteralAggregateReduceError::CountLimit { .. }
    ));
    one_below_run = exact_run;
    one_below_run.exact_literal.max_reducer_steps -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, &one_below_run),
        LiteralAggregateReduceError::ReducerStepsLimit { .. }
    ));
    one_below_run = exact_run;
    one_below_run.exact_literal.max_peak_bytes -= 1;
    assert!(matches!(
        unicode_exact_count_error(&baseline, &haystack, &one_below_run),
        LiteralAggregateReduceError::PeakLimit { .. }
    ));

    let sum = aggregate_builder("雪")
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(exact_build)
        .build_span_sum()
        .unwrap();
    let sum_result = sum.span_sum(&haystack, exact_run).unwrap();
    assert_eq!(sum_result.value(), 6);
    let AggregateExecutionDetails::ExactLiteral(sum_accounting) = sum_result.report().details()
    else {
        panic!("forced Unicode span-sum executed another plan")
    };
    assert_eq!(
        sum_accounting.identity,
        LiteralAggregateOperationIdentity::for_operation(LiteralAggregateOperation::SpanSum)
    );
    assert!(
        sum_accounting
            .accounting()
            .closes_receipt(sum_accounting.receipt())
    );
    assert!(sum_result.report().has_closed_direct_attempt());
    assert_eq!(sum.span_sum_value(&haystack, exact_run).unwrap(), 6);
    one_below_run = exact_run;
    one_below_run.exact_literal.max_span_sum -= 1;
    let audited_error = sum.span_sum(&haystack, one_below_run).unwrap_err();
    let value_error = sum.span_sum_value(&haystack, one_below_run).unwrap_err();
    assert_eq!(value_error.identity, audited_error.identity);
    assert_eq!(value_error.source, audited_error.source);
    assert_eq!(
        value_error.exact_literal_receipt(),
        audited_error.exact_literal_receipt()
    );
    let nested = audited_error
        .exact_literal_receipt()
        .expect("Unicode exact span-sum nested receipt");
    assert_eq!(
        nested.identity,
        LiteralAggregateOperationIdentity::for_operation(LiteralAggregateOperation::SpanSum)
    );
    assert_eq!(nested.actual, LiteralAggregateActualCounters::default());
    assert!(nested.retains_bounded_actual());
    assert!(matches!(
        audited_error.source,
        AggregateExecutionSource::ExactLiteral(LiteralAggregateReduceError::SpanSumLimit { .. })
    ));
}

#[test]
fn exact_success_and_refusal_receipts_cover_empty_arbitrary_and_malformed_bytes() {
    for (pattern, haystack, expected_count, expected_span_sum) in [
        ("", b"\xFFa\x80".as_slice(), 4, 0),
        (r"\xFF\x00", b"\xFF\x00\xFF\x00\x80".as_slice(), 2, 4),
    ] {
        let count = aggregate_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_count()
            .unwrap();
        let span_sum = aggregate_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceExactLiteral)
            .build_span_sum()
            .unwrap();

        let mut count_limits = AggregateRunLimits::default();
        count_limits.exact_literal.max_span_sum = 0;
        let count_result = count.count(haystack, count_limits).unwrap();
        assert_eq!(count_result.value(), expected_count);
        assert_eq!(
            count.count_value(haystack, count_limits).unwrap(),
            expected_count
        );
        assert_exact_success_receipt(
            count_result.report(),
            LiteralAggregateOperation::Count,
            haystack.len(),
        );

        let span_result = span_sum
            .span_sum(haystack, AggregateRunLimits::default())
            .unwrap();
        assert_eq!(span_result.value(), expected_span_sum);
        assert_eq!(
            span_sum
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected_span_sum
        );
        assert_exact_success_receipt(
            span_result.report(),
            LiteralAggregateOperation::SpanSum,
            haystack.len(),
        );

        let mut refused = AggregateRunLimits::default();
        refused.exact_literal.max_linear_terms = 0;
        let count_audited = count.count(haystack, refused).unwrap_err();
        let count_value = count.count_value(haystack, refused).unwrap_err();
        assert_eq!(
            count_audited.exact_literal_receipt(),
            count_value.exact_literal_receipt()
        );
        assert!(count_audited.has_closed_direct_attempt());
        assert!(count_value.has_closed_direct_attempt());
        let count_receipt = count_audited.exact_literal_receipt().unwrap();
        assert!(count_receipt.prospective.is_some());
        assert_eq!(
            count_receipt.actual,
            LiteralAggregateActualCounters::default()
        );

        let span_audited = span_sum.span_sum(haystack, refused).unwrap_err();
        let span_value = span_sum.span_sum_value(haystack, refused).unwrap_err();
        assert_eq!(
            span_audited.exact_literal_receipt(),
            span_value.exact_literal_receipt()
        );
        assert!(span_audited.has_closed_direct_attempt());
        assert!(span_value.has_closed_direct_attempt());
        let span_receipt = span_audited.exact_literal_receipt().unwrap();
        assert!(span_receipt.prospective.is_some());
        assert_eq!(
            span_receipt.actual,
            LiteralAggregateActualCounters::default()
        );
    }
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
    let (certificate, _) = continuation_details(spans.report().details());
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
    assert_eq!(
        admitted.report().cache_identity(),
        full.cache_identity(limits)
    );
    let (certificate, accounting) = continuation_details(admitted.report().details());
    assert_eq!(certificate.strategy, AggregateStrategy::FullTable);
    assert_eq!(certificate.range, 0..4);
    assert!(accounting.work <= certificate.work_bound);

    let required = certificate.random_access_bytes;
    assert!(required > 0);
    let mut refused_limits = limits;
    refused_limits.continuation.max_random_access_bytes = required - 1;
    let error = full.count(b"aaaa", refused_limits).unwrap_err();
    let value_error = full.count_value(b"aaaa", refused_limits).unwrap_err();
    let Some(identity) = error.identity.as_cache_identity() else {
        panic!("continuation attempt must retain its cache identity");
    };
    assert_eq!(identity, &full.cache_identity(refused_limits));
    assert_eq!(
        value_error.identity.as_cache_identity(),
        error.identity.as_cache_identity()
    );
    assert!(error.has_closed_continuation_attempt());
    assert!(value_error.has_closed_continuation_attempt());
    assert_eq!(value_error.source, error.source);
    assert_eq!(
        identity.continuation_strategy,
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
fn continuation_terminal_rejects_caller_visible_coherent_mutations() {
    let regex = aggregate_builder(r"(?:a+b|a)")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .strategy(AggregateStrategy::FullTable)
        .build_count()
        .unwrap();
    let limits = AggregateRunLimits::default();
    let admitted = regex.count(b"aaaa", limits).unwrap();
    let (certificate, _) = continuation_details(admitted.report().details());
    let mut refused_limits = limits;
    refused_limits.continuation.max_random_access_bytes = certificate.random_access_bytes - 1;
    let error = regex.count(b"aaaa", refused_limits).unwrap_err();
    assert!(error.has_closed_continuation_attempt());

    let mut invocation_mutation = error.clone();
    let AggregateExecutionAttemptIdentity::Continuation { receipt, .. } =
        &mut invocation_mutation.identity
    else {
        panic!("continuation terminal lost its receipt");
    };
    receipt.invocation.range = 0..1;
    receipt.invocation.haystack_len = 0;
    assert!(!invocation_mutation.has_closed_continuation_attempt());

    let mut receipt_mutation = error.clone();
    let AggregateExecutionAttemptIdentity::Continuation { receipt, .. } =
        &mut receipt_mutation.identity
    else {
        panic!("continuation terminal lost its receipt");
    };
    receipt.identity.accounting_version = 3;
    assert!(!receipt_mutation.has_closed_continuation_attempt());

    let mut source_mutation = error;
    source_mutation.source = AggregateExecutionSource::Continuation(
        AggregateEngineError::InternalInvariant("caller-spliced continuation source"),
    );
    assert!(!source_mutation.has_closed_continuation_attempt());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one facade matrix checks compact success and terminal receipt closure for all three continuation operations"
)]
fn continuation_facades_retain_closed_operation_specific_success_and_failure_evidence() {
    let pattern = r"(?:a+b|a)";
    let haystack = b"aaaab a";
    let builder = || {
        aggregate_builder(pattern)
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .strategy(AggregateStrategy::ReverseSequentialRows)
    };
    let limits = AggregateRunLimits::default();

    let spans_regex = builder().build_spans().unwrap();
    let initial_spans = spans_regex.spans(haystack, limits).unwrap();
    let (initial_spans_certificate, _) = continuation_details(initial_spans.report().details());
    let mut spans_exact = limits;
    spans_exact.continuation.max_output_bytes = initial_spans_certificate.output_bytes;
    let spans = spans_regex.spans(haystack, spans_exact).unwrap();
    let (spans_certificate, spans_accounting) = continuation_details(spans.report().details());
    assert_eq!(
        spans_certificate.operation,
        AggregateOperationAttemptKind::Spans
    );
    assert_eq!(
        spans.report().cache_identity().execution_limits,
        spans_exact
    );
    assert!(
        spans_certificate.authenticates_limits(spans_exact.continuation),
        "the compact success certificate must seal the exact admitted policy"
    );
    assert_eq!(
        spans_certificate.algorithm_version,
        fre::AGGREGATE_CONTINUATION_ALGORITHM_VERSION
    );
    assert_eq!(
        spans_certificate.accounting_version,
        fre::AGGREGATE_CONTINUATION_ACCOUNTING_VERSION
    );
    assert_ne!(
        spans_certificate.prepublication_fallback,
        fre::AggregateOperationPrepublicationFallback::None,
        "a nontrivial declared fallback must survive success compaction"
    );
    assert!(spans_certificate.output_bytes > 0);

    let mut spans_below = spans_exact;
    spans_below.continuation.max_output_bytes -= 1;
    let spans_error = spans_regex.spans(haystack, spans_below).unwrap_err();
    assert!(spans_error.has_closed_continuation_attempt());
    let spans_failure_receipt = spans_error.continuation_receipt().unwrap();
    let spans_upper = spans_failure_receipt.prospective.unwrap();
    assert_eq!(
        spans_failure_receipt.identity.regex_plan_id,
        spans_certificate.regex_plan_id
    );
    assert_eq!(
        spans_failure_receipt.identity.strategy,
        spans_certificate.strategy
    );
    assert_eq!(
        spans_failure_receipt.identity.operation,
        spans_certificate.operation
    );
    assert_eq!(
        spans_failure_receipt.identity.operation_id(),
        Some(spans_certificate.operation_id())
    );
    assert_eq!(
        spans_failure_receipt.identity.physical_route,
        Some(spans_certificate.physical_route)
    );
    assert_eq!(
        spans_failure_receipt.identity.algorithm_version,
        spans_certificate.algorithm_version
    );
    assert_eq!(
        spans_failure_receipt.identity.accounting_version,
        spans_certificate.accounting_version
    );
    assert_eq!(
        spans_failure_receipt.identity.prepublication_fallback,
        spans_certificate.prepublication_fallback
    );
    assert_continuation_certificate_preserves_prospective(spans_certificate, &spans_upper);
    assert!(spans_upper.contains(*spans_accounting));
    assert_eq!(
        spans_error
            .identity
            .as_cache_identity()
            .unwrap()
            .execution_limits,
        spans_below
    );
    assert!(
        spans_failure_receipt
            .identity
            .authenticates_limits(spans_below.continuation)
    );
    assert!(matches!(
        spans_error.source,
        AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::OutputBytes,
            required,
            limit,
        }) if required == spans_upper.output_bytes && limit + 1 == required
    ));

    let count_regex = builder().build_count().unwrap();
    let count = count_regex.count(haystack, limits).unwrap();
    let (count_certificate, count_accounting) = continuation_details(count.report().details());
    assert_eq!(
        count_certificate.operation,
        AggregateOperationAttemptKind::Count
    );
    assert!(count_certificate.authenticates_limits(limits.continuation));
    assert!(count_accounting.work <= count_certificate.work_bound);
    let count_steady = count_regex.count(haystack, limits).unwrap();
    let (count_steady_certificate, count_steady_accounting) =
        continuation_details(count_steady.report().details());
    assert_eq!(count_steady_certificate, count_certificate);
    assert_eq!(count_steady_accounting, count_accounting);

    let sum_regex = builder().build_span_sum().unwrap();
    let mut sum_exact = limits;
    sum_exact.continuation.max_span_sum = haystack.len();
    let sum = sum_regex.span_sum(haystack, sum_exact).unwrap();
    let (sum_certificate, sum_accounting) = continuation_details(sum.report().details());
    assert_eq!(
        sum_certificate.operation,
        AggregateOperationAttemptKind::SpanSum
    );
    assert!(sum_certificate.authenticates_limits(sum_exact.continuation));
    assert_ne!(
        spans_certificate.operation_id(),
        count_certificate.operation_id()
    );
    assert_ne!(
        count_certificate.operation_id(),
        sum_certificate.operation_id()
    );

    let mut sum_below = sum_exact;
    sum_below.continuation.max_span_sum -= 1;
    let sum_error = sum_regex.span_sum(haystack, sum_below).unwrap_err();
    assert!(sum_error.has_closed_continuation_attempt());
    let sum_failure_receipt = sum_error.continuation_receipt().unwrap();
    let sum_upper = sum_failure_receipt.prospective.unwrap();
    assert_eq!(
        sum_failure_receipt.identity.operation,
        AggregateOperationAttemptKind::SpanSum
    );
    assert_eq!(
        sum_error
            .identity
            .as_cache_identity()
            .unwrap()
            .execution_limits,
        sum_below
    );
    assert!(
        sum_failure_receipt
            .identity
            .authenticates_limits(sum_below.continuation)
    );
    assert_eq!(
        sum_failure_receipt.identity.regex_plan_id,
        sum_certificate.regex_plan_id
    );
    assert_eq!(
        sum_failure_receipt.identity.strategy,
        sum_certificate.strategy
    );
    assert_eq!(
        sum_failure_receipt.identity.operation_id(),
        Some(sum_certificate.operation_id())
    );
    assert_eq!(
        sum_failure_receipt.identity.physical_route,
        Some(sum_certificate.physical_route)
    );
    assert_eq!(
        sum_failure_receipt.identity.algorithm_version,
        sum_certificate.algorithm_version
    );
    assert_eq!(
        sum_failure_receipt.identity.accounting_version,
        sum_certificate.accounting_version
    );
    assert_eq!(
        sum_failure_receipt.identity.prepublication_fallback,
        sum_certificate.prepublication_fallback
    );
    assert_continuation_certificate_preserves_prospective(sum_certificate, &sum_upper);
    assert_eq!(sum_upper.span_sum, haystack.len());
    assert!(sum_upper.contains(*sum_accounting));
    assert!(matches!(
        sum_error.source,
        AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::SpanSum,
            required,
            limit,
        }) if required == sum_upper.span_sum && limit + 1 == required
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

#[test]
fn counter_value_facade_keeps_selected_values_routes_and_direct_absence() {
    let haystack = b"aaaabaaaa";
    let count = aggregate_builder(r"(?:a+b|a)")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    let ordinary_count = count
        .count_value(haystack, AggregateRunLimits::default())
        .unwrap();
    let counter_count = count
        .count_value_with_counters(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counter_count.value(), ordinary_count);
    let count_receipt = counter_count
        .continuation_receipt()
        .expect("forced continuation Count receipt");
    assert!(count_receipt.closes());
    assert_eq!(
        count_receipt.value,
        AggregateOperationCounterValue::Count(usize::try_from(ordinary_count).unwrap())
    );

    let span_sum = aggregate_builder(r"(?:a+b|a)")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_span_sum()
        .unwrap();
    let ordinary_span_sum = span_sum
        .span_sum_value(haystack, AggregateRunLimits::default())
        .unwrap();
    let counter_span_sum = span_sum
        .span_sum_value_with_counters(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counter_span_sum.value(), ordinary_span_sum);
    let span_sum_receipt = counter_span_sum
        .continuation_receipt()
        .expect("forced continuation SpanSum receipt");
    assert!(span_sum_receipt.closes());
    assert_eq!(
        span_sum_receipt.value,
        AggregateOperationCounterValue::SpanSum(usize::try_from(ordinary_span_sum).unwrap())
    );

    let direct = aggregate_builder("aba")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .build_count()
        .unwrap();
    let ordinary_direct = direct
        .count_value(b"ababaaba", AggregateRunLimits::default())
        .unwrap();
    let counter_direct = direct
        .count_value_with_counters(b"ababaaba", AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counter_direct.value(), ordinary_direct);
    assert!(counter_direct.continuation_receipt().is_none());
}

#[test]
fn continuation_value_success_uses_the_ordinary_path_and_hot_counter_receipts() {
    let pattern = r"(?:a+b|a)";
    let haystack = b"aaaab a";
    let limits = AggregateRunLimits::default();

    let count = aggregate_builder(pattern)
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    let audited_count = count.count(haystack, limits).unwrap().value();
    assert_eq!(count.count_value(haystack, limits).unwrap(), audited_count);
    let counter_count = count.count_value_with_counters(haystack, limits).unwrap();
    assert_eq!(counter_count.value(), audited_count);
    let count_receipt: &AggregateOperationHotCounterReceipt = counter_count
        .continuation_receipt()
        .expect("continuation Count hot receipt");
    assert!(count_receipt.closes());
    assert_eq!(
        count_receipt.value,
        AggregateOperationCounterValue::Count(usize::try_from(audited_count).unwrap())
    );

    let span_sum = aggregate_builder(pattern)
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_span_sum()
        .unwrap();
    let audited_span_sum = span_sum.span_sum(haystack, limits).unwrap().value();
    assert_eq!(
        span_sum.span_sum_value(haystack, limits).unwrap(),
        audited_span_sum
    );
    let counter_span_sum = span_sum
        .span_sum_value_with_counters(haystack, limits)
        .unwrap();
    assert_eq!(counter_span_sum.value(), audited_span_sum);
    let span_sum_receipt: &AggregateOperationHotCounterReceipt = counter_span_sum
        .continuation_receipt()
        .expect("continuation SpanSum hot receipt");
    assert!(span_sum_receipt.closes());
    assert_eq!(
        span_sum_receipt.value,
        AggregateOperationCounterValue::SpanSum(usize::try_from(audited_span_sum).unwrap())
    );
}

#[test]
fn continuation_value_failure_replays_and_preserves_typed_receipts() {
    let pattern = r"(?:a+b|a)";
    let haystack = b"aaaab a";

    let count = aggregate_builder(pattern)
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    let mut count_limits = AggregateRunLimits::default();
    count_limits.continuation.max_output_matches = 0;
    let count_error = count.count_value(haystack, count_limits).unwrap_err();
    assert!(count_error.has_closed_continuation_attempt());
    let AggregateExecutionSource::Continuation(count_source) = &count_error.source else {
        panic!("continuation Count failure lost its typed source");
    };
    let count_receipt = count_error
        .continuation_receipt()
        .expect("continuation Count failure receipt");
    assert!(count_receipt.authenticates_source(count_source));
    assert_eq!(
        count_receipt.identity.operation,
        AggregateOperationAttemptKind::Count
    );
    let counter_count_error = count
        .count_value_with_counters(haystack, count_limits)
        .unwrap_err();
    assert_eq!(counter_count_error.source, count_error.source);
    assert!(counter_count_error.has_closed_continuation_attempt());

    let span_sum = aggregate_builder(pattern)
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_span_sum()
        .unwrap();
    let mut span_sum_limits = AggregateRunLimits::default();
    span_sum_limits.continuation.max_span_sum = 0;
    let span_sum_error = span_sum
        .span_sum_value(haystack, span_sum_limits)
        .unwrap_err();
    assert!(span_sum_error.has_closed_continuation_attempt());
    let AggregateExecutionSource::Continuation(span_sum_source) = &span_sum_error.source else {
        panic!("continuation SpanSum failure lost its typed source");
    };
    let span_sum_receipt = span_sum_error
        .continuation_receipt()
        .expect("continuation SpanSum failure receipt");
    assert!(span_sum_receipt.authenticates_source(span_sum_source));
    assert_eq!(
        span_sum_receipt.identity.operation,
        AggregateOperationAttemptKind::SpanSum
    );
    let counter_span_sum_error = span_sum
        .span_sum_value_with_counters(haystack, span_sum_limits)
        .unwrap_err();
    assert_eq!(counter_span_sum_error.source, span_sum_error.source);
    assert!(counter_span_sum_error.has_closed_continuation_attempt());
}

#[test]
fn counter_value_facade_preserves_exact_output_gate_and_one_below_refusal() {
    let haystack = b"aaaabaaaa";
    let count = aggregate_builder(r"(?:a+b|a)")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
        .build_count()
        .unwrap();
    let audited = count
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    let mut exact = AggregateRunLimits::default();
    exact.continuation.max_output_matches = usize::try_from(audited.value()).unwrap();
    let exact_result = count.count_value_with_counters(haystack, exact).unwrap();
    assert_eq!(exact_result.value(), audited.value());
    assert!(
        exact_result
            .continuation_receipt()
            .expect("exact continuation receipt")
            .closes()
    );

    let mut one_below = exact;
    one_below.continuation.max_output_matches -= 1;
    let refusal = count
        .count_value_with_counters(haystack, one_below)
        .unwrap_err();
    assert!(matches!(
        refusal.source,
        AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::OutputMatches,
            ..
        })
    ));
}

fn exact_build_error(limits: &AggregateBuildLimits) -> LiteralAggregateBuildError {
    match aggregate_builder("needle")
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceExactLiteral)
        .limits(*limits)
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
        exact_build_error(&one_below),
        LiteralAggregateBuildError::NeedleLimit { .. }
    ));
    one_below = limits;
    one_below.exact_literal.max_build_work -= 1;
    assert!(matches!(
        exact_build_error(&one_below),
        LiteralAggregateBuildError::WorkLimit { .. }
    ));
    one_below = limits;
    one_below.exact_literal.max_scratch_bytes -= 1;
    assert!(matches!(
        exact_build_error(&one_below),
        LiteralAggregateBuildError::ScratchLimit { .. }
    ));
    one_below = limits;
    one_below.exact_literal.max_persistent_bytes -= 1;
    assert!(matches!(
        exact_build_error(&one_below),
        LiteralAggregateBuildError::PersistentLimit { .. }
    ));
    one_below = limits;
    one_below.exact_literal.max_peak_bytes -= 1;
    assert!(matches!(
        exact_build_error(&one_below),
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
    limits: &AggregateRunLimits,
) -> LiteralAggregateReduceError {
    let error = regex.count(b"needleneedleXneedle", *limits).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    let receipt = error
        .direct_receipt()
        .expect("exact refusal must retain its direct terminal receipt");
    assert!(receipt.authenticates_source(&error.source));
    assert_eq!(receipt.run_limits(), *limits);
    assert_eq!(receipt.invocation.haystack_len, 19);
    assert_eq!(receipt.invocation.range, 0..19);
    let nested = error
        .exact_literal_receipt()
        .expect("exact refusal nested kernel receipt");
    assert_eq!(
        nested.identity,
        LiteralAggregateOperationIdentity::for_operation(LiteralAggregateOperation::Count)
    );
    assert_eq!(nested.invocation.haystack_bytes, 19);
    assert_eq!(nested.invocation.limits, limits.exact_literal);
    assert!(nested.invocation.plan_origin.is_bound());
    assert!(nested.prospective.is_some());
    assert_eq!(nested.actual, LiteralAggregateActualCounters::default());
    assert_eq!(nested.actual_allocations, 0);
    assert!(nested.retains_bounded_actual());
    assert!(
        error
            .identity
            .as_cache_identity()
            .is_some_and(|identity| identity.plan == AggregatePlanKind::ExactLiteral)
    );
    match error.source {
        AggregateExecutionSource::ExactLiteral(source) => source,
        source => panic!("selected exact plan attempted another engine: {source:?}"),
    }
}

fn exact_reduce_value_error(
    regex: &fre::AggregateCountRegex,
    limits: &AggregateRunLimits,
) -> LiteralAggregateReduceError {
    let error = regex
        .count_value(b"needleneedleXneedle", *limits)
        .unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(
        error
            .direct_receipt()
            .expect("value refusal must retain its direct terminal receipt")
            .authenticates_source(&error.source)
    );
    let nested = error
        .exact_literal_receipt()
        .expect("value refusal nested kernel receipt");
    assert_eq!(nested.invocation.limits, limits.exact_literal);
    assert_eq!(nested.actual, LiteralAggregateActualCounters::default());
    assert_eq!(nested.actual_allocations, 0);
    assert!(nested.retains_bounded_actual());
    assert!(
        error
            .identity
            .as_cache_identity()
            .is_some_and(|identity| identity.plan == AggregatePlanKind::ExactLiteral)
    );
    match error.source {
        AggregateExecutionSource::ExactLiteral(source) => source,
        source => panic!("selected exact plan attempted another engine: {source:?}"),
    }
}

#[test]
fn direct_owner_is_exact_construction_provenance_on_success_and_terminal_failure() {
    let regex = aggregate_builder("needle")
        .unicode(false)
        .build_count()
        .unwrap();
    let first = regex
        .count(b"needleneedleXneedle", AggregateRunLimits::default())
        .unwrap();
    let steady = regex
        .count(b"needleneedleXneedle", AggregateRunLimits::default())
        .unwrap();
    assert!(first.report().has_closed_direct_attempt());
    assert!(steady.report().has_closed_direct_attempt());
    let first_owner = first
        .report()
        .direct_owner()
        .expect("direct success must retain its construction owner");
    let steady_owner = steady
        .report()
        .direct_owner()
        .expect("steady direct success must retain its construction owner");
    assert_eq!(first_owner, steady_owner);
    assert!(first_owner.authenticates(first.report().identity()));
    assert!(steady_owner.authenticates(steady.report().identity()));
    assert_eq!(
        first_owner.identity().route,
        fre::AggregateDirectRoute::ExactLiteral
    );
    assert_eq!(
        first_owner.identity().declared_fallback,
        fre::AggregateDirectDeclaredFallback::None
    );
    assert_eq!(
        first_owner.identity().algorithm_version,
        fre::AGGREGATE_DIRECT_OWNER_ALGORITHM_VERSION
    );
    assert_eq!(
        first_owner.identity().accounting_version,
        fre::AGGREGATE_DIRECT_OWNER_ACCOUNTING_VERSION
    );

    let separately_built = aggregate_builder("needle")
        .unicode(false)
        .build_count()
        .unwrap()
        .count(b"needleneedleXneedle", AggregateRunLimits::default())
        .unwrap();
    assert!(!first_owner.authenticates(separately_built.report().identity()));
    assert_ne!(
        first_owner,
        separately_built
            .report()
            .direct_owner()
            .expect("separate direct construction owner")
    );

    let mut refused = AggregateRunLimits::default();
    refused.exact_literal.max_linear_terms = 0;
    let error = regex.count(b"needleneedleXneedle", refused).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    let receipt = error
        .direct_receipt()
        .expect("direct terminal receipt must be present");
    assert_eq!(receipt.owner(), &first_owner);
    let terminal_cache = error
        .identity
        .as_cache_identity()
        .expect("direct terminal cache");
    assert!(!first_owner.authenticates(terminal_cache));
    assert!(receipt.owner().authenticates(terminal_cache));
    assert!(receipt.authenticates_source(&error.source));
    assert_eq!(receipt.run_limits(), refused);
    assert_eq!(
        receipt.terminal,
        fre::AggregateDirectAttemptTerminal::Failure
    );
}

#[test]
fn direct_terminal_public_source_and_identity_splices_fail_closed() {
    let exact = aggregate_builder("needle")
        .unicode(false)
        .build_count()
        .unwrap();
    let haystack = b"needleneedleXneedle";

    let mut linear_limits = AggregateRunLimits::default();
    linear_limits.exact_literal.max_linear_terms = 0;
    let exact_error = exact.count(haystack, linear_limits).unwrap_err();
    assert!(exact_error.has_closed_direct_attempt());

    let mut event_limits = AggregateRunLimits::default();
    event_limits.exact_literal.max_match_events = 0;
    let same_route_error = exact.count(haystack, event_limits).unwrap_err();
    assert!(same_route_error.has_closed_direct_attempt());

    let fixed = aggregate_builder("Sherlock Holmes")
        .unicode(false)
        .case_insensitive(true)
        .build_count()
        .unwrap();
    let mut fixed_limits = AggregateRunLimits::default();
    fixed_limits.finite_literal.max_transitions = 0;
    let fixed_error = fixed
        .count(b"xxSherLock Holmesyy", fixed_limits)
        .unwrap_err();
    assert!(fixed_error.has_closed_direct_attempt());

    let mut changed = exact_error.clone();
    changed.source = same_route_error.source.clone();
    assert!(!changed.has_closed_direct_attempt());
    changed.source = exact_error.source.clone();
    assert!(changed.has_closed_direct_attempt());

    changed.source = fixed_error.source.clone();
    assert!(!changed.has_closed_direct_attempt());
    changed.source = exact_error.source.clone();
    assert!(changed.has_closed_direct_attempt());

    changed.identity = fixed_error.identity.clone();
    assert!(!changed.has_closed_direct_attempt());
    changed.identity = exact_error.identity.clone();
    assert!(changed.has_closed_direct_attempt());

    changed.identity = fixed_error.identity.clone();
    changed.source = fixed_error.source.clone();
    assert!(changed.has_closed_direct_attempt());
    changed.identity = exact_error.identity.clone();
    changed.source = exact_error.source.clone();
    assert!(changed.has_closed_direct_attempt());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the exact and one-below matrix covers every independently enforced resource"
)]
fn every_nonzero_exact_literal_reduce_quota_is_checked_at_and_one_below() {
    let count = aggregate_builder("needle")
        .unicode(false)
        .build_count()
        .unwrap();
    let haystack = b"needleneedleXneedle";
    let baseline = count
        .count(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::ExactLiteral(accounting) = baseline.report().details() else {
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
        exact_reduce_error(&count, &one_below),
        LiteralAggregateReduceError::LinearTermsLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, &one_below),
        LiteralAggregateReduceError::LinearTermsLimit { .. }
    ));
    one_below = exact;
    one_below.exact_literal.max_match_events -= 1;
    assert!(matches!(
        exact_reduce_error(&count, &one_below),
        LiteralAggregateReduceError::MatchEventsLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, &one_below),
        LiteralAggregateReduceError::MatchEventsLimit { .. }
    ));
    one_below = exact;
    one_below.exact_literal.max_count -= 1;
    assert!(matches!(
        exact_reduce_error(&count, &one_below),
        LiteralAggregateReduceError::CountLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, &one_below),
        LiteralAggregateReduceError::CountLimit { .. }
    ));
    one_below = exact;
    one_below.exact_literal.max_reducer_steps -= 1;
    assert!(matches!(
        exact_reduce_error(&count, &one_below),
        LiteralAggregateReduceError::ReducerStepsLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, &one_below),
        LiteralAggregateReduceError::ReducerStepsLimit { .. }
    ));
    one_below = exact;
    one_below.exact_literal.max_peak_bytes -= 1;
    assert!(matches!(
        exact_reduce_error(&count, &one_below),
        LiteralAggregateReduceError::PeakLimit { .. }
    ));
    assert!(matches!(
        exact_reduce_value_error(&count, &one_below),
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
    assert_eq!(
        value_error.exact_literal_receipt(),
        error.exact_literal_receipt()
    );
    let nested = error
        .exact_literal_receipt()
        .expect("span-sum refusal nested kernel receipt");
    assert_eq!(
        nested.identity,
        LiteralAggregateOperationIdentity::for_operation(LiteralAggregateOperation::SpanSum)
    );
    assert_eq!(nested.actual, LiteralAggregateActualCounters::default());
    assert!(nested.retains_bounded_actual());
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
#[allow(
    clippy::too_many_lines,
    reason = "the route witness keeps exact scalar and dispatched SVE accounting beside the complete compatibility table"
)]
fn rebar_row_imported_leipzig_huck_saw_prefix_class_complete_spans_and_limits() {
    // rebar-row:imported/leipzig/huck-saw@rust/regex
    let huck_saw = aggregate_builder(r"Huck[a-zA-Z]+|Saw[a-zA-Z]+")
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        AggregatePlanKind::PrefixClassAlternation,
        huck_saw.build_report().plan
    );
    assert!(matches!(
        huck_saw.build_report().plan_identity,
        AggregatePlanIdentity::PrefixClassAlternation(identity)
            if identity.kernel.alternatives == 2
                && !identity.kernel.unicode
                && identity.kernel.non_overlapping
    ));
    assert_eq!(
        2,
        huck_saw
            .count_value(b"Huckle Sawx Huck!", AggregateRunLimits::default())
            .unwrap()
    );

    // Independent exact-limit witness: N=9 and
    // Q=(2+2 prefix bytes)+(1+1 class ranges)=6, so
    // W=16*N+8*Q+64=16*9+8*6+64=256. Complete spans: 0..4, 6..9.
    // The distinct fixed-16 SVE owner reserves its worst-case 16*N physical
    // classification recovery overhead as part of its own receipt.
    let witness = aggregate_builder(r"ab[a-z]+|xy[0-9]+")
        .unicode(false)
        .build_count()
        .unwrap();
    let work = if matches!(
        witness.build_report().plan_identity,
        AggregatePlanIdentity::PrefixClassAlternation(identity)
            if identity.kernel.plan_id == DISPATCHED_PREFIX_CLASS_ALTERNATION_PLAN_ID
    ) {
        256 + 9 * 16
    } else {
        256
    };
    let mut exact = AggregateRunLimits::default();
    exact.prefix_class_alternation.max_work = work;
    assert_eq!(2, witness.count_value(b"abcz--xy7", exact).unwrap());
    exact.prefix_class_alternation.max_work = work - 1;
    let terminal = witness.count_value(b"abcz--xy7", exact).unwrap_err();
    assert!(terminal.has_closed_direct_attempt());
    assert!(matches!(
        terminal.source,
        AggregateExecutionSource::PrefixClassAlternation(
            PrefixClassAlternationReduceError::WorkLimit {
                needed,
                limit,
            }
        ) if needed == work && limit == work - 1
    ));

    // Complete upstream span equality covers boundary windows, captures,
    // assertions, case folding, invalid UTF-8, complement/intersection
    // classes, and an empty-language class. Ineligible cases retain the prior
    // route instead of changing an old success into a specialized refusal.
    let cases: [(&str, &[u8], bool, bool); 7] = [
        (r"ab[a-z]+|xy[0-9]+", b"abz--xy7--ab--xy00", false, true),
        (
            r"(?P<left>ab[a-z]+)|(?P<right>xy[0-9]+)",
            b"_abzz_xy7_",
            false,
            true,
        ),
        (
            r"\bab[a-z]+\b|\bxy[0-9]+\b",
            b"abz!_abq xy7-xy8_",
            false,
            false,
        ),
        (r"ab[a-z]+|xy[0-9]+", b"ABZ--XY7--abq", true, false),
        (r"ab[a-z]+|xy[0-9]+", b"\xFFabq\x80xy0", false, true),
        (
            r"ab[a-z&&[^q]]+|xy[^A-Za-z]+",
            b"abzzq--xy12\xFF--abr",
            false,
            true,
        ),
        (r"ab[a&&[^a]]+|xy[0-9]+", b"abaaa--xy7", false, false),
    ];
    for (pattern, haystack, case_insensitive, specialized) in cases {
        let expected = upstream(pattern, haystack, case_insensitive);
        let spans = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(case_insensitive)
            .build_spans()
            .unwrap()
            .spans(haystack, AggregateRunLimits::default())
            .unwrap();
        let complete: Vec<_> = spans
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect();
        assert_eq!(expected, complete, "complete spans for {pattern:?}");

        let count = aggregate_builder(pattern)
            .unicode(false)
            .case_insensitive(case_insensitive)
            .build_count()
            .unwrap();
        assert_eq!(
            specialized,
            count.build_report().plan == AggregatePlanKind::PrefixClassAlternation,
            "selection for {pattern:?}"
        );
        assert_eq!(
            u64::try_from(expected.len()).unwrap(),
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            "count for {pattern:?}"
        );
    }
}

#[test]
fn rebar_row_name_alt4_prefix_class_span_sum_and_limits() {
    // rebar-row:imported/sherlock/name-alt4@rust/regex
    let pattern = r"Sher[a-z]+|Hol[a-z]+";
    let haystack = b"Sherlock Holmes! Holdup--Sher";
    let expected = upstream(pattern, haystack, false);
    let expected_span_sum = expected.iter().fold(0_u64, |sum, &(start, end)| {
        sum.checked_add(u64::try_from(end - start).unwrap())
            .unwrap()
    });
    let span_sum = aggregate_builder(pattern)
        .unicode(false)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        AggregatePlanKind::PrefixClassAlternation,
        span_sum.build_report().plan
    );
    assert!(matches!(
        span_sum.build_report().plan_identity,
        AggregatePlanIdentity::PrefixClassAlternation(identity)
            if identity.kernel.operation_id
                == PREFIX_CLASS_ALTERNATION_SPAN_SUM_OPERATION_ID
    ));
    assert_eq!(
        expected_span_sum,
        span_sum
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap()
    );
    let rich = span_sum
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(expected_span_sum, rich.value());
    assert!(matches!(
        rich.report().details(),
        AggregateExecutionDetails::PrefixClassAlternation(accounting)
            if accounting.identity.operation_id
                == PREFIX_CLASS_ALTERNATION_SPAN_SUM_OPERATION_ID
                && accounting.actual.span_sum == expected_span_sum
    ));

    let upper = span_sum
        .retained_full_window_upper_bounds(haystack.len())
        .unwrap()
        .expect("prefix/class span-sum publishes retained bounds");
    let fre::AggregateRetainedFullWindowUpperBounds::PrefixClassAlternation(upper) = upper else {
        panic!("prefix/class span-sum retained another bounds family")
    };
    assert_eq!(u64::try_from(haystack.len()).unwrap(), upper.span_sum);
    let mut one_below = AggregateRunLimits::default();
    one_below.prefix_class_alternation.max_span_sum = upper.span_sum - 1;
    assert!(matches!(
        span_sum.span_sum_value(haystack, one_below).unwrap_err().source,
        AggregateExecutionSource::PrefixClassAlternation(
            PrefixClassAlternationReduceError::SpanSumLimit { needed, limit }
        ) if needed == upper.span_sum && limit == upper.span_sum - 1
    ));
}
