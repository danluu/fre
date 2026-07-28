use std::sync::Arc;

use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregateOperation, AggregatePlanIdentity,
    AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits, AggregateStrategy,
    FixedPredicateWord64MatchSelection, FixedPredicateWord64MatchSemantics,
    FixedPredicateWord64Operation, FixedPredicateWord64ReduceError, FixedPredicateWord64Reducer,
    RustProfile,
};

const PATTERN: &str = "Sherlock Holmes";
const HAYSTACK: &[u8] =
    b"\xFFSHERLOCK HOLMES--sherlock holmes--SherLock Holmes--sherlock holme\x80";

fn builder() -> AggregateBuilder {
    AggregateBuilder::new(PATTERN)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(true)
}

fn upstream_spans(pattern: &str, haystack: &[u8], case_insensitive: bool) -> Vec<(usize, usize)> {
    regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .case_insensitive(case_insensitive)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

#[test]
fn dense_finite_cartesian_words_select_the_authenticated_anchor_route() {
    let cases: [(&str, bool, &[u8]); 2] = [
        (
            "[a-z]shing",
            false,
            b"ashing xshing zshing shing \xFFzshing",
        ),
        ("Twain", true, b"TWAIN twain tWaIn Twainx xTwain \xFFTWaIN"),
    ];
    for (pattern, case_insensitive, haystack) in cases {
        let expected = upstream_spans(pattern, haystack, case_insensitive);
        let build = || {
            AggregateBuilder::new(pattern)
                .profile(RustProfile::rebar_1_12_4())
                .unicode(false)
                .case_insensitive(case_insensitive)
        };
        let counted = build().build_count().unwrap();
        assert_eq!(
            counted.build_report().plan,
            AggregatePlanKind::FixedPredicateWord64
        );
        let AggregatePlanIdentity::FixedPredicateWord64(identity) =
            counted.build_report().plan_identity
        else {
            panic!("Cartesian fixed word selected another identity");
        };
        assert!(matches!(
            identity.reducer,
            FixedPredicateWord64Reducer::OneByteAnchor | FixedPredicateWord64Reducer::TwoByteAnchor
        ));
        assert_eq!(
            counted
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            u64::try_from(expected.len()).unwrap()
        );

        let span_sum = build().build_span_sum().unwrap();
        assert_eq!(
            span_sum.build_report().plan,
            AggregatePlanKind::FixedPredicateWord64
        );
        assert_eq!(
            span_sum
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected
                .iter()
                .map(|(start, end)| u64::try_from(end - start).unwrap())
                .sum::<u64>()
        );
    }
}

#[test]
fn one_byte_and_full_domain_classes_select_the_allocation_free_route() {
    let cases: [(&str, &[u8]); 2] = [("[ac]", b"abcac\xFF"), ("(?s:.)", b"\0\n\r\x80\xFF")];
    for (pattern, haystack) in cases {
        let expected = upstream_spans(pattern, haystack, false);
        let build = || {
            AggregateBuilder::new(pattern)
                .profile(RustProfile::rebar_1_12_4())
                .unicode(false)
        };
        let counted = build().build_count().unwrap();
        assert_eq!(
            counted.build_report().plan,
            AggregatePlanKind::FixedPredicateWord64,
            "pattern={pattern:?}"
        );
        let AggregateBuildAccounting::FixedPredicateWord64(accounting) =
            counted.build_report().build
        else {
            panic!("one-byte class selected another accounting family");
        };
        assert_eq!(accounting.positions, 1);
        assert_eq!(accounting.allocations, 0);
        assert_eq!(
            counted
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            u64::try_from(expected.len()).unwrap()
        );

        let span_sum = build().build_span_sum().unwrap();
        assert_eq!(
            span_sum.build_report().plan,
            AggregatePlanKind::FixedPredicateWord64
        );
        assert_eq!(
            span_sum
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected
                .iter()
                .map(|(start, end)| u64::try_from(end - start).unwrap())
                .sum()
        );
    }
}

#[test]
fn exact_repeated_ascii_classes_select_one_retained_predicate_word() {
    let pattern = r"\w{5}\s\w{6}\s\w{7}";
    let haystack =
        b"alpha bravo1 charlie; short words miss; alpha\tbravo1\ncharlie; alpha bravo1 charlie";
    let expected = upstream_spans(pattern, haystack, false);
    assert_eq!(expected.len(), 3);
    let build = || {
        AggregateBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
    };

    let count = build().build_count().unwrap();
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::FixedPredicateWord64,
        "{:#?}",
        count.build_report()
    );
    let AggregatePlanIdentity::FixedPredicateWord64(identity) = count.build_report().plan_identity
    else {
        panic!("exact repeated classes selected another identity");
    };
    assert_eq!(identity.width, 20);
    assert_eq!(identity.reducer, FixedPredicateWord64Reducer::ShiftAnd);
    assert_eq!(
        count
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        u64::try_from(expected.len()).unwrap()
    );

    let span_sum = build().build_span_sum().unwrap();
    assert_eq!(
        span_sum.build_report().plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    assert_eq!(
        span_sum
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        expected
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum::<u64>()
    );
}

#[test]
fn non_cartesian_large_finite_language_remains_on_the_dense_route() {
    let pattern = "(?:a|bb|ccc|dddd|eeeee|ffffff|ggggggg|hhhhhhhh|iiiiiiiii|jjjjjjjjjj|kkkkkkkkkkk|llllllllllll|mmmmmmmmmmmmm|nnnnnnnnnnnnnn|ooooooooooooooo|pppppppppppppppp|qqqqqqqqqqqqqqqqq)";
    let haystack = b"a bb ccc dddd eeeee ffffff ggggggg hhhhhhhh iiiiiiiii qqqqqqqqqqqqqqqqq";
    let expected = upstream_spans(pattern, haystack, false);
    let plan = AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .build_count()
        .unwrap();
    assert_eq!(
        plan.build_report().plan,
        AggregatePlanKind::FiniteLiteralDfa
    );
    assert_eq!(
        plan.count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        u64::try_from(expected.len()).unwrap()
    );
}

#[test]
fn count_identity_and_accounting_are_closed() {
    let expected = upstream_spans(PATTERN, HAYSTACK, true);
    assert_eq!(expected.len(), 3);
    let expected_sum = expected
        .iter()
        .map(|(start, end)| u64::try_from(end - start).unwrap())
        .sum::<u64>();
    assert_eq!(expected_sum, 45);

    let count = builder().build_count().unwrap();
    let report = count.build_report();
    assert_eq!(report.plan, AggregatePlanKind::FixedPredicateWord64);
    assert_eq!(report.continuation_strategy, None);
    assert_eq!(report.captures_erased, 0);
    let AggregatePlanIdentity::FixedPredicateWord64(identity) = report.plan_identity else {
        panic!("fixed predicate count selected another identity");
    };
    assert_eq!(identity.operation, FixedPredicateWord64Operation::Count);
    assert_eq!(
        identity.semantics,
        FixedPredicateWord64MatchSemantics::FixedBytePredicates
    );
    assert_eq!(
        identity.selection,
        FixedPredicateWord64MatchSelection::LeftmostFirstNonOverlapping
    );
    assert_eq!(identity.width, PATTERN.len());
    let AggregateBuildAccounting::FixedPredicateWord64(build) = report.build else {
        panic!("fixed predicate count retained another build certificate");
    };
    assert_eq!(build.positions, 15);
    assert_eq!(build.source_ranges, 29);
    assert_eq!(build.position_visits, build.positions);
    assert_eq!(build.range_inspections, build.source_ranges);
    assert!(build.work_charged <= build.work_upper_bound);
    assert_eq!(build.allocations, 0);
    assert_eq!(build.reserves, 0);
    assert_eq!(build.temporary_copies, 0);
    assert_eq!(build.scratch_bytes, 0);
    assert_eq!(build.persistent_bytes, report.retained_capacity_bytes);
    assert_eq!(build.peak_bytes, build.persistent_bytes);

    let counted = count
        .count(HAYSTACK, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counted.value(), 3);
    assert!(counted.report().has_closed_direct_attempt());
    let owner = counted
        .report()
        .direct_owner()
        .expect("fixed predicate success must retain its direct owner");
    assert_eq!(
        owner.identity().route,
        fre::AggregateDirectRoute::FixedPredicateWord64
    );
    assert!(owner.authenticates(counted.report().identity()));
    let AggregateExecutionDetails::FixedPredicateWord64(accounting) = counted.report().details()
    else {
        panic!("fixed predicate count executed another plan");
    };
    assert_eq!(accounting.identity, identity);
    assert_eq!(accounting.actual.input_bytes, HAYSTACK.len());
    assert!(accounting.actual.transitions <= accounting.upper_bounds.transitions);
    assert!(accounting.actual.predicate_checks <= accounting.upper_bounds.predicate_checks);
    assert_eq!(accounting.actual.match_events, 3);
    assert_eq!(accounting.actual.count, 3);
    assert_eq!(accounting.actual.matched_bytes, expected_sum);
    assert!(accounting.actual.work_charged <= accounting.upper_bounds.work);
    assert_eq!(accounting.actual.allocations, 0);
    assert_eq!(accounting.actual.scratch_bytes, 0);
}

#[test]
fn success_owner_rejects_every_mutable_cache_discriminator_and_splice() {
    let regex = builder().build_count().unwrap();
    let counted = regex
        .count(HAYSTACK, AggregateRunLimits::default())
        .unwrap();
    let owner = counted.report().direct_owner().unwrap();
    let original = counted.report().cache_identity();
    assert!(owner.authenticates(&original));

    macro_rules! reject {
        ($mutation:expr) => {{
            let mut changed = original.clone();
            $mutation(&mut changed);
            assert!(!owner.authenticates(&changed));
            assert!(owner.authenticates(&original));
        }};
    }

    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.schema_version = cache.schema_version.wrapping_add(1);
    });
    let separate = builder()
        .build_count()
        .unwrap()
        .count(HAYSTACK, AggregateRunLimits::default())
        .unwrap();
    assert!(!Arc::ptr_eq(
        &original.syntax_key,
        &separate.report().identity().syntax_key
    ));
    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.syntax_key = Arc::clone(&separate.report().identity().syntax_key);
    });
    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.operation = AggregateOperation::SpanSum;
    });
    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.selection = AggregatePlanSelection::ForceContinuation;
    });
    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.plan = AggregatePlanKind::ExactLiteral;
    });
    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.continuation_strategy = Some(AggregateStrategy::FullTable);
    });
    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.build_limits.max_literal_planner_work =
            cache.build_limits.max_literal_planner_work.wrapping_add(1);
    });
    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.execution_limits.finite_literal.max_transitions = cache
            .execution_limits
            .finite_literal
            .max_transitions
            .wrapping_sub(1);
    });
    reject!(|cache: &mut fre::AggregateCacheIdentity| {
        cache.execution_limits.exact_literal.max_linear_terms = cache
            .execution_limits
            .exact_literal
            .max_linear_terms
            .wrapping_sub(1);
    });

    for mutate in [
        |identity: &mut fre::FixedPredicateWord64OperationIdentity| {
            identity.plan_id = "mutated-plan";
        },
        |identity: &mut fre::FixedPredicateWord64OperationIdentity| {
            identity.operation_id = "mutated-operation";
        },
        |identity: &mut fre::FixedPredicateWord64OperationIdentity| {
            identity.operation = FixedPredicateWord64Operation::SpanSum;
        },
        |identity: &mut fre::FixedPredicateWord64OperationIdentity| {
            identity.width = identity.width.wrapping_add(1);
        },
    ] {
        reject!(|cache: &mut fre::AggregateCacheIdentity| {
            let AggregatePlanIdentity::FixedPredicateWord64(identity) = &mut cache.plan_identity
            else {
                panic!("fixed-predicate cache identity");
            };
            mutate(identity);
        });
    }

    let span_cache = builder()
        .build_span_sum()
        .unwrap()
        .span_sum(HAYSTACK, AggregateRunLimits::default())
        .unwrap()
        .report()
        .cache_identity();
    assert!(!owner.authenticates(&span_cache));
    assert_ne!(
        owner,
        separate
            .report()
            .direct_owner()
            .expect("separate construction owner")
    );
}

#[test]
fn span_sum_compile_captures_and_exclusions_are_closed() {
    let sum = builder().build_span_sum().unwrap();
    assert!(matches!(
        sum.build_report().plan_identity,
        AggregatePlanIdentity::FixedPredicateWord64(identity)
            if identity.operation == FixedPredicateWord64Operation::SpanSum
    ));
    let summed = sum
        .span_sum(HAYSTACK, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(summed.value(), 45);
    assert!(summed.report().has_closed_direct_attempt());
    assert_eq!(
        summed
            .report()
            .direct_owner()
            .expect("fixed predicate span-sum owner")
            .identity()
            .route,
        fre::AggregateDirectRoute::FixedPredicateWord64
    );
    let compiled = builder().build_compile().unwrap();
    assert_eq!(
        compiled.build_report().plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    let verified = compiled
        .verify_count(HAYSTACK, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(verified.value(), 3);
    assert!(verified.report().has_closed_direct_attempt());
    let compile_owner = verified.report().direct_owner().unwrap();
    assert_eq!(
        compile_owner.identity().operation,
        AggregateOperation::Compile
    );
    assert!(compile_owner.authenticates(verified.report().identity()));
    assert!(matches!(
        verified.report().identity().plan_identity,
        AggregatePlanIdentity::FixedPredicateWord64(identity)
            if identity.operation == FixedPredicateWord64Operation::Count
    ));

    let captured = AggregateBuilder::new("((Sherlock Holmes))")
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(true)
        .build_count()
        .unwrap();
    assert_eq!(
        captured.build_report().plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    assert_eq!(captured.build_report().captures_erased, 2);
    assert_eq!(captured.build_report().capture_erasure_work, 4);
    assert_eq!(
        captured
            .count_value(HAYSTACK, AggregateRunLimits::default())
            .unwrap(),
        3
    );

    assert_eq!(
        AggregateBuilder::new("Sherlock")
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .case_insensitive(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    assert_ne!(
        AggregateBuilder::new(PATTERN)
            .profile(RustProfile::rebar_1_12_4())
            .case_insensitive(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    assert_eq!(
        builder().build_spans().unwrap().build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        builder()
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
}

#[test]
fn planner_work_is_cumulative_for_typed_and_dense_refusals() {
    let baseline = builder().build_count().unwrap();
    let planner_work = baseline.build_report().finite_planner_work;
    assert!(planner_work > 0);
    assert_eq!(
        builder()
            .limits(AggregateBuildLimits {
                max_finite_planner_work: planner_work,
                ..AggregateBuildLimits::default()
            })
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    assert!(matches!(
        builder()
            .limits(AggregateBuildLimits {
                max_finite_planner_work: planner_work - 1,
                ..AggregateBuildLimits::default()
            })
            .build_count(),
        Err(AggregateBuildError::FinitePlannerWorkLimit { needed, limit, .. })
            if needed == planner_work && limit + 1 == planner_work
    ));

    let mut finite = AggregateBuildLimits::default().finite_literal;
    finite.max_patterns = 1_000_000;
    finite.max_pattern_bytes = 536_870_912;
    finite.max_identity_bytes = 33_554_432;
    finite.max_trie_states = 4_194_304;
    finite.max_dfa_cells = 4_194_304;
    finite.max_build_work = 67_108_864;
    finite.max_scratch_bytes = 33_554_432;
    finite.max_persistent_bytes = 67_108_864;
    finite.max_peak_bytes = 100_663_296;
    let dense_refusal_limits = AggregateBuildLimits {
        finite_literal: finite,
        ..AggregateBuildLimits::default()
    };
    let retried = builder()
        .limits(dense_refusal_limits)
        .build_count()
        .unwrap();
    assert_eq!(
        retried.build_report().plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    let retry_work = retried.build_report().finite_planner_work;
    assert!(retry_work > planner_work);
    assert!(matches!(
        builder()
            .limits(AggregateBuildLimits {
                max_finite_planner_work: retry_work - 1,
                ..dense_refusal_limits
            })
            .build_count(),
        Err(AggregateBuildError::FinitePlannerWorkLimit { needed, limit, .. })
            if needed == retry_work && limit + 1 == retry_work
    ));

    let captured = AggregateBuilder::new("((Sherlock Holmes))")
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(true)
        .limits(dense_refusal_limits)
        .build_count()
        .unwrap();
    assert_eq!(
        captured.build_report().plan,
        AggregatePlanKind::FixedPredicateWord64
    );
    assert_eq!(captured.build_report().capture_erasure_work, 4);
}

#[test]
fn shared_build_envelope_is_exact_and_one_below_falls_through() {
    let baseline = builder().build_count().unwrap();
    let AggregateBuildAccounting::FixedPredicateWord64(build) = baseline.build_report().build
    else {
        panic!("baseline selected another build family");
    };
    let mut finite = AggregateBuildLimits::default().finite_literal;
    finite.max_patterns = build.positions;
    finite.max_pattern_bytes = build.source_ranges;
    finite.max_identity_bytes = build.source_ranges.checked_mul(2).unwrap();
    finite.max_trie_states = build.positions.checked_add(1).unwrap();
    finite.max_build_work = build.work_upper_bound;
    finite.max_scratch_bytes = build.scratch_bytes;
    finite.max_persistent_bytes = build.persistent_bytes;
    finite.max_peak_bytes = build.peak_bytes;
    let exact = AggregateBuildLimits {
        finite_literal: finite,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        builder()
            .limits(exact)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::FixedPredicateWord64
    );

    let mut cases = Vec::new();
    let mut one_below = exact;
    one_below.finite_literal.max_patterns -= 1;
    cases.push(one_below);
    one_below = exact;
    one_below.finite_literal.max_pattern_bytes -= 1;
    cases.push(one_below);
    one_below = exact;
    one_below.finite_literal.max_identity_bytes -= 1;
    cases.push(one_below);
    one_below = exact;
    one_below.finite_literal.max_trie_states -= 1;
    cases.push(one_below);
    one_below = exact;
    one_below.finite_literal.max_build_work -= 1;
    cases.push(one_below);
    one_below = exact;
    one_below.finite_literal.max_persistent_bytes -= 1;
    cases.push(one_below);
    one_below = exact;
    one_below.finite_literal.max_peak_bytes -= 1;
    cases.push(one_below);
    for limits in cases {
        assert_eq!(
            builder()
                .limits(limits)
                .build_count()
                .unwrap()
                .build_report()
                .plan,
            AggregatePlanKind::ContinuationProgram
        );
    }
}

fn exact_run_limits() -> (
    fre::AggregateCountRegex,
    AggregateRunLimits,
    fre::FixedPredicateWord64UpperBounds,
) {
    let regex = builder().build_count().unwrap();
    let baseline = regex
        .count(HAYSTACK, AggregateRunLimits::default())
        .unwrap();
    assert!(baseline.report().has_closed_direct_attempt());
    let AggregateExecutionDetails::FixedPredicateWord64(accounting) = baseline.report().details()
    else {
        panic!("baseline executed another family");
    };
    let upper = accounting.upper_bounds;
    let mut finite = AggregateRunLimits::default().finite_literal;
    finite.max_transitions = upper.transitions;
    finite.max_match_events = upper.match_events;
    finite.max_count = upper.count;
    finite.max_span_sum = upper.span_sum;
    finite.max_reducer_steps = upper.reducer_steps;
    finite.max_ring_initializations = 0;
    finite.max_total_work = usize::try_from(upper.work).unwrap();
    finite.max_scratch_bytes = upper.scratch_bytes;
    finite.max_peak_bytes = upper.peak_bytes;
    (
        regex,
        AggregateRunLimits {
            finite_literal: finite,
            ..AggregateRunLimits::default()
        },
        upper,
    )
}

#[test]
fn shared_run_envelope_is_exact_and_failures_are_typed() {
    let (regex, exact, upper) = exact_run_limits();
    let counted = regex.count(HAYSTACK, exact).unwrap();
    assert_eq!(counted.value(), 3);
    assert!(counted.report().has_closed_direct_attempt());

    let mut one_below = exact;
    one_below.finite_literal.max_transitions -= 1;
    assert!(matches!(
        regex.count(HAYSTACK, one_below).unwrap_err().source,
        AggregateExecutionSource::FixedPredicateWord64(
            FixedPredicateWord64ReduceError::InputLimit { needed, limit }
        ) if needed == upper.input_bytes && limit + 1 == needed
    ));
    one_below = exact;
    one_below.finite_literal.max_match_events -= 1;
    assert!(matches!(
        regex.count_value(HAYSTACK, one_below).unwrap_err().source,
        AggregateExecutionSource::FixedPredicateWord64(
            FixedPredicateWord64ReduceError::MatchEventsLimit { needed, limit }
        ) if needed == upper.match_events && limit + 1 == needed
    ));
    one_below = exact;
    one_below.finite_literal.max_count -= 1;
    assert!(matches!(
        regex.count(HAYSTACK, one_below).unwrap_err().source,
        AggregateExecutionSource::FixedPredicateWord64(
            FixedPredicateWord64ReduceError::CountLimit { needed, limit }
        ) if needed == upper.count && limit + 1 == needed
    ));
    one_below = exact;
    one_below.finite_literal.max_reducer_steps -= 1;
    assert!(matches!(
        regex.count(HAYSTACK, one_below).unwrap_err().source,
        AggregateExecutionSource::FixedPredicateWord64(
            FixedPredicateWord64ReduceError::ReducerStepsLimit { needed, limit }
        ) if needed == upper.reducer_steps && limit + 1 == needed
    ));
    one_below = exact;
    one_below.finite_literal.max_total_work -= 1;
    assert!(matches!(
        regex.count(HAYSTACK, one_below).unwrap_err().source,
        AggregateExecutionSource::FixedPredicateWord64(
            FixedPredicateWord64ReduceError::WorkLimit { needed, limit }
        ) if needed == upper.work && limit + 1 == needed
    ));
    one_below = exact;
    one_below.finite_literal.max_peak_bytes -= 1;
    let error = regex.count(HAYSTACK, one_below).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(
        error
            .direct_receipt()
            .expect("fixed predicate terminal receipt")
            .authenticates_source(&error.source)
    );
    assert_eq!(
        error
            .direct_receipt()
            .expect("fixed predicate terminal receipt")
            .owner()
            .identity()
            .route,
        fre::AggregateDirectRoute::FixedPredicateWord64
    );
    assert!(matches!(
        error.source,
        AggregateExecutionSource::FixedPredicateWord64(
            FixedPredicateWord64ReduceError::PersistentLimit { needed, limit }
        ) if needed == upper.persistent_bytes && limit + 1 == needed
    ));

    let sum = builder().build_span_sum().unwrap();
    one_below = exact;
    one_below.finite_literal.max_span_sum -= 1;
    let error = sum.span_sum(HAYSTACK, one_below).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(
        error
            .direct_receipt()
            .expect("fixed predicate span-sum terminal receipt")
            .authenticates_source(&error.source)
    );
    assert!(matches!(
        error.source,
        AggregateExecutionSource::FixedPredicateWord64(
            FixedPredicateWord64ReduceError::SpanSumLimit { needed, limit }
        ) if needed == upper.span_sum && limit + 1 == needed
    ));
}
