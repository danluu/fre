use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregateLiteralAssertionsSemantics,
    AggregatePlanIdentity, AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits,
    LITERAL_ASSERTIONS_COUNT_OPERATION_ID, LITERAL_ASSERTIONS_SPAN_SUM_OPERATION_ID,
    LiteralAssertionsBuildLimits, LiteralAssertionsReduceError, LiteralAssertionsReduceLimits,
    LiteralAssertionsTopology, LiteralAssertionsUpperBounds, RustProfile,
};
use regex::bytes::RegexBuilder;

const PATTERN: &str = r"(?m)^Sherlock Holmes|Sherlock Holmes$";

fn builder(pattern: &str, unicode: bool) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(unicode)
        .case_insensitive(false)
}

fn oracle(pattern: &str, haystack: &[u8], unicode: bool) -> (u64, u64) {
    let spans: Vec<_> = RegexBuilder::new(pattern)
        .unicode(unicode)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| matched.start()..matched.end())
        .collect();
    let count = u64::try_from(spans.len()).unwrap();
    let span_sum = spans
        .into_iter()
        .map(|span| {
            u64::try_from(
                span.end
                    .checked_sub(span.start)
                    .expect("ordered regex span"),
            )
            .unwrap()
        })
        .sum();
    (count, span_sum)
}

#[test]
fn exact_sherlock_shape_selects_operation_owned_leaf_in_both_profiles() {
    let haystack =
        b"Sherlock Holmes and Watson\nx Sherlock Holmes\nSherlock Holmes\n\xffSherlock Holmes";
    for unicode in [false, true] {
        let expected = oracle(PATTERN, haystack, unicode);
        assert_eq!(expected, (4, 60));

        let count = builder(PATTERN, unicode).build_count().unwrap();
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::LiteralAssertions
        );
        assert_eq!(count.build_report().schema_version, 31);
        let AggregatePlanIdentity::LiteralAssertions(count_identity) =
            count.build_report().plan_identity
        else {
            panic!("Sherlock assertion count selected another identity");
        };
        assert_eq!(
            count_identity.semantics,
            if unicode {
                AggregateLiteralAssertionsSemantics::UnicodeOnByteStableLiteral
            } else {
                AggregateLiteralAssertionsSemantics::UnicodeOffByteLiteral
            }
        );
        assert_eq!(
            count_identity.kernel.topology,
            LiteralAssertionsTopology::StartLineLiteralOrLiteralEndLine
        );
        assert_eq!(
            count_identity.kernel.operation_id,
            LITERAL_ASSERTIONS_COUNT_OPERATION_ID
        );
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.0
        );

        let span_sum = builder(PATTERN, unicode).build_span_sum().unwrap();
        let AggregatePlanIdentity::LiteralAssertions(sum_identity) =
            span_sum.build_report().plan_identity
        else {
            panic!("Sherlock assertion span sum selected another identity");
        };
        assert_eq!(
            sum_identity.kernel.operation_id,
            LITERAL_ASSERTIONS_SPAN_SUM_OPERATION_ID
        );
        assert_eq!(
            span_sum
                .span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.1
        );

        let compiled = builder(PATTERN, unicode).build_compile().unwrap();
        assert_eq!(
            compiled.build_report().plan,
            AggregatePlanKind::LiteralAssertions
        );
        assert_eq!(
            compiled
                .verify_count(haystack, AggregateRunLimits::default())
                .unwrap()
                .value(),
            expected.0
        );
    }
}

#[test]
fn rejected_overlaps_and_captures_preserve_rust_semantics() {
    let overlap_pattern = r"(?m)^aaa|aaa$";
    let haystack = b"xaaaa\n";
    assert_eq!(oracle(overlap_pattern, haystack, false), (1, 3));
    assert_eq!(
        builder(overlap_pattern, false)
            .build_count()
            .unwrap()
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        1
    );

    let captured = builder(r"(?m)^((aaa))|((aaa))$", false)
        .build_span_sum()
        .unwrap();
    assert_eq!(captured.build_report().captures_erased, 4);
    assert_eq!(
        captured
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        3
    );
}

#[test]
fn near_misses_do_not_claim_the_leaf() {
    for pattern in [
        r"(?m)^Sherlock Holmes|Sherlock$",
        r"(?m)Sherlock Holmes$|^Sherlock Holmes",
        r"(?m)^Sherlock Holmes|Sherlock Holmes",
        r"(?m)^Sherlock Holmes$",
    ] {
        assert_ne!(
            builder(pattern, false)
                .build_count()
                .unwrap()
                .build_report()
                .plan,
            AggregatePlanKind::LiteralAssertions,
            "pattern={pattern:?}"
        );
    }
    assert_ne!(
        builder(PATTERN, false)
            .case_insensitive(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::LiteralAssertions
    );
    assert_eq!(
        builder(PATTERN, false)
            .build_spans()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        builder(PATTERN, false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
}

#[test]
fn planner_build_and_execution_fences_are_exact() {
    let baseline = builder(PATTERN, false).build_span_sum().unwrap();
    let report = baseline.build_report();
    let planner_work = report.literal_assertions_planner_work;
    let AggregateBuildAccounting::LiteralAssertions(build) = report.build else {
        panic!("literal assertions retained another build receipt");
    };
    let exact_build = LiteralAssertionsBuildLimits {
        max_literal_bytes: build.literal_bytes,
        max_build_work: build.work_upper_bound,
        max_scratch_bytes: build.scratch_bytes,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes,
    };
    let exact_limits = AggregateBuildLimits {
        max_literal_assertions_planner_work: planner_work,
        literal_assertions: exact_build,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        builder(PATTERN, false)
            .limits(exact_limits)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::LiteralAssertions
    );
    assert!(matches!(
        builder(PATTERN, false)
            .limits(AggregateBuildLimits {
                max_literal_assertions_planner_work: planner_work - 1,
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::LiteralAssertionsPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit == planner_work - 1
    ));
    assert!(matches!(
        builder(PATTERN, false)
            .limits(AggregateBuildLimits {
                literal_assertions: LiteralAssertionsBuildLimits {
                    max_persistent_bytes: build.persistent_bytes - 1,
                    ..exact_build
                },
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::LiteralAssertionsBuild { .. })
    ));

    let haystack = b"Sherlock Holmes\nxSherlock Holmes\n";
    let result = baseline
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::LiteralAssertions(accounting) = result.report().details else {
        panic!("literal assertions executed another family");
    };
    let upper = accounting.upper_bounds;
    let exact_run = exact_run_limits(upper);
    let exact_run_limits = AggregateRunLimits {
        literal_assertions: exact_run,
        ..AggregateRunLimits::default()
    };
    assert_eq!(
        baseline.span_sum_value(haystack, exact_run_limits).unwrap(),
        30
    );
    let error = baseline
        .span_sum(
            haystack,
            AggregateRunLimits {
                literal_assertions: LiteralAssertionsReduceLimits {
                    max_work: upper.work - 1,
                    ..exact_run
                },
                ..exact_run_limits
            },
        )
        .unwrap_err();
    assert!(matches!(
        error.source,
        AggregateExecutionSource::LiteralAssertions(
            LiteralAssertionsReduceError::WorkLimit { needed, limit }
        ) if needed == upper.work && limit == upper.work - 1
    ));
}

fn exact_run_limits(upper: LiteralAssertionsUpperBounds) -> LiteralAssertionsReduceLimits {
    LiteralAssertionsReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_source_reads: upper.source_reads,
        max_work: upper.work,
        max_candidate_scan_bytes: upper.candidate_scan_bytes,
        max_literal_comparisons: upper.literal_comparisons,
        max_assertion_checks: upper.assertion_checks,
        max_boundary_reads: upper.boundary_reads,
        max_candidate_events: upper.candidate_events,
        max_match_events: upper.match_events,
        max_count: upper.count,
        max_span_sum: upper.span_sum,
        max_scratch_bytes: upper.scratch_bytes,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    }
}
