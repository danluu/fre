use fre::{
    AggregateBlockingDelimiterSemantics, AggregateBuildAccounting, AggregateBuildError,
    AggregateBuildLimits, AggregateBuilder, AggregateExecutionDetails, AggregateExecutionSource,
    AggregatePlanIdentity, AggregatePlanKind, AggregatePlanSelection, AggregateRunLimits,
    BLOCKING_DELIMITER_COUNT_OPERATION_ID, BLOCKING_DELIMITER_SPAN_SUM_OPERATION_ID,
    BlockingDelimiterBuildLimits, BlockingDelimiterReduceError, BlockingDelimiterReduceLimits,
    BlockingDelimiterTopology, BlockingDelimiterUpperBounds, RustProfile,
};
use regex::bytes::RegexBuilder;

const PATTERN: &str = r#"["'][^"']{0,30}[?!.]["']"#;

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(false)
}

fn oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap()
        .find_iter(haystack)
        .fold((0_u64, 0_u64), |sum, matched| {
            (
                sum.0.checked_add(1).unwrap(),
                sum.1
                    .checked_add(u64::try_from(matched.len()).unwrap())
                    .unwrap(),
            )
        })
}

#[test]
fn exact_quotes_shape_selects_operation_owned_leaf() {
    let haystack = b"\"?\"|'x!'|\"a\r\n?\"|'\xff?'|\"?\"?\"|nope";
    let expected = oracle(PATTERN, haystack);
    assert_eq!(expected, (5, 20));

    let count = builder(PATTERN).build_count().unwrap();
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::BlockingDelimiter
    );
    assert_eq!(count.build_report().schema_version, 31);
    let AggregatePlanIdentity::BlockingDelimiter(count_identity) =
        count.build_report().plan_identity
    else {
        panic!("quotes count selected another identity");
    };
    assert_eq!(
        count_identity.semantics,
        AggregateBlockingDelimiterSemantics::UnicodeOffBlockingByteDelimiters
    );
    assert_eq!(
        count_identity.kernel.topology,
        BlockingDelimiterTopology::DelimiterComplementBoundedTerminalDelimiter
    );
    assert_eq!(count_identity.kernel.delimiters, [b'"', b'\'']);
    assert_eq!(count_identity.kernel.maximum_middle_bytes, 30);
    assert_eq!(
        count_identity.kernel.operation_id,
        BLOCKING_DELIMITER_COUNT_OPERATION_ID
    );
    assert_eq!(
        count
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        expected.0
    );

    let span_sum = builder(PATTERN).build_span_sum().unwrap();
    let AggregatePlanIdentity::BlockingDelimiter(span_identity) =
        span_sum.build_report().plan_identity
    else {
        panic!("quotes span sum selected another identity");
    };
    assert_eq!(
        span_identity.kernel.operation_id,
        BLOCKING_DELIMITER_SPAN_SUM_OPERATION_ID
    );
    assert_eq!(
        span_sum
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        expected.1
    );

    let compiled = builder(PATTERN).build_compile().unwrap();
    assert_eq!(
        compiled.build_report().plan,
        AggregatePlanKind::BlockingDelimiter
    );
    assert_eq!(
        compiled
            .verify_count(haystack, AggregateRunLimits::default())
            .unwrap()
            .value(),
        expected.0
    );
}

#[test]
fn captures_are_transparent_and_nearby_profiles_do_not_claim_the_leaf() {
    let captured = builder(r#"((["']))(([^"']{0,30}))(([?!.]))((["']))"#)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        captured.build_report().plan,
        AggregatePlanKind::BlockingDelimiter
    );
    assert_eq!(captured.build_report().captures_erased, 8);
    assert_eq!(
        captured
            .span_sum_value(b"\"question?\"", AggregateRunLimits::default())
            .unwrap(),
        11
    );

    for pattern in [
        r#"["'][^"']{1,30}[?!.]["']"#,
        r#"["'][^"']{0,30}?[?!.]["']"#,
        r#"["'][^']{0,30}[?!.]["']"#,
        r#"["'][^"']{0,30}[?!.]["]"#,
    ] {
        assert_ne!(
            builder(pattern).build_count().unwrap().build_report().plan,
            AggregatePlanKind::BlockingDelimiter,
            "pattern={pattern:?}"
        );
    }
    assert_ne!(
        builder(PATTERN)
            .unicode(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::BlockingDelimiter
    );
    assert_ne!(
        builder(PATTERN)
            .case_insensitive(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::BlockingDelimiter
    );
    assert_eq!(
        builder(PATTERN).build_spans().unwrap().build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        builder(PATTERN)
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
    let baseline = builder(PATTERN).build_span_sum().unwrap();
    let report = baseline.build_report();
    let planner_work = report.blocking_delimiter_planner_work;
    let AggregateBuildAccounting::BlockingDelimiter(build) = report.build else {
        panic!("blocking delimiter retained another build receipt");
    };
    let exact_build = BlockingDelimiterBuildLimits {
        max_delimiter_members: build.delimiter_members,
        max_terminal_members: build.terminal_members,
        max_middle_bytes: build.maximum_middle_bytes,
        max_build_work: build.work_upper_bound,
        max_scratch_bytes: build.scratch_bytes,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes,
    };
    let exact_limits = AggregateBuildLimits {
        max_blocking_delimiter_planner_work: planner_work,
        blocking_delimiter: exact_build,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        builder(PATTERN)
            .limits(exact_limits)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::BlockingDelimiter
    );
    assert!(matches!(
        builder(PATTERN)
            .limits(AggregateBuildLimits {
                max_blocking_delimiter_planner_work: planner_work - 1,
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::BlockingDelimiterPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit == planner_work - 1
    ));
    assert!(matches!(
        builder(PATTERN)
            .limits(AggregateBuildLimits {
                blocking_delimiter: BlockingDelimiterBuildLimits {
                    max_persistent_bytes: build.persistent_bytes - 1,
                    ..exact_build
                },
                ..exact_limits
            })
            .build_span_sum(),
        Err(AggregateBuildError::BlockingDelimiterBuild { .. })
    ));

    let haystack = b"\"question?\" and 'answer!'";
    let result = baseline
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::BlockingDelimiter(accounting) = result.report().details else {
        panic!("blocking delimiter executed another family");
    };
    let upper = accounting.upper_bounds;
    let exact_run = exact_run_limits(upper);
    let exact_run_limits = AggregateRunLimits {
        blocking_delimiter: exact_run,
        ..AggregateRunLimits::default()
    };
    assert_eq!(
        baseline.span_sum_value(haystack, exact_run_limits).unwrap(),
        20
    );
    let error = baseline
        .span_sum(
            haystack,
            AggregateRunLimits {
                blocking_delimiter: BlockingDelimiterReduceLimits {
                    max_work: upper.work - 1,
                    ..exact_run
                },
                ..exact_run_limits
            },
        )
        .unwrap_err();
    assert!(matches!(
        error.source,
        AggregateExecutionSource::BlockingDelimiter(
            BlockingDelimiterReduceError::WorkLimit { needed, limit }
        ) if needed == upper.work && limit == upper.work - 1
    ));
}

fn exact_run_limits(upper: BlockingDelimiterUpperBounds) -> BlockingDelimiterReduceLimits {
    BlockingDelimiterReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_source_reads: upper.source_reads,
        max_work: upper.work,
        max_delimiter_scan_bytes: upper.delimiter_scan_bytes,
        max_delimiter_events: upper.delimiter_events,
        max_pair_events: upper.pair_events,
        max_terminal_reads: upper.terminal_reads,
        max_match_events: upper.match_events,
        max_count: upper.count,
        max_span_sum: upper.span_sum,
        max_scratch_bytes: upper.scratch_bytes,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    }
}
