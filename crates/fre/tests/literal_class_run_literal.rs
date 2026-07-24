use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregatePlanIdentity, AggregatePlanKind,
    AggregatePlanSelection, AggregateRunLimits, LiteralClassRunLiteralBuildLimits,
    LiteralClassRunLiteralReduceError, LiteralClassRunLiteralReduceLimits, RustProfile,
};
use regex::bytes::RegexBuilder;

const ROW_PATTERN: &str = r"Sherlock\s+Holmes";

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .case_insensitive(false)
}

fn oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    let spans: Vec<_> = RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| matched.start()..matched.end())
        .collect();
    let count = u64::try_from(spans.len()).unwrap();
    let span_sum = spans
        .into_iter()
        .map(|span| u64::try_from(span.end.checked_sub(span.start).expect("ordered span")).unwrap())
        .sum();
    (count, span_sum)
}

#[test]
fn exact_sherlock_rows_select_one_operation_typed_leaf() {
    let haystack = b"Sherlock Holmes--Sherlock\t\tHolmes--SherlockxHolmes--\xffSherlock\r\nHolmes";
    let (expected_count, expected_sum) = oracle(ROW_PATTERN, haystack);
    assert_eq!((expected_count, expected_sum), (3, 47));

    let count = builder(ROW_PATTERN).build_count().unwrap();
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    assert_eq!(count.build_report().continuation_strategy, None);
    let AggregatePlanIdentity::LiteralClassRunLiteral(count_identity) =
        count.build_report().plan_identity
    else {
        panic!("Sherlock count selected another identity");
    };
    assert_eq!(count_identity.kernel.prefix_bytes, b"Sherlock".len());
    assert_eq!(count_identity.kernel.suffix_bytes, b"Holmes".len());
    assert_eq!(
        count
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        expected_count
    );

    let sum = builder(ROW_PATTERN).build_span_sum().unwrap();
    assert_eq!(
        sum.build_report().plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    let AggregatePlanIdentity::LiteralClassRunLiteral(sum_identity) =
        sum.build_report().plan_identity
    else {
        panic!("Sherlock span sum selected another identity");
    };
    assert_ne!(
        count_identity.kernel.operation_id,
        sum_identity.kernel.operation_id
    );
    assert_eq!(
        sum.span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        expected_sum
    );

    let compiled = builder(ROW_PATTERN).build_compile().unwrap();
    assert_eq!(
        compiled.build_report().plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    assert_eq!(
        compiled
            .verify_count(haystack, AggregateRunLimits::default())
            .unwrap()
            .value(),
        expected_count
    );
}

#[test]
fn captures_are_transparent_and_semantic_near_misses_fall_through() {
    let captured = builder(r"((Sherlock))(\s+)((Holmes))")
        .build_span_sum()
        .unwrap();
    assert_eq!(
        captured.build_report().plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    assert_eq!(captured.build_report().captures_erased, 5);
    assert_eq!(
        captured
            .span_sum_value(b"Sherlock \tHolmes", AggregateRunLimits::default())
            .unwrap(),
        16
    );

    for pattern in [
        r"Sherlock\s*Holmes",
        r"Sherlock\s+?Holmes",
        r"Sherlock\s{1,3}Holmes",
        r"a[ab]+c",
        r"a[bc]+b",
    ] {
        assert_ne!(
            builder(pattern).build_count().unwrap().build_report().plan,
            AggregatePlanKind::LiteralClassRunLiteral,
            "pattern={pattern:?}"
        );
    }
    assert_ne!(
        AggregateBuilder::new(ROW_PATTERN)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    assert_ne!(
        builder(ROW_PATTERN)
            .case_insensitive(true)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    assert_eq!(
        builder(ROW_PATTERN)
            .build_spans()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert_eq!(
        builder(ROW_PATTERN)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::ContinuationProgram
    );
}

#[test]
fn facade_planner_and_construction_limits_are_exact_and_one_below() {
    let baseline = builder(ROW_PATTERN).build_count().unwrap();
    let report = baseline.build_report();
    let planner_work = report.literal_class_run_literal_planner_work;
    assert!(planner_work > 0);
    let AggregateBuildAccounting::LiteralClassRunLiteral(build) = report.build else {
        panic!("Sherlock row retained another build certificate");
    };
    let exact_kernel = LiteralClassRunLiteralBuildLimits {
        max_literal_bytes: build.literal_bytes,
        max_class_ranges: build.class_ranges,
        max_class_members: build.class_members,
        max_build_work: build.work_upper_bound,
        max_scratch_bytes: build.scratch_bytes,
        max_persistent_bytes: build.persistent_bytes,
        max_peak_bytes: build.peak_bytes,
    };
    let exact = AggregateBuildLimits {
        max_literal_class_run_literal_planner_work: planner_work,
        literal_class_run_literal: exact_kernel,
        ..AggregateBuildLimits::default()
    };
    assert_eq!(
        builder(ROW_PATTERN)
            .limits(exact)
            .build_count()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );

    assert!(matches!(
        builder(ROW_PATTERN)
            .limits(AggregateBuildLimits {
                max_literal_class_run_literal_planner_work: planner_work - 1,
                ..exact
            })
            .build_count(),
        Err(AggregateBuildError::LiteralClassRunLiteralPlannerWorkLimit {
            needed,
            limit,
            ..
        }) if needed == planner_work && limit == planner_work - 1
    ));
    let mut below = exact_kernel;
    below.max_persistent_bytes -= 1;
    assert!(matches!(
        builder(ROW_PATTERN)
            .limits(AggregateBuildLimits {
                literal_class_run_literal: below,
                ..exact
            })
            .build_count(),
        Err(AggregateBuildError::LiteralClassRunLiteralBuild { .. })
    ));
}

#[test]
fn execution_exact_limits_publish_actual_at_or_below_upper() {
    let haystack = b"Sherlock Holmes--x x--Sherlock\tHolmes--SherlockxHolmes";
    let regex = builder(ROW_PATTERN).build_span_sum().unwrap();
    let baseline = regex
        .span_sum(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::LiteralClassRunLiteral(accounting) = baseline.report().details()
    else {
        panic!("Sherlock row executed another plan");
    };
    let upper = accounting.upper_bounds;
    assert!(accounting.actual.source_reads <= upper.source_reads);
    assert!(accounting.actual.classifications <= upper.classifications);
    assert!(accounting.actual.literal_comparisons <= upper.literal_comparisons);
    assert!(accounting.actual.runs <= upper.run_events);
    assert!(accounting.actual.candidates <= upper.candidate_events);
    assert!(accounting.actual.matches <= upper.match_events);
    assert!(accounting.actual.span_sum <= upper.span_sum);
    assert!(accounting.actual.work <= upper.work);
    assert_eq!(accounting.actual.scratch_bytes, 0);

    let exact_kernel = LiteralClassRunLiteralReduceLimits {
        max_input_bytes: upper.input_bytes,
        max_source_reads: upper.source_reads,
        max_work: upper.work,
        max_run_events: upper.run_events,
        max_match_events: upper.match_events,
        max_count: upper.count,
        max_span_sum: upper.span_sum,
        max_scratch_bytes: upper.scratch_bytes,
        max_persistent_bytes: upper.persistent_bytes,
        max_peak_bytes: upper.peak_bytes,
    };
    let exact = AggregateRunLimits {
        literal_class_run_literal: exact_kernel,
        ..AggregateRunLimits::default()
    };
    assert_eq!(regex.span_sum_value(haystack, exact).unwrap(), 30);

    let mut below = exact_kernel;
    below.max_work -= 1;
    let error = regex
        .span_sum(
            haystack,
            AggregateRunLimits {
                literal_class_run_literal: below,
                ..exact
            },
        )
        .unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::LiteralClassRunLiteral(
            LiteralClassRunLiteralReduceError::WorkLimit { needed, limit }
        ) if needed == upper.work && limit == upper.work - 1
    ));
}
