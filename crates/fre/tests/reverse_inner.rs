use fre::{
    AggregateBuildAccounting, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregatePlanIdentity, AggregatePlanKind,
    AggregateRetainedFullWindowUpperBounds, AggregateRunLimits, REVERSE_INNER_COUNT_OPERATION_ID,
    REVERSE_INNER_GROUPED_UNION_ACCOUNTING_ID, REVERSE_INNER_GROUPED_UNION_PLAN_ID,
    REVERSE_INNER_SPAN_SUM_OPERATION_ID, REVERSE_INNER_UNION_ACCOUNTING_ID,
    REVERSE_INNER_UNION_PLAN_ID, ReverseInnerBuildError, ReverseInnerReduceError,
    ReverseInnerUnionMode, RustProfile,
};
use regex::bytes::{Regex, RegexBuilder};

const PATTERN: &str = r"\pL+herloc\pL+|\pL+olme\pL+";
const FACTORED_PATTERN: &str = r"\pL+(?:herloc\pL+|olme\pL+)";

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
        .case_insensitive(false)
}

fn oracle(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("Rust bytes-regex oracle")
}

fn aggregates(regex: &Regex, haystack: &[u8]) -> (u64, u64) {
    regex
        .find_iter(haystack)
        .fold((0_u64, 0_u64), |(count, sum), matched| {
            (
                count.checked_add(1).unwrap(),
                sum.checked_add(
                    u64::try_from(matched.end().checked_sub(matched.start()).unwrap()).unwrap(),
                )
                .unwrap(),
            )
        })
}

#[test]
fn unfactored_and_factored_tom_shapes_select_reverse_inner() {
    let haystack =
        b"sherlock Holmes -- holmes \xff \xce\xbbsherlock\xce\xb2 xherlocy herlocx xolmey";
    for pattern in [PATTERN, FACTORED_PATTERN] {
        let expected = aggregates(&oracle(pattern), haystack);
        let count = builder(pattern).build_count().expect("count build");
        assert_eq!(count.build_report().plan, AggregatePlanKind::ReverseInner);
        assert_eq!(count.build_report().continuation_strategy, None);
        assert!(count.build_report().literal_class_run_literal_planner_work > 0);
        let AggregatePlanIdentity::ReverseInner(identity) = count.build_report().plan_identity
        else {
            panic!("reverse-inner plan retained another identity");
        };
        assert_eq!(
            identity.kernel.operation_id,
            REVERSE_INNER_COUNT_OPERATION_ID
        );
        assert_eq!(identity.kernel.literal_count, 2);
        assert_eq!(identity.kernel.literal_bytes, 10);
        assert_eq!(identity.kernel.plan_id, REVERSE_INNER_UNION_PLAN_ID);
        assert_eq!(
            identity.kernel.accounting_id,
            REVERSE_INNER_UNION_ACCOUNTING_ID
        );
        assert!(identity.kernel.unicode);
        assert!(identity.kernel.greedy);
        assert!(identity.kernel.leftmost_first);
        assert!(identity.kernel.non_overlapping);
        let AggregateBuildAccounting::ReverseInner(build) = count.build_report().build else {
            panic!("reverse-inner plan retained another build receipt");
        };
        assert_eq!(build.literal_count, 2);
        assert_eq!(build.literal_bytes, 10);
        assert_eq!(build.distinct_literal_first_bytes, 2);
        assert!(build.adaptive_union);
        assert_eq!(
            identity.kernel.union_receipt_digest,
            build.union_receipt_digest()
        );
        assert_eq!(
            count.build_report().retained_capacity_bytes,
            build.persistent_bytes
        );
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .expect("count"),
            expected.0
        );
        let counted = count
            .count(haystack, AggregateRunLimits::default())
            .expect("count with report");
        let AggregateExecutionDetails::ReverseInner(accounting) = counted.report().details() else {
            panic!("reverse-inner count executed another route");
        };
        assert_eq!(accounting.identity, identity.kernel);
        assert!(accounting.actual.work <= accounting.upper_bounds.work);

        let sum = builder(pattern).build_span_sum().expect("span-sum build");
        assert_eq!(sum.build_report().plan, AggregatePlanKind::ReverseInner);
        let AggregatePlanIdentity::ReverseInner(sum_identity) = sum.build_report().plan_identity
        else {
            panic!("reverse-inner span sum retained another identity");
        };
        assert_eq!(
            sum_identity.kernel.operation_id,
            REVERSE_INNER_SPAN_SUM_OPERATION_ID
        );
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .expect("span sum"),
            expected.1
        );

        let compiled = builder(pattern).build_compile().expect("compile build");
        assert_eq!(
            compiled.build_report().plan,
            AggregatePlanKind::ReverseInner
        );
        assert_eq!(
            compiled
                .verify_count(haystack, AggregateRunLimits::default())
                .expect("compiled verification")
                .value(),
            expected.0
        );
    }
}

#[test]
fn canonical_middle_literal_alternation_selects_adaptive_union() {
    let pattern = r"[a-zλ]+(?:ab|cd|ef|gh)[a-zλ]+";
    let plan = builder(pattern).build_count().expect("middle alternation build");
    assert_eq!(plan.build_report().plan, AggregatePlanKind::ReverseInner);
    let AggregatePlanIdentity::ReverseInner(identity) = plan.build_report().plan_identity else {
        panic!("middle alternation retained another identity");
    };
    assert_eq!(identity.kernel.literal_count, 4);
    assert_eq!(identity.kernel.plan_id, REVERSE_INNER_UNION_PLAN_ID);
    let AggregateBuildAccounting::ReverseInner(build) = plan.build_report().build else {
        panic!("middle alternation retained another build receipt");
    };
    assert!(build.adaptive_union);
    assert_eq!(build.union_mode, ReverseInnerUnionMode::AdaptiveFirstByte);
    assert_eq!(build.distinct_literal_first_bytes, 4);
    assert_eq!(
        identity.kernel.union_receipt_digest,
        build.union_receipt_digest()
    );
}

#[test]
fn shared_root_alternation_selects_grouped_union_identity() {
    let pattern = r"[a-zλ]+(?:aab|abb)[a-zλ]+";
    let plan = builder(pattern).build_count().expect("shared-root build");
    assert_eq!(plan.build_report().plan, AggregatePlanKind::ReverseInner);
    let AggregatePlanIdentity::ReverseInner(identity) = plan.build_report().plan_identity else {
        panic!("shared-root alternation retained another identity");
    };
    assert_eq!(
        identity.kernel.plan_id,
        REVERSE_INNER_GROUPED_UNION_PLAN_ID
    );
    assert_eq!(
        identity.kernel.accounting_id,
        REVERSE_INNER_GROUPED_UNION_ACCOUNTING_ID
    );
    let AggregateBuildAccounting::ReverseInner(build) = plan.build_report().build else {
        panic!("shared-root alternation retained another build receipt");
    };
    assert_eq!(build.union_mode, ReverseInnerUnionMode::GroupedFixedColumn);
    assert!(!build.adaptive_union);
    assert_eq!(build.distinct_literal_first_bytes, 1);
    assert_eq!(
        identity.kernel.union_receipt_digest,
        build.union_receipt_digest()
    );
    let haystack = b"qaabq-abb-qabbq";
    assert_eq!(
        plan.count_value(haystack, AggregateRunLimits::default())
            .expect("shared-root count"),
        aggregates(&oracle(pattern), haystack).0
    );
}

#[test]
fn overlap_near_miss_invalid_utf8_and_captures_match_oracle() {
    let pattern = r"((?:[aλ]+)(aa)([aλ]+))";
    let regex = oracle(pattern);
    let plan = builder(pattern).build_span_sum().expect("captured plan");
    assert_eq!(plan.build_report().plan, AggregatePlanKind::ReverseInner);
    assert_eq!(plan.build_report().captures_erased, 3);
    for haystack in [
        b"aaa".as_slice(),
        b"aaaa",
        b"\xce\xbbaaaa\xce\xbb",
        b"aaaa\xffaaaa",
        b"\xce\x80aaaa",
        b"aaaa\xce",
    ] {
        let expected = aggregates(&regex, haystack);
        assert_eq!(
            plan.span_sum_value(haystack, AggregateRunLimits::default())
                .expect("span sum"),
            expected.1,
            "haystack={haystack:?}"
        );
    }
}

#[test]
fn facade_exact_and_one_below_receipts_close() {
    let count = builder(PATTERN).build_count().expect("baseline build");
    let AggregateBuildAccounting::ReverseInner(build) = count.build_report().build else {
        panic!("baseline selected another build");
    };
    let upper = match count
        .retained_full_window_upper_bounds(512)
        .expect("authenticated retained bounds")
    {
        Some(AggregateRetainedFullWindowUpperBounds::ReverseInner(upper)) => upper,
        other => panic!("unexpected retained bounds: {other:?}"),
    };

    let mut build_limits = AggregateBuildLimits::default();
    build_limits.reverse_inner.max_build_work = build.work;
    build_limits.reverse_inner.max_persistent_bytes = build.persistent_bytes;
    build_limits.reverse_inner.max_peak_bytes = build.peak_bytes;
    let exact = builder(PATTERN)
        .limits(build_limits)
        .build_count()
        .expect("exact build limits");
    assert_eq!(
        exact.build_report().build,
        AggregateBuildAccounting::ReverseInner(build)
    );

    build_limits.reverse_inner.max_build_work = build.work - 1;
    assert!(matches!(
        builder(PATTERN).limits(build_limits).build_count(),
        Err(AggregateBuildError::ReverseInnerBuild {
            source: ReverseInnerBuildError::WorkLimit { .. },
            ..
        })
    ));

    let haystack = b"sherlock holmes";
    let actual_upper = match count
        .retained_full_window_upper_bounds(haystack.len())
        .expect("authenticated actual bounds")
    {
        Some(AggregateRetainedFullWindowUpperBounds::ReverseInner(upper)) => upper,
        other => panic!("unexpected retained bounds: {other:?}"),
    };
    assert!(actual_upper.work <= upper.work);
    let mut run_limits = AggregateRunLimits::default();
    run_limits.reverse_inner.max_work = actual_upper.work - 1;
    let error = count
        .count(haystack, run_limits)
        .expect_err("one-below run work must fail");
    assert!(matches!(
        error.source,
        AggregateExecutionSource::ReverseInner(ReverseInnerReduceError::WorkLimit { .. })
    ));
}

#[test]
fn unsound_shapes_fall_through_without_benchmark_name_checks() {
    for pattern in [
        r"\pL*herloc\pL+",
        r"\pL+?herloc\pL+",
        r"\pL+herloc\pN+",
        r"\pL+123\pL+",
        r"(?i:\pL+herloc\pL+)",
    ] {
        assert_ne!(
            builder(pattern)
                .build_count()
                .expect("continuation fallback")
                .build_report()
                .plan,
            AggregatePlanKind::ReverseInner,
            "pattern={pattern}"
        );
    }
}
