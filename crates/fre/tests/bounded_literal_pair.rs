use fre::{
    AGGREGATE_EXPLAIN_SCHEMA_VERSION, AggregateBuildAccounting, AggregateBuildError,
    AggregateBuilder, AggregateExecutionDetails, AggregateOperation, AggregatePlanIdentity,
    AggregatePlanKind, AggregateRunLimits, BOUNDED_LITERAL_PAIR_COUNT_OPERATION_ID,
    BOUNDED_LITERAL_PAIR_PLAN_ID, BOUNDED_LITERAL_PAIR_SPAN_SUM_OPERATION_ID,
};
use fre_kernels::{
    BoundedLiteralPairBuildLimits as KernelBuildLimits, BoundedLiteralPairPlan,
    BoundedLiteralPairReduceLimits as KernelReduceLimits,
};
use regex::bytes::{Regex, RegexBuilder};

const ROW: &str = r"Holmes.{0,25}Watson|Watson.{0,25}Holmes";

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .unicode(false)
        .case_insensitive(false)
}

fn oracle(pattern: &str) -> Regex {
    RegexBuilder::new(pattern).unicode(false).build().unwrap()
}

fn reference(regex: &Regex, haystack: &[u8]) -> (u64, u64) {
    regex
        .find_iter(haystack)
        .fold((0_u64, 0_u64), |(count, sum), item| {
            let width = item.end().checked_sub(item.start()).unwrap();
            (
                count.checked_add(1).unwrap(),
                sum.checked_add(u64::try_from(width).unwrap()).unwrap(),
            )
        })
}

#[test]
fn exact_supported_row_selects_operation_owned_count_and_span_sum_plans() {
    let haystack = [
        b"HolmesWatson".as_slice(),
        b"--WatsonabcHolmes--",
        b"HolmesWatsonxxWatson",
        b"Holmes\nWatson",
        b"HolmesxxxxxxxxxxxxxxxxxxxxxxxxxWatson",
        b"HolmesxxxxxxxxxxxxxxxxxxxxxxxxxxWatson",
    ]
    .concat();
    let expected = reference(&oracle(ROW), &haystack);

    let count = builder(ROW).build_count().unwrap();
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    assert_eq!(count.build_report().schema_version, 38);
    assert_eq!(AGGREGATE_EXPLAIN_SCHEMA_VERSION, 38);
    assert!(count.build_report().bounded_literal_pair_planner_work > 0);
    let AggregateBuildAccounting::BoundedLiteralPair(build) = count.build_report().build else {
        panic!("bounded literal-pair count retained another build receipt");
    };
    assert!(build.persistent_bytes > 0);
    let AggregatePlanIdentity::BoundedLiteralPair(identity) = count.build_report().plan_identity
    else {
        panic!("bounded literal-pair count retained another identity");
    };
    assert_eq!(identity.kernel.plan_id, BOUNDED_LITERAL_PAIR_PLAN_ID);
    assert_eq!(
        identity.kernel.operation_id,
        BOUNDED_LITERAL_PAIR_COUNT_OPERATION_ID
    );
    let counted = count
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(counted.value(), expected.0);
    assert!(counted.report().has_closed_direct_attempt());
    let mut refused = AggregateRunLimits::default();
    refused.bounded_literal_pair.max_input_bytes = 0;
    let terminal = count.count(&haystack, refused).unwrap_err();
    assert!(terminal.has_closed_direct_attempt());
    assert!(matches!(
        counted.report().details(),
        AggregateExecutionDetails::BoundedLiteralPair(_)
    ));

    let span_sum = builder(ROW).build_span_sum().unwrap();
    assert_eq!(
        span_sum.build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    let AggregatePlanIdentity::BoundedLiteralPair(identity) = span_sum.build_report().plan_identity
    else {
        panic!("bounded literal-pair span sum retained another identity");
    };
    assert_eq!(
        identity.kernel.operation_id,
        BOUNDED_LITERAL_PAIR_SPAN_SUM_OPERATION_ID
    );
    assert_eq!(
        span_sum
            .span_sum_value(&haystack, AggregateRunLimits::default())
            .unwrap(),
        expected.1
    );

    let compiled = builder(ROW).build_compile().unwrap();
    assert_eq!(
        compiled.build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    assert_eq!(
        compiled
            .verify_count(&haystack, AggregateRunLimits::default())
            .unwrap()
            .value(),
        expected.0
    );
}

#[test]
fn planner_limit_is_exact_and_one_below_refuses_before_publication() {
    let baseline = builder(ROW).build_span_sum().unwrap();
    let needed = baseline.build_report().bounded_literal_pair_planner_work;
    assert!(needed > 0);

    let exact = fre::AggregateBuildLimits {
        max_bounded_literal_pair_planner_work: needed,
        ..fre::AggregateBuildLimits::default()
    };
    assert_eq!(
        builder(ROW)
            .limits(exact)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::BoundedLiteralPair
    );

    let below = needed.checked_sub(1).unwrap();
    let one_below = fre::AggregateBuildLimits {
        max_bounded_literal_pair_planner_work: below,
        ..exact
    };
    assert!(matches!(
        builder(ROW).limits(one_below).build_span_sum(),
        Err(AggregateBuildError::BoundedLiteralPairPlannerWorkLimit {
            operation: AggregateOperation::SpanSum,
            needed: actual,
            limit,
            ..
        }) if actual == needed && limit == below
    ));
}

#[test]
fn captures_are_transparent_but_spans_and_nearby_profiles_fall_through() {
    let captured = r"(Holmes)(.{0,25})(Watson)|(Watson)(.{0,25})(Holmes)";
    let count = builder(captured).build_count().unwrap();
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    assert_eq!(count.build_report().captures_erased, 6);
    assert_eq!(
        count
            .count_value(b"Holmes...Watson", AggregateRunLimits::default())
            .unwrap(),
        1
    );

    assert_ne!(
        builder(ROW).build_spans().unwrap().build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    assert_ne!(
        AggregateBuilder::new(ROW)
            .unicode(true)
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    assert_ne!(
        builder(r"Holmes.{0,25}Watson|Watson.{0,24}Holmes")
            .build_span_sum()
            .unwrap()
            .build_report()
            .plan,
        AggregatePlanKind::BoundedLiteralPair
    );
}

#[test]
fn small_complete_byte_languages_match_the_rust_oracle() {
    const PATTERN: &str = r"a[xy]{0,2}b|b[xy]{0,2}a";
    let count = builder(PATTERN).build_count().unwrap();
    let span_sum = builder(PATTERN).build_span_sum().unwrap();
    let oracle = oracle(PATTERN);
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    assert_eq!(
        span_sum.build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );

    let alphabet = [b'a', b'b', b'x', b'y', b'\n', 0xFF];
    let mut haystack = Vec::new();
    for length in 0..=6 {
        let cases = alphabet.len().pow(length);
        for mut ordinal in 0..cases {
            haystack.clear();
            for _ in 0..length {
                let index = ordinal.checked_rem(alphabet.len()).unwrap();
                haystack.push(alphabet[index]);
                ordinal = ordinal.checked_div(alphabet.len()).unwrap();
            }
            let expected = reference(&oracle, &haystack);
            assert_eq!(
                count
                    .count_value(&haystack, AggregateRunLimits::default())
                    .unwrap(),
                expected.0,
                "count differs for {haystack:?}"
            );
            assert_eq!(
                span_sum
                    .span_sum_value(&haystack, AggregateRunLimits::default())
                    .unwrap(),
                expected.1,
                "span sum differs for {haystack:?}"
            );
        }
    }
}

#[test]
#[ignore = "manual release-mode routed-facade Auto SVE qualification"]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the ignored paired timing harness keeps alternating batches, checksums, route assertions, and one parseable record together"
)]
fn measure_routed_facade_auto_ascii_gap_runs() {
    use fre::{SimdDispatchContext, SimdFeature};
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    const PATTERN: &str = r"a[xy]{0,512}b|b[xy]{0,512}a";

    let dispatch = SimdDispatchContext::capture();
    assert!(
        dispatch
            .capabilities()
            .usable()
            .contains(SimdFeature::ArmSve),
        "this qualification benchmark requires an OS-usable SVE host"
    );
    let scalar = BoundedLiteralPairPlan::build(
        b"a",
        [(b'x', b'y')].into_iter(),
        b"b",
        512,
        KernelBuildLimits::default(),
    )
    .unwrap();
    let routed = builder(PATTERN).build_count().unwrap();
    assert_eq!(
        routed.build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    let AggregateBuildAccounting::BoundedLiteralPair(routed_build) = routed.build_report().build
    else {
        panic!("routed facade retained another build receipt");
    };
    let scalar_build = scalar.build_accounting();
    let build_work_delta = routed_build
        .work_upper_bound
        .checked_sub(scalar_build.work_upper_bound)
        .unwrap();
    let retained_bytes_delta = routed_build
        .persistent_bytes
        .checked_sub(scalar_build.persistent_bytes)
        .unwrap();
    assert_eq!(build_work_delta, 130);
    assert!(retained_bytes_delta > 0);

    let mut haystack = Vec::new();
    for block in 0..2_048 {
        if block & 1 == 0 {
            haystack.push(b'a');
            haystack.extend(core::iter::repeat_n(b'x', 512));
            haystack.extend_from_slice(b"b!");
        } else {
            haystack.push(b'b');
            haystack.extend(core::iter::repeat_n(b'y', 512));
            haystack.extend_from_slice(b"a!");
        }
    }
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

    let batches = 9_u32;
    let calls_per_batch = 16_u32;
    let mut scalar_elapsed = Duration::ZERO;
    let mut facade_elapsed = Duration::ZERO;
    let mut scalar_checksum = 0_u64;
    let mut facade_checksum = 0_u64;
    for batch in 0..batches {
        let mut time_scalar = || {
            let start = Instant::now();
            for _ in 0..calls_per_batch {
                let value = scalar
                    .count(black_box(&haystack), KernelReduceLimits::unlimited())
                    .unwrap()
                    .count;
                scalar_checksum = scalar_checksum.wrapping_add(black_box(value).wrapping_add(1));
            }
            scalar_elapsed += start.elapsed();
        };
        let mut time_facade = || {
            let start = Instant::now();
            for _ in 0..calls_per_batch {
                let value = routed
                    .count_value(black_box(&haystack), AggregateRunLimits::default())
                    .unwrap();
                facade_checksum = facade_checksum.wrapping_add(black_box(value).wrapping_add(1));
            }
            facade_elapsed += start.elapsed();
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
    eprintln!(
        "BOUNDED_LITERAL_PAIR_AUTO_RUN_FACADE_BENCH scenario=ascii_gap_512 policy=auto \
         route=bounded_literal_pair scalar_ns={} facade_ns={} facade_over_scalar={:.6} \
         build_work_delta={build_work_delta} retained_bytes_delta={retained_bytes_delta} \
         checksum={facade_checksum}",
        scalar_elapsed.as_nanos(),
        facade_elapsed.as_nanos(),
        facade_elapsed.as_secs_f64() / scalar_elapsed.as_secs_f64(),
    );
}
