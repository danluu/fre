use fre::{
    AGGREGATE_EXPLAIN_SCHEMA_VERSION, AggregateBuildAccounting, AggregateBuildError,
    AggregateBuilder, AggregateExecutionDetails, AggregateOperation, AggregatePlanIdentity,
    AggregatePlanKind, AggregateRunLimits, BOUNDED_LITERAL_PAIR_COUNT_OPERATION_ID,
    BOUNDED_LITERAL_PAIR_PLAN_ID, BOUNDED_LITERAL_PAIR_SPAN_SUM_OPERATION_ID,
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
    assert_eq!(count.build_report().schema_version, 29);
    assert_eq!(AGGREGATE_EXPLAIN_SCHEMA_VERSION, 29);
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
    assert!(matches!(
        counted.report().details,
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
