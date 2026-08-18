use fre::{
    AggregateBuildAccounting, AggregateExecutionDetails, AggregatePlanIdentity, AggregatePlanKind,
};
use rebar_compare::{
    current_fre_rebar_aggregate_builder, current_fre_rebar_aggregate_compile_lifecycle,
    current_fre_rebar_aggregate_operation_lifecycle, current_fre_rebar_aggregate_run_limits,
    current_fre_validate_generic_span_sum_identity,
};
use regex::bytes::RegexBuilder;

const PATTERN: &str = r"Holmes.{0,25}Watson|Watson.{0,25}Holmes";
const COMPILE_PLAN: &str = "compile-aggregate-bounded-literal-pair-v1";
const OPERATION_PLAN: &str = "aggregate-continuation-program";
const ROW_FIRST: &str = "imported/sherlock/holmes-cochar-watson@rust/regex::first-public-operation";
const ROW_STEADY: &str =
    "imported/sherlock/holmes-cochar-watson@rust/regex::steady-public-operation";

fn local_holmes_watson_fixture() -> Vec<u8> {
    let mut haystack = Vec::new();
    for index in 0..10 {
        let matched = if index % 2 == 0 {
            b"Holmes___Watson".as_slice()
        } else {
            b"Watson___Holmes".as_slice()
        };
        haystack.extend_from_slice(matched);
        haystack.push(b'\n');
    }
    haystack.extend_from_slice(b"Holmes\nWatson\nHolmes__________________________Watson\n\xFF");
    haystack
}

#[test]
fn holmes_watson_first_and_steady_rows_use_the_exact_route() {
    let haystack = local_holmes_watson_fixture();
    let oracle = RegexBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("pinned Rust regex accepts the exact benchmark pattern");
    let spans = oracle.find_iter(&haystack).collect::<Vec<_>>();
    let expected = spans
        .iter()
        .map(|matched| matched.end() - matched.start())
        .sum::<usize>();
    assert_eq!(spans.len(), 10);
    assert_eq!(expected, 150);

    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[PATTERN.to_string()],
        false,
        false,
        haystack.len(),
    )
    .expect("Holmes/Watson lifecycle construction");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN);

    let first = lifecycle.execute(&haystack).expect(ROW_FIRST);
    assert_eq!(first, u64::try_from(expected).unwrap(), "{ROW_FIRST}");
    let steady = lifecycle.execute(&haystack).expect(ROW_STEADY);
    assert_eq!(steady, u64::try_from(expected).unwrap(), "{ROW_STEADY}");
}

#[test]
fn holmes_watson_compile_and_span_sum_labels_bind_the_typed_plan() {
    let haystack = local_holmes_watson_fixture();
    let patterns = [PATTERN.to_string()];
    let compile =
        current_fre_rebar_aggregate_compile_lifecycle(&patterns, false, false, haystack.len())
            .expect("Holmes/Watson compile lifecycle");
    let artifact = compile.construct().expect("Holmes/Watson construction");
    assert_eq!(artifact.plan(&compile).unwrap(), COMPILE_PLAN);
    assert_eq!(artifact.verify(&compile, &haystack).unwrap(), 10);

    let regex = current_fre_rebar_aggregate_builder(PATTERN, false, false)
        .build_span_sum()
        .expect("Holmes/Watson span-sum construction");
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::BoundedLiteralPair
    );
    assert_eq!(regex.build_report().schema_version, 52);
    current_fre_validate_generic_span_sum_identity(regex.build_report(), false, "span-sum")
        .expect("typed route identity");

    let limits = current_fre_rebar_aggregate_run_limits(haystack.len(), regex.build_report())
        .expect("derived operation limits");
    let result = regex
        .span_sum(&haystack, limits)
        .expect("bounded literal-pair execution");
    assert_eq!(result.value(), 150);
    let AggregateExecutionDetails::BoundedLiteralPair(accounting) = result.report().details()
    else {
        panic!("expected bounded literal-pair accounting")
    };
    assert_eq!(accounting.upper_bounds.input_bytes, haystack.len());
    assert_eq!(
        accounting.upper_bounds.span_sum,
        u64::try_from(haystack.len()).expect("fixture length fits u64")
    );
    assert_eq!(accounting.actual.span_sum, 150);

    let mut forged_identity = regex.build_report().clone();
    let AggregatePlanIdentity::BoundedLiteralPair(identity) = &mut forged_identity.plan_identity
    else {
        panic!("expected bounded literal-pair identity")
    };
    identity.kernel.gap_max = identity.kernel.gap_max.saturating_add(1);
    assert!(
        current_fre_validate_generic_span_sum_identity(&forged_identity, false, "span-sum")
            .is_err()
    );

    let mut forged_build = regex.build_report().clone();
    let AggregateBuildAccounting::BoundedLiteralPair(build) = &mut forged_build.build else {
        panic!("expected bounded literal-pair build accounting")
    };
    build.class_members = build.class_members.saturating_sub(1);
    assert!(
        current_fre_validate_generic_span_sum_identity(&forged_build, false, "span-sum").is_err()
    );
}
