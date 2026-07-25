use fre::AggregatePlanKind;
use rebar_compare::{
    current_fre_rebar_aggregate_builder, current_fre_rebar_aggregate_compile_lifecycle,
    current_fre_rebar_aggregate_operation_lifecycle, current_fre_rebar_validate_aggregate_identity,
};
use regex::bytes::RegexBuilder;

const PATTERN: &str = r"Sherlock\s+Holmes";
const COMPILE_PLAN: &str = "compile-aggregate-literal-class-run-literal-v1";
const OPERATION_PLAN: &str = "aggregate-literal-class-run-literal-v1";
const ROW_FIRST: &str = "imported/sherlock/name-whitespace@rust/regex::first-public-operation";
const ROW_STEADY: &str = "imported/sherlock/name-whitespace@rust/regex::steady-public-operation";

fn local_name_whitespace_fixture() -> Vec<u8> {
    let mut haystack = Vec::new();
    haystack.extend_from_slice(b"SherlockHolmes|Sherlock \tMoriarty|\xFF|");
    for _ in 0..96 {
        haystack.extend_from_slice(b"Sherlock Holmes|");
    }
    haystack.extend_from_slice(b"Sherlock       Holmes");
    haystack
}

#[test]
fn name_whitespace_first_and_steady_rows_use_the_exact_route() {
    let haystack = local_name_whitespace_fixture();
    let oracle = RegexBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("pinned Rust regex accepts the exact benchmark pattern");
    let expected = oracle
        .find_iter(&haystack)
        .map(|matched| matched.end() - matched.start())
        .sum::<usize>();
    assert_eq!(expected, 1_461);

    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[PATTERN.to_string()],
        false,
        false,
        haystack.len(),
    )
    .expect("name-whitespace lifecycle construction");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN);

    let first = lifecycle.execute(&haystack).expect(ROW_FIRST);
    assert_eq!(first, u64::try_from(expected).unwrap(), "{ROW_FIRST}");
    let steady = lifecycle.execute(&haystack).expect(ROW_STEADY);
    assert_eq!(steady, u64::try_from(expected).unwrap(), "{ROW_STEADY}");
}

#[test]
fn name_whitespace_compile_and_span_sum_labels_bind_the_typed_plan() {
    let haystack = local_name_whitespace_fixture();
    let patterns = [PATTERN.to_string()];
    let compile =
        current_fre_rebar_aggregate_compile_lifecycle(&patterns, false, false, haystack.len())
            .expect("name-whitespace compile lifecycle");
    let artifact = compile.construct().expect("name-whitespace construction");
    assert_eq!(artifact.plan(&compile).unwrap(), COMPILE_PLAN);
    assert_eq!(artifact.verify(&compile, &haystack).unwrap(), 97);

    let regex = current_fre_rebar_aggregate_builder(PATTERN, false, false)
        .build_span_sum()
        .expect("name-whitespace span-sum construction");
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    assert_eq!(regex.build_report().schema_version, 35);
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count-spans")
        .expect("typed route identity");
}
