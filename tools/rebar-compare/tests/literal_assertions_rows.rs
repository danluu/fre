use fre::{AggregatePlanIdentity, AggregatePlanKind};
use rebar_compare::{
    CandidateAdapter, CurrentFreAdapter, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_compile_lifecycle, current_fre_rebar_aggregate_operation_lifecycle,
    current_fre_rebar_validate_aggregate_identity,
};
use regex::bytes::RegexBuilder;
use sha2::{Digest, Sha256};

const PATTERN: &str = r"(?m)^Sherlock Holmes|Sherlock Holmes$";
const ROW: &str = "imported/sherlock/line-boundary-sherlock-holmes";
const COMPILE_PLAN: &str = "compile-aggregate-literal-assertions-v1";
const OPERATION_PLAN: &str = "aggregate-literal-assertions-v1";

fn exact_sum_510_fixture() -> Vec<u8> {
    let mut haystack = Vec::new();
    for _ in 0..17 {
        haystack.extend_from_slice(b"Sherlock Holmes and Watson\n");
    }
    for _ in 0..17 {
        haystack.extend_from_slice(b"xSherlock Holmes\n");
    }
    haystack.extend_from_slice(b"\xffnot a match");
    haystack
}

#[test]
fn exact_sherlock_line_boundary_row_uses_literal_assertions() {
    let haystack = exact_sum_510_fixture();
    let oracle = RegexBuilder::new(PATTERN)
        .unicode(true)
        .build()
        .expect("pinned Rust regex accepts the exact row pattern");
    let spans: Vec<_> = oracle.find_iter(&haystack).collect();
    assert_eq!(spans.len(), 34);
    assert_eq!(
        spans
            .iter()
            .map(|matched| matched.end() - matched.start())
            .sum::<usize>(),
        510
    );

    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[PATTERN.to_owned()],
        true,
        false,
        haystack.len(),
    )
    .expect("exact Sherlock operation lifecycle");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN, "{ROW}");
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 510, "{ROW}");
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 510, "{ROW}");

    let compile = current_fre_rebar_aggregate_compile_lifecycle(
        &[PATTERN.to_owned()],
        true,
        false,
        haystack.len(),
    )
    .expect("exact Sherlock compile lifecycle");
    let artifact = compile.construct().expect("exact Sherlock construction");
    assert_eq!(artifact.plan(&compile).unwrap(), COMPILE_PLAN);
    assert_eq!(artifact.verify(&compile, &haystack).unwrap(), 34);

    let regex = current_fre_rebar_aggregate_builder(PATTERN, true, false)
        .build_span_sum()
        .expect("exact Sherlock facade plan");
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::LiteralAssertions
    );
    assert_eq!(regex.build_report().schema_version, 48);
    assert!(matches!(
        regex.build_report().plan_identity,
        AggregatePlanIdentity::LiteralAssertions(_)
    ));
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), true, "count-spans")
        .expect("typed literal-assertions identity");
}

#[test]
fn adapter_identity_names_the_new_operation_owned_leaf() {
    let identity = CurrentFreAdapter.identity();
    assert!(identity.adapter.contains("literal-assertions-v1"));
    assert!(identity.identity.contains("literal-assertions-v1"));
    assert!(identity.availability.contains("literal-assertions"));
}

#[test]
#[ignore = "requires the separately authenticated Rebar Sherlock corpus"]
fn authenticated_rebar_sherlock_corpus_returns_510() {
    let path = std::env::var_os("FRE_LITERAL_ASSERTIONS_SHERLOCK_HAYSTACK")
        .expect("set FRE_LITERAL_ASSERTIONS_SHERLOCK_HAYSTACK");
    let haystack = std::fs::read(path).expect("read authenticated Sherlock corpus");
    assert_eq!(haystack.len(), 594_933);
    assert_eq!(
        format!("{:x}", Sha256::digest(&haystack)),
        "242ec73a70f0a03dcbe007e32038e7deeaee004aaec9a09a07fa322743440fa8"
    );
    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[PATTERN.to_owned()],
        true,
        false,
        haystack.len(),
    )
    .expect("authenticated Sherlock lifecycle");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN, "{ROW}");
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 510, "{ROW}");
}
