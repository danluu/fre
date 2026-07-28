use fre::{AggregatePlanIdentity, AggregatePlanKind};
use rebar_compare::{
    CandidateAdapter, CurrentFreAdapter, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_compile_lifecycle, current_fre_rebar_aggregate_operation_lifecycle,
    current_fre_rebar_validate_aggregate_identity,
};
use regex::bytes::RegexBuilder;
use sha2::{Digest, Sha256};

const PATTERN: &str = r#"["'][^"']{0,30}[?!.]["']"#;
const PATTERN_SHA256: &str = "7e76857b9f5ad19a3346cc410c91142225d97cbc2556073dd27a4c78f9847b6d";
const ROW: &str = "imported/sherlock/quotes@rust/regex";
const COMPILE_PLAN: &str = "compile-aggregate-blocking-delimiter-v1";
const OPERATION_PLAN: &str = "aggregate-blocking-delimiter-v1";

fn local_quotes_fixture() -> Vec<u8> {
    let mut haystack = Vec::new();
    haystack.extend_from_slice(
        br#""elementary!" 'why?' "no terminal" 'a.' "0123456789012345678901234567890!" "#,
    );
    haystack.extend_from_slice(b"\xff");
    haystack.extend_from_slice(br#" 'restart"then!" "x!" '"#);
    haystack
}

#[test]
fn exact_sherlock_quotes_row_uses_blocking_delimiter() {
    assert_eq!(
        format!("{:x}", Sha256::digest(PATTERN.as_bytes())),
        PATTERN_SHA256
    );
    let haystack = local_quotes_fixture();
    let oracle = RegexBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("pinned Rust regex accepts the exact row pattern");
    let spans: Vec<_> = oracle.find_iter(&haystack).collect();
    let expected_span_sum = spans
        .iter()
        .map(|matched| matched.end() - matched.start())
        .sum::<usize>();

    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[PATTERN.to_owned()],
        false,
        false,
        haystack.len(),
    )
    .expect("exact Sherlock quotes operation lifecycle");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN, "{ROW}");
    assert_eq!(
        lifecycle.execute(&haystack).unwrap(),
        u64::try_from(expected_span_sum).unwrap(),
        "{ROW}"
    );
    assert_eq!(
        lifecycle.execute(&haystack).unwrap(),
        u64::try_from(expected_span_sum).unwrap(),
        "{ROW}"
    );

    let compile = current_fre_rebar_aggregate_compile_lifecycle(
        &[PATTERN.to_owned()],
        false,
        false,
        haystack.len(),
    )
    .expect("exact Sherlock quotes compile lifecycle");
    let artifact = compile
        .construct()
        .expect("exact Sherlock quotes construction");
    assert_eq!(artifact.plan(&compile).unwrap(), COMPILE_PLAN);
    assert_eq!(
        artifact.verify(&compile, &haystack).unwrap(),
        u64::try_from(spans.len()).unwrap()
    );

    let regex = current_fre_rebar_aggregate_builder(PATTERN, false, false)
        .build_span_sum()
        .expect("exact Sherlock quotes facade plan");
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::BlockingDelimiter
    );
    assert_eq!(regex.build_report().schema_version, 40);
    assert!(matches!(
        regex.build_report().plan_identity,
        AggregatePlanIdentity::BlockingDelimiter(_)
    ));
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count-spans")
        .expect("typed blocking-delimiter identity");
}

#[test]
fn adapter_identity_names_the_new_operation_owned_leaf() {
    let identity = CurrentFreAdapter.identity();
    assert!(identity.adapter.contains("blocking-delimiter-v1"));
    assert!(identity.identity.contains("blocking-delimiter-v1"));
    assert!(identity.availability.contains("blocking-delimiter"));
}

#[test]
#[ignore = "requires the separately authenticated Rebar Sherlock corpus"]
fn authenticated_rebar_sherlock_corpus_returns_14437() {
    let path = std::env::var_os("FRE_BLOCKING_DELIMITER_SHERLOCK_HAYSTACK")
        .expect("set FRE_BLOCKING_DELIMITER_SHERLOCK_HAYSTACK");
    let haystack = std::fs::read(path).expect("read authenticated Sherlock corpus");
    assert_eq!(haystack.len(), 594_933);
    assert_eq!(
        format!("{:x}", Sha256::digest(&haystack)),
        "242ec73a70f0a03dcbe007e32038e7deeaee004aaec9a09a07fa322743440fa8"
    );
    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[PATTERN.to_owned()],
        false,
        false,
        haystack.len(),
    )
    .expect("authenticated Sherlock quotes lifecycle");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN, "{ROW}");
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 14_437, "{ROW}");
}
