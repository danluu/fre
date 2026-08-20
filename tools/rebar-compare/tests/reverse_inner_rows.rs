use fre::{AggregateBuildAccounting, AggregatePlanIdentity, AggregatePlanKind};
use rebar_compare::{
    current_fre_generic_span_sum_run_limits, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_compile_lifecycle, current_fre_rebar_aggregate_operation_lifecycle,
    current_fre_rebar_count_run_limits, current_fre_rebar_validate_aggregate_identity,
    current_fre_validate_generic_span_sum_identity,
};
use regex::bytes::RegexBuilder;

const PATTERN: &str = r"\pL+herloc\pL+|\pL+olme\pL+";
const COMPILE_PLAN: &str = "compile-aggregate-reverse-inner-adaptive-union-v2";
const FORMAL_OPERATION_PLAN: &str = "aggregate-continuation-program";
const INDEPENDENT_PATTERN: &str = r"[a-zλ]+ab[a-zλ]+";
const GROUPED_PATTERN: &str = r"[a-zλ]+(?:aab|abb)[a-zλ]+";

fn fixture() -> Vec<u8> {
    let mut haystack = Vec::new();
    haystack.extend_from_slice(b"sherlock Holmes|near herloc xolmey|\xff|");
    for _ in 0..64 {
        haystack.extend_from_slice(b"SherlockHolmes sherlock holmes|");
    }
    haystack.extend_from_slice("\u{03bb}sherlock\u{03b2}".as_bytes());
    haystack
}

fn expected(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    let oracle = RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .expect("pinned Rust bytes regex accepts the benchmark pattern");
    oracle
        .find_iter(haystack)
        .fold((0_u64, 0_u64), |(count, span_sum), matched| {
            (
                count.checked_add(1).unwrap(),
                span_sum
                    .checked_add(
                        u64::try_from(matched.end().checked_sub(matched.start()).unwrap()).unwrap(),
                    )
                    .unwrap(),
            )
        })
}

#[test]
fn first_and_steady_rows_use_complete_span_lifecycle() {
    let haystack = fixture();
    let expected = expected(PATTERN, &haystack);
    for (model, value) in [("count", expected.0), ("count-spans", expected.1)] {
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            model,
            &[PATTERN.to_string()],
            true,
            false,
            haystack.len(),
        )
        .expect("reverse-inner lifecycle construction");
        assert_eq!(lifecycle.plan(), FORMAL_OPERATION_PLAN);
        assert_eq!(
            lifecycle.execute(&haystack).expect("first operation"),
            value
        );
        assert_eq!(
            lifecycle.execute(&haystack).expect("steady operation"),
            value
        );
    }
}

#[test]
fn independent_and_grouped_rows_keep_direct_and_compile_route_identities() {
    for (pattern, haystack, kernel_plan, compile_plan) in [
        (
            INDEPENDENT_PATTERN,
            b"qabq|xx|\xce\xbbabz|cabd".as_slice(),
            fre::REVERSE_INNER_PLAN_ID,
            "compile-aggregate-reverse-inner-independent-v1",
        ),
        (
            GROUPED_PATTERN,
            b"qaabq|qabbz|xaxb|zaabz".as_slice(),
            fre::REVERSE_INNER_GROUPED_UNION_PLAN_ID,
            "compile-aggregate-reverse-inner-grouped-union-v2",
        ),
    ] {
        let expected = expected(pattern, haystack);
        let count = current_fre_rebar_aggregate_builder(pattern, true, false)
            .build_count()
            .expect("reverse-inner fixture count plan");
        assert_eq!(count.build_report().schema_version, 53);
        let AggregatePlanIdentity::ReverseInner(identity) = count.build_report().plan_identity
        else {
            panic!("reverse-inner fixture retained another identity");
        };
        assert_eq!(identity.kernel.plan_id, kernel_plan);
        current_fre_rebar_validate_aggregate_identity(count.build_report(), true, "count")
            .expect("reverse-inner fixture identity");

        for (model, value) in [("count", expected.0), ("count-spans", expected.1)] {
            let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
                model,
                &[pattern.to_string()],
                true,
                false,
                haystack.len(),
            )
            .expect("reverse-inner fixture lifecycle");
            assert_eq!(lifecycle.plan(), FORMAL_OPERATION_PLAN);
            assert_eq!(lifecycle.execute(haystack).expect("first operation"), value);
            assert_eq!(
                lifecycle.execute(haystack).expect("steady operation"),
                value
            );
        }

        let patterns = [pattern.to_string()];
        let compile =
            current_fre_rebar_aggregate_compile_lifecycle(&patterns, true, false, haystack.len())
                .expect("reverse-inner fixture compile lifecycle");
        let artifact = compile
            .construct()
            .expect("reverse-inner fixture construction");
        assert_eq!(artifact.plan(&compile).unwrap(), compile_plan);
        assert_eq!(artifact.verify(&compile, haystack).unwrap(), expected.0);
    }
}

#[test]
fn compile_and_retained_limit_paths_bind_the_typed_plan() {
    let haystack = fixture();
    let expected = expected(PATTERN, &haystack);
    let patterns = [PATTERN.to_string()];
    let compile =
        current_fre_rebar_aggregate_compile_lifecycle(&patterns, true, false, haystack.len())
            .expect("reverse-inner compile lifecycle");
    let artifact = compile.construct().expect("reverse-inner construction");
    assert_eq!(artifact.plan(&compile).unwrap(), COMPILE_PLAN);
    assert_eq!(artifact.verify(&compile, &haystack).unwrap(), expected.0);

    let count = current_fre_rebar_aggregate_builder(PATTERN, true, false)
        .build_count()
        .expect("count plan");
    assert_eq!(count.build_report().schema_version, 53);
    assert_eq!(count.build_report().plan, AggregatePlanKind::ReverseInner);
    let AggregatePlanIdentity::ReverseInner(identity) = count.build_report().plan_identity else {
        panic!("adaptive reverse-inner plan retained another identity");
    };
    assert_eq!(identity.kernel.plan_id, fre::REVERSE_INNER_UNION_PLAN_ID);
    current_fre_rebar_validate_aggregate_identity(count.build_report(), true, "count")
        .expect("count identity");
    let count_limits =
        current_fre_rebar_count_run_limits(haystack.len(), &count).expect("retained count bounds");
    assert_eq!(
        count.count_value(&haystack, count_limits).unwrap(),
        expected.0
    );

    let span_sum = current_fre_rebar_aggregate_builder(PATTERN, true, false)
        .build_span_sum()
        .expect("span-sum plan");
    current_fre_validate_generic_span_sum_identity(span_sum.build_report(), true, "span-sum")
        .expect("span-sum identity");
    let span_limits = current_fre_generic_span_sum_run_limits(haystack.len(), &span_sum)
        .expect("retained span-sum bounds");
    assert_eq!(
        span_sum.span_sum_value(&haystack, span_limits).unwrap(),
        expected.1
    );
}

#[test]
fn unicode_and_receipt_transplants_fail_closed() {
    let regex = current_fre_rebar_aggregate_builder(PATTERN, true, false)
        .build_count()
        .expect("count plan");
    assert!(
        current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count")
            .is_err()
    );

    let mut forged_identity = regex.build_report().clone();
    let AggregatePlanIdentity::ReverseInner(ref mut identity) = forged_identity.plan_identity
    else {
        panic!("reverse-inner plan retained another identity");
    };
    identity.kernel.literal_fingerprint ^= 1;
    assert!(
        current_fre_rebar_validate_aggregate_identity(&forged_identity, true, "count").is_err()
    );

    let mut forged_build = regex.build_report().clone();
    let AggregateBuildAccounting::ReverseInner(ref mut build) = forged_build.build else {
        panic!("reverse-inner plan retained another build receipt");
    };
    build.literal_bytes += 1;
    assert!(current_fre_rebar_validate_aggregate_identity(&forged_build, true, "count").is_err());
}
