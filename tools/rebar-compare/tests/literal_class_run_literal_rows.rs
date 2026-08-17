use fre::{AggregatePlanIdentity, AggregatePlanKind, LiteralClassRunLiteralBoundarySemantics};
use rebar_compare::{
    current_fre_rebar_aggregate_builder, current_fre_rebar_aggregate_compile_lifecycle,
    current_fre_rebar_aggregate_operation_lifecycle, current_fre_rebar_validate_aggregate_identity,
    current_fre_validate_generic_span_sum_identity,
};
use regex::bytes::RegexBuilder;

const PATTERN: &str = r"Sherlock\s+Holmes";
const GUARDED_PATTERN: &str = r"\b\w+nn\b";
const COMPILE_PLAN: &str = "compile-aggregate-literal-class-run-literal-v2";
const OPERATION_PLAN: &str = "aggregate-literal-class-run-literal-v2";
const REBAR_COUNT_SPANS_PLAN: &str = "aggregate-continuation-program";
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
    assert_eq!(lifecycle.plan(), REBAR_COUNT_SPANS_PLAN);

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
    assert_eq!(regex.build_report().schema_version, 50);
    current_fre_validate_generic_span_sum_identity(regex.build_report(), false, "span-sum")
        .expect("typed route identity");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one authenticated test keeps the three one-sided layouts and their boundary-identity forgery adjacent"
)]
fn one_sided_class_suffix_rows_bind_the_typed_plan() {
    const PATTERN: &str = r"[a-zA-Z]+ing";
    let haystack = b"ing thing thinging x-ing aaining";
    let oracle = RegexBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("pinned Rust regex accepts the one-sided pattern");
    let expected_count = oracle.find_iter(haystack).count();
    let expected_span_sum = oracle
        .find_iter(haystack)
        .map(|matched| matched.end() - matched.start())
        .sum::<usize>();

    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count",
        &[PATTERN.to_string()],
        false,
        false,
        haystack.len(),
    )
    .expect("one-sided count lifecycle construction");
    assert_eq!(lifecycle.plan(), OPERATION_PLAN);
    assert_eq!(
        lifecycle.execute(haystack).expect("one-sided count"),
        u64::try_from(expected_count).unwrap()
    );

    let regex = current_fre_rebar_aggregate_builder(PATTERN, false, false)
        .build_span_sum()
        .expect("one-sided span-sum construction");
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    let AggregatePlanIdentity::LiteralClassRunLiteral(identity) =
        regex.build_report().plan_identity
    else {
        panic!("one-sided span-sum retained another identity");
    };
    assert_eq!(
        identity.kernel.boundary_semantics,
        LiteralClassRunLiteralBoundarySemantics::Unguarded
    );
    assert_eq!(identity.kernel.prefix_bytes, 0);
    assert_eq!(identity.kernel.suffix_bytes, 3);
    current_fre_validate_generic_span_sum_identity(regex.build_report(), false, "span-sum")
        .expect("one-sided typed route identity");
    let mut forged = regex.build_report().clone();
    let AggregatePlanIdentity::LiteralClassRunLiteral(ref mut forged_identity) =
        forged.plan_identity
    else {
        panic!("one-sided span-sum retained another identity");
    };
    forged_identity.kernel.boundary_semantics =
        LiteralClassRunLiteralBoundarySemantics::CompleteAsciiWordRun;
    assert!(
        current_fre_validate_generic_span_sum_identity(&forged, false, "span-sum").is_err(),
        "guarded boundary semantics must not authenticate an unguarded one-sided plan"
    );
    assert_eq!(
        regex
            .span_sum_value(haystack, fre::AggregateRunLimits::default())
            .unwrap(),
        u64::try_from(expected_span_sum).unwrap()
    );

    for (pattern, haystack) in [
        (r"item[0-9]+", b"item item1 item22 xitem333".as_slice()),
        (r"[0-9]+X5", b"1X567X5--X5--90X5".as_slice()),
    ] {
        let oracle = RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .expect("pinned Rust regex accepts the one-sided pattern");
        let expected_count = u64::try_from(oracle.find_iter(haystack).count()).unwrap();
        let expected_span_sum = oracle
            .find_iter(haystack)
            .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
            .sum::<u64>();

        let count = current_fre_rebar_aggregate_builder(pattern, false, false)
            .build_count()
            .expect("one-sided count construction");
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::LiteralClassRunLiteral
        );
        current_fre_rebar_validate_aggregate_identity(count.build_report(), false, "count")
            .expect("one-sided count identity");
        assert_eq!(
            count
                .count_value(haystack, fre::AggregateRunLimits::default())
                .unwrap(),
            expected_count
        );

        let spans = current_fre_rebar_aggregate_builder(pattern, false, false)
            .build_span_sum()
            .expect("one-sided span-sum construction");
        assert_eq!(
            spans.build_report().plan,
            AggregatePlanKind::LiteralClassRunLiteral
        );
        current_fre_validate_generic_span_sum_identity(spans.build_report(), false, "span-sum")
            .expect("one-sided span-sum identity");
        assert_eq!(
            spans
                .span_sum_value(haystack, fre::AggregateRunLimits::default())
                .unwrap(),
            expected_span_sum
        );
    }
}

fn guarded_expected(haystack: &[u8]) -> (u64, u64) {
    let oracle = RegexBuilder::new(GUARDED_PATTERN)
        .unicode(false)
        .build()
        .expect("pinned Rust regex accepts the guarded benchmark pattern");
    let spans: Vec<_> = oracle.find_iter(haystack).collect();
    let expected_count = u64::try_from(spans.len()).unwrap();
    let expected_span_sum = spans
        .iter()
        .map(|matched| {
            u64::try_from(
                matched
                    .end()
                    .checked_sub(matched.start())
                    .expect("ordered match span"),
            )
            .unwrap()
        })
        .sum::<u64>();
    (expected_count, expected_span_sum)
}

fn assert_guarded_operation_lifecycle(model: &str, haystack: &[u8], expected: u64) {
    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        model,
        &[GUARDED_PATTERN.to_string()],
        false,
        false,
        haystack.len(),
    )
    .expect("guarded operation lifecycle construction");
    let expected_plan = if model == "count-spans" {
        REBAR_COUNT_SPANS_PLAN
    } else {
        OPERATION_PLAN
    };
    assert_eq!(lifecycle.plan(), expected_plan);
    assert_eq!(
        lifecycle.execute(haystack).unwrap(),
        expected,
        "guarded {model} lifecycle"
    );
}

fn assert_guarded_compile_lifecycle(haystack: &[u8], expected_count: u64) {
    let patterns = [GUARDED_PATTERN.to_string()];
    let compile =
        current_fre_rebar_aggregate_compile_lifecycle(&patterns, false, false, haystack.len())
            .expect("guarded compile lifecycle");
    let artifact = compile.construct().expect("guarded compile construction");
    assert_eq!(artifact.plan(&compile).unwrap(), COMPILE_PLAN);
    assert_eq!(artifact.verify(&compile, haystack).unwrap(), expected_count);
}

#[derive(Clone, Copy)]
enum GuardedIdentityForgery {
    BoundarySemantics,
    ClassWords,
    StaleAlgorithm,
}

fn assert_guarded_identity_forgery_rejected(
    report: &fre::AggregateBuildReport,
    forgery: GuardedIdentityForgery,
) {
    let mut forged = report.clone();
    let AggregatePlanIdentity::LiteralClassRunLiteral(ref mut identity) = forged.plan_identity
    else {
        panic!("guarded plan retained another identity");
    };
    match forgery {
        GuardedIdentityForgery::BoundarySemantics => {
            identity.kernel.boundary_semantics = LiteralClassRunLiteralBoundarySemantics::Unguarded;
        }
        GuardedIdentityForgery::ClassWords => identity.kernel.class_words[0] ^= 1,
        GuardedIdentityForgery::StaleAlgorithm => {
            identity.kernel.plan_id = "literal-class-run-literal.maximal-byte-run.v3";
            identity.kernel.operation_id = "literal-class-run-literal.count.unicode-off.v3";
        }
    }
    assert!(current_fre_rebar_validate_aggregate_identity(&forged, false, "count").is_err());
}

fn assert_guarded_identity_authentication_and_near_misses() {
    let count = current_fre_rebar_aggregate_builder(GUARDED_PATTERN, false, false)
        .build_count()
        .expect("guarded count plan");
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::LiteralClassRunLiteral
    );
    assert_eq!(count.build_report().schema_version, 50);
    let AggregatePlanIdentity::LiteralClassRunLiteral(identity) =
        count.build_report().plan_identity
    else {
        panic!("guarded plan retained another identity");
    };
    assert_eq!(
        identity.kernel.boundary_semantics,
        LiteralClassRunLiteralBoundarySemantics::CompleteAsciiWordRun
    );
    assert_eq!(identity.kernel.prefix_bytes, 0);
    assert_eq!(identity.kernel.suffix_bytes, 2);
    assert_eq!(
        identity.kernel.plan_id,
        fre::LITERAL_CLASS_RUN_LITERAL_PLAN_ID
    );
    assert_eq!(
        identity.kernel.operation_id,
        fre::LITERAL_CLASS_RUN_LITERAL_COUNT_OPERATION_ID
    );
    current_fre_rebar_validate_aggregate_identity(count.build_report(), false, "count")
        .expect("guarded typed route identity");

    for forgery in [
        GuardedIdentityForgery::BoundarySemantics,
        GuardedIdentityForgery::ClassWords,
        GuardedIdentityForgery::StaleAlgorithm,
    ] {
        assert_guarded_identity_forgery_rejected(count.build_report(), forgery);
    }

    for pattern in [r"\B\w+nn\b", r"\b\w+nn\B", r"\b[a-z]+nn\b", r"\b\w+?nn\b"] {
        let near_miss = current_fre_rebar_aggregate_builder(pattern, false, false)
            .build_count()
            .expect("near-miss fallback construction");
        assert_ne!(
            near_miss.build_report().plan,
            AggregatePlanKind::LiteralClassRunLiteral,
            "pattern={pattern:?}"
        );
    }
}

#[test]
fn guarded_ascii_word_suffix_lifecycle_authenticates_and_stale_identities_fail_closed() {
    let haystack = b"nn nnn!_nn \xffann\x80nnn! znnn? nn";
    let (expected_count, expected_span_sum) = guarded_expected(haystack);
    assert_eq!((expected_count, expected_span_sum), (5, 16));
    assert_guarded_operation_lifecycle("count", haystack, expected_count);
    assert_guarded_operation_lifecycle("count-spans", haystack, expected_span_sum);
    assert_guarded_compile_lifecycle(haystack, expected_count);
    assert_guarded_identity_authentication_and_near_misses();
}
