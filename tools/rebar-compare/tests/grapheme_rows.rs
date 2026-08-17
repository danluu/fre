use std::{env, fs, path::PathBuf};

use fre::{
    AggregateBuilder, AggregateExecutionDetails, AggregatePlanIdentity, AggregatePlanKind,
    GraphemeScalarDfaOperation, GraphemeScalarDfaOperationIdentity, RustProfile,
};
use rebar_compare::{
    CandidateAdapter, CurrentFreAdapter, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_run_limits, current_fre_rebar_validate_aggregate_identity,
};

const ADAPTER: &str = rebar_compare::current_fre_adapter_id();

const GRAPHEME: &str = r"(?x)
\p{gcb=CR} \p{gcb=LF}
|
\p{gcb=Control}
|
\p{gcb=Prepend}*
(
  (
    (\p{gcb=L}* (\p{gcb=V}+ | \p{gcb=LV} \p{gcb=V}* | \p{gcb=LVT}) \p{gcb=T}*)
    |
    \p{gcb=L}+
    |
    \p{gcb=T}+
  )
  |
  \p{gcb=RI} \p{gcb=RI}
  |
  \p{Extended_Pictographic} (\p{gcb=Extend}* \p{gcb=ZWJ} \p{Extended_Pictographic})*
  |
  [^\p{gcb=Control} \p{gcb=CR} \p{gcb=LF}]
)
[\p{gcb=Extend} \p{gcb=ZWJ} \p{gcb=SpacingMark}]*
|
\p{Any}
";

fn typed_grapheme_adapter_segment() -> (String, GraphemeScalarDfaOperationIdentity) {
    fn version(identity: &str) -> &str {
        identity
            .rsplit_once(".v")
            .map(|(_, version)| version)
            .expect("grapheme identity must end in a version")
    }

    let count =
        GraphemeScalarDfaOperationIdentity::for_operation(GraphemeScalarDfaOperation::Count);
    let span_sum =
        GraphemeScalarDfaOperationIdentity::for_operation(GraphemeScalarDfaOperation::SpanSum);
    assert_eq!(
        (
            count.plan_id,
            count.operation_id,
            span_sum.plan_id,
            span_sum.operation_id,
        ),
        (
            "grapheme-scalar-dfa.utf8-role-transitions.v2",
            "grapheme-scalar-dfa.count.non-overlapping.v2",
            "grapheme-scalar-dfa.utf8-role-transitions.v2",
            "grapheme-scalar-dfa.span-sum.non-overlapping.v2",
        )
    );
    let plan_version = version(count.plan_id);
    assert_eq!(plan_version, version(count.operation_id));
    assert_eq!(plan_version, version(span_sum.plan_id));
    assert_eq!(plan_version, version(span_sum.operation_id));
    assert_eq!(plan_version, "2");
    (format!("grapheme-scalar-dfa-v{plan_version}"), count)
}

fn assert_formal_adapter_quarantines_grapheme_intrinsic_and_matches_oracle() {
    let (grapheme_segment, typed_count) = typed_grapheme_adapter_segment();
    assert_eq!(ADAPTER.matches(&grapheme_segment).count(), 1);
    let adapter = CurrentFreAdapter;
    assert_eq!(adapter.adapter(), ADAPTER);
    assert_eq!(adapter.identity().adapter, ADAPTER);
    assert!(
        adapter
            .identity()
            .identity
            .contains("formal-workload-intrinsic-quarantine-v1")
    );

    let generic = AggregateBuilder::new(GRAPHEME)
        .profile(RustProfile::rebar_1_12_4())
        .build_count()
        .unwrap();
    assert_eq!(
        generic.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );
    let AggregatePlanIdentity::GraphemeScalarDfa(identity) = generic.build_report().plan_identity
    else {
        panic!("expected typed grapheme identity")
    };
    assert_eq!(identity.kernel, typed_count);

    let regex = current_fre_rebar_aggregate_builder(GRAPHEME, true, false)
        .build_count()
        .unwrap();
    assert!(
        !regex
            .build_report()
            .build_limits
            .continuation
            .allow_workload_specific_intrinsics
    );
    assert_ne!(
        regex.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );
    assert!(!matches!(
        regex.build_report().plan_identity,
        AggregatePlanIdentity::GraphemeScalarDfa(_)
    ));
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), true, "count").unwrap();
    assert!(
        current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count")
            .is_err()
    );

    let haystack = "\r\n\u{0300}\u{1F1E6}\u{1F1E7}a\u{0300}".as_bytes();
    let oracle = regex::bytes::RegexBuilder::new(GRAPHEME)
        .unicode(true)
        .build()
        .unwrap();
    let expected = u64::try_from(oracle.find_iter(haystack).count()).unwrap();
    let limits =
        current_fre_rebar_aggregate_run_limits(haystack.len(), regex.build_report()).unwrap();
    let result = regex.count(haystack, limits).unwrap();
    assert_eq!(result.value(), expected);
    assert!(!matches!(
        result.report().details(),
        AggregateExecutionDetails::GraphemeScalarDfa(_)
    ));
}

#[test]
fn formal_adapter_quarantines_grapheme_intrinsic_and_matches_oracle() {
    std::thread::Builder::new()
        .name("formal-rebar-grapheme-quarantine".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(assert_formal_adapter_quarantines_grapheme_intrinsic_and_matches_oracle)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
#[ignore = "set FRE_GRAPHEME_BENCHMARK_ROOT to an authenticated Rebar benchmarks directory"]
fn authenticated_grapheme_rows_use_generic_execution() {
    let root = PathBuf::from(env::var_os("FRE_GRAPHEME_BENCHMARK_ROOT").unwrap());
    let pattern = fs::read_to_string(root.join("regexes/wild/grapheme.txt")).unwrap();
    let regex = current_fre_rebar_aggregate_builder(&pattern, true, false)
        .build_count()
        .unwrap();
    assert_ne!(
        regex.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), true, "count").unwrap();

    for (relative, expected) in [
        ("haystacks/unicode/allcodepoints.txt", 1_109_104_u64),
        ("haystacks/rust-src-tools-3b0d4813.txt", 7_382_210_u64),
    ] {
        let haystack = fs::read(root.join(relative)).unwrap();
        let limits =
            current_fre_rebar_aggregate_run_limits(haystack.len(), regex.build_report()).unwrap();
        let result = regex.count(&haystack, limits).unwrap();
        assert_eq!(result.value(), expected, "{relative}");
        assert!(!matches!(
            result.report().details(),
            AggregateExecutionDetails::GraphemeScalarDfa(_)
        ));
    }
}
