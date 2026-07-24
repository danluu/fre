use std::{env, fs, path::PathBuf};

use fre::{
    AggregateExecutionDetails, AggregatePlanIdentity, AggregatePlanKind,
    GraphemeScalarDfaOperation, GraphemeScalarDfaOperationIdentity,
};
use rebar_compare::{
    CandidateAdapter, CurrentFreAdapter, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_run_limits, current_fre_rebar_validate_aggregate_identity,
};

const ADAPTER: &str = "fre-current-aggregate-capture-v29-terminal-class-frontier-v1-required-literal-v2-noqa-v1-portable-word-run-v2-aggregate-word-run-v1-literal-assertions-v1-unicode-scalar-run-v4-capture-scalar-alternation-v1-line-space-operator-v2-line-configured-ruff-three-v1-line-ascii-separated-fields-v1-finite-dfa-v2-sparse-v1-guarded-ascii-word-v1-fixed-class-sandwich-v1-literal-class-run-literal-v1-bounded-literal-pair-v1-grapheme-scalar-dfa-v2-bounded-class-sequence-v1-bounded-separated-fields-v1-casefold-canonical-bytes-v1-prefix-class-alt-v1-bounded-context-v1-bounded-affix-v1-uniform-participation-v1-capture-count-v3-ordered-root-count-v1-continuation-accounting-v3-uniform-prefix-class-participation-v2-required-internal-anchor-v3-structural-quota-v8-regex-redux-composite-v2-url-aggregate-v1-fixed-absolute-domain-v1-terminal-greedy-class-v1";

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

#[test]
fn adapter_runner_and_typed_plan_identity_agree() {
    let (grapheme_segment, typed_count) = typed_grapheme_adapter_segment();
    assert_eq!(ADAPTER.matches(&grapheme_segment).count(), 1);
    let adapter = CurrentFreAdapter;
    assert_eq!(adapter.adapter(), ADAPTER);
    assert_eq!(adapter.identity().adapter, ADAPTER);
    let runner = include_str!("../examples/fre_rebar_runner.rs");
    assert_eq!(
        runner
            .matches(&format!("adapter={ADAPTER} report="))
            .count(),
        1,
    );
    assert_eq!(runner.matches("aggregate-explain=29").count(), 1);
    assert!(!runner.contains("aggregate-explain=23"));
    assert_eq!(
        runner
            .matches("current_fre_rebar_count_run_limits(")
            .count(),
        1
    );
    assert_eq!(
        runner
            .matches("current_fre_rebar_span_sum_run_limits(")
            .count(),
        1
    );

    let regex = current_fre_rebar_aggregate_builder(GRAPHEME, true, false)
        .build_count()
        .unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );
    let AggregatePlanIdentity::GraphemeScalarDfa(identity) = regex.build_report().plan_identity
    else {
        panic!("expected typed grapheme identity")
    };
    assert_eq!(identity.kernel, typed_count);
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), true, "count").unwrap();
    assert!(
        current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count")
            .is_err()
    );
}

#[test]
#[ignore = "set FRE_GRAPHEME_BENCHMARK_ROOT to an authenticated Rebar benchmarks directory"]
fn authenticated_supported_grapheme_rows_are_exact_and_bounded() {
    let root = PathBuf::from(env::var_os("FRE_GRAPHEME_BENCHMARK_ROOT").unwrap());
    let pattern = fs::read_to_string(root.join("regexes/wild/grapheme.txt")).unwrap();
    let regex = current_fre_rebar_aggregate_builder(&pattern, true, false)
        .build_count()
        .unwrap();
    assert_eq!(
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
        let AggregateExecutionDetails::GraphemeScalarDfa(accounting) = &result.report().details
        else {
            panic!("{relative} used another execution plan");
        };
        assert!(accounting.upper_bounds.work <= 536_870_912, "{relative}");
        assert_eq!(accounting.actual.count, expected, "{relative}");
    }
}
