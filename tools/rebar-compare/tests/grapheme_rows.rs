use std::{env, fs, path::PathBuf};

use fre::{AggregateExecutionDetails, AggregatePlanKind};
use rebar_compare::{
    CandidateAdapter, CurrentFreAdapter, current_fre_rebar_aggregate_builder,
    current_fre_rebar_aggregate_run_limits, current_fre_rebar_validate_aggregate_identity,
};

const ADAPTER: &str = "fre-current-aggregate-capture-v19-portable-word-run-v2-unicode-scalar-run-v4-capture-scalar-alternation-v1-finite-dfa-v2-sparse-v1-fixed-class-sandwich-v1-grapheme-scalar-dfa-v1-bounded-class-sequence-v1-casefold-canonical-bytes-v1-prefix-class-alt-v1-bounded-context-v1-bounded-affix-v1-uniform-participation-v1-structural-quota-v8";

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

#[test]
fn adapter_runner_and_typed_plan_identity_agree() {
    let adapter = CurrentFreAdapter;
    assert_eq!(adapter.adapter(), ADAPTER);
    assert_eq!(adapter.identity().adapter, ADAPTER);
    assert!(
        include_str!("../examples/fre_rebar_runner.rs")
            .contains(&format!("adapter={ADAPTER} report="))
    );

    let regex = current_fre_rebar_aggregate_builder(GRAPHEME, true, false)
        .build_count()
        .unwrap();
    assert_eq!(
        regex.build_report().plan,
        AggregatePlanKind::GraphemeScalarDfa
    );
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
