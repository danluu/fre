use fre::AggregatePlanKind;
use rebar_compare::{
    CandidateAdapter, CandidateOutcome, CandidateRequest, CurrentFreAdapter, RunLimits,
    current_fre_rebar_aggregate_builder, current_fre_rebar_aggregate_compile_lifecycle,
    current_fre_rebar_aggregate_operation_lifecycle, current_fre_rebar_validate_aggregate_identity,
};

fn execute(pattern: &str, haystack: &[u8], unicode: bool) -> CandidateOutcome {
    CurrentFreAdapter.execute(
        CandidateRequest {
            job_id: "proof/word-run",
            model: "count-spans",
            patterns: &[pattern.to_owned()],
            haystack,
            unicode,
            case_insensitive: false,
        },
        &RunLimits::default(),
    )
}

fn durable_sibling_fixture() -> Vec<u8> {
    let mut haystack = "z".repeat(839);
    haystack.push(' ');
    haystack.push_str(&"α".repeat(1_313));
    haystack.push('a');
    haystack.into_bytes()
}

#[test]
fn durable_word_run_targets_use_the_authenticated_aggregate_route() {
    let haystack = durable_sibling_fixture();
    assert_eq!(
        execute(r"\b\w{12,}\b", &haystack, true),
        CandidateOutcome::ExecutedWithPlan {
            actual: 3_466,
            plan: "aggregate-word-run-v1".to_owned(),
        }
    );

    assert_eq!(
        execute(r"\b\w{12,}\b", &haystack, false),
        CandidateOutcome::ExecutedWithPlan {
            actual: 839,
            plan: "aggregate-word-run-v1".to_owned(),
        }
    );

    for (unicode, expected_sum, expected_count) in [(true, 3_466, 2), (false, 839, 1)] {
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            "count-spans",
            &[r"\b\w{12,}\b".to_owned()],
            unicode,
            false,
            haystack.len(),
        )
        .unwrap();
        assert_eq!(lifecycle.plan(), "aggregate-word-run-v1");
        assert_eq!(lifecycle.execute(&haystack).unwrap(), expected_sum);

        let compile = current_fre_rebar_aggregate_compile_lifecycle(
            &[r"\b\w{12,}\b".to_owned()],
            unicode,
            false,
            haystack.len(),
        )
        .unwrap();
        let artifact = compile.construct().unwrap();
        assert_eq!(
            artifact.plan(&compile).unwrap(),
            "compile-aggregate-word-run-v1"
        );
        assert_eq!(
            artifact.verify(&compile, &haystack).unwrap(),
            expected_count
        );

        let regex = current_fre_rebar_aggregate_builder(r"\b\w{12,}\b", unicode, false)
            .build_span_sum()
            .unwrap();
        assert_eq!(regex.build_report().plan, AggregatePlanKind::WordRun);
        assert_eq!(regex.build_report().schema_version, 34);
        current_fre_rebar_validate_aggregate_identity(regex.build_report(), unicode, "count-spans")
            .unwrap();
    }
}

#[test]
fn adapter_identity_names_the_operation_owned_word_run() {
    let identity = CurrentFreAdapter.identity();
    assert!(identity.adapter.contains("aggregate-word-run-v1"));
    assert!(identity.identity.contains("direct aggregate word-run"));
    assert!(identity.availability.contains("direct word-run"));
}
