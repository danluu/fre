use fre::{AggregatePlanIdentity, AggregatePlanKind, WordRunTopology};
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
        let AggregatePlanIdentity::WordRun(identity) = regex.build_report().plan_identity else {
            panic!("explicit word run retained another identity");
        };
        assert_eq!(
            identity.kernel.topology,
            WordRunTopology::CompleteWordBoundaries
        );
        assert!(identity.kernel.complete_word_boundaries);
        assert_eq!(regex.build_report().schema_version, 43);
        current_fre_rebar_validate_aggregate_identity(regex.build_report(), unicode, "count-spans")
            .unwrap();
    }
}

#[test]
fn bare_greedy_word_repetitions_use_the_authenticated_aggregate_route() {
    let ascii_haystack = b"\xffone two_2 \x80x";
    for (model, expected) in [("count", 3), ("count-spans", 9)] {
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            model,
            &[r"\w+".to_owned()],
            false,
            false,
            ascii_haystack.len(),
        )
        .unwrap();
        assert_eq!(lifecycle.plan(), "aggregate-word-run-v1");
        assert_eq!(lifecycle.execute(ascii_haystack).unwrap(), expected);
    }

    let unicode_haystack = b"\xe9\x9b\xaa abc \xff \xce\x94";
    for (model, expected) in [("count", 3), ("count-spans", 8)] {
        let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
            model,
            &[r"\w+".to_owned()],
            true,
            false,
            unicode_haystack.len(),
        )
        .unwrap();
        assert_eq!(lifecycle.plan(), "aggregate-unicode-scalar-class");
        assert_eq!(lifecycle.execute(unicode_haystack).unwrap(), expected);
    }

    let minimum = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[r"\w{2,}".to_owned()],
        false,
        false,
        b"a bc def".len(),
    )
    .unwrap();
    assert_eq!(minimum.plan(), "aggregate-word-run-v1");
    assert_eq!(minimum.execute(b"a bc def").unwrap(), 5);

    let bare = current_fre_rebar_aggregate_builder(r"(\w+)", false, false)
        .build_span_sum()
        .unwrap();
    let AggregatePlanIdentity::WordRun(identity) = bare.build_report().plan_identity else {
        panic!("bare ASCII word run retained another identity");
    };
    assert_eq!(identity.kernel.topology, WordRunTopology::BareGreedyRoot);
    assert!(!identity.kernel.complete_word_boundaries);
    current_fre_rebar_validate_aggregate_identity(bare.build_report(), false, "count-spans")
        .unwrap();

    for pattern in [r"\w+?", r"\w{1,3}"] {
        let regex = current_fre_rebar_aggregate_builder(pattern, false, false)
            .build_span_sum()
            .unwrap();
        assert_ne!(regex.build_report().plan, AggregatePlanKind::WordRun);
    }
}

#[test]
fn adapter_identity_names_the_operation_owned_word_run() {
    let identity = CurrentFreAdapter.identity();
    assert!(identity.adapter.contains("aggregate-word-run-v1"));
    assert!(identity.identity.contains("direct aggregate word-run"));
    assert!(identity.availability.contains("direct word-run"));
}

#[test]
fn i1095_ascii_search_uses_authenticated_fixed_class_chunks() {
    let pattern = r"[0-9A-Za-z_]{256}";
    let haystack = vec![b'b'; 256];
    assert_eq!(
        CurrentFreAdapter.execute(
            CandidateRequest {
                job_id: "reported/i1095-word-repetition/ascii-search",
                model: "count-spans",
                patterns: &[pattern.to_owned()],
                haystack: &haystack,
                unicode: false,
                case_insensitive: false,
            },
            &RunLimits::default(),
        ),
        CandidateOutcome::ExecutedWithPlan {
            actual: 256,
            plan: "aggregate-fixed-class-chunks-v1".to_owned(),
        }
    );

    let lifecycle = current_fre_rebar_aggregate_operation_lifecycle(
        "count-spans",
        &[pattern.to_owned()],
        false,
        false,
        haystack.len(),
    )
    .unwrap();
    assert_eq!(lifecycle.plan(), "aggregate-fixed-class-chunks-v1");
    assert_eq!(lifecycle.execute(&haystack).unwrap(), 256);

    let compile = current_fre_rebar_aggregate_compile_lifecycle(
        &[pattern.to_owned()],
        false,
        false,
        haystack.len(),
    )
    .unwrap();
    let artifact = compile.construct().unwrap();
    assert_eq!(
        artifact.plan(&compile).unwrap(),
        "compile-aggregate-fixed-class-chunks-v1"
    );
    assert_eq!(artifact.verify(&compile, &haystack).unwrap(), 1);

    let regex = current_fre_rebar_aggregate_builder(pattern, false, false)
        .build_span_sum()
        .unwrap();
    assert_eq!(regex.build_report().plan, AggregatePlanKind::WordRun);
    let fre::AggregatePlanIdentity::WordRun(identity) = regex.build_report().plan_identity else {
        panic!("i1095 ASCII search retained another identity");
    };
    assert_eq!(
        identity.semantics,
        fre::AggregateWordRunSemantics::UnicodeOffFixedWidthByteClassChunks
    );
    assert_eq!(identity.kernel.fixed_chunk_bytes, Some(256));
    assert_eq!(identity.kernel.plan_id, fre::FIXED_CLASS_CHUNKS_PLAN_ID);
    assert_eq!(identity.kernel.topology, WordRunTopology::FixedClassChunks);
    assert!(!identity.kernel.complete_word_boundaries);
    current_fre_rebar_validate_aggregate_identity(regex.build_report(), false, "count-spans")
        .unwrap();

    let adapter = CurrentFreAdapter.identity();
    assert!(adapter.identity.contains("fixed-class-chunks-v1"));
    assert!(adapter.availability.contains("fixed-class chunk reducer"));
}
