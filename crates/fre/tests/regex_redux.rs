use fre::{
    AggregateBuildLimits, AggregateRunLimits, RegexReduxBuilder, RegexReduxReplacementPlan,
    RegexReduxRunError, RegexReduxRunLimits, RustProfile,
};

fn replacement(pattern: &str, replacement: &str) -> RegexReduxReplacementPlan {
    RegexReduxReplacementPlan::build(
        pattern,
        replacement,
        RustProfile::rebar_1_12_4(),
        AggregateBuildLimits::default(),
    )
    .unwrap_or_else(|error| panic!("replacement component rejected {pattern:?}: {error}"))
}

#[test]
fn replacement_component_preserves_unmatched_bytes_and_exact_offsets() {
    let plan = replacement(r"a+", "<A>");
    let result = plan
        .replace(b"zaa-xa", RegexReduxRunLimits::default())
        .expect("bounded replacement");
    assert_eq!(result.output(), b"z<A>-x<A>");
    assert_eq!(
        result
            .matches()
            .iter()
            .map(|matched| (matched.start(), matched.end()))
            .collect::<Vec<_>>(),
        vec![(1, 3), (5, 6)]
    );
}

#[test]
fn replacement_leading_literal_does_not_accept_a_late_suffix_only() {
    let plan = replacement(r"\|[^|][^|]*\|", "-");
    let result = plan
        .replace(b"agggtaaatttaccct|t", RegexReduxRunLimits::default())
        .expect("bounded replacement");
    assert!(result.matches().is_empty());
    assert_eq!(result.output(), b"agggtaaatttaccct|t");
}

#[test]
fn non_empty_promise_refuses_empty_matches_after_bounded_progress() {
    let plan = replacement(r"a*", "x");
    assert!(matches!(
        plan.replace(b"b", RegexReduxRunLimits::default()),
        Err(RegexReduxRunError::EmptyMatch {
            stage: "replacement",
            offset: 0,
        })
    ));
}

#[test]
fn complete_small_pipeline_has_exact_report_and_ordered_substitutions() {
    let plan = RegexReduxBuilder::new()
        .profile(RustProfile::rebar_1_12_4())
        .build()
        .expect("complete regex-redux plan");
    let input = b">x\nagggtaaa\ntttaccct\ntHaNt\n";
    let result = plan
        .execute(input, RegexReduxRunLimits::default())
        .expect("complete regex-redux execution");
    assert_eq!(result.input_length(), 27);
    assert_eq!(result.clean_length(), 21);
    assert_eq!(result.final_sequence(), b"agggtaaatttaccct|");
    assert_eq!(result.final_length(), 17);
    assert_eq!(result.variant_counts(), &[2, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        result.report(),
        "agggtaaa|tttaccct 2\n[cgt]gggtaaa|tttaccc[acg] 0\na[act]ggtaaa|tttacc[agt]t 0\nag[act]gtaaa|tttac[agt]ct 0\nagg[act]taaa|ttta[agt]cct 0\naggg[acg]aaa|ttt[cgt]ccct 0\nagggt[cgt]aa|tt[acg]accct 0\nagggta[cgt]a|t[acg]taccct 0\nagggtaa[cgt]|[acg]ttaccct 0\n\n27\n21\n17\n"
    );
}

#[test]
fn stage_order_mutation_is_observable() {
    let introduce = replacement(r"tHa[Nt]", "<4>");
    let collapse = replacement(r"<[^>]*>", "|");
    let limits = RegexReduxRunLimits {
        aggregate: AggregateRunLimits::default(),
        ..RegexReduxRunLimits::default()
    };
    let canonical = introduce.replace(b"tHaNt", limits).expect("introduce");
    let canonical = collapse
        .replace(canonical.output(), limits)
        .expect("collapse after introduce");
    let mutated = collapse.replace(b"tHaNt", limits).expect("early collapse");
    let mutated = introduce
        .replace(mutated.output(), limits)
        .expect("late introduce");
    assert_eq!(canonical.output(), b"|");
    assert_eq!(mutated.output(), b"<4>");
    assert_ne!(canonical.output(), mutated.output());
}

#[test]
fn output_limit_refuses_one_below_before_replacement_allocation() {
    let plan = replacement(r"a", "xyz");
    let limits = RegexReduxRunLimits {
        max_output_bytes: 5,
        ..RegexReduxRunLimits::default()
    };
    assert!(matches!(
        plan.replace(b"aa", limits),
        Err(RegexReduxRunError::OutputBytes {
            required: 6,
            limit: 5,
        })
    ));
}
