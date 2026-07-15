use fre::{
    AggregateBuilder, AggregateExecutionDetails, AggregateExecutionSource, AggregateOperation,
    AggregatePlanKind, AggregateRunLimits, AggregateStrategy, OrderedLiteralAggregateReduceError,
    RustProfile,
};

fn builder(pattern: impl Into<String>) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
}

fn oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    let spans = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    (
        u64::try_from(spans.len()).unwrap(),
        spans
            .iter()
            .map(|(start, end)| u64::try_from(end - start).unwrap())
            .sum(),
    )
}

#[test]
fn finite_dfa_preserves_order_empty_progress_captures_and_arbitrary_bytes() {
    let cases: [(&str, &[u8]); 5] = [
        (r"(?:ab|a|)", b"aba"),
        (r"(?:|a)", b"aaa"),
        (r"(?P<whole>(?:\xFFa|\xFF|b))", &[0xFF, b'a', 0xFF, b'b']),
        (r"(?i:(?:sherlock|holmes))", b"SHERLOCK x Holmes"),
        (r"(?:early|late)", b"early---late"),
    ];
    for (pattern, haystack) in cases {
        let expected = oracle(pattern, haystack);
        let count = builder(pattern).build_count().unwrap();
        assert_eq!(count.build_report().plan, AggregatePlanKind::FiniteLiteralDfa);
        assert_eq!(count.build_report().continuation_strategy, None);
        assert_eq!(count.count_value(haystack, AggregateRunLimits::default()).unwrap(), expected.0);
        let sum = builder(pattern).build_span_sum().unwrap();
        assert_eq!(sum.build_report().plan, AggregatePlanKind::FiniteLiteralDfa);
        assert_eq!(sum.span_sum_value(haystack, AggregateRunLimits::default()).unwrap(), expected.1);
    }
}

#[test]
fn finite_dfa_compile_identity_and_exact_debit_are_operation_owned() {
    let pattern = r"(?P<word>cat|dog|)";
    let compiled = builder(pattern).build_compile().unwrap();
    assert_eq!(compiled.build_report().operation, AggregateOperation::Compile);
    assert_eq!(compiled.build_report().plan, AggregatePlanKind::FiniteLiteralDfa);
    assert_eq!(compiled.build_report().captures_erased, 1);
    assert!(compiled.build_report().finite_planner_work > 0);
    let haystack = b"cat xx dog";
    let baseline = compiled
        .verify_count(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FiniteLiteral {
        upper_bounds,
        actual,
    } = &baseline.report().details
    else {
        panic!("finite compile artifact executed another plan")
    };
    assert_eq!(actual.transitions, haystack.len());
    assert_eq!(actual.reducer_steps, haystack.len() + 1);
    assert!(actual.total_work <= upper_bounds.total_work);

    let mut limits = AggregateRunLimits::default();
    limits.finite_literal.max_total_work = actual.total_work - 1;
    let error = compiled.verify_count(haystack, limits).unwrap_err();
    assert!(matches!(
        error.source,
        AggregateExecutionSource::FiniteLiteral(
            OrderedLiteralAggregateReduceError::TotalWorkLimit { .. }
        )
    ));
}

fn alternation(count: usize) -> String {
    let mut pattern = String::from("(?:");
    for index in 0..count {
        if index != 0 {
            pattern.push('|');
        }
        pattern.push_str(&format!("p{index:03}"));
    }
    pattern.push(')');
    pattern
}

fn counters(patterns: usize, input: usize) -> (usize, usize, usize) {
    let regex = builder(alternation(patterns)).build_count().unwrap();
    let haystack = vec![0xFF; input];
    let result = regex
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FiniteLiteral { actual, .. } = &result.report().details else {
        panic!("finite scaling case executed another plan")
    };
    (actual.transitions, actual.reducer_steps, actual.total_work)
}

#[test]
fn finite_dfa_n_2n_and_query_scaling_rejects_input_times_alternatives() {
    let n = 8_192;
    let q16_n = counters(16, n);
    let q64_n = counters(64, n);
    let q16_2n = counters(16, 2 * n);
    let q64_2n = counters(64, 2 * n);

    assert_eq!(q16_n.0, n);
    assert_eq!(q64_n.0, n);
    assert_eq!(q16_2n.0, 2 * n);
    assert_eq!(q64_2n.0, 2 * n);
    assert_eq!(q16_n.1, n + 1);
    assert_eq!(q64_n.1, n + 1);
    assert_eq!(q16_2n.1, 2 * n + 1);
    assert_eq!(q64_2n.1, 2 * n + 1);
    assert_eq!(q16_n.2, q64_n.2);
    assert_eq!(q16_2n.2, q64_2n.2);
    assert!(q16_2n.2 < 2 * q16_n.2 + 8);
}

#[test]
fn spans_anchors_and_unbounded_neighbors_keep_the_continuation_route() {
    for pattern in [r"(?:cat|dog)", r"\A(?:cat|dog)\z", r"(?:cat|dog)+"] {
        let regex = builder(pattern)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_spans()
            .unwrap();
        assert_eq!(regex.build_report().plan, AggregatePlanKind::ContinuationProgram);
    }
    for pattern in [r"\A(?:cat|dog)\z", r"(?:cat|dog)+"] {
        let regex = builder(pattern).build_count().unwrap();
        assert_eq!(regex.build_report().plan, AggregatePlanKind::ContinuationProgram);
    }
}
