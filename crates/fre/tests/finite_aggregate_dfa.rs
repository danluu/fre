use std::fmt::Write as _;

use fre::{
    AGGREGATE_EXPLAIN_SCHEMA_VERSION, AggregateBuildError, AggregateBuildLimits, AggregateBuilder,
    AggregateExecutionDetails, AggregateExecutionSource, AggregateFiniteLiteralSemantics,
    AggregateOperation, AggregatePlanIdentity, AggregatePlanKind, AggregateRunLimits,
    AggregateStrategy, OrderedLiteralAggregateReduceError, RustProfile,
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
            .map(|(start, end)| u64::try_from(end.checked_sub(*start).unwrap()).unwrap())
            .sum(),
    )
}

fn unicode_builder(pattern: impl Into<String>) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(true)
}

fn unicode_oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    let spans = regex::bytes::RegexBuilder::new(pattern)
        .unicode(true)
        .build()
        .unwrap()
        .find_iter(haystack)
        .map(|matched| (matched.start(), matched.end()))
        .collect::<Vec<_>>();
    (
        u64::try_from(spans.len()).unwrap(),
        spans
            .iter()
            .map(|(start, end)| u64::try_from(end.checked_sub(*start).unwrap()).unwrap())
            .sum(),
    )
}

#[test]
fn unicode_finite_dfa_matches_upstream_on_nonempty_utf8_words_and_malformed_input() {
    let cases = [
        (
            r"(?:∞|✓)",
            b"\xFF--\xE2\x88\x9E--\xE2\x9C\x93--\x80".as_slice(),
        ),
        (
            r"(?:Шерлок Холмс|Джон Уотсон)",
            "x Шерлок Холмс / Джон Уотсон".as_bytes(),
        ),
        (r"(?i:δ|ω)", "δ Δ ω Ω".as_bytes()),
        (r"(?P<word>é|雪)", "é/雪".as_bytes()),
        (r"é|éx", "éx".as_bytes()),
    ];
    for (pattern, haystack) in cases {
        let expected = unicode_oracle(pattern, haystack);
        let count = unicode_builder(pattern).build_count().unwrap();
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::FiniteLiteralDfa
        );
        assert!(matches!(
            count.build_report().plan_identity,
            AggregatePlanIdentity::FiniteLiteral(identity)
                if identity.semantics
                    == AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
        ));
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.0,
            "count pattern={pattern:?} haystack={haystack:?}"
        );
        let sum = unicode_builder(pattern).build_span_sum().unwrap();
        assert_eq!(sum.build_report().plan, AggregatePlanKind::FiniteLiteralDfa);
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.1,
            "span sum pattern={pattern:?} haystack={haystack:?}"
        );
    }
}

#[test]
fn unicode_finite_dfa_rejects_empty_and_locally_raw_byte_languages() {
    for pattern in [r"(?:|é)", r"(?-u:\xFF)|é"] {
        let built = unicode_builder(pattern).build_count().unwrap();
        assert_eq!(
            built.build_report().plan,
            AggregatePlanKind::ContinuationProgram,
            "pattern={pattern:?}"
        );
        assert!(built.build_report().finite_planner_work > 0);
    }
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
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::FiniteLiteralDfa
        );
        assert_eq!(count.build_report().continuation_strategy, None);
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.0
        );
        let sum = builder(pattern).build_span_sum().unwrap();
        assert_eq!(sum.build_report().plan, AggregatePlanKind::FiniteLiteralDfa);
        assert_eq!(
            sum.span_sum_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.1
        );
    }
}

#[test]
fn finite_dfa_compile_identity_and_exact_debit_are_operation_owned() {
    let pattern = r"(?P<word>cat|dog|)";
    let compiled = builder(pattern).build_compile().unwrap();
    assert_eq!(
        compiled.build_report().operation,
        AggregateOperation::Compile
    );
    assert_eq!(
        compiled.build_report().plan,
        AggregatePlanKind::FiniteLiteralDfa
    );
    assert_eq!(compiled.build_report().schema_version, 10);
    assert_eq!(AGGREGATE_EXPLAIN_SCHEMA_VERSION, 10);
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

#[test]
fn finite_dfa_planner_limit_fails_with_typed_ownership() {
    let pattern = r"(?:cat|dog|mouse)";
    let baseline = builder(pattern).build_count().unwrap();
    let work = baseline.build_report().finite_planner_work;
    assert!(work > 0);

    let planner_limits = AggregateBuildLimits {
        max_finite_planner_work: work.checked_sub(1).unwrap(),
        ..AggregateBuildLimits::default()
    };
    let planner_error = builder(pattern)
        .limits(planner_limits)
        .build_count()
        .unwrap_err();
    assert!(matches!(
        planner_error,
        AggregateBuildError::FinitePlannerWorkLimit { .. }
    ));
}

#[test]
fn finite_dfa_auto_falls_back_on_count_and_span_sum_kernel_limits() {
    let pattern = r"(?P<word>cat|dog|mouse)";
    let haystack = b"cat mouse dog cat";
    let expected = oracle(pattern, haystack);

    let mut count_limits = AggregateBuildLimits::default();
    count_limits.finite_literal.max_trie_states = 1;
    let count = builder(pattern).limits(count_limits).build_count().unwrap();
    assert_eq!(
        count.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert!(count.build_report().finite_planner_work > 0);
    assert_eq!(count.build_report().captures_erased, 1);
    assert_eq!(
        count
            .count_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        expected.0
    );

    let mut span_limits = AggregateBuildLimits::default();
    span_limits.finite_literal.max_dfa_cells = 1;
    let span_sum = builder(pattern)
        .limits(span_limits)
        .build_span_sum()
        .unwrap();
    assert_eq!(
        span_sum.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
    assert!(span_sum.build_report().finite_planner_work > 0);
    assert_eq!(span_sum.build_report().captures_erased, 1);
    assert_eq!(
        span_sum
            .span_sum_value(haystack, AggregateRunLimits::default())
            .unwrap(),
        expected.1
    );
}

fn alternation(count: usize) -> String {
    let mut pattern = String::from("(?:");
    for index in 0..count {
        if index != 0 {
            pattern.push('|');
        }
        write!(&mut pattern, "p{index:03}").unwrap();
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
    let small_at_n = counters(16, n);
    let large_at_n = counters(64, n);
    let small_at_double_n = counters(16, 2 * n);
    let large_at_double_n = counters(64, 2 * n);

    assert_eq!(small_at_n.0, n);
    assert_eq!(large_at_n.0, n);
    assert_eq!(small_at_double_n.0, 2 * n);
    assert_eq!(large_at_double_n.0, 2 * n);
    assert_eq!(small_at_n.1, n + 1);
    assert_eq!(large_at_n.1, n + 1);
    assert_eq!(small_at_double_n.1, 2 * n + 1);
    assert_eq!(large_at_double_n.1, 2 * n + 1);
    assert_eq!(small_at_n.2, large_at_n.2);
    assert_eq!(small_at_double_n.2, large_at_double_n.2);
    assert!(small_at_double_n.2 < 2 * small_at_n.2 + 8);
}

#[test]
fn spans_anchors_and_unbounded_neighbors_keep_the_continuation_route() {
    for pattern in [r"(?:cat|dog)", r"\A(?:cat|dog)\z", r"(?:cat|dog)+"] {
        let regex = builder(pattern)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_spans()
            .unwrap();
        assert_eq!(
            regex.build_report().plan,
            AggregatePlanKind::ContinuationProgram
        );
    }
    for pattern in [r"\A(?:cat|dog)\z", r"(?:cat|dog)+"] {
        let regex = builder(pattern).build_count().unwrap();
        assert_eq!(
            regex.build_report().plan,
            AggregatePlanKind::ContinuationProgram
        );
    }
}
