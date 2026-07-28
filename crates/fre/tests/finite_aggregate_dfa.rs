use std::fmt::Write as _;

use fre::{
    AGGREGATE_EXPLAIN_SCHEMA_VERSION, AggregateBuildAccounting, AggregateBuildError,
    AggregateBuildLimits, AggregateBuilder, AggregateExecutionDetails, AggregateExecutionSource,
    AggregateFiniteLiteralSemantics, AggregateOperation, AggregatePlanIdentity, AggregatePlanKind,
    AggregateRunLimits, AggregateStrategy, OrderedLiteralAggregateReduceError, RustProfile,
    SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID, SparseOrderedLiteralAggregateReduceError,
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
            AggregatePlanKind::PackedFiniteLiteral
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
        assert_eq!(
            sum.build_report().plan,
            AggregatePlanKind::PackedFiniteLiteral
        );
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
    let cases: [(&str, &[u8], AggregatePlanKind); 5] = [
        (r"(?:ab|a|)", b"aba", AggregatePlanKind::FiniteLiteralDfa),
        (r"(?:|a)", b"aaa", AggregatePlanKind::FiniteLiteralDfa),
        (
            r"(?P<whole>(?:\xFFa|\xFF|b))",
            &[0xFF, b'a', 0xFF, b'b'],
            AggregatePlanKind::FiniteLiteralDfa,
        ),
        (
            r"(?i:(?:sherlock|holmes))",
            b"SHERLOCK x Holmes",
            AggregatePlanKind::FiniteLiteralDfa,
        ),
        (
            r"(?:early|late)",
            b"early---late",
            AggregatePlanKind::PackedFiniteLiteral,
        ),
    ];
    for (pattern, haystack, expected_plan) in cases {
        let expected = oracle(pattern, haystack);
        let count = builder(pattern).build_count().unwrap();
        assert_eq!(count.build_report().plan, expected_plan);
        assert_eq!(count.build_report().continuation_strategy, None);
        assert_eq!(
            count
                .count_value(haystack, AggregateRunLimits::default())
                .unwrap(),
            expected.0
        );
        let sum = builder(pattern).build_span_sum().unwrap();
        assert_eq!(sum.build_report().plan, expected_plan);
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
    assert_eq!(compiled.build_report().schema_version, 40);
    assert_eq!(AGGREGATE_EXPLAIN_SCHEMA_VERSION, 40);
    assert_eq!(compiled.build_report().captures_erased, 1);
    assert!(compiled.build_report().finite_planner_work > 0);
    let haystack = b"cat xx dog";
    let baseline = compiled
        .verify_count(haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FiniteLiteral {
        upper_bounds,
        actual,
    } = baseline.report().details()
    else {
        panic!("finite compile artifact executed another plan")
    };
    assert_eq!(actual.transitions, haystack.len());
    assert_eq!(actual.reducer_steps, haystack.len() + 1);
    assert!(actual.total_work <= upper_bounds.total_work);

    let mut limits = AggregateRunLimits::default();
    limits.finite_literal.max_total_work = actual.total_work - 1;
    let error = compiled.verify_count(haystack, limits).unwrap_err();
    assert!(error.has_closed_direct_attempt());
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
    // The one-byte alternative deliberately declines the packed route so this
    // test continues to exercise dense-construction fallback ownership.
    let pattern = r"(?P<word>a|cat|dog|mouse)";
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

fn unicode_alternation(count: usize) -> (String, usize, Vec<String>) {
    let leaders = ('a'..='z').chain('A'..='Z').collect::<Vec<_>>();
    let maximum_count = leaders.len().checked_add(2).unwrap();
    assert!((3..=maximum_count).contains(&count));
    let root_words = count.checked_sub(2).unwrap();
    let mut words = (0..root_words)
        .map(|index| format!("{}{index:03}雪", leaders[index]))
        .collect::<Vec<_>>();
    let first = words[0].clone();
    words.push(first.strip_suffix('雪').unwrap().to_owned());
    words.push(first);
    let pattern_bytes = words.iter().map(String::len).sum();
    (format!("(?:{})", words.join("|")), pattern_bytes, words)
}

#[test]
fn sparse_finite_facade_preserves_unicode_priority_and_frozen_cell_quota() {
    let (pattern, pattern_bytes, words) = unicode_alternation(32);
    let mut haystack = b"\xFF--".to_vec();
    haystack.extend_from_slice(words[7].as_bytes());
    haystack.extend_from_slice(b"--\x80--");
    haystack.extend_from_slice(words[31].as_bytes());
    let expected = unicode_oracle(&pattern, &haystack);
    let mut build_limits = AggregateBuildLimits::default();
    // The sparse preflight uses at most one packed edge per literal byte.
    // The same frozen cell ceiling is too small for a dense row per state.
    build_limits.finite_literal.max_dfa_cells = pattern_bytes;

    let count = unicode_builder(&pattern)
        .limits(build_limits)
        .build_count()
        .unwrap();
    let AggregateBuildAccounting::SparseFiniteLiteral(build) = count.build_report().build else {
        panic!("cell-bound root alternative did not select the sparse representation")
    };
    assert_eq!(build.sparse_edges_upper_bound, pattern_bytes);
    assert!(build.trie_states_actual > 1);
    assert!(matches!(
        count.build_report().plan_identity,
        AggregatePlanIdentity::FiniteLiteral(identity)
            if identity.algorithm == SPARSE_ORDERED_LITERAL_AGGREGATE_ALGORITHM_ID
                && identity.semantics
                    == AggregateFiniteLiteralSemantics::UnicodeOnNonemptyUtf8Words
    ));
    assert_eq!(
        count
            .count_value(&haystack, AggregateRunLimits::default())
            .unwrap(),
        expected.0
    );

    let span = unicode_builder(&pattern)
        .limits(build_limits)
        .build_span_sum()
        .unwrap();
    let audited = span
        .span_sum(&haystack, AggregateRunLimits::default())
        .unwrap();
    assert_eq!(audited.value(), expected.1);
    let AggregateExecutionDetails::SparseFiniteLiteral {
        upper_bounds,
        actual,
    } = audited.report().details()
    else {
        panic!("sparse span-sum executed another representation")
    };
    assert!(actual.edge_search_checks <= upper_bounds.edge_search_checks);
    assert!(actual.failure_steps <= upper_bounds.failure_steps);
    assert!(actual.total_work <= upper_bounds.total_work);

    let exact_work = usize::try_from(upper_bounds.total_work).unwrap();
    let mut exact_run = AggregateRunLimits::default();
    exact_run.finite_literal.max_total_work = exact_work;
    span.span_sum_value(&haystack, exact_run).unwrap();
    exact_run.finite_literal.max_total_work = exact_work - 1;
    let error = span.span_sum_value(&haystack, exact_run).unwrap_err();
    assert!(error.has_closed_direct_attempt());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::SparseFiniteLiteral(
            SparseOrderedLiteralAggregateReduceError::TotalWorkLimit { .. }
        )
    ));

    build_limits.finite_literal.max_dfa_cells = pattern_bytes - 1;
    let one_below = unicode_builder(pattern)
        .limits(build_limits)
        .build_count()
        .unwrap();
    assert_eq!(
        one_below.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
}

#[test]
fn sparse_finite_construction_scales_beyond_old_hir_stack_and_state_ceilings() {
    let count = 65_537;
    let mut pattern = String::from("(?:");
    for index in 0..count {
        if index != 0 {
            pattern.push('|');
        }
        write!(&mut pattern, "x{index:08x}").unwrap();
    }
    pattern.push(')');
    let pattern_bytes = count * 9;
    let mut limits = AggregateBuildLimits::default();
    limits.finite_literal.max_patterns = count;
    limits.finite_literal.max_pattern_bytes = pattern_bytes;
    limits.finite_literal.max_dfa_cells = pattern_bytes;
    let compiled = builder(pattern).limits(limits).build_compile().unwrap();
    let AggregateBuildAccounting::SparseFiniteLiteral(build) = compiled.build_report().build else {
        panic!("large flat literal language did not select sparse construction")
    };
    assert!(compiled.build_report().syntax.hir_nodes > 65_536);
    assert!(build.trie_states_actual > 65_536);
    assert_eq!(build.sparse_edges_actual + 1, build.trie_states_actual);
    assert!(build.sparse_edges_actual <= build.sparse_edges_upper_bound);
}

fn counters(patterns: usize, input: usize) -> (usize, usize, usize) {
    let regex = builder(alternation(patterns)).build_count().unwrap();
    let haystack = vec![0xFF; input];
    let result = regex
        .count(&haystack, AggregateRunLimits::default())
        .unwrap();
    let AggregateExecutionDetails::FiniteLiteral { actual, .. } = result.report().details() else {
        panic!("finite scaling case executed another plan")
    };
    (actual.transitions, actual.reducer_steps, actual.total_work)
}

#[test]
fn finite_dfa_n_2n_and_query_scaling_rejects_input_times_alternatives() {
    let n = 8_192;
    // Seventeen alternatives are just beyond the packed theorem and retain
    // this test's dense-DFA scaling target.
    let small_at_n = counters(17, n);
    let large_at_n = counters(64, n);
    let small_at_double_n = counters(17, 2 * n);
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
fn spans_and_unbounded_neighbors_keep_continuation_while_anchored_count_is_fixed() {
    for pattern in [r"(?:cat|dog)", r"\A(?:cat|dog)\z", r"(?:cat|dog)+"] {
        let regex = builder(pattern)
            .strategy(AggregateStrategy::ReverseSequentialRows)
            .build_spans()
            .unwrap();
        assert_eq!(
            regex.build_report().plan,
            AggregatePlanKind::ContinuationProgram,
            "{pattern}"
        );
    }
    let anchored = builder(r"\A(?:cat|dog)\z").build_count().unwrap();
    assert_eq!(
        anchored.build_report().plan,
        AggregatePlanKind::FixedAbsoluteDomain
    );
    let unbounded = builder(r"(?:cat|dog)+").build_count().unwrap();
    assert_eq!(
        unbounded.build_report().plan,
        AggregatePlanKind::ContinuationProgram
    );
}
