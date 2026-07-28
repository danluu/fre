use fre::{
    AggregateBuilder, AggregateCountWorkspace, AggregatePlanKind, AggregatePlanSelection,
    AggregateRunLimits, AggregateSpanSumWorkspace, RustProfile,
};

fn builder(pattern: &str) -> AggregateBuilder {
    AggregateBuilder::new(pattern)
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .plan_selection(AggregatePlanSelection::ForceContinuation)
}

fn oracle(pattern: &str, haystack: &[u8]) -> (u64, u64) {
    let regex = regex::bytes::RegexBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    regex
        .find_iter(haystack)
        .try_fold((0_u64, 0_u64), |(count, sum), matched| {
            let width = u64::try_from(matched.end().checked_sub(matched.start())?).ok()?;
            Some((count.checked_add(1)?, sum.checked_add(width)?))
        })
        .unwrap()
}

#[test]
fn reusable_continuation_sweep_matches_incumbent_and_regex_oracle() {
    std::thread::Builder::new()
        .name("continuation-sweep-differential".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(reusable_continuation_sweep_matches_incumbent_and_regex_oracle_body)
        .unwrap()
        .join()
        .unwrap();
}

fn reusable_continuation_sweep_matches_incumbent_and_regex_oracle_body() {
    let cases: &[(&str, &[u8])] = &[
        ("(?:ab|a)+z", b"xxababaz abaaaz aaaaa no"),
        (r"\bco(?:m|w)[a-z]*\b", b"cow comment coam comb xcow cozz"),
        (
            r"(?:[ab][cd]|[cd][ab])+(?:x|yz)",
            b"acbdacyz zz cadbx acacx",
        ),
        (r"(?:a+b|a)", b"aaaaaaaaaaaaaaaaaaaaaaaa"),
    ];
    let limits = AggregateRunLimits::default();
    let mut retained = 0_usize;
    for &(pattern, haystack) in cases {
        let expected = oracle(pattern, haystack);
        let count = builder(pattern).build_count().unwrap();
        let sum = builder(pattern).build_span_sum().unwrap();
        assert_eq!(
            count.build_report().plan,
            AggregatePlanKind::ContinuationProgram
        );
        assert_eq!(
            sum.build_report().plan,
            AggregatePlanKind::ContinuationProgram
        );

        let incumbent_count = count.count_value(haystack, limits).unwrap();
        let incumbent_sum = sum.span_sum_value(haystack, limits).unwrap();
        assert_eq!((incumbent_count, incumbent_sum), expected);

        let mut count_workspace = AggregateCountWorkspace::new();
        let mut sum_workspace = AggregateSpanSumWorkspace::new();
        assert_eq!(
            count
                .count_value_with_workspace(haystack, limits, &mut count_workspace)
                .unwrap(),
            expected.0,
            "count pattern={pattern:?}"
        );
        assert_eq!(
            sum.span_sum_value_with_workspace(haystack, limits, &mut sum_workspace)
                .unwrap(),
            expected.1,
            "span sum pattern={pattern:?}"
        );
        assert_eq!(
            count
                .count_value_with_workspace(haystack, limits, &mut count_workspace)
                .unwrap(),
            expected.0,
            "reused count pattern={pattern:?}"
        );
        assert_eq!(
            sum.span_sum_value_with_workspace(haystack, limits, &mut sum_workspace)
                .unwrap(),
            expected.1,
            "reused span sum pattern={pattern:?}"
        );
        retained = retained
            .checked_add(
                count_workspace
                    .retained_continuation_bytes()
                    .unwrap_or_default(),
            )
            .unwrap();
        retained = retained
            .checked_add(
                sum_workspace
                    .retained_continuation_bytes()
                    .unwrap_or_default(),
            )
            .unwrap();
    }
    assert!(
        retained > 0,
        "all continuation sweep cases were structurally refused"
    );
}

#[test]
fn late_priority_adversary_preserves_value_without_restart() {
    std::thread::Builder::new()
        .name("continuation-sweep-late-priority".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(late_priority_adversary_preserves_value_without_restart_body)
        .unwrap()
        .join()
        .unwrap();
}

fn late_priority_adversary_preserves_value_without_restart_body() {
    let pattern = r"(?:abcdefghijklmnopqa+b|abcdefghijklmnopqa)";
    let mut haystack = b"abcdefghijklmnopq".to_vec();
    haystack.extend(core::iter::repeat_n(b'a', 4_096));
    let limits = AggregateRunLimits::default();
    let expected = oracle(pattern, &haystack);
    let count = builder(pattern).build_count().unwrap();
    let sum = builder(pattern).build_span_sum().unwrap();
    let mut count_workspace = AggregateCountWorkspace::new();
    let mut sum_workspace = AggregateSpanSumWorkspace::new();
    assert_eq!(
        count
            .count_value_with_workspace(&haystack, limits, &mut count_workspace)
            .unwrap(),
        expected.0
    );
    assert_eq!(
        sum.span_sum_value_with_workspace(&haystack, limits, &mut sum_workspace)
            .unwrap(),
        expected.1
    );
}

#[test]
fn admitted_workspace_terminal_is_not_replayed_through_the_incumbent() {
    std::thread::Builder::new()
        .name("continuation-sweep-terminal".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(admitted_workspace_terminal_is_not_replayed_through_the_incumbent_body)
        .unwrap()
        .join()
        .unwrap();
}

fn admitted_workspace_terminal_is_not_replayed_through_the_incumbent_body() {
    let pattern = r"(?:abcdefghijklmnopqa+b|abcdefghijklmnopqa)";
    let haystack = b"abcdefghijklmnopqaaab";
    let count = builder(pattern).build_count().unwrap();
    let mut workspace = AggregateCountWorkspace::new();
    let limits = AggregateRunLimits::default();
    count
        .count_value_with_workspace(haystack, limits, &mut workspace)
        .unwrap();
    assert!(workspace.retained_continuation_bytes().is_some());

    let mut one_below = limits;
    one_below.continuation.max_work = 0;
    let error = count
        .count_value_with_workspace(haystack, one_below, &mut workspace)
        .unwrap_err();
    assert!(error.continuation_receipt().is_none());
    assert!(error.to_string().contains("ExecutionWork"));
}
