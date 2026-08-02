use fre::{
    AggregateBuilder, AggregateCountWorkspace, AggregateEngineError,
    AggregateExecutionAttemptIdentity, AggregateExecutionSource, AggregatePlanKind,
    AggregatePlanSelection, AggregateResource, AggregateRunLimits, AggregateSpanSumWorkspace,
    RustProfile,
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
fn state_byte_incumbent_dominates_sweep_without_touching_workspace() {
    std::thread::Builder::new()
        .name("continuation-sweep-route-dominance".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(state_byte_incumbent_dominates_sweep_without_touching_workspace_body)
        .unwrap()
        .join()
        .unwrap();
}

fn state_byte_incumbent_dominates_sweep_without_touching_workspace_body() {
    // Both programs are wide enough for the continuation sweep's program-size
    // gate. The first also has a compiler-proved single-pass state/byte value
    // reducer; the ordered-alternation control does not.
    let dominated_pattern = r"[ab]+[ ]+abcdefghijklmnopq";
    let sweep_pattern = r"(?:abcdefghijklmnopq|qrstuvwxyzabcdefg)+z";
    let dominated_haystack = b"aa abcdefghijklmnopq--bb abcdefghijklmnopq--not-a-match";
    let sweep_haystack = b"xxabcdefghijklmnopqqrstuvwxyzabcdefgz--qrstuvwxyzabcdefgz";
    let limits = AggregateRunLimits::default();

    let dominated_count = builder(dominated_pattern).build_count().unwrap();
    let dominated_sum = builder(dominated_pattern).build_span_sum().unwrap();
    assert_eq!(
        dominated_count.continuation_sweep_upper_bounds().unwrap(),
        None
    );
    assert_eq!(
        dominated_sum.continuation_sweep_upper_bounds().unwrap(),
        None
    );
    let expected = oracle(dominated_pattern, dominated_haystack);
    assert_eq!(
        (
            dominated_count
                .count_value(dominated_haystack, limits)
                .unwrap(),
            dominated_sum
                .span_sum_value(dominated_haystack, limits)
                .unwrap(),
        ),
        expected
    );
    let mut count_workspace = AggregateCountWorkspace::new();
    let mut sum_workspace = AggregateSpanSumWorkspace::new();
    assert_eq!(
        dominated_count
            .count_value_with_workspace(dominated_haystack, limits, &mut count_workspace)
            .unwrap(),
        expected.0
    );
    assert_eq!(
        dominated_sum
            .span_sum_value_with_workspace(dominated_haystack, limits, &mut sum_workspace)
            .unwrap(),
        expected.1
    );
    assert_eq!(count_workspace.retained_continuation_bytes(), None);
    assert_eq!(sum_workspace.retained_continuation_bytes(), None);

    let sweep_count = builder(sweep_pattern).build_count().unwrap();
    let sweep_sum = builder(sweep_pattern).build_span_sum().unwrap();
    assert!(
        sweep_count
            .continuation_sweep_upper_bounds()
            .unwrap()
            .is_some()
    );
    assert!(
        sweep_sum
            .continuation_sweep_upper_bounds()
            .unwrap()
            .is_some()
    );
    let expected = oracle(sweep_pattern, sweep_haystack);
    let mut count_workspace = AggregateCountWorkspace::new();
    let mut sum_workspace = AggregateSpanSumWorkspace::new();
    assert_eq!(
        sweep_count
            .count_value_with_workspace(sweep_haystack, limits, &mut count_workspace)
            .unwrap(),
        expected.0
    );
    assert_eq!(
        sweep_sum
            .span_sum_value_with_workspace(sweep_haystack, limits, &mut sum_workspace)
            .unwrap(),
        expected.1
    );
    assert!(
        count_workspace
            .retained_continuation_bytes()
            .unwrap_or_default()
            > 0
    );
    assert!(
        sum_workspace
            .retained_continuation_bytes()
            .unwrap_or_default()
            > 0
    );
}

#[test]
fn disjoint_shared_fixed_candidate_dominates_sweep_without_touching_workspace() {
    std::thread::Builder::new()
        .name("continuation-sweep-fixed-candidate-dominance".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(disjoint_shared_fixed_candidate_dominates_sweep_without_touching_workspace_body)
        .unwrap()
        .join()
        .unwrap();
}

fn disjoint_shared_fixed_candidate_dominates_sweep_without_touching_workspace_body() {
    let haystack = b"bcdefghijklmnopq".repeat(32);
    let limits = AggregateRunLimits::default();

    // This source-independent shape retains an unchecked one-owner candidate
    // at one fixed offset, a shared native anchor and a disjoint mandatory
    // global byte set. The independent global proof rejects this source
    // before any candidate verification.
    for pattern in [r".efghijklmnopq[a-z]+[A-Z]"] {
        let expected = oracle(pattern, &haystack);
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
        assert_eq!(
            count.continuation_sweep_upper_bounds().unwrap(),
            None,
            "count pattern={pattern:?}"
        );
        assert_eq!(
            sum.continuation_sweep_upper_bounds().unwrap(),
            None,
            "span sum pattern={pattern:?}"
        );

        let mut count_workspace = AggregateCountWorkspace::new();
        let mut sum_workspace = AggregateSpanSumWorkspace::new();
        assert_eq!(
            count
                .count_value_with_workspace(&haystack, limits, &mut count_workspace)
                .unwrap(),
            expected.0,
            "count pattern={pattern:?}"
        );
        assert_eq!(
            sum.span_sum_value_with_workspace(&haystack, limits, &mut sum_workspace)
                .unwrap(),
            expected.1,
            "span sum pattern={pattern:?}"
        );
        assert_eq!(count_workspace.retained_continuation_bytes(), None);
        assert_eq!(sum_workspace.retained_continuation_bytes(), None);
    }

    // A similarly wide continuation whose global proof overlaps its shared
    // candidate anchor remains eligible and proves that the gate is not a
    // pattern-length or source-content heuristic.
    let control = r"(?:abcdefghijklmnopq|qrstuvwxyzabcdefg)+z";
    let count = builder(control).build_count().unwrap();
    let sum = builder(control).build_span_sum().unwrap();
    assert!(count.continuation_sweep_upper_bounds().unwrap().is_some());
    assert!(sum.continuation_sweep_upper_bounds().unwrap().is_some());
    let expected = oracle(control, &haystack);
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
    assert!(
        count_workspace
            .retained_continuation_bytes()
            .unwrap_or_default()
            > 0
    );
    assert!(
        sum_workspace
            .retained_continuation_bytes()
            .unwrap_or_default()
            > 0
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
fn incumbent_valid_work_limit_remains_valid_with_cold_or_warm_workspace() {
    std::thread::Builder::new()
        .name("continuation-sweep-work-monotone".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(incumbent_valid_work_limit_remains_valid_with_cold_or_warm_workspace_body)
        .unwrap()
        .join()
        .unwrap();
}

fn incumbent_valid_work_limit_remains_valid_with_cold_or_warm_workspace_body() {
    let pattern = r"(?:abcdefghijklmnopqa+b|abcdefghijklmnopqa)";
    let haystack = b"abcdefghijklmnopqaaab";
    let count = builder(pattern).build_count().unwrap();
    let limits = AggregateRunLimits::default();
    let expected = count.count_value(haystack, limits).unwrap();
    let mut lower = 0_usize;
    let mut upper = limits.continuation.max_work;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let mut probe = limits;
        probe.continuation.max_work = middle;
        if count.count_value(haystack, probe).is_ok() {
            upper = middle;
        } else {
            lower = middle + 1;
        }
    }
    let mut incumbent_exact = limits;
    incumbent_exact.continuation.max_work = lower;
    assert_eq!(
        count.count_value(haystack, incumbent_exact).unwrap(),
        expected
    );

    let mut workspace = AggregateCountWorkspace::new();
    count
        .count_value_with_workspace(haystack, limits, &mut workspace)
        .unwrap();
    assert!(workspace.retained_continuation_bytes().is_some());
    assert_eq!(
        count
            .count_value_with_workspace(haystack, incumbent_exact, &mut workspace)
            .unwrap(),
        expected
    );

    let mut cold = AggregateCountWorkspace::new();
    assert_eq!(
        count
            .count_value_with_workspace(haystack, incumbent_exact, &mut cold)
            .unwrap(),
        expected
    );
    assert_eq!(cold.retained_continuation_bytes(), None);
}

#[test]
fn late_priority_quadratic_sweep_reports_observed_limit_without_incumbent_replay() {
    std::thread::Builder::new()
        .name("continuation-sweep-sequential-monotone".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(late_priority_quadratic_sweep_refuses_before_an_incumbent_valid_source_read_body)
        .unwrap()
        .join()
        .unwrap();
}

fn late_priority_quadratic_sweep_refuses_before_an_incumbent_valid_source_read_body() {
    let pattern = r"(?s:a.*z|a|[\x00-\xFF]bcdefghijklmnop)";
    let haystack = vec![b'a'; 256];
    let count = builder(pattern).build_count().unwrap();
    let limits = AggregateRunLimits::default();
    let expected = count.count_value(&haystack, limits).unwrap();
    let mut lower = 0_usize;
    let mut upper = limits.continuation.max_sequential_bytes;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let mut probe = limits;
        probe.continuation.max_sequential_bytes = middle;
        if count.count_value(&haystack, probe).is_ok() {
            upper = middle;
        } else {
            lower = middle + 1;
        }
    }
    let mut incumbent_exact = limits;
    incumbent_exact.continuation.max_sequential_bytes = lower;
    assert_eq!(
        count.count_value(&haystack, incumbent_exact).unwrap(),
        expected
    );
    let mut workspace = AggregateCountWorkspace::new();
    let error = count
        .count_value_with_workspace(&haystack, incumbent_exact, &mut workspace)
        .expect_err("observed sweep limit must remain visible after source access");
    assert!(matches!(
        &error.identity,
        AggregateExecutionAttemptIdentity::Incumbent(_)
    ));
    assert!(error.continuation_receipt().is_none());
    assert!(!error.has_closed_continuation_attempt());
    assert!(workspace.retained_continuation_bytes().is_some());
    assert!(matches!(
        error.source,
        AggregateExecutionSource::Continuation(AggregateEngineError::ResourceLimit {
            resource: AggregateResource::SequentialBytes,
            required,
            limit,
        }) if required > limit && limit == lower
    ));
}

#[test]
fn lazy_only_table_and_memory_limits_preserve_the_incumbent_result() {
    std::thread::Builder::new()
        .name("continuation-sweep-storage-monotone".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(lazy_only_table_and_memory_limits_preserve_the_incumbent_result_body)
        .unwrap()
        .join()
        .unwrap();
}

fn lazy_only_table_and_memory_limits_preserve_the_incumbent_result_body() {
    let pattern = r"(?:abcdefghijklmnopq|qrstuvwxyzabcdefg)+z";
    let haystack = b"abcdefghijklmnopqqrstuvwxyzabcdefgz--qrstuvwxyzabcdefgz";
    let count = builder(pattern).build_count().unwrap();
    let limits = AggregateRunLimits::default();
    let expected = count.count_value(haystack, limits).unwrap();
    let sweep = count
        .continuation_sweep_upper_bounds()
        .unwrap()
        .expect("bounded rewind continuation must publish its sweep");

    let mut no_table = limits;
    no_table.continuation.max_table_cells = 0;
    assert_eq!(count.count_value(haystack, no_table).unwrap(), expected);
    let mut table_workspace = AggregateCountWorkspace::new();
    assert_eq!(
        count
            .count_value_with_workspace(haystack, no_table, &mut table_workspace)
            .unwrap(),
        expected
    );
    assert_eq!(table_workspace.retained_continuation_bytes(), Some(0));

    for resource in 0..3 {
        let mut one_below = limits;
        match resource {
            0 => one_below.continuation.max_random_access_bytes = sweep.workspace_bytes - 1,
            1 => one_below.continuation.max_scratch_bytes = sweep.workspace_bytes - 1,
            2 => one_below.continuation.max_peak_bytes = sweep.workspace_bytes - 1,
            _ => unreachable!(),
        }
        assert_eq!(count.count_value(haystack, one_below).unwrap(), expected);
        let mut workspace = AggregateCountWorkspace::new();
        assert_eq!(
            count
                .count_value_with_workspace(haystack, one_below, &mut workspace)
                .unwrap(),
            expected
        );
        assert_eq!(workspace.retained_continuation_bytes(), Some(0));
    }

    let mut warmed = AggregateCountWorkspace::new();
    assert_eq!(
        count
            .count_value_with_workspace(haystack, limits, &mut warmed)
            .unwrap(),
        expected
    );
    assert!(warmed.retained_continuation_bytes().unwrap_or_default() > 0);
    let mut low_warm = limits;
    low_warm.continuation.max_table_cells = sweep.table_cells - 1;
    assert_eq!(
        count
            .count_value_with_workspace(haystack, low_warm, &mut warmed)
            .unwrap(),
        expected
    );
    assert_eq!(warmed.retained_continuation_bytes(), Some(0));
}
