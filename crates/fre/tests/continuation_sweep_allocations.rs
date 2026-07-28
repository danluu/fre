#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    AggregateBuilder, AggregateCountWorkspace, AggregatePlanSelection, AggregateRunLimits,
    AggregateSpanSumWorkspace, RustProfile,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn prepared_continuation_sweep_has_zero_steady_allocation() {
    std::thread::Builder::new()
        .name("continuation-sweep-allocation-census".to_owned())
        .stack_size(16 * 1024 * 1024)
        .spawn(prepared_continuation_sweep_has_zero_steady_allocation_body)
        .unwrap()
        .join()
        .unwrap();
}

fn prepared_continuation_sweep_has_zero_steady_allocation_body() {
    let pattern = "(?:abcdefghijklmnopqa+b|abcdefghijklmnopqa)";
    let builder = || {
        AggregateBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .plan_selection(AggregatePlanSelection::ForceContinuation)
    };
    let count = builder().build_count().unwrap();
    let sum = builder().build_span_sum().unwrap();
    let haystack = b"abcdefghijklmnopqaaab--abcdefghijklmnopqa";
    let limits = AggregateRunLimits::default();
    let mut count_workspace = AggregateCountWorkspace::new();
    let mut sum_workspace = AggregateSpanSumWorkspace::new();

    let expected_count = count
        .count_value_with_workspace(haystack, limits, &mut count_workspace)
        .unwrap();
    let expected_sum = sum
        .span_sum_value_with_workspace(haystack, limits, &mut sum_workspace)
        .unwrap();
    assert!(count_workspace.retained_continuation_bytes().is_some());
    assert!(sum_workspace.retained_continuation_bytes().is_some());

    let region = Region::new(GLOBAL);
    assert_eq!(
        count
            .count_value_with_workspace(haystack, limits, &mut count_workspace)
            .unwrap(),
        expected_count
    );
    assert_eq!(
        sum.span_sum_value_with_workspace(haystack, limits, &mut sum_workspace)
            .unwrap(),
        expected_sum
    );
    assert_eq!(region.change(), Stats::default());
}
