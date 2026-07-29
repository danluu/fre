#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    AggregateBuilder, AggregateCountWorkspace, AggregateRunLimits, AggregateSpanSumWorkspace,
    RustProfile,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn impossible_match_domain_value_paths_allocate_nothing() {
    std::thread::Builder::new()
        .name("impossible-match-domain-allocation-census".to_owned())
        .stack_size(32 * 1024 * 1024)
        .spawn(impossible_match_domain_value_paths_allocate_nothing_body)
        .unwrap()
        .join()
        .unwrap();
}

fn impossible_match_domain_value_paths_allocate_nothing_body() {
    let builder = |pattern| {
        AggregateBuilder::new(pattern)
            .profile(RustProfile::rebar_1_12_4())
            .unicode(false)
            .case_insensitive(false)
    };
    let count = builder(r"^\w{30}$").build_count().unwrap();
    let span_sum = builder(r"^\w{30}$").build_span_sum().unwrap();
    let haystack = [b'a'; 52];
    let limits = AggregateRunLimits::default();
    let mut count_workspace = AggregateCountWorkspace::new();
    let mut span_workspace = AggregateSpanSumWorkspace::new();

    let region = Region::new(GLOBAL);
    assert_eq!(count.count_value(&haystack, limits).unwrap(), 0);
    assert_eq!(span_sum.span_sum_value(&haystack, limits).unwrap(), 0);
    assert_eq!(
        count
            .count_value_with_workspace(&haystack, limits, &mut count_workspace)
            .unwrap(),
        0
    );
    assert_eq!(
        span_sum
            .span_sum_value_with_workspace(&haystack, limits, &mut span_workspace)
            .unwrap(),
        0
    );
    assert_eq!(
        count
            .count_value_with_counters(&haystack, limits)
            .unwrap()
            .value(),
        0
    );
    assert_eq!(
        span_sum
            .span_sum_value_with_counters(&haystack, limits)
            .unwrap()
            .value(),
        0
    );
    assert_eq!(region.change(), Stats::default());
}
