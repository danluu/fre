#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{AggregateBuilder, AggregateRunLimits, RustProfile};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn retained_literal_anchor_has_zero_steady_execution_allocations() {
    let regex = AggregateBuilder::new(r"\b\w+\s+Holmes\s+\w+\b")
        .profile(RustProfile::rebar_1_12_4())
        .unicode(false)
        .build_count()
        .expect("token-phrase plan");
    let mut haystack = vec![b'-'; 4_096];
    haystack.extend_from_slice(b"--left Holmes right--");
    haystack.resize(8_192, b'-');

    let expected = regex
        .count_value(&haystack, AggregateRunLimits::default())
        .expect("warm token-phrase count");
    let region = Region::new(GLOBAL);
    let actual = regex
        .count_value(&haystack, AggregateRunLimits::default())
        .expect("measured token-phrase count");
    let census = region.change();

    assert_eq!(actual, expected);
    assert_eq!(census, Stats::default());
}
