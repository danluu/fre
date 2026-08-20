#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanSelection, PortableBuilder, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn immutable_k0_shortest_values_reuse_pool_scratch_without_changing_custom_limits() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap();
    let matched = b"xxxxxxxxabacabacz";
    let absent = b"xxxxxxxxxxxxxxxxx";

    let cold = Region::new(GLOBAL);
    assert_eq!(
        regex
            .shortest_match_value(matched, SearchLimits::default())
            .unwrap(),
        Some(17),
    );
    assert!(cold.change().allocations > 0);

    let warm = Region::new(GLOBAL);
    for limits in [SearchLimits::default(), SearchLimits::unlimited()] {
        for start in [0, 4, 8] {
            assert_eq!(
                regex
                    .shortest_match_at_value(matched, start, limits)
                    .unwrap(),
                Some(17),
            );
            assert_eq!(
                regex
                    .shortest_match_at_value(absent, start, limits)
                    .unwrap(),
                None,
            );
        }
    }
    assert_eq!(warm.change(), Stats::default());

    let custom = SearchLimits {
        max_work: SearchLimits::default().max_work - 1,
        ..SearchLimits::default()
    };
    for _ in 0..2 {
        let call = Region::new(GLOBAL);
        assert_eq!(
            regex.shortest_match_value(matched, custom).unwrap(),
            Some(17),
        );
        assert!(call.change().allocations > 0);
    }
}
