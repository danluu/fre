#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanSelection, PortableTextBuilder, PortableTextRegex, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn text_shortest_values_are_allocation_free_after_k0_pool_warmup() {
    let k0 = PortableTextBuilder::new(r"(?:αβ|γδ)+Z")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("forced K0 text regex");
    let exact = PortableTextRegex::new("東京").expect("exact text literal");
    let present = "☃αβγδαβZx";

    assert_eq!(
        k0.shortest_match_value(present, SearchLimits::unlimited())
            .expect("warm K0 shortest pool"),
        Some("☃αβγδαβZ".len()),
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            k0.shortest_match_value(present, SearchLimits::unlimited())
                .unwrap(),
            Some("☃αβγδαβZ".len()),
        );
        assert_eq!(
            k0.shortest_match_at_value(present, 1, SearchLimits::unlimited())
                .unwrap(),
            Some("☃αβγδαβZ".len()),
        );
        assert_eq!(
            k0.shortest_match_value("☃xxxxxxxx", SearchLimits::unlimited())
                .unwrap(),
            None,
        );
        assert_eq!(
            exact
                .shortest_match_value("xx東京yy", SearchLimits::unlimited())
                .unwrap(),
            Some("xx東京".len()),
        );
        assert!(
            exact
                .shortest_match_at_value("東京", "東京".len() + 1, SearchLimits::unlimited())
                .is_err()
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
