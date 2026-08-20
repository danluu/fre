#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanSelection, PortableBuilder, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn k0() -> fre::PortableRegex {
    PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("focused pattern builds through K0")
}

#[test]
fn exists_first_is_cheaper_then_promotes_once_without_losing_the_warm_path() {
    let regex = k0();
    let haystack = b"xxxxxxxxabacabacz";
    let limits = SearchLimits::unlimited();

    let cold_exists = Region::new(GLOBAL);
    assert!(regex.is_match_value(haystack, limits).unwrap());
    let cold_exists = cold_exists.change();
    assert!(cold_exists.allocations > 0);

    let warm_exists = Region::new(GLOBAL);
    for _ in 0..32 {
        assert!(regex.is_match_value(haystack, limits).unwrap());
    }
    assert_eq!(warm_exists.change(), Stats::default());

    let promotion = Region::new(GLOBAL);
    assert_eq!(
        regex
            .find_value(haystack, limits)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        Some((8, 17)),
    );
    assert!(promotion.change().allocations > 0);

    let warm_bidirectional = Region::new(GLOBAL);
    for _ in 0..32 {
        assert!(regex.is_match_value(haystack, limits).unwrap());
        assert_eq!(
            regex
                .find_value(haystack, limits)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            Some((8, 17)),
        );
    }
    assert_eq!(warm_bidirectional.change(), Stats::default());

    let span_first = k0();
    let cold_span = Region::new(GLOBAL);
    assert_eq!(
        span_first
            .find_value(haystack, limits)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        Some((8, 17)),
    );
    let cold_span = cold_span.change();
    assert!(
        cold_exists.allocations < cold_span.allocations
            && cold_exists.bytes_allocated < cold_span.bytes_allocated,
        "fresh Exists should omit reverse workspace allocations: exists={cold_exists:?}, span={cold_span:?}",
    );

    let exists_after_span = Region::new(GLOBAL);
    for _ in 0..32 {
        assert!(span_first.is_match_value(haystack, limits).unwrap());
    }
    assert_eq!(exists_after_span.change(), Stats::default());
}
