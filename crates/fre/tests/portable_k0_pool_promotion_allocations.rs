#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanSelection, PortableBuilder, SearchLimits, SearchSessionLimits};
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

    let endpoint_regex = k0();
    let endpoint_region = Region::new(GLOBAL);
    let endpoint = endpoint_regex
        .endpoint_search_session(SearchSessionLimits::unlimited())
        .expect("adaptive endpoint session constructs");
    let endpoint_allocations = endpoint_region.change();
    let endpoint_setup = endpoint
        .workspace_setup_accounting()
        .expect("forced K0 endpoint setup accounting");

    let fixed_regex = k0();
    let fixed_region = Region::new(GLOBAL);
    let fixed = fixed_regex
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("fixed bidirectional session constructs");
    let fixed_allocations = fixed_region.change();
    let fixed_setup = fixed
        .workspace_setup_accounting()
        .expect("forced K0 fixed setup accounting");
    assert!(
        endpoint_setup.retained_bytes().saturating_mul(2) < fixed_setup.retained_bytes(),
        "adaptive endpoint seed should retain substantially less than fixed full K0: endpoint={endpoint_setup:?}, fixed={fixed_setup:?}",
    );
    assert!(
        endpoint_allocations.bytes_allocated.saturating_mul(2) < fixed_allocations.bytes_allocated,
        "adaptive endpoint construction should allocate substantially fewer bytes: endpoint={endpoint_allocations:?}, fixed={fixed_allocations:?}",
    );
    drop(endpoint);
    drop(fixed);

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
        cold_exists.allocations.saturating_mul(3) / 2 < cold_span.allocations
            && cold_exists.bytes_allocated < cold_span.bytes_allocated,
        "fresh Exists should use substantially fewer allocation calls by omitting reverse workspace storage: exists={cold_exists:?}, span={cold_span:?}",
    );

    let exists_after_span = Region::new(GLOBAL);
    for _ in 0..32 {
        assert!(span_first.is_match_value(haystack, limits).unwrap());
    }
    assert_eq!(exists_after_span.change(), Stats::default());
}
