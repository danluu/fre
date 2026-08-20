#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    PlanKind, PlanSelection, PortableBuilder, PortableFindIterRunLimits, SearchLimits,
    SearchSessionLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const GROWTH_PATTERN: &str = r"(?-u:a?a?a?a?aaaaaaaaaa)";
const GROWTH_HAYSTACK: &[u8] = b"aaaaaaaaaaaaaa";

fn k0(pattern: &str) -> fre::PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("focused pattern builds through K0");
    assert_eq!(regex.build_report().plan, PlanKind::K0);
    regex
}

fn assert_no_growth(accounting: &fre::SearchAccounting) {
    let growth = accounting
        .cache_growth()
        .expect("forced K0 search exposes cache-growth accounting");
    assert_eq!(growth.events(), 0);
    assert_eq!(growth.allocated_bytes(), 0);
    assert_eq!(growth.initialized_bytes(), 0);
    assert_eq!(growth.retained_delta(), 0);
    assert_eq!(growth.peak_scratch_bytes(), 0);
}

#[test]
fn adaptive_search_and_iteration_growth_stabilize_to_zero_allocation() {
    let limits = SearchLimits::unlimited();
    let session_limits = SearchSessionLimits::default();

    // One new source shape grows the adaptive cache. Once that shape has
    // stabilized, repeating it reports and performs no further allocation.
    let growth_regex = k0(GROWTH_PATTERN);
    let mut adaptive = growth_regex
        .search_session(session_limits)
        .expect("adaptive full K0 session constructs");
    let seed_setup = adaptive
        .workspace_setup_accounting()
        .expect("adaptive K0 setup accounting");
    let growth_region = Region::new(GLOBAL);
    let (matched, growth_accounting) = adaptive
        .find(GROWTH_HAYSTACK, limits)
        .expect("new workload grows adaptive K0");
    assert_eq!(
        matched.map(|matched| (matched.start(), matched.end())),
        Some((0, 14))
    );
    let growth_allocations = growth_region.change();
    let growth = growth_accounting
        .cache_growth()
        .expect("forced K0 reports demand growth");
    assert!(growth.events() > 0, "new workload should grow: {growth:?}");
    assert!(growth.allocated_bytes() > 0);
    assert!(growth.initialized_bytes() > 0);
    assert!(growth.retained_delta() > 0);
    assert!(growth.peak_scratch_bytes() > seed_setup.retained_bytes());
    assert!(growth_allocations.allocations > 0);
    assert!(growth_allocations.bytes_allocated >= growth.allocated_bytes());

    let warm_region = Region::new(GLOBAL);
    for _ in 0..16 {
        let (matched, accounting) = adaptive
            .find(GROWTH_HAYSTACK, limits)
            .expect("stabilized adaptive workload reuses its cache");
        assert_eq!(
            matched.map(|matched| (matched.start(), matched.end())),
            Some((0, 14))
        );
        assert_no_growth(&accounting);
    }
    assert_eq!(warm_region.change(), Stats::default());

    // Iteration aggregates growth from every internal search, including the
    // terminal miss, and a repeated stabilized iteration stays at zero.
    let iter_regex = k0(GROWTH_PATTERN);
    let mut iter_session = iter_regex
        .search_session(session_limits)
        .expect("adaptive iterator session constructs");
    let iter_region = Region::new(GLOBAL);
    let mut iter = iter_session.find_iter(GROWTH_HAYSTACK, PortableFindIterRunLimits::unlimited());
    let matched = iter
        .next()
        .expect("adaptive iterator emits its match")
        .expect("adaptive K0 iteration succeeds");
    assert_eq!((matched.start(), matched.end()), (0, 14));
    assert!(iter.next().is_none(), "terminal miss exhausts iterator");
    let iter_accounting = iter.accounting();
    assert!(
        iter_accounting.search_calls >= 2,
        "match plus terminal miss"
    );
    assert!(iter_accounting.cache_growth_events > 0);
    assert!(iter_accounting.cache_growth_allocated_bytes > 0);
    assert!(iter_accounting.cache_growth_initialized_bytes > 0);
    assert!(iter_accounting.cache_growth_retained_delta > 0);
    assert!(iter_accounting.cache_growth_peak_scratch_bytes > 0);
    drop(iter);
    let iter_allocations = iter_region.change();
    assert!(iter_allocations.allocations > 0);

    let warm_iter_region = Region::new(GLOBAL);
    let mut warm_iter =
        iter_session.find_iter(GROWTH_HAYSTACK, PortableFindIterRunLimits::unlimited());
    let matched = warm_iter
        .next()
        .expect("warm iterator emits its match")
        .expect("warm K0 iteration succeeds");
    assert_eq!((matched.start(), matched.end()), (0, 14));
    assert!(
        warm_iter.next().is_none(),
        "warm terminal miss exhausts iterator"
    );
    let warm_iter_accounting = warm_iter.accounting();
    assert_eq!(warm_iter_accounting.cache_growth_events, 0);
    assert_eq!(warm_iter_accounting.cache_growth_allocated_bytes, 0);
    assert_eq!(warm_iter_accounting.cache_growth_initialized_bytes, 0);
    assert_eq!(warm_iter_accounting.cache_growth_retained_delta, 0);
    assert_eq!(warm_iter_accounting.cache_growth_peak_scratch_bytes, 0);
    drop(warm_iter);
    assert_eq!(warm_iter_region.change(), Stats::default());
}
