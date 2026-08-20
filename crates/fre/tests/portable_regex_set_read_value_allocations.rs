#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableRegexSet, PortableRegexSetRunLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn caller_buffer_value_search_grows_once_then_reuses_pooled_scratch() {
    let patterns = [
        "(?:ab|cd|ef)+X",
        "(?:ab|cd|ef)+Y",
        "(?:ab|cd|ef)+Z",
        "(?:ab|cd|ef)+Q",
    ];
    let haystack = b"ababX-cdcdY-efefZ-abcdQ";
    let set = PortableRegexSet::new(patterns).expect("K0 set");
    assert!((0..set.len()).all(|index| {
        set.pattern_build_report(index)
            .expect("pattern report")
            .plan
            == PlanKind::K0
    }));
    let limits = PortableRegexSetRunLimits::unlimited();
    let mut flags = [false; 6];

    let cold = Region::new(GLOBAL);
    assert!(
        set.matches_read_at_value(&mut flags, haystack, 0, limits)
            .expect("cold caller-buffer value search")
    );
    assert!(cold.change().allocations > 0);
    drop(cold);
    assert_eq!(flags, [true, true, true, true, false, false]);

    let warm = Region::new(GLOBAL);
    for start in [0, 1, haystack.len()] {
        for _ in 0..16 {
            let _ = set
                .read_matches_at_value(&mut flags, haystack, start, limits)
                .expect("warm caller-buffer value search");
        }
    }
    assert_eq!(warm.change(), Stats::default());
    drop(warm);
    assert_eq!(flags, [true, true, true, true, false, false]);
}
