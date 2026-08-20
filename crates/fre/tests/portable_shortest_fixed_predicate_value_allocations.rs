#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableBuilder, SearchAccounting, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const PATTERN: &str = r"Q[ab][cd][ef][gh][ij][kl][mn][op][rs][tu][vw][xy][01]";

#[test]
fn fixed_predicate_shortest_values_allocate_nothing_on_success_or_refusal() {
    let regex = PortableBuilder::new(PATTERN)
        .unicode(false)
        .build()
        .expect("fixed-predicate allocation fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::FixedPredicateWord64);
    let matched = b"--Qacegikmortvx0--";
    let absent = b"------------------";
    let (_, accounting) = regex
        .shortest_match(matched, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::FixedPredicateWord64(accounting) = accounting else {
        panic!("fixed-predicate fixture published another accounting family");
    };
    assert_eq!(accounting.upper_bounds.scratch_bytes, 0);
    let exact = SearchLimits {
        max_work: accounting.upper_bounds.work,
        max_scratch_bytes: 0,
    };
    let one_below = SearchLimits {
        max_work: accounting.upper_bounds.work - 1,
        max_scratch_bytes: 0,
    };

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            regex.shortest_match_value(matched, exact).unwrap(),
            Some(16),
        );
        assert_eq!(
            regex.shortest_match_at_value(matched, 2, exact).unwrap(),
            Some(16),
        );
        assert_eq!(regex.shortest_match_value(absent, exact).unwrap(), None,);
        assert!(regex.shortest_match_value(matched, one_below).is_err());
        assert!(
            regex
                .shortest_match_at_value(matched, matched.len() + 1, exact)
                .is_err()
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
