#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableBuilder, SearchAccounting, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn pure_byte_class_shortest_values_allocate_nothing() {
    let regex = PortableBuilder::new("a+")
        .unicode(false)
        .build()
        .expect("pure-byte allocation fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::PureByteClassRepeat);
    let matched = b"zzza";
    let absent = b"zzzz";
    let (_, accounting) = regex
        .shortest_match(matched, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::PureByteClassRepeat(accounting) = accounting else {
        panic!("pure-byte fixture published another accounting family");
    };
    let exact = SearchLimits {
        max_work: accounting.actual_work,
        max_scratch_bytes: 0,
    };
    let one_below = SearchLimits {
        max_work: accounting.actual_work - 1,
        max_scratch_bytes: 0,
    };

    let classified = PortableBuilder::new("(?-u:[aceg])+")
        .unicode(false)
        .build()
        .expect("classified pure-byte allocation fixture builds");
    assert_eq!(
        classified.build_report().plan,
        PlanKind::PureByteClassRepeat
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(regex.shortest_match_value(matched, exact).unwrap(), Some(4));
        assert_eq!(
            regex.shortest_match_at_value(matched, 1, exact).unwrap(),
            Some(4),
        );
        assert_eq!(regex.shortest_match_value(absent, exact).unwrap(), None);
        assert!(regex.shortest_match_value(matched, one_below).is_err());
        assert!(
            regex
                .shortest_match_at_value(matched, matched.len() + 1, exact)
                .is_err()
        );
        assert_eq!(
            classified
                .shortest_match_value(b"zzzg", SearchLimits::unlimited())
                .unwrap(),
            Some(4),
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
