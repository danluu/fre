#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PortableBuilder, SearchAccounting, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn nullable_shortest_values_allocate_nothing() {
    let optional = PortableBuilder::new(r"(?-u:[ab]?[ab]?z)")
        .unicode(false)
        .build()
        .unwrap();
    let finite = PortableBuilder::new(r"(?-u:(?:a|aa|ba){0,3}z)")
        .unicode(false)
        .build()
        .unwrap();
    let optional_haystack = b"xxaaz--z";
    let finite_haystack = b"xxaabaz--z";
    let (_, accounting) = finite
        .shortest_match(finite_haystack, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::NullableOptionalChain(accounting) = accounting else {
        panic!("finite-token shortest fixture published another accounting family");
    };
    let exact = SearchLimits {
        max_work: accounting.work_upper_bound,
        max_scratch_bytes: 0,
    };
    let refused = SearchLimits {
        max_work: accounting.work_upper_bound - 1,
        max_scratch_bytes: 0,
    };

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            optional
                .shortest_match_value(optional_haystack, SearchLimits::unlimited())
                .unwrap(),
            Some(5),
        );
        assert_eq!(
            optional
                .shortest_match_at_value(optional_haystack, 5, SearchLimits::unlimited())
                .unwrap(),
            Some(8),
        );
        assert_eq!(
            finite.shortest_match_value(finite_haystack, exact).unwrap(),
            Some(7),
        );
        assert!(
            finite
                .shortest_match_value(finite_haystack, refused)
                .is_err()
        );
        assert_eq!(
            finite
                .shortest_match_value(b"xxxxxxxx", SearchLimits::unlimited())
                .unwrap(),
            None,
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
