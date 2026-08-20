#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PortableBuilder, SearchAccounting, SearchLimits, SearchSessionLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn bounded_sequence_shortest_values_allocate_nothing() {
    let forward = PortableBuilder::new(r"(?-u:[ab]){1,3}(?-u:[CD]){1,3}(?-u:[xy])?")
        .unicode(false)
        .build()
        .unwrap();
    let tail = PortableBuilder::new(r"(?-u:[\x10-\x17]){1,3}(?-u:[\x40-\x5f]){0,11}(?-u:\x7a)")
        .unicode(false)
        .build()
        .unwrap();
    let forward_haystack = b"xxaCDx--bD";
    let tail_haystack = b"\xff\x12\x16EEz\x10z";
    let (_, accounting) = forward
        .shortest_match(forward_haystack, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::BoundedByteClassSequence(accounting) = accounting else {
        panic!("bounded-sequence shortest fixture published another accounting family");
    };
    let exact = SearchLimits {
        max_work: accounting.actual_work,
        max_scratch_bytes: 0,
    };
    let refused = SearchLimits {
        max_work: accounting.actual_work - 1,
        max_scratch_bytes: 0,
    };
    let mut session = tail
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            forward
                .shortest_match_value(forward_haystack, SearchLimits::unlimited())
                .unwrap(),
            Some(4),
        );
        assert_eq!(
            forward
                .shortest_match_at_value(forward_haystack, 4, SearchLimits::unlimited())
                .unwrap(),
            Some(10),
        );
        assert_eq!(
            session
                .shortest_match_at_value(tail_haystack, 1, SearchLimits::unlimited())
                .unwrap(),
            Some(6),
        );
        assert_eq!(
            forward
                .shortest_match_value(forward_haystack, exact)
                .unwrap(),
            Some(4),
        );
        assert!(
            forward
                .shortest_match_value(forward_haystack, refused)
                .is_err(),
        );
        assert_eq!(
            forward
                .shortest_match_value(b"xxxxxxxx", SearchLimits::unlimited())
                .unwrap(),
            None,
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
