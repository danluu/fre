#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PortableBuilder, SearchAccounting, SearchLimits, SearchSessionLimits, SearchWindow};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn pure_byte_find_values_allocate_nothing() {
    let lazy = PortableBuilder::new(r"(?-u:[a-z]+?)")
        .unicode(false)
        .build()
        .unwrap();
    let greedy = PortableBuilder::new(r"(?-u:[0-9]+)")
        .unicode(false)
        .build()
        .unwrap();
    let lazy_haystack = b"--hello--";
    let greedy_haystack = b"xx12345--";
    let (_, accounting) = lazy
        .find_accounted(lazy_haystack, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::PureByteClassRepeat(accounting) = accounting else {
        panic!("pure-byte fixture published another accounting family");
    };
    assert!(accounting.actual_work > 0);
    let exact = SearchLimits {
        max_work: accounting.work_upper_bound,
        max_scratch_bytes: 0,
    };
    let refused = SearchLimits {
        max_work: accounting.actual_work - 1,
        max_scratch_bytes: 0,
    };
    let mut lazy_session = lazy
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    let mut greedy_session = greedy
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        let matched = lazy
            .find_value(lazy_haystack, SearchLimits::unlimited())
            .unwrap()
            .unwrap();
        assert_eq!((matched.start(), matched.end()), (2, 3));
        let matched = greedy_session
            .find_value(greedy_haystack, SearchLimits::unlimited())
            .unwrap()
            .unwrap();
        assert_eq!((matched.start(), matched.end()), (2, 7));
        let matched = lazy_session
            .find_at_value(lazy_haystack, 3, exact)
            .unwrap()
            .unwrap();
        assert_eq!((matched.start(), matched.end()), (3, 4));
        assert!(lazy.find_value(lazy_haystack, refused).is_err());
        assert_eq!(
            greedy
                .find_value(b"---------", SearchLimits::unlimited())
                .unwrap(),
            None
        );
        assert!(
            lazy.find_window_value(
                lazy_haystack,
                SearchWindow::new(lazy_haystack.len() + 1, lazy_haystack.len()),
                SearchLimits::unlimited(),
            )
            .is_err()
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
