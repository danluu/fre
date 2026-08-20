#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    PlanKind, PortableBuilder, SearchAccounting, SearchLimits, SearchSessionLimits, SearchWindow,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn generalized_shortest_values_allocate_nothing() {
    let regex = PortableBuilder::new(r"a[ab]+c")
        .unicode(false)
        .build()
        .expect("generalized shortest fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::LiteralClassRunLiteral);
    let haystack = b"!!aabbc!!";
    let absent = b"!!bbbb!!";
    let window = SearchWindow::full(haystack);
    let (_, accounting) = regex
        .shortest_match(haystack, SearchLimits::unlimited())
        .unwrap();
    let SearchAccounting::LiteralClassRunLiteral(accounting) = accounting else {
        panic!("generalized fixture published another accounting family");
    };
    assert!(accounting.work > 0);
    let exact = SearchLimits {
        max_work: u64::try_from(accounting.work).unwrap(),
        max_scratch_bytes: 0,
    };
    let refusing = SearchLimits {
        max_work: exact.max_work - 1,
        max_scratch_bytes: 0,
    };
    let custom = SearchLimits {
        max_work: u64::MAX,
        max_scratch_bytes: 0,
    };
    let invalid = SearchWindow::new(haystack.len(), haystack.len() - 1);
    let guarded = PortableBuilder::new(r"\b[A-Za-z]+TRAILER\b")
        .unicode(false)
        .build()
        .expect("guarded shortest fixture builds");
    let guarded_haystack = b"!abcTRAILER!";
    let prefix_only = PortableBuilder::new(r"a[bc]*")
        .unicode(false)
        .build()
        .expect("prefix-only shortest fixture builds");
    let prefix_haystack = b"!abcb!";
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("generalized shortest session builds");

    assert_eq!(
        regex
            .shortest_match_value(haystack, SearchLimits::unlimited())
            .unwrap(),
        Some(7)
    );
    assert_eq!(
        session
            .shortest_match_window_value(haystack, window, SearchLimits::unlimited())
            .unwrap(),
        Some(7)
    );
    assert_eq!(
        guarded
            .shortest_match_value(guarded_haystack, SearchLimits::unlimited())
            .unwrap(),
        Some(11)
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            regex
                .shortest_match_value(haystack, SearchLimits::unlimited())
                .unwrap(),
            Some(7)
        );
        assert_eq!(
            session
                .shortest_match_window_value(haystack, window, SearchLimits::unlimited())
                .unwrap(),
            Some(7)
        );
        assert_eq!(
            regex
                .shortest_match_value(absent, SearchLimits::unlimited())
                .unwrap(),
            None
        );
        assert_eq!(
            regex.shortest_match_value(haystack, exact).unwrap(),
            Some(7)
        );
        assert_eq!(
            regex.shortest_match_value(haystack, custom).unwrap(),
            Some(7)
        );
        assert!(regex.shortest_match_value(haystack, refusing).is_err());
        assert!(
            session
                .shortest_match_window_value(haystack, invalid, SearchLimits::unlimited())
                .is_err()
        );
        assert_eq!(
            guarded
                .shortest_match_value(guarded_haystack, SearchLimits::unlimited())
                .unwrap(),
            Some(11)
        );
        assert_eq!(
            prefix_only
                .shortest_match_value(prefix_haystack, SearchLimits::unlimited())
                .unwrap(),
            Some(2)
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
