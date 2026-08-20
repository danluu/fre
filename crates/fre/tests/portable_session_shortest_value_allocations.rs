#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    K0SearchError, PlanKind, PlanSelection, PortableBuilder, SearchError, SearchLimits,
    SearchSessionLimits, SearchWindow,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn warm_k0_session_shortest_values_have_zero_steady_allocations() {
    let regex = PortableBuilder::new(r"(?-u:(?:a+b+c+X|d+e+f+Y))")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("shortest-value K0 fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::K0);
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("shortest-value K0 session builds");
    let full = b"aaabbbcccX";
    let ranged = b"zzdddeeefffY";
    let absent = b"xxxxxxxxxxxx";
    let unlimited = SearchLimits::unlimited();

    for _ in 0..2 {
        assert_eq!(
            session.shortest_match_value(full, unlimited).unwrap(),
            Some(full.len()),
        );
        assert_eq!(
            session
                .shortest_match_at_value(ranged, 2, unlimited)
                .unwrap(),
            Some(ranged.len()),
        );
        assert_eq!(
            session.shortest_match_value(absent, unlimited).unwrap(),
            None
        );
    }

    let region = Region::new(GLOBAL);
    for _ in 0..128 {
        assert_eq!(
            session.shortest_match_value(full, unlimited).unwrap(),
            Some(full.len()),
        );
        assert_eq!(
            session
                .shortest_match_at_value(ranged, 2, unlimited)
                .unwrap(),
            Some(ranged.len()),
        );
        assert_eq!(
            session.shortest_match_value(absent, unlimited).unwrap(),
            None
        );
    }
    let refused = SearchLimits {
        max_work: 0,
        max_scratch_bytes: usize::MAX,
    };
    assert!(matches!(
        session.shortest_match_value(full, refused),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded { .. }))
    ));
    assert!(matches!(
        session.shortest_match_window_value(
            full,
            SearchWindow::new(4, 3),
            SearchLimits::unlimited(),
        ),
        Err(SearchError::K0(K0SearchError::InvalidWindow { .. }))
    ));
    assert_eq!(region.change(), Stats::default());
}
