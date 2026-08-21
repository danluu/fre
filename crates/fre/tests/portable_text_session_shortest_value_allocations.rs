#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    PlanSelection, PortableTextBuilder, PortableTextRegex, SearchLimits, SearchSessionLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn text_session_shortest_values_are_allocation_free_after_setup() {
    let k0 = PortableTextBuilder::new(r"(?:αβ|γδ)+Z")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("forced K0 text regex");
    let exact = PortableTextRegex::new("東京").expect("exact text literal");
    let mut k0_session = k0
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("fixed K0 text session");
    let mut exact_session = exact
        .fixed_search_session(SearchSessionLimits::unlimited())
        .expect("fixed exact text session");
    k0_session
        .prepare_k0_start_filter(SearchSessionLimits::unlimited())
        .expect("optional K0 proof");
    let present = "☃αβγδαβZx";
    let expected_end = "☃αβγδαβZ".len();

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            k0_session
                .shortest_match_value(present, SearchLimits::unlimited())
                .unwrap(),
            Some(expected_end),
        );
        assert_eq!(
            k0_session
                .shortest_match_at_value(present, 1, SearchLimits::unlimited())
                .unwrap(),
            Some(expected_end),
        );
        assert_eq!(
            k0_session
                .shortest_match_value("☃xxxxxxxx", SearchLimits::unlimited())
                .unwrap(),
            None,
        );
        assert_eq!(
            exact_session
                .shortest_match_value("xx東京yy", SearchLimits::unlimited())
                .unwrap(),
            Some("xx東京".len()),
        );
        assert!(
            k0_session
                .shortest_match_value(
                    present,
                    SearchLimits {
                        max_work: 0,
                        max_scratch_bytes: usize::MAX,
                    },
                )
                .is_err()
        );
        assert!(
            exact_session
                .shortest_match_at_value("東京", "東京".len() + 1, SearchLimits::unlimited())
                .is_err()
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
