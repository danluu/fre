#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{K0SearchError, PlanSelection, PortableTextBuilder, SearchError, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn immutable_text_borrowed_values_preserve_limits_and_reuse_the_value_pool() {
    let regex = PortableTextBuilder::new(r"(?:ab|ac)+z")
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("proved K0 text regex");
    let full = "xxxxxxxxabacabacz";
    let ranged = "☃--abz--acabacz";

    let cold = Region::new(GLOBAL);
    let matched = regex
        .find_borrowed_value(full, SearchLimits::default())
        .expect("cold full borrowed value")
        .expect("full match");
    assert_eq!(
        (matched.start(), matched.end(), matched.as_str()),
        (8, 17, "abacabacz")
    );
    assert!(cold.change().allocations > 0);

    let matched = regex
        .find_at_borrowed_value(ranged, 1, SearchLimits::unlimited())
        .expect("warm ranged borrowed value")
        .expect("ranged match");
    assert_eq!(
        (matched.start(), matched.end(), matched.as_str()),
        (5, 8, "abz")
    );

    let refused = SearchLimits {
        max_work: 0,
        max_scratch_bytes: usize::MAX,
    };
    assert!(matches!(
        regex.find_borrowed_value(full, refused),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded { .. }))
    ));
    assert!(matches!(
        regex.find_at_borrowed_value(ranged, 1, refused),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded { .. }))
    ));
    assert!(
        regex
            .find_at_borrowed_value(full, full.len() + 1, SearchLimits::unlimited())
            .is_err()
    );

    let warm = Region::new(GLOBAL);
    for limits in [SearchLimits::default(), SearchLimits::unlimited()] {
        assert_eq!(
            regex
                .find_borrowed_value(full, limits)
                .expect("finite/full borrowed value")
                .map(|matched| (matched.range(), matched.as_str())),
            Some((8..17, "abacabacz")),
        );
        assert_eq!(
            regex
                .find_at_borrowed_value(ranged, 1, limits)
                .expect("finite/ranged borrowed value")
                .map(|matched| (matched.range(), matched.as_str())),
            Some((5..8, "abz")),
        );
        assert_eq!(
            regex
                .find_borrowed_value("xxxxxxxx", limits)
                .expect("borrowed value miss"),
            None,
        );
    }
    assert_eq!(warm.change(), Stats::default());
}
