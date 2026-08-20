#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{ByteMatch, K0SearchError, PlanSelection, PortableBuilder, SearchError, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn observed(matched: Option<ByteMatch<'_>>) -> Option<(usize, usize, &[u8])> {
    matched.map(|matched| (matched.start(), matched.end(), matched.as_bytes()))
}

#[test]
fn immutable_borrowed_values_preserve_limits_and_reuse_the_value_pool() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("K0 borrowed-value regex");
    let full = b"xxxxxxxxabacabacz";
    let ranged = b"abz--acabacz";

    let cold = Region::new(GLOBAL);
    assert_eq!(
        observed(
            regex
                .find_borrowed_value(full, SearchLimits::default())
                .expect("cold full borrowed value"),
        ),
        Some((8, 17, &full[8..17])),
    );
    assert!(cold.change().allocations > 0);

    assert_eq!(
        observed(
            regex
                .find_at_borrowed_value(ranged, 4, SearchLimits::unlimited())
                .expect("warm ranged borrowed value"),
        ),
        Some((5, 12, &ranged[5..12])),
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
        regex.find_at_borrowed_value(ranged, 4, refused),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded { .. }))
    ));
    assert!(matches!(
        regex.find_at_borrowed_value(full, full.len() + 1, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 18,
            end: 17,
            haystack_len: 17,
        }))
    ));

    let warm = Region::new(GLOBAL);
    for limits in [SearchLimits::default(), SearchLimits::unlimited()] {
        assert_eq!(
            observed(
                regex
                    .find_borrowed_value(full, limits)
                    .expect("finite/full borrowed value"),
            ),
            Some((8, 17, &full[8..17])),
        );
        assert_eq!(
            observed(
                regex
                    .find_at_borrowed_value(ranged, 4, limits)
                    .expect("finite/ranged borrowed value"),
            ),
            Some((5, 12, &ranged[5..12])),
        );
        assert_eq!(
            regex
                .find_borrowed_value(b"xxxxxxxx", limits)
                .expect("borrowed value miss"),
            None,
        );
    }
    assert_eq!(warm.change(), Stats::default());
}
