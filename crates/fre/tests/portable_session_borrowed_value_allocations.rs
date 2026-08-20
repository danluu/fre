#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    ByteMatch, K0SearchError, PlanSelection, PortableBuilder, SearchError, SearchLimits,
    SearchSessionLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn observed(matched: Option<ByteMatch<'_>>) -> Option<(usize, usize, &[u8])> {
    matched.map(|matched| (matched.start(), matched.end(), matched.as_bytes()))
}

#[test]
fn warm_session_borrowed_values_preserve_limits_reuse_setup_and_allocations() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("K0 borrowed-value regex");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("K0 borrowed-value session");
    let setup = session
        .workspace_setup_accounting()
        .expect("K0 session setup accounting");
    let full = b"xxxxxxxxabacabacz";
    let ranged = b"abz--acabacz";

    assert_eq!(
        observed(
            session
                .find_borrowed_value(full, SearchLimits::unlimited())
                .expect("warm full borrowed value"),
        ),
        Some((8, 17, &full[8..17])),
    );
    assert_eq!(
        observed(
            session
                .find_at_borrowed_value(ranged, 4, SearchLimits::unlimited())
                .expect("warm ranged borrowed value"),
        ),
        Some((5, 12, &ranged[5..12])),
    );
    assert_eq!(session.workspace_setup_accounting(), Some(setup));

    let region = Region::new(GLOBAL);
    for limits in [SearchLimits::default(), SearchLimits::unlimited()] {
        assert_eq!(
            observed(
                session
                    .find_borrowed_value(full, limits)
                    .expect("finite/full borrowed value"),
            ),
            Some((8, 17, &full[8..17])),
        );
        assert_eq!(
            observed(
                session
                    .find_at_borrowed_value(ranged, 4, limits)
                    .expect("finite/ranged borrowed value"),
            ),
            Some((5, 12, &ranged[5..12])),
        );
        assert_eq!(
            session
                .find_borrowed_value(b"xxxxxxxx", limits)
                .expect("borrowed value miss"),
            None,
        );
    }

    let refused = SearchLimits {
        max_work: 0,
        max_scratch_bytes: usize::MAX,
    };
    assert!(matches!(
        session.find_borrowed_value(full, refused),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded { .. }))
    ));
    assert!(matches!(
        session.find_at_borrowed_value(ranged, 4, refused),
        Err(SearchError::K0(K0SearchError::WorkLimitExceeded { .. }))
    ));
    assert!(matches!(
        session.find_at_borrowed_value(full, full.len() + 1, SearchLimits::unlimited()),
        Err(SearchError::K0(K0SearchError::InvalidWindow {
            start: 18,
            end: 17,
            haystack_len: 17,
        }))
    ));

    assert_eq!(
        observed(
            session
                .find_borrowed_value(full, SearchLimits::unlimited())
                .expect("full borrowed value after refusal"),
        ),
        Some((8, 17, &full[8..17])),
    );
    assert_eq!(
        observed(
            session
                .find_at_borrowed_value(ranged, 4, SearchLimits::unlimited())
                .expect("ranged borrowed value after refusal"),
        ),
        Some((5, 12, &ranged[5..12])),
    );
    assert_eq!(session.workspace_setup_accounting(), Some(setup));
    assert_eq!(region.change(), Stats::default());
}
