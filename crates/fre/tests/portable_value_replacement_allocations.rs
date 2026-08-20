#![forbid(unsafe_code)]

use std::{alloc::System, borrow::Cow};

use fre::{
    PlanSelection, PortableBuilder, PortableFindIterRunLimits, SearchLimits, SearchSessionLimits,
    ValueReplacementOutputLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn warm_literal_value_replacement_allocates_only_its_matched_output() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("K0 allocation regex");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("K0 allocation session");
    assert_eq!(
        session
            .find_value(b"xxxxxxxxabacabacz", SearchLimits::unlimited())
            .expect("session warmup")
            .map(|matched| (matched.start(), matched.end())),
        Some((8, 17)),
    );

    let no_match_region = Region::new(GLOBAL);
    let no_match = session
        .replace_literal_value(
            b"xxxxxxxx",
            b"_",
            PortableFindIterRunLimits::unlimited(),
            ValueReplacementOutputLimits::default(),
        )
        .expect("warm no-match replacement");
    let no_match_change = no_match_region.change();
    assert!(matches!(no_match, Cow::Borrowed(_)));
    assert_eq!(no_match.as_ref(), b"xxxxxxxx");
    assert_eq!(no_match_change, Stats::default());

    let matched_region = Region::new(GLOBAL);
    let matched = session
        .replace_literal_value(
            b"xxxxxxxxabacabacz",
            b"_",
            PortableFindIterRunLimits::unlimited(),
            ValueReplacementOutputLimits::default(),
        )
        .expect("warm matched replacement");
    let matched_change = matched_region.change();
    assert!(matches!(matched, Cow::Owned(_)));
    assert_eq!(matched.as_ref(), b"xxxxxxxx_");
    assert_eq!(matched_change.allocations, 1, "{matched_change:?}");
    assert_eq!(matched_change.reallocations, 0, "{matched_change:?}");
    assert_eq!(matched_change.deallocations, 0, "{matched_change:?}");
}
