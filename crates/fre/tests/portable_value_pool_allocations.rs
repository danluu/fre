#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanSelection, PortableBuilder, SearchLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn default_k0_value_calls_reuse_scratch_while_custom_limits_remain_one_shot() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap();
    let haystack = b"xxxxxxxxabacabacz";
    let limits = SearchLimits::default();

    let cold = Region::new(GLOBAL);
    assert_eq!(
        regex
            .find_value(haystack, limits)
            .unwrap()
            .map(|matched| (matched.start(), matched.end())),
        Some((8, 17)),
    );
    let cold_change = cold.change();
    assert!(cold_change.allocations > 0);

    let warm = Region::new(GLOBAL);
    for _ in 0..32 {
        assert_eq!(
            regex
                .find_value(haystack, limits)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            Some((8, 17)),
        );
        assert!(regex.is_match_value(haystack, limits).unwrap());
        assert_eq!(
            regex.selected_end_value(haystack, limits).unwrap(),
            Some(17)
        );
    }
    assert_eq!(warm.change(), Stats::default());

    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let cold_fallback = Region::new(GLOBAL);
                assert!(regex.is_match_value(haystack, limits).unwrap());
                assert!(
                    cold_fallback.change().allocations > 0,
                    "the first nonowner call constructs its independent fallback",
                );

                let warm_fallback = Region::new(GLOBAL);
                for _ in 0..32 {
                    assert_eq!(
                        regex
                            .find_value(haystack, limits)
                            .unwrap()
                            .map(|matched| (matched.start(), matched.end())),
                        Some((8, 17)),
                    );
                    assert!(regex.is_match_value(haystack, limits).unwrap());
                    assert_eq!(
                        regex.selected_end_value(haystack, limits).unwrap(),
                        Some(17)
                    );
                }
                assert_eq!(warm_fallback.change(), Stats::default());
            })
            .join()
            .unwrap();
    });

    let custom_regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap();
    let haystack = b"xxxxxxxxabacabacz";
    let limits = SearchLimits {
        max_work: SearchLimits::default().max_work - 1,
        ..SearchLimits::default()
    };

    for _ in 0..2 {
        let call = Region::new(GLOBAL);
        assert_eq!(
            custom_regex
                .find_value(haystack, limits)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            Some((8, 17)),
        );
        assert!(call.change().allocations > 0);
    }
}

#[test]
fn ordinary_k0_calls_reuse_scratch_without_allocating_after_warmup() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap();
    let haystack = b"xxxxxxxxabacabacz";

    let cold = Region::new(GLOBAL);
    assert_eq!(
        regex
            .find(haystack)
            .map(|matched| (matched.start(), matched.end())),
        Some((8, 17)),
    );
    assert!(cold.change().allocations > 0);

    let warm = Region::new(GLOBAL);
    for _ in 0..32 {
        assert_eq!(
            regex
                .find(haystack)
                .map(|matched| (matched.start(), matched.end())),
            Some((8, 17)),
        );
        assert!(regex.is_match(haystack));
    }
    assert_eq!(warm.change(), Stats::default());
}

#[test]
fn ordinary_prepared_k0_exists_is_allocation_free_after_warmup() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .unwrap();
    let missing = vec![b'x'; 128];
    let mut matching = missing.clone();
    matching.extend_from_slice(b"abacabacz");

    // The first pass constructs and fills the matcher-owned workspace. The
    // second pass proves both source outcomes can use its prepared rows before
    // allocation accounting begins.
    assert!(regex.is_match(&matching));
    assert!(!regex.is_match(&missing));
    assert!(regex.is_match(&matching));
    assert!(!regex.is_match(&missing));

    let warm = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(regex.is_match(&matching));
        assert!(!regex.is_match(&missing));
    }
    assert_eq!(warm.change(), Stats::default());
}
