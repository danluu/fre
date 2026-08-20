#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableTextProof, PortableTextRegexSet};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn immutable_text_set_value_existence_grows_once_then_reuses_pooled_scratch() {
    let pattern = "(?:ab|cd|ef)+X";
    let haystack = "ababX";
    let set = PortableTextRegexSet::new([pattern]).expect("K0 text set");
    let report = set.pattern_build_report(0).expect("pattern report");
    assert_eq!(report.portable.plan, PlanKind::K0);
    assert!(matches!(
        &report.proof,
        PortableTextProof::IdenticalUtf8Hir {
            has_look_assertions: false,
            ..
        }
    ));

    let cold = Region::new(GLOBAL);
    assert!(
        set.is_match_value_unlimited(haystack)
            .expect("cold value search")
    );
    assert!(cold.change().allocations > 0);
    drop(cold);

    let warm = Region::new(GLOBAL);
    for start in [0, 1, haystack.len()] {
        for _ in 0..16 {
            assert_eq!(
                set.is_match_value_at_unlimited(haystack, start)
                    .expect("warm ranged value search"),
                start < haystack.len(),
            );
        }
    }
    assert_eq!(warm.change(), Stats::default());
}
