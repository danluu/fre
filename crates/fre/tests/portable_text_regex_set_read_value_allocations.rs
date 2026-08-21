#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableTextProof, PortableTextRegexSet};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn caller_buffer_text_values_grow_once_then_reuse_pooled_scratch() {
    let set = PortableTextRegexSet::new(["(?:ab|cd|ef)+X", "a", "é"])
        .expect("mixed caller-buffer text set");
    let report = set.pattern_build_report(0).expect("K0 pattern report");
    assert_eq!(report.portable.plan, PlanKind::K0);
    assert!(matches!(
        &report.proof,
        PortableTextProof::IdenticalUtf8Hir {
            has_look_assertions: false,
            ..
        }
    ));
    let haystack = "é\nababX";
    let mut flags = [false; 5];

    let cold = Region::new(GLOBAL);
    assert!(
        set.matches_read_value_unlimited(&mut flags, haystack)
            .expect("cold caller-buffer value search")
    );
    assert!(cold.change().allocations > 0);
    drop(cold);

    let warm = Region::new(GLOBAL);
    for start in 0..=haystack.len() {
        flags.fill(false);
        let _ = set
            .matches_read_at_value_unlimited(&mut flags, haystack, start)
            .expect("warm ranged caller-buffer value search");
    }
    assert_eq!(warm.change(), Stats::default());
    drop(warm);

    let invalid = haystack.len() + 1;
    let errors = Region::new(GLOBAL);
    assert!(
        set.matches_read_at_value_unlimited(&mut flags, haystack, invalid)
            .is_err()
    );
    assert!(
        set.matches_read_at_value_unlimited(&mut flags[..1], haystack, 0)
            .is_err()
    );
    assert_eq!(errors.change(), Stats::default());
}
