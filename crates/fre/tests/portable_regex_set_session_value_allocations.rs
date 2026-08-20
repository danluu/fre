#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableRegexSet, PortableRegexSetRunLimits, PortableRegexSetSessionLimits};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn fixed_set_session_value_existence_allocates_neither_cold_nor_warm() {
    let pattern = "(?:ab|cd|ef)+X";
    let haystack = b"ababX";
    let set = PortableRegexSet::new([pattern]).expect("K0 byte set");
    assert_eq!(
        set.pattern_build_report(0).expect("pattern report").plan,
        PlanKind::K0,
    );
    let limits = PortableRegexSetRunLimits::unlimited();

    let mut proof_warmup = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("proof warmup session");
    assert!(
        proof_warmup
            .is_match_value(haystack, limits)
            .expect("proof warmup search")
    );
    drop(proof_warmup);

    let mut value = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed value session");
    let setup = value.setup_report();
    let cold = Region::new(GLOBAL);
    assert!(
        value
            .is_match_value(haystack, limits)
            .expect("cold value search")
    );
    assert_eq!(cold.change(), Stats::default());
    drop(cold);

    let warm = Region::new(GLOBAL);
    for start in [0, 1, haystack.len()] {
        for _ in 0..16 {
            assert_eq!(
                value
                    .is_match_value_at(haystack, start, limits)
                    .expect("warm ranged value search"),
                start < haystack.len(),
            );
        }
    }
    assert_eq!(warm.change(), Stats::default());
    drop(warm);
    assert_eq!(value.setup_report(), setup);
}
