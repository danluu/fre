#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    PlanKind, PortableRegexSetRunLimits, PortableRegexSetSessionLimits, PortableTextProof,
    PortableTextRegexSet,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn fixed_text_set_session_value_existence_allocates_neither_cold_nor_warm() {
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

    for start in [0, 1, haystack.len()] {
        let warm = Region::new(GLOBAL);
        for _ in 0..16 {
            assert_eq!(
                value
                    .is_match_value_at(haystack, start, limits)
                    .expect("warm ranged value search"),
                start < haystack.len(),
            );
        }
        assert_eq!(warm.change(), Stats::default(), "start {start}");
        drop(warm);
    }
    assert_eq!(value.setup_report(), setup);
    assertion_accounted_subroute_allocates_neither_cold_nor_warm();
}

fn assertion_accounted_subroute_allocates_neither_cold_nor_warm() {
    let pattern = r"(?m)^(?:ab|cd)+X$";
    let haystack = "ababX";
    let set = PortableTextRegexSet::new([pattern]).expect("asserted K0 text set");
    let report = set.pattern_build_report(0).expect("pattern report");
    assert_eq!(report.portable.plan, PlanKind::K0);
    assert!(matches!(
        &report.proof,
        PortableTextProof::IdenticalUtf8Hir {
            has_look_assertions: true,
            ..
        }
    ));
    let limits = PortableRegexSetRunLimits::unlimited();
    let mut proof_warmup = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("asserted proof warmup session");
    assert!(
        proof_warmup
            .is_match_value(haystack, limits)
            .expect("asserted proof warmup search")
    );
    drop(proof_warmup);

    let mut value = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed asserted value session");

    let cold = Region::new(GLOBAL);
    assert!(
        value
            .is_match_value(haystack, limits)
            .expect("cold asserted value search")
    );
    assert_eq!(cold.change(), Stats::default());
    drop(cold);

    let warm = Region::new(GLOBAL);
    for _ in 0..32 {
        assert!(
            value
                .is_match_value(haystack, limits)
                .expect("warm asserted value search")
        );
    }
    assert_eq!(warm.change(), Stats::default());
}
