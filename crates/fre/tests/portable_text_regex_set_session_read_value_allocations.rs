#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PlanKind, PortableRegexSetSessionLimits, PortableTextProof, PortableTextRegexSet};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn fixed_session_caller_buffer_values_allocate_neither_cold_nor_warm() {
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

    let mut proof_warmup = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("proof warmup session");
    assert!(
        proof_warmup
            .matches_read_value_unlimited(&mut flags, haystack)
            .expect("proof warmup search")
    );
    drop(proof_warmup);

    let mut value = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed caller-buffer session");
    let setup = value.setup_report();
    flags.fill(false);
    let cold = Region::new(GLOBAL);
    assert!(
        value
            .matches_read_value_unlimited(&mut flags, haystack)
            .expect("cold caller-buffer value search")
    );
    assert_eq!(cold.change(), Stats::default());
    drop(cold);

    let warm = Region::new(GLOBAL);
    for start in 0..=haystack.len() {
        flags.fill(false);
        let _ = value
            .matches_read_at_value_unlimited(&mut flags, haystack, start)
            .expect("warm ranged caller-buffer value search");
    }
    assert_eq!(warm.change(), Stats::default());
    drop(warm);
    assert_eq!(value.setup_report(), setup);

    let invalid = haystack.len() + 1;
    let errors = Region::new(GLOBAL);
    assert!(
        value
            .matches_read_at_value_unlimited(&mut flags, haystack, invalid)
            .is_err()
    );
    assert!(
        value
            .matches_read_at_value_unlimited(&mut flags[..1], haystack, 0)
            .is_err()
    );
    assert_eq!(errors.change(), Stats::default());
    drop(errors);

    assertion_accounted_subroute_allocates_neither_cold_nor_warm();
}

fn assertion_accounted_subroute_allocates_neither_cold_nor_warm() {
    let set = PortableTextRegexSet::new([r"(?m)^(?:ab|cd)+X$"]).expect("asserted K0 text set");
    let haystack = "ababX";
    let mut flags = [false; 1];

    let mut proof_warmup = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("asserted proof warmup session");
    assert!(
        proof_warmup
            .matches_read_value_unlimited(&mut flags, haystack)
            .expect("asserted proof warmup search")
    );
    drop(proof_warmup);

    flags.fill(false);
    let mut value = set
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed asserted session");
    let cold = Region::new(GLOBAL);
    assert!(
        value
            .matches_read_value_unlimited(&mut flags, haystack)
            .expect("cold asserted search")
    );
    assert_eq!(cold.change(), Stats::default());
    drop(cold);

    let warm = Region::new(GLOBAL);
    for _ in 0..32 {
        flags.fill(false);
        assert!(
            value
                .matches_read_value_unlimited(&mut flags, haystack)
                .expect("warm asserted search")
        );
    }
    assert_eq!(warm.change(), Stats::default());
}
