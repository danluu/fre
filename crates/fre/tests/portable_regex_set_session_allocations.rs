#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    PlanKind, PortableRegexSet, PortableRegexSetRunLimits, PortableRegexSetSessionLimits,
    PortableTextRegexSet,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const K0_PATTERN: &str = "(?:ab|cd|ef)+X";

#[test]
fn fixed_endpoint_set_sessions_do_not_grow_on_first_or_warm_search() {
    let limits = PortableRegexSetRunLimits::unlimited();
    let byte_haystack = b"ababX";
    let bytes = PortableRegexSet::new([K0_PATTERN]).expect("single K0 byte set");
    assert_eq!(
        bytes.pattern_build_report(0).expect("byte report").plan,
        PlanKind::K0,
    );
    let mut byte_proof_warmup = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("byte proof warmup session");
    assert!(
        byte_proof_warmup
            .is_match(byte_haystack, limits)
            .expect("byte proof warmup search")
            .0,
    );
    drop(byte_proof_warmup);

    let mut byte_session = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed byte endpoint session");
    let byte_first = Region::new(GLOBAL);
    assert!(
        byte_session
            .is_match(byte_haystack, limits)
            .expect("first fixed byte search")
            .0,
    );
    assert_eq!(byte_first.change(), Stats::default());
    drop(byte_first);
    let byte_warm = Region::new(GLOBAL);
    for _ in 0..16 {
        assert!(
            byte_session
                .is_match(byte_haystack, limits)
                .expect("warm fixed byte search")
                .0,
        );
    }
    assert_eq!(byte_warm.change(), Stats::default());
    drop(byte_warm);

    let text_haystack = "ababX";
    let text = PortableTextRegexSet::new([K0_PATTERN]).expect("single K0 text set");
    assert_eq!(
        text.pattern_build_report(0)
            .expect("text report")
            .portable
            .plan,
        PlanKind::K0,
    );
    let mut text_proof_warmup = text
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("text proof warmup session");
    assert!(
        text_proof_warmup
            .is_match(text_haystack, limits)
            .expect("text proof warmup search")
            .0,
    );
    drop(text_proof_warmup);

    let mut text_session = text
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("fixed text endpoint session");
    let text_first = Region::new(GLOBAL);
    assert!(
        text_session
            .is_match(text_haystack, limits)
            .expect("first fixed text search")
            .0,
    );
    assert_eq!(text_first.change(), Stats::default());
    drop(text_first);
    let text_warm = Region::new(GLOBAL);
    for _ in 0..16 {
        assert!(
            text_session
                .is_match(text_haystack, limits)
                .expect("warm fixed text search")
                .0,
        );
    }
    assert_eq!(text_warm.change(), Stats::default());
}
