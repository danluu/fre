#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    PlanKind, PortableRegexSet, PortableRegexSetSessionLimits, PortableSearchSession,
    PortableTextRegexSet, PortableTextSearchSession,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn all_non_k0_byte_and_text_set_sessions_allocate_one_compact_vector() {
    let patterns: Vec<String> = (0..512)
        .map(|index| format!("literal_{index:04}_payload"))
        .collect();
    let bytes = PortableRegexSet::new(patterns.iter()).expect("non-K0 byte set");
    let text = PortableTextRegexSet::new(patterns.iter()).expect("non-K0 text set");
    assert!((0..patterns.len()).all(|index| {
        bytes.pattern_build_report(index).expect("byte report").plan != PlanKind::K0
            && text
                .pattern_build_report(index)
                .expect("text report")
                .portable
                .plan
                != PlanKind::K0
    }));

    let byte_region = Region::new(GLOBAL);
    let byte_session = bytes
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("compact byte session");
    let byte_change = byte_region.change();
    drop(byte_region);
    let byte_setup = byte_session.setup_report();
    assert_eq!(byte_change.allocations, 1);
    assert_eq!(byte_change.reallocations, 0);
    assert_eq!(byte_change.deallocations, 0);
    assert_eq!(
        byte_change.bytes_allocated,
        byte_setup.session_capacity_bytes
    );
    assert!(byte_setup.session_capacity_bytes > 0);
    assert!(
        byte_setup.session_capacity_bytes
            < patterns.len() * core::mem::size_of::<PortableSearchSession<'_>>()
    );
    assert_eq!(
        byte_setup.charged_retained_bytes,
        byte_setup.session_capacity_bytes
    );
    assert_eq!(byte_setup.workspace_retained_bytes, 0);

    let text_region = Region::new(GLOBAL);
    let text_session = text
        .search_session(PortableRegexSetSessionLimits::unlimited())
        .expect("compact text session");
    let text_change = text_region.change();
    drop(text_region);
    let text_setup = text_session.setup_report();
    assert_eq!(text_change.allocations, 1);
    assert_eq!(text_change.reallocations, 0);
    assert_eq!(text_change.deallocations, 0);
    assert_eq!(
        text_change.bytes_allocated,
        text_setup.session_capacity_bytes
    );
    assert!(text_setup.session_capacity_bytes > 0);
    assert!(
        text_setup.session_capacity_bytes
            < patterns.len() * core::mem::size_of::<PortableTextSearchSession<'_>>()
    );
    assert_eq!(
        text_setup.charged_retained_bytes,
        text_setup.session_capacity_bytes
    );
    assert_eq!(text_setup.workspace_retained_bytes, 0);
}
