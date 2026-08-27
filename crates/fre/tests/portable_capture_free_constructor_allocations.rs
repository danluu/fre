#![forbid(unsafe_code)]

use std::alloc::System;

use fre::PortableBuilder;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn source(pattern: &str) -> String {
    let mut source = String::with_capacity(pattern.len());
    source.push_str(pattern);
    assert_eq!(source.capacity(), source.len());
    source
}

fn measured_build(pattern: String) -> (fre::PortableRegex, Stats, *const u8) {
    let source_pointer = pattern.as_ptr();
    let builder = PortableBuilder::new(pattern);
    let measured = Region::new(GLOBAL);
    let regex = builder.build().expect("measured portable construction");
    let stats = measured.change();
    drop(measured);
    (regex, stats, source_pointer)
}

#[test]
fn capture_free_construction_skips_generic_capture_metadata() {
    drop(
        PortableBuilder::new(source("needle"))
            .build()
            .expect("warm capture-free construction"),
    );
    drop(
        PortableBuilder::new(source("(needle)"))
            .build()
            .expect("warm captured construction"),
    );

    let (capture_free, capture_free_stats, capture_free_source) = measured_build(source("needle"));
    let (captured, captured_stats, captured_source) = measured_build(source("(needle)"));

    assert_eq!(capture_free.as_str().as_ptr(), capture_free_source);
    assert_eq!(capture_free.captures_len(), 1);
    assert_eq!(capture_free.capture_names().collect::<Vec<_>>(), [None]);
    assert_eq!(capture_free.build_report().captures_len, 1);
    assert_eq!(capture_free.build_report().capture_name_storage_bytes, 0);
    assert_eq!(captured.as_str().as_ptr(), captured_source);
    assert_eq!(captured.captures_len(), 2);
    assert_eq!(captured.capture_names().collect::<Vec<_>>(), [None, None]);
    assert!(
        capture_free_stats.allocations.saturating_add(13) <= captured_stats.allocations,
        "capture-free construction retained generic metadata allocations: capture_free={capture_free_stats:?} captured={captured_stats:?}"
    );
    // The removed capture-name slot would remain owned by the returned regex,
    // so it increases the allocation gap without changing this deallocation
    // gap measured before either regex is dropped.
    assert!(
        capture_free_stats.deallocations.saturating_add(12) <= captured_stats.deallocations,
        "capture-free construction retained generic metadata deallocations: capture_free={capture_free_stats:?} captured={captured_stats:?}"
    );
}
