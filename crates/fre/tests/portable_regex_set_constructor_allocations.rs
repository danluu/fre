#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{
    PortableRegexSet, PortableRegexSetBuilder, PortableTextRegexSet, PortableTextRegexSetBuilder,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn generic_constructors_retain_one_source_copy_and_normalize_capacity() {
    let patterns = (0..512)
        .map(|index| {
            if index == 0 {
                String::from("a+xxxxxxxxx")
            } else {
                format!("qz{index:04}match")
            }
        })
        .collect::<Vec<_>>();
    assert!(patterns.iter().all(|pattern| pattern.len() == 11));

    let byte_warm = PortableRegexSetBuilder::new(&patterns[..1])
        .build()
        .expect("warm byte set");
    drop(byte_warm);
    let borrowed_byte_region = Region::new(GLOBAL);
    let borrowed_byte = PortableRegexSetBuilder::new(&patterns)
        .build()
        .expect("borrowed byte set");
    let borrowed_byte_stats = borrowed_byte_region.change();
    drop(borrowed_byte_region);
    let generic_byte_region = Region::new(GLOBAL);
    let generic_byte = PortableRegexSet::new(patterns.iter()).expect("generic byte set");
    let generic_byte_stats = generic_byte_region.change();
    drop(generic_byte_region);
    assert_eq!(generic_byte.patterns(), patterns);
    assert_eq!(generic_byte.build_report(), borrowed_byte.build_report());
    assert_eq!(generic_byte_stats, borrowed_byte_stats);

    let text_warm = PortableTextRegexSetBuilder::new(&patterns[..1])
        .build()
        .expect("warm text set");
    drop(text_warm);
    let borrowed_text_region = Region::new(GLOBAL);
    let borrowed_text = PortableTextRegexSetBuilder::new(&patterns)
        .build()
        .expect("borrowed text set");
    let borrowed_text_stats = borrowed_text_region.change();
    drop(borrowed_text_region);
    let generic_text_region = Region::new(GLOBAL);
    let generic_text = PortableTextRegexSet::new(patterns.iter()).expect("generic text set");
    let generic_text_stats = generic_text_region.change();
    drop(generic_text_region);
    assert_eq!(generic_text.patterns(), patterns);
    assert_eq!(generic_text.build_report(), borrowed_text.build_report());
    assert_eq!(generic_text_stats, borrowed_text_stats);

    let selected = patterns
        .iter()
        .enumerate()
        .filter_map(|(index, pattern)| (index % 8 == 0).then_some(pattern.clone()))
        .collect::<Vec<_>>();
    assert_eq!(selected.len(), 64);
    let byte_reference = PortableRegexSetBuilder::new(&selected)
        .build()
        .expect("reference byte set");
    let byte = PortableRegexSet::new(
        patterns
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| (index % 8 == 0).then_some(pattern)),
    )
    .expect("overestimated-hint byte set");
    assert_eq!(byte.patterns(), selected);
    assert_eq!(byte.build_report(), byte_reference.build_report());

    let text_reference = PortableTextRegexSetBuilder::new(&selected)
        .build()
        .expect("reference text set");
    let text = PortableTextRegexSet::new(
        patterns
            .iter()
            .enumerate()
            .filter_map(|(index, pattern)| (index % 8 == 0).then_some(pattern)),
    )
    .expect("overestimated-hint text set");
    assert_eq!(text.patterns(), selected);
    assert_eq!(text.build_report(), text_reference.build_report());
}
