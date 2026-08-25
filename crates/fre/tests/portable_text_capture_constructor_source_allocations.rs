#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{CaptureBuilder, PortableTextCaptureBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn large_ignored_capture_source() -> String {
    const IGNORED_BYTES: usize = 65_536;
    const PREFIX: &str = "(?x)";
    const CAPTURE: &str = "(?P<name>a)";
    let mut pattern = String::with_capacity(PREFIX.len() + IGNORED_BYTES + CAPTURE.len());
    pattern.push_str(PREFIX);
    pattern.extend(core::iter::repeat_n(' ', IGNORED_BYTES));
    pattern.push_str(CAPTURE);
    assert_eq!(pattern.capacity(), pattern.len());
    pattern
}

fn parse_heavy_capture_source() -> String {
    const EMPTY_GROUPS: usize = 512;
    const EMPTY_GROUP: &str = "(?:)";
    const CAPTURE: &str = "(?P<name>a)";
    let mut pattern = String::with_capacity(EMPTY_GROUPS * EMPTY_GROUP.len() + CAPTURE.len());
    for _ in 0..EMPTY_GROUPS {
        pattern.push_str(EMPTY_GROUP);
    }
    pattern.push_str(CAPTURE);
    assert_eq!(pattern.capacity(), pattern.len());
    pattern
}

#[test]
fn text_capture_constructor_reuses_the_profile_proof_source_and_parse() {
    let warm = PortableTextCaptureBuilder::new(large_ignored_capture_source())
        .build()
        .expect("warm text capture construction");
    drop(warm);

    let pattern = large_ignored_capture_source();
    let source_pointer = pattern.as_ptr();
    let source_bytes = pattern.len();
    let measured = Region::new(GLOBAL);
    let regex = PortableTextCaptureBuilder::new(pattern)
        .build()
        .expect("measured text capture construction");
    let stats = measured.change();
    drop(measured);

    let retained_source = &regex.build_report().capture.plan_identity.syntax.pattern;
    assert_eq!(retained_source.as_bytes().as_ptr(), source_pointer);
    assert_eq!(retained_source.capacity_bytes(), source_bytes);
    assert!(
        stats.bytes_allocated < source_bytes,
        "duplicate source ownership or parsing escaped the handoff: {stats:?}"
    );
    drop(regex);

    let direct_warm = CaptureBuilder::new(parse_heavy_capture_source())
        .build()
        .expect("warm direct capture construction");
    let text_warm = PortableTextCaptureBuilder::new(parse_heavy_capture_source())
        .build()
        .expect("warm parse-heavy text capture construction");
    drop((direct_warm, text_warm));

    let direct_builder = CaptureBuilder::new(parse_heavy_capture_source());
    let direct_measured = Region::new(GLOBAL);
    let direct = direct_builder
        .build()
        .expect("measured direct capture construction");
    let direct_stats = direct_measured.change();
    drop(direct_measured);
    drop(direct);

    let text_builder = PortableTextCaptureBuilder::new(parse_heavy_capture_source());
    let text_measured = Region::new(GLOBAL);
    let text = text_builder
        .build()
        .expect("measured parse-heavy text capture construction");
    let text_stats = text_measured.change();
    drop(text_measured);

    assert!(
        text_stats.allocations.saturating_mul(5) < direct_stats.allocations.saturating_mul(12),
        "text construction performed a third syntax parse: direct={direct_stats:?} text={text_stats:?}"
    );
    drop(text);
}
