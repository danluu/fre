#![forbid(unsafe_code)]

use std::alloc::System;

use fre::PortableTextBuilder;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn large_ignored_source() -> String {
    const IGNORED_BYTES: usize = 65_536;
    let mut pattern = String::with_capacity("(?x)".len() + IGNORED_BYTES + 1);
    pattern.push_str("(?x)");
    pattern.extend(core::iter::repeat_n(' ', IGNORED_BYTES));
    pattern.push('a');
    assert_eq!(pattern.capacity(), pattern.len());
    pattern
}

#[test]
fn text_constructor_transfers_the_source_without_a_pattern_sized_allocation() {
    let warm = PortableTextBuilder::new(large_ignored_source())
        .build()
        .expect("warm text construction");
    drop(warm);

    let pattern = large_ignored_source();
    let source_bytes = pattern.len();
    let measured = Region::new(GLOBAL);
    let regex = PortableTextBuilder::new(pattern)
        .build()
        .expect("measured text construction");
    let stats = measured.change();
    drop(measured);

    assert_eq!(
        regex.build_report().portable.source_storage_bytes,
        source_bytes
    );
    assert!(
        stats.bytes_allocated < source_bytes,
        "a pattern-sized source copy escaped ownership transfer: {stats:?}"
    );
}
