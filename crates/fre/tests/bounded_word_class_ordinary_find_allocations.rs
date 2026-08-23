#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn bounded_word_class_ordinary_find_allocates_nothing() {
    let greek = PortableBuilder::new(r"\b\p{Greek}+\b")
        .unicode(true)
        .build()
        .expect("Unicode unbounded word-class fixture builds");
    let mixed = PortableBuilder::new(r"\b[\p{Greek}_/]+\b")
        .unicode(true)
        .build()
        .expect("mixed-wordness fixture builds");
    assert_eq!(greek.build_report().plan, PlanKind::UnicodeWordRun);
    assert_eq!(mixed.build_report().plan, PlanKind::UnicodeWordRun);
    assert_eq!(
        greek.runtime_implementation_id(),
        "bounded-word-class-linear-full-byte-v4",
    );
    assert_eq!(
        mixed.runtime_implementation_id(),
        "bounded-word-class-linear-full-byte-v4",
    );

    let greek_hit = "!Ωμέγα!".as_bytes();
    let mixed_hit = "!α/β_γ!".as_bytes();
    let miss = b"plain ASCII only";
    assert_eq!(
        greek
            .find(greek_hit)
            .map(|matched| (matched.start(), matched.end())),
        Some((1, greek_hit.len() - 1)),
    );
    assert_eq!(
        mixed
            .find(mixed_hit)
            .map(|matched| (matched.start(), matched.end())),
        Some((1, mixed_hit.len() - 1)),
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            black_box(greek.find(black_box(greek_hit)))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, greek_hit.len() - 1)),
        );
        assert_eq!(black_box(greek.find(black_box(miss))), None);
        assert_eq!(
            black_box(mixed.find(black_box(mixed_hit)))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, mixed_hit.len() - 1)),
        );
        assert_eq!(black_box(mixed.find(black_box(miss))), None);
    }
    assert_eq!(measured.change(), Stats::default());
}
