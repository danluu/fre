#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn packed_literal_set_ordinary_facades_allocate_nothing() {
    let regex = PortableBuilder::new("alpha|beta|gamma")
        .unicode(false)
        .build()
        .expect("packed literal-set fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::PackedLiteralSet);
    let hit = b"--alpha--beta--gamma--";
    let miss = b"--delta--epsilon--";
    let expected = regex.find(hit);

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(regex.is_match(black_box(hit))));
        assert_eq!(black_box(regex.find(black_box(hit))), expected);
        assert!(!black_box(regex.is_match(black_box(miss))));
        assert_eq!(black_box(regex.find(black_box(miss))), None);
    }
    assert_eq!(measured.change(), Stats::default());
}
