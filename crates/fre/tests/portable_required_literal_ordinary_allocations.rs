#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PlanSelection, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn required_literal_ordinary_find_allocates_nothing() {
    let ascii = PortableBuilder::new(r"(?-u:[a-z]+ZQ)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceRequiredLiteral)
        .build()
        .expect("ASCII required-literal fixture builds");
    let arbitrary_bytes = PortableBuilder::new(r"(?-u:[\x00\x02\x04\x80\xFF]+Z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceRequiredLiteral)
        .build()
        .expect("scalar required-literal fixture builds");
    assert_eq!(ascii.build_report().plan, PlanKind::RequiredLiteral);
    assert_eq!(
        arbitrary_bytes.build_report().plan,
        PlanKind::RequiredLiteral,
    );

    let arbitrary_hit = [b'!', 0x80, 0xff, b'Z'];
    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            black_box(ascii.find(black_box(b"!ZQ!aaaaZQ")))
                .map(|matched| (matched.start(), matched.end())),
            Some((4, 10)),
        );
        assert_eq!(black_box(ascii.find(black_box(b"!ZQ!none"))), None);
        assert_eq!(
            black_box(arbitrary_bytes.find(black_box(&arbitrary_hit)))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 4)),
        );
        assert_eq!(
            black_box(arbitrary_bytes.find(black_box(b"ascii-only"))),
            None,
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
