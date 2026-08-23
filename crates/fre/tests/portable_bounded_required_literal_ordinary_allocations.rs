#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PlanSelection, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn bounded_required_literal_ordinary_facades_allocate_nothing() {
    let ascii = PortableBuilder::new(r"(?-u:[a-z]{2,4}ZQ)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceRequiredLiteral)
        .build()
        .expect("ASCII bounded required-literal fixture builds");
    let arbitrary_bytes = PortableBuilder::new(r"(?-u:[\x00\x02\x04\x80\xFF]{2,4}Z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceRequiredLiteral)
        .build()
        .expect("scalar bounded required-literal fixture builds");
    assert_eq!(ascii.build_report().plan, PlanKind::RequiredLiteral);
    assert_eq!(
        arbitrary_bytes.build_report().plan,
        PlanKind::RequiredLiteral,
    );

    let arbitrary_hit = [b'!', 0x80, 0xff, 0x80, b'Z'];
    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(ascii.is_match(black_box(b"!ZQ!aaaaaZQ"))));
        assert!(!black_box(ascii.is_match(black_box(b"!ZQ!aZQ"))));
        assert_eq!(
            black_box(ascii.find(black_box(b"!ZQ!aaaaaZQ")))
                .map(|matched| (matched.start(), matched.end())),
            Some((5, 11)),
        );
        assert_eq!(black_box(ascii.find(black_box(b"!ZQ!aZQ"))), None);
        assert_eq!(
            black_box(arbitrary_bytes.find(black_box(&arbitrary_hit)))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 5)),
        );
        assert_eq!(
            black_box(arbitrary_bytes.find(black_box(b"ascii-only"))),
            None,
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
