#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn exact_literal_ordinary_facades_allocate_nothing() {
    let literal = PortableBuilder::new("needle")
        .unicode(false)
        .build()
        .expect("exact literal fixture builds");
    let one_byte = PortableBuilder::new("a")
        .unicode(false)
        .build()
        .expect("one-byte literal fixture builds");
    let empty = PortableBuilder::new("")
        .unicode(false)
        .build()
        .expect("empty literal fixture builds");
    for regex in [&literal, &one_byte, &empty] {
        assert_eq!(regex.build_report().plan, PlanKind::ExactLiteral);
    }

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(literal.is_match(black_box(b"--needle--"))));
        assert_eq!(
            black_box(literal.find(black_box(b"--needle--")))
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 8)),
        );
        assert!(!black_box(literal.is_match(black_box(b"--need--"))));
        assert_eq!(black_box(literal.find(black_box(b"--need--"))), None);
        assert!(black_box(one_byte.is_match(black_box(b"\xffa"))));
        assert_eq!(
            black_box(one_byte.find(black_box(b"\xffa")))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 2)),
        );
        assert!(black_box(empty.is_match(black_box(b"\xff"))));
        assert_eq!(
            black_box(empty.find(black_box(b"\xff")))
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 0)),
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
