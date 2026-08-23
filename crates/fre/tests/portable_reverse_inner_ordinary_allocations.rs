#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder, REVERSE_INNER_PLAN_ID};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn reverse_inner_single_literal_ordinary_facades_allocate_nothing() {
    let regex = PortableBuilder::new(r"[abλ]+aa[abλ]+")
        .unicode(true)
        .build()
        .expect("single-literal reverse-inner fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::ReverseInner);
    assert_eq!(regex.runtime_implementation_id(), REVERSE_INNER_PLAN_ID);

    let immediate = b"!aaaab!";
    let unicode = "!λaaaabλ!".as_bytes();
    let malformed = b"\xff!aaaab!\x80";
    let miss = b"!aa!";
    assert_eq!(
        regex
            .find(immediate)
            .map(|matched| (matched.start(), matched.end())),
        Some((1, 6)),
    );
    assert!(regex.is_match(immediate));

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            black_box(regex.find(black_box(immediate)))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 6)),
        );
        assert!(black_box(regex.is_match(black_box(immediate))));
        assert_eq!(
            black_box(regex.find(black_box(unicode)))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, unicode.len() - 1)),
        );
        assert!(black_box(regex.is_match(black_box(unicode))));
        assert_eq!(
            black_box(regex.find(black_box(malformed)))
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 7)),
        );
        assert!(black_box(regex.is_match(black_box(malformed))));
        assert_eq!(black_box(regex.find(black_box(miss))), None);
        assert!(!black_box(regex.is_match(black_box(miss))));
    }
    assert_eq!(measured.change(), Stats::default());
}
