#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn build(pattern: &str) -> fre::PortableRegex {
    let regex = PortableBuilder::new(pattern)
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(regex.build_report().plan, PlanKind::ForwardAnchored);
    assert_eq!(
        regex.runtime_implementation_id(),
        fre_kernels::FORWARD_ANCHORED_PLAN_ID,
    );
    regex
}

fn span(matched: Option<fre::Match>) -> Option<(usize, usize)> {
    matched.map(|matched| (matched.start(), matched.end()))
}

#[test]
fn forward_ordinary_full_values_allocate_nothing() {
    let first_exists = build(r"(?-u:\A[ab]+Z)");
    let measured_first_exists = Region::new(GLOBAL);
    assert!(black_box(
        first_exists.is_match(black_box(b"ababababZtail"))
    ));
    assert_eq!(measured_first_exists.change(), Stats::default());
    drop(measured_first_exists);

    let first_find = build(r"(?-u:\A[\x00\x02\x04\x06\x80\xFF]+?\x7F\xFE\z)");
    let first_find_haystack = [0x00, 0x80, 0xFF, 0x7F, 0xFE];
    let measured_first_find = Region::new(GLOBAL);
    assert_eq!(
        span(black_box(first_find.find(black_box(&first_find_haystack)))),
        Some((0, 5)),
    );
    assert_eq!(measured_first_find.change(), Stats::default());
    drop(measured_first_find);

    let greedy = build(r"(?-u:\A[ab]+Z)");
    let captured_lazy_end = build(r"(?-u:\A(?P<run>[ab]+?)Z\z)");
    let malformed = build(r"(?-u:\A[\x00\x02\x04\x06\x80\xFF]+\x7F\xFE)");
    let greedy_hit = b"ababababZtail";
    let captured_hit = b"ababababZ";
    let malformed_hit = [0x00, 0x80, 0xFF, 0x7F, 0xFE, b'!'];
    let malformed_miss = [0x00, 0x80, 0xFF, 0x7F, 0xFD];

    assert_eq!(span(greedy.find(greedy_hit)), Some((0, 9)));
    assert_eq!(span(captured_lazy_end.find(captured_hit)), Some((0, 9)));
    assert_eq!(span(malformed.find(&malformed_hit)), Some((0, 5)));

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(greedy.is_match(black_box(greedy_hit))));
        assert_eq!(
            span(black_box(greedy.find(black_box(greedy_hit)))),
            Some((0, 9)),
        );
        assert!(!black_box(greedy.is_match(black_box(b"abababab"))));
        assert_eq!(black_box(greedy.find(black_box(b"abababab"))), None);
        assert!(!black_box(greedy.is_match(black_box(b""))));
        assert_eq!(black_box(greedy.find(black_box(b""))), None);

        assert!(black_box(
            captured_lazy_end.is_match(black_box(captured_hit))
        ));
        assert_eq!(
            span(black_box(captured_lazy_end.find(black_box(captured_hit)))),
            Some((0, 9)),
        );
        assert!(!black_box(
            captured_lazy_end.is_match(black_box(b"ababababZ!"))
        ));
        assert_eq!(
            black_box(captured_lazy_end.find(black_box(b"ababababZ!"))),
            None,
        );

        assert!(black_box(
            malformed.is_match(black_box(&malformed_hit))
        ));
        assert_eq!(
            span(black_box(malformed.find(black_box(&malformed_hit)))),
            Some((0, 5)),
        );
        assert!(!black_box(
            malformed.is_match(black_box(&malformed_miss))
        ));
        assert_eq!(
            black_box(malformed.find(black_box(&malformed_miss))),
            None,
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
