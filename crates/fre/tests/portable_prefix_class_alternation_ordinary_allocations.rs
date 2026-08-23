#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{
    DISPATCHED_PREFIX_CLASS_ALTERNATION_PLAN_ID, PREFIX_CLASS_ALTERNATION_PLAN_ID, PlanKind,
    PortableBuilder, PrefixClassAlternationPlan, SimdDispatchContext,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn prefix_class_alternation_ordinary_facades_allocate_nothing() {
    let ascii = PortableBuilder::new(r"(?:ab[0-9]+|cd[A-Z]+)")
        .unicode(false)
        .build()
        .expect("ASCII prefix/class fixture builds");
    let scalar = PortableBuilder::new(r"(?:ab[\x80-\xFF]+|cd[A-Z]+)")
        .unicode(false)
        .build()
        .expect("arbitrary-byte prefix/class fixture builds");
    let captured = PortableBuilder::new(
        r"(?P<outer>(?:(?P<left>ab)[0-9]+|(?P<right>cd)[A-Z]+))",
    )
    .unicode(false)
    .build()
    .expect("capture-decorated prefix/class fixture builds");
    for regex in [&ascii, &scalar, &captured] {
        assert_eq!(regex.build_report().plan, PlanKind::PrefixClassAlternation);
    }
    let ascii_id = if PrefixClassAlternationPlan::run_scanners_usable(
        SimdDispatchContext::capture(),
    ) {
        DISPATCHED_PREFIX_CLASS_ALTERNATION_PLAN_ID
    } else {
        PREFIX_CLASS_ALTERNATION_PLAN_ID
    };
    assert_eq!(ascii.runtime_implementation_id(), ascii_id);
    assert_eq!(captured.runtime_implementation_id(), ascii_id);
    assert_eq!(
        scalar.runtime_implementation_id(),
        PREFIX_CLASS_ALTERNATION_PLAN_ID,
    );

    let mut dense_hit = b"a!".repeat(16);
    dense_hit.extend_from_slice(b"ab777!");
    let scalar_hit = [b'!', b'a', b'b', 0x80, 0xff, b'!'];
    let captured_hit = b"!cdAZ!";

    let first = Region::new(GLOBAL);
    assert!(black_box(ascii.is_match(black_box(&dense_hit))));
    assert_eq!(
        black_box(ascii.find(black_box(&dense_hit)))
            .map(|matched| (matched.start(), matched.end())),
        Some((32, 37)),
    );
    assert!(black_box(scalar.is_match(black_box(&scalar_hit))));
    assert_eq!(
        black_box(scalar.find(black_box(&scalar_hit)))
            .map(|matched| (matched.start(), matched.end())),
        Some((1, 5)),
    );
    assert!(black_box(captured.is_match(black_box(captured_hit))));
    assert_eq!(
        black_box(captured.find(black_box(captured_hit)))
            .map(|matched| (matched.start(), matched.end())),
        Some((1, 5)),
    );
    assert_eq!(first.change(), Stats::default());

    let hot = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(ascii.is_match(black_box(&dense_hit))));
        assert_eq!(
            black_box(ascii.find(black_box(&dense_hit)))
                .map(|matched| (matched.start(), matched.end())),
            Some((32, 37)),
        );
        assert!(!black_box(ascii.is_match(black_box(b"missing"))));
        assert_eq!(black_box(ascii.find(black_box(b"missing"))), None);
        assert!(black_box(scalar.is_match(black_box(&scalar_hit))));
        assert_eq!(
            black_box(scalar.find(black_box(&scalar_hit)))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 5)),
        );
        assert!(black_box(captured.is_match(black_box(captured_hit))));
        assert_eq!(
            black_box(captured.find(black_box(captured_hit)))
                .map(|matched| (matched.start(), matched.end())),
            Some((1, 5)),
        );
    }
    assert_eq!(hot.change(), Stats::default());
}
