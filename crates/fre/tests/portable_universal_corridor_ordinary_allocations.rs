#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn universal_corridor_ordinary_facades_allocate_nothing() {
    let regex = PortableBuilder::new(r"(?s-u:.{0,2}.{0,3}X)")
        .unicode(false)
        .build()
        .expect("universal finite corridor fixture builds");
    assert_eq!(regex.build_report().plan, PlanKind::RequiredLiteral);
    assert_eq!(
        regex.runtime_implementation_id(),
        "required-literal.universal-finite-greedy-corridor.v1",
    );

    let immediate = b"X";
    let repeated = b"qXZXaaaaa";
    let mut late = vec![b'a'; 4_095];
    late.push(b'X');
    let miss = vec![b'a'; 4_096];

    let first = Region::new(GLOBAL);
    assert_eq!(
        black_box(regex.find(black_box(repeated))).map(|matched| (matched.start(), matched.end())),
        Some((0, 4)),
    );
    assert!(black_box(regex.is_match(black_box(repeated))));
    assert_eq!(first.change(), Stats::default());

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            black_box(regex.find(black_box(immediate)))
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 1)),
        );
        assert!(black_box(regex.is_match(black_box(immediate))));
        assert_eq!(
            black_box(regex.find(black_box(&late))).map(|matched| (matched.start(), matched.end())),
            Some((4_090, 4_096)),
        );
        assert!(black_box(regex.is_match(black_box(&late))));
        assert_eq!(black_box(regex.find(black_box(&miss))), None);
        assert!(!black_box(regex.is_match(black_box(&miss))));
    }
    assert_eq!(measured.change(), Stats::default());
}
