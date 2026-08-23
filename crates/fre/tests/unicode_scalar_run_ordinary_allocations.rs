#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder, UNICODE_SCALAR_RUN_SEARCH_PLAN_ID};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn unicode_scalar_run_ordinary_find_and_canonical_is_match_allocate_nothing() {
    let greedy = PortableBuilder::new(r"[A\p{Greek}\x{96EA}\x{10400}]{2,6}")
        .build()
        .expect("greedy Unicode scalar-run fixture builds");
    let lazy = PortableBuilder::new(r"[A\p{Greek}\x{96EA}\x{10400}]{2,6}?")
        .build()
        .expect("lazy Unicode scalar-run fixture builds");
    for regex in [&greedy, &lazy] {
        assert_eq!(regex.build_report().plan, PlanKind::UnicodeScalarRun);
        assert_eq!(
            regex.runtime_implementation_id(),
            UNICODE_SCALAR_RUN_SEARCH_PLAN_ID,
        );
    }

    let hit = "--Aα雪𐐀A--".as_bytes();
    let miss = b"!\xff\xce\xf0\x90!";
    assert_eq!(
        greedy
            .find(hit)
            .map(|matched| (matched.start(), matched.end())),
        Some((2, hit.len() - 2)),
    );
    assert_eq!(
        lazy.find(hit)
            .map(|matched| (matched.start(), matched.end())),
        Some((2, 5)),
    );
    assert!(greedy.is_match(hit));
    assert!(lazy.is_match(hit));
    assert_eq!(greedy.find(miss), None);
    assert_eq!(lazy.find(miss), None);

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            black_box(greedy.find(black_box(hit))).map(|matched| (matched.start(), matched.end())),
            Some((2, hit.len() - 2)),
        );
        assert!(black_box(greedy.is_match(black_box(hit))));
        assert_eq!(black_box(greedy.find(black_box(miss))), None);
        assert!(!black_box(greedy.is_match(black_box(miss))));
        assert_eq!(
            black_box(lazy.find(black_box(hit))).map(|matched| (matched.start(), matched.end())),
            Some((2, 5)),
        );
        assert!(black_box(lazy.is_match(black_box(hit))));
        assert_eq!(black_box(lazy.find(black_box(miss))), None);
        assert!(!black_box(lazy.is_match(black_box(miss))));
    }
    assert_eq!(measured.change(), Stats::default());
}
