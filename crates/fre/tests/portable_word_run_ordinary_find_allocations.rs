#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{
    ASCII_WORD_RUN_PLAN_ID, PlanKind, PortableBuilder, UNICODE_WORD_RUN_PLAN_ID,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn word_run_ordinary_find_allocates_nothing() {
    let ascii = PortableBuilder::new(r"\b\w{2,}\b")
        .unicode(false)
        .build()
        .expect("ASCII word-run fixture builds");
    let unicode = PortableBuilder::new(r"\b\w{2,}\b")
        .unicode(true)
        .build()
        .expect("Unicode word-run fixture builds");
    for regex in [&ascii, &unicode] {
        assert_eq!(regex.build_report().plan, PlanKind::UnicodeWordRun);
    }
    assert_eq!(ascii.runtime_implementation_id(), ASCII_WORD_RUN_PLAN_ID);
    assert_eq!(
        unicode.runtime_implementation_id(),
        UNICODE_WORD_RUN_PLAN_ID,
    );

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            black_box(ascii.find(black_box(b"!!abc!!")))
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 5)),
        );
        assert_eq!(black_box(ascii.find(black_box(b"!!!!"))), None);
        assert_eq!(
            black_box(unicode.find(black_box("!!αβ!!".as_bytes())))
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 6)),
        );
        assert_eq!(
            black_box(unicode.find(black_box(b"!\xffab\x80")))
                .map(|matched| (matched.start(), matched.end())),
            Some((2, 4)),
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
