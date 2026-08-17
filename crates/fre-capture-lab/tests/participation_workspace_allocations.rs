#![forbid(unsafe_code)]

use std::alloc::System;

use fre_capture_lab::{Ast, BuildLimits, HistoryRegex, SearchLimits, Span, Window};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn prepared_participation_replays_allocate_nothing() {
    let regex = HistoryRegex::compile(
        &Ast::concat([
            Ast::Byte(b'a').capture(1),
            Ast::Byte(b'b')
                .capture(2)
                .repeat(0, Some(1), fre_capture_lab::Greed::Greedy),
        ]),
        BuildLimits::default(),
    )
    .expect("capture program");
    let limits = SearchLimits::default();
    let mut workspace = regex
        .prepare_participation_exact_workspace(Span { start: 0, end: 2 }, limits)
        .expect("participation workspace");

    let region = Region::new(GLOBAL);
    for &(haystack, span, expected_mask) in &[
        (&b"ab"[..], Span { start: 0, end: 2 }, Some(0b111)),
        (&b"a"[..], Span { start: 0, end: 1 }, Some(0b011)),
        (&b"ac"[..], Span { start: 0, end: 2 }, None),
    ] {
        let outcome = regex
            .captures_participation_exact_with_workspace(
                &mut workspace,
                haystack,
                Window::all(haystack),
                span,
                limits,
            )
            .expect("reusable replay");
        assert_eq!(outcome.participation_mask, expected_mask);
    }
    assert_eq!(region.change(), Stats::default());
}
