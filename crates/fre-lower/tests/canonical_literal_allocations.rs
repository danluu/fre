#![forbid(unsafe_code)]

use std::alloc::System;

use fre_lower::{CanonicalExactLiteralLimits, analyze_canonical_exact_literal};
use regex_syntax::hir::{Capture, Hir, Repetition};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn fixture() -> Hir {
    let body = Hir::concat(vec![
        Hir::capture(Capture {
            index: 1,
            name: None,
            sub: Box::new(Hir::empty()),
        }),
        Hir::literal([b'a', b'b']),
    ]);
    Hir::repetition(Repetition {
        min: 8,
        max: Some(8),
        greedy: true,
        sub: Box::new(body),
    })
}

#[test]
fn analysis_and_caller_buffer_copy_allocate_nothing() {
    let hir = fixture();
    let mut destination = [0_u8; 16];

    let region = Region::new(GLOBAL);
    let proof = analyze_canonical_exact_literal(&hir, CanonicalExactLiteralLimits::default())
        .unwrap()
        .expect("exact fixture");
    proof.copy_into(&mut destination).unwrap();
    assert_eq!(Stats::default(), region.change());
    assert_eq!(*b"abababababababab", destination);
}
