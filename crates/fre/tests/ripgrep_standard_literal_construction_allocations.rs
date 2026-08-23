#![forbid(unsafe_code)]

use std::alloc::System;

use fre::{PortableBuilder, RipgrepStandardLiteralHirBuild};
use regex_syntax::hir::Hir;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn borrowed_literals_avoid_the_owned_hir_leaf_graph() {
    let patterns = (0..256_u16)
        .map(|bits| {
            String::from_utf8(
                (0..8)
                    .map(|shift| {
                        if bits & (1 << shift) == 0 { b'q' } else { b'z' }
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("focused literals are UTF-8")
        })
        .collect::<Vec<_>>();
    let pattern_refs = patterns.iter().map(String::as_str).collect::<Vec<_>>();

    let borrowed_region = Region::new(GLOBAL);
    let borrowed = PortableBuilder::new("")
        .multi_line(true)
        .retained_find_iter(true)
        .build_ripgrep_standard_literals(&pattern_refs, usize::MAX)
        .expect("borrowed literal construction completes")
        .expect("bounded standard literals are admitted");
    let borrowed_allocations = borrowed_region.change().allocations;

    let hir_region = Region::new(GLOBAL);
    let hir = Hir::alternation(
        patterns
            .iter()
            .map(|pattern| Hir::literal(pattern.as_bytes()))
            .collect(),
    );
    let owned = PortableBuilder::new("")
        .multi_line(true)
        .retained_find_iter(true)
        .build_ripgrep_standard_literal_hir_owned(hir, usize::MAX)
        .expect("owned HIR construction completes");
    let RipgrepStandardLiteralHirBuild::Built(owned) = owned else {
        panic!("owned standard literal HIR was refused");
    };
    let hir_allocations = hir_region.change().allocations;

    assert_eq!(borrowed.as_str(), owned.as_str());
    assert_eq!(borrowed.build_report(), owned.build_report());
    assert!(
        hir_allocations >= borrowed_allocations.saturating_add(patterns.len()),
        "borrowed={borrowed_allocations}, owned-HIR={hir_allocations}",
    );
}
