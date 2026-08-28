#![forbid(unsafe_code)]

use std::{alloc::System, sync::Mutex};

use fre::{PortableBuilder, RipgrepStandardLiteralHirBuild, RipgrepStandardLiteralsBuild};
use regex_syntax::hir::Hir;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn borrowed_literals_avoid_the_owned_hir_leaf_graph() {
    let _guard = ALLOCATION_TEST_LOCK.lock().unwrap();
    for count in [2, 16, 64, 128, 256] {
        let patterns = (0..u16::try_from(count).unwrap())
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
            .build_ripgrep_standard_literals_ordinary(&pattern_refs, usize::MAX)
            .expect("borrowed literal construction completes")
            .expect("bounded standard literals are admitted");
        let RipgrepStandardLiteralsBuild::Portable(borrowed) = borrowed else {
            panic!("focused literals retained an ordinary-only owner");
        };
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

        assert_eq!(borrowed.as_str(), owned.as_str(), "count={count}");
        assert_eq!(
            borrowed.build_report(),
            owned.build_report(),
            "count={count}",
        );
        assert!(
            hir_allocations >= borrowed_allocations.saturating_add(patterns.len()),
            "count={count}, borrowed={borrowed_allocations}, owned-HIR={hir_allocations}",
        );
    }
}

#[test]
fn borrowed_fixed_metacharacters_avoid_the_owned_hir_leaf_graph() {
    let _guard = ALLOCATION_TEST_LOCK.lock().unwrap();
    let metacharacters = [
        '.', '[', ']', '(', ')', '{', '}', '*', '+', '?', '|', '^', '$', '\\', '-', '&', '~',
        '#',
    ];
    let patterns = (0..64)
        .map(|index| {
            format!(
                "{}fixed{index:04}é",
                metacharacters[index % metacharacters.len()]
            )
        })
        .collect::<Vec<_>>();
    let pattern_refs = patterns.iter().map(String::as_str).collect::<Vec<_>>();

    let borrowed_region = Region::new(GLOBAL);
    let (borrowed, _census) = PortableBuilder::new("")
        .multi_line(true)
        .retained_find_iter(true)
        .build_ripgrep_fixed_literals_ordinary_with_census(
            &pattern_refs,
            usize::MAX,
            None,
        )
        .expect("borrowed fixed-string construction completes")
        .expect("borrowed fixed strings are admitted");
    let RipgrepStandardLiteralsBuild::Portable(borrowed) = borrowed else {
        panic!("focused fixed strings retained an ordinary-only owner");
    };
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
        .expect("owned fixed-string HIR construction completes");
    let RipgrepStandardLiteralHirBuild::Built(owned) = owned else {
        panic!("owned fixed-string HIR was refused");
    };
    let hir_allocations = hir_region.change().allocations;

    assert_eq!(borrowed.as_str(), owned.as_str());
    assert_eq!(borrowed.build_report(), owned.build_report());
    assert!(
        hir_allocations >= borrowed_allocations.saturating_add(patterns.len()),
        "borrowed={borrowed_allocations}, owned-HIR={hir_allocations}",
    );
}

#[test]
fn owned_singleton_literal_adopts_the_hir_leaf_without_copy() {
    let _guard = ALLOCATION_TEST_LOCK.lock().unwrap();
    const TRANSFER_BYTES: usize = 65_537;
    drop(
        PortableBuilder::new("")
            .multi_line(true)
            .build_ripgrep_standard_literal_hir_owned(
                Hir::literal(vec![b'q'; 32]),
                usize::MAX,
            )
            .expect("warm owned singleton construction completes"),
    );
    let borrowed_hir = Hir::literal(vec![b'q'; TRANSFER_BYTES]);
    let owned_hir = Hir::literal(vec![b'q'; TRANSFER_BYTES]);

    let borrowed_region = Region::new(GLOBAL);
    let borrowed = PortableBuilder::new("")
        .multi_line(true)
        .build_ripgrep_standard_literal_hir(&borrowed_hir, usize::MAX)
        .expect("borrowed singleton construction completes")
        .expect("borrowed singleton HIR is admitted");
    let borrowed_stats = borrowed_region.change();
    drop(borrowed_region);

    let owned_region = Region::new(GLOBAL);
    let owned = PortableBuilder::new("")
        .multi_line(true)
        .build_ripgrep_standard_literal_hir_owned(owned_hir, usize::MAX)
        .expect("owned singleton construction completes");
    let RipgrepStandardLiteralHirBuild::Built(owned) = owned else {
        panic!("owned singleton HIR was refused");
    };
    let owned_stats = owned_region.change();
    drop(owned_region);

    assert_eq!(owned.as_str(), borrowed.as_str());
    assert_eq!(owned.build_report(), borrowed.build_report());
    assert_eq!(owned.find(b"not present"), borrowed.find(b"not present"));
    assert!(
        owned_stats.allocations.saturating_add(2) <= borrowed_stats.allocations,
        "borrowed singleton omitted its independent HIR clone cost: borrowed={borrowed_stats:?}, owned={owned_stats:?}",
    );
    assert!(
        owned_stats.allocations <= 3,
        "owned singleton retained a needle-copy allocation: {owned_stats:?}",
    );
    assert!(
        owned_stats.bytes_allocated < TRANSFER_BYTES.saturating_mul(2),
        "owned singleton retained a pattern-sized leaf copy: {owned_stats:?}",
    );
    assert!(
        owned_stats
            .bytes_allocated
            .saturating_add(TRANSFER_BYTES)
            <= borrowed_stats.bytes_allocated,
        "borrowed singleton omitted its cloned literal bytes: borrowed={borrowed_stats:?}, owned={owned_stats:?}",
    );
}
