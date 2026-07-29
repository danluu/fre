#![forbid(unsafe_code)]

use std::alloc::System;

use fre_automata::{
    Automaton, CompileLimits, EdgeKind, K0Workspace, RawPlan, SearchLimits, Span, StateRole,
    WorkspaceLimits,
};
use stats_alloc::{Region, Stats, StatsAlloc, INSTRUMENTED_SYSTEM};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn literal(byte: u8) -> Automaton {
    Automaton::from_raw(
        RawPlan {
            start: 0,
            roles: vec![StateRole::Consume, StateRole::Accept],
            edge_offsets: vec![0, 1, 1],
            edge_targets: vec![1],
            edge_kinds: vec![EdgeKind::ByteRange],
            byte_starts: vec![byte],
            byte_ends: vec![byte],
        },
        CompileLimits::default(),
    )
    .unwrap()
}

#[test]
fn proof_owner_is_one_cold_allocation_and_zero_steady_allocations() {
    let automaton = literal(b'a');
    let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
    let retained = workspace.retained_bytes();

    let refused_region = Region::new(GLOBAL);
    let refused = automaton
        .prepare::<Span>()
        .search_with_workspace(
            b"zzza",
            &mut workspace,
            SearchLimits {
                max_work: u64::MAX,
                max_scratch_bytes: retained,
            },
        )
        .unwrap();
    let refused_allocations = refused_region.change();
    assert_eq!(refused_allocations, Stats::default());
    assert_eq!(refused.accounting().setup().allocated_bytes(), 0);
    assert_eq!(refused.accounting().scratch_bytes(), retained);

    let cold_region = Region::new(GLOBAL);
    let cold = automaton
        .prepare::<Span>()
        .search_with_workspace(b"zzza", &mut workspace, SearchLimits::unlimited())
        .unwrap();
    let cold_allocations = cold_region.change();
    let proof_bytes = cold.accounting().setup().allocated_bytes();
    assert!(proof_bytes > 0);
    assert_eq!(cold.accounting().setup().initialized_bytes(), proof_bytes);
    assert_eq!(
        cold.accounting().scratch_bytes(),
        retained.checked_add(proof_bytes).unwrap()
    );
    assert_eq!(
        cold_allocations,
        Stats {
            allocations: 1,
            deallocations: 0,
            reallocations: 0,
            bytes_allocated: proof_bytes,
            bytes_deallocated: 0,
            bytes_reallocated: 0,
        }
    );

    let warm_region = Region::new(GLOBAL);
    let warm = automaton
        .prepare::<Span>()
        .search_with_workspace(b"zzza", &mut workspace, SearchLimits::unlimited())
        .unwrap();
    let warm_allocations = warm_region.change();
    assert_eq!(warm_allocations, Stats::default());
    assert_eq!(warm.output(), cold.output());
    assert_eq!(warm.accounting().setup().allocated_bytes(), 0);
    assert_eq!(warm.accounting().setup().initialized_bytes(), 0);
    assert_eq!(warm.accounting().scratch_bytes(), retained);
}
