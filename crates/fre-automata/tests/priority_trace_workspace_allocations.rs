#![forbid(unsafe_code)]

use std::alloc::System;

use fre_automata::{
    CompileLimits, DirectCount, DirectReduceLimits, EdgeKind, EmptyMatchProgress, ForcedExecution,
    OrderedManyRawBuildLimits, OrderedManyRawPlan, PreparationLimits, PriorityTarget, RawPlan,
    StateRole,
};
use stats_alloc::{Region, Stats, StatsAlloc, INSTRUMENTED_SYSTEM};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn raw_literal(byte: u8) -> RawPlan {
    RawPlan {
        start: 0,
        roles: vec![StateRole::Consume, StateRole::Accept],
        edge_offsets: vec![0, 1, 1],
        edge_targets: vec![1],
        edge_kinds: vec![EdgeKind::ByteRange],
        byte_starts: vec![byte],
        byte_ends: vec![byte],
    }
}

fn raw_zero_width_scc_then_literal(byte: u8) -> RawPlan {
    RawPlan {
        start: 0,
        roles: vec![
            StateRole::Split,
            StateRole::Split,
            StateRole::Consume,
            StateRole::Accept,
        ],
        edge_offsets: vec![0, 2, 3, 4, 4],
        edge_targets: vec![1, 2, 0, 3],
        edge_kinds: vec![
            EdgeKind::Epsilon,
            EdgeKind::Epsilon,
            EdgeKind::Epsilon,
            EdgeKind::ByteRange,
        ],
        byte_starts: vec![0, 0, 0, byte],
        byte_ends: vec![0, 0, 0, byte],
    }
}

#[test]
fn prepared_257_row_priority_trace_workspace_allocates_nothing_per_run() {
    let sources = (0..257).map(|_| raw_literal(b'a')).collect::<Vec<_>>();
    let prepared =
        OrderedManyRawPlan::from_sources(&sources, OrderedManyRawBuildLimits::unlimited())
            .unwrap()
            .into_priority_facts(b'\n', CompileLimits::default(), EmptyMatchProgress::Byte)
            .unwrap()
            .prepare_build_many_forced::<DirectCount>(
                ForcedExecution::Sparse,
                PriorityTarget::portable(),
                PreparationLimits::unlimited(),
            )
            .unwrap();

    let setup = Region::new(GLOBAL);
    let mut workspace = prepared
        .prepare_trace_workspace(3, DirectReduceLimits::unlimited())
        .unwrap();
    let accounting = workspace.accounting();
    assert!(accounting.closes());
    assert_eq!(
        Stats {
            allocations: accounting.allocation_attempts,
            deallocations: 0,
            reallocations: 0,
            bytes_allocated: accounting.retained_logical_bytes,
            bytes_deallocated: 0,
            bytes_reallocated: 0,
        },
        setup.change()
    );

    let allocation_free = DirectReduceLimits {
        max_allocation_attempts: 0,
        ..DirectReduceLimits::unlimited()
    };
    let first = Region::new(GLOBAL);
    let report = prepared
        .execute_forced_trace_with_workspace(b"aaa", &mut workspace, allocation_free)
        .unwrap();
    assert!(report.closes());
    assert_eq!(*report.report().output(), 3);
    assert_eq!(report.matches().len(), 3);
    assert_eq!(Stats::default(), first.change());

    let steady = Region::new(GLOBAL);
    for _ in 0..32 {
        let report = prepared
            .execute_forced_trace_with_workspace(b"aaa", &mut workspace, allocation_free)
            .unwrap();
        assert!(report.closes());
        assert_eq!(*report.report().output(), 3);
        assert_eq!(report.matches().len(), 3);
    }
    assert_eq!(Stats::default(), steady.change());

    assert_cyclic_workspace_allocates_nothing_per_run();
}

fn assert_cyclic_workspace_allocates_nothing_per_run() {
    let prepared = OrderedManyRawPlan::from_sources(
        &[raw_zero_width_scc_then_literal(b'a')],
        OrderedManyRawBuildLimits::unlimited(),
    )
    .unwrap()
    .into_priority_facts(b'\n', CompileLimits::default(), EmptyMatchProgress::Byte)
    .unwrap()
    .prepare_build_many_forced::<DirectCount>(
        ForcedExecution::Sparse,
        PriorityTarget::portable(),
        PreparationLimits::unlimited(),
    )
    .unwrap();

    let setup = Region::new(GLOBAL);
    let mut workspace = prepared
        .prepare_trace_workspace(3, DirectReduceLimits::unlimited())
        .unwrap();
    let accounting = workspace.accounting();
    assert!(accounting.closes());
    assert_eq!(accounting.allocation_attempts, 6);
    assert_eq!(
        Stats {
            allocations: accounting.allocation_attempts,
            deallocations: 0,
            reallocations: 0,
            bytes_allocated: accounting.retained_logical_bytes,
            bytes_deallocated: 0,
            bytes_reallocated: 0,
        },
        setup.change()
    );

    let allocation_free = DirectReduceLimits {
        max_allocation_attempts: 0,
        ..DirectReduceLimits::unlimited()
    };
    let hot = Region::new(GLOBAL);
    for _ in 0..32 {
        let report = prepared
            .execute_forced_trace_with_workspace(b"aaa", &mut workspace, allocation_free)
            .unwrap();
        assert!(report.closes());
        assert_eq!(*report.report().output(), 3);
        assert_eq!(report.matches().len(), 3);
    }
    assert_eq!(Stats::default(), hot.change());
}
