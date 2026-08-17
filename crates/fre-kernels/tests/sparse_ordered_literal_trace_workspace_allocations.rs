#![forbid(unsafe_code)]

use std::alloc::System;

use fre_kernels::{
    SparseOrderedLiteralAggregateBuildLimits, SparseOrderedLiteralAggregateReduceLimits,
    SparseOrderedLiteralCountPlan, SparseOrderedLiteralTraceWorkspaceLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn fixed_source_sparse_literal_trace_allocates_nothing_per_run() {
    let plan = SparseOrderedLiteralCountPlan::build(
        vec![b"ab".as_slice(), b"a".as_slice(), b"".as_slice()],
        SparseOrderedLiteralAggregateBuildLimits::unlimited(),
    )
    .unwrap();

    let setup = Region::new(GLOBAL);
    let mut workspace = plan
        .prepare_trace_workspace(8, SparseOrderedLiteralTraceWorkspaceLimits::unlimited())
        .unwrap();
    let accounting = workspace.accounting();
    assert!(accounting.closes());
    assert_eq!(accounting.allocation_attempts, 2);
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

    let first = Region::new(GLOBAL);
    let report = plan
        .execute_trace_with_workspace(
            b"abababab",
            SparseOrderedLiteralAggregateReduceLimits::unlimited(),
            &mut workspace,
        )
        .unwrap();
    assert!(report.closes());
    assert_eq!(report.count(), 4);
    assert_eq!(report.matches().len(), 4);
    assert_eq!(Stats::default(), first.change());

    let steady = Region::new(GLOBAL);
    for _ in 0..32 {
        let report = plan
            .execute_trace_with_workspace(
                b"abababab",
                SparseOrderedLiteralAggregateReduceLimits::unlimited(),
                &mut workspace,
            )
            .unwrap();
        assert!(report.closes());
        assert_eq!(report.count(), 4);
        assert_eq!(report.matches().len(), 4);
    }
    assert_eq!(Stats::default(), steady.change());
}
