#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box, mem::size_of};

use fre_aot_regex::{
    OrderedLiteralArtifactLimits, OrderedLiteralArtifactResource, OrderedLiteralArtifactV1,
    OrderedLiteralArtifactV1View, OrderedLiteralCountPlanReconstructionError,
    OrderedLiteralCountPlanReconstructionLimits,
};
use fre_kernels::SparseOrderedLiteralAggregateBuildLimits as SparseBuildLimits;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn borrowed_validation_identity_and_ordinal_walk_allocate_nothing() {
    let patterns = [b"".as_slice(), b"ab".as_slice(), b"\x00\xff".as_slice()];
    let artifact =
        OrderedLiteralArtifactV1::build(&patterns, OrderedLiteralArtifactLimits::unlimited())
            .expect("build allocation fixture");
    let wire = artifact.as_bytes();

    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        let view = OrderedLiteralArtifactV1View::from_wire(
            black_box(wire),
            OrderedLiteralArtifactLimits::unlimited(),
        )
        .expect("allocation-free strict view");
        let census = view.census();
        assert!(census.validation_accounting().closes());
        assert!(census.authenticates_wire(black_box(wire)));
        for (actual, expected) in view.patterns().zip(patterns) {
            assert_eq!(black_box(actual), expected);
        }
    }
    assert_eq!(Stats::default(), region.change());
}

fn owned_build_and_deserialize_match_exact_capacity_receipts() {
    let patterns = [b"".as_slice(), b"ab".as_slice(), b"\x00\xff".as_slice()];

    let build_region = Region::new(GLOBAL);
    let artifact = OrderedLiteralArtifactV1::build(
        black_box(&patterns),
        OrderedLiteralArtifactLimits::unlimited(),
    )
    .expect("build exact-capacity artifact");
    let build = artifact.accounting();
    assert!(build.closes(artifact.census()));
    assert_eq!(
        Stats {
            allocations: build.allocation_attempts,
            deallocations: 0,
            reallocations: 0,
            bytes_allocated: build.retained_bytes,
            bytes_deallocated: 0,
            bytes_reallocated: 0,
        },
        build_region.change(),
    );

    let deserialize_region = Region::new(GLOBAL);
    let copied = OrderedLiteralArtifactV1::deserialize(
        black_box(artifact.as_bytes()),
        OrderedLiteralArtifactLimits::unlimited(),
    )
    .expect("deserialize exact-capacity artifact");
    let deserialize = copied.accounting();
    assert!(deserialize.closes(copied.census()));
    assert_eq!(artifact.as_bytes(), copied.as_bytes());
    assert_eq!(
        Stats {
            allocations: deserialize.allocation_attempts,
            deallocations: 0,
            reallocations: 0,
            bytes_allocated: deserialize.retained_bytes,
            bytes_deallocated: 0,
            bytes_reallocated: 0,
        },
        deserialize_region.change(),
    );
}

fn repeated_sparse_plan_reauthentication_allocates_nothing() {
    let patterns = [b"ab".as_slice(), b"a".as_slice(), b"".as_slice()];
    let artifact =
        OrderedLiteralArtifactV1::build(&patterns, OrderedLiteralArtifactLimits::unlimited())
            .expect("build reauthentication fixture");
    let build = artifact
        .as_view()
        .build_sparse_count_plan(
            OrderedLiteralCountPlanReconstructionLimits::unlimited(),
            SparseBuildLimits::unlimited(),
        )
        .expect("build sparse reauthentication fixture");

    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        assert!(black_box(&build).closes());
    }
    assert_eq!(Stats::default(), region.change());

    let needed = build.reconstruction_receipt().prospective_work();
    let one_below = needed.checked_sub(1).expect("fixture work is nonzero");
    let mut limits = OrderedLiteralCountPlanReconstructionLimits::unlimited();
    limits.max_work = one_below;
    let refusal_region = Region::new(GLOBAL);
    let refusal = artifact
        .as_view()
        .build_sparse_count_plan(limits, SparseBuildLimits::unlimited())
        .expect_err("one-below authentication gate");
    assert_eq!(
        refusal,
        OrderedLiteralCountPlanReconstructionError::ResourceLimit {
            resource: OrderedLiteralArtifactResource::Work,
            needed,
            limit: one_below,
        },
    );
    assert_eq!(Stats::default(), refusal_region.change());
}

fn sparse_prebuild_refusal_observes_one_exact_temporary_reference_allocation() {
    let patterns = [b"ab".as_slice(), b"a".as_slice(), b"".as_slice()];
    let artifact =
        OrderedLiteralArtifactV1::build(&patterns, OrderedLiteralArtifactLimits::unlimited())
            .expect("build reference-allocation fixture");
    let reference_bytes = patterns
        .len()
        .checked_mul(size_of::<&[u8]>())
        .expect("small fixture reference extent");
    let one_below_reference_bytes = reference_bytes
        .checked_sub(1)
        .expect("fixture reference extent is nonzero");
    let mut plan_limits = SparseBuildLimits::unlimited();
    plan_limits.max_scratch_bytes = one_below_reference_bytes;

    let region = Region::new(GLOBAL);
    let failure = artifact
        .as_view()
        .build_sparse_count_plan(
            OrderedLiteralCountPlanReconstructionLimits::unlimited(),
            plan_limits,
        )
        .expect_err("kernel scratch gate must refuse before internal allocation");
    let receipt = match failure {
        OrderedLiteralCountPlanReconstructionError::Sparse { source, receipt } => {
            assert!(source.closes());
            receipt
        }
        other => panic!("unexpected reconstruction failure: {other:?}"),
    };
    assert!(receipt.closes());
    assert_eq!(receipt.source_reference_capacity(), patterns.len());
    assert_eq!(receipt.source_reference_bytes(), reference_bytes);
    assert_eq!(
        receipt.actual_work(),
        patterns
            .len()
            .checked_add(1)
            .expect("small fixture actual work"),
    );
    assert_eq!(
        Stats {
            allocations: 1,
            deallocations: 1,
            reallocations: 0,
            bytes_allocated: reference_bytes,
            bytes_deallocated: reference_bytes,
            bytes_reallocated: 0,
        },
        region.change(),
    );
}

#[test]
fn allocation_accounting_runs_in_one_process_serial_harness() {
    borrowed_validation_identity_and_ordinal_walk_allocate_nothing();
    owned_build_and_deserialize_match_exact_capacity_receipts();
    repeated_sparse_plan_reauthentication_allocates_nothing();
    sparse_prebuild_refusal_observes_one_exact_temporary_reference_allocation();
}
