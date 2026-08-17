#![forbid(unsafe_code)]

use std::alloc::System;

use fre_capture_lab::{
    Ast, BuildLimits, CAPTURE_PROGRAM_V1_HEADER_BYTES, CaptureProgramV1, CaptureProgramV1Census,
    CaptureProgramV1Error, CaptureProgramV1Limits, CaptureProgramV1Resource, Program,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn capture_program_v1_census_and_owner_accounting_are_exact() {
    full_body_census_and_identity_authentication_allocate_nothing();
    censused_owner_charges_exact_retained_capacities_and_no_hidden_reallocation();
}

fn full_body_census_and_identity_authentication_allocate_nothing() {
    let program = Program::compile(
        &Ast::concat([
            Ast::Class(vec![(b'a', b'c'), (b'x', b'z')]).named(1, "named"),
            Ast::Byte(b'q'),
        ]),
        BuildLimits::default(),
    )
    .expect("capture program");
    let artifact = CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
        .expect("capture V1");
    let required = CaptureProgramV1Census::scratch_words_from_header(
        &artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
        CaptureProgramV1Limits::default(),
    )
    .expect("scratch words");
    let mut scratch = vec![0_u32; required];

    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        let census = CaptureProgramV1Census::from_wire(
            artifact.as_bytes(),
            CaptureProgramV1Limits::default(),
            &mut scratch,
        )
        .expect("allocation-free full census");
        assert!(census.authenticates_wire(artifact.as_bytes()));
        assert_eq!(census.usage(), artifact.usage());
    }
    assert_eq!(region.change(), Stats::default());
}

fn censused_owner_charges_exact_retained_capacities_and_no_hidden_reallocation() {
    let program = Program::compile(
        &Ast::concat([
            Ast::Class(vec![(b'a', b'c'), (b'x', b'z')]).named(1, "named"),
            Ast::Class(vec![(b'0', b'3'), (b'7', b'9')]).named(2, "other"),
        ]),
        BuildLimits::default(),
    )
    .expect("capture program");
    let artifact = CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
        .expect("capture V1");
    let required = CaptureProgramV1Census::scratch_words_from_header(
        &artifact.as_bytes()[..CAPTURE_PROGRAM_V1_HEADER_BYTES],
        CaptureProgramV1Limits::default(),
    )
    .expect("scratch words");
    let mut scratch = vec![0_u32; required];
    let census = CaptureProgramV1Census::from_wire(
        artifact.as_bytes(),
        CaptureProgramV1Limits::default(),
        &mut scratch,
    )
    .expect("full census");
    let exact = census.owned_retained_logical_bytes();
    let one_below = exact.checked_sub(1).expect("nonempty retained owner");
    let transient = census.validation_scratch_logical_bytes();

    let refused_region = Region::new(GLOBAL);
    let refused = CaptureProgramV1::deserialize_with_census(
        artifact.as_bytes(),
        CaptureProgramV1Limits::default(),
        &census,
        one_below,
    )
    .expect_err("one-below retained cap");
    assert_eq!(
        refused,
        CaptureProgramV1Error::Resource {
            resource: CaptureProgramV1Resource::RetainedHeapBytes,
            required: exact,
            limit: one_below,
        }
    );
    assert_eq!(
        refused_region.change(),
        Stats {
            allocations: 1,
            deallocations: 1,
            reallocations: 0,
            bytes_allocated: transient,
            bytes_deallocated: transient,
            bytes_reallocated: 0,
        },
        "one-below cap must refuse before any retained owner allocation"
    );

    let admitted_region = Region::new(GLOBAL);
    let (restored, receipt) = CaptureProgramV1::deserialize_with_census(
        artifact.as_bytes(),
        CaptureProgramV1Limits::default(),
        &census,
        exact,
    )
    .expect("exact retained cap");
    assert_eq!(
        admitted_region.change(),
        Stats {
            allocations: census.owned_deserialize_nonempty_reservations(),
            deallocations: 1,
            reallocations: 0,
            bytes_allocated: transient
                .checked_add(receipt.nested_retained_heap_bytes())
                .expect("total requested allocation bytes"),
            bytes_deallocated: transient,
            bytes_reallocated: 0,
        }
    );
    assert_eq!(receipt.nested_retained_heap_bytes(), exact);
    assert_eq!(restored.as_bytes(), artifact.as_bytes());

    let authentication_region = Region::new(GLOBAL);
    for _ in 0..32 {
        assert!(receipt.authenticates_census_and_wire(&census, restored.as_bytes()));
    }
    assert_eq!(authentication_region.change(), Stats::default());
}
