#![forbid(unsafe_code)]

use std::alloc::System;

use fre_capture_lab::{
    Ast, BuildLimits, CAPTURE_PROGRAM_V1_HEADER_BYTES, CaptureProgramV1, CaptureProgramV1Census,
    CaptureProgramV1Limits, Program,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
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
