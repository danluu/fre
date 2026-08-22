#![forbid(unsafe_code)]

use std::alloc::System;

use fre_capture_lab::{
    Ast, BuildLimits, CaptureProgramV1, CaptureProgramV1Limits,
    ExactSpanParticipationNativeV1Limits, Program,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn native_participation_view_projection_and_authentication_allocate_nothing() {
    let program = Program::compile(
        &Ast::concat([
            Ast::Class(vec![(b'a', b'c'), (b'x', b'z')]).capture(1),
            Ast::Assert(fre_capture_lab::Assertion::WordEndAscii),
        ]),
        BuildLimits::default(),
    )
    .expect("capture program");
    let owner = CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
        .expect("sealed owner");

    let region = Region::new(GLOBAL);
    for _ in 0..32 {
        let view =
            owner
                .exact_span_participation_native_v1_view(
                    ExactSpanParticipationNativeV1Limits::default(),
                )
                .expect("view")
                .expect("supported schema");
        assert!(view.authenticates(&owner));
        assert_eq!(view.states().len(), view.layout().state_count());
    }
    assert_eq!(region.change(), Stats::default());
}
