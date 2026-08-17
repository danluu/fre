#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre_aot_regex::{
    AotOperationAxesV2, AotOperationSetMemberInputV2, AotOperationSetV2, AotOperationSetV2View,
    CompileMode, CompileRequest, OutputContract, Target, compile,
};
use fre_capture_lab::{Ast, BuildLimits, CaptureProgramV1, CaptureProgramV1Limits, Program};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn compiled_program(pattern: &str, output: OutputContract) -> Vec<u8> {
    compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(output),
    )
    .expect("compile borrowed V2 operation-set fixture")
    .program()
    .serialize()
    .expect("serialize borrowed V2 operation-set fixture")
}

#[test]
fn borrowed_v2_capture_preflight_and_record_walk_allocate_nothing() {
    let exists = compiled_program("alpha+", OutputContract::Exists);
    let span = compiled_program("beta+", OutputContract::Span);
    let capture_program = Program::compile(
        &Ast::concat([
            Ast::Class(vec![(b'a', b'c'), (b'x', b'z')]).named(1, "named"),
            Ast::Byte(b'q'),
        ]),
        BuildLimits::default(),
    )
    .expect("compile capture fixture");
    let capture =
        CaptureProgramV1::from_program(capture_program, CaptureProgramV1Limits::default())
            .expect("serialize capture fixture");
    let set = AotOperationSetV2::from_operations(
        [
            (
                AotOperationAxesV2::SEARCH,
                AotOperationSetMemberInputV2::CompiledProgram(exists.as_slice()),
            ),
            (
                AotOperationAxesV2::COUNT,
                AotOperationSetMemberInputV2::CompiledProgram(span.as_slice()),
            ),
            (
                AotOperationAxesV2::SPAN_SUM,
                AotOperationSetMemberInputV2::CompiledProgram(span.as_slice()),
            ),
            (
                AotOperationAxesV2::GREP,
                AotOperationSetMemberInputV2::CompiledProgram(exists.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_bytes()),
            ),
        ],
        CaptureProgramV1Limits::default(),
    )
    .expect("build borrowed V2 operation-set fixture");
    let wire = set.as_bytes();
    let required = AotOperationSetV2View::capture_validation_scratch_words_from_wire(
        wire,
        CaptureProgramV1Limits::default(),
    )
    .expect("capture scratch sizing");
    let mut scratch = vec![0_u32; required];

    let region = Region::new(GLOBAL);
    for _ in 0..16 {
        let view = AotOperationSetV2View::deserialize(
            black_box(wire),
            CaptureProgramV1Limits::default(),
            black_box(&mut scratch),
        )
        .expect("allocation-free V2 operation-set preflight");
        black_box(view.identity());
        for member in view.members() {
            black_box(member.index());
            black_box(member.kind());
            black_box(member.payload_offset());
            black_box(member.as_bytes());
            black_box(member.identity());
        }
        for index in 0..view.operation_count() {
            black_box(view.root(index).expect("validated root"));
            black_box(view.stage(index).expect("validated stage"));
            black_box(view.output(index).expect("validated output"));
        }
    }
    assert_eq!(Stats::default(), region.change());
}
