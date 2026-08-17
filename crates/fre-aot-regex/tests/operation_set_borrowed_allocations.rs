#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre_aot_regex::{
    AotOperationAxesV1, AotOperationSetV1, AotOperationSetV1View, CompileMode, CompileRequest,
    OutputContract, Target, compile,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn program(pattern: &str, output: OutputContract) -> Vec<u8> {
    compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(output),
    )
    .expect("compile borrowed operation-set fixture")
    .program()
    .serialize()
    .expect("serialize borrowed operation-set fixture")
}

#[test]
fn borrowed_operation_set_preflight_and_record_walk_allocate_nothing() {
    let exists = program("alpha+", OutputContract::Exists);
    let span = program("beta+", OutputContract::Span);
    let set = AotOperationSetV1::from_operations([
        (AotOperationAxesV1::SEARCH, exists.as_slice()),
        (AotOperationAxesV1::COUNT, span.as_slice()),
        (AotOperationAxesV1::SPAN_SUM, span.as_slice()),
        (AotOperationAxesV1::GREP, exists.as_slice()),
    ])
    .expect("build borrowed operation-set fixture");
    let wire = set.as_bytes();

    let region = Region::new(GLOBAL);
    for _ in 0..16 {
        let view = AotOperationSetV1View::deserialize(black_box(wire))
            .expect("allocation-free operation-set preflight");
        black_box(view.identity());
        for member in view.members() {
            black_box(member.index());
            black_box(member.payload_offset());
            black_box(member.as_bytes());
            black_box(member.identity());
            black_box(member.output_contract());
        }
        for index in 0..view.operation_count() {
            black_box(view.root(index).expect("validated root"));
            black_box(view.stage(index).expect("validated stage"));
            black_box(view.output(index).expect("validated output"));
        }
    }
    assert_eq!(Stats::default(), region.change());
}
