#![allow(
    unsafe_code,
    reason = "this integration test directly audits the exclusive operation-set V2 C ABI"
)]

use std::alloc::System;

use fre_aot_regex::{
    AotOperationAxesV2, AotOperationSetMemberInputV2, AotOperationSetV2, CompileMode,
    CompileRequest, OutputContract, Target, compile,
};
use fre_aot_regex_runtime::{
    FreAotRegexOperationSetExclusiveHandleV2, FreAotRegexOperationSetOutputV2,
    FreAotRegexOperationSetPrepareConfigV2, OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT,
    OPERATION_SET_OUTPUT_COUNT, OPERATION_SET_OUTPUT_GREP_COUNT,
    OPERATION_SET_OUTPUT_SEARCH_EXISTS, OPERATION_SET_OUTPUT_SPAN_SUM, STATUS_INVALID_ARGUMENT,
    STATUS_MATCH, STATUS_NO_MATCH, STATUS_SUCCESS,
    fre_aot_regex_runtime_destroy_operation_set_exclusive_v2,
    fre_aot_regex_runtime_execute_operation_set_exclusive_v2,
    fre_aot_regex_runtime_prepare_operation_set_exclusive_v2,
};
use fre_capture_lab::{Ast, BuildLimits, CaptureProgramV1, CaptureProgramV1Limits, Greed, Program};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn compiled_program(pattern: &str, output: OutputContract) -> Vec<u8> {
    compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(output),
    )
    .expect("compile V2 runtime allocation fixture")
    .program()
    .serialize_generic_nfa()
    .expect("serialize V2 runtime allocation fixture")
}

fn capture_program() -> Vec<u8> {
    let ast = Ast::concat([
        Ast::Byte(b'a').capture(1),
        Ast::Byte(b'b').capture(2).repeat(0, Some(1), Greed::Greedy),
    ]);
    let program = Program::compile(&ast, BuildLimits::default())
        .expect("compile V2 capture allocation fixture");
    CaptureProgramV1::from_program(program, CaptureProgramV1Limits::default())
        .expect("serialize V2 capture allocation fixture")
        .as_bytes()
        .to_vec()
}

fn prepare(bytes: &[u8], source_bytes: usize) -> FreAotRegexOperationSetExclusiveHandleV2 {
    let config = FreAotRegexOperationSetPrepareConfigV2::new(
        u64::try_from(source_bytes).expect("fixture source length fits u64"),
    );
    let mut handle = FreAotRegexOperationSetExclusiveHandleV2::INVALID;
    // SAFETY: all readable extents are complete and the aligned output is
    // disjoint and writable for the synchronous preparation call.
    let status = unsafe {
        fre_aot_regex_runtime_prepare_operation_set_exclusive_v2(
            bytes.as_ptr(),
            bytes.len(),
            &raw const config,
            &raw mut handle,
        )
    };
    assert_eq!(status, STATUS_SUCCESS);
    assert!(!handle.is_invalid());
    handle
}

fn measured_execute(
    handle: FreAotRegexOperationSetExclusiveHandleV2,
    haystack: &[u8],
) -> (Stats, [FreAotRegexOperationSetOutputV2; 6]) {
    let mut outputs = [FreAotRegexOperationSetOutputV2::default(); 6];
    let region = Region::new(GLOBAL);
    // SAFETY: the test exclusively owns the live handle and supplies complete,
    // aligned, disjoint source and output extents of the prepared exact size.
    let status = unsafe {
        fre_aot_regex_runtime_execute_operation_set_exclusive_v2(
            handle,
            haystack.as_ptr(),
            haystack.len(),
            outputs.as_mut_ptr(),
            outputs.len(),
        )
    };
    let allocations = region.change();
    assert_eq!(status, STATUS_SUCCESS);
    (allocations, outputs)
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end allocation region must keep preparation and both execute phases visible"
)]
fn mixed_capture_and_scalar_roots_have_allocation_free_cold_and_steady_execute() {
    let region = Region::new(GLOBAL);
    let control = Box::new([0_u8; 4_096]);
    let control_allocations = region.change();
    std::hint::black_box(&control);
    assert!(control_allocations.allocations > 0);
    assert!(control_allocations.bytes_allocated >= 4_096);
    drop(control);

    let exists = compiled_program("ab", OutputContract::Exists);
    let span = compiled_program("a(?:b)?", OutputContract::Span);
    let capture = capture_program();
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
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
            (
                AotOperationAxesV2::CAPTURE_PARTICIPATION_COUNT,
                AotOperationSetMemberInputV2::CaptureProgramV1(capture.as_slice()),
            ),
        ],
        CaptureProgramV1Limits::default(),
    )
    .expect("build mixed V2 allocation fixture");
    assert_eq!(set.member_count(), 3);
    assert_eq!(set.operation_count(), 6);
    let handle = prepare(set.as_bytes(), 4);

    let sentinel = FreAotRegexOperationSetOutputV2 {
        kind: u32::MAX,
        status: u32::MAX,
        first: u64::MAX,
        second: u64::MAX,
    };
    let mut untouched = [sentinel; 6];
    // SAFETY: all pointer/extents remain valid and disjoint; the deliberately
    // wrong source length is a recoverable checked argument mismatch.
    let status = unsafe {
        fre_aot_regex_runtime_execute_operation_set_exclusive_v2(
            handle,
            b"bad".as_ptr(),
            3,
            untouched.as_mut_ptr(),
            untouched.len(),
        )
    };
    assert_eq!(status, STATUS_INVALID_ARGUMENT);
    assert_eq!(untouched, [sentinel; 6]);

    let expected_first = [
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_SEARCH_EXISTS,
            status: STATUS_MATCH,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_COUNT,
            status: STATUS_SUCCESS,
            first: 2,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_SPAN_SUM,
            status: STATUS_SUCCESS,
            first: 3,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_GREP_COUNT,
            status: STATUS_SUCCESS,
            first: 1,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT,
            status: STATUS_SUCCESS,
            first: 5,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT,
            status: STATUS_SUCCESS,
            first: 5,
            second: 0,
        },
    ];
    let expected_steady = [
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_SEARCH_EXISTS,
            status: STATUS_NO_MATCH,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_COUNT,
            status: STATUS_SUCCESS,
            first: 1,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_SPAN_SUM,
            status: STATUS_SUCCESS,
            first: 1,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_GREP_COUNT,
            status: STATUS_SUCCESS,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT,
            status: STATUS_SUCCESS,
            first: 2,
            second: 0,
        },
        FreAotRegexOperationSetOutputV2 {
            kind: OPERATION_SET_OUTPUT_CAPTURE_PARTICIPATION_COUNT,
            status: STATUS_SUCCESS,
            first: 2,
            second: 0,
        },
    ];

    let (first_allocations, first_outputs) = measured_execute(handle, b"abax");
    assert_eq!(first_outputs, expected_first);
    assert_eq!(first_allocations, Stats::default());

    let (steady_allocations, steady_outputs) = measured_execute(handle, b"xaxx");
    assert_eq!(steady_outputs, expected_steady);
    assert_eq!(steady_allocations, Stats::default());

    // SAFETY: the test transfers its one exclusively owned live handle exactly
    // once after every execution has completed.
    assert_eq!(
        unsafe { fre_aot_regex_runtime_destroy_operation_set_exclusive_v2(handle) },
        STATUS_SUCCESS,
    );
}
