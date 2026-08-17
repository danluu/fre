#![allow(
    unsafe_code,
    reason = "this integration test directly audits the exclusive operation-set C ABI"
)]

use std::alloc::System;

use fre_aot_regex::{
    AotOperationAxesV1, AotOperationSetV1, CompileMode, CompileRequest, EngineKind,
    OutputContract, Target, compile,
};
use fre_aot_regex_runtime::{
    FreAotRegexOperationSetExclusiveHandleV1, FreAotRegexOperationSetOutputV1,
    FreAotRegexOperationSetPrepareConfigV1, OPERATION_SET_OUTPUT_COUNT,
    OPERATION_SET_OUTPUT_GREP_COUNT, OPERATION_SET_OUTPUT_SEARCH_EXISTS,
    OPERATION_SET_OUTPUT_SEARCH_SELECTED_END, OPERATION_SET_OUTPUT_SEARCH_SPAN,
    OPERATION_SET_OUTPUT_SPAN_SUM, STATUS_MATCH, STATUS_NO_MATCH, STATUS_SUCCESS,
    fre_aot_regex_runtime_destroy_operation_set_exclusive_v1,
    fre_aot_regex_runtime_execute_operation_set_exclusive_v1,
    fre_aot_regex_runtime_prepare_operation_set_exclusive_v1,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn program(pattern: &str, output: OutputContract) -> Vec<u8> {
    let compiled = compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(output),
    )
    .expect("compile operation-set allocation fixture");
    assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
    compiled
        .program()
        .serialize_generic_nfa()
        .expect("serialize generic-NFA allocation fixture")
}

fn prepare(
    bytes: &[u8],
    config: &FreAotRegexOperationSetPrepareConfigV1,
) -> FreAotRegexOperationSetExclusiveHandleV1 {
    let mut handle = FreAotRegexOperationSetExclusiveHandleV1::INVALID;
    // SAFETY: both readable extents are complete and the disjoint aligned
    // output remains writable for the synchronous call.
    let status = unsafe {
        fre_aot_regex_runtime_prepare_operation_set_exclusive_v1(
            bytes.as_ptr(),
            bytes.len(),
            config,
            &raw mut handle,
        )
    };
    assert_eq!(status, STATUS_SUCCESS);
    assert!(!handle.is_invalid());
    handle
}

fn measured_execute(
    handle: FreAotRegexOperationSetExclusiveHandleV1,
    haystack: &[u8],
) -> (Stats, [FreAotRegexOperationSetOutputV1; 6]) {
    let mut outputs = [FreAotRegexOperationSetOutputV1::default(); 6];
    let region = Region::new(GLOBAL);
    // SAFETY: the caller exclusively owns the live handle and supplies live,
    // aligned, disjoint source and complete output extents.
    let status = unsafe {
        fre_aot_regex_runtime_execute_operation_set_exclusive_v1(
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
    reason = "one measured fixture covers every Search contract, shared scalar roots, and both proof policies"
)]
fn mixed_shared_member_operation_set_executes_all_roots_without_allocation() {
    let region = Region::new(GLOBAL);
    let control = Box::new([0_u8; 4_096]);
    let control_allocations = region.change();
    std::hint::black_box(&control);
    assert!(control_allocations.allocations > 0);
    assert!(control_allocations.bytes_allocated >= 4_096);
    drop(control);

    let exists = program("abz", OutputContract::Exists);
    let selected = program("acz", OutputContract::SelectedEnd);
    let span = program("(?:ab|ac)+z", OutputContract::Span);
    let set = AotOperationSetV1::from_operations([
        (AotOperationAxesV1::SEARCH, exists.as_slice()),
        (AotOperationAxesV1::SEARCH, selected.as_slice()),
        (AotOperationAxesV1::SEARCH, span.as_slice()),
        (AotOperationAxesV1::COUNT, span.as_slice()),
        (AotOperationAxesV1::SPAN_SUM, span.as_slice()),
        (AotOperationAxesV1::GREP_COUNT, exists.as_slice()),
    ])
    .expect("build mixed shared-member operation set");
    assert_eq!(set.member_count(), 3);
    assert_eq!(set.operation_count(), 6);
    let haystack = b"xxabz--acz!\nabz\nnomatch\n";
    let expected = [
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_SEARCH_EXISTS,
            status: STATUS_MATCH,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_SEARCH_SELECTED_END,
            status: STATUS_MATCH,
            first: 10,
            second: 10,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_SEARCH_SPAN,
            status: STATUS_MATCH,
            first: 2,
            second: 5,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_COUNT,
            status: STATUS_SUCCESS,
            first: 3,
            second: 0,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_SPAN_SUM,
            status: STATUS_SUCCESS,
            first: 9,
            second: 0,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_GREP_COUNT,
            status: STATUS_SUCCESS,
            first: 2,
            second: 0,
        },
    ];
    let no_match = [
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_SEARCH_EXISTS,
            status: STATUS_NO_MATCH,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_SEARCH_SELECTED_END,
            status: STATUS_NO_MATCH,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_SEARCH_SPAN,
            status: STATUS_NO_MATCH,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_COUNT,
            status: STATUS_SUCCESS,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_SPAN_SUM,
            status: STATUS_SUCCESS,
            first: 0,
            second: 0,
        },
        FreAotRegexOperationSetOutputV1 {
            kind: OPERATION_SET_OUTPUT_GREP_COUNT,
            status: STATUS_SUCCESS,
            first: 0,
            second: 0,
        },
    ];

    for config in [
        FreAotRegexOperationSetPrepareConfigV1::new(),
        FreAotRegexOperationSetPrepareConfigV1 {
            max_start_filter_setup_work: 0,
            ..FreAotRegexOperationSetPrepareConfigV1::new()
        },
    ] {
        let handle = prepare(set.as_bytes(), &config);
        let (first_allocations, first_outputs) = measured_execute(handle, haystack);
        assert_eq!(first_outputs, expected);
        assert_eq!(first_allocations, Stats::default());

        let (steady_allocations, steady_outputs) = measured_execute(handle, b"none\n");
        assert_eq!(steady_outputs, no_match);
        assert_eq!(steady_allocations, Stats::default());

        // SAFETY: this test transfers its one exclusively owned live handle
        // exactly once after all operation calls have completed.
        assert_eq!(
            unsafe {
                fre_aot_regex_runtime_destroy_operation_set_exclusive_v1(handle)
            },
            STATUS_SUCCESS
        );
    }
}
