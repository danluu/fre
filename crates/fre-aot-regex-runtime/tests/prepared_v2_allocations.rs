#![allow(
    unsafe_code,
    reason = "this integration test directly audits the exclusive C ABI"
)]

use std::alloc::System;

use fre_aot_regex::{CompileMode, CompileRequest, EngineKind, OutputContract, Target, compile};
use fre_aot_regex_runtime::{
    FreAotRegexExclusiveHandleV1, FreAotRegexPrepareConfigV2, FreAotRegexResultV1,
    PREPARE_OPERATION_COUNT, PREPARE_OPERATION_GREP_COUNT, PREPARE_OPERATION_SEARCH,
    PREPARE_OPERATION_SPAN_SUM, STATUS_MATCH, STATUS_SUCCESS,
    fre_aot_regex_runtime_count_exclusive_v1, fre_aot_regex_runtime_destroy_exclusive_v1,
    fre_aot_regex_runtime_grep_count_exclusive_v1, fre_aot_regex_runtime_prepare_exclusive_v1,
    fre_aot_regex_runtime_prepare_exclusive_v2, fre_aot_regex_runtime_search_exclusive_v1,
    fre_aot_regex_runtime_span_sum_exclusive_v1,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

type ExclusiveReducer =
    unsafe extern "C" fn(FreAotRegexExclusiveHandleV1, *const u8, usize, *mut u64) -> u32;

fn serialized_program(pattern: &str, output: OutputContract) -> Vec<u8> {
    compile(
        CompileRequest::new(pattern, Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(output),
    )
    .expect("compile allocation fixture")
    .program()
    .serialize()
    .expect("serialize allocation fixture")
}

fn span_program() -> Vec<u8> {
    let compiled = compile(
        CompileRequest::new("(?:ab|ac)+z", Target::x86_64_linux())
            .mode(CompileMode::Fast)
            .output(OutputContract::Span),
    )
    .expect("compile ordered-NFA allocation fixture");
    assert_eq!(compiled.program().engine_kind(), EngineKind::OrderedNfa);
    compiled
        .program()
        .serialize()
        .expect("serialize ordered-NFA allocation fixture")
}

fn prepare_v1(program: &[u8]) -> FreAotRegexExclusiveHandleV1 {
    let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
    // SAFETY: the complete compiler-produced program is readable and the
    // disjoint aligned output remains writable for the synchronous call.
    let status = unsafe {
        fre_aot_regex_runtime_prepare_exclusive_v1(program.as_ptr(), program.len(), &raw mut handle)
    };
    assert_eq!(status, STATUS_SUCCESS);
    assert!(!handle.is_invalid());
    handle
}

fn prepare_v2(program: &[u8], config: &FreAotRegexPrepareConfigV2) -> FreAotRegexExclusiveHandleV1 {
    let mut handle = FreAotRegexExclusiveHandleV1::INVALID;
    // SAFETY: both readable inputs are complete and initialized, while the
    // disjoint aligned output remains writable for the synchronous call.
    let status = unsafe {
        fre_aot_regex_runtime_prepare_exclusive_v2(
            program.as_ptr(),
            program.len(),
            config,
            &raw mut handle,
        )
    };
    assert_eq!(status, STATUS_SUCCESS);
    assert!(!handle.is_invalid());
    handle
}

fn measured_reduce(
    handle: FreAotRegexExclusiveHandleV1,
    reducer: ExclusiveReducer,
    haystack: &[u8],
) -> (Stats, u64) {
    let mut value = u64::MAX;
    let region = Region::new(GLOBAL);
    // SAFETY: the caller exclusively owns the live handle; the readable
    // haystack and aligned scalar output are live and disjoint for this call.
    let status = unsafe { reducer(handle, haystack.as_ptr(), haystack.len(), &raw mut value) };
    let allocations = region.change();
    assert_eq!(status, STATUS_SUCCESS);
    (allocations, value)
}

fn measured_search(
    handle: FreAotRegexExclusiveHandleV1,
    haystack: &[u8],
) -> (Stats, FreAotRegexResultV1) {
    let mut result = FreAotRegexResultV1 {
        start: usize::MAX,
        end: usize::MAX,
    };
    let region = Region::new(GLOBAL);
    // SAFETY: the caller exclusively owns the live handle; the complete
    // haystack window and aligned result output are live and disjoint.
    let status = unsafe {
        fre_aot_regex_runtime_search_exclusive_v1(
            handle,
            haystack.as_ptr(),
            haystack.len(),
            0,
            haystack.len(),
            &raw mut result,
        )
    };
    let allocations = region.change();
    assert_eq!(status, STATUS_MATCH);
    (allocations, result)
}

fn destroy(handle: FreAotRegexExclusiveHandleV1) {
    // SAFETY: every caller transfers its one live exclusively owned handle
    // here exactly once, after all operation calls have returned.
    assert_eq!(
        unsafe { fre_aot_regex_runtime_destroy_exclusive_v1(handle) },
        STATUS_SUCCESS
    );
}

#[test]
fn declared_v2_reducers_allocate_nothing_on_their_first_operation() {
    let span_program = span_program();
    let span_haystack = b"xxabz--acz!";

    let search_handle = prepare_v2(
        &span_program,
        &FreAotRegexPrepareConfigV2::new(PREPARE_OPERATION_SEARCH),
    );
    let (search_allocations, first_match) = measured_search(search_handle, span_haystack);
    assert_eq!(first_match, FreAotRegexResultV1 { start: 2, end: 5 });
    assert_eq!(search_allocations, Stats::default());
    destroy(search_handle);

    let span_cases: [(u64, ExclusiveReducer, u64); 2] = [
        (
            PREPARE_OPERATION_COUNT,
            fre_aot_regex_runtime_count_exclusive_v1,
            2,
        ),
        (
            PREPARE_OPERATION_SPAN_SUM,
            fre_aot_regex_runtime_span_sum_exclusive_v1,
            6,
        ),
    ];
    for (operation_flags, reducer, expected) in span_cases {
        let handle = prepare_v2(
            &span_program,
            &FreAotRegexPrepareConfigV2::new(operation_flags),
        );
        let (allocations, value) = measured_reduce(handle, reducer, span_haystack);
        assert_eq!(value, expected);
        assert_eq!(allocations, Stats::default());
        destroy(handle);
    }

    for (operation_flags, reducer, expected) in span_cases {
        let handle = prepare_v2(
            &span_program,
            &FreAotRegexPrepareConfigV2 {
                max_start_filter_setup_work: 0,
                ..FreAotRegexPrepareConfigV2::new(operation_flags)
            },
        );
        let (allocations, value) = measured_reduce(handle, reducer, span_haystack);
        assert_eq!(value, expected);
        assert_eq!(allocations, Stats::default());
        destroy(handle);
    }

    let grep_program = serialized_program("^a+$", OutputContract::Exists);
    let grep_haystack = b"a\r\nno\naa\n\n";
    let grep_handle = prepare_v2(
        &grep_program,
        &FreAotRegexPrepareConfigV2::new(PREPARE_OPERATION_GREP_COUNT),
    );
    let (grep_allocations, grep_count) = measured_reduce(
        grep_handle,
        fre_aot_regex_runtime_grep_count_exclusive_v1,
        grep_haystack,
    );
    assert_eq!(grep_count, 2);
    assert_eq!(grep_allocations, Stats::default());
    destroy(grep_handle);

    let legacy_search_handle = prepare_v1(&span_program);
    let (legacy_search_allocations, first_match) =
        measured_search(legacy_search_handle, span_haystack);
    assert_eq!(first_match, FreAotRegexResultV1 { start: 2, end: 5 });
    assert!(legacy_search_allocations.allocations > 0);
    assert!(legacy_search_allocations.bytes_allocated > 0);
    destroy(legacy_search_handle);

    let legacy_handle = prepare_v1(&span_program);
    let (legacy_allocations, legacy_count) = measured_reduce(
        legacy_handle,
        fre_aot_regex_runtime_count_exclusive_v1,
        span_haystack,
    );
    assert_eq!(legacy_count, 2);
    assert!(legacy_allocations.allocations > 0);
    assert!(legacy_allocations.bytes_allocated > 0);
    destroy(legacy_handle);
}
