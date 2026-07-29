#![allow(
    unsafe_code,
    reason = "tests exercise the exported C contract with known-live Rust storage"
)]

use core::{
    mem::{align_of, offset_of, size_of},
    ptr,
};

use crate::{
    FRE_V1_ABI_VERSION, FRE_V1_DIAGNOSTIC_ARGUMENT, FRE_V1_DIAGNOSTIC_COMPILE,
    FRE_V1_DIAGNOSTIC_NONE, FRE_V1_DIAGNOSTIC_PANIC, FRE_V1_FEATURE_EXISTS,
    FRE_V1_FEATURE_PLAN_INFO, FRE_V1_FEATURE_RUST_BYTES, FRE_V1_FEATURE_SELECTED_END,
    FRE_V1_FEATURE_SPAN, FRE_V1_FEATURE_THREAD_SAFE_REGEX, FRE_V1_FEATURES, FRE_V1_JIT_DENY,
    FRE_V1_PLAN_EXACT_LITERAL, FRE_V1_PLAN_UNICODE_FOLDED_LITERAL, FRE_V1_PLAN_UNICODE_WORD_RUN,
    FRE_V1_PROFILE_RUST_BYTES, FRE_V1_STATUS_ABI_MISMATCH, FRE_V1_STATUS_COMPILE_ERROR,
    FRE_V1_STATUS_INVALID_ARGUMENT, FRE_V1_STATUS_INVALID_PATTERN_ENCODING,
    FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH, FRE_V1_STATUS_OK, FRE_V1_STATUS_PANIC,
    FRE_V1_STATUS_SEARCH_ERROR, FRE_V1_STATUS_STRUCT_TOO_SMALL, FRE_V1_STATUS_UNSUPPORTED_CONFIG,
    FRE_V1_STATUS_UNSUPPORTED_PROFILE, FreV1AbiDescriptor, FreV1Config, FreV1Diagnostic,
    FreV1ExistsResult, FreV1Header, FreV1MatchResult, FreV1PlanInfo, FreV1Regex,
    FreV1SelectedEndResult, boundary,
    ffi::{
        fre_v1_config_default, fre_v1_get_abi_descriptor, fre_v1_regex_compile,
        fre_v1_regex_exists, fre_v1_regex_plan, fre_v1_regex_release, fre_v1_regex_retain,
        fre_v1_regex_selected_end, fre_v1_regex_span,
    },
};

#[derive(Clone, Copy)]
#[repr(C)]
struct ExtendedConfig {
    known: FreV1Config,
    tail: [u8; 32],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ExtendedExists {
    known: FreV1ExistsResult,
    tail: [u8; 24],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ExtendedDiagnostic {
    known: FreV1Diagnostic,
    tail: [u8; 16],
}

#[test]
fn abi_layouts_offsets_tags_and_features_are_stable() {
    assert_eq!(size_of::<FreV1Header>(), 8);
    assert_eq!(align_of::<FreV1Header>(), 4);
    assert_eq!(offset_of!(FreV1Header, abi_version), 0);
    assert_eq!(offset_of!(FreV1Header, struct_size), 4);
    assert_eq!(size_of::<FreV1AbiDescriptor>(), 64);
    assert_eq!(size_of::<FreV1Config>(), 40);
    assert_eq!(size_of::<FreV1Diagnostic>(), 280);
    assert_eq!(size_of::<FreV1PlanInfo>(), 64);
    assert_eq!(size_of::<FreV1ExistsResult>(), 16);
    if usize::BITS == 64 {
        assert_eq!(size_of::<FreV1SelectedEndResult>(), 24);
        assert_eq!(size_of::<FreV1MatchResult>(), 32);
    }
    assert_eq!(offset_of!(FreV1Config, profile), 8);
    assert_eq!(offset_of!(FreV1Config, search_work), 24);
    assert_eq!(offset_of!(FreV1Diagnostic, message), 24);
    assert_eq!(offset_of!(FreV1PlanInfo, planner_work), 16);
    assert_eq!(offset_of!(FreV1MatchResult, start), 16);

    assert_eq!(FRE_V1_ABI_VERSION, 1);
    assert_eq!(FRE_V1_STATUS_OK, 0);
    assert_eq!(FRE_V1_PROFILE_RUST_BYTES, 1);
    assert_eq!(FRE_V1_JIT_DENY, 1);
    assert_eq!(FRE_V1_PLAN_UNICODE_FOLDED_LITERAL, 8);
    assert_eq!(
        FRE_V1_FEATURES,
        FRE_V1_FEATURE_RUST_BYTES
            | FRE_V1_FEATURE_EXISTS
            | FRE_V1_FEATURE_SELECTED_END
            | FRE_V1_FEATURE_SPAN
            | FRE_V1_FEATURE_PLAN_INFO
            | FRE_V1_FEATURE_THREAD_SAFE_REGEX
    );
}

#[test]
fn descriptor_and_default_config_are_checked() {
    let mut descriptor = FreV1AbiDescriptor::caller_init();
    // SAFETY: initialized record is valid writable output storage.
    assert_eq!(unsafe { fre_v1_get_abi_descriptor(&raw mut descriptor) }, 0);
    assert_eq!(descriptor, FreV1AbiDescriptor::current());

    let mut config = FreV1Config::caller_init();
    // SAFETY: initialized record is valid writable output storage.
    assert_eq!(unsafe { fre_v1_config_default(&raw mut config) }, 0);
    assert_eq!(config, FreV1Config::checked_default());

    let mut too_small = FreV1Config::caller_init();
    too_small.struct_size = 8;
    let before = too_small;
    // SAFETY: readable/writable common header exists, but advertises too little.
    assert_eq!(
        unsafe { fre_v1_config_default(&raw mut too_small) },
        FRE_V1_STATUS_STRUCT_TOO_SMALL
    );
    assert_eq!(too_small, before);

    let mut wrong_abi = FreV1AbiDescriptor::caller_init();
    wrong_abi.abi_version = 99;
    let before = wrong_abi;
    // SAFETY: record storage is valid; ABI mismatch is the tested input.
    assert_eq!(
        unsafe { fre_v1_get_abi_descriptor(&raw mut wrong_abi) },
        FRE_V1_STATUS_ABI_MISMATCH
    );
    assert_eq!(wrong_abi, before);
}

#[test]
fn larger_record_capacity_preserves_unknown_tail_bytes() {
    let mut extended = ExtendedConfig {
        known: FreV1Config::caller_init(),
        tail: [0xA5; 32],
    };
    extended.known.struct_size =
        u32::try_from(size_of::<ExtendedConfig>()).expect("small test record");
    // SAFETY: the known prefix is aligned/writable and advertises the complete
    // extended allocation; unknown tail bytes are non-overlapping storage.
    assert_eq!(
        unsafe { fre_v1_config_default(&raw mut extended.known) },
        FRE_V1_STATUS_OK
    );
    assert_eq!(extended.known, FreV1Config::checked_default());
    assert_eq!(extended.tail, [0xA5; 32]);

    let (regex, _) = compile(b"x", FreV1Config::checked_default());
    let mut result = ExtendedExists {
        known: FreV1ExistsResult::caller_init(),
        tail: [0x5A; 24],
    };
    result.known.struct_size =
        u32::try_from(size_of::<ExtendedExists>()).expect("small extended result");
    // SAFETY: the known result prefix and unknown writable tail are valid.
    assert_eq!(
        unsafe {
            fre_v1_regex_exists(
                regex,
                b"x".as_ptr(),
                1,
                &raw mut result.known,
                ptr::null_mut(),
            )
        },
        FRE_V1_STATUS_OK
    );
    assert_eq!(result.known.matched, 1);
    assert_eq!(result.tail, [0x5A; 24]);
    // SAFETY: transfers compile's sole reference.
    assert_eq!(unsafe { fre_v1_regex_release(regex) }, FRE_V1_STATUS_OK);

    let mut diagnostic = ExtendedDiagnostic {
        known: FreV1Diagnostic::caller_init(),
        tail: [0xC3; 16],
    };
    diagnostic.known.struct_size =
        u32::try_from(size_of::<ExtendedDiagnostic>()).expect("small extended diagnostic");
    let sentinel = ptr::without_provenance_mut::<FreV1Regex>(0x1000);
    let mut output = sentinel;
    let config = FreV1Config::checked_default();
    // SAFETY: all pointers are live; the pattern is a deterministic syntax failure.
    assert_eq!(
        unsafe {
            fre_v1_regex_compile(
                &raw const config,
                b"(".as_ptr(),
                1,
                &raw mut output,
                &raw mut diagnostic.known,
            )
        },
        FRE_V1_STATUS_COMPILE_ERROR
    );
    assert_eq!(output, sentinel);
    assert_eq!(diagnostic.tail, [0xC3; 16]);
}

#[test]
fn compile_and_all_single_search_outputs_work() {
    let (regex, diagnostic) = compile(b"needle", FreV1Config::checked_default());
    assert_eq!(diagnostic.category, FRE_V1_DIAGNOSTIC_NONE);
    let haystack = b"zzneedlezz";

    let mut exists = FreV1ExistsResult::caller_init();
    let mut diagnostic = FreV1Diagnostic::caller_init();
    // SAFETY: handle and byte/record storage meet the header contract.
    assert_eq!(
        unsafe {
            fre_v1_regex_exists(
                regex,
                haystack.as_ptr(),
                haystack.len(),
                &raw mut exists,
                &raw mut diagnostic,
            )
        },
        FRE_V1_STATUS_OK
    );
    assert_eq!(exists.matched, 1);

    let mut selected = FreV1SelectedEndResult::caller_init();
    // SAFETY: same valid handle and input, distinct writable output.
    assert_eq!(
        unsafe {
            fre_v1_regex_selected_end(
                regex,
                haystack.as_ptr(),
                haystack.len(),
                &raw mut selected,
                ptr::null_mut(),
            )
        },
        FRE_V1_STATUS_OK
    );
    assert_eq!((selected.found, selected.end), (1, 8));

    let mut matched = FreV1MatchResult::caller_init();
    // SAFETY: same valid handle and input, distinct writable output.
    assert_eq!(
        unsafe {
            fre_v1_regex_span(
                regex,
                haystack.as_ptr(),
                haystack.len(),
                &raw mut matched,
                ptr::null_mut(),
            )
        },
        FRE_V1_STATUS_OK
    );
    assert_eq!((matched.found, matched.start, matched.end), (1, 2, 8));

    let mut plan = FreV1PlanInfo::caller_init();
    // SAFETY: handle is live and plan is valid output storage.
    assert_eq!(
        unsafe { fre_v1_regex_plan(regex, &raw mut plan, ptr::null_mut()) },
        FRE_V1_STATUS_OK
    );
    assert_eq!(plan.plan, FRE_V1_PLAN_EXACT_LITERAL);
    assert!(plan.plan_storage_bytes >= 6);
    // SAFETY: transfers the sole live reference from compile.
    assert_eq!(unsafe { fre_v1_regex_release(regex) }, FRE_V1_STATUS_OK);
}

#[test]
fn unicode_word_run_has_a_stable_public_plan_tag() {
    let (regex, _) = compile(br"\b\w{2,}\b", FreV1Config::checked_default());
    let mut plan = FreV1PlanInfo::caller_init();
    // SAFETY: compile returned one live handle and plan is valid output storage.
    assert_eq!(
        unsafe { fre_v1_regex_plan(regex, &raw mut plan, ptr::null_mut()) },
        FRE_V1_STATUS_OK
    );
    assert_eq!(plan.plan, FRE_V1_PLAN_UNICODE_WORD_RUN);
    // SAFETY: transfers the sole live reference from compile.
    assert_eq!(unsafe { fre_v1_regex_release(regex) }, FRE_V1_STATUS_OK);
}

#[test]
fn null_zero_length_views_and_embedded_nul_are_supported() {
    let config = FreV1Config::checked_default();

    let sentinel = ptr::without_provenance_mut::<FreV1Regex>(0x1000);
    let mut invalid = sentinel;
    let mut invalid_diagnostic = FreV1Diagnostic::caller_init();
    // SAFETY: the null+nonzero pattern view is a checked failure; all record
    // pointers are otherwise valid and non-overlapping.
    assert_eq!(
        unsafe {
            fre_v1_regex_compile(
                &raw const config,
                ptr::null(),
                1,
                &raw mut invalid,
                &raw mut invalid_diagnostic,
            )
        },
        FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH
    );
    assert_eq!(invalid, sentinel);
    assert_eq!(invalid_diagnostic.category, FRE_V1_DIAGNOSTIC_ARGUMENT);

    let mut empty = ptr::null_mut();
    // SAFETY: null is expressly allowed for a zero-length pattern view.
    assert_eq!(
        unsafe {
            fre_v1_regex_compile(
                &raw const config,
                ptr::null(),
                0,
                &raw mut empty,
                ptr::null_mut(),
            )
        },
        FRE_V1_STATUS_OK
    );
    assert!(!empty.is_null());
    let mut matched = FreV1MatchResult::caller_init();
    // SAFETY: null is expressly allowed for a zero-length byte view.
    assert_eq!(
        unsafe { fre_v1_regex_span(empty, ptr::null(), 0, &raw mut matched, ptr::null_mut(),) },
        FRE_V1_STATUS_OK
    );
    assert_eq!((matched.found, matched.start, matched.end), (1, 0, 0));
    // SAFETY: transfers compile's reference.
    assert_eq!(unsafe { fre_v1_regex_release(empty) }, FRE_V1_STATUS_OK);

    let (nul, _) = compile(b"a\0b", FreV1Config::checked_default());
    let haystack = b"xxa\0byy";
    let mut matched = FreV1MatchResult::caller_init();
    // SAFETY: embedded NUL bytes remain inside explicitly sized readable views.
    assert_eq!(
        unsafe {
            fre_v1_regex_span(
                nul,
                haystack.as_ptr(),
                haystack.len(),
                &raw mut matched,
                ptr::null_mut(),
            )
        },
        FRE_V1_STATUS_OK
    );
    assert_eq!((matched.start, matched.end), (2, 5));
    // SAFETY: transfers compile's reference.
    assert_eq!(unsafe { fre_v1_regex_release(nul) }, FRE_V1_STATUS_OK);
}

#[test]
fn compile_failures_are_deterministic_and_leave_handle_untouched() {
    let invalid_utf8 = [0xFF];
    let first = compile_failure(&invalid_utf8, FreV1Config::checked_default());
    let second = compile_failure(&invalid_utf8, FreV1Config::checked_default());
    assert_eq!(first, second);
    assert_eq!(first.0, FRE_V1_STATUS_INVALID_PATTERN_ENCODING);

    let syntax = compile_failure(b"(", FreV1Config::checked_default());
    assert_eq!(syntax.0, FRE_V1_STATUS_COMPILE_ERROR);
    assert_eq!(syntax.1.category, FRE_V1_DIAGNOSTIC_COMPILE);

    let mut profile = FreV1Config::checked_default();
    profile.profile = 99;
    assert_eq!(
        compile_failure(b"x", profile).0,
        FRE_V1_STATUS_UNSUPPORTED_PROFILE
    );

    let mut config = FreV1Config::checked_default();
    config.jit_policy = 99;
    assert_eq!(
        compile_failure(b"x", config).0,
        FRE_V1_STATUS_UNSUPPORTED_CONFIG
    );

    let checked = FreV1Config::checked_default();
    let sentinel = ptr::without_provenance_mut::<FreV1Regex>(0x1000);
    let mut output = sentinel;
    let mut diagnostic = FreV1Diagnostic::caller_init();
    diagnostic.abi_version = 99;
    let diagnostic_before = diagnostic;
    // SAFETY: the diagnostic common header is readable but intentionally uses
    // the wrong ABI. The operation must stop before compiling or publishing.
    assert_eq!(
        unsafe {
            fre_v1_regex_compile(
                &raw const checked,
                b"x".as_ptr(),
                1,
                &raw mut output,
                &raw mut diagnostic,
            )
        },
        FRE_V1_STATUS_ABI_MISMATCH
    );
    assert_eq!(output, sentinel);
    assert_eq!(diagnostic, diagnostic_before);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-like test audits unchanged outputs for every exported result family"
)]
fn every_checked_search_failure_leaves_result_unchanged() {
    let (regex, _) = compile(b"x", FreV1Config::checked_default());
    let sentinel = FreV1MatchResult {
        abi_version: FRE_V1_ABI_VERSION,
        struct_size: u32::try_from(size_of::<FreV1MatchResult>()).expect("small record"),
        found: 7,
        reserved: 11,
        start: 13,
        end: 17,
    };
    let mut output = sentinel;
    let mut diagnostic = FreV1Diagnostic::caller_init();
    // SAFETY: all records/handle are valid; null+nonzero is a checked view error.
    assert_eq!(
        unsafe { fre_v1_regex_span(regex, ptr::null(), 1, &raw mut output, &raw mut diagnostic,) },
        FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH
    );
    assert_eq!(output, sentinel);
    assert_eq!(diagnostic.category, FRE_V1_DIAGNOSTIC_ARGUMENT);

    let first_diagnostic = diagnostic;
    output = sentinel;
    diagnostic = FreV1Diagnostic::caller_init();
    // SAFETY: repeats the same checked failure with fresh output records.
    assert_eq!(
        unsafe { fre_v1_regex_span(regex, ptr::null(), 1, &raw mut output, &raw mut diagnostic,) },
        FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH
    );
    assert_eq!(diagnostic, first_diagnostic);

    let exists_sentinel = FreV1ExistsResult {
        abi_version: FRE_V1_ABI_VERSION,
        struct_size: u32::try_from(size_of::<FreV1ExistsResult>()).expect("small record"),
        matched: 23,
        reserved: 29,
    };
    let mut exists = exists_sentinel;
    // SAFETY: null+nonzero fails before writing the valid result record.
    assert_eq!(
        unsafe { fre_v1_regex_exists(regex, ptr::null(), 1, &raw mut exists, ptr::null_mut(),) },
        FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH
    );
    assert_eq!(exists, exists_sentinel);

    let selected_sentinel = FreV1SelectedEndResult {
        abi_version: FRE_V1_ABI_VERSION,
        struct_size: u32::try_from(size_of::<FreV1SelectedEndResult>()).expect("small record"),
        found: 31,
        reserved: 37,
        end: 41,
    };
    let mut selected = selected_sentinel;
    // SAFETY: null+nonzero fails before writing the valid result record.
    assert_eq!(
        unsafe {
            fre_v1_regex_selected_end(regex, ptr::null(), 1, &raw mut selected, ptr::null_mut())
        },
        FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH
    );
    assert_eq!(selected, selected_sentinel);

    let plan_sentinel = FreV1PlanInfo {
        abi_version: FRE_V1_ABI_VERSION,
        struct_size: u32::try_from(size_of::<FreV1PlanInfo>()).expect("small record"),
        plan: 43,
        admission: 47,
        planner_work: 53,
        states: 59,
        edges: 61,
        plan_storage_bytes: 67,
        minimum_match_present: 71,
        reserved: 73,
        minimum_match_bytes: 79,
    };
    let mut plan = plan_sentinel;
    // SAFETY: null handle is a checked failure; output remains untouched.
    assert_eq!(
        unsafe { fre_v1_regex_plan(ptr::null(), &raw mut plan, ptr::null_mut()) },
        FRE_V1_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(plan, plan_sentinel);

    output = sentinel;
    output.abi_version = 99;
    let before = output;
    // SAFETY: output common header is readable but intentionally mismatched.
    assert_eq!(
        unsafe { fre_v1_regex_span(regex, b"x".as_ptr(), 1, &raw mut output, ptr::null_mut(),) },
        FRE_V1_STATUS_ABI_MISMATCH
    );
    assert_eq!(output, before);

    // SAFETY: null handles are explicitly checked before dereference.
    assert_eq!(
        unsafe {
            fre_v1_regex_span(
                ptr::null(),
                b"x".as_ptr(),
                1,
                &raw mut output,
                ptr::null_mut(),
            )
        },
        FRE_V1_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(output, before);
    // SAFETY: transfers compile's reference.
    assert_eq!(unsafe { fre_v1_regex_release(regex) }, FRE_V1_STATUS_OK);

    let mut limited = FreV1Config::checked_default();
    limited.search_work = 0;
    let (limited_regex, _) = compile(b"x", limited);
    output = sentinel;
    let before = output;
    // SAFETY: valid call whose explicit zero work limit forces search refusal.
    assert_eq!(
        unsafe {
            fre_v1_regex_span(
                limited_regex,
                b"x".as_ptr(),
                1,
                &raw mut output,
                ptr::null_mut(),
            )
        },
        FRE_V1_STATUS_SEARCH_ERROR
    );
    assert_eq!(output, before);
    // SAFETY: transfers compile's reference.
    assert_eq!(
        unsafe { fre_v1_regex_release(limited_regex) },
        FRE_V1_STATUS_OK
    );
}

#[test]
fn retain_search_release_is_concurrent_with_a_live_owner() {
    let (regex, _) = compile(b"needle", FreV1Config::checked_default());
    let address = regex.addr();
    let mut workers = Vec::new();
    for _ in 0..8 {
        // SAFETY: the main owner remains live and each successful retain creates
        // the reference transferred to exactly one worker release.
        assert_eq!(unsafe { fre_v1_regex_retain(regex) }, FRE_V1_STATUS_OK);
        workers.push(std::thread::spawn(move || {
            let regex = ptr::with_exposed_provenance::<FreV1Regex>(address);
            for _ in 0..1_000 {
                let mut output = FreV1ExistsResult::caller_init();
                // SAFETY: this worker owns a retained reference for all calls.
                assert_eq!(
                    unsafe {
                        fre_v1_regex_exists(
                            regex,
                            b"zzneedle".as_ptr(),
                            8,
                            &raw mut output,
                            ptr::null_mut(),
                        )
                    },
                    FRE_V1_STATUS_OK
                );
                assert_eq!(output.matched, 1);
            }
            // SAFETY: transfers this worker's retained reference.
            assert_eq!(unsafe { fre_v1_regex_release(regex) }, FRE_V1_STATUS_OK);
        }));
    }
    for worker in workers {
        worker.join().expect("worker does not panic");
    }
    // SAFETY: workers are joined; transfers the original compile reference.
    assert_eq!(unsafe { fre_v1_regex_release(regex) }, FRE_V1_STATUS_OK);
}

#[test]
fn unwind_build_converts_injected_panic_to_deterministic_status() {
    let first = boundary::invoke(|| panic!("injected ABI panic"));
    let second = boundary::invoke(|| panic!("injected ABI panic"));
    assert_eq!(first, second);
    assert_eq!(first.status, FRE_V1_STATUS_PANIC);
    let record = first.diagnostic.record();
    assert_eq!(record.category, FRE_V1_DIAGNOSTIC_PANIC);
    assert!(!record.message_bytes().is_empty());
}

fn compile(pattern: &[u8], config: FreV1Config) -> (*mut FreV1Regex, FreV1Diagnostic) {
    let mut output = ptr::null_mut();
    let mut diagnostic = FreV1Diagnostic::caller_init();
    // SAFETY: config/pattern/output/diagnostic storage satisfies the C contract.
    let status = unsafe {
        fre_v1_regex_compile(
            &raw const config,
            pattern.as_ptr(),
            pattern.len(),
            &raw mut output,
            &raw mut diagnostic,
        )
    };
    assert_eq!(status, FRE_V1_STATUS_OK, "{diagnostic:?}");
    assert!(!output.is_null());
    (output, diagnostic)
}

fn compile_failure(pattern: &[u8], config: FreV1Config) -> (u32, FreV1Diagnostic) {
    let sentinel = ptr::without_provenance_mut::<FreV1Regex>(0x1000);
    let mut output = sentinel;
    let mut diagnostic = FreV1Diagnostic::caller_init();
    // SAFETY: all record slots/views are valid; semantic failure is expected.
    let status = unsafe {
        fre_v1_regex_compile(
            &raw const config,
            pattern.as_ptr(),
            pattern.len(),
            &raw mut output,
            &raw mut diagnostic,
        )
    };
    assert_eq!(output, sentinel, "failure published a partial handle");
    (status, diagnostic)
}
