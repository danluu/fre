use core::{cell::Cell, num::NonZeroU32};
use std::sync::{Mutex, MutexGuard};

use fre_jit_aarch64::{
    AuditedSelectedEndRegisterImageV2, BackendVersion, DecodedInstruction, EmitLimits,
    NativeAggregateResult, NativeResult, SearchBackendPolicy, SelectedEndRegisterBackendV2, decode,
    emit, emit_audited_with_backend, emit_exact_aggregate, emit_selected_end_register_v2,
    emit_with_backend,
};
#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
use fre_jit_aarch64::{
    emit_exact_aggregate_sve2_fixed16_count_experimental,
    emit_exact_aggregate_sve2_fixed16_pair_count_experimental,
    emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental,
    emit_exact_aggregate_sve2_fixed16_span_sum_experimental,
};
use fre_kernel_ir::{
    AggregateExecutionLimits, AggregateOutput, AnchorFlags, ByteClass, CheckedSearchWindow, Count,
    ExecutionLimits, Exists, SearchWindow, SelectedEnd, Span, SpanSum, ValidateLimits,
    build_class_suffix, build_exact_aggregate, build_exact_literal,
};
use fre_kernels::{LiteralBuildLimits, LiteralPlan, LiteralSearchLimits};
use fre_target_features::{ArmCpuIdentity, TuningClass};

use crate::{
    AuditedNativeImage, CallError, FailureStage, PublicationLimits, PublishError, PublishedKernel,
    PublishedSelectedEndRegisterV2, ResourceKind, RuntimeAggregateOperation, RuntimeIdentity,
    RuntimeOperation, SelectedEndRegisterCallErrorV2,
    operation::{
        RawAggregateCallResult, RawCallResult, decode as decode_operation, decode_aggregate,
    },
    platform::{self, FailureInjection},
    publish, publish_aggregate, publish_aggregate_impl, publish_audited, publish_audited_impl,
    publish_impl, publish_selected_end_register_v2,
    selected_end_register_v2::{
        SelectedEndRegisterHostFeaturesV2, checked_selected_end_register_call_v2,
        decode_selected_end_register_v2, invoke_preflighted_selected_end_register_v2,
        publish_selected_end_register_v2_impl, validate_selected_end_register_host_features_v2,
    },
};

static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn native_test_lock() -> MutexGuard<'static, ()> {
    NATIVE_TEST_LOCK.lock().expect("native test lock")
}

#[test]
fn selected_end_register_v1_and_v2_publishers_remain_type_separated() {
    type V1Publisher = fn(
        &AuditedNativeImage,
        PublicationLimits,
    ) -> Result<PublishedKernel<SelectedEnd>, PublishError>;
    type V2Publisher = fn(
        &AuditedSelectedEndRegisterImageV2,
        PublicationLimits,
    ) -> Result<PublishedSelectedEndRegisterV2, PublishError>;

    let _v1: V1Publisher = publish_audited::<SelectedEnd>;
    let _v2: V2Publisher = publish_selected_end_register_v2;
}

#[test]
fn selected_end_register_v2_feature_admission_is_backend_exact_and_vl_free() {
    let features = |asimd, sve, sve2| SelectedEndRegisterHostFeaturesV2 { asimd, sve, sve2 };
    assert_eq!(
        validate_selected_end_register_host_features_v2(
            SelectedEndRegisterBackendV2::AsimdV8,
            features(true, false, false),
        ),
        Ok(())
    );
    assert_eq!(
        validate_selected_end_register_host_features_v2(
            SelectedEndRegisterBackendV2::AsimdV8,
            features(false, true, true),
        ),
        Err(PublishError::CpuFeatureUnavailable { feature: "asimd" })
    );
    for (available, missing) in [
        (features(false, true, true), "asimd"),
        (features(true, false, true), "sve"),
        (features(true, true, false), "sve2"),
    ] {
        assert_eq!(
            validate_selected_end_register_host_features_v2(
                SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
                available,
            ),
            Err(PublishError::CpuFeatureUnavailable { feature: missing })
        );
    }
    assert_eq!(
        validate_selected_end_register_host_features_v2(
            SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
            features(true, true, true),
        ),
        Ok(())
    );
}

#[test]
fn selected_end_register_v2_end_or_zero_decode_is_closed() {
    let window = SearchWindow::new(4, 32);
    assert_eq!(decode_selected_end_register_v2(0, window, 6), Ok(None));
    assert_eq!(
        decode_selected_end_register_v2(12, window, 6),
        Ok(Some(fre_kernel_ir::MatchSpan::new(6, 12)))
    );
    for (end_or_zero, literal_bytes) in [(5, 6), (8, 6), (33, 6), (usize::MAX, 6), (12, 0)] {
        assert_eq!(
            decode_selected_end_register_v2(end_or_zero, window, literal_bytes),
            Err(SelectedEndRegisterCallErrorV2::InvalidNativeEnd {
                end_or_zero,
                literal_bytes,
                window_start: window.start(),
                window_end: window.end(),
            })
        );
    }
}

#[test]
fn selected_end_register_v2_preflight_refuses_before_entry_and_returns_accounting() {
    let calls = Cell::new(0_usize);
    let literal_bytes = NonZeroU32::new(6).expect("nonzero literal");
    let haystack = b"xxneedlezz";
    let window = SearchWindow::new(2, 8);
    let (matched, accounting) = checked_selected_end_register_call_v2(
        literal_bytes,
        haystack,
        window,
        LiteralSearchLimits::unlimited(),
        || {
            calls.set(calls.get() + 1);
            8
        },
    )
    .expect("checked ABI2 call");
    assert_eq!(matched, Some(fre_kernel_ir::MatchSpan::new(2, 8)));
    assert_eq!(accounting.needle_bytes, 6);
    assert_eq!(accounting.searched_bytes, 6);
    assert_eq!(accounting.linear_terms, 12);
    assert_eq!(accounting.scratch_bytes, 0);
    assert_eq!(calls.get(), 1);

    for (bad_window, limits) in [
        (SearchWindow::new(9, 8), LiteralSearchLimits::unlimited()),
        (
            SearchWindow::new(0, haystack.len() + 1),
            LiteralSearchLimits::unlimited(),
        ),
        (
            SearchWindow::new(0, haystack.len()),
            LiteralSearchLimits {
                max_linear_terms: 1,
            },
        ),
    ] {
        let before = calls.get();
        let refused = checked_selected_end_register_call_v2(
            literal_bytes,
            haystack,
            bad_window,
            limits,
            || {
                calls.set(calls.get() + 1);
                0
            },
        );
        assert!(matches!(
            refused,
            Err(SelectedEndRegisterCallErrorV2::Preflight(_))
        ));
        assert_eq!(calls.get(), before);
    }
}

#[test]
fn selected_end_register_v2_consumes_one_authoritative_preflight_and_checks_exact_literal() {
    let haystack = b"xxneedlezz";
    let checked = CheckedSearchWindow::new(haystack, SearchWindow::new(2, 8))
        .expect("checked literal window");
    let plan = LiteralPlan::new(b"needle", LiteralBuildLimits::default()).expect("literal plan");
    let preflight = plan
        .preflight_checked_window(checked, LiteralSearchLimits::unlimited())
        .expect("authoritative literal preflight");
    let expected_accounting = preflight.accounting();
    let calls = Cell::new(0_usize);
    let result = invoke_preflighted_selected_end_register_v2(
        NonZeroU32::new(6).expect("nonzero literal"),
        b"needle",
        None,
        preflight,
        |bound_haystack, bound_window| {
            calls.set(calls.get() + 1);
            assert!(core::ptr::eq(bound_haystack, haystack));
            assert_eq!(bound_window, SearchWindow::new(2, 8));
            8
        },
    )
    .expect("preflighted ABI2 call");
    assert_eq!(
        result,
        (
            Some(fre_kernel_ir::MatchSpan::new(2, 8)),
            expected_accounting
        )
    );
    assert_eq!(calls.get(), 1);

    let wrong_plan =
        LiteralPlan::new(b"needles", LiteralBuildLimits::default()).expect("wrong-width plan");
    let wrong = wrong_plan
        .preflight_checked_window(checked, LiteralSearchLimits::unlimited())
        .expect("wrong-width preflight remains internally valid");
    let before = calls.get();
    assert_eq!(
        invoke_preflighted_selected_end_register_v2(
            NonZeroU32::new(6).expect("nonzero literal"),
            b"needle",
            None,
            wrong,
            |_, _| {
                calls.set(calls.get() + 1);
                0
            },
        ),
        Err(SelectedEndRegisterCallErrorV2::LiteralWidthMismatch {
            expected_bytes: 6,
            actual_bytes: 7,
        })
    );
    assert_eq!(calls.get(), before);

    let wrong_identity =
        LiteralPlan::new(b"noodle", LiteralBuildLimits::default()).expect("same-width wrong plan");
    let wrong_identity_preflight = wrong_identity
        .preflight_checked_window(checked, LiteralSearchLimits::unlimited())
        .expect("same-width wrong preflight remains internally valid");
    assert_eq!(
        invoke_preflighted_selected_end_register_v2(
            NonZeroU32::new(6).expect("nonzero literal"),
            b"needle",
            None,
            wrong_identity_preflight,
            |_, _| {
                calls.set(calls.get() + 1);
                0
            },
        ),
        Err(SelectedEndRegisterCallErrorV2::LiteralIdentityMismatch)
    );
    assert_eq!(calls.get(), before);

    let plan_bound = invoke_preflighted_selected_end_register_v2(
        NonZeroU32::new(6).expect("nonzero literal"),
        b"needle",
        Some(&plan),
        preflight,
        |_, _| {
            calls.set(calls.get() + 1);
            8
        },
    )
    .expect("exact plan identity takes the allocation-free hot path");
    assert_eq!(plan_bound.0, Some(fre_kernel_ir::MatchSpan::new(2, 8)));
    assert_eq!(calls.get(), before + 1);

    let equal_but_distinct =
        LiteralPlan::new(b"needle", LiteralBuildLimits::default()).expect("distinct equal plan");
    let equal_but_distinct_preflight = equal_but_distinct
        .preflight_checked_window(checked, LiteralSearchLimits::unlimited())
        .expect("distinct equal preflight");
    assert_eq!(
        invoke_preflighted_selected_end_register_v2(
            NonZeroU32::new(6).expect("nonzero literal"),
            b"needle",
            Some(&plan),
            equal_but_distinct_preflight,
            |_, _| {
                calls.set(calls.get() + 1);
                0
            },
        ),
        Err(SelectedEndRegisterCallErrorV2::LiteralIdentityMismatch)
    );
    assert_eq!(calls.get(), before + 1);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one source seal keeps the distinct entry, repeated P1 audit, session-only API, and authoritative preflight boundaries together"
)]
fn selected_end_register_v2_source_boundaries_are_sealed() {
    fn position(source: &str, marker: &str) -> usize {
        source
            .find(marker)
            .unwrap_or_else(|| panic!("missing ABI2 source marker: {marker}"))
    }

    let runtime = include_str!("selected_end_register_v2.rs");
    let support_start = position(
        runtime,
        "pub fn native_selected_end_register_backend_support_v2(",
    );
    let publish_start = position(
        runtime,
        "pub(crate) fn publish_selected_end_register_v2_impl(",
    );
    let support = &runtime[support_start..publish_start];
    assert!(support.contains("platform::ensure_host_supported()?"));
    assert!(support.contains("platform::has_asimd()"));
    assert!(support.contains("platform::has_sve()"));
    assert!(support.contains("platform::has_sve2()"));
    assert!(!support.contains("current_thread_sve_vector_bytes"));

    let preflight_start = position(runtime, "fn preflight_selected_end_register_v2(");
    let publish = &runtime[publish_start..preflight_start];
    assert_eq!(
        publish
            .matches("audit_selected_end_register_v2(image)")
            .count(),
        1
    );
    assert!(publish.contains("platform::publish_selected_end_register_v2("));

    let target_start = position(runtime, "fn validate_selected_end_register_target_v2(");
    let preflight = &runtime[preflight_start..target_start];
    assert_eq!(
        preflight
            .matches("audit_selected_end_register_v2(image)")
            .count(),
        1
    );
    assert!(!preflight.contains("current_thread_sve_vector_bytes"));

    let handle_start = position(runtime, "impl PublishedSelectedEndRegisterV2 {");
    let session_start = position(
        runtime,
        "impl PublishedSelectedEndRegisterThreadSessionV2<'_> {",
    );
    let handle = &runtime[handle_start..session_start];
    assert!(handle.contains("pub fn begin_current_thread_session("));
    assert!(handle.contains("pub fn begin_current_thread_session_for_literal_plan"));
    assert!(handle.contains("plan.needle() != self.exact_literal()"));
    assert!(handle.contains("let required = self.backend.fixed_active_vector_bytes();"));
    assert!(handle.contains("if required != 0"));
    assert_eq!(
        handle.matches("current_thread_sve_vector_bytes()").count(),
        1
    );
    assert!(!handle.contains("pub fn search("));
    assert!(!handle.contains("pub fn find("));

    let token_start = position(
        runtime,
        "pub(crate) fn invoke_preflighted_selected_end_register_v2(",
    );
    let decode_start = position(runtime, "pub(crate) fn decode_selected_end_register_v2(");
    let token = &runtime[token_start..decode_start];
    assert!(token.contains("preflight.literal_bytes()"));
    assert!(token.contains("preflight.literal() == exact_literal"));
    assert!(token.contains("preflight.was_issued_by(plan)"));
    assert!(token.contains("preflight.checked_window()"));
    assert!(!token.contains("preflight_literal_window("));

    let platform = include_str!("platform/aarch64.rs");
    assert!(platform.contains("unsafe extern \"C\" fn(*const u8, usize, usize, usize) -> usize;"));
    assert!(platform.contains("Self::SelectedEndRegisterV2(image) =>"));
    assert!(platform.contains("audit_selected_end_register_v2(image)"));
    assert!(platform.contains("self.selected_end_register_literal_bytes_v2.is_none()"));
    assert!(
        platform.contains("self.selected_end_register_literal_bytes_v2 == Some(literal_bytes)")
    );
    assert!(platform.contains("self.sve_vector_bytes_at_publication.is_none()"));
    assert!(platform.contains("self.target.features == CpuFeatures::ASIMD"));
    assert!(platform.contains("self.target.features == CpuFeatures::ASIMD_SVE2"));
}

#[test]
fn selected_end_register_v2_strict_wx_guards_accounting_and_failures_are_closed() {
    let _lock = native_test_lock();
    assert_eq!(platform::live_code_mappings(), 0);
    let literal = b"needle";
    let program = build_exact_literal::<SelectedEnd>(
        literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("nonempty exact SelectedEnd");
    let image = emit_selected_end_register_v2(
        &program,
        SelectedEndRegisterBackendV2::AsimdV8,
        EmitLimits::default(),
    )
    .expect("sealed register ABI2 image");

    for stage in [
        FailureStage::Reserve,
        FailureStage::MakeWritable,
        FailureStage::Copy,
        FailureStage::Verify,
        FailureStage::Reaudit,
        FailureStage::MakeExecutable,
        FailureStage::InvalidateInstructionCache,
        FailureStage::Publish,
    ] {
        let error = publish_selected_end_register_v2_impl(
            &image,
            PublicationLimits::default(),
            FailureInjection::At(stage),
        )
        .expect_err("injected ABI2 publication stage fails");
        assert_eq!(error, PublishError::InjectedFailure { stage });
        assert_eq!(platform::live_code_mappings(), 0, "leak at {stage:?}");
    }
    assert_eq!(
        publish_selected_end_register_v2_impl(
            &image,
            PublicationLimits::default(),
            FailureInjection::CorruptCopy,
        )
        .expect_err("corrupt ABI2 copy is rejected"),
        PublishError::CopyVerificationFailed
    );
    assert_eq!(platform::live_code_mappings(), 0);

    let kernel = publish_selected_end_register_v2(&image, PublicationLimits::default())
        .expect("strict-W^X ABI2 publication");
    assert_eq!(kernel.artifact_identity(), image.artifact_identity());
    assert_eq!(kernel.backend(), SelectedEndRegisterBackendV2::AsimdV8);
    assert_eq!(
        kernel.literal_bytes(),
        u32::try_from(literal.len()).expect("small literal")
    );
    let accounting = kernel.accounting();
    assert_eq!(
        accounting.guard_bytes,
        accounting
            .page_bytes
            .checked_mul(2)
            .expect("two guard pages")
    );
    assert_eq!(
        accounting.total_mapped_bytes,
        accounting
            .payload_mapped_bytes
            .checked_add(accounting.guard_bytes)
            .expect("bounded ABI2 mapping")
    );
    assert!(
        kernel
            .mapping
            .selected_end_register_v2_contract_valid(kernel.literal_bytes())
    );
    assert!(
        !kernel
            .mapping
            .call_contract_valid(fre_kernel_ir::OutputKind::SelectedEnd)
    );
    let protections = kernel
        .mapping
        .protections()
        .expect("ABI2 mapping protection query");
    assert_eq!(protections.left_guard, libc::PROT_NONE);
    assert_eq!(protections.payload, libc::PROT_READ | libc::PROT_EXEC);
    assert_eq!(protections.payload & libc::PROT_WRITE, 0);
    assert_eq!(protections.right_guard, libc::PROT_NONE);
    assert!(
        kernel
            .mapping
            .post_publication_write_is_blocked()
            .expect("isolated ABI2 write probe")
    );

    let session = kernel
        .begin_current_thread_session()
        .expect("V8 ABI2 session creation is syscall-free");
    assert_eq!(
        session
            .find(b"zzneedlezz", LiteralSearchLimits::unlimited())
            .expect("complete ABI2 search")
            .0,
        Some(fre_kernel_ir::MatchSpan::new(2, 8))
    );
    for right_guard in [false, true] {
        platform::with_guarded_haystack(b"zzneedle", right_guard, |haystack| {
            let (matched, call_accounting) = session
                .find(haystack, LiteralSearchLimits::unlimited())
                .expect("guarded ABI2 search");
            assert_eq!(matched, Some(fre_kernel_ir::MatchSpan::new(2, 8)));
            assert_eq!(call_accounting.needle_bytes, literal.len());
            assert_eq!(call_accounting.searched_bytes, haystack.len());
            assert_eq!(
                call_accounting.linear_terms,
                literal
                    .len()
                    .checked_add(haystack.len())
                    .expect("bounded literal accounting")
            );
            assert_eq!(call_accounting.scratch_bytes, 0);
        })
        .expect("guarded ABI2 haystack");
    }

    for (resource, exact) in [
        (ResourceKind::CodeBytes, accounting.code_bytes),
        (ResourceKind::DataBytes, accounting.data_bytes),
        (ResourceKind::PayloadBytes, accounting.payload_mapped_bytes),
        (ResourceKind::MappedBytes, accounting.total_mapped_bytes),
        (ResourceKind::Pages, accounting.total_pages),
    ] {
        let exact_limits = limits_with(resource, exact);
        drop(
            publish_selected_end_register_v2(&image, exact_limits)
                .expect("exact ABI2 publication boundary"),
        );
        let failing = limits_with(resource, exact.checked_sub(1).expect("nonzero resource"));
        assert!(matches!(
            publish_selected_end_register_v2(&image, failing),
            Err(PublishError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }
    drop(session);
    drop(kernel);
    assert_eq!(platform::live_code_mappings(), 0);
}

#[test]
fn search_backend_admission_requirement_partition_is_exact() {
    for backend in [
        BackendVersion::SEARCH_SVE16_V1,
        BackendVersion::SEARCH_SVE2_16_V1,
        BackendVersion::SEARCH_SVE16_V6,
        BackendVersion::SEARCH_SVE2_FIXED16_V2,
    ] {
        assert!(crate::search_backend_requires_capability_snapshot(backend));
    }
    for backend in [
        BackendVersion::SEARCH_V1,
        BackendVersion::SEARCH_V8,
        BackendVersion::AGGREGATE_CURRENT,
    ] {
        assert!(!crate::search_backend_requires_capability_snapshot(backend));
    }
    for backend in [
        BackendVersion::SEARCH_SVE2_16_V1,
        BackendVersion::SEARCH_SVE16_V6,
        BackendVersion::SEARCH_SVE2_FIXED16_V2,
    ] {
        assert!(crate::search_backend_requires_fixed16_tuning(backend));
    }
    for backend in [BackendVersion::SEARCH_V8, BackendVersion::SEARCH_SVE16_V1] {
        assert!(!crate::search_backend_requires_fixed16_tuning(backend));
    }
}

#[test]
fn sve16_v6_admission_requires_and_binds_exact_vl16() {
    let backend = BackendVersion::SEARCH_SVE16_V6;
    let capabilities = |asimd, sve, vector_bytes| {
        crate::NativeHostCapabilities::new(asimd, sve, false, vector_bytes)
    };
    assert_eq!(
        crate::validate_search_backend_capabilities(backend, capabilities(false, true, Some(16)),),
        Err(PublishError::CpuFeatureUnavailable { feature: "asimd" })
    );
    assert_eq!(
        crate::validate_search_backend_capabilities(backend, capabilities(true, false, Some(16)),),
        Err(PublishError::CpuFeatureUnavailable { feature: "sve" })
    );
    assert_eq!(
        crate::validate_search_backend_capabilities(backend, capabilities(true, true, None),),
        Err(PublishError::SveVectorLengthMismatch {
            expected: 16,
            actual: None,
        })
    );
    assert_eq!(
        crate::validate_search_backend_capabilities(backend, capabilities(true, true, Some(32)),),
        Err(PublishError::SveVectorLengthMismatch {
            expected: 16,
            actual: Some(32),
        })
    );
    assert_eq!(
        crate::validate_search_backend_capabilities(backend, capabilities(true, true, Some(16)),),
        Ok(Some(16))
    );
    assert!(crate::search_vector_length_contract_valid(
        backend,
        Some(16)
    ));
    assert!(!crate::search_vector_length_contract_valid(backend, None));
    assert!(!crate::search_vector_length_contract_valid(
        backend,
        Some(32)
    ));
    assert_eq!(
        crate::validate_search_sve_vector_bytes(BackendVersion::SEARCH_V8, Some(32)),
        Ok(None)
    );
    assert!(crate::search_vector_length_contract_valid(
        BackendVersion::SEARCH_V8,
        None
    ));
    assert!(!crate::search_vector_length_contract_valid(
        BackendVersion::SEARCH_V8,
        Some(16)
    ));
}

#[test]
fn legacy_sve16_admission_requires_sve_before_emission_without_binding_vl() {
    let backend = BackendVersion::SEARCH_SVE16_V1;
    let capabilities = |asimd, sve, sve2, vector_bytes| {
        crate::NativeHostCapabilities::new(asimd, sve, sve2, vector_bytes)
    };
    assert_eq!(
        crate::validate_search_backend_capabilities(
            backend,
            capabilities(true, false, false, None),
        ),
        Err(PublishError::CpuFeatureUnavailable { feature: "sve" })
    );
    assert_eq!(
        crate::validate_search_backend_capabilities(
            backend,
            capabilities(false, true, false, Some(16)),
        ),
        Ok(None)
    );
    assert_eq!(
        crate::validate_search_backend_capabilities(
            backend,
            capabilities(true, true, true, Some(32)),
        ),
        Ok(None)
    );
    assert!(crate::search_vector_length_contract_valid(backend, None));
    assert!(!crate::search_vector_length_contract_valid(
        backend,
        Some(16)
    ));
}

#[test]
fn sve2_fixed16_admission_requires_features_and_binds_exact_vl16() {
    let capabilities = |asimd, sve, sve2, vector_bytes| {
        crate::NativeHostCapabilities::new(asimd, sve, sve2, vector_bytes)
    };
    for backend in [
        BackendVersion::SEARCH_SVE2_16_V1,
        BackendVersion::SEARCH_SVE2_FIXED16_V2,
    ] {
        assert_eq!(
            crate::validate_search_backend_capabilities(
                backend,
                capabilities(false, true, true, Some(16)),
            ),
            Err(PublishError::CpuFeatureUnavailable { feature: "asimd" })
        );
        assert_eq!(
            crate::validate_search_backend_capabilities(
                backend,
                capabilities(true, false, true, Some(16)),
            ),
            Err(PublishError::CpuFeatureUnavailable { feature: "sve" })
        );
        assert_eq!(
            crate::validate_search_backend_capabilities(
                backend,
                capabilities(true, true, false, Some(16)),
            ),
            Err(PublishError::CpuFeatureUnavailable { feature: "sve2" })
        );
        assert_eq!(
            crate::validate_search_backend_capabilities(
                backend,
                capabilities(true, true, true, None),
            ),
            Err(PublishError::SveVectorLengthMismatch {
                expected: 16,
                actual: None,
            })
        );
        assert_eq!(
            crate::validate_search_backend_capabilities(
                backend,
                capabilities(true, true, true, Some(32)),
            ),
            Err(PublishError::SveVectorLengthMismatch {
                expected: 16,
                actual: Some(32),
            })
        );
        assert_eq!(
            crate::validate_search_backend_capabilities(
                backend,
                capabilities(true, true, true, Some(16)),
            ),
            Ok(Some(16))
        );
        assert!(crate::search_vector_length_contract_valid(
            backend,
            Some(16)
        ));
        assert!(!crate::search_vector_length_contract_valid(backend, None));
        assert!(!crate::search_vector_length_contract_valid(
            backend,
            Some(32)
        ));
    }
}

#[test]
fn fixed_lane_search_capability_admission_matches_the_complete_truth_table() {
    let mut cases = 0_usize;
    for backend in [
        BackendVersion::SEARCH_SVE16_V1,
        BackendVersion::SEARCH_SVE2_16_V1,
        BackendVersion::SEARCH_SVE16_V6,
        BackendVersion::SEARCH_SVE2_FIXED16_V2,
    ] {
        for asimd in [false, true] {
            for sve in [false, true] {
                for sve2 in [false, true] {
                    for vector_bytes in [None, Some(16), Some(32)] {
                        let actual = crate::validate_search_backend_capabilities(
                            backend,
                            crate::NativeHostCapabilities::new(asimd, sve, sve2, vector_bytes),
                        );
                        let expected = if matches!(
                            backend,
                            BackendVersion::SEARCH_SVE2_16_V1
                                | BackendVersion::SEARCH_SVE16_V6
                                | BackendVersion::SEARCH_SVE2_FIXED16_V2
                        ) && !asimd
                        {
                            Err(PublishError::CpuFeatureUnavailable { feature: "asimd" })
                        } else if !sve {
                            Err(PublishError::CpuFeatureUnavailable { feature: "sve" })
                        } else if matches!(
                            backend,
                            BackendVersion::SEARCH_SVE2_16_V1
                                | BackendVersion::SEARCH_SVE2_FIXED16_V2
                        ) && !sve2
                        {
                            Err(PublishError::CpuFeatureUnavailable { feature: "sve2" })
                        } else if matches!(
                            backend,
                            BackendVersion::SEARCH_SVE2_16_V1
                                | BackendVersion::SEARCH_SVE16_V6
                                | BackendVersion::SEARCH_SVE2_FIXED16_V2
                        ) && vector_bytes != Some(16)
                        {
                            Err(PublishError::SveVectorLengthMismatch {
                                expected: 16,
                                actual: vector_bytes,
                            })
                        } else if backend == BackendVersion::SEARCH_SVE16_V1 {
                            Ok(None)
                        } else {
                            Ok(Some(16))
                        };
                        assert_eq!(actual, expected);
                        cases = cases.checked_add(1).expect("bounded truth table");
                    }
                }
            }
        }
    }
    assert_eq!(cases, 96);
}

#[test]
fn qualified_fixed16_search_admission_is_scoped_to_arm_41_d84() {
    let tuning = |implementer, part| TuningClass::ArmServer {
        cpu: Some(ArmCpuIdentity {
            implementer,
            part,
            variant: None,
            revision: None,
        }),
    };
    for backend in [
        BackendVersion::SEARCH_SVE2_16_V1,
        BackendVersion::SEARCH_SVE16_V6,
        BackendVersion::SEARCH_SVE2_FIXED16_V2,
    ] {
        assert_eq!(
            crate::validate_search_backend_tuning(backend, tuning(0x41, 0x0d84)),
            Ok(())
        );
        for unqualified in [
            TuningClass::Generic,
            TuningClass::ArmServer { cpu: None },
            tuning(0x41, 0x0d4f),
            tuning(0x42, 0x0d84),
        ] {
            assert_eq!(
                crate::validate_search_backend_tuning(backend, unqualified),
                Err(PublishError::CpuTuningUnavailable {
                    required: "arm-41-d84",
                })
            );
        }
    }
    for generic in [BackendVersion::SEARCH_V8, BackendVersion::SEARCH_SVE16_V1] {
        assert_eq!(
            crate::validate_search_backend_tuning(generic, TuningClass::Generic),
            Ok(())
        );
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
#[ignore = "hardware proof: requires Arm 0x41/0xd84 with ASIMD+SVE+SVE2 and VL16"]
fn fixed_vl16_checked_calls_require_tags_10_19_and_21() {
    let _lock = native_test_lock();
    let literal = b"0123456789abcdef";
    let haystack = b"zz0123456789abcdefyy";
    let window = SearchWindow::new(0, haystack.len());
    let checked = CheckedSearchWindow::new(haystack, window).expect("checked VL16 fixture");
    let program = build_exact_literal::<SelectedEnd>(
        literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("VL16 selected-end checked-call program");

    for (policy, backend) in [
        (
            SearchBackendPolicy::Sve2Fixed16,
            BackendVersion::SEARCH_SVE2_16_V1,
        ),
        (
            SearchBackendPolicy::Sve16V6,
            BackendVersion::SEARCH_SVE16_V6,
        ),
        (
            SearchBackendPolicy::Sve2Fixed16V2,
            BackendVersion::SEARCH_SVE2_FIXED16_V2,
        ),
    ] {
        crate::native_search_backend_support(backend)
            .expect("fixture host must satisfy this exact fixed-VL backend");
        let image = emit_with_backend(&program, policy, EmitLimits::default()).expect("VL16 image");
        assert_eq!(image.backend_version(), backend);
        let kernel = publish::<SelectedEnd>(&image, PublicationLimits::default())
            .expect("VL16 selected-end publication");
        assert_eq!(kernel.sve_vector_bytes_at_publication(), Some(16));
        assert!(kernel.requires_current_thread_session());

        let direct = kernel
            .search_checked(checked)
            .expect("direct checked fixed-VL call");
        assert_eq!(direct, Some(18));
        let session = kernel
            .begin_current_thread_session()
            .expect("current thread retains VL16");
        let session_result = session
            .search_checked(checked)
            .expect("session checked fixed-VL call");
        assert_eq!(session_result, direct);
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
#[ignore = "qualification receipt: requires Arm 0x41/0xd84 with ASIMD+SVE+SVE2 and VL16"]
fn fixed_16_sve_qualification_receipt() {
    use std::{hint::black_box, time::Instant};

    use fre_jit_aarch64::{NativeImage, emit_sve2_16, emit_sve16};

    const HAYSTACK_BYTES: usize = 1 << 20;
    const ITERATIONS: usize = 64;

    fn measure(
        kernel: &crate::PublishedKernel<Span>,
        haystack: &[u8],
        iterations: usize,
    ) -> (u128, usize) {
        let window = SearchWindow::new(0, haystack.len());
        let session = kernel
            .begin_current_thread_session()
            .expect("qualification thread must retain the publication VL");
        let started = Instant::now();
        let mut checksum = 0_usize;
        for _ in 0..iterations {
            let found = session
                .search(black_box(haystack), black_box(window))
                .expect("native qualification call")
                .expect("qualification haystack contains the literal");
            checksum ^= black_box(found.start());
        }
        (started.elapsed().as_nanos(), checksum)
    }

    fn instruction_mix(image: &NativeImage) -> (usize, usize, usize) {
        let instructions = decode(image.code()).expect("audited image decodes");
        (
            instructions
                .iter()
                .filter(|instruction| instruction.is_asimd())
                .count(),
            instructions
                .iter()
                .filter(|instruction| instruction.is_sve())
                .count(),
            instructions
                .iter()
                .filter(|instruction| instruction.is_sve2())
                .count(),
        )
    }

    let _lock = native_test_lock();
    crate::native_search_backend_support(BackendVersion::SEARCH_SVE2_16_V1)
        .expect("qualification host must satisfy the exact tag10 admission contract");
    println!(
        "fre_sve16_receipt,backend,width,code_bytes,rodata_bytes,asimd_instructions,sve_instructions,sve2_instructions,iterations,haystack_bytes,elapsed_ns,checksum,identity"
    );
    for width in [1_usize, 3, 15, 16, 17, 31, 32] {
        let literal: Vec<u8> = (0..width)
            .map(|index| {
                u8::try_from(index)
                    .expect("qualification widths fit u8")
                    .wrapping_mul(37)
                    .wrapping_add(11)
            })
            .collect();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("qualification program");
        let images = [
            (
                "asimd_v7",
                emit_with_backend(
                    &program,
                    SearchBackendPolicy::AsimdV7,
                    EmitLimits::default(),
                ),
            ),
            ("sve16", emit_sve16(&program, EmitLimits::default())),
            ("sve2_16", emit_sve2_16(&program, EmitLimits::default())),
        ];
        let mut haystack = vec![0xe7; HAYSTACK_BYTES];
        let expected_start = HAYSTACK_BYTES
            .checked_sub(width)
            .and_then(|value| value.checked_sub(31))
            .expect("bounded qualification dimensions");
        haystack[expected_start..expected_start + width].copy_from_slice(&literal);

        for (backend, image) in images {
            let image = image.expect("qualification image");
            let kernel = publish::<Span>(&image, PublicationLimits::default())
                .expect("host must advertise every qualification backend");
            let found = kernel
                .search(&haystack, SearchWindow::new(0, haystack.len()))
                .expect("qualification correctness call")
                .expect("qualification match");
            assert_eq!(found.start(), expected_start);
            assert_eq!(found.end(), expected_start + width);

            let (asimd, sve, sve2) = instruction_mix(&image);
            let (elapsed_ns, checksum) = measure(&kernel, &haystack, ITERATIONS);
            println!(
                "fre_sve16_receipt,{backend},{width},{},{},{asimd},{sve},{sve2},{ITERATIONS},{HAYSTACK_BYTES},{elapsed_ns},{checksum},{:?}",
                image.code().len(),
                image.rodata().len(),
                kernel.identity()
            );
        }
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
#[ignore = "parseable qualification benchmark: requires a native Linux/AArch64 host with SVE2"]
#[allow(
    clippy::too_many_lines,
    reason = "the parseable native receipt keeps setup, correctness, measurement, and both backend rows together"
)]
fn sve2_fixed16_pair_count_benchmark_receipt() {
    use std::{env, hint::black_box, time::Instant};

    use fre_jit_aarch64::{
        NativeAggregateImage, emit_exact_aggregate_sve2_fixed16_pair_count_experimental,
    };

    fn env_usize(name: &str, default: usize) -> usize {
        env::var(name).map_or(default, |value| {
            value
                .parse()
                .unwrap_or_else(|error| panic!("invalid {name}={value:?}: {error}"))
        })
    }

    fn measure(
        kernel: &crate::PublishedAggregateKernel<Count>,
        haystack: &[u8],
        iterations: usize,
    ) -> (u128, u64) {
        let limits = AggregateExecutionLimits::unlimited();
        for _ in 0..16 {
            black_box(
                kernel
                    .aggregate(black_box(haystack), limits)
                    .expect("warm aggregate call"),
            );
        }
        let started = Instant::now();
        let mut checksum = 0_u64;
        for _ in 0..iterations {
            checksum = checksum.wrapping_add(black_box(
                kernel
                    .aggregate(black_box(haystack), limits)
                    .expect("measured aggregate call"),
            ));
        }
        (started.elapsed().as_nanos(), checksum)
    }

    fn report(
        pair_kind: &str,
        backend: &str,
        kernel: &crate::PublishedAggregateKernel<Count>,
        image: &NativeAggregateImage,
        haystack: &[u8],
        iterations: usize,
        expected: u64,
    ) {
        let (total_ns, checksum) = measure(kernel, haystack, iterations);
        let iteration_count = u128::try_from(iterations).expect("iterations fit u128");
        let total_bytes = u128::try_from(haystack.len())
            .expect("length fits u128")
            .checked_mul(iteration_count)
            .expect("bounded benchmark bytes");
        let ns_per_iter = total_ns
            .checked_div(iteration_count)
            .expect("positive iteration count");
        let bytes_per_second = total_bytes
            .checked_mul(1_000_000_000)
            .expect("bounded benchmark rate numerator")
            .checked_div(total_ns.max(1))
            .expect("nonzero elapsed denominator");
        println!(
            "fre-sve2-pair-count16-v1,{pair_kind},{backend},{},{},{iterations},{total_ns},{ns_per_iter},{bytes_per_second},{checksum},{expected},{},{}",
            haystack.len(),
            haystack.as_ptr().addr() & 15,
            image.stats().code_bytes,
            image.stats().vector_instructions,
        );
    }

    let _lock = native_test_lock();
    assert!(platform::has_sve2(), "qualification host must expose SVE2");
    let haystack_bytes = env_usize("FRE_SVE2_PAIR_COUNT16_BENCH_BYTES", 1 << 20);
    let iterations = env_usize("FRE_SVE2_PAIR_COUNT16_BENCH_ITERS", 200);
    let alignment = env_usize("FRE_SVE2_PAIR_COUNT16_BENCH_ALIGNMENT", 0);
    assert!(haystack_bytes > 0 && iterations > 0 && alignment < 16);
    println!(
        "schema,pair_kind,backend,haystack_bytes,alignment_mod16,iterations,total_ns,ns_per_iter,bytes_per_second,checksum,result,code_bytes,vector_instructions"
    );

    for (pair_kind, literal) in [
        ("non_self_overlapping", b"ab".as_slice()),
        ("equal_byte_recovery", b"aa".as_slice()),
    ] {
        let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("pair benchmark program");
        let current_image =
            emit_exact_aggregate(&program, EmitLimits::default()).expect("current image");
        let sve2_image = emit_exact_aggregate_sve2_fixed16_pair_count_experimental(
            &program,
            EmitLimits::default(),
        )
        .expect("SVE2 pair image");
        let current = publish_aggregate::<Count>(&current_image, PublicationLimits::default())
            .expect("current publication");
        let sve2 = publish_aggregate::<Count>(&sve2_image, PublicationLimits::default())
            .expect("SVE2 pair publication");

        let storage_bytes = alignment
            .checked_add(haystack_bytes)
            .expect("bounded benchmark allocation");
        let mut storage = vec![b'x'; storage_bytes];
        let haystack = &mut storage[alignment..];
        for start in (3..haystack.len().saturating_sub(1)).step_by(97) {
            haystack[start..start + 2].copy_from_slice(literal);
        }
        let expected = current
            .aggregate(haystack, AggregateExecutionLimits::unlimited())
            .expect("current result");
        assert_eq!(
            sve2.aggregate(haystack, AggregateExecutionLimits::unlimited())
                .expect("SVE2 result"),
            expected
        );
        report(
            pair_kind,
            "aarch64-current",
            &current,
            &current_image,
            haystack,
            iterations,
            expected,
        );
        report(
            pair_kind,
            "sve2-fixed16-pair-count-experimental-v1",
            &sve2,
            &sve2_image,
            haystack,
            iterations,
            expected,
        );
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
fn fixed_16_sve_native_execution_matches_v7() {
    use fre_jit_aarch64::{SearchBackendPolicy, emit_sve2_16, emit_sve16, emit_with_backend};

    if let Err(error) = crate::native_search_backend_support(BackendVersion::SEARCH_SVE16_V1) {
        eprintln!("skipped: host does not satisfy legacy tag9 admission: {error}");
        return;
    }
    let tag10_supported =
        crate::native_search_backend_support(BackendVersion::SEARCH_SVE2_16_V1).is_ok();
    let _lock = native_test_lock();
    for width in [1_usize, 3, 15, 16, 17, 31, 32] {
        let literal: Vec<u8> = (0..width)
            .map(|index| {
                u8::try_from(index)
                    .expect("native test widths fit u8")
                    .wrapping_mul(37)
                    .wrapping_add(11)
            })
            .collect();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("native SVE test program");
        let mut images = vec![
            emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV7,
                EmitLimits::default(),
            )
            .expect("V7 image"),
            emit_sve16(&program, EmitLimits::default()).expect("SVE16 image"),
        ];
        if tag10_supported {
            images.push(emit_sve2_16(&program, EmitLimits::default()).expect("SVE2-16 image"));
        }
        for alignment in [0_usize, 1, 15, 16, 31] {
            let mut storage = vec![0xe7; alignment + 127 + width];
            let expected_start = alignment + 63;
            storage[expected_start..expected_start + width].copy_from_slice(&literal);
            let haystack = &storage[alignment..];
            let window = SearchWindow::new(0, haystack.len());
            let expected = program
                .execute(haystack, window, ExecutionLimits::unlimited())
                .expect("oracle")
                .into_output();
            for image in &images {
                let kernel = publish::<Span>(image, PublicationLimits::default())
                    .expect("native SVE publication");
                assert_eq!(kernel.search(haystack, window), Ok(expected));
            }
        }
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
fn fixed_16_sve_class_suffix_native_execution_matches_v7() {
    use fre_jit_aarch64::{SearchBackendPolicy, emit_with_backend};

    const ALPHABET: &[u8] = b"bcdefghijklmnopqrstuvwxyz012345";

    if let Err(error) = crate::native_search_backend_support(BackendVersion::SEARCH_SVE16_V1) {
        eprintln!("skipped: host does not satisfy legacy tag9 admission: {error}");
        return;
    }
    let tag10_supported =
        crate::native_search_backend_support(BackendVersion::SEARCH_SVE2_16_V1).is_ok();
    let _lock = native_test_lock();
    for member_count in [1_usize, 2, 5, 16] {
        let members: Vec<u8> = (0..member_count)
            .map(|index| b'A' + u8::try_from(index).expect("small native class"))
            .collect();
        for suffix_len in [1_usize, 16, 32] {
            let suffix: Vec<u8> = (0..suffix_len)
                .map(|index| ALPHABET[index % ALPHABET.len()])
                .collect();
            for anchors in [
                AnchorFlags::default(),
                AnchorFlags {
                    start: false,
                    end: true,
                },
            ] {
                let program = build_class_suffix::<Span>(
                    ByteClass::from_bytes(&members),
                    &suffix,
                    anchors,
                    ValidateLimits::default(),
                )
                .expect("native class-suffix program");
                let mut policies = vec![SearchBackendPolicy::AsimdV7];
                if member_count == 1 {
                    policies.push(SearchBackendPolicy::Sve16);
                }
                if tag10_supported {
                    policies.push(SearchBackendPolicy::Sve2Fixed16);
                }
                let images: Vec<_> = policies
                    .into_iter()
                    .map(|policy| {
                        emit_with_backend(&program, policy, EmitLimits::default())
                            .expect("native class-suffix image")
                    })
                    .collect();
                let kernels: Vec<_> = images
                    .iter()
                    .map(|image| {
                        publish::<Span>(image, PublicationLimits::default())
                            .expect("native class-suffix publication")
                    })
                    .collect();

                for alignment in [0_usize, 1, 15] {
                    for run_len in [1_usize, 17, 33] {
                        let mut haystack = vec![b'x'; alignment];
                        haystack.extend((0..run_len).map(|index| members[index % member_count]));
                        haystack.extend_from_slice(&suffix);
                        if !anchors.end {
                            haystack.extend_from_slice(b"tail");
                        }
                        let window = SearchWindow::new(alignment, haystack.len());
                        let expected = program
                            .execute(&haystack, window, ExecutionLimits::unlimited())
                            .expect("class-suffix oracle")
                            .into_output();
                        for kernel in &kernels {
                            assert_eq!(kernel.search(&haystack, window), Ok(expected));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
#[ignore = "qualification receipt: requires Arm 0x41/0xd84 with ASIMD+SVE+SVE2 and VL16"]
#[allow(
    clippy::too_many_lines,
    reason = "one ignored benchmark emits a complete parseable receipt for all class-suffix backends"
)]
fn fixed_16_sve_class_suffix_qualification_receipt() {
    use std::{hint::black_box, time::Instant};

    use fre_jit_aarch64::{NativeImage, SearchBackendPolicy, emit_with_backend};

    const ALPHABET: &[u8] = b"bcdefghijklmnopqrstuvwxyz012345";
    const HAYSTACK_BYTES: usize = 1 << 20;
    const ITERATIONS: usize = 64;
    const CLASS_RUN_BYTES: usize = 64;

    fn measure(
        kernel: &crate::PublishedKernel<Span>,
        haystack: &[u8],
        iterations: usize,
    ) -> (u128, usize) {
        let window = SearchWindow::new(0, haystack.len());
        let started = Instant::now();
        let mut checksum = 0_usize;
        for _ in 0..iterations {
            let found = kernel
                .search(black_box(haystack), black_box(window))
                .expect("native class-suffix benchmark call")
                .expect("benchmark haystack contains a match");
            checksum = checksum
                .wrapping_add(black_box(found.start()))
                .wrapping_add(black_box(found.end()));
        }
        (started.elapsed().as_nanos(), checksum)
    }

    fn instruction_mix(image: &NativeImage) -> (usize, usize, usize) {
        let instructions = decode(image.code()).expect("benchmark image decodes");
        (
            instructions
                .iter()
                .filter(|instruction| instruction.is_asimd())
                .count(),
            instructions
                .iter()
                .filter(|instruction| instruction.is_sve())
                .count(),
            instructions
                .iter()
                .filter(|instruction| instruction.is_sve2())
                .count(),
        )
    }

    let _lock = native_test_lock();
    crate::native_search_backend_support(BackendVersion::SEARCH_SVE2_16_V1)
        .expect("qualification host must satisfy the exact tag10 admission contract");
    println!(
        "fre_sve16_class_suffix_receipt,backend,class_members,suffix_bytes,code_bytes,rodata_bytes,feature_bits,asimd_instructions,sve_instructions,sve2_instructions,iterations,haystack_bytes,elapsed_ns,checksum,identity"
    );
    for member_count in [1_usize, 2, 4, 8, 16] {
        let members: Vec<u8> = (0..member_count)
            .map(|index| b'A' + u8::try_from(index).expect("small benchmark class"))
            .collect();
        for suffix_len in [1_usize, 3, 16, 32] {
            let suffix: Vec<u8> = (0..suffix_len)
                .map(|index| ALPHABET[index % ALPHABET.len()])
                .collect();
            let program = build_class_suffix::<Span>(
                ByteClass::from_bytes(&members),
                &suffix,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("benchmark class-suffix program");
            let images: &[(&str, SearchBackendPolicy)] = if member_count == 1 {
                &[
                    ("asimd_v7", SearchBackendPolicy::AsimdV7),
                    ("sve16", SearchBackendPolicy::Sve16),
                    ("sve2_16", SearchBackendPolicy::Sve2Fixed16),
                ]
            } else {
                &[
                    ("asimd_v7", SearchBackendPolicy::AsimdV7),
                    ("sve2_16", SearchBackendPolicy::Sve2Fixed16),
                ]
            };
            let mut haystack = vec![b'x'; HAYSTACK_BYTES];
            let expected_start = HAYSTACK_BYTES
                .checked_sub(suffix_len)
                .and_then(|value| value.checked_sub(CLASS_RUN_BYTES))
                .expect("bounded benchmark dimensions");
            for (index, byte) in haystack[expected_start..expected_start + CLASS_RUN_BYTES]
                .iter_mut()
                .enumerate()
            {
                *byte = members[index % member_count];
            }
            haystack[expected_start + CLASS_RUN_BYTES..].copy_from_slice(&suffix);

            for &(backend, policy) in images {
                let image = emit_with_backend(&program, policy, EmitLimits::default())
                    .expect("benchmark image");
                let kernel = publish::<Span>(&image, PublicationLimits::default())
                    .expect("host must advertise every benchmark backend");
                let found = kernel
                    .search(&haystack, SearchWindow::new(0, haystack.len()))
                    .expect("benchmark correctness call")
                    .expect("benchmark match");
                assert_eq!(found.start(), expected_start);
                assert_eq!(found.end(), HAYSTACK_BYTES);

                let (asimd, sve, sve2) = instruction_mix(&image);
                let (elapsed_ns, checksum) = measure(&kernel, &haystack, ITERATIONS);
                println!(
                    "fre_sve16_class_suffix_receipt,{backend},{member_count},{suffix_len},{},{},{},{asimd},{sve},{sve2},{ITERATIONS},{HAYSTACK_BYTES},{elapsed_ns},{checksum},{}",
                    image.code().len(),
                    image.rodata().len(),
                    image.target().features.bits(),
                    kernel.identity()
                );
            }
        }
    }
}

#[test]
fn strict_wx_smoke_matches_kernel_ir() {
    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("valid exact literal");
    let image = emit(&program, EmitLimits::default()).expect("emitted image");
    let expected_identity = RuntimeIdentity::for_image(&image);
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("strict W^X");
    assert_eq!(kernel.identity(), expected_identity);
    let haystack = b"zzneedlezz";
    let window = SearchWindow::new(0, haystack.len());
    let expected = program
        .execute(haystack, window, ExecutionLimits::unlimited())
        .expect("oracle")
        .into_output();
    let actual = kernel.search(haystack, window).expect("native call");
    assert_eq!(actual, expected);
}

#[test]
fn emitter_attested_publication_matches_oracle_and_rolls_back_every_failure() {
    let _lock = native_test_lock();
    assert_eq!(platform::live_code_mappings(), 0);
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("valid exact literal");
    let audited = emit_audited_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )
    .expect("audited image");
    let expected_identity = RuntimeIdentity::for_image(audited.as_image());
    assert!(matches!(
        publish_audited::<Exists>(&audited, PublicationLimits::default()),
        Err(PublishError::OutputContractMismatch { .. })
    ));
    assert_eq!(platform::live_code_mappings(), 0);

    for stage in [
        FailureStage::Reserve,
        FailureStage::MakeWritable,
        FailureStage::Copy,
        FailureStage::Verify,
        FailureStage::Reaudit,
        FailureStage::MakeExecutable,
        FailureStage::InvalidateInstructionCache,
        FailureStage::Publish,
    ] {
        let error = publish_audited_impl::<Span>(
            &audited,
            PublicationLimits::default(),
            FailureInjection::At(stage),
        )
        .expect_err("injected audited publication stage fails");
        assert_eq!(error, PublishError::InjectedFailure { stage });
        assert_eq!(platform::live_code_mappings(), 0, "leak at {stage:?}");
    }
    assert_eq!(
        publish_audited_impl::<Span>(
            &audited,
            PublicationLimits::default(),
            FailureInjection::CorruptCopy,
        )
        .expect_err("corrupt audited-image copy rejected"),
        PublishError::CopyVerificationFailed
    );
    assert_eq!(platform::live_code_mappings(), 0);

    let kernel =
        publish_audited::<Span>(&audited, PublicationLimits::default()).expect("strict W^X");
    assert_eq!(kernel.identity(), expected_identity);
    let haystack = b"zzneedlezz";
    let window = SearchWindow::new(0, haystack.len());
    let expected = program
        .execute(haystack, window, ExecutionLimits::unlimited())
        .expect("oracle")
        .into_output();
    assert_eq!(
        kernel.search(haystack, window).expect("native call"),
        expected
    );
    drop(kernel);
    assert_eq!(platform::live_code_mappings(), 0);
}

#[test]
#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
fn search_call_preserves_aapcs64_vector_callee_saved_lanes() {
    let _lock = native_test_lock();
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("fixed-width exact program");
    let image = emit(&program, EmitLimits::default()).expect("fixed-width exact image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("published kernel");
    let canaries = [
        0x0808_0808_0808_0808,
        0x0909_0909_0909_0909,
        0x1010_1010_1010_1010,
        0x1111_1111_1111_1111,
        0x1212_1212_1212_1212,
        0x1313_1313_1313_1313,
        0x1414_1414_1414_1414,
        0x1515_1515_1515_1515,
    ];
    let (raw, observed) = platform::invoke_with_vector_callee_saved_canary(
        &kernel.mapping,
        literal,
        SearchWindow::new(0, literal.len()),
        canaries,
    );
    assert_eq!(raw.status, 1);
    assert_eq!(raw.slot.start, 0);
    assert_eq!(raw.slot.end, literal.len());
    assert_eq!(observed, canaries);
}

#[test]
fn aggregate_one_call_hardware_matches_oracle_exhaustively() {
    let _lock = native_test_lock();
    let literals = all_sequences(b"ab", 3);
    let haystacks = all_sequences(b"ab", 6);
    let mut comparisons = 0_u64;
    for literal in &literals {
        let count = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("count program");
        let spans = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("span program");
        let count_image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
        let span_image = emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image");
        let count_kernel = publish_aggregate::<Count>(&count_image, PublicationLimits::default())
            .expect("count publication");
        let span_kernel = publish_aggregate::<SpanSum>(&span_image, PublicationLimits::default())
            .expect("span publication");
        for haystack in &haystacks {
            assert_aggregate_matches(&count, &count_kernel, haystack);
            assert_aggregate_matches(&spans, &span_kernel, haystack);
            comparisons = comparisons.checked_add(2).expect("bounded corpus");
        }
    }
    let arbitrary_literals = all_sequences(&[0x00, 0x7f, 0x80, 0xff], 2);
    let arbitrary_haystacks = all_sequences(&[0x00, 0x7f, 0x80, 0xff], 4);
    for literal in &arbitrary_literals {
        let count = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("arbitrary-byte count program");
        let spans = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("arbitrary-byte span program");
        let count_image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
        let span_image = emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image");
        let count_kernel = publish_aggregate::<Count>(&count_image, PublicationLimits::default())
            .expect("count publication");
        let span_kernel = publish_aggregate::<SpanSum>(&span_image, PublicationLimits::default())
            .expect("span publication");
        for haystack in &arbitrary_haystacks {
            assert_aggregate_matches(&count, &count_kernel, haystack);
            assert_aggregate_matches(&spans, &span_kernel, haystack);
            comparisons = comparisons.checked_add(2).expect("bounded corpus");
        }
    }
    assert_eq!(comparisons, 18_132);
}

#[test]
#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
fn experimental_sve2_fixed16_count_hardware_matches_oracle() {
    if !platform::has_sve2() {
        return;
    }
    let _lock = native_test_lock();
    let program =
        build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).expect("count program");
    let image =
        emit_exact_aggregate_sve2_fixed16_count_experimental(&program, EmitLimits::default())
            .expect("SVE2 image");
    let kernel = publish_aggregate::<Count>(&image, PublicationLimits::default())
        .expect("OS-usable SVE2 publication");

    for alignment in 0..16 {
        for length in [0, 1, 2, 15, 16, 17, 31, 32, 33, 255, 256, 257] {
            let mut storage = vec![b'y'; alignment + length + 16];
            let haystack = &mut storage[alignment..alignment + length];
            for (index, byte) in haystack.iter_mut().enumerate() {
                if index % 5 == alignment % 5 {
                    *byte = b'x';
                }
            }
            assert_aggregate_matches(&program, &kernel, haystack);
        }
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
#[ignore = "parseable qualification benchmark: requires a native Linux/AArch64 host with SVE2"]
#[allow(
    clippy::too_many_lines,
    reason = "the parseable native receipt keeps setup, correctness, measurement, and both backend rows together"
)]
fn sve2_fixed16_pair_span_sum_benchmark_receipt() {
    use std::{env, hint::black_box, time::Instant};

    use fre_jit_aarch64::{
        NativeAggregateImage, emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental,
    };

    fn env_usize(name: &str, default: usize) -> usize {
        env::var(name).map_or(default, |value| {
            value
                .parse()
                .unwrap_or_else(|error| panic!("invalid {name}={value:?}: {error}"))
        })
    }

    fn measure(
        kernel: &crate::PublishedAggregateKernel<SpanSum>,
        haystack: &[u8],
        iterations: usize,
    ) -> (u128, u64) {
        let limits = AggregateExecutionLimits::unlimited();
        for _ in 0..16 {
            black_box(
                kernel
                    .aggregate(black_box(haystack), limits)
                    .expect("warm aggregate call"),
            );
        }
        let started = Instant::now();
        let mut checksum = 0_u64;
        for _ in 0..iterations {
            checksum = checksum.wrapping_add(black_box(
                kernel
                    .aggregate(black_box(haystack), limits)
                    .expect("measured aggregate call"),
            ));
        }
        (started.elapsed().as_nanos(), checksum)
    }

    fn report(
        workload: &str,
        backend: &str,
        kernel: &crate::PublishedAggregateKernel<SpanSum>,
        image: &NativeAggregateImage,
        haystack: &[u8],
        iterations: usize,
        expected: u64,
    ) {
        let (total_ns, checksum) = measure(kernel, haystack, iterations);
        let iteration_count = u128::try_from(iterations).expect("iterations fit u128");
        let total_bytes = u128::try_from(haystack.len())
            .expect("length fits u128")
            .checked_mul(iteration_count)
            .expect("bounded benchmark bytes");
        let ns_per_iter = total_ns
            .checked_div(iteration_count)
            .expect("positive iteration count");
        let bytes_per_second = total_bytes
            .checked_mul(1_000_000_000)
            .expect("bounded benchmark rate numerator")
            .checked_div(total_ns.max(1))
            .expect("nonzero elapsed denominator");
        println!(
            "fre-sve2-pair-span-sum16-v1,{workload},{backend},{},{},{iterations},{total_ns},{ns_per_iter},{bytes_per_second},{checksum},{expected},{},{},{}",
            haystack.len(),
            haystack.as_ptr().addr() & 15,
            image.stats().code_bytes,
            image.stats().vector_instructions,
            image.stats().emission_work,
        );
    }

    let _lock = native_test_lock();
    assert!(platform::has_sve2(), "qualification host must expose SVE2");
    let haystack_bytes = env_usize("FRE_SVE2_PAIR_SPAN_SUM16_BENCH_BYTES", 1 << 20);
    let iterations = env_usize("FRE_SVE2_PAIR_SPAN_SUM16_BENCH_ITERS", 200);
    let alignment = env_usize("FRE_SVE2_PAIR_SPAN_SUM16_BENCH_ALIGNMENT", 0);
    assert!(haystack_bytes > 1 && iterations > 0 && alignment < 16);
    println!(
        "schema,workload,backend,haystack_bytes,alignment_mod16,iterations,total_ns,ns_per_iter,bytes_per_second,checksum,result,code_bytes,vector_instructions,emission_work"
    );

    let program = build_exact_aggregate::<SpanSum>(b"ab", ValidateLimits::default())
        .expect("pair SpanSum benchmark program");
    let current_image =
        emit_exact_aggregate(&program, EmitLimits::default()).expect("current image");
    let sve2_image = emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(
        &program,
        EmitLimits::default(),
    )
    .expect("SVE2 pair SpanSum image");
    let current = publish_aggregate::<SpanSum>(&current_image, PublicationLimits::default())
        .expect("current publication");
    let sve2 = publish_aggregate::<SpanSum>(&sve2_image, PublicationLimits::default())
        .expect("SVE2 pair SpanSum publication");

    for workload in ["dense", "sparse_1_per_97"] {
        let storage_bytes = alignment
            .checked_add(haystack_bytes)
            .expect("bounded benchmark allocation");
        let mut storage = vec![b'x'; storage_bytes];
        let haystack = &mut storage[alignment..];
        match workload {
            "dense" => {
                for (index, byte) in haystack.iter_mut().enumerate() {
                    *byte = if index % 2 == 0 { b'a' } else { b'b' };
                }
            }
            "sparse_1_per_97" => {
                for start in (3..haystack.len().saturating_sub(1)).step_by(97) {
                    haystack[start..start + 2].copy_from_slice(b"ab");
                }
            }
            _ => unreachable!("closed benchmark workload"),
        }
        let expected = current
            .aggregate(haystack, AggregateExecutionLimits::unlimited())
            .expect("current result");
        assert_eq!(
            sve2.aggregate(haystack, AggregateExecutionLimits::unlimited())
                .expect("SVE2 result"),
            expected
        );
        report(
            workload,
            "aarch64-current",
            &current,
            &current_image,
            haystack,
            iterations,
            expected,
        );
        report(
            workload,
            "sve2-fixed16-pair-span-sum-experimental-v1",
            &sve2,
            &sve2_image,
            haystack,
            iterations,
            expected,
        );
    }
}

#[test]
#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
fn experimental_sve2_fixed16_pair_count_hardware_matches_oracle_and_guard_pages() {
    if !platform::has_sve2() {
        return;
    }
    let _lock = native_test_lock();
    for literal in [b"ab".as_slice(), b"aa", b"\0\0", b"\xff\0"] {
        let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("pair count program");
        let image = emit_exact_aggregate_sve2_fixed16_pair_count_experimental(
            &program,
            EmitLimits::default(),
        )
        .expect("SVE2 pair image");
        let kernel = publish_aggregate::<Count>(&image, PublicationLimits::default())
            .expect("OS-usable SVE2 pair publication");

        for alignment in 0..16 {
            for length in [0, 1, 2, 3, 15, 16, 17, 18, 31, 32, 33, 34, 255, 256, 257] {
                let mut storage = vec![0x5a; alignment + length + 16];
                let haystack = &mut storage[alignment..alignment + length];
                for (index, byte) in haystack.iter_mut().enumerate() {
                    *byte = if (index + alignment) % 5 < 3 {
                        literal[(index + alignment) % 2]
                    } else {
                        u8::try_from((index * 37 + alignment * 19) & 0xff).expect("masked byte")
                    };
                }
                assert_aggregate_matches(&program, &kernel, haystack);
            }
        }

        for length in [0, 1, 2, 15, 16, 17, 18, 31, 32, 33, 34, 63, 64, 65] {
            let guarded: Vec<u8> = (0..length)
                .map(|index| {
                    if index % 5 < 3 {
                        literal[index % 2]
                    } else {
                        0x5a
                    }
                })
                .collect();
            for right in [false, true] {
                platform::with_guarded_haystack(&guarded, right, |haystack| {
                    assert_aggregate_matches(&program, &kernel, haystack);
                })
                .expect("guarded SVE2 pair haystack");
            }
        }
    }
}

#[test]
#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
fn experimental_sve2_fixed16_pair_span_sum_hardware_matches_oracle_and_guard_pages() {
    if !platform::has_sve2() {
        return;
    }
    let _lock = native_test_lock();
    for literal in [b"ab".as_slice(), b"\0\xff", b"\xff\0"] {
        let program = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("pair SpanSum program");
        let image = emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(
            &program,
            EmitLimits::default(),
        )
        .expect("SVE2 pair SpanSum image");
        let kernel = publish_aggregate::<SpanSum>(&image, PublicationLimits::default())
            .expect("OS-usable SVE2 pair SpanSum publication");

        for alignment in 0..16 {
            for length in [0, 1, 2, 3, 15, 16, 17, 18, 31, 32, 33, 34, 255, 256, 257] {
                let mut storage = vec![0x5a; alignment + length + 16];
                let haystack = &mut storage[alignment..alignment + length];
                for (index, byte) in haystack.iter_mut().enumerate() {
                    *byte = if (index + alignment) % 5 < 3 {
                        literal[(index + alignment) % 2]
                    } else {
                        u8::try_from((index * 37 + alignment * 19) & 0xff).expect("masked byte")
                    };
                }
                assert_aggregate_matches(&program, &kernel, haystack);
            }
        }

        for length in [0, 1, 2, 15, 16, 17, 18, 31, 32, 33, 34, 63, 64, 65] {
            let guarded: Vec<u8> = (0..length)
                .map(|index| {
                    if index % 5 < 3 {
                        literal[index % 2]
                    } else {
                        0x5a
                    }
                })
                .collect();
            for right in [false, true] {
                platform::with_guarded_haystack(&guarded, right, |haystack| {
                    assert_aggregate_matches(&program, &kernel, haystack);
                })
                .expect("guarded SVE2 pair SpanSum haystack");
            }
        }
    }
}

#[test]
#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
fn experimental_sve2_fixed16_span_sum_hardware_matches_oracle() {
    if !platform::has_sve2() {
        return;
    }
    let _lock = native_test_lock();
    let program = build_exact_aggregate::<SpanSum>(b"x", ValidateLimits::default())
        .expect("span-sum program");
    let image =
        emit_exact_aggregate_sve2_fixed16_span_sum_experimental(&program, EmitLimits::default())
            .expect("SVE2 image");
    let kernel = publish_aggregate::<SpanSum>(&image, PublicationLimits::default())
        .expect("OS-usable SVE2 publication");

    for alignment in 0..16 {
        for length in [0, 1, 2, 15, 16, 17, 31, 32, 33, 255, 256, 257] {
            let mut storage = vec![b'y'; alignment + length + 16];
            let haystack = &mut storage[alignment..alignment + length];
            for (index, byte) in haystack.iter_mut().enumerate() {
                if index % 5 == alignment % 5 {
                    *byte = b'x';
                }
            }
            assert_aggregate_matches(&program, &kernel, haystack);
        }
    }
}

#[test]
#[cfg(all(
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
fn experimental_sve2_fixed16_aggregates_require_os_usable_sve() {
    let _lock = native_test_lock();
    let count =
        build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).expect("count program");
    let spans = build_exact_aggregate::<SpanSum>(b"x", ValidateLimits::default())
        .expect("span-sum program");
    let pair =
        build_exact_aggregate::<Count>(b"ab", ValidateLimits::default()).expect("pair program");
    let pair_spans = build_exact_aggregate::<SpanSum>(b"ab", ValidateLimits::default())
        .expect("pair SpanSum program");
    let count_image =
        emit_exact_aggregate_sve2_fixed16_count_experimental(&count, EmitLimits::default())
            .expect("SVE2 count image");
    let span_image =
        emit_exact_aggregate_sve2_fixed16_span_sum_experimental(&spans, EmitLimits::default())
            .expect("SVE2 span-sum image");
    let pair_image =
        emit_exact_aggregate_sve2_fixed16_pair_count_experimental(&pair, EmitLimits::default())
            .expect("SVE2 pair image");
    let pair_span_image = emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(
        &pair_spans,
        EmitLimits::default(),
    )
    .expect("SVE2 pair SpanSum image");
    assert!(matches!(
        publish_aggregate::<Count>(&count_image, PublicationLimits::default()),
        Err(PublishError::CpuFeatureUnavailable { feature: "sve" })
    ));
    assert!(matches!(
        publish_aggregate::<SpanSum>(&span_image, PublicationLimits::default()),
        Err(PublishError::CpuFeatureUnavailable { feature: "sve" })
    ));
    assert!(matches!(
        publish_aggregate::<Count>(&pair_image, PublicationLimits::default()),
        Err(PublishError::CpuFeatureUnavailable { feature: "sve" })
    ));
    assert!(matches!(
        publish_aggregate::<SpanSum>(&pair_span_image, PublicationLimits::default()),
        Err(PublishError::CpuFeatureUnavailable { feature: "sve" })
    ));
}

#[test]
fn aggregate_hardware_covers_bytes_alignments_tails_and_filter_liveness() {
    let _lock = native_test_lock();
    let mut comparisons = 0_u64;
    for literal_len in [1_usize, 2, 3, 15, 16, 17, 31, 32] {
        let literal: Vec<u8> = (0..literal_len)
            .map(|index| {
                u8::try_from(index)
                    .expect("width capped at 32")
                    .wrapping_mul(37)
                    .wrapping_add(if index % 2 == 0 { 0 } else { 0xff })
            })
            .collect();
        let count = build_exact_aggregate::<Count>(&literal, ValidateLimits::default())
            .expect("count program");
        let spans = build_exact_aggregate::<SpanSum>(&literal, ValidateLimits::default())
            .expect("span program");
        let count_image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
        let span_image = emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image");
        let count_kernel = publish_aggregate::<Count>(&count_image, PublicationLimits::default())
            .expect("count kernel");
        let span_kernel = publish_aggregate::<SpanSum>(&span_image, PublicationLimits::default())
            .expect("span kernel");
        for alignment in 0..32 {
            for tail in 0..32 {
                let mut storage = vec![0x5a; alignment];
                storage.extend_from_slice(&literal);
                storage.extend(std::iter::repeat_n(0xa5, tail));
                storage.extend_from_slice(&literal);
                let haystack = &storage[alignment..];
                assert_aggregate_matches(&count, &count_kernel, haystack);
                assert_aggregate_matches(&spans, &span_kernel, haystack);
                comparisons = comparisons.checked_add(2).expect("bounded corpus");
            }
        }
    }

    let literal = b"abcdefghijklmnop";
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("liveness program");
    let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("liveness image");
    let kernel =
        publish_aggregate::<Count>(&image, PublicationLimits::default()).expect("liveness kernel");
    let mut haystack = vec![b'x'; 47];
    haystack[0] = literal[0];
    haystack[15] = literal[15];
    haystack[31..47].copy_from_slice(literal);
    assert_aggregate_matches(&program, &kernel, &haystack);

    let every_byte: Vec<u8> = (0_u8..=u8::MAX).collect();
    for literal in 0_u8..=u8::MAX {
        let program = build_exact_aggregate::<Count>(&[literal], ValidateLimits::default())
            .expect("single-byte program");
        let image =
            emit_exact_aggregate(&program, EmitLimits::default()).expect("single-byte image");
        let kernel = publish_aggregate::<Count>(&image, PublicationLimits::default())
            .expect("single-byte kernel");
        assert_aggregate_matches(&program, &kernel, &every_byte);
    }
    assert_eq!(comparisons, 16_384);
}

#[test]
fn aggregate_guard_pages_cover_empty_short_vector_and_tail_paths() {
    let _lock = native_test_lock();
    for literal in [
        b"".as_slice(),
        b"a",
        b"needle",
        b"0123456789abcdefg",
        &[b'x'; 32],
    ] {
        let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("guard program");
        let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("guard image");
        let kernel =
            publish_aggregate::<Count>(&image, PublicationLimits::default()).expect("guard kernel");
        let mut bytes = b"q".to_vec();
        bytes.extend_from_slice(literal);
        bytes.push(b'z');
        for guarded in [bytes.as_slice(), b"tiny".as_slice(), b"".as_slice()] {
            for right in [false, true] {
                platform::with_guarded_haystack(guarded, right, |haystack| {
                    assert_aggregate_matches(&program, &kernel, haystack);
                })
                .expect("guarded aggregate haystack");
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one test keeps every aggregate call ceiling and exact/one-below result together"
)]
fn aggregate_call_preflight_accepts_exact_and_refuses_each_positive_one_below() {
    let _lock = native_test_lock();
    let program =
        build_exact_aggregate::<Count>(b"aa", ValidateLimits::default()).expect("count program");
    let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("count image");
    let kernel =
        publish_aggregate::<Count>(&image, PublicationLimits::default()).expect("count kernel");
    let haystack = b"aaaaaaaaaaaaaaaa";
    let upper = program
        .upper_bounds(haystack.len())
        .expect("checked bounds");
    let exact = AggregateExecutionLimits {
        max_haystack_bytes: upper.haystack_bytes,
        max_literal_bytes: upper.literal_bytes,
        max_candidate_positions: upper.candidate_positions,
        max_work: upper.work,
        max_match_events: upper.match_events,
        max_output: upper.count,
        max_reducer_steps: upper.reducer_steps,
        max_scratch_bytes: upper.scratch_bytes,
        max_native_invocations: upper.native_invocations,
    };
    assert_eq!(kernel.aggregate(haystack, exact), Ok(8));
    for (limits, expected) in [
        (
            AggregateExecutionLimits {
                max_haystack_bytes: upper.haystack_bytes - 1,
                ..exact
            },
            "haystack",
        ),
        (
            AggregateExecutionLimits {
                max_literal_bytes: upper.literal_bytes - 1,
                ..exact
            },
            "literal",
        ),
        (
            AggregateExecutionLimits {
                max_candidate_positions: upper.candidate_positions - 1,
                ..exact
            },
            "candidates",
        ),
        (
            AggregateExecutionLimits {
                max_work: upper.work - 1,
                ..exact
            },
            "work",
        ),
        (
            AggregateExecutionLimits {
                max_match_events: upper.match_events - 1,
                ..exact
            },
            "events",
        ),
        (
            AggregateExecutionLimits {
                max_output: upper.count - 1,
                ..exact
            },
            "output",
        ),
        (
            AggregateExecutionLimits {
                max_reducer_steps: upper.reducer_steps - 1,
                ..exact
            },
            "steps",
        ),
        (
            AggregateExecutionLimits {
                max_native_invocations: upper.native_invocations - 1,
                ..exact
            },
            "invocations",
        ),
    ] {
        let error = kernel
            .aggregate(haystack, limits)
            .expect_err("one-below call refuses before native entry");
        assert!(
            matches!(
                (&error, expected),
                (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::HaystackBytesLimit { .. }
                    ),
                    "haystack"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::LiteralBytesLimit { .. }
                    ),
                    "literal"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::CandidatePositionsLimit { .. }
                    ),
                    "candidates"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::WorkLimit { .. }
                    ),
                    "work"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::MatchEventsLimit { .. }
                    ),
                    "events"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::OutputLimit { .. }
                    ),
                    "output"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::ReducerStepsLimit { .. }
                    ),
                    "steps"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::NativeInvocationsLimit { .. }
                    ),
                    "invocations"
                )
            ),
            "wrong {expected} failure: {error:?}"
        );
    }

    let empty = build_exact_aggregate::<SpanSum>(b"", ValidateLimits::default())
        .expect("empty span program");
    let empty_image = emit_exact_aggregate(&empty, EmitLimits::default()).expect("empty image");
    let empty_kernel = publish_aggregate::<SpanSum>(&empty_image, PublicationLimits::default())
        .expect("empty kernel");
    let upper = empty.upper_bounds(0).expect("empty bounds");
    assert_eq!(
        empty_kernel.aggregate(
            b"",
            AggregateExecutionLimits {
                max_haystack_bytes: 0,
                max_literal_bytes: 0,
                max_candidate_positions: 0,
                max_work: upper.work,
                max_match_events: upper.match_events,
                max_output: 0,
                max_reducer_steps: upper.reducer_steps,
                max_scratch_bytes: 0,
                max_native_invocations: 1,
            }
        ),
        Ok(0)
    );
}

#[test]
fn search_result_decoding_ignores_fault_slots_and_validates_success_spans() {
    let window = SearchWindow::new(2, 8);
    for status in [2_u64, 0x55, u64::MAX] {
        for poisoned in [
            NativeResult { start: 0, end: 0 },
            NativeResult {
                start: usize::MAX,
                end: usize::MAX,
            },
        ] {
            assert_eq!(
                decode_operation::<Span>(
                    RawCallResult {
                        status,
                        slot: poisoned,
                    },
                    window,
                ),
                Err(CallError::BackendFault { status })
            );
            assert_eq!(
                decode_operation::<SelectedEnd>(
                    RawCallResult {
                        status,
                        slot: poisoned,
                    },
                    window,
                ),
                Err(CallError::BackendFault { status })
            );
            assert_eq!(
                decode_operation::<Exists>(
                    RawCallResult {
                        status,
                        slot: poisoned,
                    },
                    window,
                ),
                Err(CallError::BackendFault { status })
            );
        }
    }
    assert!(matches!(
        decode_operation::<Span>(
            RawCallResult {
                status: 1,
                slot: NativeResult { start: 1, end: 9 },
            },
            window,
        ),
        Err(CallError::InvalidNativeOutput {
            output: fre_kernel_ir::OutputKind::Span,
            window_start: 2,
            window_end: 8,
            ..
        })
    ));
}

#[test]
fn aggregate_result_decoding_ignores_fault_slots_and_validates_success_values() {
    for poisoned in [0_u64, u64::MAX] {
        assert_eq!(
            decode_aggregate::<Count>(
                RawAggregateCallResult {
                    status: 1,
                    slot: NativeAggregateResult { value: poisoned },
                },
                8,
                1,
            ),
            Err(CallError::AggregateArithmeticOverflow)
        );
    }
    assert_eq!(
        decode_aggregate::<Count>(
            RawAggregateCallResult {
                status: 2,
                slot: NativeAggregateResult { value: 0 },
            },
            8,
            1,
        ),
        Err(CallError::AggregateBackendFault { status: 2 })
    );
    assert!(matches!(
        decode_aggregate::<Count>(
            RawAggregateCallResult {
                status: 0,
                slot: NativeAggregateResult { value: u64::MAX },
            },
            8,
            1,
        ),
        Err(CallError::InvalidNativeAggregateOutput {
            output: AggregateOutput::Count,
            ..
        })
    ));
    for (value, literal_len) in [(1_u64, 0_usize), (3, 2), (10, 2)] {
        assert!(matches!(
            decode_aggregate::<SpanSum>(
                RawAggregateCallResult {
                    status: 0,
                    slot: NativeAggregateResult { value },
                },
                8,
                literal_len,
            ),
            Err(CallError::InvalidNativeAggregateOutput {
                output: AggregateOutput::SpanSum,
                ..
            })
        ));
    }
}

#[test]
fn aggregate_publication_is_operation_typed_and_all_failures_roll_back() {
    let _lock = native_test_lock();
    let count = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("count program");
    let image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
    assert!(matches!(
        publish_aggregate::<SpanSum>(&image, PublicationLimits::default()),
        Err(PublishError::AggregateOutputContractMismatch {
            expected: AggregateOutput::SpanSum,
            actual: AggregateOutput::Count,
        })
    ));
    assert_eq!(platform::live_code_mappings(), 0);
    for stage in [
        FailureStage::Reserve,
        FailureStage::MakeWritable,
        FailureStage::Copy,
        FailureStage::Verify,
        FailureStage::Reaudit,
        FailureStage::MakeExecutable,
        FailureStage::InvalidateInstructionCache,
        FailureStage::Publish,
    ] {
        assert_eq!(
            publish_aggregate_impl::<Count>(
                &image,
                PublicationLimits::default(),
                FailureInjection::At(stage),
            )
            .expect_err("injected aggregate publication failure"),
            PublishError::InjectedFailure { stage }
        );
        assert_eq!(platform::live_code_mappings(), 0, "leak at {stage:?}");
    }
    assert_eq!(
        publish_aggregate_impl::<Count>(
            &image,
            PublicationLimits::default(),
            FailureInjection::CorruptCopy,
        )
        .expect_err("corrupt aggregate copy rejected"),
        PublishError::CopyVerificationFailed
    );
    assert_eq!(platform::live_code_mappings(), 0);
}

#[test]
fn exact_literal_hardware_matches_oracle_for_all_outputs() {
    let _lock = native_test_lock();
    let comparisons = exact_comparisons::<Exists>()
        .checked_add(exact_comparisons::<SelectedEnd>())
        .and_then(|count| count.checked_add(exact_comparisons::<Span>()))
        .expect("bounded exact comparison count");
    assert!(comparisons > 100_000);
    eprintln!("exact literal actual-hardware comparisons: {comparisons}");
}

#[test]
fn class_suffix_hardware_matches_oracle_for_all_outputs() {
    let _lock = native_test_lock();
    let comparisons = class_suffix_comparisons::<Exists>()
        .checked_add(class_suffix_comparisons::<SelectedEnd>())
        .and_then(|count| count.checked_add(class_suffix_comparisons::<Span>()))
        .expect("bounded class comparison count");
    assert!(comparisons > 100_000);
    eprintln!("class+suffix actual-hardware comparisons: {comparisons}");
}

#[test]
fn vector_candidate_tails_and_haystack_alignments_match_oracle() {
    let _lock = native_test_lock();
    let mut comparisons = 0_u64;
    for literal in [
        b"a".as_slice(),
        b"needle",
        b"Sherlock Holmes",
        b"0123456789abcdef",
        b"0123456789abcdefg",
    ] {
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("vector exact program");
        let image = emit(&program, EmitLimits::default()).expect("vector exact image");
        assert!(image.stats().vector_instructions >= 4);
        let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
        for alignment in 0..32 {
            for tail in 0..32 {
                let mut storage = vec![0x55; alignment];
                storage.extend_from_slice(b"prefix-");
                storage.extend_from_slice(literal);
                storage.extend(std::iter::repeat_n(b'x', tail));
                let haystack = &storage[alignment..];
                let window = SearchWindow::new(0, haystack.len());
                assert_native_matches(&program, &kernel, haystack, window);
                comparisons = comparisons.checked_add(1).expect("bounded test count");
            }
        }
    }
    assert_eq!(comparisons, 5_120);
}

#[test]
fn v8_adaptive_secondary_screen_rechecks_primary_before_fallback() {
    const WIDE_CANDIDATES: usize = 64;
    const PRIMARY_OFFSET: usize = 7;
    const SECONDARY_OFFSET: usize = 6;
    const TRUE_MATCH: usize = 320;

    let _lock = native_test_lock();
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("adaptive V8 program");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )
    .expect("adaptive V8 image");
    let filter_offsets = decode(image.code())
        .expect("adaptive V8 image decodes")
        .into_iter()
        .filter_map(|instruction| match instruction {
            DecodedInstruction::LoadByte {
                destination: 11,
                base: 8,
                offset,
            } => Some(usize::from(offset)),
            _ => None,
        })
        .take(2)
        .collect::<Vec<_>>();
    assert_eq!(filter_offsets, [PRIMARY_OFFSET, SECONDARY_OFFSET]);
    let kernel =
        publish::<Span>(&image, PublicationLimits::default()).expect("adaptive V8 publication");

    for match_start in [None, Some(TRUE_MATCH)] {
        let mut haystack = vec![b'x'; 512];
        haystack[PRIMARY_OFFSET] = literal[PRIMARY_OFFSET];
        haystack[WIDE_CANDIDATES + SECONDARY_OFFSET..].fill(literal[SECONDARY_OFFSET]);
        if let Some(start) = match_start {
            let end = start
                .checked_add(literal.len())
                .expect("bounded true match");
            haystack[start..end].copy_from_slice(literal);
        }

        let first_group_primary_hits = (0..WIDE_CANDIDATES)
            .filter(|&candidate| haystack[candidate + PRIMARY_OFFSET] == literal[PRIMARY_OFFSET])
            .count();
        assert_eq!(first_group_primary_hits, 1);
        assert!((0..WIDE_CANDIDATES).all(|candidate| {
            haystack[candidate + PRIMARY_OFFSET] != literal[PRIMARY_OFFSET]
                || haystack[candidate + SECONDARY_OFFSET] != literal[SECONDARY_OFFSET]
        }));
        let maximum_start = haystack
            .len()
            .checked_sub(literal.len())
            .expect("literal fits adaptive haystack");
        let first_secondary_group_end = WIDE_CANDIDATES
            .checked_mul(2)
            .expect("bounded first secondary group");
        assert!(
            (WIDE_CANDIDATES..first_secondary_group_end).all(|candidate| {
                haystack[candidate + SECONDARY_OFFSET] == literal[SECONDARY_OFFSET]
                    && haystack[candidate + PRIMARY_OFFSET] != literal[PRIMARY_OFFSET]
            })
        );
        if let Some(start) = match_start {
            assert!((first_secondary_group_end..start).all(|candidate| {
                haystack[candidate + PRIMARY_OFFSET] != literal[PRIMARY_OFFSET]
            }));
            assert_eq!(
                &haystack[start..start + literal.len()],
                literal,
                "the first later pair must be the declared true match"
            );
        } else {
            assert!(
                (first_secondary_group_end..=maximum_start).all(|candidate| {
                    haystack[candidate + PRIMARY_OFFSET] != literal[PRIMARY_OFFSET]
                })
            );
        }

        let window = SearchWindow::new(0, haystack.len());
        let actual = kernel
            .search(&haystack, window)
            .expect("adaptive V8 execution")
            .map(|span| (span.start(), span.end()));
        let expected = match_start.map(|start| (start, start + literal.len()));
        assert_eq!(actual, expected);
        assert_native_matches(&program, &kernel, &haystack, window);
    }
}

#[test]
fn rare_pair_vector_candidates_respect_guard_pages_and_leftmost_windows() {
    const WINDOW_START: usize = 3;
    const CANDIDATE_STARTS: usize = 16;
    const FIRST_LANE: usize = 0;
    const LAST_LANE: usize = CANDIDATE_STARTS - 1;

    let _lock = native_test_lock();
    // The emitter's pinned packed-pair selector chooses these offsets. Keeping
    // both address orders here exercises the add and subtract forms used to
    // reach the secondary vector column.
    for (literal, primary_offset, secondary_offset) in [
        (b"7a".as_slice(), 0_usize, 1_usize),
        (b"a7".as_slice(), 1_usize, 0_usize),
    ] {
        assert_ne!(primary_offset, secondary_offset);
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("rare-pair exact program");
        let image = emit(&program, EmitLimits::default()).expect("rare-pair exact image");
        assert!(image.stats().vector_instructions >= 4);
        let kernel =
            publish::<Span>(&image, PublicationLimits::default()).expect("rare-pair publication");
        let window_len = CANDIDATE_STARTS
            .checked_add(literal.len())
            .and_then(|length| length.checked_sub(1))
            .expect("bounded window length");

        for (scenario, match_lanes, primary_only_lanes, expected_lane) in [
            (
                "absent-primary-lanes-0-and-15",
                [].as_slice(),
                [FIRST_LANE, LAST_LANE].as_slice(),
                None,
            ),
            (
                "lane-0",
                [FIRST_LANE].as_slice(),
                [].as_slice(),
                Some(FIRST_LANE),
            ),
            (
                "lane-15",
                [LAST_LANE].as_slice(),
                [].as_slice(),
                Some(LAST_LANE),
            ),
            (
                "lane-0-and-15",
                [FIRST_LANE, LAST_LANE].as_slice(),
                [].as_slice(),
                Some(FIRST_LANE),
            ),
        ] {
            let haystack_len = WINDOW_START
                .checked_add(window_len)
                .expect("bounded haystack length");
            let mut bytes = vec![b'x'; haystack_len];
            // A valid match before the nonzero window must never be selected.
            bytes[..literal.len()].copy_from_slice(literal);
            // Primary-only hits force the secondary vector load but must not
            // turn into exact matches.
            for &lane in primary_only_lanes {
                let start = WINDOW_START.checked_add(lane).expect("bounded lane");
                let selected = start
                    .checked_add(primary_offset)
                    .expect("bounded selected offset");
                bytes[selected] = literal[primary_offset];
            }
            for &lane in match_lanes {
                let start = WINDOW_START.checked_add(lane).expect("bounded lane");
                let end = start.checked_add(literal.len()).expect("bounded literal");
                bytes[start..end].copy_from_slice(literal);
            }
            let window = SearchWindow::new(WINDOW_START, bytes.len());
            let candidate_starts = window
                .end()
                .checked_sub(window.start())
                .and_then(|length| length.checked_sub(literal.len()))
                .and_then(|last_start| last_start.checked_add(1))
                .expect("literal fits in the window");
            assert_eq!(candidate_starts, CANDIDATE_STARTS);

            for right_boundary in [false, true] {
                platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
                    let actual = kernel
                        .search(haystack, window)
                        .expect("guarded native execution")
                        .map(|span| (span.start(), span.end()));
                    let expected = expected_lane.map(|lane| {
                        let start = WINDOW_START.checked_add(lane).expect("bounded lane");
                        let end = start.checked_add(literal.len()).expect("bounded literal");
                        (start, end)
                    });
                    assert_eq!(
                        actual, expected,
                        "literal={literal:?} offsets={primary_offset},{secondary_offset} \
                         scenario={scenario} right_boundary={right_boundary}"
                    );
                    assert_native_matches(&program, &kernel, haystack, window);
                })
                .expect("guarded rare-pair haystack");
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the native v7 lane matrix keeps both offset directions, every lane, all groups, and false-before-true recovery together"
)]
fn v7_sparse_recovery_covers_every_lane_group_and_pair_direction() {
    const WINDOW_START: usize = 5;
    const LANES: usize = 16;
    const GROUPS: usize = 3;
    const CANDIDATE_STARTS: usize = LANES * GROUPS;

    let _lock = native_test_lock();
    // The packed-pair policy selects 0->1 for the first literal and 1->0 for
    // the second. The next two ranked columns are staged only if the prior
    // mask still has multiple survivors.
    // The trailing space remains outside the four selected columns, so a
    // staged-mask hit can still fail whole-literal confirmation.
    for (literal, primary_offset, secondary_offset) in [
        (b"7a e ".as_slice(), 0_usize, 1_usize),
        (b"a7 e ".as_slice(), 1_usize, 0_usize),
    ] {
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("ranked exact program");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV7,
            EmitLimits::default(),
        )
        .expect("ranked exact image");
        assert_eq!(image.backend_version(), BackendVersion::SEARCH_V7);
        let instructions = decode(image.code()).expect("v7 native image decode");
        let filter_offsets: Vec<usize> = instructions
            .iter()
            .filter_map(|instruction| match instruction {
                DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset,
                } => Some(usize::from(*offset)),
                _ => None,
            })
            .take(4)
            .collect();
        assert_eq!(filter_offsets.len(), 4);
        assert_eq!(filter_offsets[..2], [primary_offset, secondary_offset]);
        let verification_offset = filter_offsets[2];
        let quaternary_offset = filter_offsets[3];
        assert!(instructions.iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                    destination: 2,
                    source: 0
                }
            )
        }));
        assert!(instructions.iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::ReverseBits64 {
                    destination: 10,
                    source: 0
                }
            )
        }));
        assert!(instructions.iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CountLeadingZeros64 {
                    destination: 10,
                    source: 10
                }
            )
        }));
        let kernel =
            publish::<Span>(&image, PublicationLimits::default()).expect("ranked publication");
        let window_len = CANDIDATE_STARTS
            .checked_add(literal.len())
            .and_then(|length| length.checked_sub(1))
            .expect("bounded window length");
        let haystack_len = WINDOW_START
            .checked_add(window_len)
            .expect("bounded haystack length");

        for group in 0..GROUPS {
            for lane in 0..LANES {
                let candidate = group
                    .checked_mul(LANES)
                    .and_then(|start| start.checked_add(lane))
                    .expect("bounded candidate lane");
                let start = WINDOW_START
                    .checked_add(candidate)
                    .expect("bounded match start");
                let end = start.checked_add(literal.len()).expect("bounded literal");
                let mut bytes = vec![b'x'; haystack_len];
                bytes[start..end].copy_from_slice(literal);
                let window = SearchWindow::new(WINDOW_START, bytes.len());
                for right_boundary in [false, true] {
                    platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
                        let actual = kernel
                            .search(haystack, window)
                            .expect("native lane execution")
                            .map(|span| (span.start(), span.end()));
                        assert_eq!(
                            actual,
                            Some((start, end)),
                            "literal={literal:?} group={group} lane={lane} \
                             right_boundary={right_boundary}"
                        );
                        assert_native_matches(&program, &kernel, haystack, window);
                    })
                    .expect("guarded ranked lane haystack");
                }
            }
        }

        for lane in 0..LANES {
            let mut bytes = vec![b'x'; haystack_len];
            let false_start = WINDOW_START.checked_add(lane).expect("bounded false start");
            for offset in [
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
            ] {
                bytes[false_start + offset] = literal[offset];
            }
            let true_start = WINDOW_START
                .checked_add(2 * LANES)
                .and_then(|start| start.checked_add(lane))
                .expect("bounded later true start");
            let true_end = true_start
                .checked_add(literal.len())
                .expect("bounded later literal");
            bytes[true_start..true_end].copy_from_slice(literal);
            let window = SearchWindow::new(WINDOW_START, bytes.len());
            for right_boundary in [false, true] {
                platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
                    let actual = kernel
                        .search(haystack, window)
                        .expect("native false-then-true execution")
                        .map(|span| (span.start(), span.end()));
                    assert_eq!(
                        actual,
                        Some((true_start, true_end)),
                        "literal={literal:?} lane={lane} right_boundary={right_boundary}"
                    );
                    assert_native_matches(&program, &kernel, haystack, window);
                })
                .expect("guarded false-then-true haystack");
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the native multi-survivor matrix keeps every same-mask, next-block, tail, direction, width, and guard case explicit"
)]
fn v7_multi_survivor_masks_preserve_leftmost_across_blocks_and_tail() {
    const WINDOW_START: usize = 5;

    let _lock = native_test_lock();
    for width in [16_usize, 17, 32] {
        // Lower frequency rank wins. Four leading `a` columns therefore beat
        // the `e` at offset four and are selected in increasing order. An
        // all-`a` block consequently has sixteen simultaneous filter hits,
        // while every complete confirmation fails at offset four.
        let mut add_literal = vec![b'a'; width];
        add_literal[4] = b'e';
        let add_program = build_exact_literal::<Span>(
            &add_literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("add-direction exact program");
        let add_image = emit_with_backend(
            &add_program,
            SearchBackendPolicy::AsimdV7,
            EmitLimits::default(),
        )
        .expect("add-direction image");
        let add_offsets = initial_v7_filter_offsets(&add_image);
        assert_eq!(add_offsets, [0, 1, 2, 3]);
        let add_kernel =
            publish::<Span>(&add_image, PublicationLimits::default()).expect("add kernel");

        for true_lane in 1..16 {
            let mut bytes = candidate_haystack(width, 32, b'a');
            install_literal(&mut bytes, WINDOW_START + true_lane, &add_literal);
            assert_guarded_v7_case(
                &add_program,
                &add_kernel,
                &bytes,
                Some(WINDOW_START + true_lane),
                "lane-0-false-then-same-mask-true",
            );
        }

        let mut several_false = candidate_haystack(width, 32, b'a');
        install_literal(&mut several_false, WINDOW_START + 9, &add_literal);
        assert_guarded_v7_case(
            &add_program,
            &add_kernel,
            &several_false,
            Some(WINDOW_START + 9),
            "several-earlier-false-bits",
        );

        let mut all_sixteen_then_next = candidate_haystack(width, 32, b'a');
        install_literal(&mut all_sixteen_then_next, WINDOW_START + 16, &add_literal);
        assert_guarded_v7_case(
            &add_program,
            &add_kernel,
            &all_sixteen_then_next,
            Some(WINDOW_START + 16),
            "all-sixteen-false-then-next-block-lane-zero",
        );

        let mut lane_fifteen_then_next = candidate_haystack(width, 32, b'x');
        install_filter_hit(
            &mut lane_fifteen_then_next,
            WINDOW_START + 15,
            &add_literal,
            add_offsets,
        );
        install_literal(&mut lane_fifteen_then_next, WINDOW_START + 16, &add_literal);
        assert_guarded_v7_case(
            &add_program,
            &add_kernel,
            &lane_fifteen_then_next,
            Some(WINDOW_START + 16),
            "lane-fifteen-false-then-next-block-lane-zero",
        );

        let all_false_tail = candidate_haystack(width, 21, b'a');
        assert_guarded_v7_case(
            &add_program,
            &add_kernel,
            &all_false_tail,
            None,
            "all-sixteen-false-then-tail-none",
        );

        // These four control bytes have strict ranks 28, 29, 30, and 31.
        // Their offsets force every staged column pointer to subtract from the
        // primary offset, while lane spacings 5/10/15 avoid write conflicts.
        let mut subtract_literal = vec![b'e'; width];
        subtract_literal[8] = 0x1f;
        subtract_literal[4] = 0x1e;
        subtract_literal[2] = 0x1d;
        subtract_literal[1] = 0x1c;
        let subtract_program = build_exact_literal::<Span>(
            &subtract_literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("subtract-direction exact program");
        let subtract_image = emit_with_backend(
            &subtract_program,
            SearchBackendPolicy::AsimdV7,
            EmitLimits::default(),
        )
        .expect("subtract-direction image");
        let subtract_offsets = initial_v7_filter_offsets(&subtract_image);
        assert_eq!(subtract_offsets, [8, 4, 2, 1]);
        let subtract_kernel = publish::<Span>(&subtract_image, PublicationLimits::default())
            .expect("subtract kernel");
        let mut subtract_bytes = candidate_haystack(width, 32, b'x');
        for lane in [0_usize, 5, 10, 15] {
            install_filter_hit(
                &mut subtract_bytes,
                WINDOW_START + lane,
                &subtract_literal,
                subtract_offsets,
            );
        }
        install_literal(&mut subtract_bytes, WINDOW_START + 31, &subtract_literal);
        assert_guarded_v7_case(
            &subtract_program,
            &subtract_kernel,
            &subtract_bytes,
            Some(WINDOW_START + 31),
            "ranked-subtract-multi-survivor-mask",
        );
    }
}

fn initial_v7_filter_offsets(image: &fre_jit_aarch64::NativeImage) -> [usize; 4] {
    let offsets: Vec<usize> = decode(image.code())
        .expect("v7 filter image decode")
        .iter()
        .filter_map(|instruction| match instruction {
            DecodedInstruction::LoadByte {
                destination: 11,
                base: 8,
                offset,
            } => Some(usize::from(*offset)),
            _ => None,
        })
        .take(4)
        .collect();
    offsets.try_into().expect("v7 has four ranked filter loads")
}

fn candidate_haystack(width: usize, candidate_starts: usize, fill: u8) -> Vec<u8> {
    let length = WINDOW_START_FOR_V7_TESTS
        .checked_add(candidate_starts)
        .and_then(|value| value.checked_add(width))
        .and_then(|value| value.checked_sub(1))
        .expect("bounded v7 multi-survivor haystack");
    vec![fill; length]
}

const WINDOW_START_FOR_V7_TESTS: usize = 5;

fn install_filter_hit(haystack: &mut [u8], start: usize, literal: &[u8], offsets: [usize; 4]) {
    for offset in offsets {
        let position = start.checked_add(offset).expect("bounded filter position");
        haystack[position] = literal[offset];
    }
}

fn install_literal(haystack: &mut [u8], start: usize, literal: &[u8]) {
    let end = start
        .checked_add(literal.len())
        .expect("bounded literal position");
    haystack[start..end].copy_from_slice(literal);
}

fn assert_guarded_v7_case(
    program: &fre_kernel_ir::ValidatedProgram<Span>,
    kernel: &crate::PublishedKernel<Span>,
    bytes: &[u8],
    expected_start: Option<usize>,
    scenario: &str,
) {
    let window = SearchWindow::new(WINDOW_START_FOR_V7_TESTS, bytes.len());
    for right_boundary in [false, true] {
        platform::with_guarded_haystack(bytes, right_boundary, |haystack| {
            let actual = kernel
                .search(haystack, window)
                .expect("guarded v7 multi-survivor execution");
            let actual = actual.map(fre_kernel_ir::MatchSpan::start);
            assert_eq!(
                actual, expected_start,
                "scenario={scenario} right_boundary={right_boundary}"
            );
            assert_native_matches(program, kernel, haystack, window);
        })
        .expect("guarded v7 multi-survivor haystack");
    }
}

#[test]
fn v7_overlapping_candidates_preserve_leftmost_and_window_nonoverlap() {
    const WINDOW_START: usize = 5;
    const CANDIDATE_STARTS: usize = 32;
    const LITERAL: &[u8] = b"aba";

    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(LITERAL, AnchorFlags::default(), ValidateLimits::default())
            .expect("overlapping exact program");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV7,
        EmitLimits::default(),
    )
    .expect("overlapping v7 image");
    assert_eq!(image.backend_version(), BackendVersion::SEARCH_V7);
    let kernel =
        publish::<Span>(&image, PublicationLimits::default()).expect("overlapping publication");
    let haystack_len = WINDOW_START
        .checked_add(CANDIDATE_STARTS)
        .and_then(|length| length.checked_add(LITERAL.len() - 1))
        .expect("bounded overlapping haystack");
    let mut bytes = vec![b'x'; haystack_len];
    bytes[WINDOW_START..WINDOW_START + 5].copy_from_slice(b"ababa");

    for right_boundary in [false, true] {
        platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
            let whole = SearchWindow::new(WINDOW_START, haystack.len());
            let first = kernel
                .search(haystack, whole)
                .expect("first overlapping native search")
                .map(|span| (span.start(), span.end()));
            assert_eq!(first, Some((WINDOW_START, WINDOW_START + LITERAL.len())));
            assert_native_matches(&program, &kernel, haystack, whole);

            let after_first_start = WINDOW_START + 1;
            let after_first = SearchWindow::new(after_first_start, haystack.len());
            let second = kernel
                .search(haystack, after_first)
                .expect("second overlapping native search")
                .map(|span| (span.start(), span.end()));
            assert_eq!(
                second,
                Some((WINDOW_START + 2, WINDOW_START + 2 + LITERAL.len()))
            );
            assert_native_matches(&program, &kernel, haystack, after_first);
        })
        .expect("guarded overlapping v7 haystack");
    }
}

#[test]
fn fixed_16_false_pair_confirmation_resumes_before_a_guarded_distant_match() {
    const WINDOW_START: usize = 5;
    const CANDIDATE_STARTS: usize = 48;
    const DISTANT_LANE: usize = 32;
    const LITERAL: &[u8; 16] = b"0123456789abcdef";

    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(LITERAL, AnchorFlags::default(), ValidateLimits::default())
            .expect("fixed-16 exact program");
    let image = emit(&program, EmitLimits::default()).expect("fixed-16 exact image");
    let kernel =
        publish::<Span>(&image, PublicationLimits::default()).expect("fixed-16 publication");
    let window_len = CANDIDATE_STARTS
        .checked_add(LITERAL.len())
        .and_then(|length| length.checked_sub(1))
        .expect("bounded window length");

    for present in [false, true] {
        let haystack_len = WINDOW_START
            .checked_add(window_len)
            .expect("bounded guarded haystack length");
        let mut bytes = vec![b'x'; haystack_len];
        // The canonical pair for this literal is at offsets 7 and 6. This
        // candidate passes both vector columns but fails fixed-width
        // confirmation at offset 8. In particular, confirmation must reset
        // X15 from the primary-column pointer before its 16-byte load.
        let false_start = WINDOW_START;
        let false_end = false_start
            .checked_add(LITERAL.len())
            .expect("bounded false candidate");
        bytes[false_start..false_end].copy_from_slice(LITERAL);
        bytes[false_start + 8] = b'X';
        if present {
            let match_start = WINDOW_START
                .checked_add(DISTANT_LANE)
                .expect("bounded distant match");
            let match_end = match_start
                .checked_add(LITERAL.len())
                .expect("bounded distant literal");
            bytes[match_start..match_end].copy_from_slice(LITERAL);
        }
        let window = SearchWindow::new(WINDOW_START, bytes.len());

        for right_boundary in [false, true] {
            platform::with_guarded_haystack(&bytes, right_boundary, |haystack| {
                let actual = kernel
                    .search(haystack, window)
                    .expect("guarded native execution")
                    .map(|span| (span.start(), span.end()));
                let expected = present.then_some((
                    WINDOW_START + DISTANT_LANE,
                    WINDOW_START + DISTANT_LANE + LITERAL.len(),
                ));
                assert_eq!(
                    actual, expected,
                    "present={present} right_boundary={right_boundary}"
                );
                assert_native_matches(&program, &kernel, haystack, window);
            })
            .expect("guarded fixed-16 false-pair haystack");
        }
    }
}

#[test]
fn suffix_first_tails_and_haystack_alignments_match_oracle() {
    let _lock = native_test_lock();
    let suffix = b"bcdefghijklmnopq";
    let program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("suffix-first program");
    let image = emit(&program, EmitLimits::default()).expect("suffix-first image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let mut comparisons = 0_u64;
    for alignment in 0..32 {
        for tail in 0..32 {
            let mut storage = vec![0x55; alignment];
            storage.extend_from_slice(b"prefix-");
            storage.extend_from_slice(b"aaaa");
            storage.extend_from_slice(suffix);
            storage.extend(std::iter::repeat_n(b'x', tail));
            let haystack = &storage[alignment..];
            let window = SearchWindow::new(0, haystack.len());
            assert_native_matches(&program, &kernel, haystack, window);
            comparisons = comparisons.checked_add(1).expect("bounded test count");
        }
    }
    assert_eq!(comparisons, 1_024);
}

#[test]
fn inaccessible_haystack_boundaries_are_respected() {
    let _lock = native_test_lock();
    for literal in [
        b"a".as_slice(),
        b"needle",
        b"Sherlock Holmes",
        b"0123456789abcdefg",
    ] {
        let exact =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("vector exact program");
        let exact_image = emit(&exact, EmitLimits::default()).expect("exact image");
        assert!(exact_image.stats().vector_instructions >= 4);
        let exact_kernel =
            publish::<Span>(&exact_image, PublicationLimits::default()).expect("exact");
        let mut bytes = b"xx".to_vec();
        bytes.extend_from_slice(literal);
        for right in [false, true] {
            platform::with_guarded_haystack(&bytes, right, |haystack| {
                let window = SearchWindow::new(0, haystack.len());
                assert_native_matches(&exact, &exact_kernel, haystack, window);
            })
            .expect("guarded exact haystack");
        }
    }

    // The canonical primary byte for this literal is at offset 7. A first-byte
    // hit at the final candidate therefore proves that scalar confirmation
    // resets its primary-column pointer before the 16-byte load at a right
    // guard boundary.
    let boundary_literal = b"0123456789abcdef";
    let boundary_program = build_exact_literal::<Span>(
        boundary_literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("fixed-width boundary program");
    let boundary_image =
        emit(&boundary_program, EmitLimits::default()).expect("fixed-width boundary image");
    let boundary_kernel =
        publish::<Span>(&boundary_image, PublicationLimits::default()).expect("boundary kernel");
    let mut final_candidate = vec![b'x'; 15];
    final_candidate.extend_from_slice(boundary_literal);
    platform::with_guarded_haystack(&final_candidate, true, |haystack| {
        let actual = boundary_kernel
            .search(haystack, SearchWindow::new(0, haystack.len()))
            .expect("final-candidate native execution")
            .map(|span| (span.start(), span.end()));
        assert_eq!(actual, Some((15, 31)));
        assert_native_matches(
            &boundary_program,
            &boundary_kernel,
            haystack,
            SearchWindow::new(0, haystack.len()),
        );
    })
    .expect("right-guard fixed-width final candidate");

    let empty = build_exact_literal::<Span>(b"", AnchorFlags::default(), ValidateLimits::default())
        .expect("empty exact program");
    let empty_image = emit(&empty, EmitLimits::default()).expect("empty image");
    let empty_kernel = publish::<Span>(&empty_image, PublicationLimits::default()).expect("empty");
    for right in [false, true] {
        platform::with_guarded_haystack(b"", right, |haystack| {
            let window = SearchWindow::new(0, 0);
            assert_native_matches(&empty, &empty_kernel, haystack, window);
        })
        .expect("guarded empty haystack");
    }

    let suffix = b"bcdefghijklmnopq";
    for class in [ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"ac")] {
        let class_program = build_class_suffix::<Span>(
            class,
            suffix,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("class suffix program");
        let class_image = emit(&class_program, EmitLimits::default()).expect("class suffix image");
        let class_kernel =
            publish::<Span>(&class_image, PublicationLimits::default()).expect("class suffix");
        for right in [false, true] {
            platform::with_guarded_haystack(b"aaabcdefghijklmnopq", right, |haystack| {
                let window = SearchWindow::new(0, haystack.len());
                assert_native_matches(&class_program, &class_kernel, haystack, window);
            })
            .expect("guarded class haystack");
        }
    }
}

#[test]
fn mapping_guards_and_rx_permissions_are_observed_by_host() {
    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let protections = kernel
        .mapping
        .protections()
        .expect("mapping protection query");
    assert_eq!(protections.left_guard, libc::PROT_NONE);
    assert_eq!(protections.payload, libc::PROT_READ | libc::PROT_EXEC);
    assert_eq!(protections.payload & libc::PROT_WRITE, 0);
    assert_eq!(protections.right_guard, libc::PROT_NONE);
    assert!(
        kernel
            .mapping
            .post_publication_write_is_blocked()
            .expect("isolated write probe")
    );

    let aggregate = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("aggregate program");
    let aggregate_image =
        emit_exact_aggregate(&aggregate, EmitLimits::default()).expect("aggregate image");
    let aggregate_kernel =
        publish_aggregate::<Count>(&aggregate_image, PublicationLimits::default())
            .expect("aggregate publish");
    let protections = aggregate_kernel
        .mapping
        .protections()
        .expect("aggregate mapping protection query");
    assert_eq!(protections.left_guard, libc::PROT_NONE);
    assert_eq!(protections.payload, libc::PROT_READ | libc::PROT_EXEC);
    assert_eq!(protections.payload & libc::PROT_WRITE, 0);
    assert_eq!(protections.right_guard, libc::PROT_NONE);
}

#[test]
fn every_injected_failure_rolls_back_without_a_callable() {
    let _lock = native_test_lock();
    assert_eq!(platform::live_code_mappings(), 0);
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    for stage in [
        FailureStage::Reserve,
        FailureStage::MakeWritable,
        FailureStage::Copy,
        FailureStage::Verify,
        FailureStage::Reaudit,
        FailureStage::MakeExecutable,
        FailureStage::InvalidateInstructionCache,
        FailureStage::Publish,
    ] {
        let error = publish_impl::<Span>(
            &image,
            PublicationLimits::default(),
            FailureInjection::At(stage),
        )
        .expect_err("injected stage fails");
        assert_eq!(error, PublishError::InjectedFailure { stage });
        assert_eq!(platform::live_code_mappings(), 0, "leak at {stage:?}");
    }
    assert_eq!(
        publish_impl::<Span>(
            &image,
            PublicationLimits::default(),
            FailureInjection::CorruptCopy,
        )
        .expect_err("corrupt copy rejected"),
        PublishError::CopyVerificationFailed
    );
    assert_eq!(platform::live_code_mappings(), 0);

    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("recovery publish");
    assert_eq!(platform::live_code_mappings(), 1);
    drop(kernel);
    assert_eq!(platform::live_code_mappings(), 0);
}

#[test]
fn output_contract_window_and_resource_failures_are_typed() {
    let _lock = native_test_lock();
    let program = build_exact_literal::<Span>(
        b"0123456789abcdefg",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    assert!(matches!(
        publish::<Exists>(&image, PublicationLimits::default()),
        Err(PublishError::OutputContractMismatch { .. })
    ));

    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let accounting = kernel.accounting();
    assert_eq!(
        accounting.guard_bytes,
        accounting
            .page_bytes
            .checked_mul(2)
            .expect("two guard pages")
    );
    assert_eq!(
        accounting.total_mapped_bytes,
        accounting
            .payload_mapped_bytes
            .checked_add(accounting.guard_bytes)
            .expect("bounded mapping")
    );
    assert_eq!(
        kernel.search(b"tiny", SearchWindow::new(2, 6)),
        Err(CallError::InvalidWindow {
            start: 2,
            end: 6,
            haystack_len: 4,
        })
    );
    let session = kernel
        .begin_current_thread_session()
        .expect("V8 establishes a syscall-free thread session");
    assert!(!kernel.requires_current_thread_session());
    assert_eq!(session.kernel().identity(), kernel.identity());
    assert_eq!(
        session.search(b"tiny", SearchWindow::new(2, 6)),
        Err(CallError::InvalidWindow {
            start: 2,
            end: 6,
            haystack_len: 4,
        })
    );
    assert_eq!(
        session
            .search(
                b"zz0123456789abcdefgzz",
                SearchWindow::new(0, b"zz0123456789abcdefgzz".len()),
            )
            .expect("session native search")
            .map(|span| (span.start(), span.end())),
        Some((2, 19))
    );
    let checked_haystack = b"zz0123456789abcdefgzz";
    let checked = CheckedSearchWindow::new(
        checked_haystack,
        SearchWindow::new(0, checked_haystack.len()),
    )
    .expect("valid checked window");
    assert_eq!(
        kernel
            .search_checked(checked)
            .expect("direct prechecked native search")
            .map(|span| (span.start(), span.end())),
        Some((2, 19))
    );
    assert_eq!(
        session
            .search_checked(checked)
            .expect("prechecked session native search")
            .map(|span| (span.start(), span.end())),
        Some((2, 19))
    );
    drop(kernel);

    for (resource, exact) in [
        (ResourceKind::CodeBytes, accounting.code_bytes),
        (ResourceKind::DataBytes, accounting.data_bytes),
        (ResourceKind::PayloadBytes, accounting.payload_mapped_bytes),
        (ResourceKind::MappedBytes, accounting.total_mapped_bytes),
        (ResourceKind::Pages, accounting.total_pages),
    ] {
        let exact_limits = limits_with(resource, exact);
        drop(publish::<Span>(&image, exact_limits).expect("exact boundary"));
        let failing = limits_with(resource, exact.checked_sub(1).expect("nonzero resource"));
        assert!(matches!(
            publish::<Span>(&image, failing),
            Err(PublishError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }
}

#[test]
fn cloned_ownership_prevents_call_unmap_races() {
    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let mut workers = Vec::new();
    for _ in 0..8 {
        let clone = kernel.clone();
        workers.push(std::thread::spawn(move || {
            let haystack = b"zzneedlezz";
            let window = SearchWindow::new(0, haystack.len());
            let checked =
                CheckedSearchWindow::new(haystack, window).expect("worker checked window");
            for _ in 0..2_000 {
                let span = clone
                    .search_checked(checked)
                    .expect("concurrent prechecked call");
                assert_eq!(span.map(|value| (value.start(), value.end())), Some((2, 8)));
            }
        }));
    }
    drop(kernel);
    for worker in workers {
        worker.join().expect("worker does not panic");
    }
    assert_eq!(platform::live_code_mappings(), 0);
}

fn exact_comparisons<O: RuntimeOperation>() -> u64
where
    O::Output: Eq,
{
    let mut haystacks = all_sequences(b"ab", 5);
    haystacks.extend([
        b"xxxxxxxxxxxxxxx0123456789abcdef".to_vec(),
        b"xxxxxxxxxxxxxxxx0123456789abcdefg".to_vec(),
        b"0123456789abcdeg0123456789abcdef".to_vec(),
        vec![b'x'; 65],
    ]);
    let literals = [
        b"".as_slice(),
        b"a",
        b"ab",
        b"0123456789abcdef",
        b"0123456789abcdefg",
        &[b'x'; fre_jit_aarch64::MAX_REPEATED_CONFIRM_BYTES],
    ];
    let mut comparisons = 0_u64;
    for literal in literals {
        for anchors in anchor_options() {
            let program =
                build_exact_literal::<O>(literal, anchors, ValidateLimits::default()).expect("IR");
            let image = emit(&program, EmitLimits::default()).expect("emit");
            let kernel = publish::<O>(&image, PublicationLimits::default()).expect("publish");
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        assert_native_matches(
                            &program,
                            &kernel,
                            haystack,
                            SearchWindow::new(start, end),
                        );
                        comparisons = comparisons.checked_add(1).expect("bounded test count");
                    }
                }
            }
        }
    }
    comparisons
}

fn class_suffix_comparisons<O: RuntimeOperation>() -> u64
where
    O::Output: Eq,
{
    let mut haystacks = all_sequences(b"abc", 5);
    haystacks.extend([
        b"aaaaaaaaaaaaaaaaabcdefghijklmnopq".to_vec(),
        b"ccccccccccccccccabcdefghijklmnopq".to_vec(),
        b"xxaaaaaaaaaaaaaaaaabcdefghijklmnopqyy".to_vec(),
    ]);
    let cases = [
        (ByteClass::from_bytes(b"a"), b"b".as_slice()),
        (ByteClass::from_bytes(b"ac"), b"ba".as_slice()),
        (ByteClass::from_bytes(b"ac"), b"bcdefghijklmnopq".as_slice()),
    ];
    let mut comparisons = 0_u64;
    for (class, suffix) in cases {
        for anchors in anchor_options() {
            let program =
                build_class_suffix::<O>(class, suffix, anchors, ValidateLimits::default())
                    .expect("proved-disjoint IR");
            let image = emit(&program, EmitLimits::default()).expect("emit");
            let kernel = publish::<O>(&image, PublicationLimits::default()).expect("publish");
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        assert_native_matches(
                            &program,
                            &kernel,
                            haystack,
                            SearchWindow::new(start, end),
                        );
                        comparisons = comparisons.checked_add(1).expect("bounded test count");
                    }
                }
            }
        }
    }
    comparisons
}

fn assert_native_matches<O: RuntimeOperation>(
    program: &fre_kernel_ir::ValidatedProgram<O>,
    kernel: &crate::PublishedKernel<O>,
    haystack: &[u8],
    window: SearchWindow,
) where
    O::Output: Eq,
{
    let expected = program
        .execute(haystack, window, ExecutionLimits::unlimited())
        .expect("oracle execution")
        .into_output();
    let actual = kernel.search(haystack, window).expect("native execution");
    assert_eq!(
        actual,
        expected,
        "output={:?} haystack={haystack:?} window={}..{}",
        O::KIND,
        window.start(),
        window.end()
    );
}

fn assert_aggregate_matches<A: RuntimeAggregateOperation>(
    program: &fre_kernel_ir::ExactAggregateProgram<A>,
    kernel: &crate::PublishedAggregateKernel<A>,
    haystack: &[u8],
) {
    let expected = program
        .execute(haystack, AggregateExecutionLimits::unlimited())
        .expect("aggregate oracle")
        .into_output();
    let actual = kernel
        .aggregate(haystack, AggregateExecutionLimits::unlimited())
        .expect("native aggregate");
    assert_eq!(
        actual,
        expected,
        "aggregate={:?} literal={:?} haystack={haystack:?}",
        A::OUTPUT,
        program.literal()
    );
}

fn anchor_options() -> [AnchorFlags; 4] {
    [
        AnchorFlags {
            start: false,
            end: false,
        },
        AnchorFlags {
            start: true,
            end: false,
        },
        AnchorFlags {
            start: false,
            end: true,
        },
        AnchorFlags {
            start: true,
            end: true,
        },
    ]
}

fn all_sequences(alphabet: &[u8], maximum: usize) -> Vec<Vec<u8>> {
    let mut output = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..maximum {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                output.push(value.clone());
                next.push(value);
            }
        }
        frontier = next;
    }
    output
}

fn limits_with(resource: ResourceKind, exact: usize) -> PublicationLimits {
    let exact = u64::try_from(exact).expect("small test resource");
    let mut limits = PublicationLimits::default();
    match resource {
        ResourceKind::CodeBytes => limits.max_code_bytes = exact,
        ResourceKind::DataBytes => limits.max_data_bytes = exact,
        ResourceKind::PayloadBytes => limits.max_payload_bytes = exact,
        ResourceKind::MappedBytes => limits.max_mapped_bytes = exact,
        ResourceKind::Pages => limits.max_pages = exact,
    }
    limits
}
