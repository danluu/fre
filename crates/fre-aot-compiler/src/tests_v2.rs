use fre::RustProfile;
use fre_aot_aarch64::{
    AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2, AOT_COUNT_BACKEND_VERSION_V2,
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, AOT_COUNT_KIR_ABI_VERSION_V2,
    AOT_COUNT_KIR_SEMANTICS_VERSION_V2, CountAotError, CountAotResource, CountEmitLimitsV2,
};
use fre_aot_macho::{
    AbiKind, CALL_ABI_SCHEMA_V2, METADATA_VERSION_V2, ObjectError, ObjectResource, PLATFORM_MACOS,
    STATUS_BITS_V2,
};
use fre_kernel_ir::{
    AggregateBuildError, BuildError, ResourceKind as KernelResource, ValidateError,
};

use crate::{
    AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V2, AOT_COMPILER_VERSION_V2, AOT_COUNT_COMPILER_SUPPORT_V2,
    AOT_MANIFEST_SCHEMA_VERSION_V2, AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2, CompileError,
    CompilePolicyV2, CompileResource, MacosAarch64CountManifestV2, ManifestError, ReceiptMismatch,
    ReceiptValidationError, STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2,
    plan_and_compile_macos_aarch64_count_v2,
};

fn unicode_off_profile() -> RustProfile {
    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    profile
}

fn compile_pattern(
    pattern: &str,
    manifest: &MacosAarch64CountManifestV2,
) -> crate::CompiledObjectV2 {
    plan_and_compile_macos_aarch64_count_v2(
        *manifest,
        pattern.as_bytes().to_vec(),
        unicode_off_profile(),
    )
    .expect("compiler-v2 Count AOT compile")
}

#[test]
fn compiler_v2_deterministically_binds_the_complete_exact_tuple_and_all_identities() {
    let manifest = MacosAarch64CountManifestV2::default();
    let first = compile_pattern("needle", &manifest);
    let second = compile_pattern("needle", &manifest);
    assert_eq!(first.object().as_bytes(), second.object().as_bytes());
    assert_eq!(first.receipt(), second.receipt());

    let receipt = first.receipt();
    let support = receipt.support();
    assert_eq!(support, AOT_COUNT_COMPILER_SUPPORT_V2);
    assert_eq!(support.backend_version, AOT_COUNT_BACKEND_VERSION_V2);
    assert_eq!(
        support.algorithm_version,
        AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2
    );
    assert_eq!(
        support.kir_semantics_version,
        AOT_COUNT_KIR_SEMANTICS_VERSION_V2
    );
    assert_eq!(support.kir_abi_version, AOT_COUNT_KIR_ABI_VERSION_V2);
    assert_eq!(support.output_kind, 1);
    assert_eq!(support.architecture, 1);
    assert!(support.little_endian);
    assert_eq!(support.pointer_width, 64);
    assert_eq!(support.target_abi, 1);
    assert_eq!(support.allowed_features.bits(), 1);

    let metadata = receipt.metadata();
    assert_eq!(metadata.format_version(), METADATA_VERSION_V2);
    assert_eq!(metadata.backend_version(), AOT_COUNT_BACKEND_VERSION_V2.0);
    assert_eq!(metadata.algorithm_version(), support.algorithm_version);
    assert_eq!(
        metadata.kir_semantics_version(),
        support.kir_semantics_version
    );
    assert_eq!(metadata.kir_abi_version(), support.kir_abi_version);
    assert_eq!(metadata.max_literal_bytes(), support.max_literal_bytes);
    assert_eq!(metadata.abi_kind(), AbiKind::Aggregate);
    assert_eq!(metadata.output_kind(), support.output_kind);
    assert_eq!(metadata.architecture(), support.architecture);
    assert_eq!(metadata.little_endian(), support.little_endian);
    assert_eq!(metadata.pointer_width(), support.pointer_width);
    assert_eq!(metadata.target_abi(), support.target_abi);
    assert_eq!(metadata.platform(), PLATFORM_MACOS);
    assert_eq!(metadata.status_bits(), STATUS_BITS_V2);
    assert_eq!(metadata.abi_schema(), CALL_ABI_SCHEMA_V2);
    assert_eq!(metadata.actual_features(), 1);
    assert_eq!(metadata.allowed_features(), support.allowed_features.bits());
    assert_eq!(
        metadata.source_identity(),
        receipt.program_identity().as_bytes()
    );
    assert_eq!(
        metadata.artifact_identity(),
        receipt.image_identity().as_bytes()
    );
    assert_eq!(
        receipt.compile_identity(),
        first.object().compile_identity()
    );
    assert_eq!(receipt.object_identity(), first.object().object_identity());

    let inspection = receipt
        .validate_object_bytes(first.object().as_bytes())
        .expect("receipt reopens exact bytes");
    assert_eq!(inspection.metadata(), metadata);
    assert!(
        receipt
            .object_binding_identity()
            .matches_claim(inspection.metadata().claimed_binding_identity())
    );
    assert!(
        receipt
            .compile_identity()
            .matches_claim(inspection.claimed_compile_identity())
    );
    assert!(
        receipt
            .object_identity()
            .matches_claim(inspection.claimed_object_identity())
    );
}

#[test]
fn compiler_v2_preserves_typed_image_stats_audit_and_resource_receipts() {
    let compiled = compile_pattern("needle", &MacosAarch64CountManifestV2::default());
    let accounting = compiled.receipt().accounting();
    let prospective = accounting.image_prospective();
    let stats = accounting.image_stats();
    let build = accounting.image_build_receipt();
    let audit = accounting.image_audit();
    assert_eq!(build.support, AOT_COUNT_COMPILER_SUPPORT_V2);
    assert_eq!(build.audit, audit);
    assert_eq!(audit.decode_passes, 1);
    assert_eq!(audit.source_identity_rebuilds, 0);
    assert_eq!(stats.audit_work_upper_bound, audit.work_upper_bound);
    assert_eq!(stats.total_work_upper_bound, build.work_upper_bound);
    assert_eq!(
        stats.scratch_bytes_upper_bound,
        build.scratch_bytes_upper_bound
    );
    assert!(u64::from(stats.code_bytes) <= prospective.code_bytes_upper_bound);
    assert!(stats.total_work_upper_bound <= prospective.total_work_upper_bound);
    assert_eq!(accounting.object_report(), compiled.object().report());
    assert_eq!(
        accounting.object_validation().image_audit(),
        accounting.object_report().image_audit
    );
    assert!(
        accounting.reported_pipeline_work_upper_bound()
            <= compiled.receipt().manifest().policy().max_pipeline_work
    );
    assert!(
        accounting
            .pipeline_live()
            .pipeline_peak_live_bytes_upper_bound()
            <= compiled
                .receipt()
                .manifest()
                .policy()
                .max_pipeline_peak_live_bytes
    );
}

#[test]
fn compiler_v2_covers_empty_scalar_and_full_width_contract_boundaries() {
    let manifest = MacosAarch64CountManifestV2::default();
    for pattern in ["", "x", "xy", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"] {
        let compiled = compile_pattern(pattern, &manifest);
        let receipt = compiled.receipt();
        assert_eq!(
            usize::try_from(receipt.live_literal_bytes()).unwrap(),
            pattern.len()
        );
        assert_eq!(
            receipt.metadata().literal_bytes(),
            receipt.live_literal_bytes()
        );
        assert_eq!(
            receipt.metadata().actual_features(),
            u64::from(!pattern.is_empty())
        );
        assert!(
            receipt
                .validate_object_bytes(compiled.object().as_bytes())
                .is_ok()
        );
        assert!(
            compiled
                .static_count_expectation()
                .authenticates_claim(&compiled.static_count_expectation().claim())
        );
    }
}

#[test]
fn expectation_is_explicitly_v2_and_refuses_stale_algorithm_3() {
    let compiled = compile_pattern("needle", &MacosAarch64CountManifestV2::default());
    let expectation = compiled.static_count_expectation();
    assert!(expectation.authenticates_itself());
    assert!(
        expectation.build_report().identity_bytes_hashed()
            <= STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2
    );
    let claim = expectation.claim();
    assert_eq!(
        claim.schema_version(),
        AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2
    );
    assert_eq!(claim.compiler_version(), AOT_COMPILER_VERSION_V2);
    assert_eq!(
        claim.image_schema_version(),
        AOT_COUNT_IMAGE_SCHEMA_VERSION_V2
    );
    assert!(expectation.authenticates_claim(&claim));
    assert_eq!(
        claim.metadata().algorithm_version(),
        AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2
    );
}

#[test]
fn version_namespaces_are_not_silent_v1_reinterpretations() {
    assert_eq!(AOT_COMPILER_VERSION_V2, 2);
    assert_eq!(AOT_MANIFEST_SCHEMA_VERSION_V2, 2);
    assert_eq!(AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V2, 2);
    assert_eq!(AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2, 2);
    assert_ne!(
        MacosAarch64CountManifestV2::default().identity(),
        crate::MacosAarch64CountManifestV1::default().identity()
    );
}

#[test]
fn escaped_source_and_literal_substitution_separate_every_downstream_identity() {
    let manifest = MacosAarch64CountManifestV2::default();
    let plain = compile_pattern("needle", &manifest);
    let escaped = compile_pattern(r"\x6e\x65\x65\x64\x6c\x65", &manifest);
    assert_eq!(
        plain.receipt().live_literal_identity(),
        escaped.receipt().live_literal_identity()
    );
    assert_ne!(
        plain.receipt().source_identity(),
        escaped.receipt().source_identity()
    );
    assert_eq!(
        plain.receipt().program_identity(),
        escaped.receipt().program_identity()
    );
    assert_eq!(
        plain.receipt().image_identity(),
        escaped.receipt().image_identity()
    );
    assert_ne!(
        plain.receipt().semantic_binding_identity(),
        escaped.receipt().semantic_binding_identity()
    );
    assert_ne!(
        plain.receipt().object_binding_identity(),
        escaped.receipt().object_binding_identity()
    );
    assert_ne!(
        plain.receipt().compile_identity(),
        escaped.receipt().compile_identity()
    );
    assert_ne!(
        plain.receipt().object_identity(),
        escaped.receipt().object_identity()
    );
    assert_ne!(
        plain.receipt().receipt_identity(),
        escaped.receipt().receipt_identity()
    );
    assert!(matches!(
        plain
            .receipt()
            .validate_object_bytes(escaped.object().as_bytes()),
        Err(ReceiptValidationError::Mismatch {
            field: ReceiptMismatch::ObjectIdentity,
        })
    ));

    let bravo = compile_pattern("bravoo", &manifest);
    assert_ne!(
        plain.receipt().live_literal_identity(),
        bravo.receipt().live_literal_identity()
    );
    assert_ne!(
        plain.receipt().program_identity(),
        bravo.receipt().program_identity()
    );
    assert_ne!(
        plain.receipt().image_identity(),
        bravo.receipt().image_identity()
    );
    assert_ne!(
        plain.receipt().object_identity(),
        bravo.receipt().object_identity()
    );
}

#[test]
fn direct_aot_and_object_one_below_limits_remain_typed() {
    let manifest = MacosAarch64CountManifestV2::default();
    let baseline = compile_pattern("needle", &manifest);
    let accounting = baseline.receipt().accounting();

    let code_required = accounting.image_prospective().code_bytes_upper_bound;
    let mut code_policy = CompilePolicyV2::high_fuel();
    code_policy.native.max_code_bytes = code_required - 1;
    let code_manifest = MacosAarch64CountManifestV2::new(code_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(
            code_manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::CountNative(CountAotError::ResourceLimit {
            resource: CountAotResource::CodeBytes,
            limit,
            required,
        })) if limit + 1 == required && required == code_required
    ));

    let scratch_required = accounting.image_prospective().scratch_bytes_upper_bound;
    let mut scratch_policy = CompilePolicyV2::high_fuel();
    scratch_policy.native.max_scratch_bytes = scratch_required - 1;
    let scratch_manifest = MacosAarch64CountManifestV2::new(scratch_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(
            scratch_manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::CountNative(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit,
            required,
        })) if limit + 1 == required && required == scratch_required
    ));

    let labels_required = accounting.image_prospective().labels_upper_bound;
    let mut labels_policy = CompilePolicyV2::high_fuel();
    labels_policy.native.max_labels = labels_required - 1;
    let labels_manifest = MacosAarch64CountManifestV2::new(labels_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(
            labels_manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::CountNative(CountAotError::ResourceLimit {
            resource: CountAotResource::Labels,
            limit,
            required,
        })) if limit + 1 == required && required == labels_required
    ));

    let object_required =
        u64::try_from(accounting.object_report().object_bytes).expect("object width");
    let mut object_policy = CompilePolicyV2::high_fuel();
    object_policy.object.max_object_bytes = object_required - 1;
    let object_manifest = MacosAarch64CountManifestV2::new(object_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(
            object_manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::Object(ObjectError::ResourceLimit {
            resource: ObjectResource::ObjectBytes,
            limit,
            required,
        })) if limit + 1 == required && required == object_required
    ));
}

#[test]
fn source_and_kir_boundaries_refuse_before_unbounded_downstream_work() {
    let manifest = MacosAarch64CountManifestV2::default();
    let required_capacity = usize::try_from(manifest.policy().max_source_bytes)
        .unwrap()
        .checked_add(1)
        .unwrap();
    let mut oversized_capacity = Vec::with_capacity(required_capacity);
    oversized_capacity.extend_from_slice(b"needle");
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(
            manifest,
            oversized_capacity,
            unicode_off_profile(),
        ),
        Err(CompileError::ResourceLimit {
            resource: CompileResource::SourceCapacityBytes,
            limit,
            required,
        }) if limit + 1 == required
    ));
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(manifest, vec![0xff], unicode_off_profile(),),
        Err(CompileError::InvalidUtf8Source)
    ));

    let mut kernel_policy = CompilePolicyV2::high_fuel();
    kernel_policy.kernel_ir.max_data_bytes = 5;
    let kernel_manifest = MacosAarch64CountManifestV2::new(kernel_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(
            kernel_manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::Kernel(AggregateBuildError::Search(
            BuildError::Validate(ValidateError::ResourceLimit {
                resource: KernelResource::DataBytes,
                limit: 5,
                required: 6,
            })
        )))
    ));
}

#[test]
fn source_hard_refusal_precedes_the_first_manifest_canonical_pass() {
    let manifest = MacosAarch64CountManifestV2::default();
    let required_capacity = usize::try_from(crate::MAX_AOT_SOURCE_BYTES_V2)
        .unwrap()
        .checked_add(1)
        .unwrap();
    let oversized_capacity = Vec::with_capacity(required_capacity);

    crate::manifest_v2::manifest_encode_trace::reset();
    crate::compiler_v2::hard_identity_gate_trace::reset();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(
            manifest,
            oversized_capacity,
            unicode_off_profile(),
        ),
        Err(CompileError::ResourceLimit {
            resource: CompileResource::SourceCapacityBytes,
            limit,
            required,
        }) if limit + 1 == required
    ));
    assert_eq!(
        crate::manifest_v2::manifest_encode_trace::passes(),
        0,
        "the hard owned-buffer boundary must not trust or hash the manifest"
    );
    assert_eq!(
        crate::compiler_v2::hard_identity_gate_trace::observation(),
        (1, 0),
        "the hard prospective identity gate must precede the first manifest encode"
    );

    crate::manifest_v2::manifest_encode_trace::reset();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(manifest, vec![0xff], unicode_off_profile(),),
        Err(CompileError::InvalidUtf8Source)
    ));
    assert_eq!(
        crate::manifest_v2::manifest_encode_trace::passes(),
        1,
        "an admitted source entry authenticates its manifest exactly once"
    );

    crate::manifest_v2::manifest_encode_trace::reset();
    crate::compiler_v2::hard_identity_gate_trace::reset();
    let compiled = plan_and_compile_macos_aarch64_count_v2(
        manifest,
        b"needle".to_vec(),
        unicode_off_profile(),
    )
    .expect("valid source-first compile");
    assert_eq!(
        crate::manifest_v2::manifest_encode_trace::passes(),
        1,
        "a complete valid compile must not reauthenticate the manifest"
    );
    assert_eq!(
        crate::compiler_v2::hard_identity_gate_trace::observation(),
        (1, 0)
    );
    assert!(
        compiled
            .receipt()
            .validate_object_bytes(compiled.object().as_bytes())
            .is_ok()
    );
}

#[test]
fn valid_compile_hashes_each_compiler_owned_seal_exactly_once() {
    let manifest = MacosAarch64CountManifestV2::default();
    crate::manifest_v2::manifest_encode_trace::reset();
    crate::manifest_v2::policy_limits_encode_trace::reset();
    crate::receipt_v2::resource_receipt_hash_trace::reset();
    crate::receipt_v2::receipt_hash_trace::reset();
    crate::static_expectation_v2::expectation_identity_trace::reset();

    let compiled = compile_pattern("once-only-seals", &manifest);

    assert_eq!(crate::manifest_v2::manifest_encode_trace::passes(), 1);
    assert_eq!(crate::manifest_v2::policy_limits_encode_trace::passes(), 1);
    assert_eq!(crate::receipt_v2::resource_receipt_hash_trace::passes(), 1);
    assert_eq!(crate::receipt_v2::receipt_hash_trace::passes(), 1);
    assert_eq!(
        crate::static_expectation_v2::expectation_identity_trace::passes(),
        1
    );
    assert_eq!(
        compiled
            .receipt()
            .accounting()
            .compiler_identity()
            .resource_receipt_count_passes(),
        2
    );
    assert_eq!(
        compiled
            .receipt()
            .accounting()
            .compiler_identity()
            .compile_receipt_count_passes(),
        2
    );
}

#[test]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the test restates every exact accounting equation and its one-below gate"
)]
fn compiler_identity_expectation_and_final_live_accounting_are_exact_and_one_below() {
    let compiled = compile_pattern(
        "identity-accounting",
        &MacosAarch64CountManifestV2::default(),
    );
    let receipt = compiled.receipt();
    let accounting = receipt.accounting();
    let identity = accounting.compiler_identity();
    assert_eq!(
        identity.manifest_canonical_bytes(),
        receipt.manifest().identity_bytes_hashed()
    );
    assert_eq!(
        identity.literal_identity_bytes(),
        u64::from(receipt.live_literal_bytes())
    );
    assert_eq!(identity.manifest_authentication_hash_passes(), 1);
    assert_eq!(
        identity.policy_limits_canonical_bytes(),
        receipt.manifest().policy_limits_identity_bytes_hashed()
    );
    assert_eq!(identity.policy_limits_hash_passes(), 1);
    assert_eq!(identity.literal_hash_passes(), 1);
    assert_eq!(identity.object_binding_hash_passes(), 1);
    assert_eq!(identity.resource_receipt_count_passes(), 2);
    assert_eq!(identity.resource_receipt_hash_passes(), 1);
    assert_eq!(identity.compile_receipt_count_passes(), 2);
    assert_eq!(identity.compile_receipt_hash_passes(), 1);
    let traversed = identity.manifest_canonical_bytes()
        + identity.policy_limits_canonical_bytes()
        + identity.literal_identity_bytes()
        + identity.object_binding_canonical_bytes()
        + 3 * identity.resource_receipt_canonical_bytes()
        + 3 * identity.compile_receipt_canonical_bytes();
    assert_eq!(identity.canonical_bytes_traversed(), traversed);
    assert_eq!(
        identity.traversal_fixed_work(),
        10 * crate::canonical::CANONICAL_TRAVERSAL_FIXED_WORK_V2
    );
    assert_eq!(
        identity.hash_finalize_work(),
        6 * crate::canonical::IDENTITY_HASH_FINALIZE_WORK_V2
    );
    assert_eq!(
        identity.total_work_upper_bound(),
        traversed + identity.traversal_fixed_work() + identity.hash_finalize_work()
    );
    assert_eq!(
        accounting.compiler_identity_work(),
        identity.total_work_upper_bound()
    );
    assert_eq!(
        identity.identity_scratch_bytes_upper_bound(),
        crate::canonical::CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2
    );

    let expectation = compiled.static_count_expectation();
    let expectation_report = expectation.build_report();
    assert_eq!(
        expectation_report.canonical_bytes_hashed(),
        crate::STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2
    );
    assert_eq!(
        expectation_report.canonical_bytes_traversed(),
        crate::STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2
    );
    assert_eq!(expectation_report.canonical_count_passes(), 1);
    assert_eq!(expectation_report.canonical_hash_passes(), 1);
    assert_eq!(
        expectation_report.work_upper_bound(),
        crate::STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2
    );
    assert_eq!(
        expectation_report.scratch_bytes_upper_bound(),
        crate::STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2
    );
    assert_eq!(
        expectation_report.retained_bytes(),
        core::mem::size_of::<crate::StaticCountExpectationV2>()
    );
    assert_eq!(expectation_report.allocations(), 0);
    assert_eq!(accounting.static_expectation_build(), expectation_report);
    assert!(expectation.authenticates_itself());
    assert!(expectation.authenticates_claim(&expectation.claim()));

    let expected_peak_scratch = u64::try_from(accounting.candidate_build().scratch_bytes)
        .unwrap()
        .max(
            accounting
                .candidate_identity_projection()
                .scratch_bytes_upper_bound(),
        )
        .max(
            u64::try_from(
                accounting
                    .kernel_build()
                    .resources()
                    .validation_scratch_bytes(),
            )
            .unwrap(),
        )
        .max(accounting.image_build_receipt().scratch_bytes_upper_bound)
        .max(accounting.object_report().scratch_bytes_upper_bound)
        .max(accounting.object_validation().scratch_bytes_upper_bound())
        .max(crate::canonical::CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2)
        .max(expectation_report.scratch_bytes_upper_bound());
    assert_eq!(
        accounting.peak_scratch_bytes_upper_bound(),
        expected_peak_scratch
    );

    let live = accounting.pipeline_live();
    let base_without_expectation = u64::try_from(live.facade_live_persistent_bytes()).unwrap()
        + u64::try_from(live.kir_retained_bytes()).unwrap()
        + u64::try_from(live.image_retained_bytes()).unwrap()
        + u64::try_from(live.image_inline_bytes()).unwrap()
        + u64::try_from(live.object_retained_bytes()).unwrap()
        + u64::try_from(live.compiled_object_inline_bytes()).unwrap()
        - u64::try_from(live.static_expectation_inline_bytes()).unwrap();
    assert_eq!(
        live.static_expectation_inline_bytes(),
        core::mem::size_of::<crate::StaticCountExpectationV2>()
    );
    assert_eq!(
        live.identity_scratch_bytes_upper_bound(),
        crate::canonical::CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2
    );
    assert_eq!(
        live.identity_peak_live_bytes(),
        base_without_expectation + live.identity_scratch_bytes_upper_bound()
    );
    assert_eq!(
        live.expectation_peak_live_bytes(),
        base_without_expectation + expectation_report.scratch_bytes_upper_bound()
    );
    assert_eq!(
        live.final_peak_live_bytes(),
        base_without_expectation + u64::try_from(expectation_report.retained_bytes()).unwrap()
    );
    assert_eq!(
        live.pipeline_peak_live_bytes_upper_bound(),
        [
            live.planning_peak_live_bytes(),
            live.kir_peak_live_bytes(),
            live.image_peak_live_bytes(),
            live.object_peak_live_bytes(),
            live.identity_peak_live_bytes(),
            live.expectation_peak_live_bytes(),
            live.final_peak_live_bytes(),
        ]
        .into_iter()
        .max()
        .unwrap()
    );

    for (resource, required) in [
        (
            CompileResource::CompilerIdentityWork,
            accounting.compiler_identity_work(),
        ),
        (
            CompileResource::PipelineWork,
            accounting.reported_pipeline_work_upper_bound(),
        ),
        (
            CompileResource::PeakScratchBytes,
            accounting.peak_scratch_bytes_upper_bound(),
        ),
        (
            CompileResource::PipelinePeakLiveBytes,
            live.pipeline_peak_live_bytes_upper_bound(),
        ),
    ] {
        crate::compiler::enforce(resource, required, required).expect("exact limit");
        assert!(matches!(
            crate::compiler::enforce(resource, required, required - 1),
            Err(CompileError::ResourceLimit {
                resource: observed,
                limit,
                required: observed_required,
            }) if observed == resource
                && limit + 1 == observed_required
                && observed_required == required
        ));
    }
    assert!(
        receipt
            .validate_object_bytes(compiled.object().as_bytes())
            .is_ok()
    );
}

#[test]
fn manifest_refuses_native_limits_wider_than_the_exact_v2_hard_contract() {
    assert_eq!(
        CompilePolicyV2::high_fuel().native,
        CountEmitLimitsV2::default(),
        "compiler-v2 defaults must track the exact current direct backend envelope"
    );
    let mut policy = CompilePolicyV2::high_fuel();
    policy.native.max_work = policy.native.max_work.checked_add(1).unwrap();
    assert!(matches!(
        MacosAarch64CountManifestV2::new(policy),
        Err(ManifestError::CountNativePolicyExceedsHardLimit {
            resource: CountAotResource::Work,
            limit,
            requested,
        }) if requested == limit + 1
    ));
}

#[test]
fn compiler_level_resource_one_below_limits_fail_closed() {
    let baseline = compile_pattern("needle", &MacosAarch64CountManifestV2::default());
    let accounting = baseline.receipt().accounting();

    let final_required =
        u64::try_from(accounting.final_persistent_bytes()).expect("persistent width");
    let mut persistent_policy = CompilePolicyV2::high_fuel();
    persistent_policy.max_final_persistent_bytes = final_required - 1;
    let persistent_manifest = MacosAarch64CountManifestV2::new(persistent_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count_v2(
            persistent_manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::ResourceLimit {
            resource: CompileResource::FinalPersistentBytes,
            limit,
            required,
        }) if limit + 1 == required && required == final_required
    ));
}

#[test]
fn changed_object_bytes_and_cross_object_splices_never_authenticate() {
    let manifest = MacosAarch64CountManifestV2::default();
    let compiled = compile_pattern("needle", &manifest);
    let mut changed = compiled.object().as_bytes().to_vec();
    *changed.last_mut().expect("nonempty object") ^= 1;
    assert!(compiled.receipt().validate_object_bytes(&changed).is_err());

    let other = compile_pattern("bravoo", &manifest);
    assert!(matches!(
        compiled
            .receipt()
            .validate_object_bytes(other.object().as_bytes()),
        Err(ReceiptValidationError::Mismatch {
            field: ReceiptMismatch::ObjectIdentity,
        })
    ));
}
