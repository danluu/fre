use fre::RustProfile;
use fre_aot_macho::{ObjectError, ObjectResource};
use fre_jit_aarch64::{BackendVersion, ResourceKind as NativeResource};
use fre_kernel_ir::{
    AggregateBuildError, BuildError, MAX_EXACT_AGGREGATE_LITERAL_BYTES,
    ResourceKind as KernelResource, ValidateError,
};

use crate::{
    AOT_AGGREGATE_BACKEND_VERSION_V1, CompileError, CompilePolicyV1, CompileResource,
    MacosAarch64CountManifestV1, ManifestError, ReceiptMismatch, ReceiptValidationError,
    STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V1,
    STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1,
    STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1, inspect_static_count_expectation_v1,
    plan_and_compile_macos_aarch64_count, receipt::object_report_identity_projection_for_test,
};

fn unicode_off_profile() -> RustProfile {
    let mut profile = RustProfile::default();
    profile.options.unicode = false;
    profile
}

#[allow(
    clippy::large_types_passed_by_value,
    reason = "the test helper mirrors the public ownership boundary and consumes the sealed manifest"
)]
fn compile_pattern(pattern: &str, manifest: MacosAarch64CountManifestV1) -> crate::CompiledObject {
    plan_and_compile_macos_aarch64_count(
        manifest,
        pattern.as_bytes().to_vec(),
        unicode_off_profile(),
    )
    .expect("AOT compile")
}

#[test]
fn deterministic_compile_seals_every_identity_and_strictly_reopens_bytes() {
    let manifest = MacosAarch64CountManifestV1::default();
    let first = compile_pattern("needle", manifest);
    let second = compile_pattern("needle", manifest);

    assert_eq!(first.object().as_bytes(), second.object().as_bytes());
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(
        first.receipt().manifest_identity(),
        second.receipt().manifest_identity()
    );
    assert_eq!(
        first.receipt().compile_identity(),
        first.object().compile_identity()
    );
    assert_eq!(
        first.receipt().object_identity(),
        first.object().object_identity()
    );
    assert_eq!(first.receipt().metadata(), first.object().metadata());
    let inspection = first
        .receipt()
        .validate_object_bytes(first.object().as_bytes())
        .expect("trusted receipt authenticates strict object inspection");
    assert_eq!(inspection.metadata(), first.receipt().metadata());
    assert!(
        first
            .receipt()
            .object_binding_identity()
            .matches_claim(inspection.metadata().claimed_binding_identity())
    );
    assert!(
        first
            .receipt()
            .compile_identity()
            .matches_claim(inspection.claimed_compile_identity())
    );
    assert!(
        first
            .receipt()
            .object_identity()
            .matches_claim(inspection.claimed_object_identity())
    );
    let accounting = first.receipt().accounting();
    assert_eq!(accounting.object_report(), first.object().report());
    assert_eq!(accounting.object_report().image_audit.decode_passes, 1);
    assert_eq!(
        accounting
            .object_report()
            .image_audit
            .source_identity_rebuilds,
        1
    );
    let kernel_shape = accounting.kernel_stats();
    assert_eq!(kernel_shape.blocks(), 4);
    assert_eq!(kernel_shape.instructions(), 4);
    assert_eq!(kernel_shape.data_blobs(), 1);
    assert_eq!(kernel_shape.data_bytes(), b"needle".len());
    assert_eq!(kernel_shape.serialized_bytes(), b"needle".len() + 53);
    let kernel_resources = accounting.kernel_build().resources();
    assert_eq!(
        kernel_resources.version(),
        fre_kernel_ir::ResourceAccounting::VERSION
    );
    assert_eq!(kernel_resources.hash_invocations(), 2);
    assert_eq!(
        accounting.kernel_construction_work_upper_bound(),
        kernel_resources.construction_work()
    );
    assert!(accounting.reported_pipeline_work_upper_bound() <= manifest.policy().max_pipeline_work);
    assert!(
        u64::try_from(accounting.final_persistent_bytes()).unwrap()
            <= manifest.policy().max_final_persistent_bytes
    );
}

#[test]
fn aggregate_manifest_and_receipt_bind_the_aggregate_backend_audit_contract() {
    assert_eq!(BackendVersion::SEARCH_CURRENT, BackendVersion::SEARCH_V8);
    assert_ne!(BackendVersion::SEARCH_V8, BackendVersion::AGGREGATE_CURRENT);
    assert_eq!(
        AOT_AGGREGATE_BACKEND_VERSION_V1,
        BackendVersion::AGGREGATE_CURRENT.0
    );

    let compiled = compile_pattern("receipt-audit", MacosAarch64CountManifestV1::default());
    assert_eq!(
        compiled.object().metadata().backend_version(),
        BackendVersion::AGGREGATE_CURRENT.0
    );
    let report = compiled.receipt().accounting().object_report();
    let (baseline_identity, baseline_bytes) =
        object_report_identity_projection_for_test(report).unwrap();

    let mut changed_binding_work = report;
    changed_binding_work.image_binding_work_upper_bound = changed_binding_work
        .image_binding_work_upper_bound
        .checked_add(1)
        .unwrap();
    let (binding_identity, binding_bytes) =
        object_report_identity_projection_for_test(changed_binding_work).unwrap();
    assert_eq!(binding_bytes, baseline_bytes);
    assert_ne!(binding_identity, baseline_identity);

    let mut changed_decode = report;
    changed_decode.image_audit.decode_passes = changed_decode
        .image_audit
        .decode_passes
        .checked_add(1)
        .unwrap();
    let (decode_identity, decode_bytes) =
        object_report_identity_projection_for_test(changed_decode).unwrap();
    assert_eq!(decode_bytes, baseline_bytes);
    assert_ne!(decode_identity, baseline_identity);

    let mut changed_rebuild = report;
    changed_rebuild.image_audit.source_identity_rebuilds = changed_rebuild
        .image_audit
        .source_identity_rebuilds
        .checked_add(1)
        .unwrap();
    let (rebuild_identity, rebuild_bytes) =
        object_report_identity_projection_for_test(changed_rebuild).unwrap();
    assert_eq!(rebuild_bytes, baseline_bytes);
    assert_ne!(rebuild_identity, baseline_identity);
}

#[test]
fn escaped_source_with_same_live_literal_cannot_splice_semantic_receipts() {
    let manifest = MacosAarch64CountManifestV1::default();
    let plain = compile_pattern("needle", manifest);
    let escaped = compile_pattern(r"\x6e\x65\x65\x64\x6c\x65", manifest);

    assert_eq!(
        plain.receipt().live_literal_identity(),
        escaped.receipt().live_literal_identity()
    );
    assert_eq!(
        plain.receipt().kir_identity(),
        escaped.receipt().kir_identity()
    );
    assert_eq!(
        plain.receipt().native_artifact_identity(),
        escaped.receipt().native_artifact_identity()
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
}

#[test]
fn static_expectation_is_built_once_and_strictly_reopens() {
    let compiled = compile_pattern("needle", MacosAarch64CountManifestV1::default());
    let expectation = compiled.static_count_expectation();
    let report = expectation.build_report();
    assert!(
        report.canonical_bytes_hashed()
            <= STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V1
    );
    assert!(report.work_upper_bound() <= STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1);
    assert_eq!(
        report.scratch_bytes_upper_bound(),
        STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1
    );
    let claim = inspect_static_count_expectation_v1(compiled.static_count_expectation_bytes())
        .expect("cached expectation wire is canonical");
    assert!(expectation.authenticates_claim(&claim));

    let mut changed = *compiled.static_count_expectation_bytes();
    changed[17] ^= 1;
    assert!(inspect_static_count_expectation_v1(&changed).is_err());
}

#[test]
fn same_length_literal_substitution_changes_every_semantic_artifact_identity() {
    let manifest = MacosAarch64CountManifestV1::default();
    let alpha = compile_pattern("alpha", manifest);
    let bravo = compile_pattern("bravo", manifest);

    assert_eq!(
        alpha.receipt().live_literal_bytes(),
        bravo.receipt().live_literal_bytes()
    );
    assert_ne!(
        alpha.receipt().live_literal_identity(),
        bravo.receipt().live_literal_identity()
    );
    assert_ne!(
        alpha.receipt().kir_identity(),
        bravo.receipt().kir_identity()
    );
    assert_ne!(
        alpha.receipt().native_artifact_identity(),
        bravo.receipt().native_artifact_identity()
    );
    assert_ne!(
        alpha.receipt().object_binding_identity(),
        bravo.receipt().object_binding_identity()
    );
    assert_ne!(
        alpha.receipt().object_identity(),
        bravo.receipt().object_identity()
    );
    assert_ne!(
        alpha.receipt().receipt_identity(),
        bravo.receipt().receipt_identity()
    );
}

#[test]
fn profile_substitution_changes_source_proof_without_rewriting_live_literal() {
    let manifest = MacosAarch64CountManifestV1::default();
    let default =
        plan_and_compile_macos_aarch64_count(manifest, b"needle".to_vec(), RustProfile::default())
            .unwrap();
    let rebar = plan_and_compile_macos_aarch64_count(
        manifest,
        b"needle".to_vec(),
        RustProfile::rebar_1_12_4(),
    )
    .unwrap();

    assert_eq!(
        default.receipt().live_literal_identity(),
        rebar.receipt().live_literal_identity()
    );
    assert_eq!(
        default.receipt().kir_identity(),
        rebar.receipt().kir_identity()
    );
    assert_ne!(
        default.receipt().semantic_binding_identity(),
        rebar.receipt().semantic_binding_identity()
    );
    assert_ne!(
        default.receipt().object_identity(),
        rebar.receipt().object_identity()
    );
}

#[test]
fn policy_substitution_is_bound_before_object_publication() {
    let first_manifest = MacosAarch64CountManifestV1::default();
    let mut second_policy = CompilePolicyV1::high_fuel();
    second_policy.max_final_persistent_bytes = second_policy
        .max_final_persistent_bytes
        .checked_add(1)
        .unwrap();
    let second_manifest = MacosAarch64CountManifestV1::new(second_policy).unwrap();
    let first = compile_pattern("needle", first_manifest);
    let second = compile_pattern("needle", second_manifest);

    assert_ne!(
        first.receipt().manifest_identity(),
        second.receipt().manifest_identity()
    );
    assert_eq!(
        first.receipt().kir_identity(),
        second.receipt().kir_identity()
    );
    assert_eq!(
        first.receipt().native_artifact_identity(),
        second.receipt().native_artifact_identity()
    );
    assert_ne!(
        first.receipt().object_binding_identity(),
        second.receipt().object_binding_identity()
    );
    assert_ne!(
        first.receipt().object_identity(),
        second.receipt().object_identity()
    );
}

#[test]
fn literal_policy_cannot_undercut_the_pre_hash_fixed_envelope() {
    let mut policy = CompilePolicyV1::high_fuel();
    policy.max_literal_bytes = 5;
    assert_eq!(
        MacosAarch64CountManifestV1::new(policy),
        Err(ManifestError::LiteralPolicyBelowFixedEnvelope {
            required: u64::try_from(MAX_EXACT_AGGREGATE_LITERAL_BYTES).unwrap(),
            supplied: 5,
        })
    );
}

#[test]
fn raw_source_gates_precede_utf8_and_facade_work() {
    let manifest = MacosAarch64CountManifestV1::default();
    let over_length = vec![
        0xff;
        usize::try_from(manifest.policy().max_source_bytes)
            .unwrap()
            .checked_add(1)
            .unwrap()
    ];
    let required = u64::try_from(over_length.len()).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count(
            manifest,
            over_length,
            unicode_off_profile(),
        ),
        Err(CompileError::ResourceLimit {
            resource: CompileResource::SourceBytes,
            limit,
            required: observed,
        }) if limit == manifest.policy().max_source_bytes && observed == required
    ));

    assert!(matches!(
        plan_and_compile_macos_aarch64_count(manifest, vec![0xff], unicode_off_profile(),),
        Err(CompileError::InvalidUtf8Source)
    ));

    let mut over_capacity = Vec::with_capacity(
        usize::try_from(manifest.policy().max_source_bytes)
            .unwrap()
            .checked_add(1)
            .unwrap(),
    );
    over_capacity.push(b'a');
    let required = u64::try_from(over_capacity.capacity()).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count(
            manifest,
            over_capacity,
            unicode_off_profile(),
        ),
        Err(CompileError::ResourceLimit {
            resource: CompileResource::SourceCapacityBytes,
            limit,
            required: observed,
        }) if limit == manifest.policy().max_source_bytes && observed == required
    ));
}

#[test]
fn kernel_native_and_object_one_below_limits_remain_typed() {
    let mut kernel_policy = CompilePolicyV1::high_fuel();
    kernel_policy.kernel_ir.max_data_bytes = 5;
    let kernel_manifest = MacosAarch64CountManifestV1::new(kernel_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count(
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

    let baseline = compile_pattern("needle", MacosAarch64CountManifestV1::default());
    let code_bytes = u64::from(baseline.receipt().accounting().native_stats().code_bytes);
    let mut native_policy = CompilePolicyV1::high_fuel();
    native_policy.native.max_code_bytes = code_bytes.checked_sub(1).unwrap();
    let native_manifest = MacosAarch64CountManifestV1::new(native_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count(
            native_manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::Native(
            fre_jit_aarch64::EmitError::ResourceLimit {
                resource: NativeResource::CodeBytes,
                limit,
                required,
            }
        )) if limit + 1 == required
    ));

    let object_bytes =
        u64::try_from(baseline.receipt().accounting().object_report().object_bytes).unwrap();
    let mut object_policy = CompilePolicyV1::high_fuel();
    object_policy.object.max_object_bytes = object_bytes.checked_sub(1).unwrap();
    let object_manifest = MacosAarch64CountManifestV1::new(object_policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count(
            object_manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::Object(ObjectError::ResourceLimit {
            resource: ObjectResource::ObjectBytes,
            limit,
            required,
        })) if limit + 1 == required
    ));
}

#[test]
fn final_persistent_one_below_is_a_compiler_level_refusal() {
    let baseline = compile_pattern("needle", MacosAarch64CountManifestV1::default());
    let required = u64::try_from(baseline.receipt().accounting().final_persistent_bytes()).unwrap();
    let mut policy = CompilePolicyV1::high_fuel();
    policy.max_final_persistent_bytes = required.checked_sub(1).unwrap();
    let manifest = MacosAarch64CountManifestV1::new(policy).unwrap();
    assert!(matches!(
        plan_and_compile_macos_aarch64_count(
            manifest,
            b"needle".to_vec(),
            unicode_off_profile(),
        ),
        Err(CompileError::ResourceLimit {
            resource: CompileResource::FinalPersistentBytes,
            limit,
            required: observed,
        }) if limit == required - 1 && observed == required
    ));
}

#[test]
fn manifest_rejects_incoherent_or_wider_contracts() {
    let mut too_wide = CompilePolicyV1::high_fuel();
    too_wide.max_literal_bytes = u64::try_from(MAX_EXACT_AGGREGATE_LITERAL_BYTES)
        .unwrap()
        .checked_add(1)
        .unwrap();
    assert!(matches!(
        MacosAarch64CountManifestV1::new(too_wide),
        Err(ManifestError::LiteralPolicyExceedsHardLimit { .. })
    ));

    let baseline = MacosAarch64CountManifestV1::default();
    let mut too_little_work = CompilePolicyV1::high_fuel();
    too_little_work.max_pipeline_work = baseline
        .declared_stage_work_upper_bound()
        .checked_sub(1)
        .unwrap();
    assert!(matches!(
        MacosAarch64CountManifestV1::new(too_little_work),
        Err(ManifestError::InconsistentWorkCeiling { .. })
    ));

    let mut too_little_scratch = CompilePolicyV1::high_fuel();
    too_little_scratch.max_peak_scratch_bytes = too_little_scratch
        .kernel_ir
        .max_validation_scratch_bytes
        .checked_sub(1)
        .unwrap();
    assert!(matches!(
        MacosAarch64CountManifestV1::new(too_little_scratch),
        Err(ManifestError::InconsistentScratchCeiling { .. })
    ));
}

#[test]
fn changed_object_bytes_never_authenticate_under_the_original_receipt() {
    let compiled = compile_pattern("needle", MacosAarch64CountManifestV1::default());
    let mut changed = compiled.object().as_bytes().to_vec();
    let last = changed.last_mut().expect("nonempty object");
    *last ^= 1;
    assert!(compiled.receipt().validate_object_bytes(&changed).is_err());
}
