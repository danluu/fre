use fre_aot_aarch64::{
    AotCountCpuFeatures, AotCountTargetSpec, CountEmitLimitsV2, CountEmitLimitsV3,
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3, audit_count_mapped_code_v3, emit_count_v2,
};
use fre_aot_count_contract::v3::{
    METADATA_ACTUAL_FEATURES_OFFSET_V3, METADATA_BYTES_V3, METADATA_TARGET_IDENTITY_OFFSET_V3,
    STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3, STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V3,
    compute_count_target_identity_v3, inspect_count_metadata_v3,
    inspect_static_count_expectation_v3,
};
use fre_aot_optimizer::{
    COUNT_V3_OPTIMIZER_VERSION, COUNT_V3_RECIPE_SCHEMA_VERSION, CountV3RegisterPlanId,
    CountV3RequiredIsa, CountV3TuningClass, encode_count_recipe_v3,
    inspect_count_v3_optimizer_receipt,
};
use fre_kernel_ir::{Count, ValidateLimits, build_exact_aggregate};
use sha2::{Digest, Sha256};

use crate::{
    CountCompileLimitsV3, CountCompileRequestV3, CountCompileTargetV3, CountObjectFormatV3,
    CountObjectLimitsV2, CountSemanticCandidateV3, RuntimeAuthorityV3, compile_count_v3,
    inspect_count_implementation_object_elf_v2, inspect_count_implementation_object_v3,
    publish_count_implementation_object_elf_v2, publish_count_implementation_object_macho_v2,
};

fn candidate() -> CountSemanticCandidateV3 {
    CountSemanticCandidateV3 {
        manifest_identity: [1; 32],
        policy_limits_identity: [2; 32],
        semantic_binding_identity: [3; 32],
        planning_receipt_identity: [4; 32],
        object_binding_identity: [5; 32],
        claimed_receipt_identity: [6; 32],
        claimed_resource_receipt_identity: [7; 32],
    }
}

fn compile(format: CountObjectFormatV3) -> crate::FocusedCompiledCountV3 {
    compile_for_isa(format, CountV3RequiredIsa::Aarch64Neon128)
}

fn compile_for_isa(
    format: CountObjectFormatV3,
    required_isa: CountV3RequiredIsa,
) -> crate::FocusedCompiledCountV3 {
    compile_count_v3(
        CountCompileRequestV3 {
            literal: b"needle",
            semantic_candidate: candidate(),
            target: CountCompileTargetV3 {
                object_format: format,
                tuning_class: CountV3TuningClass::GenericAarch64,
                required_isa,
            },
        },
        CountCompileLimitsV3::default(),
    )
    .expect("source-only Count-v3 compilation")
}

#[test]
fn both_containers_preserve_identical_audited_code_semantics() {
    let macho = compile(CountObjectFormatV3::MachOArm64);
    let elf = compile(CountObjectFormatV3::Elf64Aarch64);
    let macho_view = inspect_count_implementation_object_v3(
        macho.implementation_object().as_bytes(),
        CountCompileLimitsV3::default().object,
    )
    .expect("strict Mach-O inspection");
    let elf_view = inspect_count_implementation_object_v3(
        elf.implementation_object().as_bytes(),
        CountCompileLimitsV3::default().object,
    )
    .expect("strict ELF inspection");
    assert_eq!(macho_view.code(), elf_view.code());
    assert_ne!(macho_view.compile_identity(), elf_view.compile_identity());
    assert_ne!(macho_view.object_identity(), elf_view.object_identity());
    assert_eq!(
        macho_view.metadata().artifact_identity(),
        elf_view.metadata().artifact_identity()
    );
    assert_eq!(
        macho_view.metadata().canonical_recipe(),
        elf_view.metadata().canonical_recipe()
    );

    let program =
        build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).expect("Count KIR");
    for view in [macho_view, elf_view] {
        audit_count_mapped_code_v3(
            &program,
            view.metadata().canonical_recipe(),
            view.code(),
            view.mapped_metadata().expect("mapped metadata"),
            CountEmitLimitsV3::default(),
        )
        .expect("independent mapped-code regeneration audit");
    }
}

#[test]
fn complete_recipe_literal_and_optimizer_receipt_are_retained() {
    let compiled = compile(CountObjectFormatV3::Elf64Aarch64);
    let metadata = inspect_count_metadata_v3(compiled.implementation_object().metadata_bytes())
        .expect("strict metadata");
    assert_eq!(&metadata.literal_manifest()[..6], b"needle");
    assert!(
        metadata.literal_manifest()[6..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        metadata.canonical_recipe(),
        &encode_count_recipe_v3(compiled.recipe())
    );
    assert_eq!(
        METADATA_BYTES_V3,
        compiled.implementation_object().metadata_bytes().len()
    );
    inspect_count_v3_optimizer_receipt(compiled.unsigned_prelink_receipt().optimizer_receipt())
        .expect("strict optimizer receipt");
    let expectation =
        inspect_static_count_expectation_v3(compiled.expectation()).expect("strict v3 expectation");
    let eligibility = metadata.general_eligibility_tuple();
    assert_eq!(
        expectation.metadata().general_eligibility_tuple(),
        eligibility
    );
    assert_eq!(
        compiled
            .general_eligibility_tuple()
            .expect("eligibility tuple"),
        eligibility
    );
    assert_eq!(eligibility.object_format, CountObjectFormatV3::Elf64Aarch64);
    assert_eq!(eligibility.literal_bytes, 6);
    assert_eq!(
        eligibility.recipe_schema_version,
        COUNT_V3_RECIPE_SCHEMA_VERSION
    );
    assert_eq!(eligibility.optimizer_version, COUNT_V3_OPTIMIZER_VERSION);
    assert!(eligibility.little_endian);
    assert_eq!(eligibility.pointer_width, 64);
    assert_eq!(compiled.runtime_authority(), RuntimeAuthorityV3::Absent);
}

#[test]
fn sve2_expectation_rejects_each_missing_prerequisite_feature() {
    let compiled = compile_for_isa(
        CountObjectFormatV3::Elf64Aarch64,
        CountV3RequiredIsa::Aarch64Sve2Vl16,
    );
    let original_metadata =
        inspect_count_metadata_v3(compiled.implementation_object().metadata_bytes())
            .expect("valid SVE2 metadata");
    let complete_features = AotCountCpuFeatures::ASIMD
        .union(AotCountCpuFeatures::SVE)
        .union(AotCountCpuFeatures::SVE2)
        .bits();
    assert_eq!(original_metadata.actual_features(), complete_features);
    assert_eq!(
        original_metadata.register_plan_id(),
        CountV3RegisterPlanId::Aarch64NeonSve2Vl16V1.wire_id()
    );
    let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[2];
    assert_eq!(support.allowed_features.bits(), complete_features);

    for removed in [
        AotCountCpuFeatures::ASIMD.bits(),
        AotCountCpuFeatures::SVE.bits(),
        AotCountCpuFeatures::SVE2.bits(),
    ] {
        let mutated_features = complete_features ^ removed;
        let mut expectation = *compiled.expectation();
        let actual_start =
            STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V3 + METADATA_ACTUAL_FEATURES_OFFSET_V3;
        expectation[actual_start..actual_start + 8]
            .copy_from_slice(&mutated_features.to_le_bytes());
        let target = AotCountTargetSpec {
            architecture: original_metadata.architecture(),
            little_endian: original_metadata.little_endian(),
            pointer_width: original_metadata.pointer_width(),
            abi: original_metadata.target_abi(),
            features: AotCountCpuFeatures::from_bits(mutated_features)
                .expect("known one-bit SVE2 near miss"),
        };
        let target_identity = compute_count_target_identity_v3(
            original_metadata.object_format(),
            support,
            target,
            original_metadata.tuning_class_id(),
            original_metadata.register_plan_id(),
            original_metadata.required_isa_id(),
        );
        let target_start =
            STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V3 + METADATA_TARGET_IDENTITY_OFFSET_V3;
        expectation[target_start..target_start + 32].copy_from_slice(&target_identity);

        let mut hasher = Sha256::new();
        hasher.update(b"FRE-AOT-STATIC-COUNT-EXPECTATION-IDENTITY\0\x03");
        hasher.update(&expectation[..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3]);
        let expectation_identity: [u8; 32] = hasher.finalize().into();
        expectation[STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3..]
            .copy_from_slice(&expectation_identity);

        let metadata: &[u8; METADATA_BYTES_V3] = expectation
            [STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V3
                ..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3]
            .try_into()
            .expect("fixed metadata range");
        inspect_count_metadata_v3(metadata)
            .expect("near miss remains an internally canonical metadata claim");
        let error = inspect_static_count_expectation_v3(&expectation)
            .expect_err("SVE2 expectation must require both SVE and SVE2");
        assert_eq!(error.at(), "metadata expectation binding");
    }
}

#[test]
fn object_and_receipt_mutations_fail_closed() {
    let compiled = compile(CountObjectFormatV3::Elf64Aarch64);
    let mut object = compiled.implementation_object().as_bytes().to_vec();
    object[64] ^= 1;
    assert!(
        inspect_count_implementation_object_v3(&object, CountCompileLimitsV3::default().object)
            .is_err()
    );
    assert!(
        compiled
            .unsigned_prelink_receipt()
            .validate_candidate(&object, CountCompileLimitsV3::default().object)
            .is_err()
    );
}

#[test]
fn linux_v2_control_wrapper_preserves_v2_metadata_and_payload() {
    let program =
        build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).expect("Count KIR");
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).expect("Count-v2 image");
    let object =
        publish_count_implementation_object_elf_v2(&image, [9; 32], CountObjectLimitsV2::default())
            .expect("qualification v2 ELF");
    let view = inspect_count_implementation_object_elf_v2(
        object.as_bytes(),
        CountObjectLimitsV2::default(),
    )
    .expect("strict v2 ELF inspection");
    assert_eq!(view.metadata_bytes(), object.metadata_bytes());
    assert_eq!(&view.payload()[..image.code().len()], image.code());
}

#[test]
fn local_v2_control_wrapper_is_raw_and_self_inspecting() {
    let program =
        build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).expect("Count KIR");
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).expect("Count-v2 image");
    let object = publish_count_implementation_object_macho_v2(
        &image,
        [10; 32],
        CountObjectLimitsV2::default(),
    )
    .expect("qualification v2 Mach-O");
    let view = crate::inspect_count_implementation_object_v2(
        object.as_bytes(),
        CountObjectLimitsV2::default(),
    )
    .expect("strict v2 Mach-O inspection");
    assert_eq!(view.metadata_bytes(), object.metadata_bytes());
    assert_eq!(&view.payload()[..image.code().len()], image.code());
}
