use fre_aot_aarch64::{
    CountEmitLimitsV2, CountEmitLimitsV3, audit_count_mapped_code_v3, emit_count_v2,
};
use fre_aot_count_contract::v3::{
    METADATA_BYTES_V3, inspect_count_metadata_v3, inspect_static_count_expectation_v3,
};
use fre_aot_optimizer::{
    CountV3RequiredIsa, CountV3TuningClass, encode_count_recipe_v3,
    inspect_count_v3_optimizer_receipt,
};
use fre_kernel_ir::{Count, ValidateLimits, build_exact_aggregate};

use crate::{
    CountCompileLimitsV3, CountCompileRequestV3, CountCompileTargetV3, CountObjectFormatV3,
    CountObjectLimitsV2, CountSemanticCandidateV3, RuntimeAuthorityV3, compile_count_v3,
    inspect_count_implementation_object_elf_v2, inspect_count_implementation_object_v3,
    publish_count_implementation_object_elf_v2,
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
    compile_count_v3(
        CountCompileRequestV3 {
            literal: b"needle",
            semantic_candidate: candidate(),
            target: CountCompileTargetV3 {
                object_format: format,
                tuning_class: CountV3TuningClass::GenericAarch64,
                required_isa: CountV3RequiredIsa::Aarch64Neon128,
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
    assert_eq!(
        expectation.metadata().general_eligibility_tuple(),
        compiled
            .general_eligibility_tuple()
            .expect("eligibility tuple")
    );
    assert_eq!(compiled.runtime_authority(), RuntimeAuthorityV3::Absent);
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
