use fre_aot_optimizer::{
    CountV3OptimizerLimits, CountV3TuningClass, encode_count_recipe_v3, optimize_count_v3,
};
use fre_kernel_ir::{Count, ValidateLimits, build_exact_aggregate};

use crate::{
    AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3, AOT_COUNT_BACKEND_VERSION_V1,
    AOT_COUNT_BACKEND_VERSION_V2, AOT_COUNT_BACKEND_VERSION_V3, AOT_COUNT_IMAGE_SCHEMA_VERSION_V3,
    AotCountCpuFeatures, AotCountImageViewV3, AotCountMappedMetadataV3, CountAotError,
    CountAotResource, CountEmitLimitsV3, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3,
    audit_count_image_v3, audit_count_image_view_v3, audit_count_mapped_code_v3, emit_count_v3,
    emit_v3::IDENTITY_DOMAIN_V3, prospective_count_v3,
};

fn optimized(
    literal: &[u8],
) -> (
    fre_kernel_ir::ExactAggregateProgram<Count>,
    fre_aot_optimizer::OptimizedCountV3,
) {
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default()).unwrap();
    let optimized = optimize_count_v3(
        &program,
        CountV3TuningClass::GenericAarch64,
        CountV3OptimizerLimits::default(),
    )
    .unwrap();
    (program, optimized)
}

#[test]
fn v3_versions_and_identity_domain_are_disjoint() {
    assert_eq!(AOT_COUNT_IMAGE_SCHEMA_VERSION_V3, 3);
    assert_eq!(AOT_COUNT_BACKEND_VERSION_V3.0, 0xa003);
    assert_eq!(AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3, 5);
    assert_ne!(AOT_COUNT_BACKEND_VERSION_V3, AOT_COUNT_BACKEND_VERSION_V1);
    assert_ne!(AOT_COUNT_BACKEND_VERSION_V3, AOT_COUNT_BACKEND_VERSION_V2);
    assert_eq!(IDENTITY_DOMAIN_V3.last(), Some(&3));
    assert!(SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3.iter().all(|row| {
        row.backend_version == AOT_COUNT_BACKEND_VERSION_V3
            && row.backend_version != AOT_COUNT_BACKEND_VERSION_V1
            && row.backend_version != AOT_COUNT_BACKEND_VERSION_V2
            && row.algorithm_version == AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3
    }));
}

#[test]
fn feature_parser_preserves_sve_and_sve2_as_two_bits() {
    let scalable = AotCountCpuFeatures::SVE.union(AotCountCpuFeatures::SVE2);
    assert_eq!(scalable.bits(), 6);
    assert_eq!(AotCountCpuFeatures::from_bits(6), Some(scalable));
    assert_eq!(AotCountCpuFeatures::from_bits(8), None);
}

#[test]
fn selected_recipes_emit_and_independently_audit_across_widths() {
    for literal in [
        &b""[..],
        &b"x"[..],
        &b"aa"[..],
        &b"needle"[..],
        &b"abababab"[..],
        &b"0123456789abcdef"[..],
        &b"0123456789abcdef0123456789abcde"[..],
    ] {
        let (program, optimized) = optimized(literal);
        let recipe = optimized.recipe();
        let prospective = prospective_count_v3(&program, recipe).unwrap();
        let image = emit_count_v3(&program, recipe, CountEmitLimitsV3::default()).unwrap();
        let support = image.support();
        let target = image.target();
        let wire_metadata = AotCountMappedMetadataV3::from_wire_parts(
            support.backend_version.0,
            support.algorithm_version,
            support.kir_semantics_version,
            support.kir_abi_version,
            support.output_kind,
            support.architecture,
            support.little_endian,
            support.pointer_width,
            support.target_abi,
            target.features.bits(),
            support.allowed_features.bits(),
            support.max_literal_bytes,
            support.candidate_block_starts,
            support.vector_bytes,
            support.sve_vector_length_bytes,
            *image.source_identity().as_bytes(),
            image.literal_bytes(),
            image.recipe_manifest().recipe_identity(),
            *image.artifact_identity().as_bytes(),
            u32::try_from(image.code().len()).unwrap(),
        )
        .unwrap();
        assert_eq!(wire_metadata, AotCountMappedMetadataV3::from_image(&image));
        assert_eq!(
            image.recipe_manifest().canonical_recipe(),
            &encode_count_recipe_v3(recipe)
        );
        assert!(u64::from(image.stats().code_bytes) <= prospective.code_bytes_upper_bound);
        assert_eq!(
            audit_count_image_v3(&program, recipe, &image).unwrap(),
            image.build_receipt().audit
        );
        assert_eq!(
            audit_count_image_view_v3(
                &program,
                recipe,
                AotCountImageViewV3::from(&image),
                CountEmitLimitsV3::default(),
            )
            .unwrap(),
            image.build_receipt().audit
        );
        assert_eq!(
            audit_count_mapped_code_v3(
                &program,
                image.recipe_manifest().canonical_recipe(),
                image.code(),
                wire_metadata,
                CountEmitLimitsV3::default(),
            )
            .unwrap(),
            image.build_receipt().audit
        );
    }
}

#[test]
fn every_width_and_tuning_class_stays_inside_the_source_envelope() {
    for tuning in [
        CountV3TuningClass::GenericAarch64,
        CountV3TuningClass::AppleMSeries,
        CountV3TuningClass::NeoverseV2V3,
    ] {
        for width in 0_usize..=32 {
            let literal = (0..width)
                .map(|index| {
                    if index.is_multiple_of(5) {
                        b'a'
                    } else {
                        u8::try_from(index.checked_mul(29).unwrap() % 251).unwrap()
                    }
                })
                .collect::<Vec<_>>();
            let program =
                build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
            let optimized =
                optimize_count_v3(&program, tuning, CountV3OptimizerLimits::default()).unwrap();
            let recipe = optimized.recipe();
            let prospective = prospective_count_v3(&program, recipe).unwrap();
            let image = emit_count_v3(&program, recipe, CountEmitLimitsV3::default()).unwrap();
            let stats = image.stats();
            let audit = audit_count_image_v3(&program, recipe, &image).unwrap();
            assert!(u64::from(stats.code_bytes) <= prospective.code_bytes_upper_bound);
            assert!(u64::from(stats.labels) <= prospective.labels_upper_bound);
            assert!(u64::from(stats.relocations) <= prospective.relocations_upper_bound);
            assert!(stats.identity_bytes_hashed <= prospective.identity_bytes_hashed_upper_bound);
            assert_eq!(
                stats.total_work_upper_bound,
                prospective.total_work_upper_bound
            );
            assert_eq!(
                stats.scratch_bytes_upper_bound,
                prospective.scratch_bytes_upper_bound
            );
            assert_eq!(audit, image.build_receipt().audit);
            assert_eq!(
                image.target().features,
                if width == 0 {
                    AotCountCpuFeatures::NONE
                } else {
                    AotCountCpuFeatures::ASIMD
                }
            );
        }
    }
}

#[test]
fn audit_rejects_code_and_recipe_manifest_mutation() {
    let (program, optimized) = optimized(b"abababab");
    let recipe = optimized.recipe();
    let mut code = emit_count_v3(&program, recipe, CountEmitLimitsV3::default()).unwrap();
    code.code[0] ^= 1;
    assert!(audit_count_image_v3(&program, recipe, &code).is_err());

    let mut manifest = emit_count_v3(&program, recipe, CountEmitLimitsV3::default()).unwrap();
    manifest.recipe_manifest.schedule_id ^= 1;
    assert!(audit_count_image_v3(&program, recipe, &manifest).is_err());
}

#[test]
fn every_prospective_limit_is_refused_one_below() {
    let (program, optimized) = optimized(b"0123456789abcdef");
    let recipe = optimized.recipe();
    let prospective = prospective_count_v3(&program, recipe).unwrap();
    for (resource, required) in [
        (
            CountAotResource::CodeBytes,
            prospective.code_bytes_upper_bound,
        ),
        (CountAotResource::Labels, prospective.labels_upper_bound),
        (
            CountAotResource::Relocations,
            prospective.relocations_upper_bound,
        ),
        (CountAotResource::Work, prospective.total_work_upper_bound),
        (
            CountAotResource::ScratchBytes,
            prospective.scratch_bytes_upper_bound,
        ),
        (
            CountAotResource::PersistentBytes,
            prospective.persistent_bytes_upper_bound,
        ),
    ] {
        let mut limits = CountEmitLimitsV3::default();
        let refused = required.saturating_sub(1);
        match resource {
            CountAotResource::CodeBytes => limits.max_code_bytes = refused,
            CountAotResource::Labels => limits.max_labels = refused,
            CountAotResource::Relocations => limits.max_relocations = refused,
            CountAotResource::Work => limits.max_work = refused,
            CountAotResource::ScratchBytes => limits.max_scratch_bytes = refused,
            CountAotResource::PersistentBytes => limits.max_persistent_bytes = refused,
            CountAotResource::DataBytes => unreachable!(),
            _ => unreachable!(),
        }
        assert!(matches!(
            emit_count_v3(&program, recipe, limits),
            Err(CountAotError::ResourceLimit {
                resource: observed,
                ..
            }) if observed == resource
        ));
    }
}
