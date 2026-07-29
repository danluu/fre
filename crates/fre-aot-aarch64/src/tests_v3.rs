use fre_aot_optimizer::{
    CountV3OptimizerLimits, CountV3RegisterPlanId, CountV3RequiredIsa, CountV3Strategy,
    CountV3TuningClass, encode_count_recipe_v3, optimize_count_v3, optimize_count_v3_for_isa,
};
use fre_kernel_ir::{Count, ValidateLimits, build_exact_aggregate};

use crate::{
    AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3, AOT_COUNT_BACKEND_VERSION_V1,
    AOT_COUNT_BACKEND_VERSION_V2, AOT_COUNT_BACKEND_VERSION_V3, AOT_COUNT_IMAGE_SCHEMA_VERSION_V3,
    AotCountCpuFeatures, AotCountImageViewV3, AotCountMappedMetadataV3, CountAotError,
    CountAotResource, CountEmitLimitsV3, LabelKindV3, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3,
    audit_count_image_v3, audit_count_image_view_v3, audit_count_mapped_code_v3,
    audit_v3::{DecodedInstructionV3, decode_word_v3},
    emit_count_v3,
    emit_v3::IDENTITY_DOMAIN_V3,
    prospective_count_v3,
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

fn optimized_for(
    literal: &[u8],
    required_isa: CountV3RequiredIsa,
) -> (
    fre_kernel_ir::ExactAggregateProgram<Count>,
    fre_aot_optimizer::OptimizedCountV3,
) {
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default()).unwrap();
    let optimized = optimize_count_v3_for_isa(
        &program,
        CountV3TuningClass::GenericAarch64,
        required_isa,
        CountV3OptimizerLimits::default(),
    )
    .unwrap();
    (program, optimized)
}

fn decoded_v3(image: &crate::AotCountImageV3) -> Vec<DecodedInstructionV3> {
    image
        .code()
        .chunks_exact(4)
        .enumerate()
        .map(|(index, bytes)| {
            decode_word_v3(
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                u32::try_from(index * 4).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

fn branch_target_v3(instructions: &[DecodedInstructionV3], index: usize) -> u32 {
    let displacement = match instructions[index] {
        DecodedInstructionV3::Branch { displacement }
        | DecodedInstructionV3::BranchCondition { displacement, .. } => displacement,
        _ => panic!("instruction at {index} is not a branch"),
    };
    let offset = i64::try_from(index.checked_mul(4).unwrap()).unwrap();
    u32::try_from(offset.checked_add(i64::from(displacement)).unwrap()).unwrap()
}

#[test]
fn v3_versions_and_identity_domain_are_disjoint() {
    assert_eq!(AOT_COUNT_IMAGE_SCHEMA_VERSION_V3, 3);
    assert_eq!(AOT_COUNT_BACKEND_VERSION_V3.0, 0xa003);
    assert_eq!(AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3, 7);
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
fn target_aware_sve_rows_emit_real_independently_audited_opcodes() {
    for (required_isa, register_plan, features, support_index, expect_match) in [
        (
            CountV3RequiredIsa::Aarch64SveVl16,
            CountV3RegisterPlanId::Aarch64SveVl16V1,
            AotCountCpuFeatures::SVE,
            1,
            false,
        ),
        (
            CountV3RequiredIsa::Aarch64Sve2Vl16,
            CountV3RegisterPlanId::Aarch64Sve2Vl16V1,
            AotCountCpuFeatures::SVE.union(AotCountCpuFeatures::SVE2),
            2,
            true,
        ),
    ] {
        for literal in [&b"x"[..], &b"abc"[..], &b"target-aware-sve"[..]] {
            let (program, optimized) = optimized_for(literal, required_isa);
            assert_eq!(optimized.recipe().register_plan_id(), register_plan);
            let image =
                emit_count_v3(&program, optimized.recipe(), CountEmitLimitsV3::default()).unwrap();
            assert_eq!(
                image.support(),
                SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[support_index]
            );
            assert_eq!(image.target().features, features);
            assert_eq!(image.support().vector_bytes, 16);
            assert_eq!(image.support().sve_vector_length_bytes, 16);
            let decoded = decoded_v3(&image);
            assert!(decoded.iter().any(|instruction| matches!(
                instruction,
                DecodedInstructionV3::SvePtrueBytesVl16 { .. }
            )));
            assert_eq!(
                decoded.iter().any(|instruction| matches!(
                    instruction,
                    DecodedInstructionV3::Sve2MatchBytes { .. }
                )),
                expect_match
            );
            assert_eq!(
                audit_count_image_v3(&program, optimized.recipe(), &image).unwrap(),
                image.build_receipt().audit
            );
        }
    }

    let (empty_program, empty_optimized) = optimized_for(b"", CountV3RequiredIsa::Aarch64Sve2Vl16);
    let empty = emit_count_v3(
        &empty_program,
        empty_optimized.recipe(),
        CountEmitLimitsV3::default(),
    )
    .unwrap();
    assert_eq!(empty.support(), SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3[2]);
    assert_eq!(empty.target().features, AotCountCpuFeatures::NONE);
    assert!(
        decoded_v3(&empty)
            .iter()
            .all(|instruction| !matches!(instruction, DecodedInstructionV3::Sve2MatchBytes { .. }))
    );
    assert_eq!(
        audit_count_image_v3(&empty_program, empty_optimized.recipe(), &empty).unwrap(),
        empty.build_receipt().audit
    );
}

#[test]
fn sve_decoder_and_metadata_reject_near_miss_feature_relabeling() {
    assert_eq!(
        decode_word_v3(0x2518_e120, 0).unwrap(),
        DecodedInstructionV3::SvePtrueBytesVl16 { destination: 0 }
    );
    assert!(matches!(
        decode_word_v3(0x2403_a001, 4).unwrap(),
        DecodedInstructionV3::SveCompareEqualBytes { .. }
    ));
    assert!(matches!(
        decode_word_v3(0x4523_8001, 8).unwrap(),
        DecodedInstructionV3::Sve2MatchBytes { .. }
    ));
    assert!(decode_word_v3(0x4523_8001 ^ (1 << 13), 8).is_err());

    let (program, optimized) = optimized_for(
        b"metadata-cannot-relabel-opcodes",
        CountV3RequiredIsa::Aarch64Sve2Vl16,
    );
    let mut image =
        emit_count_v3(&program, optimized.recipe(), CountEmitLimitsV3::default()).unwrap();
    image.target.features = AotCountCpuFeatures::SVE;
    assert!(audit_count_image_v3(&program, optimized.recipe(), &image).is_err());
}

#[test]
fn selected_recipes_emit_and_independently_audit_across_widths() {
    for literal in [
        &b""[..],
        &b"x"[..],
        &b"aa"[..],
        &b"abc"[..],
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
fn direct_masks_and_periodic_absence_batching_have_distinct_graphs() {
    let (direct_program, direct_optimized) = optimized(b"abc");
    assert_eq!(
        direct_optimized.recipe().strategy(),
        CountV3Strategy::DirectExactMask
    );
    let direct = emit_count_v3(
        &direct_program,
        direct_optimized.recipe(),
        CountEmitLimitsV3::default(),
    )
    .unwrap();
    assert_eq!(direct.build_receipt().audit.simd_candidate_blocks, 0);
    assert_eq!(direct.build_receipt().audit.sparse_lane_recoveries, 0);
    assert_eq!(
        direct
            .labels()
            .iter()
            .filter(|label| label.kind == LabelKindV3::VectorLoop)
            .count(),
        2
    );

    let (periodic_program, periodic_optimized) = optimized(b"aeaeaeaeae");
    assert_eq!(
        periodic_optimized.recipe().strategy(),
        CountV3Strategy::PeriodicRun
    );
    let periodic = emit_count_v3(
        &periodic_program,
        periodic_optimized.recipe(),
        CountEmitLimitsV3::default(),
    )
    .unwrap();
    assert!(
        periodic
            .labels()
            .iter()
            .filter(|label| label.kind == LabelKindV3::VectorLoop)
            .count()
            >= 2
    );
    assert!(
        periodic
            .labels()
            .iter()
            .filter(|label| label.kind == LabelKindV3::CandidateLoop)
            .count()
            >= 2
    );
    assert_eq!(
        audit_count_image_v3(&periodic_program, periodic_optimized.recipe(), &periodic).unwrap(),
        periodic.build_receipt().audit
    );
}

#[test]
fn primary_empty_scan_is_single_column_and_pair_fallback_is_disjoint() {
    let (program, optimized) = optimized(b"abababab");
    assert_eq!(optimized.recipe().strategy(), CountV3Strategy::PeriodicRun);
    let image = emit_count_v3(&program, optimized.recipe(), CountEmitLimitsV3::default()).unwrap();
    let decoded = decoded_v3(&image);

    // The ordinary block proves the primary mask empty before loading the
    // secondary column. This branch is the only entry to the one-column scan.
    let primary_probe = decoded
        .windows(5)
        .position(|window| {
            window[0]
                == DecodedInstructionV3::CompareEqualBytes16 {
                    destination: 0,
                    left: 0,
                    right: 2,
                }
                && window[1]
                    == DecodedInstructionV3::UnsignedMaxAcrossBytes16 {
                        destination: 1,
                        source: 0,
                    }
                && window[2]
                    == DecodedInstructionV3::MoveVectorByteTo32 {
                        destination: 8,
                        source: 1,
                    }
                && window[3]
                    == DecodedInstructionV3::CompareImmediate64 {
                        register: 8,
                        immediate: 0,
                    }
                && matches!(
                    window[4],
                    DecodedInstructionV3::BranchCondition {
                        condition: crate::ConditionV3::Equal,
                        ..
                    }
                )
        })
        .expect("ordinary primary-empty proof");
    let primary_scan_offset = branch_target_v3(&decoded, primary_probe + 4);
    let primary_scan = usize::try_from(primary_scan_offset / 4).unwrap();
    assert_eq!(
        decoded[primary_scan],
        DecodedInstructionV3::AddImmediate64 {
            destination: 3,
            source: 3,
            immediate: 16,
        }
    );
    assert_eq!(
        decoded[primary_scan + 4],
        DecodedInstructionV3::CompareImmediate64 {
            register: 5,
            immediate: 127,
        }
    );
    for block in 0_u16..8 {
        let index = primary_scan + 8 + usize::from(block) * 2;
        let mask = u8::try_from(24 + block).unwrap();
        assert_eq!(
            decoded[index],
            DecodedInstructionV3::LoadVector128 {
                destination: mask,
                base: 8,
                offset: block * 16,
            }
        );
        assert_eq!(
            decoded[index + 1],
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: mask,
                left: mask,
                right: 2,
            }
        );
    }
    let next_primary_iteration = decoded
        .iter()
        .enumerate()
        .skip(primary_scan + 24)
        .take(24)
        .find(|(index, instruction)| {
            matches!(instruction, DecodedInstructionV3::Branch { .. })
                && branch_target_v3(&decoded, *index) == primary_scan_offset
        })
        .map(|(index, _)| index)
        .expect("primary sparse loop backedge");
    assert_eq!(
        decoded[next_primary_iteration - 1],
        DecodedInstructionV3::AddImmediate64 {
            destination: 3,
            source: 3,
            immediate: 112,
        }
    );

    // A primary-present block whose complete filter is empty branches to a
    // separate pair scan. The two loads and comparisons per block are retained
    // here, preventing common-primary adversarial input from using the
    // one-column scan.
    let composite_probe = decoded
        .windows(2)
        .enumerate()
        .skip(primary_probe + 5)
        .find(|(_, window)| {
            window[0]
                == DecodedInstructionV3::CompareImmediate64 {
                    register: 6,
                    immediate: 0,
                }
                && matches!(
                    window[1],
                    DecodedInstructionV3::BranchCondition {
                        condition: crate::ConditionV3::Equal,
                        ..
                    }
                )
        })
        .map(|(index, _)| index)
        .expect("composite-empty proof");
    let pair_scan_offset = branch_target_v3(&decoded, composite_probe + 1);
    assert_ne!(pair_scan_offset, primary_scan_offset);
    let pair_scan = usize::try_from(pair_scan_offset / 4).unwrap();
    assert_eq!(
        decoded[pair_scan + 4],
        DecodedInstructionV3::CompareImmediate64 {
            register: 5,
            immediate: 127,
        }
    );
    for block in 0_u16..8 {
        let index = pair_scan + 9 + usize::from(block) * 5;
        let mask = u8::try_from(24 + block).unwrap();
        assert_eq!(
            decoded[index],
            DecodedInstructionV3::LoadVector128 {
                destination: 0,
                base: 8,
                offset: block * 16,
            }
        );
        assert_eq!(
            decoded[index + 1],
            DecodedInstructionV3::LoadVector128 {
                destination: 1,
                base: 9,
                offset: block * 16,
            }
        );
        assert_eq!(
            decoded[index + 2],
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: 2,
            }
        );
        assert_eq!(
            decoded[index + 3],
            DecodedInstructionV3::CompareEqualBytes16 {
                destination: 1,
                left: 1,
                right: 3,
            }
        );
        assert_eq!(
            decoded[index + 4],
            DecodedInstructionV3::AndBytes16 {
                destination: mask,
                left: 0,
                right: 1,
            }
        );
    }
    assert_eq!(
        audit_count_image_v3(&program, optimized.recipe(), &image).unwrap(),
        image.build_receipt().audit
    );
}

#[test]
fn every_direct_vector_head_guards_exact_exhaustion_before_subtraction() {
    for required_isa in [
        CountV3RequiredIsa::Aarch64Neon128,
        CountV3RequiredIsa::Aarch64SveVl16,
        CountV3RequiredIsa::Aarch64Sve2Vl16,
    ] {
        let (program, optimized) = optimized_for(b"abc", required_isa);
        let image =
            emit_count_v3(&program, optimized.recipe(), CountEmitLimitsV3::default()).unwrap();
        let decoded = decoded_v3(&image);
        let vector_heads = image
            .labels()
            .iter()
            .filter(|label| label.kind == LabelKindV3::VectorLoop)
            .collect::<Vec<_>>();
        assert_eq!(vector_heads.len(), 2);
        for head in vector_heads {
            let index = usize::try_from(head.offset / 4).unwrap();
            assert_eq!(
                decoded[index],
                DecodedInstructionV3::CompareRegister64 { left: 3, right: 4 }
            );
            assert!(matches!(
                decoded[index + 1],
                DecodedInstructionV3::BranchCondition {
                    condition: crate::ConditionV3::Higher,
                    ..
                }
            ));
            assert!(matches!(
                decoded[index + 2],
                DecodedInstructionV3::SubtractRegister64 {
                    destination: 6,
                    left: 4,
                    right: 3
                }
            ));
        }
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
