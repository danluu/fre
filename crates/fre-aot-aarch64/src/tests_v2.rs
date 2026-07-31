#![allow(
    clippy::arithmetic_side_effects,
    clippy::field_reassign_with_default,
    reason = "bounded adversarial test models intentionally use direct index arithmetic and mutate one limit at a time"
)]

use fre_exact_alloc::ExactVec;
use fre_kernel_ir::{Count, ValidateLimits, build_exact_aggregate};

use crate::{
    AOT_COUNT_BACKEND_ALGORITHM_VERSION_SPARSE_V3, AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2,
    AOT_COUNT_BACKEND_VERSION_V1, AOT_COUNT_BACKEND_VERSION_V2, AotCountCpuFeatures,
    AotCountImageV2, CountAotArithmeticSite, CountAotError, CountAotResource, CountEmitLimitsV1,
    CountEmitLimitsV2, LabelKindV2, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2, audit_count_image_v2,
    audit_v2::{
        DecodedInstructionV2, audit_count_image_with_scratch_limit_for_test_v2,
        audit_work_components_v2, independent_filter_meter_overflow_for_test_v2,
        independent_filter_observed_work_for_test_v2, independent_filter_work_envelope_v2,
    },
    emit_count_v1, emit_count_v2,
    emit_v2::{
        EmitImagePhaseForTestV2, artifact_identity_encoded_len_v2,
        candidate_filter_meter_overflow_for_test_v2, candidate_filter_observed_work_for_test_v2,
        candidate_filter_v2, candidate_filter_work_envelope_v2, compute_artifact_identity_v2,
        identity_bytes_upper_bound_v2, identity_structural_traversal_work_v2,
        observe_emit_image_phase_scratch_for_test_v2, rare_pair_v2,
    },
    is_supported_aot_count_backend_tuple_v2, prospective_count_v2,
};

#[allow(
    clippy::manual_div_ceil,
    reason = "the benchmark fixture keeps its dependency-free pinned expression"
)]
#[path = "../benches/fixtures/count_v2_dense_absent.rs"]
mod dense_absent_fixtures;

fn exact_with_extra<T: Copy>(values: &[T], extra: usize) -> ExactVec<T> {
    let capacity = values.len().checked_add(extra).unwrap();
    let mut result = ExactVec::try_with_capacity(capacity).unwrap();
    for value in values.iter().copied() {
        result.try_push(value).ok().unwrap();
    }
    result
}

fn reseal_v2(image: &mut AotCountImageV2) {
    let (identity, bytes) = compute_artifact_identity_v2(image).unwrap();
    assert_eq!(bytes, image.stats.identity_bytes_hashed);
    image.artifact_identity = identity;
}

fn independently_count_filter_stage(literal: &[u8], selected_offsets: &[usize]) -> (u64, u64, u64) {
    let mut byte_visits = 0_u64;
    let mut contains_probes = 0_u64;
    let mut value_probes = 0_u64;
    for (index, byte) in literal.iter().copied().enumerate() {
        byte_visits = byte_visits.checked_add(1).unwrap();
        let mut selected = false;
        for offset in selected_offsets {
            contains_probes = contains_probes.checked_add(1).unwrap();
            if *offset == index {
                selected = true;
                break;
            }
        }
        if selected {
            continue;
        }
        for offset in selected_offsets {
            value_probes = value_probes.checked_add(1).unwrap();
            if literal[*offset] == byte {
                break;
            }
        }
    }
    (byte_visits, contains_probes, value_probes)
}

#[test]
fn v2_is_numerically_and_structurally_disjoint_from_v1() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let v1 = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    let v2 = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();

    assert_eq!(v1.backend_version(), AOT_COUNT_BACKEND_VERSION_V1);
    assert_eq!(v2.backend_version(), AOT_COUNT_BACKEND_VERSION_V2);
    assert_ne!(v1.backend_version(), v2.backend_version());
    assert_ne!(v1.code(), v2.code());
    assert!(v1.rodata().is_empty());
    assert!(v2.rodata().is_empty());
}

#[test]
fn adaptive_template_advances_and_enforces_the_algorithm_contract() {
    assert_eq!(AOT_COUNT_BACKEND_ALGORITHM_VERSION_SPARSE_V3, 3);
    assert_eq!(AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2, 4);
    let current = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];
    assert_eq!(
        current.algorithm_version,
        AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2
    );
    assert!(is_supported_aot_count_backend_tuple_v2(current));

    let predecessor = crate::AotCountBackendSupportV2 {
        algorithm_version: AOT_COUNT_BACKEND_ALGORITHM_VERSION_SPARSE_V3,
        ..current
    };
    assert!(!is_supported_aot_count_backend_tuple_v2(predecessor));
    assert!(!is_supported_aot_count_backend_tuple_v2(
        crate::AotCountBackendSupportV2 {
            algorithm_version: 2,
            ..current
        }
    ));

    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    assert_eq!(
        image.support().algorithm_version,
        AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2
    );

    let current_identity = image.artifact_identity();
    let mut stale_tuple = image;
    stale_tuple.support.algorithm_version = AOT_COUNT_BACKEND_ALGORITHM_VERSION_SPARSE_V3;
    stale_tuple.build_receipt.support.algorithm_version =
        AOT_COUNT_BACKEND_ALGORITHM_VERSION_SPARSE_V3;
    reseal_v2(&mut stale_tuple);
    assert_ne!(stale_tuple.artifact_identity(), current_identity);
    assert!(matches!(
        audit_count_image_v2(&program, &stale_tuple),
        Err(CountAotError::InvalidImage {
            at: "v2 support tuple"
        })
    ));
}

#[test]
fn v2_artifact_identity_binds_decode_and_source_rebuild_multiplicities() {
    let program =
        build_exact_aggregate::<Count>(b"audit-passes", ValidateLimits::default()).unwrap();
    let baseline = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();

    let mut changed_decode = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    changed_decode.build_receipt.audit.decode_passes = changed_decode
        .build_receipt
        .audit
        .decode_passes
        .checked_add(1)
        .unwrap();
    reseal_v2(&mut changed_decode);
    assert_ne!(
        changed_decode.artifact_identity(),
        baseline.artifact_identity()
    );
    assert!(audit_count_image_v2(&program, &changed_decode).is_err());

    let mut changed_rebuild = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    changed_rebuild.build_receipt.audit.source_identity_rebuilds = changed_rebuild
        .build_receipt
        .audit
        .source_identity_rebuilds
        .checked_add(1)
        .unwrap();
    reseal_v2(&mut changed_rebuild);
    assert_ne!(
        changed_rebuild.artifact_identity(),
        baseline.artifact_identity()
    );
    assert!(audit_count_image_v2(&program, &changed_rebuild).is_err());
}

#[test]
fn rare_pair_selection_matches_the_pinned_frequency_policy() {
    assert_eq!(rare_pair_v2(b""), None);
    assert_eq!(rare_pair_v2(b"a"), None);
    assert_eq!(rare_pair_v2(b"0123456789abcdef"), Some((7, 6)));
    assert_eq!(rare_pair_v2(b"Sherlock Holmes"), Some((9, 7)));
    assert_eq!(rare_pair_v2(&[b'a'; 32]), Some((0, 1)));

    let filter = candidate_filter_v2(b"0123456789abcdef").unwrap();
    assert_eq!(filter.offsets(), &[7, 6, 8, 5]);
    assert_eq!(filter.len(), 4);
    let selected = filter
        .offsets()
        .iter()
        .map(|offset| b"0123456789abcdef"[usize::from(*offset)])
        .collect::<Vec<_>>();
    assert_eq!(selected, b"7685");
}

#[test]
fn every_width_stays_inside_its_source_only_resource_formula() {
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
        let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
        let prospective = prospective_count_v2(&program).unwrap();
        let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
        let stats = image.stats();
        let audit = audit_count_image_v2(&program, &image).unwrap();

        assert_eq!(image.backend_version(), AOT_COUNT_BACKEND_VERSION_V2);
        assert!(u64::from(stats.code_bytes) <= prospective.code_bytes_upper_bound);
        assert!(u64::from(stats.labels) <= prospective.labels_upper_bound);
        assert!(u64::from(stats.relocations) <= prospective.relocations_upper_bound);
        assert_eq!(stats.data_bytes, 0);
        assert_eq!(
            stats.audit_work_upper_bound,
            prospective.audit_work_upper_bound
        );
        assert_eq!(
            stats.total_work_upper_bound,
            prospective.total_work_upper_bound
        );
        assert!(stats.identity_bytes_hashed <= prospective.identity_bytes_hashed_upper_bound);
        assert_eq!(
            stats.scratch_bytes_upper_bound,
            prospective.scratch_bytes_upper_bound
        );
        assert_eq!(
            audit.scratch_bytes_upper_bound,
            prospective.audit_scratch_bytes_upper_bound
        );
        assert_eq!(audit.decode_passes, 1);
        assert_eq!(audit.source_identity_rebuilds, 0);
        let retained = image
            .build_receipt()
            .retained_heap_bytes
            .checked_add(image.build_receipt().inline_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .unwrap();
        assert!(retained <= prospective.persistent_bytes_upper_bound);
        assert!(
            image.build_receipt().emission_peak_scratch_bytes
                <= prospective.emission_scratch_bytes_upper_bound
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
        if width >= 2 {
            let expected_filter = candidate_filter_v2(&literal).unwrap();
            assert_eq!(audit.simd_candidate_blocks, 2);
            assert_eq!(audit.sparse_lane_recoveries, 1);
            assert_eq!(
                image.literal_manifest().candidate_pair(),
                rare_pair_v2(&literal)
            );
            assert_eq!(
                image.literal_manifest().candidate_filter_offsets(),
                expected_filter.offsets()
            );
            assert_eq!(
                audit.staged_filter_checks,
                u32::from(
                    image
                        .literal_manifest()
                        .candidate_filter_len()
                        .saturating_sub(3)
                )
            );
        } else {
            assert_eq!(audit.simd_candidate_blocks, 0);
            assert_eq!(audit.sparse_lane_recoveries, 0);
            assert_eq!(image.literal_manifest().candidate_pair(), None);
            assert!(
                image
                    .literal_manifest()
                    .candidate_filter_offsets()
                    .is_empty()
            );
        }
    }
}

#[test]
fn named_v2_audit_work_recomposes_every_width_and_identity_pass() {
    for width in 0_usize..=32 {
        let literal = (0..width)
            .map(|index| u8::try_from((index * 37) % 251).unwrap())
            .collect::<Vec<_>>();
        let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
        let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
        let prospective = prospective_count_v2(&program).unwrap();
        let components = audit_work_components_v2(
            usize::try_from(prospective.code_bytes_upper_bound).unwrap(),
            usize::try_from(prospective.labels_upper_bound).unwrap(),
            usize::try_from(prospective.relocations_upper_bound).unwrap(),
            width,
        )
        .unwrap();
        let recomposed = components
            .support_target_layout_and_seals
            .checked_add(components.manifest_and_filter_selection)
            .and_then(|work| work.checked_add(components.decode))
            .and_then(|work| work.checked_add(components.canonical_policy_regeneration))
            .and_then(|work| work.checked_add(components.canonical_label_order))
            .and_then(|work| work.checked_add(components.canonical_compare))
            .and_then(|work| work.checked_add(components.cfg_and_relocations))
            .and_then(|work| work.checked_add(components.identity_structural_traversal))
            .and_then(|work| work.checked_add(components.identity_hash_bytes))
            .and_then(|work| work.checked_add(components.identity_hash_finalization))
            .and_then(|work| work.checked_add(components.scratch_and_allocation_accounting))
            .unwrap();
        assert_eq!(components.total, recomposed);
        assert_eq!(components.total, prospective.audit_work_upper_bound);

        let structural = identity_structural_traversal_work_v2(
            prospective.labels_upper_bound,
            prospective.relocations_upper_bound,
        )
        .unwrap();
        assert_eq!(components.identity_structural_traversal, structural * 2);
        assert_eq!(
            components.identity_hash_bytes,
            prospective.identity_bytes_hashed_upper_bound
        );
        assert_eq!(
            identity_bytes_upper_bound_v2(
                usize::try_from(prospective.code_bytes_upper_bound).unwrap(),
                usize::try_from(prospective.labels_upper_bound).unwrap(),
                usize::try_from(prospective.relocations_upper_bound).unwrap(),
            )
            .unwrap(),
            prospective.identity_bytes_hashed_upper_bound
        );
        assert_eq!(
            artifact_identity_encoded_len_v2(&image).unwrap(),
            identity_bytes_upper_bound_v2(
                image.code().len(),
                image.labels().len(),
                image.relocations().len(),
            )
            .unwrap()
        );
    }
    // The fixed writes include both audit multiplicity fields. This exact
    // witness prevents a new identity field from silently under-accounting
    // every direct identity and independent audit traversal.
    let fixed_identity_writes = identity_structural_traversal_work_v2(0, 0).unwrap();
    assert_eq!(fixed_identity_writes, 65);
    let empty_audit = audit_work_components_v2(0, 0, 0, 0).unwrap();
    assert_eq!(empty_audit.identity_structural_traversal, 130);
    assert_eq!(fixed_identity_writes * 3, 195);
    assert_eq!(empty_audit.identity_structural_traversal * 2, 260);
    assert_eq!(
        fixed_identity_writes * 3 + empty_audit.identity_structural_traversal * 2,
        455
    );
    assert!(identity_structural_traversal_work_v2(u64::MAX, 0).is_none());
    assert!(identity_structural_traversal_work_v2(0, u64::MAX).is_none());
}

#[test]
fn width32_three_value_filter_scans_have_independent_probe_witnesses() {
    let literal = (0_usize..32)
        .map(|index| u8::try_from(index % 3).unwrap())
        .collect::<Vec<_>>();
    let filter = candidate_filter_v2(&literal).unwrap();
    assert_eq!(filter.offsets(), &[2, 1, 0]);

    let initial_byte_visits = u64::try_from(literal.len()).unwrap();
    let two_offset = independently_count_filter_stage(&literal, &[2, 1]);
    let three_offset = independently_count_filter_stage(&literal, &[2, 1, 0]);
    let emitter = candidate_filter_observed_work_for_test_v2(&literal).unwrap();
    let auditor = independent_filter_observed_work_for_test_v2(&literal).unwrap();
    for observed in [
        (
            emitter.initial_byte_visits,
            emitter.two_offset_byte_visits,
            emitter.two_offset_contains_probes,
            emitter.two_offset_value_probes,
            emitter.three_offset_byte_visits,
            emitter.three_offset_contains_probes,
            emitter.three_offset_value_probes,
            emitter.total().unwrap(),
        ),
        (
            auditor.initial_byte_visits,
            auditor.two_offset_byte_visits,
            auditor.two_offset_contains_probes,
            auditor.two_offset_value_probes,
            auditor.three_offset_byte_visits,
            auditor.three_offset_contains_probes,
            auditor.three_offset_value_probes,
            auditor.total().unwrap(),
        ),
    ] {
        assert_eq!(observed.0, initial_byte_visits);
        assert_eq!((observed.1, observed.2, observed.3), two_offset);
        assert_eq!((observed.4, observed.5, observed.6), three_offset);
        assert_eq!(
            observed.7,
            initial_byte_visits
                .checked_add(two_offset.0)
                .and_then(|work| work.checked_add(two_offset.1))
                .and_then(|work| work.checked_add(two_offset.2))
                .and_then(|work| work.checked_add(three_offset.0))
                .and_then(|work| work.checked_add(three_offset.1))
                .and_then(|work| work.checked_add(three_offset.2))
                .unwrap()
        );
    }

    let emitter_envelope = candidate_filter_work_envelope_v2(literal.len()).unwrap();
    let auditor_envelope = independent_filter_work_envelope_v2(literal.len()).unwrap();
    assert_eq!(emitter_envelope.initial_scan, 32);
    assert_eq!(emitter_envelope.two_offset_scan, 32 * 5);
    assert_eq!(emitter_envelope.three_offset_scan, 32 * 7);
    assert_eq!(emitter_envelope.total, 32 * 13);
    assert_eq!(auditor_envelope.initial_scan, emitter_envelope.initial_scan);
    assert_eq!(
        auditor_envelope.two_offset_scan,
        emitter_envelope.two_offset_scan
    );
    assert_eq!(
        auditor_envelope.three_offset_scan,
        emitter_envelope.three_offset_scan
    );
    assert_eq!(auditor_envelope.total, emitter_envelope.total);
    assert!(emitter.total().unwrap() <= emitter_envelope.total);
    assert!(auditor.total().unwrap() <= auditor_envelope.total);

    let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
    let exact = prospective_count_v2(&program)
        .unwrap()
        .total_work_upper_bound;
    emit_count_v2(
        &program,
        CountEmitLimitsV2 {
            max_work: exact,
            ..CountEmitLimitsV2::default()
        },
    )
    .unwrap();
    let one_below = exact.checked_sub(1).unwrap();
    assert_eq!(
        emit_count_v2(
            &program,
            CountEmitLimitsV2 {
                max_work: one_below,
                // This competing later refusal proves selection cannot start
                // before the combined work envelope has been admitted.
                max_persistent_bytes: 0,
                ..CountEmitLimitsV2::default()
            },
        ),
        Err(CountAotError::ResourceLimit {
            resource: CountAotResource::Work,
            limit: one_below,
            required: exact,
        })
    );
}

#[test]
fn ranked_filter_work_arithmetic_and_meters_fail_closed() {
    assert!(matches!(
        candidate_filter_work_envelope_v2(usize::MAX),
        Err(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Prospective,
        })
    ));
    assert!(matches!(
        independent_filter_work_envelope_v2(usize::MAX),
        Err(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Audit,
        })
    ));
    assert!(matches!(
        candidate_filter_meter_overflow_for_test_v2(),
        Err(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Prospective,
        })
    ));
    assert!(matches!(
        independent_filter_meter_overflow_for_test_v2(),
        Err(CountAotError::ArithmeticOverflow {
            site: CountAotArithmeticSite::Audit,
        })
    ));
}

#[test]
fn exact_v2_work_limit_accepts_and_one_below_refuses_every_width() {
    for width in 0_usize..=32 {
        let literal = vec![b'x'; width];
        let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
        let exact = prospective_count_v2(&program)
            .unwrap()
            .total_work_upper_bound;
        let accepted = emit_count_v2(
            &program,
            CountEmitLimitsV2 {
                max_work: exact,
                ..CountEmitLimitsV2::default()
            },
        )
        .unwrap();
        assert_eq!(accepted.stats().total_work_upper_bound, exact);
        let one_below = exact.checked_sub(1).unwrap();
        assert!(matches!(
            emit_count_v2(
                &program,
                CountEmitLimitsV2 {
                    max_work: one_below,
                    ..CountEmitLimitsV2::default()
                }
            ),
            Err(CountAotError::ResourceLimit {
                resource: CountAotResource::Work,
                limit,
                required,
            }) if limit == one_below && required == exact
        ));
    }
}

#[test]
fn every_v2_audit_and_identity_phase_refuses_one_below_before_work() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    let audit_exact = prospective_count_v2(&program)
        .unwrap()
        .audit_scratch_bytes_upper_bound;
    assert_eq!(
        audit_count_image_with_scratch_limit_for_test_v2(&program, &image, audit_exact,).unwrap(),
        image.build_receipt().audit
    );
    let audit_one_below = audit_exact.checked_sub(1).unwrap();
    assert!(matches!(
        audit_count_image_with_scratch_limit_for_test_v2(
            &program,
            &image,
            audit_one_below,
        ),
        Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit,
            required,
        }) if limit == audit_one_below && required == audit_exact
    ));

    for phase in [
        EmitImagePhaseForTestV2::InitialIdentityLength,
        EmitImagePhaseForTestV2::CandidateAudit,
        EmitImagePhaseForTestV2::SealedIdentityLength,
        EmitImagePhaseForTestV2::SealedIdentityHash,
        EmitImagePhaseForTestV2::SealedAudit,
    ] {
        let exact = observe_emit_image_phase_scratch_for_test_v2(&program, &image, phase, u64::MAX)
            .unwrap();
        let one_below = exact.checked_sub(1).unwrap();
        assert!(matches!(
            observe_emit_image_phase_scratch_for_test_v2(
                &program,
                &image,
                phase,
                one_below,
            ),
            Err(CountAotError::ResourceLimit {
                resource: CountAotResource::ScratchBytes,
                limit,
                required,
            }) if limit == one_below && required == exact
        ));
    }
}

#[test]
fn v2_capacity_persistent_and_scratch_claims_are_independently_sealed() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();

    let mut code_overcapacity = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    code_overcapacity.code = exact_with_extra(code_overcapacity.code.as_slice(), 1);
    assert!(matches!(
        audit_count_image_v2(&program, &code_overcapacity),
        Err(CountAotError::InvalidImage {
            at: "v2 persistent capacity receipt" | "v2 prospective persistent seal"
        })
    ));

    let mut retained_high = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    retained_high.build_receipt.retained_heap_bytes += 1;
    reseal_v2(&mut retained_high);
    assert!(matches!(
        audit_count_image_v2(&program, &retained_high),
        Err(CountAotError::InvalidImage {
            at: "v2 persistent capacity receipt"
        })
    ));

    let mut scratch_low = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    scratch_low.build_receipt.scratch_bytes_upper_bound -= 1;
    reseal_v2(&mut scratch_low);
    assert!(matches!(
        audit_count_image_v2(&program, &scratch_low),
        Err(CountAotError::InvalidImage {
            at: "v2 sealed receipt or identity"
        })
    ));

    let mut emission_high = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    emission_high.build_receipt.emission_peak_scratch_bytes = prospective_count_v2(&program)
        .unwrap()
        .emission_scratch_bytes_upper_bound
        + 1;
    reseal_v2(&mut emission_high);
    assert!(matches!(
        audit_count_image_v2(&program, &emission_high),
        Err(CountAotError::InvalidImage {
            at: "v2 emission scratch receipt"
        })
    ));

    let mut emission_low = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    emission_low.build_receipt.emission_peak_scratch_bytes -= 1;
    reseal_v2(&mut emission_low);
    assert!(matches!(
        audit_count_image_v2(&program, &emission_low),
        Err(CountAotError::InvalidImage {
            at: "v2 emission scratch receipt"
        })
    ));
}

#[test]
fn multi_byte_code_contains_exact_sparse_lane_recovery_in_order() {
    let program =
        build_exact_aggregate::<Count>(b"0123456789abcdef", ValidateLimits::default()).unwrap();
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    let words = image
        .code()
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .collect::<Vec<_>>();

    let shrn = position(&words, |word| word & 0xffff_fc00 == 0x0f0c_8400);
    let fmov = position_after(&words, shrn, |word| word & 0xffff_fc00 == 0x9e66_0000);
    let rbit = position_after(&words, fmov, |word| word & 0xffff_fc00 == 0xdac0_0000);
    let clz = position_after(&words, rbit, |word| word & 0xffff_fc00 == 0xdac0_1000);
    let lsr_two = position_after(&words, clz, |word| {
        word & 0xffc0_0000 == 0xd340_0000
            && ((word >> 16) & 0x3f) == 2
            && ((word >> 10) & 0x3f) == 63
    });

    assert!(shrn < fmov && fmov < rbit && rbit < clz && clz < lsr_two);
    assert_eq!(
        words
            .iter()
            .filter(|word| **word & 0xffff_fc00 == 0x0f0c_8400)
            .count(),
        2
    );

    let staged = words
        .iter()
        .enumerate()
        .filter_map(|(index, word)| {
            (*word & 0xffff_fc00 == 0x6e30_a800 && (*word >> 5).trailing_zeros() >= 5)
                .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(staged.len(), 1);
    for index in staged {
        assert_eq!(words[index + 1] & 0xffff_fc00, 0x0e01_3c00);
        assert_eq!(words[index + 2], 0xf100_011f);
        assert_eq!(words[index + 3] & 0xff00_001f, 0x5400_0000);
        assert_eq!(words[index + 4] & 0xffc0_0000, 0x9100_0000);
        assert_eq!(words[index + 5] & 0xffc0_0000, 0x3dc0_0000);
        assert!(index + 5 < shrn);
    }

    let sparse_or = words
        .iter()
        .filter(|word| {
            **word & 0xffe0_fc00 == 0x4ea0_1c00 && (**word >> 5) & 0x1f == 18 && **word & 0x1f == 18
        })
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(sparse_or.len(), 3);

    let localized_block_masks = words
        .iter()
        .filter_map(|word| {
            (*word & 0xffe0_fc00 == 0x4e20_1c00
                && (*word >> 16) & 0x1f == 1
                && (*word >> 5).trailing_zeros() >= 5
                && matches!(*word & 0x1f, 24..=27))
            .then_some(u8::try_from(*word & 0x1f).unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(localized_block_masks, [24, 25, 26, 27]);
    for (destination, left, right) in [(28, 24, 25), (29, 26, 27), (18, 28, 29)] {
        assert!(words.iter().any(|word| {
            *word & 0xffe0_fc00 == 0x4ea0_1c00
                && *word & 0x1f == destination
                && (*word >> 5) & 0x1f == left
                && (*word >> 16) & 0x1f == right
        }));
    }

    let sparse_reduce = words
        .iter()
        .position(|word| *word & 0xffff_fc00 == 0x6e30_a800 && ((*word >> 5) & 0x1f) == 18)
        .unwrap();
    assert_eq!(words[sparse_reduce + 1] & 0xffff_fc00, 0x0e01_3c00);
    assert_eq!(words[sparse_reduce + 2], 0xf100_011f);
    assert_eq!(words[sparse_reduce + 3] & 0xff00_001f, 0x5400_0001);
}

#[test]
fn shrn_nibble_model_recovers_every_lane_set_in_ascending_order() {
    for lane_flags in 0_u32..=u32::from(u16::MAX) {
        let lane_flags = u16::try_from(lane_flags).unwrap();
        let mut packed = 0_u64;
        for lane in 0_u32..16 {
            if lane_flags & (1_u16 << lane) != 0 {
                packed |= 0xf_u64 << (lane * 4);
            }
        }
        let mut sparse = packed & 0x1111_1111_1111_1111;
        let mut recovered = 0_u16;
        let mut previous = None;
        while sparse != 0 {
            let bit = sparse.trailing_zeros();
            sparse &= sparse - 1;
            let lane = bit / 4;
            if let Some(previous) = previous {
                assert!(previous < lane);
            }
            previous = Some(lane);
            recovered |= 1_u16 << lane;
        }
        assert_eq!(recovered, lane_flags);
    }
}

#[test]
fn pair_density_reduction_classifies_every_possible_lane_count() {
    for hits in 0_u16..=16 {
        let reduced = u8::try_from((u16::from(u8::MAX) * hits) & 0xff).unwrap();
        match hits {
            0 => assert_eq!(reduced, 0),
            1 => assert_eq!(reduced, u8::MAX),
            _ => assert!(reduced != 0 && reduced != u8::MAX),
        }
    }
}

#[test]
fn dense_first_last_filter_remains_intersected_with_the_rare_pair_mask() {
    let program =
        build_exact_aggregate::<Count>(b"0123456789abcdef", ValidateLimits::default()).unwrap();
    let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    let words = image
        .code()
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .collect::<Vec<_>>();
    let density = position(&words, |word| {
        word & 0xffff_fc00 == 0x4e31_b800 && (word >> 5).trailing_zeros() >= 5 && word & 0x1f == 1
    });
    let pair_copy = words
        .iter()
        .skip(density + 1)
        .position(|word| {
            *word & 0xffe0_fc00 == 0x4ea0_1c00
                && (*word >> 16).trailing_zeros() >= 5
                && (*word >> 5).trailing_zeros() >= 5
                && *word & 0x1f == 18
        })
        .map(|position| density + 1 + position)
        .expect("rare-pair mask copied to v18 only on the dense path");
    let dense_intersection = position_after(&words, pair_copy, |word| {
        word & 0xffe0_fc00 == 0x4e20_1c00
            && (word >> 16) & 0x1f == 18
            && (word >> 5).trailing_zeros() >= 5
            && word.trailing_zeros() >= 5
    });
    let dense_shrn = position_after(&words, dense_intersection, |word| {
        word & 0xffff_fc00 == 0x0f0c_8400
    });
    assert!(
        density < pair_copy && pair_copy < dense_intersection && dense_intersection < dense_shrn
    );

    let rare_pair = (1_u16 << 2) | (1_u16 << 9);
    let adversarial_first_last = u16::MAX;
    assert_eq!(rare_pair & adversarial_first_last, rare_pair);
}

#[test]
fn width_one_hoists_256_and_chunk_constants_are_hoisted_once() {
    let single_program = build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).unwrap();
    let single = emit_count_v2(&single_program, CountEmitLimitsV2::default()).unwrap();
    let x5_moves = single
        .code()
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .filter(|word| word & 0x1f == 5 && word & 0xff80_0000 == 0xd280_0000)
        .count();
    assert_eq!(x5_moves, 1);

    let wide_program = build_exact_aggregate::<Count>(
        b"0123456789abcdefghijklmnopqrstuv",
        ValidateLimits::default(),
    )
    .unwrap();
    let wide = emit_count_v2(&wide_program, CountEmitLimitsV2::default()).unwrap();
    let hoisted_doubles = wide
        .code()
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .filter(|word| word & 0xffff_fc00 == 0x9e67_0000)
        .count();
    assert_eq!(hoisted_doubles, 2);
    let hoisted_high_doubles = wide
        .code()
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .filter(|word| word & 0xffff_fc00 == 0x4e18_1c00)
        .count();
    assert_eq!(hoisted_high_doubles, 2);
}

#[test]
fn lowest_lane_restart_model_preserves_successive_non_overlap() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"aaaaaa", b"aa"),
        (b"ababababa", b"aba"),
        (b"xxneedleneedleneedlex", b"needle"),
        (b"012301230123", b"0123"),
        (b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", b"aaaaaaaa"),
    ];
    for &(haystack, literal) in cases {
        assert_eq!(
            modeled_sparse_count(haystack, literal),
            reference_successive_count(haystack, literal)
        );
    }
}

#[test]
fn sparse_run_model_preserves_late_pair_fallback_and_successors() {
    let literal = b"0123456789abcdef";
    let mut haystack = vec![b'x'; 512];
    for start in [70_usize, 143, 271] {
        haystack[start + 7] = literal[7];
        haystack[start + 6] = literal[6];
    }
    for start in [160_usize, 320, 336, 493] {
        if start + literal.len() <= haystack.len() {
            haystack[start..start + literal.len()].copy_from_slice(literal);
        }
    }
    assert_eq!(
        modeled_sparse_run_count(&haystack, literal),
        reference_successive_count(&haystack, literal)
    );
}

#[test]
fn staged_filters_defeat_pair_dense_and_triple_dense_absent_fixtures() {
    let pair_dense = dense_absent_fixtures::pair_dense_absent();
    let triple_dense = dense_absent_fixtures::triple_dense_absent();
    let filter = candidate_filter_v2(dense_absent_fixtures::LITERAL).unwrap();
    assert_eq!(filter.offsets(), &dense_absent_fixtures::FILTER_OFFSETS);

    let pair_hits = count_filter_hits(
        &pair_dense,
        dense_absent_fixtures::LITERAL,
        &filter.offsets()[..2],
    );
    let pair_after_third = count_filter_hits(
        &pair_dense,
        dense_absent_fixtures::LITERAL,
        &filter.offsets()[..3],
    );
    assert!(pair_hits >= dense_absent_fixtures::PAIR_INTENTIONAL_HITS);
    assert_eq!(pair_after_third, 0);

    let triple_hits = count_filter_hits(
        &triple_dense,
        dense_absent_fixtures::LITERAL,
        &filter.offsets()[..3],
    );
    let triple_after_fourth = count_filter_hits(
        &triple_dense,
        dense_absent_fixtures::LITERAL,
        filter.offsets(),
    );
    assert!(triple_hits >= dense_absent_fixtures::TRIPLE_INTENTIONAL_HITS);
    assert_eq!(triple_after_fourth, 0);
    assert_eq!(
        reference_successive_count(&pair_dense, dense_absent_fixtures::LITERAL),
        0
    );
    assert_eq!(
        reference_successive_count(&triple_dense, dense_absent_fixtures::LITERAL),
        0
    );
}

#[test]
fn v2_refuses_from_the_prospective_envelope_before_emission() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let mut limits = CountEmitLimitsV2::default();
    limits.max_work = 0;
    assert!(matches!(
        emit_count_v2(&program, limits),
        Err(CountAotError::ResourceLimit {
            resource: CountAotResource::Work,
            limit: 0,
            ..
        })
    ));
}

#[test]
fn every_nonzero_v2_resource_refuses_one_below_its_envelope() {
    let literal = *b"0123456789abcdefghijklmnopqrstuv";
    let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
    let prospective = prospective_count_v2(&program).unwrap();
    let cases = [
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
    ];
    for (resource, required) in cases {
        let limit = required.checked_sub(1).unwrap();
        let mut limits = CountEmitLimitsV2::default();
        match resource {
            CountAotResource::CodeBytes => limits.max_code_bytes = limit,
            CountAotResource::Labels => limits.max_labels = limit,
            CountAotResource::Relocations => {
                limits.max_relocations = limit;
            }
            CountAotResource::Work => limits.max_work = limit,
            CountAotResource::ScratchBytes => {
                limits.max_scratch_bytes = limit;
            }
            CountAotResource::PersistentBytes => {
                limits.max_persistent_bytes = limit;
            }
            CountAotResource::DataBytes => {
                unreachable!("zero-byte v2 data has no one-below limit");
            }
        }
        assert!(matches!(
            emit_count_v2(&program, limits),
            Err(CountAotError::ResourceLimit {
                resource: observed,
                limit: observed_limit,
                required: observed_required,
            }) if observed == resource
                && observed_limit == limit
                && observed_required == required
        ));
    }
}

#[test]
fn independent_v2_audit_rejects_code_manifest_and_edge_mutations() {
    let program =
        build_exact_aggregate::<Count>(b"0123456789abcdef", ValidateLimits::default()).unwrap();
    let mut code = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    code.code[0] ^= 1;
    assert!(audit_count_image_v2(&program, &code).is_err());

    let mut manifest = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    manifest.literal_manifest =
        crate::AotCountLiteralManifestV2::from_literal_and_offsets(program.literal(), &[0, 1])
            .unwrap();
    assert!(audit_count_image_v2(&program, &manifest).is_err());

    let mut label = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    label.labels[1].kind = LabelKindV2::Overflow;
    assert!(audit_count_image_v2(&program, &label).is_err());

    let mut edge = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    edge.relocations.swap(0, 1);
    assert!(audit_count_image_v2(&program, &edge).is_err());
}

#[test]
fn independent_v2_audit_rejects_every_callee_saved_simd_destination() {
    let program =
        build_exact_aggregate::<Count>(b"0123456789abcdef", ValidateLimits::default()).unwrap();
    let original = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
    let sparse_mask_offset = original
        .code()
        .chunks_exact(4)
        .position(|bytes| {
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            word & 0xffe0_fc00 == 0x4e20_1c00 && word & 0x1f == 24
        })
        .unwrap()
        * 4;

    for forbidden in 8_u32..=15 {
        let mut image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
        let bytes = &mut image.code[sparse_mask_offset..sparse_mask_offset + 4];
        let mut word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        word = (word & !0x1f) | forbidden;
        bytes.copy_from_slice(&word.to_le_bytes());
        reseal_v2(&mut image);
        assert!(matches!(
            audit_count_image_v2(&program, &image),
            Err(CountAotError::InvalidImage {
                at: "v2 forbidden callee-saved SIMD write"
            })
        ));
    }
}

#[test]
fn decoded_simd_destination_introspection_covers_every_writing_opcode() {
    let writes = [
        DecodedInstructionV2::LoadVector128 {
            destination: 8,
            base: 0,
            offset: 0,
        },
        DecodedInstructionV2::LoadVectorDouble {
            destination: 8,
            base: 0,
            offset: 0,
        },
        DecodedInstructionV2::DuplicateByte16 {
            destination: 8,
            source: 0,
        },
        DecodedInstructionV2::CompareEqualBytes16 {
            destination: 8,
            left: 0,
            right: 1,
        },
        DecodedInstructionV2::CompareEqualBytes8 {
            destination: 8,
            left: 0,
            right: 1,
        },
        DecodedInstructionV2::AndBytes16 {
            destination: 8,
            left: 0,
            right: 1,
        },
        DecodedInstructionV2::OrBytes16 {
            destination: 8,
            left: 0,
            right: 1,
        },
        DecodedInstructionV2::ShrinkNarrowBytesFromHalfwords {
            destination: 8,
            source: 0,
            shift: 4,
        },
        DecodedInstructionV2::AddAcrossBytes16 {
            destination: 8,
            source: 0,
        },
        DecodedInstructionV2::UnsignedMaxAcrossBytes16 {
            destination: 8,
            source: 0,
        },
        DecodedInstructionV2::UnsignedMinAcrossBytes8 {
            destination: 8,
            source: 0,
        },
        DecodedInstructionV2::UnsignedMinAcrossBytes16 {
            destination: 8,
            source: 0,
        },
        DecodedInstructionV2::Move64ToVectorDouble {
            destination: 8,
            source: 0,
        },
        DecodedInstructionV2::Insert64ToVectorDoubleLane1 {
            destination: 8,
            source: 0,
        },
    ];
    assert!(
        writes
            .iter()
            .all(|instruction| instruction.written_simd_register() == Some(8))
    );

    for read in [
        DecodedInstructionV2::MoveVectorByteTo32 {
            destination: 0,
            source: 8,
        },
        DecodedInstructionV2::MoveVectorDoubleTo64 {
            destination: 0,
            source: 8,
        },
    ] {
        assert_eq!(read.written_simd_register(), None);
    }
}

fn position(words: &[u32], predicate: impl Fn(u32) -> bool) -> usize {
    words.iter().copied().position(predicate).unwrap()
}

fn position_after(words: &[u32], start: usize, predicate: impl Fn(u32) -> bool) -> usize {
    start
        .checked_add(1)
        .and_then(|offset| {
            words[offset..]
                .iter()
                .copied()
                .position(predicate)
                .map(|position| offset + position)
        })
        .unwrap()
}

fn modeled_sparse_count(haystack: &[u8], literal: &[u8]) -> usize {
    let filter = candidate_filter_v2(literal).unwrap();
    let mut count = 0_usize;
    let mut cursor = 0_usize;
    let last = haystack.len().saturating_sub(literal.len());
    while cursor <= last && literal.len() <= haystack.len() {
        let block_len = 16.min(last - cursor + 1);
        let mut mask = 0_u16;
        for lane in 0..block_len {
            if filter.offsets().iter().all(|offset| {
                haystack[cursor + lane + usize::from(*offset)] == literal[usize::from(*offset)]
            }) {
                mask |= 1 << lane;
            }
        }
        let mut matched = false;
        while mask != 0 {
            let lane = usize::try_from(mask.trailing_zeros()).unwrap();
            mask &= mask - 1;
            let candidate = cursor + lane;
            if haystack[candidate..candidate + literal.len()] == *literal {
                count += 1;
                cursor = candidate + literal.len();
                matched = true;
                break;
            }
        }
        if !matched {
            cursor += block_len;
        }
    }
    count
}

fn modeled_sparse_run_count(haystack: &[u8], literal: &[u8]) -> usize {
    let filter = candidate_filter_v2(literal).unwrap();
    let mut count = 0_usize;
    let mut cursor = 0_usize;
    let last = haystack.len().saturating_sub(literal.len());
    while cursor <= last && literal.len() <= haystack.len() {
        let block_len = 16.min(last - cursor + 1);
        let pair_hit = (0..block_len).any(|lane| {
            filter.offsets()[..2].iter().all(|offset| {
                haystack[cursor + lane + usize::from(*offset)] == literal[usize::from(*offset)]
            })
        });
        if !pair_hit {
            cursor += block_len;
            while cursor <= last && last - cursor + 1 >= 64 {
                let sparse_pair_hit = (0..64).any(|lane| {
                    filter.offsets()[..2].iter().all(|offset| {
                        haystack[cursor + lane + usize::from(*offset)]
                            == literal[usize::from(*offset)]
                    })
                });
                if sparse_pair_hit {
                    break;
                }
                cursor += 64;
            }
            continue;
        }
        let mut matched = false;
        for lane in 0..block_len {
            let candidate = cursor + lane;
            if filter.offsets().iter().all(|offset| {
                haystack[candidate + usize::from(*offset)] == literal[usize::from(*offset)]
            }) && haystack[candidate..candidate + literal.len()] == *literal
            {
                count += 1;
                cursor = candidate + literal.len();
                matched = true;
                break;
            }
        }
        if !matched {
            cursor += block_len;
        }
    }
    count
}

fn reference_successive_count(haystack: &[u8], literal: &[u8]) -> usize {
    let mut count = 0_usize;
    let mut cursor = 0_usize;
    while cursor + literal.len() <= haystack.len() {
        if haystack[cursor..cursor + literal.len()] == *literal {
            count += 1;
            cursor += literal.len();
        } else {
            cursor += 1;
        }
    }
    count
}

fn count_filter_hits(haystack: &[u8], literal: &[u8], offsets: &[u8]) -> usize {
    if literal.len() > haystack.len() {
        return 0;
    }
    (0..=haystack.len() - literal.len())
        .filter(|start| {
            offsets.iter().all(|offset| {
                haystack[*start + usize::from(*offset)] == literal[usize::from(*offset)]
            })
        })
        .count()
}

#[test]
fn v2_algorithm_four_machine_code_is_byte_identical_every_width() {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    for width in 0_usize..=32 {
        let literal = (0..width)
            .map(|value| u8::try_from(value).unwrap())
            .collect::<Vec<_>>();
        let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
        let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
        digest.update(u64::try_from(width).unwrap().to_le_bytes());
        digest.update(u64::try_from(image.code().len()).unwrap().to_le_bytes());
        digest.update(image.code());
    }
    assert_eq!(
        &digest.finalize()[..],
        &[
            0x2f, 0x1b, 0x36, 0xeb, 0x3f, 0x87, 0x9b, 0x32, 0xe2, 0xb2, 0x46, 0x0c, 0x0e, 0x38,
            0x1a, 0x68, 0xee, 0x11, 0xe1, 0x42, 0x01, 0x54, 0x30, 0xd1, 0x07, 0xc5, 0xfc, 0x2e,
            0x28, 0x40, 0x75, 0xda,
        ]
    );
}
