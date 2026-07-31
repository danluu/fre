use core::mem::size_of;

use fre_exact_alloc::ExactVec;
use fre_kernel_ir::{Count, ValidateLimits, build_exact_aggregate};

use crate::audit::{
    audit_canonical_resource_work_components_v1, audit_count_image_with_scratch_limit_for_test,
    audit_work_components_for_dimensions,
};
use crate::emit::{
    EmitImagePhaseForTestV1, artifact_identity_encoded_len, compute_artifact_identity,
    identity_count_work_upper_bound_v1, identity_structural_traversal_work_v1,
    observe_emit_image_phase_scratch_for_test,
};
use crate::{
    AOT_COUNT_BACKEND_VERSION_V1, AotCountCpuFeatures, AotCountImageV1, CodeLabelV1, CountAotError,
    CountAotResource, CountEmitLimitsV1, LabelKindV1, RelocationV1, audit_count_image_v1,
    emit_count_v1, prospective_count_v1,
};

fn exact_with_extra<T: Copy>(values: &[T], extra: usize) -> ExactVec<T> {
    let capacity = values.len().checked_add(extra).unwrap();
    let mut result = ExactVec::try_with_capacity(capacity).unwrap();
    for value in values.iter().copied() {
        result.try_push(value).ok().unwrap();
    }
    assert_eq!(result.capacity(), capacity);
    result
}

fn sync_capacity_receipt(image: &mut AotCountImageV1) {
    image.build_receipt.code_capacity_bytes = image.code.capacity();
    image.build_receipt.label_capacity_bytes = image
        .labels
        .capacity()
        .checked_mul(size_of::<CodeLabelV1>())
        .unwrap();
    image.build_receipt.relocation_capacity_bytes = image
        .relocations
        .capacity()
        .checked_mul(size_of::<RelocationV1>())
        .unwrap();
    image.build_receipt.retained_heap_bytes = image
        .build_receipt
        .code_capacity_bytes
        .checked_add(image.build_receipt.label_capacity_bytes)
        .and_then(|bytes| bytes.checked_add(image.build_receipt.relocation_capacity_bytes))
        .unwrap();
    image.build_receipt.inline_bytes = size_of::<AotCountImageV1>();
}

fn reseal_artifact_identity(image: &mut AotCountImageV1) {
    let (identity, bytes) = compute_artifact_identity(image).unwrap();
    assert_eq!(bytes, image.stats.identity_bytes_hashed);
    image.artifact_identity = identity;
}

#[test]
fn empty_single_and_chunked_images_have_distinct_typed_shapes() {
    let empty_program = build_exact_aggregate::<Count>(b"", ValidateLimits::default()).unwrap();
    let empty = emit_count_v1(&empty_program, CountEmitLimitsV1::default()).unwrap();
    let single_program = build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).unwrap();
    let single = emit_count_v1(&single_program, CountEmitLimitsV1::default()).unwrap();
    let chunked_program =
        build_exact_aggregate::<Count>(b"0123456789abcdef", ValidateLimits::default()).unwrap();
    let chunked = emit_count_v1(&chunked_program, CountEmitLimitsV1::default()).unwrap();

    assert_eq!(empty.backend_version(), AOT_COUNT_BACKEND_VERSION_V1);
    assert_eq!(empty.target().features, AotCountCpuFeatures::NONE);
    assert_eq!(single.target().features, AotCountCpuFeatures::ASIMD);
    assert_eq!(chunked.target().features, AotCountCpuFeatures::NONE);
    assert!(empty.rodata().is_empty());
    assert!(single.rodata().is_empty());
    assert!(chunked.rodata().is_empty());
    assert_ne!(empty.artifact_identity(), single.artifact_identity());
    assert_ne!(single.artifact_identity(), chunked.artifact_identity());
    assert_eq!(
        audit_count_image_v1(&chunked_program, &chunked).unwrap(),
        chunked.build_receipt().audit
    );
}

#[test]
fn work_refuses_before_emission_and_hashing() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let limits = CountEmitLimitsV1 {
        max_work: 0,
        ..CountEmitLimitsV1::default()
    };
    assert!(matches!(
        emit_count_v1(&program, limits),
        Err(CountAotError::ResourceLimit {
            resource: CountAotResource::Work,
            limit: 0,
            ..
        })
    ));
}

#[test]
fn audit_binds_original_literal_and_every_sealed_dimension() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let wrong_program =
        build_exact_aggregate::<Count>(b"needlf", ValidateLimits::default()).unwrap();
    let mut image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();

    assert!(audit_count_image_v1(&wrong_program, &image).is_err());
    image.stats.code_bytes = image.stats.code_bytes.checked_add(4).unwrap();
    assert!(audit_count_image_v1(&program, &image).is_err());
}

#[test]
fn audit_rejects_code_and_relocation_mutations() {
    let program =
        build_exact_aggregate::<Count>(b"0123456789abcdef", ValidateLimits::default()).unwrap();
    let mut code_image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    code_image.code[0] ^= 1;
    assert!(audit_count_image_v1(&program, &code_image).is_err());

    let mut relocation_image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    relocation_image.relocations[0].resolved_word ^= 4;
    assert!(audit_count_image_v1(&program, &relocation_image).is_err());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "all independent work-component equalities stay beside the full-width envelope proof"
)]
fn every_literal_width_matches_the_exact_prospective_envelope() {
    for width in 0_usize..=32 {
        let literal = (0..width)
            .map(|index| {
                if index.is_multiple_of(3) {
                    0
                } else {
                    u8::try_from(index.checked_mul(17).unwrap() % 251).unwrap()
                }
            })
            .collect::<Vec<_>>();
        let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
        let prospective = prospective_count_v1(&program).unwrap();
        let image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
        let stats = image.stats();
        let receipt = image.build_receipt();
        let identity_bytes = artifact_identity_encoded_len(&image).unwrap();
        let audit_work = audit_work_components_for_dimensions(
            image.code().len(),
            image.labels().len(),
            image.relocations().len(),
        )
        .unwrap();
        let structural_identity_pass = 68_u64
            .checked_add(u64::from(stats.labels).checked_mul(2).unwrap())
            .and_then(|work| work.checked_add(u64::from(stats.relocations).checked_mul(4).unwrap()))
            .unwrap();
        let expected_identity_count_work = structural_identity_pass.checked_mul(4).unwrap();
        let expected_assembler_derivation = 4_u64 + 2 + 3 + 5 + 7 + 7 + 7 + 4 + 1;
        let expected_observed_capacity_multiplications = 5_u64 * 4;
        let expected_observed_backing_additions = 5_u64 * 2;
        let expected_observed_phase_additions = 3_u64 + 5 + 7 + 7 + 7;
        let expected_observed_conversions = 5_u64;
        let expected_observed_admission_and_maxima = 5_u64 * 3;
        let expected_observed_total = expected_observed_capacity_multiplications
            .checked_add(expected_observed_backing_additions)
            .and_then(|work| work.checked_add(expected_observed_phase_additions))
            .and_then(|work| work.checked_add(expected_observed_conversions))
            .and_then(|work| work.checked_add(expected_observed_admission_and_maxima))
            .unwrap();
        let expected_canonical_resource_total = 16_u64
            .checked_add(expected_assembler_derivation.checked_mul(2).unwrap())
            .and_then(|work| work.checked_add(expected_observed_total))
            .and_then(|work| work.checked_add(7))
            .unwrap();
        let named_audit_work = audit_work
            .canonical_emission
            .checked_add(audit_work.canonical_resource_accounting.total)
            .and_then(|work| work.checked_add(audit_work.canonical_compare))
            .and_then(|work| work.checked_add(audit_work.decode))
            .and_then(|work| work.checked_add(audit_work.independent_policy))
            .and_then(|work| work.checked_add(audit_work.cfg_and_relocations))
            .and_then(|work| work.checked_add(audit_work.identity_structural_traversal))
            .and_then(|work| work.checked_add(audit_work.identity_hash_bytes))
            .and_then(|work| work.checked_add(audit_work.identity_hash_finalization))
            .and_then(|work| work.checked_add(audit_work.fixed_scalar_checks))
            .unwrap();

        assert_eq!(
            u64::from(stats.code_bytes),
            prospective.code_bytes_upper_bound
        );
        assert_eq!(
            u64::from(stats.data_bytes),
            prospective.data_bytes_upper_bound
        );
        assert_eq!(u64::from(stats.labels), prospective.labels_upper_bound);
        assert_eq!(
            u64::from(stats.relocations),
            prospective.relocations_upper_bound
        );
        assert_eq!(
            stats.identity_bytes_hashed,
            prospective.identity_bytes_hashed_upper_bound
        );
        assert_eq!(
            identity_bytes,
            prospective.identity_bytes_hashed_upper_bound
        );
        assert_eq!(audit_work.identity_hash_bytes, identity_bytes);
        assert_eq!(
            audit_work.identity_structural_traversal,
            structural_identity_pass.checked_mul(2).unwrap()
        );
        assert_eq!(
            identity_count_work_upper_bound_v1(
                u64::from(stats.labels),
                u64::from(stats.relocations),
            )
            .unwrap(),
            expected_identity_count_work
        );
        let canonical_resource = audit_work.canonical_resource_accounting;
        assert_eq!(
            canonical_resource,
            audit_canonical_resource_work_components_v1().unwrap()
        );
        assert_eq!(canonical_resource.scratch_envelope_arithmetic, 16);
        assert_eq!(
            canonical_resource.assembler_envelope_derivations,
            expected_assembler_derivation.checked_mul(2).unwrap()
        );
        assert_eq!(
            canonical_resource
                .observed_emission_phase_scratch
                .capacity_multiplications,
            expected_observed_capacity_multiplications
        );
        assert_eq!(
            canonical_resource
                .observed_emission_phase_scratch
                .backing_additions,
            expected_observed_backing_additions
        );
        assert_eq!(
            canonical_resource
                .observed_emission_phase_scratch
                .phase_additions,
            expected_observed_phase_additions
        );
        assert_eq!(
            canonical_resource
                .observed_emission_phase_scratch
                .conversions,
            expected_observed_conversions
        );
        assert_eq!(
            canonical_resource
                .observed_emission_phase_scratch
                .admission_checks_and_peak_maxima,
            expected_observed_admission_and_maxima
        );
        assert_eq!(
            canonical_resource.observed_emission_phase_scratch.total,
            expected_observed_total
        );
        assert_eq!(canonical_resource.admission_and_seal_checks, 7);
        assert_eq!(canonical_resource.total, expected_canonical_resource_total);
        assert_eq!(audit_work.identity_hash_finalization, 8);
        assert_eq!(audit_work.total, named_audit_work);
        assert_eq!(
            receipt.emission_peak_scratch_bytes,
            prospective.emission_scratch_bytes_upper_bound
        );
        assert_eq!(
            stats.audit_work_upper_bound,
            prospective.audit_work_upper_bound
        );
        assert_eq!(
            receipt.audit.scratch_bytes_upper_bound,
            prospective.audit_scratch_bytes_upper_bound
        );
        assert_eq!(
            stats.total_work_upper_bound,
            prospective.total_work_upper_bound
        );
        assert_eq!(
            stats.scratch_bytes_upper_bound,
            prospective.scratch_bytes_upper_bound
        );
        assert_eq!(receipt.code_capacity_bytes, image.code().len());
        assert_eq!(
            receipt
                .retained_heap_bytes
                .checked_add(receipt.inline_bytes)
                .unwrap(),
            usize::try_from(prospective.persistent_bytes_upper_bound).unwrap()
        );
        assert_eq!(
            audit_count_image_v1(&program, &image).unwrap(),
            receipt.audit
        );
    }
}

#[test]
fn every_nonzero_resource_limit_refuses_one_below_exact_preflight() {
    let literal = [0_u8; 32];
    let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
    let prospective = prospective_count_v1(&program).unwrap();
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
    for (resource, exact) in cases {
        let mut limits = CountEmitLimitsV1::default();
        let one_below = exact.checked_sub(1).unwrap();
        match resource {
            CountAotResource::CodeBytes => limits.max_code_bytes = one_below,
            CountAotResource::Labels => limits.max_labels = one_below,
            CountAotResource::Relocations => limits.max_relocations = one_below,
            CountAotResource::Work => limits.max_work = one_below,
            CountAotResource::ScratchBytes => limits.max_scratch_bytes = one_below,
            CountAotResource::PersistentBytes => {
                limits.max_persistent_bytes = one_below;
            }
            CountAotResource::DataBytes => unreachable!("zero-byte data has no one-below limit"),
        }
        assert!(matches!(
            emit_count_v1(&program, limits),
            Err(CountAotError::ResourceLimit {
                resource: observed,
                limit,
                required,
            }) if observed == resource && limit == one_below && required == exact
        ));
    }
}

#[test]
fn exact_complete_work_limit_accepts_and_one_below_refuses_every_width() {
    for width in 0_usize..=32 {
        let literal = vec![0x5a; width];
        let program = build_exact_aggregate::<Count>(&literal, ValidateLimits::default()).unwrap();
        let exact = prospective_count_v1(&program)
            .unwrap()
            .total_work_upper_bound;
        let exact_limits = CountEmitLimitsV1 {
            max_work: exact,
            ..CountEmitLimitsV1::default()
        };
        let image = emit_count_v1(&program, exact_limits).unwrap();
        assert_eq!(image.stats().total_work_upper_bound, exact);
        assert_eq!(image.build_receipt().work_upper_bound, exact);

        let one_below = exact.checked_sub(1).unwrap();
        let refusing_limits = CountEmitLimitsV1 {
            max_work: one_below,
            ..CountEmitLimitsV1::default()
        };
        assert!(matches!(
            emit_count_v1(&program, refusing_limits),
            Err(CountAotError::ResourceLimit {
                resource: CountAotResource::Work,
                limit,
                required,
            }) if limit == one_below && required == exact
        ));
    }
}

#[test]
fn identity_and_audit_work_arithmetic_refuses_overflow_edges() {
    assert_eq!(identity_structural_traversal_work_v1(0, 0), Some(68));
    assert_eq!(
        identity_structural_traversal_work_v1(5, 15),
        Some(68 + (2 * 5) + (4 * 15))
    );
    assert!(identity_structural_traversal_work_v1(u64::MAX, 0).is_none());
    assert!(identity_structural_traversal_work_v1(0, u64::MAX).is_none());
    assert!(identity_count_work_upper_bound_v1(u64::MAX / 4, 0).is_none());
    assert!(matches!(
        audit_work_components_for_dimensions(usize::MAX, usize::MAX, usize::MAX),
        Err(CountAotError::ArithmeticOverflow { .. })
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "each independently sealed scratch claim is mutated high or low"
)]
fn audit_rejects_high_and_low_scratch_claims() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();

    let mut stats_high = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    stats_high.stats.scratch_bytes_upper_bound = stats_high
        .stats
        .scratch_bytes_upper_bound
        .checked_add(1)
        .unwrap();
    assert!(matches!(
        audit_count_image_v1(&program, &stats_high),
        Err(CountAotError::InvalidImage {
            at: "prospective scratch seal"
        })
    ));

    let mut receipt_low = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    receipt_low.build_receipt.scratch_bytes_upper_bound = receipt_low
        .build_receipt
        .scratch_bytes_upper_bound
        .checked_sub(1)
        .unwrap();
    assert!(matches!(
        audit_count_image_v1(&program, &receipt_low),
        Err(CountAotError::InvalidImage {
            at: "prospective scratch seal"
        })
    ));

    let mut audit_high = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    audit_high.build_receipt.audit.scratch_bytes_upper_bound = audit_high
        .build_receipt
        .audit
        .scratch_bytes_upper_bound
        .checked_add(1)
        .unwrap();
    assert!(matches!(
        audit_count_image_v1(&program, &audit_high),
        Err(CountAotError::InvalidImage {
            at: "prospective scratch seal"
        })
    ));

    let mut audit_low = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    audit_low.build_receipt.audit.scratch_bytes_upper_bound = audit_low
        .build_receipt
        .audit
        .scratch_bytes_upper_bound
        .checked_sub(1)
        .unwrap();
    assert!(matches!(
        audit_count_image_v1(&program, &audit_low),
        Err(CountAotError::InvalidImage {
            at: "prospective scratch seal"
        })
    ));

    let mut emission_high = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    emission_high.build_receipt.emission_peak_scratch_bytes = emission_high
        .build_receipt
        .emission_peak_scratch_bytes
        .checked_add(1)
        .unwrap();
    assert!(matches!(
        audit_count_image_v1(&program, &emission_high),
        Err(CountAotError::InvalidImage {
            at: "prospective scratch seal"
        })
    ));

    let mut emission_low = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    emission_low.build_receipt.emission_peak_scratch_bytes = emission_low
        .build_receipt
        .emission_peak_scratch_bytes
        .checked_sub(1)
        .unwrap();
    assert!(matches!(
        audit_count_image_v1(&program, &emission_low),
        Err(CountAotError::InvalidImage {
            at: "prospective scratch seal"
        })
    ));
}

#[test]
fn audit_scratch_refuses_exactly_one_below_before_allocation() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let prospective = prospective_count_v1(&program).unwrap();
    let image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    let exact = prospective.audit_scratch_bytes_upper_bound;
    assert_eq!(
        audit_count_image_with_scratch_limit_for_test(&program, &image, exact).unwrap(),
        image.build_receipt().audit
    );
    let one_below = exact.checked_sub(1).unwrap();
    assert!(matches!(
        audit_count_image_with_scratch_limit_for_test(
            &program,
            &image,
            one_below,
        ),
        Err(CountAotError::ResourceLimit {
            resource: CountAotResource::ScratchBytes,
            limit,
            required,
        }) if limit == one_below && required == exact
    ));
}

#[test]
fn every_emit_identity_and_audit_phase_rereads_capacity_and_refuses_one_below() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    let phases = [
        EmitImagePhaseForTestV1::InitialIdentityLength,
        EmitImagePhaseForTestV1::CandidateAudit,
        EmitImagePhaseForTestV1::SealedIdentityLength,
        EmitImagePhaseForTestV1::SealedIdentityHash,
        EmitImagePhaseForTestV1::SealedAudit,
    ];
    for phase in phases {
        let exact =
            observe_emit_image_phase_scratch_for_test(&program, &image, phase, u64::MAX).unwrap();
        let one_below = exact.checked_sub(1).unwrap();
        assert!(matches!(
            observe_emit_image_phase_scratch_for_test(
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

    let mut code_overcapacity = image;
    code_overcapacity.code = exact_with_extra(code_overcapacity.code.as_slice(), 1);
    let mut label_overcapacity = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    label_overcapacity.labels = exact_with_extra(label_overcapacity.labels.as_slice(), 1);
    let mut relocation_overcapacity =
        emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    relocation_overcapacity.relocations =
        exact_with_extra(relocation_overcapacity.relocations.as_slice(), 1);
    for overcapacity in [
        &code_overcapacity,
        &label_overcapacity,
        &relocation_overcapacity,
    ] {
        for phase in phases {
            assert!(matches!(
                observe_emit_image_phase_scratch_for_test(&program, overcapacity, phase, u64::MAX,),
                Err(CountAotError::InternalInvariant {
                    at: "image backing prospective"
                })
            ));
        }
    }
}

fn assert_persistent_seal_rejects(
    program: &fre_kernel_ir::ExactAggregateProgram<Count>,
    mut image: AotCountImageV1,
) {
    reseal_artifact_identity(&mut image);
    assert!(matches!(
        audit_count_image_v1(program, &image),
        Err(CountAotError::InvalidImage {
            at: "prospective persistent seal"
        })
    ));
}

#[test]
fn audit_rejects_resealed_overcapacity_backing_before_content_scans() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();

    let mut code_image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    code_image.code = exact_with_extra(code_image.code.as_slice(), 1);
    sync_capacity_receipt(&mut code_image);
    assert_persistent_seal_rejects(&program, code_image);

    let mut label_image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    label_image.labels = exact_with_extra(label_image.labels.as_slice(), 1);
    sync_capacity_receipt(&mut label_image);
    assert_persistent_seal_rejects(&program, label_image);

    let mut relocation_image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    relocation_image.relocations = exact_with_extra(relocation_image.relocations.as_slice(), 1);
    sync_capacity_receipt(&mut relocation_image);
    assert_persistent_seal_rejects(&program, relocation_image);

    let mut over_hard_limit = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    let hard_limit_capacity = 128_usize.checked_mul(1024).unwrap();
    over_hard_limit.code = exact_with_extra(
        over_hard_limit.code.as_slice(),
        hard_limit_capacity
            .checked_sub(over_hard_limit.code.len())
            .unwrap(),
    );
    sync_capacity_receipt(&mut over_hard_limit);
    assert_persistent_seal_rejects(&program, over_hard_limit);
}

#[test]
fn audit_rejects_resealed_high_and_low_persistent_receipt_claims() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();

    let mut retained_high = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    retained_high.build_receipt.retained_heap_bytes = retained_high
        .build_receipt
        .retained_heap_bytes
        .checked_add(1)
        .unwrap();
    assert_persistent_seal_rejects(&program, retained_high);

    let mut retained_low = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    retained_low.build_receipt.retained_heap_bytes = retained_low
        .build_receipt
        .retained_heap_bytes
        .checked_sub(1)
        .unwrap();
    assert_persistent_seal_rejects(&program, retained_low);

    let mut inline_high = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    inline_high.build_receipt.inline_bytes = inline_high
        .build_receipt
        .inline_bytes
        .checked_add(1)
        .unwrap();
    assert_persistent_seal_rejects(&program, inline_high);

    let mut inline_low = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    inline_low.build_receipt.inline_bytes = inline_low
        .build_receipt
        .inline_bytes
        .checked_sub(1)
        .unwrap();
    assert_persistent_seal_rejects(&program, inline_low);
}

#[test]
fn audit_rejects_independent_label_and_edge_mutations() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default()).unwrap();
    let mut label_image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    label_image.labels[1].kind = LabelKindV1::Overflow;
    assert!(audit_count_image_v1(&program, &label_image).is_err());

    let mut edge_image = emit_count_v1(&program, CountEmitLimitsV1::default()).unwrap();
    edge_image.relocations.swap(0, 1);
    assert!(audit_count_image_v1(&program, &edge_image).is_err());
}
