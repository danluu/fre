use fre_kernel_ir::{
    AnchorFlags, ByteClass, Exists, OutputKind, SelectedEnd, Span, ValidateLimits,
    build_class_suffix, build_exact_literal,
};

use crate::{
    AotArtifact, AotError, AotLimits, AuditError, AuditLimits, CallingConvention, EmitConfig,
    EmitError, EmitResource, FeatureTier, KernelShape, RelocationKind, Section, TargetStamp,
    audit_image, emit, emit_raw, inspect_aot,
};

#[test]
fn all_shapes_lengths_anchors_and_tiers_decode() {
    let lengths = [0, 1, 2, 3, 4, 5, 8, 9, 16, 17, 31, 32, 33, 65];
    for tier in tiers() {
        for anchors in anchors() {
            for length in lengths {
                let literal = vec![b'x'; length];
                let program =
                    build_exact_literal::<Span>(&literal, anchors, ValidateLimits::default())
                        .unwrap();
                let image = emit_with_tier(&program, tier).unwrap_or_else(|error| {
                    panic!("literal length={length} tier={tier:?} anchors={anchors:?}: {error:?}")
                });
                let report = audit_image(&image, AuditLimits::default()).unwrap();
                assert_eq!(report.decoded_bytes, image.code().len());
                assert_eq!(report.shape.returns, 3);
                assert_eq!(report.highest_feature_tier, image.stamp().used_tier);
            }
        }
        for anchors in anchors() {
            for length in [1, 2, 16, 17, 32, 33, 65] {
                let suffix = vec![b'X'; length];
                for class in [ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"abcde")] {
                    let program = build_class_suffix::<Span>(
                        class,
                        &suffix,
                        anchors,
                        ValidateLimits::default(),
                    )
                    .unwrap();
                    let image = emit_with_tier(&program, tier).unwrap_or_else(|error| {
                        panic!(
                            "suffix length={length} tier={tier:?} anchors={anchors:?}: {error:?}"
                        )
                    });
                    let report = audit_image(&image, AuditLimits::default()).unwrap();
                    assert_eq!(report.decoded_bytes, image.code().len());
                    assert_eq!(report.shape.returns, 3);
                }
            }
        }
    }
}

#[test]
fn feature_tiers_have_independently_decoded_instruction_shapes() {
    let literal = vec![b'x'; 65];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .unwrap();
    let scalar = emit_with_tier(&program, FeatureTier::Scalar).unwrap();
    let sse2 = emit_with_tier(&program, FeatureTier::Sse2).unwrap();
    let avx2 = emit_with_tier(&program, FeatureTier::Avx2).unwrap();
    let scalar_audit = audit_image(&scalar, AuditLimits::default()).unwrap();
    let sse2_audit = audit_image(&sse2, AuditLimits::default()).unwrap();
    let avx2_audit = audit_image(&avx2, AuditLimits::default()).unwrap();

    assert_eq!(scalar.stamp().used_tier, FeatureTier::Scalar);
    assert_eq!(scalar_audit.shape.sse2_comparisons, 0);
    assert_eq!(scalar_audit.shape.avx2_comparisons, 0);
    assert_eq!(sse2.stamp().used_tier, FeatureTier::Sse2);
    assert!(sse2_audit.shape.sse2_comparisons > 0);
    assert_eq!(sse2_audit.shape.avx2_comparisons, 0);
    assert_eq!(avx2.stamp().used_tier, FeatureTier::Avx2);
    assert!(avx2_audit.shape.avx2_comparisons > 0);
    assert_eq!(avx2_audit.shape.avx_cleanups, 3);
    assert!(contains(avx2.code(), &[0xC5, 0xFD, 0x74, 0x02]));
    assert!(contains(avx2.code(), &[0xC5, 0xF8, 0x77, 0xC3]));

    let short =
        build_exact_literal::<Span>(b"short", AnchorFlags::default(), ValidateLimits::default())
            .unwrap();
    let short_avx = emit_with_tier(&short, FeatureTier::Avx2).unwrap();
    assert_eq!(short_avx.stamp().requested_tier, FeatureTier::Avx2);
    assert_eq!(short_avx.stamp().used_tier, FeatureTier::Scalar);
}

#[test]
fn shared_capability_facts_map_to_existing_emitter_tiers() {
    use fre_target_features::{Architecture as HostArchitecture, Feature, FeatureSet};

    assert_eq!(
        FeatureTier::for_usable_features(HostArchitecture::Other, FeatureSet::EMPTY),
        FeatureTier::Scalar
    );
    assert_eq!(
        FeatureTier::for_usable_features(
            HostArchitecture::X86_64,
            FeatureSet::of(Feature::X86Sse2)
        ),
        FeatureTier::Sse2
    );
    assert_eq!(
        FeatureTier::for_usable_features(
            HostArchitecture::X86_64,
            FeatureSet::EMPTY
                .with(Feature::X86Sse2)
                .with(Feature::X86Avx2)
        ),
        FeatureTier::Avx2
    );
}

#[test]
fn short_class_confirmation_preserves_run_end_register() {
    let program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"abcde"),
        b"12345678",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let image = emit_with_tier(&program, FeatureTier::Avx2).unwrap();
    // movabs r9,imm64; cmp [rdi+r11],r9. R11 remains the run end.
    assert!(contains(
        image.code(),
        &[
            0x49, 0xB9, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', 0x4E, 0x39, 0x0C, 0x1F,
        ]
    ));
    assert!(!contains(image.code(), &[0x4E, 0x39, 0x1C, 0x1F]));
}

#[test]
fn long_exact_confirmation_preserves_last_candidate_register() {
    let program = build_exact_literal::<Span>(
        &[b'x'; 17],
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let image = emit_with_tier(&program, FeatureTier::Scalar).unwrap();
    // R10 is the last legal candidate. The constant pointer is therefore RDX.
    assert!(contains(image.code(), &[0x48, 0x8D, 0x15]));
    assert!(!contains(image.code(), &[0x4C, 0x8D, 0x15]));
    assert!(contains(image.code(), &[0x4D, 0x39, 0xD1])); // cmp r9,r10
}

#[test]
fn constants_and_relocations_are_minimal_and_resolved() {
    let short =
        build_exact_literal::<Span>(b"small", AnchorFlags::default(), ValidateLimits::default())
            .unwrap();
    let short_image = emit_with_tier(&short, FeatureTier::Scalar).unwrap();
    assert!(short_image.data().is_empty());
    assert!(short_image.relocations().is_empty());

    let sparse = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"ab"),
        b"X",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let sparse_image = emit_with_tier(&sparse, FeatureTier::Scalar).unwrap();
    assert!(sparse_image.data().is_empty());
    assert!(sparse_image.relocations().is_empty());

    let suffix = vec![b'X'; 65];
    let dense = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"abcde"),
        &suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let image = emit_with_tier(&dense, FeatureTier::Avx2).unwrap();
    assert_eq!(image.data().len(), 256 + suffix.len());
    assert_eq!(image.relocations().len(), 3);
    assert_eq!(&image.data()[256..], suffix);
    for relocation in image.relocations() {
        assert_eq!(relocation.kind, RelocationKind::RipRelativeI32);
        assert_eq!(relocation.source_section, Section::Code);
        assert_eq!(relocation.target_section, Section::Data);
        let displacement_offset = usize::try_from(relocation.displacement_offset).unwrap();
        let displacement = i32::from_le_bytes(
            image.code()[displacement_offset..displacement_offset + 4]
                .try_into()
                .unwrap(),
        );
        let actual = add_signed(displacement_offset + 4, displacement).unwrap();
        assert_eq!(
            actual,
            usize::try_from(image.data_offset()).unwrap()
                + usize::try_from(relocation.target_offset).unwrap()
        );
    }
}

#[test]
fn output_contract_and_backend_neutral_shape_are_stamped() {
    let anchors = AnchorFlags {
        start: true,
        end: false,
    };
    let span = build_exact_literal::<Span>(b"needle", anchors, ValidateLimits::default()).unwrap();
    let end =
        build_exact_literal::<SelectedEnd>(b"needle", anchors, ValidateLimits::default()).unwrap();
    let exists =
        build_exact_literal::<Exists>(b"needle", anchors, ValidateLimits::default()).unwrap();
    let span_image = emit(&span, EmitConfig::default()).unwrap();
    let end_image = emit(&end, EmitConfig::default()).unwrap();
    let exists_image = emit(&exists, EmitConfig::default()).unwrap();
    assert_eq!(span_image.code(), end_image.code());
    assert_eq!(span_image.code(), exists_image.code());
    assert_eq!(span_image.output_kind(), OutputKind::Span);
    assert_eq!(end_image.output_kind(), OutputKind::SelectedEnd);
    assert_eq!(exists_image.output_kind(), OutputKind::Exists);
    assert_ne!(span_image.kernel_identity(), end_image.kernel_identity());
    assert_eq!(
        span_image.kernel_shape(),
        KernelShape::ExactLiteral {
            literal_len: 6,
            anchors,
        }
    );

    let class = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"cba"),
        b"XYZ",
        anchors,
        ValidateLimits::default(),
    )
    .unwrap();
    let class_image = emit(&class, EmitConfig::default()).unwrap();
    assert_eq!(
        class_image.kernel_shape(),
        KernelShape::DisjointClassSuffix {
            class_population: 3,
            suffix_len: 3,
            anchors,
        }
    );
}

#[test]
fn emission_and_aot_are_deterministic() {
    let program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"edcba"),
        &[b'X'; 65],
        AnchorFlags {
            start: false,
            end: true,
        },
        ValidateLimits::default(),
    )
    .unwrap();
    let config = config(FeatureTier::Avx2);
    let first = emit(&program, config).unwrap();
    let second = emit(&program, config).unwrap();
    assert_eq!(first, second);
    let first_aot = AotArtifact::from_image(&first, AotLimits::default()).unwrap();
    let second_aot = AotArtifact::from_image(&second, AotLimits::default()).unwrap();
    assert_eq!(first_aot, second_aot);
    assert_eq!(
        inspect_aot(first_aot.as_bytes(), AotLimits::default()).unwrap(),
        first_aot.header()
    );
    assert_eq!(&first_aot.as_bytes()[..8], b"FREX64\0\x01");
}

#[test]
fn every_emission_resource_boundary_is_enforced() {
    let suffix = [b'X'; 65];
    let program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"abcde"),
        &suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let baseline = emit_with_tier(&program, FeatureTier::Avx2).unwrap();
    let stats = baseline.stats();

    assert_emit_limit(
        &program,
        |limits| limits.max_code_bytes = below(stats.code_bytes),
        EmitResource::CodeBytes,
    );
    assert_emit_limit(
        &program,
        |limits| limits.max_data_bytes = below(stats.data_bytes),
        EmitResource::DataBytes,
    );
    assert_emit_limit(
        &program,
        |limits| limits.max_image_bytes = below(stats.image_bytes),
        EmitResource::ImageBytes,
    );
    assert_emit_limit(
        &program,
        |limits| limits.max_relocations = below(stats.relocations),
        EmitResource::Relocations,
    );
    assert_emit_limit(
        &program,
        |limits| limits.max_internal_branches = below(stats.internal_branches),
        EmitResource::InternalBranches,
    );
    assert_emit_limit(
        &program,
        |limits| {
            limits.max_branch_displacement = stats.maximum_branch_displacement - 1;
        },
        EmitResource::BranchDisplacement,
    );
    assert_emit_limit(
        &program,
        |limits| {
            limits.max_relocation_displacement = stats.maximum_relocation_displacement - 1;
        },
        EmitResource::RelocationDisplacement,
    );
    assert_emit_limit(
        &program,
        |limits| limits.max_emit_work = stats.emit_work - 1,
        EmitResource::EmitWork,
    );
    assert_emit_limit(
        &program,
        |limits| limits.max_emit_scratch_bytes = below(stats.emit_scratch_bytes),
        EmitResource::EmitScratchBytes,
    );
    assert_emit_limit(
        &program,
        |limits| limits.max_runtime_work_factor = stats.runtime_work_factor - 1,
        EmitResource::RuntimeWorkFactor,
    );
    let mut exact = config(FeatureTier::Avx2);
    exact.limits.max_code_bytes = u64::try_from(stats.code_bytes).unwrap();
    exact.limits.max_data_bytes = u64::try_from(stats.data_bytes).unwrap();
    exact.limits.max_image_bytes = u64::try_from(stats.image_bytes).unwrap();
    exact.limits.max_relocations = u64::try_from(stats.relocations).unwrap();
    exact.limits.max_internal_branches = u64::try_from(stats.internal_branches).unwrap();
    exact.limits.max_branch_displacement = stats.maximum_branch_displacement;
    exact.limits.max_relocation_displacement = stats.maximum_relocation_displacement;
    exact.limits.max_emit_work = stats.emit_work;
    exact.limits.max_emit_scratch_bytes = u64::try_from(stats.emit_scratch_bytes).unwrap();
    exact.limits.max_runtime_work_factor = stats.runtime_work_factor;
    exact.limits.max_runtime_scratch_bytes = 0;
    assert_eq!(emit(&program, exact).unwrap().stats(), stats);
}

#[test]
fn every_audit_and_aot_resource_boundary_is_enforced() {
    let program = build_exact_literal::<Span>(
        &[b'x'; 65],
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let image = emit_with_tier(&program, FeatureTier::Avx2).unwrap();
    let report = audit_image(&image, AuditLimits::default()).unwrap();
    for (limits, resource) in [
        (
            AuditLimits {
                max_instructions: below(report.shape.instructions),
                ..AuditLimits::default()
            },
            EmitResource::AuditInstructions,
        ),
        (
            AuditLimits {
                max_work: report.work - 1,
                ..AuditLimits::default()
            },
            EmitResource::AuditWork,
        ),
        (
            AuditLimits {
                max_scratch_bytes: below(report.scratch_bytes),
                ..AuditLimits::default()
            },
            EmitResource::AuditScratchBytes,
        ),
    ] {
        assert_audit_resource(&audit_image(&image, limits).unwrap_err(), resource);
    }

    let artifact = AotArtifact::from_image(&image, AotLimits::default()).unwrap();
    let aot_work = u64::try_from(artifact.as_bytes().len() + image.relocations().len()).unwrap();
    for (limits, resource) in [
        (
            AotLimits {
                max_bytes: below(artifact.as_bytes().len()),
                ..AotLimits::default()
            },
            EmitResource::AotBytes,
        ),
        (
            AotLimits {
                max_work: aot_work - 1,
                ..AotLimits::default()
            },
            EmitResource::AotWork,
        ),
        (
            AotLimits {
                max_scratch_bytes: 0,
                ..AotLimits::default()
            },
            EmitResource::AotScratchBytes,
        ),
    ] {
        assert_aot_resource(
            &AotArtifact::from_image(&image, limits).unwrap_err(),
            resource,
        );
    }
}

#[test]
fn malformed_ir_and_windows_abi_are_typed_refusals() {
    let program = build_exact_literal::<Span>(
        b"literal",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let mut raw = program.raw().clone();
    raw.schema_version = 99;
    assert!(matches!(
        emit_raw::<Span>(raw, ValidateLimits::default(), EmitConfig::default()),
        Err(EmitError::KernelValidation(_))
    ));

    let error = emit(
        &program,
        EmitConfig {
            target: TargetStamp::windows_x64_v1(),
            ..EmitConfig::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        EmitError::UnsupportedTarget(target)
            if target.target.calling_convention == CallingConvention::WindowsX64V1
                && target.supported_calling_convention == CallingConvention::SystemVAMD64V1
    ));
}

#[test]
fn authenticity_audit_rejects_corruption() {
    let program = build_exact_literal::<Span>(
        &[b'x'; 65],
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let baseline = emit_with_tier(&program, FeatureTier::Avx2).unwrap();

    let mut indirect = baseline.clone();
    indirect.image[0] = 0xFF;
    assert!(matches!(
        audit_image(&indirect, AuditLimits::default()),
        Err(AuditError::ForbiddenControlFlow { offset: 0 })
    ));

    let mut outside = baseline.clone();
    outside.image[5..9].copy_from_slice(&i32::MAX.to_le_bytes());
    assert!(matches!(
        audit_image(&outside, AuditLimits::default()),
        Err(AuditError::BranchTargetOutOfRange { .. })
    ));

    let mut middle = baseline.clone();
    middle.image[5..9].copy_from_slice(&(-8_i32).to_le_bytes());
    assert!(matches!(
        audit_image(&middle, AuditLimits::default()),
        Err(AuditError::BranchTargetNotInstruction { target: 1, .. })
    ));

    let mut data = baseline.clone();
    let displacement = usize::try_from(data.relocations()[0].displacement_offset).unwrap();
    data.image[displacement..displacement + 4].copy_from_slice(&0_i32.to_le_bytes());
    assert!(matches!(
        audit_image(&data, AuditLimits::default()),
        Err(AuditError::RelocationManifestMismatch { .. })
    ));

    let mut tier = baseline.clone();
    tier.stamp.used_tier = FeatureTier::Scalar;
    assert!(matches!(
        audit_image(&tier, AuditLimits::default()),
        Err(AuditError::TierMismatch { .. })
    ));

    let mut cleanup = baseline.clone();
    let cleanup_offset = find(cleanup.code(), &[0xC5, 0xF8, 0x77, 0xC3]).unwrap();
    cleanup.image[cleanup_offset..cleanup_offset + 3].copy_from_slice(&[0x48, 0x39, 0xCA]);
    assert!(matches!(
        audit_image(&cleanup, AuditLimits::default()),
        Err(AuditError::MissingAvxCleanup { .. })
    ));

    let mut truncated = baseline;
    truncated.code_len = 1;
    assert!(matches!(
        audit_image(&truncated, AuditLimits::default()),
        Err(AuditError::TruncatedInstruction { offset: 0 })
    ));
}

#[test]
fn aot_inspection_rejects_malformed_containers() {
    let program = build_exact_literal::<Span>(
        &[b'x'; 65],
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let image = emit_with_tier(&program, FeatureTier::Sse2).unwrap();
    let artifact = AotArtifact::from_image(&image, AotLimits::default()).unwrap();
    let mut bytes = artifact.as_bytes().to_vec();
    bytes[0] ^= 0xFF;
    assert_eq!(
        inspect_aot(&bytes, AotLimits::default()).unwrap_err(),
        AotError::InvalidMagic
    );
    let mut bytes = artifact.as_bytes().to_vec();
    bytes[8..10].copy_from_slice(&99_u16.to_le_bytes());
    assert_eq!(
        inspect_aot(&bytes, AotLimits::default()).unwrap_err(),
        AotError::UnsupportedVersion { actual: 99 }
    );
    assert_eq!(
        inspect_aot(&artifact.as_bytes()[..20], AotLimits::default()).unwrap_err(),
        AotError::Truncated
    );
}

#[test]
fn code_size_and_instruction_shape_evidence_is_bounded() {
    let exact = build_exact_literal::<Span>(
        &[b'x'; 65],
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    let class = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"abcde"),
        &[b'X'; 65],
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .unwrap();
    for tier in tiers() {
        for image in [
            emit_with_tier(&exact, tier).unwrap(),
            emit_with_tier(&class, tier).unwrap(),
        ] {
            let audit = audit_image(&image, AuditLimits::default()).unwrap();
            assert!(image.code().len() < 512);
            assert!(audit.shape.instructions < 128);
            assert_eq!(audit.shape.direct_branches, image.stats().internal_branches);
            assert_eq!(audit.shape.data_references, image.stats().relocations);
            assert_eq!(image.stats().runtime_scratch_bytes, 0);
        }
    }
}

fn emit_with_tier<O: fre_kernel_ir::Operation>(
    program: &fre_kernel_ir::ValidatedProgram<O>,
    tier: FeatureTier,
) -> Result<crate::NativeImage, EmitError> {
    emit(program, config(tier))
}

fn config(tier: FeatureTier) -> EmitConfig {
    EmitConfig {
        feature_tier: tier,
        ..EmitConfig::default()
    }
}

fn tiers() -> [FeatureTier; 3] {
    [FeatureTier::Scalar, FeatureTier::Sse2, FeatureTier::Avx2]
}

fn anchors() -> [AnchorFlags; 4] {
    [
        AnchorFlags::default(),
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

fn assert_emit_limit<O: fre_kernel_ir::Operation>(
    program: &fre_kernel_ir::ValidatedProgram<O>,
    mutate: impl FnOnce(&mut crate::EmitLimits),
    expected: EmitResource,
) {
    let mut config = config(FeatureTier::Avx2);
    mutate(&mut config.limits);
    let error = emit(program, config).unwrap_err();
    assert!(
        matches!(error, EmitError::ResourceLimit { resource, .. } if resource == expected),
        "expected {expected:?}, got {error:?}"
    );
}

fn assert_audit_resource(error: &AuditError, expected: EmitResource) {
    assert!(
        matches!(error, AuditError::ResourceLimit { resource, .. } if *resource == expected),
        "expected {expected:?}, got {error:?}"
    );
}

fn assert_aot_resource(error: &AotError, expected: EmitResource) {
    assert!(
        matches!(error, AotError::ResourceLimit { resource, .. } if *resource == expected),
        "expected {expected:?}, got {error:?}"
    );
}

fn below(value: usize) -> u64 {
    u64::try_from(value.checked_sub(1).unwrap()).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn add_signed(base: usize, displacement: i32) -> Option<usize> {
    if displacement >= 0 {
        base.checked_add(usize::try_from(displacement).ok()?)
    } else {
        base.checked_sub(usize::try_from(displacement.unsigned_abs()).ok()?)
    }
}
