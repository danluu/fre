use fre_kernel_ir::{
    AnchorFlags, ByteClass, OutputKind, SelectedEnd, ValidateLimits, build_class_suffix,
    build_exact_literal,
};
use sha2::{Digest, Sha256};

use crate::{
    AotLimits, AuditError, BackendVersion, CpuFeatures, DecodedInstruction, EmitError, EmitLimits,
    SearchBackendPolicy, SelectedEndAapcs64V2, SelectedEndRegisterBackendV2, UnsupportedReason,
    audit, audit::audit_selected_end_register_image_for_test_v2, audit_selected_end_register_v2,
    decode, emit_selected_end_register_v2, emit_with_backend, image::SearchCallAbi,
    selected_end_v2::AuditedSelectedEndRegisterImageV2,
};

#[test]
fn selected_end_register_abi2_mapping_is_exact() {
    assert_eq!(SelectedEndAapcs64V2::HAYSTACK_BASE.number(), 0);
    assert_eq!(SelectedEndAapcs64V2::HAYSTACK_LEN.number(), 1);
    assert_eq!(SelectedEndAapcs64V2::WINDOW_START.number(), 2);
    assert_eq!(SelectedEndAapcs64V2::WINDOW_END.number(), 3);
    assert_eq!(SelectedEndAapcs64V2::END_OR_ZERO.number(), 0);
}

#[test]
fn selected_end_register_v2_v8_and_tag21_have_exact_store_free_returns() {
    for (backend, policy, literal, version, features, v1_magic) in [
        (
            SelectedEndRegisterBackendV2::AsimdV8,
            SearchBackendPolicy::AsimdV8,
            b"needle".as_slice(),
            BackendVersion::SEARCH_V8,
            CpuFeatures::ASIMD,
            b"FREA64\0\x08".as_slice(),
        ),
        (
            SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
            SearchBackendPolicy::Sve2Fixed16V2,
            b"0123456789abcdef".as_slice(),
            BackendVersion::SEARCH_SVE2_FIXED16_V2,
            CpuFeatures::ASIMD_SVE2,
            b"FREA64\0\x15".as_slice(),
        ),
    ] {
        let program = build_exact_literal::<SelectedEnd>(
            literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("non-empty exact SelectedEnd");
        let image = emit_selected_end_register_v2(&program, backend, EmitLimits::default())
            .expect("ABI2 image");
        let repeated = emit_selected_end_register_v2(&program, backend, EmitLimits::default())
            .expect("deterministic ABI2 image");
        assert_eq!(image, repeated);
        assert_eq!(image.backend(), backend);
        assert_eq!(image.backend_version(), version);
        assert_eq!(image.output(), OutputKind::SelectedEnd);
        assert_eq!(image.literal_bytes(), u32::try_from(literal.len()).unwrap());
        assert_eq!(image.required_features(), features);
        assert_eq!(
            image.backend().fixed_active_vector_bytes(),
            if version == BackendVersion::SEARCH_SVE2_FIXED16_V2 {
                16
            } else {
                0
            }
        );

        let report =
            audit_selected_end_register_v2(&image).expect("independent ABI2 whole-template audit");
        assert_eq!(report.stores, 0);
        assert_eq!(report.returns, 2);
        let instructions = decode(image.code()).expect("ABI2 image decodes");
        assert!(
            instructions
                .iter()
                .all(|instruction| !instruction.uses_gpr(4)),
            "the removed Search-v1 result pointer must be wholly unused"
        );
        assert!(
            !instructions
                .iter()
                .any(|instruction| matches!(instruction, DecodedInstruction::Store64 { .. }))
        );
        assert!(instructions.ends_with(&[
            DecodedInstruction::MoveRegister64 {
                destination: 0,
                source: 14,
            },
            DecodedInstruction::Return,
            DecodedInstruction::MoveZero64 {
                destination: 0,
                immediate: 0,
                shift: 0,
            },
            DecodedInstruction::Return,
        ]));

        let artifact = image
            .to_aot(AotLimits::default())
            .expect("bounded ABI2 AOT");
        assert_eq!(&artifact.as_bytes()[..8], b"FRESR64\x02");
        assert_eq!(artifact.as_bytes()[15], 2);
        assert_eq!(image.artifact_identity(), artifact.identity());

        let mut domain_hash = Sha256::new();
        domain_hash
            .update(crate::selected_end_v2::SELECTED_END_REGISTER_ARTIFACT_IDENTITY_DOMAIN_V2);
        domain_hash.update(artifact.as_bytes());
        assert_eq!(
            image.artifact_identity().as_bytes(),
            &<[u8; 32]>::from(domain_hash.finalize())
        );

        let v1 = emit_with_backend(&program, policy, EmitLimits::default())
            .expect("unchanged Search-v1 image");
        let v1_artifact = v1.to_aot(AotLimits::default()).expect("bounded v1 AOT");
        assert_eq!(&v1_artifact.as_bytes()[..8], v1_magic);
        assert_eq!(v1_artifact.as_bytes()[15], 0);
        assert_eq!(v1.search_call_abi(), SearchCallAbi::OutSlotV1);
        assert_eq!(v1.artifact_identity(), v1_artifact.identity());
        assert_eq!(
            v1.artifact_identity().as_bytes(),
            &<[u8; 32]>::from(Sha256::digest(v1_artifact.as_bytes())),
            "Search-v1 retains its exact unprefixed identity domain"
        );
        assert_ne!(
            v1.artifact_identity().as_bytes(),
            image.artifact_identity().as_bytes()
        );
        assert_eq!(audit(image.inner()), Err(AuditError::InvalidImageContract));
        assert_eq!(
            audit_selected_end_register_image_for_test_v2(&v1),
            Err(AuditError::InvalidImageContract)
        );
        assert_eq!(
            AuditedSelectedEndRegisterImageV2::from_emitter_candidate(v1),
            Err(EmitError::InternalInvariant)
        );
    }
}

#[test]
fn selected_end_register_v2_v8_authenticates_every_exact_anchor_shape() {
    for anchors in [
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
    ] {
        let program =
            build_exact_literal::<SelectedEnd>(b"needle", anchors, ValidateLimits::default())
                .expect("anchored exact SelectedEnd");
        let image = emit_selected_end_register_v2(
            &program,
            SelectedEndRegisterBackendV2::AsimdV8,
            EmitLimits::default(),
        )
        .expect("anchored ABI2 V8 image");
        assert_eq!(
            audit_selected_end_register_v2(&image)
                .expect("anchored independent template")
                .stores,
            0
        );
    }
}

#[test]
fn selected_end_register_v2_refuses_empty_and_non_exact_programs() {
    let empty =
        build_exact_literal::<SelectedEnd>(b"", AnchorFlags::default(), ValidateLimits::default())
            .expect("empty exact SelectedEnd remains valid KIR");
    assert_eq!(
        emit_selected_end_register_v2(
            &empty,
            SelectedEndRegisterBackendV2::AsimdV8,
            EmitLimits::default(),
        ),
        Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        })
    );

    let class = build_class_suffix::<SelectedEnd>(
        ByteClass::from_bytes(b"ab"),
        b"tail",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("class-suffix SelectedEnd remains valid KIR");
    assert_eq!(
        emit_selected_end_register_v2(
            &class,
            SelectedEndRegisterBackendV2::AsimdV8,
            EmitLimits::default(),
        ),
        Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        })
    );
}

#[test]
fn selected_end_register_v2_literal_boundaries_are_explicit() {
    for width in [1_usize, 32] {
        let literal = vec![b'x'; width];
        let program = build_exact_literal::<SelectedEnd>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("boundary exact SelectedEnd");
        let image = emit_selected_end_register_v2(
            &program,
            SelectedEndRegisterBackendV2::AsimdV8,
            EmitLimits::default(),
        )
        .expect("V8 admits non-empty exact boundaries");
        assert_eq!(image.literal_bytes(), u32::try_from(width).unwrap());
        assert_eq!(image.backend(), SelectedEndRegisterBackendV2::AsimdV8);
        assert_eq!(image.backend().fixed_active_vector_bytes(), 0);
    }

    for width in [15_usize, 17] {
        let literal = vec![b'x'; width];
        let program = build_exact_literal::<SelectedEnd>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("near-tag21 exact SelectedEnd");
        assert_eq!(
            emit_selected_end_register_v2(
                &program,
                SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
                EmitLimits::default(),
            ),
            Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            })
        );
    }
}

#[test]
fn selected_end_register_v2_audit_independently_refuses_x4_and_any_store() {
    let program = build_exact_literal::<SelectedEnd>(
        b"needle",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("exact SelectedEnd");
    let valid = emit_selected_end_register_v2(
        &program,
        SelectedEndRegisterBackendV2::AsimdV8,
        EmitLimits::default(),
    )
    .expect("ABI2 image");

    let mut x4 = valid.clone();
    x4.inner_mut_for_test().code[..4].copy_from_slice(&0xaa00_03e4_u32.to_le_bytes());
    assert_eq!(
        audit_selected_end_register_v2(&x4),
        Err(AuditError::ForbiddenSelectedEndRegisterUse {
            offset: 0,
            register: 4,
        })
    );

    let mut store = valid;
    let instructions = decode(store.code()).expect("valid image decodes");
    let found_return = instructions.len().checked_sub(4).expect("two return pairs");
    let found_offset = found_return.checked_mul(4).expect("bounded code offset");
    let store_word = crate::decode::canonical_word(DecodedInstruction::Store64 {
        source: 14,
        base: 5,
        offset: 8,
    })
    .expect("canonical store");
    store.inner_mut_for_test().code[found_offset..found_offset + 4]
        .copy_from_slice(&store_word.to_le_bytes());
    assert_eq!(
        audit_selected_end_register_v2(&store),
        Err(AuditError::ForbiddenStore {
            offset: u32::try_from(found_offset).unwrap(),
            base: 5,
            displacement: 8,
        })
    );
}
