#![allow(
    clippy::arithmetic_side_effects,
    reason = "the bounded test ISA model intentionally implements architectural wrapping arithmetic"
)]

use core::mem::{align_of, size_of};

use fre_kernel_ir::{
    AggregateExecutionLimits, AggregateOutput, AnchorFlags, BlockId, ByteClass, Count,
    ExecutionLimits, Exists, InvalidProgram, OutputKind, RawProgram, SearchWindow, SelectedEnd,
    Span, SpanSum, ValidateError, ValidateLimits, build_class_suffix, build_exact_aggregate,
    build_exact_literal,
};

use crate::{
    AggregateResultLayout, AotLimits, AuditError, BackendVersion, Condition, ConfirmationKind,
    CpuFeatures, DataSymbol, DataSymbolKind, DecodeError, DecodedInstruction, EmitError,
    EmitLimits, LabelKind, MAX_REPEATED_CONFIRM_BYTES, NativeAggregateImage, NativeAggregateResult,
    NativeImage, NativeResult, RelocationKind, RelocationTarget, ResourceKind, ResultLayout,
    SearchBackendPolicy, UnsupportedReason, audit, audit_aggregate, decode, decode_one, emit,
    emit::emit_search_version_for_test, emit_audited_with_backend, emit_exact_aggregate,
    emit_exact_aggregate_sve2_fixed16_count_experimental,
    emit_exact_aggregate_sve2_fixed16_pair_count_experimental,
    emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental,
    emit_exact_aggregate_sve2_fixed16_span_sum_experimental, emit_sve2_16, emit_sve2_fixed16_v2,
    emit_sve16, emit_sve16_v6, emit_with_backend, image::SearchShape,
};

const HAYSTACK_BASE: u64 = 0x0010_0000;
const RESULT_BASE: u64 = 0x0020_0000;
const CODE_BASE: u64 = 0x0030_0000;

#[test]
fn abi_layout_is_stable() {
    assert_eq!(
        size_of::<NativeResult>(),
        usize::from(ResultLayout::AARCH64.size)
    );
    assert_eq!(
        align_of::<NativeResult>(),
        usize::from(ResultLayout::AARCH64.alignment)
    );
    assert_eq!(ResultLayout::AARCH64.start_offset, 0);
    assert_eq!(ResultLayout::AARCH64.end_offset, 8);
    assert_eq!(
        size_of::<NativeAggregateResult>(),
        usize::from(AggregateResultLayout::AARCH64.size)
    );
    assert_eq!(
        align_of::<NativeAggregateResult>(),
        usize::from(AggregateResultLayout::AARCH64.alignment)
    );
    assert_eq!(AggregateResultLayout::AARCH64.value_offset, 0);
}

#[test]
fn audited_emission_is_the_same_immutable_image_as_legacy_emission() {
    let program = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("program");
    let audited = emit_audited_with_backend(
        &program,
        SearchBackendPolicy::Sve2Fixed16V2,
        EmitLimits::default(),
    )
    .expect("audited image");
    let legacy = emit_with_backend(
        &program,
        SearchBackendPolicy::Sve2Fixed16V2,
        EmitLimits::default(),
    )
    .expect("legacy image");
    assert_eq!(audited.as_image(), &legacy);
    assert_eq!(audited.into_image(), legacy);

    let mut mutated = legacy.clone();
    mutated.code[0] ^= u8::MAX;
    reseal_test_image(&mut mutated);
    assert!(
        audit(&mutated).is_err(),
        "a resealed plain-image mutation must still fail the independent audit"
    );
}

#[test]
fn exact_literal_images_decode_and_are_deterministic() {
    for literal in [
        b"".as_slice(),
        b"a",
        b"needle",
        b"0123456789abcdef",
        b"0123456789abcdefg",
        &[b'x'; MAX_REPEATED_CONFIRM_BYTES],
    ] {
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("valid literal kernel");
        let first = emit(&program, EmitLimits::default())
            .unwrap_or_else(|error| panic!("emission succeeds for {literal:?}: {error:?}"));
        let second = emit(&program, EmitLimits::default()).expect("emission is repeatable");
        assert_eq!(first, second);
        assert_eq!(audit(&first).expect("authentic image").returns, 2);
        assert_eq!(
            decode(first.code()).expect("known instruction set").len() * 4,
            first.code().len()
        );
        assert_eq!(
            first.target().features.contains(CpuFeatures::ASIMD),
            !literal.is_empty()
        );
        let aot = first
            .to_aot(AotLimits::default())
            .expect("bounded AOT image");
        assert_eq!(first.artifact_identity(), aot.identity());
        let receipt = first.artifact_identity_receipt();
        assert_eq!(receipt.identity, aot.identity());
        assert_eq!(receipt.canonical_bytes_hashed, 0);
        assert_eq!(receipt.scratch_bytes, 0);
        assert_eq!(receipt.heap_allocations, 0);
        assert!(
            first.stats().emission_work
                >= u64::try_from(aot.as_bytes().len()).expect("AOT length fits u64")
        );
        assert_eq!(
            aot,
            second.to_aot(AotLimits::default()).expect("same AOT image")
        );
        assert_eq!(aot.identity(), aot.identity());
        assert_ne!(aot.identity().as_bytes(), &[0; 32]);
        assert!(!aot.as_bytes().windows(8).any(|bytes| {
            bytes == HAYSTACK_BASE.to_le_bytes() || bytes == RESULT_BASE.to_le_bytes()
        }));
    }
}

#[test]
fn aggregate_images_are_typed_deterministic_and_domain_separated() {
    let count = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("count aggregate");
    let spans = build_exact_aggregate::<SpanSum>(b"needle", ValidateLimits::default())
        .expect("span aggregate");
    let count_image =
        emit_exact_aggregate(&count, EmitLimits::default()).expect("count image emission");
    let repeated =
        emit_exact_aggregate(&count, EmitLimits::default()).expect("deterministic emission");
    let span_image =
        emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image emission");
    assert_eq!(count_image, repeated);
    assert_eq!(count_image.output(), AggregateOutput::Count);
    assert_eq!(span_image.output(), AggregateOutput::SpanSum);
    assert_eq!(count_image.literal_bytes(), 6);
    assert_eq!(
        audit_aggregate(&count_image)
            .expect("aggregate audit")
            .stores,
        1
    );
    assert_eq!(
        audit_aggregate(&span_image)
            .expect("aggregate audit")
            .stores,
        1
    );
    assert_eq!(
        audit(count_image.inner()),
        Err(AuditError::InvalidImageContract)
    );
    assert_ne!(count.cache_identity(), spans.cache_identity());
    assert_ne!(
        count_image.artifact_identity(),
        span_image.artifact_identity()
    );
    let count_aot = count_image.to_aot(AotLimits::default()).expect("count AOT");
    assert_eq!(&count_aot.as_bytes()[..8], b"FREA64A\x01");
    assert_eq!(count_aot.identity(), count_image.artifact_identity());
    assert_ne!(
        count_aot,
        span_image.to_aot(AotLimits::default()).expect("span AOT")
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the experimental backend receipt keeps emission, audit, decoding, identity, mutation, and oracle checks together"
)]
fn experimental_sve2_fixed16_count_is_explicit_audited_and_matches_oracle() {
    let program =
        build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).expect("count program");
    let current =
        emit_exact_aggregate(&program, EmitLimits::default()).expect("current aggregate image");
    let image =
        emit_exact_aggregate_sve2_fixed16_count_experimental(&program, EmitLimits::default())
            .expect("experimental SVE2 image");
    let repeated =
        emit_exact_aggregate_sve2_fixed16_count_experimental(&program, EmitLimits::default())
            .expect("deterministic experimental image");

    assert_eq!(image, repeated);
    assert_eq!(current.backend_version(), BackendVersion::AGGREGATE_CURRENT);
    assert_eq!(
        image.backend_version(),
        BackendVersion::AGGREGATE_SVE2_FIXED16_COUNT_EXPERIMENTAL_V1
    );
    assert_eq!(current.target().features, CpuFeatures::ASIMD);
    assert_eq!(
        image.target().features,
        CpuFeatures::SVE.union(CpuFeatures::SVE2)
    );
    assert_eq!(
        audit_aggregate(&image)
            .expect("whole-template audit")
            .stores,
        1
    );

    let current_instructions = decode(current.code()).expect("current ASIMD decoder");
    assert_eq!(current_instructions.len(), 42);
    assert!(
        current_instructions.contains(&DecodedInstruction::CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        })
    );
    assert!(
        current_instructions.contains(&DecodedInstruction::AddAcrossBytes16 {
            destination: 0,
            source: 0,
        })
    );
    let instructions = decode(image.code()).expect("SVE2 decoder");
    assert_eq!(instructions.len(), 39);
    assert_eq!(image.stats().vector_instructions, 5);
    assert!(
        instructions
            .iter()
            .all(|instruction| !instruction.is_asimd())
    );
    assert!(instructions.contains(&DecodedInstruction::SvePtrueBytesVl16 { destination: 0 }));
    assert!(instructions.contains(&DecodedInstruction::Sve2MatchBytes {
        destination: 1,
        predicate: 0,
        left: 0,
        right: 1,
    }));
    assert!(
        instructions.contains(&DecodedInstruction::SveCountPredicateBytes {
            destination: 10,
            predicate: 0,
            source: 1,
        })
    );

    assert_eq!(
        decode_one(0x2518_e120, 0),
        Ok(DecodedInstruction::SvePtrueBytesVl16 { destination: 0 })
    );
    assert_eq!(
        decode_one(0x0520_3961, 4),
        Ok(DecodedInstruction::SveDuplicateByte {
            destination: 1,
            source: 11,
        })
    );
    assert_eq!(
        decode_one(0xa400_a1e0, 8),
        Ok(DecodedInstruction::SveLoadBytes {
            destination: 0,
            predicate: 0,
            base: 15,
        })
    );
    assert_eq!(
        decode_one(0x4521_8001, 12),
        Ok(DecodedInstruction::Sve2MatchBytes {
            destination: 1,
            predicate: 0,
            left: 0,
            right: 1,
        })
    );
    assert_eq!(
        decode_one(0x2520_802a, 16),
        Ok(DecodedInstruction::SveCountPredicateBytes {
            destination: 10,
            predicate: 0,
            source: 1,
        })
    );

    for length in [0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
        for phase in 0..4 {
            let haystack: Vec<u8> = (0..length)
                .map(|index| if index % 4 == phase { b'x' } else { b'y' })
                .collect();
            let expected = *program
                .execute(&haystack, AggregateExecutionLimits::unlimited())
                .expect("oracle")
                .output();
            let actual = simulate_aggregate(&image, &haystack).expect("fixed-16 SVE2 simulation");
            assert_eq!(aggregate_output(actual), Ok(expected));
        }
    }

    let width_two =
        build_exact_aggregate::<Count>(b"xx", ValidateLimits::default()).expect("width-two count");
    assert_eq!(
        emit_exact_aggregate_sve2_fixed16_count_experimental(&width_two, EmitLimits::default()),
        Err(EmitError::Unsupported {
            reason: crate::UnsupportedReason::KernelShape,
        })
    );

    let mut missing_sve2 = image.inner().clone();
    missing_sve2.target.features = CpuFeatures::SVE;
    reseal_test_image(&mut missing_sve2);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(missing_sve2)),
        Err(AuditError::FeatureMismatch)
    );

    for (index, replacement) in [
        (4, DecodedInstruction::SvePtrueBytesVl16 { destination: 1 }),
        (
            14,
            DecodedInstruction::Sve2MatchBytes {
                destination: 2,
                predicate: 0,
                left: 0,
                right: 1,
            },
        ),
    ] {
        let mut mutated = image.inner().clone();
        replace_test_decoded_at(&mut mutated, index, replacement);
        reseal_test_image(&mut mutated);
        assert!(
            audit_aggregate(&NativeAggregateImage::new(mutated)).is_err(),
            "SVE operand mutation at instruction {index} must fail"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the pair backend receipt keeps admission, audit, decoding, identity, overlap, and boundary checks together"
)]
fn experimental_sve2_fixed16_pair_count_is_exact_explicit_and_audited() {
    let direct_program =
        build_exact_aggregate::<Count>(b"ab", ValidateLimits::default()).expect("pair program");
    let recovery_program = build_exact_aggregate::<Count>(b"aa", ValidateLimits::default())
        .expect("self-overlapping pair program");
    let current =
        emit_exact_aggregate(&direct_program, EmitLimits::default()).expect("current image");
    let direct = emit_exact_aggregate_sve2_fixed16_pair_count_experimental(
        &direct_program,
        EmitLimits::default(),
    )
    .expect("direct SVE2 pair image");
    let repeated = emit_exact_aggregate_sve2_fixed16_pair_count_experimental(
        &direct_program,
        EmitLimits::default(),
    )
    .expect("deterministic pair image");
    let recovery = emit_exact_aggregate_sve2_fixed16_pair_count_experimental(
        &recovery_program,
        EmitLimits::default(),
    )
    .expect("overlap-safe SVE2 pair image");

    assert_eq!(direct, repeated);
    assert_eq!(current.backend_version(), BackendVersion::AGGREGATE_CURRENT);
    assert_eq!(
        direct.backend_version(),
        BackendVersion::AGGREGATE_SVE2_FIXED16_PAIR_COUNT_EXPERIMENTAL_V1
    );
    assert_eq!(direct.output(), AggregateOutput::Count);
    assert_eq!(direct.literal_bytes(), 2);
    assert_eq!(
        direct.target().features,
        CpuFeatures::SVE.union(CpuFeatures::SVE2)
    );
    assert_ne!(direct.artifact_identity(), current.artifact_identity());
    assert_ne!(direct.artifact_identity(), recovery.artifact_identity());
    let direct_aot = direct
        .to_aot(AotLimits::default())
        .expect("pair aggregate AOT");
    assert_eq!(&direct_aot.as_bytes()[..8], b"FREA64A\x01");
    assert_eq!(direct_aot.identity(), direct.artifact_identity());
    assert_ne!(
        direct_aot,
        current
            .to_aot(AotLimits::default())
            .expect("current aggregate AOT")
    );
    assert_eq!(
        audit_aggregate(&direct)
            .expect("direct whole-template audit")
            .stores,
        1
    );
    assert_eq!(
        audit_aggregate(&recovery)
            .expect("recovery whole-template audit")
            .stores,
        1
    );

    let direct_instructions = decode(direct.code()).expect("direct pair decode");
    let recovery_instructions = decode(recovery.code()).expect("recovery pair decode");
    for (image, instructions) in [
        (&direct, &direct_instructions),
        (&recovery, &recovery_instructions),
    ] {
        assert_eq!(instructions.len(), 55);
        assert_eq!(image.stats().vector_instructions, 9);
        assert!(
            instructions
                .iter()
                .all(|instruction| !instruction.is_asimd())
        );
        assert!(instructions.contains(&DecodedInstruction::SvePtrueBytesVl16 { destination: 0 }));
        assert!(instructions.contains(&DecodedInstruction::SveLoadBytes {
            destination: 2,
            predicate: 0,
            base: 10,
        }));
        assert!(instructions.contains(&DecodedInstruction::Sve2MatchBytes {
            destination: 2,
            predicate: 0,
            left: 2,
            right: 3,
        }));
        assert!(
            instructions.contains(&DecodedInstruction::SveAndPredicateBytes {
                destination: 1,
                predicate: 0,
                left: 1,
                right: 2,
            })
        );
    }
    assert!(
        direct_instructions.contains(&DecodedInstruction::SveCountPredicateBytes {
            destination: 10,
            predicate: 0,
            source: 1,
        })
    );
    assert!(!direct_instructions.iter().any(|instruction| matches!(
        instruction,
        DecodedInstruction::SveTestPredicateBytes { .. }
    )));
    assert!(
        recovery_instructions.contains(&DecodedInstruction::SveTestPredicateBytes {
            predicate: 0,
            tested: 1,
        })
    );
    assert!(!recovery_instructions.iter().any(|instruction| matches!(
        instruction,
        DecodedInstruction::SveCountPredicateBytes { .. }
    )));

    assert_eq!(
        decode_one(0xa400_a142, 0),
        Ok(DecodedInstruction::SveLoadBytes {
            destination: 2,
            predicate: 0,
            base: 10,
        })
    );
    assert_eq!(
        decode_one(0x4523_8042, 4),
        Ok(DecodedInstruction::Sve2MatchBytes {
            destination: 2,
            predicate: 0,
            left: 2,
            right: 3,
        })
    );
    assert_eq!(
        decode_one(0x2502_4021, 8),
        Ok(DecodedInstruction::SveAndPredicateBytes {
            destination: 1,
            predicate: 0,
            left: 1,
            right: 2,
        })
    );

    for literal in [b"ab".as_slice(), b"aa", b"\0\0", b"\xff\0"] {
        let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("differential pair program");
        let image = emit_exact_aggregate_sve2_fixed16_pair_count_experimental(
            &program,
            EmitLimits::default(),
        )
        .expect("differential pair image");
        for length in [0, 1, 2, 3, 15, 16, 17, 18, 31, 32, 33, 34, 63, 64, 65] {
            for phase in 0..7 {
                let haystack: Vec<u8> = (0..length)
                    .map(|index| {
                        if (index + phase) % 5 < 3 {
                            literal[(index + phase) % 2]
                        } else {
                            u8::try_from((index * 37 + phase * 19) & 0xff).expect("masked byte")
                        }
                    })
                    .collect();
                let expected = *program
                    .execute(&haystack, AggregateExecutionLimits::unlimited())
                    .expect("oracle")
                    .output();
                let actual = simulate_aggregate(&image, &haystack).expect("SVE2 pair simulation");
                assert_eq!(
                    aggregate_output(actual),
                    Ok(expected),
                    "literal={literal:?} length={length} phase={phase}"
                );
            }
        }
    }

    for run_length in 0..=80 {
        let haystack = vec![b'a'; run_length];
        let expected = u64::try_from(run_length / 2).expect("bounded run");
        let actual = simulate_aggregate(&recovery, &haystack).expect("overlap simulation");
        assert_eq!(aggregate_output(actual), Ok(expected));
    }

    for invalid_literal in [b"x".as_slice(), b"xyz".as_slice()] {
        let invalid = build_exact_aggregate::<Count>(invalid_literal, ValidateLimits::default())
            .expect("invalid-width pair program");
        assert_eq!(
            emit_exact_aggregate_sve2_fixed16_pair_count_experimental(
                &invalid,
                EmitLimits::default()
            ),
            Err(EmitError::Unsupported {
                reason: crate::UnsupportedReason::KernelShape,
            })
        );
    }

    for (index, replacement) in [
        (
            20,
            DecodedInstruction::SveLoadBytes {
                destination: 2,
                predicate: 0,
                base: 15,
            },
        ),
        (
            23,
            DecodedInstruction::SveAndPredicateBytes {
                destination: 2,
                predicate: 0,
                left: 1,
                right: 2,
            },
        ),
    ] {
        let mut mutated = direct.inner().clone();
        replace_test_decoded_at(&mut mutated, index, replacement);
        reseal_test_image(&mut mutated);
        assert!(
            audit_aggregate(&NativeAggregateImage::new(mutated)).is_err(),
            "pair operand mutation at instruction {index} must fail"
        );
    }

    let mut wrong_output = direct.inner().clone();
    wrong_output
        .aggregate
        .as_mut()
        .expect("aggregate manifest")
        .output = AggregateOutput::SpanSum;
    reseal_test_image(&mut wrong_output);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(wrong_output)),
        Err(AuditError::InvalidAggregateManifest)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the pair SpanSum receipt keeps exact reuse, accounting, audit, differential, and admission checks together"
)]
fn experimental_sve2_fixed16_pair_span_sum_reuses_checked_count_result() {
    let count =
        build_exact_aggregate::<Count>(b"ab", ValidateLimits::default()).expect("count program");
    let spans =
        build_exact_aggregate::<SpanSum>(b"ab", ValidateLimits::default()).expect("span program");
    let current = emit_exact_aggregate(&spans, EmitLimits::default()).expect("current image");
    let count_image =
        emit_exact_aggregate_sve2_fixed16_pair_count_experimental(&count, EmitLimits::default())
            .expect("pair count image");
    let span_image =
        emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(&spans, EmitLimits::default())
            .expect("pair span-sum image");
    let repeated =
        emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(&spans, EmitLimits::default())
            .expect("deterministic pair span-sum image");

    assert_eq!(span_image, repeated);
    assert_eq!(current.backend_version(), BackendVersion::AGGREGATE_CURRENT);
    assert_eq!(
        span_image.backend_version(),
        BackendVersion::AGGREGATE_SVE2_FIXED16_PAIR_SPAN_SUM_EXPERIMENTAL_V1
    );
    assert_eq!(span_image.output(), AggregateOutput::SpanSum);
    assert_eq!(span_image.literal_bytes(), 2);
    assert_eq!(
        span_image.target().features,
        CpuFeatures::SVE.union(CpuFeatures::SVE2)
    );
    assert_ne!(
        span_image.artifact_identity(),
        count_image.artifact_identity()
    );
    assert_ne!(span_image.artifact_identity(), current.artifact_identity());
    assert_eq!(
        audit_aggregate(&span_image).expect("sealed audit").stores,
        1
    );

    let count_stats = count_image.stats();
    assert_eq!(count_stats.code_bytes, 220);
    assert_eq!(count_stats.relocations, 12);
    assert_eq!(count_stats.labels, 6);
    assert_eq!(count_stats.vector_instructions, 9);
    assert_eq!(count_stats.emission_work, 739);
    let stats = span_image.stats();
    assert_eq!(stats.code_bytes, 236);
    assert_eq!(stats.data_bytes, 2);
    assert_eq!(stats.relocations, 13);
    assert_eq!(stats.labels, 6);
    assert_eq!(stats.vector_instructions, 9);
    assert_eq!(stats.emission_work, 780);
    assert_eq!(span_image.layout().rodata_from_code_start, 240);
    assert_eq!(span_image.layout().total_mapped_bytes, 242);
    let aot = span_image
        .to_aot(AotLimits::default())
        .expect("pair SpanSum AOT");
    assert_eq!(aot.as_bytes().len(), 694);
    assert_eq!(aot.identity(), span_image.artifact_identity());

    let instructions = decode(span_image.code()).expect("pair SpanSum decode");
    assert_eq!(instructions.len(), 59);
    assert_eq!(
        &instructions[50..54],
        &[
            DecodedInstruction::MoveRegister64 {
                destination: 14,
                source: 13,
            },
            DecodedInstruction::AddRegister64 {
                destination: 13,
                left: 13,
                right: 13,
            },
            DecodedInstruction::CompareRegister64 {
                left: 13,
                right: 14,
            },
            DecodedInstruction::BranchCondition {
                condition: Condition::CarryClear,
                displacement: 16,
            },
        ]
    );
    assert!(
        instructions.contains(&DecodedInstruction::SveCountPredicateBytes {
            destination: 10,
            predicate: 0,
            source: 1,
        })
    );
    assert!(
        instructions
            .iter()
            .all(|instruction| !instruction.is_asimd())
    );

    for (index, replacement) in [
        (
            51,
            DecodedInstruction::AddRegister64 {
                destination: 13,
                left: 13,
                right: 10,
            },
        ),
        (
            53,
            DecodedInstruction::BranchCondition {
                condition: Condition::CarrySet,
                displacement: 16,
            },
        ),
    ] {
        let mut mutated = span_image.inner().clone();
        replace_test_decoded_at(&mut mutated, index, replacement);
        reseal_test_image(&mut mutated);
        assert!(
            audit_aggregate(&NativeAggregateImage::new(mutated)).is_err(),
            "checked-double mutation at instruction {index} must fail"
        );
    }

    for literal in [b"ab".as_slice(), b"\0\xff".as_slice(), b"\xff\0".as_slice()] {
        let count_program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("differential count program");
        let span_program = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("differential span program");
        let image = emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(
            &span_program,
            EmitLimits::default(),
        )
        .expect("differential pair SpanSum image");
        for length in [0, 1, 2, 3, 15, 16, 17, 18, 31, 32, 33, 34, 63, 64, 65] {
            for phase in 0..7 {
                let haystack: Vec<u8> = (0..length)
                    .map(|index| {
                        if (index + phase) % 5 < 3 {
                            literal[(index + phase) % 2]
                        } else {
                            u8::try_from((index * 37 + phase * 19) & 0xff).expect("masked byte")
                        }
                    })
                    .collect();
                let expected_count = *count_program
                    .execute(&haystack, AggregateExecutionLimits::unlimited())
                    .expect("count oracle")
                    .output();
                let expected = *span_program
                    .execute(&haystack, AggregateExecutionLimits::unlimited())
                    .expect("SpanSum oracle")
                    .output();
                assert_eq!(expected, expected_count * 2);
                let actual =
                    simulate_aggregate(&image, &haystack).expect("pair SpanSum simulation");
                assert_eq!(
                    aggregate_output(actual),
                    Ok(expected),
                    "literal={literal:?} length={length} phase={phase}"
                );
            }
        }
    }

    for invalid_literal in [
        b"".as_slice(),
        b"x".as_slice(),
        b"aa".as_slice(),
        b"xyz".as_slice(),
    ] {
        let invalid = build_exact_aggregate::<SpanSum>(invalid_literal, ValidateLimits::default())
            .expect("invalid-shape SpanSum program");
        assert_eq!(
            emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(
                &invalid,
                EmitLimits::default()
            ),
            Err(EmitError::Unsupported {
                reason: crate::UnsupportedReason::KernelShape,
            })
        );
    }

    for (resource, exact) in [
        (ResourceKind::CodeBytes, u64::from(stats.code_bytes)),
        (ResourceKind::DataBytes, u64::from(stats.data_bytes)),
        (ResourceKind::Relocations, u64::from(stats.relocations)),
        (ResourceKind::Labels, u64::from(stats.labels)),
        (ResourceKind::EmissionWork, stats.emission_work),
        (ResourceKind::ScratchBytes, stats.scratch_bytes),
    ] {
        emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(
            &spans,
            with_limit(EmitLimits::default(), resource, exact),
        )
        .expect("exact pair SpanSum resource boundary succeeds");
        let error = emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(
            &spans,
            with_limit(EmitLimits::default(), resource, exact - 1),
        )
        .expect_err("one below pair SpanSum resource boundary fails");
        assert!(
            matches!(
                error,
                EmitError::ResourceLimit {
                    resource: actual,
                    ..
                } if actual == resource
            ),
            "wrong error for {resource:?}: {error:?}"
        );
    }
}

#[test]
fn experimental_sve2_fixed16_span_sum_reuses_the_qualified_width_one_loop() {
    let count =
        build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).expect("count program");
    let spans = build_exact_aggregate::<SpanSum>(b"x", ValidateLimits::default())
        .expect("span-sum program");
    let count_image =
        emit_exact_aggregate_sve2_fixed16_count_experimental(&count, EmitLimits::default())
            .expect("count image");
    let span_image =
        emit_exact_aggregate_sve2_fixed16_span_sum_experimental(&spans, EmitLimits::default())
            .expect("span-sum image");

    assert_eq!(
        span_image.backend_version(),
        BackendVersion::AGGREGATE_SVE2_FIXED16_SPAN_SUM_EXPERIMENTAL_V1
    );
    assert_eq!(span_image.output(), AggregateOutput::SpanSum);
    assert_eq!(span_image.code(), count_image.code());
    assert_eq!(span_image.rodata(), count_image.rodata());
    assert_ne!(
        span_image.artifact_identity(),
        count_image.artifact_identity()
    );
    audit_aggregate(&span_image).expect("span-sum template audit");

    for length in [0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
        for phase in 0..4 {
            let haystack: Vec<u8> = (0..length)
                .map(|index| if index % 4 == phase { b'x' } else { b'y' })
                .collect();
            let expected = *spans
                .execute(&haystack, AggregateExecutionLimits::unlimited())
                .expect("oracle")
                .output();
            let actual =
                simulate_aggregate(&span_image, &haystack).expect("fixed-16 SVE2 simulation");
            assert_eq!(aggregate_output(actual), Ok(expected));
        }
    }

    let width_two = build_exact_aggregate::<SpanSum>(b"xx", ValidateLimits::default())
        .expect("width-two span sum");
    assert_eq!(
        emit_exact_aggregate_sve2_fixed16_span_sum_experimental(&width_two, EmitLimits::default()),
        Err(EmitError::Unsupported {
            reason: crate::UnsupportedReason::KernelShape,
        })
    );
}

#[test]
fn aggregate_decoded_execution_matches_oracle_exhaustively() {
    let literals = all_sequences(b"ab", 3);
    let haystacks = all_sequences(b"ab", 6);
    let mut comparisons = 0_u64;
    for literal in &literals {
        let count = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("count program");
        let spans = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("span-sum program");
        let count_image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
        let span_image = emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image");
        for haystack in &haystacks {
            let expected_count = *count
                .execute(haystack, AggregateExecutionLimits::unlimited())
                .expect("count oracle")
                .output();
            let expected_spans = *spans
                .execute(haystack, AggregateExecutionLimits::unlimited())
                .expect("span oracle")
                .output();
            assert_eq!(
                aggregate_output(
                    simulate_aggregate(&count_image, haystack).expect("count ISA model")
                ),
                Ok(expected_count),
                "count literal={literal:?} haystack={haystack:?}"
            );
            assert_eq!(
                aggregate_output(
                    simulate_aggregate(&span_image, haystack).expect("span ISA model")
                ),
                Ok(expected_spans),
                "span literal={literal:?} haystack={haystack:?}"
            );
            comparisons += 2;
        }
    }
    assert_eq!(comparisons, 3_810);
}

#[test]
fn aggregate_simd_tails_arbitrary_bytes_and_overlap_are_exact() {
    let directed = [
        (
            b"a".as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
        ),
        (b"aa", b"aaaaa"),
        (b"aba", b"abababa"),
        (b"\0\xff", b"x\0\xff\0\xffy"),
    ];
    for (literal, haystack) in directed {
        assert_aggregate_pair(literal, haystack);
    }
    let literal_lengths = [1_usize, 2, 3, 15, 16, 17, 31, 32];
    for literal_len in literal_lengths {
        let literal: Vec<u8> = (0..literal_len)
            .map(|index| {
                u8::try_from(index)
                    .expect("length capped at 32")
                    .wrapping_mul(37)
                    .wrapping_add(if index % 2 == 0 { 0 } else { 0xff })
            })
            .collect();
        for prefix in 0..32 {
            for tail in 0..32 {
                let mut haystack = vec![0x5a; prefix];
                haystack.extend_from_slice(&literal);
                haystack.extend(core::iter::repeat_n(0xa5, tail));
                haystack.extend_from_slice(&literal);
                assert_aggregate_pair(&literal, &haystack);
            }
        }
    }
}

#[test]
fn aggregate_long_confirmation_preserves_filter_state_and_cursor_order() {
    let literal = b"abcdefghijklmnop";
    let mut false_then_true = vec![b'x'; 47];
    false_then_true[0] = literal[0];
    false_then_true[15] = literal[15];
    false_then_true[31..47].copy_from_slice(literal);
    assert_aggregate_pair(literal, &false_then_true);

    let repeated_edge = b"a12345678901234a";
    let mut false_only = vec![b'x'; 47];
    for start in [0_usize, 15, 16, 31] {
        false_only[start] = repeated_edge[0];
        false_only[start + repeated_edge.len() - 1] = repeated_edge[15];
    }
    assert_aggregate_pair(repeated_edge, &false_only);

    let long: Vec<u8> = (0_u8..32).map(|byte| byte.wrapping_mul(7)).collect();
    for first_start in [0_usize, 15, 16] {
        let second_start = first_start + long.len();
        let mut haystack = vec![0xee; second_start + long.len()];
        haystack[first_start..first_start + long.len()].copy_from_slice(&long);
        haystack[second_start..second_start + long.len()].copy_from_slice(&long);
        assert_aggregate_pair(&long, &haystack);
    }

    let mut worst_false_positive = vec![b'a'; 32];
    worst_false_positive[30] = b'b';
    assert_aggregate_pair(&worst_false_positive, &[b'a'; 160]);
    assert_aggregate_pair(&[b'a'; 32], &[b'a'; 96]);

    let boundary_literal = b"aba";
    for candidates in [0_usize, 1, 15, 16, 17, 31, 32, 33] {
        let haystack_len = if candidates == 0 {
            boundary_literal.len() - 1
        } else {
            candidates + boundary_literal.len() - 1
        };
        let empty = vec![b'x'; haystack_len];
        assert_aggregate_pair(boundary_literal, &empty);
        for lane in [0_usize, 15, 16] {
            if lane < candidates {
                let mut matched = empty.clone();
                matched[lane..lane + boundary_literal.len()].copy_from_slice(boundary_literal);
                assert_aggregate_pair(boundary_literal, &matched);
            }
        }
    }
}

#[test]
fn aggregate_emission_resources_are_exact_and_bounded() {
    let program = build_exact_aggregate::<Count>(
        &[b'x'; fre_kernel_ir::MAX_EXACT_AGGREGATE_LITERAL_BYTES],
        ValidateLimits::default(),
    )
    .expect("maximum admitted aggregate literal");
    let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("baseline image");
    let stats = image.stats();
    for (resource, exact) in [
        (ResourceKind::CodeBytes, u64::from(stats.code_bytes)),
        (ResourceKind::DataBytes, u64::from(stats.data_bytes)),
        (ResourceKind::Relocations, u64::from(stats.relocations)),
        (ResourceKind::Labels, u64::from(stats.labels)),
        (ResourceKind::EmissionWork, stats.emission_work),
        (ResourceKind::ScratchBytes, stats.scratch_bytes),
    ] {
        emit_exact_aggregate(&program, with_limit(EmitLimits::default(), resource, exact))
            .expect("exact aggregate resource boundary succeeds");
        let error = emit_exact_aggregate(
            &program,
            with_limit(
                EmitLimits::default(),
                resource,
                exact.checked_sub(1).expect("nonzero resource"),
            ),
        )
        .expect_err("one below aggregate resource boundary fails");
        assert!(matches!(
            error,
            EmitError::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
    }
    let aot = image.to_aot(AotLimits::default()).expect("aggregate AOT");
    let exact = u64::try_from(aot.as_bytes().len()).expect("small AOT");
    image
        .to_aot(AotLimits { max_bytes: exact })
        .expect("exact aggregate AOT limit");
    assert!(matches!(
        image.to_aot(AotLimits {
            max_bytes: exact - 1,
        }),
        Err(EmitError::ResourceLimit {
            resource: ResourceKind::AotBytes,
            ..
        })
    ));
}

#[test]
fn repeated_naive_confirmation_has_a_semantic_hard_cap() {
    let exact_limit = vec![b'x'; MAX_REPEATED_CONFIRM_BYTES];
    let exact_over = vec![b'x'; MAX_REPEATED_CONFIRM_BYTES + 1];
    let admitted = build_exact_literal::<Span>(
        &exact_limit,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("limit exact IR");
    emit(&admitted, EmitLimits::default()).expect("exact limit admitted");
    let refused = build_exact_literal::<Span>(
        &exact_over,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("over-limit exact IR remains valid for another backend");
    assert_eq!(
        emit(&refused, EmitLimits::default()),
        Err(EmitError::ConfirmationLengthLimit {
            kind: ConfirmationKind::ExactLiteral,
            limit: MAX_REPEATED_CONFIRM_BYTES,
            required: MAX_REPEATED_CONFIRM_BYTES + 1,
        })
    );
    for anchors in [
        AnchorFlags {
            start: true,
            end: false,
        },
        AnchorFlags {
            start: false,
            end: true,
        },
    ] {
        let single_candidate =
            build_exact_literal::<Span>(&exact_over, anchors, ValidateLimits::default())
                .expect("single-candidate exact IR");
        emit(&single_candidate, EmitLimits::default())
            .expect("single-candidate confirmation is linear in pattern bytes");
    }

    let suffix: Vec<u8> = (0_u8..=u8::try_from(MAX_REPEATED_CONFIRM_BYTES)
        .expect("small semantic cap"))
        .map(|byte| byte.wrapping_add(b'@'))
        .collect();
    let class = ByteClass::from_bytes(b"a");
    let repeated = build_class_suffix::<Span>(
        class,
        &suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("over-limit class IR remains valid for another backend");
    assert_eq!(
        emit(&repeated, EmitLimits::default()),
        Err(EmitError::ConfirmationLengthLimit {
            kind: ConfirmationKind::ClassSuffix,
            limit: MAX_REPEATED_CONFIRM_BYTES,
            required: MAX_REPEATED_CONFIRM_BYTES + 1,
        })
    );
    let single_run = build_class_suffix::<Span>(
        class,
        &suffix,
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("single-run class IR");
    emit(&single_run, EmitLimits::default())
        .expect("single-run confirmation is linear in pattern bytes");
}

#[test]
fn precomputed_artifact_identity_is_sensitive_and_hot_access_is_constant_work() {
    let span = build_exact_literal::<Span>(
        b"identity",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("span program");
    let changed_literal = build_exact_literal::<Span>(
        b"identity!",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("changed program");
    let selected = build_exact_literal::<SelectedEnd>(
        b"identity",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("selected-end program");
    let span_image = emit(&span, EmitLimits::default()).expect("span image");
    let repeated = emit(&span, EmitLimits::default()).expect("repeat image");
    let changed_image = emit(&changed_literal, EmitLimits::default()).expect("changed image");
    let selected_image = emit(&selected, EmitLimits::default()).expect("selected image");
    assert_eq!(span_image.artifact_identity(), repeated.artifact_identity());
    assert_ne!(
        span_image.artifact_identity(),
        changed_image.artifact_identity()
    );
    assert_ne!(
        span_image.artifact_identity(),
        selected_image.artifact_identity()
    );
    assert_eq!(
        span_image.artifact_identity(),
        span_image
            .to_aot(AotLimits::default())
            .expect("canonical AOT")
            .identity()
    );
    for _ in 0..10_000 {
        let receipt = span_image.artifact_identity_receipt();
        assert_eq!(receipt.identity, span_image.artifact_identity());
        assert_eq!(
            (
                receipt.canonical_bytes_hashed,
                receipt.scratch_bytes,
                receipt.heap_allocations,
            ),
            (0, 0, 0)
        );
    }
}

#[test]
fn exact_literal_decoded_execution_matches_oracle_exhaustively() {
    let mut haystacks = all_sequences(b"ab", 6);
    haystacks.extend([
        b"xxxxxxxxxxxxxxx0123456789abcdef".to_vec(),
        b"xxxxxxxxxxxxxxxx0123456789abcdefg".to_vec(),
        b"0123456789abcdeg0123456789abcdef".to_vec(),
    ]);
    let literals = [
        b"".as_slice(),
        b"a",
        b"ab",
        b"ba",
        b"0123456789abcdef",
        b"0123456789abcdefg",
    ];
    let mut comparisons = 0_u64;
    for literal in literals {
        for anchors in anchor_options() {
            let program = build_exact_literal::<Span>(literal, anchors, ValidateLimits::default())
                .expect("valid literal kernel");
            let image = emit(&program, EmitLimits::default()).expect("emission succeeds");
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let expected = program
                            .execute(haystack, window, ExecutionLimits::unlimited())
                            .expect("valid oracle execution")
                            .output()
                            .map(|span| (span.start(), span.end()));
                        let actual =
                            simulate(&image, haystack, start, end).expect("safe ISA model");
                        assert_eq!(
                            span_output(actual),
                            expected,
                            "literal={literal:?} anchors={anchors:?} haystack={haystack:?} window={start}..{end}"
                        );
                        comparisons += 1;
                    }
                }
            }
        }
    }
    assert_eq!(comparisons, 107_976);
}

#[test]
fn class_suffix_decoded_execution_matches_oracle_exhaustively() {
    let mut haystacks = all_sequences(b"abc", 6);
    haystacks.extend([
        b"aaaaaaaaaaaaaaaaabcdefghijklmnopq".to_vec(),
        b"ccccccccccccccccabcdefghijklmnopq".to_vec(),
        b"xxaaaaaaaaaaaaaaaaabcdefghijklmnopqyy".to_vec(),
    ]);
    let cases = [
        (ByteClass::from_bytes(b"a"), b"b".as_slice()),
        (ByteClass::from_bytes(b"ac"), b"ba".as_slice()),
        (ByteClass::from_bytes(b"ac"), b"bcdefghijklmnopq".as_slice()),
    ];
    let mut comparisons = 0_u64;
    for (class, suffix) in cases {
        for anchors in anchor_options() {
            let program =
                build_class_suffix::<Span>(class, suffix, anchors, ValidateLimits::default())
                    .expect("proved-disjoint class suffix");
            let image = emit(&program, EmitLimits::default()).expect("emission succeeds");
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let expected = program
                            .execute(haystack, window, ExecutionLimits::unlimited())
                            .expect("valid oracle execution")
                            .output()
                            .map(|span| (span.start(), span.end()));
                        let actual =
                            simulate(&image, haystack, start, end).expect("safe ISA model");
                        assert_eq!(
                            span_output(actual),
                            expected,
                            "suffix={suffix:?} anchors={anchors:?} haystack={haystack:?} window={start}..{end}"
                        );
                        comparisons += 1;
                    }
                }
            }
        }
    }
    assert_eq!(comparisons, 347_940);
}

#[test]
fn all_output_contracts_observe_the_same_native_abi() {
    let haystack = b"zzneedlezz";
    let limits = ValidateLimits::default();
    let span = build_exact_literal::<Span>(b"needle", AnchorFlags::default(), limits)
        .expect("span program");
    let end = build_exact_literal::<SelectedEnd>(b"needle", AnchorFlags::default(), limits)
        .expect("end program");
    let exists =
        build_exact_literal::<fre_kernel_ir::Exists>(b"needle", AnchorFlags::default(), limits)
            .expect("exists program");
    let span_result = simulate(
        &emit(&span, EmitLimits::default()).expect("span image"),
        haystack,
        0,
        haystack.len(),
    )
    .expect("span execution");
    let end_result = simulate(
        &emit(&end, EmitLimits::default()).expect("end image"),
        haystack,
        0,
        haystack.len(),
    )
    .expect("end execution");
    let exists_result = simulate(
        &emit(&exists, EmitLimits::default()).expect("exists image"),
        haystack,
        0,
        haystack.len(),
    )
    .expect("exists execution");
    assert_eq!(span_output(span_result), Some((2, 8)));
    assert_eq!(end_output(end_result), Some(8));
    assert!(exists_result.status == 1);
    assert_eq!(exists_result.slot, NativeResult::default());
}

#[test]
fn each_emission_resource_accepts_exact_boundary_and_refuses_one_less() {
    let program = build_exact_literal::<Span>(
        b"0123456789abcdefg",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("baseline image");
    let stats = image.stats();
    for (resource, exact) in [
        (ResourceKind::CodeBytes, u64::from(stats.code_bytes)),
        (ResourceKind::DataBytes, u64::from(stats.data_bytes)),
        (ResourceKind::Relocations, u64::from(stats.relocations)),
        (ResourceKind::Labels, u64::from(stats.labels)),
        (ResourceKind::EmissionWork, stats.emission_work),
        (ResourceKind::ScratchBytes, stats.scratch_bytes),
    ] {
        let exact_limits = with_limit(EmitLimits::default(), resource, exact);
        emit(&program, exact_limits).expect("exact resource boundary succeeds");
        let failing = with_limit(EmitLimits::default(), resource, exact - 1);
        let error = emit(&program, failing).expect_err("one below boundary fails");
        assert!(
            matches!(
                error,
                EmitError::ResourceLimit {
                    resource: actual,
                    ..
                } if actual == resource
            ),
            "wrong error for {resource:?}: {error:?}"
        );
    }
    let aot = image.to_aot(AotLimits::default()).expect("AOT image");
    let exact = u64::try_from(aot.as_bytes().len()).expect("small artifact");
    image
        .to_aot(AotLimits { max_bytes: exact })
        .expect("exact AOT boundary succeeds");
    assert!(matches!(
        image.to_aot(AotLimits {
            max_bytes: exact - 1
        }),
        Err(EmitError::ResourceLimit {
            resource: ResourceKind::AotBytes,
            ..
        })
    ));
}

fn independently_derived_v8_work(image: &NativeImage, policy_scan_work: u64) -> u64 {
    const V8_AOT_FIXED_BYTES: u64 = 8 + 2 + 6 + 8 + 32 + 16 + 20 + 36 + 54;

    // Derive the receipt from structural outputs and the fixed V8 wire layout,
    // without reading the emission-work receipt under test. Emission charges
    // each copied rodata byte once, each label once when created and once when
    // bound, each emitted word once, each resolved relocation once, and every
    // canonical byte once for the final identity.
    let rodata_copy_work = u64::try_from(image.rodata().len()).expect("bounded rodata");
    let label_work = u64::try_from(image.labels().len())
        .expect("bounded labels")
        .checked_mul(2)
        .expect("label creation and binding");
    let instruction_work =
        u64::try_from(image.code().len() / 4).expect("bounded instruction count");
    let relocation_work = u64::try_from(image.relocations().len()).expect("bounded relocations");
    let canonical_identity_work = V8_AOT_FIXED_BYTES
        .checked_add(u64::try_from(image.code().len()).expect("bounded code"))
        .and_then(|work| {
            work.checked_add(u64::try_from(image.rodata().len()).expect("bounded rodata"))
        })
        .and_then(|work| {
            work.checked_add(
                u64::try_from(image.labels().len())
                    .expect("bounded labels")
                    .checked_mul(8)
                    .expect("bounded label records"),
            )
        })
        .and_then(|work| {
            work.checked_add(
                u64::try_from(image.symbols().len())
                    .expect("bounded symbols")
                    .checked_mul(16)
                    .expect("bounded symbol records"),
            )
        })
        .and_then(|work| {
            work.checked_add(
                u64::try_from(image.relocations().len())
                    .expect("bounded relocations")
                    .checked_mul(20)
                    .expect("bounded relocation records"),
            )
        })
        .expect("bounded canonical identity work");
    assert_eq!(
        u64::try_from(
            image
                .to_aot(AotLimits::default())
                .expect("bounded V8 artifact")
                .as_bytes()
                .len()
        )
        .expect("bounded V8 artifact"),
        canonical_identity_work
    );
    policy_scan_work
        .checked_add(rodata_copy_work)
        .and_then(|work| work.checked_add(label_work))
        .and_then(|work| work.checked_add(instruction_work))
        .and_then(|work| work.checked_add(relocation_work))
        .and_then(|work| work.checked_add(canonical_identity_work))
        .expect("bounded independently derived work")
}

#[test]
fn v8_ranked_policy_scans_are_precharged_and_total_work_is_exact() {
    let literal: Vec<u8> = (0_u8..32).map(|byte| byte.wrapping_mul(73)).collect();
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("maximum repeated-confirmation program");

    let scan_work = u64::try_from(literal.len())
        .expect("bounded literal")
        .checked_mul(2)
        .expect("two bounded scans");
    let one_below_first_scan = u64::try_from(literal.len())
        .expect("bounded literal")
        .checked_sub(1)
        .expect("nonempty literal");
    let one_below_scan_work = scan_work.checked_sub(1).expect("nonzero scan work");
    // The first limit distinguishes one combined 64-unit admission from two
    // sequential 32-unit charges. Data capacity is a competing later refusal:
    // at the second limit, a charge deferred until after rodata handling would
    // lose to DataBytes. The move-only admission token then gates both scans.
    for work_limit in [one_below_first_scan, one_below_scan_work] {
        let error = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV8,
            EmitLimits {
                max_data_bytes: 0,
                max_emission_work: work_limit,
                ..EmitLimits::default()
            },
        )
        .expect_err("the combined scan admission precedes the competing data refusal");
        assert_eq!(
            error,
            EmitError::ResourceLimit {
                resource: ResourceKind::EmissionWork,
                limit: work_limit,
                required: scan_work,
            }
        );
    }

    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )
    .expect("baseline v8 image");
    assert_eq!(image.rodata(), literal);
    assert_eq!(image.code().len() % 4, 0);
    let exact_work = independently_derived_v8_work(&image, scan_work);
    assert_eq!(image.stats().emission_work, exact_work);

    emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits {
            max_emission_work: exact_work,
            ..EmitLimits::default()
        },
    )
    .expect("exact v7 work receipt succeeds");
    assert_eq!(
        emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV8,
            EmitLimits {
                max_emission_work: exact_work.checked_sub(1).expect("nonzero total work"),
                ..EmitLimits::default()
            },
        ),
        Err(EmitError::ResourceLimit {
            resource: ResourceKind::EmissionWork,
            limit: exact_work - 1,
            required: exact_work,
        })
    );
}

#[test]
fn singleton_suffix_first_resources_accept_exact_boundary_and_refuse_one_less() {
    let program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        b"bcdefghijklmnopq",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("suffix-first program");
    let image = emit(&program, EmitLimits::default()).expect("baseline image");
    let stats = image.stats();
    for (resource, exact) in [
        (ResourceKind::CodeBytes, u64::from(stats.code_bytes)),
        (ResourceKind::DataBytes, u64::from(stats.data_bytes)),
        (ResourceKind::Relocations, u64::from(stats.relocations)),
        (ResourceKind::Labels, u64::from(stats.labels)),
        (ResourceKind::EmissionWork, stats.emission_work),
        (ResourceKind::ScratchBytes, stats.scratch_bytes),
    ] {
        emit(&program, with_limit(EmitLimits::default(), resource, exact))
            .expect("exact suffix-first resource boundary succeeds");
        let error = emit(
            &program,
            with_limit(
                EmitLimits::default(),
                resource,
                exact.checked_sub(1).expect("nonzero resource"),
            ),
        )
        .expect_err("one below suffix-first boundary fails");
        assert!(matches!(
            error,
            EmitError::ResourceLimit {
                resource: actual,
                ..
            } if actual == resource
        ));
    }
}

#[test]
fn malformed_ir_is_stopped_before_native_emission() {
    let program =
        build_exact_literal::<Span>(b"x", AnchorFlags::default(), ValidateLimits::default())
            .expect("valid source");
    let mut raw: RawProgram = program.raw().clone();
    let BlockId(out_of_range) = BlockId(99);
    if let fre_kernel_ir::BlockOp::Entry { next } = &mut raw.blocks[0].op {
        *next = BlockId(out_of_range);
    }
    assert!(matches!(
        raw.validate::<Span>(ValidateLimits::default()),
        Err(ValidateError::Invalid(
            InvalidProgram::BlockTargetOutOfRange { .. }
        ))
    ));
}

#[test]
fn decoder_and_auditor_refuse_unknown_or_tampered_instructions() {
    assert_eq!(
        decode(&[0, 0, 0]),
        Err(DecodeError::UnalignedCodeLength { length: 3 })
    );
    assert!(matches!(
        decode(&0xd61f_0000_u32.to_le_bytes()),
        Err(DecodeError::UnknownInstruction { .. })
    ));
    // The architectural LDP Q immediate is signed. Tag 21 admits only its
    // canonical nonnegative #0/#32 forms, so a negative-offset encoding must
    // fail closed instead of being reinterpreted as a large unsigned offset.
    assert!(matches!(
        decode(&0xad7f_8440_u32.to_le_bytes()),
        Err(DecodeError::UnknownInstruction { .. })
    ));
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("program");
    let mut image = emit(&program, EmitLimits::default()).expect("image");
    image.code[0..4].copy_from_slice(&0xd61f_0000_u32.to_le_bytes());
    assert!(matches!(audit(&image), Err(AuditError::Decode(_))));

    let mut image = emit(&program, EmitLimits::default()).expect("fresh image");
    let branch = image
        .relocations
        .iter()
        .position(|relocation| relocation.kind == RelocationKind::Branch26)
        .expect("direct branch relocation");
    image.relocations[branch].resolved_word ^= 4;
    assert!(matches!(
        audit(&image),
        Err(AuditError::RelocationWordMismatch { .. })
    ));
}

#[test]
fn auditor_rejects_result_pointer_clobbers_for_both_abis() {
    let search =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("search program");
    let mut search_image = emit(&search, EmitLimits::default()).expect("search image");
    // Replace the non-relocated entry `mov x9, x0` with `mov x4, x0`.
    search_image.code[0..4].copy_from_slice(&0xaa00_03e4_u32.to_le_bytes());
    assert_eq!(
        audit(&search_image),
        Err(AuditError::ResultPointerClobber {
            offset: 0,
            register: 4,
        })
    );

    let aggregate = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("aggregate program");
    let aggregate_image =
        emit_exact_aggregate(&aggregate, EmitLimits::default()).expect("aggregate image");
    let mut inner = aggregate_image.inner().clone();
    // Replace the non-relocated entry `movz x13, #0` with `movz x2, #0`.
    inner.code[0..4].copy_from_slice(&0xd280_0002_u32.to_le_bytes());
    let aggregate_image = NativeAggregateImage::new(inner);
    assert_eq!(
        audit_aggregate(&aggregate_image),
        Err(AuditError::ResultPointerClobber {
            offset: 0,
            register: 2,
        })
    );
}

#[test]
fn aggregate_audit_preflights_symbol_cardinality() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("aggregate program");
    let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("aggregate image");
    let mut inner = image.inner().clone();
    let mut symbols = inner.symbols.into_vec();
    symbols.push(symbols[0]);
    inner.symbols = symbols.into_boxed_slice();

    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateManifest)
    );
}

#[test]
fn aggregate_v1_envelope_is_exact_for_every_shape_family() {
    for width in [0_usize, 1, 2, 3, 15, 16, 17, 32] {
        let literal = vec![b'x'; width];
        let count = build_exact_aggregate::<Count>(&literal, ValidateLimits::default())
            .expect("Count aggregate");
        let spans = build_exact_aggregate::<SpanSum>(&literal, ValidateLimits::default())
            .expect("SpanSum aggregate");
        let images = [
            emit_exact_aggregate(&count, EmitLimits::default()).expect("Count image"),
            emit_exact_aggregate(&spans, EmitLimits::default()).expect("SpanSum image"),
        ];
        let repeated = [
            emit_exact_aggregate(&count, EmitLimits::default()).expect("repeated Count image"),
            emit_exact_aggregate(&spans, EmitLimits::default()).expect("repeated SpanSum image"),
        ];
        for (image, repeated) in images.into_iter().zip(repeated) {
            let (instructions, labels, relocations, vectors) = match (image.output(), width) {
                (AggregateOutput::Count, 0) => (14_usize, 3_usize, 2_usize, 0_u32),
                (AggregateOutput::SpanSum, 0) => (5, 2, 1, 0),
                (_, 1) => (42, 6, 9, 5),
                (_, 2) => (55, 9, 13, 9),
                (_, 3..=15) => (68, 12, 17, 9),
                (_, 16..=32) => (80, 13, 19, 14),
                _ => unreachable!("covered width"),
            };
            assert_eq!(image.code().len(), instructions * 4);
            assert_eq!(image.labels().len(), labels);
            assert_eq!(image.relocations().len(), relocations);
            assert_eq!(image.stats().vector_instructions, vectors);
            assert_eq!(image, repeated, "deterministic image for M={width}");
            let aot = image.to_aot(AotLimits::default()).expect("bounded AOT");
            let repeated_aot = repeated
                .to_aot(AotLimits::default())
                .expect("repeated bounded AOT");
            assert!(aot.as_bytes().len() <= 984);
            assert_eq!(aot, repeated_aot, "deterministic AOT for M={width}");
            assert_eq!(aot.identity(), image.artifact_identity());
            audit_aggregate(&image).expect("exact v1 envelope passes");
        }
    }
}

struct M17CountTemplateCursor<'a> {
    instructions: &'a [DecodedInstruction],
    position: usize,
}

impl<'a> M17CountTemplateCursor<'a> {
    const fn new(instructions: &'a [DecodedInstruction]) -> Self {
        Self {
            instructions,
            position: 0,
        }
    }

    fn expect(&mut self, expected: DecodedInstruction) -> bool {
        if self.instructions.get(self.position) != Some(&expected) {
            return false;
        }
        self.position += 1;
        true
    }

    fn finished(&self) -> bool {
        self.position == self.instructions.len()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the independently transcribed M=17 Count prototype keeps every decoded operand visible"
)]
fn m17_count_template_matches(image: &NativeImage) -> bool {
    use DecodedInstruction::{
        AddImmediate64, AddRegister64, Address, AndBytes16, Branch, BranchCondition,
        CompareBranchZero64, CompareEqualBytes16, CompareImmediate32, CompareImmediate64,
        CompareRegister32, CompareRegister64, DuplicateByte16, LoadByte, LoadByteRegister,
        LoadVector128, MoveRegister64, MoveVectorByteTo32, MoveZero64, Return, Store64,
        SubtractImmediate64, SubtractRegister64, UnsignedMaxBytes16, UnsignedMinBytes16,
    };

    let expected = [
        MoveZero64 {
            destination: 13,
            immediate: 0,
            shift: 0,
        },
        Address {
            destination: 8,
            displacement: 316,
        },
        MoveZero64 {
            destination: 12,
            immediate: 17,
            shift: 0,
        },
        CompareRegister64 { left: 1, right: 12 },
        BranchCondition {
            condition: Condition::CarryClear,
            displacement: 284,
        },
        SubtractRegister64 {
            destination: 6,
            left: 1,
            right: 12,
        },
        MoveZero64 {
            destination: 5,
            immediate: 0,
            shift: 0,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: 0,
        },
        DuplicateByte16 {
            destination: 1,
            source: 11,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: 16,
        },
        DuplicateByte16 {
            destination: 3,
            source: 11,
        },
        CompareRegister64 { left: 5, right: 6 },
        BranchCondition {
            condition: Condition::Higher,
            displacement: 252,
        },
        SubtractRegister64 {
            destination: 10,
            left: 6,
            right: 5,
        },
        CompareImmediate64 {
            register: 10,
            immediate: 15,
        },
        BranchCondition {
            condition: Condition::CarryClear,
            displacement: 60,
        },
        AddRegister64 {
            destination: 15,
            left: 0,
            right: 5,
        },
        LoadVector128 {
            destination: 0,
            base: 15,
            offset: 0,
        },
        CompareEqualBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
        AddImmediate64 {
            destination: 10,
            source: 15,
            immediate: 16,
        },
        LoadVector128 {
            destination: 2,
            base: 10,
            offset: 0,
        },
        CompareEqualBytes16 {
            destination: 2,
            left: 2,
            right: 3,
        },
        AndBytes16 {
            destination: 0,
            left: 0,
            right: 2,
        },
        UnsignedMaxBytes16 {
            destination: 0,
            source: 0,
        },
        MoveVectorByteTo32 {
            destination: 10,
            source: 0,
        },
        CompareBranchZero64 {
            register: 10,
            nonzero: true,
            displacement: 12,
        },
        AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 16,
        },
        Branch { displacement: -64 },
        AddImmediate64 {
            destination: 7,
            source: 5,
            immediate: 15,
        },
        Branch { displacement: 8 },
        MoveRegister64 {
            destination: 7,
            source: 6,
        },
        CompareRegister64 { left: 5, right: 7 },
        BranchCondition {
            condition: Condition::Higher,
            displacement: -84,
        },
        LoadByteRegister {
            destination: 10,
            base: 0,
            index: 5,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: 0,
        },
        CompareRegister32 {
            left: 10,
            right: 11,
        },
        BranchCondition {
            condition: Condition::NotEqual,
            displacement: 148,
        },
        AddRegister64 {
            destination: 15,
            left: 0,
            right: 5,
        },
        LoadByte {
            destination: 10,
            base: 15,
            offset: 16,
        },
        LoadByte {
            destination: 11,
            base: 8,
            offset: 16,
        },
        CompareRegister32 {
            left: 10,
            right: 11,
        },
        BranchCondition {
            condition: Condition::NotEqual,
            displacement: 128,
        },
        MoveRegister64 {
            destination: 15,
            source: 15,
        },
        MoveRegister64 {
            destination: 16,
            source: 8,
        },
        MoveZero64 {
            destination: 17,
            immediate: 17,
            shift: 0,
        },
        CompareImmediate64 {
            register: 17,
            immediate: 16,
        },
        BranchCondition {
            condition: Condition::CarryClear,
            displacement: 48,
        },
        LoadVector128 {
            destination: 4,
            base: 15,
            offset: 0,
        },
        LoadVector128 {
            destination: 5,
            base: 16,
            offset: 0,
        },
        CompareEqualBytes16 {
            destination: 4,
            left: 4,
            right: 5,
        },
        UnsignedMinBytes16 {
            destination: 4,
            source: 4,
        },
        MoveVectorByteTo32 {
            destination: 10,
            source: 4,
        },
        CompareImmediate32 {
            register: 10,
            immediate: 255,
        },
        BranchCondition {
            condition: Condition::NotEqual,
            displacement: 80,
        },
        AddImmediate64 {
            destination: 15,
            source: 15,
            immediate: 16,
        },
        AddImmediate64 {
            destination: 16,
            source: 16,
            immediate: 16,
        },
        SubtractImmediate64 {
            destination: 17,
            source: 17,
            immediate: 16,
        },
        Branch { displacement: -48 },
        CompareBranchZero64 {
            register: 17,
            nonzero: false,
            displacement: 36,
        },
        LoadByte {
            destination: 10,
            base: 15,
            offset: 0,
        },
        LoadByte {
            destination: 11,
            base: 16,
            offset: 0,
        },
        CompareRegister32 {
            left: 10,
            right: 11,
        },
        BranchCondition {
            condition: Condition::NotEqual,
            displacement: 44,
        },
        AddImmediate64 {
            destination: 15,
            source: 15,
            immediate: 1,
        },
        AddImmediate64 {
            destination: 16,
            source: 16,
            immediate: 1,
        },
        SubtractImmediate64 {
            destination: 17,
            source: 17,
            immediate: 1,
        },
        CompareBranchZero64 {
            register: 17,
            nonzero: true,
            displacement: -28,
        },
        MoveRegister64 {
            destination: 14,
            source: 13,
        },
        AddImmediate64 {
            destination: 13,
            source: 13,
            immediate: 1,
        },
        CompareRegister64 {
            left: 13,
            right: 14,
        },
        BranchCondition {
            condition: Condition::CarryClear,
            displacement: 32,
        },
        AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 17,
        },
        Branch { displacement: -164 },
        AddImmediate64 {
            destination: 5,
            source: 5,
            immediate: 1,
        },
        Branch { displacement: -172 },
        Store64 {
            source: 13,
            base: 2,
            offset: 0,
        },
        MoveZero64 {
            destination: 0,
            immediate: 0,
            shift: 0,
        },
        Return,
        MoveZero64 {
            destination: 0,
            immediate: 1,
            shift: 0,
        },
        Return,
    ];
    let expected_labels = [
        (0, LabelKind::Entry),
        (44, LabelKind::Loop),
        (104, LabelKind::Internal),
        (112, LabelKind::SlowPath),
        (120, LabelKind::SlowPath),
        (124, LabelKind::Loop),
        (180, LabelKind::Loop),
        (232, LabelKind::Internal),
        (236, LabelKind::Loop),
        (268, LabelKind::Internal),
        (292, LabelKind::Internal),
        (300, LabelKind::ReturnFound),
        (312, LabelKind::ReturnNone),
    ];
    let expected_relocations = [
        (
            4,
            RelocationKind::Address21,
            RelocationTarget::RodataOffset(0),
        ),
        (
            16,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(300),
        ),
        (
            48,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(300),
        ),
        (
            60,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(120),
        ),
        (
            100,
            RelocationKind::CompareBranch19,
            RelocationTarget::CodeOffset(112),
        ),
        (
            108,
            RelocationKind::Branch26,
            RelocationTarget::CodeOffset(44),
        ),
        (
            116,
            RelocationKind::Branch26,
            RelocationTarget::CodeOffset(124),
        ),
        (
            128,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(44),
        ),
        (
            144,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(292),
        ),
        (
            164,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(292),
        ),
        (
            184,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(232),
        ),
        (
            212,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(292),
        ),
        (
            228,
            RelocationKind::Branch26,
            RelocationTarget::CodeOffset(180),
        ),
        (
            232,
            RelocationKind::CompareBranch19,
            RelocationTarget::CodeOffset(268),
        ),
        (
            248,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(292),
        ),
        (
            264,
            RelocationKind::CompareBranch19,
            RelocationTarget::CodeOffset(236),
        ),
        (
            280,
            RelocationKind::ConditionalBranch19,
            RelocationTarget::CodeOffset(312),
        ),
        (
            288,
            RelocationKind::Branch26,
            RelocationTarget::CodeOffset(124),
        ),
        (
            296,
            RelocationKind::Branch26,
            RelocationTarget::CodeOffset(124),
        ),
    ];

    if image.code.len() != 320
        || image.rodata.len() != 17
        || image.labels.len() != expected_labels.len()
        || image.relocations.len() != expected_relocations.len()
        || image.stats.vector_instructions != 14
        || !matches!(
            image.aggregate_manifest(),
            Some(manifest)
                if manifest.output == AggregateOutput::Count && manifest.literal_bytes == 17
        )
        || !image
            .labels
            .iter()
            .zip(expected_labels)
            .all(|(actual, (offset, kind))| actual.offset == offset && actual.kind == kind)
        || !image.relocations.iter().zip(expected_relocations).all(
            |(actual, (offset, kind, target))| {
                let start = usize::try_from(offset).expect("small prototype offset");
                let resolved = u32::from_le_bytes(
                    image.code[start..start + 4]
                        .try_into()
                        .expect("one instruction"),
                );
                actual.code_offset == offset
                    && actual.kind == kind
                    && actual.target == target
                    && actual.addend == 0
                    && actual.resolved_word == resolved
            },
        )
    {
        return false;
    }

    let Ok(instructions) = decode(image.code()) else {
        return false;
    };
    let mut cursor = M17CountTemplateCursor::new(&instructions);
    expected
        .into_iter()
        .all(|instruction| cursor.expect(instruction))
        && cursor.finished()
}

fn reseal_test_image(image: &mut NativeImage) {
    image.artifact_identity = image
        .compute_artifact_identity()
        .expect("bounded test artifact identity");
}

fn exact_span_search_image(literal: &[u8]) -> NativeImage {
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("bounded exact search program");
    emit(&program, EmitLimits::default()).expect("bounded exact search image")
}

fn assert_resealed_search_rejected(mut image: NativeImage, mutation: &str) {
    reseal_test_image(&mut image);
    assert!(decode(image.code()).is_ok(), "{mutation} remains decodable");
    assert!(
        audit(&image).is_err(),
        "search audit accepted resealed mutation: {mutation}"
    );
}

#[test]
fn v5_exact_search_template_accepts_every_width_output_and_pair_direction() {
    for width in [1_usize, 2, 3, 15, 16, 17, 31, 32] {
        let literal = vec![b'x'; width];
        let exists = build_exact_literal::<fre_kernel_ir::Exists>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("Exists program");
        let selected_end = build_exact_literal::<SelectedEnd>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("SelectedEnd program");
        let span = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("Span program");
        for image in [
            emit_search_version_for_test(&exists, EmitLimits::default(), BackendVersion::SEARCH_V5)
                .expect("Exists image"),
            emit_search_version_for_test(
                &selected_end,
                EmitLimits::default(),
                BackendVersion::SEARCH_V5,
            )
            .expect("SelectedEnd image"),
            emit_search_version_for_test(&span, EmitLimits::default(), BackendVersion::SEARCH_V5)
                .expect("Span image"),
        ] {
            audit(&image).expect("canonical v5 exact template");
        }
    }
    for literal in [b"Za".as_slice(), b"aZ"] {
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("pair-direction program");
        let image = emit_search_version_for_test(
            &program,
            EmitLimits::default(),
            BackendVersion::SEARCH_V5,
        )
        .expect("v5 pair-direction image");
        audit(&image).expect("both signed secondary-filter directions authenticate");
    }
}

#[test]
fn sealed_search_manifest_versions_and_cold_audit_accounting_are_explicit() {
    let exact = exact_span_search_image(b"needle");
    let exact_manifest = exact.search_manifest().expect("sealed exact manifest");
    assert_eq!(exact.backend_version(), BackendVersion::SEARCH_CURRENT);
    assert_eq!(
        exact_manifest.backend_version,
        BackendVersion::SEARCH_CURRENT
    );
    assert_eq!(exact_manifest.shape, SearchShape::ExactLiteral);
    assert_eq!(exact_manifest.output, OutputKind::Span);
    assert_eq!(exact_manifest.anchors, AnchorFlags::default());
    assert_eq!(exact_manifest.literal_bytes, 6);
    assert_eq!(exact_manifest.candidate_policy_version, 4);
    assert_eq!(exact_manifest.candidate_block_width, 16);
    assert_eq!(
        (
            exact_manifest.primary_offset,
            exact_manifest.secondary_offset
        ),
        (3, 4)
    );
    assert_ne!(exact_manifest.verification_offset, u16::MAX);
    assert_ne!(exact_manifest.quaternary_offset, u16::MAX);
    assert_eq!(exact_manifest.source_identity, exact.source_identity());
    assert_eq!(
        &exact.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
        b"FREA64\0\x08"
    );
    let report = audit(&exact).expect("sealed exact audit");
    assert_eq!(report.decode_passes, 1);
    assert_eq!(report.source_identity_rebuilds, 1);

    let class = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"ab"),
        b"Z",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("class program");
    let class_image = emit(&class, EmitLimits::default()).expect("class image");
    let class_manifest = class_image
        .search_manifest()
        .expect("sealed class manifest");
    assert_eq!(class_manifest.shape, SearchShape::ClassSuffix);
    assert_eq!(class_manifest.literal_bytes, 1);
    let report = audit(&class_image).expect("sealed class audit");
    assert_eq!(
        (report.decode_passes, report.source_identity_rebuilds),
        (1, 1)
    );

    let aggregate = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("aggregate program");
    let aggregate_image =
        emit_exact_aggregate(&aggregate, EmitLimits::default()).expect("aggregate image");
    assert_eq!(
        aggregate_image.backend_version(),
        BackendVersion::AGGREGATE_CURRENT
    );
    assert!(aggregate_image.inner().search_manifest().is_none());
    let report = audit_aggregate(&aggregate_image).expect("separate v1 aggregate audit");
    assert_eq!(
        (report.decode_passes, report.source_identity_rebuilds),
        (1, 1)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the version compatibility and downgrade matrix keeps all three dispatch contracts together"
)]
fn search_backend_dispatch_accepts_legacy_shapes_and_rejects_v2_code_as_v1() {
    let exact_empty =
        build_exact_literal::<Span>(b"", AnchorFlags::default(), ValidateLimits::default())
            .expect("empty exact");
    let class_program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"ab"),
        b"Z",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("class program");
    let anchored_program = build_exact_literal::<Span>(
        b"needle",
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("anchored exact");
    let unanchored_program = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("unanchored exact");
    for backend in [BackendVersion::SEARCH_V1, BackendVersion::SEARCH_V2] {
        for image in [
            emit_search_version_for_test(&exact_empty, EmitLimits::default(), backend)
                .expect("legacy empty exact"),
            emit_search_version_for_test(&class_program, EmitLimits::default(), backend)
                .expect("legacy class"),
            emit_search_version_for_test(&anchored_program, EmitLimits::default(), backend)
                .expect("legacy anchored exact"),
            emit_search_version_for_test(&unanchored_program, EmitLimits::default(), backend)
                .expect("legacy unanchored exact"),
        ] {
            assert!(image.search_manifest().is_none());
            assert_eq!(
                &image.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
                b"FREA64\0\x01"
            );
            let report = audit(&image).expect("authenticated legacy search shape");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 5),
                "legacy semantic enumeration must report actual rebuild work"
            );
        }
    }

    for (backend, wire) in [
        (BackendVersion::SEARCH_V3, b"FREA64\0\x03"),
        (BackendVersion::SEARCH_V4, b"FREA64\0\x04"),
    ] {
        for image in [
            emit_search_version_for_test(&exact_empty, EmitLimits::default(), backend)
                .expect("sealed empty exact"),
            emit_search_version_for_test(&class_program, EmitLimits::default(), backend)
                .expect("sealed class"),
            emit_search_version_for_test(&anchored_program, EmitLimits::default(), backend)
                .expect("sealed anchored exact"),
            emit_search_version_for_test(&unanchored_program, EmitLimits::default(), backend)
                .expect("sealed unanchored exact"),
        ] {
            let manifest = image.search_manifest().expect("sealed manifest");
            assert_eq!(manifest.backend_version, backend);
            assert_eq!(manifest.verification_offset, u16::MAX);
            assert_eq!(
                &image.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
                wire
            );
            let report = audit(&image).expect("authenticated sealed search shape");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 1)
            );
        }
    }

    for (backend, wire) in [
        (BackendVersion::SEARCH_V5, b"FREA64\0\x05"),
        (BackendVersion::SEARCH_V6, b"FREA64\0\x06"),
    ] {
        for (image, verification_offset) in [
            (
                emit_search_version_for_test(&exact_empty, EmitLimits::default(), backend)
                    .expect("sealed empty exact"),
                u16::MAX,
            ),
            (
                emit_search_version_for_test(&class_program, EmitLimits::default(), backend)
                    .expect("sealed class"),
                u16::MAX,
            ),
            (
                emit_search_version_for_test(&anchored_program, EmitLimits::default(), backend)
                    .expect("sealed anchored exact"),
                u16::MAX,
            ),
            (
                emit_search_version_for_test(&unanchored_program, EmitLimits::default(), backend)
                    .expect("sealed unanchored exact"),
                0,
            ),
        ] {
            let manifest = image.search_manifest().expect("sealed manifest");
            assert_eq!(manifest.backend_version, backend);
            assert_eq!(manifest.verification_offset, verification_offset);
            assert_eq!(manifest.quaternary_offset, u16::MAX);
            assert_eq!(
                &image.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
                wire
            );
            let report = audit(&image).expect("authenticated sealed search shape");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 1)
            );
        }
    }

    for (image, verification_offset, quaternary_offset) in [
        (
            emit_search_version_for_test(
                &exact_empty,
                EmitLimits::default(),
                BackendVersion::SEARCH_V7,
            )
            .expect("sealed v7 empty exact"),
            u16::MAX,
            u16::MAX,
        ),
        (
            emit_search_version_for_test(
                &class_program,
                EmitLimits::default(),
                BackendVersion::SEARCH_V7,
            )
            .expect("sealed v7 class"),
            u16::MAX,
            u16::MAX,
        ),
        (
            emit_search_version_for_test(
                &anchored_program,
                EmitLimits::default(),
                BackendVersion::SEARCH_V7,
            )
            .expect("sealed v7 anchored exact"),
            u16::MAX,
            u16::MAX,
        ),
        (
            emit_search_version_for_test(
                &unanchored_program,
                EmitLimits::default(),
                BackendVersion::SEARCH_V7,
            )
            .expect("sealed v7 unanchored exact"),
            8,
            5,
        ),
    ] {
        let manifest = image.search_manifest().expect("sealed v7 manifest");
        assert_eq!(manifest.backend_version, BackendVersion::SEARCH_V7);
        assert_eq!(manifest.verification_offset, verification_offset);
        assert_eq!(manifest.quaternary_offset, quaternary_offset);
        assert_eq!(
            &image.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
            b"FREA64\0\x07"
        );
        let report = audit(&image).expect("authenticated v7 search shape");
        assert_eq!(
            (report.decode_passes, report.source_identity_rebuilds),
            (1, 1)
        );
    }

    let mut v2_as_v1 = emit_search_version_for_test(
        &unanchored_program,
        EmitLimits::default(),
        BackendVersion::SEARCH_V2,
    )
    .expect("canonical v2");
    v2_as_v1.backend_version = BackendVersion::SEARCH_V1;
    let instructions = decode(v2_as_v1.code()).expect("canonical v2 code");
    for (index, instruction) in instructions.into_iter().enumerate() {
        let replacement = match instruction {
            DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                destination, left, ..
            } => Some(DecodedInstruction::UnsignedMaxBytes16 {
                destination,
                source: left,
            }),
            DecodedInstruction::MoveVectorDoubleTo64 {
                destination,
                source,
            } => Some(DecodedInstruction::MoveVectorByteTo32 {
                destination,
                source,
            }),
            _ => None,
        };
        if let Some(replacement) = replacement {
            replace_test_decoded_at(&mut v2_as_v1, index, replacement);
        }
    }
    reseal_test_image(&mut v2_as_v1);
    assert!(matches!(
        audit(&v2_as_v1),
        Err(AuditError::InvalidSearchCandidateContract { .. })
    ));

    let mut unknown = exact_span_search_image(b"needle");
    unknown.backend_version = BackendVersion(20);
    unknown.code[0..4].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
    assert_eq!(
        audit(&unknown),
        Err(AuditError::SearchBackendVersionMismatch {
            expected: BackendVersion::SEARCH_CURRENT.0,
            actual: 20,
        })
    );

    let aggregate = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("aggregate program");
    let aggregate =
        emit_exact_aggregate(&aggregate, EmitLimits::default()).expect("aggregate image");
    let mut historical_aggregate = aggregate.inner().clone();
    historical_aggregate.backend_version = BackendVersion::AGGREGATE_HISTORICAL_V2;
    reseal_test_image(&mut historical_aggregate);
    audit_aggregate(&NativeAggregateImage::new(historical_aggregate))
        .expect("explicit historical aggregate-v2 tag");

    let mut wrong_aggregate_version = aggregate.inner().clone();
    wrong_aggregate_version.backend_version = BackendVersion::SEARCH_CURRENT;
    reseal_test_image(&mut wrong_aggregate_version);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(wrong_aggregate_version)),
        Err(AuditError::InvalidAggregateManifest)
    );
}

#[test]
fn oversized_identity_valid_legacy_search_envelopes_fail_closed() {
    let oversized_len = usize::from(u16::MAX) + 2;
    let exact_literal = vec![b'x'; oversized_len];
    let exact_program = build_exact_literal::<Span>(
        &exact_literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("oversized exact Kernel IR remains identity-valid");
    let exact_seed =
        build_exact_literal::<Span>(b"x", AnchorFlags::default(), ValidateLimits::default())
            .expect("exact seed");

    let class = ByteClass::from_bytes(b"x");
    let class_suffix = vec![b'y'; oversized_len];
    let class_program = build_class_suffix::<Span>(
        class,
        &class_suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("oversized class-suffix Kernel IR remains identity-valid");
    let class_seed = build_class_suffix::<Span>(
        class,
        b"y",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("class-suffix seed");

    for backend in [BackendVersion::SEARCH_V1, BackendVersion::SEARCH_V2] {
        let mut exact = emit_search_version_for_test(&exact_seed, EmitLimits::default(), backend)
            .expect("legacy exact seed image");
        exact.rodata = exact_literal.clone().into_boxed_slice();
        exact.symbols[0].length =
            u32::try_from(oversized_len).expect("oversized test length fits u32");
        exact.source_identity = exact_program.cache_identity();
        reseal_test_image(&mut exact);
        assert_eq!(
            audit(&exact),
            Err(AuditError::InvalidSearchManifest),
            "oversized exact backend {} must return an error",
            backend.0
        );

        let mut class_image =
            emit_search_version_for_test(&class_seed, EmitLimits::default(), backend)
                .expect("legacy class-suffix seed image");
        let mut rodata = class_image.rodata[..32].to_vec();
        rodata.extend_from_slice(&class_suffix);
        class_image.rodata = rodata.into_boxed_slice();
        class_image.symbols[1].length =
            u32::try_from(oversized_len).expect("oversized test length fits u32");
        class_image.source_identity = class_program.cache_identity();
        reseal_test_image(&mut class_image);
        assert_eq!(
            audit(&class_image),
            Err(AuditError::InvalidSearchManifest),
            "oversized class suffix backend {} must return an error",
            backend.0
        );
    }
}

#[test]
fn complete_search_templates_reject_anchored_and_class_post_prefix_load_mutations() {
    let literal = b"0123456789abcdef";
    let anchored = build_exact_literal::<Span>(
        literal,
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("anchored exact");
    let mut anchored_image = emit(&anchored, EmitLimits::default()).expect("anchored image");
    let anchored_load = decode(anchored_image.code())
        .expect("anchored code")
        .iter()
        .rposition(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadVector128 {
                    destination: 0,
                    base: 15,
                    offset: 0
                }
            )
        })
        .expect("post-prefix anchored vector load");
    replace_test_decoded_at(
        &mut anchored_image,
        anchored_load,
        DecodedInstruction::LoadVector128 {
            destination: 0,
            base: 14,
            offset: 0,
        },
    );
    reseal_test_image(&mut anchored_image);
    assert!(matches!(
        audit(&anchored_image),
        Err(AuditError::InvalidSearchCandidateContract { .. })
    ));

    let class = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"ab"),
        literal,
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("anchored class suffix");
    let mut class_image = emit(&class, EmitLimits::default()).expect("class image");
    let class_load = decode(class_image.code())
        .expect("class code")
        .iter()
        .rposition(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadVector128 {
                    destination: 0,
                    base: 15,
                    offset: 0
                }
            )
        })
        .expect("post-prefix class vector load");
    replace_test_decoded_at(
        &mut class_image,
        class_load,
        DecodedInstruction::LoadVector128 {
            destination: 0,
            base: 14,
            offset: 0,
        },
    );
    reseal_test_image(&mut class_image);
    assert!(matches!(
        audit(&class_image),
        Err(AuditError::InvalidSearchCandidateContract { .. })
    ));
}

#[test]
fn current_v8_candidate_policy_and_manifest_exclusivity_are_authenticated() {
    let canonical = exact_span_search_image(b"0123456789abcdef");
    for mutation in 0_u8..5 {
        let mut image = canonical.clone();
        let manifest = image.search.as_mut().expect("current V8 search manifest");
        match mutation {
            0 => manifest.candidate_policy_version = 2,
            1 => manifest.candidate_block_width = 15,
            2 => manifest.primary_offset = manifest.secondary_offset,
            3 => manifest.verification_offset = manifest.secondary_offset,
            4 => manifest.quaternary_offset = manifest.verification_offset,
            _ => unreachable!(),
        }
        reseal_test_image(&mut image);
        assert_eq!(audit(&image), Err(AuditError::InvalidSearchManifest));
    }

    let aggregate_program =
        build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).expect("aggregate");
    let aggregate =
        emit_exact_aggregate(&aggregate_program, EmitLimits::default()).expect("aggregate image");
    let mut both_search = canonical.clone();
    both_search.aggregate = aggregate.inner().aggregate;
    reseal_test_image(&mut both_search);
    assert_eq!(audit(&both_search), Err(AuditError::InvalidImageContract));

    let mut both_aggregate = aggregate.inner().clone();
    both_aggregate.search = canonical.search;
    assert!(NativeAggregateImage::try_new(both_aggregate.clone()).is_err());
    reseal_test_image(&mut both_aggregate);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(both_aggregate)),
        Err(AuditError::InvalidImageContract)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the v4/v5 downgrade and tertiary-filter mutation matrix keeps each new operand and control edge explicit"
)]
fn v5_rejects_resealed_v4_downgrades_and_tertiary_filter_mutations() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("exact program");
    let canonical_v5 =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V5)
            .expect("canonical v5");
    let canonical_v4 =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V4)
            .expect("canonical v4");

    let mut v5_as_v4 = canonical_v5.clone();
    v5_as_v4.backend_version = BackendVersion::SEARCH_V4;
    {
        let manifest = v5_as_v4.search.as_mut().expect("v5 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V4;
        manifest.candidate_policy_version = 1;
        manifest.verification_offset = u16::MAX;
    }
    assert_resealed_search_rejected(v5_as_v4, "v5 code resealed as v4");

    let mut v4_as_v5 = canonical_v4;
    v4_as_v5.backend_version = BackendVersion::SEARCH_V5;
    {
        let manifest = v4_as_v5.search.as_mut().expect("v4 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V5;
        manifest.candidate_policy_version = 2;
        manifest.verification_offset = 0;
    }
    assert_resealed_search_rejected(v4_as_v5, "v4 code resealed as v5");

    for offset in [3_u16, 4, 15, u16::MAX] {
        let mut image = canonical_v5.clone();
        image
            .search
            .as_mut()
            .expect("v5 manifest")
            .verification_offset = offset;
        assert_resealed_search_rejected(image, "noncanonical sealed verification offset");
    }

    let decoded = decode(canonical_v5.code()).expect("canonical v5 code");
    let verification_literal_load = decoded
        .windows(2)
        .position(|pair| {
            pair == [
                DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset: 0,
                },
                DecodedInstruction::DuplicateByte16 {
                    destination: 5,
                    source: 11,
                },
            ]
        })
        .expect("verification literal load");
    let mut wrong_literal_offset = canonical_v5.clone();
    replace_test_decoded_at(
        &mut wrong_literal_offset,
        verification_literal_load,
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 8,
            offset: 1,
        },
    );
    assert_resealed_search_rejected(
        wrong_literal_offset,
        "verification literal load uses wrong offset",
    );

    let verification_pointer = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::SubtractImmediate64 {
                    destination: 10,
                    source: 15,
                    immediate: 7,
                }
        })
        .expect("verification column pointer");
    let mut wrong_pointer_offset = canonical_v5.clone();
    replace_test_decoded_at(
        &mut wrong_pointer_offset,
        verification_pointer,
        DecodedInstruction::SubtractImmediate64 {
            destination: 10,
            source: 15,
            immediate: 6,
        },
    );
    assert_resealed_search_rejected(
        wrong_pointer_offset,
        "verification column uses wrong offset",
    );

    let verification_load = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::LoadVector128 {
                    destination: 4,
                    base: 10,
                    offset: 0,
                }
        })
        .expect("verification vector load");
    let mut wrong_vector_base = canonical_v5.clone();
    replace_test_decoded_at(
        &mut wrong_vector_base,
        verification_load,
        DecodedInstruction::LoadVector128 {
            destination: 4,
            base: 9,
            offset: 0,
        },
    );
    assert_resealed_search_rejected(wrong_vector_base, "verification vector base mutation");

    let verification_intersection = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::AndBytes16 {
                    destination: 0,
                    left: 0,
                    right: 4,
                }
        })
        .expect("verification mask intersection");
    let mut wrong_intersection = canonical_v5.clone();
    replace_test_decoded_at(
        &mut wrong_intersection,
        verification_intersection,
        DecodedInstruction::AndBytes16 {
            destination: 0,
            left: 0,
            right: 2,
        },
    );
    assert_resealed_search_rejected(wrong_intersection, "verification mask bypass");

    let final_branch = decoded
        .windows(3)
        .position(|window| {
            matches!(
                window,
                [
                    DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                        destination: 0,
                        left: 0,
                        right: 0
                    },
                    DecodedInstruction::MoveVectorDoubleTo64 {
                        destination: 10,
                        source: 0
                    },
                    DecodedInstruction::CompareBranchZero64 {
                        register: 10,
                        nonzero: true,
                        ..
                    }
                ]
            )
        })
        .map(|index| index + 2)
        .expect("post-verification recovery branch");
    let DecodedInstruction::CompareBranchZero64 {
        register,
        displacement,
        ..
    } = decoded[final_branch]
    else {
        unreachable!("selected post-verification branch");
    };
    let mut inverted_branch = canonical_v5;
    replace_test_decoded_at(
        &mut inverted_branch,
        final_branch,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: false,
            displacement,
        },
    );
    let branch_offset = u32::try_from(final_branch * 4).expect("small code");
    let branch_word = u32::from_le_bytes(
        inverted_branch.code[final_branch * 4..final_branch * 4 + 4]
            .try_into()
            .expect("one branch word"),
    );
    inverted_branch
        .relocations
        .iter_mut()
        .find(|relocation| relocation.code_offset == branch_offset)
        .expect("post-verification branch relocation")
        .resolved_word = branch_word;
    assert_resealed_search_rejected(inverted_branch, "post-verification branch inversion");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the v6 downgrade, sparse-mask operand, lane-selection, clear-bit, resume, and complete branch mutation matrix is one security boundary"
)]
fn v6_rejects_resealed_v5_downgrades_and_every_sparse_recovery_mutation() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("exact program");
    let canonical_v6 =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V6)
            .expect("canonical v6");
    assert_eq!(canonical_v6.backend_version(), BackendVersion::SEARCH_V6);
    let canonical_v5 =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V5)
            .expect("canonical v5");

    let mut v6_as_v5 = canonical_v6.clone();
    v6_as_v5.backend_version = BackendVersion::SEARCH_V5;
    v6_as_v5
        .search
        .as_mut()
        .expect("v6 manifest")
        .backend_version = BackendVersion::SEARCH_V5;
    assert_resealed_search_rejected(v6_as_v5, "v6 code resealed as v5");

    let mut v5_as_v6 = canonical_v5;
    v5_as_v6.backend_version = BackendVersion::SEARCH_V6;
    v5_as_v6
        .search
        .as_mut()
        .expect("v5 manifest")
        .backend_version = BackendVersion::SEARCH_V6;
    assert_resealed_search_rejected(v5_as_v6, "v5 code resealed as v6");

    let decoded = decode(canonical_v6.code()).expect("canonical v6 decode");
    let mutations = [
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                            destination: 2,
                            source: 0,
                        }
                })
                .expect("SHRN #4 mask pack"),
            DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                destination: 2,
                source: 1,
            },
            "SHRN source",
        ),
        (
            decoded
                .windows(2)
                .position(|window| {
                    window
                        == [
                            DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                                destination: 2,
                                source: 0,
                            },
                            DecodedInstruction::MoveVectorDoubleTo64 {
                                destination: 0,
                                source: 2,
                            },
                        ]
                })
                .map(|index| index + 1)
                .expect("packed mask FMOV"),
            DecodedInstruction::MoveVectorDoubleTo64 {
                destination: 0,
                source: 0,
            },
            "packed mask FMOV source",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::MoveZero64 {
                            destination: 11,
                            immediate: 0x1111,
                            shift: 0,
                        }
                })
                .expect("sparse mask constant"),
            DecodedInstruction::MoveZero64 {
                destination: 11,
                immediate: 0x1110,
                shift: 0,
            },
            "sparse mask constant",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::AndRegister64 {
                            destination: 0,
                            left: 0,
                            right: 11,
                        }
                })
                .expect("sparse lane mask AND"),
            DecodedInstruction::AndRegister64 {
                destination: 0,
                left: 0,
                right: 10,
            },
            "sparse lane mask AND operand",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::MoveRegister64 {
                            destination: 7,
                            source: 5,
                        }
                })
                .expect("block base capture"),
            DecodedInstruction::MoveRegister64 {
                destination: 7,
                source: 6,
            },
            "block base capture",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::ReverseBits64 {
                            destination: 10,
                            source: 0,
                        }
                })
                .expect("RBIT lane selection"),
            DecodedInstruction::ReverseBits64 {
                destination: 10,
                source: 1,
            },
            "RBIT source",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::CountLeadingZeros64 {
                            destination: 10,
                            source: 10,
                        }
                })
                .expect("CLZ lane selection"),
            DecodedInstruction::CountLeadingZeros64 {
                destination: 10,
                source: 0,
            },
            "CLZ source",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::LogicalShiftRightImmediate64 {
                            destination: 10,
                            source: 10,
                            shift: 2,
                        }
                })
                .expect("nibble-bit lane scale"),
            DecodedInstruction::LogicalShiftRightImmediate64 {
                destination: 10,
                source: 10,
                shift: 3,
            },
            "lane scale",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::AddRegister64 {
                            destination: 5,
                            left: 7,
                            right: 10,
                        }
                })
                .expect("selected lane address"),
            DecodedInstruction::AddRegister64 {
                destination: 5,
                left: 7,
                right: 11,
            },
            "selected lane address operand",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::SubtractImmediate64 {
                            destination: 10,
                            source: 0,
                            immediate: 1,
                        }
                })
                .expect("lowest-bit clear predecessor"),
            DecodedInstruction::SubtractImmediate64 {
                destination: 10,
                source: 0,
                immediate: 2,
            },
            "lowest-bit clear predecessor",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::AndRegister64 {
                            destination: 0,
                            left: 0,
                            right: 10,
                        }
                })
                .expect("lowest-bit clear AND"),
            DecodedInstruction::AndRegister64 {
                destination: 0,
                left: 0,
                right: 11,
            },
            "lowest-bit clear AND operand",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::AddImmediate64 {
                            destination: 5,
                            source: 7,
                            immediate: 16,
                        }
                })
                .expect("block resume width"),
            DecodedInstruction::AddImmediate64 {
                destination: 5,
                source: 7,
                immediate: 15,
            },
            "block resume width",
        ),
        (
            decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::SubtractImmediate64 {
                            destination: 10,
                            source: 15,
                            immediate: 7,
                        }
                })
                .expect("verification column offset"),
            DecodedInstruction::SubtractImmediate64 {
                destination: 10,
                source: 15,
                immediate: 6,
            },
            "verification column offset",
        ),
    ];
    for (index, replacement, description) in mutations {
        let mut image = canonical_v6.clone();
        replace_test_decoded_at(&mut image, index, replacement);
        assert_resealed_search_rejected(image, description);
    }

    for (index, instruction) in decoded.iter().copied().enumerate() {
        let replacement = match instruction {
            DecodedInstruction::Branch { displacement } => Some(DecodedInstruction::Branch {
                displacement: displacement
                    .checked_add(4)
                    .expect("bounded branch mutation"),
            }),
            DecodedInstruction::BranchCondition {
                condition,
                displacement,
            } => Some(DecodedInstruction::BranchCondition {
                condition: if condition == Condition::Equal {
                    Condition::NotEqual
                } else {
                    Condition::Equal
                },
                displacement,
            }),
            DecodedInstruction::CompareBranchZero64 {
                register,
                nonzero,
                displacement,
            } => Some(DecodedInstruction::CompareBranchZero64 {
                register,
                nonzero: !nonzero,
                displacement,
            }),
            _ => None,
        };
        let Some(replacement) = replacement else {
            continue;
        };
        let mut image = canonical_v6.clone();
        replace_test_branch_and_relocation_at(&mut image, index, replacement);
        assert_resealed_search_rejected(image, "complete v6 branch mutation");
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the v7 downgrade, staged-mask operands, retained constants, caller-saved confirmation vectors, and complete branch matrix form one boundary"
)]
fn v7_rejects_downgrades_and_every_staged_recovery_mutation() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("exact program");
    let canonical_v7 =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V7)
            .expect("canonical v7");
    assert_eq!(canonical_v7.backend_version(), BackendVersion::SEARCH_V7);
    let manifest = canonical_v7.search_manifest().expect("v7 manifest");
    assert_eq!(
        (
            manifest.candidate_policy_version,
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
        ),
        (3, 7, 6, 8, 5)
    );
    let canonical_v6 =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V6)
            .expect("canonical v6");

    let mut v7_as_v6 = canonical_v7.clone();
    v7_as_v6.backend_version = BackendVersion::SEARCH_V6;
    {
        let manifest = v7_as_v6.search.as_mut().expect("v7 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V6;
        manifest.candidate_policy_version = 2;
        manifest.verification_offset = 0;
        manifest.quaternary_offset = u16::MAX;
    }
    assert_resealed_search_rejected(v7_as_v6, "v7 code resealed as v6");

    let mut v6_as_v7 = canonical_v6;
    v6_as_v7.backend_version = BackendVersion::SEARCH_V7;
    {
        let manifest = v6_as_v7.search.as_mut().expect("v6 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V7;
        manifest.candidate_policy_version = 3;
        manifest.verification_offset = 8;
        manifest.quaternary_offset = 5;
    }
    assert_resealed_search_rejected(v6_as_v7, "v6 code resealed as v7");

    let decoded = decode(canonical_v7.code()).expect("canonical v7 decode");
    assert_eq!(
        decoded
            .iter()
            .filter(|instruction| {
                matches!(
                    instruction,
                    DecodedInstruction::MoveZero64 {
                        destination: 14,
                        immediate: 0x1111,
                        shift: 0
                    }
                )
            })
            .count(),
        1,
        "the sparse mask constant is materialized once"
    );
    for vector in [1_u8, 3, 5, 7] {
        assert_eq!(
            decoded
                .iter()
                .filter(|instruction| {
                    matches!(
                        instruction,
                        DecodedInstruction::DuplicateByte16 {
                            destination,
                            source: 11
                        } if *destination == vector
                    )
                })
                .count(),
            1,
            "filter constant v{vector} is retained across rejected candidates"
        );
    }
    assert!(decoded.iter().any(|instruction| {
        matches!(
            instruction,
            DecodedInstruction::LoadVector128 {
                destination: 16,
                base: 15,
                offset: 0
            }
        )
    }));
    assert!(decoded.iter().any(|instruction| {
        matches!(
            instruction,
            DecodedInstruction::LoadVector128 {
                destination: 17,
                base: 8,
                offset: 0
            }
        )
    }));

    let mask_constant = decoded
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::MoveZero64 {
                    destination: 14,
                    immediate: 0x1111,
                    shift: 0
                }
            )
        })
        .expect("hoisted mask constant");
    let first_sparse_and = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::AndRegister64 {
                    destination: 0,
                    left: 0,
                    right: 14,
                }
        })
        .expect("v7 sparse mask AND");
    let fourth_intersection = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::AndBytes16 {
                    destination: 0,
                    left: 0,
                    right: 6,
                }
        })
        .expect("fourth-column intersection");
    let confirmation_load = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::LoadVector128 {
                    destination: 16,
                    base: 15,
                    offset: 0,
                }
        })
        .expect("caller-saved confirmation load");
    for (index, replacement, description) in [
        (
            mask_constant,
            DecodedInstruction::MoveZero64 {
                destination: 14,
                immediate: 0x1110,
                shift: 0,
            },
            "hoisted mask constant",
        ),
        (
            first_sparse_and,
            DecodedInstruction::AndRegister64 {
                destination: 0,
                left: 0,
                right: 11,
            },
            "hoisted sparse-mask operand",
        ),
        (
            fourth_intersection,
            DecodedInstruction::AndBytes16 {
                destination: 0,
                left: 0,
                right: 4,
            },
            "fourth-column intersection",
        ),
        (
            confirmation_load,
            DecodedInstruction::LoadVector128 {
                destination: 0,
                base: 15,
                offset: 0,
            },
            "retained-filter confirmation temporary",
        ),
    ] {
        let mut image = canonical_v7.clone();
        replace_test_decoded_at(&mut image, index, replacement);
        assert_resealed_search_rejected(image, description);
    }

    let mut forbidden_caller_saved_extension = canonical_v7.clone();
    replace_test_decoded_at(
        &mut forbidden_caller_saved_extension,
        confirmation_load,
        DecodedInstruction::LoadVector128 {
            destination: 18,
            base: 15,
            offset: 0,
        },
    );
    reseal_test_image(&mut forbidden_caller_saved_extension);
    assert!(matches!(
        audit(&forbidden_caller_saved_extension),
        Err(AuditError::ForbiddenSearchVectorRegister { register: 18, .. })
    ));

    for (index, instruction) in decoded.iter().copied().enumerate() {
        let replacement = match instruction {
            DecodedInstruction::Branch { displacement } => Some(DecodedInstruction::Branch {
                displacement: displacement
                    .checked_add(4)
                    .expect("bounded branch mutation"),
            }),
            DecodedInstruction::BranchCondition {
                condition,
                displacement,
            } => Some(DecodedInstruction::BranchCondition {
                condition: if condition == Condition::Equal {
                    Condition::NotEqual
                } else {
                    Condition::Equal
                },
                displacement,
            }),
            DecodedInstruction::CompareBranchZero64 {
                register,
                nonzero,
                displacement,
            } => Some(DecodedInstruction::CompareBranchZero64 {
                register,
                nonzero: !nonzero,
                displacement,
            }),
            _ => None,
        };
        let Some(replacement) = replacement else {
            continue;
        };
        let mut image = canonical_v7.clone();
        replace_test_branch_and_relocation_at(&mut image, index, replacement);
        assert_resealed_search_rejected(image, "complete v7 branch mutation");
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the fixed-lane semantic matrix keeps widths, windows, backend identities, and oracle comparisons together"
)]
fn sve16_backends_are_differentiated_deterministic_and_match_the_oracle() {
    let mut comparisons = 0_u64;
    for width in [1_usize, 2, 3, 15, 16, 17, 31, 32] {
        let literal: Vec<u8> = (0..width)
            .map(|index| {
                u8::try_from(index)
                    .expect("bounded width")
                    .wrapping_mul(37)
                    .wrapping_add(11)
            })
            .collect();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("SVE exact program");
        let sve = emit_sve16(&program, EmitLimits::default()).expect("SVE16 image");
        let sve_repeat = emit_sve16(&program, EmitLimits::default()).expect("repeat SVE16 image");
        let sve2 = emit_sve2_16(&program, EmitLimits::default()).expect("SVE2-16 image");
        assert_eq!(sve, sve_repeat);
        assert_eq!(sve.backend_version(), BackendVersion::SEARCH_SVE16_V1);
        assert_eq!(sve2.backend_version(), BackendVersion::SEARCH_SVE2_16_V1);
        assert_eq!(BackendVersion::SEARCH_CURRENT, BackendVersion::SEARCH_V8);
        assert_eq!(
            sve.search_manifest()
                .expect("SVE manifest")
                .candidate_policy_version,
            5
        );
        assert_eq!(
            sve2.search_manifest()
                .expect("SVE2 manifest")
                .candidate_policy_version,
            6
        );
        let expected_asimd = width >= 16;
        for image in [&sve, &sve2] {
            let report = audit(image).expect("independent SVE whole-template audit");
            assert!(report.vector_instructions > 0);
            assert_eq!(
                image.target().features.contains(CpuFeatures::ASIMD),
                expected_asimd
            );
            assert!(image.target().features.contains(CpuFeatures::SVE));
            assert_eq!(
                image.target().features.contains(CpuFeatures::SVE2),
                image.backend_version() == BackendVersion::SEARCH_SVE2_16_V1
            );
        }
        let baseline_instructions = decode(sve.code()).expect("SVE decode");
        let match_instructions = decode(sve2.code()).expect("SVE2 decode");
        assert!(baseline_instructions.iter().any(|instruction| matches!(
            instruction,
            DecodedInstruction::SvePtrueBytesVl16 { destination: 0 }
        )));
        assert!(baseline_instructions.iter().any(|instruction| matches!(
            instruction,
            DecodedInstruction::SveCompareEqualBytes { .. }
        )));
        assert!(
            !baseline_instructions
                .iter()
                .any(|instruction| instruction.is_sve2())
        );
        assert!(
            match_instructions.iter().any(|instruction| matches!(
                instruction,
                DecodedInstruction::Sve2MatchBytes { .. }
            ))
        );
        assert!(!match_instructions.iter().any(|instruction| matches!(
            instruction,
            DecodedInstruction::SveCompareEqualBytes { .. }
        )));
        assert_eq!(
            &sve.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
            b"FREA64\0\x09"
        );
        assert_eq!(
            &sve2.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
            b"FREA64\0\x0a"
        );

        let mut haystacks = vec![
            Vec::new(),
            literal.clone(),
            vec![0x55; width.saturating_sub(1)],
            vec![literal[0]; 79],
        ];
        for start in [0_usize, 1, 15, 16, 17, 31, 32, 63] {
            let mut haystack = vec![literal[0]; start + width + 19];
            for candidate in (0..start).step_by(3) {
                let available = haystack.len().saturating_sub(candidate).min(width);
                haystack[candidate..candidate + available].copy_from_slice(&literal[..available]);
                if available == width {
                    haystack[candidate + width - 1] ^= 1;
                }
            }
            haystack[start..start + width].copy_from_slice(&literal);
            haystacks.push(haystack);
        }
        for haystack in &haystacks {
            for (start, end) in [
                (0, haystack.len()),
                (0, haystack.len().saturating_sub(1)),
                (haystack.len().min(1), haystack.len()),
            ] {
                let window = SearchWindow::new(start, end);
                let expected = program
                    .execute(haystack, window, ExecutionLimits::unlimited())
                    .expect("oracle execution")
                    .output()
                    .map(|span| (span.start(), span.end()));
                for image in [&sve, &sve2] {
                    let actual =
                        simulate(image, haystack, start, end).expect("fixed-lane SVE ISA model");
                    assert_eq!(
                        span_output(actual),
                        expected,
                        "backend={:?} width={width} haystack_len={} window={start}..{end}",
                        image.backend_version(),
                        haystack.len()
                    );
                    comparisons = comparisons.checked_add(1).expect("bounded matrix");
                }
            }
        }
    }
    assert_eq!(comparisons, 576);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one versioned-backend test keeps policy, audit, layout, and oracle witnesses together"
)]
fn sve16_v6_candidate_is_distinct_audited_and_matches_the_oracle() {
    for width in [16_usize, 17, 32] {
        let literal: Vec<u8> = (0..width)
            .map(|index| {
                u8::try_from(index)
                    .expect("bounded width")
                    .wrapping_mul(41)
                    .wrapping_add(7)
            })
            .collect();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("SVE16 v6 program");
        let image = emit_sve16_v6(&program, EmitLimits::default()).expect("SVE16 v6 image");
        let repeated =
            emit_sve16_v6(&program, EmitLimits::default()).expect("repeat SVE16 v6 image");
        let v8 = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV8,
            EmitLimits::default(),
        )
        .expect("V8 layout reference");

        assert_eq!(image, repeated);
        assert_eq!(image.backend_version(), BackendVersion::SEARCH_SVE16_V6);
        assert_eq!(image.target().features, CpuFeatures::ASIMD_SVE);
        let manifest = image.search_manifest().expect("SVE16 v6 manifest");
        assert_eq!(manifest.candidate_policy_version, 5);
        audit(&image).expect("independent SVE16 v6 whole-template audit");
        let instructions = decode(image.code()).expect("SVE16 v6 decode");
        let ptrue_positions: Vec<_> = instructions
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                matches!(
                    instruction,
                    DecodedInstruction::SvePtrueBytesVl16 { destination: 0 }
                )
                .then_some(index)
            })
            .collect();
        let literal_vector_positions: Vec<_> = instructions
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                matches!(
                    instruction,
                    DecodedInstruction::SveLoadBytes {
                        destination: 31,
                        predicate: 0,
                        base: 8,
                    }
                )
                .then_some(index)
            })
            .collect();
        assert_eq!(ptrue_positions.len(), 1);
        assert_eq!(literal_vector_positions.len(), 1);
        assert_eq!(literal_vector_positions[0], ptrue_positions[0] + 1);
        let first_wide_pair = instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    DecodedInstruction::LoadVectorPair128 {
                        first_destination: 0,
                        second_destination: 2,
                        base: 15,
                        offset: 0,
                    }
                )
            })
            .expect("tag19 primary wide pair");
        assert!(
            literal_vector_positions[0] < first_wide_pair,
            "tag19 must establish P0/Z31 once before entering the wide screen"
        );
        let filters_cover_zero = manifest.primary_offset == 0
            || manifest.secondary_offset == 0
            || manifest.verification_offset == 0
            || manifest.quaternary_offset == 0;
        if !filters_cover_zero {
            assert_eq!(
                instructions
                    .iter()
                    .filter(|instruction| {
                        **instruction
                            == DecodedInstruction::MoveZero64 {
                                destination: 11,
                                immediate: u16::from(literal[0]),
                                shift: 0,
                            }
                    })
                    .count(),
                1,
                "tag19 retains literal[0] in x11 once per invocation"
            );
            assert!(
                instructions.windows(2).any(|window| matches!(
                    window,
                    [
                        DecodedInstruction::LoadByteRegister {
                            destination: 10,
                            base: 9,
                            index: 5,
                        },
                        DecodedInstruction::CompareRegister32 {
                            left: 10,
                            right: 11,
                        },
                    ]
                )),
                "tag19 recovery must compare directly against retained x11"
            );
        }
        if width > 16 {
            assert!(
                instructions.iter().any(|instruction| matches!(
                    instruction,
                    DecodedInstruction::LoadByte {
                        destination: 13,
                        base: 16,
                        offset: 0,
                    }
                )),
                "tag19 remainder confirmation must preserve retained x11"
            );
        }
        assert!(instructions.iter().any(|instruction| matches!(
            instruction,
            DecodedInstruction::SveBitClearPredicateBytesSetFlags { .. }
        )));
        assert!(!instructions.iter().any(|instruction| instruction.is_sve2()));
        if width == 16 {
            assert_eq!(
                image.stats().code_bytes,
                v8.stats().code_bytes,
                "the unreachable padding preserves V8's fixed-16 cold-tail address"
            );
        }
        assert_eq!(
            &image.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
            b"FREA64\0\x13"
        );

        let mut haystacks = vec![
            Vec::new(),
            literal.clone(),
            vec![literal[0]; 95],
            [b"prefix".as_slice(), literal.as_slice(), b"suffix"].concat(),
        ];
        let mut late = vec![literal[0]; 129 + width];
        late[129..].copy_from_slice(&literal);
        haystacks.push(late);
        for haystack in &haystacks {
            for (start, end) in [
                (0, haystack.len()),
                (haystack.len().min(1), haystack.len()),
                (0, haystack.len().saturating_sub(1)),
            ] {
                let window = SearchWindow::new(start, end);
                let expected = program
                    .execute(haystack, window, ExecutionLimits::unlimited())
                    .expect("oracle execution")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, haystack, start, end).expect("SVE16 v6 ISA model");
                assert_eq!(span_output(actual), expected);
            }
        }
    }

    let short = build_exact_literal::<Span>(
        b"0123456789abcde",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("short exact program");
    assert_eq!(
        emit_sve16_v6(&short, EmitLimits::default()),
        Err(EmitError::Unsupported {
            reason: crate::UnsupportedReason::KernelShape
        })
    );
    let anchored = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("anchored exact program");
    assert_eq!(
        emit_sve16_v6(&anchored, EmitLimits::default()),
        Err(EmitError::Unsupported {
            reason: crate::UnsupportedReason::KernelShape
        })
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the tag21 source gate keeps identity, ISA shape, mutations, and the fixed-lane oracle matrix together"
)]
fn sve2_fixed16_v2_candidate_is_versioned_audited_and_matches_the_oracle() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("tag21 exact program");
    let image =
        emit_sve2_fixed16_v2(&program, EmitLimits::default()).expect("tag21 candidate image");
    let repeated =
        emit_sve2_fixed16_v2(&program, EmitLimits::default()).expect("repeat tag21 image");

    assert_eq!(image, repeated);
    assert_eq!(
        image.backend_version(),
        BackendVersion::SEARCH_SVE2_FIXED16_V2
    );
    assert_eq!(image.target().features, CpuFeatures::ASIMD_SVE2);
    let manifest = image.search_manifest().expect("tag21 manifest");
    assert_eq!(manifest.candidate_policy_version, 8);
    assert_eq!(manifest.candidate_block_width, 16);
    assert_eq!(
        (
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ),
        (7, 6, 8, 5, 15)
    );
    audit(&image).expect("independent tag21 whole-template audit");
    let instructions = decode(image.code()).expect("tag21 decode");
    let setup_immediates: Vec<_> = instructions
        .iter()
        .filter_map(|instruction| match instruction {
            DecodedInstruction::MoveZero64 {
                destination: 11,
                immediate,
                shift: 0,
            } => Some(*immediate),
            _ => None,
        })
        .collect();
    assert_eq!(
        setup_immediates,
        [
            u16::from(literal[7]),
            u16::from(literal[6]),
            u16::from(literal[8]),
            u16::from(literal[5]),
            u16::from(literal[15]),
            u16::from(literal[0]),
        ],
        "tag21 materializes five filter bytes and the retained offset-zero byte without setup loads"
    );
    assert!(instructions.iter().any(|instruction| matches!(
        instruction,
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 0,
            second_destination: 2,
            base: 15,
            offset: 0,
        }
    )));
    assert!(instructions.iter().any(|instruction| matches!(
        instruction,
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 4,
            second_destination: 6,
            base: 15,
            offset: 32,
        }
    )));
    for retained_filter in [5_u8, 7, 22] {
        assert!(
            instructions.iter().any(|instruction| matches!(
                instruction,
                DecodedInstruction::CompareEqualBytes16 {
                    right,
                    ..
                } if *right == retained_filter
            )),
            "missing retained wide filter q{retained_filter}"
        );
    }
    let wide_pack_sources: Vec<_> = instructions
        .iter()
        .filter_map(|instruction| match instruction {
            DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                destination: 16,
                source,
            } => Some(*source),
            _ => None,
        })
        .collect();
    assert_eq!(wide_pack_sources, [0, 2, 4, 6]);
    assert_eq!(
        instructions
            .iter()
            .filter(|instruction| matches!(
                instruction,
                DecodedInstruction::LoadByteRegister {
                    destination: 10,
                    base: 9,
                    index: 13,
                }
            ))
            .count(),
        2,
        "wide and narrow tag21 recovery both reject offset-zero mismatches before SVE confirmation"
    );
    let mask_constant = instructions
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::MoveZero64 {
                    destination: 14,
                    immediate: 0x1111,
                    shift: 0,
                }
        })
        .expect("lazy tag21 sparse mask constant");
    let first_sparse_and = instructions
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::AndRegister64 {
                    destination: 0,
                    left: 0,
                    right: 14,
                }
        })
        .expect("first tag21 sparse mask AND");
    assert_eq!(
        &instructions[mask_constant..=first_sparse_and],
        &[
            DecodedInstruction::MoveZero64 {
                destination: 14,
                immediate: 0x1111,
                shift: 0,
            },
            DecodedInstruction::MoveKeep64 {
                destination: 14,
                immediate: 0x1111,
                shift: 16,
            },
            DecodedInstruction::MoveKeep64 {
                destination: 14,
                immediate: 0x1111,
                shift: 32,
            },
            DecodedInstruction::MoveKeep64 {
                destination: 14,
                immediate: 0x1111,
                shift: 48,
            },
            DecodedInstruction::AndRegister64 {
                destination: 0,
                left: 0,
                right: 14,
            },
        ],
        "tag21 materializes the four-instruction mask immediately before its first rare-path use"
    );
    assert_eq!(
        instructions.get(
            mask_constant
                .checked_sub(1)
                .expect("mask follows one instruction"),
        ),
        Some(&DecodedInstruction::MoveVectorDoubleTo64 {
            destination: 0,
            source: 16,
        }),
        "tag21 keeps mask setup out of eager and common screening paths"
    );
    for expected in ["MATCH", "CMPEQ", "ANDS", "BRKA", "BICS"] {
        assert!(
            instructions.iter().any(|instruction| match expected {
                "MATCH" => matches!(instruction, DecodedInstruction::Sve2MatchBytes { .. }),
                "CMPEQ" => matches!(instruction, DecodedInstruction::SveCompareEqualBytes { .. }),
                "ANDS" => matches!(
                    instruction,
                    DecodedInstruction::SveAndPredicateBytesSetFlags { .. }
                ),
                "BRKA" => matches!(instruction, DecodedInstruction::SveBreakAfterBytes { .. }),
                "BICS" => matches!(
                    instruction,
                    DecodedInstruction::SveBitClearPredicateBytesSetFlags { .. }
                ),
                _ => unreachable!("fixed tag21 instruction witness"),
            }),
            "missing tag21 {expected} witness"
        );
    }
    let aot = image.to_aot(AotLimits::default()).expect("tag21 AOT");
    assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x15");
    assert_eq!(aot.identity(), image.artifact_identity());

    let mut haystacks = vec![
        Vec::new(),
        literal.to_vec(),
        vec![b'x'; 15],
        vec![literal[7]; 160],
    ];
    for start in [0_usize, 1, 15, 16, 31, 32, 48, 63, 64, 65, 127] {
        let mut haystack = vec![literal[7]; start + literal.len() + 19];
        for false_start in (0..start).step_by(5) {
            for &offset in &[7_usize, 6, 8, 5, 15] {
                if let Some(slot) = haystack.get_mut(false_start + offset) {
                    *slot = literal[offset];
                }
            }
        }
        haystack[start..start + literal.len()].copy_from_slice(literal);
        haystacks.push(haystack);
    }
    let filter_offsets = [7_usize, 6, 8, 5, 15];
    // Force each retained wide filter to reject a survivor in every quarter,
    // while a later complete literal proves that scanning resumes exactly.
    for rejected_filter in 2..filter_offsets.len() {
        for false_start in [0_usize, 16, 32, 48] {
            let true_start = 80;
            let mut haystack = vec![0xa5; true_start + literal.len() + 19];
            for &offset in &filter_offsets[..rejected_filter] {
                haystack[false_start + offset] = literal[offset];
            }
            haystack[true_start..true_start + literal.len()].copy_from_slice(literal);
            haystacks.push(haystack);
        }
    }
    // Exercise sparse-mask recovery after an exact-confirmation miss, including
    // moving from each earlier 16-lane quarter to a later survivor.
    for (false_start, true_start) in [(0_usize, 16_usize), (0, 32), (0, 48), (16, 48), (32, 48)] {
        let mut haystack = vec![0xa5; 96];
        for &offset in &filter_offsets {
            haystack[false_start + offset] = literal[offset];
        }
        haystack[true_start..true_start + literal.len()].copy_from_slice(literal);
        haystacks.push(haystack);
    }
    for haystack in &haystacks {
        for (start, end) in [
            (0, haystack.len()),
            (haystack.len().min(1), haystack.len()),
            (0, haystack.len().saturating_sub(1)),
        ] {
            let window = SearchWindow::new(start, end);
            let expected = program
                .execute(haystack, window, ExecutionLimits::unlimited())
                .expect("tag21 oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual = simulate(&image, haystack, start, end).expect("tag21 ISA model");
            assert_eq!(
                span_output(actual),
                expected,
                "tag21 haystack_len={} window={start}..{end}",
                haystack.len()
            );
        }
    }

    let pair_index = instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadVectorPair128 {
                    first_destination: 0,
                    second_destination: 2,
                    base: 15,
                    offset: 0,
                }
            )
        })
        .expect("tag21 primary pair");
    for replacement in [
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 1,
            second_destination: 2,
            base: 15,
            offset: 0,
        },
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 0,
            second_destination: 3,
            base: 15,
            offset: 0,
        },
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 0,
            second_destination: 2,
            base: 14,
            offset: 0,
        },
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 0,
            second_destination: 2,
            base: 15,
            offset: 16,
        },
    ] {
        let mut mutated = image.clone();
        replace_test_decoded_at(&mut mutated, pair_index, replacement);
        assert_resealed_search_rejected(mutated, "tag21 pair-load substitution");
    }

    let break_after_index = instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::SveBreakAfterBytes {
                    destination: 3,
                    predicate: 0,
                    source: 1,
                }
            )
        })
        .expect("tag21 BRKA");
    for replacement in [
        DecodedInstruction::SveBreakAfterBytes {
            destination: 2,
            predicate: 0,
            source: 1,
        },
        DecodedInstruction::SveBreakAfterBytes {
            destination: 3,
            predicate: 1,
            source: 1,
        },
        DecodedInstruction::SveBreakAfterBytes {
            destination: 3,
            predicate: 0,
            source: 2,
        },
    ] {
        let mut mutated = image.clone();
        replace_test_decoded_at(&mut mutated, break_after_index, replacement);
        assert_resealed_search_rejected(mutated, "tag21 BRKA operand");
    }

    let and_set_flags_index = instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::SveAndPredicateBytesSetFlags {
                    destination: 1,
                    predicate: 0,
                    left: 1,
                    right: 2,
                }
            )
        })
        .expect("tag21 predicate ANDS");
    for replacement in [
        DecodedInstruction::SveAndPredicateBytesSetFlags {
            destination: 2,
            predicate: 0,
            left: 1,
            right: 2,
        },
        DecodedInstruction::SveAndPredicateBytesSetFlags {
            destination: 1,
            predicate: 1,
            left: 1,
            right: 2,
        },
        DecodedInstruction::SveAndPredicateBytesSetFlags {
            destination: 1,
            predicate: 0,
            left: 2,
            right: 2,
        },
        DecodedInstruction::SveAndPredicateBytesSetFlags {
            destination: 1,
            predicate: 0,
            left: 1,
            right: 3,
        },
        DecodedInstruction::SveAndPredicateBytes {
            destination: 1,
            predicate: 0,
            left: 1,
            right: 2,
        },
    ] {
        let mut mutated = image.clone();
        replace_test_decoded_at(&mut mutated, and_set_flags_index, replacement);
        assert_resealed_search_rejected(mutated, "tag21 predicate-ANDS substitution");
    }

    let bit_clear_index = instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::SveBitClearPredicateBytesSetFlags {
                    destination: 1,
                    predicate: 0,
                    left: 1,
                    right: 3,
                }
            )
        })
        .expect("tag21 predicate BICS");
    for replacement in [
        DecodedInstruction::SveBitClearPredicateBytesSetFlags {
            destination: 2,
            predicate: 0,
            left: 1,
            right: 3,
        },
        DecodedInstruction::SveBitClearPredicateBytesSetFlags {
            destination: 1,
            predicate: 1,
            left: 1,
            right: 3,
        },
        DecodedInstruction::SveBitClearPredicateBytesSetFlags {
            destination: 1,
            predicate: 0,
            left: 2,
            right: 3,
        },
        DecodedInstruction::SveBitClearPredicateBytesSetFlags {
            destination: 1,
            predicate: 0,
            left: 1,
            right: 2,
        },
    ] {
        let mut mutated = image.clone();
        replace_test_decoded_at(&mut mutated, bit_clear_index, replacement);
        assert_resealed_search_rejected(mutated, "tag21 predicate-BICS operand");
    }

    let mut mutated_fifth = image.clone();
    mutated_fifth
        .search
        .as_mut()
        .expect("tag21 manifest")
        .quinary_offset = manifest.primary_offset;
    reseal_test_image(&mut mutated_fifth);
    assert_eq!(
        audit(&mutated_fifth),
        Err(AuditError::InvalidSearchManifest)
    );

    for invalid_literal in [
        b"0123456789abcde".as_slice(),
        b"0123456789abcdefg".as_slice(),
    ] {
        let invalid = build_exact_literal::<Span>(
            invalid_literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("tag21 invalid-width source still forms valid IR");
        assert_eq!(
            emit_sve2_fixed16_v2(&invalid, EmitLimits::default()),
            Err(EmitError::Unsupported {
                reason: crate::UnsupportedReason::KernelShape
            })
        );
    }
    let anchored = build_exact_literal::<Span>(
        literal,
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("tag21 anchored source still forms valid IR");
    assert_eq!(
        emit_sve2_fixed16_v2(&anchored, EmitLimits::default()),
        Err(EmitError::Unsupported {
            reason: crate::UnsupportedReason::KernelShape
        })
    );
    let class_suffix = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"ab"),
        b"0123456789abcde",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("tag21 class-suffix source still forms valid IR");
    assert_eq!(
        emit_sve2_fixed16_v2(&class_suffix, EmitLimits::default()),
        Err(EmitError::Unsupported {
            reason: crate::UnsupportedReason::KernelShape
        })
    );
}

#[test]
fn tag21_omits_redundant_zero_precheck_when_a_filter_covers_zero() {
    let literal = [b'a'; 16];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("repeated tag21 exact program");
    let image =
        emit_sve2_fixed16_v2(&program, EmitLimits::default()).expect("repeated tag21 image");
    let manifest = image.search_manifest().expect("repeated tag21 manifest");
    let filter_offsets = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ];
    assert_eq!(filter_offsets, [0, 1, 2, 3, 15]);
    audit(&image).expect("zero-covered tag21 whole-template audit");

    let instructions = decode(image.code()).expect("zero-covered tag21 decode");
    let setup_immediates: Vec<_> = instructions
        .iter()
        .filter_map(|instruction| match instruction {
            DecodedInstruction::MoveZero64 {
                destination: 11,
                immediate,
                shift: 0,
            } => Some(*immediate),
            _ => None,
        })
        .collect();
    assert_eq!(
        setup_immediates,
        [u16::from(b'a'); 5],
        "an offset-zero filter needs five filter immediates and no retained duplicate"
    );
    assert!(
        !instructions.iter().any(|instruction| matches!(
            instruction,
            DecodedInstruction::LoadByteRegister {
                destination: 10,
                base: 9,
                index: 13,
            }
        )),
        "a selected offset-zero filter makes both scalar recovery prechecks redundant"
    );

    let mut false_only = vec![b'x'; 96];
    for &offset in &filter_offsets {
        false_only[usize::from(offset)] = literal[usize::from(offset)];
    }
    let mut false_then_match = false_only.clone();
    false_then_match[48..64].copy_from_slice(&literal);
    for haystack in [&false_only, &false_then_match] {
        let window = SearchWindow::new(0, haystack.len());
        let expected = program
            .execute(haystack, window, ExecutionLimits::unlimited())
            .expect("zero-covered tag21 oracle")
            .output()
            .map(|span| (span.start(), span.end()));
        let actual =
            simulate(&image, haystack, 0, haystack.len()).expect("zero-covered tag21 ISA model");
        assert_eq!(span_output(actual), expected);
    }
}

#[test]
fn tag21_fifth_offset_is_wire_versioned_without_changing_old_aot_layouts() {
    let program = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("versioned AOT program");
    for policy in [
        SearchBackendPolicy::AsimdV8,
        SearchBackendPolicy::Sve2Fixed16,
        SearchBackendPolicy::Sve16V6,
    ] {
        let mut image = emit_with_backend(&program, policy, EmitLimits::default())
            .expect("historical AOT image");
        let before = image.to_aot(AotLimits::default()).expect("historical AOT");
        image
            .search
            .as_mut()
            .expect("sealed historical manifest")
            .quinary_offset = 4;
        reseal_test_image(&mut image);
        let after = image
            .to_aot(AotLimits::default())
            .expect("historical AOT after in-memory-only field mutation");
        assert_eq!(
            before,
            after,
            "old backend {} serialized a tag21-only field",
            image.backend_version().0
        );
    }

    let canonical =
        emit_sve2_fixed16_v2(&program, EmitLimits::default()).expect("canonical tag21 image");
    let mut fifth_mutation = canonical.clone();
    fifth_mutation
        .search
        .as_mut()
        .expect("tag21 manifest")
        .quinary_offset = 3;
    reseal_test_image(&mut fifth_mutation);
    assert_ne!(
        canonical.to_aot(AotLimits::default()).expect("tag21 AOT"),
        fifth_mutation
            .to_aot(AotLimits::default())
            .expect("tag21 fifth-offset AOT"),
        "tag21 must serialize its fifth authenticated offset"
    );
}

#[test]
fn explicit_search_backend_policy_selects_distinct_artifact_identities() {
    let program = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("policy test program");
    let policies = [
        (SearchBackendPolicy::AsimdV7, BackendVersion::SEARCH_V7),
        (SearchBackendPolicy::AsimdV8, BackendVersion::SEARCH_V8),
        (SearchBackendPolicy::AsimdV9, BackendVersion::SEARCH_V9),
        (SearchBackendPolicy::AsimdV10, BackendVersion::SEARCH_V10),
        (SearchBackendPolicy::Sve16, BackendVersion::SEARCH_SVE16_V1),
        (
            SearchBackendPolicy::Sve2Fixed16,
            BackendVersion::SEARCH_SVE2_16_V1,
        ),
        (
            SearchBackendPolicy::Sve16V6,
            BackendVersion::SEARCH_SVE16_V6,
        ),
        (
            SearchBackendPolicy::Sve2Fixed16V2,
            BackendVersion::SEARCH_SVE2_FIXED16_V2,
        ),
    ];
    assert_eq!(SearchBackendPolicy::CURRENT, SearchBackendPolicy::AsimdV8);
    assert_eq!(SearchBackendPolicy::default(), SearchBackendPolicy::CURRENT);
    assert_eq!(
        SearchBackendPolicy::CURRENT.backend_version(),
        BackendVersion::SEARCH_CURRENT
    );
    assert_eq!(
        emit(&program, EmitLimits::default()).expect("default image"),
        emit_with_backend(
            &program,
            SearchBackendPolicy::CURRENT,
            EmitLimits::default()
        )
        .expect("explicit current image")
    );

    let mut identities = Vec::new();
    for (policy, expected_backend) in policies {
        assert_eq!(policy.backend_version(), expected_backend);
        let image = emit_with_backend(&program, policy, EmitLimits::default())
            .expect("policy-selected image");
        assert_eq!(image.backend_version(), expected_backend);
        assert_eq!(image.source_identity(), program.cache_identity());
        audit(&image).expect("policy-selected image audits");
        identities.push(image.artifact_identity());
    }
    for left in 0..identities.len() {
        for right in left + 1..identities.len() {
            assert_ne!(identities[left], identities[right]);
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the fixed-lane class-suffix matrix keeps policy selection, feature identity, and oracle comparisons together"
)]
fn sve16_singleton_class_suffix_matches_v7_and_the_oracle() {
    const SUFFIX_ALPHABET: &[u8] = b"bcdefghijklmnopqrstuvwxyz012345";

    let class = ByteClass::from_bytes(b"a");
    let mut comparisons = 0_u64;
    for suffix_len in [1_usize, 2, 15, 16, 17, 32] {
        let suffix: Vec<u8> = (0..suffix_len)
            .map(|index| SUFFIX_ALPHABET[index % SUFFIX_ALPHABET.len()])
            .collect();
        for anchors in [
            AnchorFlags::default(),
            AnchorFlags {
                start: false,
                end: true,
            },
        ] {
            let program =
                build_class_suffix::<Span>(class, &suffix, anchors, ValidateLimits::default())
                    .expect("singleton class-suffix program");
            let images = [
                emit_with_backend(
                    &program,
                    SearchBackendPolicy::AsimdV7,
                    EmitLimits::default(),
                )
                .expect("V7 class-suffix image"),
                emit_with_backend(&program, SearchBackendPolicy::Sve16, EmitLimits::default())
                    .expect("SVE16 class-suffix image"),
                emit_with_backend(
                    &program,
                    SearchBackendPolicy::Sve2Fixed16,
                    EmitLimits::default(),
                )
                .expect("SVE2 class-suffix image"),
            ];
            for (index, image) in images.iter().enumerate() {
                audit(image).expect("class-suffix image audits");
                let manifest = image.search_manifest().expect("sealed manifest");
                assert_eq!(manifest.shape, SearchShape::ClassSuffix);
                assert_eq!(manifest.candidate_policy_version, [1, 5, 6][index]);
                assert_eq!(
                    image.target().features.contains(CpuFeatures::SVE),
                    index != 0
                );
                assert_eq!(
                    image.target().features.contains(CpuFeatures::SVE2),
                    index == 2
                );
                assert_eq!(
                    image.target().features.contains(CpuFeatures::ASIMD),
                    index == 0 || suffix_len >= 16
                );
            }
            assert!(
                decode(images[1].code())
                    .expect("SVE class-suffix decode")
                    .iter()
                    .any(|instruction| matches!(
                        instruction,
                        DecodedInstruction::SveCountPredicateBytes { .. }
                    ))
            );
            assert!(
                decode(images[2].code())
                    .expect("SVE2 class-suffix decode")
                    .iter()
                    .any(|instruction| matches!(
                        instruction,
                        DecodedInstruction::Sve2MatchBytes { .. }
                    ))
            );

            let mut immediate = vec![b'a'];
            immediate.extend_from_slice(&suffix);
            let mut long_run = vec![b'a'; 47];
            long_run.extend_from_slice(&suffix);
            let mut offset_run = vec![b'x'; 19];
            offset_run.extend(std::iter::repeat_n(b'a', 33));
            offset_run.extend_from_slice(&suffix);
            offset_run.extend_from_slice(b"tail");
            let mut false_candidates = vec![b'x'; 96];
            for offset in (3..false_candidates.len()).step_by(11) {
                false_candidates[offset] = suffix[0];
            }
            let haystacks = [
                Vec::new(),
                suffix.clone(),
                immediate,
                long_run,
                offset_run,
                false_candidates,
            ];
            for haystack in &haystacks {
                let windows = [
                    SearchWindow::new(0, haystack.len()),
                    SearchWindow::new(haystack.len().min(1), haystack.len()),
                    SearchWindow::new(0, haystack.len().saturating_sub(1)),
                ];
                for window in windows {
                    let expected = program
                        .execute(haystack, window, ExecutionLimits::unlimited())
                        .expect("class-suffix oracle")
                        .output()
                        .map(|span| (span.start(), span.end()));
                    for image in &images {
                        let actual = simulate(image, haystack, window.start(), window.end())
                            .expect("fixed-lane class-suffix ISA model");
                        assert_eq!(
                            span_output(actual),
                            expected,
                            "backend={:?} suffix_len={suffix_len} anchors={anchors:?} haystack_len={} window={}..{}",
                            image.backend_version(),
                            haystack.len(),
                            window.start(),
                            window.end()
                        );
                        comparisons = comparisons.checked_add(1).expect("bounded matrix");
                    }
                }
            }

            let mut downgraded_policy = images[1].clone();
            downgraded_policy
                .search
                .as_mut()
                .expect("SVE class manifest")
                .candidate_policy_version = 1;
            reseal_test_image(&mut downgraded_policy);
            assert_eq!(
                audit(&downgraded_policy),
                Err(AuditError::InvalidSearchManifest)
            );
        }
    }
    assert_eq!(comparisons, 648);
}

#[test]
fn fixed16_class_suffix_refuses_unqualified_shapes() {
    let admitted_sve2_multi = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"ac"),
        b"suffix",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("multi-byte class program");
    let anchored = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        b"suffix",
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("start-anchored class program");
    let too_wide_members: Vec<u8> = (0..17).map(|index| b'A' + index).collect();
    let too_wide = build_class_suffix::<Span>(
        ByteClass::from_bytes(&too_wide_members),
        b"suffix",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("too-wide ASCII class program");
    let non_ascii = build_class_suffix::<Span>(
        ByteClass::from_bytes(&[b'A', 0x80]),
        b"suffix",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("non-ASCII class program");

    assert_eq!(
        emit_with_backend(
            &admitted_sve2_multi,
            SearchBackendPolicy::Sve16,
            EmitLimits::default()
        ),
        Err(EmitError::Unsupported {
            reason: crate::UnsupportedReason::KernelShape
        })
    );
    emit_with_backend(
        &admitted_sve2_multi,
        SearchBackendPolicy::Sve2Fixed16,
        EmitLimits::default(),
    )
    .expect("SVE2 admits a canonical two-member ASCII class");

    for program in [&anchored, &too_wide, &non_ascii] {
        for policy in [SearchBackendPolicy::Sve16, SearchBackendPolicy::Sve2Fixed16] {
            assert_eq!(
                emit_with_backend(program, policy, EmitLimits::default()),
                Err(EmitError::Unsupported {
                    reason: crate::UnsupportedReason::KernelShape
                })
            );
        }
    }

    for (program, backend) in [
        (&admitted_sve2_multi, BackendVersion::SEARCH_SVE16_V1),
        (&too_wide, BackendVersion::SEARCH_SVE2_16_V1),
        (&non_ascii, BackendVersion::SEARCH_SVE2_16_V1),
    ] {
        let mut relabeled =
            emit_with_backend(program, SearchBackendPolicy::AsimdV7, EmitLimits::default())
                .expect("V7 refusal seed");
        relabeled.backend_version = backend;
        relabeled
            .search
            .as_mut()
            .expect("sealed refusal seed")
            .backend_version = backend;
        reseal_test_image(&mut relabeled);
        assert_eq!(audit(&relabeled), Err(AuditError::InvalidSearchManifest));
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the SVE2 table matrix keeps canonical rodata, decoded operands, and oracle equivalence in one reviewable qualification"
)]
fn sve2_fixed16_ascii_class_tables_match_v7_and_the_oracle() {
    const SUFFIX_ALPHABET: &[u8] = b"bcdefghijklmnopqrstuvwxyz012345";

    let mut comparisons = 0_u64;
    for member_count in [2_usize, 3, 8, 16] {
        let canonical_members: Vec<u8> = if member_count == 2 {
            vec![0, 0x7f]
        } else {
            (0..member_count)
                .map(|index| b'A' + u8::try_from(index).expect("small class"))
                .collect()
        };
        let mut constructor_members: Vec<u8> = canonical_members.iter().copied().rev().collect();
        constructor_members.push(canonical_members[0]);
        let class = ByteClass::from_bytes(&constructor_members);
        let expected_table: [u8; 16] =
            core::array::from_fn(|index| canonical_members[index % member_count]);

        for suffix_len in [1_usize, 2, 16, 32] {
            let suffix: Vec<u8> = (0..suffix_len)
                .map(|index| SUFFIX_ALPHABET[index % SUFFIX_ALPHABET.len()])
                .collect();
            for anchors in [
                AnchorFlags::default(),
                AnchorFlags {
                    start: false,
                    end: true,
                },
            ] {
                let program =
                    build_class_suffix::<Span>(class, &suffix, anchors, ValidateLimits::default())
                        .expect("ASCII class-suffix program");
                let v7 = emit_with_backend(
                    &program,
                    SearchBackendPolicy::AsimdV7,
                    EmitLimits::default(),
                )
                .expect("V7 ASCII class image");
                let sve2 = emit_with_backend(
                    &program,
                    SearchBackendPolicy::Sve2Fixed16,
                    EmitLimits::default(),
                )
                .expect("SVE2 ASCII class image");
                audit(&v7).expect("V7 class image audits");
                audit(&sve2).expect("SVE2 class image audits");

                assert_eq!(v7.symbols.len(), 2);
                assert_eq!(v7.rodata.len(), 32 + suffix_len);
                let table_offset = (32 + suffix_len + 15) & !15;
                assert_eq!(sve2.symbols.len(), 3);
                assert_eq!(
                    sve2.symbols[2],
                    DataSymbol {
                        ir_data_id: 2,
                        offset: u32::try_from(table_offset).expect("small table offset"),
                        length: 16,
                        alignment: 16,
                        kind: DataSymbolKind::Bytes,
                    }
                );
                assert_eq!(
                    sve2.rodata.get(table_offset..table_offset + 16),
                    Some(expected_table.as_slice())
                );
                assert!(
                    sve2.rodata[32 + suffix_len..table_offset]
                        .iter()
                        .all(|&byte| byte == 0)
                );
                let manifest = sve2.search_manifest().expect("SVE2 class manifest");
                assert_eq!(manifest.shape, SearchShape::ClassSuffix);
                assert_eq!(manifest.candidate_policy_version, 6);
                assert_eq!(
                    sve2.target().features.contains(CpuFeatures::ASIMD),
                    suffix_len >= 16
                );
                assert!(sve2.target().features.contains(CpuFeatures::SVE));
                assert!(sve2.target().features.contains(CpuFeatures::SVE2));
                let decoded = decode(sve2.code()).expect("SVE2 table image decodes");
                assert!(decoded.iter().any(|instruction| {
                    matches!(
                        instruction,
                        DecodedInstruction::SveLoadBytes {
                            destination: 5,
                            predicate: 0,
                            base: 16
                        }
                    )
                }));
                assert!(decoded.iter().any(|instruction| {
                    matches!(
                        instruction,
                        DecodedInstruction::Sve2MatchBytes {
                            destination: 1,
                            predicate: 0,
                            left: 4,
                            right: 5
                        }
                    )
                }));

                let mut immediate = vec![canonical_members[0]];
                immediate.extend_from_slice(&suffix);
                let mut long_run: Vec<u8> = (0..47)
                    .map(|index| canonical_members[index % member_count])
                    .collect();
                long_run.extend_from_slice(&suffix);
                let mut offset_run = vec![b'!'; 19];
                offset_run
                    .extend((0..33).map(|index| canonical_members[(index + 1) % member_count]));
                offset_run.extend_from_slice(&suffix);
                offset_run.extend_from_slice(b"tail");
                let mut false_candidates = vec![b'!'; 96];
                for offset in (3..false_candidates.len()).step_by(11) {
                    false_candidates[offset] = suffix[0];
                }
                let haystacks = [
                    Vec::new(),
                    suffix.clone(),
                    immediate,
                    long_run,
                    offset_run,
                    false_candidates,
                ];
                for haystack in &haystacks {
                    for window in [
                        SearchWindow::new(0, haystack.len()),
                        SearchWindow::new(haystack.len().min(1), haystack.len()),
                        SearchWindow::new(0, haystack.len().saturating_sub(1)),
                    ] {
                        let expected = program
                            .execute(haystack, window, ExecutionLimits::unlimited())
                            .expect("ASCII class oracle")
                            .output()
                            .map(|span| (span.start(), span.end()));
                        for image in [&v7, &sve2] {
                            let actual = simulate(image, haystack, window.start(), window.end())
                                .expect("ASCII class ISA model");
                            assert_eq!(
                                span_output(actual),
                                expected,
                                "backend={:?} members={member_count} suffix_len={suffix_len} anchors={anchors:?} haystack_len={} window={}..{}",
                                image.backend_version(),
                                haystack.len(),
                                window.start(),
                                window.end()
                            );
                            comparisons = comparisons.checked_add(1).expect("bounded matrix");
                        }
                    }
                }
            }
        }
    }
    assert_eq!(comparisons, 1_152);

    let mutation_program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"CA"),
        b"suffix",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("table mutation program");
    let canonical =
        emit_sve2_16(&mutation_program, EmitLimits::default()).expect("canonical table image");
    let table_offset = usize::try_from(canonical.symbols[2].offset).expect("table offset");
    let exact_data_bytes = u64::try_from(canonical.rodata.len()).expect("bounded table image");
    emit_sve2_16(
        &mutation_program,
        EmitLimits {
            max_data_bytes: exact_data_bytes,
            ..EmitLimits::default()
        },
    )
    .expect("exact derived-table data boundary");
    assert!(matches!(
        emit_sve2_16(
            &mutation_program,
            EmitLimits {
                max_data_bytes: exact_data_bytes - 1,
                ..EmitLimits::default()
            }
        ),
        Err(EmitError::ResourceLimit {
            resource: ResourceKind::DataBytes,
            ..
        })
    ));

    let mut table_mutation = canonical.clone();
    table_mutation.rodata[table_offset] ^= 1;
    reseal_test_image(&mut table_mutation);
    assert_eq!(
        audit(&table_mutation),
        Err(AuditError::InvalidSearchManifest)
    );

    let mut padding_mutation = canonical.clone();
    padding_mutation.rodata[38] = 1;
    reseal_test_image(&mut padding_mutation);
    assert_eq!(
        audit(&padding_mutation),
        Err(AuditError::InvalidSearchManifest)
    );

    let decoded = decode(canonical.code()).expect("canonical table decode");
    let table_load = decoded
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::SveLoadBytes {
                    destination: 5,
                    predicate: 0,
                    base: 16
                }
            )
        })
        .expect("table load");
    let mut load_operand_mutation = canonical;
    replace_test_decoded_at(
        &mut load_operand_mutation,
        table_load,
        DecodedInstruction::SveLoadBytes {
            destination: 5,
            predicate: 0,
            base: 15,
        },
    );
    assert_resealed_search_rejected(load_operand_mutation, "SVE2 class-table load base mutation");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "admission, feature, relabeling, and every SVE1 operand mutation form one fail-closed contract"
)]
fn sve16_admission_features_relabels_and_operands_fail_closed() {
    let literal = b"0123456789abcdef";
    let span =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("SVE mutation program");
    let canonical = emit_sve16(&span, EmitLimits::default()).expect("canonical SVE");
    let canonical_sve2 = emit_sve2_16(&span, EmitLimits::default()).expect("canonical SVE2");

    let empty = build_exact_literal::<Span>(b"", AnchorFlags::default(), ValidateLimits::default())
        .expect("empty exact");
    let anchored = build_exact_literal::<Span>(
        literal,
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("anchored exact");
    for refused in [
        emit_sve16(&empty, EmitLimits::default()),
        emit_sve2_16(&empty, EmitLimits::default()),
        emit_sve16(&anchored, EmitLimits::default()),
        emit_sve2_16(&anchored, EmitLimits::default()),
    ] {
        assert_eq!(
            refused,
            Err(EmitError::Unsupported {
                reason: crate::UnsupportedReason::KernelShape
            })
        );
    }

    for (feature, description) in [
        (CpuFeatures::ASIMD, "missing SVE"),
        (CpuFeatures::SVE, "missing ASIMD"),
        (CpuFeatures::ASIMD_SVE2, "extra SVE2"),
    ] {
        let mut image = canonical.clone();
        image.target.features = feature;
        reseal_test_image(&mut image);
        assert_eq!(
            audit(&image),
            Err(AuditError::FeatureMismatch),
            "{description}"
        );
    }

    let mut sve_as_sve2 = canonical.clone();
    sve_as_sve2.backend_version = BackendVersion::SEARCH_SVE2_16_V1;
    sve_as_sve2.target.features = CpuFeatures::ASIMD_SVE2;
    {
        let manifest = sve_as_sve2.search.as_mut().expect("SVE manifest");
        manifest.backend_version = BackendVersion::SEARCH_SVE2_16_V1;
        manifest.candidate_policy_version = 6;
    }
    assert_resealed_search_rejected(sve_as_sve2, "SVE code relabeled SVE2");

    let mut sve2_as_sve = canonical_sve2.clone();
    sve2_as_sve.backend_version = BackendVersion::SEARCH_SVE16_V1;
    sve2_as_sve.target.features = CpuFeatures::ASIMD_SVE;
    {
        let manifest = sve2_as_sve.search.as_mut().expect("SVE2 manifest");
        manifest.backend_version = BackendVersion::SEARCH_SVE16_V1;
        manifest.candidate_policy_version = 5;
    }
    assert_resealed_search_rejected(sve2_as_sve, "SVE2 code relabeled SVE");

    let decoded = decode(canonical.code()).expect("canonical SVE decode");
    for (index, instruction) in decoded.into_iter().enumerate() {
        let replacement = match instruction {
            DecodedInstruction::SvePtrueBytesVl16 { destination } => {
                Some(DecodedInstruction::SvePtrueBytesVl16 {
                    destination: destination ^ 1,
                })
            }
            DecodedInstruction::SveDuplicateByte {
                destination,
                source,
            } => Some(DecodedInstruction::SveDuplicateByte {
                destination: destination ^ 2,
                source,
            }),
            DecodedInstruction::SveLoadBytes {
                destination,
                predicate,
                base,
            } => Some(DecodedInstruction::SveLoadBytes {
                destination,
                predicate,
                base: base ^ 1,
            }),
            DecodedInstruction::SveCompareEqualBytes {
                destination,
                predicate,
                left,
                right,
            } => Some(DecodedInstruction::SveCompareEqualBytes {
                destination: destination ^ 1,
                predicate,
                left,
                right,
            }),
            DecodedInstruction::SveAndPredicateBytes {
                destination,
                predicate,
                left,
                right,
            } => Some(DecodedInstruction::SveAndPredicateBytes {
                destination,
                predicate: predicate ^ 1,
                left,
                right,
            }),
            DecodedInstruction::SveAndPredicateBytesSetFlags {
                destination,
                predicate,
                left,
                right,
            } => Some(DecodedInstruction::SveAndPredicateBytesSetFlags {
                destination,
                predicate: predicate ^ 1,
                left,
                right,
            }),
            DecodedInstruction::SveTestPredicateBytes { predicate, tested } => {
                Some(DecodedInstruction::SveTestPredicateBytes {
                    predicate,
                    tested: tested ^ 1,
                })
            }
            DecodedInstruction::SveBreakBeforeBytes {
                destination,
                predicate,
                source,
            } => Some(DecodedInstruction::SveBreakBeforeBytes {
                destination,
                predicate,
                source: source ^ 1,
            }),
            DecodedInstruction::SveCountPredicateBytes {
                destination,
                predicate,
                source,
            } => Some(DecodedInstruction::SveCountPredicateBytes {
                destination: destination ^ 1,
                predicate,
                source,
            }),
            _ => None,
        };
        if let Some(replacement) = replacement {
            let mut image = canonical.clone();
            replace_test_decoded_at(&mut image, index, replacement);
            assert_resealed_search_rejected(image, "SVE operand mutation");
        }
    }
}

#[test]
fn sve2_operands_and_non_vl16_predicate_patterns_fail_closed() {
    let program = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("SVE2 mutation program");
    let canonical = emit_sve2_16(&program, EmitLimits::default()).expect("canonical SVE2 image");
    let instructions = decode(canonical.code()).expect("canonical SVE2 decode");
    let (match_index, matched) = instructions
        .iter()
        .copied()
        .enumerate()
        .find(|(_, instruction)| matches!(instruction, DecodedInstruction::Sve2MatchBytes { .. }))
        .expect("SVE2 backend contains MATCH");
    let DecodedInstruction::Sve2MatchBytes {
        destination,
        predicate,
        left,
        right,
    } = matched
    else {
        unreachable!("MATCH search above fixes the variant");
    };
    for replacement in [
        DecodedInstruction::Sve2MatchBytes {
            destination: destination ^ 1,
            predicate,
            left,
            right,
        },
        DecodedInstruction::Sve2MatchBytes {
            destination,
            predicate: predicate ^ 1,
            left,
            right,
        },
        DecodedInstruction::Sve2MatchBytes {
            destination,
            predicate,
            left: left ^ 2,
            right,
        },
        DecodedInstruction::Sve2MatchBytes {
            destination,
            predicate,
            left,
            right: right ^ 2,
        },
    ] {
        let mut image = canonical.clone();
        replace_test_decoded_at(&mut image, match_index, replacement);
        assert_resealed_search_rejected(image, "SVE2 MATCH operand mutation");
    }

    let mut non_vl16 = canonical;
    let ptrue_offset = decoded_position(non_vl16.code(), |instruction| {
        matches!(
            instruction,
            DecodedInstruction::SvePtrueBytesVl16 { destination: 0 }
        )
    });
    let ptrue_end = ptrue_offset.checked_add(4).expect("small code offset");
    let bytes = non_vl16
        .code
        .get_mut(ptrue_offset..ptrue_end)
        .expect("PTRUE word");
    let mut word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    // PTRUE's pattern is bits 9:5. Toggle VL16 (pattern 9) to VL8
    // (pattern 8); this remains architectural but is outside this contract.
    word ^= 1 << 5;
    bytes.copy_from_slice(&word.to_le_bytes());
    reseal_test_image(&mut non_vl16);
    assert!(decode(non_vl16.code()).is_err());
    assert!(audit(&non_vl16).is_err());
}

#[test]
fn v7_canonical_image_identity_remains_frozen_after_v8() {
    let program = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("frozen v7 program");
    let image =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V7)
            .expect("frozen v7 image");
    assert_eq!(
        image.artifact_identity().to_string(),
        "6573feb9a1938ded6baf58586dbc7ef7eae166a166c8c31c4e5889ea5be7c02c"
    );
    assert_eq!(
        &image.to_aot(AotLimits::default()).unwrap().as_bytes()[..8],
        b"FREA64\0\x07"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V8 mutation matrix keeps the wide and adaptive control-flow contracts together"
)]
fn v8_rejects_v7_relabeling_and_wide_screen_mutations() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("v8 mutation program");
    let canonical_v8 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )
    .expect("canonical v8");
    let canonical_v7 =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V7)
            .expect("canonical v7");
    assert_eq!(canonical_v8.backend_version(), BackendVersion::SEARCH_V8);
    assert_eq!(
        canonical_v8
            .search_manifest()
            .expect("v8 manifest")
            .candidate_policy_version,
        4
    );

    let mut v8_as_v7 = canonical_v8.clone();
    v8_as_v7.backend_version = BackendVersion::SEARCH_V7;
    {
        let manifest = v8_as_v7.search.as_mut().expect("v8 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V7;
        manifest.candidate_policy_version = 3;
    }
    assert_resealed_search_rejected(v8_as_v7, "v8 code resealed as v7");

    let mut v7_as_v8 = canonical_v7;
    v7_as_v8.backend_version = BackendVersion::SEARCH_V8;
    {
        let manifest = v7_as_v8.search.as_mut().expect("v7 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V8;
        manifest.candidate_policy_version = 4;
    }
    assert_resealed_search_rejected(v7_as_v8, "v7 code resealed as v8");

    let decoded = decode(canonical_v8.code()).expect("canonical v8 decode");
    let wide_pairs: Vec<_> = decoded
        .iter()
        .filter(|instruction| matches!(instruction, DecodedInstruction::LoadVectorPair128 { .. }))
        .copied()
        .collect();
    assert_eq!(
        wide_pairs,
        [
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 0,
                second_destination: 2,
                base: 15,
                offset: 0,
            },
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 4,
                second_destination: 6,
                base: 15,
                offset: 32,
            },
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 18,
                second_destination: 19,
                base: 10,
                offset: 0,
            },
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 20,
                second_destination: 21,
                base: 10,
                offset: 32,
            },
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 0,
                second_destination: 2,
                base: 10,
                offset: 0,
            },
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 4,
                second_destination: 6,
                base: 10,
                offset: 32,
            },
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 18,
                second_destination: 19,
                base: 15,
                offset: 0,
            },
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 20,
                second_destination: 21,
                base: 15,
                offset: 32,
            },
        ],
        "V8 uses the tag21 paired-load shape for every wide 64-byte group"
    );
    assert_eq!(
        decoded
            .iter()
            .filter(|instruction| {
                **instruction
                    == DecodedInstruction::MoveZero64 {
                        destination: 11,
                        immediate: u16::from(literal[0]),
                        shift: 0,
                    }
            })
            .count(),
        1,
        "V8 retains literal[0] in x11 once per invocation"
    );
    assert!(
        decoded.windows(2).any(|window| matches!(
            window,
            [
                DecodedInstruction::LoadByteRegister {
                    destination: 10,
                    base: 9,
                    index: 5,
                },
                DecodedInstruction::CompareRegister32 {
                    left: 10,
                    right: 11,
                },
            ]
        )),
        "V8 recovery must compare directly against retained x11"
    );
    let wide_secondary_load = decoded
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadVectorPair128 {
                    first_destination: 18,
                    second_destination: 19,
                    base: 10,
                    offset: 0
                }
            )
        })
        .expect("wide secondary load");
    let mut vector_operand = canonical_v8.clone();
    replace_test_decoded_at(
        &mut vector_operand,
        wide_secondary_load,
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 22,
            second_destination: 19,
            base: 10,
            offset: 0,
        },
    );
    assert_resealed_search_rejected(vector_operand, "v8 wide vector operand");

    let adaptive_primary_load = decoded
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadVectorPair128 {
                    first_destination: 18,
                    second_destination: 19,
                    base: 15,
                    offset: 0
                }
            )
        })
        .expect("adaptive primary recheck");
    let secondary_empty_branch = adaptive_primary_load
        .checked_sub(1)
        .expect("adaptive primary recheck follows its secondary-empty branch");
    assert!(matches!(
        decoded.get(secondary_empty_branch),
        Some(DecodedInstruction::CompareBranchZero64 {
            register: 10,
            nonzero: false,
            ..
        })
    ));
    let adaptive_recheck = [
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 18,
            second_destination: 19,
            base: 15,
            offset: 0,
        },
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 20,
            second_destination: 21,
            base: 15,
            offset: 32,
        },
        DecodedInstruction::CompareEqualBytes16 {
            destination: 18,
            left: 18,
            right: 1,
        },
        DecodedInstruction::AndBytes16 {
            destination: 0,
            left: 0,
            right: 18,
        },
        DecodedInstruction::CompareEqualBytes16 {
            destination: 19,
            left: 19,
            right: 1,
        },
        DecodedInstruction::AndBytes16 {
            destination: 2,
            left: 2,
            right: 19,
        },
        DecodedInstruction::CompareEqualBytes16 {
            destination: 20,
            left: 20,
            right: 1,
        },
        DecodedInstruction::AndBytes16 {
            destination: 4,
            left: 4,
            right: 20,
        },
        DecodedInstruction::CompareEqualBytes16 {
            destination: 21,
            left: 21,
            right: 1,
        },
        DecodedInstruction::AndBytes16 {
            destination: 6,
            left: 6,
            right: 21,
        },
    ];
    let adaptive_recheck_end = adaptive_primary_load
        .checked_add(adaptive_recheck.len())
        .expect("bounded adaptive recheck");
    assert_eq!(
        decoded.get(adaptive_primary_load..adaptive_recheck_end),
        Some(adaptive_recheck.as_slice())
    );
    let pair_empty_branch = adaptive_recheck_end
        .checked_add(5)
        .expect("bounded adaptive presence reduction");
    assert!(matches!(
        decoded.get(pair_empty_branch),
        Some(DecodedInstruction::CompareBranchZero64 {
            register: 10,
            nonzero: false,
            ..
        })
    ));
    let branch_target = |instruction_index: usize| {
        let DecodedInstruction::CompareBranchZero64 { displacement, .. } =
            decoded[instruction_index]
        else {
            panic!("adaptive branch must be CBZ");
        };
        let instruction_bytes = i64::try_from(instruction_index)
            .expect("small adaptive instruction index")
            .checked_mul(4)
            .expect("small adaptive instruction address");
        let target_bytes = instruction_bytes
            .checked_add(i64::from(displacement))
            .expect("bounded adaptive branch target");
        assert_eq!(target_bytes % 4, 0);
        usize::try_from(target_bytes / 4).expect("nonnegative adaptive branch target")
    };
    let secondary_only_advance = branch_target(secondary_empty_branch);
    let wide_advance = branch_target(pair_empty_branch);
    assert!(
        wide_advance < secondary_only_advance,
        "pair-empty recheck must switch back to the earlier primary-first advance"
    );
    for advance in [wide_advance, secondary_only_advance] {
        assert_eq!(
            decoded.get(advance),
            Some(&DecodedInstruction::AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: 64,
            })
        );
    }
    let redirected_displacement = i64::try_from(secondary_only_advance)
        .expect("small secondary-only advance")
        .checked_sub(i64::try_from(pair_empty_branch).expect("small adaptive branch"))
        .and_then(|instructions| instructions.checked_mul(4))
        .and_then(|bytes| i32::try_from(bytes).ok())
        .expect("encodable adaptive redirect");
    let mut redirected_pair_empty = canonical_v8.clone();
    replace_test_branch_and_relocation_at(
        &mut redirected_pair_empty,
        pair_empty_branch,
        DecodedInstruction::CompareBranchZero64 {
            register: 10,
            nonzero: false,
            displacement: redirected_displacement,
        },
    );
    assert_resealed_search_rejected(redirected_pair_empty, "v8 adaptive pair-empty mode switch");
    let mut adaptive_operand = canonical_v8.clone();
    replace_test_decoded_at(
        &mut adaptive_operand,
        adaptive_primary_load,
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 18,
            second_destination: 19,
            base: 10,
            offset: 0,
        },
    );
    assert_resealed_search_rejected(adaptive_operand, "v8 adaptive primary operand");

    let wide_presence_branch = decoded
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 10,
                    nonzero: true,
                    ..
                }
            )
        })
        .expect("v8 wide presence branch");
    let DecodedInstruction::CompareBranchZero64 {
        register,
        nonzero,
        displacement,
    } = decoded[wide_presence_branch]
    else {
        unreachable!()
    };
    let mut inverted_branch = canonical_v8;
    replace_test_branch_and_relocation_at(
        &mut inverted_branch,
        wide_presence_branch,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: !nonzero,
            displacement,
        },
    );
    assert_resealed_search_rejected(inverted_branch, "v8 wide presence branch");
}

#[test]
fn v6_sparse_recovery_widths_authenticate_for_every_output() {
    for width in [1_usize, 15, 17, 31, 32] {
        let mut literal = vec![b'a'; width];
        literal[width / 2] = b'Z';
        let exists = build_exact_literal::<Exists>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("Exists exact");
        let selected = build_exact_literal::<SelectedEnd>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("SelectedEnd exact");
        let span = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("Span exact");
        for image in [
            emit_search_version_for_test(&exists, EmitLimits::default(), BackendVersion::SEARCH_V6)
                .expect("Exists v6"),
            emit_search_version_for_test(
                &selected,
                EmitLimits::default(),
                BackendVersion::SEARCH_V6,
            )
            .expect("SelectedEnd v6"),
            emit_search_version_for_test(&span, EmitLimits::default(), BackendVersion::SEARCH_V6)
                .expect("Span v6"),
        ] {
            assert_eq!(image.backend_version(), BackendVersion::SEARCH_V6);
            audit(&image).expect("whole v6 sparse recovery template");
        }
    }
}

#[test]
fn v8_every_admitted_width_audits_and_round_trips_for_every_output() {
    for width in 0_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal: Vec<u8> = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded width")
                    .wrapping_mul(73)
                    .wrapping_add(19)
            })
            .collect();
        let exists = build_exact_literal::<Exists>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("Exists exact");
        let selected = build_exact_literal::<SelectedEnd>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("SelectedEnd exact");
        let span = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("Span exact");
        for image in [
            emit_with_backend(&exists, SearchBackendPolicy::AsimdV8, EmitLimits::default())
                .expect("Exists v8"),
            emit_with_backend(
                &selected,
                SearchBackendPolicy::AsimdV8,
                EmitLimits::default(),
            )
            .expect("SelectedEnd v8"),
            emit_with_backend(&span, SearchBackendPolicy::AsimdV8, EmitLimits::default())
                .expect("Span v8"),
        ] {
            assert_eq!(image.backend_version(), BackendVersion::SEARCH_V8);
            let manifest = image.search_manifest().expect("sealed v8 manifest");
            assert_eq!(
                manifest.candidate_policy_version,
                u16::from(width != 0) * 4,
                "candidate-policy eligibility at width {width}"
            );
            assert_eq!(
                manifest.secondary_offset != u16::MAX,
                width >= 2,
                "second-column eligibility at width {width}"
            );
            assert_eq!(
                manifest.verification_offset != u16::MAX,
                width >= 3,
                "third-column eligibility at width {width}"
            );
            assert_eq!(
                manifest.quaternary_offset != u16::MAX,
                width >= 4,
                "fourth-column eligibility at width {width}"
            );

            let report = audit(&image).expect("independent whole-template v8 audit");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 1)
            );
            let decoded = decode(image.code()).expect("v8 image decodes");
            assert_eq!(decoded.len() * 4, image.code().len());
            for (encoded, instruction) in image.code().chunks_exact(4).zip(decoded) {
                let word = u32::from_le_bytes(
                    encoded
                        .try_into()
                        .expect("instruction chunks are exactly four bytes"),
                );
                assert_eq!(
                    crate::decode::canonical_word(instruction),
                    Some(word),
                    "instruction round trip at literal width {width}"
                );
            }
            let aot = image.to_aot(AotLimits::default()).expect("bounded v8 AOT");
            assert_eq!(aot.identity(), image.artifact_identity());
        }
    }

    let over_limit = vec![b'x'; MAX_REPEATED_CONFIRM_BYTES + 1];
    let program = build_exact_literal::<Span>(
        &over_limit,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("over-limit IR remains available to another backend");
    assert_eq!(
        emit(&program, EmitLimits::default()),
        Err(EmitError::ConfirmationLengthLimit {
            kind: ConfirmationKind::ExactLiteral,
            limit: MAX_REPEATED_CONFIRM_BYTES,
            required: MAX_REPEATED_CONFIRM_BYTES + 1,
        })
    );
}

#[test]
fn v9_is_a_distinct_audited_exact_literal_contract_and_v8_remains_sealed() {
    for width in 1_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal: Vec<u8> = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect();
        for output in [
            OutputKind::Exists,
            OutputKind::SelectedEnd,
            OutputKind::Span,
        ] {
            let image = match output {
                OutputKind::Exists => {
                    let program = build_exact_literal::<Exists>(
                        &literal,
                        AnchorFlags::default(),
                        ValidateLimits::default(),
                    )
                    .expect("V9 Exists IR");
                    emit_with_backend(
                        &program,
                        SearchBackendPolicy::AsimdV9,
                        EmitLimits::default(),
                    )
                }
                OutputKind::SelectedEnd => {
                    let program = build_exact_literal::<SelectedEnd>(
                        &literal,
                        AnchorFlags::default(),
                        ValidateLimits::default(),
                    )
                    .expect("V9 SelectedEnd IR");
                    emit_with_backend(
                        &program,
                        SearchBackendPolicy::AsimdV9,
                        EmitLimits::default(),
                    )
                }
                OutputKind::Span => {
                    let program = build_exact_literal::<Span>(
                        &literal,
                        AnchorFlags::default(),
                        ValidateLimits::default(),
                    )
                    .expect("V9 Span IR");
                    emit_with_backend(
                        &program,
                        SearchBackendPolicy::AsimdV9,
                        EmitLimits::default(),
                    )
                }
            }
            .expect("V9 exact image");
            assert_eq!(image.backend_version(), BackendVersion::SEARCH_V9);
            assert_eq!(
                image
                    .search_manifest()
                    .expect("V9 manifest")
                    .candidate_policy_version,
                9
            );
            let report = audit(&image).expect("independent V9 whole-template audit");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 1)
            );
            let aot = image.to_aot(AotLimits::default()).expect("bounded V9 AOT");
            assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x16");
            assert_eq!(aot.identity(), image.artifact_identity());
        }
    }

    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V8/V9 identity program");
    let canonical_v8 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )
    .expect("canonical V8");
    let canonical_v9 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV9,
        EmitLimits::default(),
    )
    .expect("canonical V9");
    assert_ne!(canonical_v8.code(), canonical_v9.code());
    assert_ne!(
        canonical_v8.artifact_identity(),
        canonical_v9.artifact_identity()
    );

    let mut v9_as_v8 = canonical_v9.clone();
    v9_as_v8.backend_version = BackendVersion::SEARCH_V8;
    {
        let manifest = v9_as_v8.search.as_mut().expect("V9 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V8;
        manifest.candidate_policy_version = 4;
    }
    assert_resealed_search_rejected(v9_as_v8, "V9 code resealed as V8");

    let mut v8_as_v9 = canonical_v8;
    v8_as_v9.backend_version = BackendVersion::SEARCH_V9;
    {
        let manifest = v8_as_v9.search.as_mut().expect("V8 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V9;
        manifest.candidate_policy_version = 9;
    }
    assert_resealed_search_rejected(v8_as_v9, "V8 code resealed as V9");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V10 contract test keeps wire identity, terminal-filter shape, relabel resistance, and adversarial semantic coverage together"
)]
fn v10_terminal_filter_is_distinct_audited_and_matches_the_oracle() {
    let mut comparisons = 0_u64;
    for width in 1_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal: Vec<u8> = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V10 Span IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV10,
            EmitLimits::default(),
        )
        .expect("V10 exact image");
        assert_eq!(image.backend_version(), BackendVersion::SEARCH_V10);
        let manifest = image.search_manifest().expect("V10 manifest");
        assert_eq!(manifest.candidate_policy_version, 10);
        let terminal = u16::try_from(width - 1).expect("bounded terminal offset");
        if manifest.primary_offset != terminal && manifest.secondary_offset != terminal {
            assert_eq!(
                manifest.quinary_offset, terminal,
                "V10 must reserve the terminal byte when the packed pair does not"
            );
        }
        let selected_offsets = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ];
        for left in 0..selected_offsets.len() {
            if selected_offsets[left] == u16::MAX {
                continue;
            }
            assert!(usize::from(selected_offsets[left]) < width);
            for right in left + 1..selected_offsets.len() {
                assert_ne!(selected_offsets[left], selected_offsets[right]);
            }
        }
        let report = audit(&image).expect("independent V10 whole-template audit");
        assert_eq!(
            (report.decode_passes, report.source_identity_rebuilds),
            (1, 1)
        );
        let aot = image.to_aot(AotLimits::default()).expect("bounded V10 AOT");
        assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x17");
        assert_eq!(aot.identity(), image.artifact_identity());
        let extra_outputs = [
            {
                let program = build_exact_literal::<Exists>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("V10 Exists IR");
                emit_with_backend(
                    &program,
                    SearchBackendPolicy::AsimdV10,
                    EmitLimits::default(),
                )
                .expect("V10 Exists image")
            },
            {
                let program = build_exact_literal::<SelectedEnd>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("V10 SelectedEnd IR");
                emit_with_backend(
                    &program,
                    SearchBackendPolicy::AsimdV10,
                    EmitLimits::default(),
                )
                .expect("V10 SelectedEnd image")
            },
        ];
        for extra_image in extra_outputs {
            assert_eq!(extra_image.backend_version(), BackendVersion::SEARCH_V10);
            assert_eq!(
                extra_image
                    .search_manifest()
                    .expect("V10 output manifest")
                    .candidate_policy_version,
                10
            );
            audit(&extra_image).expect("independent V10 output-template audit");
            assert_eq!(
                &extra_image
                    .to_aot(AotLimits::default())
                    .expect("bounded V10 output AOT")
                    .as_bytes()[..8],
                b"FREA64\0\x17"
            );
        }

        let decoded = decode(image.code()).expect("V10 decode");
        let has_fifth_filter = decoded.iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareEqualBytes16 {
                    destination: 22,
                    left: 22,
                    right: 23,
                }
            )
        });
        assert_eq!(
            has_fifth_filter,
            manifest.quinary_offset != u16::MAX,
            "the fifth code column and authenticated offset must be present together"
        );

        let mut terminal_near_miss = literal.clone();
        terminal_near_miss[width - 1] ^= 0x80;
        let mut near_miss_stream = Vec::new();
        for _ in 0..8 {
            near_miss_stream.extend_from_slice(&terminal_near_miss);
        }
        near_miss_stream.extend_from_slice(&literal);
        let mut dense_matches = Vec::new();
        for _ in 0..8 {
            dense_matches.extend_from_slice(&literal);
        }
        let mut haystacks = vec![
            Vec::new(),
            literal.clone(),
            vec![0xa5; 257],
            near_miss_stream,
            dense_matches,
        ];
        for candidate_start in [0_usize, 1, 15, 16, 17, 31, 32, 63] {
            let mut haystack = vec![0xe3; candidate_start + width + 67];
            haystack[candidate_start..candidate_start + width].copy_from_slice(&literal);
            haystacks.push(haystack);
        }
        for haystack in &haystacks {
            for (start, end) in [
                (0, haystack.len()),
                (haystack.len().min(1), haystack.len()),
                (0, haystack.len().saturating_sub(1)),
            ] {
                let window = SearchWindow::new(start, end);
                let expected = program
                    .execute(haystack, window, ExecutionLimits::unlimited())
                    .expect("V10 oracle execution")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual =
                    simulate(&image, haystack, start, end).expect("V10 safe ISA simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} haystack_len={} window={start}..{end}",
                    haystack.len()
                );
                comparisons = comparisons.checked_add(1).expect("bounded matrix");
            }
        }
    }
    assert_eq!(comparisons, 1_248);

    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V8/V9/V10 identity program");
    let canonical_v8 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV8,
        EmitLimits::default(),
    )
    .expect("canonical V8");
    let canonical_v9 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV9,
        EmitLimits::default(),
    )
    .expect("canonical V9");
    let canonical_v10 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV10,
        EmitLimits::default(),
    )
    .expect("canonical V10");
    assert_ne!(canonical_v10.code(), canonical_v8.code());
    assert_ne!(canonical_v10.code(), canonical_v9.code());
    assert_ne!(
        canonical_v10.artifact_identity(),
        canonical_v8.artifact_identity()
    );
    assert_ne!(
        canonical_v10.artifact_identity(),
        canonical_v9.artifact_identity()
    );

    let mut v10_as_v9 = canonical_v10;
    v10_as_v9.backend_version = BackendVersion::SEARCH_V9;
    {
        let manifest = v10_as_v9.search.as_mut().expect("V10 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V9;
        manifest.candidate_policy_version = 9;
        manifest.quinary_offset = u16::MAX;
    }
    assert_resealed_search_rejected(v10_as_v9, "V10 code resealed as V9");

    let mut v9_as_v10 = canonical_v9;
    v9_as_v10.backend_version = BackendVersion::SEARCH_V10;
    {
        let manifest = v9_as_v10.search.as_mut().expect("V9 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V10;
        manifest.candidate_policy_version = 10;
        manifest.quinary_offset = 15;
    }
    assert_resealed_search_rejected(v9_as_v10, "V9 code resealed as V10");
}

#[test]
fn v9_and_v10_reject_shapes_without_one_nonempty_unanchored_exact_candidate() {
    for backend in [SearchBackendPolicy::AsimdV9, SearchBackendPolicy::AsimdV10] {
        for anchors in [
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
            let anchored =
                build_exact_literal::<Span>(b"x", anchors, ValidateLimits::default()).expect("IR");
            assert_eq!(
                emit_with_backend(&anchored, backend, EmitLimits::default()),
                Err(EmitError::Unsupported {
                    reason: UnsupportedReason::KernelShape,
                })
            );
        }
        let empty =
            build_exact_literal::<Span>(b"", AnchorFlags::default(), ValidateLimits::default())
                .expect("empty IR");
        assert_eq!(
            emit_with_backend(&empty, backend, EmitLimits::default()),
            Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            })
        );
        let class = build_class_suffix::<Span>(
            ByteClass::from_bytes(b"a"),
            b"bc",
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("class IR");
        assert_eq!(
            emit_with_backend(&class, backend, EmitLimits::default()),
            Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            })
        );
    }
}

#[test]
fn v5_generic_recovery_widths_authenticate_for_every_output() {
    for width in [1_usize, 15, 17, 31, 32] {
        let mut literal = vec![b'a'; width];
        literal[width / 2] = b'Z';
        let exists = build_exact_literal::<Exists>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("Exists exact");
        let selected = build_exact_literal::<SelectedEnd>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("SelectedEnd exact");
        let span = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("Span exact");
        for image in [
            emit_search_version_for_test(&exists, EmitLimits::default(), BackendVersion::SEARCH_V5)
                .expect("Exists image"),
            emit_search_version_for_test(
                &selected,
                EmitLimits::default(),
                BackendVersion::SEARCH_V5,
            )
            .expect("SelectedEnd image"),
            emit_search_version_for_test(&span, EmitLimits::default(), BackendVersion::SEARCH_V5)
                .expect("Span image"),
        ] {
            let report = audit(&image).expect("whole generic recovery template");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 1)
            );
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the coordinated exploit remains one auditable mutation sequence"
)]
fn sealed_manifest_rejects_coordinated_identity_opcode_bound_load_and_branch_exploit() {
    let literal = b"0123456789abcdef";
    let mut image = exact_span_search_image(literal);
    let anchored = build_exact_literal::<Span>(
        literal,
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("alternate anchored identity");
    image.source_identity = anchored.cache_identity();
    {
        let manifest = image.search.as_mut().expect("search manifest");
        manifest.source_identity = anchored.cache_identity();
        manifest.anchors = AnchorFlags {
            start: true,
            end: false,
        };
    }

    let instructions = decode(image.code()).expect("canonical v5 code");
    for (index, instruction) in instructions.into_iter().enumerate() {
        let replacement = match instruction {
            DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                destination, left, ..
            } => Some(DecodedInstruction::UnsignedMaxBytes16 {
                destination,
                source: left,
            }),
            DecodedInstruction::MoveVectorDoubleTo64 {
                destination,
                source,
            } => Some(DecodedInstruction::MoveVectorByteTo32 {
                destination,
                source,
            }),
            _ => None,
        };
        if let Some(replacement) = replacement {
            replace_test_decoded_at(&mut image, index, replacement);
        }
    }
    let instructions = decode(image.code()).expect("downgraded opcode code");
    let bound = instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::SubtractImmediate64 {
                    destination: 7,
                    source: 6,
                    immediate: 15
                }
            )
        })
        .expect("hoisted bound");
    replace_test_decoded_at(
        &mut image,
        bound,
        DecodedInstruction::SubtractImmediate64 {
            destination: 7,
            source: 6,
            immediate: 14,
        },
    );
    let instructions = decode(image.code()).expect("bound mutation");
    let load = instructions
        .iter()
        .rposition(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadVector128 {
                    destination: 0,
                    base: 15,
                    offset: 0
                }
            )
        })
        .expect("fixed confirmation load");
    replace_test_decoded_at(
        &mut image,
        load,
        DecodedInstruction::LoadVector128 {
            destination: 0,
            base: 14,
            offset: 0,
        },
    );
    let instructions = decode(image.code()).expect("load mutation");
    let branch = instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 10,
                    nonzero: true,
                    ..
                }
            )
        })
        .expect("candidate branch");
    let DecodedInstruction::CompareBranchZero64 {
        register,
        displacement,
        ..
    } = instructions[branch]
    else {
        unreachable!("selected candidate branch");
    };
    replace_test_decoded_at(
        &mut image,
        branch,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: false,
            displacement,
        },
    );
    let branch_offset = u32::try_from(branch * 4).expect("small branch");
    let word = u32::from_le_bytes(
        image.code[branch * 4..branch * 4 + 4]
            .try_into()
            .expect("one branch"),
    );
    image
        .relocations
        .iter_mut()
        .find(|relocation| relocation.code_offset == branch_offset)
        .expect("branch relocation")
        .resolved_word = word;

    reseal_test_image(&mut image);
    assert!(
        !decode(image.code()).unwrap().iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::UnsignedMaxPairwiseBytes16 { .. }
                    | DecodedInstruction::MoveVectorDoubleTo64 { .. }
            )
        }),
        "exploit removes the obvious v2-era opcode discriminator"
    );
    assert!(audit(&image).is_err());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the v5 fail-closed mutation matrix keeps each safety-critical operand visible"
)]
fn v5_exact_search_audit_rejects_resealed_template_and_envelope_mutations() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("v5 exact program");
    let canonical =
        emit_search_version_for_test(&program, EmitLimits::default(), BackendVersion::SEARCH_V5)
            .expect("canonical v5");

    let mut missing_primary = canonical.clone();
    let primary_dup = decode(missing_primary.code())
        .expect("canonical image")
        .into_iter()
        .position(|instruction| {
            instruction
                == DecodedInstruction::DuplicateByte16 {
                    destination: 1,
                    source: 11,
                }
        })
        .expect("primary duplicate");
    replace_test_decoded_at(
        &mut missing_primary,
        primary_dup,
        DecodedInstruction::DuplicateByte16 {
            destination: 2,
            source: 11,
        },
    );
    assert_resealed_search_rejected(missing_primary, "removed primary signature");

    let mut pair_offset = canonical.clone();
    let primary_load = decode(pair_offset.code())
        .expect("canonical image")
        .into_iter()
        .position(|instruction| {
            instruction
                == DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset: 7,
                }
        })
        .expect("canonical rare primary byte");
    replace_test_decoded_at(
        &mut pair_offset,
        primary_load,
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 8,
            offset: 8,
        },
    );
    assert_resealed_search_rejected(pair_offset, "noncanonical pair offset");

    let mut hoisted_bound = canonical.clone();
    let bound = decode(hoisted_bound.code())
        .expect("canonical image")
        .into_iter()
        .position(|instruction| {
            instruction
                == DecodedInstruction::SubtractImmediate64 {
                    destination: 7,
                    source: 6,
                    immediate: 15,
                }
        })
        .expect("hoisted vector bound");
    replace_test_decoded_at(
        &mut hoisted_bound,
        bound,
        DecodedInstruction::SubtractImmediate64 {
            destination: 7,
            source: 6,
            immediate: 14,
        },
    );
    assert_resealed_search_rejected(hoisted_bound, "weakened hoisted bound");

    let mut missing_scalar_reset = canonical.clone();
    let scalar_reset = decode(missing_scalar_reset.code())
        .expect("canonical image")
        .into_iter()
        .enumerate()
        .filter(|(_, instruction)| {
            *instruction
                == DecodedInstruction::AddRegister64 {
                    destination: 15,
                    left: 9,
                    right: 5,
                }
        })
        .map(|(index, _)| index)
        .next_back()
        .expect("scalar reset after candidate filter");
    replace_test_decoded_at(
        &mut missing_scalar_reset,
        scalar_reset,
        DecodedInstruction::MoveRegister64 {
            destination: 15,
            source: 15,
        },
    );
    assert_resealed_search_rejected(missing_scalar_reset, "missing scalar pointer reset");

    let mut fixed_load_base = canonical.clone();
    let fixed_load = decode(fixed_load_base.code())
        .expect("canonical image")
        .into_iter()
        .enumerate()
        .filter(|(_, instruction)| {
            *instruction
                == DecodedInstruction::LoadVector128 {
                    destination: 0,
                    base: 15,
                    offset: 0,
                }
        })
        .map(|(index, _)| index)
        .next_back()
        .expect("fixed-width confirmation load");
    replace_test_decoded_at(
        &mut fixed_load_base,
        fixed_load,
        DecodedInstruction::LoadVector128 {
            destination: 0,
            base: 14,
            offset: 0,
        },
    );
    assert_resealed_search_rejected(fixed_load_base, "wrong fixed-width load base");

    let reduction = decode(canonical.code())
        .expect("canonical image")
        .into_iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                    destination: 2,
                    left: 0,
                    right: 0
                }
            )
        })
        .expect("primary reduction");
    for register in 8_u8..=15 {
        let mut callee_saved_vector = canonical.clone();
        replace_test_decoded_at(
            &mut callee_saved_vector,
            reduction,
            DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                destination: register,
                left: 0,
                right: 0,
            },
        );
        reseal_test_image(&mut callee_saved_vector);
        assert!(matches!(
            audit(&callee_saved_vector),
            Err(AuditError::ForbiddenSearchVectorRegister {
                register: actual,
                ..
            }) if actual == register
        ));
    }

    let mut bad_status = canonical.clone();
    let found_status = decode(bad_status.code())
        .expect("canonical image")
        .into_iter()
        .position(|instruction| {
            instruction
                == DecodedInstruction::MoveZero64 {
                    destination: 0,
                    immediate: 1,
                    shift: 0,
                }
        })
        .expect("found status");
    replace_test_decoded_at(
        &mut bad_status,
        found_status,
        DecodedInstruction::MoveZero64 {
            destination: 0,
            immediate: 2,
            shift: 0,
        },
    );
    assert_resealed_search_rejected(bad_status, "noncanonical found status");

    let mut second_symbol = canonical.clone();
    let mut symbols = second_symbol.symbols.into_vec();
    symbols.push(DataSymbol {
        ir_data_id: 1,
        offset: u32::try_from(literal.len()).expect("small literal"),
        length: 0,
        alignment: 1,
        kind: DataSymbolKind::Bytes,
    });
    second_symbol.symbols = symbols.into_boxed_slice();
    assert_resealed_search_rejected(second_symbol, "second zero-length symbol");

    let mut wrong_kind = canonical.clone();
    wrong_kind.symbols[0].kind = DataSymbolKind::ByteClass;
    assert_resealed_search_rejected(wrong_kind, "non-Bytes exact symbol");

    let mut duplicate_none_label = canonical;
    let none = duplicate_none_label
        .labels
        .iter()
        .find(|label| label.kind == LabelKind::ReturnNone)
        .copied()
        .expect("return-none label");
    let mut labels = duplicate_none_label.labels.into_vec();
    labels.push(none);
    labels.sort_unstable();
    duplicate_none_label.labels = labels.into_boxed_slice();
    duplicate_none_label.stats.labels += 1;
    assert_resealed_search_rejected(duplicate_none_label, "duplicate return-none label");
}

#[test]
fn m17_count_decoded_template_accepts_only_the_canonical_phase_graph() {
    let program = build_exact_aggregate::<Count>(b"0123456789abcdefg", ValidateLimits::default())
        .expect("M=17 Count program");
    let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=17 Count image");
    assert!(m17_count_template_matches(image.inner()));
    audit_aggregate(&image).expect("existing independent audit also accepts the canonical image");
}

fn replace_test_instruction(
    image: &mut NativeImage,
    predicate: impl Fn(DecodedInstruction) -> bool,
    replacement: u32,
) -> u32 {
    let position = decoded_position(image.code(), predicate);
    let offset = u32::try_from(position).expect("small test image");
    decode_one(replacement, offset).expect("canonical test mutation");
    image.code[position..position + 4].copy_from_slice(&replacement.to_le_bytes());
    offset
}

fn replace_test_decoded_at(
    image: &mut NativeImage,
    instruction_index: usize,
    replacement: DecodedInstruction,
) {
    let offset = instruction_index
        .checked_mul(4)
        .expect("small test instruction offset");
    let offset_u32 = u32::try_from(offset).expect("small test image");
    let word = crate::decode::canonical_word(replacement).expect("canonical test mutation");
    assert_eq!(decode_one(word, offset_u32), Ok(replacement));
    image.code[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
}

fn replace_test_branch_and_relocation_at(
    image: &mut NativeImage,
    instruction_index: usize,
    replacement: DecodedInstruction,
) {
    let (DecodedInstruction::Branch { displacement }
    | DecodedInstruction::BranchCondition { displacement, .. }
    | DecodedInstruction::CompareBranchZero64 { displacement, .. }) = replacement
    else {
        panic!("branch replacement required");
    };
    replace_test_decoded_at(image, instruction_index, replacement);
    let code_offset = u32::try_from(
        instruction_index
            .checked_mul(4)
            .expect("small branch instruction offset"),
    )
    .expect("small branch code offset");
    let target = i64::from(code_offset)
        .checked_add(i64::from(displacement))
        .and_then(|value| u32::try_from(value).ok())
        .expect("bounded branch target");
    let resolved_word = u32::from_le_bytes(
        image.code[usize::try_from(code_offset).expect("small code offset")
            ..usize::try_from(code_offset).expect("small code offset") + 4]
            .try_into()
            .expect("one branch word"),
    );
    let relocation = image
        .relocations
        .iter_mut()
        .find(|relocation| relocation.code_offset == code_offset)
        .expect("branch relocation");
    relocation.target = RelocationTarget::CodeOffset(target);
    relocation.resolved_word = resolved_word;
}

fn assert_m17_prototype_rejects(mut image: NativeImage, mutation: &str) {
    reseal_test_image(&mut image);
    assert!(decode(image.code()).is_ok(), "{mutation} remains decodable");
    assert!(
        !m17_count_template_matches(&image),
        "M=17 prototype accepted {mutation}"
    );
    assert!(
        audit_aggregate(&NativeAggregateImage::new(image)).is_err(),
        "production template accepted {mutation}"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the bounded prototype keeps one coherent witness from each semantic mutation class together"
)]
fn m17_count_decoded_template_rejects_representative_semantic_mutations() {
    let program = build_exact_aggregate::<Count>(b"0123456789abcdefg", ValidateLimits::default())
        .expect("M=17 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=17 Count image");

    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::SubtractRegister64 {
                    destination: 10,
                    left: 6,
                    right: 5
                }
            )
        },
        0xcb05_002a,
    );
    assert_m17_prototype_rejects(inner, "remaining-length source substitution");

    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::AddImmediate64 {
                    destination: 15,
                    source: 15,
                    immediate: 16
                }
            )
        },
        0x9100_05ef,
    );
    assert_m17_prototype_rejects(inner, "vector-confirmation stride substitution");

    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::MoveRegister64 {
                    destination: 15,
                    source: 15
                }
            )
        },
        0x9100_41ef,
    );
    assert_m17_prototype_rejects(inner, "confirmation prologue pointer advance");

    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadByte {
                    destination: 10,
                    base: 15,
                    offset: 0
                }
            )
        },
        0x3940_010a,
    );
    assert_m17_prototype_rejects(inner, "scalar-confirmation load-role substitution");

    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareEqualBytes16 {
                    destination: 0,
                    left: 0,
                    right: 1
                }
            )
        },
        0x6e20_8c00,
    );
    assert_m17_prototype_rejects(inner, "SIMD self-compare substitution");

    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 16
                }
            )
        },
        0x9100_44a5,
    );
    assert_m17_prototype_rejects(inner, "vector-skip cursor delta substitution");

    let mut inner = valid.inner().clone();
    let branch_offset = 264_u32;
    let target = 180_u32;
    let displacement_words = i32::try_from(target).expect("small target")
        - i32::try_from(branch_offset).expect("small branch");
    let displacement_words = displacement_words / 4;
    let immediate = u32::from_ne_bytes(displacement_words.to_ne_bytes()) & 0x7_ffff;
    let replacement = 0xb500_0000 | (immediate << 5) | 17;
    assert_eq!(
        decode_one(replacement, branch_offset),
        Ok(DecodedInstruction::CompareBranchZero64 {
            register: 17,
            nonzero: true,
            displacement: -84,
        })
    );
    inner.code[264..268].copy_from_slice(&replacement.to_le_bytes());
    let relocation = inner
        .relocations
        .iter_mut()
        .find(|relocation| relocation.code_offset == branch_offset)
        .expect("scalar confirmation relocation");
    relocation.target = RelocationTarget::CodeOffset(target);
    relocation.resolved_word = replacement;
    assert_m17_prototype_rejects(inner, "confirmation CBNZ retarget");

    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset: 16
                }
            )
        },
        0x3940_010b,
    );
    assert_m17_prototype_rejects(inner, "last-byte filter offset substitution");

    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::AddImmediate64 {
                    destination: 13,
                    source: 13,
                    immediate: 1
                }
            )
        },
        0x9100_45ad,
    );
    assert_m17_prototype_rejects(inner, "Count reducer-delta substitution");

    let mut inner = valid.inner().clone();
    for byte in 0..4 {
        inner.code.swap(168 + byte, 172 + byte);
    }
    assert_m17_prototype_rejects(inner, "instruction reorder");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the three independently simulated overread witnesses remain adjacent for auditability"
)]
fn semantic_memory_mutants_have_independent_invalid_read_witnesses() {
    let literal = b"0123456789abcdefg";
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("M=17 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=17 Count image");

    let mut remainder_source = valid.inner().clone();
    let index = decode(remainder_source.code())
        .expect("canonical M=17 decode")
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::SubtractRegister64 {
                    destination: 10,
                    left: 6,
                    right: 5
                }
            )
        })
        .expect("remaining-length subtraction");
    replace_test_decoded_at(
        &mut remainder_source,
        index,
        DecodedInstruction::SubtractRegister64 {
            destination: 10,
            left: 1,
            right: 5,
        },
    );
    assert_eq!(
        simulate_aggregate(
            &NativeAggregateImage::new(remainder_source.clone()),
            literal
        ),
        Err(SimError::InvalidMemoryRead),
        "x10=x1-x5 admits an out-of-range last-column vector load"
    );
    assert_m17_prototype_rejects(remainder_source, "remaining-length source overread");

    let mut advanced_prologue = valid.inner().clone();
    let index = decode(advanced_prologue.code())
        .expect("canonical M=17 decode")
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::MoveRegister64 {
                    destination: 15,
                    source: 15
                }
            )
        })
        .expect("confirmation prologue");
    replace_test_decoded_at(
        &mut advanced_prologue,
        index,
        DecodedInstruction::AddImmediate64 {
            destination: 15,
            source: 15,
            immediate: 16,
        },
    );
    assert_eq!(
        simulate_aggregate(
            &NativeAggregateImage::new(advanced_prologue.clone()),
            literal
        ),
        Err(SimError::InvalidMemoryRead),
        "advanced confirmation prologue reads beyond the exact-width haystack"
    );
    assert_m17_prototype_rejects(advanced_prologue, "confirmation prologue overread");

    let literal = b"0123456789abcdefgh";
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("M=18 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=18 Count image");
    let mut scalar_stride = valid.inner().clone();
    let instructions = decode(scalar_stride.code()).expect("canonical M=18 decode");
    let index = instructions
        .iter()
        .rposition(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::AddImmediate64 {
                    destination: 15,
                    source: 15,
                    immediate: 1
                }
            )
        })
        .expect("scalar confirmation haystack stride");
    replace_test_decoded_at(
        &mut scalar_stride,
        index,
        DecodedInstruction::AddImmediate64 {
            destination: 15,
            source: 15,
            immediate: 16,
        },
    );
    assert_eq!(
        simulate_aggregate(&NativeAggregateImage::new(scalar_stride.clone()), literal),
        Err(SimError::InvalidMemoryRead),
        "scalar +16 stride overruns before the remaining counter reaches zero"
    );
    reseal_test_image(&mut scalar_stride);
    assert!(audit_aggregate(&NativeAggregateImage::new(scalar_stride)).is_err());
}

#[test]
fn m17_template_rejects_every_cursor_delta_pairwise_substitution() {
    let program = build_exact_aggregate::<Count>(b"0123456789abcdefg", ValidateLimits::default())
        .expect("M=17 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=17 Count image");
    let instructions = decode(valid.code()).expect("canonical M=17 decode");
    for (index, instruction) in instructions.iter().copied().enumerate() {
        let DecodedInstruction::AddImmediate64 {
            destination: 5,
            source: 5,
            immediate,
        } = instruction
        else {
            continue;
        };
        if !matches!(immediate, 1 | 16 | 17) {
            continue;
        }
        for replacement in [1_u16, 16, 17] {
            if replacement == immediate {
                continue;
            }
            let mut inner = valid.inner().clone();
            replace_test_decoded_at(
                &mut inner,
                index,
                DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: replacement,
                },
            );
            assert_m17_prototype_rejects(inner, "pairwise cursor-delta phase substitution");
        }
    }
}

#[test]
fn m17_template_rejects_every_confirmation_stride_and_load_base_substitution() {
    let program = build_exact_aggregate::<Count>(b"0123456789abcdefg", ValidateLimits::default())
        .expect("M=17 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=17 Count image");
    let instructions = decode(valid.code()).expect("canonical M=17 decode");

    for (index, instruction) in instructions.iter().copied().enumerate() {
        if let DecodedInstruction::AddImmediate64 {
            destination,
            source,
            immediate,
        } = instruction
            && matches!(
                (destination, source, immediate),
                (15, 15, 1 | 16) | (16, 16, 1 | 16)
            )
        {
            let mut inner = valid.inner().clone();
            replace_test_decoded_at(
                &mut inner,
                index,
                DecodedInstruction::AddImmediate64 {
                    destination,
                    source,
                    immediate: if immediate == 1 { 16 } else { 1 },
                },
            );
            assert_m17_prototype_rejects(inner, "confirmation stride substitution");
        }

        let (actual_base, replacement_instruction) = match instruction {
            DecodedInstruction::LoadVector128 {
                destination: 4 | 5,
                base,
                offset: 0,
            } if matches!(base, 15 | 16) => (base, 0_u8),
            DecodedInstruction::LoadByte {
                destination: 10 | 11,
                base,
                offset: 0,
            } if matches!(base, 15 | 16) => (base, 1_u8),
            _ => continue,
        };
        for replacement_base in [8_u8, 15, 16] {
            if replacement_base == actual_base {
                continue;
            }
            let replacement = match (replacement_instruction, instruction) {
                (
                    0,
                    DecodedInstruction::LoadVector128 {
                        destination,
                        offset,
                        ..
                    },
                ) => DecodedInstruction::LoadVector128 {
                    destination,
                    base: replacement_base,
                    offset,
                },
                (
                    1,
                    DecodedInstruction::LoadByte {
                        destination,
                        offset,
                        ..
                    },
                ) => DecodedInstruction::LoadByte {
                    destination,
                    base: replacement_base,
                    offset,
                },
                _ => unreachable!("classified confirmation load"),
            };
            let mut inner = valid.inner().clone();
            replace_test_decoded_at(&mut inner, index, replacement);
            assert_m17_prototype_rejects(inner, "confirmation load-base role substitution");
        }

        let replacement = match instruction {
            DecodedInstruction::LoadVector128 {
                destination,
                base,
                offset,
            } => DecodedInstruction::LoadVector128 {
                destination: if destination == 4 { 5 } else { 4 },
                base,
                offset,
            },
            DecodedInstruction::LoadByte {
                destination,
                base,
                offset,
            } => DecodedInstruction::LoadByte {
                destination: if destination == 10 { 11 } else { 10 },
                base,
                offset,
            },
            _ => unreachable!("classified confirmation load"),
        };
        let mut inner = valid.inner().clone();
        replace_test_decoded_at(&mut inner, index, replacement);
        assert_m17_prototype_rejects(inner, "confirmation load destination-role substitution");
    }
}

#[test]
fn template_rejects_each_last_filter_and_width_one_simd_opcode_substitution() {
    let program = build_exact_aggregate::<Count>(b"0123456789abcdefg", ValidateLimits::default())
        .expect("M=17 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=17 Count image");
    for (index, instruction) in decode(valid.code())
        .expect("canonical M=17 decode")
        .into_iter()
        .enumerate()
    {
        let replacement = match instruction {
            DecodedInstruction::LoadByte {
                destination: 11,
                base: 8,
                offset: 16,
            } => Some(DecodedInstruction::LoadByte {
                destination: 11,
                base: 8,
                offset: 0,
            }),
            DecodedInstruction::LoadByte {
                destination: 10,
                base: 15,
                offset: 16,
            } => Some(DecodedInstruction::LoadByte {
                destination: 10,
                base: 15,
                offset: 0,
            }),
            _ => None,
        };
        let Some(replacement) = replacement else {
            continue;
        };
        let mut inner = valid.inner().clone();
        replace_test_decoded_at(&mut inner, index, replacement);
        assert_m17_prototype_rejects(inner, "last-byte filter offset reset");
    }

    let width_one =
        build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).expect("M=1 Count program");
    let valid = emit_exact_aggregate(&width_one, EmitLimits::default()).expect("M=1 Count image");
    let instructions = decode(valid.code()).expect("canonical M=1 decode");
    let index = instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareEqualBytes16 {
                    destination: 0,
                    left: 0,
                    right: 1
                }
            )
        })
        .expect("width-one SIMD compare");
    let mut inner = valid.inner().clone();
    replace_test_decoded_at(
        &mut inner,
        index,
        DecodedInstruction::AndBytes16 {
            destination: 0,
            left: 0,
            right: 1,
        },
    );
    reseal_test_image(&mut inner);
    assert!(audit_aggregate(&NativeAggregateImage::new(inner)).is_err());
}

#[test]
fn width_one_audit_rejects_in_cycle_cursor_reset() {
    let program =
        build_exact_aggregate::<Count>(b"x", ValidateLimits::default()).expect("M=1 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=1 Count image");
    let mut inner = valid.inner().clone();
    replace_test_instruction(
        &mut inner,
        |instruction| {
            matches!(
                instruction,
                DecodedInstruction::MoveZero64 {
                    destination: 11,
                    immediate: 256,
                    shift: 0
                }
            )
        },
        0xd280_0005,
    );
    assert_eq!(
        simulate_aggregate(&NativeAggregateImage::new(inner.clone()), &[b'x'; 32]),
        Err(SimError::StepLimit),
        "cursor reset repeats the second vector block indefinitely"
    );
    reseal_test_image(&mut inner);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateTemplate { offset: 64 })
    );
}

#[test]
fn aggregate_template_rejects_coherent_structural_and_metadata_mutations() {
    let program = build_exact_aggregate::<Count>(b"0123456789abcdefg", ValidateLimits::default())
        .expect("M=17 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=17 Count image");

    let mut inner = valid.inner().clone();
    let mut code = inner.code.into_vec();
    code.extend_from_slice(&0xd65f_03c0_u32.to_le_bytes());
    inner.code = code.into_boxed_slice();
    inner.stats.code_bytes = 324;
    inner.layout.rodata_from_code_start = 336;
    inner.layout.total_mapped_bytes = 353;
    let address = crate::decode::canonical_word(DecodedInstruction::Address {
        destination: 8,
        displacement: 332,
    })
    .expect("canonical shifted ADR");
    inner.code[4..8].copy_from_slice(&address.to_le_bytes());
    inner.relocations[0].resolved_word = address;
    reseal_test_image(&mut inner);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateManifest),
        "coherent unreachable tail must fail the exact early envelope"
    );

    let mut inner = valid.inner().clone();
    let mut code = inner.code.into_vec();
    code.truncate(316);
    inner.code = code.into_boxed_slice();
    inner.stats.code_bytes = 316;
    reseal_test_image(&mut inner);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateManifest),
        "omitted final instruction must fail the exact early envelope"
    );

    let mut inner = valid.inner().clone();
    let mut labels = inner.labels.into_vec();
    let extra = *labels.last().expect("canonical labels");
    labels.push(extra);
    inner.labels = labels.into_boxed_slice();
    inner.stats.labels = 14;
    reseal_test_image(&mut inner);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateManifest),
        "extra label must fail the exact early envelope"
    );

    let mut inner = valid.inner().clone();
    let branch = crate::decode::canonical_word(DecodedInstruction::Branch { displacement: -4 })
        .expect("canonical alternate branch");
    inner.code[296..300].copy_from_slice(&branch.to_le_bytes());
    let relocation = inner
        .relocations
        .iter_mut()
        .find(|relocation| relocation.code_offset == 296)
        .expect("canonical final backedge relocation");
    relocation.target = RelocationTarget::CodeOffset(292);
    relocation.resolved_word = branch;
    reseal_test_image(&mut inner);
    assert!(
        audit_aggregate(&NativeAggregateImage::new(inner)).is_err(),
        "coherent alternate relocation must fail"
    );
}

#[test]
fn aggregate_template_rejects_cbnz_retarget_to_inserted_confirmation_reset_label() {
    let literal = b"0123456789abcdefgh";
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("M=18 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=18 Count image");
    let mut inner = valid.inner().clone();
    let branch_index = decode(inner.code())
        .expect("canonical M=18 decode")
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 17,
                    nonzero: true,
                    ..
                }
            )
        })
        .expect("scalar confirmation CBNZ");
    let branch_offset = u32::try_from(branch_index * 4).expect("small code");
    assert_eq!(branch_offset, 264);
    replace_test_decoded_at(
        &mut inner,
        branch_index,
        DecodedInstruction::CompareBranchZero64 {
            register: 17,
            nonzero: true,
            displacement: -116,
        },
    );
    let resolved_word = u32::from_le_bytes(
        inner.code[branch_index * 4..branch_index * 4 + 4]
            .try_into()
            .expect("one instruction"),
    );
    let relocation = inner
        .relocations
        .iter_mut()
        .find(|relocation| relocation.code_offset == branch_offset)
        .expect("scalar confirmation relocation");
    relocation.target = RelocationTarget::CodeOffset(148);
    relocation.resolved_word = resolved_word;

    let mut labels = inner.labels.into_vec();
    let mut inserted = labels[0];
    inserted.offset = 148;
    inserted.kind = LabelKind::Loop;
    labels.push(inserted);
    labels.sort_unstable();
    inner.labels = labels.into_boxed_slice();
    inner.stats.labels = 14;
    assert_eq!(
        simulate_aggregate(&NativeAggregateImage::new(inner.clone()), literal),
        Err(SimError::StepLimit),
        "the taken reset edge reinitializes confirmation forever"
    );
    reseal_test_image(&mut inner);
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateManifest),
        "the exact pre-decode label envelope rejects the inserted reset target"
    );
}

#[test]
fn aggregate_audit_rejects_stale_artifact_identity_after_semantic_checks() {
    let program = build_exact_aggregate::<Count>(b"0123456789abcdefg", ValidateLimits::default())
        .expect("M=17 Count program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("M=17 Count image");
    let mut inner = valid.inner().clone();
    inner.stats.emission_work = inner
        .stats
        .emission_work
        .checked_add(1)
        .expect("bounded accounting mutation");
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::ArtifactIdentityMismatch)
    );
}

#[test]
fn search_audit_rejects_explicit_x18_x30_and_sp_operands() {
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("search program");
    let valid = emit(&program, EmitLimits::default()).expect("search image");
    // The exact RET encoding still has its implicit x30 use. These are all
    // explicit entry operands, including the concrete no-match SP mutation.
    for (word, register) in [
        (0xaa00_03f2_u32, 18_u8),
        (0xaa00_03fe_u32, 30_u8),
        (0x9100_43ff_u32, 31_u8),
    ] {
        let mut image = valid.clone();
        image.code[0..4].copy_from_slice(&word.to_le_bytes());
        reseal_test_image(&mut image);
        assert_eq!(
            audit(&image),
            Err(AuditError::ForbiddenAggregateRegister {
                offset: 0,
                register,
            })
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "one adversarial test keeps the complete aggregate audit mutation matrix visible"
)]
fn aggregate_contract_auditor_rejects_cfg_abi_status_load_and_manifest_tampering() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("aggregate program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("aggregate image");

    for (word, register) in [(0xd280_001e_u32, 30_u8), (0x9100_03ff_u32, 31_u8)] {
        let mut inner = valid.inner().clone();
        inner.code[0..4].copy_from_slice(&word.to_le_bytes());
        let tampered = NativeAggregateImage::new(inner);
        assert_eq!(
            audit_aggregate(&tampered),
            Err(AuditError::ForbiddenAggregateRegister {
                offset: 0,
                register,
            })
        );
    }

    let mut inner = valid.inner().clone();
    let status = decoded_position(inner.code(), |instruction| {
        matches!(
            instruction,
            DecodedInstruction::MoveZero64 {
                destination: 0,
                immediate: 1,
                shift: 0
            }
        )
    });
    inner.code[status..status + 4].copy_from_slice(&0xd280_0040_u32.to_le_bytes());
    let tampered = NativeAggregateImage::new(inner);
    assert_eq!(
        audit_aggregate(&tampered),
        Err(AuditError::InvalidAggregateStatus {
            offset: u32::try_from(status).expect("small code"),
            status: 2,
        })
    );

    let mut inner = valid.inner().clone();
    let store = decoded_position(inner.code(), |instruction| {
        matches!(instruction, DecodedInstruction::Store64 { .. })
    });
    inner.code[store..store + 4].copy_from_slice(&0xaa0d_03ed_u32.to_le_bytes());
    assert!(matches!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateStoreContract
            | AuditError::InvalidAggregateControlFlow { .. })
    ));

    let mut inner = valid.inner().clone();
    inner.code[0..4].copy_from_slice(&0xf900_004d_u32.to_le_bytes());
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateStoreContract)
    );

    let mut inner = valid.inner().clone();
    let load = decoded_position(inner.code(), |instruction| {
        matches!(
            instruction,
            DecodedInstruction::LoadByte {
                destination: 11,
                base: 8,
                offset: 5
            }
        )
    });
    let out_of_literal = 0x3940_0000_u32 | (6 << 10) | (8 << 5) | 11;
    inner.code[load..load + 4].copy_from_slice(&out_of_literal.to_le_bytes());
    assert!(matches!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateLoad { .. }
            | AuditError::InvalidAggregateControlFlow { .. })
    ));

    let mut inner = valid.inner().clone();
    inner
        .aggregate
        .as_mut()
        .expect("aggregate manifest")
        .literal_bytes = 7;
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateManifest)
    );

    let mut inner = valid.inner().clone();
    let progress = decoded_position(inner.code(), |instruction| {
        matches!(
            instruction,
            DecodedInstruction::AddImmediate64 {
                destination: 5,
                source: 5,
                immediate: 16
            }
        )
    });
    inner.code[progress..progress + 4].copy_from_slice(&0x9100_00a5_u32.to_le_bytes());
    assert!(matches!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateControlFlow { .. })
    ));

    let producer_tampers: [(fn(DecodedInstruction) -> bool, u32); 4] = [
        (
            |instruction| {
                matches!(
                    instruction,
                    DecodedInstruction::AddRegister64 {
                        destination: 15,
                        left: 0,
                        right: 5
                    }
                )
            },
            0xaa01_03ef_u32,
        ),
        (
            |instruction| {
                matches!(
                    instruction,
                    DecodedInstruction::MoveRegister64 {
                        destination: 16,
                        source: 8
                    }
                )
            },
            0xaa01_03f0_u32,
        ),
        (
            |instruction| {
                matches!(
                    instruction,
                    DecodedInstruction::MoveZero64 {
                        destination: 17,
                        immediate: 6,
                        shift: 0
                    }
                )
            },
            0xd280_0011_u32,
        ),
        (
            |instruction| {
                matches!(
                    instruction,
                    DecodedInstruction::AddImmediate64 {
                        destination: 10,
                        source: 15,
                        immediate: 5
                    }
                )
            },
            0x9100_142a_u32,
        ),
    ];
    for (predicate, replacement) in producer_tampers {
        let mut inner = valid.inner().clone();
        let producer = decoded_position(inner.code(), predicate);
        inner.code[producer..producer + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(matches!(
            audit_aggregate(&NativeAggregateImage::new(inner)),
            Err(AuditError::InvalidAggregateControlFlow { .. })
        ));
    }

    let mut inner = valid.inner().clone();
    let vector = decoded_position(inner.code(), |instruction| {
        matches!(instruction, DecodedInstruction::DuplicateByte16 { .. })
    });
    let original = u32::from_le_bytes(
        inner.code[vector..vector + 4]
            .try_into()
            .expect("one instruction word"),
    );
    let v8_destination = (original & !0x1f) | 8;
    inner.code[vector..vector + 4].copy_from_slice(&v8_destination.to_le_bytes());
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::ForbiddenAggregateVectorRegister {
            offset: u32::try_from(vector).expect("small code"),
            register: 8,
        })
    );

    let mut inner = valid.inner().clone();
    let early = decoded_position(inner.code(), |instruction| {
        matches!(
            instruction,
            DecodedInstruction::BranchCondition {
                condition: Condition::CarryClear,
                ..
            }
        )
    });
    let vector_loop = decoded_position(inner.code(), |instruction| {
        matches!(
            instruction,
            DecodedInstruction::CompareRegister64 { left: 5, right: 6 }
        )
    });
    let early_u32 = u32::try_from(early).expect("small code");
    let vector_u32 = u32::try_from(vector_loop).expect("small code");
    assert!(inner.labels.iter().any(|label| label.offset == vector_u32));
    let displacement = vector_u32
        .checked_sub(early_u32)
        .expect("vector loop follows early branch");
    let instruction_words = displacement.checked_div(4).expect("aligned branch");
    let retargeted_word = 0x5400_0000_u32 | (instruction_words << 5) | 3;
    inner.code[early..early + 4].copy_from_slice(&retargeted_word.to_le_bytes());
    let relocation = inner
        .relocations
        .iter_mut()
        .find(|relocation| relocation.code_offset == early_u32)
        .expect("conditional relocation");
    relocation.target = RelocationTarget::CodeOffset(vector_u32);
    relocation.resolved_word = retargeted_word;
    assert!(matches!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateControlFlow { offset }) if offset == early_u32
    ));
}

#[test]
fn aggregate_audit_rejects_confirmation_scalar_last_offset() {
    let literal = b"0123456789abcdefg";
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("aggregate program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("aggregate image");
    let mut inner = valid.inner().clone();
    let confirmation_load = decoded_position(inner.code(), |instruction| {
        matches!(
            instruction,
            DecodedInstruction::LoadByte {
                destination: 10,
                base: 15,
                offset: 0
            }
        )
    });
    let malicious_offset = u16::try_from(literal.len() - 1).expect("small literal");
    let malicious_word = 0x3940_0000_u32 | (u32::from(malicious_offset) << 10) | (15 << 5) | 10;
    inner.code[confirmation_load..confirmation_load + 4]
        .copy_from_slice(&malicious_word.to_le_bytes());
    assert_eq!(
        decode_one(
            malicious_word,
            u32::try_from(confirmation_load).expect("small code")
        ),
        Ok(DecodedInstruction::LoadByte {
            destination: 10,
            base: 15,
            offset: malicious_offset,
        })
    );
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateControlFlow {
            offset: u32::try_from(confirmation_load).expect("small code")
        })
    );
}

#[test]
fn aggregate_audit_rejects_nonprogress_scalar_scan_backedge() {
    let program = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("aggregate program");
    let valid = emit_exact_aggregate(&program, EmitLimits::default()).expect("aggregate image");
    let mut inner = valid.inner().clone();
    let instructions = decode(inner.code()).expect("valid aggregate code");
    let branch_index = instructions
        .windows(2)
        .position(|pair| {
            matches!(
                pair,
                [
                    DecodedInstruction::CompareRegister64 { left: 5, right: 7 },
                    DecodedInstruction::BranchCondition {
                        condition: Condition::Higher,
                        ..
                    }
                ]
            )
        })
        .expect("scalar scan guard")
        + 1;
    let branch = branch_index.checked_mul(4).expect("small code");
    let scalar_guard = branch.checked_sub(4).expect("branch follows guard");
    let branch_u32 = u32::try_from(branch).expect("small code");
    let scalar_guard_u32 = u32::try_from(scalar_guard).expect("small code");
    assert!(
        inner
            .labels
            .iter()
            .any(|label| label.offset == scalar_guard_u32)
    );
    let malicious_word = 0x54ff_ffe8_u32;
    inner.code[branch..branch + 4].copy_from_slice(&malicious_word.to_le_bytes());
    let relocation = inner
        .relocations
        .iter_mut()
        .find(|relocation| relocation.code_offset == branch_u32)
        .expect("scalar scan relocation");
    relocation.target = RelocationTarget::CodeOffset(scalar_guard_u32);
    relocation.resolved_word = malicious_word;
    assert_eq!(
        decode_one(malicious_word, branch_u32),
        Ok(DecodedInstruction::BranchCondition {
            condition: Condition::Higher,
            displacement: -4,
        })
    );
    assert_eq!(
        audit_aggregate(&NativeAggregateImage::new(inner)),
        Err(AuditError::InvalidAggregateControlFlow { offset: branch_u32 })
    );
}

#[test]
fn aggregate_audit_binds_reducer_delta_to_manifest() {
    let literal = b"needle";
    let count = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("count aggregate program");
    let spans = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
        .expect("span-sum aggregate program");
    let count_image =
        emit_exact_aggregate(&count, EmitLimits::default()).expect("count aggregate image");
    let span_image =
        emit_exact_aggregate(&spans, EmitLimits::default()).expect("span-sum aggregate image");

    for (valid, output, malicious_delta) in [
        (
            count_image,
            AggregateOutput::Count,
            u16::try_from(literal.len()).expect("small literal"),
        ),
        (span_image, AggregateOutput::SpanSum, 1_u16),
    ] {
        assert_eq!(valid.output(), output);
        let mut inner = valid.inner().clone();
        let reducer = decoded_position(inner.code(), |instruction| {
            matches!(
                instruction,
                DecodedInstruction::AddImmediate64 {
                    destination: 13,
                    source: 13,
                    ..
                }
            )
        });
        let malicious_word = 0x9100_0000_u32 | (u32::from(malicious_delta) << 10) | (13 << 5) | 13;
        inner.code[reducer..reducer + 4].copy_from_slice(&malicious_word.to_le_bytes());
        assert_eq!(
            decode_one(malicious_word, u32::try_from(reducer).expect("small code")),
            Ok(DecodedInstruction::AddImmediate64 {
                destination: 13,
                source: 13,
                immediate: malicious_delta,
            })
        );
        assert_eq!(
            audit_aggregate(&NativeAggregateImage::new(inner)),
            Err(AuditError::InvalidAggregateControlFlow {
                offset: u32::try_from(reducer).expect("small code")
            })
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "independently assembled fixtures keep every newly admitted encoding in one round-trip table"
)]
fn decoder_matches_independently_assembled_instruction_words() {
    let fixtures = [
        (
            0xaa00_03e9,
            DecodedInstruction::MoveRegister64 {
                destination: 9,
                source: 0,
            },
        ),
        (
            0xd346_fd4b,
            DecodedInstruction::LogicalShiftRightImmediate64 {
                destination: 11,
                source: 10,
                shift: 6,
            },
        ),
        (
            0xf86b_790f,
            DecodedInstruction::Load64RegisterScaled {
                destination: 15,
                base: 8,
                index: 11,
            },
        ),
        (
            0xad40_0440,
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 0,
                second_destination: 1,
                base: 2,
                offset: 0,
            },
        ),
        (
            0xad5f_8440,
            DecodedInstruction::LoadVectorPair128 {
                first_destination: 0,
                second_destination: 1,
                base: 2,
                offset: 1008,
            },
        ),
        (
            0x6e21_8c00,
            DecodedInstruction::CompareEqualBytes16 {
                destination: 0,
                left: 0,
                right: 1,
            },
        ),
        (
            0x4e22_1c00,
            DecodedInstruction::AndBytes16 {
                destination: 0,
                left: 0,
                right: 2,
            },
        ),
        (
            0x8a0b_0000,
            DecodedInstruction::AndRegister64 {
                destination: 0,
                left: 0,
                right: 11,
            },
        ),
        (
            0x0f0c_8402,
            DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                destination: 2,
                source: 0,
            },
        ),
        (
            0xdac0_000a,
            DecodedInstruction::ReverseBits64 {
                destination: 10,
                source: 0,
            },
        ),
        (
            0xdac0_114a,
            DecodedInstruction::CountLeadingZeros64 {
                destination: 10,
                source: 10,
            },
        ),
        (
            0x6e31_a800,
            DecodedInstruction::UnsignedMinBytes16 {
                destination: 0,
                source: 0,
            },
        ),
        (
            0x6e20_a402,
            DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                destination: 2,
                left: 0,
                right: 0,
            },
        ),
        (
            0x9e66_004a,
            DecodedInstruction::MoveVectorDoubleTo64 {
                destination: 10,
                source: 2,
            },
        ),
        (
            0x4e31_b820,
            DecodedInstruction::AddAcrossBytes16 {
                destination: 0,
                source: 1,
            },
        ),
        (
            0x10ff_fb68,
            DecodedInstruction::Address {
                destination: 8,
                displacement: -148,
            },
        ),
        (
            0x2518_e120,
            DecodedInstruction::SvePtrueBytesVl16 { destination: 0 },
        ),
        (
            0x0520_3967,
            DecodedInstruction::SveDuplicateByte {
                destination: 7,
                source: 11,
            },
        ),
        (
            0xa400_a146,
            DecodedInstruction::SveLoadBytes {
                destination: 6,
                predicate: 0,
                base: 10,
            },
        ),
        (
            0x2407_a0c2,
            DecodedInstruction::SveCompareEqualBytes {
                destination: 2,
                predicate: 0,
                left: 6,
                right: 7,
            },
        ),
        (
            0x4527_80c2,
            DecodedInstruction::Sve2MatchBytes {
                destination: 2,
                predicate: 0,
                left: 6,
                right: 7,
            },
        ),
        (
            0x2502_4021,
            DecodedInstruction::SveAndPredicateBytes {
                destination: 1,
                predicate: 0,
                left: 1,
                right: 2,
            },
        ),
        (
            0x2542_4021,
            DecodedInstruction::SveAndPredicateBytesSetFlags {
                destination: 1,
                predicate: 0,
                left: 1,
                right: 2,
            },
        ),
        (
            0x2503_4031,
            DecodedInstruction::SveBitClearPredicateBytes {
                destination: 1,
                predicate: 0,
                left: 1,
                right: 3,
            },
        ),
        (
            0x2550_c020,
            DecodedInstruction::SveTestPredicateBytes {
                predicate: 0,
                tested: 1,
            },
        ),
        (
            0x2590_4023,
            DecodedInstruction::SveBreakBeforeBytes {
                destination: 3,
                predicate: 0,
                source: 1,
            },
        ),
        (
            0x2510_4023,
            DecodedInstruction::SveBreakAfterBytes {
                destination: 3,
                predicate: 0,
                source: 1,
            },
        ),
        (
            0x2520_806a,
            DecodedInstruction::SveCountPredicateBytes {
                destination: 10,
                predicate: 0,
                source: 3,
            },
        ),
    ];
    for (word, expected) in fixtures {
        let decoded = decode_one(word, 0).expect("known clang word");
        assert_eq!(decoded, expected);
        assert_eq!(crate::decode::canonical_word(decoded), Some(word));
    }
    assert_eq!(
        crate::decode::canonical_word(DecodedInstruction::LoadVectorPair128 {
            first_destination: 1,
            second_destination: 1,
            base: 2,
            offset: 0,
        }),
        None,
        "pair loads with aliased destinations are noncanonical"
    );
}

#[test]
fn compatibility_search_v1_through_v6_aot_identities_are_stable() {
    let program = build_exact_literal::<Span>(
        b"0123456789abcdef",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("compatibility program");
    for (backend, expected_identity, expected_code, expected_aot) in [
        (
            BackendVersion::SEARCH_V1,
            "cc46a2f52f3ecabe805f1be23496f7d063c4036f0829c86a38ef5399ba7a4468",
            320,
            984,
        ),
        (
            BackendVersion::SEARCH_V2,
            "0eb6ab47d210d09c9c2684d09da4e3cb7eb64ea10a4c99f5cabfac9d82d9f473",
            276,
            848,
        ),
        (
            BackendVersion::SEARCH_V3,
            "9aed55e5f2a604ecdf13d83c31d7e62992a296bac23bf36ef92cd51884e94072",
            356,
            1_130,
        ),
        (
            BackendVersion::SEARCH_V4,
            "6b2c18cdd65e7c1caeccd154dbee834392e214db9123df34f661e00f1bb79835",
            448,
            1_366,
        ),
        (
            BackendVersion::SEARCH_V5,
            "195fd258bf0ffb39777cca291d5bac97cb1ff18fb7c56d5b3ade9126cba19ad4",
            472,
            1_392,
        ),
        (
            BackendVersion::SEARCH_V6,
            "6126b37306b39830ea677d31c829ff55f2720386253329d665946072bebf4f1d",
            472,
            1_268,
        ),
    ] {
        let image = emit_search_version_for_test(&program, EmitLimits::default(), backend)
            .expect("compatibility image");
        let aot = image
            .to_aot(AotLimits::default())
            .expect("compatibility AOT");
        assert_eq!(image.artifact_identity().to_string(), expected_identity);
        assert_eq!(image.code().len(), expected_code);
        assert_eq!(aot.as_bytes().len(), expected_aot);
        assert_eq!(aot.identity(), image.artifact_identity());
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "every admitted decoded form is deliberately enumerated in one coverage table"
)]
fn written_gpr_policy_covers_every_admitted_instruction_form() {
    let writers = [
        DecodedInstruction::MoveRegister64 {
            destination: 17,
            source: 1,
        },
        DecodedInstruction::MoveZero64 {
            destination: 17,
            immediate: 1,
            shift: 0,
        },
        DecodedInstruction::MoveKeep64 {
            destination: 17,
            immediate: 1,
            shift: 16,
        },
        DecodedInstruction::AddRegister64 {
            destination: 17,
            left: 1,
            right: 2,
        },
        DecodedInstruction::AddImmediate64 {
            destination: 17,
            source: 1,
            immediate: 1,
        },
        DecodedInstruction::SubtractRegister64 {
            destination: 17,
            left: 1,
            right: 2,
        },
        DecodedInstruction::SubtractImmediate64 {
            destination: 17,
            source: 1,
            immediate: 1,
        },
        DecodedInstruction::AndRegister64 {
            destination: 17,
            left: 1,
            right: 2,
        },
        DecodedInstruction::AndLowBits64 {
            destination: 17,
            source: 1,
            bits: 8,
        },
        DecodedInstruction::LogicalShiftRightImmediate64 {
            destination: 17,
            source: 1,
            shift: 1,
        },
        DecodedInstruction::LogicalShiftLeftImmediate64 {
            destination: 17,
            source: 1,
            shift: 1,
        },
        DecodedInstruction::LoadByte {
            destination: 17,
            base: 1,
            offset: 0,
        },
        DecodedInstruction::LoadByteRegister {
            destination: 17,
            base: 1,
            index: 2,
        },
        DecodedInstruction::Load64RegisterScaled {
            destination: 17,
            base: 1,
            index: 2,
        },
        DecodedInstruction::MoveVectorByteTo32 {
            destination: 17,
            source: 1,
        },
        DecodedInstruction::MoveVectorDoubleTo64 {
            destination: 17,
            source: 1,
        },
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination: 17,
            source: 1,
            shift: 2,
        },
        DecodedInstruction::ReverseBits64 {
            destination: 17,
            source: 1,
        },
        DecodedInstruction::CountLeadingZeros64 {
            destination: 17,
            source: 1,
        },
        DecodedInstruction::Address {
            destination: 17,
            displacement: 0,
        },
    ];
    assert!(
        writers
            .into_iter()
            .all(|instruction| instruction.written_gpr() == Some(17))
    );

    let non_writers = [
        DecodedInstruction::CompareRegister64 { left: 1, right: 2 },
        DecodedInstruction::CompareRegister32 { left: 1, right: 2 },
        DecodedInstruction::CompareImmediate64 {
            register: 1,
            immediate: 1,
        },
        DecodedInstruction::CompareImmediate32 {
            register: 1,
            immediate: 1,
        },
        DecodedInstruction::Store64 {
            source: 1,
            base: 2,
            offset: 0,
        },
        DecodedInstruction::LoadVector128 {
            destination: 0,
            base: 1,
            offset: 0,
        },
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 0,
            second_destination: 1,
            base: 2,
            offset: 0,
        },
        DecodedInstruction::DuplicateByte16 {
            destination: 0,
            source: 1,
        },
        DecodedInstruction::CompareEqualBytes16 {
            destination: 0,
            left: 1,
            right: 2,
        },
        DecodedInstruction::AndBytes16 {
            destination: 0,
            left: 1,
            right: 2,
        },
        DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
            destination: 0,
            source: 1,
        },
        DecodedInstruction::UnsignedMinBytes16 {
            destination: 0,
            source: 1,
        },
        DecodedInstruction::UnsignedMaxBytes16 {
            destination: 0,
            source: 1,
        },
        DecodedInstruction::UnsignedMaxPairwiseBytes16 {
            destination: 0,
            left: 1,
            right: 2,
        },
        DecodedInstruction::AddAcrossBytes16 {
            destination: 0,
            source: 1,
        },
        DecodedInstruction::Branch { displacement: 0 },
        DecodedInstruction::BranchCondition {
            condition: Condition::Equal,
            displacement: 0,
        },
        DecodedInstruction::CompareBranchZero64 {
            register: 1,
            nonzero: false,
            displacement: 0,
        },
        DecodedInstruction::Return,
    ];
    assert!(
        non_writers
            .into_iter()
            .all(|instruction| instruction.written_gpr().is_none())
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "each decoded GPR field is instantiated separately at the common audit boundary"
)]
fn every_explicit_gpr_role(register: u8) -> Vec<DecodedInstruction> {
    vec![
        DecodedInstruction::MoveRegister64 {
            destination: register,
            source: 1,
        },
        DecodedInstruction::MoveRegister64 {
            destination: 1,
            source: register,
        },
        DecodedInstruction::MoveZero64 {
            destination: register,
            immediate: 0,
            shift: 0,
        },
        DecodedInstruction::MoveKeep64 {
            destination: register,
            immediate: 0,
            shift: 16,
        },
        DecodedInstruction::CompareImmediate64 {
            register,
            immediate: 0,
        },
        DecodedInstruction::CompareImmediate32 {
            register,
            immediate: 0,
        },
        DecodedInstruction::MoveVectorByteTo32 {
            destination: register,
            source: 0,
        },
        DecodedInstruction::MoveVectorDoubleTo64 {
            destination: register,
            source: 0,
        },
        DecodedInstruction::Address {
            destination: register,
            displacement: 0,
        },
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: false,
            displacement: 0,
        },
        DecodedInstruction::CompareRegister64 {
            left: register,
            right: 1,
        },
        DecodedInstruction::CompareRegister64 {
            left: 1,
            right: register,
        },
        DecodedInstruction::CompareRegister32 {
            left: register,
            right: 1,
        },
        DecodedInstruction::CompareRegister32 {
            left: 1,
            right: register,
        },
        DecodedInstruction::AddRegister64 {
            destination: register,
            left: 1,
            right: 2,
        },
        DecodedInstruction::AddRegister64 {
            destination: 1,
            left: register,
            right: 2,
        },
        DecodedInstruction::AddRegister64 {
            destination: 1,
            left: 2,
            right: register,
        },
        DecodedInstruction::SubtractRegister64 {
            destination: register,
            left: 1,
            right: 2,
        },
        DecodedInstruction::SubtractRegister64 {
            destination: 1,
            left: register,
            right: 2,
        },
        DecodedInstruction::SubtractRegister64 {
            destination: 1,
            left: 2,
            right: register,
        },
        DecodedInstruction::AndRegister64 {
            destination: register,
            left: 1,
            right: 2,
        },
        DecodedInstruction::AndRegister64 {
            destination: 1,
            left: register,
            right: 2,
        },
        DecodedInstruction::AndRegister64 {
            destination: 1,
            left: 2,
            right: register,
        },
        DecodedInstruction::AddImmediate64 {
            destination: register,
            source: 1,
            immediate: 0,
        },
        DecodedInstruction::AddImmediate64 {
            destination: 1,
            source: register,
            immediate: 0,
        },
        DecodedInstruction::SubtractImmediate64 {
            destination: register,
            source: 1,
            immediate: 0,
        },
        DecodedInstruction::SubtractImmediate64 {
            destination: 1,
            source: register,
            immediate: 0,
        },
        DecodedInstruction::AndLowBits64 {
            destination: register,
            source: 1,
            bits: 8,
        },
        DecodedInstruction::AndLowBits64 {
            destination: 1,
            source: register,
            bits: 8,
        },
        DecodedInstruction::LogicalShiftRightImmediate64 {
            destination: register,
            source: 1,
            shift: 1,
        },
        DecodedInstruction::LogicalShiftRightImmediate64 {
            destination: 1,
            source: register,
            shift: 1,
        },
        DecodedInstruction::LogicalShiftLeftImmediate64 {
            destination: register,
            source: 1,
            shift: 1,
        },
        DecodedInstruction::LogicalShiftLeftImmediate64 {
            destination: 1,
            source: register,
            shift: 1,
        },
        DecodedInstruction::LoadByte {
            destination: register,
            base: 1,
            offset: 0,
        },
        DecodedInstruction::LoadByte {
            destination: 1,
            base: register,
            offset: 0,
        },
        DecodedInstruction::LoadVector128 {
            destination: 0,
            base: register,
            offset: 0,
        },
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 0,
            second_destination: 1,
            base: register,
            offset: 0,
        },
        DecodedInstruction::LoadByteRegister {
            destination: register,
            base: 1,
            index: 2,
        },
        DecodedInstruction::LoadByteRegister {
            destination: 1,
            base: register,
            index: 2,
        },
        DecodedInstruction::LoadByteRegister {
            destination: 1,
            base: 2,
            index: register,
        },
        DecodedInstruction::Load64RegisterScaled {
            destination: register,
            base: 1,
            index: 2,
        },
        DecodedInstruction::Load64RegisterScaled {
            destination: 1,
            base: register,
            index: 2,
        },
        DecodedInstruction::Load64RegisterScaled {
            destination: 1,
            base: 2,
            index: register,
        },
        DecodedInstruction::Store64 {
            source: register,
            base: 1,
            offset: 0,
        },
        DecodedInstruction::Store64 {
            source: 1,
            base: register,
            offset: 0,
        },
        DecodedInstruction::DuplicateByte16 {
            destination: 0,
            source: register,
        },
        DecodedInstruction::SveDuplicateByte {
            destination: 0,
            source: register,
        },
        DecodedInstruction::SveLoadBytes {
            destination: 0,
            predicate: 0,
            base: register,
        },
        DecodedInstruction::SveCountPredicateBytes {
            destination: register,
            predicate: 0,
            source: 0,
        },
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination: register,
            source: 1,
            shift: 2,
        },
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination: 1,
            source: register,
            shift: 2,
        },
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination: 1,
            source: 2,
            shift: register,
        },
        DecodedInstruction::ReverseBits64 {
            destination: register,
            source: 1,
        },
        DecodedInstruction::ReverseBits64 {
            destination: 1,
            source: register,
        },
        DecodedInstruction::CountLeadingZeros64 {
            destination: register,
            source: 1,
        },
        DecodedInstruction::CountLeadingZeros64 {
            destination: 1,
            source: register,
        },
    ]
}

#[test]
fn explicit_gpr_visitor_covers_x18_x30_and_register_31_in_every_role() {
    for forbidden in [18_u8, 30, 31] {
        for instruction in every_explicit_gpr_role(forbidden) {
            assert_eq!(
                crate::audit::first_forbidden_explicit_gpr(instruction),
                Some(forbidden),
                "missed explicit register {forbidden} in {instruction:?}"
            );
        }
    }
    for instruction in every_explicit_gpr_role(17) {
        assert_eq!(
            crate::audit::first_forbidden_explicit_gpr(instruction),
            None
        );
    }
    assert_eq!(
        crate::audit::first_forbidden_explicit_gpr(DecodedInstruction::Return),
        None,
        "RET's implicit x30 is permitted"
    );
}

#[test]
fn explicit_gpr_visitor_covers_removed_selected_end_x4_in_every_role() {
    for instruction in every_explicit_gpr_role(4) {
        assert!(
            instruction.uses_gpr(4),
            "missed explicit x4 role in {instruction:?}"
        );
    }
    for instruction in every_explicit_gpr_role(17) {
        assert!(
            !instruction.uses_gpr(4),
            "reported x4 in unrelated {instruction:?}"
        );
    }
    assert!(!DecodedInstruction::Return.uses_gpr(4));
}

fn with_limit(mut limits: EmitLimits, resource: ResourceKind, value: u64) -> EmitLimits {
    match resource {
        ResourceKind::CodeBytes => limits.max_code_bytes = value,
        ResourceKind::DataBytes => limits.max_data_bytes = value,
        ResourceKind::Relocations => limits.max_relocations = value,
        ResourceKind::Labels => limits.max_labels = value,
        ResourceKind::EmissionWork => limits.max_emission_work = value,
        ResourceKind::ScratchBytes => limits.max_scratch_bytes = value,
        ResourceKind::AotBytes => unreachable!("AOT has a separate limit type"),
    }
    limits
}

fn decoded_position(code: &[u8], predicate: impl Fn(DecodedInstruction) -> bool) -> usize {
    decode(code)
        .expect("valid test image")
        .into_iter()
        .position(predicate)
        .expect("requested instruction exists")
        .checked_mul(4)
        .expect("small code")
}

fn anchor_options() -> [AnchorFlags; 4] {
    [
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
    ]
}

fn all_sequences(alphabet: &[u8], maximum: usize) -> Vec<Vec<u8>> {
    let mut output = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..maximum {
        let mut next = Vec::new();
        for prefix in &frontier {
            for &byte in alphabet {
                let mut value = prefix.clone();
                value.push(byte);
                output.push(value.clone());
                next.push(value);
            }
        }
        frontier = next;
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SimResult {
    status: u64,
    slot: NativeResult,
    steps: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SimError {
    InvalidProgramCounter,
    InvalidMemoryRead,
    InvalidMemoryWrite,
    StepLimit,
    Arithmetic,
}

fn span_output(result: SimResult) -> Option<(usize, usize)> {
    (result.status == 1).then_some((result.slot.start, result.slot.end))
}

fn end_output(result: SimResult) -> Option<usize> {
    (result.status == 1).then_some(result.slot.end)
}

fn aggregate_output(result: SimResult) -> Result<u64, u64> {
    if result.status == 0 {
        Ok(u64::try_from(result.slot.start).expect("test result fits u64"))
    } else {
        Err(result.status)
    }
}

fn assert_aggregate_pair(literal: &[u8], haystack: &[u8]) {
    let count =
        build_exact_aggregate::<Count>(literal, ValidateLimits::default()).expect("count program");
    let spans =
        build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default()).expect("span program");
    let expected_count = *count
        .execute(haystack, AggregateExecutionLimits::unlimited())
        .expect("count oracle")
        .output();
    let expected_spans = *spans
        .execute(haystack, AggregateExecutionLimits::unlimited())
        .expect("span oracle")
        .output();
    let count_image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
    let span_image = emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image");
    assert_eq!(
        aggregate_output(simulate_aggregate(&count_image, haystack).expect("count simulation")),
        Ok(expected_count),
        "count literal={literal:?} haystack={haystack:?}"
    );
    assert_eq!(
        aggregate_output(simulate_aggregate(&span_image, haystack).expect("span simulation")),
        Ok(expected_spans),
        "span literal={literal:?} haystack={haystack:?}"
    );
}

fn simulate(
    image: &NativeImage,
    haystack: &[u8],
    window_start: usize,
    window_end: usize,
) -> Result<SimResult, SimError> {
    let instructions = decode(image.code()).map_err(|_| SimError::InvalidProgramCounter)?;
    let mut machine = SimMachine {
        registers: [0; 32],
        vectors: [[0; 16]; 32],
        predicates: [0; 16],
        zero: false,
        carry: false,
        pc: 0,
        slot: NativeResult::default(),
        steps: 0,
        instructions: &instructions,
        image,
        haystack,
    };
    machine.registers[0] = HAYSTACK_BASE;
    machine.registers[1] = u64::try_from(haystack.len()).map_err(|_| SimError::Arithmetic)?;
    machine.registers[2] = u64::try_from(window_start).map_err(|_| SimError::Arithmetic)?;
    machine.registers[3] = u64::try_from(window_end).map_err(|_| SimError::Arithmetic)?;
    machine.registers[4] = RESULT_BASE;
    machine.run()
}

fn simulate_aggregate(
    image: &NativeAggregateImage,
    haystack: &[u8],
) -> Result<SimResult, SimError> {
    let image = image.inner();
    let instructions = decode(image.code()).map_err(|_| SimError::InvalidProgramCounter)?;
    let mut machine = SimMachine {
        registers: [0; 32],
        vectors: [[0; 16]; 32],
        predicates: [0; 16],
        zero: false,
        carry: false,
        pc: 0,
        slot: NativeResult::default(),
        steps: 0,
        instructions: &instructions,
        image,
        haystack,
    };
    machine.registers[0] = HAYSTACK_BASE;
    machine.registers[1] = u64::try_from(haystack.len()).map_err(|_| SimError::Arithmetic)?;
    machine.registers[2] = RESULT_BASE;
    machine.run()
}

struct SimMachine<'a> {
    registers: [u64; 32],
    vectors: [[u8; 16]; 32],
    predicates: [u16; 16],
    zero: bool,
    carry: bool,
    pc: u32,
    slot: NativeResult,
    steps: u64,
    instructions: &'a [DecodedInstruction],
    image: &'a NativeImage,
    haystack: &'a [u8],
}

impl SimMachine<'_> {
    #[allow(
        clippy::too_many_lines,
        reason = "the test-only ISA model keeps all decoded instruction semantics in one auditable dispatch"
    )]
    fn run(&mut self) -> Result<SimResult, SimError> {
        let haystack_work = u64::try_from(self.haystack.len())
            .map_err(|_| SimError::Arithmetic)?
            .checked_add(1)
            .ok_or(SimError::Arithmetic)?;
        let code_work = u64::try_from(self.instructions.len())
            .map_err(|_| SimError::Arithmetic)?
            .checked_add(1)
            .ok_or(SimError::Arithmetic)?;
        let step_limit = haystack_work
            .checked_mul(code_work)
            .and_then(|work| work.checked_mul(16))
            .ok_or(SimError::Arithmetic)?;
        loop {
            if self.steps == step_limit {
                return Err(SimError::StepLimit);
            }
            self.steps += 1;
            let index = usize::try_from(self.pc / 4).map_err(|_| SimError::Arithmetic)?;
            let instruction = *self
                .instructions
                .get(index)
                .ok_or(SimError::InvalidProgramCounter)?;
            let next = self.pc.checked_add(4).ok_or(SimError::Arithmetic)?;
            match instruction {
                DecodedInstruction::MoveRegister64 {
                    destination,
                    source,
                } => self.set(destination, self.get(source)),
                DecodedInstruction::MoveZero64 {
                    destination,
                    immediate,
                    shift,
                } => self.set(destination, u64::from(immediate) << shift),
                DecodedInstruction::MoveKeep64 {
                    destination,
                    immediate,
                    shift,
                } => {
                    let mask = !(0xffff_u64 << shift);
                    self.set(
                        destination,
                        (self.get(destination) & mask) | (u64::from(immediate) << shift),
                    );
                }
                DecodedInstruction::CompareRegister64 { left, right } => {
                    self.compare(self.get(left), self.get(right));
                }
                DecodedInstruction::CompareRegister32 { left, right } => {
                    self.compare(
                        self.get(left) & u64::from(u32::MAX),
                        self.get(right) & u64::from(u32::MAX),
                    );
                }
                DecodedInstruction::CompareImmediate64 {
                    register,
                    immediate,
                } => self.compare(self.get(register), u64::from(immediate)),
                DecodedInstruction::CompareImmediate32 {
                    register,
                    immediate,
                } => self.compare(
                    self.get(register) & u64::from(u32::MAX),
                    u64::from(immediate),
                ),
                DecodedInstruction::AddRegister64 {
                    destination,
                    left,
                    right,
                } => self.set(destination, self.get(left).wrapping_add(self.get(right))),
                DecodedInstruction::AddImmediate64 {
                    destination,
                    source,
                    immediate,
                } => self.set(
                    destination,
                    self.get(source).wrapping_add(u64::from(immediate)),
                ),
                DecodedInstruction::SubtractRegister64 {
                    destination,
                    left,
                    right,
                } => self.set(destination, self.get(left).wrapping_sub(self.get(right))),
                DecodedInstruction::SubtractImmediate64 {
                    destination,
                    source,
                    immediate,
                } => self.set(
                    destination,
                    self.get(source).wrapping_sub(u64::from(immediate)),
                ),
                DecodedInstruction::AndRegister64 {
                    destination,
                    left,
                    right,
                } => self.set(destination, self.get(left) & self.get(right)),
                DecodedInstruction::AndLowBits64 {
                    destination,
                    source,
                    bits,
                } => {
                    let mask = (1_u64 << bits) - 1;
                    self.set(destination, self.get(source) & mask);
                }
                DecodedInstruction::LogicalShiftRightImmediate64 {
                    destination,
                    source,
                    shift,
                } => self.set(destination, self.get(source) >> shift),
                DecodedInstruction::LogicalShiftLeftImmediate64 {
                    destination,
                    source,
                    shift,
                } => self.set(destination, self.get(source) << shift),
                DecodedInstruction::LoadByte {
                    destination,
                    base,
                    offset,
                } => {
                    let address = self.get(base).wrapping_add(u64::from(offset));
                    let value = self.load(address, 1)?[0];
                    self.set(destination, u64::from(value));
                }
                DecodedInstruction::LoadByteRegister {
                    destination,
                    base,
                    index,
                } => {
                    let address = self.get(base).wrapping_add(self.get(index));
                    let value = self.load(address, 1)?[0];
                    self.set(destination, u64::from(value));
                }
                DecodedInstruction::Load64RegisterScaled {
                    destination,
                    base,
                    index,
                } => {
                    let address = self.get(base).wrapping_add(self.get(index).wrapping_mul(8));
                    let bytes = self.load(address, 8)?;
                    self.set(
                        destination,
                        u64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]),
                    );
                }
                DecodedInstruction::Store64 {
                    source,
                    base,
                    offset,
                } => {
                    let address = self.get(base).wrapping_add(u64::from(offset));
                    self.store(address, self.get(source))?;
                }
                DecodedInstruction::LoadVector128 {
                    destination,
                    base,
                    offset,
                } => {
                    let address = self.get(base).wrapping_add(u64::from(offset));
                    let bytes = self.load(address, 16)?;
                    let mut value = [0_u8; 16];
                    value.copy_from_slice(bytes);
                    self.vectors[usize::from(destination)] = value;
                }
                DecodedInstruction::LoadVectorPair128 {
                    first_destination,
                    second_destination,
                    base,
                    offset,
                } => {
                    let address = self.get(base).wrapping_add(u64::from(offset));
                    let bytes = self.load(address, 32)?;
                    let mut first = [0_u8; 16];
                    let mut second = [0_u8; 16];
                    first.copy_from_slice(&bytes[..16]);
                    second.copy_from_slice(&bytes[16..]);
                    self.vectors[usize::from(first_destination)] = first;
                    self.vectors[usize::from(second_destination)] = second;
                }
                DecodedInstruction::DuplicateByte16 {
                    destination,
                    source,
                }
                | DecodedInstruction::SveDuplicateByte {
                    destination,
                    source,
                } => {
                    let byte = u8::try_from(self.get(source) & 0xff).expect("masked byte");
                    self.vectors[usize::from(destination)] = [byte; 16];
                }
                DecodedInstruction::CompareEqualBytes16 {
                    destination,
                    left,
                    right,
                } => {
                    let mut result = [0_u8; 16];
                    for (index, value) in result.iter_mut().enumerate() {
                        *value = if self.vectors[usize::from(left)][index]
                            == self.vectors[usize::from(right)][index]
                        {
                            0xff
                        } else {
                            0
                        };
                    }
                    self.vectors[usize::from(destination)] = result;
                }
                DecodedInstruction::AndBytes16 {
                    destination,
                    left,
                    right,
                } => {
                    let mut result = [0_u8; 16];
                    for (index, value) in result.iter_mut().enumerate() {
                        *value = self.vectors[usize::from(left)][index]
                            & self.vectors[usize::from(right)][index];
                    }
                    self.vectors[usize::from(destination)] = result;
                }
                DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                    destination,
                    source,
                } => {
                    let source = self.vectors[usize::from(source)];
                    let mut result = [0_u8; 16];
                    for index in 0..8 {
                        let halfword =
                            u16::from_le_bytes([source[index * 2], source[index * 2 + 1]]);
                        result[index] =
                            u8::try_from((halfword >> 4) & 0xff).expect("masked narrow byte");
                    }
                    self.vectors[usize::from(destination)] = result;
                }
                DecodedInstruction::UnsignedMinBytes16 {
                    destination,
                    source,
                } => {
                    let value = *self.vectors[usize::from(source)]
                        .iter()
                        .min()
                        .expect("vector is nonempty");
                    self.vectors[usize::from(destination)][0] = value;
                }
                DecodedInstruction::UnsignedMaxBytes16 {
                    destination,
                    source,
                } => {
                    let value = *self.vectors[usize::from(source)]
                        .iter()
                        .max()
                        .expect("vector is nonempty");
                    self.vectors[usize::from(destination)][0] = value;
                }
                DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                    destination,
                    left,
                    right,
                } => {
                    let left = self.vectors[usize::from(left)];
                    let right = self.vectors[usize::from(right)];
                    let mut result = [0_u8; 16];
                    for index in 0..8 {
                        result[index] = left[index * 2].max(left[index * 2 + 1]);
                        result[index + 8] = right[index * 2].max(right[index * 2 + 1]);
                    }
                    self.vectors[usize::from(destination)] = result;
                }
                DecodedInstruction::AddAcrossBytes16 {
                    destination,
                    source,
                } => {
                    let value = self.vectors[usize::from(source)]
                        .iter()
                        .copied()
                        .fold(0_u8, u8::wrapping_add);
                    self.vectors[usize::from(destination)][0] = value;
                }
                DecodedInstruction::MoveVectorByteTo32 {
                    destination,
                    source,
                } => self.set(destination, u64::from(self.vectors[usize::from(source)][0])),
                DecodedInstruction::MoveVectorDoubleTo64 {
                    destination,
                    source,
                } => self.set(
                    destination,
                    u64::from_le_bytes(
                        self.vectors[usize::from(source)][..8]
                            .try_into()
                            .expect("fixed vector prefix"),
                    ),
                ),
                DecodedInstruction::SvePtrueBytesVl16 { destination } => {
                    self.predicates[usize::from(destination)] = u16::MAX;
                }
                DecodedInstruction::SveLoadBytes {
                    destination,
                    predicate,
                    base,
                } => {
                    let active = self.predicates[usize::from(predicate)];
                    let address = self.get(base);
                    let mut result = [0_u8; 16];
                    for (lane, value) in result.iter_mut().enumerate() {
                        if active & (1_u16 << lane) != 0 {
                            *value = self.load(
                                address
                                    .checked_add(
                                        u64::try_from(lane).map_err(|_| SimError::Arithmetic)?,
                                    )
                                    .ok_or(SimError::Arithmetic)?,
                                1,
                            )?[0];
                        }
                    }
                    self.vectors[usize::from(destination)] = result;
                }
                DecodedInstruction::SveCompareEqualBytes {
                    destination,
                    predicate,
                    left,
                    right,
                } => {
                    let active = self.predicates[usize::from(predicate)];
                    let mut result = 0_u16;
                    for lane in 0..16 {
                        if active & (1_u16 << lane) != 0
                            && self.vectors[usize::from(left)][lane]
                                == self.vectors[usize::from(right)][lane]
                        {
                            result |= 1_u16 << lane;
                        }
                    }
                    self.predicates[usize::from(destination)] = result;
                }
                DecodedInstruction::Sve2MatchBytes {
                    destination,
                    predicate,
                    left,
                    right,
                } => {
                    let active = self.predicates[usize::from(predicate)];
                    let right = self.vectors[usize::from(right)];
                    let mut result = 0_u16;
                    for lane in 0..16 {
                        if active & (1_u16 << lane) != 0
                            && right.contains(&self.vectors[usize::from(left)][lane])
                        {
                            result |= 1_u16 << lane;
                        }
                    }
                    self.predicates[usize::from(destination)] = result;
                }
                DecodedInstruction::SveAndPredicateBytes {
                    destination,
                    predicate,
                    left,
                    right,
                } => {
                    self.predicates[usize::from(destination)] = self.predicates
                        [usize::from(predicate)]
                        & self.predicates[usize::from(left)]
                        & self.predicates[usize::from(right)];
                }
                DecodedInstruction::SveAndPredicateBytesSetFlags {
                    destination,
                    predicate,
                    left,
                    right,
                } => {
                    let result = self.predicates[usize::from(predicate)]
                        & self.predicates[usize::from(left)]
                        & self.predicates[usize::from(right)];
                    self.predicates[usize::from(destination)] = result;
                    self.zero = result == 0;
                }
                DecodedInstruction::SveBitClearPredicateBytesSetFlags {
                    destination,
                    predicate,
                    left,
                    right,
                } => {
                    let result = self.predicates[usize::from(predicate)]
                        & self.predicates[usize::from(left)]
                        & !self.predicates[usize::from(right)];
                    self.predicates[usize::from(destination)] = result;
                    self.zero = result == 0;
                }
                DecodedInstruction::SveBitClearPredicateBytes {
                    destination,
                    predicate,
                    left,
                    right,
                } => {
                    self.predicates[usize::from(destination)] = self.predicates
                        [usize::from(predicate)]
                        & self.predicates[usize::from(left)]
                        & !self.predicates[usize::from(right)];
                }
                DecodedInstruction::SveTestPredicateBytes { predicate, tested } => {
                    self.zero = self.predicates[usize::from(predicate)]
                        & self.predicates[usize::from(tested)]
                        == 0;
                }
                DecodedInstruction::SveBreakBeforeBytes {
                    destination,
                    predicate,
                    source,
                } => {
                    let active = self.predicates[usize::from(predicate)];
                    let matches = active & self.predicates[usize::from(source)];
                    let before = if matches == 0 {
                        u16::MAX
                    } else {
                        let first = matches.trailing_zeros();
                        1_u16.checked_shl(first).unwrap_or(0).wrapping_sub(1)
                    };
                    self.predicates[usize::from(destination)] = active & before;
                }
                DecodedInstruction::SveBreakAfterBytes {
                    destination,
                    predicate,
                    source,
                } => {
                    let active = self.predicates[usize::from(predicate)];
                    let matches = active & self.predicates[usize::from(source)];
                    let through = if matches == 0 {
                        u16::MAX
                    } else {
                        let first_after = matches.trailing_zeros() + 1;
                        1_u16.checked_shl(first_after).unwrap_or(0).wrapping_sub(1)
                    };
                    self.predicates[usize::from(destination)] = active & through;
                }
                DecodedInstruction::SveCountPredicateBytes {
                    destination,
                    predicate,
                    source,
                } => {
                    let count = (self.predicates[usize::from(predicate)]
                        & self.predicates[usize::from(source)])
                    .count_ones();
                    self.set(destination, u64::from(count));
                }
                DecodedInstruction::LogicalShiftRightVariable64 {
                    destination,
                    source,
                    shift,
                } => {
                    let amount = u32::try_from(self.get(shift) & 63).expect("masked shift");
                    self.set(destination, self.get(source) >> amount);
                }
                DecodedInstruction::ReverseBits64 {
                    destination,
                    source,
                } => self.set(destination, self.get(source).reverse_bits()),
                DecodedInstruction::CountLeadingZeros64 {
                    destination,
                    source,
                } => self.set(destination, u64::from(self.get(source).leading_zeros())),
                DecodedInstruction::Address {
                    destination,
                    displacement,
                } => {
                    let address = add_signed(CODE_BASE + u64::from(self.pc), displacement)?;
                    self.set(destination, address);
                }
                DecodedInstruction::Branch { displacement } => {
                    self.pc = add_pc(self.pc, displacement)?;
                    continue;
                }
                DecodedInstruction::BranchCondition {
                    condition,
                    displacement,
                } => {
                    if self.condition(condition) {
                        self.pc = add_pc(self.pc, displacement)?;
                        continue;
                    }
                }
                DecodedInstruction::CompareBranchZero64 {
                    register,
                    nonzero,
                    displacement,
                } => {
                    if (self.get(register) != 0) == nonzero {
                        self.pc = add_pc(self.pc, displacement)?;
                        continue;
                    }
                }
                DecodedInstruction::Return => {
                    return Ok(SimResult {
                        status: self.registers[0],
                        slot: self.slot,
                        steps: self.steps,
                    });
                }
            }
            self.pc = next;
        }
    }

    fn get(&self, register: u8) -> u64 {
        self.registers[usize::from(register)]
    }

    fn set(&mut self, register: u8, value: u64) {
        if register != 31 {
            self.registers[usize::from(register)] = value;
        }
    }

    fn compare(&mut self, left: u64, right: u64) {
        self.zero = left == right;
        self.carry = left >= right;
    }

    const fn condition(&self, condition: Condition) -> bool {
        match condition {
            Condition::Equal => self.zero,
            Condition::NotEqual => !self.zero,
            Condition::CarrySet => self.carry,
            Condition::CarryClear => !self.carry,
            Condition::Higher => self.carry && !self.zero,
            Condition::LowerOrSame => !self.carry || self.zero,
            Condition::Always => true,
        }
    }

    fn load(&self, address: u64, length: usize) -> Result<&[u8], SimError> {
        if let Some(offset) = region_offset(address, HAYSTACK_BASE, self.haystack.len(), length) {
            return self
                .haystack
                .get(offset..offset + length)
                .ok_or(SimError::InvalidMemoryRead);
        }
        let rodata_base = CODE_BASE + u64::from(self.image.layout().rodata_from_code_start);
        if let Some(offset) = region_offset(address, rodata_base, self.image.rodata().len(), length)
        {
            return self
                .image
                .rodata()
                .get(offset..offset + length)
                .ok_or(SimError::InvalidMemoryRead);
        }
        Err(SimError::InvalidMemoryRead)
    }

    fn store(&mut self, address: u64, value: u64) -> Result<(), SimError> {
        match address.checked_sub(RESULT_BASE) {
            Some(0) => {
                self.slot.start = usize::try_from(value).map_err(|_| SimError::Arithmetic)?;
                Ok(())
            }
            Some(8) => {
                self.slot.end = usize::try_from(value).map_err(|_| SimError::Arithmetic)?;
                Ok(())
            }
            _ => Err(SimError::InvalidMemoryWrite),
        }
    }
}

fn region_offset(address: u64, base: u64, region_len: usize, width: usize) -> Option<usize> {
    let offset = address.checked_sub(base)?;
    let offset = usize::try_from(offset).ok()?;
    let end = offset.checked_add(width)?;
    (end <= region_len).then_some(offset)
}

fn add_pc(pc: u32, displacement: i32) -> Result<u32, SimError> {
    let target = i64::from(pc)
        .checked_add(i64::from(displacement))
        .ok_or(SimError::Arithmetic)?;
    u32::try_from(target).map_err(|_| SimError::InvalidProgramCounter)
}

fn add_signed(base: u64, displacement: i32) -> Result<u64, SimError> {
    if displacement >= 0 {
        base.checked_add(u64::try_from(displacement).map_err(|_| SimError::Arithmetic)?)
            .ok_or(SimError::Arithmetic)
    } else {
        base.checked_sub(u64::from(displacement.unsigned_abs()))
            .ok_or(SimError::Arithmetic)
    }
}

#[test]
fn instruction_shapes_are_small_and_simd_is_visible() {
    let short =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("short");
    let long = build_exact_literal::<Span>(
        b"0123456789abcdefg",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("long");
    let class = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"abc"),
        b"Zsuffix",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("class");
    let short = emit(&short, EmitLimits::default()).expect("short image");
    let long = emit(&long, EmitLimits::default()).expect("long image");
    let class = emit(&class, EmitLimits::default()).expect("class image");
    assert!(short.code().len() < 1_024);
    assert!(long.code().len() < 1_152);
    assert!(class.code().len() < 1_024);
    assert!(audit(&short).expect("short audit").vector_instructions >= 4);
    assert!(audit(&long).expect("long audit").vector_instructions >= 8);
    assert!(
        decode(long.code())
            .expect("long image decodes")
            .iter()
            .any(|instruction| matches!(instruction, DecodedInstruction::AndBytes16 { .. }))
    );
    assert_eq!(class.symbols().len(), 2);
    assert_eq!(class.output(), OutputKind::Span);
}

#[test]
fn singleton_class_authenticates_suffix_first_shape_only_when_admitted() {
    let suffix = b"bcdefghijklmnopq";
    let singleton = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("singleton program");
    let multiple = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"ac"),
        suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("multiple-byte program");
    let anchored = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        suffix,
        AnchorFlags {
            start: true,
            end: false,
        },
        ValidateLimits::default(),
    )
    .expect("anchored singleton program");
    let singleton = emit(&singleton, EmitLimits::default()).expect("suffix-first image");
    let multiple = emit(&multiple, EmitLimits::default()).expect("bitmap image");
    let anchored = emit(&anchored, EmitLimits::default()).expect("one-run image");
    let suffix_first = decode(singleton.code()).expect("suffix-first image decodes");
    assert!(
        suffix_first
            .iter()
            .any(|instruction| matches!(instruction, DecodedInstruction::AndBytes16 { .. }))
    );
    assert!(
        !suffix_first.iter().any(|instruction| matches!(
            instruction,
            DecodedInstruction::Load64RegisterScaled { .. }
        ))
    );
    for retained in [&multiple, &anchored] {
        assert!(
            decode(retained.code())
                .expect("retained image decodes")
                .iter()
                .any(|instruction| matches!(
                    instruction,
                    DecodedInstruction::Load64RegisterScaled { .. }
                ))
        );
    }
    for byte in [0_u8, 63, 64, 127, 128, 191, 192, 255] {
        assert_eq!(
            super::emit::singleton_byte(ByteClass::from_bytes(&[byte])),
            Some(byte)
        );
    }
    assert_eq!(
        super::emit::singleton_byte(ByteClass::from_bytes(b"ab")),
        None
    );
}
