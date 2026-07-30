#![allow(
    clippy::arithmetic_side_effects,
    reason = "the bounded test ISA model intentionally implements architectural wrapping arithmetic"
)]

use core::mem::{align_of, size_of};
use std::collections::BTreeSet;

use fre_kernel_ir::{
    AggregateExecutionLimits, AggregateOutput, AnchorFlags, BlockId, ByteClass, Count,
    ExecutionLimits, Exists, InvalidProgram, OutputKind, RawProgram, SearchWindow, SelectedEnd,
    Span, SpanSum, ValidateError, ValidateLimits, build_class_suffix, build_exact_aggregate,
    build_exact_literal,
};
use sha2::{Digest, Sha256};

use crate::{
    AggregateResultLayout, AotLimits, AuditError, BackendVersion, Condition, ConfirmationKind,
    CpuFeatures, DataSymbol, DataSymbolKind, DecodeError, DecodedInstruction, EmitError,
    EmitLimits, LabelKind, MAX_REPEATED_CONFIRM_BYTES, NativeAggregateImage, NativeAggregateResult,
    NativeImage, NativeResult, RelocationKind, RelocationTarget, ResourceKind, ResultLayout,
    SearchBackendPolicy, UnsupportedReason, audit, audit_aggregate, decode, decode_one, emit,
    emit::emit_search_version_for_test,
    emit_audited_with_backend, emit_exact_aggregate,
    emit_exact_aggregate_sve2_fixed16_count_experimental,
    emit_exact_aggregate_sve2_fixed16_pair_count_experimental,
    emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental,
    emit_exact_aggregate_sve2_fixed16_span_sum_experimental, emit_sve2_16, emit_sve2_fixed16_v2,
    emit_sve16, emit_sve16_v6, emit_with_backend,
    image::{SearchManifest, SearchShape},
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
        (SearchBackendPolicy::AsimdV11, BackendVersion::SEARCH_V11),
        (SearchBackendPolicy::AsimdV12, BackendVersion::SEARCH_V12),
        (SearchBackendPolicy::AsimdV13, BackendVersion::SEARCH_V13),
        (SearchBackendPolicy::AsimdV14, BackendVersion::SEARCH_V14),
        (SearchBackendPolicy::AsimdV15, BackendVersion::SEARCH_V15),
        (SearchBackendPolicy::AsimdV16, BackendVersion::SEARCH_V16),
        (SearchBackendPolicy::AsimdV17, BackendVersion::SEARCH_V17),
        (SearchBackendPolicy::AsimdV18, BackendVersion::SEARCH_V18),
        (SearchBackendPolicy::AsimdV19, BackendVersion::SEARCH_V19),
        (SearchBackendPolicy::AsimdV20, BackendVersion::SEARCH_V20),
        (SearchBackendPolicy::AsimdV21, BackendVersion::SEARCH_V21),
        (SearchBackendPolicy::AsimdV22, BackendVersion::SEARCH_V22),
        (SearchBackendPolicy::AsimdV23, BackendVersion::SEARCH_V23),
        (SearchBackendPolicy::AsimdV24, BackendVersion::SEARCH_V24),
        (SearchBackendPolicy::AsimdV25, BackendVersion::SEARCH_V25),
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
        let mut head_near_miss = literal.clone();
        head_near_miss[0] ^= 0x80;
        let mut head_near_miss_stream = Vec::new();
        for _ in 0..8 {
            head_near_miss_stream.extend_from_slice(&head_near_miss);
        }
        head_near_miss_stream.extend_from_slice(&literal);
        let mut dense_matches = Vec::new();
        for _ in 0..8 {
            dense_matches.extend_from_slice(&literal);
        }
        let mut haystacks = vec![
            Vec::new(),
            literal.clone(),
            vec![0xa5; 257],
            near_miss_stream,
            head_near_miss_stream,
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
    assert_eq!(comparisons, 1_344);

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
#[allow(
    clippy::too_many_lines,
    reason = "the V11 contract keeps endpoint reservations, frozen wire identity, independent audit, relabel resistance, and every-offset semantics together"
)]
fn v11_dual_endpoint_filter_is_distinct_audited_and_matches_every_offset() {
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
        .expect("V11 Span IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV11,
            EmitLimits::default(),
        )
        .expect("V11 exact image");
        assert_eq!(image.backend_version(), BackendVersion::SEARCH_V11);
        let manifest = image.search_manifest().expect("V11 manifest");
        assert_eq!(manifest.candidate_policy_version, 11);
        let terminal = u16::try_from(width - 1).expect("bounded terminal offset");
        let selected_offsets = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ];
        assert!(
            selected_offsets.contains(&0),
            "V11 must select the literal head at width {width}"
        );
        assert!(
            selected_offsets.contains(&terminal),
            "V11 must select the literal terminal at width {width}"
        );
        for left in 0..selected_offsets.len() {
            if selected_offsets[left] == u16::MAX {
                continue;
            }
            assert!(usize::from(selected_offsets[left]) < width);
            for right in left + 1..selected_offsets.len() {
                assert_ne!(selected_offsets[left], selected_offsets[right]);
            }
        }
        let report = audit(&image).expect("independent V11 whole-template audit");
        assert_eq!(
            (report.decode_passes, report.source_identity_rebuilds),
            (1, 1)
        );
        let aot = image.to_aot(AotLimits::default()).expect("bounded V11 AOT");
        assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x18");
        assert_eq!(aot.identity(), image.artifact_identity());

        for extra_image in [
            {
                let extra = build_exact_literal::<Exists>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("V11 Exists IR");
                emit_with_backend(&extra, SearchBackendPolicy::AsimdV11, EmitLimits::default())
                    .expect("V11 Exists image")
            },
            {
                let extra = build_exact_literal::<SelectedEnd>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("V11 SelectedEnd IR");
                emit_with_backend(&extra, SearchBackendPolicy::AsimdV11, EmitLimits::default())
                    .expect("V11 SelectedEnd image")
            },
        ] {
            assert_eq!(extra_image.backend_version(), BackendVersion::SEARCH_V11);
            assert_eq!(
                extra_image
                    .search_manifest()
                    .expect("V11 output manifest")
                    .candidate_policy_version,
                11
            );
            audit(&extra_image).expect("independent V11 output-template audit");
            assert_eq!(
                &extra_image
                    .to_aot(AotLimits::default())
                    .expect("bounded V11 output AOT")
                    .as_bytes()[..8],
                b"FREA64\0\x18"
            );
        }

        let decoded = decode(image.code()).expect("V11 decode");
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

        let mut dense_matches = Vec::new();
        for _ in 0..8 {
            dense_matches.extend_from_slice(&literal);
        }
        let mut haystacks = vec![Vec::new(), literal.clone(), vec![0xa5; 257], dense_matches];
        for candidate_start in [0_usize, 15, 16, 31] {
            let mut haystack = vec![0xe3; candidate_start + width + 67];
            haystack[candidate_start..candidate_start + width].copy_from_slice(&literal);
            haystacks.push(haystack);
        }
        for mutation_offset in 0..width {
            let mut near_miss = literal.clone();
            near_miss[mutation_offset] ^= 0x80;
            let mut stream = Vec::new();
            for _ in 0..8 {
                stream.extend_from_slice(&near_miss);
            }
            stream.extend_from_slice(&literal);
            haystacks.push(stream);
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
                    .expect("V11 oracle execution")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual =
                    simulate(&image, haystack, start, end).expect("V11 safe ISA simulation");
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
    assert_eq!(comparisons, 2_352);

    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V10/V11 identity program");
    let canonical_v10 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV10,
        EmitLimits::default(),
    )
    .expect("canonical V10");
    let canonical_v11 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV11,
        EmitLimits::default(),
    )
    .expect("canonical V11");
    assert_ne!(canonical_v11.code(), canonical_v10.code());
    assert_ne!(
        canonical_v11.artifact_identity(),
        canonical_v10.artifact_identity()
    );
    let v10_offsets = {
        let manifest = canonical_v10.search_manifest().expect("V10 manifest");
        (
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        )
    };
    let v11_offsets = {
        let manifest = canonical_v11.search_manifest().expect("V11 manifest");
        (
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        )
    };

    let mut v11_as_v10 = canonical_v11;
    v11_as_v10.backend_version = BackendVersion::SEARCH_V10;
    {
        let manifest = v11_as_v10.search.as_mut().expect("V11 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V10;
        manifest.candidate_policy_version = 10;
        (
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ) = v10_offsets;
    }
    assert_resealed_search_rejected(v11_as_v10, "V11 code resealed as V10");

    let mut v10_as_v11 = canonical_v10;
    v10_as_v11.backend_version = BackendVersion::SEARCH_V11;
    {
        let manifest = v10_as_v11.search.as_mut().expect("V10 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V11;
        manifest.candidate_policy_version = 11;
        (
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ) = v11_offsets;
    }
    assert_resealed_search_rejected(v10_as_v11, "V10 code resealed as V11");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V12 contract keeps specialized-width shape, wire identity, independent audit, relabel resistance, and every-offset semantics together"
)]
fn v12_specialized_confirmation_is_audited_and_matches_every_offset() {
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
        .expect("V12 Span IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV12,
            EmitLimits::default(),
        )
        .expect("V12 exact image");
        assert_eq!(image.backend_version(), BackendVersion::SEARCH_V12);
        let manifest = image.search_manifest().expect("V12 manifest");
        assert_eq!(manifest.candidate_policy_version, 12);
        let selected_offsets = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ];
        assert!(selected_offsets.contains(&0));
        assert!(
            selected_offsets.contains(&u16::try_from(width - 1).expect("bounded terminal offset"))
        );
        let report = audit(&image).expect("independent V12 whole-template audit");
        assert_eq!(
            (report.decode_passes, report.source_identity_rebuilds),
            (1, 1)
        );
        let aot = image.to_aot(AotLimits::default()).expect("bounded V12 AOT");
        assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x19");
        assert_eq!(aot.identity(), image.artifact_identity());

        let decoded = decode(image.code()).expect("V12 decode");
        if (2..=3).contains(&width) {
            assert!(
                decoded
                    .iter()
                    .any(|instruction| matches!(instruction, DecodedInstruction::Load16 { .. })),
                "width {width} must use exact 16-bit confirmation loads"
            );
        }
        if (4..=7).contains(&width) {
            assert!(
                decoded
                    .iter()
                    .any(|instruction| matches!(instruction, DecodedInstruction::Load32 { .. })),
                "width {width} must use exact 32-bit confirmation loads"
            );
        }
        if (8..=15).contains(&width) {
            assert!(
                decoded
                    .iter()
                    .any(|instruction| matches!(instruction, DecodedInstruction::Load64 { .. })),
                "width {width} must use exact 64-bit confirmation loads"
            );
        }
        if (17..=32).contains(&width) {
            assert!(
                decoded.iter().any(|instruction| {
                    matches!(
                        instruction,
                        DecodedInstruction::LoadVector128 {
                            destination: 18,
                            ..
                        }
                    )
                }),
                "width {width} must use an overlapping second vector"
            );
        }

        for extra_image in [
            {
                let extra = build_exact_literal::<Exists>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("V12 Exists IR");
                emit_with_backend(&extra, SearchBackendPolicy::AsimdV12, EmitLimits::default())
                    .expect("V12 Exists image")
            },
            {
                let extra = build_exact_literal::<SelectedEnd>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("V12 SelectedEnd IR");
                emit_with_backend(&extra, SearchBackendPolicy::AsimdV12, EmitLimits::default())
                    .expect("V12 SelectedEnd image")
            },
        ] {
            audit(&extra_image).expect("independent V12 output-template audit");
        }

        let mut haystacks = Vec::new();
        for candidate_start in [0_usize, 1, 15, 16, 31] {
            let mut haystack = vec![0xe3; candidate_start + width + 67];
            haystack[candidate_start..candidate_start + width].copy_from_slice(&literal);
            haystacks.push(haystack);
        }
        for mutation_offset in 0..width {
            let mut near_miss = literal.clone();
            near_miss[mutation_offset] ^= 0x80;
            let mut stream = Vec::new();
            for _ in 0..8 {
                stream.extend_from_slice(&near_miss);
            }
            stream.extend_from_slice(&literal);
            haystacks.push(stream);
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
                    .expect("V12 oracle execution")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual =
                    simulate(&image, haystack, start, end).expect("V12 safe ISA simulation");
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
    assert_eq!(comparisons, 2_064);

    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V11/V12 identity program");
    let canonical_v11 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV11,
        EmitLimits::default(),
    )
    .expect("canonical V11");
    let canonical_v12 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV12,
        EmitLimits::default(),
    )
    .expect("canonical V12");
    assert_ne!(canonical_v12.code(), canonical_v11.code());
    assert_ne!(
        canonical_v12.artifact_identity(),
        canonical_v11.artifact_identity()
    );

    let mut v12_as_v11 = canonical_v12;
    v12_as_v11.backend_version = BackendVersion::SEARCH_V11;
    {
        let manifest = v12_as_v11.search.as_mut().expect("V12 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V11;
        manifest.candidate_policy_version = 11;
    }
    assert_resealed_search_rejected(v12_as_v11, "V12 code resealed as V11");

    let mut v11_as_v12 = canonical_v11;
    v11_as_v12.backend_version = BackendVersion::SEARCH_V12;
    {
        let manifest = v11_as_v12.search.as_mut().expect("V11 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V12;
        manifest.candidate_policy_version = 12;
    }
    assert_resealed_search_rejected(v11_as_v12, "V11 code resealed as V12");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V13 matrix binds adaptive instruction count, independent audit, every width/offset/shape semantic, output contracts, and relabel resistance"
)]
fn v13_adaptive_retained_mask_is_audited_and_matches_every_offset() {
    let mut comparisons = 0_u64;
    for width in 1_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literals = [
            (0..width)
                .map(|offset| {
                    u8::try_from(offset)
                        .expect("bounded width")
                        .wrapping_mul(61)
                        .wrapping_add(7)
                })
                .collect::<Vec<_>>(),
            vec![b'a'; width],
            (0..width)
                .map(|offset| if offset & 1 == 0 { b'a' } else { b'b' })
                .collect::<Vec<_>>(),
        ];
        for literal in literals {
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V13 Span IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV13,
                EmitLimits::default(),
            )
            .expect("V13 exact image");
            assert_eq!(image.backend_version(), BackendVersion::SEARCH_V13);
            let manifest = image.search_manifest().expect("V13 manifest");
            assert_eq!(manifest.candidate_policy_version, 13);
            audit(&image).expect("independent V13 whole-template audit");
            let aot = image.to_aot(AotLimits::default()).expect("bounded V13 AOT");
            assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x1a");

            let selected = [
                manifest.primary_offset,
                manifest.secondary_offset,
                manifest.verification_offset,
                manifest.quaternary_offset,
                manifest.quinary_offset,
            ];
            let selected_count = selected
                .into_iter()
                .filter(|offset| *offset != u16::MAX)
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            let expected_adaptive_columns = width.saturating_sub(selected_count);
            let decoded = decode(image.code()).expect("V13 decode");
            assert_eq!(
                decoded
                    .iter()
                    .filter(|instruction| {
                        matches!(
                            instruction,
                            DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                                destination: 18,
                                source: 16
                            }
                        )
                    })
                    .count(),
                expected_adaptive_columns
            );

            let avoid = (0_u16..=255)
                .map(|value| u8::try_from(value).expect("bounded byte"))
                .find(|byte| !literal.contains(byte))
                .expect("literal leaves an avoiding byte");
            for mutation_offset in 0..width {
                let mut near_miss = literal.clone();
                near_miss[mutation_offset] = avoid;
                let mut haystack = Vec::new();
                for _ in 0..17 {
                    haystack.extend_from_slice(&near_miss);
                }
                haystack.extend_from_slice(&literal);
                for (start, end) in [
                    (0, haystack.len()),
                    (haystack.len().min(1), haystack.len()),
                    (0, haystack.len().saturating_sub(1)),
                ] {
                    let window = SearchWindow::new(start, end);
                    let expected = program
                        .execute(&haystack, window, ExecutionLimits::unlimited())
                        .expect("V13 oracle")
                        .output()
                        .map(|span| (span.start(), span.end()));
                    let actual =
                        simulate(&image, &haystack, start, end).expect("V13 safe ISA simulation");
                    assert_eq!(
                        span_output(actual),
                        expected,
                        "width={width} mutation={mutation_offset} literal={literal:?} \
                         window={start}..{end}"
                    );
                    comparisons = comparisons.checked_add(1).expect("bounded matrix");
                }
            }
        }
    }
    assert_eq!(comparisons, 4_752);

    let literal = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for image in [
        {
            let program = build_exact_literal::<Exists>(
                literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V13 Exists IR");
            emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV13,
                EmitLimits::default(),
            )
            .expect("V13 Exists")
        },
        {
            let program = build_exact_literal::<SelectedEnd>(
                literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V13 SelectedEnd IR");
            emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV13,
                EmitLimits::default(),
            )
            .expect("V13 SelectedEnd")
        },
    ] {
        audit(&image).expect("independent V13 output-template audit");
    }

    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V12/V13 identity program");
    let canonical_v12 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV12,
        EmitLimits::default(),
    )
    .expect("canonical V12");
    let canonical_v13 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV13,
        EmitLimits::default(),
    )
    .expect("canonical V13");
    assert_ne!(canonical_v13.code(), canonical_v12.code());
    assert_ne!(
        canonical_v13.artifact_identity(),
        canonical_v12.artifact_identity()
    );

    let mut v13_as_v12 = canonical_v13;
    v13_as_v12.backend_version = BackendVersion::SEARCH_V12;
    {
        let manifest = v13_as_v12.search.as_mut().expect("V13 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V12;
        manifest.candidate_policy_version = 12;
    }
    assert_resealed_search_rejected(v13_as_v12, "V13 code resealed as V12");

    let mut v12_as_v13 = canonical_v12;
    v12_as_v13.backend_version = BackendVersion::SEARCH_V13;
    {
        let manifest = v12_as_v13.search.as_mut().expect("V12 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V13;
        manifest.candidate_policy_version = 13;
    }
    assert_resealed_search_rejected(v12_as_v13, "V12 code resealed as V13");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V14 matrix binds its learned-state instruction graph, every width/offset/shape semantic, nonstationary transitions, output contracts, and relabel resistance"
)]
fn v14_persistent_learned_column_is_audited_and_matches_every_offset() {
    let mut comparisons = 0_u64;
    for width in 1_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literals = [
            (0..width)
                .map(|offset| {
                    u8::try_from(offset)
                        .expect("bounded width")
                        .wrapping_mul(61)
                        .wrapping_add(7)
                })
                .collect::<Vec<_>>(),
            vec![b'a'; width],
            (0..width)
                .map(|offset| if offset & 1 == 0 { b'a' } else { b'b' })
                .collect::<Vec<_>>(),
        ];
        for literal in literals {
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V14 Span IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV14,
                EmitLimits::default(),
            )
            .expect("V14 exact image");
            assert_eq!(image.backend_version(), BackendVersion::SEARCH_V14);
            let manifest = image.search_manifest().expect("V14 manifest");
            assert_eq!(manifest.candidate_policy_version, 14);
            assert!(
                [
                    manifest.primary_offset,
                    manifest.secondary_offset,
                    manifest.verification_offset,
                    manifest.quaternary_offset,
                    manifest.quinary_offset,
                ]
                .contains(&0),
                "the authenticated dual-endpoint policy always covers literal byte zero"
            );
            audit(&image).expect("independent V14 whole-template audit");
            let aot = image.to_aot(AotLimits::default()).expect("bounded V14 AOT");
            assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x1b");

            let decoded = decode(image.code()).expect("V14 decode");
            assert_eq!(
                decoded
                    .iter()
                    .filter(|instruction| {
                        **instruction
                            == DecodedInstruction::DuplicateByte16 {
                                destination: 24,
                                source: 13,
                            }
                    })
                    .count(),
                1
            );
            assert_eq!(
                decoded
                    .iter()
                    .filter(|instruction| {
                        **instruction
                            == DecodedInstruction::DuplicateByte16 {
                                destination: 25,
                                source: 11,
                            }
                    })
                    .count(),
                1
            );
            assert_eq!(
                decoded
                    .iter()
                    .filter(|instruction| {
                        **instruction
                            == DecodedInstruction::MoveVectorByteTo32 {
                                destination: 10,
                                source: 25,
                            }
                    })
                    .count(),
                2
            );

            let avoid = (0_u16..=255)
                .map(|value| u8::try_from(value).expect("bounded byte"))
                .find(|byte| !literal.contains(byte))
                .expect("literal leaves an avoiding byte");
            for mutation_offset in 0..width {
                let mut near_miss = literal.clone();
                near_miss[mutation_offset] = avoid;
                let mut haystack = Vec::new();
                for _ in 0..17 {
                    haystack.extend_from_slice(&near_miss);
                }
                haystack.extend_from_slice(&literal);
                for (start, end) in [
                    (0, haystack.len()),
                    (haystack.len().min(1), haystack.len()),
                    (0, haystack.len().saturating_sub(1)),
                ] {
                    let window = SearchWindow::new(start, end);
                    let expected = program
                        .execute(&haystack, window, ExecutionLimits::unlimited())
                        .expect("V14 oracle")
                        .output()
                        .map(|span| (span.start(), span.end()));
                    let actual =
                        simulate(&image, &haystack, start, end).expect("V14 safe ISA simulation");
                    assert_eq!(
                        span_output(actual),
                        expected,
                        "width={width} mutation={mutation_offset} literal={literal:?} \
                         window={start}..{end}"
                    );
                    comparisons = comparisons.checked_add(1).expect("bounded matrix");
                }
            }
        }
    }
    assert_eq!(comparisons, 4_752);

    // The first region teaches one unselected mismatch column and immediately
    // produces a six-column survivor, forcing the one-way V13 fallback. The
    // second region then exercises multiple later exact misses without any
    // re-entry to discovery before the final exact match.
    let literal = [b'a'; 16];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V14 transition IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV14,
        EmitLimits::default(),
    )
    .expect("V14 transition image");
    let selected = {
        let manifest = image.search_manifest().expect("V14 transition manifest");
        [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ]
    };
    let unselected = (0_u16..16)
        .filter(|offset| !selected.contains(offset))
        .collect::<Vec<_>>();
    assert!(unselected.len() >= 2);
    let mut haystack = Vec::new();
    for (mutation, chunks) in [(unselected[0], 8_usize), (unselected[1], 8)] {
        let mut near_miss = literal;
        near_miss[usize::from(mutation)] = b'x';
        for _ in 0..chunks {
            haystack.extend_from_slice(&near_miss);
        }
    }
    haystack.extend_from_slice(&literal);
    let expected = program
        .execute(
            &haystack,
            SearchWindow::new(0, haystack.len()),
            ExecutionLimits::unlimited(),
        )
        .expect("V14 transition oracle")
        .output()
        .map(|span| (span.start(), span.end()));
    let decoded = decode(image.code()).expect("V14 transition decode");
    let learned_byte = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::DuplicateByte16 {
                    destination: 24,
                    source: 13,
                }
        })
        .expect("V14 learned-byte DUP");
    let learned_offset = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::DuplicateByte16 {
                    destination: 25,
                    source: 11,
                }
        })
        .expect("V14 learned-offset DUP");
    assert_eq!(learned_offset, learned_byte + 1);
    let candidate_miss = decoded
        .windows(3)
        .position(|window| {
            window[0]
                == DecodedInstruction::SubtractImmediate64 {
                    destination: 10,
                    source: 0,
                    immediate: 1,
                }
                && window[1]
                    == DecodedInstruction::AndRegister64 {
                        destination: 0,
                        left: 0,
                        right: 10,
                    }
                && matches!(
                    window[2],
                    DecodedInstruction::CompareBranchZero64 {
                        register: 11,
                        nonzero: false,
                        ..
                    }
                )
        })
        .expect("V14 candidate-miss state gate");
    let target = |index: usize| {
        let displacement = match decoded[index] {
            DecodedInstruction::Branch { displacement }
            | DecodedInstruction::BranchCondition { displacement, .. }
            | DecodedInstruction::CompareBranchZero64 { displacement, .. } => displacement,
            _ => panic!("instruction {index} is not a decoded V14 branch"),
        };
        let address = i64::try_from(index)
            .expect("small instruction index")
            .checked_mul(4)
            .and_then(|address| address.checked_add(i64::from(displacement)))
            .expect("bounded V14 branch target");
        assert_eq!(address % 4, 0);
        usize::try_from(address / 4).expect("nonnegative V14 target")
    };
    let discover = target(candidate_miss + 2);
    let learned_column_probes = decoded
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (*instruction
                == DecodedInstruction::MoveVectorByteTo32 {
                    destination: 10,
                    source: 25,
                })
            .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(learned_column_probes.len(), 2);
    let disable_sites = decoded
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (*instruction
                == DecodedInstruction::MoveZero64 {
                    destination: 11,
                    immediate: 2,
                    shift: 0,
                })
            .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(disable_sites.len(), 3);
    let six_survivor_disable = disable_sites
        .iter()
        .copied()
        .find(|index| learned_column_probes[0] < *index && *index < learned_column_probes[1])
        .expect("current six-column survivor disable site");
    assert!(
        decoded
            .iter()
            .enumerate()
            .skip(learned_offset + 1)
            .all(|(index, instruction)| {
                !matches!(
                    instruction,
                    DecodedInstruction::Branch { .. }
                        | DecodedInstruction::BranchCondition { .. }
                        | DecodedInstruction::CompareBranchZero64 { .. }
                ) || target(index) != discover
            }),
        "no post-discovery CFG edge may re-enter discovery"
    );

    let (actual, trace) = simulate_with_instruction_trace(&image, &haystack, 0, haystack.len())
        .expect("V14 nonstationary traced safe ISA simulation");
    assert_eq!(span_output(actual), expected);
    assert_eq!(
        trace.iter().filter(|&&index| index == learned_byte).count(),
        1,
        "the learned-byte DUP executes exactly once"
    );
    assert_eq!(
        trace
            .iter()
            .filter(|&&index| index == learned_offset)
            .count(),
        1,
        "the learned-offset DUP executes exactly once"
    );
    let disable_trace = trace
        .iter()
        .position(|&index| index == six_survivor_disable)
        .expect("the current six-column survivor disables learned mode");
    assert!(
        trace[disable_trace + 1..]
            .iter()
            .filter(|&&index| index == candidate_miss)
            .count()
            >= 2,
        "at least two later exact misses remain in the one-way V13 fallback"
    );

    for image in [
        {
            let program = build_exact_literal::<Exists>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V14 Exists IR");
            emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV14,
                EmitLimits::default(),
            )
            .expect("V14 Exists")
        },
        {
            let program = build_exact_literal::<SelectedEnd>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V14 SelectedEnd IR");
            emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV14,
                EmitLimits::default(),
            )
            .expect("V14 SelectedEnd")
        },
    ] {
        audit(&image).expect("independent V14 output-template audit");
    }

    let canonical_v13 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV13,
        EmitLimits::default(),
    )
    .expect("canonical V13");
    let canonical_v14 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV14,
        EmitLimits::default(),
    )
    .expect("canonical V14");
    assert_ne!(canonical_v14.code(), canonical_v13.code());
    assert_ne!(
        canonical_v14.artifact_identity(),
        canonical_v13.artifact_identity()
    );

    let mut v14_as_v13 = canonical_v14;
    v14_as_v13.backend_version = BackendVersion::SEARCH_V13;
    {
        let manifest = v14_as_v13.search.as_mut().expect("V14 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V13;
        manifest.candidate_policy_version = 13;
    }
    assert_resealed_search_rejected(v14_as_v13, "V14 code resealed as V13");

    let mut v13_as_v14 = canonical_v13;
    v13_as_v14.backend_version = BackendVersion::SEARCH_V14;
    {
        let manifest = v13_as_v14.search.as_mut().expect("V13 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V14;
        manifest.candidate_policy_version = 14;
    }
    assert_resealed_search_rejected(v13_as_v14, "V13 code resealed as V14");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V15 contract exhausts its complete small binary selector space, every phase and width boundary, independent audit, semantics, and wire relabel resistance"
)]
fn v15_phase_unique_selector_is_exhaustive_audited_and_semantic() {
    let phase_unique = |literal: &[u8], manifest: SearchManifest| {
        let selected = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ]
        .map(usize::from);
        assert_eq!(
            selected.iter().copied().collect::<BTreeSet<_>>().len(),
            5,
            "the endpoint-preserving V3 ranker authenticates five distinct columns"
        );
        assert!(selected.iter().all(|&offset| offset < literal.len()));
        assert!(literal.len() > selected.len());
        (1..literal.len()).all(|phase| {
            selected
                .iter()
                .any(|&offset| literal[offset] != literal[(offset + phase) % literal.len()])
        })
    };

    let mut eligible = 0_u64;
    let mut refused = 0_u64;
    let mut audited = 0_u64;
    for width in 6_usize..=10 {
        for bits in 0_u64..(1_u64 << width) {
            let literal = (0..width)
                .map(|offset| {
                    if bits & (1_u64 << offset) == 0 {
                        3
                    } else {
                        197
                    }
                })
                .collect::<Vec<_>>();
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V15 exhaustive binary IR");
            let v14 = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV14,
                EmitLimits::default(),
            )
            .expect("frozen V14 exposes the authenticated V3 offsets");
            let expected = phase_unique(
                &literal,
                v14.search_manifest().expect("V14 search manifest"),
            );
            match emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV15,
                EmitLimits::default(),
            ) {
                Ok(image) => {
                    assert!(expected, "V15 admitted an ambiguous cyclic signature");
                    assert_eq!(image.backend_version(), BackendVersion::SEARCH_V15);
                    assert_eq!(
                        image
                            .search_manifest()
                            .expect("V15 manifest")
                            .candidate_policy_version,
                        15
                    );
                    audit(&image).expect("independent V15 selector and template audit");
                    assert_eq!(
                        &image
                            .to_aot(AotLimits::default())
                            .expect("bounded V15 AOT")
                            .as_bytes()[..8],
                        b"FREA64\0\x1c"
                    );
                    eligible = eligible.checked_add(1).expect("bounded selector count");
                    audited = audited.checked_add(1).expect("bounded audit count");
                }
                Err(error) => {
                    assert!(!expected, "V15 refused a phase-unique signature");
                    assert_eq!(
                        error,
                        EmitError::Unsupported {
                            reason: UnsupportedReason::KernelShape,
                        }
                    );
                    refused = refused.checked_add(1).expect("bounded selector count");
                }
            }
        }
    }
    assert_eq!(eligible + refused, 1_984);
    assert_eq!(audited, eligible);
    assert!(eligible > 0 && refused > 0);

    let mut semantic_comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V15 width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V15 width-boundary IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV15,
            EmitLimits::default(),
        )
        .expect("phase-unique V15 width-boundary image");
        let manifest = image.search_manifest().expect("V15 manifest");
        assert!(phase_unique(&literal, manifest));
        assert_eq!(
            [
                manifest.primary_offset,
                manifest.secondary_offset,
                manifest.verification_offset,
                manifest.quaternary_offset,
                manifest.quinary_offset,
            ]
            .into_iter()
            .map(usize::from)
            .filter(|offset| *offset < width)
            .count(),
            5
        );
        assert!(width > 5, "at least one column remains unselected");
        audit(&image).expect("V15 width-boundary audit");

        let avoid = (0_u16..=255)
            .map(|value| u8::try_from(value).expect("bounded byte"))
            .find(|byte| !literal.contains(byte))
            .expect("V15 literal leaves an avoiding byte");
        for mutation_offset in 0..width {
            let mut near_miss = literal.clone();
            near_miss[mutation_offset] = avoid;
            let mut haystack = Vec::new();
            for _ in 0..17 {
                haystack.extend_from_slice(&near_miss);
            }
            haystack.extend_from_slice(&literal);
            let expected = program
                .execute(
                    &haystack,
                    SearchWindow::new(0, haystack.len()),
                    ExecutionLimits::unlimited(),
                )
                .expect("V15 semantic oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual =
                simulate(&image, &haystack, 0, haystack.len()).expect("V15 safe ISA simulation");
            assert_eq!(
                span_output(actual),
                expected,
                "width={width} mutation={mutation_offset}"
            );
            semantic_comparisons = semantic_comparisons
                .checked_add(1)
                .expect("bounded semantic comparisons");
        }
    }
    assert_eq!(semantic_comparisons, 513);

    for literal in [
        vec![b'a'; 16],
        b"abababababababab".to_vec(),
        b"0123456701234567".to_vec(),
    ] {
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V15 ambiguous IR");
        assert_eq!(
            emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV15,
                EmitLimits::default(),
            ),
            Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            })
        );
    }
    for width in 1_usize..6 {
        let literal = (0..width)
            .map(|offset| u8::try_from(offset).expect("small width"))
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V15 below-boundary IR");
        assert_eq!(
            emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV15,
                EmitLimits::default(),
            ),
            Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            })
        );
    }

    let literal = b"phase-unique-15!";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V15 wire IR");
    let canonical_v14 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV14,
        EmitLimits::default(),
    )
    .expect("canonical V14");
    let canonical_v15 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV15,
        EmitLimits::default(),
    )
    .expect("canonical V15");
    assert_ne!(canonical_v15.code(), canonical_v14.code());
    assert_ne!(
        canonical_v15.artifact_identity(),
        canonical_v14.artifact_identity()
    );

    let mut v15_as_v14 = canonical_v15;
    v15_as_v14.backend_version = BackendVersion::SEARCH_V14;
    {
        let manifest = v15_as_v14.search.as_mut().expect("V15 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V14;
        manifest.candidate_policy_version = 14;
    }
    assert_resealed_search_rejected(v15_as_v14, "V15 code resealed as V14");

    let mut v14_as_v15 = canonical_v14;
    v14_as_v15.backend_version = BackendVersion::SEARCH_V15;
    {
        let manifest = v14_as_v15.search.as_mut().expect("V14 manifest");
        manifest.backend_version = BackendVersion::SEARCH_V15;
        manifest.candidate_policy_version = 15;
    }
    assert_resealed_search_rejected(v14_as_v15, "V14 code resealed as V15");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V16 semantic seed, staged-graph mutations, and cross-version resealing checks jointly authenticate one new backend boundary"
)]
fn v16_stages_repeated_learned_bytes_before_full_recovery() {
    let literal = [
        0x63, 0x1c, 0x0e, 0x53, 0xc4, 0xe4, 0xb3, 0x5c, 0xf7, 0x1d, 0x14, 0xcc, 0x07, 0xdb, 0x88,
        0x7b, 0xa2, 0x41, 0x99, 0xb9, 0x02, 0x92, 0xbb, 0x79, 0x4c, 0xe1, 0x0b, 0x28, 0x92, 0x63,
        0x68, 0x3d,
    ];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V16 repeated-learned-byte IR");
    let v15 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV15,
        EmitLimits::default(),
    )
    .expect("V15 diagnostic image");
    let v16 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV16,
        EmitLimits::default(),
    )
    .expect("V16 staged image");

    assert_eq!(v16.backend_version(), BackendVersion::SEARCH_V16);
    assert_eq!(
        v16.search_manifest()
            .expect("V16 manifest")
            .candidate_policy_version,
        15,
        "V16 changes recovery, not the frozen phase-unique selector"
    );
    assert_eq!(
        &v16.to_aot(AotLimits::default())
            .expect("bounded V16 AOT")
            .as_bytes()[..8],
        b"FREA64\0\x1d"
    );
    assert_ne!(v16.code(), v15.code());
    assert_ne!(v16.artifact_identity(), v15.artifact_identity());
    audit(&v16).expect("independent V16 staged-template audit");

    let staged_reductions = decode(v16.code())
        .expect("V16 decode")
        .into_iter()
        .filter(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                    destination: 18,
                    left: 16,
                    right: 16,
                }
            )
        })
        .count();
    assert!(
        staged_reductions >= 2,
        "V16 must separately test learned-byte and learned/primary presence"
    );

    for mutation_offset in 0..literal.len() {
        let mut near_miss = literal;
        near_miss[mutation_offset] = 0;
        let mut haystack = Vec::new();
        for _ in 0..257 {
            haystack.extend_from_slice(&near_miss);
        }
        haystack.extend_from_slice(&literal);
        let expected = program
            .execute(
                &haystack,
                SearchWindow::new(0, haystack.len()),
                ExecutionLimits::unlimited(),
            )
            .expect("V16 semantic oracle")
            .output()
            .map(|span| (span.start(), span.end()));
        let actual = simulate(&v16, &haystack, 0, haystack.len()).expect("V16 safe ISA simulation");
        assert_eq!(
            span_output(actual),
            expected,
            "mutation offset {mutation_offset}"
        );
    }

    let decoded = decode(v16.code()).expect("V16 mutation decode");
    let primary_stage = decoded
        .windows(3)
        .position(|window| {
            matches!(
                window,
                [
                    DecodedInstruction::CompareEqualBytes16 {
                        destination: 18,
                        left: 18,
                        right: 1,
                    },
                    DecodedInstruction::AndBytes16 {
                        destination: 16,
                        left: 16,
                        right: 18,
                    },
                    DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                        destination: 18,
                        left: 16,
                        right: 16,
                    },
                ]
            )
        })
        .expect("V16 learned/primary stage");
    let mut wrong_primary = v16.clone();
    replace_test_decoded_at(
        &mut wrong_primary,
        primary_stage,
        DecodedInstruction::CompareEqualBytes16 {
            destination: 18,
            left: 18,
            right: 3,
        },
    );
    assert_resealed_search_rejected(wrong_primary, "V16 wrong primary constant");

    let mut omitted_learned = v16.clone();
    replace_test_decoded_at(
        &mut omitted_learned,
        primary_stage + 1,
        DecodedInstruction::AndBytes16 {
            destination: 16,
            left: 18,
            right: 18,
        },
    );
    assert_resealed_search_rejected(omitted_learned, "V16 omitted learned-mask intersection");

    let staged_empty_branches = decoded
        .windows(3)
        .enumerate()
        .filter_map(|(index, window)| {
            matches!(
                window,
                [
                    DecodedInstruction::UnsignedMaxPairwiseBytes16 {
                        destination: 18,
                        left: 16,
                        right: 16,
                    },
                    DecodedInstruction::MoveVectorDoubleTo64 {
                        destination: 0,
                        source: 18,
                    },
                    DecodedInstruction::CompareBranchZero64 {
                        register: 0,
                        nonzero: false,
                        ..
                    },
                ]
            )
            .then_some(index + 2)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        staged_empty_branches.len(),
        2,
        "V16 has one learned-presence and one learned/primary-presence branch"
    );
    let branch = staged_empty_branches[1];
    let DecodedInstruction::CompareBranchZero64 {
        register,
        displacement,
        ..
    } = decoded[branch]
    else {
        unreachable!("selected V16 staged-empty branch")
    };
    let mut inverted_empty = v16.clone();
    replace_test_branch_and_relocation_at(
        &mut inverted_empty,
        branch,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: true,
            displacement,
        },
    );
    assert_resealed_search_rejected(inverted_empty, "V16 staged-empty branch inversion");

    let mut v16_as_v15 = v16;
    v16_as_v15.backend_version = BackendVersion::SEARCH_V15;
    v16_as_v15
        .search
        .as_mut()
        .expect("V16 manifest")
        .backend_version = BackendVersion::SEARCH_V15;
    assert_resealed_search_rejected(v16_as_v15, "V16 code resealed as V15");

    let mut v15_as_v16 = v15;
    v15_as_v16.backend_version = BackendVersion::SEARCH_V16;
    v15_as_v16
        .search
        .as_mut()
        .expect("V15 manifest")
        .backend_version = BackendVersion::SEARCH_V16;
    assert_resealed_search_rejected(v15_as_v16, "V15 code resealed as V16");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V17 graph test binds continuation edges, traced repeated misses, mutations, wire identity, and cross-version sealing together"
)]
fn v17_retains_learned_masks_across_exact_candidate_misses() {
    let literal = [
        0x63, 0x1c, 0x0e, 0x53, 0xc4, 0xe4, 0xb3, 0x5c, 0xf7, 0x1d, 0x14, 0xcc, 0x07, 0xdb, 0x88,
        0x7b, 0xa2, 0x41, 0x99, 0xb9, 0x02, 0x92, 0xbb, 0x79, 0x4c, 0xe1, 0x0b, 0x28, 0x92, 0x63,
        0x68, 0x3d,
    ];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V17 continuation IR");
    let v16 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV16,
        EmitLimits::default(),
    )
    .expect("frozen V16 image");
    let v17 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV17,
        EmitLimits::default(),
    )
    .expect("V17 continuation image");
    assert_eq!(v17.backend_version(), BackendVersion::SEARCH_V17);
    assert_eq!(
        v17.search_manifest()
            .expect("V17 manifest")
            .candidate_policy_version,
        15,
        "V17 changes only the graph, not phase-unique admission"
    );
    assert_eq!(
        &v17.to_aot(AotLimits::default())
            .expect("bounded V17 AOT")
            .as_bytes()[..8],
        b"FREA64\0\x1e"
    );
    assert_ne!(v17.code(), v16.code());
    assert_ne!(v17.artifact_identity(), v16.artifact_identity());
    audit(&v17).expect("independent V17 learned-continuation template");

    let decoded = decode(v17.code()).expect("V17 continuation decode");
    assert!(
        !decoded.iter().any(|instruction| {
            *instruction
                == DecodedInstruction::MoveZero64 {
                    destination: 11,
                    immediate: 2,
                    shift: 0,
                }
        }),
        "V17 must not contain the learned-disabled state transition"
    );
    let learned_byte = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::DuplicateByte16 {
                    destination: 24,
                    source: 13,
                }
        })
        .expect("V17 learned byte");
    let learned_offset = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::DuplicateByte16 {
                    destination: 25,
                    source: 11,
                }
        })
        .expect("V17 learned offset");
    assert_eq!(learned_offset, learned_byte + 1);
    let candidate_miss = decoded
        .windows(5)
        .position(|window| {
            window[0]
                == DecodedInstruction::SubtractImmediate64 {
                    destination: 10,
                    source: 0,
                    immediate: 1,
                }
                && window[1]
                    == DecodedInstruction::AndRegister64 {
                        destination: 0,
                        left: 0,
                        right: 10,
                    }
                && matches!(
                    window[2],
                    DecodedInstruction::CompareBranchZero64 {
                        register: 11,
                        nonzero: false,
                        ..
                    }
                )
                && matches!(
                    window[3],
                    DecodedInstruction::CompareBranchZero64 {
                        register: 0,
                        nonzero: true,
                        ..
                    }
                )
                && matches!(window[4], DecodedInstruction::Branch { .. })
        })
        .expect("V17 candidate-miss continuation gate");

    let manifest = v17.search_manifest().expect("V17 selected offsets");
    let selected = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ];
    let unselected = (0_u16..u16::try_from(literal.len()).expect("small literal"))
        .filter(|offset| !selected.contains(offset))
        .collect::<Vec<_>>();
    assert!(unselected.len() >= 2);
    let learned_mutation = usize::from(unselected[0]);
    let later_mutation = usize::from(unselected[1]);
    let mut first_near_miss = literal;
    first_near_miss[learned_mutation] = literal[learned_mutation].wrapping_add(1);
    let mut later_near_miss = literal;
    later_near_miss[later_mutation] = literal[later_mutation].wrapping_add(1);
    let mut haystack = Vec::new();
    // Candidate zero takes the frozen first-candidate path. The second copy
    // reaches ordinary recovery and teaches `learned_mutation`; every later
    // copy matches that newly learned column but misses at `later_mutation`.
    haystack.extend_from_slice(&first_near_miss);
    haystack.extend_from_slice(&first_near_miss);
    for _ in 0..96 {
        haystack.extend_from_slice(&later_near_miss);
    }
    haystack.extend_from_slice(&literal);
    let expected = program
        .execute(
            &haystack,
            SearchWindow::new(0, haystack.len()),
            ExecutionLimits::unlimited(),
        )
        .expect("V17 traced oracle")
        .output()
        .map(|span| (span.start(), span.end()));
    let (actual, trace) = simulate_with_instruction_trace(&v17, &haystack, 0, haystack.len())
        .expect("V17 traced safe ISA simulation");
    assert_eq!(span_output(actual), expected);
    assert_eq!(
        trace.iter().filter(|&&index| index == learned_byte).count(),
        1,
        "the mismatch column is learned once"
    );
    assert!(
        trace
            .iter()
            .filter(|&&index| index == candidate_miss)
            .count()
            >= 32,
        "many later exact misses must return through the same active learned gate"
    );
    let learned_block_probe = decoded
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (*instruction
                == DecodedInstruction::MoveVectorByteTo32 {
                    destination: 10,
                    source: 25,
                })
            .then_some(index)
        })
        .nth(1)
        .expect("V17 subsequent learned-block probe");
    assert!(
        trace
            .iter()
            .filter(|&&index| index == learned_block_probe)
            .count()
            >= 32,
        "later blocks must continue probing the retained learned column"
    );

    let DecodedInstruction::CompareBranchZero64 {
        register,
        displacement,
        ..
    } = decoded[candidate_miss + 3]
    else {
        unreachable!("selected V17 active-mask branch")
    };
    let mut inverted_continuation = v17.clone();
    replace_test_branch_and_relocation_at(
        &mut inverted_continuation,
        candidate_miss + 3,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: false,
            displacement,
        },
    );
    assert_resealed_search_rejected(
        inverted_continuation,
        "V17 active retained-mask continuation inversion",
    );

    let mut v17_as_v16 = v17;
    v17_as_v16.backend_version = BackendVersion::SEARCH_V16;
    v17_as_v16
        .search
        .as_mut()
        .expect("V17 manifest")
        .backend_version = BackendVersion::SEARCH_V16;
    assert_resealed_search_rejected(v17_as_v16, "V17 code resealed as V16");

    let mut v16_as_v17 = v16;
    v16_as_v17.backend_version = BackendVersion::SEARCH_V17;
    v16_as_v17
        .search
        .as_mut()
        .expect("V16 manifest")
        .backend_version = BackendVersion::SEARCH_V17;
    assert_resealed_search_rejected(v16_as_v17, "V16 code resealed as V17");
}

#[test]
fn v18_wide_screen_applies_third_filter_before_narrow_fallback() {
    let literal = [11_u8, 37, 63, 89, 115, 141, 167, 193, 219, 245, 17, 43, 69];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V18 wide-third IR");
    let v17 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV17,
        EmitLimits::default(),
    )
    .expect("frozen V17 permanent-narrow image");
    let v18 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV18,
        EmitLimits::default(),
    )
    .expect("V18 wide-third image");
    audit(&v18).expect("independent V18 wide-third template");

    let manifest = v18.search_manifest().expect("V18 selected offsets");
    let primary = usize::from(manifest.primary_offset);
    let secondary = usize::from(manifest.secondary_offset);
    let verification = usize::from(manifest.verification_offset);
    let candidate = 7_usize;
    let mut haystack = vec![0_u8; 2_048];
    haystack[candidate + primary] = literal[primary];
    haystack[candidate + secondary] = literal[secondary];
    assert_eq!(haystack[candidate + verification], 0);
    assert_ne!(literal[verification], 0);

    let expected = program
        .execute(
            &haystack,
            SearchWindow::new(0, haystack.len()),
            ExecutionLimits::unlimited(),
        )
        .expect("V18 wide-third oracle")
        .output()
        .map(|span| (span.start(), span.end()));
    let (actual_v17, trace_v17) =
        simulate_with_instruction_trace(&v17, &haystack, 0, haystack.len())
            .expect("frozen V17 permanent-narrow trace");
    let (actual_v18, trace_v18) =
        simulate_with_instruction_trace(&v18, &haystack, 0, haystack.len())
            .expect("V18 wide-third trace");
    assert_eq!(span_output(actual_v17), expected);
    assert_eq!(span_output(actual_v18), expected);

    let wide_load = DecodedInstruction::LoadVectorPair128 {
        first_destination: 0,
        second_destination: 2,
        base: 15,
        offset: 0,
    };
    let decoded_v17 = decode(v17.code()).expect("frozen V17 witness decode");
    let decoded_v18 = decode(v18.code()).expect("V18 wide-third witness decode");
    let wide_v17 = decoded_v17
        .iter()
        .position(|instruction| *instruction == wide_load)
        .expect("V17 wide entry");
    let wide_v18 = decoded_v18
        .iter()
        .position(|instruction| *instruction == wide_load)
        .expect("V18 wide entry");
    assert_eq!(
        trace_v17
            .iter()
            .filter(|&&instruction| instruction == wide_v17)
            .count(),
        1,
        "V17 retains its frozen permanent-narrow behavior"
    );
    assert!(
        trace_v18
            .iter()
            .filter(|&&instruction| instruction == wide_v18)
            .count()
            >= 2,
        "V18 must revisit the 64-candidate screen after the third column eliminates the pair"
    );

    let third_wide_filter = decoded_v18
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::CompareEqualBytes16 {
                    destination: 18,
                    left: 18,
                    right: 5,
                }
        })
        .expect("V18 wide third filter");
    let narrow_load = DecodedInstruction::LoadVector128 {
        destination: 0,
        base: 15,
        offset: 0,
    };
    let narrow_v17 = decoded_v17
        .iter()
        .position(|instruction| *instruction == narrow_load)
        .expect("V17 narrow entry");
    let narrow_v18 = decoded_v18
        .iter()
        .position(|instruction| *instruction == narrow_load)
        .expect("V18 narrow entry");
    assert_eq!(
        narrow_v18, narrow_v17,
        "V18 keeps the frozen V17 narrow-loop placement"
    );
    assert!(
        third_wide_filter < narrow_v18,
        "V18's optional third-wide policy stays adjacent to the wide screen"
    );
    assert!(
        !decoded_v17[..narrow_v17].iter().any(|instruction| {
            *instruction
                == DecodedInstruction::CompareEqualBytes16 {
                    destination: 18,
                    left: 18,
                    right: 5,
                }
        }),
        "V17 retains its frozen pair-only wide screen"
    );
    let wide_advance = decoded_v18
        .windows(2)
        .position(|window| {
            window[0]
                == DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 64,
                }
                && window[1]
                    == DecodedInstruction::AddImmediate64 {
                        destination: 15,
                        source: 15,
                        immediate: 64,
                    }
        })
        .expect("V18 wide advance");
    let empty_third = decoded_v18[third_wide_filter..]
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 10,
                    nonzero: false,
                    ..
                }
            )
        })
        .map(|offset| third_wide_filter + offset)
        .expect("V18 wide third-filter empty edge");
    let DecodedInstruction::CompareBranchZero64 {
        register,
        displacement,
        ..
    } = decoded_v18[empty_third]
    else {
        unreachable!("selected V18 third-filter branch")
    };
    let target = i64::try_from(empty_third)
        .expect("small V18 graph")
        .checked_mul(4)
        .and_then(|address| address.checked_add(i64::from(displacement)))
        .and_then(|address| usize::try_from(address / 4).ok())
        .expect("bounded V18 wide-empty target");
    assert_eq!(target, wide_advance);

    let mut inverted_empty = v18;
    replace_test_branch_and_relocation_at(
        &mut inverted_empty,
        empty_third,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: true,
            displacement,
        },
    );
    assert_resealed_search_rejected(inverted_empty, "V18 wide third-filter empty-edge inversion");
}

#[test]
fn v18_bounded_deterministic_fuzz_matches_the_kir_oracle() {
    let mut state = 0x86a3_5b19_d20f_47c1_u64;
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V18 width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V18 fuzz IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV18,
            EmitLimits::default(),
        )
        .expect("V18 fuzz image");
        audit(&image).expect("V18 fuzz image audit");
        let manifest = image.search_manifest().expect("V18 fuzz manifest");
        let selected = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ]
        .map(usize::from);
        let unselected = (0..width)
            .filter(|offset| !selected.contains(offset))
            .collect::<Vec<_>>();
        assert!(!unselected.is_empty());
        let avoid = (0_u16..=255)
            .map(|value| u8::try_from(value).expect("bounded byte"))
            .find(|byte| !literal.contains(byte))
            .expect("V18 fuzz literal leaves an avoiding byte");

        for case in 0..8_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mutation_offset =
                unselected[usize::try_from(state).expect("host usize") % unselected.len()];
            let mut near_miss = literal.clone();
            near_miss[mutation_offset] = literal[(mutation_offset + 1) % width];
            let prefix = usize::try_from(state >> 8).expect("host usize") & 15;
            let repetitions = 5 + (usize::try_from(state >> 16).expect("host usize") % 37);
            let mut haystack = vec![avoid; prefix];
            for _ in 0..repetitions {
                haystack.extend_from_slice(&near_miss);
            }
            if case & 1 == 0 {
                haystack.extend_from_slice(&literal);
            } else {
                haystack.extend_from_slice(&near_miss);
            }
            for (start, end) in [
                (0, haystack.len()),
                (prefix.min(haystack.len()), haystack.len()),
                (0, haystack.len().saturating_sub(case & 1)),
            ] {
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(start, end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V18 fuzz oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual =
                    simulate(&image, &haystack, start, end).expect("V18 fuzz safe ISA simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} case={case} mutation={mutation_offset} window={start}..{end}"
                );
                comparisons = comparisons.checked_add(1).expect("bounded fuzz matrix");
            }
        }
    }
    assert_eq!(comparisons, 648);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V19 structural gate binds its wire, fixed four-mask conversion, shared queue/verifier, restoration, and mutation rejection in one reviewable proof"
)]
fn v19_saved_mask_graph_is_distinct_exact_and_independently_audited() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V19 structural IR");
    let v17 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV17,
        EmitLimits::default(),
    )
    .expect("frozen V17 image");
    let v19 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV19,
        EmitLimits::default(),
    )
    .expect("V19 saved-mask image");
    audit(&v19).expect("independent V19 saved-mask template");
    assert_eq!(v19.backend_version(), BackendVersion::SEARCH_V19);
    assert_eq!(
        &v19.to_aot(AotLimits::default())
            .expect("bounded V19 AOT")
            .as_bytes()[..8],
        b"FREA64\0\x20"
    );
    assert_ne!(v19.code(), v17.code());
    assert_ne!(v19.artifact_identity(), v17.artifact_identity());
    let v17_manifest = v17.search_manifest().expect("V17 manifest");
    let v19_manifest = v19.search_manifest().expect("V19 manifest");
    assert_eq!(v19_manifest.candidate_policy_version, 15);
    assert_eq!(
        (
            v19_manifest.primary_offset,
            v19_manifest.secondary_offset,
            v19_manifest.verification_offset,
            v19_manifest.quaternary_offset,
            v19_manifest.quinary_offset,
        ),
        (
            v17_manifest.primary_offset,
            v17_manifest.secondary_offset,
            v17_manifest.verification_offset,
            v17_manifest.quaternary_offset,
            v17_manifest.quinary_offset,
        ),
        "V19 reuses the frozen phase-unique V17 selector"
    );

    let decoded = decode(v19.code()).expect("V19 structural decode");
    let conversions = [(0_u8, 0_u8), (2, 1), (4, 2), (6, 3)];
    let conversion_starts = decoded
        .windows(12)
        .enumerate()
        .filter_map(|(start, window)| {
            conversions
                .iter()
                .enumerate()
                .all(|(ordinal, &(source, destination))| {
                    let base = ordinal * 3;
                    window[base]
                        == DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                            destination: 16,
                            source,
                        }
                        && window[base + 1]
                            == DecodedInstruction::MoveVectorDoubleTo64 {
                                destination,
                                source: 16,
                            }
                        && window[base + 2]
                            == DecodedInstruction::AndRegister64 {
                                destination,
                                left: destination,
                                right: 14,
                            }
                })
                .then_some(start)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        conversion_starts.len(),
        1,
        "exactly one Q0/Q2/Q4/Q6 to X0/X1/X2/X3 conversion site"
    );
    let saved = conversion_starts[0];
    assert_eq!(
        decoded[saved + 12],
        DecodedInstruction::MoveRegister64 {
            destination: 7,
            source: 5,
        }
    );
    assert_eq!(
        decoded[saved + 13],
        DecodedInstruction::MoveZero64 {
            destination: 11,
            immediate: 4,
            shift: 0,
        }
    );

    let branch_target = |index: usize| {
        let displacement = match decoded[index] {
            DecodedInstruction::Branch { displacement }
            | DecodedInstruction::BranchCondition { displacement, .. }
            | DecodedInstruction::CompareBranchZero64 { displacement, .. } => displacement,
            _ => panic!("instruction {index} is not a V19 branch"),
        };
        let address = i64::try_from(index)
            .expect("small V19 graph")
            .checked_mul(4)
            .and_then(|address| address.checked_add(i64::from(displacement)))
            .expect("bounded V19 branch target");
        assert_eq!(address % 4, 0);
        usize::try_from(address / 4).expect("nonnegative V19 branch target")
    };
    let saved_entries = decoded
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 10,
                    nonzero: true,
                    ..
                }
            )
            .then(|| branch_target(index))
            .filter(|&target| target == saved)
            .map(|_| index)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        saved_entries.len(),
        1,
        "primary-first pair hits enter the one saved-mask site"
    );

    let reset = decoded[saved..]
        .windows(3)
        .position(|window| {
            window[0]
                == DecodedInstruction::MoveZero64 {
                    destination: 11,
                    immediate: 0,
                    shift: 0,
                }
                && window[1]
                    == DecodedInstruction::AddImmediate64 {
                        destination: 5,
                        source: 7,
                        immediate: 16,
                    }
                && window[2]
                    == DecodedInstruction::AddRegister64 {
                        destination: 15,
                        left: 9,
                        right: 5,
                    }
        })
        .map(|offset| saved + offset)
        .expect("V19 saved-mask restoration");
    let saved_graph = &decoded[saved..reset];
    assert_eq!(
        saved_graph
            .iter()
            .filter(|instruction| {
                **instruction
                    == DecodedInstruction::ReverseBits64 {
                        destination: 10,
                        source: 0,
                    }
            })
            .count(),
        1,
        "all four blocks share one lane selector and exact verifier"
    );
    assert_eq!(
        saved_graph
            .windows(3)
            .filter(|window| {
                *window
                    == [
                        DecodedInstruction::MoveRegister64 {
                            destination: 0,
                            source: 1,
                        },
                        DecodedInstruction::MoveRegister64 {
                            destination: 1,
                            source: 2,
                        },
                        DecodedInstruction::MoveRegister64 {
                            destination: 2,
                            source: 3,
                        },
                    ]
            })
            .count(),
        1,
        "the queue has exactly one fixed destructive X1/X2/X3 shift"
    );
    assert!(
        !saved_graph.iter().any(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::LoadVectorPair128 { .. }
                    | DecodedInstruction::DuplicateByte16 { .. }
                    | DecodedInstruction::CompareEqualBytes16 {
                        right: 1 | 3 | 5 | 7 | 23,
                        ..
                    }
            )
        }),
        "saved recovery must not reload or recompute any screening column"
    );

    let queue_shift = saved_graph
        .windows(3)
        .position(|window| {
            window[0]
                == DecodedInstruction::MoveRegister64 {
                    destination: 0,
                    source: 1,
                }
                && window[1]
                    == DecodedInstruction::MoveRegister64 {
                        destination: 1,
                        source: 2,
                    }
                && window[2]
                    == DecodedInstruction::MoveRegister64 {
                        destination: 2,
                        source: 3,
                    }
        })
        .map(|offset| saved + offset)
        .expect("V19 fixed queue shift");
    let mut queue_mutation = v19.clone();
    replace_test_decoded_at(
        &mut queue_mutation,
        queue_shift + 1,
        DecodedInstruction::MoveRegister64 {
            destination: 1,
            source: 3,
        },
    );
    assert_resealed_search_rejected(queue_mutation, "V19 reordered saved-mask queue");

    let mut v19_as_v17 = v19.clone();
    v19_as_v17.backend_version = BackendVersion::SEARCH_V17;
    v19_as_v17
        .search
        .as_mut()
        .expect("V19 manifest")
        .backend_version = BackendVersion::SEARCH_V17;
    assert_resealed_search_rejected(v19_as_v17, "V19 code resealed as V17");

    let mut v17_as_v19 = v17;
    v17_as_v19.backend_version = BackendVersion::SEARCH_V19;
    v17_as_v19
        .search
        .as_mut()
        .expect("V17 manifest")
        .backend_version = BackendVersion::SEARCH_V19;
    assert_resealed_search_rejected(v17_as_v19, "V17 code resealed as V19");
}

#[test]
fn v19_saved_masks_cover_every_lane_block_and_false_survivor_shape() {
    let literal = [11_u8, 37, 63, 89, 115, 141, 167, 193, 219, 245, 17, 43, 69];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V19 four-block IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV19,
        EmitLimits::default(),
    )
    .expect("V19 four-block image");
    audit(&image).expect("V19 four-block image audit");
    let manifest = image.search_manifest().expect("V19 four-block manifest");
    let primary = usize::from(manifest.primary_offset);
    let secondary = usize::from(manifest.secondary_offset);
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded byte"))
        .find(|byte| !literal.contains(byte))
        .expect("V19 literal leaves an avoiding byte");
    let window_start = 3_usize;
    let wide_base = window_start + 1;

    for block in 0..4_usize {
        for lane in 0..16_usize {
            let candidate = wide_base + block * 16 + lane;
            let mut haystack = vec![avoid; 160];
            haystack[candidate..candidate + literal.len()].copy_from_slice(&literal);
            let expected = program
                .execute(
                    &haystack,
                    SearchWindow::new(window_start, haystack.len()),
                    ExecutionLimits::unlimited(),
                )
                .expect("V19 lane/block oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual = simulate(&image, &haystack, window_start, haystack.len())
                .expect("V19 lane/block simulation");
            assert_eq!(span_output(actual), expected, "block={block} lane={lane}");
            assert_eq!(expected, Some((candidate, candidate + literal.len())));
        }
    }

    let scenarios: &[(&[usize], Option<usize>)] = &[
        (&[0, 2, 14, 33, 35, 47], Some(63)),
        (&[0, 7, 32, 46], None),
        (&[17, 18, 31], Some(55)),
        (&[15, 16, 31, 32, 47, 48, 61], Some(62)),
    ];
    for (scenario, &(false_offsets, exact_offset)) in scenarios.iter().enumerate() {
        let mut haystack = vec![avoid; 160];
        for &offset in false_offsets {
            let candidate = wide_base + offset;
            haystack[candidate + primary] = literal[primary];
            haystack[candidate + secondary] = literal[secondary];
        }
        if let Some(offset) = exact_offset {
            let candidate = wide_base + offset;
            haystack[candidate..candidate + literal.len()].copy_from_slice(&literal);
        }
        let expected = program
            .execute(
                &haystack,
                SearchWindow::new(window_start, haystack.len()),
                ExecutionLimits::unlimited(),
            )
            .expect("V19 survivor-shape oracle")
            .output()
            .map(|span| (span.start(), span.end()));
        let actual = simulate(&image, &haystack, window_start, haystack.len())
            .expect("V19 survivor-shape simulation");
        assert_eq!(
            span_output(actual),
            expected,
            "false-survivor scenario={scenario}"
        );
        assert_eq!(
            expected,
            exact_offset.map(|offset| {
                let start = wide_base + offset;
                (start, start + literal.len())
            })
        );
    }
}

#[test]
fn v19_every_width_and_window_shape_matches_the_kir_oracle() {
    let mut state = 0xa6f3_917c_42de_580b_u64;
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V19 width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V19 every-width IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV19,
            EmitLimits::default(),
        )
        .expect("V19 every-width image");
        audit(&image).expect("V19 every-width image audit");
        let manifest = image.search_manifest().expect("V19 every-width manifest");
        let primary = usize::from(manifest.primary_offset);
        let secondary = usize::from(manifest.secondary_offset);

        for case in 0..8_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let hay_len = 112 + usize::try_from(state >> 24).expect("host usize") % 97;
            let mut haystack = Vec::with_capacity(hay_len);
            for _ in 0..hay_len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                haystack.push(state.to_le_bytes()[0]);
            }

            for offset in [1_usize, 17, 34, 63] {
                if offset + secondary.max(primary) < haystack.len() {
                    haystack[offset + primary] = literal[primary];
                    haystack[offset + secondary] = literal[secondary];
                }
            }
            let exact = (case & 1 == 0).then(|| {
                5 + (usize::try_from(state >> 8).expect("host usize")
                    % (haystack.len() - width - 5))
            });
            if let Some(candidate) = exact {
                haystack[candidate..candidate + width].copy_from_slice(&literal);
            }

            let random_start =
                usize::try_from(state >> 16).expect("host usize") % (haystack.len() + 1);
            let random_end = random_start
                + (usize::try_from(state >> 32).expect("host usize")
                    % (haystack.len() - random_start + 1));
            let short_end = width.saturating_sub(1).min(haystack.len());
            let exact_window = exact
                .map(|candidate| (candidate, candidate + width))
                .unwrap_or((random_start, random_end));
            let windows = [
                (0, 0),
                (0, short_end),
                (0, haystack.len()),
                (random_start, haystack.len()),
                (random_start, random_end),
                exact_window,
            ];
            for (start, end) in windows {
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(start, end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V19 every-width oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, &haystack, start, end)
                    .expect("V19 every-width safe ISA simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} case={case} window={start}..{end}"
                );
                comparisons = comparisons.checked_add(1).expect("bounded V19 matrix");
            }
        }
    }
    assert_eq!(comparisons, 1_296);
}

#[test]
fn v20_pair_empty_switches_to_secondary_only_then_refines_a_real_pair() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V20 explicit-edge IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV20,
        EmitLimits::default(),
    )
    .expect("V20 explicit-edge image");
    audit(&image).expect("V20 explicit-edge independent template");
    let manifest = image.search_manifest().expect("V20 explicit-edge manifest");
    let selected = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ]
    .map(usize::from);
    assert_eq!(selected.iter().copied().collect::<BTreeSet<_>>().len(), 5);
    let [primary, secondary, verification, _, _] = selected;
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded avoiding byte"))
        .find(|byte| !literal.contains(byte))
        .expect("literal leaves an avoiding byte");

    // The exact first-candidate miss advances the wide base from zero to one.
    // Group zero has a primary hit but no secondary hit, selecting
    // secondary-only for group one. Group one's real pair then reaches the
    // shared remaining-column block.
    let first_wide_base = 1_usize;
    let secondary_only_base = first_wide_base + 64;
    let resumed_primary_base = secondary_only_base + 64;
    let group_zero_primary = first_wide_base + 7;
    let group_one_candidate = secondary_only_base + 11;
    let group_two_candidate = resumed_primary_base + 13;

    let mut exact_in_secondary_only = vec![avoid; 240];
    exact_in_secondary_only[group_zero_primary + primary] = literal[primary];
    exact_in_secondary_only[group_one_candidate..group_one_candidate + literal.len()]
        .copy_from_slice(literal);
    let secondary_result = simulate(&image, &exact_in_secondary_only, 0, 240)
        .expect("V20 secondary-only real-pair simulation");
    assert_eq!(
        span_output(secondary_result),
        Some((group_one_candidate, group_one_candidate + literal.len()))
    );

    // The same reachable edge with only the pair present must be eliminated by
    // the first remaining column, resume primary-first at group two, and find
    // the later exact match. This also proves a primary-empty group never
    // spuriously enters secondary-only: only a primary-present/pair-empty
    // group selects that state.
    let mut third_column_empty = vec![avoid; 240];
    third_column_empty[group_zero_primary + primary] = literal[primary];
    third_column_empty[group_one_candidate + primary] = literal[primary];
    third_column_empty[group_one_candidate + secondary] = literal[secondary];
    assert_eq!(
        third_column_empty[group_one_candidate + verification],
        avoid
    );
    third_column_empty[group_two_candidate..group_two_candidate + literal.len()]
        .copy_from_slice(literal);
    let resumed_result = simulate(&image, &third_column_empty, 0, 240)
        .expect("V20 third-column-empty resumed simulation");
    assert_eq!(
        span_output(resumed_result),
        Some((group_two_candidate, group_two_candidate + literal.len()))
    );
}

#[test]
fn v21_and_v22_preserve_primary_present_pair_empty_secondary_only_transitions() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V21/V22 explicit-edge IR");
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded avoiding byte"))
        .find(|byte| !literal.contains(byte))
        .expect("literal leaves an avoiding byte");

    for policy in [SearchBackendPolicy::AsimdV21, SearchBackendPolicy::AsimdV22] {
        let image = emit_with_backend(&program, policy, EmitLimits::default())
            .expect("V21/V22 explicit-edge image");
        audit(&image).expect("V21/V22 explicit-edge independent template");
        let manifest = image
            .search_manifest()
            .expect("V21/V22 explicit-edge manifest");
        let selected = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ]
        .map(usize::from);
        assert_eq!(selected.iter().copied().collect::<BTreeSet<_>>().len(), 5);
        let [primary, secondary, verification, _, _] = selected;

        let first_wide_base = 1_usize;
        let secondary_only_base = first_wide_base + 64;
        let resumed_primary_base = secondary_only_base + 64;
        let group_zero_primary = first_wide_base + 7;
        let group_one_candidate = secondary_only_base + 11;
        let group_two_candidate = resumed_primary_base + 13;

        let mut exact_in_secondary_only = vec![avoid; 240];
        exact_in_secondary_only[group_zero_primary + primary] = literal[primary];
        exact_in_secondary_only[group_one_candidate..group_one_candidate + literal.len()]
            .copy_from_slice(literal);
        let secondary_result = simulate(&image, &exact_in_secondary_only, 0, 240)
            .expect("V21/V22 secondary-only real-pair simulation");
        assert_eq!(
            span_output(secondary_result),
            Some((group_one_candidate, group_one_candidate + literal.len())),
            "policy={policy:?}"
        );

        // A real primary/secondary pair that fails the next authenticated
        // column resumes the primary-first graph. It must not enter learning,
        // whose precondition is a complete five-column survivor.
        let mut third_column_empty = vec![avoid; 240];
        third_column_empty[group_zero_primary + primary] = literal[primary];
        third_column_empty[group_one_candidate + primary] = literal[primary];
        third_column_empty[group_one_candidate + secondary] = literal[secondary];
        assert_eq!(
            third_column_empty[group_one_candidate + verification],
            avoid
        );
        third_column_empty[group_two_candidate..group_two_candidate + literal.len()]
            .copy_from_slice(literal);
        let resumed_result = simulate(&image, &third_column_empty, 0, 240)
            .expect("V21/V22 third-column-empty resumed simulation");
        assert_eq!(
            span_output(resumed_result),
            Some((group_two_candidate, group_two_candidate + literal.len())),
            "policy={policy:?}"
        );
    }
}

#[test]
fn v20_dense_pair_preserving_streams_are_filtered_at_each_remaining_column() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V20 dense-refinement IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV20,
        EmitLimits::default(),
    )
    .expect("V20 dense-refinement image");
    audit(&image).expect("V20 dense-refinement independent template");
    let manifest = image
        .search_manifest()
        .expect("V20 dense-refinement manifest");
    let remaining = [
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ]
    .map(usize::from);
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded avoiding byte"))
        .find(|byte| !literal.contains(byte))
        .expect("literal leaves an avoiding byte");

    for (stage, mutation) in remaining.into_iter().enumerate() {
        let mut near_miss = *literal;
        near_miss[mutation] = avoid;
        let mut haystack = Vec::with_capacity(literal.len() * 17);
        for _ in 0..16 {
            haystack.extend_from_slice(&near_miss);
        }
        let exact = haystack.len();
        haystack.extend_from_slice(literal);
        let expected = program
            .execute(
                &haystack,
                SearchWindow::new(0, haystack.len()),
                ExecutionLimits::unlimited(),
            )
            .expect("V20 dense-refinement oracle")
            .output()
            .map(|span| (span.start(), span.end()));
        let actual = simulate(&image, &haystack, 0, haystack.len())
            .expect("V20 dense-refinement safe ISA simulation");
        assert_eq!(expected, Some((exact, exact + literal.len())));
        assert_eq!(span_output(actual), expected, "remaining stage={stage}");
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V20 structural gate freezes its exact wide-refinement instruction model, explicit entries, wire, code size, and mutation rejection"
)]
fn v20_wide_refinement_matches_the_preregistered_instruction_model() {
    const REFINEMENT_INSTRUCTIONS: usize = 46;
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V20 structural IR");
    let v17 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV17,
        EmitLimits::default(),
    )
    .expect("frozen V17 structural image");
    let v19 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV19,
        EmitLimits::default(),
    )
    .expect("frozen V19 structural image");
    let v20 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV20,
        EmitLimits::default(),
    )
    .expect("V20 structural image");
    audit(&v20).expect("independent V20 structural template");
    assert_eq!(v20.backend_version(), BackendVersion::SEARCH_V20);
    assert_eq!(
        &v20.to_aot(AotLimits::default())
            .expect("bounded V20 AOT")
            .as_bytes()[..8],
        b"FREA64\0\x21"
    );
    assert_eq!(
        v20.code().len().checked_sub(v19.code().len()),
        Some(192),
        "three columns, one intermediate checkpoint, explicit final edges, and two explicit entries"
    );
    assert!(v20.code().len() <= 1_792);
    assert_ne!(v20.artifact_identity(), v19.artifact_identity());
    assert_ne!(v20.artifact_identity(), v17.artifact_identity());
    let v17_manifest = v17.search_manifest().expect("V17 structural manifest");
    let v20_manifest = v20.search_manifest().expect("V20 structural manifest");
    assert_eq!(
        (
            v20_manifest.primary_offset,
            v20_manifest.secondary_offset,
            v20_manifest.verification_offset,
            v20_manifest.quaternary_offset,
            v20_manifest.quinary_offset,
        ),
        (
            v17_manifest.primary_offset,
            v17_manifest.secondary_offset,
            v17_manifest.verification_offset,
            v17_manifest.quaternary_offset,
            v17_manifest.quinary_offset,
        ),
        "V20 reuses the frozen phase-unique V17 selector"
    );

    let decoded = decode(v20.code()).expect("V20 structural decode");
    let conversions = [(0_u8, 0_u8), (2, 1), (4, 2), (6, 3)];
    let saved_starts = decoded
        .windows(12)
        .enumerate()
        .filter_map(|(start, window)| {
            conversions
                .iter()
                .enumerate()
                .all(|(ordinal, &(source, destination))| {
                    let base = ordinal * 3;
                    window[base]
                        == DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                            destination: 16,
                            source,
                        }
                        && window[base + 1]
                            == DecodedInstruction::MoveVectorDoubleTo64 {
                                destination,
                                source: 16,
                            }
                        && window[base + 2]
                            == DecodedInstruction::AndRegister64 {
                                destination,
                                left: destination,
                                right: 14,
                            }
                })
                .then_some(start)
        })
        .collect::<Vec<_>>();
    assert_eq!(saved_starts.len(), 1);
    let saved = saved_starts[0];
    let remaining_start = saved
        .checked_sub(REFINEMENT_INSTRUCTIONS)
        .expect("V20 refinement precedes conversion");
    let refinement = &decoded[remaining_start..saved];
    assert_eq!(
        refinement
            .iter()
            .filter(|instruction| matches!(
                instruction,
                DecodedInstruction::LoadVectorPair128 { .. }
            ))
            .count(),
        6
    );
    for constant in [5_u8, 7, 23] {
        assert_eq!(
            refinement
                .iter()
                .filter(|instruction| matches!(
                    instruction,
                    DecodedInstruction::CompareEqualBytes16 { right, .. } if *right == constant
                ))
                .count(),
            4,
            "four blocks use Q{constant}"
        );
    }
    assert_eq!(
        refinement
            .iter()
            .filter(|instruction| matches!(instruction, DecodedInstruction::AndBytes16 { .. }))
            .count(),
        12
    );
    assert_eq!(
        refinement
            .iter()
            .filter(|instruction| matches!(
                instruction,
                DecodedInstruction::UnsignedMaxPairwiseBytes16 { .. }
            ))
            .count(),
        8
    );
    assert_eq!(
        refinement
            .iter()
            .filter(|instruction| matches!(
                instruction,
                DecodedInstruction::MoveVectorDoubleTo64 {
                    destination: 10,
                    source: 16
                }
            ))
            .count(),
        2
    );
    assert_eq!(
        refinement
            .iter()
            .filter(|instruction| matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 10,
                    nonzero: false,
                    ..
                }
            ))
            .count(),
        2
    );

    let branch_target = |index: usize| {
        let displacement = match decoded[index] {
            DecodedInstruction::Branch { displacement }
            | DecodedInstruction::BranchCondition { displacement, .. }
            | DecodedInstruction::CompareBranchZero64 { displacement, .. } => displacement,
            _ => panic!("instruction {index} is not a V20 branch"),
        };
        let address = i64::try_from(index)
            .expect("small V20 graph")
            .checked_mul(4)
            .and_then(|address| address.checked_add(i64::from(displacement)))
            .expect("bounded V20 branch target");
        assert_eq!(address % 4, 0);
        usize::try_from(address / 4).expect("nonnegative V20 branch target")
    };
    let explicit_entries = decoded[..remaining_start]
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            matches!(instruction, DecodedInstruction::Branch { .. })
                .then(|| branch_target(index))
                .filter(|&target| target == remaining_start)
                .map(|_| index)
        })
        .collect::<Vec<_>>();
    assert_eq!(explicit_entries.len(), 2);
    for entry in explicit_entries {
        assert!(matches!(
            decoded[entry - 1],
            DecodedInstruction::CompareBranchZero64 {
                register: 10,
                nonzero: false,
                ..
            }
        ));
    }
    assert!(matches!(
        decoded[saved - 2],
        DecodedInstruction::CompareBranchZero64 {
            register: 10,
            nonzero: false,
            ..
        }
    ));
    assert!(matches!(
        decoded[saved - 1],
        DecodedInstruction::Branch { .. }
    ));
    assert_eq!(branch_target(saved - 1), saved);

    let first_refinement_and = refinement
        .iter()
        .position(|instruction| matches!(instruction, DecodedInstruction::AndBytes16 { .. }))
        .map(|offset| remaining_start + offset)
        .expect("V20 wide refinement AND");
    let mut bypassed_refinement = v20.clone();
    replace_test_decoded_at(
        &mut bypassed_refinement,
        first_refinement_and,
        DecodedInstruction::AndBytes16 {
            destination: 0,
            left: 0,
            right: 0,
        },
    );
    assert_resealed_search_rejected(
        bypassed_refinement,
        "V20 bypassed one authenticated wide refinement",
    );

    let mut v20_as_v19 = v20.clone();
    v20_as_v19.backend_version = BackendVersion::SEARCH_V19;
    v20_as_v19
        .search
        .as_mut()
        .expect("V20 manifest")
        .backend_version = BackendVersion::SEARCH_V19;
    assert_resealed_search_rejected(v20_as_v19, "V20 code resealed as V19");

    let mut v19_as_v20 = v19;
    v19_as_v20.backend_version = BackendVersion::SEARCH_V20;
    v19_as_v20
        .search
        .as_mut()
        .expect("V19 manifest")
        .backend_version = BackendVersion::SEARCH_V20;
    assert_resealed_search_rejected(v19_as_v20, "V19 code resealed as V20");
}

#[test]
fn v20_code_size_delta_is_fixed_and_bounded_across_every_gate_width() {
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V20 width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V20 size-bound IR");
        let v19 = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV19,
            EmitLimits::default(),
        )
        .expect("V19 size-bound image");
        let v20 = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV20,
            EmitLimits::default(),
        )
        .expect("V20 size-bound image");
        assert_eq!(
            v20.code().len().checked_sub(v19.code().len()),
            Some(192),
            "width={width}"
        );
        assert!(v20.code().len() <= 1_792, "width={width}");
    }
}

#[test]
fn v20_refined_saved_masks_cover_every_lane_block_and_false_survivor_shape() {
    let literal = [11_u8, 37, 63, 89, 115, 141, 167, 193, 219, 245, 17, 43, 69];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V20 four-block IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV20,
        EmitLimits::default(),
    )
    .expect("V20 four-block image");
    audit(&image).expect("V20 four-block image audit");
    let manifest = image.search_manifest().expect("V20 four-block manifest");
    let selected = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ]
    .map(usize::from);
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded byte"))
        .find(|byte| !literal.contains(byte))
        .expect("V20 literal leaves an avoiding byte");
    let window_start = 3_usize;
    let wide_base = window_start + 1;

    for block in 0..4_usize {
        for lane in 0..16_usize {
            let candidate = wide_base + block * 16 + lane;
            let mut haystack = vec![avoid; 192];
            haystack[candidate..candidate + literal.len()].copy_from_slice(&literal);
            let expected = program
                .execute(
                    &haystack,
                    SearchWindow::new(window_start, haystack.len()),
                    ExecutionLimits::unlimited(),
                )
                .expect("V20 lane/block oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual = simulate(&image, &haystack, window_start, haystack.len())
                .expect("V20 lane/block simulation");
            assert_eq!(span_output(actual), expected, "block={block} lane={lane}");
            assert_eq!(expected, Some((candidate, candidate + literal.len())));
        }
    }

    let scenarios: &[(&[usize], Option<usize>)] = &[
        (&[0, 20, 40], Some(60)),
        (&[2, 18, 34, 50], None),
        (&[0, 17], Some(51)),
        (&[1, 22, 43], Some(64)),
    ];
    for (scenario, &(false_offsets, exact_offset)) in scenarios.iter().enumerate() {
        let mut haystack = vec![avoid; 192];
        for &offset in false_offsets {
            let candidate = wide_base + offset;
            for &selected_offset in &selected {
                haystack[candidate + selected_offset] = literal[selected_offset];
            }
        }
        if let Some(offset) = exact_offset {
            let candidate = wide_base + offset;
            haystack[candidate..candidate + literal.len()].copy_from_slice(&literal);
        }
        let expected = program
            .execute(
                &haystack,
                SearchWindow::new(window_start, haystack.len()),
                ExecutionLimits::unlimited(),
            )
            .expect("V20 survivor-shape oracle")
            .output()
            .map(|span| (span.start(), span.end()));
        let actual = simulate(&image, &haystack, window_start, haystack.len())
            .expect("V20 survivor-shape simulation");
        assert_eq!(
            span_output(actual),
            expected,
            "refined false-survivor scenario={scenario}"
        );
        assert_eq!(
            expected,
            exact_offset.map(|offset| {
                let start = wide_base + offset;
                (start, start + literal.len())
            })
        );
    }
}

#[test]
fn v20_every_width_and_window_shape_matches_the_kir_oracle() {
    let mut state = 0x83c1_b75e_d2a9_460f_u64;
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V20 width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V20 every-width IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV20,
            EmitLimits::default(),
        )
        .expect("V20 every-width image");
        audit(&image).expect("V20 every-width image audit");

        for case in 0..8_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let hay_len = 112 + usize::try_from(state >> 24).expect("host usize") % 97;
            let mut haystack = Vec::with_capacity(hay_len);
            for _ in 0..hay_len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                haystack.push(state.to_le_bytes()[0]);
            }

            let exact = (case & 1 == 0).then(|| {
                5 + (usize::try_from(state >> 8).expect("host usize")
                    % (haystack.len() - width - 5))
            });
            if let Some(candidate) = exact {
                haystack[candidate..candidate + width].copy_from_slice(&literal);
            }

            let random_start =
                usize::try_from(state >> 16).expect("host usize") % (haystack.len() + 1);
            let random_end = random_start
                + (usize::try_from(state >> 32).expect("host usize")
                    % (haystack.len() - random_start + 1));
            let short_end = width.saturating_sub(1).min(haystack.len());
            let exact_window = exact
                .map(|candidate| (candidate, candidate + width))
                .unwrap_or((random_start, random_end));
            let windows = [
                (0, 0),
                (0, short_end),
                (0, haystack.len()),
                (random_start, haystack.len()),
                (random_start, random_end),
                exact_window,
            ];
            for (start, end) in windows {
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(start, end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V20 every-width oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, &haystack, start, end)
                    .expect("V20 every-width safe ISA simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} case={case} window={start}..{end}"
                );
                comparisons = comparisons.checked_add(1).expect("bounded V20 matrix");
            }
        }
    }
    assert_eq!(comparisons, 1_296);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V21 contract keeps wire identity, decoded learned-column structure, relabel resistance, and mutation rejection in one reviewable gate"
)]
fn v21_current_group_learning_is_distinct_bounded_and_independently_audited() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V21 structural IR");
    let v20 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV20,
        EmitLimits::default(),
    )
    .expect("frozen V20 structural image");
    let v21 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV21,
        EmitLimits::default(),
    )
    .expect("V21 structural image");
    let report = audit(&v21).expect("independent V21 structural template");
    assert_eq!(
        (report.decode_passes, report.source_identity_rebuilds),
        (1, 1)
    );
    assert_eq!(v21.backend_version(), BackendVersion::SEARCH_V21);
    assert_eq!(
        &v21.to_aot(AotLimits::default())
            .expect("bounded V21 AOT")
            .as_bytes()[..8],
        b"FREA64\0\x22"
    );
    assert!(v21.code().len() <= 2_304);
    assert_ne!(v21.artifact_identity(), v20.artifact_identity());

    let v20_manifest = v20.search_manifest().expect("V20 structural manifest");
    let v21_manifest = v21.search_manifest().expect("V21 structural manifest");
    assert_eq!(
        (
            v21_manifest.primary_offset,
            v21_manifest.secondary_offset,
            v21_manifest.verification_offset,
            v21_manifest.quaternary_offset,
            v21_manifest.quinary_offset,
        ),
        (
            v20_manifest.primary_offset,
            v20_manifest.secondary_offset,
            v20_manifest.verification_offset,
            v20_manifest.quaternary_offset,
            v20_manifest.quinary_offset,
        ),
        "V21 changes only current-group recovery after frozen V20 screening"
    );

    let decoded = decode(v21.code()).expect("V21 structural decode");
    let learned_dup = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::DuplicateByte16 {
                    destination: 24,
                    source: 13,
                }
        })
        .expect("V21 learned literal byte");
    let selection_conversions = decoded[..learned_dup]
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| match instruction {
            DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                destination: 16,
                source: 0 | 2 | 4 | 6,
            } => Some(index),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        selection_conversions
            .iter()
            .map(|&index| match decoded[index] {
                DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 { source, .. } => source,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>(),
        [0, 2, 4, 6],
        "V21 selects from Q0/Q2/Q4/Q6 without overwriting them"
    );
    for &index in &selection_conversions {
        assert_eq!(
            decoded[index + 1],
            DecodedInstruction::MoveVectorDoubleTo64 {
                destination: 0,
                source: 16,
            }
        );
        assert_eq!(
            decoded[index + 2],
            DecodedInstruction::AndRegister64 {
                destination: 0,
                left: 0,
                right: 14,
            }
        );
    }

    let candidate_entry = decoded[selection_conversions[3] + 3..learned_dup]
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::AddRegister64 {
                    destination: 5,
                    left: 7,
                    right: 13,
                }
        })
        .map(|offset| selection_conversions[3] + 3 + offset)
        .expect("V21 sampled-candidate entry");
    let confirmation_pointer = decoded[candidate_entry..learned_dup]
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::AddRegister64 {
                    destination: 15,
                    left: 9,
                    right: 5,
                }
        })
        .map(|offset| candidate_entry + offset)
        .expect("V21 sampled exact pointer");
    let success_publish = decoded[confirmation_pointer + 1..learned_dup]
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::MoveRegister64 {
                    destination: 13,
                    source: 5,
                }
        })
        .map(|offset| confirmation_pointer + 1 + offset)
        .expect("V21 sampled exact success publication");
    let retained_vectors = [0_u8, 2, 4, 6];
    for &instruction in &decoded[confirmation_pointer + 1..success_publish] {
        assert_ne!(
            instruction.written_gpr(),
            Some(14),
            "sampled exact confirmation must retain X14"
        );
        match instruction {
            DecodedInstruction::LoadVector128 { destination, .. }
            | DecodedInstruction::DuplicateByte16 { destination, .. }
            | DecodedInstruction::CompareEqualBytes16 { destination, .. }
            | DecodedInstruction::AndBytes16 { destination, .. }
            | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 { destination, .. }
            | DecodedInstruction::UnsignedMinBytes16 { destination, .. }
            | DecodedInstruction::UnsignedMaxBytes16 { destination, .. }
            | DecodedInstruction::UnsignedMaxPairwiseBytes16 { destination, .. }
            | DecodedInstruction::AddAcrossBytes16 { destination, .. } => {
                assert!(!retained_vectors.contains(&destination));
            }
            DecodedInstruction::LoadVectorPair128 {
                first_destination,
                second_destination,
                ..
            } => {
                assert!(!retained_vectors.contains(&first_destination));
                assert!(!retained_vectors.contains(&second_destination));
            }
            _ => {}
        }
    }
    assert_eq!(
        decoded[learned_dup + 1],
        DecodedInstruction::AddRegister64 {
            destination: 15,
            left: 9,
            right: 7,
        }
    );
    assert_eq!(
        decoded[learned_dup + 2],
        DecodedInstruction::AddRegister64 {
            destination: 15,
            left: 15,
            right: 11,
        }
    );
    assert_eq!(
        decoded[learned_dup + 3..learned_dup + 5],
        [
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
        ]
    );
    assert_eq!(
        decoded[learned_dup + 5..learned_dup + 13]
            .iter()
            .filter(|instruction| {
                matches!(
                    instruction,
                    DecodedInstruction::CompareEqualBytes16 { right: 24, .. }
                )
            })
            .count(),
        4
    );
    assert_eq!(
        decoded[learned_dup + 5..learned_dup + 13]
            .iter()
            .filter(|instruction| matches!(instruction, DecodedInstruction::AndBytes16 { .. }))
            .count(),
        4
    );

    let mut bypassed_learned_column = v21.clone();
    replace_test_decoded_at(
        &mut bypassed_learned_column,
        learned_dup,
        DecodedInstruction::DuplicateByte16 {
            destination: 24,
            source: 11,
        },
    );
    assert_resealed_search_rejected(
        bypassed_learned_column,
        "V21 learned literal source substitution",
    );

    let mut v21_as_v20 = v21.clone();
    v21_as_v20.backend_version = BackendVersion::SEARCH_V20;
    v21_as_v20
        .search
        .as_mut()
        .expect("V21 manifest")
        .backend_version = BackendVersion::SEARCH_V20;
    assert_resealed_search_rejected(v21_as_v20, "V21 code resealed as V20");

    let mut v20_as_v21 = v20;
    v20_as_v21.backend_version = BackendVersion::SEARCH_V21;
    v20_as_v21
        .search
        .as_mut()
        .expect("V20 manifest")
        .backend_version = BackendVersion::SEARCH_V21;
    assert_resealed_search_rejected(v20_as_v21, "V20 code resealed as V21");
}

#[test]
fn v21_all_width_code_bound_and_frozen_old_backend_bytes_are_exact() {
    fn gate_literal(topology: u8, width: usize) -> Vec<u8> {
        match topology {
            0 => (0..width)
                .map(|offset| 33 + u8::try_from((17 * offset) % 64).expect("bounded"))
                .collect(),
            1 => {
                let mut literal = vec![b'~'; width];
                literal[..5].copy_from_slice(b"A3mQz");
                literal
            }
            2 => {
                let mut literal = vec![b'x'; width];
                for (offset, byte) in [0, width / 4, width / 2, (3 * width) / 4, width - 1]
                    .into_iter()
                    .zip(*b"MNOPR")
                {
                    literal[offset] = byte;
                }
                literal
            }
            3 => {
                const ALPHABET: &[u8; 16] = b"0123456789ABCDEF";
                let mut state =
                    0x9e37_79b9_7f4a_7c15_u64 ^ u64::try_from(width).expect("host width");
                (0..width)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        ALPHABET[usize::from(state.to_le_bytes()[0] & 15)]
                    })
                    .collect()
            }
            _ => unreachable!(),
        }
    }

    // V17/V19/V20 were generated from the exact frozen V20 base commit
    // 9f03761d0b02258ce44771dff936852e10355e17, tree
    // 3a3f8d2158603ca0097fb82ad7e2216096fae011. V21 is pinned to the V22
    // implementation base fbba639cd21f18bbf1ac4b65964ed454cc93eecc, tree
    // c1b267c80f73eb64ad40eeea77e8f040c6286f7b. Each digest frames complete AOT
    // bytes for all four preregistered topologies at widths 6..32.
    for (name, policy, expected) in [
        (
            "V17",
            SearchBackendPolicy::AsimdV17,
            "e940a3075ad75f876df48cc8777d01834475282f0ed12671fd7a1b10142f2089",
        ),
        (
            "V19",
            SearchBackendPolicy::AsimdV19,
            "015a7eb171419bbec91876a1a6023160ef5814cbb5e88231555c65c49d62942d",
        ),
        (
            "V20",
            SearchBackendPolicy::AsimdV20,
            "84e6e4879358ba27d964bfda6de9918bc709b32d5e4e0bedd32e4e786814b978",
        ),
        (
            "V21",
            SearchBackendPolicy::AsimdV21,
            "9b23ecde0d6982538b02b66bc96e6d0480c579dd879f8aec1a3ef0ae4c017618",
        ),
    ] {
        let mut digest = Sha256::new();
        digest.update(b"FRE-V21-FROZEN-OLD-BACKEND-MATRIX-V1\0");
        digest.update(policy.backend_version().0.to_le_bytes());
        for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
            for topology in 0_u8..4 {
                let literal = gate_literal(topology, width);
                let program = build_exact_literal::<Span>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("old-backend byte-identity IR");
                let image = emit_with_backend(&program, policy, EmitLimits::default())
                    .expect("old-backend byte-identity image");
                audit(&image).expect("old-backend byte-identity audit");
                let aot = image
                    .to_aot(AotLimits::default())
                    .expect("old-backend bounded AOT");
                digest.update([topology]);
                digest.update(u64::try_from(width).expect("width").to_le_bytes());
                digest.update(
                    u64::try_from(aot.as_bytes().len())
                        .expect("AOT length")
                        .to_le_bytes(),
                );
                digest.update(aot.as_bytes());
            }
        }
        assert_eq!(format!("{:x}", digest.finalize()), expected, "{name}");
    }

    let mut maximum = 0_usize;
    let mut maximum_case = None;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for topology in 0_u8..4 {
            let literal = gate_literal(topology, width);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V21 all-width size IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV21,
                EmitLimits::default(),
            )
            .expect("V21 all-width size image");
            audit(&image).expect("V21 all-width size audit");
            if image.code().len() > maximum {
                maximum = image.code().len();
                maximum_case = Some((width, topology, format!("{}", image.artifact_identity())));
            }
            assert!(
                image.code().len() <= 2_304,
                "width={width} topology={topology} code_bytes={}",
                image.code().len()
            );
        }
    }
    assert_eq!(
        (maximum, maximum_case),
        (
            2_072,
            Some((
                17,
                0,
                "5d9c1c7a5eebbd75e93c525f05dc2f004bb5335567d8773f1dfef802833849f9".to_owned(),
            )),
        ),
        "the first deterministic worst-case artifact is source-bound"
    );
}

#[test]
fn v22_all_width_code_bound_is_exact() {
    fn gate_literal(topology: u8, width: usize) -> Vec<u8> {
        match topology {
            0 => (0..width)
                .map(|offset| 33 + u8::try_from((17 * offset) % 64).expect("bounded"))
                .collect(),
            1 => {
                let mut literal = vec![b'~'; width];
                literal[..5].copy_from_slice(b"A3mQz");
                literal
            }
            2 => {
                let mut literal = vec![b'x'; width];
                for (offset, byte) in [0, width / 4, width / 2, (3 * width) / 4, width - 1]
                    .into_iter()
                    .zip(*b"MNOPR")
                {
                    literal[offset] = byte;
                }
                literal
            }
            3 => {
                const ALPHABET: &[u8; 16] = b"0123456789ABCDEF";
                let mut state =
                    0x9e37_79b9_7f4a_7c15_u64 ^ u64::try_from(width).expect("host width");
                (0..width)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        ALPHABET[usize::from(state.to_le_bytes()[0] & 15)]
                    })
                    .collect()
            }
            _ => unreachable!(),
        }
    }

    let mut maximum = 0_usize;
    let mut maximum_case = None;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for topology in 0_u8..4 {
            let literal = gate_literal(topology, width);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V22 all-width size IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV22,
                EmitLimits::default(),
            )
            .expect("V22 all-width size image");
            audit(&image).expect("V22 all-width size audit");
            if image.code().len() > maximum {
                maximum = image.code().len();
                maximum_case = Some((width, topology, format!("{}", image.artifact_identity())));
            }
            assert!(
                image.code().len() <= 3_072,
                "width={width} topology={topology} code_bytes={}",
                image.code().len()
            );
        }
    }
    assert_eq!(
        (maximum, maximum_case),
        (
            2_472,
            Some((
                17,
                0,
                "3973a384391215bf51ef17841cd60b0f1f73e3b937332903729783229095a781".to_owned(),
            )),
        ),
        "the first deterministic V22 worst-case artifact is source-bound"
    );
}

#[test]
fn v21_first_survivor_and_learned_empty_restore_every_block_and_lane() {
    let literal = [11_u8, 37, 63, 89, 115, 141, 167, 193, 219, 245, 17, 43, 69];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V21 block/lane IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV21,
        EmitLimits::default(),
    )
    .expect("V21 block/lane image");
    audit(&image).expect("V21 block/lane audit");
    let manifest = image.search_manifest().expect("V21 block/lane manifest");
    let selected = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ]
    .map(usize::from);
    let mismatch = (0..literal.len())
        .find(|offset| !selected.contains(offset))
        .expect("V21 leaves one learnable offset");
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded byte"))
        .find(|byte| !literal.contains(byte))
        .expect("V21 literal leaves an avoiding byte");
    let window_start = 3_usize;
    let wide_base = window_start + 1;

    for block in 0..4_usize {
        for lane in 0..16_usize {
            let candidate = wide_base + block * 16 + lane;

            let mut direct = vec![avoid; 224];
            direct[candidate..candidate + literal.len()].copy_from_slice(&literal);
            assert_eq!(
                span_output(
                    simulate(&image, &direct, window_start, direct.len())
                        .expect("V21 direct first-survivor simulation")
                ),
                Some((candidate, candidate + literal.len())),
                "direct block={block} lane={lane}"
            );

            let mut learned_empty = vec![avoid; 224];
            for &offset in &selected {
                learned_empty[candidate + offset] = literal[offset];
            }
            assert_eq!(learned_empty[candidate + mismatch], avoid);
            let exact = wide_base + 96;
            learned_empty[exact..exact + literal.len()].copy_from_slice(&literal);
            let expected = program
                .execute(
                    &learned_empty,
                    SearchWindow::new(window_start, learned_empty.len()),
                    ExecutionLimits::unlimited(),
                )
                .expect("V21 learned-empty oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual = simulate(&image, &learned_empty, window_start, learned_empty.len())
                .expect("V21 learned-empty simulation");
            assert_eq!(
                span_output(actual),
                expected,
                "learned-empty block={block} lane={lane}"
            );
            assert_eq!(expected, Some((exact, exact + literal.len())));
        }
    }
}

#[test]
fn v21_learns_every_unselected_source_offset_across_every_gate_width() {
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V21 width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V21 every-mismatch IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV21,
            EmitLimits::default(),
        )
        .expect("V21 every-mismatch image");
        audit(&image).expect("V21 every-mismatch audit");
        let manifest = image
            .search_manifest()
            .expect("V21 every-mismatch manifest");
        let selected = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ]
        .map(usize::from);
        let avoid = (0_u16..=255)
            .map(|value| u8::try_from(value).expect("bounded byte"))
            .find(|byte| !literal.contains(byte))
            .expect("V21 literal leaves an avoiding byte");
        let window_start = 3_usize;
        let wide_base = window_start + 1;
        let false_candidate = wide_base + 7;
        let exact = wide_base + 96;

        for mismatch in (0..width).filter(|offset| !selected.contains(offset)) {
            let mut haystack = vec![avoid; 256];
            for &offset in &selected {
                haystack[false_candidate + offset] = literal[offset];
            }
            assert_eq!(haystack[false_candidate + mismatch], avoid);
            haystack[exact..exact + width].copy_from_slice(&literal);
            let expected = program
                .execute(
                    &haystack,
                    SearchWindow::new(window_start, haystack.len()),
                    ExecutionLimits::unlimited(),
                )
                .expect("V21 every-mismatch oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual = simulate(&image, &haystack, window_start, haystack.len())
                .expect("V21 every-mismatch simulation");
            assert_eq!(
                span_output(actual),
                expected,
                "width={width} mismatch={mismatch}"
            );
            assert_eq!(expected, Some((exact, exact + width)));
            comparisons = comparisons
                .checked_add(1)
                .expect("bounded V21 mismatch matrix");
        }
    }
    assert_eq!(comparisons, 513 - 27 * 5);
}

#[test]
fn v21_learned_nonempty_mask_preserves_source_order_before_exact_match() {
    let literal = [11_u8, 37, 63, 89, 115, 141, 167, 193, 219, 245, 17, 43, 69];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V21 learned-nonempty IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV21,
        EmitLimits::default(),
    )
    .expect("V21 learned-nonempty image");
    let manifest = image
        .search_manifest()
        .expect("V21 learned-nonempty manifest");
    let selected = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ]
    .map(usize::from);
    let unselected = (0..literal.len())
        .filter(|offset| !selected.contains(offset))
        .collect::<Vec<_>>();
    assert!(unselected.len() >= 2);
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded byte"))
        .find(|byte| !literal.contains(byte))
        .expect("V21 literal leaves an avoiding byte");
    let window_start = 3_usize;
    let wide_base = window_start + 1;
    let first_false = wide_base + 2;
    let second_false = wide_base + 21;
    let exact = wide_base + 43;
    let mut haystack = vec![avoid; 192];
    for &offset in &selected {
        haystack[first_false + offset] = literal[offset];
        haystack[second_false + offset] = literal[offset];
    }
    // The first false survivor teaches this source-order column. The second
    // false survivor passes it, then misses at the next unselected byte.
    haystack[second_false + unselected[0]] = literal[unselected[0]];
    assert_eq!(haystack[second_false + unselected[1]], avoid);
    haystack[exact..exact + literal.len()].copy_from_slice(&literal);

    let expected = program
        .execute(
            &haystack,
            SearchWindow::new(window_start, haystack.len()),
            ExecutionLimits::unlimited(),
        )
        .expect("V21 learned-nonempty oracle")
        .output()
        .map(|span| (span.start(), span.end()));
    let actual = simulate(&image, &haystack, window_start, haystack.len())
        .expect("V21 learned-nonempty simulation");
    assert_eq!(span_output(actual), expected);
    assert_eq!(expected, Some((exact, exact + literal.len())));
}

#[test]
fn v21_every_width_and_window_shape_matches_the_kir_oracle() {
    let mut state = 0x4d8e_a711_93c2_6bf5_u64;
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V21 width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V21 every-width IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV21,
            EmitLimits::default(),
        )
        .expect("V21 every-width image");
        audit(&image).expect("V21 every-width audit");

        for case in 0..8_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let hay_len = 112 + usize::try_from(state >> 24).expect("host usize") % 97;
            let mut haystack = Vec::with_capacity(hay_len);
            for _ in 0..hay_len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                haystack.push(state.to_le_bytes()[0]);
            }

            let exact = (case & 1 == 0).then(|| {
                5 + (usize::try_from(state >> 8).expect("host usize")
                    % (haystack.len() - width - 5))
            });
            if let Some(candidate) = exact {
                haystack[candidate..candidate + width].copy_from_slice(&literal);
            }

            let random_start =
                usize::try_from(state >> 16).expect("host usize") % (haystack.len() + 1);
            let random_end = random_start
                + (usize::try_from(state >> 32).expect("host usize")
                    % (haystack.len() - random_start + 1));
            let short_end = width.saturating_sub(1).min(haystack.len());
            let exact_window = exact.map_or((random_start, random_end), |candidate| {
                (candidate, candidate + width)
            });
            let windows = [
                (0, 0),
                (0, short_end),
                (0, haystack.len()),
                (random_start, haystack.len()),
                (random_start, random_end),
                exact_window,
            ];
            for (start, end) in windows {
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(start, end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V21 every-width oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, &haystack, start, end)
                    .expect("V21 every-width safe ISA simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} case={case} window={start}..{end}"
                );
                comparisons = comparisons.checked_add(1).expect("bounded V21 matrix");
            }
        }
    }
    assert_eq!(comparisons, 1_296);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V22 structural gate keeps its wire, persistent register contract, old-backend separation, and decoded learned-wide shape reviewable together"
)]
fn v22_persistent_learned_wide_is_distinct_bounded_and_independently_audited() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V22 structural IR");
    let v21 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV21,
        EmitLimits::default(),
    )
    .expect("frozen V21 structural image");
    let v22 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV22,
        EmitLimits::default(),
    )
    .expect("V22 structural image");
    let report = audit(&v22).expect("independent V22 structural template");
    assert_eq!(
        (report.decode_passes, report.source_identity_rebuilds),
        (1, 1)
    );
    assert_eq!(v22.backend_version(), BackendVersion::SEARCH_V22);
    assert_eq!(
        &v22.to_aot(AotLimits::default())
            .expect("bounded V22 AOT")
            .as_bytes()[..8],
        b"FREA64\0\x23"
    );
    assert!(v22.code().len() <= 3_072);
    assert_ne!(v22.artifact_identity(), v21.artifact_identity());

    let v21_manifest = v21.search_manifest().expect("V21 structural manifest");
    let v22_manifest = v22.search_manifest().expect("V22 structural manifest");
    assert_eq!(
        (
            v22_manifest.primary_offset,
            v22_manifest.secondary_offset,
            v22_manifest.verification_offset,
            v22_manifest.quaternary_offset,
            v22_manifest.quinary_offset,
        ),
        (
            v21_manifest.primary_offset,
            v21_manifest.secondary_offset,
            v21_manifest.verification_offset,
            v21_manifest.quaternary_offset,
            v21_manifest.quinary_offset,
        ),
        "V22 changes only post-learning continuation"
    );

    let decoded = decode(v22.code()).expect("V22 structural decode");
    let learned_byte = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::DuplicateByte16 {
                    destination: 24,
                    source: 13,
                }
        })
        .expect("V22 learned byte initialization");
    assert_eq!(
        decoded[learned_byte + 1],
        DecodedInstruction::DuplicateByte16 {
            destination: 25,
            source: 11,
        },
        "V22 freezes the learned offset before repurposing X11"
    );
    assert_eq!(
        decoded[learned_byte + 2],
        DecodedInstruction::MoveZero64 {
            destination: 11,
            immediate: 1,
            shift: 0,
        }
    );

    let persistent_address = decoded[learned_byte + 3..]
        .windows(3)
        .position(|window| {
            window
                == [
                    DecodedInstruction::AddRegister64 {
                        destination: 13,
                        left: 9,
                        right: 5,
                    },
                    DecodedInstruction::MoveVectorByteTo32 {
                        destination: 10,
                        source: 25,
                    },
                    DecodedInstruction::AddRegister64 {
                        destination: 10,
                        left: 13,
                        right: 10,
                    },
                ]
        })
        .map(|offset| learned_byte + 3 + offset)
        .expect("V22 persistent X13/X10 learned address");
    assert_eq!(
        &decoded[persistent_address + 3..persistent_address + 5],
        &[
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
        ]
    );

    let persistent_queue = decoded[persistent_address..]
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                    destination: 16,
                    source: 0,
                }
        })
        .map(|offset| persistent_address + offset)
        .expect("V22 persistent queue");
    assert!(
        decoded[persistent_address..persistent_queue]
            .iter()
            .all(|instruction| instruction.written_gpr() != Some(15)),
        "persistent screening must retain X15 as the primary-column pointer"
    );
    assert_eq!(
        decoded
            .iter()
            .filter(|instruction| {
                **instruction
                    == DecodedInstruction::DuplicateByte16 {
                        destination: 24,
                        source: 13,
                    }
            })
            .count(),
        2,
        "V22 has one wide and one inherited narrow learning site"
    );
    assert_eq!(
        decoded
            .iter()
            .filter(|instruction| {
                **instruction
                    == DecodedInstruction::DuplicateByte16 {
                        destination: 25,
                        source: 11,
                    }
            })
            .count(),
        2,
        "V22 has one wide and one inherited narrow learning site"
    );

    let mut v22_as_v21 = v22.clone();
    v22_as_v21.backend_version = BackendVersion::SEARCH_V21;
    v22_as_v21
        .search
        .as_mut()
        .expect("V22 manifest")
        .backend_version = BackendVersion::SEARCH_V21;
    assert_resealed_search_rejected(v22_as_v21, "V22 code resealed as V21");

    let mut v21_as_v22 = v21;
    v21_as_v22.backend_version = BackendVersion::SEARCH_V22;
    v21_as_v22
        .search
        .as_mut()
        .expect("V21 manifest")
        .backend_version = BackendVersion::SEARCH_V22;
    assert_resealed_search_rejected(v21_as_v22, "V21 code resealed as V22");
}

#[test]
fn v22_persistent_mask_algebra_exhausts_every_block_lane_and_static_stage() {
    fn intersect(mut masks: [u16; 4], columns: &[[u16; 4]]) -> [u16; 4] {
        for column in columns {
            for block in 0..4 {
                masks[block] &= column[block];
            }
        }
        masks
    }

    // Every possible candidate bit must survive exactly when the learned
    // column and all five authenticated static columns contain it. Enumerate
    // all 64 Boolean relations independently for every block/lane; unrelated
    // noise proves that staged intersections cannot create a candidate bit.
    for block in 0..4_usize {
        for lane in 0..16_u32 {
            let bit = 1_u16 << lane;
            for configuration in 0_u8..64 {
                let mut operands = [
                    [0xaaaa_u16, 0x5555, 0xf0f0, 0x0f0f],
                    [0x7fff, 0xbfff, 0xdfff, 0xefff],
                    [0xfffe, 0xfffd, 0xfffb, 0xfff7],
                    [0xaaaa, 0x7777, 0xdddd, 0xf3f3],
                    [0x5555, 0xbbbb, 0xeeee, 0xfcfc],
                    [0x3333, 0xcccc, 0x9696, 0x6969],
                ];
                for (stage, operand) in operands.iter_mut().enumerate() {
                    let stage_bit = 1_u8
                        .checked_shl(u32::try_from(stage).expect("six algebra stages"))
                        .expect("bounded algebra shift");
                    if configuration & stage_bit == 0 {
                        operand[block] &= !bit;
                    } else {
                        operand[block] |= bit;
                    }
                }

                let actual = intersect(operands[0], &operands[1..]);
                assert_eq!(
                    actual[block] & bit,
                    if configuration == 0x3f { bit } else { 0 },
                    "block={block} lane={lane} configuration={configuration:#08b}"
                );
            }
        }
    }

    // A non-singleton four-mask relation supplies an independently calculated
    // whole-mask witness in addition to the exhaustive per-bit truth table.
    assert_eq!(
        intersect(
            [0xffff, 0xaaaa, 0x0f0f, 0x8001],
            &[
                [0x0f0f, 0xffff, 0xffff, 0xffff],
                [0x3333, 0x5555, 0xffff, 0xffff],
                [0xffff, 0xffff, 0x00ff, 0xffff],
                [0xffff, 0xffff, 0xf0f0, 0xffff],
                [0xffff, 0xffff, 0xffff, 0x7fff],
            ],
        ),
        [0x0303, 0, 0, 1]
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the all-width decoded liveness proof names every persistent edge and vector destination explicitly"
)]
fn v22_q24_q25_x15_and_persistent_entry_liveness_hold_for_every_equality_shape() {
    fn writes_vector(instruction: DecodedInstruction, register: u8) -> bool {
        match instruction {
            DecodedInstruction::LoadVector128 { destination, .. }
            | DecodedInstruction::DuplicateByte16 { destination, .. }
            | DecodedInstruction::CompareEqualBytes16 { destination, .. }
            | DecodedInstruction::AndBytes16 { destination, .. }
            | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 { destination, .. }
            | DecodedInstruction::UnsignedMinBytes16 { destination, .. }
            | DecodedInstruction::UnsignedMaxBytes16 { destination, .. }
            | DecodedInstruction::UnsignedMaxPairwiseBytes16 { destination, .. }
            | DecodedInstruction::AddAcrossBytes16 { destination, .. } => destination == register,
            DecodedInstruction::LoadVectorPair128 {
                first_destination,
                second_destination,
                ..
            } => first_destination == register || second_destination == register,
            _ => false,
        }
    }

    fn direct_target(index: usize, instruction: DecodedInstruction) -> Option<usize> {
        if !matches!(
            instruction,
            DecodedInstruction::Branch { .. }
                | DecodedInstruction::BranchCondition { .. }
                | DecodedInstruction::CompareBranchZero64 { .. }
        ) {
            return None;
        }
        let displacement = i64::from(instruction.direct_displacement()?);
        let byte_index = i64::try_from(index).ok()?.checked_mul(4)?;
        let target = byte_index.checked_add(displacement)?;
        if target < 0 || target % 4 != 0 {
            return None;
        }
        usize::try_from(target / 4).ok()
    }

    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V22 liveness width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V22 liveness IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV22,
            EmitLimits::default(),
        )
        .expect("V22 liveness image");
        audit(&image).expect("V22 liveness audit");
        let decoded = decode(image.code()).expect("V22 liveness decode");

        let learning_sites = decoded
            .windows(3)
            .enumerate()
            .filter_map(|(index, window)| {
                (window
                    == [
                        DecodedInstruction::DuplicateByte16 {
                            destination: 24,
                            source: 13,
                        },
                        DecodedInstruction::DuplicateByte16 {
                            destination: 25,
                            source: 11,
                        },
                        DecodedInstruction::MoveZero64 {
                            destination: 11,
                            immediate: 1,
                            shift: 0,
                        },
                    ])
                .then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(learning_sites.len(), 2, "width={width}");
        let wide_learning = learning_sites[0];
        let narrow_learning = learning_sites[1];

        let persistent = decoded[wide_learning + 3..narrow_learning]
            .windows(3)
            .position(|window| {
                window
                    == [
                        DecodedInstruction::AddRegister64 {
                            destination: 13,
                            left: 9,
                            right: 5,
                        },
                        DecodedInstruction::MoveVectorByteTo32 {
                            destination: 10,
                            source: 25,
                        },
                        DecodedInstruction::AddRegister64 {
                            destination: 10,
                            left: 13,
                            right: 10,
                        },
                    ]
            })
            .map(|offset| wide_learning + 3 + offset)
            .expect("V22 persistent entry");
        let queue = decoded[persistent..narrow_learning]
            .iter()
            .position(|instruction| {
                *instruction
                    == DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                        destination: 16,
                        source: 0,
                    }
            })
            .map(|offset| persistent + offset)
            .expect("V22 persistent queue");
        let restore = decoded[queue..narrow_learning]
            .windows(3)
            .position(|window| {
                window
                    == [
                        DecodedInstruction::MoveZero64 {
                            destination: 11,
                            immediate: 1,
                            shift: 0,
                        },
                        DecodedInstruction::AddImmediate64 {
                            destination: 5,
                            source: 7,
                            immediate: 16,
                        },
                        DecodedInstruction::AddRegister64 {
                            destination: 15,
                            left: 9,
                            right: 5,
                        },
                    ]
            })
            .map(|offset| queue + offset)
            .expect("V22 queue restoration");
        let verifier_pointer = decoded[queue..restore]
            .iter()
            .position(|instruction| {
                *instruction
                    == DecodedInstruction::AddRegister64 {
                        destination: 15,
                        left: 9,
                        right: 5,
                    }
            })
            .map(|offset| queue + offset)
            .expect("V22 specialized queue verifier");
        assert!(verifier_pointer < restore, "width={width}");

        for &instruction in &decoded[wide_learning + 3..narrow_learning] {
            assert!(!writes_vector(instruction, 24), "Q24 width={width}");
            assert!(!writes_vector(instruction, 25), "Q25 width={width}");
        }
        assert!(
            decoded[persistent..queue]
                .iter()
                .all(|instruction| instruction.written_gpr() != Some(15)),
            "persistent screening retains X15 width={width}"
        );

        let advance_edge = decoded[..persistent]
            .iter()
            .enumerate()
            .find_map(|(index, instruction)| {
                (direct_target(index, *instruction) == Some(persistent)).then_some(index)
            })
            .expect("V22 persistent advance edge");
        assert_eq!(
            decoded[advance_edge],
            DecodedInstruction::BranchCondition {
                condition: Condition::LowerOrSame,
                displacement: i32::try_from(
                    (i64::try_from(persistent).expect("index")
                        - i64::try_from(advance_edge).expect("index"))
                        * 4,
                )
                .expect("bounded branch"),
            },
            "width={width}"
        );
        let persistent_advance = advance_edge
            .checked_sub(3)
            .expect("persistent advance prefix");
        assert_eq!(
            &decoded[persistent_advance..advance_edge],
            &[
                DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 64,
                },
                DecodedInstruction::AddImmediate64 {
                    destination: 15,
                    source: 15,
                    immediate: 64,
                },
                DecodedInstruction::CompareRegister64 { left: 5, right: 7 },
            ],
            "width={width}"
        );
        let advance_predecessors = decoded
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (direct_target(index, *instruction) == Some(persistent_advance)).then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            advance_predecessors.len(),
            6,
            "one learned-refinement empty edge plus learned, primary, secondary, first-remaining, and final persistent-empty edges width={width}"
        );
        for &predecessor in &advance_predecessors {
            assert!(
                predecessor >= wide_learning + 3 && predecessor < queue,
                "persistent-advance predecessor is dominated by initialized Q24/Q25/X11 and precedes queue state width={width} predecessor={predecessor}"
            );
            assert!(
                decoded[wide_learning + 3..=predecessor]
                    .iter()
                    .all(|instruction| instruction.written_gpr() != Some(11)),
                "X11 remains one from initialization to persistent-advance predecessor width={width} predecessor={predecessor}"
            );
        }

        let incoming = decoded
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (direct_target(index, *instruction) == Some(persistent)).then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(incoming.len(), 2, "width={width}");
        assert_eq!(incoming[0], advance_edge, "width={width}");
        assert!(
            incoming[1] > restore,
            "queue predecessor restores X11 before persistent entry width={width}"
        );
        assert_eq!(
            decoded[restore],
            DecodedInstruction::MoveZero64 {
                destination: 11,
                immediate: 1,
                shift: 0,
            },
            "width={width}"
        );
        assert!(
            decoded[restore + 1..=incoming[1]]
                .iter()
                .all(|instruction| instruction.written_gpr() != Some(11)),
            "X11 remains one from queue restoration to persistent entry width={width}"
        );
    }
}

#[test]
fn v22_rejects_resealed_persistent_state_address_and_branch_mutations() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V22 mutation IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV22,
        EmitLimits::default(),
    )
    .expect("V22 mutation image");
    let decoded = decode(image.code()).expect("V22 mutation decode");
    let learned = decoded
        .windows(3)
        .position(|window| {
            window
                == [
                    DecodedInstruction::DuplicateByte16 {
                        destination: 24,
                        source: 13,
                    },
                    DecodedInstruction::DuplicateByte16 {
                        destination: 25,
                        source: 11,
                    },
                    DecodedInstruction::MoveZero64 {
                        destination: 11,
                        immediate: 1,
                        shift: 0,
                    },
                ]
        })
        .expect("V22 mutation learning site");
    let persistent = decoded[learned + 3..]
        .windows(3)
        .position(|window| {
            window
                == [
                    DecodedInstruction::AddRegister64 {
                        destination: 13,
                        left: 9,
                        right: 5,
                    },
                    DecodedInstruction::MoveVectorByteTo32 {
                        destination: 10,
                        source: 25,
                    },
                    DecodedInstruction::AddRegister64 {
                        destination: 10,
                        left: 13,
                        right: 10,
                    },
                ]
        })
        .map(|offset| learned + 3 + offset)
        .expect("V22 mutation persistent entry");
    let learned_empty_branch = decoded[persistent..]
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 10,
                    nonzero: false,
                    ..
                }
            )
        })
        .map(|offset| persistent + offset)
        .expect("V22 mutation learned-empty branch");

    let mut wrong_offset_source = image.clone();
    replace_test_decoded_at(
        &mut wrong_offset_source,
        learned + 1,
        DecodedInstruction::DuplicateByte16 {
            destination: 25,
            source: 13,
        },
    );
    assert_resealed_search_rejected(wrong_offset_source, "V22 Q25 source substitution");

    let mut wrong_learned_address = image.clone();
    replace_test_decoded_at(
        &mut wrong_learned_address,
        persistent + 2,
        DecodedInstruction::AddRegister64 {
            destination: 10,
            left: 15,
            right: 10,
        },
    );
    assert_resealed_search_rejected(
        wrong_learned_address,
        "V22 learned-address base substitution",
    );

    let DecodedInstruction::CompareBranchZero64 {
        register,
        displacement,
        ..
    } = decoded[learned_empty_branch]
    else {
        unreachable!();
    };
    let mut inverted_empty_edge = image;
    replace_test_decoded_at(
        &mut inverted_empty_edge,
        learned_empty_branch,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: true,
            displacement,
        },
    );
    assert_resealed_search_rejected(inverted_empty_edge, "V22 learned-empty branch inversion");
}

#[test]
fn v22_persists_learned_column_across_empty_groups_before_an_exact_match() {
    let literal = [11_u8, 37, 63, 89, 115, 141, 167, 193, 219, 245, 17, 43, 69];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V22 persistent-empty IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV22,
        EmitLimits::default(),
    )
    .expect("V22 persistent-empty image");
    audit(&image).expect("V22 persistent-empty audit");
    let manifest = image
        .search_manifest()
        .expect("V22 persistent-empty manifest");
    let selected = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ]
    .map(usize::from);
    let mismatch = (0..literal.len())
        .find(|offset| !selected.contains(offset))
        .expect("V22 leaves one learnable offset");
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded byte"))
        .find(|byte| !literal.contains(byte))
        .expect("V22 literal leaves an avoiding byte");
    let window_start = 3_usize;
    let wide_base = window_start + 1;

    for block in 0..4_usize {
        for lane in [0_usize, 7, 15] {
            let false_candidate = wide_base + block * 16 + lane;
            let exact = wide_base + 4 * 64 + 9;
            let mut haystack = vec![avoid; exact + literal.len() + 80];
            for &offset in &selected {
                haystack[false_candidate + offset] = literal[offset];
            }
            assert_eq!(haystack[false_candidate + mismatch], avoid);
            haystack[exact..exact + literal.len()].copy_from_slice(&literal);

            let expected = program
                .execute(
                    &haystack,
                    SearchWindow::new(window_start, haystack.len()),
                    ExecutionLimits::unlimited(),
                )
                .expect("V22 persistent-empty oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual = simulate(&image, &haystack, window_start, haystack.len())
                .expect("V22 persistent-empty safe ISA simulation");
            assert_eq!(span_output(actual), expected, "block={block} lane={lane}");
            assert_eq!(expected, Some((exact, exact + literal.len())));
        }
    }
}

#[test]
fn v22_persistent_nonempty_groups_preserve_source_order() {
    let literal = [11_u8, 37, 63, 89, 115, 141, 167, 193, 219, 245, 17, 43, 69];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V22 persistent-nonempty IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV22,
        EmitLimits::default(),
    )
    .expect("V22 persistent-nonempty image");
    audit(&image).expect("V22 persistent-nonempty audit");
    let manifest = image
        .search_manifest()
        .expect("V22 persistent-nonempty manifest");
    let selected = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ]
    .map(usize::from);
    let unselected = (0..literal.len())
        .filter(|offset| !selected.contains(offset))
        .collect::<Vec<_>>();
    assert!(unselected.len() >= 2);
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded byte"))
        .find(|byte| !literal.contains(byte))
        .expect("V22 literal leaves an avoiding byte");
    let window_start = 3_usize;
    let wide_base = window_start + 1;
    let discovery_false = wide_base + 1;
    for (relation, later_false) in [
        ("same-block", wide_base + 14),
        ("later-block", wide_base + 3 * 16 + 4),
        ("later-group", wide_base + 64 + 21),
    ] {
        let exact = wide_base + 3 * 64 + 43;
        let mut haystack = vec![avoid; exact + literal.len() + 96];
        for &offset in &selected {
            haystack[discovery_false + offset] = literal[offset];
            haystack[later_false + offset] = literal[offset];
        }
        haystack[later_false + unselected[0]] = literal[unselected[0]];
        assert_eq!(haystack[later_false + unselected[1]], avoid);
        haystack[exact..exact + literal.len()].copy_from_slice(&literal);

        let expected = program
            .execute(
                &haystack,
                SearchWindow::new(window_start, haystack.len()),
                ExecutionLimits::unlimited(),
            )
            .expect("V22 persistent-nonempty oracle")
            .output()
            .map(|span| (span.start(), span.end()));
        let actual = simulate(&image, &haystack, window_start, haystack.len())
            .expect("V22 persistent-nonempty safe ISA simulation");
        assert_eq!(
            span_output(actual),
            expected,
            "false-survivor relation={relation}"
        );
        assert_eq!(
            expected,
            Some((exact, exact + literal.len())),
            "false-survivor relation={relation}"
        );
    }
}

#[test]
fn v22_persistent_pair_empty_bypasses_prelearning_secondary_only_without_losing_match() {
    let literal = [11_u8, 37, 63, 89, 115, 141, 167, 193, 219, 245, 17, 43, 69];
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V22 persistent pair-empty IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV22,
        EmitLimits::default(),
    )
    .expect("V22 persistent pair-empty image");
    audit(&image).expect("V22 persistent pair-empty audit");
    let manifest = image
        .search_manifest()
        .expect("V22 persistent pair-empty manifest");
    let selected = [
        manifest.primary_offset,
        manifest.secondary_offset,
        manifest.verification_offset,
        manifest.quaternary_offset,
        manifest.quinary_offset,
    ]
    .map(usize::from);
    let learned = (0..literal.len())
        .find(|offset| !selected.contains(offset))
        .expect("V22 persistent pair-empty learned offset");
    let avoid = (0_u16..=255)
        .map(|value| u8::try_from(value).expect("bounded byte"))
        .find(|byte| !literal.contains(byte))
        .expect("V22 persistent pair-empty avoiding byte");
    let wide_base = 1_usize;
    let discovery_false = wide_base + 5;
    let pair_empty = wide_base + 64 + 19;
    let exact = wide_base + 2 * 64 + 37;
    let mut haystack = vec![avoid; exact + literal.len() + 80];

    // The discovery-group survivor passes all static columns and teaches the
    // first unselected mismatch. The next group has learned+primary hits but
    // no secondary hit. Persistent screening must advance directly rather
    // than re-entering the pre-learning secondary-only state machine.
    for &offset in &selected {
        haystack[discovery_false + offset] = literal[offset];
    }
    haystack[pair_empty + learned] = literal[learned];
    haystack[pair_empty + selected[0]] = literal[selected[0]];
    assert_eq!(haystack[pair_empty + selected[1]], avoid);
    haystack[exact..exact + literal.len()].copy_from_slice(&literal);

    let expected = program
        .execute(
            &haystack,
            SearchWindow::new(0, haystack.len()),
            ExecutionLimits::unlimited(),
        )
        .expect("V22 persistent pair-empty oracle")
        .output()
        .map(|span| (span.start(), span.end()));
    let actual = simulate(&image, &haystack, 0, haystack.len())
        .expect("V22 persistent pair-empty simulation");
    assert_eq!(expected, Some((exact, exact + literal.len())));
    assert_eq!(span_output(actual), expected);
}

#[test]
fn v22_all_search_output_contracts_emit_audit_and_serialize() {
    for width in [6_usize, 13, 32] {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V22 output width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let exists = build_exact_literal::<Exists>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V22 Exists IR");
        let selected_end = build_exact_literal::<SelectedEnd>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V22 SelectedEnd IR");
        let span = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V22 Span IR");
        for (output, image) in [
            (
                OutputKind::Exists,
                emit_with_backend(
                    &exists,
                    SearchBackendPolicy::AsimdV22,
                    EmitLimits::default(),
                )
                .expect("V22 Exists image"),
            ),
            (
                OutputKind::SelectedEnd,
                emit_with_backend(
                    &selected_end,
                    SearchBackendPolicy::AsimdV22,
                    EmitLimits::default(),
                )
                .expect("V22 SelectedEnd image"),
            ),
            (
                OutputKind::Span,
                emit_with_backend(&span, SearchBackendPolicy::AsimdV22, EmitLimits::default())
                    .expect("V22 Span image"),
            ),
        ] {
            assert_eq!(image.backend_version(), BackendVersion::SEARCH_V22);
            assert_eq!(
                image.search_manifest().expect("V22 output manifest").output,
                output
            );
            let report = audit(&image).expect("V22 output template audit");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 1)
            );
            let aot = image.to_aot(AotLimits::default()).expect("V22 output AOT");
            assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x23");
            assert_eq!(aot.identity(), image.artifact_identity());
        }
    }
}

#[test]
fn v22_learns_every_unselected_offset_across_every_gate_width() {
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V22 mismatch width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V22 every-mismatch IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV22,
            EmitLimits::default(),
        )
        .expect("V22 every-mismatch image");
        audit(&image).expect("V22 every-mismatch audit");
        let manifest = image
            .search_manifest()
            .expect("V22 every-mismatch manifest");
        let selected = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ]
        .map(usize::from);
        let avoid = (0_u16..=255)
            .map(|value| u8::try_from(value).expect("bounded byte"))
            .find(|byte| !literal.contains(byte))
            .expect("V22 literal leaves an avoiding byte");
        let window_start = 3_usize;
        let wide_base = window_start + 1;
        let false_candidate = wide_base + 7;
        let exact = wide_base + 4 * 64 + 11;

        for mismatch in (0..width).filter(|offset| !selected.contains(offset)) {
            let mut haystack = vec![avoid; exact + width + 96];
            for &offset in &selected {
                haystack[false_candidate + offset] = literal[offset];
            }
            assert_eq!(haystack[false_candidate + mismatch], avoid);
            haystack[exact..exact + width].copy_from_slice(&literal);
            let expected = program
                .execute(
                    &haystack,
                    SearchWindow::new(window_start, haystack.len()),
                    ExecutionLimits::unlimited(),
                )
                .expect("V22 every-mismatch oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual = simulate(&image, &haystack, window_start, haystack.len())
                .expect("V22 every-mismatch simulation");
            assert_eq!(
                span_output(actual),
                expected,
                "width={width} mismatch={mismatch}"
            );
            assert_eq!(expected, Some((exact, exact + width)));
            comparisons = comparisons
                .checked_add(1)
                .expect("bounded V22 mismatch matrix");
        }
    }
    assert_eq!(comparisons, 513 - 27 * 5);
}

#[test]
fn v22_wide_to_narrow_and_tail_boundaries_cover_every_window_residue() {
    let mut comparisons = 0_u64;
    for width in [6_usize, 13, 32] {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V22 boundary width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V22 boundary IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV22,
            EmitLimits::default(),
        )
        .expect("V22 boundary image");
        let manifest = image.search_manifest().expect("V22 boundary manifest");
        let selected = [
            manifest.primary_offset,
            manifest.secondary_offset,
            manifest.verification_offset,
            manifest.quaternary_offset,
            manifest.quinary_offset,
        ]
        .map(usize::from);
        let avoid = (0_u16..=255)
            .map(|value| u8::try_from(value).expect("bounded byte"))
            .find(|byte| !literal.contains(byte))
            .expect("V22 boundary literal leaves an avoiding byte");

        for window_start in 0_usize..16 {
            let wide_base = window_start + 1;
            let false_candidate = wide_base + 5;
            for (kind, exact, last_candidate) in [
                ("narrow", wide_base + 64 + 7, wide_base + 64 + 20),
                ("tail", wide_base + 64 + 18, wide_base + 64 + 18),
            ] {
                let window_end = last_candidate + width;
                let mut haystack = vec![avoid; window_end + 17];
                for &offset in &selected {
                    haystack[false_candidate + offset] = literal[offset];
                }
                haystack[exact..exact + width].copy_from_slice(&literal);
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(window_start, window_end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V22 boundary oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, &haystack, window_start, window_end)
                    .expect("V22 boundary simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} residue={window_start} kind={kind}"
                );
                assert_eq!(expected, Some((exact, exact + width)));
                comparisons = comparisons
                    .checked_add(1)
                    .expect("bounded V22 boundary matrix");
            }
        }
    }
    assert_eq!(comparisons, 3 * 16 * 2);
}

#[test]
fn v22_every_width_and_window_shape_matches_the_kir_oracle() {
    let mut state = 0xcab4_991d_26e8_735f_u64;
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        let literal = (0..width)
            .map(|offset| {
                u8::try_from(offset)
                    .expect("bounded V22 width")
                    .wrapping_mul(61)
                    .wrapping_add(7)
            })
            .collect::<Vec<_>>();
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V22 every-width IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV22,
            EmitLimits::default(),
        )
        .expect("V22 every-width image");
        audit(&image).expect("V22 every-width audit");

        for case in 0..8_usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let hay_len = 256 + usize::try_from(state >> 24).expect("host usize") % 257;
            let mut haystack = Vec::with_capacity(hay_len);
            for _ in 0..hay_len {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                haystack.push(state.to_le_bytes()[0]);
            }

            let exact = (case & 1 == 0).then(|| {
                5 + (usize::try_from(state >> 8).expect("host usize")
                    % (haystack.len() - width - 5))
            });
            if let Some(candidate) = exact {
                haystack[candidate..candidate + width].copy_from_slice(&literal);
            }

            let random_start =
                usize::try_from(state >> 16).expect("host usize") % (haystack.len() + 1);
            let random_end = random_start
                + (usize::try_from(state >> 32).expect("host usize")
                    % (haystack.len() - random_start + 1));
            let short_end = width.saturating_sub(1).min(haystack.len());
            let exact_window = exact.map_or((random_start, random_end), |candidate| {
                (candidate, candidate + width)
            });
            let windows = [
                (0, 0),
                (0, short_end),
                (0, haystack.len()),
                (random_start, haystack.len()),
                (random_start, random_end),
                exact_window,
            ];
            for (start, end) in windows {
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(start, end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V22 every-width oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, &haystack, start, end)
                    .expect("V22 every-width safe ISA simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} case={case} window={start}..{end}"
                );
                comparisons = comparisons.checked_add(1).expect("bounded V22 matrix");
            }
        }
    }
    assert_eq!(comparisons, 1_296);
}

fn v23_pointer_test_literal(width: usize, zero_primary: bool) -> Vec<u8> {
    assert!((6..=MAX_REPEATED_CONFIRM_BYTES).contains(&width));
    let primary = if zero_primary { 0 } else { width - 1 };
    let secondary = if zero_primary { width - 1 } else { 0 };
    let mut literal = vec![b'e'; width];
    literal[primary] = 0x1f;
    literal[secondary] = 0x1e;
    literal
}

fn exact_output_image_with_backend(
    literal: &[u8],
    output: OutputKind,
    backend: SearchBackendPolicy,
) -> NativeImage {
    match output {
        OutputKind::Exists => {
            let program = build_exact_literal::<Exists>(
                literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("exact Exists IR");
            emit_with_backend(&program, backend, EmitLimits::default()).expect("exact Exists image")
        }
        OutputKind::SelectedEnd => {
            let program = build_exact_literal::<SelectedEnd>(
                literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("exact SelectedEnd IR");
            emit_with_backend(&program, backend, EmitLimits::default())
                .expect("exact SelectedEnd image")
        }
        OutputKind::Span => {
            let program = build_exact_literal::<Span>(
                literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("exact Span IR");
            emit_with_backend(&program, backend, EmitLimits::default()).expect("exact Span image")
        }
    }
}

fn v23_direct_target(index: usize, instruction: DecodedInstruction) -> Option<usize> {
    if !matches!(
        instruction,
        DecodedInstruction::Branch { .. }
            | DecodedInstruction::BranchCondition { .. }
            | DecodedInstruction::CompareBranchZero64 { .. }
    ) {
        return None;
    }
    let displacement = i64::from(instruction.direct_displacement()?);
    let byte_index = i64::try_from(index).ok()?.checked_mul(4)?;
    let target = byte_index.checked_add(displacement)?;
    if target < 0 || target % 4 != 0 {
        return None;
    }
    usize::try_from(target / 4).ok()
}

fn v23_without_direct_displacement(instruction: DecodedInstruction) -> DecodedInstruction {
    match instruction {
        DecodedInstruction::Branch { .. } => DecodedInstruction::Branch { displacement: 0 },
        DecodedInstruction::BranchCondition { condition, .. } => {
            DecodedInstruction::BranchCondition {
                condition,
                displacement: 0,
            }
        }
        DecodedInstruction::CompareBranchZero64 {
            register, nonzero, ..
        } => DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero,
            displacement: 0,
        },
        instruction => instruction,
    }
}

fn v23_cfg_reaches(
    decoded: &[DecodedInstruction],
    start: usize,
    goal: usize,
    blocked: Option<usize>,
) -> bool {
    let mut pending = vec![start];
    let mut visited = vec![false; decoded.len()];
    while let Some(index) = pending.pop() {
        if index >= decoded.len() || Some(index) == blocked || visited[index] {
            continue;
        }
        if index == goal {
            return true;
        }
        visited[index] = true;
        match decoded[index] {
            DecodedInstruction::Branch { .. } => {
                if let Some(target) = v23_direct_target(index, decoded[index]) {
                    pending.push(target);
                }
            }
            DecodedInstruction::BranchCondition { .. }
            | DecodedInstruction::CompareBranchZero64 { .. } => {
                if let Some(target) = v23_direct_target(index, decoded[index]) {
                    pending.push(target);
                }
                pending.push(index + 1);
            }
            DecodedInstruction::Return => {}
            _ => pending.push(index + 1),
        }
    }
    false
}

fn v24_sixth_static_start(decoded: &[DecodedInstruction], sixth_offset: u16) -> usize {
    decoded
        .windows(2)
        .position(|window| {
            window
                == [
                    DecodedInstruction::LoadByte {
                        destination: 10,
                        base: 8,
                        offset: sixth_offset,
                    },
                    DecodedInstruction::DuplicateByte16 {
                        destination: 24,
                        source: 10,
                    },
                ]
        })
        .expect("V24 lazy sixth-static literal broadcast")
}

fn v24_writes_vector(instruction: DecodedInstruction, register: u8) -> bool {
    match instruction {
        DecodedInstruction::LoadVector128 { destination, .. }
        | DecodedInstruction::DuplicateByte16 { destination, .. }
        | DecodedInstruction::CompareEqualBytes16 { destination, .. }
        | DecodedInstruction::AndBytes16 { destination, .. }
        | DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 { destination, .. }
        | DecodedInstruction::UnsignedMinBytes16 { destination, .. }
        | DecodedInstruction::UnsignedMaxBytes16 { destination, .. }
        | DecodedInstruction::UnsignedMaxPairwiseBytes16 { destination, .. }
        | DecodedInstruction::AddAcrossBytes16 { destination, .. } => destination == register,
        DecodedInstruction::LoadVectorPair128 {
            first_destination,
            second_destination,
            ..
        } => first_destination == register || second_destination == register,
        _ => false,
    }
}

#[test]
fn v23_policy_version_wire_and_output_contracts_are_explicit() {
    for width in 1_usize..6 {
        let literal = vec![b'x'; width];
        let outside_envelope = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("valid exact literal below the V23 envelope");
        assert_eq!(
            emit_with_backend(
                &outside_envelope,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            ),
            Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            }),
            "width={width}"
        );
    }
    let literal = v23_pointer_test_literal(13, false);
    let span =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V23 Span IR");
    assert_eq!(
        SearchBackendPolicy::AsimdV23.backend_version(),
        BackendVersion::SEARCH_V23
    );
    let selected = emit_with_backend(&span, SearchBackendPolicy::AsimdV23, EmitLimits::default())
        .expect("policy-selected V23 image");
    assert_eq!(
        selected,
        emit_search_version_for_test(&span, EmitLimits::default(), BackendVersion::SEARCH_V23,)
            .expect("version-selected V23 image")
    );

    let exists =
        build_exact_literal::<Exists>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V23 Exists IR");
    let selected_end = build_exact_literal::<SelectedEnd>(
        &literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("V23 SelectedEnd IR");
    for (output, image) in [
        (
            OutputKind::Exists,
            emit_with_backend(
                &exists,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            )
            .expect("V23 Exists image"),
        ),
        (
            OutputKind::SelectedEnd,
            emit_with_backend(
                &selected_end,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            )
            .expect("V23 SelectedEnd image"),
        ),
        (OutputKind::Span, selected.clone()),
    ] {
        assert_eq!(image.backend_version(), BackendVersion::SEARCH_V23);
        assert_eq!(
            image.search_manifest().expect("V23 manifest").output,
            output
        );
        let report = audit(&image).expect("whole-template V23 audit");
        assert_eq!(
            (report.decode_passes, report.source_identity_rebuilds),
            (1, 1)
        );
        assert!(image.code().len() <= 3_072);
        let aot = image.to_aot(AotLimits::default()).expect("bounded V23 AOT");
        assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x24");
        assert_eq!(aot.identity(), image.artifact_identity());
    }

    let v22 = emit_with_backend(&span, SearchBackendPolicy::AsimdV22, EmitLimits::default())
        .expect("frozen V22 image");
    assert_ne!(selected.artifact_identity(), v22.artifact_identity());

    let mut v23_as_v22 = selected.clone();
    v23_as_v22.backend_version = BackendVersion::SEARCH_V22;
    v23_as_v22
        .search
        .as_mut()
        .expect("V23 manifest")
        .backend_version = BackendVersion::SEARCH_V22;
    assert_resealed_search_rejected(v23_as_v22, "V23 code resealed as V22");

    let mut v22_as_v23 = v22;
    v22_as_v23.backend_version = BackendVersion::SEARCH_V23;
    v22_as_v23
        .search
        .as_mut()
        .expect("V22 manifest")
        .backend_version = BackendVersion::SEARCH_V23;
    assert_resealed_search_rejected(v22_as_v23, "V22 code resealed as V23");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the all-width decoded V23 proof keeps pointer setup, both reconstructions, X13 liveness, CFG dominance, and the frozen V22 suffix adjacent"
)]
fn v23_pointer_wide_cfg_and_x13_liveness_hold_for_every_width() {
    let mut zero_primary_cases = 0_u64;
    let mut nonzero_primary_cases = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V23 pointer CFG IR");
            let v22 = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV22,
                EmitLimits::default(),
            )
            .expect("frozen V22 CFG image");
            let v23 = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            )
            .expect("V23 pointer CFG image");
            audit(&v23).expect("V23 pointer CFG audit");
            assert!(v23.code().len() <= 3_072, "width={width}");
            let manifest = v23.search_manifest().expect("V23 pointer CFG manifest");
            assert_eq!(
                manifest.primary_offset,
                if zero_primary {
                    zero_primary_cases += 1;
                    0
                } else {
                    nonzero_primary_cases += 1;
                    u16::try_from(width - 1).expect("bounded primary offset")
                },
                "width={width} zero_primary={zero_primary}"
            );
            let v22_manifest = v22.search_manifest().expect("V22 CFG manifest");
            assert_eq!(
                (
                    manifest.primary_offset,
                    manifest.secondary_offset,
                    manifest.verification_offset,
                    manifest.quaternary_offset,
                    manifest.quinary_offset,
                ),
                (
                    v22_manifest.primary_offset,
                    v22_manifest.secondary_offset,
                    v22_manifest.verification_offset,
                    v22_manifest.quaternary_offset,
                    v22_manifest.quinary_offset,
                ),
                "V23 retains the V22 gate width={width} zero_primary={zero_primary}"
            );

            let primary_offset = manifest.primary_offset;
            let decoded = decode(v23.code()).expect("V23 pointer CFG decode");
            let bound_setup = decoded
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::AddRegister64 {
                            destination: 13,
                            left: 9,
                            right: 7,
                        }
                })
                .expect("V23 X13 final-primary-pointer setup");
            let after_bound = if primary_offset == 0 {
                bound_setup + 1
            } else {
                assert_eq!(
                    decoded[bound_setup + 1],
                    DecodedInstruction::AddImmediate64 {
                        destination: 13,
                        source: 13,
                        immediate: primary_offset,
                    },
                    "width={width}"
                );
                bound_setup + 2
            };
            let wide = decoded[after_bound..]
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::LoadVectorPair128 {
                            first_destination: 0,
                            second_destination: 2,
                            base: 15,
                            offset: 0,
                        }
                })
                .map(|offset| after_bound + offset)
                .expect("V23 primary-wide entry");
            assert!(
                decoded[after_bound..wide]
                    .iter()
                    .all(|instruction| instruction.written_gpr() != Some(13)),
                "X13 remains the final pointer before wide entry width={width}"
            );

            let learn_select = decoded[wide..]
                .windows(2)
                .position(|window| {
                    window
                        == [
                            DecodedInstruction::MoveRegister64 {
                                destination: 7,
                                source: 5,
                            },
                            DecodedInstruction::MoveZero64 {
                                destination: 13,
                                immediate: 0,
                                shift: 0,
                            },
                        ]
                })
                .map(|offset| wide + offset)
                .expect("V23 wide_learn_select");
            let first_x13_clobber = decoded[after_bound..]
                .iter()
                .position(|instruction| instruction.written_gpr() == Some(13))
                .map(|offset| after_bound + offset)
                .expect("V23 post-setup X13 reuse");
            assert_eq!(
                first_x13_clobber,
                learn_select + 1,
                "wide_learn_select is the first X13 clobber width={width}"
            );

            let pointer_advance = decoded[wide..learn_select]
                .windows(3)
                .position(|window| {
                    window[0]
                        == DecodedInstruction::AddImmediate64 {
                            destination: 15,
                            source: 15,
                            immediate: 64,
                        }
                        && window[1]
                            == DecodedInstruction::CompareRegister64 {
                                left: 15,
                                right: 13,
                            }
                        && matches!(
                            window[2],
                            DecodedInstruction::BranchCondition {
                                condition: Condition::LowerOrSame,
                                ..
                            }
                        )
                })
                .map(|offset| wide + offset)
                .expect("V23 primary-pointer advance");
            assert_eq!(
                v23_direct_target(pointer_advance + 2, decoded[pointer_advance + 2]),
                Some(wide),
                "V23 pointer bound backedge width={width}"
            );
            assert!(
                !matches!(
                    decoded[pointer_advance.saturating_sub(1)],
                    DecodedInstruction::AddImmediate64 {
                        destination: 5,
                        source: 5,
                        immediate: 64,
                    }
                ),
                "the primary-empty steady state removes the V22 X5 add width={width}"
            );

            let reconstructions = decoded[..learn_select]
                .iter()
                .enumerate()
                .filter_map(|(index, instruction)| {
                    (*instruction
                        == DecodedInstruction::SubtractRegister64 {
                            destination: 5,
                            left: 15,
                            right: 9,
                        })
                    .then_some(index)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                reconstructions.len(),
                2,
                "one exhaustion and one primary-hit reconstruction width={width}"
            );
            let exhaustion_reconstruction = pointer_advance + 3;
            assert!(
                reconstructions.contains(&exhaustion_reconstruction),
                "wide exhaustion reconstructs X5 width={width}"
            );
            let primary_hit_reconstruction = *reconstructions
                .iter()
                .find(|&&index| index != exhaustion_reconstruction)
                .expect("V23 primary-hit reconstruction");
            for &reconstruction in &reconstructions {
                if primary_offset == 0 {
                    assert_ne!(
                        decoded.get(reconstruction + 1),
                        Some(&DecodedInstruction::SubtractImmediate64 {
                            destination: 5,
                            source: 5,
                            immediate: 0,
                        }),
                        "zero offset needs no immediate reconstruction width={width}"
                    );
                } else {
                    assert_eq!(
                        decoded[reconstruction + 1],
                        DecodedInstruction::SubtractImmediate64 {
                            destination: 5,
                            source: 5,
                            immediate: primary_offset,
                        },
                        "width={width}"
                    );
                }
            }
            let primary_hit_edge = (wide..pointer_advance)
                .find(|&index| {
                    v23_direct_target(index, decoded[index]) == Some(primary_hit_reconstruction)
                })
                .expect("V23 primary-hit edge");
            assert!(
                matches!(
                    decoded[primary_hit_edge],
                    DecodedInstruction::CompareBranchZero64 {
                        register: 10,
                        nonzero: true,
                        ..
                    }
                ),
                "primary presence reaches reconstruction width={width}"
            );

            let incoming_pointer_advances = decoded[..learn_select]
                .iter()
                .enumerate()
                .filter_map(|(index, instruction)| {
                    (v23_direct_target(index, *instruction) == Some(pointer_advance))
                        .then_some(index)
                })
                .collect::<Vec<_>>();
            assert!(
                incoming_pointer_advances.len() == 3,
                "static-empty paths return to the pointer advance width={width}"
            );
            assert!(
                incoming_pointer_advances
                    .iter()
                    .all(|&index| index > primary_hit_reconstruction),
                "every static backedge is dominated by X5 reconstruction width={width}"
            );
            assert!(
                v23_cfg_reaches(&decoded, 0, learn_select, None),
                "wide learning is reachable width={width}"
            );
            assert!(
                !v23_cfg_reaches(&decoded, 0, learn_select, Some(primary_hit_reconstruction),),
                "primary-hit X5 reconstruction dominates wide learning width={width}"
            );
            assert!(
                !v23_cfg_reaches(&decoded, learn_select, pointer_advance, None),
                "learned state cannot return to pointer-only advance width={width}"
            );

            let v22_decoded = decode(v22.code()).expect("V22 suffix decode");
            let v22_learn_select = v22_decoded
                .windows(2)
                .position(|window| {
                    window
                        == [
                            DecodedInstruction::MoveRegister64 {
                                destination: 7,
                                source: 5,
                            },
                            DecodedInstruction::MoveZero64 {
                                destination: 13,
                                immediate: 0,
                                shift: 0,
                            },
                        ]
                })
                .expect("V22 wide_learn_select");
            assert_eq!(
                decoded[learn_select..]
                    .iter()
                    .copied()
                    .map(v23_without_direct_displacement)
                    .collect::<Vec<_>>(),
                v22_decoded[v22_learn_select..]
                    .iter()
                    .copied()
                    .map(v23_without_direct_displacement)
                    .collect::<Vec<_>>(),
                "V23 retains the complete V22 learned and suffix graph width={width}"
            );
        }
    }
    assert_eq!(zero_primary_cases, 27);
    assert_eq!(nonzero_primary_cases, 27);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V23 mutation test authenticates the bound, advance, comparison, and both reconstruction exits together"
)]
fn v23_rejects_resealed_bound_advance_compare_and_both_reconstruction_mutations() {
    let literal = v23_pointer_test_literal(13, false);
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V23 pointer mutation IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV23,
        EmitLimits::default(),
    )
    .expect("V23 pointer mutation image");
    let decoded = decode(image.code()).expect("V23 pointer mutation decode");
    let learn_select = decoded
        .windows(2)
        .position(|window| {
            window
                == [
                    DecodedInstruction::MoveRegister64 {
                        destination: 7,
                        source: 5,
                    },
                    DecodedInstruction::MoveZero64 {
                        destination: 13,
                        immediate: 0,
                        shift: 0,
                    },
                ]
        })
        .expect("V23 mutation wide_learn_select");
    let bound = decoded[..learn_select]
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::AddRegister64 {
                    destination: 13,
                    left: 9,
                    right: 7,
                }
        })
        .expect("V23 mutation bound");
    let advance = decoded[..learn_select]
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::AddImmediate64 {
                    destination: 15,
                    source: 15,
                    immediate: 64,
                }
        })
        .expect("V23 mutation pointer advance");
    let comparison = decoded[advance + 1..learn_select]
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::CompareRegister64 {
                    left: 15,
                    right: 13,
                }
        })
        .map(|offset| advance + 1 + offset)
        .expect("V23 mutation pointer comparison");
    let reconstructions = decoded[..learn_select]
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (*instruction
                == DecodedInstruction::SubtractRegister64 {
                    destination: 5,
                    left: 15,
                    right: 9,
                })
            .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(reconstructions.len(), 2);

    let mut wrong_bound = image.clone();
    replace_test_decoded_at(
        &mut wrong_bound,
        bound,
        DecodedInstruction::AddRegister64 {
            destination: 13,
            left: 9,
            right: 6,
        },
    );
    assert_resealed_search_rejected(wrong_bound, "V23 X13 bound source substitution");

    let mut wrong_advance = image.clone();
    replace_test_decoded_at(
        &mut wrong_advance,
        advance,
        DecodedInstruction::AddImmediate64 {
            destination: 15,
            source: 15,
            immediate: 63,
        },
    );
    assert_resealed_search_rejected(wrong_advance, "V23 pointer stride substitution");

    let mut wrong_comparison = image.clone();
    replace_test_decoded_at(
        &mut wrong_comparison,
        comparison,
        DecodedInstruction::CompareRegister64 { left: 15, right: 7 },
    );
    assert_resealed_search_rejected(wrong_comparison, "V23 pointer bound substitution");

    for (exit, reconstruction) in ["wide exhaustion", "primary hit"]
        .into_iter()
        .zip(reconstructions)
    {
        let mut wrong_reconstruction = image.clone();
        replace_test_decoded_at(
            &mut wrong_reconstruction,
            reconstruction,
            DecodedInstruction::SubtractRegister64 {
                destination: 5,
                left: 15,
                right: 8,
            },
        );
        assert_resealed_search_rejected(
            wrong_reconstruction,
            &format!("V23 {exit} reconstruction base substitution"),
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V23 pointer-state semantic gate keeps every exit and pre-learning backedge scenario explicit"
)]
fn v23_primary_pointer_exits_and_static_backedges_match_the_kir_oracle() {
    let mut comparisons = 0_u64;
    for width in [6_usize, 13, 32] {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V23 pointer semantic IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            )
            .expect("V23 pointer semantic image");
            audit(&image).expect("V23 pointer semantic audit");
            let manifest = image.search_manifest().expect("V23 pointer manifest");
            let selected = [
                manifest.primary_offset,
                manifest.secondary_offset,
                manifest.verification_offset,
                manifest.quaternary_offset,
                manifest.quinary_offset,
            ]
            .map(usize::from);
            let avoid = (0_u16..=255)
                .map(|value| u8::try_from(value).expect("bounded byte"))
                .find(|byte| !literal.contains(byte))
                .expect("V23 pointer literal leaves an avoiding byte");
            let window_start = 3_usize;
            let wide_base = window_start + 1;
            let post_three_wide = wide_base + 3 * 64;

            // The first three complete primary groups are empty. Exercise
            // every pointer-only exit: another wide group containing a match,
            // wide exhaustion into narrow, wide exhaustion into scalar tail,
            // and a no-match exhaustion.
            for (kind, exact, last_candidate) in [
                (
                    "wide exact",
                    Some(post_three_wide + 11),
                    post_three_wide + 80,
                ),
                (
                    "narrow exact",
                    Some(post_three_wide + 7),
                    post_three_wide + 20,
                ),
                ("tail exact", Some(post_three_wide + 7), post_three_wide + 7),
                ("no match", None, post_three_wide + 7),
            ] {
                let window_end = last_candidate + width;
                let mut haystack = vec![avoid; window_end + 17];
                if let Some(candidate) = exact {
                    haystack[candidate..candidate + width].copy_from_slice(&literal);
                }
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(window_start, window_end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V23 pointer-exit oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, &haystack, window_start, window_end)
                    .expect("V23 pointer-exit simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} zero_primary={zero_primary} exit={kind}"
                );
                assert_eq!(
                    expected,
                    exact.map(|candidate| (candidate, candidate + width)),
                    "width={width} zero_primary={zero_primary} exit={kind}"
                );
                comparisons = comparisons.checked_add(1).expect("bounded exit matrix");
            }

            // Passing primary and secondary before each remaining static
            // column becomes empty must return through pointer-wide advance.
            // Repeat across three groups so stale X5 or clobbered X13 cannot
            // accidentally survive a single transition.
            for missing_stage in 2_usize..selected.len() {
                let exact = post_three_wide + 7;
                let last_candidate = post_three_wide + 20;
                let window_end = last_candidate + width;
                let mut haystack = vec![avoid; window_end + 17];
                for group in 0..3_usize {
                    let false_candidate = wide_base + group * 64 + 5;
                    for &offset in &selected[..missing_stage] {
                        haystack[false_candidate + offset] = literal[offset];
                    }
                    assert_eq!(haystack[false_candidate + selected[missing_stage]], avoid);
                }
                haystack[exact..exact + width].copy_from_slice(&literal);
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(window_start, window_end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V23 static-empty oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, &haystack, window_start, window_end)
                    .expect("V23 static-empty simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} zero_primary={zero_primary} missing_stage={missing_stage}"
                );
                assert_eq!(expected, Some((exact, exact + width)));
                comparisons = comparisons
                    .checked_add(1)
                    .expect("bounded static-empty matrix");
            }

            // A primary hit without its secondary enters secondary-only
            // mode. An empty secondary group advances in that mode; a later
            // secondary hit without primary rechecks the primary masks and
            // returns to pointer-wide advance before the exact group.
            let primary_only = wide_base + 5;
            let secondary_only = wide_base + 2 * 64 + 9;
            let exact = wide_base + 3 * 64 + 11;
            let window_end = exact + width + 80;
            let mut haystack = vec![avoid; window_end + 17];
            haystack[primary_only + selected[0]] = literal[selected[0]];
            assert_eq!(haystack[primary_only + selected[1]], avoid);
            haystack[secondary_only + selected[1]] = literal[selected[1]];
            assert_eq!(haystack[secondary_only + selected[0]], avoid);
            haystack[exact..exact + width].copy_from_slice(&literal);
            let expected = program
                .execute(
                    &haystack,
                    SearchWindow::new(window_start, window_end),
                    ExecutionLimits::unlimited(),
                )
                .expect("V23 secondary-only oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            let actual = simulate(&image, &haystack, window_start, window_end)
                .expect("V23 secondary-only simulation");
            assert_eq!(
                span_output(actual),
                expected,
                "width={width} zero_primary={zero_primary} secondary-only"
            );
            assert_eq!(expected, Some((exact, exact + width)));
            comparisons = comparisons
                .checked_add(1)
                .expect("bounded secondary-only matrix");
        }
    }
    assert_eq!(comparisons, 3 * 2 * (4 + 3 + 1));
}

#[test]
fn v23_learns_every_unselected_mismatch_at_zero_and_nonzero_primary_offsets() {
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V23 every-mismatch IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            )
            .expect("V23 every-mismatch image");
            audit(&image).expect("V23 every-mismatch audit");
            let manifest = image
                .search_manifest()
                .expect("V23 every-mismatch manifest");
            let selected = [
                manifest.primary_offset,
                manifest.secondary_offset,
                manifest.verification_offset,
                manifest.quaternary_offset,
                manifest.quinary_offset,
            ]
            .map(usize::from);
            let avoid = (0_u16..=255)
                .map(|value| u8::try_from(value).expect("bounded byte"))
                .find(|byte| !literal.contains(byte))
                .expect("V23 literal leaves an avoiding byte");
            let window_start = 3_usize;
            let wide_base = window_start + 1;
            let false_candidate = wide_base + 7;
            let exact = wide_base + 4 * 64 + 11;

            for mismatch in (0..width).filter(|offset| !selected.contains(offset)) {
                let mut haystack = vec![avoid; exact + width + 96];
                haystack[false_candidate..false_candidate + width].copy_from_slice(&literal);
                haystack[false_candidate + mismatch] = avoid;
                haystack[exact..exact + width].copy_from_slice(&literal);
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(window_start, haystack.len()),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V23 every-mismatch oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                let actual = simulate(&image, &haystack, window_start, haystack.len())
                    .expect("V23 every-mismatch simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} zero_primary={zero_primary} mismatch={mismatch}"
                );
                assert_eq!(expected, Some((exact, exact + width)));
                comparisons = comparisons
                    .checked_add(1)
                    .expect("bounded V23 mismatch matrix");
            }
        }
    }
    assert_eq!(comparisons, 2 * (513 - 27 * 5));
}

#[test]
fn v23_wide_to_narrow_and_tail_boundaries_cover_every_window_residue() {
    let mut comparisons = 0_u64;
    for width in [6_usize, 13, 32] {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V23 boundary IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            )
            .expect("V23 boundary image");
            let manifest = image.search_manifest().expect("V23 boundary manifest");
            let selected = [
                manifest.primary_offset,
                manifest.secondary_offset,
                manifest.verification_offset,
                manifest.quaternary_offset,
                manifest.quinary_offset,
            ]
            .map(usize::from);
            let avoid = (0_u16..=255)
                .map(|value| u8::try_from(value).expect("bounded byte"))
                .find(|byte| !literal.contains(byte))
                .expect("V23 boundary literal leaves an avoiding byte");

            for window_start in 0_usize..16 {
                let wide_base = window_start + 1;
                let false_candidate = wide_base + 5;
                for (kind, exact, last_candidate) in [
                    ("narrow", wide_base + 64 + 7, wide_base + 64 + 20),
                    ("tail", wide_base + 64 + 18, wide_base + 64 + 18),
                ] {
                    let window_end = last_candidate + width;
                    let mut haystack = vec![avoid; window_end + 17];
                    for &offset in &selected {
                        haystack[false_candidate + offset] = literal[offset];
                    }
                    haystack[exact..exact + width].copy_from_slice(&literal);
                    let expected = program
                        .execute(
                            &haystack,
                            SearchWindow::new(window_start, window_end),
                            ExecutionLimits::unlimited(),
                        )
                        .expect("V23 boundary oracle")
                        .output()
                        .map(|span| (span.start(), span.end()));
                    let actual = simulate(&image, &haystack, window_start, window_end)
                        .expect("V23 boundary simulation");
                    assert_eq!(
                        span_output(actual),
                        expected,
                        "width={width} zero_primary={zero_primary} residue={window_start} kind={kind}"
                    );
                    assert_eq!(expected, Some((exact, exact + width)));
                    comparisons = comparisons
                        .checked_add(1)
                        .expect("bounded V23 boundary matrix");
                }
            }
        }
    }
    assert_eq!(comparisons, 3 * 2 * 16 * 2);
}

#[test]
fn v23_every_width_primary_offset_and_window_shape_matches_the_kir_oracle() {
    let mut state = 0x8c74_15a9_d20e_f36b_u64;
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V23 every-width IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            )
            .expect("V23 every-width image");
            audit(&image).expect("V23 every-width audit");

            for case in 0..8_usize {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let hay_len = 256 + usize::try_from(state >> 24).expect("host usize") % 257;
                let mut haystack = Vec::with_capacity(hay_len);
                for _ in 0..hay_len {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    haystack.push(state.to_le_bytes()[0]);
                }

                let exact = (case & 1 == 0).then(|| {
                    5 + (usize::try_from(state >> 8).expect("host usize")
                        % (haystack.len() - width - 5))
                });
                if let Some(candidate) = exact {
                    haystack[candidate..candidate + width].copy_from_slice(&literal);
                }

                let random_start =
                    usize::try_from(state >> 16).expect("host usize") % (haystack.len() + 1);
                let random_end = random_start
                    + (usize::try_from(state >> 32).expect("host usize")
                        % (haystack.len() - random_start + 1));
                let short_end = width.saturating_sub(1).min(haystack.len());
                let exact_window = exact.map_or((random_start, random_end), |candidate| {
                    (candidate, candidate + width)
                });
                let windows = [
                    (0, 0),
                    (0, short_end),
                    (0, haystack.len()),
                    (random_start, haystack.len()),
                    (random_start, random_end),
                    exact_window,
                ];
                for (start, end) in windows {
                    let expected = program
                        .execute(
                            &haystack,
                            SearchWindow::new(start, end),
                            ExecutionLimits::unlimited(),
                        )
                        .expect("V23 every-width oracle")
                        .output()
                        .map(|span| (span.start(), span.end()));
                    let actual = simulate(&image, &haystack, start, end)
                        .expect("V23 every-width safe ISA simulation");
                    assert_eq!(
                        span_output(actual),
                        expected,
                        "width={width} zero_primary={zero_primary} case={case} window={start}..{end}"
                    );
                    comparisons = comparisons
                        .checked_add(1)
                        .expect("bounded V23 random matrix");
                }
            }
        }
    }
    assert_eq!(comparisons, 2_592);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the all-width V24 decoded proof keeps sixth selection, five-column dominance, empty routing, and Q24 overwrite liveness adjacent"
)]
fn v24_policy_wire_sixth_selection_cfg_and_q24_liveness_are_explicit() {
    for width in 1_usize..6 {
        let literal = vec![b'x'; width];
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("valid exact literal below the V24 envelope");
        assert_eq!(
            emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV24,
                EmitLimits::default(),
            ),
            Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            }),
            "width={width}"
        );
    }
    assert_eq!(
        SearchBackendPolicy::AsimdV24.backend_version(),
        BackendVersion::SEARCH_V24
    );

    let mut cases = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V24 structural IR");
            let v23 = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV23,
                EmitLimits::default(),
            )
            .expect("frozen V23 structural image");
            let v24 = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV24,
                EmitLimits::default(),
            )
            .expect("V24 structural image");
            let report = audit(&v24).expect("independent V24 template");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 1)
            );
            assert_eq!(v24.backend_version(), BackendVersion::SEARCH_V24);
            assert!(v24.code().len() <= 3_072, "width={width}");
            assert_eq!(
                &v24.to_aot(AotLimits::default())
                    .expect("bounded V24 AOT")
                    .as_bytes()[..8],
                b"FREA64\0\x25"
            );
            assert_ne!(v24.artifact_identity(), v23.artifact_identity());

            let manifest = v24.search_manifest().expect("V24 structural manifest");
            let prior = v23.search_manifest().expect("V23 structural manifest");
            assert_eq!(
                (
                    manifest.primary_offset,
                    manifest.secondary_offset,
                    manifest.verification_offset,
                    manifest.quaternary_offset,
                    manifest.quinary_offset,
                ),
                (
                    prior.primary_offset,
                    prior.secondary_offset,
                    prior.verification_offset,
                    prior.quaternary_offset,
                    prior.quinary_offset,
                ),
                "V24 changes no manifest field width={width} zero_primary={zero_primary}"
            );
            let sixth =
                crate::search_template::independent_sixth_static_offset_v24(&literal, manifest)
                    .expect("one remaining V24 offset");
            assert!(usize::from(sixth) < width);
            assert!(
                ![
                    manifest.primary_offset,
                    manifest.secondary_offset,
                    manifest.verification_offset,
                    manifest.quaternary_offset,
                    manifest.quinary_offset,
                ]
                .contains(&sixth),
                "sixth offset is distinct width={width} zero_primary={zero_primary}"
            );

            let decoded = decode(v24.code()).expect("V24 structural decode");
            let sixth_start = v24_sixth_static_start(&decoded, sixth);
            assert!(
                decoded[..sixth_start]
                    .iter()
                    .all(|&instruction| !v24_writes_vector(instruction, 24)),
                "Q24 is dead before lazy sixth entry width={width} zero_primary={zero_primary}"
            );
            let delta = sixth.abs_diff(manifest.primary_offset);
            assert_eq!(
                decoded[sixth_start + 2],
                if sixth > manifest.primary_offset {
                    DecodedInstruction::AddImmediate64 {
                        destination: 10,
                        source: 15,
                        immediate: delta,
                    }
                } else {
                    DecodedInstruction::SubtractImmediate64 {
                        destination: 10,
                        source: 15,
                        immediate: delta,
                    }
                },
                "sixth column address width={width} zero_primary={zero_primary}"
            );
            assert_eq!(
                &decoded[sixth_start + 3..sixth_start + 13],
                &[
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
                    DecodedInstruction::CompareEqualBytes16 {
                        destination: 18,
                        left: 18,
                        right: 24,
                    },
                    DecodedInstruction::AndBytes16 {
                        destination: 0,
                        left: 0,
                        right: 18,
                    },
                    DecodedInstruction::CompareEqualBytes16 {
                        destination: 19,
                        left: 19,
                        right: 24,
                    },
                    DecodedInstruction::AndBytes16 {
                        destination: 2,
                        left: 2,
                        right: 19,
                    },
                    DecodedInstruction::CompareEqualBytes16 {
                        destination: 20,
                        left: 20,
                        right: 24,
                    },
                    DecodedInstruction::AndBytes16 {
                        destination: 4,
                        left: 4,
                        right: 20,
                    },
                    DecodedInstruction::CompareEqualBytes16 {
                        destination: 21,
                        left: 21,
                        right: 24,
                    },
                    DecodedInstruction::AndBytes16 {
                        destination: 6,
                        left: 6,
                        right: 21,
                    },
                ],
                "exact sixth static algebra width={width} zero_primary={zero_primary}"
            );

            let fifth_empty = decoded[..sixth_start]
                .iter()
                .rposition(|instruction| {
                    matches!(
                        instruction,
                        DecodedInstruction::CompareBranchZero64 {
                            register: 10,
                            nonzero: false,
                            ..
                        }
                    )
                })
                .expect("five-column empty branch");
            assert_eq!(
                fifth_empty + 1,
                sixth_start,
                "sixth load is the fallthrough after five-column survival"
            );
            let sixth_empty = decoded[sixth_start + 13..]
                .iter()
                .position(|instruction| {
                    matches!(
                        instruction,
                        DecodedInstruction::CompareBranchZero64 {
                            register: 10,
                            nonzero: false,
                            ..
                        }
                    )
                })
                .map(|offset| sixth_start + 13 + offset)
                .expect("sixth-empty branch");
            assert_eq!(
                v23_direct_target(fifth_empty, decoded[fifth_empty]),
                v23_direct_target(sixth_empty, decoded[sixth_empty]),
                "five-empty and sixth-empty share V23 wide advance"
            );
            let learn_edge = sixth_empty + 1;
            assert!(matches!(
                decoded[learn_edge],
                DecodedInstruction::Branch { .. }
            ));
            let learn_select = v23_direct_target(learn_edge, decoded[learn_edge])
                .expect("V24 branch to unchanged wide_learn_select");
            assert_eq!(
                &decoded[learn_select..learn_select + 2],
                &[
                    DecodedInstruction::MoveRegister64 {
                        destination: 7,
                        source: 5,
                    },
                    DecodedInstruction::MoveZero64 {
                        destination: 13,
                        immediate: 0,
                        shift: 0,
                    },
                ]
            );

            let learned_overwrite = decoded[learn_select..]
                .iter()
                .position(|instruction| {
                    *instruction
                        == DecodedInstruction::DuplicateByte16 {
                            destination: 24,
                            source: 13,
                        }
                })
                .map(|offset| learn_select + offset)
                .expect("V24 learned Q24 overwrite");
            assert!(
                decoded[sixth_start + 2..learned_overwrite]
                    .iter()
                    .all(|&instruction| !v24_writes_vector(instruction, 24)),
                "only the sixth broadcast owns Q24 before learned overwrite"
            );
            let learned_consumer = decoded[learned_overwrite + 1..]
                .iter()
                .position(|instruction| {
                    matches!(
                        instruction,
                        DecodedInstruction::CompareEqualBytes16 { right: 24, .. }
                    )
                })
                .map(|offset| learned_overwrite + 1 + offset)
                .expect("V24 learned Q24 consumer");
            assert!(
                !v23_cfg_reaches(
                    &decoded,
                    learn_select,
                    learned_consumer,
                    Some(learned_overwrite),
                ),
                "learned Q24 overwrite dominates learned consumers"
            );
            cases = cases.checked_add(1).expect("bounded V24 cases");
        }
    }
    assert_eq!(cases, 54);
}

#[test]
fn v24_all_search_output_contracts_emit_audit_and_serialize() {
    let literal = v23_pointer_test_literal(13, false);
    let exists =
        build_exact_literal::<Exists>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V24 Exists IR");
    let selected_end = build_exact_literal::<SelectedEnd>(
        &literal,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("V24 SelectedEnd IR");
    let span =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V24 Span IR");
    for (output, image) in [
        (
            OutputKind::Exists,
            emit_with_backend(
                &exists,
                SearchBackendPolicy::AsimdV24,
                EmitLimits::default(),
            )
            .expect("V24 Exists image"),
        ),
        (
            OutputKind::SelectedEnd,
            emit_with_backend(
                &selected_end,
                SearchBackendPolicy::AsimdV24,
                EmitLimits::default(),
            )
            .expect("V24 SelectedEnd image"),
        ),
        (
            OutputKind::Span,
            emit_with_backend(&span, SearchBackendPolicy::AsimdV24, EmitLimits::default())
                .expect("V24 Span image"),
        ),
    ] {
        assert_eq!(image.backend_version(), BackendVersion::SEARCH_V24);
        assert_eq!(image.output(), output);
        audit(&image).expect("whole-template V24 output audit");
        assert!(image.code().len() <= 3_072);
        assert_eq!(
            &image
                .to_aot(AotLimits::default())
                .expect("bounded V24 output AOT")
                .as_bytes()[..8],
            b"FREA64\0\x25"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V24 mutation gate authenticates every new sixth-static operand and edge at one reviewable site"
)]
fn v24_rejects_resealed_sixth_load_address_broadcast_filter_and_branch_mutations() {
    let literal = v23_pointer_test_literal(13, false);
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V24 mutation IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV24,
        EmitLimits::default(),
    )
    .expect("V24 mutation image");
    let manifest = image.search_manifest().expect("V24 mutation manifest");
    let sixth = crate::search_template::independent_sixth_static_offset_v24(&literal, manifest)
        .expect("V24 mutation sixth offset");
    let decoded = decode(image.code()).expect("V24 mutation decode");
    let start = v24_sixth_static_start(&decoded, sixth);
    let sixth_empty = decoded[start + 13..]
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 10,
                    nonzero: false,
                    ..
                }
            )
        })
        .map(|offset| start + 13 + offset)
        .expect("V24 mutation sixth-empty branch");

    let mut wrong_literal_offset = image.clone();
    replace_test_decoded_at(
        &mut wrong_literal_offset,
        start,
        DecodedInstruction::LoadByte {
            destination: 10,
            base: 8,
            offset: (sixth + 1) % 13,
        },
    );
    assert_resealed_search_rejected(
        wrong_literal_offset,
        "V24 sixth literal load offset substitution",
    );

    let mut wrong_address = image.clone();
    replace_test_decoded_at(
        &mut wrong_address,
        start + 2,
        match decoded[start + 2] {
            DecodedInstruction::AddImmediate64 {
                destination,
                source,
                immediate,
            } => DecodedInstruction::AddImmediate64 {
                destination,
                source,
                immediate: immediate + 1,
            },
            DecodedInstruction::SubtractImmediate64 {
                destination,
                source,
                immediate,
            } => DecodedInstruction::SubtractImmediate64 {
                destination,
                source,
                immediate: immediate + 1,
            },
            instruction => panic!("unexpected V24 sixth address: {instruction:?}"),
        },
    );
    assert_resealed_search_rejected(wrong_address, "V24 sixth column address substitution");

    let mut wrong_broadcast = image.clone();
    replace_test_decoded_at(
        &mut wrong_broadcast,
        start + 1,
        DecodedInstruction::DuplicateByte16 {
            destination: 22,
            source: 10,
        },
    );
    assert_resealed_search_rejected(wrong_broadcast, "V24 sixth Q24 broadcast substitution");

    let mut wrong_pair_base = image.clone();
    replace_test_decoded_at(
        &mut wrong_pair_base,
        start + 3,
        DecodedInstruction::LoadVectorPair128 {
            first_destination: 18,
            second_destination: 19,
            base: 11,
            offset: 0,
        },
    );
    assert_resealed_search_rejected(wrong_pair_base, "V24 sixth column pair-load base");

    for index in [start + 5, start + 7, start + 9, start + 11] {
        let DecodedInstruction::CompareEqualBytes16 {
            destination,
            left,
            right: 24,
        } = decoded[index]
        else {
            panic!("unexpected V24 sixth comparison at {index}");
        };
        let mut wrong_comparison = image.clone();
        replace_test_decoded_at(
            &mut wrong_comparison,
            index,
            DecodedInstruction::CompareEqualBytes16 {
                destination,
                left,
                right: 23,
            },
        );
        assert_resealed_search_rejected(
            wrong_comparison,
            &format!("V24 sixth comparison substitution at {index}"),
        );
    }
    for index in [start + 6, start + 8, start + 10, start + 12] {
        let DecodedInstruction::AndBytes16 {
            destination,
            left,
            right,
        } = decoded[index]
        else {
            panic!("unexpected V24 sixth intersection at {index}");
        };
        let mut wrong_intersection = image.clone();
        replace_test_decoded_at(
            &mut wrong_intersection,
            index,
            DecodedInstruction::AndBytes16 {
                destination,
                left,
                right: if right == 17 { 18 } else { 17 },
            },
        );
        assert_resealed_search_rejected(
            wrong_intersection,
            &format!("V24 sixth intersection substitution at {index}"),
        );
    }

    let DecodedInstruction::CompareBranchZero64 {
        register,
        nonzero,
        displacement,
    } = decoded[sixth_empty]
    else {
        panic!("unexpected V24 sixth-empty edge");
    };
    let mut inverted_empty = image.clone();
    replace_test_decoded_at(
        &mut inverted_empty,
        sixth_empty,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: !nonzero,
            displacement,
        },
    );
    assert_resealed_search_rejected(inverted_empty, "V24 sixth-empty branch inversion");

    let v23 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV23,
        EmitLimits::default(),
    )
    .expect("frozen V23 relabel image");
    let mut v24_as_v23 = image;
    v24_as_v23.backend_version = BackendVersion::SEARCH_V23;
    v24_as_v23
        .search
        .as_mut()
        .expect("V24 relabel manifest")
        .backend_version = BackendVersion::SEARCH_V23;
    assert_resealed_search_rejected(v24_as_v23, "V24 code resealed as V23");

    let mut v23_as_v24 = v23;
    v23_as_v24.backend_version = BackendVersion::SEARCH_V24;
    v23_as_v24
        .search
        .as_mut()
        .expect("V23 relabel manifest")
        .backend_version = BackendVersion::SEARCH_V24;
    assert_resealed_search_rejected(v23_as_v24, "V23 code resealed as V24");
}

fn v25_promotion_sites(decoded: &[DecodedInstruction], sixth: u16) -> (usize, usize, usize) {
    let sixth_start = v24_sixth_static_start(decoded, sixth);
    let sixth_empty = decoded[sixth_start + 13..]
        .iter()
        .position(|instruction| {
            matches!(
                instruction,
                DecodedInstruction::CompareBranchZero64 {
                    register: 10,
                    nonzero: false,
                    ..
                }
            )
        })
        .map(|offset| sixth_start + 13 + offset)
        .expect("V25 sixth-empty edge");
    let promotion = v23_direct_target(sixth_empty, decoded[sixth_empty])
        .expect("V25 sixth-empty promotion target");
    (sixth_start, sixth_empty, promotion)
}

#[test]
fn v25_exact_promotion_cfg_is_authenticated_for_every_width_and_primary_form() {
    assert_eq!(
        SearchBackendPolicy::AsimdV25.backend_version(),
        BackendVersion::SEARCH_V25
    );
    let mut cases = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V25 CFG IR");
            let v24 = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV24,
                EmitLimits::default(),
            )
            .expect("frozen V24 CFG image");
            let v25 = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV25,
                EmitLimits::default(),
            )
            .expect("V25 CFG image");
            let report = audit(&v25).expect("independent exact V25 template");
            assert_eq!(
                (report.decode_passes, report.source_identity_rebuilds),
                (1, 1)
            );
            assert_eq!(v25.backend_version(), BackendVersion::SEARCH_V25);
            assert_eq!(
                &v25.to_aot(AotLimits::default())
                    .expect("bounded V25 AOT")
                    .as_bytes()[..8],
                b"FREA64\0\x26"
            );
            let manifest = v25.search_manifest().expect("V25 CFG manifest");
            let prior = v24.search_manifest().expect("V24 CFG manifest");
            assert_eq!(
                (
                    manifest.primary_offset,
                    manifest.secondary_offset,
                    manifest.verification_offset,
                    manifest.quaternary_offset,
                    manifest.quinary_offset,
                ),
                (
                    prior.primary_offset,
                    prior.secondary_offset,
                    prior.verification_offset,
                    prior.quaternary_offset,
                    prior.quinary_offset,
                ),
                "V25 preserves all five manifest columns width={width} zero_primary={zero_primary}"
            );
            let sixth =
                crate::search_template::independent_sixth_static_offset_v24(&literal, manifest)
                    .expect("V25 deterministic sixth offset");
            let decoded = decode(v25.code()).expect("V25 CFG decode");
            let (sixth_start, sixth_empty, promotion) = v25_promotion_sites(&decoded, sixth);
            assert_eq!(
                &decoded[promotion..promotion + 5],
                &[
                    DecodedInstruction::MoveZero64 {
                        destination: 10,
                        immediate: sixth,
                        shift: 0,
                    },
                    DecodedInstruction::DuplicateByte16 {
                        destination: 25,
                        source: 10,
                    },
                    DecodedInstruction::MoveZero64 {
                        destination: 11,
                        immediate: 1,
                        shift: 0,
                    },
                    DecodedInstruction::SubtractImmediate64 {
                        destination: 7,
                        source: 6,
                        immediate: 63,
                    },
                    decoded[promotion + 4],
                ],
                "exact V25 promotion operands width={width} zero_primary={zero_primary}"
            );
            let DecodedInstruction::Branch { .. } = decoded[promotion + 4] else {
                panic!("V25 promotion must branch to persistent advance");
            };
            let persistent_advance = v23_direct_target(promotion + 4, decoded[promotion + 4])
                .expect("V25 persistent-advance target");
            assert!(
                decoded[sixth_start..promotion + 5]
                    .iter()
                    .all(|instruction| !matches!(instruction.written_gpr(), Some(5 | 15))),
                "the sixth filter and promotion preserve exact X5/X15 cursors width={width} zero_primary={zero_primary}"
            );
            assert_eq!(
                &decoded[persistent_advance..persistent_advance + 4],
                &[
                    DecodedInstruction::AddImmediate64 {
                        destination: 5,
                        source: 5,
                        immediate: 64,
                    },
                    DecodedInstruction::AddImmediate64 {
                        destination: 15,
                        source: 15,
                        immediate: 64,
                    },
                    DecodedInstruction::CompareRegister64 { left: 5, right: 7 },
                    decoded[persistent_advance + 3],
                ]
            );
            assert!(matches!(
                decoded[persistent_advance + 3],
                DecodedInstruction::BranchCondition {
                    condition: Condition::LowerOrSame,
                    ..
                }
            ));

            let recovery_edge = sixth_empty + 1;
            let DecodedInstruction::Branch { .. } = decoded[recovery_edge] else {
                panic!("V25 sixth survivor must retain the V24 recovery edge");
            };
            let recovery = v23_direct_target(recovery_edge, decoded[recovery_edge])
                .expect("V25 recovery target");
            assert_eq!(
                &decoded[recovery..recovery + 2],
                &[
                    DecodedInstruction::MoveRegister64 {
                        destination: 7,
                        source: 5,
                    },
                    DecodedInstruction::MoveZero64 {
                        destination: 13,
                        immediate: 0,
                        shift: 0,
                    },
                ]
            );
            assert!(
                decoded[sixth_start + 2..=sixth_empty]
                    .iter()
                    .chain(decoded[promotion..promotion + 5].iter())
                    .all(|&instruction| !v24_writes_vector(instruction, 24)),
                "the promotion edge retains Q24 width={width} zero_primary={zero_primary}"
            );
            let persistent_q24_consumer = decoded[persistent_advance..]
                .iter()
                .position(|instruction| {
                    matches!(
                        instruction,
                        DecodedInstruction::CompareEqualBytes16 { right: 24, .. }
                    )
                })
                .map(|offset| persistent_advance + offset)
                .expect("persistent graph consumes promoted Q24");
            assert!(
                decoded[persistent_advance..persistent_q24_consumer]
                    .iter()
                    .all(|&instruction| !v24_writes_vector(instruction, 24)),
                "persistent graph consumes retained Q24 before any overwrite"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 54);
}

#[test]
fn v25_rejects_every_promotion_operand_edge_and_v24_relabel() {
    let literal = v23_pointer_test_literal(13, false);
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V25 mutation IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV25,
        EmitLimits::default(),
    )
    .expect("V25 mutation image");
    let manifest = image.search_manifest().expect("V25 mutation manifest");
    let sixth = crate::search_template::independent_sixth_static_offset_v24(&literal, manifest)
        .expect("V25 mutation sixth");
    let decoded = decode(image.code()).expect("V25 mutation decode");
    let (_, sixth_empty, promotion) = v25_promotion_sites(&decoded, sixth);

    for (name, index, replacement) in [
        (
            "offset",
            promotion,
            DecodedInstruction::MoveZero64 {
                destination: 10,
                immediate: sixth + 1,
                shift: 0,
            },
        ),
        (
            "offset broadcast",
            promotion + 1,
            DecodedInstruction::DuplicateByte16 {
                destination: 24,
                source: 10,
            },
        ),
        (
            "active state",
            promotion + 2,
            DecodedInstruction::MoveZero64 {
                destination: 11,
                immediate: 0,
                shift: 0,
            },
        ),
        (
            "wide bound",
            promotion + 3,
            DecodedInstruction::SubtractImmediate64 {
                destination: 7,
                source: 6,
                immediate: 62,
            },
        ),
    ] {
        let mut mutated = image.clone();
        replace_test_decoded_at(&mut mutated, index, replacement);
        assert_resealed_search_rejected(mutated, &format!("V25 promotion {name}"));
    }

    let DecodedInstruction::CompareBranchZero64 {
        register,
        nonzero,
        displacement,
    } = decoded[sixth_empty]
    else {
        panic!("V25 sixth-empty branch");
    };
    let mut inverted = image.clone();
    replace_test_decoded_at(
        &mut inverted,
        sixth_empty,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero: !nonzero,
            displacement,
        },
    );
    assert_resealed_search_rejected(inverted, "V25 sixth-empty branch inversion");

    let mut wrong_cbz_register = image.clone();
    replace_test_decoded_at(
        &mut wrong_cbz_register,
        sixth_empty,
        DecodedInstruction::CompareBranchZero64 {
            register: 9,
            nonzero,
            displacement,
        },
    );
    assert_resealed_search_rejected(wrong_cbz_register, "V25 sixth-empty CBZ register");

    let mut wrong_cbz_target = image.clone();
    replace_test_branch_and_relocation_at(
        &mut wrong_cbz_target,
        sixth_empty,
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero,
            displacement: displacement + 4,
        },
    );
    assert_resealed_search_rejected(wrong_cbz_target, "V25 sixth-empty CBZ target");

    let DecodedInstruction::Branch { displacement } = decoded[promotion + 4] else {
        panic!("V25 promotion branch");
    };
    let mut wrong_target = image.clone();
    replace_test_branch_and_relocation_at(
        &mut wrong_target,
        promotion + 4,
        DecodedInstruction::Branch {
            displacement: displacement + 4,
        },
    );
    assert_resealed_search_rejected(wrong_target, "V25 promotion target");

    let v24 = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV24,
        EmitLimits::default(),
    )
    .expect("frozen V24 relabel image");
    let mut v25_as_v24 = image;
    v25_as_v24.backend_version = BackendVersion::SEARCH_V24;
    v25_as_v24
        .search
        .as_mut()
        .expect("V25 relabel manifest")
        .backend_version = BackendVersion::SEARCH_V24;
    assert_resealed_search_rejected(v25_as_v24, "V25 code resealed as V24");

    let mut v24_as_v25 = v24;
    v24_as_v25.backend_version = BackendVersion::SEARCH_V25;
    v24_as_v25
        .search
        .as_mut()
        .expect("V24 relabel manifest")
        .backend_version = BackendVersion::SEARCH_V25;
    assert_resealed_search_rejected(v24_as_v25, "V24 code resealed as V25");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the V24 semantic matrix keeps every preregistered cold path in one auditable test"
)]
fn v24_sixth_empty_false_survivor_exact_narrow_tail_and_no_match_paths_are_exact() {
    let mut comparisons = 0_u64;
    for width in [6_usize, 13, 32] {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V24 path semantic IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV24,
                EmitLimits::default(),
            )
            .expect("V24 path semantic image");
            audit(&image).expect("V24 path semantic audit");
            let manifest = image.search_manifest().expect("V24 path manifest");
            let sixth = usize::from(
                crate::search_template::independent_sixth_static_offset_v24(&literal, manifest)
                    .expect("V24 path sixth offset"),
            );
            let selected = [
                manifest.primary_offset,
                manifest.secondary_offset,
                manifest.verification_offset,
                manifest.quaternary_offset,
                manifest.quinary_offset,
            ]
            .map(usize::from);
            let mut all_static = selected.to_vec();
            all_static.push(sixth);
            let avoid = (0_u16..=255)
                .map(|value| u8::try_from(value).expect("bounded byte"))
                .find(|byte| !literal.contains(byte))
                .expect("V24 literal leaves an avoiding byte");
            let window_start = 3_usize;
            let wide_base = window_start + 1;
            let post_three_wide = wide_base + 3 * 64;

            // Three groups survive all five manifest columns but fail only at
            // the new sixth column. A later exact group must still be found.
            let exact = post_three_wide + 11;
            let window_end = exact + width + 80;
            let mut sixth_empty = vec![avoid; window_end + 17];
            for group in 0..3_usize {
                let candidate = wide_base + group * 64 + 5;
                for &offset in &selected {
                    sixth_empty[candidate + offset] = literal[offset];
                }
                assert_eq!(sixth_empty[candidate + sixth], avoid);
            }
            sixth_empty[exact..exact + width].copy_from_slice(&literal);
            let expected = program
                .execute(
                    &sixth_empty,
                    SearchWindow::new(window_start, window_end),
                    ExecutionLimits::unlimited(),
                )
                .expect("V24 sixth-empty oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            assert_eq!(expected, Some((exact, exact + width)));
            assert_eq!(
                span_output(
                    simulate(&image, &sixth_empty, window_start, window_end)
                        .expect("V24 sixth-empty simulation")
                ),
                expected
            );
            comparisons += 1;

            // Widths above six have a source offset outside all six static
            // columns. Passing the sixth filter and missing there must enter
            // the unchanged learned graph before a later exact group.
            if let Some(mismatch) = (0..width).find(|offset| !all_static.contains(offset)) {
                let false_candidate = wide_base + 7;
                let mut false_survivor = vec![avoid; window_end + 17];
                false_survivor[false_candidate..false_candidate + width].copy_from_slice(&literal);
                false_survivor[false_candidate + mismatch] = avoid;
                false_survivor[exact..exact + width].copy_from_slice(&literal);
                let expected = program
                    .execute(
                        &false_survivor,
                        SearchWindow::new(window_start, window_end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V24 sixth-survivor oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                assert_eq!(expected, Some((exact, exact + width)));
                assert_eq!(
                    span_output(
                        simulate(&image, &false_survivor, window_start, window_end)
                            .expect("V24 sixth-survivor simulation")
                    ),
                    expected
                );
                comparisons += 1;
            }

            for (kind, exact, last_candidate) in [
                (
                    "wide exact",
                    Some(post_three_wide + 11),
                    post_three_wide + 80,
                ),
                (
                    "narrow exact",
                    Some(post_three_wide + 7),
                    post_three_wide + 20,
                ),
                ("tail exact", Some(post_three_wide + 7), post_three_wide + 7),
                ("no match", None, post_three_wide + 7),
            ] {
                let window_end = last_candidate + width;
                let mut haystack = vec![avoid; window_end + 17];
                for group in 0..3_usize {
                    let candidate = wide_base + group * 64 + 5;
                    for &offset in &selected {
                        haystack[candidate + offset] = literal[offset];
                    }
                }
                if let Some(candidate) = exact {
                    haystack[candidate..candidate + width].copy_from_slice(&literal);
                }
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(window_start, window_end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V24 exit oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                assert_eq!(
                    span_output(
                        simulate(&image, &haystack, window_start, window_end)
                            .expect("V24 exit simulation")
                    ),
                    expected,
                    "width={width} zero_primary={zero_primary} path={kind}"
                );
                assert_eq!(
                    expected,
                    exact.map(|candidate| (candidate, candidate + width))
                );
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, 3 * 2 * 5 + 2 * 2);
}

#[test]
fn v24_learns_every_offset_outside_the_six_static_columns_for_every_width() {
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V24 every-mismatch IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV24,
                EmitLimits::default(),
            )
            .expect("V24 every-mismatch image");
            audit(&image).expect("V24 every-mismatch audit");
            let manifest = image
                .search_manifest()
                .expect("V24 every-mismatch manifest");
            let sixth = usize::from(
                crate::search_template::independent_sixth_static_offset_v24(&literal, manifest)
                    .expect("V24 every-mismatch sixth"),
            );
            let mut selected = [
                manifest.primary_offset,
                manifest.secondary_offset,
                manifest.verification_offset,
                manifest.quaternary_offset,
                manifest.quinary_offset,
            ]
            .map(usize::from)
            .to_vec();
            selected.push(sixth);
            let avoid = (0_u16..=255)
                .map(|value| u8::try_from(value).expect("bounded byte"))
                .find(|byte| !literal.contains(byte))
                .expect("V24 every-mismatch avoiding byte");
            let window_start = 3_usize;
            let false_candidate = window_start + 1 + 7;
            let exact = window_start + 1 + 4 * 64 + 11;

            for mismatch in (0..width).filter(|offset| !selected.contains(offset)) {
                let mut haystack = vec![avoid; exact + width + 96];
                haystack[false_candidate..false_candidate + width].copy_from_slice(&literal);
                haystack[false_candidate + mismatch] = avoid;
                haystack[exact..exact + width].copy_from_slice(&literal);
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(window_start, haystack.len()),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V24 every-mismatch oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                assert_eq!(expected, Some((exact, exact + width)));
                assert_eq!(
                    span_output(
                        simulate(&image, &haystack, window_start, haystack.len())
                            .expect("V24 every-mismatch simulation")
                    ),
                    expected,
                    "width={width} zero_primary={zero_primary} mismatch={mismatch}"
                );
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, 2 * (513 - 27 * 6));
}

#[test]
fn v24_third_policy_scan_is_precharged_and_total_work_is_exact() {
    let literal = v23_pointer_test_literal(MAX_REPEATED_CONFIRM_BYTES, false);
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V24 work IR");
    let policy_work = u64::try_from(literal.len())
        .expect("bounded V24 width")
        .checked_mul(3)
        .expect("three bounded policy scans");
    let one_less = policy_work.checked_sub(1).expect("nonzero V24 policy work");
    assert_eq!(
        emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV24,
            EmitLimits {
                max_data_bytes: 0,
                max_emission_work: one_less,
                ..EmitLimits::default()
            },
        ),
        Err(EmitError::ResourceLimit {
            resource: ResourceKind::EmissionWork,
            limit: one_less,
            required: policy_work,
        }),
        "the complete third scan is admitted before any sixth-offset work"
    );

    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV24,
        EmitLimits::default(),
    )
    .expect("V24 work image");
    let exact_work = image.stats().emission_work;
    emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV24,
        EmitLimits {
            max_emission_work: exact_work,
            ..EmitLimits::default()
        },
    )
    .expect("exact V24 work receipt succeeds");
    assert_eq!(
        emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV24,
            EmitLimits {
                max_emission_work: exact_work - 1,
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
fn v24_v25_sixth_empty_wide_to_narrow_and_tail_cover_every_modulo_16_boundary() {
    let mut comparisons = 0_u64;
    for backend in [SearchBackendPolicy::AsimdV24, SearchBackendPolicy::AsimdV25] {
        for width in [6_usize, 13, 32] {
            for zero_primary in [true, false] {
                let literal = v23_pointer_test_literal(width, zero_primary);
                let program = build_exact_literal::<Span>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("V24 boundary IR");
                let image = emit_with_backend(&program, backend, EmitLimits::default())
                    .expect("V24/V25 boundary image");
                let manifest = image.search_manifest().expect("V24 boundary manifest");
                let sixth_u16 =
                    crate::search_template::independent_sixth_static_offset_v24(&literal, manifest)
                        .expect("V24/V25 boundary sixth");
                let sixth = usize::from(sixth_u16);
                let promotion = (backend == SearchBackendPolicy::AsimdV25).then(|| {
                    let decoded = decode(image.code()).expect("V25 boundary decode");
                    v25_promotion_sites(&decoded, sixth_u16).2
                });
                let selected = [
                    manifest.primary_offset,
                    manifest.secondary_offset,
                    manifest.verification_offset,
                    manifest.quaternary_offset,
                    manifest.quinary_offset,
                ]
                .map(usize::from);
                let avoid = (0_u16..=255)
                    .map(|value| u8::try_from(value).expect("bounded byte"))
                    .find(|byte| !literal.contains(byte))
                    .expect("V24 boundary avoiding byte");

                for window_start in 0_usize..16 {
                    let wide_base = window_start + 1;
                    let false_candidate = wide_base + 5;
                    for (kind, exact, last_candidate) in [
                        ("narrow", wide_base + 64 + 7, wide_base + 64 + 20),
                        ("tail", wide_base + 64 + 18, wide_base + 64 + 18),
                    ] {
                        let window_end = last_candidate + width;
                        let mut haystack = vec![avoid; window_end + 17];
                        for &offset in &selected {
                            haystack[false_candidate + offset] = literal[offset];
                        }
                        assert_eq!(haystack[false_candidate + sixth], avoid);
                        haystack[exact..exact + width].copy_from_slice(&literal);
                        let expected = program
                            .execute(
                                &haystack,
                                SearchWindow::new(window_start, window_end),
                                ExecutionLimits::unlimited(),
                            )
                            .expect("V24 boundary oracle")
                            .output()
                            .map(|span| (span.start(), span.end()));
                        assert_eq!(expected, Some((exact, exact + width)));
                        let (actual, trace) = simulate_with_instruction_trace(
                            &image,
                            &haystack,
                            window_start,
                            window_end,
                        )
                        .expect("V24/V25 boundary simulation");
                        assert_eq!(
                            span_output(actual),
                            expected,
                            "backend={backend:?} width={width} zero_primary={zero_primary} residue={window_start} path={kind}"
                        );
                        if let Some(promotion) = promotion {
                            assert!(trace.contains(&promotion));
                        }
                        comparisons += 1;
                    }
                }
            }
        }
    }
    assert_eq!(comparisons, 2 * 3 * 2 * 16 * 2);
}

#[test]
fn v24_v25_every_width_primary_offset_and_randomized_window_matches_the_kir_oracle() {
    let mut state = 0x2d9c_71e5_a408_63bf_u64;
    let mut comparisons = 0_u64;
    for backend in [SearchBackendPolicy::AsimdV24, SearchBackendPolicy::AsimdV25] {
        for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
            for zero_primary in [true, false] {
                let literal = v23_pointer_test_literal(width, zero_primary);
                let program = build_exact_literal::<Span>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("V24 randomized IR");
                let image = emit_with_backend(&program, backend, EmitLimits::default())
                    .expect("V24/V25 randomized image");
                audit(&image).expect("V24/V25 randomized audit");

                for case in 0..8_usize {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let hay_len = 256 + usize::try_from(state >> 24).expect("host usize") % 257;
                    let mut haystack = Vec::with_capacity(hay_len);
                    for _ in 0..hay_len {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        haystack.push(state.to_le_bytes()[0]);
                    }
                    let exact = (case & 1 == 0).then(|| {
                        5 + (usize::try_from(state >> 8).expect("host usize")
                            % (haystack.len() - width - 5))
                    });
                    if let Some(candidate) = exact {
                        haystack[candidate..candidate + width].copy_from_slice(&literal);
                    }

                    let random_start =
                        usize::try_from(state >> 16).expect("host usize") % (haystack.len() + 1);
                    let random_end = random_start
                        + (usize::try_from(state >> 32).expect("host usize")
                            % (haystack.len() - random_start + 1));
                    let short_end = width.saturating_sub(1).min(haystack.len());
                    let exact_window = exact.map_or((random_start, random_end), |candidate| {
                        (candidate, candidate + width)
                    });
                    for (start, end) in [
                        (0, 0),
                        (0, short_end),
                        (0, haystack.len()),
                        (random_start, haystack.len()),
                        (random_start, random_end),
                        exact_window,
                    ] {
                        let expected = program
                            .execute(
                                &haystack,
                                SearchWindow::new(start, end),
                                ExecutionLimits::unlimited(),
                            )
                            .expect("V24 randomized oracle")
                            .output()
                            .map(|span| (span.start(), span.end()));
                        assert_eq!(
                            span_output(
                                simulate(&image, &haystack, start, end)
                                    .expect("V24 randomized simulation")
                            ),
                            expected,
                            "backend={backend:?} width={width} zero_primary={zero_primary} case={case} window={start}..{end}"
                        );
                        comparisons += 1;
                    }
                }
            }
        }
    }
    assert_eq!(comparisons, 2 * 2_592);
}

#[test]
fn v25_all_widths_promote_first_middle_final_and_preserve_source_order_and_learning() {
    let mut comparisons = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            let program = build_exact_literal::<Span>(
                &literal,
                AnchorFlags::default(),
                ValidateLimits::default(),
            )
            .expect("V25 promotion semantic IR");
            let image = emit_with_backend(
                &program,
                SearchBackendPolicy::AsimdV25,
                EmitLimits::default(),
            )
            .expect("V25 promotion semantic image");
            audit(&image).expect("V25 promotion semantic audit");
            let manifest = image
                .search_manifest()
                .expect("V25 promotion semantic manifest");
            let selected = [
                manifest.primary_offset,
                manifest.secondary_offset,
                manifest.verification_offset,
                manifest.quaternary_offset,
                manifest.quinary_offset,
            ]
            .map(usize::from);
            let sixth_u16 =
                crate::search_template::independent_sixth_static_offset_v24(&literal, manifest)
                    .expect("V25 promotion semantic sixth");
            let sixth = usize::from(sixth_u16);
            let decoded = decode(image.code()).expect("V25 promotion semantic decode");
            let (_, sixth_empty, promotion) = v25_promotion_sites(&decoded, sixth_u16);
            let recovery = v23_direct_target(sixth_empty + 1, decoded[sixth_empty + 1])
                .expect("V25 sixth-survivor recovery target");
            let mut all_static = selected.to_vec();
            all_static.push(sixth);
            let avoid = (0_u16..=255)
                .map(|value| u8::try_from(value).expect("bounded byte"))
                .find(|byte| !literal.contains(byte))
                .expect("V25 literal leaves an avoiding byte");
            let window_start = 3_usize;
            let wide_base = window_start + 1;
            let narrow_base = wide_base + 3 * 64;
            let after = narrow_base + 7;
            let later = after + width + 1;
            let window_end = (narrow_base + 20).max(later) + width;

            // Exactly one of the first, middle, or final complete wide groups
            // reaches the sixth-empty promotion edge. The match after all
            // three complete groups must remain exact.
            for promoted_group in 0..3_usize {
                let false_candidate = wide_base + promoted_group * 64 + 5;
                let mut haystack = vec![avoid; window_end + 17];
                for &offset in &selected {
                    haystack[false_candidate + offset] = literal[offset];
                }
                assert_eq!(haystack[false_candidate + sixth], avoid);
                haystack[after..after + width].copy_from_slice(&literal);
                haystack[later..later + width].copy_from_slice(&literal);
                let expected = program
                    .execute(
                        &haystack,
                        SearchWindow::new(window_start, window_end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V25 promoted-group oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                assert_eq!(expected, Some((after, after + width)));
                let (actual, trace) =
                    simulate_with_instruction_trace(&image, &haystack, window_start, window_end)
                        .expect("V25 promoted-group traced simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} zero_primary={zero_primary} promoted_group={promoted_group}"
                );
                assert!(
                    trace.contains(&promotion),
                    "crafted group must execute promotion width={width} zero_primary={zero_primary} promoted_group={promoted_group}"
                );
                comparisons += 1;
            }

            // An exact match before a would-be promoted group must win over
            // another exact match after it.
            let before = window_start;
            let false_candidate = wide_base + 64 + 5;
            let mut ordered = vec![avoid; window_end + 17];
            for &offset in &selected {
                ordered[false_candidate + offset] = literal[offset];
            }
            ordered[before..before + width].copy_from_slice(&literal);
            ordered[after..after + width].copy_from_slice(&literal);
            let expected = program
                .execute(
                    &ordered,
                    SearchWindow::new(window_start, window_end),
                    ExecutionLimits::unlimited(),
                )
                .expect("V25 source-order oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            assert_eq!(expected, Some((before, before + width)));
            let (actual, trace) =
                simulate_with_instruction_trace(&image, &ordered, window_start, window_end)
                    .expect("V25 source-order traced simulation");
            assert_eq!(span_output(actual), expected);
            assert!(
                !trace.contains(&promotion),
                "an earlier exact result returns before a later promotion"
            );
            comparisons += 1;

            // A sixth survivor with a mismatch outside all six static
            // columns must retain V23's persistent discovery and learning.
            if let Some(mismatch) = (0..width).find(|offset| !all_static.contains(offset)) {
                let false_candidate = wide_base + 7;
                let mut survivor = vec![avoid; window_end + 17];
                survivor[false_candidate..false_candidate + width].copy_from_slice(&literal);
                survivor[false_candidate + mismatch] = avoid;
                survivor[after..after + width].copy_from_slice(&literal);
                let expected = program
                    .execute(
                        &survivor,
                        SearchWindow::new(window_start, window_end),
                        ExecutionLimits::unlimited(),
                    )
                    .expect("V25 sixth-survivor oracle")
                    .output()
                    .map(|span| (span.start(), span.end()));
                assert_eq!(expected, Some((after, after + width)));
                let (actual, trace) =
                    simulate_with_instruction_trace(&image, &survivor, window_start, window_end)
                        .expect("V25 sixth-survivor traced simulation");
                assert_eq!(
                    span_output(actual),
                    expected,
                    "width={width} zero_primary={zero_primary} mismatch={mismatch}"
                );
                assert!(!trace.contains(&promotion));
                assert!(
                    trace.contains(&recovery),
                    "sixth survivor must enter unchanged V24/V23 recovery"
                );
                comparisons += 1;
            }

            // The third group is the final complete group and the last legal
            // candidate is its final lane. Promotion advances X5 to X6 + 1,
            // which must exit without a speculative narrow or tail read.
            let last_candidate = wide_base + 3 * 64 - 1;
            let final_window_end = last_candidate + width;
            let false_candidate = wide_base + 2 * 64 + 5;
            let mut final_empty = vec![avoid; final_window_end + 17];
            for &offset in &selected {
                final_empty[false_candidate + offset] = literal[offset];
            }
            let expected = program
                .execute(
                    &final_empty,
                    SearchWindow::new(window_start, final_window_end),
                    ExecutionLimits::unlimited(),
                )
                .expect("V25 final-group transition oracle")
                .output()
                .map(|span| (span.start(), span.end()));
            assert_eq!(expected, None);
            let (actual, trace) = simulate_with_instruction_trace(
                &image,
                &final_empty,
                window_start,
                final_window_end,
            )
            .expect("V25 final-group transition simulation");
            assert_eq!(span_output(actual), expected);
            assert!(
                trace.contains(&promotion),
                "final complete group must execute promotion"
            );
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 27 * 2 * 5 + 26 * 2);
}

#[test]
fn v25_envelope_all_widths_outputs_audit_and_aot_wire_are_exact() {
    for width in 1_usize..6 {
        let literal = vec![b'x'; width];
        let span = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("valid IR below V25 envelope");
        assert_eq!(
            emit_with_backend(&span, SearchBackendPolicy::AsimdV25, EmitLimits::default(),),
            Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            }),
            "width={width}"
        );
    }

    let mut images = 0_u64;
    for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
        for zero_primary in [true, false] {
            let literal = v23_pointer_test_literal(width, zero_primary);
            for output in [
                OutputKind::Exists,
                OutputKind::SelectedEnd,
                OutputKind::Span,
            ] {
                let image = exact_output_image_with_backend(
                    &literal,
                    output,
                    SearchBackendPolicy::AsimdV25,
                );
                assert_eq!(image.backend_version(), BackendVersion::SEARCH_V25);
                assert_eq!(image.output(), output);
                let report = audit(&image).expect("independent V25 output template");
                assert_eq!(
                    (report.decode_passes, report.source_identity_rebuilds),
                    (1, 1)
                );
                let aot = image.to_aot(AotLimits::default()).expect("V25 output AOT");
                assert_eq!(&aot.as_bytes()[..8], b"FREA64\0\x26");
                assert_eq!(aot.identity(), image.artifact_identity());
                images += 1;
            }
        }
    }
    assert_eq!(images, 27 * 2 * 3);
}

#[test]
fn v25_third_policy_scan_and_complete_emission_work_are_precharged_exactly() {
    let literal = v23_pointer_test_literal(MAX_REPEATED_CONFIRM_BYTES, false);
    let program =
        build_exact_literal::<Span>(&literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V25 work IR");
    let policy_work = u64::try_from(literal.len())
        .expect("bounded V25 width")
        .checked_mul(3)
        .expect("three bounded policy scans");
    let one_less = policy_work.checked_sub(1).expect("nonzero V25 policy work");
    assert_eq!(
        emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV25,
            EmitLimits {
                max_data_bytes: 0,
                max_emission_work: one_less,
                ..EmitLimits::default()
            },
        ),
        Err(EmitError::ResourceLimit {
            resource: ResourceKind::EmissionWork,
            limit: one_less,
            required: policy_work,
        })
    );

    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV25,
        EmitLimits::default(),
    )
    .expect("V25 work image");
    let exact_work = image.stats().emission_work;
    emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV25,
        EmitLimits {
            max_emission_work: exact_work,
            ..EmitLimits::default()
        },
    )
    .expect("exact V25 work receipt");
    assert_eq!(
        emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV25,
            EmitLimits {
                max_emission_work: exact_work - 1,
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
fn v25_frozen_v24_all_width_primary_output_aot_matrix_bytes_are_exact() {
    let mut digest = Sha256::new();
    digest.update(b"FRE-V25-FROZEN-V24-ALL-WIDTH-PRIMARY-OUTPUT-AOT-V1\0");
    let mut images = 0_u64;
    for output in [
        OutputKind::Exists,
        OutputKind::SelectedEnd,
        OutputKind::Span,
    ] {
        digest.update([match output {
            OutputKind::Exists => 1,
            OutputKind::SelectedEnd => 2,
            OutputKind::Span => 3,
        }]);
        for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
            for zero_primary in [true, false] {
                let literal = v23_pointer_test_literal(width, zero_primary);
                let image = exact_output_image_with_backend(
                    &literal,
                    output,
                    SearchBackendPolicy::AsimdV24,
                );
                audit(&image).expect("frozen V24 image audit");
                assert_eq!(image.backend_version(), BackendVersion::SEARCH_V24);
                let aot = image.to_aot(AotLimits::default()).expect("frozen V24 AOT");
                digest.update([u8::from(zero_primary)]);
                digest.update(u64::try_from(width).expect("width").to_le_bytes());
                digest.update(
                    u64::try_from(aot.as_bytes().len())
                        .expect("AOT length")
                        .to_le_bytes(),
                );
                digest.update(aot.as_bytes());
                images += 1;
            }
        }
    }
    assert_eq!(images, 3 * 27 * 2);
    assert_eq!(
        format!("{:x}", digest.finalize()),
        "8453163f9d1eeb878e4bee4bcb7585d26b7c4ff2a5a7c82d135991abe5782dd2"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the frozen V23 output/topology matrix keeps its generator and authenticated AOT digest adjacent"
)]
fn v24_frozen_v23_aot_code_manifest_and_output_matrix_bytes_are_exact() {
    fn gate_literal(topology: u8, width: usize) -> Vec<u8> {
        match topology {
            0 => (0..width)
                .map(|offset| 33 + u8::try_from((17 * offset) % 64).expect("bounded"))
                .collect(),
            1 => {
                let mut literal = vec![b'~'; width];
                literal[..5].copy_from_slice(b"A3mQz");
                literal
            }
            2 => {
                let mut literal = vec![b'x'; width];
                for (offset, byte) in [0, width / 4, width / 2, (3 * width) / 4, width - 1]
                    .into_iter()
                    .zip(*b"MNOPR")
                {
                    literal[offset] = byte;
                }
                literal
            }
            3 => {
                const ALPHABET: &[u8; 16] = b"0123456789ABCDEF";
                let mut state =
                    0x9e37_79b9_7f4a_7c15_u64 ^ u64::try_from(width).expect("host width");
                (0..width)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        ALPHABET[usize::from(state.to_le_bytes()[0] & 15)]
                    })
                    .collect()
            }
            _ => unreachable!(),
        }
    }

    let mut digest = Sha256::new();
    digest.update(b"FRE-V24-FROZEN-V23-ALL-OUTPUT-AOT-MATRIX-V1\0");
    let mut images = 0_u64;
    for output in [
        OutputKind::Exists,
        OutputKind::SelectedEnd,
        OutputKind::Span,
    ] {
        let output_tag = match output {
            OutputKind::Exists => 1_u8,
            OutputKind::SelectedEnd => 2,
            OutputKind::Span => 3,
        };
        digest.update([output_tag]);
        for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
            for topology in 0_u8..4 {
                let literal = gate_literal(topology, width);
                let image = match output {
                    OutputKind::Exists => {
                        let program = build_exact_literal::<Exists>(
                            &literal,
                            AnchorFlags::default(),
                            ValidateLimits::default(),
                        )
                        .expect("frozen V23 Exists IR");
                        emit_search_version_for_test(
                            &program,
                            EmitLimits::default(),
                            BackendVersion::SEARCH_V23,
                        )
                        .expect("frozen V23 Exists image")
                    }
                    OutputKind::SelectedEnd => {
                        let program = build_exact_literal::<SelectedEnd>(
                            &literal,
                            AnchorFlags::default(),
                            ValidateLimits::default(),
                        )
                        .expect("frozen V23 SelectedEnd IR");
                        emit_search_version_for_test(
                            &program,
                            EmitLimits::default(),
                            BackendVersion::SEARCH_V23,
                        )
                        .expect("frozen V23 SelectedEnd image")
                    }
                    OutputKind::Span => {
                        let program = build_exact_literal::<Span>(
                            &literal,
                            AnchorFlags::default(),
                            ValidateLimits::default(),
                        )
                        .expect("frozen V23 Span IR");
                        emit_search_version_for_test(
                            &program,
                            EmitLimits::default(),
                            BackendVersion::SEARCH_V23,
                        )
                        .expect("frozen V23 Span image")
                    }
                };
                audit(&image).expect("frozen V23 output image audit");
                assert_eq!(image.backend_version(), BackendVersion::SEARCH_V23);
                assert_eq!(image.output(), output);
                let aot = image
                    .to_aot(AotLimits::default())
                    .expect("frozen V23 bounded AOT");
                digest.update([topology]);
                digest.update(u64::try_from(width).expect("width").to_le_bytes());
                digest.update(
                    u64::try_from(aot.as_bytes().len())
                        .expect("AOT length")
                        .to_le_bytes(),
                );
                digest.update(aot.as_bytes());
                images += 1;
            }
        }
    }
    assert_eq!(images, 3 * 27 * 4);
    assert_eq!(
        format!("{:x}", digest.finalize()),
        "23038d31987fe49dd30624d699284ca17b1447a9e3c97f48d01e3b8ccb17a561"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the complete frozen backend matrix keeps its topology generator and authenticated digest adjacent"
)]
fn v23_frozen_all_prior_search_aot_matrix_bytes_are_exact() {
    fn gate_literal(topology: u8, width: usize) -> Vec<u8> {
        match topology {
            0 => (0..width)
                .map(|offset| 33 + u8::try_from((17 * offset) % 64).expect("bounded"))
                .collect(),
            1 => {
                let mut literal = vec![b'~'; width];
                literal[..5].copy_from_slice(b"A3mQz");
                literal
            }
            2 => {
                let mut literal = vec![b'x'; width];
                for (offset, byte) in [0, width / 4, width / 2, (3 * width) / 4, width - 1]
                    .into_iter()
                    .zip(*b"MNOPR")
                {
                    literal[offset] = byte;
                }
                literal
            }
            3 => {
                const ALPHABET: &[u8; 16] = b"0123456789ABCDEF";
                let mut state =
                    0x9e37_79b9_7f4a_7c15_u64 ^ u64::try_from(width).expect("host width");
                (0..width)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        ALPHABET[usize::from(state.to_le_bytes()[0] & 15)]
                    })
                    .collect()
            }
            _ => unreachable!(),
        }
    }

    let backends = [
        BackendVersion::SEARCH_V1,
        BackendVersion::SEARCH_V2,
        BackendVersion::SEARCH_V3,
        BackendVersion::SEARCH_V4,
        BackendVersion::SEARCH_V5,
        BackendVersion::SEARCH_V6,
        BackendVersion::SEARCH_V7,
        BackendVersion::SEARCH_V8,
        BackendVersion::SEARCH_V9,
        BackendVersion::SEARCH_V10,
        BackendVersion::SEARCH_V11,
        BackendVersion::SEARCH_V12,
        BackendVersion::SEARCH_V13,
        BackendVersion::SEARCH_V14,
        BackendVersion::SEARCH_V15,
        BackendVersion::SEARCH_V16,
        BackendVersion::SEARCH_V17,
        BackendVersion::SEARCH_V18,
        BackendVersion::SEARCH_V19,
        BackendVersion::SEARCH_V20,
        BackendVersion::SEARCH_V21,
        BackendVersion::SEARCH_V22,
        BackendVersion::SEARCH_SVE16_V1,
        BackendVersion::SEARCH_SVE2_16_V1,
        BackendVersion::SEARCH_SVE16_V6,
        BackendVersion::SEARCH_SVE2_FIXED16_V2,
    ];
    let mut digest = Sha256::new();
    digest.update(b"FRE-V23-FROZEN-ALL-PRIOR-BACKEND-MATRIX-V1\0");
    digest.update(
        u64::try_from(backends.len())
            .expect("backend count")
            .to_le_bytes(),
    );
    for backend in backends {
        digest.update(backend.0.to_le_bytes());
        for width in 6_usize..=MAX_REPEATED_CONFIRM_BYTES {
            if (backend == BackendVersion::SEARCH_SVE16_V6 && width < 16)
                || (backend == BackendVersion::SEARCH_SVE2_FIXED16_V2 && width != 16)
            {
                continue;
            }
            for topology in 0_u8..4 {
                let literal = gate_literal(topology, width);
                let program = build_exact_literal::<Span>(
                    &literal,
                    AnchorFlags::default(),
                    ValidateLimits::default(),
                )
                .expect("frozen prior-backend byte-identity IR");
                let image = emit_search_version_for_test(&program, EmitLimits::default(), backend)
                    .expect("frozen prior-backend byte-identity image");
                audit(&image).expect("frozen prior-backend byte-identity audit");
                let aot = image
                    .to_aot(AotLimits::default())
                    .expect("frozen prior-backend bounded AOT");
                digest.update([topology]);
                digest.update(u64::try_from(width).expect("width").to_le_bytes());
                digest.update(
                    u64::try_from(aot.as_bytes().len())
                        .expect("AOT length")
                        .to_le_bytes(),
                );
                digest.update(aot.as_bytes());
            }
        }
    }
    assert_eq!(
        format!("{:x}", digest.finalize()),
        "b3d24177ac88eb4c855248b84a1c910e4bcc4d2e45d9eee8bb2fea65a4f40502"
    );
}

#[test]
fn v17_post_window_setup_leaves_x1_x2_x3_available_for_saved_masks() {
    let literal = b"0123456789abcdef";
    let program =
        build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
            .expect("V17 liveness IR");
    let image = emit_with_backend(
        &program,
        SearchBackendPolicy::AsimdV17,
        EmitLimits::default(),
    )
    .expect("V17 liveness image");
    let decoded = decode(image.code()).expect("V17 liveness decode");
    let window_setup = decoded
        .iter()
        .position(|instruction| {
            *instruction
                == DecodedInstruction::MoveRegister64 {
                    destination: 5,
                    source: 2,
                }
        })
        .expect("unanchored candidate cursor setup");
    for register in [1, 2, 3] {
        assert!(
            decoded[window_setup + 1..]
                .iter()
                .all(|instruction| !instruction.uses_gpr(register)),
            "X{register} must be dead after X5/X6 capture for V19/V20 saved masks"
        );
    }
    assert!(
        decoded
            .iter()
            .all(|instruction| instruction.written_gpr() != Some(4)),
        "the search result pointer remains immutable"
    );
}

#[test]
fn v13_adaptive_recovery_decoded_edges_cover_zero_one_and_max_remaining_columns() {
    for (width, expected_columns) in [(5_usize, 0_usize), (6, 1), (32, 27)] {
        let literal = vec![b'a'; width];
        let program = build_exact_literal::<Span>(
            &literal,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("V13 boundary-column IR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::AsimdV13,
            EmitLimits::default(),
        )
        .expect("V13 boundary-column image");
        let decoded = decode(image.code()).expect("V13 boundary-column decode");

        let target = |index: usize| {
            let displacement = match decoded[index] {
                DecodedInstruction::Branch { displacement }
                | DecodedInstruction::CompareBranchZero64 { displacement, .. } => displacement,
                _ => panic!("instruction {index} is not a decoded V13 branch"),
            };
            let address = i64::try_from(index)
                .expect("small instruction index")
                .checked_mul(4)
                .and_then(|address| address.checked_add(i64::from(displacement)))
                .expect("bounded V13 target");
            assert_eq!(address % 4, 0);
            usize::try_from(address / 4).expect("nonnegative V13 target")
        };
        let adaptive_entry = decoded
            .iter()
            .position(|instruction| {
                *instruction
                    == DecodedInstruction::AddRegister64 {
                        destination: 13,
                        left: 9,
                        right: 7,
                    }
            })
            .expect("V13 adaptive entry");
        assert!(adaptive_entry >= 7);
        assert_eq!(
            &decoded[adaptive_entry - 7..adaptive_entry],
            &[
                DecodedInstruction::SubtractImmediate64 {
                    destination: 10,
                    source: 0,
                    immediate: 1,
                },
                DecodedInstruction::AndRegister64 {
                    destination: 0,
                    left: 0,
                    right: 10,
                },
                decoded[adaptive_entry - 5],
                DecodedInstruction::SubtractImmediate64 {
                    destination: 10,
                    source: 0,
                    immediate: 1,
                },
                DecodedInstruction::AndRegister64 {
                    destination: 10,
                    left: 0,
                    right: 10,
                },
                decoded[adaptive_entry - 2],
                decoded[adaptive_entry - 1],
            ]
        );
        assert!(matches!(
            decoded[adaptive_entry - 5],
            DecodedInstruction::CompareBranchZero64 {
                register: 0,
                nonzero: false,
                ..
            }
        ));
        assert!(matches!(
            decoded[adaptive_entry - 2],
            DecodedInstruction::CompareBranchZero64 {
                register: 10,
                nonzero: true,
                ..
            }
        ));
        assert_eq!(target(adaptive_entry - 2), adaptive_entry);

        let adaptive_masks = decoded
            .iter()
            .enumerate()
            .filter_map(|(index, instruction)| {
                (*instruction
                    == DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                        destination: 18,
                        source: 16,
                    })
                .then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(adaptive_masks.len(), expected_columns);
        let exhausted_target = target(adaptive_entry - 5);
        assert_eq!(
            decoded[exhausted_target],
            DecodedInstruction::AddImmediate64 {
                destination: 5,
                source: 7,
                immediate: 16,
            }
        );
        let lane_loop_target = target(adaptive_entry - 1);
        assert_eq!(
            decoded[lane_loop_target],
            DecodedInstruction::ReverseBits64 {
                destination: 10,
                source: 0,
            }
        );

        for (ordinal, &mask) in adaptive_masks.iter().enumerate() {
            assert_eq!(
                decoded.get(mask..mask + 5),
                Some(
                    [
                        DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
                            destination: 18,
                            source: 16,
                        },
                        DecodedInstruction::MoveVectorDoubleTo64 {
                            destination: 10,
                            source: 18,
                        },
                        DecodedInstruction::AndRegister64 {
                            destination: 10,
                            left: 10,
                            right: 14,
                        },
                        DecodedInstruction::AndRegister64 {
                            destination: 0,
                            left: 0,
                            right: 10,
                        },
                        decoded[mask + 4],
                    ]
                    .as_slice()
                )
            );
            assert!(matches!(
                decoded[mask + 4],
                DecodedInstruction::CompareBranchZero64 {
                    register: 0,
                    nonzero: false,
                    ..
                }
            ));
            assert_eq!(target(mask + 4), exhausted_target);
            if ordinal + 1 < adaptive_masks.len() {
                assert_eq!(
                    &decoded[mask + 5..mask + 7],
                    &[
                        DecodedInstruction::SubtractImmediate64 {
                            destination: 10,
                            source: 0,
                            immediate: 1,
                        },
                        DecodedInstruction::AndRegister64 {
                            destination: 10,
                            left: 0,
                            right: 10,
                        },
                    ]
                );
                assert!(matches!(
                    decoded[mask + 7],
                    DecodedInstruction::CompareBranchZero64 {
                        register: 10,
                        nonzero: false,
                        ..
                    }
                ));
                assert_eq!(target(mask + 7), lane_loop_target);
            }
        }
    }
}

#[test]
fn v9_through_v25_reject_shapes_without_one_nonempty_unanchored_exact_candidate() {
    for backend in [
        SearchBackendPolicy::AsimdV9,
        SearchBackendPolicy::AsimdV10,
        SearchBackendPolicy::AsimdV11,
        SearchBackendPolicy::AsimdV12,
        SearchBackendPolicy::AsimdV13,
        SearchBackendPolicy::AsimdV14,
        SearchBackendPolicy::AsimdV15,
        SearchBackendPolicy::AsimdV16,
        SearchBackendPolicy::AsimdV17,
        SearchBackendPolicy::AsimdV18,
        SearchBackendPolicy::AsimdV19,
        SearchBackendPolicy::AsimdV20,
        SearchBackendPolicy::AsimdV21,
        SearchBackendPolicy::AsimdV22,
        SearchBackendPolicy::AsimdV23,
        SearchBackendPolicy::AsimdV24,
        SearchBackendPolicy::AsimdV25,
    ] {
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
            0x7940_01ea,
            DecodedInstruction::Load16 {
                destination: 10,
                base: 15,
                offset: 0,
            },
        ),
        (
            0xb940_01ea,
            DecodedInstruction::Load32 {
                destination: 10,
                base: 15,
                offset: 0,
            },
        ),
        (
            0xf940_01ea,
            DecodedInstruction::Load64 {
                destination: 10,
                base: 15,
                offset: 0,
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
        instruction_trace: None,
    };
    machine.registers[0] = HAYSTACK_BASE;
    machine.registers[1] = u64::try_from(haystack.len()).map_err(|_| SimError::Arithmetic)?;
    machine.registers[2] = u64::try_from(window_start).map_err(|_| SimError::Arithmetic)?;
    machine.registers[3] = u64::try_from(window_end).map_err(|_| SimError::Arithmetic)?;
    machine.registers[4] = RESULT_BASE;
    machine.run()
}

fn simulate_with_instruction_trace(
    image: &NativeImage,
    haystack: &[u8],
    window_start: usize,
    window_end: usize,
) -> Result<(SimResult, Vec<usize>), SimError> {
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
        instruction_trace: Some(Vec::new()),
        instructions: &instructions,
        image,
        haystack,
    };
    machine.registers[0] = HAYSTACK_BASE;
    machine.registers[1] = u64::try_from(haystack.len()).map_err(|_| SimError::Arithmetic)?;
    machine.registers[2] = u64::try_from(window_start).map_err(|_| SimError::Arithmetic)?;
    machine.registers[3] = u64::try_from(window_end).map_err(|_| SimError::Arithmetic)?;
    machine.registers[4] = RESULT_BASE;
    let result = machine.run()?;
    let trace = machine
        .instruction_trace
        .take()
        .expect("trace-enabled simulator owns a trace");
    Ok((result, trace))
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
        instruction_trace: None,
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
    instruction_trace: Option<Vec<usize>>,
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
            if let Some(instruction_trace) = self.instruction_trace.as_mut() {
                instruction_trace.push(index);
            }
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
                DecodedInstruction::Load16 {
                    destination,
                    base,
                    offset,
                } => {
                    let address = self.get(base).wrapping_add(u64::from(offset));
                    let bytes = self.load(address, 2)?;
                    self.set(
                        destination,
                        u64::from(u16::from_le_bytes([bytes[0], bytes[1]])),
                    );
                }
                DecodedInstruction::Load32 {
                    destination,
                    base,
                    offset,
                } => {
                    let address = self.get(base).wrapping_add(u64::from(offset));
                    let bytes = self.load(address, 4)?;
                    self.set(
                        destination,
                        u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
                    );
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
                DecodedInstruction::Load64 {
                    destination,
                    base,
                    offset,
                } => {
                    let address = self.get(base).wrapping_add(u64::from(offset));
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
