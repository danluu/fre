#![allow(
    clippy::arithmetic_side_effects,
    reason = "the bounded test ISA model intentionally implements architectural wrapping arithmetic"
)]

use core::mem::{align_of, size_of};

use fre_kernel_ir::{
    AggregateExecutionLimits, AggregateOutput, AnchorFlags, BlockId, ByteClass, Count,
    ExecutionLimits, InvalidProgram, OutputKind, RawProgram, SearchWindow, SelectedEnd, Span,
    SpanSum, ValidateError, ValidateLimits, build_class_suffix, build_exact_aggregate,
    build_exact_literal,
};

use crate::{
    AggregateResultLayout, AotLimits, AuditError, Condition, ConfirmationKind, CpuFeatures,
    DecodeError, DecodedInstruction, EmitError, EmitLimits, MAX_REPEATED_CONFIRM_BYTES,
    NativeAggregateImage, NativeAggregateResult, NativeImage, NativeResult, RelocationKind,
    RelocationTarget, ResourceKind, ResultLayout, audit, audit_aggregate, decode, decode_one, emit,
    emit_exact_aggregate,
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
        let first = emit(&program, EmitLimits::default()).expect("emission succeeds");
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
        for image in images {
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
            assert!(
                image
                    .to_aot(AotLimits::default())
                    .expect("bounded AOT")
                    .as_bytes()
                    .len()
                    <= 984
            );
            audit_aggregate(&image).expect("exact v1 envelope passes");
        }
    }
}

#[test]
fn search_audit_rejects_explicit_sp_operand() {
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("search program");
    let mut image = emit(&program, EmitLimits::default()).expect("search image");
    // The exact RET encoding still has its implicit x30 use; this explicit
    // `add sp, sp, #16` at entry must be rejected by the common operand visitor.
    image.code[0..4].copy_from_slice(&0x9100_43ff_u32.to_le_bytes());
    image.artifact_identity = image.compute_artifact_identity().expect("bounded identity");
    assert_eq!(
        audit(&image),
        Err(AuditError::ForbiddenAggregateRegister {
            offset: 0,
            register: 31,
        })
    );
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
            0x6e31_a800,
            DecodedInstruction::UnsignedMinBytes16 {
                destination: 0,
                source: 0,
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
    ];
    for (word, expected) in fixtures {
        let decoded = decode_one(word, 0).expect("known clang word");
        assert_eq!(decoded, expected);
        assert_eq!(crate::decode::canonical_word(decoded), Some(word));
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
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination: 17,
            source: 1,
            shift: 2,
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
        DecodedInstruction::UnsignedMinBytes16 {
            destination: 0,
            source: 1,
        },
        DecodedInstruction::UnsignedMaxBytes16 {
            destination: 0,
            source: 1,
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
                DecodedInstruction::DuplicateByte16 {
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
                DecodedInstruction::LogicalShiftRightVariable64 {
                    destination,
                    source,
                    shift,
                } => {
                    let amount = u32::try_from(self.get(shift) & 63).expect("masked shift");
                    self.set(destination, self.get(source) >> amount);
                }
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
    assert!(short.code().len() < 512);
    assert!(long.code().len() < 768);
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
