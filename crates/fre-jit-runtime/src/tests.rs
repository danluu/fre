use std::sync::{Mutex, MutexGuard};

use fre_jit_aarch64::{EmitLimits, NativeAggregateResult, emit, emit_exact_aggregate};
use fre_kernel_ir::{
    AggregateExecutionLimits, AggregateOutput, AnchorFlags, ByteClass, Count, ExecutionLimits,
    Exists, SearchWindow, SelectedEnd, Span, SpanSum, ValidateLimits, build_class_suffix,
    build_exact_aggregate, build_exact_literal,
};

use crate::{
    CallError, FailureStage, PublicationLimits, PublishError, ResourceKind,
    RuntimeAggregateOperation, RuntimeIdentity, RuntimeOperation,
    operation::{RawAggregateCallResult, decode_aggregate},
    platform::{self, FailureInjection},
    publish, publish_aggregate, publish_aggregate_impl, publish_impl,
};

static NATIVE_TEST_LOCK: Mutex<()> = Mutex::new(());

fn native_test_lock() -> MutexGuard<'static, ()> {
    NATIVE_TEST_LOCK.lock().expect("native test lock")
}

#[test]
fn strict_wx_smoke_matches_kernel_ir() {
    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("valid exact literal");
    let image = emit(&program, EmitLimits::default()).expect("emitted image");
    let expected_identity = RuntimeIdentity::for_image(&image);
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("strict W^X");
    assert_eq!(kernel.identity(), expected_identity);
    let haystack = b"zzneedlezz";
    let window = SearchWindow::new(0, haystack.len());
    let expected = program
        .execute(haystack, window, ExecutionLimits::unlimited())
        .expect("oracle")
        .into_output();
    let actual = kernel.search(haystack, window).expect("native call");
    assert_eq!(actual, expected);
}

#[test]
fn aggregate_one_call_hardware_matches_oracle_exhaustively() {
    let _lock = native_test_lock();
    let literals = all_sequences(b"ab", 3);
    let haystacks = all_sequences(b"ab", 6);
    let mut comparisons = 0_u64;
    for literal in &literals {
        let count = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("count program");
        let spans = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("span program");
        let count_image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
        let span_image = emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image");
        let count_kernel = publish_aggregate::<Count>(&count_image, PublicationLimits::default())
            .expect("count publication");
        let span_kernel = publish_aggregate::<SpanSum>(&span_image, PublicationLimits::default())
            .expect("span publication");
        for haystack in &haystacks {
            assert_aggregate_matches(&count, &count_kernel, haystack);
            assert_aggregate_matches(&spans, &span_kernel, haystack);
            comparisons = comparisons.checked_add(2).expect("bounded corpus");
        }
    }
    let arbitrary_literals = all_sequences(&[0x00, 0x7f, 0x80, 0xff], 2);
    let arbitrary_haystacks = all_sequences(&[0x00, 0x7f, 0x80, 0xff], 4);
    for literal in &arbitrary_literals {
        let count = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("arbitrary-byte count program");
        let spans = build_exact_aggregate::<SpanSum>(literal, ValidateLimits::default())
            .expect("arbitrary-byte span program");
        let count_image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
        let span_image = emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image");
        let count_kernel = publish_aggregate::<Count>(&count_image, PublicationLimits::default())
            .expect("count publication");
        let span_kernel = publish_aggregate::<SpanSum>(&span_image, PublicationLimits::default())
            .expect("span publication");
        for haystack in &arbitrary_haystacks {
            assert_aggregate_matches(&count, &count_kernel, haystack);
            assert_aggregate_matches(&spans, &span_kernel, haystack);
            comparisons = comparisons.checked_add(2).expect("bounded corpus");
        }
    }
    assert_eq!(comparisons, 18_132);
}

#[test]
fn aggregate_hardware_covers_bytes_alignments_tails_and_filter_liveness() {
    let _lock = native_test_lock();
    let mut comparisons = 0_u64;
    for literal_len in [1_usize, 2, 3, 15, 16, 17, 31, 32] {
        let literal: Vec<u8> = (0..literal_len)
            .map(|index| {
                u8::try_from(index)
                    .expect("width capped at 32")
                    .wrapping_mul(37)
                    .wrapping_add(if index % 2 == 0 { 0 } else { 0xff })
            })
            .collect();
        let count = build_exact_aggregate::<Count>(&literal, ValidateLimits::default())
            .expect("count program");
        let spans = build_exact_aggregate::<SpanSum>(&literal, ValidateLimits::default())
            .expect("span program");
        let count_image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
        let span_image = emit_exact_aggregate(&spans, EmitLimits::default()).expect("span image");
        let count_kernel = publish_aggregate::<Count>(&count_image, PublicationLimits::default())
            .expect("count kernel");
        let span_kernel = publish_aggregate::<SpanSum>(&span_image, PublicationLimits::default())
            .expect("span kernel");
        for alignment in 0..32 {
            for tail in 0..32 {
                let mut storage = vec![0x5a; alignment];
                storage.extend_from_slice(&literal);
                storage.extend(std::iter::repeat_n(0xa5, tail));
                storage.extend_from_slice(&literal);
                let haystack = &storage[alignment..];
                assert_aggregate_matches(&count, &count_kernel, haystack);
                assert_aggregate_matches(&spans, &span_kernel, haystack);
                comparisons = comparisons.checked_add(2).expect("bounded corpus");
            }
        }
    }

    let literal = b"abcdefghijklmnop";
    let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
        .expect("liveness program");
    let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("liveness image");
    let kernel =
        publish_aggregate::<Count>(&image, PublicationLimits::default()).expect("liveness kernel");
    let mut haystack = vec![b'x'; 47];
    haystack[0] = literal[0];
    haystack[15] = literal[15];
    haystack[31..47].copy_from_slice(literal);
    assert_aggregate_matches(&program, &kernel, &haystack);

    let every_byte: Vec<u8> = (0_u8..=u8::MAX).collect();
    for literal in 0_u8..=u8::MAX {
        let program = build_exact_aggregate::<Count>(&[literal], ValidateLimits::default())
            .expect("single-byte program");
        let image =
            emit_exact_aggregate(&program, EmitLimits::default()).expect("single-byte image");
        let kernel = publish_aggregate::<Count>(&image, PublicationLimits::default())
            .expect("single-byte kernel");
        assert_aggregate_matches(&program, &kernel, &every_byte);
    }
    assert_eq!(comparisons, 16_384);
}

#[test]
fn aggregate_guard_pages_cover_empty_short_vector_and_tail_paths() {
    let _lock = native_test_lock();
    for literal in [
        b"".as_slice(),
        b"a",
        b"needle",
        b"0123456789abcdefg",
        &[b'x'; 32],
    ] {
        let program = build_exact_aggregate::<Count>(literal, ValidateLimits::default())
            .expect("guard program");
        let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("guard image");
        let kernel =
            publish_aggregate::<Count>(&image, PublicationLimits::default()).expect("guard kernel");
        let mut bytes = b"q".to_vec();
        bytes.extend_from_slice(literal);
        bytes.push(b'z');
        for guarded in [bytes.as_slice(), b"tiny".as_slice(), b"".as_slice()] {
            for right in [false, true] {
                platform::with_guarded_haystack(guarded, right, |haystack| {
                    assert_aggregate_matches(&program, &kernel, haystack);
                })
                .expect("guarded aggregate haystack");
            }
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one test keeps every aggregate call ceiling and exact/one-below result together"
)]
fn aggregate_call_preflight_accepts_exact_and_refuses_each_positive_one_below() {
    let _lock = native_test_lock();
    let program =
        build_exact_aggregate::<Count>(b"aa", ValidateLimits::default()).expect("count program");
    let image = emit_exact_aggregate(&program, EmitLimits::default()).expect("count image");
    let kernel =
        publish_aggregate::<Count>(&image, PublicationLimits::default()).expect("count kernel");
    let haystack = b"aaaaaaaaaaaaaaaa";
    let upper = program
        .upper_bounds(haystack.len())
        .expect("checked bounds");
    let exact = AggregateExecutionLimits {
        max_haystack_bytes: upper.haystack_bytes,
        max_literal_bytes: upper.literal_bytes,
        max_candidate_positions: upper.candidate_positions,
        max_work: upper.work,
        max_match_events: upper.match_events,
        max_output: upper.count,
        max_reducer_steps: upper.reducer_steps,
        max_scratch_bytes: upper.scratch_bytes,
        max_native_invocations: upper.native_invocations,
    };
    assert_eq!(kernel.aggregate(haystack, exact), Ok(8));
    for (limits, expected) in [
        (
            AggregateExecutionLimits {
                max_haystack_bytes: upper.haystack_bytes - 1,
                ..exact
            },
            "haystack",
        ),
        (
            AggregateExecutionLimits {
                max_literal_bytes: upper.literal_bytes - 1,
                ..exact
            },
            "literal",
        ),
        (
            AggregateExecutionLimits {
                max_candidate_positions: upper.candidate_positions - 1,
                ..exact
            },
            "candidates",
        ),
        (
            AggregateExecutionLimits {
                max_work: upper.work - 1,
                ..exact
            },
            "work",
        ),
        (
            AggregateExecutionLimits {
                max_match_events: upper.match_events - 1,
                ..exact
            },
            "events",
        ),
        (
            AggregateExecutionLimits {
                max_output: upper.count - 1,
                ..exact
            },
            "output",
        ),
        (
            AggregateExecutionLimits {
                max_reducer_steps: upper.reducer_steps - 1,
                ..exact
            },
            "steps",
        ),
        (
            AggregateExecutionLimits {
                max_native_invocations: upper.native_invocations - 1,
                ..exact
            },
            "invocations",
        ),
    ] {
        let error = kernel
            .aggregate(haystack, limits)
            .expect_err("one-below call refuses before native entry");
        assert!(
            matches!(
                (&error, expected),
                (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::HaystackBytesLimit { .. }
                    ),
                    "haystack"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::LiteralBytesLimit { .. }
                    ),
                    "literal"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::CandidatePositionsLimit { .. }
                    ),
                    "candidates"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::WorkLimit { .. }
                    ),
                    "work"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::MatchEventsLimit { .. }
                    ),
                    "events"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::OutputLimit { .. }
                    ),
                    "output"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::ReducerStepsLimit { .. }
                    ),
                    "steps"
                ) | (
                    CallError::AggregatePreflight(
                        fre_kernel_ir::AggregateExecuteError::NativeInvocationsLimit { .. }
                    ),
                    "invocations"
                )
            ),
            "wrong {expected} failure: {error:?}"
        );
    }

    let empty = build_exact_aggregate::<SpanSum>(b"", ValidateLimits::default())
        .expect("empty span program");
    let empty_image = emit_exact_aggregate(&empty, EmitLimits::default()).expect("empty image");
    let empty_kernel = publish_aggregate::<SpanSum>(&empty_image, PublicationLimits::default())
        .expect("empty kernel");
    let upper = empty.upper_bounds(0).expect("empty bounds");
    assert_eq!(
        empty_kernel.aggregate(
            b"",
            AggregateExecutionLimits {
                max_haystack_bytes: 0,
                max_literal_bytes: 0,
                max_candidate_positions: 0,
                max_work: upper.work,
                max_match_events: upper.match_events,
                max_output: 0,
                max_reducer_steps: upper.reducer_steps,
                max_scratch_bytes: 0,
                max_native_invocations: 1,
            }
        ),
        Ok(0)
    );
}

#[test]
fn aggregate_result_decoding_ignores_fault_slots_and_validates_success_values() {
    for poisoned in [0_u64, u64::MAX] {
        assert_eq!(
            decode_aggregate::<Count>(
                RawAggregateCallResult {
                    status: 1,
                    slot: NativeAggregateResult { value: poisoned },
                },
                8,
                1,
            ),
            Err(CallError::AggregateArithmeticOverflow)
        );
    }
    assert_eq!(
        decode_aggregate::<Count>(
            RawAggregateCallResult {
                status: 2,
                slot: NativeAggregateResult { value: 0 },
            },
            8,
            1,
        ),
        Err(CallError::AggregateBackendFault { status: 2 })
    );
    assert!(matches!(
        decode_aggregate::<Count>(
            RawAggregateCallResult {
                status: 0,
                slot: NativeAggregateResult { value: u64::MAX },
            },
            8,
            1,
        ),
        Err(CallError::InvalidNativeAggregateOutput {
            output: AggregateOutput::Count,
            ..
        })
    ));
    for (value, literal_len) in [(1_u64, 0_usize), (3, 2), (10, 2)] {
        assert!(matches!(
            decode_aggregate::<SpanSum>(
                RawAggregateCallResult {
                    status: 0,
                    slot: NativeAggregateResult { value },
                },
                8,
                literal_len,
            ),
            Err(CallError::InvalidNativeAggregateOutput {
                output: AggregateOutput::SpanSum,
                ..
            })
        ));
    }
}

#[test]
fn aggregate_publication_is_operation_typed_and_all_failures_roll_back() {
    let _lock = native_test_lock();
    let count = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("count program");
    let image = emit_exact_aggregate(&count, EmitLimits::default()).expect("count image");
    assert!(matches!(
        publish_aggregate::<SpanSum>(&image, PublicationLimits::default()),
        Err(PublishError::AggregateOutputContractMismatch {
            expected: AggregateOutput::SpanSum,
            actual: AggregateOutput::Count,
        })
    ));
    assert_eq!(platform::live_code_mappings(), 0);
    for stage in [
        FailureStage::Reserve,
        FailureStage::MakeWritable,
        FailureStage::Copy,
        FailureStage::Verify,
        FailureStage::Reaudit,
        FailureStage::MakeExecutable,
        FailureStage::InvalidateInstructionCache,
        FailureStage::Publish,
    ] {
        assert_eq!(
            publish_aggregate_impl::<Count>(
                &image,
                PublicationLimits::default(),
                FailureInjection::At(stage),
            )
            .expect_err("injected aggregate publication failure"),
            PublishError::InjectedFailure { stage }
        );
        assert_eq!(platform::live_code_mappings(), 0, "leak at {stage:?}");
    }
    assert_eq!(
        publish_aggregate_impl::<Count>(
            &image,
            PublicationLimits::default(),
            FailureInjection::CorruptCopy,
        )
        .expect_err("corrupt aggregate copy rejected"),
        PublishError::CopyVerificationFailed
    );
    assert_eq!(platform::live_code_mappings(), 0);
}

#[test]
fn exact_literal_hardware_matches_oracle_for_all_outputs() {
    let _lock = native_test_lock();
    let comparisons = exact_comparisons::<Exists>()
        .checked_add(exact_comparisons::<SelectedEnd>())
        .and_then(|count| count.checked_add(exact_comparisons::<Span>()))
        .expect("bounded exact comparison count");
    assert!(comparisons > 100_000);
    eprintln!("exact literal actual-hardware comparisons: {comparisons}");
}

#[test]
fn class_suffix_hardware_matches_oracle_for_all_outputs() {
    let _lock = native_test_lock();
    let comparisons = class_suffix_comparisons::<Exists>()
        .checked_add(class_suffix_comparisons::<SelectedEnd>())
        .and_then(|count| count.checked_add(class_suffix_comparisons::<Span>()))
        .expect("bounded class comparison count");
    assert!(comparisons > 100_000);
    eprintln!("class+suffix actual-hardware comparisons: {comparisons}");
}

#[test]
fn vector_candidate_tails_and_haystack_alignments_match_oracle() {
    let _lock = native_test_lock();
    let mut comparisons = 0_u64;
    for literal in [
        b"a".as_slice(),
        b"needle",
        b"Sherlock Holmes",
        b"0123456789abcdefg",
    ] {
        let program =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("vector exact program");
        let image = emit(&program, EmitLimits::default()).expect("vector exact image");
        assert!(image.stats().vector_instructions >= 4);
        let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
        for alignment in 0..32 {
            for tail in 0..32 {
                let mut storage = vec![0x55; alignment];
                storage.extend_from_slice(b"prefix-");
                storage.extend_from_slice(literal);
                storage.extend(std::iter::repeat_n(b'x', tail));
                let haystack = &storage[alignment..];
                let window = SearchWindow::new(0, haystack.len());
                assert_native_matches(&program, &kernel, haystack, window);
                comparisons = comparisons.checked_add(1).expect("bounded test count");
            }
        }
    }
    assert_eq!(comparisons, 4_096);
}

#[test]
fn suffix_first_tails_and_haystack_alignments_match_oracle() {
    let _lock = native_test_lock();
    let suffix = b"bcdefghijklmnopq";
    let program = build_class_suffix::<Span>(
        ByteClass::from_bytes(b"a"),
        suffix,
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("suffix-first program");
    let image = emit(&program, EmitLimits::default()).expect("suffix-first image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let mut comparisons = 0_u64;
    for alignment in 0..32 {
        for tail in 0..32 {
            let mut storage = vec![0x55; alignment];
            storage.extend_from_slice(b"prefix-");
            storage.extend_from_slice(b"aaaa");
            storage.extend_from_slice(suffix);
            storage.extend(std::iter::repeat_n(b'x', tail));
            let haystack = &storage[alignment..];
            let window = SearchWindow::new(0, haystack.len());
            assert_native_matches(&program, &kernel, haystack, window);
            comparisons = comparisons.checked_add(1).expect("bounded test count");
        }
    }
    assert_eq!(comparisons, 1_024);
}

#[test]
fn inaccessible_haystack_boundaries_are_respected() {
    let _lock = native_test_lock();
    for literal in [
        b"a".as_slice(),
        b"needle",
        b"Sherlock Holmes",
        b"0123456789abcdefg",
    ] {
        let exact =
            build_exact_literal::<Span>(literal, AnchorFlags::default(), ValidateLimits::default())
                .expect("vector exact program");
        let exact_image = emit(&exact, EmitLimits::default()).expect("exact image");
        assert!(exact_image.stats().vector_instructions >= 4);
        let exact_kernel =
            publish::<Span>(&exact_image, PublicationLimits::default()).expect("exact");
        let mut bytes = b"xx".to_vec();
        bytes.extend_from_slice(literal);
        for right in [false, true] {
            platform::with_guarded_haystack(&bytes, right, |haystack| {
                let window = SearchWindow::new(0, haystack.len());
                assert_native_matches(&exact, &exact_kernel, haystack, window);
            })
            .expect("guarded exact haystack");
        }
    }

    let empty = build_exact_literal::<Span>(b"", AnchorFlags::default(), ValidateLimits::default())
        .expect("empty exact program");
    let empty_image = emit(&empty, EmitLimits::default()).expect("empty image");
    let empty_kernel = publish::<Span>(&empty_image, PublicationLimits::default()).expect("empty");
    for right in [false, true] {
        platform::with_guarded_haystack(b"", right, |haystack| {
            let window = SearchWindow::new(0, 0);
            assert_native_matches(&empty, &empty_kernel, haystack, window);
        })
        .expect("guarded empty haystack");
    }

    let suffix = b"bcdefghijklmnopq";
    for class in [ByteClass::from_bytes(b"a"), ByteClass::from_bytes(b"ac")] {
        let class_program = build_class_suffix::<Span>(
            class,
            suffix,
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("class suffix program");
        let class_image = emit(&class_program, EmitLimits::default()).expect("class suffix image");
        let class_kernel =
            publish::<Span>(&class_image, PublicationLimits::default()).expect("class suffix");
        for right in [false, true] {
            platform::with_guarded_haystack(b"aaabcdefghijklmnopq", right, |haystack| {
                let window = SearchWindow::new(0, haystack.len());
                assert_native_matches(&class_program, &class_kernel, haystack, window);
            })
            .expect("guarded class haystack");
        }
    }
}

#[test]
fn mapping_guards_and_rx_permissions_are_observed_by_mach() {
    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let protections = kernel.mapping.protections().expect("mach_vm_region");
    assert_eq!(protections.left_guard, libc::PROT_NONE);
    assert_eq!(protections.payload, libc::PROT_READ | libc::PROT_EXEC);
    assert_eq!(protections.payload & libc::PROT_WRITE, 0);
    assert_eq!(protections.right_guard, libc::PROT_NONE);
    assert!(
        kernel
            .mapping
            .post_publication_write_is_blocked()
            .expect("isolated write probe")
    );

    let aggregate = build_exact_aggregate::<Count>(b"needle", ValidateLimits::default())
        .expect("aggregate program");
    let aggregate_image =
        emit_exact_aggregate(&aggregate, EmitLimits::default()).expect("aggregate image");
    let aggregate_kernel =
        publish_aggregate::<Count>(&aggregate_image, PublicationLimits::default())
            .expect("aggregate publish");
    let protections = aggregate_kernel
        .mapping
        .protections()
        .expect("aggregate mach_vm_region");
    assert_eq!(protections.left_guard, libc::PROT_NONE);
    assert_eq!(protections.payload, libc::PROT_READ | libc::PROT_EXEC);
    assert_eq!(protections.payload & libc::PROT_WRITE, 0);
    assert_eq!(protections.right_guard, libc::PROT_NONE);
}

#[test]
fn every_injected_failure_rolls_back_without_a_callable() {
    let _lock = native_test_lock();
    assert_eq!(platform::live_code_mappings(), 0);
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    for stage in [
        FailureStage::Reserve,
        FailureStage::MakeWritable,
        FailureStage::Copy,
        FailureStage::Verify,
        FailureStage::Reaudit,
        FailureStage::MakeExecutable,
        FailureStage::InvalidateInstructionCache,
        FailureStage::Publish,
    ] {
        let error = publish_impl::<Span>(
            &image,
            PublicationLimits::default(),
            FailureInjection::At(stage),
        )
        .expect_err("injected stage fails");
        assert_eq!(error, PublishError::InjectedFailure { stage });
        assert_eq!(platform::live_code_mappings(), 0, "leak at {stage:?}");
    }
    assert_eq!(
        publish_impl::<Span>(
            &image,
            PublicationLimits::default(),
            FailureInjection::CorruptCopy,
        )
        .expect_err("corrupt copy rejected"),
        PublishError::CopyVerificationFailed
    );
    assert_eq!(platform::live_code_mappings(), 0);

    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("recovery publish");
    assert_eq!(platform::live_code_mappings(), 1);
    drop(kernel);
    assert_eq!(platform::live_code_mappings(), 0);
}

#[test]
fn output_contract_window_and_resource_failures_are_typed() {
    let _lock = native_test_lock();
    let program = build_exact_literal::<Span>(
        b"0123456789abcdefg",
        AnchorFlags::default(),
        ValidateLimits::default(),
    )
    .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    assert!(matches!(
        publish::<Exists>(&image, PublicationLimits::default()),
        Err(PublishError::OutputContractMismatch { .. })
    ));

    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let accounting = kernel.accounting();
    assert_eq!(
        accounting.guard_bytes,
        accounting
            .page_bytes
            .checked_mul(2)
            .expect("two guard pages")
    );
    assert_eq!(
        accounting.total_mapped_bytes,
        accounting
            .payload_mapped_bytes
            .checked_add(accounting.guard_bytes)
            .expect("bounded mapping")
    );
    assert_eq!(
        kernel.search(b"tiny", SearchWindow::new(2, 6)),
        Err(CallError::InvalidWindow {
            start: 2,
            end: 6,
            haystack_len: 4,
        })
    );
    drop(kernel);

    for (resource, exact) in [
        (ResourceKind::CodeBytes, accounting.code_bytes),
        (ResourceKind::DataBytes, accounting.data_bytes),
        (ResourceKind::PayloadBytes, accounting.payload_mapped_bytes),
        (ResourceKind::MappedBytes, accounting.total_mapped_bytes),
        (ResourceKind::Pages, accounting.total_pages),
    ] {
        let exact_limits = limits_with(resource, exact);
        drop(publish::<Span>(&image, exact_limits).expect("exact boundary"));
        let failing = limits_with(resource, exact.checked_sub(1).expect("nonzero resource"));
        assert!(matches!(
            publish::<Span>(&image, failing),
            Err(PublishError::ResourceLimit {
                resource: actual,
                ..
            }) if actual == resource
        ));
    }
}

#[test]
fn cloned_ownership_prevents_call_unmap_races() {
    let _lock = native_test_lock();
    let program =
        build_exact_literal::<Span>(b"needle", AnchorFlags::default(), ValidateLimits::default())
            .expect("program");
    let image = emit(&program, EmitLimits::default()).expect("image");
    let kernel = publish::<Span>(&image, PublicationLimits::default()).expect("publish");
    let mut workers = Vec::new();
    for _ in 0..8 {
        let clone = kernel.clone();
        workers.push(std::thread::spawn(move || {
            let haystack = b"zzneedlezz";
            let window = SearchWindow::new(0, haystack.len());
            for _ in 0..2_000 {
                let span = clone.search(haystack, window).expect("concurrent call");
                assert_eq!(span.map(|value| (value.start(), value.end())), Some((2, 8)));
            }
        }));
    }
    drop(kernel);
    for worker in workers {
        worker.join().expect("worker does not panic");
    }
    assert_eq!(platform::live_code_mappings(), 0);
}

fn exact_comparisons<O: RuntimeOperation>() -> u64
where
    O::Output: Eq,
{
    let mut haystacks = all_sequences(b"ab", 5);
    haystacks.extend([
        b"xxxxxxxxxxxxxxx0123456789abcdef".to_vec(),
        b"xxxxxxxxxxxxxxxx0123456789abcdefg".to_vec(),
        b"0123456789abcdeg0123456789abcdef".to_vec(),
        vec![b'x'; 65],
    ]);
    let literals = [
        b"".as_slice(),
        b"a",
        b"ab",
        b"0123456789abcdef",
        b"0123456789abcdefg",
        &[b'x'; fre_jit_aarch64::MAX_REPEATED_CONFIRM_BYTES],
    ];
    let mut comparisons = 0_u64;
    for literal in literals {
        for anchors in anchor_options() {
            let program =
                build_exact_literal::<O>(literal, anchors, ValidateLimits::default()).expect("IR");
            let image = emit(&program, EmitLimits::default()).expect("emit");
            let kernel = publish::<O>(&image, PublicationLimits::default()).expect("publish");
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        assert_native_matches(
                            &program,
                            &kernel,
                            haystack,
                            SearchWindow::new(start, end),
                        );
                        comparisons = comparisons.checked_add(1).expect("bounded test count");
                    }
                }
            }
        }
    }
    comparisons
}

fn class_suffix_comparisons<O: RuntimeOperation>() -> u64
where
    O::Output: Eq,
{
    let mut haystacks = all_sequences(b"abc", 5);
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
                build_class_suffix::<O>(class, suffix, anchors, ValidateLimits::default())
                    .expect("proved-disjoint IR");
            let image = emit(&program, EmitLimits::default()).expect("emit");
            let kernel = publish::<O>(&image, PublicationLimits::default()).expect("publish");
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        assert_native_matches(
                            &program,
                            &kernel,
                            haystack,
                            SearchWindow::new(start, end),
                        );
                        comparisons = comparisons.checked_add(1).expect("bounded test count");
                    }
                }
            }
        }
    }
    comparisons
}

fn assert_native_matches<O: RuntimeOperation>(
    program: &fre_kernel_ir::ValidatedProgram<O>,
    kernel: &crate::PublishedKernel<O>,
    haystack: &[u8],
    window: SearchWindow,
) where
    O::Output: Eq,
{
    let expected = program
        .execute(haystack, window, ExecutionLimits::unlimited())
        .expect("oracle execution")
        .into_output();
    let actual = kernel.search(haystack, window).expect("native execution");
    assert_eq!(
        actual,
        expected,
        "output={:?} haystack={haystack:?} window={}..{}",
        O::KIND,
        window.start(),
        window.end()
    );
}

fn assert_aggregate_matches<A: RuntimeAggregateOperation>(
    program: &fre_kernel_ir::ExactAggregateProgram<A>,
    kernel: &crate::PublishedAggregateKernel<A>,
    haystack: &[u8],
) {
    let expected = program
        .execute(haystack, AggregateExecutionLimits::unlimited())
        .expect("aggregate oracle")
        .into_output();
    let actual = kernel
        .aggregate(haystack, AggregateExecutionLimits::unlimited())
        .expect("native aggregate");
    assert_eq!(
        actual,
        expected,
        "aggregate={:?} literal={:?} haystack={haystack:?}",
        A::OUTPUT,
        program.literal()
    );
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

fn limits_with(resource: ResourceKind, exact: usize) -> PublicationLimits {
    let exact = u64::try_from(exact).expect("small test resource");
    let mut limits = PublicationLimits::default();
    match resource {
        ResourceKind::CodeBytes => limits.max_code_bytes = exact,
        ResourceKind::DataBytes => limits.max_data_bytes = exact,
        ResourceKind::PayloadBytes => limits.max_payload_bytes = exact,
        ResourceKind::MappedBytes => limits.max_mapped_bytes = exact,
        ResourceKind::Pages => limits.max_pages = exact,
    }
    limits
}
